#!/usr/bin/env bash
#############################################
# EdgeBox - Protocol Health Monitor (v4.1.0)
#
# Architecture: 3-protocol (Reality + Hysteria2 + WS)
# Default mode: MONITOR (detect + alert only, no automatic repairs)
#
# What this does:
#   1. Probes each of the 3 protocols for liveness
#   2. Writes /etc/edgebox/traffic/protocol-health.json (for dashboard)
#   3. On state CHANGE (healthy -> down), sends alerts via configured channels
#   4. In monitor mode (default): NEVER touches services or firewall rules
#   5. In repair mode (opt-in): may restart service (only - no config edits)
#
# Detection logic:
#   reality / ws (TCP):
#     - healthy: xray active AND port listening
#     - down:    xray inactive OR port not listening
#
#   hysteria2 (UDP, three-state):
#     - healthy:              sing-box active AND port listening
#                             AND log shows recent UDP activity (24h)
#     - listening_unverified: sing-box active AND port listening
#                             but no log activity yet (normal for new servers)
#     - down:                 sing-box inactive OR port not listening
#
# Alert behavior:
#   - State CHANGE triggers ONE alert (healthy -> down, listening_unverified -> down)
#   - Repeated 'down' state does NOT re-alert (avoids flooding)
#   - Recovery (down -> healthy) also triggers ONE alert
#   - listening_unverified is NOT a down state and does NOT alert
#   - All alerts respect the silence file
#
# State persistence:
#   - /run/edgebox/monitor/last_state.json (per-protocol last known state)
#   - Survives within the same boot; cleared on reboot (which is OK -
#     services restart on reboot too, so re-evaluating is correct)
#
# Configuration:
#   HEALTH_MODE      = monitor (default) | repair | off
#   ALERT_ON_CHANGE  = 1 (default) | 0
#   LOG_LOOKBACK_HRS = 24 (default)
#
# Exit codes:
#   0  - normal completion (regardless of protocol health)
#   1  - the script itself failed (config missing, jq broken, etc.)
#############################################

# Defensive: don't crash on small failures
set +e
set +u
set -o pipefail 2>/dev/null || true

# ==================== CONFIG ====================
# Priority: env var > /etc/edgebox/traffic/health_mode > default "monitor"
if [[ -z "${HEALTH_MODE:-}" ]] && [[ -f "${TRAFFIC_DIR:-/etc/edgebox/traffic}/health_mode" ]]; then
    HEALTH_MODE=$(cat "${TRAFFIC_DIR:-/etc/edgebox/traffic}/health_mode" 2>/dev/null | tr -d '[:space:]')
fi
HEALTH_MODE="${HEALTH_MODE:-monitor}"   # monitor | repair | off
ALERT_ON_CHANGE="${ALERT_ON_CHANGE:-1}"
LOG_LOOKBACK_HRS="${LOG_LOOKBACK_HRS:-24}"

CONFIG_DIR="${CONFIG_DIR:-/etc/edgebox/config}"
TRAFFIC_DIR="${TRAFFIC_DIR:-/etc/edgebox/traffic}"
SCRIPTS_DIR="${SCRIPTS_DIR:-/etc/edgebox/scripts}"
LOG_DIR="${LOG_DIR:-/var/log/edgebox}"

OUTPUT_JSON="${TRAFFIC_DIR}/protocol-health.json"
STATE_DIR="${STATE_DIR:-/run/edgebox/monitor}"
STATE_FILE="${STATE_DIR}/last_state.json"
LOG_FILE="${LOG_DIR}/health-monitor.log"

mkdir -p "$LOG_DIR" "$STATE_DIR" "$TRAFFIC_DIR" 2>/dev/null || true

# ==================== LOAD ALERT LIB ====================
if [[ -f "${SCRIPTS_DIR}/lib/alert.sh" ]]; then
    # shellcheck source=/dev/null
    source "${SCRIPTS_DIR}/lib/alert.sh" 2>/dev/null || true
fi

# Fallback: if alert.sh isn't available, define a no-op so we don't crash
if ! declare -F eb_alert_send >/dev/null 2>&1; then
    eb_alert_send() {
        echo "[$(date -Is)] [WARN] alert.sh not loaded; would have sent: $1" >> "$LOG_FILE"
    }
fi

# ==================== LOGGING HELPERS ====================
_log() {
    local level="$1"; shift
    echo "[$(date -Is)] [$level] $*" >> "$LOG_FILE" 2>/dev/null
}
log_info()    { _log INFO    "$@"; }
log_warn()    { _log WARN    "$@"; }
log_error()   { _log ERROR   "$@"; }
log_success() { _log SUCCESS "$@"; }

# ==================== EXIT GUARD: mode=off ====================
if [[ "$HEALTH_MODE" == "off" ]]; then
    log_info "HEALTH_MODE=off; skipping all checks."
    # Still emit a minimal protocol-health.json so dashboard doesn't break
    cat > "${OUTPUT_JSON}.tmp" <<EOF
{
  "mode": "off",
  "metrics": {"total": 0, "healthy": 0, "down": 0, "listening_unverified": 0, "avg_health_score": 0},
  "protocols": [],
  "services": {},
  "generated_at": "$(date -Is)"
}
EOF
    mv -f "${OUTPUT_JSON}.tmp" "$OUTPUT_JSON" 2>/dev/null
    exit 0
fi

# ==================== STATE FILE HELPERS ====================

# Read previous state for a protocol; default to "unknown"
_get_last_state() {
    local proto="$1"
    if [[ -f "$STATE_FILE" ]]; then
        jq -r --arg p "$proto" '.protocols[$p].state // "unknown"' "$STATE_FILE" 2>/dev/null || echo "unknown"
    else
        echo "unknown"
    fi
}

# Atomically update state file with all current results
# Input: JSON object {reality: {state, ...}, hysteria2: {...}, ws: {...}}
_write_state() {
    local results_json="$1"
    local tmp="${STATE_FILE}.tmp"
    jq -n --argjson p "$results_json" --arg ts "$(date -Is)" \
        '{updated_at: $ts, protocols: $p}' > "$tmp" 2>/dev/null

    if [[ -s "$tmp" ]]; then
        mv -f "$tmp" "$STATE_FILE"
    else
        rm -f "$tmp"
        log_error "Failed to write state file"
    fi
}

# ==================== PROBES ====================

# Check if a TCP port is listening on the host (any interface)
_is_tcp_listening() {
    local port="$1"
    ss -tln 2>/dev/null | grep -qE "[:.]${port}[[:space:]]"
}

# Check if a UDP port is listening
_is_udp_listening() {
    local port="$1"
    ss -uln 2>/dev/null | grep -qE "[:.]${port}[[:space:]]"
}

# Check if a systemd unit is active
_is_service_active() {
    local svc="$1"
    systemctl is-active --quiet "$svc" 2>/dev/null
}

# Check if sing-box logs have shown UDP traffic activity in the last N hours
# (for hysteria2 verification)
_has_recent_udp_activity() {
    local hours="${1:-24}"
    # Try several keyword patterns - sing-box log formats vary by version
    local since_arg
    since_arg="${hours} hours ago"

    # Common log lines for hysteria2 traffic:
    #   "accepted udp connection"
    #   "inbound/hysteria2 ... handshake"
    #   "client connected"
    # On a fresh server with no clients connected, none of these appear.
    journalctl -u sing-box --since "$since_arg" --no-pager 2>/dev/null \
        | grep -iE "(accepted.*connection|hysteria2.*connect|udp.*accept|client.*authent)" \
        | head -1 \
        | grep -q . 2>/dev/null
}

# ==================== INDIVIDUAL PROTOCOL CHECKS ====================

# Returns JSON: {"state": "...", "details": "...", "checked_at": "..."}
check_reality() {
    local state details
    if ! _is_service_active xray; then
        state="down"; details="xray service inactive"
    elif ! _is_tcp_listening 11443; then
        state="down"; details="xray reality backend port 11443 not listening"
    elif ! _is_tcp_listening 443; then
        state="down"; details="nginx front port 443/tcp not listening"
    else
        state="healthy"; details="xray active, port 11443 + 443 listening"
    fi

    jq -n --arg s "$state" --arg d "$details" --arg ts "$(date -Is)" \
        '{state: $s, details: $d, checked_at: $ts}'
}

check_ws() {
    local state details
    if ! _is_service_active xray; then
        state="down"; details="xray service inactive"
    elif ! _is_tcp_listening 10086; then
        state="down"; details="xray ws backend port 10086 not listening"
    elif ! _is_tcp_listening 443; then
        state="down"; details="nginx front port 443/tcp not listening"
    else
        state="healthy"; details="xray active, port 10086 + 443 listening"
    fi

    jq -n --arg s "$state" --arg d "$details" --arg ts "$(date -Is)" \
        '{state: $s, details: $d, checked_at: $ts}'
}

check_hysteria2() {
    local state details
    if ! _is_service_active sing-box; then
        state="down"; details="sing-box service inactive"
    elif ! _is_udp_listening 443; then
        state="down"; details="port 443/udp not listening"
    elif _has_recent_udp_activity "$LOG_LOOKBACK_HRS"; then
        state="healthy"; details="sing-box active, UDP/443 listening, log activity within ${LOG_LOOKBACK_HRS}h"
    else
        # Third state: listening but no observed activity yet
        state="listening_unverified"
        details="sing-box active, UDP/443 listening; no client activity in last ${LOG_LOOKBACK_HRS}h (normal for new servers)"
    fi

    jq -n --arg s "$state" --arg d "$details" --arg ts "$(date -Is)" \
        '{state: $s, details: $d, checked_at: $ts}'
}

# ==================== REPAIR ACTIONS (stubbed in monitor mode) ====================

# Even in repair mode, we ONLY allow service restart - never config changes.
# This is the conservative subset of v3's repair logic.
maybe_repair() {
    local proto="$1" service="$2" state="$3"

    if [[ "$state" != "down" ]]; then
        return 0  # nothing to do
    fi

    if [[ "$HEALTH_MODE" == "monitor" ]]; then
        log_info "[$proto] would attempt repair (restart $service) - but mode=monitor, skipping"
        return 0
    fi

    if [[ "$HEALTH_MODE" != "repair" ]]; then
        return 0
    fi

    log_warn "[$proto] HEALTH_MODE=repair: attempting to restart $service"
    if systemctl restart "$service" 2>>"$LOG_FILE"; then
        log_success "[$proto] $service restart issued; will re-check on next cycle"
    else
        log_error "[$proto] failed to restart $service"
    fi
}

# ==================== ALERT ON STATE CHANGE ====================

emit_alert_if_changed() {
    local proto="$1" new_state="$2" details="$3"
    local prev_state
    prev_state=$(_get_last_state "$proto")

    # Track only meaningful transitions
    case "${prev_state}->${new_state}" in
        # Going down
        "healthy->down"|"listening_unverified->down")
            [[ "$ALERT_ON_CHANGE" == "1" ]] && eb_alert_send \
                "协议 ${proto} 故障" \
                "$(printf '状态从 %s 变为 down。\n详情: %s' "$prev_state" "$details")" \
                "critical"
            ;;
        # Recovering
        "down->healthy"|"down->listening_unverified")
            [[ "$ALERT_ON_CHANGE" == "1" ]] && eb_alert_send \
                "协议 ${proto} 已恢复" \
                "$(printf '状态从 down 变为 %s。\n详情: %s' "$new_state" "$details")" \
                "info"
            ;;
        # First-time observation that things are bad
        "unknown->down")
            [[ "$ALERT_ON_CHANGE" == "1" ]] && eb_alert_send \
                "协议 ${proto} 初次检测为 down" \
                "详情: ${details}" \
                "critical"
            ;;
        # No alerts for:
        #   * same state repeating (healthy->healthy, down->down)
        #   * normal-to-normal transitions (healthy->listening_unverified is OK,
        #     it just means traffic dried up but service is fine)
        #   * unknown->healthy/listening_unverified (initial good state)
        *)
            :  # no-op
            ;;
    esac
}

# ==================== MAIN ====================
main() {
    log_info "=========================================="
    log_info "Health monitor starting (mode=$HEALTH_MODE)"

    # v4.6.0-rc1: 检测 CDN 模式
    # CDN 模式下 Reality / Hysteria2 被主动停用，不应报为故障
    local server_json="/etc/edgebox/config/server.json"
    local cdn_enabled cdn_host
    if [[ -f "$server_json" ]]; then
        cdn_enabled=$(jq -r '.cdn.enabled // false' "$server_json" 2>/dev/null)
        cdn_host=$(jq -r '.cdn.host // empty' "$server_json" 2>/dev/null)
    fi

    local in_cdn_mode=false
    if [[ "$cdn_enabled" == "true" && -n "$cdn_host" && "$cdn_host" != "null" ]]; then
        in_cdn_mode=true
        log_info "CDN mode detected (host=$cdn_host); only checking VLESS-WS"
    fi

    # 状态变量初始化
    local reality_json hysteria2_json ws_json
    local reality_state hysteria2_state ws_state
    local reality_details hysteria2_details ws_details
    local total

    if $in_cdn_mode; then
        # CDN 模式：只检查 WS
        reality_json='{"state":"disabled","details":"CDN mode: Reality intentionally disabled"}'
        hysteria2_json='{"state":"disabled","details":"CDN mode: Hysteria2 intentionally disabled (CDNs do not proxy UDP)"}'
        ws_json=$(check_ws)
        total=1
    else
        # 直连模式：全部 3 协议
        reality_json=$(check_reality)
        hysteria2_json=$(check_hysteria2)
        ws_json=$(check_ws)
        total=3
    fi

    reality_state=$(jq -r '.state'    <<<"$reality_json")
    reality_details=$(jq -r '.details' <<<"$reality_json")
    hysteria2_state=$(jq -r '.state'    <<<"$hysteria2_json")
    hysteria2_details=$(jq -r '.details' <<<"$hysteria2_json")
    ws_state=$(jq -r '.state'    <<<"$ws_json")
    ws_details=$(jq -r '.details' <<<"$ws_json")

    log_info "reality: $reality_state ($reality_details)"
    log_info "hysteria2: $hysteria2_state ($hysteria2_details)"
    log_info "ws: $ws_state ($ws_details)"

    # 仅对实际激活的协议发告警 + 尝试 repair
    if $in_cdn_mode; then
        emit_alert_if_changed "ws" "$ws_state" "$ws_details"
        maybe_repair "ws" "xray" "$ws_state"
    else
        emit_alert_if_changed "reality" "$reality_state" "$reality_details"
        emit_alert_if_changed "hysteria2" "$hysteria2_state" "$hysteria2_details"
        emit_alert_if_changed "ws" "$ws_state" "$ws_details"
        maybe_repair "reality" "xray" "$reality_state"
        maybe_repair "hysteria2" "sing-box" "$hysteria2_state"
        maybe_repair "ws" "xray" "$ws_state"
    fi

    # Build combined state JSON for state file (保留全部 3 个键以保持 dashboard 兼容)
    local combined
    combined=$(jq -n \
        --argjson r "$reality_json" \
        --argjson h "$hysteria2_json" \
        --argjson w "$ws_json" \
        '{reality: $r, hysteria2: $h, ws: $w}')

    _write_state "$combined"

    # Build dashboard-facing JSON
    # 注：disabled 状态不算 healthy 也不算 down，统计为 0
    local healthy_count down_count unverified_count avg
    if $in_cdn_mode; then
        healthy_count=$([[ "$ws_state" == "healthy" ]] && echo 1 || echo 0)
        down_count=$([[ "$ws_state" == "down" ]] && echo 1 || echo 0)
        unverified_count=$([[ "$ws_state" == "listening_unverified" ]] && echo 1 || echo 0)
        avg=$(( healthy_count * 100 + unverified_count * 50 ))
    else
        healthy_count=$(jq -n --argjson r "$reality_json" --argjson h "$hysteria2_json" --argjson w "$ws_json" \
            '[$r.state, $h.state, $w.state] | map(select(. == "healthy")) | length')
        down_count=$(jq -n --argjson r "$reality_json" --argjson h "$hysteria2_json" --argjson w "$ws_json" \
            '[$r.state, $h.state, $w.state] | map(select(. == "down")) | length')
        unverified_count=$(jq -n --argjson r "$reality_json" --argjson h "$hysteria2_json" --argjson w "$ws_json" \
            '[$r.state, $h.state, $w.state] | map(select(. == "listening_unverified")) | length')
        avg=$(jq -n --argjson h "$healthy_count" --argjson u "$unverified_count" \
            '(($h * 100) + ($u * 50)) / 3 | floor')
    fi

    local services_json
    services_json=$(jq -n \
        --arg xray "$(systemctl is-active xray 2>/dev/null || echo 'unknown')" \
        --arg sb "$(systemctl is-active sing-box 2>/dev/null || echo 'unknown')" \
        --arg nginx "$(systemctl is-active nginx 2>/dev/null || echo 'unknown')" \
        '{xray: $xray, "sing-box": $sb, nginx: $nginx}')

    # Protocols array: CDN 模式只含 WS
    local protocols_arr
    if $in_cdn_mode; then
        protocols_arr=$(jq -n \
            --argjson w "$ws_json" \
            '[{name: "VLESS-WS", protocol: "ws"} + $w]')
    else
        protocols_arr=$(jq -n \
            --argjson r "$reality_json" \
            --argjson h "$hysteria2_json" \
            --argjson w "$ws_json" \
            '[
              {name: "VLESS-Reality", protocol: "reality"} + $r,
              {name: "Hysteria2",     protocol: "hysteria2"} + $h,
              {name: "VLESS-WS",      protocol: "ws"}      + $w
            ]')
    fi

    # Output JSON
    local tmp="${OUTPUT_JSON}.tmp"
    jq -n \
        --arg mode "$HEALTH_MODE" \
        --arg ts "$(date -Is)" \
        --argjson total "$total" \
        --argjson healthy "$healthy_count" \
        --argjson down "$down_count" \
        --argjson unverified "$unverified_count" \
        --argjson avg "$avg" \
        --argjson protocols "$protocols_arr" \
        --argjson services "$services_json" \
        '{
          mode: $mode,
          metrics: {
            total: $total,
            healthy: $healthy,
            down: $down,
            listening_unverified: $unverified,
            avg_health_score: $avg
          },
          protocols: $protocols,
          services: $services,
          generated_at: $ts
        }' > "$tmp" 2>>"$LOG_FILE"

    if [[ -s "$tmp" ]]; then
        mv -f "$tmp" "$OUTPUT_JSON"
        chmod 644 "$OUTPUT_JSON" 2>/dev/null
        log_success "Health report written: $OUTPUT_JSON"
        log_info "Summary: healthy=$healthy_count down=$down_count unverified=$unverified_count score=$avg"
    else
        rm -f "$tmp"
        log_error "Failed to build health report JSON"
        exit 1
    fi

    log_info "Health monitor done."
}

# Run main if script is executed (not sourced)
if [[ "${BASH_SOURCE[0]}" == "${0}" ]] || [[ -z "${BASH_SOURCE[0]:-}" ]]; then
    main "$@"
fi
