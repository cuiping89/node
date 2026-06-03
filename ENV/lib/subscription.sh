#!/usr/bin/env bash
#############################################
# EdgeBox - Subscription Generator (subscription.sh)
# Version: v4.0.0
#
# Architecture: 3-protocol triple-layer
#   Layer 1: VLESS-Reality   (TCP/443, primary daily use)
#   Layer 2: Hysteria2       (UDP/443, fallback when TCP is interfered)
#   Layer 3: VLESS-WS        (TCP/443, IP-blocked fallback - CDN-ready)
#
# Output: 4 subscription formats, written atomically as a set.
#   1. subscription.txt           - plain URI list (v2rayN, v2rayNG, Streisand)
#   2. subscription.base64        - base64-encoded plain list (legacy clients)
#   3. subscription.clash.yaml    - Mihomo / Clash Meta YAML
#   4. subscription.singbox.json  - sing-box native config
#
# Modes:
#   - IP mode (cert_mode = "self-signed"):
#       * Reality: server_ip:443, SNI = real public domain (microsoft.com etc)
#       * Hysteria2: server_ip:443, insecure=1
#       * WS: server_ip:443, SNI = ws.edgebox.internal, allowInsecure=1
#   - Domain mode (cert_mode = "letsencrypt:<domain>"):
#       * Reality: <domain>:443, SNI = real public domain (unchanged)
#       * Hysteria2: <domain>:443, real TLS
#       * WS: <domain>:443, SNI = <domain>, real TLS
#
# CDN mode is reserved for block 5 (see eb_gen_subscription() entry point).
#############################################

# Resolve the directory of this script so we can source common.sh next to it
EB_LIB_DIR="${EB_LIB_DIR:-$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)}"

# shellcheck source=./common.sh
source "${EB_LIB_DIR}/common.sh"

#############################################
# URI builders - one per protocol
#############################################

# Build VLESS-Reality URI.
# Reality URI is mode-independent: the host changes (IP or domain) but the SNI
# is always the real public domain used by Reality TLS handshake.
_eb_uri_reality() {
    local host="$1"
    local uuid reality_sni pubkey sid
    uuid=$(eb_get_uuid_reality)
    reality_sni=$(eb_get_reality_sni)
    pubkey=$(eb_get_reality_pubkey)
    sid=$(eb_get_reality_sid)

    if [[ -z "$uuid" || -z "$pubkey" || -z "$sid" ]]; then
        eb_log_warn "Reality credentials incomplete, skipping URI"
        return 1
    fi

    printf 'vless://%s@%s:443?encryption=none&flow=xtls-rprx-vision&security=reality&sni=%s&fp=chrome&pbk=%s&sid=%s&type=tcp#EdgeBox-REALITY\n' \
        "$uuid" "$host" "$reality_sni" "$pubkey" "$sid"
}

# Build Hysteria2 URI.
# Spec: hysteria2://[auth@]hostname[:port]/?[key=value]&...
# Note the '/' before '?' - required by spec, enforced by newer parsers.
_eb_uri_hysteria2() {
    local host="$1"
    local mode="$2"
    local password pw_enc
    password=$(eb_get_password_hy2)

    if [[ -z "$password" ]]; then
        eb_log_warn "Hysteria2 password missing, skipping URI"
        return 1
    fi

    pw_enc=$(eb_url_encode "$password")

    if [[ "$mode" == "domain" ]]; then
        printf 'hysteria2://%s@%s:443/?sni=%s&alpn=h3#EdgeBox-HYSTERIA2\n' \
            "$pw_enc" "$host" "$host"
    else
        printf 'hysteria2://%s@%s:443/?sni=%s&alpn=h3&insecure=1#EdgeBox-HYSTERIA2\n' \
            "$pw_enc" "$host" "$host"
    fi
}

# Build VLESS-WS URI.
_eb_uri_ws() {
    local host="$1"
    local mode="$2"
    local uuid path path_enc
    uuid=$(eb_get_uuid_ws)
    path=$(eb_get_ws_path)

    if [[ -z "$uuid" ]]; then
        eb_log_warn "WS UUID missing, skipping URI"
        return 1
    fi

    path_enc=$(eb_url_encode "$path")

    if [[ "$mode" == "domain" ]]; then
        printf 'vless://%s@%s:443?encryption=none&security=tls&sni=%s&host=%s&alpn=http%%2F1.1&type=ws&path=%s&fp=chrome#EdgeBox-WS\n' \
            "$uuid" "$host" "$host" "$host" "$path_enc"
    else
        printf 'vless://%s@%s:443?encryption=none&security=tls&sni=ws.edgebox.internal&host=ws.edgebox.internal&alpn=http%%2F1.1&type=ws&path=%s&fp=chrome&allowInsecure=1#EdgeBox-WS\n' \
            "$uuid" "$host" "$path_enc"
    fi
}

#############################################
# Format 1: Plain URI list
#############################################
_eb_gen_plain() {
    local host="$1"
    local mode="$2"
    local out=""
    local line

    # Note: command substitution $(...) strips trailing newlines, so we
    # re-add the newline explicitly between URIs.
    line=$(_eb_uri_reality   "$host"       ) && out+="${line}"$'\n'
    line=$(_eb_uri_hysteria2 "$host" "$mode") && out+="${line}"$'\n'
    line=$(_eb_uri_ws        "$host" "$mode") && out+="${line}"$'\n'

    printf '%s' "$out"
}

#############################################
# Format 2: Base64 (encodes the plain list)
#############################################
_eb_gen_base64() {
    local plain="$1"
    if base64 --help 2>&1 | grep -q -- '-w'; then
        printf '%s' "$plain" | base64 -w0
    else
        printf '%s' "$plain" | base64 | tr -d '\n'
    fi
}

#############################################
# Format 3: Clash / Mihomo YAML
#
# Built via heredoc with eb_yaml_squote on every user-controlled string.
# This is safer than YAML libraries for shell scripts because we have full
# control over output structure.
#############################################
_eb_gen_clash() {
    local host="$1"
    local mode="$2"

    local uuid_reality reality_sni pubkey sid
    local password_hy2
    local uuid_ws ws_path
    local insecure_str

    uuid_reality=$(eb_get_uuid_reality)
    reality_sni=$(eb_get_reality_sni)
    pubkey=$(eb_get_reality_pubkey)
    sid=$(eb_get_reality_sid)
    password_hy2=$(eb_get_password_hy2)
    uuid_ws=$(eb_get_uuid_ws)
    ws_path=$(eb_get_ws_path)

    if [[ "$mode" == "domain" ]]; then
        insecure_str="false"
    else
        insecure_str="true"
    fi

    # Pre-quote all user-controlled strings for YAML safety
    local Q_uuid_reality Q_reality_sni Q_pubkey Q_sid
    local Q_password_hy2 Q_uuid_ws Q_ws_path Q_host Q_ws_sni
    Q_uuid_reality=$(eb_yaml_squote "$uuid_reality")
    Q_reality_sni=$(eb_yaml_squote "$reality_sni")
    Q_pubkey=$(eb_yaml_squote "$pubkey")
    Q_sid=$(eb_yaml_squote "$sid")
    Q_password_hy2=$(eb_yaml_squote "$password_hy2")
    Q_uuid_ws=$(eb_yaml_squote "$uuid_ws")
    Q_ws_path=$(eb_yaml_squote "$ws_path")
    Q_host=$(eb_yaml_squote "$host")

    if [[ "$mode" == "domain" ]]; then
        Q_ws_sni=$(eb_yaml_squote "$host")
    else
        Q_ws_sni=$(eb_yaml_squote "ws.edgebox.internal")
    fi

    cat <<YAML
# EdgeBox Clash / Mihomo subscription
# Generated: $(date -Is)
# Architecture: 3-protocol (Reality + Hysteria2 + WS)

proxies:
  - name: 'EdgeBox-REALITY'
    type: vless
    server: ${Q_host}
    port: 443
    uuid: ${Q_uuid_reality}
    network: tcp
    udp: true
    tls: true
    flow: xtls-rprx-vision
    servername: ${Q_reality_sni}
    client-fingerprint: chrome
    reality-opts:
      public-key: ${Q_pubkey}
      short-id: ${Q_sid}

  - name: 'EdgeBox-HYSTERIA2'
    type: hysteria2
    server: ${Q_host}
    port: 443
    password: ${Q_password_hy2}
    sni: ${Q_host}
    skip-cert-verify: ${insecure_str}
    alpn:
      - h3

  - name: 'EdgeBox-WS'
    type: vless
    server: ${Q_host}
    port: 443
    uuid: ${Q_uuid_ws}
    network: ws
    udp: true
    tls: true
    servername: ${Q_ws_sni}
    skip-cert-verify: ${insecure_str}
    client-fingerprint: chrome
    ws-opts:
      path: ${Q_ws_path}
      headers:
        Host: ${Q_ws_sni}

proxy-groups:
  - name: 'EdgeBox'
    type: select
    proxies:
      - 'EdgeBox-REALITY'
      - 'EdgeBox-HYSTERIA2'
      - 'EdgeBox-WS'
      - DIRECT

  - name: 'EdgeBox-Auto'
    type: url-test
    proxies:
      - 'EdgeBox-REALITY'
      - 'EdgeBox-HYSTERIA2'
      - 'EdgeBox-WS'
    url: 'http://www.gstatic.com/generate_204'
    interval: 300

rules:
  - MATCH,EdgeBox
YAML
}

#############################################
# Format 4: sing-box JSON
#
# Generated via jq -n for safe string embedding.
#############################################
_eb_gen_singbox() {
    local host="$1"
    local mode="$2"

    local uuid_reality reality_sni pubkey sid
    local password_hy2
    local uuid_ws ws_path
    local insecure_bool
    local ws_sni

    uuid_reality=$(eb_get_uuid_reality)
    reality_sni=$(eb_get_reality_sni)
    pubkey=$(eb_get_reality_pubkey)
    sid=$(eb_get_reality_sid)
    password_hy2=$(eb_get_password_hy2)
    uuid_ws=$(eb_get_uuid_ws)
    ws_path=$(eb_get_ws_path)

    if [[ "$mode" == "domain" ]]; then
        insecure_bool="false"
        ws_sni="$host"
    else
        insecure_bool="true"
        ws_sni="ws.edgebox.internal"
    fi

    jq -n \
        --arg host          "$host" \
        --arg uuid_reality  "$uuid_reality" \
        --arg reality_sni   "$reality_sni" \
        --arg pubkey        "$pubkey" \
        --arg sid           "$sid" \
        --arg password_hy2  "$password_hy2" \
        --arg uuid_ws       "$uuid_ws" \
        --arg ws_path       "$ws_path" \
        --arg ws_sni        "$ws_sni" \
        --argjson insecure  "$insecure_bool" \
        '{
            log: { level: "info", timestamp: true },
            dns: {
                servers: [
                    { tag: "google", address: "tls://8.8.8.8" },
                    { tag: "local",  address: "local", detour: "direct" }
                ],
                rules: [
                    { outbound: "any", server: "local" }
                ]
            },
            inbounds: [
                {
                    type: "mixed",
                    tag: "mixed-in",
                    listen: "127.0.0.1",
                    listen_port: 2080,
                    sniff: true
                }
            ],
            outbounds: [
                {
                    type: "selector",
                    tag: "EdgeBox",
                    outbounds: ["EdgeBox-REALITY", "EdgeBox-HYSTERIA2", "EdgeBox-WS", "direct"],
                    default: "EdgeBox-REALITY"
                },
                {
                    type: "vless",
                    tag: "EdgeBox-REALITY",
                    server: $host,
                    server_port: 443,
                    uuid: $uuid_reality,
                    flow: "xtls-rprx-vision",
                    tls: {
                        enabled: true,
                        server_name: $reality_sni,
                        utls: { enabled: true, fingerprint: "chrome" },
                        reality: { enabled: true, public_key: $pubkey, short_id: $sid }
                    }
                },
                {
                    type: "hysteria2",
                    tag: "EdgeBox-HYSTERIA2",
                    server: $host,
                    server_port: 443,
                    password: $password_hy2,
                    tls: {
                        enabled: true,
                        server_name: $host,
                        insecure: $insecure,
                        alpn: ["h3"]
                    }
                },
                {
                    type: "vless",
                    tag: "EdgeBox-WS",
                    server: $host,
                    server_port: 443,
                    uuid: $uuid_ws,
                    tls: {
                        enabled: true,
                        server_name: $ws_sni,
                        insecure: $insecure,
                        utls: { enabled: true, fingerprint: "chrome" },
                        alpn: ["http/1.1"]
                    },
                    transport: {
                        type: "ws",
                        path: $ws_path,
                        headers: { Host: $ws_sni }
                    }
                },
                { type: "direct", tag: "direct" },
                { type: "block",  tag: "block"  },
                { type: "dns",    tag: "dns-out" }
            ],
            route: {
                rules: [
                    { protocol: "dns", outbound: "dns-out" },
                    { ip_is_private: true, outbound: "direct" }
                ],
                final: "EdgeBox",
                auto_detect_interface: true
            }
        }'
}

#############################################
# Web sync
#
# Maintains 4 symlinks in $EB_WEB_ROOT:
#   /sub-<token>            -> subscription.txt
#   /sub-<token>.base64     -> subscription.base64
#   /sub-<token>.clash      -> subscription.clash.yaml
#   /sub-<token>.singbox    -> subscription.singbox.json
#############################################
_eb_sync_web_links() {
    local token="$1"
    if [[ -z "$token" ]]; then
        eb_log_error "master_sub_token missing - cannot create web symlinks"
        return 1
    fi

    mkdir -p "$EB_WEB_ROOT"

    # Defensive: if an older install wrote a regular file at /sub-<token>,
    # remove it before creating the symlink.
    local p
    for p in "${EB_WEB_ROOT}/sub-${token}" \
             "${EB_WEB_ROOT}/sub-${token}.base64" \
             "${EB_WEB_ROOT}/sub-${token}.clash" \
             "${EB_WEB_ROOT}/sub-${token}.singbox"; do
        if [[ -e "$p" && ! -L "$p" ]]; then
            rm -f "$p"
        fi
    done

    ln -sfn "$EB_SUB_PLAIN"   "${EB_WEB_ROOT}/sub-${token}"
    ln -sfn "$EB_SUB_BASE64"  "${EB_WEB_ROOT}/sub-${token}.base64"
    ln -sfn "$EB_SUB_CLASH"   "${EB_WEB_ROOT}/sub-${token}.clash"
    ln -sfn "$EB_SUB_SINGBOX" "${EB_WEB_ROOT}/sub-${token}.singbox"
}

#############################################
# Main entry point
#############################################
eb_gen_subscription() {
    eb_check_tools jq base64 mktemp || return 1

    local server_ip token cert_mode domain
    server_ip=$(eb_get_server_ip)
    token=$(eb_get_master_token)
    cert_mode=$(eb_get_cert_mode)
    domain=$(eb_get_domain)

    if [[ -z "$server_ip" ]]; then
        eb_log_error "server_ip not set in $EB_SERVER_JSON"
        return 1
    fi
    if [[ -z "$token" ]]; then
        eb_log_error "master_sub_token not set in $EB_SERVER_JSON"
        return 1
    fi

    local host mode
    if [[ -n "$domain" ]]; then
        host="$domain"
        mode="domain"
        eb_log_info "Generating subscription in domain mode: $host"
    else
        host="$server_ip"
        mode="ip"
        eb_log_info "Generating subscription in IP mode: $host"
    fi

    # ============================================================
    # CDN mode dispatch (reserved for block 5)
    # ============================================================
    local cdn_enabled
    cdn_enabled=$(eb_jq_get '.cdn.enabled' 'false')
    if [[ "$cdn_enabled" == "true" ]]; then
        eb_log_warn "CDN mode enabled but not implemented yet (block 5)"
        eb_log_warn "Falling back to direct mode generation"
        # In block 5 this becomes: _eb_gen_cdn_subscription && return
    fi

    # ============================================================
    # Generate all 4 formats
    # ============================================================
    local plain base64_str clash_str singbox_str

    plain=$(_eb_gen_plain "$host" "$mode")
    if [[ -z "$plain" ]]; then
        eb_log_error "Failed to generate plain subscription"
        return 1
    fi

    base64_str=$(_eb_gen_base64 "$plain")
    if [[ -z "$base64_str" ]]; then
        eb_log_error "Failed to generate base64 subscription"
        return 1
    fi

    clash_str=$(_eb_gen_clash "$host" "$mode")
    if [[ -z "$clash_str" ]]; then
        eb_log_error "Failed to generate Clash YAML subscription"
        return 1
    fi

    singbox_str=$(_eb_gen_singbox "$host" "$mode")
    if [[ -z "$singbox_str" ]]; then
        eb_log_error "Failed to generate sing-box JSON subscription"
        return 1
    fi

    # ============================================================
    # Validate generated content before publishing
    # ============================================================

    # singbox: must be valid JSON
    if ! printf '%s' "$singbox_str" | jq empty 2>/dev/null; then
        eb_log_error "Generated sing-box JSON is invalid"
        return 1
    fi

    # plain: must contain exactly 3 URI lines
    local line_count
    line_count=$(printf '%s' "$plain" | grep -c '^[a-z]')
    if [[ "$line_count" -ne 3 ]]; then
        eb_log_error "Plain subscription has $line_count protocols, expected 3"
        return 1
    fi

    # ============================================================
    # Atomic publish: all 4 files at once, or none
    # ============================================================
    declare -A files_to_write=(
        ["$EB_SUB_PLAIN"]="$plain"
        ["$EB_SUB_BASE64"]="$base64_str"
        ["$EB_SUB_CLASH"]="$clash_str"
        ["$EB_SUB_SINGBOX"]="$singbox_str"
    )

    if ! eb_atomic_write_set files_to_write; then
        eb_log_error "Atomic publish failed; no subscription files were updated"
        return 1
    fi

    # ============================================================
    # Update web symlinks
    # ============================================================
    if ! _eb_sync_web_links "$token"; then
        eb_log_error "Subscription files were published but web symlinks failed"
        return 1
    fi

    eb_log_success "Subscription updated (3 protocols, 4 formats)"
    eb_log_info "  plain:   ${EB_WEB_ROOT}/sub-${token}"
    eb_log_info "  base64:  ${EB_WEB_ROOT}/sub-${token}.base64"
    eb_log_info "  clash:   ${EB_WEB_ROOT}/sub-${token}.clash"
    eb_log_info "  singbox: ${EB_WEB_ROOT}/sub-${token}.singbox"

    return 0
}

# CLI entry point
if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
    eb_gen_subscription
    exit $?
fi
