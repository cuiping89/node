#!/usr/bin/env bash
# EdgeBox - Monthly Traffic Alert (v4.6.0-rc1)
# - Thresholds from /etc/edgebox/traffic/alert-public.json (web-readable)
# - Channel secrets from /etc/edgebox/config/alert.env (root:root 600, via lib/alert.sh)

set +e
set +u

SCRIPTS_DIR="${SCRIPTS_DIR:-/etc/edgebox/scripts}"
TRAFFIC_DIR="/etc/edgebox/traffic"
CONFIG_DIR="/etc/edgebox/config"
LOG_DIR="$TRAFFIC_DIR/logs"
PUBLIC_CONF="$TRAFFIC_DIR/alert-public.json"
STATE="$TRAFFIC_DIR/alert.state"
LOG="/var/log/edgebox-traffic-alert.log"

mkdir -p "$(dirname "$LOG")" 2>/dev/null || true

# Source the shared alert library (which loads secrets from /etc/edgebox/config/alert.env)
if [[ -f "${SCRIPTS_DIR}/lib/alert.sh" ]]; then
    # shellcheck source=/dev/null
    source "${SCRIPTS_DIR}/lib/alert.sh"
else
    echo "[$(date -Is)] [ERROR] ${SCRIPTS_DIR}/lib/alert.sh not found" >> "$LOG"
    eb_alert_send() { echo "[$(date -Is)] [LOCAL-ONLY] $1: $2" >> "$LOG"; }
fi

# Read thresholds from public JSON
ALERT_MONTHLY_GIB=100
ALERT_STEPS="30,60,90"
if [[ -r "$PUBLIC_CONF" ]] && command -v jq >/dev/null 2>&1; then
    _mg=$(jq -r '.monthly_gib // 100' "$PUBLIC_CONF" 2>/dev/null)
    [[ "$_mg" =~ ^[0-9]+$ ]] && ALERT_MONTHLY_GIB="$_mg"

    _steps=$(jq -r '.steps // [30,60,90] | join(",")' "$PUBLIC_CONF" 2>/dev/null)
    [[ "$_steps" =~ ^[0-9]+(,[0-9]+)*$ ]] && ALERT_STEPS="$_steps"
fi

month="$(date +%Y-%m)"
row="$(grep "^${month}," "$LOG_DIR/monthly.csv" 2>/dev/null || true)"
if [[ -z "$row" ]]; then
    echo "[$(date -Is)] [INFO] No traffic data for current month yet." >> "$LOG"
    exit 0
fi

# CSV: month,vps,resi,total,tx,rx
IFS=',' read -r _ vps resi total tx rx <<<"$row"
budget_bytes=$(( ALERT_MONTHLY_GIB * 1024 * 1024 * 1024 ))
used=$total

if [[ $budget_bytes -eq 0 ]]; then
    echo "[$(date -Is)] [WARN] Monthly budget is 0, cannot calculate percentage." >> "$LOG"
    exit 0
fi

pct=$(( used * 100 / budget_bytes ))

sent=""
[[ -f "$STATE" ]] && sent="$(cat "$STATE")"

parse_steps() {
    IFS=',' read -ra a <<<"$ALERT_STEPS"
    for s in "${a[@]}"; do echo "$s"; done
}

new_sent="$sent"
for s in $(parse_steps); do
    # Threshold reached and not yet alerted
    if [[ "$pct" -ge "$s" ]] && ! grep -qE "(^|,)${s}(,|$)" <<<",${sent},"; then
        human_used="$(awk -v b="$used" 'BEGIN{printf "%.2f GiB", b/1024/1024/1024}')"
        human_budget="$(awk -v b="$budget_bytes" 'BEGIN{printf "%.0f GiB", b/1024/1024/1024}')"

        # Severity escalates with threshold
        severity="info"
        [[ "$s" -ge 60 ]] && severity="warning"
        [[ "$s" -ge 90 ]] && severity="critical"

        eb_alert_send \
            "流量预警: ${s}% 阈值" \
            "本月用量 ${human_used}（${pct}% / 预算 ${human_budget}），触达 ${s}% 阈值。" \
            "$severity"

        new_sent="${new_sent:+${new_sent},}${s}"
    fi
done
echo "$new_sent" > "$STATE"
