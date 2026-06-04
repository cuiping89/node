#!/usr/bin/env bash
#############################################
# EdgeBox - Alert Sender Library (alert.sh)
# Version: v4.1.0 (block 2)
#
# Purpose:
#   Shared notification function used by:
#     - traffic-alert.sh   (monthly traffic threshold alerts)
#     - protocol-alert.sh  (protocol up/down state alerts)
#     - any future alerting code
#
# Channels: Telegram, Discord, PushPlus, Webhook, Email
# Config file: /etc/edgebox/traffic/alert.conf
#
# Provides:
#   eb_alert_send "<title>" "<body>" [severity]
#     severity = info | warning | critical (defaults to "warning")
#     Reads channel config from alert.conf, sends to all configured channels.
#     Always logs to /var/log/edgebox/alerts.log.
#
#   eb_alert_is_silenced
#     Returns 0 if alerts are currently silenced (returns 1 otherwise).
#     Silencing is via touching /etc/edgebox/traffic/alert.silenced_until with
#     a unix timestamp inside.
#############################################

[[ -n "${EDGEBOX_ALERT_SH_LOADED:-}" ]] && return 0
EDGEBOX_ALERT_SH_LOADED=1

# Required by common.sh, which provides logging helpers and EB_* paths
if [[ -z "${EDGEBOX_COMMON_SH_LOADED:-}" ]]; then
    # Try to source common.sh from typical locations
    for _try in \
        "$(dirname "${BASH_SOURCE[0]}")/common.sh" \
        "/etc/edgebox/scripts/lib/common.sh"; do
        if [[ -f "$_try" ]]; then
            # shellcheck disable=SC1090
            source "$_try"
            break
        fi
    done
fi

# v4.6.0-rc1: 机密文件搬到 /etc/edgebox/config/ (root:root 600)
# 公共阈值在 /etc/edgebox/traffic/alert-public.json (web-readable)
# 注: lib/alert.sh 总是被 root 调用（cron 或 edgeboxctl），所以能读 600
EB_ALERT_CONF="${EB_ALERT_CONF:-${EB_CONFIG_DIR:-/etc/edgebox/config}/alert.env}"
EB_ALERT_PUBLIC_JSON="${EB_ALERT_PUBLIC_JSON:-${EB_TRAFFIC_DIR:-/etc/edgebox/traffic}/alert-public.json}"
EB_ALERT_LOG="${EB_ALERT_LOG:-/var/log/edgebox/alerts.log}"
EB_ALERT_SILENCE_FILE="${EB_ALERT_SILENCE_FILE:-${EB_TRAFFIC_DIR:-/etc/edgebox/traffic}/alert.silenced_until}"

# Ensure log dir exists; ignore failure (will be retried later)
mkdir -p "$(dirname "$EB_ALERT_LOG")" 2>/dev/null || true

# Internal: log an event to the alert log (always succeeds)
_eb_alert_log() {
    local msg="$1"
    echo "[$(date -Is)] $msg" >> "$EB_ALERT_LOG" 2>/dev/null || true
}

# Check if alerts are silenced.
# Returns 0 if silenced (caller should skip sending), 1 otherwise.
eb_alert_is_silenced() {
    [[ -f "$EB_ALERT_SILENCE_FILE" ]] || return 1
    local until_ts now
    until_ts=$(cat "$EB_ALERT_SILENCE_FILE" 2>/dev/null)
    [[ "$until_ts" =~ ^[0-9]+$ ]] || return 1
    now=$(date +%s)
    if (( now < until_ts )); then
        return 0  # still silenced
    else
        # Silence expired; remove the file
        rm -f "$EB_ALERT_SILENCE_FILE"
        return 1
    fi
}

# Silence alerts for N hours.
# Usage: eb_alert_silence 4   # silence for 4 hours
eb_alert_silence() {
    local hours="${1:-1}"
    [[ "$hours" =~ ^[0-9]+$ ]] || {
        echo "Invalid hours: $hours" >&2
        return 1
    }
    local until_ts
    until_ts=$(( $(date +%s) + hours * 3600 ))
    mkdir -p "$(dirname "$EB_ALERT_SILENCE_FILE")" 2>/dev/null || true
    echo "$until_ts" > "$EB_ALERT_SILENCE_FILE"
    _eb_alert_log "Alerts silenced until $(date -d "@$until_ts" -Is 2>/dev/null || echo "$until_ts")"
}

# Unsilence (clear the silence file)
eb_alert_unsilence() {
    rm -f "$EB_ALERT_SILENCE_FILE"
    _eb_alert_log "Alerts unsilenced"
}

# Send an alert via all configured channels.
#
# Usage: eb_alert_send "<title>" "<body>" [severity]
#   severity is just a label included in the message; defaults to "warning"
#
# Returns 0 always (failures are logged but don't propagate, since alerting
# failures should never crash the caller).
eb_alert_send() {
    local title="$1"
    local body="$2"
    local severity="${3:-warning}"

    # Compose full message
    local timestamp full_msg hostname
    timestamp=$(date -Is)
    hostname=$(hostname 2>/dev/null || echo "unknown")
    full_msg="[${severity^^}] EdgeBox @${hostname}
${title}

${body}

时间: ${timestamp}"

    # Always log locally (this is the "panel-visible" channel)
    _eb_alert_log "=== ALERT [${severity}] ${title} ==="
    while IFS= read -r line; do
        _eb_alert_log "  | $line"
    done <<< "$body"

    # Check silencing
    if eb_alert_is_silenced; then
        _eb_alert_log "(silenced - not sending to external channels)"
        return 0
    fi

    # Load channel config
    if [[ ! -r "$EB_ALERT_CONF" ]]; then
        _eb_alert_log "alert.conf not readable; only local log used"
        return 0
    fi

    # shellcheck disable=SC1090
    source "$EB_ALERT_CONF" 2>/dev/null || true

    # --- Telegram ---
    if [[ -n "${ALERT_TG_BOT_TOKEN:-}" && -n "${ALERT_TG_CHAT_ID:-}" ]]; then
        local tg_url tg_payload
        tg_url="https://api.telegram.org/bot${ALERT_TG_BOT_TOKEN}/sendMessage"
        tg_payload=$(jq -n --arg chat "${ALERT_TG_CHAT_ID}" --arg text "$full_msg" \
            '{chat_id: $chat, text: $text}' 2>/dev/null)
        if [[ -n "$tg_payload" ]]; then
            env -u ALL_PROXY -u HTTP_PROXY -u HTTPS_PROXY -u http_proxy -u https_proxy \
                curl -m 10 -sS -X POST -H 'Content-Type: application/json' \
                -d "$tg_payload" "$tg_url" >>"$EB_ALERT_LOG" 2>&1 || true
            _eb_alert_log "  -> sent via Telegram"
        fi
    fi

    # --- Discord ---
    if [[ -n "${ALERT_DISCORD_WEBHOOK:-}" ]]; then
        local discord_payload
        discord_payload=$(jq -n --arg content "$full_msg" \
            '{content: $content}' 2>/dev/null)
        if [[ -n "$discord_payload" ]]; then
            env -u ALL_PROXY -u HTTP_PROXY -u HTTPS_PROXY -u http_proxy -u https_proxy \
                curl -m 10 -sS -X POST -H 'Content-Type: application/json' \
                -d "$discord_payload" "$ALERT_DISCORD_WEBHOOK" >>"$EB_ALERT_LOG" 2>&1 || true
            _eb_alert_log "  -> sent via Discord"
        fi
    fi

    # --- PushPlus (WeChat) ---
    if [[ -n "${ALERT_PUSHPLUS_TOKEN:-}" ]]; then
        local pp_payload
        pp_payload=$(jq -n --arg token "${ALERT_PUSHPLUS_TOKEN}" \
            --arg title "$title" --arg content "$full_msg" \
            '{token: $token, title: $title, content: $content, template: "txt"}' 2>/dev/null)
        if [[ -n "$pp_payload" ]]; then
            env -u ALL_PROXY -u HTTP_PROXY -u HTTPS_PROXY -u http_proxy -u https_proxy \
                curl -m 10 -sS -X POST -H 'Content-Type: application/json' \
                -d "$pp_payload" "http://www.pushplus.plus/send" >>"$EB_ALERT_LOG" 2>&1 || true
            _eb_alert_log "  -> sent via PushPlus"
        fi
    fi

    # --- Generic webhook ---
    if [[ -n "${ALERT_WEBHOOK:-}" ]]; then
        local wh_format="${ALERT_WEBHOOK_FORMAT:-raw}"
        local wh_payload
        case "$wh_format" in
            slack)
                wh_payload=$(jq -n --arg text "$full_msg" '{text: $text}' 2>/dev/null)
                ;;
            discord)
                wh_payload=$(jq -n --arg content "$full_msg" '{content: $content}' 2>/dev/null)
                ;;
            *)
                # raw: simple {title,body,severity,timestamp,host}
                wh_payload=$(jq -n \
                    --arg title "$title" --arg body "$body" \
                    --arg severity "$severity" --arg ts "$timestamp" \
                    --arg host "$hostname" \
                    '{title:$title, body:$body, severity:$severity, timestamp:$ts, host:$host}' \
                    2>/dev/null)
                ;;
        esac
        if [[ -n "$wh_payload" ]]; then
            env -u ALL_PROXY -u HTTP_PROXY -u HTTPS_PROXY -u http_proxy -u https_proxy \
                curl -m 10 -sS -X POST -H 'Content-Type: application/json' \
                -d "$wh_payload" "$ALERT_WEBHOOK" >>"$EB_ALERT_LOG" 2>&1 || true
            _eb_alert_log "  -> sent via webhook ($wh_format)"
        fi
    fi

    # --- Email ---
    if [[ -n "${ALERT_EMAIL:-}" ]] && command -v mail >/dev/null 2>&1; then
        echo "$full_msg" | mail -s "[EdgeBox/${severity}] $title" "$ALERT_EMAIL" 2>>"$EB_ALERT_LOG" || true
        _eb_alert_log "  -> sent via email"
    fi

    return 0
}

# CLI entry (for testing): bash alert.sh test
if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
    case "${1:-}" in
        test)
            eb_alert_send "Test Alert" "This is a test message from EdgeBox alert library." "info"
            echo "Test alert sent. Check $EB_ALERT_LOG for details."
            ;;
        silence)
            eb_alert_silence "${2:-1}"
            echo "Alerts silenced for ${2:-1} hour(s)."
            ;;
        unsilence)
            eb_alert_unsilence
            echo "Alerts unsilenced."
            ;;
        status)
            if eb_alert_is_silenced; then
                local ts; ts=$(cat "$EB_ALERT_SILENCE_FILE")
                echo "Alerts SILENCED until $(date -d "@$ts")"
            else
                echo "Alerts ACTIVE"
            fi
            ;;
        *)
            echo "Usage: bash alert.sh {test|silence <hours>|unsilence|status}"
            exit 1
            ;;
    esac
fi
