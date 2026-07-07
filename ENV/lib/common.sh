#!/usr/bin/env bash
#############################################
# EdgeBox - Shared Library (common.sh)
# Version: v4.0.0
#
# Purpose: Path constants, logging, jq helpers, atomic writes.
# All new modules (subscription.sh, monitor.sh, cron.sh, etc.)
# source this file as their first action.
#
# This file is idempotent: sourcing it multiple times is safe.
#############################################

# Guard against double-sourcing
[[ -n "${EDGEBOX_COMMON_SH_LOADED:-}" ]] && return 0
EDGEBOX_COMMON_SH_LOADED=1

set -o pipefail

#############################################
# Path Constants
#
# These can be overridden by environment variables for testing.
# In production, they default to the standard EdgeBox locations.
#############################################

# Core directory structure (unchanged from v3.x to preserve compatibility)
: "${EB_INSTALL_DIR:=/etc/edgebox}"
: "${EB_CONFIG_DIR:=${EB_INSTALL_DIR}/config}"
: "${EB_CERT_DIR:=${EB_INSTALL_DIR}/cert}"
: "${EB_TRAFFIC_DIR:=${EB_INSTALL_DIR}/traffic}"
: "${EB_SCRIPTS_DIR:=${EB_INSTALL_DIR}/scripts}"
: "${EB_TEMPLATES_DIR:=${EB_INSTALL_DIR}/templates}"
: "${EB_BACKUP_DIR:=/root/edgebox-backup}"

# Configuration files
: "${EB_SERVER_JSON:=${EB_CONFIG_DIR}/server.json}"
: "${EB_XRAY_JSON:=${EB_CONFIG_DIR}/xray.json}"
: "${EB_SINGBOX_JSON:=${EB_CONFIG_DIR}/sing-box.json}"
: "${EB_CERT_MODE_FILE:=${EB_CONFIG_DIR}/cert_mode}"

# Web root
: "${EB_WEB_ROOT:=/var/www/html}"

# Subscription output files (4 formats, written atomically as a set)
: "${EB_SUB_PLAIN:=${EB_CONFIG_DIR}/subscription.txt}"
: "${EB_SUB_BASE64:=${EB_CONFIG_DIR}/subscription.base64}"
: "${EB_SUB_CLASH:=${EB_CONFIG_DIR}/subscription.clash.yaml}"
: "${EB_SUB_SINGBOX:=${EB_CONFIG_DIR}/subscription.singbox.json}"

# Log files
: "${EB_LOG_FILE:=/var/log/edgebox-install.log}"

# Version
readonly EB_VERSION="v4.7.0"

#############################################
# Logging
#############################################

if [[ -t 1 ]]; then
    readonly EB_RED=$'\033[0;31m'
    readonly EB_GREEN=$'\033[0;32m'
    readonly EB_YELLOW=$'\033[0;33m'
    readonly EB_BLUE=$'\033[0;34m'
    readonly EB_CYAN=$'\033[0;36m'
    readonly EB_NC=$'\033[0m'
else
    readonly EB_RED=""
    readonly EB_GREEN=""
    readonly EB_YELLOW=""
    readonly EB_BLUE=""
    readonly EB_CYAN=""
    readonly EB_NC=""
fi

eb_log_info() {
    local msg="[$(date '+%F %T')] [INFO] $*"
    echo "${EB_GREEN}${msg}${EB_NC}" >&2
    [[ -w "$(dirname "$EB_LOG_FILE")" ]] 2>/dev/null && echo "$msg" >> "$EB_LOG_FILE" 2>/dev/null || true
}

eb_log_warn() {
    local msg="[$(date '+%F %T')] [WARN] $*"
    echo "${EB_YELLOW}${msg}${EB_NC}" >&2
    [[ -w "$(dirname "$EB_LOG_FILE")" ]] 2>/dev/null && echo "$msg" >> "$EB_LOG_FILE" 2>/dev/null || true
}

eb_log_error() {
    local msg="[$(date '+%F %T')] [ERROR] $*"
    echo "${EB_RED}${msg}${EB_NC}" >&2
    [[ -w "$(dirname "$EB_LOG_FILE")" ]] 2>/dev/null && echo "$msg" >> "$EB_LOG_FILE" 2>/dev/null || true
}

eb_log_success() {
    local msg="[$(date '+%F %T')] [OK] $*"
    echo "${EB_GREEN}${msg}${EB_NC}" >&2
    [[ -w "$(dirname "$EB_LOG_FILE")" ]] 2>/dev/null && echo "$msg" >> "$EB_LOG_FILE" 2>/dev/null || true
}

eb_log_debug() {
    [[ "${EB_LOG_LEVEL:-info}" == "debug" ]] || return 0
    local msg="[$(date '+%F %T')] [DEBUG] $*"
    echo "${EB_CYAN}${msg}${EB_NC}" >&2
    [[ -w "$(dirname "$EB_LOG_FILE")" ]] 2>/dev/null && echo "$msg" >> "$EB_LOG_FILE" 2>/dev/null || true
}

#############################################
# jq Helpers
#############################################

# Read a single field from server.json (or any json) with a default value.
# Usage: eb_jq_get '.uuid.vless.reality' '' [/path/to/file.json]
eb_jq_get() {
    local query="$1"
    local default="${2:-}"
    local file="${3:-$EB_SERVER_JSON}"

    if [[ ! -f "$file" ]]; then
        echo "$default"
        return 1
    fi

    local result
    result=$(jq -r "${query} // empty" "$file" 2>/dev/null) || {
        echo "$default"
        return 1
    }

    if [[ -z "$result" || "$result" == "null" ]]; then
        echo "$default"
        return 0
    fi

    echo "$result"
    return 0
}

# URL-encode a string using jq's @uri filter.
# Safer than hand-rolled bash url_encode for arbitrary password characters.
eb_url_encode() {
    printf '%s' "$1" | jq -sRr @uri
}

# Single-quote a string for safe YAML inclusion.
# YAML single-quoted scalars only need ' doubled to '', no escape sequences.
# This is the safest way to embed arbitrary strings (passwords with :, #, !, etc.)
# Usage: safe=$(eb_yaml_squote "$raw_value")  → outputs 'value' with quotes
eb_yaml_squote() {
    local s="$1"
    printf "'%s'" "${s//\'/\'\'}"
}

#############################################
# Atomic write helpers
#############################################

# Write content to a file atomically (write to .tmp, then mv).
# Usage:  printf '%s' "$content" | eb_atomic_write /path/to/target [mode]
eb_atomic_write() {
    local target="$1"
    local mode="${2:-0644}"
    local tmp

    tmp=$(mktemp "${target}.XXXXXX") || {
        eb_log_error "atomic_write: mktemp failed for $target"
        return 1
    }

    if ! cat > "$tmp"; then
        eb_log_error "atomic_write: write to tmp failed for $target"
        rm -f "$tmp"
        return 1
    fi

    chmod "$mode" "$tmp" 2>/dev/null || true

    if ! mv -f "$tmp" "$target"; then
        eb_log_error "atomic_write: mv failed for $target"
        rm -f "$tmp"
        return 1
    fi

    return 0
}

# Publish a set of files as a unit. All files are first written to temp files;
# only if every temp write succeeds are they moved into place. If any mv in the
# publish phase fails, already-published files are rolled back from snapshots,
# so callers observe either the full new set or the original set (best-effort
# transactional — true 2-phase commit across independent files is not possible
# in shell, but partial states are repaired rather than left behind).
#
# Usage:
#   declare -A files=(
#     ["/path/to/a.txt"]="content for a"
#     ["/path/to/b.json"]="content for b"
#   )
#   eb_atomic_write_set files
eb_atomic_write_set() {
    local -n _files_ref="$1"
    local -a tmp_files=()
    local -a target_files=()
    local target tmp content rc=0

    # Phase 1: write all to .tmp
    for target in "${!_files_ref[@]}"; do
        content="${_files_ref[$target]}"
        tmp=$(mktemp "${target}.XXXXXX") || {
            eb_log_error "atomic_write_set: mktemp failed for $target"
            rc=1
            break
        }
        # v4.6.0-rc4: 保证文件以单个 \n 结尾
        # 修复 $(...) 命令替换吞掉 trailing newline 导致最后一行被 `while read` 丢弃的问题
        # 现象: subscription.txt 最后一行没换行符 → dashboard-backend 的 while read 跳过它
        # 做法: 先剥掉所有 trailing newline，再用 '%s\n' 加回单个换行符
        # 对二进制内容（不该被这函数处理）以及空内容都安全
        if ! printf '%s\n' "${content%$'\n'}" > "$tmp"; then
            eb_log_error "atomic_write_set: write failed for $target"
            rm -f "$tmp"
            rc=1
            break
        fi
        chmod 0644 "$tmp" 2>/dev/null || true
        tmp_files+=("$tmp")
        target_files+=("$target")
    done

    # Phase 2: snapshot existing targets, then mv each temp into place.
    # If any mv fails, roll the already-moved targets back from their snapshots
    # so the whole set is all-or-none rather than a mix of new and old.
    if [[ $rc -eq 0 ]]; then
        local i
        local -a moved_idx=()
        local -a backups=()

        # 2a. snapshot every target that currently exists
        for i in "${!target_files[@]}"; do
            if [[ -e "${target_files[$i]}" ]]; then
                local bk
                bk=$(mktemp "${target_files[$i]}.bak.XXXXXX") || { eb_log_error "atomic_write_set: snapshot mktemp failed for ${target_files[$i]}"; rc=1; break; }
                if ! cp -p "${target_files[$i]}" "$bk"; then
                    eb_log_error "atomic_write_set: snapshot copy failed for ${target_files[$i]}"
                    rm -f "$bk"; rc=1; break
                fi
                backups[$i]="$bk"
            else
                backups[$i]=""
            fi
        done

        # 2b. publish
        if [[ $rc -eq 0 ]]; then
            for i in "${!tmp_files[@]}"; do
                if mv -f "${tmp_files[$i]}" "${target_files[$i]}"; then
                    moved_idx+=("$i")
                else
                    eb_log_error "atomic_write_set: mv failed for ${target_files[$i]}，回滚本次发布"
                    rc=1
                    break
                fi
            done
        fi

        # 2c. rollback already-moved targets on any failure
        if [[ $rc -ne 0 ]]; then
            local j
            for j in "${moved_idx[@]}"; do
                if [[ -n "${backups[$j]:-}" ]]; then
                    mv -f "${backups[$j]}" "${target_files[$j]}" 2>/dev/null || true
                else
                    rm -f "${target_files[$j]}" 2>/dev/null || true   # target didn't exist before
                fi
            done
        fi

        # 2d. clean up any remaining snapshots
        for i in "${!backups[@]}"; do
            [[ -n "${backups[$i]:-}" && -f "${backups[$i]}" ]] && rm -f "${backups[$i]}"
        done
    fi

    # Cleanup any leftover .tmp files on failure
    if [[ $rc -ne 0 ]]; then
        local f
        for f in "${tmp_files[@]}"; do
            [[ -f "$f" ]] && rm -f "$f"
        done
    fi

    return $rc
}

#############################################
# Server.json convenience accessors
#############################################

eb_get_server_ip()       { eb_jq_get '.server_ip'              ''; }
eb_get_master_token()    { eb_jq_get '.master_sub_token'       ''; }

eb_get_cert_mode()       {
    if [[ -f "$EB_CERT_MODE_FILE" ]]; then
        cat "$EB_CERT_MODE_FILE"
    else
        echo "self-signed"
    fi
}

eb_get_domain()          {
    local mode
    mode=$(eb_get_cert_mode)
    if [[ "$mode" == letsencrypt:* ]]; then
        echo "${mode#letsencrypt:}"
    else
        echo ""
    fi
}

# Reality
eb_get_uuid_reality()    { eb_jq_get '.uuid.vless.reality'     ''; }
eb_get_reality_pubkey()  { eb_jq_get '.reality.public_key'     ''; }
eb_get_reality_sid()     { eb_jq_get '.reality.short_id'       ''; }

eb_get_reality_sni()     {
    local sni=""
    if [[ -f "$EB_XRAY_JSON" ]]; then
        sni=$(jq -r '
            first(.inbounds[]? | select(.tag=="vless-reality") | .streamSettings.realitySettings.serverNames[0])
            // (first(.inbounds[]? | select(.tag=="vless-reality") | .streamSettings.realitySettings.dest) | split(":")[0])
            // empty
        ' "$EB_XRAY_JSON" 2>/dev/null)
    fi
    echo "${sni:-www.cloudflare.com}"
}

# Hysteria2
eb_get_password_hy2()    { eb_jq_get '.password.hysteria2'     ''; }

#############################################
# Validation helpers
#############################################

eb_check_tools() {
    local missing=()
    local tool
    for tool in "$@"; do
        command -v "$tool" >/dev/null 2>&1 || missing+=("$tool")
    done
    if [[ ${#missing[@]} -gt 0 ]]; then
        eb_log_error "Missing required tools: ${missing[*]}"
        return 1
    fi
    return 0
}

eb_is_valid_domain() {
    local d="$1"
    [[ -n "$d" ]] && [[ "$d" =~ ^[A-Za-z0-9]([A-Za-z0-9-]*[A-Za-z0-9])?(\.[A-Za-z0-9]([A-Za-z0-9-]*[A-Za-z0-9])?)+$ ]]
}

eb_is_valid_ipv4() {
    local ip="$1"
    [[ "$ip" =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}$ ]] || return 1
    local IFS=.
    local -a octets=($ip)
    local o
    for o in "${octets[@]}"; do
        [[ "$o" -le 255 ]] || return 1
    done
    return 0
}

# Generate a random alphanumeric string (lowercase + digits).
# Usage: eb_random_string [length]   (default length 8)
eb_random_string() {
    local len="${1:-8}"
    tr -dc 'a-z0-9' < /dev/urandom | head -c "$len"
}
