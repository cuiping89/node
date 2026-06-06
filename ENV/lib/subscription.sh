#!/usr/bin/env bash
#############################################
# EdgeBox - Subscription Generator (subscription.sh)
# Version: v4.7.0
#
# Architecture: 2-protocol dual-layer (direct only)
#   Layer 1: VLESS-Reality   (TCP/443, primary daily use, anti-censorship)
#   Layer 2: Hysteria2       (UDP/443, fallback when TCP is interfered)
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
#   - Domain mode (cert_mode = "letsencrypt:<domain>"):
#       * Reality: <domain>:443, SNI = real public domain (unchanged)
#       * Hysteria2: <domain>:443, real TLS
#
# NOTE: WS transport and CDN relay mode were removed in v4.7.0. Both protocols
# are direct-connect by design; there is no CDN fronting in this build.
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

    # v4.7.0 (审计 H-2): Salamander obfs —— 两端口令必须一致
    local obfs_pw obfs_q=""
    obfs_pw=$(eb_get_hy2_obfs)
    if [[ -n "$obfs_pw" ]]; then
        obfs_q="&obfs=salamander&obfs-password=$(eb_url_encode "$obfs_pw")"
    fi

    if [[ "$mode" == "domain" ]]; then
        printf 'hysteria2://%s@%s:443/?sni=%s&alpn=h3%s#EdgeBox-HYSTERIA2\n' \
            "$pw_enc" "$host" "$host" "$obfs_q"
    else
        printf 'hysteria2://%s@%s:443/?sni=%s&alpn=h3&insecure=1%s#EdgeBox-HYSTERIA2\n' \
            "$pw_enc" "$host" "$host" "$obfs_q"
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
    local insecure_str

    uuid_reality=$(eb_get_uuid_reality)
    reality_sni=$(eb_get_reality_sni)
    pubkey=$(eb_get_reality_pubkey)
    sid=$(eb_get_reality_sid)
    password_hy2=$(eb_get_password_hy2)

    if [[ "$mode" == "domain" ]]; then
        insecure_str="false"
    else
        insecure_str="true"
    fi

    # Pre-quote all user-controlled strings for YAML safety
    local Q_uuid_reality Q_reality_sni Q_pubkey Q_sid
    local Q_password_hy2 Q_host
    Q_uuid_reality=$(eb_yaml_squote "$uuid_reality")
    Q_reality_sni=$(eb_yaml_squote "$reality_sni")
    Q_pubkey=$(eb_yaml_squote "$pubkey")
    Q_sid=$(eb_yaml_squote "$sid")
    Q_password_hy2=$(eb_yaml_squote "$password_hy2")
    Q_host=$(eb_yaml_squote "$host")

    # v4.7.0 (审计 H-2): Salamander obfs（两端口令必须一致）
    local obfs_pw Q_obfs_pw hy2_obfs_yaml=""
    obfs_pw=$(eb_get_hy2_obfs)
    if [[ -n "$obfs_pw" ]]; then
        Q_obfs_pw=$(eb_yaml_squote "$obfs_pw")
        hy2_obfs_yaml="    obfs: salamander
    obfs-password: ${Q_obfs_pw}"
    fi

    cat <<YAML
# EdgeBox Clash / Mihomo subscription
# Generated: $(date -Is)
# Architecture: 2-protocol (Reality + Hysteria2)

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
${hy2_obfs_yaml}
    sni: ${Q_host}
    skip-cert-verify: ${insecure_str}
    alpn:
      - h3

proxy-groups:
  - name: 'EdgeBox'
    type: select
    proxies:
      - 'EdgeBox-REALITY'
      - 'EdgeBox-HYSTERIA2'
      - DIRECT

  - name: 'EdgeBox-Auto'
    type: url-test
    proxies:
      - 'EdgeBox-REALITY'
      - 'EdgeBox-HYSTERIA2'
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
    local insecure_bool

    uuid_reality=$(eb_get_uuid_reality)
    reality_sni=$(eb_get_reality_sni)
    pubkey=$(eb_get_reality_pubkey)
    sid=$(eb_get_reality_sid)
    password_hy2=$(eb_get_password_hy2)

    if [[ "$mode" == "domain" ]]; then
        insecure_bool="false"
    else
        insecure_bool="true"
    fi

    jq -n \
        --arg host          "$host" \
        --arg uuid_reality  "$uuid_reality" \
        --arg reality_sni   "$reality_sni" \
        --arg pubkey        "$pubkey" \
        --arg sid           "$sid" \
        --arg password_hy2  "$password_hy2" \
        --arg obfs_pw       "$(eb_get_hy2_obfs)" \
        --argjson insecure  "$insecure_bool" \
        '{
            log: { level: "warn", timestamp: true },
            dns: {
                servers: [
                    { tag: "proxy-dns", address: "tls://8.8.8.8", detour: "EdgeBox" },
                    { tag: "direct-dns", address: "local", detour: "direct" }
                ],
                rules: [
                    { domain: [$host], server: "direct-dns" }
                ],
                final: "proxy-dns",
                strategy: "prefer_ipv4"
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
                    outbounds: ["EdgeBox-REALITY", "EdgeBox-HYSTERIA2", "direct"],
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
                { type: "direct", tag: "direct" }
            ],
            route: {
                rules: [
                    { protocol: "dns", action: "hijack-dns" },
                    { ip_is_private: true, outbound: "direct" }
                ],
                final: "EdgeBox",
                auto_detect_interface: true
            }
        }
        | (.outbounds |= map(
              if (.tag == "EdgeBox-HYSTERIA2" and ($obfs_pw | length) > 0)
              then . + { obfs: { type: "salamander", password: $obfs_pw } }
              else . end
          ))'
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

    # v4.7.0 (审计): 清理不属于当前 token 的旧 sub-* 残留。
    #   旧实现只建当前 token 的软链、从不删旧的，而所有 token 软链都指向同一份订阅文件，
    #   导致历史上每个 token（重装/轮换前的）都长期有效、无法吊销。这里把非当前 token 的
    #   sub-* 一律删除，使"换 token"能真正吊销旧链接。只动 sub-* 形态，其它文件不碰。
    #   token 为 hex（openssl rand -hex 16），无 glob 元字符，-name 匹配安全。
    find "${EB_WEB_ROOT}" -maxdepth 1 -name 'sub-*' \
         ! -name "sub-${token}" \
         ! -name "sub-${token}.base64" \
         ! -name "sub-${token}.clash" \
         ! -name "sub-${token}.singbox" \
         -exec rm -f {} + 2>/dev/null || true
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
    else
        host="$server_ip"
        mode="ip"
    fi

    local plain base64_str clash_str singbox_str

    if [[ "$mode" == "domain" ]]; then
        eb_log_info "Generating subscription in domain mode: $host"
    else
        eb_log_info "Generating subscription in IP mode: $host"
    fi

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

    # plain: must contain the expected number of URI lines (2 protocols)
    local line_count expected_count
    line_count=$(printf '%s' "$plain" | grep -c '^[a-z]')
    expected_count=2
    if [[ "$line_count" -ne "$expected_count" ]]; then
        eb_log_error "Plain subscription has $line_count protocols, expected $expected_count"
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

    eb_log_success "Subscription updated (2 protocols: Reality + Hysteria2, 4 formats)"
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
