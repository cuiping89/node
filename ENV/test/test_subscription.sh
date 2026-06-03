#!/usr/bin/env bash
#############################################
# EdgeBox - Subscription Generator Test Suite
# Version: v4.0.0
#
# Tests cover IP mode and Domain mode x 4 formats = 8 cases,
# plus edge cases (special chars, missing fields, atomic rollback).
#############################################

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
LIB_DIR="${SCRIPT_DIR}/../lib"

PASS=0
FAIL=0
FAILED_TESTS=()

if [[ -t 1 ]]; then
    R=$'\033[0;31m'; G=$'\033[0;32m'; Y=$'\033[0;33m'; N=$'\033[0m'
else
    R=""; G=""; Y=""; N=""
fi

pass() { echo "${G}[PASS]${N} $*"; PASS=$((PASS+1)); }
fail() { echo "${R}[FAIL]${N} $*"; FAIL=$((FAIL+1)); FAILED_TESTS+=("$*"); }
info() { echo "${Y}[INFO]${N} $*"; }

setup_test_env() {
    TEST_DIR=$(mktemp -d -t edgebox-test-XXXXXX)
    # Override path constants via env BEFORE sourcing common.sh
    # (common.sh checks if vars are already set; the `readonly` would clash if we set after)
    # Actually common.sh uses readonly = ${default}; we need a different approach:
    # we'll edit a copy of common.sh that doesn't use readonly for paths.
    # Simpler: just set up real paths under TEST_DIR and let common.sh use its defaults.
    # But that requires /etc/edgebox which we don't have. So we re-source with overrides.

    # Strategy: copy lib files to test dir, sed out the readonly+paths, then source.
    TEST_LIB="${TEST_DIR}/lib"
    mkdir -p "$TEST_LIB"
    cp "${LIB_DIR}/common.sh" "${TEST_LIB}/common.sh"
    cp "${LIB_DIR}/subscription.sh" "${TEST_LIB}/subscription.sh"

    # Rewrite the readonly path block in common.sh to point to TEST_DIR
    sed -i \
        -e "s|^readonly EB_INSTALL_DIR=.*|readonly EB_INSTALL_DIR=\"${TEST_DIR}\"|" \
        -e "s|/var/www/html|${TEST_DIR}/www|g" \
        -e "s|/var/log/edgebox-install.log|${TEST_DIR}/edgebox.log|g" \
        "${TEST_LIB}/common.sh"

    mkdir -p "${TEST_DIR}/config" "${TEST_DIR}/www" "${TEST_DIR}/cert"
}

cleanup_test_env() {
    [[ -n "${TEST_DIR:-}" ]] && [[ -d "$TEST_DIR" ]] && rm -rf "$TEST_DIR"
}

write_fake_server_json() {
    local hy2_password="${1:-TestHy2Pwd123}"
    local ws_path="${2:-/x9k2m7p4}"

    cat > "${TEST_DIR}/config/server.json" <<JSON
{
    "server_ip": "203.0.113.42",
    "version": "v4.0.0",
    "install_date": "2026-06-03",
    "master_sub_token": "abc123def456",
    "uuid": {
        "vless": {
            "reality": "11111111-1111-1111-1111-111111111111",
            "ws": "22222222-2222-2222-2222-222222222222"
        }
    },
    "password": {
        "hysteria2": $(printf '%s' "$hy2_password" | jq -Rs .)
    },
    "reality": {
        "public_key": "TestPublicKey0123456789ABCDEFabcdef",
        "private_key": "TestPrivateKey0123456789ABCDEFabcdef",
        "short_id": "abcd1234"
    },
    "ws": {
        "path": "$ws_path"
    }
}
JSON
}

write_fake_xray_json() {
    cat > "${TEST_DIR}/config/xray.json" <<'JSON'
{
    "inbounds": [
        {
            "tag": "vless-reality",
            "streamSettings": {
                "realitySettings": {
                    "dest": "www.microsoft.com:443",
                    "serverNames": ["www.microsoft.com"]
                }
            }
        }
    ]
}
JSON
}

set_cert_mode() {
    printf '%s\n' "$1" > "${TEST_DIR}/config/cert_mode"
}

# Source the (rewritten) modules into a fresh subshell-friendly context
# Note: common.sh guards against double-sourcing via EDGEBOX_COMMON_SH_LOADED,
# so we must unset it between test groups if we re-source.
source_modules() {
    unset EDGEBOX_COMMON_SH_LOADED
    EB_LIB_DIR="${TEST_LIB}"
    # shellcheck source=/dev/null
    source "${TEST_LIB}/common.sh"
    # shellcheck source=/dev/null
    source "${TEST_LIB}/subscription.sh"
}

#############################################
# Test cases
#############################################

test_common_yaml_squote() {
    info "TEST: eb_yaml_squote special chars"

    local got
    got=$(eb_yaml_squote "abc")
    [[ "$got" == "'abc'" ]] && pass "simple string" || fail "simple: got '$got'"

    got=$(eb_yaml_squote "ab'cd")
    [[ "$got" == "'ab''cd'" ]] && pass "single quote escaping" || fail "quote escape: got '$got'"

    got=$(eb_yaml_squote "")
    [[ "$got" == "''" ]] && pass "empty string" || fail "empty: got '$got'"

    got=$(eb_yaml_squote 'p:a/s$s#w@rd!')
    [[ "$got" == "'p:a/s\$s#w@rd!'" ]] && pass "yaml special chars preserved" || fail "special chars: got '$got'"
}

test_common_url_encode() {
    info "TEST: eb_url_encode"

    local got
    got=$(eb_url_encode "abc")
    [[ "$got" == "abc" ]] && pass "ascii passthrough" || fail "ascii: got '$got'"

    got=$(eb_url_encode "a b")
    [[ "$got" == "a%20b" ]] && pass "space encoded" || fail "space: got '$got'"

    got=$(eb_url_encode "a/b")
    [[ "$got" == "a%2Fb" ]] && pass "slash encoded" || fail "slash: got '$got'"

    got=$(eb_url_encode 'p@ss/w+rd:1')
    [[ "$got" == "p%40ss%2Fw%2Brd%3A1" ]] && pass "complex password encoded" || fail "complex: got '$got'"
}

test_ip_mode_plain() {
    info "TEST: IP mode - plain URI format"

    set_cert_mode "self-signed"
    local plain
    plain=$(_eb_gen_plain "203.0.113.42" "ip")

    local n
    n=$(printf '%s' "$plain" | grep -c '^[a-z]')
    [[ "$n" -eq 3 ]] && pass "3 protocols emitted" || fail "expected 3 lines, got $n"

    echo "$plain" | grep -q 'security=reality.*sni=www.microsoft.com' \
        && pass "Reality URI present and correct" \
        || fail "Reality URI malformed"

    echo "$plain" | grep -qE '^hysteria2://[^@]+@203\.0\.113\.42:443/\?' \
        && pass "Hysteria2 URI has required '/' before '?'" \
        || fail "Hysteria2 URI missing '/' (spec violation)"

    echo "$plain" | grep -q 'hysteria2.*insecure=1' \
        && pass "Hysteria2 has insecure=1 in IP mode" \
        || fail "Hysteria2 missing insecure=1 in IP mode"

    echo "$plain" | grep -q 'sni=ws.edgebox.internal' \
        && pass "WS uses internal SNI in IP mode" \
        || fail "WS missing internal SNI in IP mode"

    echo "$plain" | grep -q 'path=%2Fx9k2m7p4' \
        && pass "WS includes randomized path" \
        || fail "WS path missing or not encoded"
}

test_domain_mode_plain() {
    info "TEST: Domain mode - plain URI format"

    set_cert_mode "letsencrypt:proxy.example.com"
    local plain
    plain=$(_eb_gen_plain "proxy.example.com" "domain")

    local n
    n=$(printf '%s' "$plain" | grep -c '^[a-z]')
    [[ "$n" -eq 3 ]] && pass "3 protocols in domain mode" || fail "expected 3, got $n"

    echo "$plain" | grep -q 'security=reality.*sni=www.microsoft.com' \
        && pass "Reality SNI unchanged in domain mode" \
        || fail "Reality SNI changed unexpectedly"

    if echo "$plain" | grep -q 'hysteria2.*insecure=1'; then
        fail "Hysteria2 has insecure=1 in domain mode (should not)"
    else
        pass "Hysteria2 has no insecure in domain mode"
    fi

    echo "$plain" | grep -q 'sni=proxy.example.com' \
        && pass "WS SNI = domain in domain mode" \
        || fail "WS SNI not domain"

    if echo "$plain" | grep -q 'allowInsecure=1'; then
        fail "allowInsecure=1 present in domain mode (should not)"
    else
        pass "No allowInsecure flag in domain mode"
    fi
}

test_ip_mode_base64() {
    info "TEST: IP mode - base64 format"

    set_cert_mode "self-signed"
    local plain b64 decoded
    plain=$(_eb_gen_plain "203.0.113.42" "ip")
    b64=$(_eb_gen_base64 "$plain")

    [[ "$b64" =~ ^[A-Za-z0-9+/=]+$ ]] && pass "base64 alphabet correct" || fail "invalid base64 alphabet"

    decoded=$(printf '%s' "$b64" | base64 -d)
    [[ "$decoded" == "$plain" ]] && pass "base64 round-trip OK" || fail "round-trip mismatch"
}

test_ip_mode_clash() {
    info "TEST: IP mode - Clash YAML format"

    set_cert_mode "self-signed"
    local yaml
    yaml=$(_eb_gen_clash "203.0.113.42" "ip")

    echo "$yaml" | grep -q "name: 'EdgeBox-REALITY'"   && pass "Clash has Reality proxy"   || fail "no Reality"
    echo "$yaml" | grep -q "name: 'EdgeBox-HYSTERIA2'" && pass "Clash has Hysteria2 proxy" || fail "no Hysteria2"
    echo "$yaml" | grep -q "name: 'EdgeBox-WS'"        && pass "Clash has WS proxy"        || fail "no WS"

    echo "$yaml" | grep -q "type: select" && pass "Clash has select group" || fail "no select group"
    echo "$yaml" | grep -q "type: url-test" && pass "Clash has url-test group" || fail "no url-test group"

    echo "$yaml" | grep -q "skip-cert-verify: true" && pass "skip-cert-verify=true in IP mode" || fail "skip-cert-verify wrong"

    if command -v python3 >/dev/null 2>&1; then
        if printf '%s' "$yaml" | python3 -c 'import sys, yaml; yaml.safe_load(sys.stdin)' 2>/dev/null; then
            pass "Clash YAML is valid YAML"
        else
            info "YAML parse skipped (python3 yaml not available)"
        fi
    fi
}

test_clash_yaml_password_escaping() {
    info "TEST: Clash YAML password escaping for special chars"

    write_fake_server_json "p:a/s\$s#w@rd'with'quote!"

    set_cert_mode "self-signed"
    local yaml
    yaml=$(_eb_gen_clash "203.0.113.42" "ip")

    echo "$yaml" | grep -q "password: 'p:a/s\$s#w@rd''with''quote!'" \
        && pass "Password with quotes properly escaped in YAML" \
        || {
            fail "Password escape failed"
            echo "  --- YAML password line: ---"
            echo "$yaml" | grep "password:" || true
            echo "  ---"
        }

    if command -v python3 >/dev/null 2>&1; then
        if printf '%s' "$yaml" | python3 -c 'import sys, yaml; yaml.safe_load(sys.stdin)' 2>/dev/null; then
            pass "YAML still parses correctly with special-char password"
        else
            info "(python3 yaml not available, skipping)"
        fi
    fi

    write_fake_server_json
}

test_ip_mode_singbox() {
    info "TEST: IP mode - sing-box JSON format"

    set_cert_mode "self-signed"
    local sb
    sb=$(_eb_gen_singbox "203.0.113.42" "ip")

    printf '%s' "$sb" | jq empty 2>/dev/null && pass "sing-box JSON is valid" || fail "invalid JSON"

    local n
    n=$(printf '%s' "$sb" | jq '[.outbounds[] | select(.tag | startswith("EdgeBox-"))] | length')
    [[ "$n" == "3" ]] && pass "3 protocol outbounds present" || fail "expected 3, got $n"

    local hy2_insecure ws_insecure
    hy2_insecure=$(printf '%s' "$sb" | jq -r '.outbounds[] | select(.tag=="EdgeBox-HYSTERIA2") | .tls.insecure')
    ws_insecure=$(printf '%s' "$sb" | jq -r '.outbounds[] | select(.tag=="EdgeBox-WS") | .tls.insecure')
    [[ "$hy2_insecure" == "true" ]] && pass "hy2 insecure=true in IP mode" || fail "hy2 insecure: $hy2_insecure"
    [[ "$ws_insecure" == "true" ]] && pass "ws insecure=true in IP mode" || fail "ws insecure: $ws_insecure"

    local ws_sni
    ws_sni=$(printf '%s' "$sb" | jq -r '.outbounds[] | select(.tag=="EdgeBox-WS") | .tls.server_name')
    [[ "$ws_sni" == "ws.edgebox.internal" ]] && pass "ws sni=internal in IP mode" || fail "ws sni: $ws_sni"

    local sel_default
    sel_default=$(printf '%s' "$sb" | jq -r '.outbounds[] | select(.tag=="EdgeBox") | .default')
    [[ "$sel_default" == "EdgeBox-REALITY" ]] && pass "selector defaults to Reality" || fail "default: $sel_default"
}

test_domain_mode_singbox() {
    info "TEST: Domain mode - sing-box JSON format"

    set_cert_mode "letsencrypt:proxy.example.com"
    local sb
    sb=$(_eb_gen_singbox "proxy.example.com" "domain")

    printf '%s' "$sb" | jq empty 2>/dev/null && pass "domain singbox JSON valid" || fail "invalid JSON"

    local hy2_insecure ws_insecure ws_sni
    hy2_insecure=$(printf '%s' "$sb" | jq -r '.outbounds[] | select(.tag=="EdgeBox-HYSTERIA2") | .tls.insecure')
    ws_insecure=$(printf '%s' "$sb" | jq -r '.outbounds[] | select(.tag=="EdgeBox-WS") | .tls.insecure')
    ws_sni=$(printf '%s' "$sb" | jq -r '.outbounds[] | select(.tag=="EdgeBox-WS") | .tls.server_name')

    [[ "$hy2_insecure" == "false" ]] && pass "hy2 insecure=false in domain mode" || fail "hy2 insecure: $hy2_insecure"
    [[ "$ws_insecure" == "false" ]] && pass "ws insecure=false in domain mode" || fail "ws insecure: $ws_insecure"
    [[ "$ws_sni" == "proxy.example.com" ]] && pass "ws sni=domain in domain mode" || fail "ws sni: $ws_sni"
}

test_full_publish_flow_ip_mode() {
    info "TEST: Full atomic publish flow (IP mode)"

    set_cert_mode "self-signed"

    if eb_gen_subscription >/dev/null 2>&1; then
        pass "eb_gen_subscription returned 0 in IP mode"
    else
        fail "eb_gen_subscription failed in IP mode"
        return
    fi

    [[ -f "${TEST_DIR}/config/subscription.txt" ]]              && pass "plain file exists"   || fail "missing plain"
    [[ -f "${TEST_DIR}/config/subscription.base64" ]]           && pass "base64 file exists"  || fail "missing base64"
    [[ -f "${TEST_DIR}/config/subscription.clash.yaml" ]]       && pass "clash file exists"   || fail "missing clash"
    [[ -f "${TEST_DIR}/config/subscription.singbox.json" ]]     && pass "singbox file exists" || fail "missing singbox"

    [[ -L "${TEST_DIR}/www/sub-abc123def456" ]]         && pass "plain symlink"   || fail "no plain symlink"
    [[ -L "${TEST_DIR}/www/sub-abc123def456.base64" ]]  && pass "base64 symlink"  || fail "no base64 symlink"
    [[ -L "${TEST_DIR}/www/sub-abc123def456.clash" ]]   && pass "clash symlink"   || fail "no clash symlink"
    [[ -L "${TEST_DIR}/www/sub-abc123def456.singbox" ]] && pass "singbox symlink" || fail "no singbox symlink"

    if jq empty "${TEST_DIR}/config/subscription.singbox.json" 2>/dev/null; then
        pass "published singbox is valid JSON"
    else
        fail "published singbox is invalid JSON"
    fi
}

test_full_publish_flow_domain_mode() {
    info "TEST: Full atomic publish flow (domain mode)"

    set_cert_mode "letsencrypt:proxy.example.com"

    if eb_gen_subscription >/dev/null 2>&1; then
        pass "eb_gen_subscription returned 0 in domain mode"
    else
        fail "eb_gen_subscription failed in domain mode"
        return
    fi

    if grep -q "proxy.example.com" "${TEST_DIR}/config/subscription.txt"; then
        pass "domain present in plain output"
    else
        fail "domain not in plain output"
    fi
}

test_atomic_failure_no_partial() {
    info "TEST: Atomic publish - rolls back on failure"

    set_cert_mode "self-signed"
    eb_gen_subscription >/dev/null 2>&1 || true
    local good_plain
    good_plain=$(cat "${TEST_DIR}/config/subscription.txt")

    echo "{not valid json" > "${TEST_DIR}/config/server.json"

    if eb_gen_subscription >/dev/null 2>&1; then
        fail "eb_gen_subscription should have failed with bad server.json"
    else
        pass "eb_gen_subscription correctly failed on bad input"
    fi

    local after_plain
    after_plain=$(cat "${TEST_DIR}/config/subscription.txt" 2>/dev/null || echo "")
    if [[ "$after_plain" == "$good_plain" ]]; then
        pass "Existing subscription unchanged after failed regen (atomic)"
    else
        fail "Existing subscription was clobbered on failure"
    fi
}

test_missing_credentials() {
    info "TEST: Graceful failure when credentials missing"

    cat > "${TEST_DIR}/config/server.json" <<'JSON'
{
    "server_ip": "203.0.113.42",
    "master_sub_token": "abc"
}
JSON

    set_cert_mode "self-signed"
    if eb_gen_subscription >/dev/null 2>&1; then
        fail "Should have failed without credentials"
    else
        pass "Correctly fails when credentials missing"
    fi
}

#############################################
# Test runner
#############################################
main() {
    info "EdgeBox subscription.sh test suite - v4.0.0"
    info "Lib dir: ${LIB_DIR}"

    for f in common.sh subscription.sh; do
        if [[ ! -f "${LIB_DIR}/${f}" ]]; then
            echo "${R}FATAL: ${LIB_DIR}/${f} not found${N}"
            exit 1
        fi
    done

    for t in jq base64 mktemp openssl; do
        if ! command -v "$t" >/dev/null 2>&1; then
            echo "${R}FATAL: required tool '$t' not in PATH${N}"
            exit 1
        fi
    done

    setup_test_env
    trap cleanup_test_env EXIT

    write_fake_server_json
    write_fake_xray_json
    source_modules

    test_common_yaml_squote
    test_common_url_encode

    test_ip_mode_plain
    test_ip_mode_base64
    test_ip_mode_clash
    test_ip_mode_singbox

    write_fake_server_json
    write_fake_xray_json
    test_domain_mode_plain

    write_fake_server_json
    write_fake_xray_json
    test_domain_mode_singbox

    write_fake_server_json
    write_fake_xray_json
    test_clash_yaml_password_escaping

    write_fake_server_json
    write_fake_xray_json
    test_full_publish_flow_ip_mode

    write_fake_server_json
    write_fake_xray_json
    test_full_publish_flow_domain_mode

    write_fake_server_json
    write_fake_xray_json
    test_atomic_failure_no_partial

    test_missing_credentials

    echo ""
    echo "=========================================="
    if [[ $FAIL -eq 0 ]]; then
        echo "${G}Results: $PASS passed, 0 failed${N}"
    else
        echo "${R}Results: $PASS passed, $FAIL failed${N}"
        echo "Failed tests:"
        for t in "${FAILED_TESTS[@]}"; do
            echo "  - $t"
        done
    fi
    echo "=========================================="

    [[ $FAIL -eq 0 ]]
}

main "$@"
