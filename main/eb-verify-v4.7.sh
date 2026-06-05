#!/usr/bin/env bash
#==============================================================================
# eb-verify-v4.7.sh  —  EdgeBox v4.7.0 verification (WS/CDN removal + audit fixes)
#
# Self-contained. No parameters, no file transfers. Run anywhere with curl:
#     bash <(curl -fsSL https://raw.githubusercontent.com/cuiping89/node/main/ENV/test/eb-verify-v4.7.sh)
# or after copying it onto the box:
#     bash eb-verify-v4.7.sh
#
# PART A (always): fetches the source from GitHub main and checks the refactor
#                  is correct + the bootstrap manifest matches the served files.
# PART B (auto):   if /etc/edgebox exists, also checks the live runtime state.
#
# Exit code 0 only if every assertion passes (skips don't fail the run).
#==============================================================================

REPO="cuiping89/node"
BRANCH="${EDGEBOX_BRANCH:-main}"

# ---- output helpers ----------------------------------------------------------
if [[ -t 1 ]]; then G=$'\033[32m'; R=$'\033[31m'; Y=$'\033[33m'; C=$'\033[36m'; N=$'\033[0m'
else G=""; R=""; Y=""; C=""; N=""; fi
OK=0; BAD=0; SK=0; FAILED=""
pass(){ printf "  ${G}PASS${N} %s\n" "$1"; OK=$((OK+1)); }
fail(){ printf "  ${R}FAIL${N} %s\n" "$1"; BAD=$((BAD+1)); FAILED+=$'\n   - '"$1"; }
skip(){ printf "  ${Y}SKIP${N} %s\n" "$1"; SK=$((SK+1)); }
hdr(){ printf "\n${C}== %s ==${N}\n" "$1"; }

need(){ command -v "$1" >/dev/null 2>&1; }

# ---- resolve raw base (handle subdir layouts) --------------------------------
BASE=""
for cand in \
  "https://raw.githubusercontent.com/${REPO}/${BRANCH}/ENV" \
  "https://raw.githubusercontent.com/${REPO}/${BRANCH}/main/ENV"; do
  if [[ "$(curl -fsS -o /dev/null -w '%{http_code}' "$cand/bootstrap.sh" 2>/dev/null)" == "200" ]]; then
    BASE="$cand"; break
  fi
done
if [[ -z "$BASE" ]]; then
  echo "${R}ERROR${N}: cannot reach repo bootstrap.sh on branch '$BRANCH'. Check network/branch."
  exit 2
fi

WORK="$(mktemp -d)"; trap 'rm -rf "$WORK"' EXIT
# files we need to inspect (local mirror path under $WORK)
FILES=( bootstrap.sh VERSION install.sh
        lib/common.sh lib/subscription.sh
        scripts/edgeboxctl scripts/dashboard-backend.sh
        scripts/protocol-health-monitor.sh scripts/edgebox-traffic-randomize.sh
        web/dashboard.js test/test_subscription.sh )

echo "${C}EdgeBox v4.7.0 verifier${N}  (repo=$REPO  branch=$BRANCH)"
echo "raw base: $BASE"

hdr "Fetching source from GitHub"
fetch_ok=1
for f in "${FILES[@]}"; do
  mkdir -p "$WORK/$(dirname "$f")"
  if curl -fsSL "$BASE/$f" -o "$WORK/$f" 2>/dev/null && [[ -s "$WORK/$f" ]]; then
    :
  else
    echo "  ${R}could not fetch${N} $f"; fetch_ok=0
  fi
done
[[ "$fetch_ok" == 1 ]] && echo "  all source files fetched" || echo "  ${Y}some files missing — related checks will be skipped${N}"

have(){ [[ -s "$WORK/$1" ]]; }                       # file fetched?
gq(){ grep -qE "$2" "$WORK/$1" 2>/dev/null; }        # pattern present?
gqv(){ ! grep -qE "$2" "$WORK/$1" 2>/dev/null; }     # pattern absent?

#==============================================================================
hdr "PART A1 — Bootstrap manifest matches served files (install-gate)"
#==============================================================================
if have bootstrap.sh && need sha256sum; then
  mok=0; mbad=0
  while IFS='|' read -r remote local sha; do
    [[ -z "$remote" ]] && continue
    tmp="$WORK/.m_$(echo "$remote" | tr '/' '_')"
    if curl -fsSL "$BASE/$remote" -o "$tmp" 2>/dev/null; then
      act="$(sha256sum "$tmp" | awk '{print $1}')"
      if [[ "$act" == "$sha" ]]; then mok=$((mok+1)); else mbad=$((mbad+1)); echo "      ${R}mismatch${N} $remote (manifest ${sha:0:12} != actual ${act:0:12})"; fi
    else mbad=$((mbad+1)); echo "      ${R}missing${N} $remote"; fi
  done < <(grep -oE '"[^"]+\|[^"]+\|[a-f0-9]{64}"' "$WORK/bootstrap.sh" | tr -d '"')
  if [[ "$mbad" -eq 0 && "$mok" -gt 0 ]]; then pass "manifest: all $mok entries match served files"
  else fail "manifest: $mbad mismatch/missing (run tools/gen-manifest.sh and re-push)"; fi
else
  skip "manifest check (bootstrap.sh or sha256sum unavailable)"
fi

#==============================================================================
hdr "PART A2 — Version unified to 4.7.0"
#==============================================================================
if have VERSION; then [[ "$(tr -d '[:space:]' < "$WORK/VERSION")" == "4.7.0" ]] && pass "ENV/VERSION = 4.7.0" || fail "ENV/VERSION != 4.7.0"; else skip "VERSION"; fi
if have install.sh; then
  gq install.sh 'EDGEBOX_VER="4\.7\.0"' && pass "install.sh EDGEBOX_VER = 4.7.0" || fail "install.sh EDGEBOX_VER not 4.7.0"
  # the killer: main() must not re-export the old version
  gqv install.sh 'export EDGEBOX_VER="4\.6' && pass "install.sh main() does not re-export rc4 (server.json.version will be 4.7.0)" \
    || fail "install.sh still re-exports EDGEBOX_VER=4.6.x in main()"
fi
have bootstrap.sh && { gq bootstrap.sh 'EDGEBOX_BOOTSTRAP_VERSION="4\.7\.0"' && pass "bootstrap EDGEBOX_BOOTSTRAP_VERSION = 4.7.0" || fail "bootstrap version not 4.7.0"; }
# no FUNCTIONAL rc4 assignments left (comments dated v4.6.0-rc4 are fine)
for f in install.sh bootstrap.sh lib/common.sh scripts/edgeboxctl scripts/dashboard-backend.sh; do
  have "$f" || continue
  if grep -E '4\.6\.0-rc4' "$WORK/$f" | grep -vE '^\s*#|//' | grep -qE '="?v?4\.6\.0-rc4|rc4\+|\(三协议'; then
    fail "$f has a functional 4.6.0-rc4 string"
  fi
done
[[ "$BAD" -eq "$BAD" ]]  # no-op to keep set -e off

#==============================================================================
hdr "PART A3 — Two-protocol convergence (no WS / no CDN code paths)"
#==============================================================================
# feature artifacts that would mean WS or CDN can still start
ART='vless-ws|EdgeBox-WS|ws\.edgebox\.internal|127\.0\.0\.1:10086|:10086|cdn\.enabled|cdn\.host|cdn_enable|cdn_disable|in_cdn_mode|uuid\.vless\.ws|\.ws\.path|_eb_uri_ws|UUID_VLESS_WS'
artifact_hits=0
for f in install.sh lib/subscription.sh lib/common.sh scripts/edgeboxctl \
         scripts/dashboard-backend.sh scripts/protocol-health-monitor.sh \
         scripts/edgebox-traffic-randomize.sh web/dashboard.js; do
  have "$f" || continue
  h="$(grep -nE "$ART" "$WORK/$f" 2>/dev/null | grep -viE 'cdnjs|aiv-cdn|hbo-cdn|tiktokcdn|已移除|removed|deprecated')"
  if [[ -n "$h" ]]; then artifact_hits=$((artifact_hits+1)); echo "      ${R}$f${N}: $(echo "$h" | head -2)"; fi
done
[[ "$artifact_hits" -eq 0 ]] && pass "no WS/CDN feature artifacts in any script" || fail "$artifact_hits file(s) still contain WS/CDN feature code"

# subscription source-of-truth
if have lib/subscription.sh; then
  gq lib/subscription.sh 'expected_count=2' && pass "subscription.sh expects exactly 2 protocols" || fail "subscription.sh expected_count != 2"
  gqv lib/subscription.sh 'EdgeBox-WS|_eb_uri_ws|_eb_gen_singbox_cdn|_eb_gen_clash_cdn' && pass "subscription.sh has no WS/CDN builders" || fail "subscription.sh still has WS/CDN builders"
fi
# xray inbound template
if have install.sh; then
  gq install.sh '"tag": "vless-reality"' && pass "install.sh xray template has Reality inbound" || fail "install.sh missing Reality inbound"
  gqv install.sh '"tag": "vless-ws"' && pass "install.sh xray template has NO WS inbound" || fail "install.sh still defines vless-ws inbound"
fi

#==============================================================================
hdr "PART A4 — Audit fixes present"
#==============================================================================
# #4 restart_services propagates failure
if have scripts/edgeboxctl; then
  awk '/^restart_services\(\)/{f=1} f{print} f&&/^}/{exit}' "$WORK/scripts/edgeboxctl" | grep -qE 'return "?\$failed' \
    && pass "edgeboxctl restart_services returns failure code" || fail "edgeboxctl restart_services still swallows failures"
fi
# #2 traffic reset hardening + restart_services_safely no longer skips inactive
if have scripts/edgebox-traffic-randomize.sh; then
  body="$(awk '/^restart_services_safely\(\)/{f=1} f{print} f&&/^}/{exit}' "$WORK/scripts/edgebox-traffic-randomize.sh")"
  echo "$body" | grep -qE 'return "?\$failed' && pass "restart_services_safely propagates failure" || fail "restart_services_safely does not propagate failure"
  echo "$body" | grep -qE 'if systemctl is-active --quiet "\$_svc"; then' && fail "restart_services_safely still skips inactive services" || pass "restart_services_safely no longer skips inactive services"
  awk '/== "reset"/{f=1} f{print} f&&/exit 0/{exit}' "$WORK/scripts/edgebox-traffic-randomize.sh" | grep -q 'verify_randomization_result' \
    && pass "traffic reset verifies result before reporting success" || fail "traffic reset still skips verification"
fi
# #3 share dir permission split
if have scripts/edgeboxctl; then
  awk '/^ensure_sub_dirs\(\)/{f=1} f{print} f&&/^}/{exit}' "$WORK/scripts/edgeboxctl" | grep -qE 'chmod 755 "\$SUB_DIR"' \
    && pass "ensure_sub_dirs makes web /share 755 (nginx-readable)" || fail "ensure_sub_dirs does not set /share to 755"
fi
# #1 install log: password not written + log file locked down
if have install.sh; then
  grep -E 'log_(success|info)[^=]*控制面板密码' "$WORK/install.sh" | grep -qE '\$\{?DASHBOARD_PASSCODE' \
    && fail "install.sh logs the full panel password" || pass "install.sh does not log the full panel password"
  gq install.sh 'chmod 600 "\$\{LOG_FILE\}"' && pass "install.sh locks install log to 600" || fail "install.sh does not chmod 600 the log"
fi

#==============================================================================
hdr "PART A5 — Syntax check (bash -n) + subscription test suite"
#==============================================================================
if need bash; then
  for f in install.sh bootstrap.sh lib/common.sh lib/subscription.sh scripts/edgeboxctl \
           scripts/dashboard-backend.sh scripts/protocol-health-monitor.sh scripts/edgebox-traffic-randomize.sh; do
    have "$f" || continue
    bash -n "$WORK/$f" 2>/dev/null && pass "bash -n $f" || fail "bash -n $f (syntax error)"
  done
else skip "bash -n (bash unavailable)"; fi

if need bash && need jq && have lib/subscription.sh && have lib/common.sh; then
  fake="$WORK/fakeenv"; mkdir -p "$fake/config"
  cat > "$fake/config/server.json" <<'JSON'
{ "server_ip":"203.0.113.7","version":"4.7.0","master_sub_token":"verifytoken",
  "uuid":{"vless":{"reality":"11111111-1111-1111-1111-111111111111"}},
  "password":{"hysteria2":"VerifyPass123"},
  "reality":{"public_key":"PUBKEYxxx","private_key":"PRIVKEYxxx","short_id":"ab12"},
  "cert":{"mode":"self-signed"} }
JSON
  gen="$(cd "$WORK" && EB_INSTALL_DIR="$fake" EB_WEB_ROOT="$fake/www" EB_LIB_DIR="$WORK/lib" bash -c '
      source lib/common.sh 2>/dev/null
      source lib/subscription.sh 2>/dev/null
      _eb_gen_plain "203.0.113.7" "ip"' 2>/dev/null)"
  n="$(printf '%s' "$gen" | grep -c '^[a-z]')"
  if [[ "$n" == "2" ]] && printf '%s' "$gen" | grep -q 'REALITY' \
       && printf '%s' "$gen" | grep -q 'HYSTERIA2' && ! printf '%s' "$gen" | grep -q 'EdgeBox-WS'; then
    pass "live subscription generation: exactly 2 protocols (Reality + Hysteria2, no WS)"
  else
    fail "live subscription generation produced $n protocol line(s) (expected 2 Reality+HY2)"
  fi
else skip "live generation check (needs bash+jq)"; fi

# Informational: the repo test file is NOT deployed (not in manifest); flag if stale.
if have test/test_subscription.sh; then
  if grep -qE '3 protocol|expected 3|test suite - v4\.0\.0' "$WORK/test/test_subscription.sh"; then
    skip "test/test_subscription.sh in repo is STALE (still 3-protocol/v4.0.0) — not deployed, but update it to match v4.7.0"
  else
    pass "repo test/test_subscription.sh is current (2-protocol)"
  fi
fi

#==============================================================================
hdr "PART B — Live runtime (only if installed)"
#==============================================================================
CFG=/etc/edgebox/config
if [[ ! -d /etc/edgebox ]]; then
  echo "  /etc/edgebox not found — not an installed node, skipping runtime checks"
else
  # services
  for s in nginx xray sing-box; do
    systemctl is-active --quiet "$s" 2>/dev/null && pass "service $s active" || fail "service $s not active"
  done
  # ports
  if need ss; then
    ss -tln 2>/dev/null | grep -qE '[:.]443[[:space:]]'   && pass "TCP/443 listening"  || fail "TCP/443 not listening"
    ss -uln 2>/dev/null | grep -qE '[:.]443[[:space:]]'   && pass "UDP/443 listening (HY2)" || fail "UDP/443 not listening"
    ss -tln 2>/dev/null | grep -qE '127\.0\.0\.1:11443'   && pass "Reality internal 11443 listening" || fail "Reality 11443 not listening"
    ss -tln 2>/dev/null | grep -qE '127\.0\.0\.1:10086'   && fail "WS internal 10086 still listening (should be gone)" || pass "WS 10086 NOT listening (correct)"
  else skip "port checks (ss unavailable)"; fi
  # configs
  if need jq && [[ -f "$CFG/xray.json" ]]; then
    tags="$(jq -r '.inbounds[].tag' "$CFG/xray.json" 2>/dev/null | sort | tr '\n' ',')"
    echo "$tags" | grep -q 'vless-reality' && pass "xray.json has Reality inbound" || fail "xray.json missing Reality inbound"
    echo "$tags" | grep -q 'vless-ws' && fail "xray.json still has WS inbound" || pass "xray.json has NO WS inbound"
  else skip "xray.json check"; fi
  if need jq && [[ -f "$CFG/sing-box.json" ]]; then
    jq -e '[.inbounds[]?|select(.type=="hysteria2")]|length>0' "$CFG/sing-box.json" >/dev/null 2>&1 && pass "sing-box.json has Hysteria2 inbound" || fail "sing-box.json missing Hysteria2"
  else skip "sing-box.json check"; fi
  if need jq && [[ -f "$CFG/server.json" ]]; then
    [[ "$(jq -r '.version//empty' "$CFG/server.json")" == "4.7.0" ]] && pass "server.json version = 4.7.0" || fail "server.json version != 4.7.0"
    [[ "$(jq -r '.cdn//"absent"' "$CFG/server.json")" == "absent" ]] && pass "server.json has no .cdn block" || fail "server.json still has .cdn block"
    [[ "$(jq -r '.uuid.vless.ws//"absent"' "$CFG/server.json")" == "absent" ]] && pass "server.json has no uuid.vless.ws" || fail "server.json still has uuid.vless.ws"
  else skip "server.json check"; fi
  # subscription
  if [[ -f "$CFG/subscription.txt" ]]; then
    n="$(grep -cE '^[a-z]' "$CFG/subscription.txt")"
    [[ "$n" == "2" ]] && pass "subscription.txt has exactly 2 protocols" || fail "subscription.txt has $n protocols (expected 2)"
    grep -q 'EdgeBox-WS' "$CFG/subscription.txt" && fail "subscription.txt still contains a WS link" || pass "subscription.txt has no WS link"
  else skip "subscription.txt check"; fi
  # permissions (#3)
  if [[ -d /var/www/html/share ]]; then
    p="$(stat -c '%a' /var/www/html/share 2>/dev/null)"
    [[ "$p" == "755" || "$p" == "751" || "$p" == "711" ]] && pass "/var/www/html/share traversable ($p)" || fail "/var/www/html/share is $p (nginx may 403)"
  else skip "/var/www/html/share (no dedicated subs issued yet)"; fi
  if [[ -d /etc/edgebox/sub ]]; then
    p="$(stat -c '%a' /etc/edgebox/sub 2>/dev/null)"
    [[ "$p" == "700" ]] && pass "/etc/edgebox/sub is private (700)" || fail "/etc/edgebox/sub is $p (expected 700)"
  else skip "/etc/edgebox/sub (no dedicated subs issued yet)"; fi
  # firewall (best effort)
  if need ufw && ufw status >/dev/null 2>&1; then
    us="$(ufw status 2>/dev/null)"
    echo "$us" | grep -qE '443/tcp' && echo "$us" | grep -qE '443/udp' && pass "ufw allows 443/tcp + 443/udp" || skip "ufw rules (verify 80/443 manually)"
  else skip "firewall check (ufw not active; verify 80,443/tcp + 443/udp manually)"; fi
fi

#==============================================================================
echo ""
printf "${C}==============================================${N}\n"
printf " Result: ${G}%d passed${N}, ${R}%d failed${N}, ${Y}%d skipped${N}\n" "$OK" "$BAD" "$SK"
printf "${C}==============================================${N}\n"
if [[ "$BAD" -gt 0 ]]; then
  printf "${R}FAILED:${N}%s\n" "$FAILED"
  exit 1
fi
echo "${G}All checks passed.${N}"
exit 0
