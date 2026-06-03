# EdgeBox Block 1 - Integration Guide

This document explains how to integrate the new subscription generator
(`lib/common.sh` + `lib/subscription.sh`) into the existing `install.sh`.

This is a **surgical patch**: we keep install.sh's structure, replace the
4 inconsistent subscription-generating functions with calls to the new
unified generator, and remove the 3 deleted protocols (gRPC, Trojan, TUIC).

The patch is grouped into 6 changes, ordered to be applied top-to-bottom.

---

## Change 1: Add lib loading at the top of install.sh

After the existing path constants block (around line 100-130), add:

```bash
#############################################
# Library Loading (v4.0.0)
#############################################

# The lib/ directory is downloaded by the bootstrap installer (see Change 6)
# alongside install.sh into a temp dir.
EB_BOOTSTRAP_LIB_DIR="${EB_BOOTSTRAP_LIB_DIR:-$(dirname "${BASH_SOURCE[0]}")/lib}"

# common.sh provides path constants, logging, jq helpers, atomic writes
if [[ -f "${EB_BOOTSTRAP_LIB_DIR}/common.sh" ]]; then
    # shellcheck source=lib/common.sh
    source "${EB_BOOTSTRAP_LIB_DIR}/common.sh"
else
    echo "[FATAL] lib/common.sh not found - cannot proceed" >&2
    exit 1
fi

# subscription.sh provides eb_gen_subscription()
if [[ -f "${EB_BOOTSTRAP_LIB_DIR}/subscription.sh" ]]; then
    # shellcheck source=lib/subscription.sh
    source "${EB_BOOTSTRAP_LIB_DIR}/subscription.sh"
fi
```

Also ensure the lib files end up in `/etc/edgebox/scripts/lib/` for runtime use
by `edgeboxctl`. Add this to the installation finalization step:

```bash
# Install lib files for edgeboxctl runtime use
mkdir -p "${EB_SCRIPTS_DIR}/lib"
install -m 0644 "${EB_BOOTSTRAP_LIB_DIR}/common.sh"       "${EB_SCRIPTS_DIR}/lib/"
install -m 0644 "${EB_BOOTSTRAP_LIB_DIR}/subscription.sh" "${EB_SCRIPTS_DIR}/lib/"
```

---

## Change 2: Update server.json schema

In the `generate_credentials()` function and the `save_config_info()` function,
the server.json needs three new fields and three removed fields.

**Remove** these field generations (gRPC, Trojan, TUIC are gone):

```bash
# REMOVE:
UUID_VLESS_GRPC=$(uuidgen)
UUID_VLESS_TROJAN=$(uuidgen)
UUID_TUIC=$(uuidgen)
PASSWORD_TROJAN=$(openssl rand -base64 32 | tr -d '\n')
PASSWORD_TUIC=$(openssl rand -base64 32 | tr -d '\n')
```

**Add** these field generations:

```bash
# ADD: Random WS path for de-fingerprinting (8 chars, lowercase alphanumeric)
WS_PATH="/$(eb_random_string 8)"
```

**Update** the jq construction in `save_config_info()` to produce the new schema:

```jsonc
{
    "server_ip": "...",
    "version": "v4.0.0",
    "install_date": "...",
    "master_sub_token": "...",
    "uuid": {
        "vless": {
            "reality": "...",
            "ws": "..."
        }
    },
    "password": {
        "hysteria2": "..."
    },
    "reality": {
        "public_key": "...",
        "private_key": "...",
        "short_id": "..."
    },
    "ws": {
        "path": "/x9k2m7p4"
    },
    "cdn": {
        "enabled": false,
        "host": null
    },
    "cloud": { "...": "..." },
    "spec": { "...": "..." }
}
```

The `cdn` field is reserved for block 5 (CDN relay mode). Setting it now
keeps the schema stable across the v4.x series.

---

## Change 3: Replace the 4 old subscription functions with calls to eb_gen_subscription

The existing install.sh has 4 different subscription generators:

1. `generate_subscription()` - in install module
2. `regen_sub_domain()` - in edgeboxctl
3. `regen_sub_ip()` - in edgeboxctl
4. The jq inline expression in `get_protocols_status()` - in dashboard-backend.sh

**Replace all four** with the same single call:

```bash
# Old call sites:
generate_subscription            →    eb_gen_subscription
regen_sub_domain "$domain"       →    eb_gen_subscription
regen_sub_ip                     →    eb_gen_subscription
```

In `get_protocols_status()` (dashboard-backend.sh generator), the inline
URI construction should be removed entirely. The dashboard reads
`subscription.txt` if it needs the URIs:

```bash
# In dashboard-backend.sh:
get_protocols_status() {
    # ... (existing code that doesn't deal with URI generation) ...
    # Read share_link from the published subscription.txt if needed,
    # but better: just point users to the subscription URL.
}
```

---

## Change 4: Nginx config simplification

### 4.1 Stream map - delete ALPN second-level routing

Find the stream block in nginx.conf generation (around line 3274 `configure_nginx`).

**Delete** these sections (they handle gRPC and ALPN routing, no longer needed):

```nginx
# DELETE THIS WHOLE BLOCK:
map $ssl_preread_alpn_protocols $decision_2 {
    ~\bh2\b         "grpc";
    ~\bhttp/1\.1\b  "websocket";
    default         "reality";
}

map $decision_1 $final_target {
    "check_alpn"    $decision_2;
    default         $decision_1;
}
```

**Replace** with simpler single-level routing:

```nginx
# v4.0.0 simplified routing:
# - Reality SNIs (microsoft.com etc) -> reality upstream
# - ws.edgebox.internal OR <domain>  -> ws upstream
# - default (no SNI / unknown SNI)   -> reality (fallback)

map $ssl_preread_server_name $final_target {
    # Reality fallback SNIs (real public domains)
    ~*^(www\.)?(microsoft|apple|cloudflare|amazon|fastly)\.com$  reality;

    # WS routing - internal SNI (IP mode) and domain (domain mode)
    ws.edgebox.internal                                          ws;
    # Note: in domain mode, edgeboxctl injects the live domain here:
    #   <domain>                                                 ws;
    # See change 4.3 below for the domain injection mechanism.

    # Everything else falls back to Reality (safe default)
    default                                                      reality;
}

upstream reality { server 127.0.0.1:11443; }
upstream ws      { server 127.0.0.1:10086; }

server {
    listen 443 reuseport;
    listen [::]:443 reuseport;
    proxy_pass $final_target;
    ssl_preread on;
    proxy_protocol off;
}
```

The `upstream` for grpc (`10085`) and trojan (`10143`) are removed.

### 4.2 HTTP routes - add 3 new subscription paths via regex

In the http block, find the existing subscription location:

```nginx
# OLD - single hardcoded path:
location = /sub-${MASTER_SUB_TOKEN} {
    default_type text/plain;
    add_header Cache-Control "no-store, no-cache, must-revalidate";
    root /var/www/html;
    try_files /sub-${MASTER_SUB_TOKEN} =404;
}
```

**Replace** with a regex that matches all 4 subscription formats:

```nginx
# v4.0.0 - regex location handles 4 formats:
# /sub-<token>          -> plain text (default_type text/plain)
# /sub-<token>.base64   -> base64 (text/plain)
# /sub-<token>.clash    -> YAML (text/yaml)
# /sub-<token>.singbox  -> JSON (application/json)

location ~ "^/sub-[a-f0-9]+(\.(base64|clash|singbox))?$" {
    add_header Cache-Control "no-store, no-cache, must-revalidate";

    # Determine content type from extension
    location ~ "\.clash$"   { default_type "text/yaml; charset=utf-8";        root /var/www/html; }
    location ~ "\.singbox$" { default_type "application/json; charset=utf-8"; root /var/www/html; }
    location ~ "\.base64$"  { default_type "text/plain; charset=utf-8";       root /var/www/html; }
    location ~ ".*"         { default_type "text/plain; charset=utf-8";       root /var/www/html; }
}
```

The token is restricted to `[a-f0-9]+` (hex chars) because master_sub_token
is generated via `openssl rand -hex`. If you ever change token generation,
update this regex.

### 4.3 Domain mode SNI injection

When `edgeboxctl switch-to-domain <domain>` is called, the WS routing
needs to add the new domain to the SNI map. Currently this is done by
`update_sni_domain()`. The new equivalent:

```bash
# In edgeboxctl, after successful LE cert issuance:
_eb_inject_ws_domain_to_nginx() {
    local domain="$1"
    local map_file="/etc/nginx/conf.d/edgebox_stream_map.conf"

    # The map file is rewritten from scratch each switch
    cat > "${map_file}.tmp" <<EOF
map \$ssl_preread_server_name \$final_target {
    ~*^(www\\.)?(microsoft|apple|cloudflare|amazon|fastly)\\.com\$  reality;
    ws.edgebox.internal                                            ws;
    ${domain}                                                      ws;
    default                                                        reality;
}
EOF
    mv "${map_file}.tmp" "$map_file"

    nginx -t && systemctl reload nginx
}
```

---

## Change 5: Hook subscription regen into config-changing events

Whenever any config that affects the subscription changes, call
`eb_gen_subscription`. The following call sites need this:

```bash
# After Reality key rotation:
rotate_reality_keys() {
    # ... existing key generation + xray.json update ...
    eb_gen_subscription      # <- add this line, replaces regen_sub_*
}

# After Reality SID rotation:
rotate_reality_sid_graceful() {
    # ... existing sid append + xray reload ...
    eb_gen_subscription      # <- add this line
}

# After SNI domain change:
update_sni_domain() {
    # ... existing serverNames update ...
    eb_gen_subscription      # <- add this line
}

# After switching to domain mode (LE cert success):
switch_to_domain() {
    # ... existing certbot + cert symlink ...
    eb_gen_subscription      # <- add this line
}

# After switching back to IP mode:
switch_to_ip() {
    # ... existing cert switch ...
    eb_gen_subscription      # <- add this line
}

# After regenerating UUIDs/passwords:
regenerate_uuid() {
    # ... existing uuid/password regeneration ...
    eb_gen_subscription      # <- add this line
}

# Initial install (end of main install flow):
main_install() {
    # ... existing install steps ...
    eb_gen_subscription      # <- add this line, replaces generate_subscription
}
```

---

## Change 6: Bootstrap install.sh download flow

Update the top of install.sh (after the auto-sudo block) to download the
lib files before executing the main flow:

```bash
#############################################
# Bootstrap: download lib modules from GitHub
#############################################

EDGEBOX_CHANNEL="${EDGEBOX_CHANNEL:-stable}"
EDGEBOX_VERSION="${EDGEBOX_VERSION:-v4.0.0}"

case "$EDGEBOX_CHANNEL" in
    stable) REPO_REF="$EDGEBOX_VERSION" ;;
    dev)    REPO_REF="main"
            echo "[WARN] Using dev channel (main branch) - not for production" >&2 ;;
    *)      echo "[FATAL] Unknown EDGEBOX_CHANNEL: $EDGEBOX_CHANNEL" >&2; exit 1 ;;
esac

REPO_RAW="https://raw.githubusercontent.com/cuiping89/node/${REPO_REF}/ENV"

# If we're being executed via curl | bash, $0 is "bash" and there's no lib/
# next to install.sh. Download lib/ to a temp dir.
if [[ ! -d "$(dirname "${BASH_SOURCE[0]}")/lib" ]]; then
    EB_BOOTSTRAP_TMP=$(mktemp -d -t edgebox-bootstrap-XXXXXX)
    trap 'rm -rf "$EB_BOOTSTRAP_TMP"' EXIT
    mkdir -p "${EB_BOOTSTRAP_TMP}/lib"

    for f in common.sh subscription.sh; do
        if ! curl -fsSL "${REPO_RAW}/lib/${f}" -o "${EB_BOOTSTRAP_TMP}/lib/${f}"; then
            echo "[FATAL] Failed to download lib/${f} from ${REPO_RAW}" >&2
            exit 1
        fi
    done

    EB_BOOTSTRAP_LIB_DIR="${EB_BOOTSTRAP_TMP}/lib"
fi
```

This preserves the one-liner UX:

```bash
curl -fsSL https://raw.githubusercontent.com/cuiping89/node/v4.0.0/ENV/install.sh | bash
```

Users on `stable` (the default) get a pinned version. Developers can opt in:

```bash
EDGEBOX_CHANNEL=dev curl -fsSL ... | bash
```

---

## Verification

After applying all 6 changes:

```bash
# 1. Syntax check the modified install.sh
bash -n install.sh

# 2. Run unit tests for the subscription generator
bash test/test_subscription.sh

# 3. Do a clean install in a VM and verify:
#    - 4 subscription URLs all return correct content with correct Content-Type
curl -s http://<server_ip>/sub-<token>          # plain text, 3 URIs
curl -s http://<server_ip>/sub-<token>.base64   # base64 string
curl -s http://<server_ip>/sub-<token>.clash    # valid YAML
curl -s http://<server_ip>/sub-<token>.singbox  # valid JSON

# 4. Each subscription should be importable in its respective client:
#    - plain  -> v2rayN / v2rayNG (paste URL)
#    - clash  -> Mihomo Party (subscribe to URL)
#    - singbox -> sing-box / NekoBox (import config URL)

# 5. Switch to domain mode and verify subscriptions auto-update:
edgeboxctl switch-to-domain proxy.example.com
curl -s http://proxy.example.com/sub-<token>    # now uses proxy.example.com, no insecure flags
```

---

## Files Modified

```
ENV/install.sh                  # patches: Change 1, 2, 3, 5, 6
ENV/lib/common.sh               # NEW (block 1)
ENV/lib/subscription.sh         # NEW (block 1)
ENV/test/test_subscription.sh   # NEW (block 1)
```

---

## What's NOT changed in block 1

These remain identical to v3.x and are left for future blocks:

- `cron.sh` (block 3)
- `monitor.sh` (block 2)
- `edgeboxctl.sh` (block 4)
- `templates/` (block 5)
- Front-end HTML/CSS/JS (block 7)

The front-end's dashboard.json contract is unchanged: it still receives
`protocols: [...]`, just with 3 items instead of 6. No front-end code changes
are needed for block 1 to work; the protocol table will simply render 3 rows.
