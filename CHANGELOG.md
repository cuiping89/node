# Changelog

## v4.6.0-rc2 — 2nd security audit fixes

External audit returned 8 P1 issues + P2 cleanup after rc1 VPS verification.
All P1 fixed; selected P2 cleanup applied.

### P1#1: switch-to-domain didn't update server.json.cert → CDN broken
`switch_to_domain` wrote `cert_mode` file (`letsencrypt:<domain>`) but left
`server.json.cert.mode = "self-signed"` from initial install. Since `cdn enable`
prerequisite check reads `server.json.cert.mode`, the user would see CDN refuse
even after successfully switching to LE domain mode.

Fixed: `switch_to_domain` and `switch_to_ip` both now also update
`server.json.cert.{mode,domain,auto_renew}` via jq. `chmod 600 + chown root:root`
applied after each update.

### P1#2: edgeboxctl operations let protected files drop back to 644
`server.json`, `xray.json`, `sing-box.json` contain Reality private key, VLESS
UUIDs, HY2 password, dashboard secrets, master sub token. Initial install set
them 600, but ~10 management commands wrote tmp files and `mv`d them in,
leaving 644 (umask default). Audit identified all sites.

Fixed: added `secure_replace()` helper (install -o root -g root -m 600).
Patched every `mv` site that lands on a protected file:
- edgeboxctl: dashboard passcode, SNI update (was `install -m 644` → 600),
  Reality key rotation, SID rotation, VPS/resi shunt mode, smart shunt mode,
  sing-box reset, cdn_modify_xray (was explicit `chmod 644`)
- edgebox-traffic-randomize: HY2 config randomize, randomization reset
- xray.json.template now 600

Grep verification: 0 occurrences of "chmod 644.*protected_file" remain.

### P1#3: dashboard share_link generation had 3 bugs
`dashboard-backend.sh:get_protocols_status()` reimplemented URI building:
- IP-mode Hysteria2 missing `insecure=1` → self-signed cert clients reject
- IP-mode WS used server IP for SNI (should be `ws.edgebox.internal`)
- CDN mode used `host_or_ip` not `cdn.host`

Fixed: dashboard no longer builds URIs. Reads `${CONFIG_DIR}/subscription.txt`
(produced correctly by `lib/subscription.sh`) and matches lines by trailing
`#EdgeBox-REALITY` / `#EdgeBox-HYSTERIA2` / `#EdgeBox-WS` / `#EdgeBox-WS-CDN`
tags into an associative array.

### P1#4: alert.env loaded via `source` — Webhook URLs broke
`lib/alert.sh` and `edgeboxctl alert show` both used `source $ALERT_ENV`,
which lets Shell interpret `&`, `#`, spaces, quotes, `$` in webhook URLs —
URLs got truncated or accidentally executed commands.

Fixed: replaced both `source` sites with safe parsers.
- `lib/alert.sh`: inline `_eb_load_alert_env()` parses `KEY=VAL` with bash
  regex `^([A-Z_][A-Z0-9_]*)=(.*)$`, strips quoted values, whitelist of
  permitted keys, uses `printf -v` (no eval).
- `edgeboxctl alert show`: replaced `source` subshell with `grep -qE`
  presence checks on whitelist of keys.

File format unchanged (still KEY=VAL .env), only reader logic changed.

### P1#5: reload_or_restart_services silently swallowed failures
Old code: `systemctl reload || systemctl restart; log_info "重启了"`. Even
if both failed, function returned 0 because `log_info` succeeded. Audit's
`cdn enable` nginx reload was the same pattern.

Fixed: function returns 1 if both reload AND restart fail, dumps last 20
lines of `systemctl status`. `cdn_enable` and `cdn_disable` nginx reload
calls now check return code and trigger `cdn_rollback` on failure.

### P1#8: No logrotate config — logs eventually fill disk
Xray access/error logs + nginx stream log + EdgeBox install/alert/edgebox
logs all written continuously. No `/etc/logrotate.d/edgebox` shipped.
Matches "service slowly degrades after months of uptime" failure pattern.

Fixed: install.sh `setup_logrotate()` writes `/etc/logrotate.d/edgebox`:
- `/var/log/xray/*.log` — daily, rotate 14, compress, postrotate reload xray
- `/var/log/nginx/stream.log` — daily, rotate 14, postrotate reload nginx
- `/var/log/edgebox*.log` + `/var/log/edgebox/*.log` — daily, rotate 14
Validates with `logrotate -d` syntax check. Wired into main().

### Upgrade preservation
Old `edgeboxctl upgrade` only preserved `server.json`. Re-install wiped
`cert_mode`, `alert.env` (Webhook/Token), `shunt/` config, and Let's Encrypt
cert symlinks. Domain-mode users would lose CDN state and need to re-enter
all alerting config.

Fixed: `edgeboxctl upgrade` now also stashes these to `/tmp/edgebox-keep-state/`
before bootstrap, and restores them after install completes. If `cert_mode`
indicates `letsencrypt:<domain>`, also re-links `current.pem`/`current.key`
to LE live cert and syncs `server.json.cert.{mode,domain,auto_renew}`.

`install.sh:execute_module2` also reads old `server.json`'s `cert`, `cdn`,
`reality.sni` fields when keep file exists, so newly-written `server.json`
retains these states.

### P2 cleanup
- sing-box version comment now explicit: "兼容性锁定 1.12.8" (client config
  still uses pre-1.13.0 schema)
- edgeboxctl: removed duplicate `log_info/log_warn/log_error/log_success`
  definitions at line ~397 (kept the originals at ~100)
- Distro support narrowed to Debian 11+/Ubuntu 20.04+. CentOS/RHEL/Rocky/
  AlmaLinux explicitly rejected with clear error (code hardcodes www-data,
  dpkg, modules-enabled — won't actually work on those distros)
- `setup_firewall_rollback` no longer called twice in main() (the inner
  configure_firewall already invokes it)
- `dashboard.html` "(80, 443, 2053)" → "(80, 443)"
- nginx.conf header updated v4.0.0 → v4.6.0-rc2; removed Trojan/gRPC
  comment in stream map
- Removed deprecated `location = /sub` (v3 era pre-token URL)

### Deferred (not in rc2)
- P1#6 HTTPS for dashboard/subscription (user accepted current HTTP +
  6-digit passcode + Cookie secret as the trade-off)
- P1#7 Chart.js/QRCode.js bundling (low priority; v4.7 target)

# Changelog

## v4.6.0-rc1 — Security audit fixes

External security audit identified 8 P0 issues. All fixed in rc1.

### P0 #1: Dashboard auth bypass + weak passcode
- `Cookie: ebp=1` was a literal compare — anyone could forge it without
  knowing the passcode. Fixed: cookie value is now a 64-hex random secret
  generated at install time, stored in `server.json:dashboard_cookie_secret`.
  Nginx maps `$cookie_ebp` to that secret, not `"1"`.
- Passcode generation was `$((RANDOM % 10))` repeated 6 times — only 10
  possible passwords. Fixed: 6 independent digits (10^6 possibilities).
- `edgeboxctl dashboard passcode` now also rotates the cookie secret,
  invalidating all old sessions.
- Install summary prints a security advisory recommending users change
  the default passcode immediately.

### P0 #2: alert.conf privilege escalation chain
Old: `alert.conf` contained Telegram Bot Token + webhook URLs, was
chmod 644 and chown www-data (web-readable), and was sourced by a
root cron via `lib/alert.sh`. Anyone who got the dashboard cookie
could read the tokens; anyone with www-data write could inject shell
into the file and get root execution.

Fixed: split into two files.
- `/etc/edgebox/config/alert.env` — secrets only (root:root 600,
  sourced by root cron, never web-accessible)
- `/etc/edgebox/traffic/alert-public.json` — thresholds only
  (web-readable, monthly_gib + steps, never secrets)

Both `traffic-alert.sh` and `edgeboxctl alert ...` rewritten to use
the split. `dashboard.js` reads `alert-public.json` instead of the
old conf. Old `alert.conf` is auto-deleted on upgrade.

### P0 #3: Domain mode + CDN mode WS routing broken
`generate_nginx_stream_map_conf()` declared a 2nd `$domain` parameter
but never used it. In domain/CDN mode, the user's domain was not
mapped to `websocket` backend — it fell through to `default reality`
and WS clients connected to the Reality port 11443, which silently
fails the WS handshake.

Fixed: function now takes mode (`ip`/`domain`/`cdn`) + domain, and
generates the right map for each. `cdn enable` and `switch_to_domain`
now both call it correctly.

### P0 #4: dashboard.json leaks Reality private key + jq syntax bug
`get_secrets_info()` in `dashboard-backend.sh` had broken jq (missing
comma before `master_sub_token` + trailing comma), so `.secrets` came
out as `{}` and the dashboard couldn't show UUIDs.

Fixed jq syntax. Also removed `private_key` from the output entirely
(NEVER ship Reality private key over HTTP), and removed v3 fields
(`grpc`, `tuic_uuid`, `password.trojan`, `password.tuic`).

### P0 #5: `main()` ignored critical failures
Many critical steps (`install_xray`, `configure_nginx`,
`generate_subscription`, etc.) had no return-code check. If they
failed, `main()` continued and printed "installation successful".

Fixed: every critical step now `|| { log_error ...; exit 1; }`.
`setup_certbot_renewal_hook` stays warning-only (self-signed mode
doesn't need it). Legacy `/sub` validation replaced with token-based
`/sub-<token>` check.

### P0 #6: `edgeboxctl update` was unusable
Old: ran `curl install.sh | bash` which (a) bypassed bootstrap
SHA256, (b) hit the non-interactive guard and exited, (c) had no
credential migration so all clients were broken on every upgrade.

Fixed: `edgeboxctl upgrade` now:
1. Creates `/root/edgebox-backup/upgrade-<ts>.tar.gz`
2. Copies `server.json` to `/tmp/edgebox-keep-server.json`
3. Calls `bootstrap.sh` with `EDGEBOX_UPGRADE=1`
4. `install.sh:execute_module2` detects the keep file and reuses
   ALL credentials (UUIDs, passwords, Reality keys, sub token)
5. If upgrade fails, prints manual restore instructions (backup
   path + tar command). No automatic rollback.

`install.sh` non-interactive guard now allows upgrade via
`EDGEBOX_UPGRADE=1` env var or `/tmp/edgebox-keep-server.json`
marker file.

### P0 #7: Version string scattered across the codebase
Some files said `4.6.0`, others `4.0.0`, others `4.6.0-batchD`.

Fixed: single source `ENV/VERSION`, all scripts now read or display
`4.6.0-rc1`. Banner text, server.json fallbacks, dashboard backend
defaults — all unified.

### P0 #8: sing-box client config compatibility
Client config emitted `{"type":"block","tag":"block"}` and
`{"type":"dns","tag":"dns-out"}` outbounds. sing-box 1.13.0
removed these.

Solution chosen: pin server to `sing-box 1.12.8` (existing
`DEFAULT_SING_BOX_VERSION` lock). Client config kept as-is.
README will document the version pin and reason.

### Audit #9: Permission inconsistencies
- `sing-box.json` was 644 (contains HY2 password) → now 600 root
- `server.json` was reset to 644 by `edgeboxctl alias` → now stays 600
- `NOBODY_GRP` variable typo (`nobody_group` used instead) → fixed
- Certificate dir now correctly applies the local variable

### Audit #10: Hysteria2 could reach private networks
HY2 sing-box config routed `127.0.0.0/8`, `10.0.0.0/8`, etc. to
`direct` outbound — i.e. HY2 clients could probe the server's
private network and cloud metadata endpoints.

Fixed: added `block` outbound and routed all RFC1918 + link-local
+ cloud metadata ranges (`100.64.0.0/10`, `169.254.0.0/16`) to it.
`final: direct` keeps normal egress.

### Audit #12: CDN mode false-alarmed monitor and dashboard
When CDN was enabled, Reality and HY2 were intentionally stopped,
but `protocol-health-monitor.sh` and `dashboard-backend.sh` still
checked all three protocols and reported Reality/HY2 as "down".

Fixed: both scripts now read `cdn.enabled` from `server.json`.
In CDN mode, only WS is checked/displayed; Reality/HY2 are marked
`"state": "disabled"` with explanation. No alerts emitted for
disabled protocols.

### v3 residue cleanup
- TUIC port 2053 references removed (DEFAULT_PORTS, PORT_TUIC,
  verify_port_listening, ufw, firewalld, nftables counter, debug-ports
  help text)
- TUIC_PARAMS array deleted
- `[tuic]` section in randomization.ini deleted
- `randomize_tuic_config()` deleted, traffic randomize medium/heavy
  no longer call it
- VLESS `grpc_services` array entry removed
- Trojan subdomain (`trojan.<domain>`) certificate request removed
- `dashboard.js` trojan/tuic link parsers removed
- `dashboard.js` protocol type map reduced to 3 protocols

### Files changed (17 manifest entries)
All updated with new SHA256 hashes in `bootstrap.sh`.

# Changelog

## v4.6.0 (Block 7) — Frontend extraction + v3 cleanup

- Extract CSS/JS/HTML from `install.sh` heredocs to `ENV/web/`:
  - `dashboard.css` (2568 lines)
  - `dashboard.js`  (1440 lines)
  - `dashboard.html` (442 lines)
- Generalize `_install_script` helper:
  - 3rd arg `<subdir>`: `scripts` (default) or `web`
  - 4th arg `<mode>`: `exec` (default, +x) or `data` (chmod 644)
  - 100% backward compatible — 2-arg calls unchanged
- Clean v3 residue in `edgeboxctl config show`:
  - Remove `VLESS gRPC UUID`, `TUIC UUID/password`, `Trojan password`
  - Fix `.uuid.vless` rendered as JSON object (jq path was wrong)
  - Add `Reality SNI` (reads real value from xray.json)
  - Add `WS path`
- Dashboard UI: `(6协议)` labels → `(3协议)`
- HTML copy: remove leftover TUIC mentions
- **install.sh: 10525 → 6079 lines (−4446)**

## v4.5.0-batchC (Block 6 Batch C) — edgeboxctl extraction

- Extract `edgeboxctl` (4097 lines) from a single giant heredoc into
  standalone `ENV/scripts/edgeboxctl` (no `.sh` extension)
- `_install_script` helper already worked with any basename — zero
  changes needed
- **install.sh: 14622 → 10525 lines (−4097)**

## v4.5.0-batchB2 (Block 6 Batch B2) — extract 5 small scripts

- Extract from heredocs to independent files:
  - `traffic-alert.sh` (82 lines)
  - `traffic-collector.sh` (77 lines)
  - `apply-firewall.sh` (87 lines)
  - `system-stats.sh` (58 lines)
  - `edgebox-init.sh` (45 lines)
- Deliberately keep `firewall_rollback.sh` inline (it's a 5-minute
  self-destructing install-time safety mechanism)
- **install.sh: 14976 → 14622 lines (−354)**

## v4.5.0-batchB1 (Block 6 Batch B1) — extract 4 large scripts

- Extract from heredocs to independent files:
  - `dashboard-backend.sh` (846 lines)
  - `protocol-health-monitor.sh` (426 lines)
  - `edgebox-traffic-randomize.sh` (373 lines)
  - `edgebox-ipq.sh` (271 lines)
- New `_install_script` helper: copies from bootstrap-downloaded files
  if `EDGEBOX_BOOTSTRAP_TMP` set, falls back to GitHub Raw download
- **Hotfix**: jq lexer can't handle nested `\"` inside `\(...)`
  interpolation. Fixed `WS_PATH=\(.ws.path // \"/ws\" | @sh)` →
  `WS_PATH=\((.ws.path // "/ws") | @sh)`. Removed cosmetic
  `[ERROR] 配置文件JSON格式错误或解析失败` at edgeboxctl startup.
- **install.sh: 16898 → 14976 lines (−1922)**

## v4.5.0-batchA (Block 6 Batch A) — bootstrap.sh + SHA256

- New `ENV/bootstrap.sh` is the user entry point. It:
  - Downloads `install.sh` + `lib/*` from GitHub
  - Verifies SHA256 of every file before running
  - Refuses to continue on mismatch with clear error
- `tools/gen-manifest.sh` regenerates SHA256 manifest before each release
- `EDGEBOX_SKIP_VERIFY=1` env var bypasses verification (with loud warning)
- Old `curl install.sh | bash` still works (no breaking change)

## v4.4.0 (Block 5) — CDN relay mode

- New `cdn` subcommand: `edgeboxctl cdn {status|enable <host>|disable|help}`
- When enabled:
  - Removes `vless-reality` inbound from `xray.json`
  - Stops + disables `sing-box` (CDNs don't proxy UDP)
  - Subscription contains **only** the WS-CDN URI; VPS IP never appears
- Prereqs: must already have Let's Encrypt cert for the CDN host
- Automatic snapshot + rollback on failure
- Cloudflare-specific (other CDNs work too if user knows what they're doing)

## v4.3.0 (Block 4) — Reality key rotation safety

- `rotate-reality` requires `--confirm` flag; bare call shows warning + exits 1
- `--force` alone shows legacy warning + 5-second countdown
- `rotate-sid` grace period: 24h → 168h (7 days)
- Removed duplicate `reality-status` branch (v3 bug)
- Cleaned more v3 fields from `load_config_once`

## v4.2.0 (Block 3) — Cron governance

- Cron tasks split into two files:
  - `/etc/cron.d/edgebox-default` — 4 read-only tasks (dashboard refresh,
    traffic collect, traffic alert, IP quality)
  - `/etc/cron.d/edgebox-optin` — 5 opt-in tasks, **default empty**
- User crontab is never touched
- New commands: `edgeboxctl cron {list|enable <name>|disable <name>}`
- `rotate-reality` permanently blacklisted from cron (only manual + `--confirm`)
- IPQ installer no longer writes to user crontab

## v4.1.0 (Block 2) — Health monitoring + alerting

- Default `HEALTH_MODE=monitor` (read-only). Old default was auto-repair
  which silently restarted services.
- Three-state UDP detection: `HEALTHY` / `LISTENING_UNVERIFIED` / `DOWN`
- State-change-only alerting: don't spam on every check
- New `lib/alert.sh` with channels: Telegram, Discord, WeChat (PushPlus),
  generic Webhook (raw/slack/discord formats)
- New commands:
  - `edgeboxctl monitor {status|mode|test|logs}`
  - `edgeboxctl alert {status|silence|unsilence|...}`

## v4.0.0 (Block 1) — 3-protocol architecture

- Remove protocols: VLESS-gRPC, Trojan-TLS, TUIC
- Keep: VLESS-Reality, Hysteria2, VLESS-WS
- New `lib/common.sh` and `lib/subscription.sh` (independent files)
- Subscription generator emits 4 formats (plain / base64 / Clash / sing-box)
- Atomic subscription publish (all 4 formats or none)

## v3.0.0 (legacy starting point)

- 6 protocols, monolithic install.sh (17260 lines / 612 KB)
- Health monitoring auto-repairs by default
- All cron in user crontab
- No file integrity verification
