# Changelog

## v4.7.0 — CDN/WS removal + security-hardening pass

### 抗 GFW / 大陆监控 加固 (审计 follow-up)

针对 GFW 主动探测 / DPI / 审查 / 取证 威胁模型的一轮加固，详见
`SECURITY-AUDIT-GFW-v4.7.0.md`。本轮实现 4 项：

- **H-1　80 端口不再明文提供订阅。** 明文订阅在墙内被拉取会把整份节点凭据
  (IP/UUID/Reality公钥+shortId/HY2密码/SNI) 暴露给 GFW 的 DPI。nginx 80 块
  改为：仅保留 `/.well-known/acme-challenge/`（兼容 webroot/--nginx 续期）与
  明文 `/health`，其余 (`/sub-*`、`/share/`、`/traffic/`、`/status/`) 一律 301
  跳 `https://$host:8443`。域名模式下订阅经有效证书的 HTTPS 提供，GFW 读不到。
- **H-2　Hysteria2 启用 Salamander obfs。** 此前全程无混淆，QUIC 握手可被 DPI
  指纹化。新增服务端 `obfs:{type:salamander,password:<hex16>}`；口令纳入
  `server.json` (`.password.hysteria2_obfs`)、随 UUID/密码一同生成与升级保留
  （旧版本升级会生成新口令）；订阅三格式 (plain URI / Clash / sing-box) 同步
  带 obfs 参数。**两端口令必须一致 → 客户端需重新导入订阅。**
- **M-3　masquerade 写进基础配置。** 此前 masquerade 仅由 randomize cron 注入，
  安装到首次 cron 之间 HY2 对主动探测会露馅。现基础配置即带
  `masquerade:"https://www.bing.com"`（cron 仍在站点池内轮换，原地改、保留 obfs）。
- **M-2　nginx 访问日志匿名化。** `log_format` 去掉 `$remote_addr` / `$remote_user`
  / referer / UA，仅留方法/路径/状态/字节。服务器被查封/镜像时不再暴露
  "哪些客户端 IP 访问过本节点"。

未实现（需客户端协调 + 防火墙变更，按需再做）：M-1 HY2 端口跳跃。
固有权衡（非 bug）：Reality SNI 与 IP 归属错配、默认 SNI 偏流行。

Files: `install.sh` (nginx 80/log + HY2 obfs/masquerade + obfs 密钥管理),
`lib/subscription.sh` (三格式 obfs), `lib/common.sh` (`eb_get_hy2_obfs`),
`uninstall.sh` (systemd unit 检查 SIGPIPE 修复).


Single-box topology change plus a security review of the v4.7.0 tree.
Seven issues fixed, ranked below by IP-exposure / privacy risk rather than
by a formal P1/P2 audit grade.

### Architecture change: CDN / VLESS-WS removed

The optional Cloudflare CDN relay and the VLESS-WS inbound are gone.
Deployment is now a single box running **VLESS-Reality (TCP/443)** +
**Hysteria2 (UDP/443)** only. nginx owns TCP/443 via `ssl_preread`
(single-level SNI routing → Reality); HY2 runs directly on UDP/443 via
sing-box. The `edgeboxctl cdn` subcommand and the WS stream/HTTP routing
were removed.

**Privacy consequence (documented, not a bug):** both protocols connect
clients directly to the server, so the VPS IP is exposed to clients by
design. There is no longer an IP-hiding layer. README updated to say so.

### Security findings fixed

#### 1 (HIGH): reverse-SSH lifeline leaked operator IP + auto-enabled
`install.sh` ran `ensure_reverse_ssh` unconditionally during install, and
`auto_detect_reverse_ssh_params` had a fallback that grabbed the current
SSH client IP (`SSH_CONNECTION`) — i.e. the operator's home/office public
IP — wrote it into `/etc/edgebox/reverse-ssh.env`, and set up a persistent
`Restart=always` reverse tunnel back to it. The env file was written with
no explicit mode (inherited umask → typically 644, world-readable). For an
anonymity-oriented proxy this links the operator's real IP to the VPS.

Fixed:
- Removed the `SSH_CONNECTION` → client-IP fallback entirely. Only explicit
  config is honored now (env file, or `~/.ssh/config` bastion aliases).
- Feature is now **opt-in**: `ensure_reverse_ssh` / `install_reverse_ssh_unit`
  return early unless `EB_RSSH_ENABLE=1` (env var or in reverse-ssh.env).
  Default installs do **not** set up any reverse tunnel.
- `reverse-ssh.env` now `chmod 600`.

#### 2: client subscription DNS leak
The generated client sing-box config (`lib/subscription.sh`) used
`dns.rules: [{ outbound: "any", server: "local" }]` with the `local` server
on `detour: "direct"`. Result: DNS queries bypassed the tunnel and went from
the client's real IP to its local/ISP resolver — the ISP could see every
domain queried. (The defined `tls://8.8.8.8` server was never reached
because the catch-all rule sent everything to `local`.)

Fixed: DNS now resolves through the tunnel —
- `proxy-dns` = `tls://8.8.8.8` with `detour: "EdgeBox"` (queries egress at
  the VPS).
- `direct-dns` = `local`/`direct`, used **only** for the server's own
  endpoint (`dns.rules: [{ domain: [$host], server: "direct-dns" }]`) to
  avoid a resolution loop in domain mode. Inert when `$host` is an IP.
- `dns.final: "proxy-dns"` so everything else goes through the tunnel.
- Fails closed (no DNS if tunnel down) — correct for a privacy tool.

#### 3: server logs recorded client IP + destinations
xray `loglevel: "info"` with `access: /var/log/xray/access.log`, and
sing-box `level: "info"`, logged per-connection source IP + destination to
disk on the VPS (14-day retention). On seizure/compromise that's a
"who-from-where-to-what" record.

Fixed (`install.sh`): xray → `"access": "none"`, `"loglevel": "warning"`;
sing-box server → `"level": "warn"`. Client config log also lowered to
`warn`. Error logs retained for debugging.

#### 4: install.sh `eval` lacked `@sh` quoting
The server.json variable-reload `eval` in `install.sh` interpolated values
without `@sh` (unlike the already-fixed `edgeboxctl` path). Low severity
(values are self-generated, polluting server.json needs root) but an
inconsistency / defense-in-depth gap.

Fixed: all five interpolated fields now use `| @sh`. Verified that a value
containing shell metacharacters is neutralized.

#### 5: dashboard passcode was 6-digit numeric
Default passcode space was 10^6 (brute-forceable), and a degenerate fallback
generated a single digit repeated six times. The `edgeboxctl dashboard
passcode` reset command also hard-required `^[0-9]{6}$`.

Fixed:
- Default is now 12 chars `[a-z0-9]` from `/dev/urandom` (~62 bits).
  Restricted to alphanumerics to avoid URL / nginx-map quoting issues.
- Degenerate single-digit fallback replaced with the same 12-char CSPRNG.
- `update_dashboard_passcode` relaxed to accept `^[A-Za-z0-9]{6,64}$`
  (still backward-compatible with old 6-digit passcodes) and auto-generates
  12 chars when left blank. Help text updated.

#### 6: README claimed CDN hides the VPS IP (stale)
README still advertised "Optional CDN relay (Cloudflare) hides the VPS IP
entirely" and listed `edgeboxctl cdn` commands + a VLESS-WS protocol — all
removed in v4.7.0. Updated header to v4.7.0, fixed the architecture section,
removed the stale `cdn` command rows, and corrected the sing-box schema note.

#### 7: install summary claimed switch-to-domain gives dashboard HTTPS (false)
The post-install security reminder told users to run `switch-to-domain` for
HTTPS — but that cert only serves Reality/HY2; the dashboard and subscription
stay on plaintext HTTP/80 regardless. Replaced with accurate guidance (see #8,
which actually adds the HTTPS path).

#### 8: HTTPS dashboard on 8443 (self-signed in IP mode, real cert in domain mode)
Follow-up to #3/#7: instead of leaving the dashboard on plaintext HTTP, added
a dedicated `listen 8443 ssl` server block in `configure_nginx`. It can't go on
443 (the stream module owns 443 via `ssl_preread`), so 8443 is the HTTPS entry.

- **Cert source** is the `/etc/edgebox/cert/current.pem|key` symlink pair:
  self-signed in IP mode (browser warns, click through — traffic is still TLS),
  Let's Encrypt in domain mode.
- **Forward-compatible:** `switch-to-domain` only repoints those symlinks +
  reloads nginx; it does not rewrite `nginx.conf`. So the 8443 block
  automatically serves the real cert after a domain switch, no edits needed.
- **Port 80 dashboard is now HTTPS-only:** `/` and `/traffic/` on :80 return
  `301` to `https://$host:8443/...`. Plaintext dashboard is gone.
- **Subscription stays on HTTP/80** (`/sub-<token>`): client apps (Clash Verge,
  Shadowrocket) fetch self-signed HTTPS unreliably, so the subscription endpoint
  is intentionally left on 80. The 8443 block also serves `/sub-*` for browser
  fetches. Subscription content is credentials — don't share the link.
- **Cookie hardening:** the dashboard session cookie now carries `Secure`, so
  browsers only send it over HTTPS — closes plaintext cookie sniffing on :80.
- Firewall opens `8443/tcp` (install.sh port set + apply-firewall.sh for
  ufw/firewalld/iptables). All user-facing dashboard URLs (install summary,
  `edgeboxctl sub`, health check) updated to `https://<ip>:8443/traffic/`.
- Validated with `nginx -t` on the generated config (syntax OK; the only
  sandbox error was lack of IPv6 for the `[::]` listen, irrelevant on a real VPS).

### Not changed (architectural tradeoffs, documented not patched)

- **Subscription endpoint on plaintext HTTP/80.** Kept deliberately — client
  apps don't reliably accept self-signed HTTPS for subscription import. Fetch it
  once and paste, or rely on token secrecy + rotatable credentials. (The
  *dashboard* is now HTTPS-only on 8443; only the subscription stays on 80.)
- **HY2 `insecure=true` in IP mode.** Inherent to self-signed certs; only
  domain mode (real cert) removes the MITM exposure on the HY2 channel.
  Reality is unaffected (own X25519 auth). Decision: keep HY2 + accept the
  low-probability active-MITM risk on that one channel in exchange for the
  QUIC fallback; domain mode closes it cleanly later.
- **VPS IP exposed to clients.** By design after CDN/WS removal (see above).

### Files changed + hashes

| File | sha256 |
|---|---|
| install.sh | 051c015245cb7337c1a5cbeed62dcd136136b17d051d3ee5312f5cefa8b98454 |
| lib/subscription.sh | ab9364aabd76fa0d25ab504c0b45485da9368c8d553f3128759e100fe485d0e7 |
| scripts/edgeboxctl | 7da1b883fb1799b699954727c08e64cfbccb06c23e0b88db81de60299ac49a05 |
| scripts/apply-firewall.sh | f36170b7e5e8caf727d5c83198391ca1db23b654b34999443facafc4bbed29b9 |

Docs also updated (not hash-tracked): `README.md`, `CHANGELOG.md`.
Run `bash tools/gen-manifest.sh` after these edits (already done for this
release) and commit `ENV/bootstrap.sh` in the same commit.

### Post-upgrade verification (suggested)
- dashboard reachable at `https://<ip>:8443/traffic/?passcode=...` (self-signed
  warning in IP mode is expected)
- `http://<ip>/traffic/` returns `301` to the 8443 HTTPS URL
- `grep loglevel /etc/edgebox/xray.json` → `warning`
- `systemctl status edgebox-reverse-ssh` → inactive / not-found on default installs
- re-pull subscription → client sing-box DNS shows `proxy-dns` + `dns.final`
- `ufw status | grep 8443` → 8443/tcp ALLOW

---

### Dashboard data fixes (follow-up)

Two display bugs surfaced after upgrading a ~1GB GCP VM to v4.7.0:

#### Memory shown as "0GiB"
`get_memory_info` (install.sh) computed `total_kb / 1024 / 1024` with **integer
division**, so any host with < 1024 MiB-rounding RAM (e.g. a 1GB GCP e2-micro,
MemTotal≈1009136 kB → 0) displayed "0GiB". Swap at exactly 1 GiB still showed
"1GiB", hence "0GiB + 1GiB Swap". `.spec.memory` is only written at
install/upgrade, so the value reappeared each time `edgeboxctl upgrade` re-ran
the detection — explaining the "fixed yesterday, broke today" intermittency.

Fixed: compute one-decimal GiB via awk (`%.1f`), so a 1GB box shows "1.0GiB".

#### Traffic spike of hundreds of GiB in a single day
`traffic-collector.sh` derives daily traffic as `tx_bytes − PREV_TX`. Its
guard only clamps counter *rollback* (cur < prev → 0); it did **not** guard the
*first-run / no-baseline* case. When the state file is absent — which happens
right after the v4.6.0 path migration (`.state` → `/var/lib/edgebox/traffic.state.json`)
or if it's wiped — `PREV_TX` defaults to 0, so the first delta records the
entire since-boot `tx_bytes` (hundreds of GiB on a long-lived VM) as one day's
traffic. This is why May tracked normally (~48 GiB) but June showed a ~575 GiB
single-day spike right after the upgrade.

Fixed: added a `HAVE_PREV` flag set only when a numeric `PREV_TX` is
successfully read. Missing/corrupt/non-numeric state → treat as first run:
establish the baseline from current counters and record **0** deltas for that
interval. Normal delta accounting resumes on the next run.

**One-time data cleanup required** (the fix prevents recurrence but doesn't
retroactively remove the bad row). Zero the spike day in
`/etc/edgebox/traffic/logs/daily.csv`, then re-run `traffic-collector.sh` +
`dashboard-backend.sh --now` to regenerate `monthly.csv` / `traffic.json`.

Files changed: `install.sh`
(`45dcd6aeee7bc153b0bdfe7ba4bf1f8d27afa8a359134de9fb18816625b080c5`),
`scripts/traffic-collector.sh`
(`0de953573e69578a9ab2fd48dd6ba4cc94cb2f9c40e0b4854691040015e009cd`).

---

## v4.6.0-rc4 — 4th security audit fixes (8 P1 + 7 P2)

The 4th audit was the most rigorous yet — auditor ran actual commands and
checked exit codes, found that **nearly every CLI command was returning 0
on failure**. Fixed all 8 P1 + 7 P2 items.

### P1#1: Wrong xray validation command
`cdn_modify_xray` used `xray test -c FILE` — but Xray has no `test`
subcommand; it's `xray -test -format json -c FILE`. CDN enable silently
failed at validation.

Fixed: `/usr/local/bin/xray -test -format json -c "$tmp"` matches all
other call sites.

### P1#2 (CRITICAL): Exit code propagation broken across entire CLI
The biggest finding. Old script structure:
```
case "$1" in ... esac        # case branches with return 1
if [[ BASH_SOURCE... ]]      # ← this runs AFTER case
    load_config_once         # ← this returns 0
fi                           # ← script exits 0
```

Bash exit code = last command. So ANY `edgeboxctl <cmd>` that called a
function returning 1 would still exit 0. Auditor verified with 5 commands:
- `edgeboxctl cdn enable invalid.example` → echo $? = 0 (BUG)
- `edgeboxctl switch-to-domain invalid.invalid` → 0 (BUG)
- `edgeboxctl config regenerate-uuid` → 0 (BUG)
- `edgeboxctl backup restore /nonexistent/file` → 0 (BUG)
- `edgeboxctl sni set invalid.invalid` → 0 (BUG)

Plus 4 case branches had unconditional `exit 0 ;;` at the end (cdn, monitor,
cron, shunt) that swallowed all sub-command failures.

Fixed:
- Config loading moved BEFORE `case` (top of dispatch section)
- After `esac`: explicit `exit "$?"` captures case's last command rc
- All 4 `exit 0 ;;` removed — replaced with plain `;;` to let function rc flow

### P1#3 (CRITICAL): regenerate_uuid completely unsafe
Old version:
- Wrote `server.json`/`xray.json`/`sing-box.json` via tmp+mv, no `chmod 600` after
- No `xray -test` before activation → bad JSON would crash the service
- `systemctl reload || true` swallowed reload failures
- `eb_gen_subscription` return value ignored

Net result: one bad invocation could leave server.json/xray.json world-readable
(leaking Reality private key), or push broken JSON live with no way to recover.

Fixed: complete rewrite —
1. Build candidate configs in `mktemp` under `umask 077`
2. Validate xray.json with `xray -test -format json -c`
3. Validate sing-box.json with `sing-box check -c`
4. Atomic-replace via `install -o root -g root -m 600` (NEVER mv)
5. `systemctl reload` rc check; failure → restore backup, retry reload
6. `eb_gen_subscription` rc check
7. Force-arg accepts `"true"`, `"force"`, `--force`, OR numeric (for back-compat
   with old `sub_revoke` callers that pass `0` / `24`)

### P1#4: sub revoke --force never actually forced
Two bugs:
- `regenerate_uuid` checked `$1 == "true"` but caller passed `regenerate_uuid 0`
- Documentation said "用户已保存的 Reality 私钥" — clients have the **public** key
  (pbk), private key only lives in server's xray.json

Fixed: regenerate_uuid now accepts numeric force values; sub_revoke calls
`regenerate_uuid true` and checks return code; doc updated to "Reality 公钥 (pbk)".

### P1#5: cdn_rollback always reported success
`cdn_rollback` had 6 `|| true`'s and unconditionally logged "回滚完成" at the end.
If anything failed, caller couldn't tell.

Plus `cdn_enable` had no post-enable verification — would log success even if
sing-box was still running or UDP/443 was still listening.

Fixed:
- `cdn_rollback` accumulates failures in `_rb_rc` array, returns 1 if any fail
- `cdn_enable` post-state verification: sing-box must be inactive, UDP 443
  must NOT be listening, port 10086 (WS backend) must be listening,
  nginx + xray must be active. Failed verification → auto rollback.

### P1#6: switch-to-domain/switch-to-ip ignored critical failures
Multiple unchecked calls (`generate_nginx_stream_map_conf`, `reload_or_restart_services`,
`regen_sub_domain`, `fix_permissions`). Server could end up with server.json
saying "domain mode" while nginx map was still IP mode.

Fixed: every critical step now checked with `if ! ... then return 1`. Both
functions also validate domain format via `eb_is_valid_domain` if available.

### P1#7: Upgrade declared success after topology restoration failure
After install.sh ran during upgrade, we re-apply CDN / domain topology. Old
code: failures only `log_warn`, then unconditionally printed "✅ 升级成功".

Fixed: `_topology_rc` tracks any topology restoration failure. If non-zero,
print "❌ 升级完成但拓扑恢复失败" and propagate rc=1 to script exit.

### P1#8: Reality key/SID rotation lacked candidate validation
`update_xray_reality_keys` / `update_server_reality_keys` had no rc checks.
`rotate_reality_sid_graceful` wrote via tmp+mv without xray -test. Broken
JSON would only be caught at xray reload time.

Fixed: both helper functions now mktemp + jq + xray -test + install -m 600,
and return real rc. `rotate_reality_keys` checks both helpers' rc, restores
from `xray_backup_${ts}.json` + `server_backup_${ts}.json` on failure.
SID rotation same pattern: candidate xray.json validated before write.

### P2#1-7 cleanup
- `sub_db_apply` uses `install -m 600` instead of mv (preserves perms on users.json)
- `ensure_sub_dirs` sets 700 root:root on sub dir, 600 root:root on users.json
- Device stats uses gawk explicitly (match() 3-arg is gawk-specific)
- ipq.sh VPS view unsets `http_proxy/HTTPS_PROXY/...` env vars before curl,
  passes `--noproxy '*'` for belt-and-suspenders
- cdn_enable validates host via eb_is_valid_domain
- Removed duplicate function definitions: `get_server_info` (was defined twice,
  the second override was a less-validated wrapper), `ensure_traffic_dir`,
  `build_sub_payload`
- backup_create returns non-zero on tar failure (was log_error only)

### Hash matrix
| File | sha256 |
|---|---|
| install.sh | daeb99f86867de229bcebdf0f49e1c530e36b649bc8ccc17cae6f30c1a22d06e |
| edgeboxctl | b0be866204cd1392c8a669367c4001d37b711513802bea1a8fcf1a3be65b39a8 |
| edgebox-ipq.sh | d2b8b42cac18f76ac7d5b492b2a915720a61d4575fefd5e6fca6d17d6825d84c |


## v4.6.0 — stable release (security-hardened, 3-round audit cleared)

**Released**: 2026-06-04

Real-VPS verified on Debian 12 + RackNerd. All 11 P1 + P2 findings from the
3rd audit fixed (incl. critical root-privilege-escalation chain via traffic
state file).

Three audit rounds, 27 total findings, all closed.

### Verification matrix (real VPS, IP mode)
| Check | Result |
|---|---|
| `.state` no longer in www-data writable area | ✅ `/var/lib/edgebox/traffic.state.json` root 600 |
| `traffic-collector.sh` source/eval-free | ✅ JSON + jq + regex validation |
| `/etc/edgebox/traffic` ownership | ✅ root:root 755 |
| logrotate dash compatibility | ✅ `[ -x ]` only |
| SNI grace cleanup creates xray.json 600 | ✅ umask 077 + install -m 600 |
| `rotate-sid` creates real systemd timer | ✅ `edgebox-sid-cleanup-XXXXXX.timer` |
| ipq.sh has zero `eval` | ✅ |
| Subscription has 3 valid share_links | ✅ 235/136/218 chars |
| nginx + xray + sing-box active | ✅ |
| `edgeboxctl help` clean | ✅ |
| `cert/` 750 root:nogroup | ✅ |

### Detailed change log (rc1 → rc2 → rc3 → stable)

## v4.6.0 — 3rd security audit fixes

Third audit pass found 11 issues including 1 root-privilege-escalation chain.
All fixed.

### P1#1: traffic state file privilege escalation chain (CRITICAL)
The most serious finding. Chain:
- `install.sh:setup_traffic_monitoring` did `chown -R www-data:www-data /etc/edgebox/traffic`
- `traffic-collector.sh` had `STATE="/etc/edgebox/traffic/.state"` and `. "$STATE"`
- traffic-collector runs as root via cron

Net result: www-data could write `/etc/edgebox/traffic/.state` with any shell
commands; root cron would source it next run; arbitrary root command execution.

Fixed:
- State file moved to `/var/lib/edgebox/traffic.state.json` (root:root 600)
- Format changed to JSON, read via `jq -r` with bash regex validation
  (`^[0-9]+$`) — never `source`/`eval`d
- `/etc/edgebox/traffic` now owned `root:root 755`. Nginx alias reads via
  filesystem permissions (root 644 files), no longer needs ownership.
- Legacy `/etc/edgebox/traffic/.state` deleted on upgrade.

### P1#2: logrotate postrotate used bash-only `[[`
`/etc/logrotate.d/edgebox` ran `if [[ -x /usr/local/bin/xray ]]` in postrotate,
but logrotate invokes via `/bin/sh` which on Debian/Ubuntu is dash. dash doesn't
support `[[ ]]`. Failure was silent; Xray would keep writing to renamed old
logs after rotation.

Fixed: changed to POSIX `if [ -x ... ]`.

### P1#3: SNI grace cleanup left xray.json 644
The `update_sni_domain` grace cleanup payload (scheduled via systemd-run) wrote
`${cfg}.tmp` then `mv $tmp $cfg`. mktemp's default umask 022 produced 644; mv
preserves that. Xray.json contains Reality private key — leaking it to all
local users.

Fixed: payload now uses `umask 077` + `mktemp /tmp/xray.sni-grace.XXXXXX` +
`install -o root -g root -m 600` for atomic-replace with correct perms.

### P1#5: `sub revoke` made misleading promises
Old: `sub revoke` claimed "其他用户无影响". But ALL users share the same
Reality/HY2/WS credentials. Revoking a subscription URL only removes the
download link; that user's already-imported client config keeps working
forever because the protocol UUIDs/passwords don't change.

Fixed: revoke now prints a clear warning that revoking the URL ≠ revoking
the credentials; explains `--force` will rotate global creds (affecting all
users). `sub limit` similarly clarifies the limit is a soft cap / display
indicator, not a hard enforcement (Reality/HY2/WS don't support per-user
connection-count limits).

### P1#6: device stats searched wrong path AND had read-loop bug
- Path: `sub_scan_devices` grepped `/sub/u-<token>` but actual URL is
  `/share/u-<token>` → 0 matches always
- awk output: 4 tab-separated columns; read consumed 5 (`t ip _ uri ua`)
  with the `_` discard between ip and uri → uri was always empty,
  every line skipped

Fixed: grep `/share/u-` + read aligned to 4 columns (`t ip uri ua`).

### P1#7: rotate-sid never created the promised timer
SID rotation echoed "已安排 ${grace_hours}h 后清理旧 SID …systemd-run 持久定时器"
but the timer creation block was just a placeholder comment:
`# ... (at command scheduling) ...`. Old SIDs accumulated forever.

Fixed: real `systemd-run --unit=edgebox-sid-cleanup-<sid>-<ts>
--on-active=<N>h --timer-property=Persistent=true --property=Type=oneshot`
that runs the cleanup payload (umask 077, install -m 600, xray reload).
Persistent=true ensures it fires even if VPS is offline at scheduled time.

### P1#8 (a/b/c): CDN state management
**(a)** `xray.json.template` was saved only the first time CDN was enabled —
could be months stale by the time of disable. Disable would restore the
ancient config, wiping any subsequent SNI/key/shunt changes.

Fixed: every `cdn enable` now refreshes the template.

**(b)** `cdn_backup` saved configs but NOT the nginx stream map. If enable
failed after stream map rewrite, rollback restored configs but left CDN
routing in place.

Fixed: cdn_backup snapshots `/etc/nginx/conf.d/edgebox_stream_map.conf`;
cdn_rollback restores it.

**(c)** `cdn_disable` silently ignored sing-box start failure and xray
reload failure (`|| true`). Could report success while HY2 stayed down.

Fixed: both now error + rollback on failure with `systemctl status` dump.

### P1#9: upgrade overwrote running topology for domain/CDN nodes
Upgrade preserved configs (server.json/cert_mode/alert.env/shunt) but
install.sh always sets up direct IP-mode topology (Reality+HY2+WS, IP-mode
stream map). After upgrade of a CDN node:
- server.json said cdn.enabled=true
- xray.json had Reality back in
- sing-box was running
- stream map was IP-mode
- subscription was IP-mode

Fixed: upgrade restoration step reads `cdn.enabled` and `cert.mode` from the
keep file, then:
- CDN mode → re-runs `cdn_enable <was_host>` (stops sing-box, strips Reality,
  rewrites map, regens CDN subscription)
- Domain mode → restores LE cert symlinks, rewrites stream map for domain,
  regens domain-mode subscription, reloads services
- IP mode → default install topology, no extra work

### P1#10: traffic randomization restarted sing-box in CDN mode
The `edgebox-traffic-randomize.sh` cron task always restarted sing-box,
re-exposing HY2 even when CDN mode was enabled (HY2 should be off in CDN).

Fixed: script now reads `server.json.cdn.enabled` first and exits 0
immediately if true (with logged explanation).

### P1#11: edgebox-ipq.sh `eval` everywhere
3 sites: bandwidth test download, bandwidth test upload, proxy latency test —
all built `curl $proxy_args …URL` as a string and ran via `eval`. Proxy URL
or password containing `&` `#` space `'` etc. would either truncate the URL
or worse, execute embedded shell commands (root cron).

Fixed: introduced global `PROXY_ARGS=()` bash array. `build_proxy_args` now
populates the array instead of returning a string. `test_bandwidth_correct`
and latency check use `curl "${PROXY_ARGS[@]}" …`. `curl_json` rewritten to
accept array form. Zero remaining `eval` in this script.

### P2 cleanup
- `fix_permissions` cert dir: 755 root:root → 750 root:nogroup (matches
  `setup_directories` initial perms, eliminates inconsistency)
- All version strings → 4.6.0

### What's still kept (with caveats)
- `sub issue / revoke / limit / stats` features kept but README + CLI output
  now clearly state these are "subscription URL management" + "soft caps for
  display" — NOT enforced quotas, NOT independent per-user credentials.
- Bandwidth test in ipq still hits public endpoints (tele2/httpbin) —
  could be disabled in v4.7 if those endpoints become unreliable.

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
