# EdgeBox v4.7.0

**Stable** — security-hardened, 4 audit rounds cleared.
See `CHANGELOG.md` for the full audit log.

Multi-protocol proxy node manager with health monitoring and a modular
installer.

> **v4.7.0 note — CDN / WS removed.** Earlier releases shipped an optional
> Cloudflare CDN relay (via a VLESS-WS inbound) that could front the VPS IP.
> That path is **gone** in v4.7.0: the deployment is now a single box running
> Reality (TCP/443) + Hysteria2 (UDP/443) only. Because both protocols connect
> clients directly to the server, **the VPS IP is always visible to clients**;
> there is no longer any IP-hiding layer. If you need to mask the origin IP,
> put your own CDN/proxy in front out-of-band.

## Compatibility note

This release pins `sing-box` to **1.12.8** on the server side. The
subscription generator emits client configs using the pre-1.13.0 schema
(rule actions such as `hijack-dns` / `reject`). Upgrading the server past
1.12.x without first migrating the client config schema will break clients.

## Quick install

```bash
curl -fsSL https://raw.githubusercontent.com/cuiping89/node/main/ENV/bootstrap.sh | bash
```

The bootstrap downloads `install.sh`, `lib/*`, `scripts/*`, and `web/*` from
GitHub and verifies the SHA256 of every file before running anything.

## Architecture

Two protocols on a single box:

- **VLESS-Reality** (TCP/443) — daily-driver, direct
- **Hysteria2** (UDP/443) — QUIC alternative, direct

Both connect clients straight to the VPS, so the server IP is exposed by
design. nginx owns TCP/443 via `ssl_preread` and routes Reality SNIs to the
Xray backend; Hysteria2 runs on UDP/443 directly through sing-box.

The control dashboard is served over **HTTPS on port 8443** (`https://<ip>:8443/traffic/`).
In IP mode this uses a self-signed cert (browser warning is expected; traffic is
still TLS); after `edgeboxctl switch-to-domain <domain>` it automatically switches
to the Let's Encrypt cert with no config change. Port 80 keeps the subscription
endpoint (`/sub-<token>`, plaintext — client apps fetch self-signed HTTPS
unreliably) and 301-redirects any dashboard hit to 8443.

## Repository layout

```
ENV/                            # Production code (downloaded by users)
├── bootstrap.sh                # Entry point, fetches everything via SHA256
├── install.sh                  # Installer (~6000 lines)
├── lib/
│   ├── common.sh               # Shared helpers + path constants
│   ├── alert.sh                # Notification channels (TG/Discord/wechat/webhook)
│   └── subscription.sh         # 4-format subscription generator
├── scripts/                    # Runtime helpers (installed to /etc/edgebox/scripts/)
│   ├── edgeboxctl              # Management CLI (~4000 lines)
│   ├── dashboard-backend.sh    # Dashboard data collector
│   ├── protocol-health-monitor.sh
│   ├── edgebox-ipq.sh          # IP quality scoring (installs to /usr/local/bin/)
│   ├── edgebox-traffic-randomize.sh
│   ├── traffic-alert.sh
│   ├── traffic-collector.sh
│   ├── apply-firewall.sh
│   ├── system-stats.sh
│   └── edgebox-init.sh
└── web/                        # Dashboard frontend (served from /etc/edgebox/traffic/)
    ├── dashboard.html
    ├── dashboard.css
    └── dashboard.js

tools/                          # Developer tools (not downloaded)
└── gen-manifest.sh             # Regenerates SHA256 manifest in bootstrap.sh
```

## Releasing

After any change to `ENV/*`:

```bash
bash tools/gen-manifest.sh
git diff ENV/bootstrap.sh
git commit -am "Update manifest"
git push
```

If you skip this step, the next install will fail SHA256 verification.

To bypass verification for testing:

```bash
EDGEBOX_SKIP_VERIFY=1 bash <(curl -fsSL <bootstrap.sh URL>)
```

## Commands

After install, `edgeboxctl` is the entry point for everything.
Run `edgeboxctl` with no args for the full help menu.

Common commands:

| Command | Purpose |
|---|---|
| `edgeboxctl status` | Service + port health |
| `edgeboxctl sub` | Subscription URLs |
| `edgeboxctl monitor status` | Protocol health summary |
| `edgeboxctl cron list` | Cron tasks (default + opt-in) |
| `edgeboxctl alert status` | Alert system + recent events |
| `edgeboxctl switch-to-domain <d>` | Get Let's Encrypt cert |
| `edgeboxctl config show` | UUIDs, passwords, SNI |
| `edgeboxctl rotate-reality --confirm` | Manual Reality key rotation |
| `edgeboxctl backup create` | Snapshot config |

See `CHANGELOG.md` for the full history of changes from v3 to v4.6.
