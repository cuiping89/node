# EdgeBox v4.6.0-rc3

**Release candidate** — 3rd security audit (P1 + P2) completed.
P1 fixes applied; awaiting real-VPS verification.
See `CHANGELOG.md` for the full list.

Multi-protocol proxy node manager with CDN relay, health monitoring,
and modular installer.

## Compatibility note

This release pins `sing-box` to **1.12.8** on the server side. The
subscription generator emits client configs using the pre-1.13.0 schema
(`block` and `dns-out` outbounds). Upgrading the server past 1.12.x
without first migrating the client config schema will break clients.

## Quick install

```bash
curl -fsSL https://raw.githubusercontent.com/cuiping89/node/main/ENV/bootstrap.sh | bash
```

The bootstrap downloads `install.sh`, `lib/*`, `scripts/*`, and `web/*` from
GitHub and verifies the SHA256 of every file before running anything.

## Architecture

Three protocols:

- **VLESS-Reality** (TCP/443) — daily-driver, direct
- **Hysteria2** (UDP/443) — QUIC fallback
- **VLESS-WS** (TCP/443) — CDN-ready fallback

Optional CDN relay (Cloudflare) hides the VPS IP entirely; subscription
contains only the CDN-fronted WS URI.

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
| `edgeboxctl cdn status` | CDN relay mode state |
| `edgeboxctl cdn enable <host>` | Switch to CDN mode |
| `edgeboxctl cron list` | Cron tasks (default + opt-in) |
| `edgeboxctl alert status` | Alert system + recent events |
| `edgeboxctl switch-to-domain <d>` | Get Let's Encrypt cert |
| `edgeboxctl config show` | UUIDs, passwords, SNI |
| `edgeboxctl rotate-reality --confirm` | Manual Reality key rotation |
| `edgeboxctl backup create` | Snapshot config |

See `CHANGELOG.md` for the full history of changes from v3 to v4.6.
