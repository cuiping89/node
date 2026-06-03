# EdgeBox Changelog

## v4.0.0 - Three-Layer Architecture (Block 1)

**Release date**: TBD
**Breaking change**: Yes - protocol set and subscription format changed.

### Summary

EdgeBox v4.0.0 transitions from a 6-protocol "kitchen-sink" architecture to a
focused **3-layer architecture** based on what each protocol actually delivers:

- **Layer 1**: VLESS-Reality (TCP/443) - daily driver, censorship-resistant
- **Layer 2**: Hysteria2 (UDP/443) - QUIC fallback for TCP interference
- **Layer 3**: VLESS-WS (TCP/443) - CDN-ready fallback for IP blocking

### Breaking Changes

#### Removed Protocols

These protocols are **no longer included** in fresh installs:

- ❌ **VLESS-gRPC** - In IP mode, used `grpc.edgebox.internal` internal SNI which
  provided no real anti-DPI value over Reality. In domain mode, no real advantage
  over WS.
- ❌ **Trojan-TLS** - Effectively superseded by VLESS-WS-TLS. No unique capability.
- ❌ **TUIC** - Functional overlap with Hysteria2 (both QUIC/UDP). Non-standard
  port 2053 was a fingerprinting risk.

#### Subscription Format Changes

The subscription system now publishes **4 formats** instead of 1+1:

| URL pattern | Format | Target clients |
|-------------|--------|----------------|
| `/sub-<token>` | Plain URI list (existing) | v2rayN, v2rayNG, Streisand |
| `/sub-<token>.base64` | Base64 of plain list | Legacy v2ray subscription |
| `/sub-<token>.clash` | Mihomo / Clash Meta YAML | **NEW** - Clash Meta users |
| `/sub-<token>.singbox` | sing-box native JSON | **NEW** - sing-box / NekoBox |

The plain URL is unchanged for backward compatibility.

#### URI Spec Compliance

- **Hysteria2 URI now includes `/` before `?`** per the official Hysteria 2 spec:
  ```
  Before: hysteria2://pass@host:443?sni=...&alpn=h3
  After:  hysteria2://pass@host:443/?sni=...&alpn=h3
  ```
  Newer parsers (mihomo, sing-box) enforce this strictly. This change fixes
  "subscription not recognized" errors reported in v3.x.

#### server.json Schema Changes

- **Removed fields** (gRPC, Trojan, TUIC related):
  - `uuid.vless.grpc`
  - `uuid.vless.trojan`
  - `uuid.tuic`
  - `password.trojan`
  - `password.tuic`

- **Added fields**:
  - `ws.path` - Randomized WS path (8 chars, generated at install time)
  - `cdn.enabled` - Reserved for v4.x CDN relay mode (default: `false`)
  - `cdn.host` - Reserved for CDN host name (default: `null`)

#### Nginx Routing Simplification

- Removed `$ssl_preread_alpn_protocols` second-level routing (ALPN map).
- Removed upstreams for gRPC (10085) and Trojan (10143).
- Stream routing is now single-level: SNI → upstream, with Reality as the
  default fallback.

### New Features

#### WS Path Randomization

Each install now generates a random 8-character WS path (e.g. `/x9k2m7p4`)
stored in `server.json`. This de-fingerprints EdgeBox installations - the
historical `/ws` default is no longer used.

The path is generated **once at install time** and does not rotate. It's
included in all subscription URIs automatically.

#### Atomic Subscription Publishing

All 4 subscription formats are written to `.tmp` files first, validated, and
then atomically moved into place as a set. If any format fails to generate
correctly, **no file is updated** - the existing subscription remains intact.

This eliminates the "half-updated subscription" race condition.

#### Safer YAML/JSON Generation

- Clash YAML strings are now single-quoted with proper escape sequences.
  Passwords with `:`, `#`, `'`, etc. no longer break YAML parsing.
- sing-box JSON is generated via `jq -n` for guaranteed safe string escaping.

### Library Refactor

Block 1 introduces a `lib/` directory containing shared modules:

```
ENV/lib/common.sh       - path constants, logging, jq helpers, atomic writes
ENV/lib/subscription.sh - 4-format subscription generator
```

These are sourced by `install.sh` during bootstrap and installed to
`/etc/edgebox/scripts/lib/` for runtime use by `edgeboxctl`.

### Bootstrap Channel Locking

`install.sh` now respects two environment variables for download source:

```bash
EDGEBOX_CHANNEL=stable    # default - pins to a released tag
EDGEBOX_VERSION=v4.0.0    # the tag to pin to
EDGEBOX_CHANNEL=dev       # opt-in: tracks main branch (not for production)
```

The default install command is unchanged:

```bash
curl -fsSL https://raw.githubusercontent.com/cuiping89/node/v4.0.0/ENV/install.sh | bash
```

But you now have version-locked installations by default. No more "today
worked, tomorrow broke because main was edited".

### Migration Guide

#### From v3.x (fresh install only)

There is **no in-place upgrade path** from v3.x to v4.0.0. This is a
deliberate decision: the protocol set changed enough that upgrade-in-place
would either break clients silently or require a complex 30-day legacy mode.

For new installations: install v4.0.0 normally.

For existing v3.x deployments that wish to migrate:
1. Note your current subscription URL.
2. Back up `/etc/edgebox/config/server.json`.
3. Run the v4.0.0 installer - it will replace the existing install.
4. Re-distribute the new subscription URL to clients.

(This decision was made because the user confirmed no existing deployments
needed to be preserved.)

### What's NOT changed

These remain identical to v3.x:

- File paths (`/etc/edgebox/...`)
- Dashboard data contracts (`dashboard.json`, `traffic.json`, `system.json`)
  - The `protocols` array now has 3 items instead of 6, but the schema is identical
- One-liner install command
- `edgeboxctl` command surface (commands referring to gRPC/Trojan/TUIC will error)
- Web UI front-end (will render 3 rows in the protocol table instead of 6)

### Upcoming (planned for v4.1.0+)

These were originally planned for v4.0.0 but moved to subsequent blocks:

- **Block 2 (v4.1)**: Health monitor → read-only mode (no auto-repair)
- **Block 3 (v4.2)**: Cron jobs → opt-in via `edgeboxctl cron enable/disable`
- **Block 4 (v4.3)**: edgeboxctl command surface cleanup, `rotate-reality --confirm` flag
- **Block 5 (v4.4)**: Full-rerender config generation, CDN relay mode
- **Block 6 (v4.5)**: install.sh bootstrap finalization (target ≤ 500 lines)
- **Block 7 (v4.6)**: Front-end extraction to standalone files
