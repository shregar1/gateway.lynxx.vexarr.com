# Lynxx — Threat Model

Scope: the lynxx product as it ships today (private beta). Updated when
the trust boundaries change. Last reviewed: 2026-05-18.

## System diagram (logical)

```
                                    Public internet
                                          │
                            (1) TLS  ─────┼─────  (2) http/2, h3
                                          │
              ┌───────────────────────────▼─────────────────────────────┐
              │  gateway.lynxx.vexarr.com  (Rust, single binary)         │
              │  ┌─────────┐  ┌────────────┐  ┌────────────┐             │
              │  │ ingress │  │ plugin     │  │ proxy →    │             │
              │  │ + TLS   │─▶│ chain      │─▶│ upstream   │             │
              │  └─────────┘  │ (auth,     │  └────────────┘             │
              │               │ rate-limit │                             │
              │               │ JWT, mTLS, │                             │
              │               │ HMAC, ACL) │                             │
              │               └────────────┘                             │
              │                  ▲                                       │
              │                  │ (3) admin port (28081, local only)    │
              │  ┌───────────────┴───────┐                                │
              │  │ admin API + dashboard │                                │
              │  └───────────────────────┘                                │
              └───────────────────────────────────────────────────────────┘
                        │ (4) keyx licence verify                          │ (5) OCSP / ACME (DNS, Let's Encrypt)
                        ▼                                                  ▼
              api.lynxx.vexarr.com                                 External CAs / DNS
               (auth, signing, OAuth)
                        ▲
                        │ (6) HttpOnly session cookie + CSRF token
                        │
              website.lynxx.vexarr.com         node.dashboard.lynxx.vexarr.com
                  (SignUp, billing,                  (admin UI, served same-origin
                   SignIn, account)                   from gateway:9001)
```

## Trust boundaries (numbered above)

1. **Public TLS** — the gateway terminates TLS for customer traffic.
2. **HTTP/2 / HTTP/3 / WebSocket / gRPC** — protocol surface exposed to
   any internet client.
3. **Admin port (default 28081)** — admin API + dashboard. Loopback only by
   default; exposing to a network requires Bearer token auth.
4. **keyx licence verify** — outbound mTLS to vexarr's keyx service to
   re-verify the licence signature every 6h.
5. **OCSP / ACME** — outbound to external CAs (Let's Encrypt etc.) and DNS
   providers for cert provisioning and revocation checks.
6. **Dashboard / website auth** — HttpOnly session cookie + double-submit
   CSRF token (header `X-Lynxx-Csrf`).

## Asset register

| ID | Asset | Sensitivity |
|---|---|---|
| A1 | Customer API keys (gateway-issued) | Critical — grants upstream access |
| A2 | Customer session cookies | Critical — grants dashboard access |
| A3 | Customer telemetry (logs, metrics, traces) | Confidential per tenant |
| A4 | Lynxx licence signing keys | Critical — held in keyx, not here |
| A5 | Gateway TLS private keys | Critical — issued via ACME, on disk under storage_dir |
| A6 | Plugin runtime config (rate-limit, ACL rules) | Integrity-sensitive |
| A7 | Recording captures (request/response replays) | Confidential — may contain PII |

## Threats by STRIDE (highest priority first)

### S — Spoofing

| # | Threat | Mitigation today | Gaps |
|---|---|---|---|
| S1 | Forged session cookie on dashboard/website | HttpOnly + Secure + SameSite=Lax; double-submit CSRF token | None for in-browser; **gap**: long-lived cookies not yet bound to client IP / TLS fingerprint |
| S2 | Forged ACME challenge response | rustls-issued cert; HTTP-01 served only on `:80` by gateway | **gap**: no DNSSEC validation on outbound DNS lookups for resolvability check |
| S3 | Forged keyx licence bundle | Ed25519 signature verified against keyx-published signing key | None — keys rotated by keyx |

### T — Tampering

| # | Threat | Mitigation today | Gaps |
|---|---|---|---|
| T1 | Plugin chain config tampered to bypass rate-limit / auth | Admin API requires Bearer token; all writes audited via `audit.rs` | **gap**: no cryptographic config signing; any admin-token holder can disable |
| T2 | Recording captures tampered (false replay results) | Captures stored under storage_dir; integrity on FS-level only | **gap**: no per-capture HMAC |
| T3 | Cert store tampered on disk | File-system permissions (`storage_dir` mode 0700) | **gap**: no integrity check on cert files; relies on FS perms |

### R — Repudiation

| # | Threat | Mitigation today | Gaps |
|---|---|---|---|
| R1 | Customer disputes a key revocation | Admin audit log records actor + timestamp | **gap**: audit log not append-only / not externally signed |
| R2 | Operator disputes a config change | Same as R1 | Same |

### I — Information disclosure

| # | Threat | Mitigation today | Gaps |
|---|---|---|---|
| I1 | API key leak in error message | `GatewayError` variants don't include key material; errors logged at debug, not info | **gap**: no test asserting no-key-in-message |
| I2 | Recording captures leak customer PII | Redaction rules in `recording/redact.rs` (header allowlist) | **gap**: body redaction is opt-in per service, not default |
| I3 | Stack traces / panic messages leak path / config | `panic=abort` in release; panic surface ~zero in hot path (see audit) | None known |
| I4 | Side-channel timing on key compare | constant-time `subtle` crate used in HMAC verify | **gap**: not audited for non-key compares (e.g. tenant slug match) |

### D — Denial of service

| # | Threat | Mitigation today | Gaps |
|---|---|---|---|
| D1 | Slowloris / connection-exhaustion | rustls + tokio default limits; per-listener accept queue | **gap**: no global connection cap; one runaway tenant can exhaust |
| D2 | Compression bombs (zstd/br response) | Streaming response body; no buffered decode in gateway | None |
| D3 | Plugin chain amplification (e.g. JWT verify CPU) | None today | **gap**: no per-plugin time budget |
| D4 | Quota exhaustion from a single tenant | `QuotaTracker` per-tenant counters; soft + hard limits | **gap**: counters in-memory, lost on restart |
| D5 | Cert provisioning storm (on-demand TLS) | `ISSUANCE_TX` debounce via mpsc bounded channel | **gap**: per-domain dedup but no per-source-IP cap |

### E — Elevation of privilege

| # | Threat | Mitigation today | Gaps |
|---|---|---|---|
| E1 | Customer key with `read` scope used for write | Per-route scope enforcement (`feat(auth): per-route scope enforcement honouring keyx principal scopes`) | None known |
| E2 | Admin token leak escalates to full control | Cached in `AdminAuthCache` w/ TTL; never logged | **gap**: no rotation policy enforced |
| E3 | Plugin executes arbitrary code on host | WASM sandbox via wasmtime; capability-restricted | **gap**: no audit of capability surface vs. spec |

## Highest-impact open items (audit follow-ups)

Ordered by impact, not urgency. Each blocks GA in some way.

1. **External pentest** of the api.lynxx.vexarr.com auth/billing path before
   opening signup beyond invited beta. Estimated $10–15k from a reputable
   small firm; ~2-week engagement.
2. **Append-only audit log** (T1 + R1+R2). Today it's a SQLite table; a
   tamper-evident chain (hash-linked records or externally exported) would
   close the repudiation gap.
3. **Per-tenant resource caps** (D1, D3, D4) — connection cap, plugin
   CPU/time budget, persistent quota counters. Tier 2 work.
4. **Body-default redaction** for recordings (I2) — flip the default from
   opt-in to opt-out for body capture; per-service whitelist for full
   bodies on debug.
5. **SOC 2 Type 1** — auditor-driven, 3–6 months once the controls above
   are in place. Required by enterprise prospects.

## What this document is NOT

- It is **not** a pentest. It enumerates threats from a code/architecture
  review; an adversarial test will find more.
- It is **not** a compliance certification. SOC 2 / ISO 27001 require
  evidence of operating controls, not just designed ones.
- It is **not** exhaustive. Anything reviewed in [SECURITY.md](SECURITY.md)
  as "in scope" gets the same threat treatment when changes land.

## Review cadence

- This document is re-reviewed quarterly, and on every change that adds a
  trust boundary or moves data across one.
- The reviewer commits a `Reviewed: YYYY-MM-DD by <name>` line at the top
  on each pass.
