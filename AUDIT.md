# lynxx-gateway — Full Audit Report

**Target:** `lynxx-gateway` v0.9.0 — proprietary high-performance Rust API gateway / reverse proxy  
**Date:** 2026-06-09  
**Scope:** ~81K LOC, 271 Rust files. Security + performance + correctness, whole tree.  
**Method:** 22 subsystem×lens finder agents → independent adversarial verification of every finding (re-read the cited code, default to reject/uncertain without evidence, re-rate severity) → synthesis. 2 finder slices (unsafe/eBPF, data-integrity) were re-run as self-verifying backfills.  
**Stack reviewed:** axum 0.7, hyper 1, tokio, rustls 0.23 (ring), sqlx 0.8 (sqlite+postgres), wasmtime 27, eBPF/XDP, jsonwebtoken, argon2, ed25519-dalek, redis, kube.

> Findings are *confirmed* (survived adversarial verification) unless noted. Severities are the post-verification adjusted values. Line numbers are from the audited tree and may drift as code changes.

---

## Executive summary

**115 confirmed findings** (6 critical · 32 high · 40 medium · 35 low · 2 info).

| Severity | Security | Performance | Quality | Total |
|---|---:|---:|---:|---:|
| 🔴 Critical | 6 | 0 | 0 | 6 |
| 🟠 High | 19 | 6 | 7 | 32 |
| 🟡 Medium | 22 | 11 | 7 | 40 |
| ⚪ Low | 18 | 8 | 9 | 35 |
| 🔵 Info | 1 | 0 | 1 | 2 |
| **Total** | **66** | **25** | **24** | **115** |

### The headline: the admin plane is unauthenticated by default

The 6 criticals collapse to **3 distinct root issues**, two of which were independently flagged by 3 separate finder agents (strong corroboration):

1. **`/admin/v1/config` is mounted *outside* the auth middleware** (C1–C3). In `src/admin/mod.rs:466-497` the live-config sub-router is attached via `.nest()` *after* `extract_token`/`require_role` were layered onto a different sub-router; in axum 0.7 those layers do not wrap later-nested routes. Result: unauthenticated `GET`/`PUT`/`PATCH` of the entire running config — repoint upstreams, disable auth/WAF plugins, change TLS — a full admin-plane takeover.
2. **`GET /admin/v1/config` serializes secrets in cleartext** (C4–C5): license `api_key`, DB URL, telemetry key, AWS secret, ACME DNS tokens, EAB HMAC key. No `skip_serializing` anywhere in `config.rs`. Combined with #1 → unauthenticated secret exfiltration.
3. **LLM-gateway response cache key omits tenant identity** (C6, `plugins/llm_gateway/cache.rs:87-108`): cross-tenant response leakage.

Compounding it: **`auth_required` defaults to `false`** (H-tier, `auth/middleware.rs`), and the documented "auth turns on automatically once a token exists" bootstrap is **not implemented** — so even the *properly*-mounted admin routes are open by default. Default `bind_address = "0.0.0.0"` exposes all of this on every interface.

### Cross-cutting themes (high tier)

- **Identity headers are client-spoofable.** `x-consumer-*` headers feed ACLs, per-tenant LLM/GraphQL/anomaly keys, and HMAC identity, but ingress does not strip them from inbound requests (`hmac_auth.rs`, `llm_gateway/mod.rs`). Auth plugins also have concrete bypasses: digest-auth accepts any client nonce and validates the client-claimed URI; GraphQL guard skips named fragment spreads (depth/complexity bypass).
- **SSRF surface is wide open.** Discovered upstream URLs (`discovery/consul.rs` et al.) are never scheme/host-validated before becoming proxy targets — reachable to metadata/internal/unix/file.
- **Data plane does blocking work on the async runtime.** Buffering spills bodies to `/tmp` with blocking `std::fs`; compression runs gzip/brotli/zstd inline with no `spawn_blocking`; per-request `Service` structs are deep-cloned; key/basic/hmac auth linear-scan the *entire* consumers table per request.
- **Audit log integrity is not guaranteed.** Hash-chain forks under concurrent admin writes (no locking on Postgres) and `verify_chain` only checks the newest 1000 rows (false-positive breakage past 1000 entries). Billable overage counts are never persisted.
- **Secrets land in logs/storage.** `request_recorder` persists response headers + bodies (Set-Cookie, tokens, PII) and non-JSON request bodies with no redaction.

### Unsafe / eBPF

Only ~25 `unsafe` blocks, concentrated in eBPF/io_uring/ktls/profiling. No memory-safety landmines found, but: XDP packet reads dereference **unaligned** raw pointers (Rust-level UB; use `read_unaligned`), and the XDP token-bucket rate limiter has a **cross-CPU read-modify-write race** that lets a single source exceed its budget by ~#RX-CPUs.

---

## 🔴 Critical findings (6)

#### C1 · 🔴 CRITICAL · Live config API (/admin/v1/config) mounted outside auth middleware — unauthenticated config read/write

- **Where:** `src/admin/mod.rs`:466-497  
- **Dimension:** security · **Subsystem:** `sec-admin` · **Confidence:** high  

**What's wrong.** In admin_router, the authenticated API is built as `let api = reads.merge(mutations).merge(tokens).layer(from_fn_with_state(state, extract_token)).layer(api_envelope)` (lines 475-479). The live-config sub-router is built separately: `let config_sub = config_api::config_router(config_store).layer(from_fn(api_envelope))` (lines 467-469) — note it gets ONLY api_envelope, no extract_token and no require_role. It is then attached to the OUTER router via `.nest("/admin/v1/config", config_sub)` (line 494), so the per-route `extract_token`/role layers that wrap `api` never apply to it. config_router itself (src/admin/config_api.rs:421-431) adds no auth layer either. The only layers covering the nested routes are spa_navigation_guard and admin_cors (lines 495-496), neither of which authenticates. The result: GET/PUT/PATCH/POST on /admin/v1/config, /admin/v1/config/validate, /admin/v1/config/history, /admin/v1/config/@id/:tag, and /admin/v1/config/*path are reachable with NO token whatsoever, regardless of the gateway.auth_required setting.

**Impact.** Any client that can reach the admin port can read the entire running gateway configuration and overwrite it (PUT /admin/v1/config) or patch arbitrary fields (PATCH /admin/v1/config/*path) — repointing upstreams, disabling TLS, changing ports, injecting routes — with zero authentication, even in a hardened deployment where auth_required=true and all other admin routes require an Admin/Operator token.

**Fix.** Apply the same extract_token + require_role guards to config_sub before/after nesting. Either nest config_sub inside the `api` router (so it inherits the extract_token layer) and add `.route_layer(require_role(Role::Admin))` to config_router, or wrap the nested router: `.nest("/admin/v1/config", config_sub.route_layer(from_fn_with_state(state.clone(), extract_token)).route_layer(from_fn(require_admin)))`. Config read/write should be Admin-only.

#### C2 · 🔴 CRITICAL · GET /admin/v1/config serializes secrets (master license api_key, DB URL, telemetry key, AWS secret) enabling full privilege escalation

- **Where:** `src/config.rs`:4-48  
- **Dimension:** security · **Subsystem:** `sec-admin` · **Confidence:** high  

**What's wrong.** GatewayConfig derives Serialize (config.rs:4) and has NO #[serde(skip_serializing)] on any secret field. get_config (src/admin/config_api.rs:168-171) returns `Json(ConfigResponse { config })` — the full struct. The struct embeds: license.api_key (config.rs:41-47, the customer's lnx_live_ key), telemetry.api_key (config.rs:51-59), gateway.database_url which may contain DB credentials (config.rs:82-83), and providers AWS secret_access_key (config.rs:611-613). Critically, license.api_key IS the master admin credential: resolve_actor in src/auth/middleware.rs:205-215 grants Role::Admin to any request whose bearer equals state.license_api_key (which is config.license.api_key, see src/main.rs:538). Combined with the unauthenticated nesting bug above, an attacker reads GET /admin/v1/config, extracts license.api_key, and now holds the master Admin token for every authenticated admin endpoint.

**Impact.** Unauthenticated disclosure of the master admin API key, database connection string (with password), telemetry token, and cloud (AWS) secret access key. The leaked license key grants full Admin over the entire admin API including token management, so this escalates to complete gateway and data-plane takeover even if every other route is properly authenticated.

**Fix.** Never serialize secrets out of the config API. Add #[serde(skip_serializing)] (or a dedicated redacting wrapper) to license.api_key, telemetry.api_key, providers.*.secret_access_key, and redact credentials from database_url before returning. Better: return a purpose-built sanitized view type for the config API rather than the raw GatewayConfig. Independently, stop accepting the license key as a master admin credential, or scope it tightly.

#### C3 · 🔴 CRITICAL · Unauthenticated /admin/v1/config router: nest() applied after auth layers bypasses extract_token and require_role

- **Where:** `src/admin/mod.rs`:466-497  
- **Dimension:** security · **Subsystem:** `sec-auth` · **Confidence:** high  

**What's wrong.** The live-config sub-router is built with no auth of its own: `config_api::config_router(config_store).layer(middleware::from_fn(api_envelope))` (mod.rs:468-469), and `api_envelope` performs no authentication. It is mounted onto the main router via `.nest("/admin/v1/config", config_sub)` at mod.rs:494 — AFTER `extract_token` and the per-route `require_role` guards were attached to the separate `api` sub-router (mod.rs:475-479). In axum 0.7, a `.layer()` applied to the `api` router only wraps `api`'s own routes; routes added later via `.nest()` on the outer router do NOT inherit them. The only layers wrapping the nested config routes are `spa_navigation_guard` (mod.rs:495, no auth — confirmed) and `admin_cors()` (mod.rs:496). I verified config_api.rs handlers (`get_config`, `put_config`, `patch_config`, `validate_config_handler`, `config_history`) take no `CurrentActor`/`Extension` and perform no token check. `put_config` does a full GatewayConfig replace + reinitialize (config_api.rs:174-212); `patch_config` applies an arbitrary JSON-path mutation to the running config (config_api.rs:218+).

**Impact.** Any unauthenticated network client that can reach the admin port can GET the full running gateway configuration (including any secrets serialized into it) and PUT/PATCH a new configuration that reinitializes the gateway — e.g. repoint upstreams, disable WAF/auth plugins, change TLS/bind settings. With the default `bind_address = "0.0.0.0"` (config.rs:1311, test at 2264) the admin port is exposed on all interfaces. This is a complete admin-plane compromise that ignores the entire token/RBAC system.

**Fix.** Nest the config router BEFORE applying the auth layers, or wrap `config_sub` with the same `extract_token` + `require_role(Role::Admin)` layers it needs (e.g. `config_sub.route_layer(from_fn(admin_only)).layer(from_fn_with_state(state.clone(), extract_token))`). Add an integration test that asserts a request with no/invalid bearer to `/admin/v1/config` returns 401/403. Generally, prefer `.merge()` for routers that should share the parent's middleware, and never rely on layer ordering to gate a nested router.

#### C4 · 🔴 CRITICAL · Live config API (/admin/v1/config) mounted with no authentication or RBAC layer

- **Where:** `src/admin/mod.rs`:466-497  
- **Dimension:** security · **Subsystem:** `sec-config` · **Confidence:** high  

**What's wrong.** In `admin_router`, the `config_sub` router is built at lines 467-469 with only the `api_envelope` layer: `config_api::config_router(config_store).layer(middleware::from_fn(api_envelope))`. The authentication middleware `extract_token` (line 478, `from_fn_with_state(state.clone(), extract_token)`) and the per-role guards (`viewer`/`operator`/`admin_only`) are applied ONLY to the `api` router (the merged `reads`+`mutations`+`tokens`). `config_sub` is attached separately via `.nest("/admin/v1/config", config_sub)` at line 494, so it never passes through `extract_token` and never reaches any `require_role` guard. The only layers wrapping it are the post-nest `spa_navigation_guard` and `admin_cors`, neither of which authenticates. The endpoints in `src/admin/config_api.rs` (`GET /admin/v1/config`, `PUT /admin/v1/config`, `PATCH /admin/v1/config/*path`, `POST /admin/v1/config/validate`, `GET /admin/v1/config/history`, `GET /admin/v1/config/@id/:tag`) are therefore fully reachable with no credentials. The admin listener binds to `config.gateway.bind_address` which defaults to `0.0.0.0` (src/config.rs:1311-1312), so this is exposed on all interfaces.

**Impact.** Any unauthenticated network client that can reach the admin port (default 28081, bound 0.0.0.0) can read the entire running configuration via `GET /admin/v1/config` — including plaintext secrets (see related finding) — and can fully replace the gateway configuration via `PUT /admin/v1/config` (e.g. inject malicious upstreams/routes to redirect or MITM proxied traffic, disable TLS, alter plugins). This bypasses the master license key and all RBAC even when `auth_required=true`. Full compromise of the data plane.

**Fix.** Apply `extract_token` and at minimum `require_role(Role::Admin)` to `config_sub` before nesting (config read/replace is the most sensitive admin surface). E.g. add `.layer(middleware::from_fn_with_state(state.clone(), extract_token))` and a role guard to `config_sub`, or merge the config routes into the authenticated `api` router instead of nesting them outside it. Add an integration test that asserts an unauthenticated request to `/admin/v1/config` returns 401.

#### C5 · 🔴 CRITICAL · GET /admin/v1/config returns plaintext secrets (license api_key, telemetry api_key, ACME DNS tokens, EAB HMAC key)

- **Where:** `src/admin/config_api.rs`:167-171  
- **Dimension:** security · **Subsystem:** `sec-config` · **Confidence:** high  

**What's wrong.** `get_config` serializes the whole `GatewayConfig` with `Json(ConfigResponse { config })` and no redaction. The config struct carries secrets that all derive plain `Serialize` with no `skip_serializing`: `LicenseSettings.api_key` (src/config.rs:46-47 — the master admin/license key), `TelemetrySettings.api_key` (src/config.rs:58-59), `Dns01Config.api_token` and `Dns01Config.secret_access_key` (src/config.rs:597-613), and `AcmeConfig.eab_hmac_key` (src/config.rs:508-510). `validate_config` and `patch_config` also round-trip the full struct including these fields. Combined with the missing auth layer on `/admin/v1/config`, these are disclosed without credentials; even if auth were fixed, a Viewer/Operator that can read config would see the master credential.

**Impact.** Disclosure of the master `license.api_key` lets an attacker authenticate as Admin to the entire admin API (it is the master bearer per src/auth/middleware.rs:205) and validate/abuse the vexarr subscription. Disclosure of Cloudflare/AWS DNS credentials and the OTLP bearer token enables lateral movement (DNS takeover, AWS access, telemetry-pipeline injection).

**Fix.** Redact secret fields before returning config from the admin API: serialize through a sanitized view that masks `license.api_key`, `telemetry.api_key`, `acme.dns01.api_token`, `acme.dns01.secret_access_key`, and `acme.eab_hmac_key` (e.g. replace with `"***"` or omit). Prefer a dedicated DTO over the raw `GatewayConfig` for read responses, and never echo secrets in `PATCH`/`validate` error messages.

#### C6 · 🔴 CRITICAL · LLM gateway response cache key omits consumer/tenant identity, leaking cross-tenant responses

- **Where:** `src/plugins/llm_gateway/cache.rs`:87-108  
- **Dimension:** security · **Subsystem:** `sec-llm-gql` · **Confidence:** high  

**What's wrong.** ResponseCache::key() hashes only model, temperature, top_p, max_tokens, response_format, tools, and messages (the canonical object built at lines 95-103). It deliberately excludes any consumer / API-key / tenant identifier. The cache store is a single process-wide DashMap (struct field `store: DashMap<String, CacheEntry>`, line 35), shared across every consumer that hits the plugin. In mod.rs the key is computed as `self.cache.key(&model, &json)` (line 294) with no consumer mixed in, then looked up in the shared store (line 296) and the upstream response is written back keyed the same way (put(), lines 506-511). Two different tenants who send a byte-identical request body therefore collide on the same cache entry.

**Impact.** Tenant B issuing the same prompt+params as Tenant A receives Tenant A's cached completion verbatim (including the cached upstream response headers stored at line 509). For an internet-facing multi-tenant LLM gateway this is a cross-tenant data leak: confidential prompts/answers, and any per-tenant personalization in the response, cross trust boundaries. It also enables deliberate cache poisoning: a low-trust tenant can pre-seed a deterministic prompt's cache entry so other tenants get an attacker-influenced response within the TTL.

**Fix.** Incorporate a trust-boundary identity into the cache key (e.g. the authenticated consumer id / api-key id / tenant id resolved by the auth plugin, not the spoofable x-consumer-username) so entries are partitioned per tenant. Alternatively, key the DashMap by (tenant, hash). Do not derive the partition from a client-supplied header that is not stripped at ingress.

---

## 🟠 High findings (32)

#### H1 · 🟠 HIGH · Default auth_required=false leaves entire admin surface unauthenticated; documented 'auth turns on when a token exists' mitigation absent in code

- **Where:** `src/auth/middleware.rs`:176-188  
- **Dimension:** security · **Subsystem:** `sec-admin` · **Confidence:** high  

**What's wrong.** resolve_actor returns Ok(None) when no Authorization header is present and `!state.auth_required` (lines 180-188). enforce_role then treats CurrentActor(None) as allowed: `None => next.run(req).await` (src/auth/middleware.rs:380-381). gateway.auth_required is #[serde(default)] = false (src/config.rs:139-140, 1164) and the shipped config.toml does not set it, so the default is false. The module docstring (middleware.rs:5-8) and config docstring (config.rs:135-140) claim bootstrap mode only applies 'while admin_tokens is empty' and 'auth turns on automatically as soon as any token exists' — but no code path counts tokens; resolve_actor checks ONLY the auth_required flag. A grep for count_admin_tokens / tokens.is_empty in src/ finds no such check. Combined with default bind_address = "0.0.0.0" (config.rs:1311, test at 2262-2264), the admin port is internet-facing and fully open by default.

**Impact.** With the shipped default config, every reads/mutations/tokens admin route is accessible with no credentials from any network that can reach the admin port — list/create/delete services, routes, plugins, consumers, admin tokens, reset circuit breakers, etc. Operators who believe creating a token enables enforcement (per the docs) remain fully exposed because that behavior is not implemented.

**Fix.** Implement the documented behavior: in resolve_actor, when the header is missing, treat the request as unauthenticated only if the admin_tokens table is empty (query a cached count); otherwise 401. Default auth_required to true, or refuse to bind the admin listener to a non-loopback address while auth is disabled. Fix the docstrings to match actual behavior.

#### H2 · 🟠 HIGH · enforce_role grants full admin access to credential-less requests when auth_required=false (the shipped default)

- **Where:** `src/auth/middleware.rs`:176-188, 374-396  
- **Dimension:** security · **Subsystem:** `sec-auth` · **Confidence:** high  

**What's wrong.** `resolve_actor` returns `Ok(None)` for a request with no Authorization header whenever `!state.auth_required` (middleware.rs:182-185), producing `CurrentActor(None)`. `enforce_role` then matches `None => next.run(req).await` (middleware.rs:380-381), allowing the request through for ALL guards including `require_admin` on token-management routes. The doc comments claim a DB-driven bootstrap: middleware.rs:5-8 says "If the DB has zero tokens we are in bootstrap mode" and config.rs:137-138 says "auth turns on automatically as soon as any token exists." Neither is implemented — `auth_required` is read straight from config (`config.gateway.auth_required` at main.rs:841) and defaults to `false` (config.rs:139-140 `#[serde(default)]`, explicit `auth_required: false` at config.rs:1164). There is no code that counts `admin_tokens` and flips the flag (grep for count/bootstrap confirms none). The shipped config.toml and deploy/quickstart-config.toml do not set `auth_required`, so it is false in the default deployment.

**Impact.** In a default deployment an attacker who can reach the admin port and simply omits the Authorization header is treated as an unauthenticated bootstrap actor with no role ceiling, gaining Admin-level access to every admin route (create/delete tokens, mutate services/routes/plugins, etc.). Operators are misled by the comments into believing creating a token closes the door; it does not.

**Fix.** Either (a) implement the documented behavior — at startup count non-deleted `admin_tokens` and force `auth_required = true` when any exist, and re-check periodically — or (b) make `auth_required` default to `true` and remove the misleading comments. Additionally, `enforce_role`'s `None` arm should not blanket-allow; distinguish license-key actors (which already produce `Some(AdminToken{role: Admin})`, middleware.rs:206-214) from the no-credential case so that a missing actor only passes in an explicit, logged bootstrap state.

#### H3 · 🟠 HIGH · Admin API unauthenticated by default: auth_required defaults to false with no auto-enable

- **Where:** `src/auth/middleware.rs`:180-188  
- **Dimension:** security · **Subsystem:** `sec-config` · **Confidence:** high  

**What's wrong.** `resolve_actor` returns `Ok(None)` (no actor) whenever the request has no `Authorization` header and `state.auth_required` is false (lines 183-185). `auth_required` defaults to `false` (src/config.rs:1164) and is a static flag passed straight from config to the router (src/admin/mod.rs:100, main.rs:841) — there is no logic anywhere that flips it on when admin tokens exist (the doc comment at src/config.rs:135-138 claims 'auth turns on automatically as soon as any token exists', but grep shows `auth_required` is only ever read, never recomputed). With `CurrentActor(None)`, every role guard passes the request through unconditionally: `enforce_role` matches `None => next.run(req).await` (src/auth/middleware.rs:380-381). So in the default configuration an attacker simply omits the Authorization header and gets full Operator/Admin access to all `/services`, `/routes`, `/plugins`, `/tokens`, `/reload` endpoints.

**Impact.** Out-of-the-box, an unauthenticated client reachable on the admin port (default 0.0.0.0:28081) can list/create/modify/delete services, routes, plugins, and admin tokens — full control of the gateway — without any credential, despite a license key being required to boot. Operators relying on the documented 'auto-enable' behavior are silently unprotected.

**Fix.** Default `auth_required` to `true`, or actually implement the documented behavior (treat the presence of any `admin_tokens` row OR a non-empty `license_api_key` as forcing auth on). At minimum, when an Authorization header is absent and no token exists, still require the master license key. Fix or remove the misleading doc comment.

#### H4 · 🟠 HIGH · install_gateway.sh fails open: signature/checksum verification skipped when headers absent

- **Where:** `assets/install/install_gateway.sh`:56-103  
- **Dimension:** security · **Subsystem:** `sec-config` · **Confidence:** high  

**What's wrong.** `verify_artifact` only enforces integrity when the server happens to send the sidecar headers. If `X-Content-SHA256` is missing it just `warn`s and continues (lines 74-76). If `X-Content-Signature` is missing it returns success without verifying (lines 80-83 `return 0`). If `openssl` is absent or lacks Ed25519 it also skips signature verification (lines 84-91). The pinned `LYNXX_RELEASE_PUBKEY` (lines 47-49) is therefore only consulted when the response chooses to include a signature header. The gateway's own `/v1/install/binary` handler (src/install/mod.rs:250-259) only adds these headers when the `.sha256`/`.sig` sidecars exist in the bucket and explicitly treats them as optional ('legacy artifacts upload without them and the install script falls back with a visible warning'). The stated guarantee in the script comment — 'even bucket compromise can't substitute binaries without the private key' — is false, because an attacker who controls the bucket (or strips the header) just omits the signature and the installer proceeds.

**Impact.** An attacker who can tamper with the GCS bucket contents, or otherwise influence the served binary/headers, can ship an unsigned malicious gateway binary that installs without any signature failure (only a warning piped to stderr, easily missed in `curl | bash`). Results in remote code execution on every installing host. The pinned-key supply-chain defense is fully bypassable.

**Fix.** Make verification fail-closed: if `X-Content-Signature` (or `X-Content-SHA256`) is absent, `err` and refuse to install rather than `warn`+continue. Require openssl-with-Ed25519 as a hard prerequisite (abort if missing) instead of skipping. Provide an explicit, loud opt-out only via an env var the user must set (e.g. `LYNXX_ALLOW_UNSIGNED=1`).

#### H5 · 🟠 HIGH · License response trusted without ed25519 signature verification against an embedded pubkey

- **Where:** `src/integrations/keyx.rs`:115-183  
- **Dimension:** security · **Subsystem:** `sec-license` · **Confidence:** high  

**What's wrong.** validate_license_against() POSTs the api key to {AUTH_URL}/v1/keys/verify and decides the license is valid based solely on parsing the JSON envelope and reading data.valid (keyx.rs:160-180). There is no signature on the response. Grepping the entire license + integrations tree shows zero use of ed25519/Ed25519/VerifyingKey/verify/embedded pubkey on this path (only install/mod.rs and acme.rs use Ed25519, for binaries and certs). The only integrity guarantee is the TLS connection to AUTH_URL, which is baked in at compile time via env!("AUTH_URL") (keyx.rs:48). The reqwest client is built with defaults (KeyxClient::new, keyx.rs:78-84) and honors the standard HTTPS_PROXY/proxy env vars (no .no_proxy()), so the verify call traverses any configured proxy. The audit task asks whether 'the ed25519 response signature is actually verified against the embedded pubkey before trust' — it is not; there is no such verification, and the LicenseInfo struct carries no signature field at all (abstraction.rs:50-59).

**Impact.** An attacker who can terminate/intercept TLS to auth.vexarr.com (compromised CA in the trust store, MITM proxy injected via HTTPS_PROXY, hostile DNS plus a cert for the hostname, or simply a self-hosted keyx pointed at by an attacker-controlled AUTH_URL build) can return {valid:true, tier:enterprise, expires_at: far future, max_nodes: large} and the gateway accepts it as a fully-licensed Enterprise install. There is no cryptographic binding of the license verdict to a Vexarr-held private key, so the entire license model degrades to 'whatever the TLS endpoint says'.

**Fix.** Have keyx sign the license payload (canonical bytes of customer_urn|tier|expires_at|max_nodes|nonce|issued_at) with an Ed25519 key, ship the corresponding public key embedded in the binary as a const, and reject any verify response whose ed25519-dalek VerifyingKey::verify_strict() fails. Include a server-issued nonce/timestamp in the signed payload to prevent replay. Do not rely on TLS alone for license integrity.

#### H6 · 🟠 HIGH · License expiry (expires_at) is loaded but never enforced at runtime — days_remaining() is dead code

- **Where:** `src/license/mod.rs`:112-152  
- **Dimension:** security · **Subsystem:** `sec-license` · **Confidence:** high  

**What's wrong.** License::from_info (mod.rs:112-125) and from_cache_entry (mod.rs:127-145) populate expires_at, and days_remaining() (mod.rs:149-152) clamps it to >=0, but a tree-wide grep shows days_remaining() is never called anywhere (the only other days_remaining hits are in acme.rs for cert renewal). The single runtime license gate in the proxy hot path is `if !state.license.is_active()` (proxy/handler.rs:477), and is_active() (mod.rs:201-203) only reads the AtomicBool kill-switch. That bool starts true (mod.rs:192) and is flipped false ONLY when the background re-verifier receives a Rejected (mod.rs:258). Nothing ever compares license.expires_at against Utc::now() to deny service.

**Impact.** A license that has passed its expiry date but has not been explicitly revoked server-side continues to serve proxy traffic indefinitely. Expiry provides no enforcement; only an affirmative server-side Rejected stops the gateway. Combined with the offline cache (see other findings), this lets an expired subscription keep running forever as long as keyx is unreachable or simply never returns Rejected.

**Fix.** In the proxy gate and in the re-verifier, treat expires_at as a hard deadline: if expires_at is Some and < now, flip the kill-switch / return 402. Enforce it on boot in License::load (reject when from_info/from_cache_entry yields an already-expired license) and periodically in spawn_license_refresher, not just on a server Rejected.

#### H7 · 🟠 HIGH · Offline license cache is unsigned and clock-trusting — editable to forge tier/expiry/limits and extendable by setting the clock back

- **Where:** `src/license/mod.rs`:127-145  
- **Dimension:** security · **Subsystem:** `sec-license` · **Confidence:** high  

**What's wrong.** from_cache_entry computes age via `(Utc::now().timestamp() - entry.verified_at).max(0) / 86_400` and only rejects when age_days > OFFLINE_GRACE_DAYS (mod.rs:128-131). Utc::now() is the local machine wall clock, and verified_at is read straight from the on-disk JSON. read_cache (mod.rs:322-337) deserializes ~/.lynxx/license.cache.json (or $LYNXX_CACHE_DIR, mod.rs:286-294) with serde and the ONLY integrity check is `entry.api_key_hash != api_key_hash` (mod.rs:333) — a SHA-256 of the api key the operator already holds (key_fingerprint, mod.rs:296-301). The cache is plain serde_json with no MAC/signature (write_cache, mod.rs:303-320). The fields tier, expires_at, max_nodes, active_nodes, monthly_call_limit, allow_overage all come straight from this file into from_cache_entry.

**Impact.** An operator who holds a valid (even free-tier) api key can, while keyx is unreachable: (a) edit the cache JSON to set tier=enterprise, expires_at far future, max_nodes huge, monthly_call_limit huge, allow_overage=true — api_key_hash still matches because it is derived from their own key; and/or (b) set the system clock backward so verified_at never appears older than 7 days, extending the offline grace window indefinitely. License::load happily returns this forged license on any non-Rejected error path (mod.rs:101-105). Result: self-service tier upgrade and unlimited offline runtime with no cryptographic obstacle.

**Fix.** Bind the cache to a server signature: store the keyx-signed payload + Ed25519 signature in the cache and re-verify the signature (not just the api_key_hash) on read. Use a monotonic/server-provided timestamp rather than trusting local wall-clock for the grace computation, or store verified_at inside the signed blob so it cannot be edited. Reject a cache whose signed expires_at is in the past regardless of grace window.

#### H8 · 🟠 HIGH · request-recorder persists response headers and response bodies with no redaction (Set-Cookie, tokens, PII)

- **Where:** `src/plugins/request_recorder/mod.rs`:244-274  
- **Dimension:** security · **Subsystem:** `sec-llm-gql` · **Confidence:** high  

**What's wrong.** On the response side the plugin collects raw response headers into resp_headers (lines 245-249) and the response body (lines 230-243) and stores them directly into RecordedResponse { status, headers: resp_headers, body_b64: STANDARD.encode(&truncated) } (lines 267-271) with no call to redact::redact_headers or redact::redact_body_paths. Redaction is applied ONLY to the request side (headers at line 142, JSON body at line 148). The default redact lists (config.rs lines 21-26) cover request `Authorization`/`Cookie`/`X-API-Key` and request body `password`/`credit_card`/`ssn`, but nothing covers the response. Recordings are written as plaintext JSON to the content-addressed store (recording/store.rs put(), serialized via serde_json::to_vec_pretty and tokio::fs::write with default 0644 perms) and are retrievable via the admin API get_recording handler (src/admin/routes.rs:1818-1825).

**Impact.** Captured recordings contain `Set-Cookie` session tokens, upstream auth tokens echoed in response headers, and any secrets/PII in response bodies (SSNs, emails, API keys, account data), all in plaintext on disk and downloadable through the admin surface. An operator or anyone with admin/file access (or via a recording-listing privilege) can harvest live session cookies and PII. Even at the 5% default sample rate this steadily accumulates sensitive material.

**Fix.** Run redact_headers over resp_headers (at minimum Set-Cookie, Authorization, and the configured header list) and run redact_body_paths over JSON response bodies before building RecordedResponse. Consider encrypting recordings at rest and tightening file permissions (0600). Add Set-Cookie to the default redact_headers list.

#### H9 · 🟠 HIGH · request-recorder stores non-JSON request bodies (e.g. form-encoded credentials) completely unredacted

- **Where:** `src/plugins/request_recorder/mod.rs`:144-152  
- **Dimension:** security · **Subsystem:** `sec-llm-gql` · **Confidence:** high  

**What's wrong.** Body redaction only runs when the request body parses as JSON: `match serde_json::from_slice::<serde_json::Value>(&truncated) { Ok(mut v) => { redact_body_paths(...); ... } Err(_) => truncated.clone() }`. Any body that is not valid JSON — `application/x-www-form-urlencoded` (e.g. `username=alice&password=hunter2`), multipart form data, XML, or a JSON body truncated mid-token by the `max_body_bytes` slice at lines 131-135 (which cuts on a raw byte boundary and will fail to parse) — falls into the `Err(_)` branch and is recorded verbatim. The default redact_body_paths (password/credit_card/ssn) therefore never applies to login forms and similar payloads.

**Impact.** Plaintext credentials and PII submitted via form-encoded or otherwise non-JSON request bodies (classic HTML login POSTs, OAuth token exchanges) are stored unredacted in recordings on disk and exposed through the admin retrieval API. Truncation of a large JSON body also silently disables redaction for that capture.

**Fix.** Add content-type-aware redaction for at least application/x-www-form-urlencoded (parse and redact matching keys), and consider redaction patterns over raw bytes for non-JSON types. For truncated bodies, redact before truncation or skip recording the body when it can no longer be parsed/redacted. Document that only JSON bodies are redacted and fail safe (drop body) otherwise.

#### H10 · 🟠 HIGH · GraphQL guard does not traverse named fragment spreads, bypassing depth and complexity limits

- **Where:** `src/plugins/graphql_guard/parse.rs`:176-187  
- **Dimension:** security · **Subsystem:** `sec-llm-gql` · **Confidence:** high  

**What's wrong.** In walk(), a Selection::FragmentSpread is charged only `cfg.default_field_cost` and its definition is never visited (lines 176-182); the collected named fragments at lines 45-55 are bound to `_fragments` and never used. Depth is computed solely from inline selection sets and inline fragments. An attacker can move all expensive/deep selections into named fragments and reference them via spreads: e.g. `query { a { ...F } } fragment F on T { b { c { d { ...G } } } } fragment G on T { ...repeat }`. The deep/expensive subtree lives in the fragment body, so summary.depth stays ~2 and summary.complexity stays ~default_field_cost, sailing under the QUERY_TOO_DEEP (mod.rs 264), QUERY_TOO_COMPLEX (mod.rs 300), and TOO_MANY_ALIASES (mod.rs 282, since aliases inside fragments are never counted) checks. Most GraphQL servers fully expand fragments before execution.

**Impact.** The DoS protections this plugin exists to provide (it is pitched as protecting upstreams from deep-nesting/complexity attacks that generic gateways miss) are trivially bypassable by expressing the abusive query through named fragments. The expensive query reaches the upstream unblocked, defeating depth/complexity/alias enforcement. The behavior is documented as a 'v1 limitation' but is exploitable in production.

**Fix.** Resolve named fragment spreads against the pre-collected fragment map during the walk (with cycle detection / a visited set to avoid infinite recursion), inlining their selection sets so depth, complexity, and alias counts reflect post-expansion shape. Until then, reject documents containing fragment spreads when limits are enabled, or refuse queries whose fragment graph is cyclic.

#### H11 · 🟠 HIGH · Per-consumer LLM/GraphQL/anomaly keys derive from client-spoofable x-consumer-username without ingress stripping

- **Where:** `src/plugins/llm_gateway/mod.rs`:171-176  
- **Dimension:** security · **Subsystem:** `sec-llm-gql` · **Confidence:** medium  

**What's wrong.** The LLM gateway derives the rate-limit/cost/metrics identity straight from the inbound `x-consumer-username` header (lines 171-176), as do graphql_guard (mod.rs:229-234 for field rate-limit keying and anonymous-mutation bypass) and anomaly_detector (mod.rs:104-124). The proxy entry path (src/proxy/handler.rs around line 613-624) reads this header but does NOT strip an inbound client-supplied value before the plugin chain runs; it is only overwritten if an auth plugin (key_auth/basic_auth/hmac_auth/session) happens to run and call headers.insert (e.g. src/plugins/key_auth.rs:108). On any route where these plugins run without a preceding authenticating plugin, the client fully controls the value.

**Impact.** A client can set x-consumer-username to an arbitrary or rotating value to: evade the per-consumer LLM token/request rate limits and cost accounting (buckets keyed per name), evade GraphQL per-field rate limits, masquerade as 'anonymous' or any consumer to flip the block_mutations_for_anonymous decision, and poison/sidestep anomaly-detector baselines (each forged identity gets a fresh warmup baseline). On an internet-facing data plane this neutralizes the abuse/cost controls these plugins provide.

**Fix.** Strip inbound x-consumer-username (and x-consumer-id) from client requests at ingress before the plugin chain runs, so only authenticating plugins can set them. Where these plugins need identity, source it from a trusted request extension populated by auth rather than from the raw header.

#### H12 · 🟠 HIGH · Digest auth accepts any client-supplied nonce with no server-side nonce issuance/tracking (unbounded replay)

- **Where:** `src/plugins/digest_auth.rs`:133-175, 91-97  
- **Dimension:** security · **Subsystem:** `sec-plugin-auth` · **Confidence:** high  

**What's wrong.** build_challenge() generates a fresh random nonce per 401 (line 92), but validate() (lines 133-175) recomputes the expected response using the nonce taken directly from the client's Authorization header (params.get("nonce"), line 138) and never checks that the server actually issued that nonce. There is no nonce store, no opaque value, no nonce expiry, and no nonce-count (nc) tracking anywhere in the file (confirmed: no nonce_store/used_nonces/seen_nonce in the codebase). validate() simply does `expected == *response` against whatever nonce/nc/cnonce the client provides.

**Impact.** An attacker who observes a single valid `Authorization: Digest ...` header (e.g. via logs, a proxy, or a downgraded link) can replay it indefinitely. Because the server never verifies it minted the nonce and never tracks nc, captured digest responses authenticate forever. This defeats the core anti-replay property digest auth is supposed to provide.

**Fix.** Maintain a server-side store of issued nonces (with creation time and a monotonically increasing expected nc per nonce), reject any nonce the server did not issue or that has expired, and reject any (nonce, nc) pair already seen. Use a stale=true challenge to rotate nonces. Bind the nonce to a short TTL.

#### H13 · 🟠 HIGH · Digest auth validates against the client-claimed `uri` param, never the actual request target (path-confusion auth bypass)

- **Where:** `src/plugins/digest_auth.rs`:133-175, 208-218  
- **Dimension:** security · **Subsystem:** `sec-plugin-auth` · **Confidence:** high  

**What's wrong.** validate() computes HA2 = SHA256(method:uri) using `uri` taken from the Authorization header params (line 158-161, 168), and is invoked with only `method` and `params` (line 212). It never compares params["uri"] against the real request URI (req.uri().path_and_query()). The method is the real req.method(), so method is bound, but the request target is not.

**Impact.** A captured/valid Digest header that was computed for one resource (e.g. uri="/public") authenticates a request sent to a completely different path (e.g. /admin/delete) as long as the HTTP method matches, because the server validates the digest against the attacker-claimed uri, not the path actually being requested. Combined with the missing nonce tracking, one captured digest header authorizes requests to arbitrary paths.

**Fix.** After parsing, require params["uri"] to exactly equal the effective request target (req.uri().path_and_query()) before/while validating, and reject on mismatch. Also enforce qop=="auth" and algorithm=="SHA-256" rather than echoing the client-supplied values into the hash.

#### H14 · 🟠 HIGH · HMAC remote (keyx) mode does not set or clear x-consumer-* identity headers, letting clients spoof identity to ACL

- **Where:** `src/plugins/hmac_auth.rs`:230-238, 240-255, 313-320  
- **Dimension:** security · **Subsystem:** `sec-plugin-auth` · **Confidence:** high  

**What's wrong.** In keyx/remote mode the consumer lookup is 'best-effort' and can be None (lines 230-238, comment lines 226-229). The downstream identity headers are only inserted `if let Some(c) = consumer` (lines 313-320), so when consumer is None they are not set — and nothing strips an inbound, client-supplied `x-consumer-username`/`x-consumer-id`. The proxy handler reads client-supplied x-consumer-username straight from request headers (src/proxy/handler.rs:616-619) and the ACL plugin (src/plugins/acl.rs:33-49) makes its allow/deny decision based on that header with no provenance check. No inbound stripping of x-consumer-* exists.

**Impact.** After passing HMAC verification in remote mode (or in any flow where consumer resolves to None), a client can send `X-Consumer-Username: admin` and it flows untouched into ACL authorization and per-consumer rate-limiting/metering. This is an authorization bypass / identity spoof via a trusted-but-unauthenticated header.

**Fix.** Always overwrite (or explicitly remove) x-consumer-username / x-consumer-id at the start of every auth plugin's success path, even when the consumer row is unknown. Additionally, strip all inbound x-consumer-* (and x-jwt-claims, x-oauth-subject) headers at ingress before plugins run so they can never be client-supplied.

#### H15 · 🟠 HIGH · Subdomain host-match fast path (match_route_for_service) ignores route hosts/headers/query_params constraints

- **Where:** `src/proxy/router.rs`:157-179  
- **Dimension:** security · **Subsystem:** `sec-routing` · **Confidence:** high  

**What's wrong.** In proxy_handler (src/proxy/handler.rs:369-377) the subdomain routing fast path calls route_table.match_by_host(h) and then match_route_for_service(&svc.id, path, method). match_route_for_service only evaluates path_matches(route, path) and route.methods — it never checks route.hosts, route.headers, or route.query_params. The general path match_route_full (src/proxy/router.rs:335-416) DOES enforce all of host/header/query constraints. So whenever a Service has subdomain+domain configured (host_index hit), its routes are selected with their header/query/host constraints silently bypassed, and if no route's path/method matches, the handler substitutes Route::passthrough (paths=["/*"], no methods, no constraints, strip_path=false) so the request still proxies through.

**Impact.** An operator who scopes a route with header/query/host conditions (e.g. require header X-Internal=1, or query feature-flag, or a specific Host) believing it gates access can have those conditions bypassed by any client that reaches the gateway over the service's configured subdomain.domain. Routes intended to be conditionally exposed become unconditionally reachable, and the passthrough fallback exposes the entire upstream under that host regardless of method/path constraints.

**Fix.** Make the subdomain fast path enforce the same predicate set as match_route_full: evaluate route.hosts (or skip the dedicated host check since host already matched), route.headers via match_headers, and route.query_params via match_query before accepting a route. Do not fall back to a wide-open Route::passthrough when constrained routes exist for the service; return RouteNotFound instead, or only passthrough when the service explicitly opts into catch-all behaviour.

#### H16 · 🟠 HIGH · Discovered upstream URLs are never scheme/host-validated before becoming proxy targets (SSRF to metadata/internal/unix/file)

- **Where:** `src/discovery/consul.rs`:414-424, 296-302  
- **Dimension:** security · **Subsystem:** `sec-ssrf` · **Confidence:** high  

**What's wrong.** Every dynamic provider copies a backend-supplied `url` string straight into `Service.url` with no validation of scheme or host. In Consul KV the value is `cfg.url` (consul.rs:417) taken verbatim from a base64+JSON KV blob; the catalog path builds `http://{addr}:{port}` from `ServiceAddress`/`Address` (consul.rs:295) with no check that the address isn't link-local. The same pattern exists in src/discovery/etcd.rs:298 (`url: cfg.url`), src/discovery/redis_kv.rs:236 (`url: cfg.url`), src/discovery/http_provider.rs:264/281 (`url: svc.url.clone()`), src/discovery/nomad.rs:223-226 (tag-supplied `...http.services.<svc>.url`), and the Docker `lynxx.service.url` label (src/discovery/docker.rs:561). There is no allow-list, no scheme allow-list, and no private/link-local/loopback filter anywhere (confirmed by grep across src/discovery and src/db). The handler then parses `service.url` into `upstream_uri` and forwards (src/proxy/handler.rs:1048-1050, 1100-1132), and the unix-socket branch at handler.rs:867 will happily dial a `unix://` path embedded in a discovered URL.

**Impact.** Any actor able to write to the configured discovery backend — a multi-tenant Consul/etcd/Redis KV, a CI pipeline publishing the HTTP-provider JSON, or a workload that can set its own Docker/Nomad labels — can register an upstream of `http://169.254.169.254/...` (cloud metadata / IMDS), `http://127.0.0.1:<admin-port>`, an arbitrary internal host, or `unix:///var/run/...`. Client requests routed to that service are then proxied to the attacker-chosen internal target, and the response body is returned to the client: full SSRF against the gateway's network position, including cloud credential theft via IMDS.

**Fix.** Validate every discovered `url` before persisting it as a service: enforce an allow-list of schemes (`http`/`https`, plus `unix` only if explicitly enabled), reject hosts that resolve to loopback/link-local/private ranges unless an operator opt-in flag is set, and reject `169.254.169.254`/`fd00:ec2::254` by default. Centralise this in a shared `validate_upstream_url` helper called from every provider's reconcile path.

#### H17 · 🟠 HIGH · Static file serving has no symlink containment (lexical-only path check in safe_resolve)

- **Where:** `src/proxy/static_files.rs`:311-325, 839-947, 1055-1169  
- **Dimension:** security · **Subsystem:** `sec-static` · **Confidence:** high  

**What's wrong.** safe_resolve() only performs lexical traversal defense: it rejects request paths whose string contains ".." and whose joined PathBuf has a ParentDir component, then returns root.join(clean). It never canonicalizes the resolved path nor verifies it stays within document_root, and the file is read with plain tokio::fs::metadata/fs::read (try_serve_file / try_serve_file_with_fs), which follow symlinks. There is zero canonicalize()/realpath/starts_with(root) containment anywhere in the serve path (confirmed by grep: no canonicalize in static_files.rs). A symlink placed under the document root (e.g. /var/www/html/leak -> /etc, or a checked-out repo/archive containing a symlink, or an attacker who can write into an upload dir) is followed and its target served. The directory-listing code even uses symlink_metadata only to *annotate* targets, never to block serving them.

**Impact.** An attacker requesting /leak/passwd (where leak is a symlink to /etc) reads arbitrary files outside the document root — e.g. /etc/passwd, app secrets, TLS private keys. Any deployment that serves a directory tree containing symlinks (common with build artifacts, node_modules, extracted tarballs, or user-uploaded content) is exposed. This is an arbitrary-file-read on an internet-facing data plane.

**Fix.** After safe_resolve, canonicalize the candidate (tokio::fs::canonicalize) and the root, and reject if the canonical candidate does not start with the canonical root. Alternatively open with O_NOFOLLOW on the final component / walk components rejecting symlinks, and add a config switch (e.g. follow_symlinks=false by default) like nginx's disable_symlinks.

#### H18 · 🟠 HIGH · Configured hide_patterns are dropped and only 9 hardcoded names are hidden — arbitrary dotfiles (.aws/.ssh/.npmrc) are served

- **Where:** `src/proxy/handler.rs`:659-683  
- **Dimension:** security · **Subsystem:** `sec-static` · **Confidence:** high  

**What's wrong.** The production static handler builds ServeOptions with hide_patterns: &[] hardcoded (handler.rs:660), so any operator-configured hidden patterns are never passed to serve_with_options. As a result only DEFAULT_HIDDEN (static_files.rs:19-29: .git, .env, .DS_Store, .htaccess, .htpasswd, Thumbs.db, desktop.ini, .svn, .hg) are blocked. is_hidden_path (static_files.rs:328-347) does an exact, case-sensitive segment == pattern comparison and has no general "any dotfile" rule. So files/dirs such as /.aws/credentials, /.ssh/id_rsa, /.npmrc, /.git-credentials, /config.php~, /.well-known/../<x>, backup files (*.bak, *.orig) and Composer/NPM lock dirs are served directly. The directory-listing renderer skips '.'-prefixed entries (line 618) but direct file GETs do not, so the skip provides no protection against a client that knows the name. Case-sensitive compare also means /.ENV resolves to .env on case-insensitive filesystems (macOS/Windows) and is served.

**Impact.** Sensitive dotfiles and backup files placed anywhere under the document root are downloadable by unauthenticated clients, and operators who set a hide_patterns config get a false sense of protection because the setting is silently ignored on the real serving path. Credential/secret disclosure.

**Fix.** Wire service config hide_patterns through to ServeOptions.hide_patterns instead of &[]. Add a default rule to hide any path segment beginning with '.' (with an opt-in for .well-known), and make pattern matching case-insensitive on case-insensitive filesystems.

#### H19 · 🟠 HIGH · lynxx_random_bytes allocates an unbounded host Vec from guest-controlled len (host OOM DoS)

- **Where:** `src/plugins/wasm/host.rs`:310-342  
- **Dimension:** security · **Subsystem:** `sec-wasm` · **Confidence:** high  

**What's wrong.** In the `lynxx_random_bytes` host function the only validation of the guest-supplied length is `if len <= 0 { return 0; }`. Immediately after, the host allocates a host-side buffer with `let mut buf = vec![0u8; len as usize];` and only *after* filling it does it attempt `memory.write(&mut caller, ptr as usize, &buf)`. `len` is an `i32` chosen by the guest, so a guest can pass `len = i32::MAX` (~2.1 GB) and force the HOST process to allocate ~2 GB of zeroed memory before the wasm linear-memory bounds check (inside `memory.write`) ever rejects the oversized write. The allocation is in the host's address space, not the sandboxed linear memory, so the per-store `StoreLimits.memory_size` cap (build_limits in mod.rs) does NOT bound it. Fuel is also not consumed proportionally to the host-side allocation. Contrast with `read_bytes`/`write_bytes` which validate against `memory.data(caller).len()` before copying; this path validates nothing about `len` against guest memory size before the host allocation.

**Impact.** An attacker who can get any wasm plugin (or a malicious/compromised plugin module) to call `lynxx_random_bytes` with a large length triggers a multi-gigabyte host allocation per request. A single request can OOM-kill the internet-facing gateway process, or repeated requests cause memory pressure / allocator thrash across all tenants sharing the data plane. Because the allocation happens before any bounds check, even a 'too-large' call that ultimately fails the write still consumes the host RAM transiently.

**Fix.** Cap `len` to a small sane maximum (e.g. the configured body_max_bytes or a few KB) before allocating, returning ERR_TOO_LARGE otherwise. Better: bounds-check `ptr`/`len` against `memory.data(&caller).len()` first (mirroring read_bytes), and only allocate a buffer no larger than the validated guest region. Avoid `vec![0u8; len]` on guest-controlled sizes entirely.

#### H20 · 🟠 HIGH · key-auth / basic-auth / hmac-auth fetch the entire consumers table (list_consumers) and linear-scan it on every authenticated request

- **Where:** `src/plugins/key_auth.rs`:88-112  
- **Dimension:** performance · **Subsystem:** `perf-db-conc` · **Confidence:** high  

**What's wrong.** KeyAuthPlugin::on_request runs on every proxied request that has the key-auth plugin enabled. It calls `repo.list_consumers().await` (src/plugins/key_auth.rs:97-100) which executes `SELECT id, username, custom_id, api_key, ... FROM consumers WHERE is_deleted = 0` against the DB and materialises EVERY consumer row into a Vec (src/db/sqlite.rs:513-521, src/db/postgres.rs:503-511), then does an in-memory linear scan `consumers.into_iter().find(|c| c.api_key.as_deref() == Some(key))` (key_auth.rs:102-105). The identical anti-pattern is repeated in basic-auth (src/plugins/basic_auth.rs:83-98, scan by username then argon2 verify) and hmac-auth (src/plugins/hmac_auth.rs:230-238, scan by username). There is NO consumer cache and NO indexed/parameterised lookup anywhere in the codebase — `grep` for a `get_consumer_by_api_key`/`get_consumer_by_username` repository method finds none; the Repository trait only exposes `list_consumers()` for these lookups. The plugin chain (src/plugins/mod.rs:354-368 run_request) invokes this per request with no result caching.

**Impact.** Every request through an API-key / basic / HMAC protected route issues a full-table read of `consumers` plus an O(N) CPU scan on the tokio runtime. At a few hundred consumers and a few thousand RPS this is a constant stream of full-table SELECTs that saturate the 8-connection DB pool (see related pool finding), add a DB round-trip to every request's latency, and scale linearly with consumer count — a deployment that adds consumers silently slows down its entire authenticated data plane. On SQLite this also contends for the single writer/reader lock.

**Fix.** Add an indexed repository lookup (`get_consumer_by_api_key(&str)` / `get_consumer_by_username(&str)` backed by a UNIQUE index on `consumers.api_key` / `consumers.username`) and/or an in-memory consumer cache (DashMap keyed by api_key/username) refreshed on the existing cluster-bus reload events, mirroring how RouteTable caches routes. For hmac local mode the secret can be cached the same way with invalidation on consumer update. This turns the per-request cost from O(consumers) + full-table fetch into an O(1) cache hit.

#### H21 · 🟠 HIGH · Service struct deep-cloned by value on every request in route lookup (get_service / match_by_host)

- **Where:** `src/proxy/router.rs`:150-154, 239-241, 335-416  
- **Dimension:** performance · **Subsystem:** `perf-hotpath` · **Confidence:** high  

**What's wrong.** `match_route_full` returns `(Arc<Route>, Service)` and `match_by_host` returns `Service` — both obtain the `Service` via `self.services.get(id).map(|s| s.clone())` (lines 153 and 240). `Route` was deliberately wrapped in `Arc` to avoid deep clones (see the doc comment on `routes: DashMap<Uuid, Arc<Route>>`, line 32-42), but `Service` was NOT given the same treatment. The `Service` struct (src/models/mod.rs:60-138) has ~30 fields including `url: String`, `lb_strategy: String`, `service_type: String`, `index_file: String`, `domain: String`, `subdomain: String` plus 6+ `Option<String>` (TLS paths, lb_hash_header, lb_hash_query_param, document_root). Cloning it heap-allocates 6+ Strings unconditionally per request. The proxy handler calls this on every request: `match_by_host` at handler.rs:371 and `match_route_full` at handler.rs:380.

**Impact.** Every single proxied request pays 6+ heap allocations plus the memcpy of the whole Service struct purely to satisfy the by-value return type. At 100k RPS this is 600k+ allocator hits/sec of pure waste — directly inflating p99 and CPU on the hot path the recent ktls/telemetry work was trying to shave. Only a handful of Service fields (`url`, `name`, `lb_strategy`, ids, `pass_host_header`, `service_type`, `document_root`) are actually read downstream.

**Fix.** Store services as `DashMap<Uuid, Arc<Service>>` (mirroring the `routes` map) and have `get_service` / `match_by_host` / `match_route_full` return `Arc<Service>`. The handler already treats most fields as read-only borrows, so the change is mechanical (`service.id`, `service.name.clone()` on an `Arc<str>` stays cheap). This turns a multi-allocation deep clone into one atomic refcount bump per request.

#### H22 · 🟠 HIGH · Buffering plugin spills bodies to /tmp with blocking std::fs write+read inside the async on_request/on_response path

- **Where:** `src/plugins/buffering.rs`:83-108, 117-143, 145-171  
- **Dimension:** performance · **Subsystem:** `perf-plugins` · **Confidence:** high  

**What's wrong.** buffer_bytes is called from the async on_request/on_response with no spawn_blocking. For bodies above mem_threshold it does std::fs::File::create, file.write_all(data), file.flush(), then std::fs::read of the whole file, then std::fs::remove_file — all synchronous blocking syscalls executed directly on a tokio worker thread. Worse, the spill round-trips the entire body through disk and reads it straight back into a Vec (std::fs::read at line 104), so even the disk path keeps the full body resident in memory anyway — the data.to_vec() in the in-memory path and the read-back both produce a full heap copy. The temp filename uses SystemTime nanos + pid, which can collide under concurrency, and cleanup is best-effort so a panic leaks the temp file.

**Impact.** A large upload/download stalls the tokio worker thread on blocking disk IO, starving every other task scheduled on that worker and spiking tail latency for unrelated requests. The disk round-trip provides no memory benefit (contradicting the module doc claiming bounded resident memory) — it adds two full-body copies plus disk IO. At scale this serializes the runtime and can cause request timeouts.

**Fix.** Wrap the disk spill in tokio::task::spawn_blocking (or use tokio::fs). Better: for the in-memory path return the Bytes directly without to_vec, and for true spillover keep an on-disk handle and stream it back via a memory-mapped/streaming Body rather than std::fs::read-ing the whole file into a Vec. Use tempfile crate (O_TMPFILE / mkstemp) to avoid filename collisions and guarantee cleanup.

#### H23 · 🟠 HIGH · Response compression runs gzip/brotli/zstd synchronously on the tokio runtime with no spawn_blocking

- **Where:** `src/plugins/response_compression.rs`:329-369  
- **Dimension:** performance · **Subsystem:** `perf-plugins` · **Confidence:** high  

**What's wrong.** on_response buffers the whole response body (body.collect().await) and then runs the chosen codec inline on the async task: flate2 GzEncoder.write_all/finish, brotli::CompressorWriter.write_all, or zstd::encode_all(bytes.as_ref(), level). All three are CPU-bound, fully synchronous, and executed directly on the tokio worker thread that is driving the request future. Brotli at the configurable level (up to 11) and gzip level 9 can take many milliseconds for moderately sized bodies.

**Impact.** Compressing a large response blocks the tokio worker for the entire duration of the compression, preventing it from polling any other connection's futures. Under concurrency this collapses throughput and inflates p99 for all co-scheduled requests, not just the one being compressed — the classic 'CPU-bound work on the async runtime' anti-pattern in a latency-sensitive data plane.

**Fix.** Move the encode step into tokio::task::spawn_blocking (or a dedicated rayon/blocking pool) so the runtime worker stays free to poll IO. Consider a streaming compressor (async-compression) so large bodies don't have to be fully buffered before compression begins.

#### H24 · 🟠 HIGH · Proxy-cache map grows unbounded — expired entries are never removed and there is no size/capacity limit

- **Where:** `src/plugins/proxy_cache.rs`:19-28, 127-145, 211-219  
- **Dimension:** performance · **Subsystem:** `perf-plugins` · **Confidence:** high  

**What's wrong.** The process-global CACHE is a DashMap<String, CacheEntry> with no maximum size and no eviction sweep. The comment at line 127 says 'Eviction: if entry exists but has expired, drop it before lookup', but the code only SKIPS an expired entry on read (returns None) — it never calls remove, so the stale CacheEntry (including its full body Vec) stays in the map forever. There is no retain/clear/LRU and no cap on entry count. cache_key_strategy 'method_path_query' keys on the full query string, so distinct query strings each create a permanent entry.

**Impact.** An attacker (or just normal traffic with high-cardinality query strings) can drive unbounded memory growth: each unique key inserts a CacheEntry that is never reclaimed even after TTL expiry, leading to OOM. As the map grows, shard sizes and rehash cost rise, degrading every cache lookup. This is both a memory-exhaustion DoS and a steady performance regression over uptime.

**Fix.** Bound the cache (e.g. moka or a sharded LRU with a max entry/byte budget and TTL-based expiry that actually evicts). At minimum, remove the expired entry on read (self.cache.remove(&key)) and run a periodic background sweep to purge expired keys.

#### H25 · 🟠 HIGH · HTTPS gRPC builds a fresh hyper client (new connection pool) on every request

- **Where:** `src/proxy/grpc.rs`:57-74  
- **Dimension:** performance · **Subsystem:** `qual-proxy` · **Confidence:** high  

**What's wrong.** In `handle_grpc`, the `https` scheme branch calls `build_grpc_tls_client()` inline for every request (line 59), constructing a brand-new `hyper_util` `Client` with its own `HttpsConnector` and connection pool. The h2c `GrpcClient` is built once at startup and shared (main.rs:487, stored in `ProxyState.grpc_client`), but the TLS client is never cached. Each HTTPS gRPC request therefore performs a full TCP + TLS handshake (no connection reuse) and allocates a fresh pool that is dropped when the function returns. `handle_grpc_web` routes to the same code path, so it inherits the cost.

**Impact.** Every HTTPS gRPC / grpc-web call pays a full TLS handshake and connector build instead of reusing a pooled h2 connection — large per-request latency (often 1-50ms) and CPU cost, plus churn of short-lived sockets/idle-pool allocations under load. Negates the whole point of the shared-client design used elsewhere.

**Fix.** Build the TLS gRPC client once at startup (alongside `build_grpc_client()`), store it in `ProxyState` next to `grpc_client`, and pass it into `handle_grpc`. Optionally cache per-service like `ProxyClientPool` does for the HTTP hot path.

#### H26 · 🟠 HIGH · Docker / SRV-DNS provider discoveries never go live on the originating node (self-published bus events are filtered)

- **Where:** `src/discovery/docker.rs`:431-511  
- **Dimension:** quality · **Subsystem:** `qual-core` · **Confidence:** high  

**What's wrong.** DockerProvider (and SrvDnsProvider) converge discovered entities by writing to the DB (repo.create_service/create_route/create_target) and then calling self.publish(ChangeEvent::ServiceCreated/RouteCreated/TargetChanged { origin: self.node_id }). The provider struct holds only config/docker/repo/bus/node_id/owned (lines 118-128) — it has NO handle to the live RouteTable, LoadBalancerRegistry, or HealthRegistry and never updates them directly. The only path that refreshes in-memory state from a ChangeEvent is the cluster subscriber's apply_remote_event, but both bus backends drop self-originated events: SqliteBus `if event.origin() == node_id { continue; }` (src/cluster/sqlite.rs:108) and PostgresBus the same (src/cluster/postgres.rs:74). main.rs passes the SAME node_id to the docker provider (src/main.rs:751) and to spawn_cluster_subscriber (src/main.rs:713).

**Impact.** On a single-node deployment (the common case) a container started/stopped via the Docker provider, or an SRV record change, is persisted to the DB and a bus event is emitted, but the gateway never updates its in-memory routing/LB tables — so the discovered service/route/target does not actually serve or stop serving traffic until the gateway is restarted (or an unrelated /reload FullSync happens). Discovery appears to work (rows/logs show it) but routing silently does not reflect it. Multi-node peers DO apply it (origin differs); only the discovering node is stuck.

**Fix.** Have the provider update the in-memory RouteTable/LoadBalancerRegistry/HealthRegistry locally (the same mutations apply_remote_event performs) in addition to publishing the bus event, OR have apply_remote_event run for self-origin events too while still skipping the redundant DB refetch. Pass the route_table/lb/health handles into DockerProvider/SrvDnsProvider.

#### H27 · 🟠 HIGH · Audit hash-chain fork under concurrent admin writes (no locking on Postgres)

- **Where:** `src/db/postgres.rs`:809-834  
- **Dimension:** quality · **Subsystem:** `qual-data` · **Confidence:** high  

**What's wrong.** append_audit does SELECT hash ... ORDER BY id DESC LIMIT 1 then INSERTs inside a plain pool.begin() transaction. The Postgres pool uses default READ COMMITTED (no SERIALIZABLE, no SELECT ... FOR UPDATE, no advisory lock) and there is no UNIQUE index on hash/prev_hash. Two concurrent admin requests can read the same prev_hash, compute hashes off the same parent, and both commit. The code comment claiming writers serialise here is false for Postgres.

**Impact.** The tamper-evident audit chain can be silently forked by ordinary concurrent admin activity (no attacker needed). verify_chain walks linearly via prev, so a fork makes the chain unverifiable, undermining the integrity guarantee.

**Fix.** Serialise appends with pg_advisory_xact_lock on a fixed key, or SERIALIZABLE + retry, or a UNIQUE constraint on prev_hash so forks fail loudly. SQLite needs BEGIN IMMEDIATE equivalent.

#### H28 · 🟠 HIGH · verify_chain only inspects the most recent 1000 rows and falsely reports breakage past 1000 entries

- **Where:** `src/audit/mod.rs`:211-254  
- **Dimension:** quality · **Subsystem:** `qual-data` · **Confidence:** high  

**What's wrong.** verify_chain's doc says it recomputes from row 1, but it calls list_audit with limit Some(1000); list_audit orders ts DESC,id DESC and clamps to 1000, so only the newest 1000 rows are fetched. After sort_by_key(id), the first checked row is not row 1 once the log exceeds 1000 entries; verification starts with prev=None so row.prev_hash != prev is true and it returns ok:false. Older rows are never verified.

**Impact.** Once the audit log exceeds 1000 rows, verification always reports a false integrity failure and all but the newest 1000 entries are never checked — defeating tamper detection exactly when the log is large.

**Fix.** Verify the full table from id=1 ascending, paging through all rows, seeding prev from the first row's actual prev_hash rather than None.

#### H29 · 🟠 HIGH · Overage call counts are never persisted, losing billing data on every restart

- **Where:** `src/quota/mod.rs`:270-277  
- **Dimension:** quality · **Subsystem:** `qual-data` · **Confidence:** high  

**What's wrong.** Paid-tier overages are documented as billed, but flush() only persists calls and rejected (upsert_quota_usage(period, calls, rejected)); overage is incremented in memory only. quota_usage has no overage column anywhere, and load() always initialises overage to 0.

**Impact.** All overage accounting is in-memory and resets to 0 on every restart/redeploy/crash. Billable overage is silently lost → systematic under-billing of Pro/Business tenants and an unauditable billing record.

**Fix.** Add a calls_overage column (both backends + migration), persist overage in flush(), and load it back in QuotaTracker::load().

#### H30 · 🟠 HIGH · request-recorder PENDING capture map leaks entries (and buffered request bodies) when on_response never matches

- **Where:** `src/plugins/request_recorder/mod.rs`:40-44, 193, 205-221  
- **Dimension:** quality · **Subsystem:** `qual-plugins` · **Confidence:** high  

**What's wrong.** A sampled request inserts a PendingCapture into the process-global static `PENDING` DashMap (line 193) keyed by a freshly minted uuid, and stashes a copy of the (truncated) request body of up to `max_body_bytes` (default 1 MiB) inside it. The ONLY place the entry is removed is `on_response` at line 218, gated on the matching `x-lynxx-recorder-id` header reaching the response. There is no TTL/sweeper for PENDING — `spawn_retention_sweeper` only prunes the DB index, not this map. The recorder id is bridged from request to response by the proxy handler (handler.rs line 1060 captures it, line 977/1559 re-attaches), but several reachable paths never re-attach it: (a) the upstream proxy call returns `Err` before the bridge (e.g. unix-socket error path handler.rs ~line 932, connect failures, body-read errors), (b) a later plugin's `on_response` returns `Err`, which `PluginExecutor::run_response` (mod.rs lines 380-382) propagates with `?` BEFORE the recorder (chain runs in reverse) gets to remove its entry, (c) a plugin ordered after request-recorder short-circuits or errors in `on_request` so the response path bypasses the bridge. In all these cases the PENDING entry — including up to 1 MiB of buffered body — leaks permanently.

**Impact.** On any deployment that hits these error/short-circuit paths under load, the global PENDING map grows without bound, retaining buffered request bodies indefinitely. This is an unbounded memory leak that an attacker can amplify by driving requests through a path that errors before the response bridge (e.g. an unreachable/unix upstream) while the recorder is sampling, eventually OOM-ing the gateway. Recording is documented as best-effort and should never accumulate state.

**Fix.** Store an insertion timestamp in PendingCapture (it already has `started: Instant`) and add a background sweeper (mirroring spawn_retention_sweeper) that periodically evicts entries older than a bound (e.g. a few minutes). Additionally bound the map size. Consider also having the proxy handler always attempt to remove the pending entry on error paths.

#### H31 · 🟠 HIGH · TokenCountingStream buffer grows unbounded on SSE streams lacking frame terminators

- **Where:** `src/plugins/llm_gateway/stream.rs`:78-91, 184-203  
- **Dimension:** quality · **Subsystem:** `qual-plugins` · **Confidence:** high  

**What's wrong.** `poll_next` appends every upstream chunk into `self.buffer` via `extend_from_slice` (line 187), then `process_buffer` (lines 78-91) only drains bytes up to the last complete `\n\n` frame separator: `self.buffer.drain(0..pos)` where `pos` is the end of the last terminated frame. Any trailing bytes with no `\n\n` separator are retained for the next poll. There is no cap on `self.buffer`. This stream wraps a genuinely incremental upstream (`dispatch_result.response.bytes_stream()`, mod.rs line 398-417) forwarded to the client via `Body::from_stream`, so it is fed live from the upstream. A malicious or malformed upstream that streams a very large `data:` payload (or simply never emits a `\n\n` terminator until the very end) forces the gateway to buffer the entire response body in memory in addition to forwarding it, with no limit.

**Impact.** A compromised/misbehaving LLM upstream (or one an attacker can influence) can drive the gateway to buffer arbitrarily large amounts of data per concurrent stream, exhausting memory. The token-counting side channel makes the gateway's resident footprint scale with the largest unterminated SSE frame rather than staying bounded.

**Fix.** Cap `self.buffer` length: if it exceeds a sane maximum (e.g. a few hundred KB of un-terminated data), stop accumulating / counting and clear the buffer (token counting is best-effort), or drop the leading bytes. Forwarding to the client is unaffected since the raw `bytes` are passed through independently of the buffer.

#### H32 · 🟠 HIGH · Streaming LLM token refund compares input estimate against completion tokens, under-charging the rate-limit bucket

- **Where:** `src/plugins/llm_gateway/stream.rs`:205-227  
- **Dimension:** quality · **Subsystem:** `qual-plugins` · **Confidence:** high  

**What's wrong.** At admission, `buckets.check(consumer, est_input)` charges the consumer's token bucket `est_input` INPUT tokens (buckets.rs line 112). For the streaming path, `TokenCountingStream::drop` computes `actual_total = upstream_completion_tokens.unwrap_or(self.usage.completion_tokens)` — a COMPLETION-token count — then `delta = initial_estimate (est_input) - actual_total` and calls `self.buckets.refund(consumer, delta)`. This subtracts two unrelated quantities (input estimate minus output tokens). When the prompt is large and the completion short, `delta` is large positive and `refund` (buckets.rs lines 143-144) subtracts it from the bucket — effectively refunding most of the input tokens that were legitimately charged, and never adding the completion tokens that should be charged. The buffered (non-streaming) path does this correctly: `deduct(consumer, (input - est_input) + output)` (mod.rs lines 456-457). The in-code TODO at line 222 acknowledges the formula is wrong but the buggy version ships.

**Impact.** Streaming LLM requests systematically under-deduct from the per-consumer token-per-minute bucket compared to identical non-streaming requests, and can even net-refund tokens for large-prompt/short-output requests. A consumer can bypass token rate limits / quotas (and skew cost accounting) simply by setting stream=true.

**Fix.** On the streaming side, charge the completion tokens after the fact like the buffered path: call `buckets.deduct(consumer, actual_completion_tokens)` (plus any input correction `upstream_prompt_tokens.saturating_sub(est_input)`), rather than `refund(est_input - completion)`. Only refund when the client cancels mid-stream and the actual usage is genuinely below the estimate.

---

## 🟡 Medium findings (40)

#### M1 · 🟡 MEDIUM · Admin CORS allows any origin and any header, exposing admin API responses to cross-origin reads

- **Where:** `src/admin/mod.rs`:674-687  
- **Dimension:** security · **Subsystem:** `sec-admin` · **Confidence:** high  

**What's wrong.** admin_cors() builds a CorsLayer with allow_methods(GET/POST/PUT/DELETE/PATCH/OPTIONS), allow_headers(Any), allow_origin(Any), and expose_headers(Any) (lines 674-687). This layer wraps the entire admin router including the unauthenticated /admin/v1/config sub-router and (in default bootstrap mode) all other admin routes. With allow_origin(Any) the browser permits any website's JavaScript to issue these requests and READ the responses. Because admin auth uses Bearer tokens rather than cookies (and credentials are not set), the lack of allow_credentials does not protect the endpoints that require no credentials at all — e.g. GET /admin/v1/config or, in bootstrap mode, every read endpoint.

**Impact.** Any malicious web page visited by an operator (or any browser able to route to the admin host, e.g. on an internal network) can silently read the full gateway config and other admin data cross-origin, and issue state-changing requests against unauthenticated routes. This turns the config-leak and bootstrap-mode issues into drive-by, browser-deliverable attacks.

**Fix.** Restrict allow_origin to an explicit, configured allowlist of dashboard origins instead of Any. Restrict allow_headers to the specific headers the dashboard sends. Do not reflect Any on an authentication-bearing admin surface.

#### M2 · 🟡 MEDIUM · SSRF via /admin/proxy/try and /admin/proxy/replay — arbitrary URL fetch with full response returned

- **Where:** `src/admin/docs.rs`:97-143  
- **Dimension:** security · **Subsystem:** `sec-admin` · **Confidence:** high  

**What's wrong.** proxy_try (docs.rs:97-143) takes a caller-supplied body.url and arbitrary method/headers/body and issues `state.http_client.request(method, &body.url).send()`, then returns the upstream status, all response headers, and up to 4096 bytes of the response body to the caller. proxy_replay (src/admin/replay.rs:25-70) is identical with an 8192-byte body. There is no allowlist, no scheme restriction, and no block on internal/link-local/loopback targets. Both routes are gated by the Operator role layer (mod.rs:387-388, 452), but in the default auth_required=false bootstrap mode they are reachable unauthenticated, and even with auth they hand any Operator a full read-SSRF primitive.

**Impact.** An attacker (unauthenticated by default, or any Operator) can make the gateway fetch internal-only URLs — cloud instance metadata (http://169.254.169.254/...), internal admin panels, databases over HTTP, link-local services — and read the responses, enabling internal recon, credential theft from metadata services, and pivoting.

**Fix.** Resolve the target host and reject private/loopback/link-local/unique-local addresses and non-http(s) schemes before sending; enforce an outbound allowlist where possible; consider requiring Admin role and disabling these tools in production. Re-resolve after redirects (or disable redirects) to prevent DNS-rebinding/redirect bypass.

#### M3 · 🟡 MEDIUM · No rate limiting on public /auth/sign-in enables license-key brute force and validation oracle

- **Where:** `src/admin/routes.rs`:1920-1965  
- **Dimension:** security · **Subsystem:** `sec-admin` · **Confidence:** medium  

**What's wrong.** auth_sign_in (routes.rs:1920-1965) is registered as a deliberately public route that bypasses extract_token (mod.rs:486-488). It reads the bearer credential and calls license_state.validate_key(raw), forwarding the key to the keyx/license backend and returning distinct outcomes: success with customer_urn/tier/quota on a valid key, Unauthorized on Rejected, ServiceUnavailable on transport error. There is no rate limiting, lockout, or throttling on this route (grep for governor/tower::limit/RateLimit across src/admin and main.rs finds none on the admin router), and the response cleanly distinguishes 'valid key' from 'invalid key'.

**Impact.** An unauthenticated attacker can brute-force / credential-stuff lnx_live_ license keys against this endpoint at full speed, using it as an oracle to confirm valid keys; a confirmed key is the master Admin credential (see resolve_actor license-key path). It also lets an attacker hammer the upstream license backend (amplification / DoS of keyx).

**Fix.** Add per-IP rate limiting and exponential backoff to /auth/sign-in, return a uniform generic failure for all rejection causes, add metrics/alerting on repeated failures, and consider a short negative-cache to avoid amplifying load on the license backend.

#### M4 · 🟡 MEDIUM · License master-admin key compared with non-constant-time string equality (timing side channel)

- **Where:** `src/auth/middleware.rs`:204-215  
- **Dimension:** security · **Subsystem:** `sec-auth` · **Confidence:** high  

**What's wrong.** The master credential fast-path compares the caller-supplied bearer against the license key with `raw == state.license_api_key` (middleware.rs:205), a standard `&str`/`String` equality that short-circuits on the first differing byte and is therefore not constant-time. A match grants `Role::Admin` with `id = Uuid::nil()` and no expiry (middleware.rs:206-214). The `subtle` crate is declared in Cargo.toml (line 223 `subtle = "2.6.1"`) but is not imported anywhere in `src` (grep for `use subtle`/`subtle::`/`ct_eq` returns nothing), so no constant-time comparison is used for this secret. Note the local DB token path compares SHA-256 *hashes* via DB lookup so it is less exposed, but the license key is compared raw.

**Impact.** An attacker who can issue many admin requests can in principle use response-timing differences to recover the license/master-admin key byte-by-byte. Because this key is also the master admin bearer and the licensing credential (main.rs:536-538), recovery yields full admin-plane access plus license abuse. Exploitability over a network is reduced by jitter but is a real concern for a long-lived high-value secret on an internet-facing data plane.

**Fix.** Compare the raw key in constant time, e.g. hash both sides with `hash_token` and compare the fixed-length hex (or use `subtle::ConstantTimeEq` / a `constant_time_eq` helper). Reject empty keys (already guarded by `!is_empty()`). Consider eliminating the raw-key fast path entirely in favor of a hashed lookup like the DB token path.

#### M5 · 🟡 MEDIUM · License re-verifier and boot path fail open on all non-Rejected errors (network block defeats the kill-switch)

- **Where:** `src/license/mod.rs`:246-265  
- **Dimension:** security · **Subsystem:** `sec-license` · **Confidence:** high  

**What's wrong.** spawn_license_refresher matches validate_license: Ok => debug log, Rejected => flip_inactive, and `Err(e) => tracing::warn!(...; "keeping current state")` for Transport/Http/Malformed (mod.rs:256-262). So the kill-switch is engaged only on an authoritative Rejected. The boot path mirrors this: License::load falls back to the (unsigned, editable) cache on Transport and Http errors, and only returns Err on Rejected/Malformed/Missing (mod.rs:100-109). Note also that keyx.rs maps any 5xx to Http (keyx.rs:150-155) — so an attacker-controlled or DoS'd keyx that always answers 503 is treated as ambiguous and never disables the gateway.

**Impact.** An operator or on-path attacker who simply prevents the gateway from reaching keyx (firewall/DNS sinkhole the AUTH_URL host, or stand up a fake keyx that returns 503) ensures the re-verifier never sees a Rejected and the kill-switch never trips, while the boot path keeps falling back to the editable offline cache. Revocation is effectively bypassable by denying egress; combined with the missing expiry enforcement and the unsigned cache, the license can never be turned off short of an authoritative Rejected reaching the box.

**Fix.** Make sustained inability to re-verify fail closed: after the offline grace window (computed from a trusted/signed timestamp) elapses with no successful verify, flip the kill-switch instead of 'keeping current state'. Track last-successful-verify in the LicenseState and 402 when it exceeds the grace bound. Treat repeated Http/Transport beyond a threshold as degraded rather than indefinitely benign.

#### M6 · 🟡 MEDIUM · No hostname/node binding on license cache or key — single license usable on unlimited hosts; max_nodes never enforced

- **Where:** `src/license/mod.rs`:271-337  
- **Dimension:** security · **Subsystem:** `sec-license` · **Confidence:** high  

**What's wrong.** compute_instance_id() (mod.rs:271-284) hashes hostname + data dir + tenant seed, but it is used only for the admin status display and is NEVER mixed into the cache. write_cache/read_cache bind the cache exclusively to api_key_hash (mod.rs:307-336), so any host with the same api key accepts the same cache file, and a cache file copied between hosts validates unchanged. max_nodes/active_nodes flow from the same unsigned source into LicenseState (main.rs:545-546) but are only surfaced on the admin status endpoint (admin/routes.rs:1873-1893, 1960-1962) — a tree-wide grep finds no code path that rejects requests or boot when active_nodes exceeds max_nodes. The module doc itself states the cache 'covers boot ... provided the api-key hash matches' with no host binding.

**Impact.** The seat/node-cap part of the license is advisory only. One api key (or one copied cache file) runs an unlimited number of gateway instances; the gateway never refuses to start or serve based on node count, so a customer on a 1-node plan can run a fleet. There is no per-host cryptographic binding to detect or prevent cloning.

**Fix.** Have keyx issue node-bound, signed activations (include the instance_id in the signed payload and verify it locally against compute_instance_id), and enforce max_nodes as a hard gate on boot/re-verify rather than only displaying it. Bind the offline cache to the instance_id so a copied cache fails on a different host.

#### M7 · 🟡 MEDIUM · GraphQL guard passes through unknown persisted-query hashes, skipping all guard checks when upstream supports APQ

- **Where:** `src/plugins/graphql_guard/mod.rs`:175-195  
- **Dimension:** security · **Subsystem:** `sec-llm-gql` · **Confidence:** high  

**What's wrong.** When a request carries an APQ hash but no `query`, and the hash is not in the operator's configured persisted_queries map, and persisted_queries_only is false, the plugin restores the original body and returns Ok(()) (lines 188-192) — explicitly noting 'Pass through; upstream may have its own APQ store.' No parsing, depth, complexity, alias, mutation, or introspection check runs because there is no query text to analyze. If the upstream maintains its own Apollo APQ registry (the common Apollo Server default), the previously-registered query executes upstream with zero gateway enforcement.

**Impact.** An attacker who can get any query registered in the upstream's APQ store (Apollo auto-registers on first full query+hash submission) can subsequently invoke it by hash alone and completely bypass the gateway's depth/complexity/alias/introspection/anonymous-mutation guards. This converts the persisted-query optimization into a guard-evasion channel whenever the upstream owns the APQ store.

**Fix.** Do not blindly pass through unknown hashes. Either require persisted_queries_only (reject unknown hashes), or when an unknown hash is seen respond with PersistedQueryNotFound (forcing the client to send the full query so it can be analyzed) rather than forwarding it. At minimum make passthrough-on-unknown-hash an explicit opt-in that warns it disables enforcement.

#### M8 · 🟡 MEDIUM · OAuth2 introspection caches active=true for full TTL, ignoring token exp and IdP revocation

- **Where:** `src/plugins/oauth2_introspect.rs`:130-161, 196-214  
- **Dimension:** security · **Subsystem:** `sec-plugin-auth` · **Confidence:** high  

**What's wrong.** introspect() reads only `active`, `sub`, and `scope` from the RFC 7662 response and discards the standard `exp` field (lines 149-160). The cache entry's expires_at is set unconditionally to now + cache_ttl (line 159, default 60s). On_request caches and reuses active=true entries for the full TTL (lines 196-210) with no revocation channel. A token that the IdP revokes — or that expires 1 second after introspection — continues to be accepted locally for up to cache_ttl.

**Impact.** Revoked or just-expired bearer tokens remain accepted by the gateway for up to cache_ttl_seconds (default 60s, operator-configurable higher). For an internet-facing data plane this is a window where logout/revocation does not take effect and short-lived tokens are honored past their real expiry.

**Fix.** Clamp the cache entry's expiry to min(now + cache_ttl, token `exp` from the introspection response). Keep cache_ttl small and document the revocation-latency tradeoff. Consider not caching active=true at all when the response omits exp, or supporting a revocation/push channel.

#### M9 · 🟡 MEDIUM · HMAC auth replay protection is fully opt-out: clock-skew check only runs when client chooses to sign `date`

- **Where:** `src/plugins/hmac_auth.rs`:193-222  
- **Dimension:** security · **Subsystem:** `sec-plugin-auth` · **Confidence:** high  

**What's wrong.** The signed-headers list is entirely client-controlled (params["headers"], lines 193-196). The only anti-replay control — the clock-skew check — is gated on `if signed_headers.iter().any(|h| h.eq_ignore_ascii_case("date"))` (lines 205-208). If the attacker omits `date` from the signed list, no time check runs at all. There is no nonce/jti/Authorization-replay cache anywhere. Even when date IS signed, replay is permitted for the entire clock_skew window (default 300s) since there is no nonce.

**Impact.** A captured valid HMAC request can be replayed: unbounded if date was not in the signed set, or within the 300s skew window otherwise. An attacker can also strip request-line from the signed set (it is not required) so the same signature authenticates different methods/paths.

**Fix.** Require a minimum signed-header set server-side (at least `date` and `request-line`), reject requests whose signed list omits them, enforce the clock-skew check unconditionally, and add a nonce/jti replay cache (e.g. Redis) keyed on the signature within the skew window.

#### M10 · 🟡 MEDIUM · HMAC body integrity bypass: Digest header not required to be signed, and check skipped without Content-Length

- **Where:** `src/plugins/hmac_auth.rs`:193-196, 273-311  
- **Dimension:** security · **Subsystem:** `sec-plugin-auth` · **Confidence:** high  

**What's wrong.** Body integrity relies solely on a `Digest: SHA-256=...` header (lines 284-308), but (1) the `digest` header is never required to be in the client-controlled signed-headers list (lines 193-196), so an attacker can present a fresh body plus a matching fresh Digest header while the HMAC signature only covers e.g. `date`; the signature still verifies. (2) The body check is gated on `content-length > 0` (lines 277-283); a request using Transfer-Encoding: chunked (no Content-Length) yields content_length=0 and skips the digest check entirely.

**Impact.** An attacker who captures a signed request (or signs with a minimal header set) can substitute an arbitrary request body — directly defeating request-body authenticity for write operations on an internet-facing proxy.

**Fix.** Require `digest` to be present in the signed-headers list whenever a body is present, compute body length from the actually-buffered body rather than trusting Content-Length, and reject bodied requests that lack a signed Digest. Reject ambiguous chunked-without-Digest requests.

#### M11 · 🟡 MEDIUM · JWT plugin has no issuer/audience binding and no leeway/nbf config; aud only weakly defaulted

- **Where:** `src/plugins/jwt.rs`:96-119, 171-187  
- **Dimension:** security · **Subsystem:** `sec-plugin-auth` · **Confidence:** high  

**What's wrong.** from_config sets validation.validate_exp=true and clears required_spec_claims (lines 96-100) but never sets validation.iss or validation.aud, and exposes no config knobs for them. With jsonwebtoken 9 defaults, validate_aud stays true but aud is None: per validation.rs lines 309-328 a token that carries no `aud` claim passes (the `_ => {}` arm), so there is no way to bind tokens to this gateway's audience, and no issuer pinning at all. The custom required-claims loop (lines 181-187) only checks presence, not value.

**Impact.** A valid token minted for a different audience/service by the same issuer (or, in HS* shared-secret deployments, by any party holding the secret) is accepted. Without iss pinning the plugin trusts any token its key can verify. This widens token-confusion / cross-service token-reuse risk.

**Fix.** Add optional `issuer` and `audience` config fields and wire them to validation.set_issuer(...) and validation.set_audience(...); when audience is configured, set validation.aud so tokens missing aud are rejected. Optionally expose leeway and nbf validation.

#### M12 · 🟡 MEDIUM · template plugin {{.Env "VAR"}} expands arbitrary process env vars from upstream/attacker-influenced response body (SSTI secret exfiltration)

- **Where:** `src/plugins/template.rs`:110-125, 169-217  
- **Dimension:** security · **Subsystem:** `sec-plugin-exec` · **Confidence:** high  

**What's wrong.** TemplatePlugin::render is invoked on the UPSTREAM RESPONSE BODY in on_response (line 193-213: the body is drained via body.collect(), turned into body_str, and rendered whenever body_str.contains(self.open_delim) and the Content-Type matches content_types, default text/html). render() supports a `{{.Env "VAR_NAME"}}` directive: lines 110-122 locate the literal prefix `{{.Env "` in the body, parse the var name out of the body text itself, and call std::env::var(var_name).unwrap_or_default() (line 117), substituting the result back into the body. There is NO allowlist of permitted env var names — the name is taken verbatim from whatever string appears between the quotes in the body. The gateway process environment holds secrets (confirmed: DATABASE_URL is read from env in src/config.rs:1711 and src/main.rs:83; LYNXX_API_KEY / LYNXX_TELEMETRY_API_KEY in config.rs). Any content that reaches the response body containing e.g. `{{.Env "DATABASE_URL"}}` or `{{.Env "LYNXX_API_KEY"}}` causes the gateway to substitute the secret into the body returned to the client.

**Impact.** An attacker who can get the literal substring `{{.Env "SECRET_NAME"}}` into an upstream's response body — e.g. an upstream app that reflects user input into an error page, a profile field, a comment, search results, or filename — causes lynxx-gateway to read that environment variable and return its value to the client. This exfiltrates the database URL/credentials, the vexarr license API key, telemetry keys, AWS credentials, and any other secret present in the process environment. A malicious or compromised upstream can do this trivially. This is a server-side template injection leading to full secret/credential disclosure. Secondarily, each distinct {{.Env ...}} occurrence triggers a full-body result.replace scan, giving an attacker O(n*m) work amplification on large bodies (DoS amplification).

**Fix.** Do not parse env var names out of the (untrusted) body being rendered. Either remove the .Env directive entirely, or restrict it to an operator-configured allowlist of permitted variable names declared in plugin config, resolving values at config load time rather than from body content. More broadly, template rendering must only substitute a fixed, operator-defined variable set — never reflect identifiers extracted from the data being rendered. Also bound the number of substitutions per body to avoid amplification.

#### M13 · 🟡 MEDIUM · script-runner writes full request/response body to child stdin without a timeout, deadlocking on scripts that do not drain stdin (request-hanging DoS)

- **Where:** `src/plugins/script_runner.rs`:227-249  
- **Dimension:** security · **Subsystem:** `sec-plugin-exec` · **Confidence:** high  

**What's wrong.** In run_script, the entire serialized ScriptInput (which includes the base64-encoded request/response body up to max_body_bytes, default 2 MB, so ~2.7 MB of JSON) is written to the child's stdin via `stdin.write_all(&input_json).await` at line 229. This write is awaited to completion sequentially BEFORE the timeout-guarded wait at line 235 (tokio::time::timeout(def.timeout, child.wait())). The configured timeout therefore covers only child.wait(), not the stdin write. If the spawned script does not read its stdin (or reads it slowly), the OS pipe buffer (~64 KB on Linux) fills and write_all blocks indefinitely; the timeout never fires because execution has not yet reached child.wait(). The kill path (line 243) is also unreachable in that state.

**Impact.** A request whose body exceeds the pipe buffer, routed through a script-runner whose script does not fully consume stdin, hangs the request-handling task forever (the future is parked on the stdin write). Repeated such requests exhaust the worker/connection pool with permanently-stuck tasks, a denial of service on the data plane. Even a correct-but-buggy operator script (e.g. one that exits early or only reads a header) turns large request bodies into a hang rather than a 5s timeout.

**Fix.** Wrap the entire script interaction — stdin write plus wait plus stdout/stderr reads — in a single tokio::time::timeout, or perform the stdin write concurrently with reading stdout/stderr (e.g. spawn the write, use child.wait_with_output() or select! over the timeout). Drop stdin on timeout to unblock the write. Ensure the timeout cannot be bypassed by a blocked write.

#### M14 · 🟡 MEDIUM · script-runner spawns child process inheriting the gateway's full environment (DATABASE_URL, license/API keys) — no env_clear

- **Where:** `src/plugins/script_runner.rs`:212-225  
- **Dimension:** security · **Subsystem:** `sec-plugin-exec` · **Confidence:** high  

**What's wrong.** run_script builds tokio::process::Command::new(&def.command) and calls .envs(env) to add operator-configured variables (lines 212-217) but never calls env_clear(). tokio/std Command spawns the child with the parent process's full environment by default. The gateway process environment contains secrets — DATABASE_URL (src/main.rs:83, src/config.rs:1711), LYNXX_API_KEY / LYNXX_TELEMETRY_API_KEY, AWS_SECRET_ACCESS_KEY (config.rs:611), etc. Every script-runner invocation therefore exposes all of these to the spawned subprocess, regardless of what the configured `env` map contains.

**Impact.** Any script configured under script-runner runs with the gateway's database credentials, vexarr license key, telemetry keys, and cloud credentials in its environment. A bug, supply-chain compromise, or over-broad script (e.g. one that logs `printenv` or forwards its environment) leaks these secrets. It also broadens the blast radius if the script binary is ever attacker-replaceable on disk. Defense-in-depth is violated: the subprocess gets far more privilege/secret material than it needs.

**Fix.** Call cmd.env_clear() before .envs(env) so the child receives only the explicitly-configured variables (plus a minimal PATH if required). If inheritance is sometimes desired, make it an explicit opt-in config flag and document the secret-exposure risk. Consider scrubbing known-secret variable names from any inherited set.

#### M15 · 🟡 MEDIUM · X-Forwarded-For / X-Real-IP trusted unconditionally by default (empty trusted_proxies = trust-all)

- **Where:** `src/proxy/handler.rs`:517-540  
- **Dimension:** security · **Subsystem:** `sec-routing` · **Confidence:** high  

**What's wrong.** The client-IP extraction sets trust_headers = true when state.trusted_proxies.is_empty() ("no allowlist → trust unconditionally (backward compat)"), and trusted_proxies defaults to Vec::new() (src/config.rs:1173, parsed in src/main.rs:550-566). When trusted, it reads x-real-ip or the first comma element of x-forwarded-for verbatim into client_ip_owned with no validation. Because the default is empty, an internet-facing deployment trusts attacker-supplied X-Forwarded-For/X-Real-IP out of the box. client_ip_owned feeds the load-balancer RequestContext (consistent-hash bucketing, sticky routing) and the access log. The same client-controlled headers are independently re-read by the security-relevant ip-restriction ACL plugin (src/plugins/ip_restriction.rs:31-48) and the rate-limit plugins, none of which apply the trusted_proxies gate.

**Impact.** By default, a remote client can spoof its logged source IP, skew/abuse consistent-hash and sticky load balancing (cache/session poisoning, targeting a specific backend), and — via the ip-restriction plugin and rate limiters that read the raw header — bypass IP allow/deny ACLs or evade per-IP rate limits by injecting an arbitrary X-Forwarded-For value.

**Fix.** Default to NOT trusting forwarding headers when no trusted_proxies allowlist is configured (fail closed), or require an explicit opt-in flag. Centralise client-IP resolution behind a single trusted_proxies-aware helper and have ip-restriction / rate-limit plugins consume that resolved value instead of re-parsing raw headers. Honour trusted_proxies_strict consistently.

#### M16 · 🟡 MEDIUM · TCP L4 router peek_sni has no read timeout and serve_tcp has no connection cap (slowloris / FD exhaustion)

- **Where:** `src/proxy/tcp_router.rs`:200-208, 389-435  
- **Dimension:** security · **Subsystem:** `sec-routing` · **Confidence:** high  

**What's wrong.** peek_sni allocates a 16 KiB buffer (MAX_PEEK) and awaits stream.peek(&mut buf) with no timeout. A client that connects but sends no bytes leaves the peek future pending indefinitely, holding the connection and its buffer open. serve_tcp (lines 423-435) accepts in a loop and tokio::spawn's handle_tcp_conn with no global concurrency/semaphore limit, and handle_tcp_conn itself has no overall deadline before copy_bidirectional. There is no per-connection or aggregate cap anywhere.

**Impact.** An attacker can open a large number of TCP connections to the L4 proxy port and send nothing (or trickle), each pinning a tasks + 16 KiB buffer + file descriptor with no timeout, exhausting memory/FDs and denying service to legitimate TLS-passthrough traffic.

**Fix.** Wrap peek_sni in tokio::time::timeout (e.g. a few seconds) and drop the connection on timeout. Add a global tokio::sync::Semaphore (configurable max concurrent L4 connections) acquired before spawning handle_tcp_conn, and an overall idle/handshake deadline.

#### M17 · 🟡 MEDIUM · UDP L4 proxy creates unbounded sessions keyed by spoofable source address (socket/FD + task exhaustion)

- **Where:** `src/proxy/udp_router.rs`:101-177, 197-221  
- **Dimension:** security · **Subsystem:** `sec-routing` · **Confidence:** high  

**What's wrong.** handle_packet_inner keys sessions by src.to_string() (the datagram source address). For each previously-unseen source it binds a new ephemeral UdpSocket (UdpSocket::bind("0.0.0.0:0")), inserts a UdpSession into the sessions DashMap, and tokio::spawn's a relay task. There is no cap on the number of concurrent sessions — the only bound is prune_expired running every 5s removing sessions idle longer than timeout (default 10s). UDP source addresses are trivially spoofable, so each spoofed src creates a distinct session.

**Impact.** An attacker sending UDP packets with varied/spoofed source addresses at high rate forces the gateway to allocate one ephemeral socket (file descriptor), one DashMap entry, and one spawned task per unique source within the timeout window, exhausting file descriptors / memory and denying service. The relayed traffic is also reflected to spoofed sources, enabling the proxy to act as a UDP reflector/amplifier.

**Fix.** Enforce a configurable maximum session count (reject or LRU-evict beyond the cap), rate-limit new-session creation per time window, and consider requiring a verified first response before committing a long-lived relay. Avoid binding a dedicated socket per source when possible.

#### M18 · 🟡 MEDIUM · On-Demand TLS defaults to allow-all: any SNI triggers background ACME issuance, enabling cert-flood / ACME rate-limit (and billing) exhaustion

- **Where:** `src/proxy/on_demand_tls.rs`:149-159, 215-244, 366-412  
- **Dimension:** security · **Subsystem:** `sec-ssrf` · **Confidence:** high  

**What's wrong.** When neither `allowed_domains` nor `ask_url` is configured, `is_domain_allowed` returns `true` for every domain (on_demand_tls.rs:215-244), and the constructor explicitly sets `allowed_domains = None` for the empty case (149-159). The config default has both empty (src/config.rs:573-582), so the safe-by-default posture is off. `resolve()` (366-412) is reachable by any TLS client that sets an arbitrary SNI: on a cache miss it queues the SNI to the issuance loop via `try_send`, which calls `trigger_issuance`. The only throttle on the real ACME order is the sliding-window `RateLimiter` (default `max_certs_per_minute = 10`, config.rs:584-586).

**Impact.** An internet-facing gateway with on-demand TLS enabled but no allow-list/ask endpoint will attempt to issue a public ACME certificate for any hostname an attacker puts in the TLS SNI. At 10/min sustained this rapidly burns Let's Encrypt's per-account new-order and duplicate-cert limits (the module doc itself cites 300 orders/3h, 50 certs/week), locking the operator out of legitimate issuance, and on paid ACME/CA plans drives real cost. The module advertises abuse prevention but it is opt-in.

**Fix.** Make on-demand issuance fail-closed: if `enabled` is true but neither `allowed_domains` nor `ask_url` is set, refuse to start (or log a hard error and serve only the fallback cert without ever triggering issuance). At minimum, change the documented default behaviour from allow-all to deny-all.

#### M19 · 🟡 MEDIUM · Redis-KV provider uses blocking KEYS pattern scan on every poll despite documenting SCAN

- **Where:** `src/discovery/redis_kv.rs`:191-196  
- **Dimension:** security · **Subsystem:** `sec-ssrf` · **Confidence:** high  

**What's wrong.** `poll_keys` runs `redis::cmd("KEYS").arg(format!("{}*", config.prefix))` against the shared Redis server on every poll interval (default 15s, min 5s). The module-level doc (lines 9-12) claims it uses `SCAN`, but the implementation uses `KEYS`, which is O(N) over the entire keyspace and blocks the single-threaded Redis event loop for the duration.

**Impact.** On any Redis instance shared with other workloads (the common case), the gateway periodically stalls the whole Redis server proportional to total key count. With a large keyspace this is a self-inflicted DoS against shared infrastructure, and an attacker who can inflate the keyspace (or the prefix namespace) amplifies the stall. Production Redis guidance explicitly forbids KEYS in request paths.

**Fix.** Replace `KEYS {prefix}*` with an iterative `SCAN ... MATCH {prefix}* COUNT n` cursor loop (the `redis` crate's `AsyncIter`/`scan_match` helpers), matching what the doc already promises.

#### M20 · 🟡 MEDIUM · Range and full-file responses read the entire file into memory (unbounded buffering DoS)

- **Where:** `src/proxy/static_files.rs`:912-947, 1133-1168  
- **Dimension:** security · **Subsystem:** `sec-static` · **Confidence:** high  

**What's wrong.** Both the virtual-FS path (try_serve_file_with_fs) and the local-FS path (try_serve_file) handle Range requests by calling filesystem.read(path)/fs::read(path) which loads the WHOLE file into a Vec<u8>, then slices bytes[(start)..=(end)].to_vec() (a second full copy of the requested window). Non-range responses likewise read the entire file with fs::read before sending. There is no max-file-size limit and no streaming (grep shows no max_file_size / streaming in this module). A request for Range: bytes=0-0 against a multi-GB file still buffers the entire file in RAM; many concurrent such requests multiply memory usage.

**Impact.** An unauthenticated client can force the gateway to allocate memory equal to the largest served file per concurrent request (plus a copy for the slice), enabling memory-exhaustion / OOM denial of service against the data plane simply by issuing range or full-file requests for large assets.

**Fix.** Stream file contents (e.g. tokio::io with a ReaderStream / Body::from_stream) instead of fs::read; for ranges, seek and read only the requested window rather than the whole file. Enforce a configurable maximum in-memory buffer size and fall back to streaming above it.

#### M21 · 🟡 MEDIUM · lynxx_random_bytes documented as cryptographically-unpredictable but uses reversible per-request xorshift64 seed

- **Where:** `src/plugins/wasm/host.rs`:310-342  
- **Dimension:** security · **Subsystem:** `sec-wasm` · **Confidence:** high  

**What's wrong.** The host function fills the output buffer with a plain xorshift64 stream: `s ^= s << 13; s ^= s >> 7; s ^= s << 17;` advancing a single 64-bit state `caller.data().rng_seed`. The context docstring (context.rs lines 33-37) and the surrounding comment claim the guest 'still gets cryptographically-unpredictable bytes'. xorshift64 is a non-cryptographic PRNG: its full internal state is exactly the 8 bytes it emits each round, so observing 8 consecutive output bytes lets an attacker recover the state and predict (and rewind) the entire stream. While the per-request seed comes from thread_rng (rand_seed() in mod.rs), the stream itself is trivially predictable once any output leaks. Guests are explicitly told elsewhere (host.rs lines 6-9 of the random comment) that this is suitable for 'id generation'.

**Impact.** Any wasm plugin that uses `lynxx_random_bytes` to generate security-sensitive values (request IDs used for idempotency/anti-replay, CSRF-style tokens, nonces, session identifiers) inherits a predictable PRNG. An attacker who observes a few output bytes can predict subsequent tokens, defeating any guarantee the plugin author assumed from the 'cryptographically-unpredictable' documentation. The mismatch between the doc claim and the implementation is the trap.

**Fix.** Either fill the buffer from a CSPRNG (e.g. `rand::rngs::OsRng` / `getrandom` directly into the buffer) instead of advancing xorshift from a stored seed, or correct the documentation in both host.rs and context.rs to state plainly that the output is NOT cryptographically secure and must not be used for tokens/nonces.

#### M22 · 🟡 MEDIUM · WASM guest executes synchronously on the async worker; epoch wall-timeout depends on a ticker that may never spawn

- **Where:** `src/plugins/wasm/runtime.rs`:58-75  
- **Dimension:** security · **Subsystem:** `sec-wasm` · **Confidence:** medium  

**What's wrong.** Wall-clock enforcement relies entirely on the epoch ticker in `spawn_epoch_ticker`, which is started only if `tokio::runtime::Handle::try_current()` succeeds at the moment the global engine is first built (runtime.rs:63-66); if it fails it `return`s and NO ticker is ever spawned for the process lifetime (the engine is a process-wide OnceLock, built once). If the very first `WasmEngine::global()` call happens off a tokio runtime, `store.set_epoch_deadline(wall_timeout_ms)` in mod.rs:113 never triggers because the epoch never advances — the only remaining bound is fuel. Separately, `WasmPlugin::invoke` (mod.rs:103-138) calls `func.call(&mut store, ())` synchronously inside the async `on_request`/`on_response`, with no `spawn_blocking`, so a guest burns CPU on a tokio worker thread for up to the full fuel/wall budget, blocking other tasks on that worker.

**Impact.** In a deployment where the engine is first materialized outside a runtime (config validation, a CLI/seed path, or a future sync caller), the wall-clock cap silently becomes inert and a guest can run until fuel exhaustion only — and a compute-heavy-per-instruction guest can stall a worker thread. Combined with synchronous execution on the async runtime, a malicious or buggy plugin degrades the whole data-plane's tail latency. Even with the ticker alive, blocking the executor for up to wall_timeout_ms per request under load is a throughput hazard.

**Fix.** Run wasm execution via `tokio::task::spawn_blocking` (or wasmtime async + fuel_async_yield) so it cannot block async workers. Make the epoch ticker robust: build the engine lazily from inside a known-runtime context, or panic/error if no runtime is present when fuel/epoch enforcement is required, rather than silently disabling the wall-clock cap.

#### M23 · 🟡 MEDIUM · SQLite pool opened without WAL journal_mode or busy_timeout, so concurrent reads/writes serialize and throw SQLITE_BUSY under load

- **Where:** `src/db/sqlite.rs`:32-49  
- **Dimension:** performance · **Subsystem:** `perf-db-conc` · **Confidence:** high  

**What's wrong.** SqliteRepository::new builds the pool with `SqlitePoolOptions::new().max_connections(8).after_connect(... PRAGMA foreign_keys = ON ...)`. The only PRAGMA executed is `foreign_keys = ON`. A grep across the whole tree for `journal_mode`, `WAL`, `busy_timeout`, `synchronous`, and `SqliteConnectOptions` shows none are ever set (the only hits are unrelated comments). With sqlx's default rollback (DELETE) journal mode, SQLite permits only a single writer and a writer blocks all readers for the duration of the write; opening 8 pooled connections against that single-writer database means concurrent writers immediately collide. Without `busy_timeout` set, a busy lock returns `SQLITE_BUSY` instead of waiting.

**Impact.** Under concurrent traffic (the runtime spawns num_cpus worker threads — src/main.rs:243-248), the per-request DB work from the auth plugins and the buffered log/metric writers contend on the single SQLite write lock. Operators see request latency spikes and intermittent `database is locked` (SQLITE_BUSY) errors surfacing as 500s, even though only 8 connections are configured. The 8 pooled connections give a false impression of concurrency that the default journal mode cannot deliver.

**Fix.** Use `SqliteConnectOptions` with `.journal_mode(SqliteJournalMode::Wal)`, `.busy_timeout(Duration::from_secs(5))` (or `PRAGMA busy_timeout`), and `.synchronous(Normal)` in `after_connect`/connect options. WAL lets readers proceed concurrently with a writer; busy_timeout makes contending writers wait rather than error. Consider a single dedicated writer connection plus a read pool, since WAL still serialises writers.

#### M24 · 🟡 MEDIUM · DB connection pools hardcoded to max_connections(8) with no acquire_timeout while the runtime uses num_cpus worker threads

- **Where:** `src/db/postgres.rs`:34-43  
- **Dimension:** performance · **Subsystem:** `perf-db-conc` · **Confidence:** high  

**What's wrong.** Both backends fix the pool at 8 connections with no other tuning: Postgres `PgPoolOptions::new().max_connections(8).connect(url)` (src/db/postgres.rs:35-38) and SQLite `max_connections(8)` (src/db/sqlite.rs:33-34). Neither sets `acquire_timeout`, `min_connections`, or `max_lifetime`, so the sqlx default 30s acquire timeout applies. The pool size is not derived from config or core count, whereas the Tokio runtime is sized to `num_cpus::get()` worker threads (src/main.rs:243-248) — on a typical server that is far more than 8. Per-request DB-touching code paths (the consumer-scan auth plugins above, grant revocation check in src/auth/middleware.rs:131) all draw from this same 8-connection pool.

**Impact.** When concurrent in-flight requests needing a DB connection exceed 8, the surplus requests block in `pool.acquire()` for up to ~30s before timing out, manifesting as head-of-line latency and sporadic 5xx under load spikes. The pool cannot scale up on multi-core hardware because the cap is a compile-time constant, leaving CPU idle while requests queue on connection acquisition.

**Fix.** Make `max_connections` configurable (default proportional to worker_threads, e.g. workers + small headroom for Postgres), set a short `acquire_timeout` so back-pressure surfaces fast instead of a 30s hang, and set `min_connections`/`max_lifetime` for steady-state warmth. For Postgres consider a larger ceiling; for SQLite keep it small but pair with WAL (see SQLite finding).

#### M25 · 🟡 MEDIUM · Per-client rate-limit / in-flight DashMaps grow unbounded — no eviction of stale IP/host buckets

- **Where:** `src/plugins/rate_limit.rs`:40-94  
- **Dimension:** performance · **Subsystem:** `perf-db-conc` · **Confidence:** high  

**What's wrong.** RateLimitPlugin keeps `buckets: DashMap<String, TokenBucket>` keyed by client IP (`get_client_id` derives the key from X-Forwarded-For, rate_limit.rs:63-73) and inserts a new entry per unique client via `self.buckets.entry(client_id).or_insert_with(...)` in on_request (rate_limit.rs:84-87). A grep for `retain`/`remove`/`evict`/`reaper`/`prune` across rate_limit.rs, inflight_req.rs and response_ratelimiting.rs finds no eviction whatsoever. InFlightReqPlugin (`keyed_counters: Arc<DashMap<String, Arc<AtomicU64>>>`, inflight_req.rs:69, 145-160) and ResponseRatelimitingPlugin (`state: Arc<DashMap<String, Bucket>>`, response_ratelimiting.rs:24, 119) share the identical never-evicted per-key pattern.

**Impact.** For IP-keyed limiting, every distinct source IP (trivially spoofable via X-Forwarded-For) creates a permanent map entry. Under organic traffic the map grows with the unique-client population; under an adversary rotating X-Forwarded-For values it grows without bound — a memory-exhaustion DoS — and the growing shard sizes degrade DashMap lookup/insert latency on the hot path for all clients. The atomics/buckets are correctly not held across .await, so this is purely growth/contention, not a deadlock.

**Fix.** Add periodic eviction: a background sweep (or opportunistic on-insert) that drops token buckets whose `last_refill` is older than a few windows and in-flight counters that have decayed to zero, e.g. `buckets.retain(|_, b| now - b.last_refill < idle_ttl)`. Alternatively switch to a bounded LRU/TTL cache (e.g. moka) keyed by client id.

#### M26 · 🟡 MEDIUM · Per-request String allocations for Prometheus metric labels in record_request_metric / record_request_duration

- **Where:** `src/proxy/handler.rs`:100-137  
- **Dimension:** performance · **Subsystem:** `perf-hotpath` · **Confidence:** high  

**What's wrong.** `record_request_metric` and `record_request_duration` build the metric labels with `svc.to_string()`, `route.to_string()`, `method.to_string()`, `target.to_string()` (lines 111-116 and 130-135). These run on every successful request whenever `minimal_telemetry` is false (the default). The counter call allocates 4 Strings; the histogram call allocates 4 more — even though `svc` comes from `Arc<str>`, `route_id` is already an owned `String` built once at line 416, `method` is a `&'static`-ish verb string, and `target_label` is an `Arc<str>`. The `metrics` macro re-allocates fresh `String`s for labels that are identical on every request to the same route.

**Impact.** 8 String heap allocations per request on the default telemetry path, on top of the metrics crate's own per-emission label hashing. At high RPS this is a measurable allocator and CPU cost on the latency-sensitive data plane, defeating the intent of the `minimal_telemetry` gate for operators who still want metrics.

**Fix.** Pre-register/cache the label sets per (service,route,method,target) tuple, or use the metrics crate's static-label / interned-label APIs so the per-request emission reuses existing label allocations instead of calling `.to_string()` each time. At minimum, pass `Arc<str>`/`&'static str` through and avoid converting `Arc<str>` labels back into owned `String`s.

#### M27 · 🟡 MEDIUM · match_route_for_service scans the entire global route DashMap O(N) on the subdomain-routing hot path

- **Where:** `src/proxy/router.rs`:157-179  
- **Dimension:** performance · **Subsystem:** `perf-hotpath` · **Confidence:** high  

**What's wrong.** `match_route_for_service` iterates `self.routes.iter()` — every route in the gateway, across all services — and filters by `service_id` inside the loop (line 165: `if &route.service_id != service_id { continue; }`). There is no per-service route index. This is invoked from the subdomain/host-routing fast path: handler.rs:373 calls it for every request whose Host matched a service via `match_by_host`. So for a host-routed request, the cost is O(total routes in the system), not O(routes for that service). The non-host `match_route_full` path has an `exact_index` O(1) shortcut, but `match_route_for_service` has none.

**Impact.** On a gateway hosting many services/routes (the target deployment), every subdomain-routed request walks the full route table and the DashMap shard locks for each entry. As route count grows this becomes a linear per-request cost that doesn't show up in small benchmarks but dominates at scale — the opposite of the O(1) goal stated for `exact_index`/`host_index`.

**Fix.** Add a `routes_by_service: DashMap<Uuid, Vec<Uuid>>` (or `DashMap<Uuid, Vec<Arc<Route>>>`) index maintained in add/update/remove/load_from_repo, and have `match_route_for_service` iterate only that service's routes. Reuse it to also speed `match_route_full` when a host already narrowed the candidate service.

#### M28 · 🟡 MEDIUM · Random and P2C load-balancer strategies allocate a Vec of healthy targets on every pick

- **Where:** `src/proxy/loadbalancer.rs`:240-274, 383-401  
- **Dimension:** performance · **Subsystem:** `perf-hotpath` · **Confidence:** high  

**What's wrong.** `pick_random` (line 384) and `pick_random_choose` (line 399) build `let healthy: Vec<_> = self.targets.iter().filter(|s| s.is_routable()).collect();` on every request. Similarly, the zone-aware branch in `pick` (lines 255-259) collects `let zone_targets: Vec<_> = ...` per request for RoundRobin/LeastConn/RandomChoose/First/LeastTime whenever `local_zone` is set. These heap-allocate a `Vec` of references per request just to index into it once.

**Impact.** Services using `random`, `random-choose`/`p2c`, or any zone-aware strategy pay one Vec allocation per request inside the LB pick — on the hot path, under the registry read-lock. P2C and zone-awareness are exactly the strategies operators pick for high-throughput fan-out, so the allocation lands on the busiest services.

**Fix.** For P2C, pick two random indices directly over `self.targets` and skip non-routable ones with bounded retries instead of materialising a filtered Vec (matching the allocation-free style of `pick_rr`). For zone-aware, precompute per-zone index lists at `ServiceLoadBalancer::new`/rebuild time (like `rr_ring`) and index into them, rather than filtering+collecting per request.

#### M29 · 🟡 MEDIUM · LeastTime EWMA (avg_response_us) is never updated outside tests, silently degrading the strategy to least-connections

- **Where:** `src/proxy/loadbalancer.rs`:145-156, 435-454  
- **Dimension:** performance · **Subsystem:** `perf-hotpath` · **Confidence:** high  

**What's wrong.** `TargetState::record_response_time` (the only writer of `avg_response_us`) is never called from the request path — a repo-wide grep finds it only inside `#[cfg(test)]` modules. The handler records health success/failure and in-flight counts but never feeds upstream latency back into the EWMA. Consequently `avg_response_us` stays 0, and `pick_least_time` computes `score = avg.max(1).saturating_mul(inflight + 1)` = `1 * (inflight + 1)` (line 447), i.e. it always behaves as plain least-connections and never actually steers traffic by latency.

**Impact.** Operators selecting the `least-time` strategy believe they are getting latency-aware routing that shifts load off slow upstreams; in reality the latency signal is dead and a slow-but-idle backend keeps receiving traffic. This defeats the documented purpose of the strategy and can worsen tail latency rather than improve it.

**Fix.** Record the per-request upstream duration into the picked target's EWMA after the response completes, e.g. call `ts.record_response_time(start.elapsed().as_micros() as u64)` in the handler's success path (both streaming and buffered branches) using the `picked` target. Alternatively remove the LeastTime strategy if it can't be wired up, so it doesn't masquerade as latency-aware.

#### M30 · 🟡 MEDIUM · resolve_chain rebuilds the plugin Vec with two RwLock reads + per-plugin Arc clones on every request and response

- **Where:** `src/plugins/mod.rs`:319-384  
- **Dimension:** performance · **Subsystem:** `perf-plugins` · **Confidence:** high  

**What's wrong.** run_request and run_response each call resolve_chain (handler.rs:628 and :982/:1564), and resolve_chain acquires TWO tokio RwLock read guards (self.index.read().await and self.built.read().await), then allocates a fresh Vec<Arc<dyn Plugin>> and pushes a cloned Arc for every matching global/service/route plugin. So every request that has at least one plugin configured pays: 4 async RwLock acquisitions total (2 per direction), 2 Vec heap allocations, and N atomic-refcount Arc::clone operations per direction. The index/built maps only change on admin CRUD (rebuild), yet they are re-read and the chain is re-materialized on the hot path for every single request.

**Impact.** Under load (the doc-comments cite 100k RPS targets), every proxied request that touches any plugin incurs RwLock read contention against the rebuild writer plus 2 allocations and a burst of atomic refcount traffic. The Arc clones and Vec allocation are pure overhead — the chain is identical for all requests on the same route until the next rebuild. This shows up as elevated p99 and cache-line contention on the Arc strong counts of hot plugins.

**Fix.** Resolve the chain once per (service_id, route_id) at rebuild time into an immutable Arc<[Arc<dyn Plugin>]> stored behind a single arc-swap::ArcSwap (or per-route precomputed chains). On the hot path, do one lock-free load and iterate by reference — no per-request Vec allocation, no per-plugin Arc clone, no RwLock. At minimum, take a single combined RwLock read for both directions and iterate the index by reference without cloning Arcs into a Vec.

#### M31 · 🟡 MEDIUM · Proxy-cache clones the entire cached response body while holding the DashMap shard read lock on every cache hit

- **Where:** `src/plugins/proxy_cache.rs`:129-145  
- **Dimension:** performance · **Subsystem:** `perf-plugins` · **Confidence:** high  

**What's wrong.** On a cache hit, on_request does `self.cache.get(&key).and_then(|e| { if e.expires_at > now { Some(e.clone()) } ... })`. DashMap::get returns a Ref that holds the shard's read lock for the duration of the closure, and CacheEntry derives Clone with body: Vec<u8> and headers: Vec<(String,String)> — so the full response body and all header strings are deep-copied while the shard lock is held. Then on the very next lines the headers are cloned AGAIN (`entry.headers.clone()` at line 138) and the body is moved into the ShortCircuit response.

**Impact.** Hot cached keys all hash to the same DashMap shard; cloning a multi-KB body under that shard's read lock serializes/contends every concurrent reader of that shard, and the double header clone plus full body copy per hit burns CPU and allocations exactly on the path that is supposed to be the fast one. The headers are cloned twice per hit.

**Fix.** Store the body as Arc<[u8]> (or Bytes) and headers as Arc<[(HeaderName,HeaderValue)]> in CacheEntry so a hit clones cheap Arc handles, not the payload. Clone the Arc out of the Ref quickly to release the shard lock, and avoid the second headers.clone() by building the ShortCircuit headers from the already-cloned handle.

#### M32 · 🟡 MEDIUM · Per-key inflight limiter takes a DashMap write-path entry() lock on every request and never reclaims idle keys

- **Where:** `src/plugins/inflight_req.rs`:98-121, 145-161  
- **Dimension:** performance · **Subsystem:** `perf-plugins` · **Confidence:** high  

**What's wrong.** For source_criterion request.ip / request.host, on_request calls self.keyed_counters.entry(key).or_insert_with(...).clone() on EVERY request. DashMap::entry takes the shard's write lock (not a read lock) even when the key already exists, so two requests from the same client IP/host always serialize on that shard's write lock. extract_key also allocates a fresh String per request (trim().to_string()/host string). Additionally, keyed_counters entries are never removed when a counter returns to zero, so the map accumulates one Arc<AtomicU64> per distinct IP/host seen for the lifetime of the process.

**Impact.** Per-IP/per-host inflight limiting becomes a write-lock contention point under load — bursts from the same shard of clients serialize on DashMap write locks, the opposite of the lock-free counter the General path enjoys. With many distinct source IPs (e.g. a botnet or large NAT fleet) the map grows without bound, an attacker-controllable memory leak.

**Fix.** Use get() (read lock) for the common already-present case and only fall back to entry() on miss, or use an atomic counter keyed structure designed for read-mostly access. Reclaim keys whose counter hits zero (e.g. remove on guard drop when count reaches 0, or periodic sweep). Avoid the per-request String allocation by hashing the borrowed key.

#### M33 · 🟡 MEDIUM · io_uring acceptor feeds an unbounded mpsc channel, allowing memory growth and head-of-line buildup under accept storms

- **Where:** `src/utilities/io_uring_accept.rs`:158-182, 240-330  
- **Dimension:** performance · **Subsystem:** `perf-tls` · **Confidence:** high  

**What's wrong.** IoUringAcceptor::start() creates the handoff channel with tokio::sync::mpsc::unbounded_channel() (line 162) and the SQ/CQ thread pushes every accepted FD with tx.send(AcceptedConn { fd }) (line 307) with no backpressure. The whole point of this module (per its own doc, lines 20-25) is to absorb connection-storm scenarios, but in exactly that scenario the io_uring thread can accept FDs faster than serve_inner's single-threaded next_conn()/handshake loop drains them. Every queued AcceptedConn holds a live kernel FD; an unbounded backlog means unbounded open sockets plus an unbounded Vec inside the channel.

**Impact.** Under a SYN/connection flood the accept thread keeps minting FDs into an ever-growing queue. The process can exhaust its file-descriptor limit (EMFILE) and grow channel memory without bound, while the connections at the head of the queue sit unhandshaken for an unbounded time (latency spike / effective DoS). A bounded channel would instead apply natural backpressure by stalling resubmission of Accept SQEs.

**Fix.** Use a bounded mpsc channel sized to a multiple of ring_entries, and gate resubmission of the Accept SQE on available channel capacity (e.g. try_send / permit-based send and only push_accept when a slot is free). This caps in-flight accepted-but-unhandled FDs and bounds memory.

#### M34 · 🟡 MEDIUM · SQLite has no busy_timeout/WAL; concurrent transactional writes hit SQLITE_BUSY and audit rows are silently dropped

- **Where:** `src/db/sqlite.rs`:33-49  
- **Dimension:** quality · **Subsystem:** `qual-data` · **Confidence:** high  

**What's wrong.** The SQLite pool opens with max_connections(8) and only PRAGMA foreign_keys=ON — no journal_mode=WAL and no busy_timeout. In default rollback-journal mode only one writer is allowed and with no busy_timeout a competing write fails immediately with SQLITE_BUSY. append_audit/insert_logs/cascade deletes all use pool.begin(); AuditLog::record swallows the error with only a WARN, silently dropping the audit entry.

**Impact.** Under concurrent admin activity on SQLite, audit appends can be silently lost (best-effort, no retry) and other transactional writes fail intermittently — losing audit coverage and causing non-deterministic write failures.

**Fix.** Set WAL and busy_timeout (~5s) in after_connect, add bounded SQLITE_BUSY retry on critical transactions, consider a single-connection writer pool for SQLite.

#### M35 · 🟡 MEDIUM · buffering plugin performs blocking std::fs disk-spill I/O on the async runtime and leaks temp files on read failure

- **Where:** `src/plugins/buffering.rs`:83-108, 117-171  
- **Dimension:** quality · **Subsystem:** `qual-plugins` · **Confidence:** high  

**What's wrong.** `buffer_bytes` (lines 83-108) uses synchronous `std::fs::File::create`, `write_all`, `flush`, and `std::fs::read` to spill large bodies to `/tmp`. It is called directly from the async `on_request` (line 138) and `on_response` (line 166) without `tokio::task::spawn_blocking`. For bodies above the memory threshold (default 1 MiB) this blocks the tokio worker thread for the full duration of a potentially multi-gigabyte write+read (the doc-comment advertises multi-GB uploads). Additionally, the temp filename is derived from PID + nanosecond timestamp; under high concurrency two requests can collide on the same nanosecond and clobber/interleave each other's spill file. If `std::fs::read` (line 104) returns an error, the function returns early via the `?`-less assignment and the `remove_file` cleanup on line 106 still runs, but if `File::create`/`write_all` fails earlier (lines 100-102 use `?`), the partially written temp file at `tmp_path` is never removed (the `remove_file` at line 106 is unreachable on the `?` early-return), leaking files in /tmp.

**Impact.** Large request/response bodies stall a tokio worker thread, harming tail latency and throughput for all requests sharing that thread (defeating the whole point of an async proxy). Repeated mid-spill write failures (full disk, permissions) accumulate orphaned temp files. Nanosecond+PID filename collisions can corrupt spilled bodies under concurrency.

**Fix.** Wrap the spill in `tokio::task::spawn_blocking` (or use tokio::fs); use a unique temp file (e.g. the `tempfile` crate / a UUID) instead of PID+timestamp; and ensure the temp file is removed on every error path (RAII guard or explicit cleanup before the `?`).

#### M36 · 🟡 MEDIUM · grpc-web-text proxying drops all client headers (auth/metadata) when rebuilding the request

- **Where:** `src/proxy/grpc.rs`:141-156  
- **Dimension:** quality · **Subsystem:** `qual-proxy` · **Confidence:** high  

**What's wrong.** In `handle_grpc_web`, the `is_text` branch (content-type ending in `-text`) rebuilds the upstream request from scratch with `Request::builder().method(POST).uri(...).header(CONTENT_TYPE, "application/grpc").body(decoded)`. This discards every original request header — `authorization`, gRPC metadata (`x-*`), `grpc-timeout`, custom headers, etc. The non-text branch (the `else` at line 157-163) instead mutates only the content-type and preserves all headers, so behaviour is inconsistent between the two grpc-web encodings.

**Impact.** Authenticated or metadata-bearing `application/grpc-web-text` requests lose all their headers on the way to the upstream: auth tokens, tracing/correlation headers, and gRPC call metadata vanish. Upstreams reject the call (401/unauthenticated) or behave incorrectly, while the binary grpc-web variant works fine — a confusing, encoding-dependent failure.

**Fix.** Preserve the original `HeaderMap` when rebuilding: take `req.into_parts()`, swap the body/content-type and URI on the existing `parts.headers`, rather than constructing a fresh builder. Mirror the header handling of the `else` branch.

#### M37 · 🟡 MEDIUM · match_route_full short-circuits the entire scan via `?` when a matched route's service is missing

- **Where:** `src/proxy/router.rs`:403-412  
- **Dimension:** quality · **Subsystem:** `qual-proxy` · **Confidence:** high  

**What's wrong.** In the linear-scan portion of `match_route_full`, the host-constrained branch does `best = Some((Arc::clone(route), self.get_service(&route.service_id)?));` (line 405). The `?` on `get_service(...)` returns `Option`, so if a host-bearing route matches the path/method/host but its `service_id` no longer resolves (orphaned route — `routes` and `services` are independent DashMaps with no transactional consistency, e.g. mid service-deletion), the `?` returns `None` from the whole function, aborting the scan. A later route that would have matched is never considered. The adjacent fallback branch (line 408) correctly uses `if let Some(service)` and skips the bad route gracefully, so the two paths are inconsistent.

**Impact.** A single dangling route reference (possible during concurrent service delete/update across the two maps) can make `match_route_full` return 'no route' for requests that have a perfectly valid matching route later in iteration, yielding spurious 404s instead of routing correctly.

**Fix.** Replace the `?` at line 405 with a graceful `if let Some(service) = self.get_service(&route.service_id) { ... } else { continue; }` so an unresolved service skips that one route instead of aborting the entire match.

#### M38 · 🟡 MEDIUM · UDP relay timeout races with session re-creation and removes a newer session (TOCTOU)

- **Where:** `src/proxy/udp_router.rs`:145-185  
- **Dimension:** quality · **Subsystem:** `qual-proxy` · **Confidence:** medium  

**What's wrong.** Each UDP session spawns a relay task keyed by the client `SocketAddr` string. On its own inactivity timeout the relay task unconditionally calls `sessions.remove(&key)` (line 169). Sessions are also reaped independently by `prune_expired` every 5s (line 181-185). There is no generation/identity check: if the original session expires (relay task about to fire its timeout) and the same client sends a new packet, `handle_packet_inner` finds no entry and inserts a brand-new session with the same key plus a new relay task (line 133-145). When the OLD relay task's timeout then fires, its `sessions.remove(&key)` deletes the NEW session entry, even though the new relay task and its socket are still live. The new relay task subsequently hits the `get_mut` miss (line 152→154) and breaks, silently dropping an active client's upstream traffic.

**Impact.** Long-lived or reconnecting UDP clients (DNS, QUIC, game traffic) can have their active session torn down by a stale timer from a previous session that shared the same source address, causing intermittent, hard-to-diagnose packet loss / dropped sessions under churn.

**Fix.** Give each session a unique generation token/id stored in `UdpSession`; the relay task should capture its own token and only `sessions.remove` if the current entry's token still matches. Alternatively have the relay task `remove_if` (DashMap) comparing the `Arc<UdpSocket>` pointer identity it owns.

#### M39 · 🟡 MEDIUM · XDP packet reads dereference unaligned raw pointers (UB in Rust)

- **Where:** `ebpf/lynxx-ebpf-program/src/main.rs`:208-214  
- **Dimension:** quality · **Subsystem:** `qual-unsafe` · **Confidence:** high  

**What's wrong.** The XDP program reads packet fields with direct raw-pointer dereferences: *((data + 12) as *const u16) for ethertype and a u32 read at packet offset 26 for src IP. The Ethernet header is 14 bytes, so the IPv4 source at offset 26 is only 2-byte aligned, and the ethertype at offset 12 is 2-aligned. Dereferencing a *const u32/u16 at an address that does not meet the type alignment is UB in Rust regardless of whether the BPF JIT tolerates unaligned access. Idiomatic sound form is core::ptr::read_unaligned.

**Impact.** Language-level UB; LLVM/Rust frontend may assume alignment and miscompile the load. Verifier or strict-alignment NICs may reject/mis-handle on non-x86.

**Fix.** Use core::ptr::read_unaligned((data + off) as *const _), or aya bounds-checked ptr_at helper that reads via read_unaligned.

#### M40 · 🟡 MEDIUM · XDP token-bucket rate limiter has a read-modify-write race across CPUs, allowing budget bypass

- **Where:** `ebpf/lynxx-ebpf-program/src/main.rs`:218-248  
- **Dimension:** quality · **Subsystem:** `qual-unsafe` · **Confidence:** high  

**What's wrong.** try_xdp_ratelimit does a non-atomic read-modify-write on the per-source-IP bucket: XDP_BUCKETS.get(&src) copies out, mutates tokens locally, then insert() writes back. XDP runs concurrently per RX queue/CPU. Two packets for the same source on different CPUs both read the same count, each decrement a local copy, and the second insert overwrites the first (lost update). The map is a plain HashMap (not per-CPU, no bpf_spin_lock), so the decrement is not atomic.

**Impact.** Under concurrent single-source traffic (the DoS scenario this limiter exists for), tokens are under-decremented, letting an attacker exceed the per-IP budget by ~the number of RX CPUs; the in-kernel rate-limit control is partially bypassable. Same race undercounts XDP_DROPPED/RETRANSMITS metrics.

**Fix.** Use PerCpuHashMap (aggregate in userspace), a bpf_spin_lock-guarded map value, or atomic/__sync helpers for the token decrement.

---

## ⚪ Low findings (35)

- **L1** · [security/sec-admin] **pprof/profiling endpoints leak process internals and are unauthenticated in default config** — `src/admin/mod.rs`:144-148  
  The /debug/pprof/{heap,tasks,threads,uptime,stats} routes are registered under the `reads` group with the Viewer role layer (mod.rs:144-148, 242). Their handlers (src/admin/profiling.rs) expose process PID (runtime_profile, profiling.rs:229-236), resident/virtual memory and peak/live heap byte counts (heap_profile, 59-73), tokio task counts and worker/blocking thread counts (tasks_profile, 87-97), uptime, num_cpus, and OS thread names from /proc/self/task on Linux (enumerate_threads, 128-167). Because the default auth_required=false makes Viewer-gated routes pass with CurrentActor(None) (see enforce_role None branch), these are reachable with no credentials on the default 0.0.0.0 admin listener.  
  *Fix:* Move debug/pprof endpoints behind at least Operator (preferably Admin) role, and gate them on a config flag that is off by default in production. At minimum ensure they cannot be served in bootstrap/unauthenticated mode.
- **L2** · [security/sec-admin] **Byte-offset string slicing in proxy_try/proxy_replay body truncation can panic on multibyte responses** — `src/admin/docs.rs`:131-135  
  proxy_try truncates the upstream body with `&resp_body[..4096]` (docs.rs:131-135) and proxy_replay with `&resp_body[..8192]` (src/admin/replay.rs:58-62). resp_body comes from resp.text(), a String, and `&str[..n]` panics if byte index n is not a UTF-8 char boundary. Since the body is fully attacker-influenced (the caller picks the URL, and via the SSRF above can point at content they control), an upstream can return a response where byte 4096/8192 lands inside a multibyte character, panicking the handler.  
  *Fix:* Truncate on a char boundary, e.g. use resp_body.char_indices() to find a boundary <= the limit, or take bytes and use String::from_utf8_lossy, or floor the index with str::floor_char_boundary.
- **L3** · [security/sec-auth] **Verifier-issued admin principals cached with no real expiry; revoked keyx tokens stay valid until cache TTL** — `src/auth/middleware.rs`:234-258, 276-298  
  When a bearer is not in the local `admin_tokens` table, `resolve_actor` falls back to the external `TokenValidator` and caches the synthesized `AdminToken` keyed by SHA-256 of the raw token (middleware.rs:242-249). `admin_token_from_principal` always sets `expires_at: None` (middleware.rs:286), so the per-token expiry check `!cached.is_expired(Utc::now())` (middleware.rs:237) and `token.is_expired` (line 254) can never fire for these principals — the cache's wall-clock `ttl` is the only bound. The cache `get` also does not prune and re-validation only happens after `ttl` elapses (AdminAuthCache docs at middleware.rs:33-35 acknowledge this). The principal's own expiry/TTL from the backend is discarded.  
  *Fix:* Propagate the principal's real expiry into `AdminToken.expires_at` (and clamp the cache entry's `expires_at` to `min(ttl, principal_exp)`), so `is_expired` enforces the backend's lifetime. Keep cache TTL short for admin tokens, and add a revocation/invalidation hook (or check `token_validator` more aggressively for high-privilege roles). At minimum, document the configured TTL as the maximum revocation-staleness window in operator-facing docs.
- **L4** · [security/sec-auth] **Runtime grant JWT verified with Validation::default() (no aud/iss binding) and heartbeat reissues hardcoded capabilities** — `src/auth/grant.rs`:53-94  
  `GrantManager::verify_grant` decodes with `Validation::default()` (grant.rs:90), which validates `exp` and the HS256 signature but binds no audience or issuer, so any HS256 token signed with the same shared secret is accepted for any customer/device. The secret is symmetric (`from_secret`, grant.rs:56-57) so the signing and verifying parties are identical, but there is no defense against token reuse across token *types* if the same secret were ever shared. Separately, `heartbeat` (handshake.rs:229-237) reissues a fresh grant with a hardcoded `vec![Capability::ProxyBasic, Capability::LlmGateway]` regardless of the customer's actual scopes or whether capabilities were narrowed/revoked (the inline comment at handshake.rs:231 admits this), so a heartbeat can escalate a low-scope grant to include LlmGateway. NOTE: I could not find any route registration for `init_handshake`, `heartbeat`, `execute_premium`, or the `validate_grant` middleware (grep across src shows references only inside src/auth/handshake.rs), so this path appears to be dead/unwired code today — hence low severity. It becomes high-impact if these handlers are ever mounted.  
  *Fix:* Before mounting these handlers: set explicit `Validation` with required `aud`/`iss` and `sub` checks; in `heartbeat`, re-derive capabilities from the persisted grant or by re-reading the API key's current scopes rather than a hardcoded vector; verify the device is still un-blocked (the heartbeat device-status check at handshake.rs:224-227 is a no-op stub). If the module is intentionally unused, gate it behind a feature flag or remove it to avoid accidental future exposure.
- **L5** · [security/sec-config] **Master license/admin key compared with non-constant-time `==` in admin auth path** — `src/auth/middleware.rs`:205-215  
  The fast-path master-credential check uses `if !state.license_api_key.is_empty() && raw == state.license_api_key`, where `raw` is the attacker-supplied bearer token and `license_api_key` comes from config/`LYNXX_API_KEY`. Rust's `str`/`String` `==` is a length check followed by a byte-by-byte memcmp that short-circuits on the first mismatch, leaking timing information about how many leading bytes matched. The codebase depends on `subtle` (Cargo.toml:223) but it is not used in this comparison (no `ct_eq`/`ConstantTimeEq` anywhere under src/). DB-stored tokens are looked up by SHA-256 hash (constant-ish via hashmap), but the highest-value secret — the master key that grants full Admin — uses the raw timing-leaky compare.  
  *Fix:* Compare the presented bearer against the master key using a constant-time primitive, e.g. `subtle::ConstantTimeEq` on the byte slices (or compare fixed-length SHA-256 digests of both with `ct_eq`). Ensure the comparison does not early-return on length mismatch.
- **L6** · [security/sec-config] **Config {env.VAR} interpolation can expand any environment variable into config fields** — `src/config.rs`:1626-1641  
  `expand_env_vars` runs a regex substitution of `{env.NAME}` placeholders against the raw config file contents before parsing (called from `load_config` at line 1641), resolving each to `std::env::var(NAME)` for any matching `[A-Za-z_][A-Za-z0-9_]*`. There is no allow-list of which variables may be referenced, so a config file can pull in process secrets like `AWS_SECRET_ACCESS_KEY`, `POSTGRES_PASSWORD`, etc. into arbitrary string fields. Because the full config is exposed via the (currently unauthenticated) `GET /admin/v1/config` and is written into rollback history snapshots (src/admin/config_api.rs:36-39, 62-75), an attacker who can influence the config file (e.g. via a writable import path or the PUT/PATCH endpoints) can exfiltrate any environment variable's value by placing `{env.SECRET}` into a readable field and then reading it back.  
  *Fix:* Restrict `{env.VAR}` expansion to an explicit allow-list of permitted variable names (or a `LYNXX_`-prefixed namespace), and/or only expand placeholders in fields that are not echoed back by the config API. Combined with redaction (other finding), avoid storing expanded secret values in history snapshots.
- **L7** · [security/sec-llm-gql] **anomaly-detector buffers entire response body on every sampled response without using it** — `src/plugins/anomaly_detector/mod.rs`:385-417  
  on_response unconditionally drains and fully buffers the response body into memory (`body.collect().await ... .to_bytes()`, lines 386-391) before doing anything else. The collected bytes are then never inspected — check_response (line 394) only reads resp.status() and the error window, and check_response itself early-returns at line 247 when error_rate is disabled. The body is simply re-wrapped at line 417. There is no size cap on this buffering.  
  *Fix:* Read resp.status() and update the error window without collecting the body at all (do not std::mem::replace/collect the body). If a future signal genuinely needs the body, gate the collection behind that signal being enabled and impose a max-bytes cap.
- **L8** · [security/sec-plugin-auth] **Digest auth response compared with non-constant-time String equality (`expected == *response`)** — `src/plugins/digest_auth.rs`:174  
  validate() returns `expected == *response`, a standard variable-time String comparison of the computed digest hex against the client-supplied response. Both are SHA-256-derived hex strings dependent on the secret/HA1. The comparison short-circuits on the first differing byte.  
  *Fix:* Compare with a constant-time primitive (e.g. subtle::ConstantTimeEq on the decoded bytes, or hmac/ring's fixed-time compare) after normalizing to bytes.
- **L9** · [security/sec-routing] **gRPC-Web handler buffers entire upstream response into an unbounded Vec** — `src/proxy/grpc.rs`:169-204  
  handle_grpc_web collects the full upstream gRPC response by looping over incoming.into_data_stream() and resp_body_bytes.extend_from_slice(&chunk) with no size ceiling (unlike the request side which caps to_bytes at 10 MiB). The buffered Vec is then returned as the whole response body. Whereas the normal HTTP and gRPC paths stream the body, the gRPC-Web path fully materialises it in memory.  
  *Fix:* Impose a configurable maximum buffered size on the gRPC-Web response aggregation (return 502/413 when exceeded), or implement proper streaming trailers-in-body framing instead of full buffering (the code already has a TODO acknowledging trailers-in-body is unimplemented).
- **L10** · [security/sec-routing] **Routing/directive engine (matchers, handle blocks, uri_directives, intercept rules) is defined but never invoked in the request path** — `src/proxy/handler.rs`:334-631  
  Route carries matchers, matcher_refs, handle_blocks, try_files, uri_directives, and intercept_rules (src/models/mod.rs:288-293), and src/proxy/matchers.rs, src/proxy/directives.rs, and src/proxy/response_intercept.rs implement them — but a repo-wide search shows their evaluation functions (matchers::evaluate / evaluate_all, evaluate_handles, apply_uri_directives, apply_intercept_rules, try_files_rewrite, response_intercept::evaluate_rules) are referenced only from their own #[cfg(test)] modules (and directives.rs internally). proxy_handler never calls them; routing/rewriting is done solely by router.rs path matching and resolve_upstream_path. Note matchers.rs also compiles regexes per request (e.g. PathRegex/HeaderRegex/VarRegex and evaluate_expression's path.matches) which would be a ReDoS/perf concern if it were live — it currently is not.  
  *Fix:* Either wire the matcher/directive/intercept evaluation into proxy_handler (after route match, before upstream dispatch and on the response side) — applying request-context matchers as a hard gate and compiling all regexes once at route load like RouteCache already does for path_regexes — or remove the unused fields/config surface so operators cannot configure controls that do nothing.
- **L11** · [security/sec-ssrf] **Caching DNS resolver applies no private/link-local egress filtering, enabling DNS-rebinding-style pivots for discovery-controlled upstreams** — `src/proxy/http_client.rs`:84-146  
  `CachingDnsResolver` resolves whatever hostname the upstream connector hands it (http_client.rs:133-145) and returns all A/AAAA records with a 30s positive cache (89-92). There is no filtering of loopback, link-local (169.254/16), or RFC1918 results, and the resolved IP is used at connect time. Combined with the absence of upstream-URL validation (see the SSRF finding), a discovery backend can register `http://attacker.example/` whose DNS resolves to `169.254.169.254` or an internal IP; because resolution happens at connect time with only a 30s cache, the answer can also be flipped between a benign IP (passing any future host check) and an internal IP (DNS rebinding).  
  *Fix:* When egress filtering is added for upstream URLs, enforce it in the resolver/connector too: after resolution, reject SocketAddrs in loopback/link-local/private/metadata ranges unless an explicit operator opt-in is set, so rebinding cannot bypass a name-based check.
- **L12** · [security/sec-ssrf] **Consul/Nomad service names are interpolated unescaped into catalog API request paths** — `src/discovery/consul.rs`:314-318  
  `fetch_catalog_service` builds `format!("{}/v1/catalog/service/{}", endpoint, name)` with the raw service name (consul.rs:314-318); Nomad does the same with `format!("{}/v1/service/{}", endpoint, name)` (src/discovery/nomad.rs:276-280). The `name` comes from the `/v1/catalog/services` map keys / Nomad service stubs and is not percent-encoded before being placed in the URL path. A name containing `../`, `?`, `#`, or additional path segments alters the request URL sent to the Consul/Nomad API.  
  *Fix:* Percent-encode the service name path segment (e.g. via `url::Url` join or a `utf8_percent_encode` over the path-segment set) before building the catalog/registration request URL in both providers.
- **L13** · [security/sec-static] **FastCGI SCRIPT_FILENAME built by raw string concat with no traversal/extension validation (PHP-FPM source disclosure / RCE)** — `src/proxy/fastcgi.rs`:214-229  
  send_fastcgi computes script_filename = format!("{document_root}/{script_name}") and sends it verbatim as the SCRIPT_FILENAME FastCGI param to PHP-FPM, with no check that the resolved file stays under document_root, exists, or has a .php extension, and no PATH_INFO splitting. SCRIPT_NAME is also set directly to script_name. If script_name is derived from the request URL (the documented php_fastcgi use case in the module header), a value containing ../ or an absolute path or a NUL-trimmed/extension-trick (e.g. /uploads/avatar.png/../../../../etc/passwd, or pointing SCRIPT_FILENAME at an uploaded file) causes PHP-FPM to execute/interpret an arbitrary file. PHP-FPM trusts SCRIPT_FILENAME implicitly; this is the canonical PHP-FPM arbitrary-PHP-execution / source-disclosure primitive. The code also does not reject script_name pointing outside the root because the only traversal guard in the codebase (safe_resolve) is in the static-file module and is not applied here.  
  *Fix:* Resolve script_filename against a canonicalized document_root and reject if it escapes the root; require the target to exist and match an allowed extension set (e.g. .php); strip NUL bytes; implement proper PATH_INFO splitting so only the real script is passed as SCRIPT_FILENAME. Document that script_name must never be passed raw from the URL.
- **L14** · [security/sec-static] **FastCGI CGI response headers passed through unfiltered (hop-by-hop / Content-Length / Transfer-Encoding from backend)** — `src/proxy/fastcgi.rs`:315-356  
  parse_cgi_response iterates over every header line the backend emits and calls builder.header(name, value) for all of them except a special-cased "Status" (lines 336-349). There is no allowlist/denylist: backend-controlled Content-Length, Transfer-Encoding, Connection, and other hop-by-hop headers are copied straight into the client-facing Response while hyper independently frames the body it builds from body_bytes. A backend (a buggy or compromised PHP app, or one influenced by attacker input) can set Content-Length/Transfer-Encoding values that conflict with the actual body hyper sends, or inject Set-Cookie/CSP/cache headers. Header *values* cannot contain raw CRLF (lines are split on '\n' so embedded newlines are dropped), so direct CRLF response-splitting is mitigated, but the unfiltered duplicate framing headers create request/response desync risk and let a backend dictate caching/security headers.  
  *Fix:* Strip hop-by-hop headers (Connection, Transfer-Encoding, Keep-Alive, Upgrade, etc.) and the backend-supplied Content-Length from CGI output; let hyper own framing based on the actual body. Optionally validate/normalize header names and reject obviously malformed ones.
- **L15** · [security/sec-static] **Directory listing renders symlink targets and entry names without HTML escaping** — `src/proxy/static_files.rs`:615-656  
  render_directory_listing builds table rows with format! using raw filesystem-derived strings: entry.name is used for both href and display, and when browse_reveal_symlinks is enabled the symlink target is interpolated as "&#8594; {target}" — none of these are HTML-escaped before being placed inside <a href="{href}">{display}{symlink_info}</a>. (Contrast with error_pages.rs which correctly html_escapes the path.) request_path is likewise substituted into the page title and into custom templates ({{path}}) without escaping. A filename or symlink target containing HTML/JS (e.g. a file named '<img src=x onerror=alert(1)>.txt', creatable in upload directories) is reflected verbatim into the listing page.  
  *Fix:* HTML-escape entry.name, the symlink target, and request_path (reuse the html_escape helper from error_pages.rs) before interpolating into the listing; URL-encode href values.
- **L16** · [security/sec-tls] **Embedded ACME server signs internal-CA certificates for any requested domain with no challenge validation and no JWS/account verification** — `src/proxy/acme_server.rs`:342-407, 409-494, 146-207  
  The embedded ACME server's new_order_handler (lines 342-407) creates orders with status forced directly to OrderStatus::Ready (line 381 'skip pending — no real challenge') and account_id left empty (line 379 '// simplified — no JWS account binding'). finalize_handler (lines 409-494) then calls sign_csr() which mints a leaf certificate for the order's domains signed by the intermediate CA (lines 146-207) — and explicitly ignores the CSR contents (line 191 'let _ = csr_der'), deriving the SANs purely from the order's requested domains. None of the handlers verify the RFC 8555 JWS signature, the account key, the nonce on the protected header, or any domain-control challenge (HTTP-01/DNS-01/TLS-ALPN-01). Any client able to POST to /acme/new-order then /acme/finalize/{id} obtains a cert for any DNS name, signed by the gateway's internal CA (pki::PkiAuthority root/intermediate, which clients are told to trust).  
  *Fix:* Before mounting these handlers, implement real RFC 8555 flow: verify the JWS signature against the account key, enforce nonces, bind orders to the authenticated account, and require a completed domain-control challenge (authorizations must be Valid) before finalize signs anything. Until then, gate the module behind a hard compile/runtime guard so it cannot be accidentally exposed. Do not derive certs solely from requested domains without proof of control.
- **L17** · [security/sec-tls] **OCSP staple with no nextUpdate is cached and served indefinitely without refresh** — `src/proxy/ocsp.rs`:495-562, 233-253  
  CachedOcsp.expires is set from parse_ocsp_next_update(), which returns None when the OCSP response lacks a nextUpdate field or is otherwise unparseable (lines 233-253, 318-325). In the staple() fast path (lines 543-551) the validity check is `cached.expires.map(|exp| now < exp).unwrap_or(true)` — i.e. when expires is None the cached response is treated as permanently valid and is never re-fetched by this path. The OcspStapler also performs no verification that the fetched response's certStatus is 'good' or that the CertID matches the served chain; it only checks the top-level responseStatus==successful purely to extract nextUpdate. A response indicating 'revoked' would still be stapled.  
  *Fix:* When nextUpdate is absent, apply a short bounded TTL (e.g. re-fetch within minutes/hours) instead of caching forever. Additionally parse and reject responses whose certStatus is not 'good', verify the CertID matches the served leaf, and check thisUpdate/nextUpdate against the current time before stapling.
- **L18** · [security/sec-wasm] **WASM module_path / hot-reload trusts operator DB config with no path confinement or re-validation provenance** — `src/plugins/wasm/mod.rs`:240-270  
  `load_module_bytes` reads `cfg.module_path` (a free-form String taken from the plugin's JSON config persisted in the DB, see plugins/mod.rs:308) directly via `std::fs::read(path)` with no canonicalization, no allow-list directory confinement, and no symlink resolution. The watcher (watcher.rs) then polls that same arbitrary path by mtime and triggers a recompile-from-disk on any change (sync_paths in plugins/mod.rs:305-313 feeds it the raw module_path strings). The only gate is the 5MB size cap and the wasm magic check. There is no integrity check (hash/signature) on the loaded bytes. Anyone able to write the configured path (or swap a symlink it points to) gets their bytes JIT-compiled and run in-process on the next 2s poll, with no operator action.  
  *Fix:* Confine module_path to a configured, operator-owned plugins directory (canonicalize and verify the resolved path is inside it, rejecting symlinks that escape). Add an optional content hash / ed25519 signature (the project already depends on ed25519-dalek) recorded in config and verified on every load and every hot-reload before compilation. Log and reject reloads whose bytes don't match the expected digest.
- **L19** · [performance/perf-hotpath] **match_by_host allocates a new lowercased String for the host on every request** — `src/proxy/router.rs`:150-154  
  `match_by_host` does `let key = host.to_ascii_lowercase();` (line 151) unconditionally before the `host_index` lookup. `to_ascii_lowercase()` always heap-allocates a fresh String, even when the host is already lowercase (the overwhelmingly common case, since browsers send lowercase hosts and the handler already strips the port at handler.rs:360). This runs for every request that carries a Host header (handler.rs:370-371).  
  *Fix:* Fast-path the already-lowercase case: if `host.bytes().all(|b| !b.is_ascii_uppercase())`, look up `host` directly via `self.host_index.get(host)` with no allocation; only allocate a lowercased copy when an uppercase byte is present. (DashMap supports borrowed `&str` lookups for `String` keys via the Borrow impl.)
- **L20** · [performance/perf-plugins] **Compression buffers and compresses the full body before honoring Content-Length, ignoring the upstream's declared length for the min_body_size gate** — `src/plugins/response_compression.rs`:329-338  
  on_response always does `let body = mem::replace(...); let bytes = body.collect().await...` to materialize the entire body, and only afterward checks `if bytes.len() < self.min_body_size { restore; return }`. When the upstream response carries a Content-Length header smaller than min_body_size (the common case for small JSON/API responses), the plugin still drains and buffers the whole streaming body into a contiguous Bytes before deciding not to compress, defeating any streaming the upstream would have allowed.  
  *Fix:* Before draining the body, check the CONTENT_LENGTH header: if present and below min_body_size, return early without collecting the body. Only buffer when the declared length (or absence of one) makes the body a genuine compression candidate.
- **L21** · [performance/perf-plugins] **Request-transformer allocates two Vecs and clones HeaderNames per request even when no header value contains a placeholder** — `src/plugins/request_transformer.rs`:226-251  
  on_request unconditionally builds expanded_add and expanded_replace by iterating self.add / self.replace, calling expand_placeholders on each value and collecting into two new Vec<(HeaderName, HeaderValue)> with cloned HeaderNames and re-parsed HeaderValues — for every request. expand_placeholders has a fast `!template.contains('{')` early-out (returns to_string), but the per-request Vec allocations, HeaderName::clone, and HeaderValue::from_str re-parse happen regardless of whether any configured value actually uses a placeholder.  
  *Fix:* At from_config time, detect whether any add/replace value contains '{'. If none do, store the already-parsed (HeaderName,HeaderValue) list and apply it directly each request (no per-request rebuild). Only run the expand/collect path for entries that actually contain placeholders.
- **L22** · [performance/perf-tls] **io_uring accept path adds per-connection set_nonblocking + peer_addr getpeername syscalls, eroding the single-syscall-per-accept win** — `src/proxy/ktls_listener.rs`:213-228  
  AcceptSource::Channel::next_conn() rebuilds each FD via fd_to_std_stream, then calls std_stream.set_nonblocking(true)? (line 222, an fcntl syscall) and std_stream.peer_addr() (line 223-225, a getpeername syscall) for every accepted connection before from_std. The module's stated benefit (io_uring_accept.rs lines 20-25) is replacing 'one syscall per accept' with an SQE submission, but this tokio-side glue immediately re-adds two syscalls per accept. peer_addr is only used to produce the `peer` value, which is consumed solely as a tracing::debug! field in the spawned task (ktls_listener.rs line 345).  
  *Fix:* Have the io_uring acceptor return the peer SocketAddr it can already capture from the Accept CQE (write the sockaddr buffer instead of passing null pointers) so the tokio side needs neither getpeername nor a separate call; and avoid the redundant set_nonblocking — io_uring-accepted sockets can be opened nonblocking, or the flag can be set once via the CQE. At minimum, skip peer_addr() entirely when the value is only used for a debug-level log.
- **L23** · [performance/perf-tls] **Pre-warmer deep-clones the entire service table every tick, then re-clones each Service a second time** — `src/proxy/prewarm.rs`:62-96  
  run_once() starts with let services = route_table.list_services(); (line 68). list_services() (router.rs lines 250-252) iterates the DashMap and does s.clone() for every entry, producing a Vec<Service> where Service (models/mod.rs lines 59-114+) is a heavy struct of many String/Option<String> fields. Then inside the per-service loop run_once additionally does svc_clone = svc.clone() (line 95) plus svc.name.clone() (line 94) and url.to_string() (line 84) — i.e. each service is fully deep-copied at least twice per tick. This fires on every prewarm_interval_secs tick for the full upstream set.  
  *Fix:* Add a lighter accessor that yields only the fields prewarm needs (id, name as Arc<str>, url) without cloning the full Service — e.g. route_table.list_prewarm_targets() returning (Uuid, Arc<str>, String). Inside the loop, move the single owned copy into the spawned task instead of cloning the Service again. The name field is already Arc<str>, so prefer cloning that over the whole struct.
- **L24** · [performance/perf-tls] **biased select polls the JoinSet-reap arm ahead of the accept arm, deprioritizing new-connection acceptance under churn** — `src/proxy/ktls_listener.rs`:308-353  
  serve_inner's accept loop uses tokio::select! { biased; ... }. With biased ordering the arms are polled top-to-bottom: shutdown (311), then Some(_done) = tasks.join_next(), if !tasks.is_empty() (317), then accept = source.next_conn() (318). Because reaping completed connection tasks is ranked above accepting new connections, whenever there is a steady stream of completing connections the runtime will keep draining join_next before it polls next_conn(), so the accept arm is only serviced once no completion is immediately ready.  
  *Fix:* Either drop `biased` so tokio randomizes fairly, or reorder so next_conn() is polled before tasks.join_next(). Reaping can also be made cheaper/less frequent (e.g. try_join_next in a tight non-awaiting drain after each accept) rather than competing as a top-priority select arm.
- **L25** · [performance/qual-proxy] **HTTP/3 request body is collected unbounded and byte-by-byte (no size limit, O(n) pushes)** — `src/proxy/h3.rs`:66-83  
  `handle_connection` collects the entire H3 request body into a `Vec<u8>` by looping `while chunk.has_remaining() { body_bytes.push(chunk.get_u8()); }` (lines 71-73) with no maximum-size check. The axum `DefaultBodyLimit::max(64MB)` layer is only applied to the TCP-listener router (main.rs:694); the H3 path builds the `Request` itself and calls `proxy_handler` directly, bypassing that layer entirely. Per-byte `Vec::push` also defeats bulk copy/reserve. (`spawn_h3_server` is currently not invoked anywhere in src/, so this is latent rather than live.)  
  *Fix:* Enforce an explicit byte cap while reading (abort with an error past the limit, matching the axum 64MB ceiling) and append chunks in bulk via `body_bytes.extend_from_slice(chunk.chunk())` / `Bytes` concatenation instead of `get_u8()`. Better: stream the body into `axum::body::Body` rather than fully buffering.
- **L26** · [performance/qual-proxy] **grpc-web response body buffered fully into a Vec with no size limit** — `src/proxy/grpc.rs`:171-188  
  `handle_grpc_web` collects the upstream gRPC response by looping over `incoming.into_data_stream()` and `resp_body_bytes.extend_from_slice(&chunk)` (lines 171-178) with no upper bound, then builds the downstream response from the fully materialised Vec. The request side caps buffering at 10MB (line 142), but the response side is uncapped. (Note the module also TODOs that trailers-in-body encoding is unimplemented, so large streamed responses are buffered for no functional benefit yet.)  
  *Fix:* Apply a configurable size cap when accumulating `resp_body_bytes` (error past the limit), or stream the body through with `Body::new(incoming)` once trailers-in-body handling is implemented, instead of unconditionally buffering the whole response.
- **L27** · [quality/qual-core] **RouteTable::load_from_repo clears live maps in place, creating a 404 window during FullSync/reload propagation** — `src/proxy/router.rs`:207-228  
  load_from_repo does `self.services.clear(); self.routes.clear();` and only then re-inserts the freshly fetched rows, followed by rebuild_exact_index/host_index/regex_cache. The maps are DashMaps read by the hot path (match_route, match_by_host) with no overall snapshot/double-buffering, so concurrent proxy requests observe a partially-empty (or fully empty, right after the two clears) route table. This path is invoked on every ChangeEvent::FullSync (src/main.rs:1428), which is published after each successful /reload or SIGHUP (src/reload/mod.rs:92-95) and consumed by every OTHER node.  
  *Fix:* Build the new services/routes/index maps fully off to the side, then atomically swap them in (e.g. wrap the maps in an ArcSwap, or compute a diff and apply add/update/remove like run_reload does instead of clear-and-reload). Avoid leaving the table empty for any observable instant.
- **L28** · [quality/qual-core] **Active health checker can unregister a concurrently-added service as 'stale' within the same tick** — `src/health/checker.rs`:115-263  
  run_once snapshots `current_ids` from route_table.list_services() at the very start (lines 115-119), then awaits network probes for every service+target (potentially seconds). At the end it computes `stale = registry.list() - current_ids` and unregisters each stale id (lines 252-263). A service added during the in-flight tick (via admin API or apply_remote_event, which call health.register) is present in the registry but absent from the start-of-tick current_ids snapshot, so it is unregistered as 'stale'.  
  *Fix:* Recompute current_ids from route_table.list_services() immediately before the stale sweep, or only unregister ids that are absent from a freshly-read service list at sweep time, so additions that happened during the tick are not collected as stale.
- **L29** · [quality/qual-core] **Reload task permanently disabled (not crashed) if run_reload ever panics** — `src/reload/mod.rs`:79-99  
  spawn_reloader runs `while let Some(resp) = rx.recv().await { ... run_reload(...).await ... }` inside a single tokio::spawn. If run_reload (or any future change to it) panics, the spawned task terminates, the mpsc receiver is dropped, and every subsequent ReloadHandle::trigger() fails with GatewayError::Internal("reload task is gone") (lines 55-64). The process keeps running but config reload via SIGHUP and POST /reload is dead until restart. Today run_reload is largely panic-free (load_config returns Result, diffs use Result, plugin config uses unwrap_or), so this is latent rather than active.  
  *Fix:* Wrap each reload invocation so a panic cannot kill the loop, e.g. run the work via tokio::task::spawn(...).await and report JoinError as a ReloadResult error, or use Futures/catch_unwind around run_reload; on panic, send an error ReloadResult back through `resp` and keep the receiver loop alive.
- **L30** · [quality/qual-data] **row_to_audit silently coerces decode errors to None on chain-relevant fields** — `src/db/sqlite.rs`:3328-3340  
  row_to_audit reads actor_name, actor_role, resource_id, prev_hash with try_get(...).ok(), discarding decode errors as None (same in postgres.rs:3003-3010). These feed compute_hash during verify_chain (prev_hash is compared directly). A decode failure silently turns a present value into None, changing the recomputed hash or breaking the prev comparison and producing a spurious verification failure with no error surfaced.  
  *Fix:* Use try_get(...)? (propagate) for fields that participate in the hash chain, especially prev_hash.
- **L31** · [quality/qual-data] **Quota period rollover resets counters without flushing the closing period's final usage** — `src/quota/mod.rs`:279-295  
  maybe_rollover resets calls/rejected/overage to 0 on a new period without first persisting the closing period's final counts; flush() only runs every 30s, so the last up-to-30s of the prior period's activity is discarded and never written to that period's quota_usage row.  
  *Fix:* In maybe_rollover, persist the closing period's final counts before resetting in-memory counters.
- **L32** · [quality/qual-plugins] **file-log writer drops every batch silently with `let _ =` on write_all, masking persistent write failures** — `src/plugins/file_log.rs`:346-369, 373-395  
  In `writer_task`, every `file.write_all(&buf).await` and `file.flush().await` result is discarded with `let _ = ...` (lines 346, 367-368, 377). If writes start failing after the file was successfully opened (disk full, file deleted out from under the handle, permission change, NFS error), the task keeps looping forever, clearing `buf` after each failed write (lines 348, 378) so the log lines are silently lost with no warning emitted. Unlike the open-failure path (lines 324-327) which logs and returns, a runtime write failure produces zero observability and silently discards all subsequent access logs.  
  *Fix:* Inspect the write/flush Result; on error, emit a rate-limited `tracing::warn!` and attempt to reopen the file (as the rotation path already does) before giving up, so failures are visible and recoverable.
- **L33** · [quality/qual-proxy] **Deploy-retry InFlightGuard is dropped before the response body is consumed, undercounting in-flight** — `src/proxy/handler.rs`:1228-1285  
  In the deploy-aware retry loop, the chosen retry target's `InFlightGuard` is bound to `let _guard = InFlightGuard::new(retry_ts.clone());` (line 1228) inside the `for` loop body. On a successful retry the code does `upstream_resp = Some(r); picked_target_id = Some(retry_ts.target.id); ... break;` (lines 1274-1278); the `break` drops `_guard` immediately, decrementing `in_flight` for that target before the response is even returned/streamed. The primary path instead holds its guard in the function-scoped `_in_flight` binding (line 577-580). So for deploy-retried requests the surviving target's `in_flight` is decremented far earlier than for normal requests, and never reflects the in-flight work the retry actually represents.  
  *Fix:* Hoist the retry guard out of the loop into a binding that lives until the end of `proxy_handler` (e.g. assign the winning guard into a mutable outer `Option<InFlightGuard>` on success), mirroring the primary-path `_in_flight` lifetime.
- **L34** · [quality/qual-proxy] **Status-based retries double-increment lynxx_upstream_retries_total** — `src/proxy/handler.rs`:1152-1183  
  In the buffered retry loop, the top of every attempt with `attempt > 0` increments `lynxx_upstream_retries_total` (lines 1154-1159). Separately, when an upstream response matches `retry_on_status`, the code increments the same counter again (lines 1175-1181) right before `continue`. A status-triggered retry therefore counts twice (once when deciding to retry, once at the start of the next attempt), whereas a connection-error retry counts only once (only at the next-iteration top). The metric is both inflated and inconsistent between retry causes.  
  *Fix:* Increment the retry counter in exactly one place — either only at the top of each `attempt > 0` iteration, or only at each retry decision — and drop the duplicate at lines 1175-1181.
- **L35** · [quality/qual-unsafe] **thread_count_macos returns the task scheduling policy as the thread count** — `src/admin/profiling.rs`:176-192  
  Inside the task_info unsafe block the function returns info.policy as usize as the process thread count. mach_task_basic_info_data_t has no thread-count field; policy is the task default scheduling policy (small constant). The unsafe FFI itself is well-formed (zeroed struct, correct count, KERN_SUCCESS checked) but the returned value is meaningless; threads_profile then fabricates that many placeholder ThreadInfo entries.  
  *Fix:* Use task_threads(mach_task_self(), ...) (and vm_deallocate the array) for a real count, or drop the macOS branch and document Linux-only thread enumeration.

## 🔵 Info findings (2)

- **I1** · [security/sec-tls] **PROXY protocol parser is dead code: proxy_protocol config flag is never wired to the listener** — `src/proxy/proxy_protocol.rs`:36-52  
  read_proxy_header() (and parse_v1/parse_v2) is the only inbound consumer of PROXY protocol, but a repo-wide search shows it has zero callers; the [gateway].proxy_protocol bool (config.rs:875) is read by no listener code. So when an operator sets proxy_protocol=true expecting the real client IP to be recovered from an upstream L4 LB header, nothing happens — the PROXY header bytes are left in the stream and parsed as the start of the HTTP request. Separately, even the encoder/decoder has no notion of a trusted-source allowlist (the audit's spoofing concern); the client-IP path that IS live uses X-Forwarded-For gated by trusted_proxies (handler.rs:517-528), which is unaffected, but the advertised PROXY-protocol feature is non-functional.  
  *Fix:* Either wire read_proxy_header() into the TCP accept loop behind the proxy_protocol flag (and add a trusted-source CIDR allowlist so only configured L4 LBs are honored), or remove the flag and module so operators are not misled into believing client-IP recovery is active.
- **I2** · [quality/qual-core] **Service-level body-match health probe silently records nothing when response body read fails** — `src/health/checker.rs`:127-187  
  When hc_config.expected_body.is_some(), the service-level probe sets `body_text = resp.text().await.ok()` (line 129). The status-based success/failure recording branch is skipped (it is in the `else` of expected_body.is_some()), and success/failure is only recorded inside `if let Some(ref bt) = body_text` (lines 160-187). If resp.text() returns Err (truncated/timeout while reading body), `.ok()` yields None, the body-match block is skipped entirely, and neither record_success nor record_failure is called for that service this tick.  
  *Fix:* Treat a body read error as a probe failure: on the None branch, call registry.record_failure(&svc.id, &svc.name, "failed to read health response body"). Reusing is_probe_healthy after fetching the body would also fix this.

---

## Coverage & gaps

Audited slices (file lists in each finder's scope): auth core · license/ed25519 · proxy routing & smuggling · TLS/ACME/OCSP/mTLS · SSRF (proxy+discovery) · auth plugins · exec/template plugins · WASM sandbox · SQL injection · admin API & profiling · config/secrets/privilege · LLM/GraphQL/OpenAPI/recorder · static-files/FastCGI · proxy hot path · TLS/accept perf · plugin middleware perf · DB+concurrency perf · proxy correctness · plugin correctness · lifecycle/reload · unsafe/eBPF · data integrity.

**Known limitations of this audit:**
- Static review only — no dynamic testing, fuzzing, or running the binary. Findings marked `confidence: medium/low` warrant a runtime repro before acting.
- `cargo audit`/`cargo deny` (dependency CVEs) was **not** run as part of this pass — recommend running it separately; `deny.toml` exists in-repo.
- The two backfill slices (unsafe/eBPF, data-integrity) were self-verified by a single conservative agent rather than a separate adversarial verifier.
- 1 finding was rejected and 1 left uncertain during verification (see appendix).

**Recommended remediation order:** C1–C5 (admin auth + secret exposure) and `auth_required` default are an emergency fix — they are a single-request full compromise on a default deployment. Then the identity-spoofing/SSRF/auth-plugin high tier, then the audit-integrity and async-blocking items.

---

## Appendix: uncertain & rejected

- **UNCERTAIN** · Per-target active health check ignores expected_status when expected_body is configured — `src/health/checker.rs`:216-241: The code defect is exactly as described: in checker.rs:216-241 the per-target branch does `let body = r.text().await.unwrap_or_default();`, discarding the status, then hardcodes `status_ok = true` in BOTH sub-branches (lines 221 and 225) with the misleading comments. The 'already got 2xx' comment is false (no status check precedes .text()). The final verdict `status_ok && body.contains(expected)` never consults status. is_probe_healthy() (lines 89-105) is the correct implementation and is confirmed dead code (grep shows only its definition at line 89, no callers). So the technical/code claim is fully accurate. HOWEVER, the claimed operator-facing IMPACT is not reachable in the current build. The active checker's HealthCheckConfig has exactly one construction site (main.rs:502: `HealthCheckConfig::default()`), where expected_body is hardcoded None and expected_status is empty. config.rs exposes only health_check_interval_ms; there is NO plumbing from config.toml or the admin API into this struct (the expected_status/expected_body in admin/probes.rs, dtos/probes.rs, models are a separate Probe feature, not this struct). Therefore the buggy `hc_config.expected_body.is_some()` branch can never execute today, so no 500-with-matching-body target is ever marked healthy. Real latent defect, but the asserted high-severity impact is currently unreachable; downgraded to low.
- **REJECTED** · On-demand TLS issues certificates for arbitrary attacker-chosen hostnames when neither allowed_domains nor ask_url is configured — `src/proxy/on_demand_tls.rs`:215-244, 366-413, 573-586: The internal logic claims are accurate: is_domain_allowed() (on_demand_tls.rs:215-244) returns true for every domain when both allowed_domains and ask_url are None; the constructor (149-159) sets both to None when config strings are empty; and OnDemandTlsConfig::default() (config.rs:573-582) ships both empty. resolve() (366-413) does push cache-miss SNIs into ISSUANCE_TX and the loop calls trigger_issuance. HOWEVER the load-bearing premise of the finding — that this resolver is 'the rustls ResolvesServerCert hook on the public 443 data plane' — is false. A repo-wide grep across src/ and crates/ shows OnDemandTlsResolver is never instantiated, spawn_issuance_loop is never called, ISSUANCE_TX is never populated by any caller, and config.on_demand is never read by any listener/server code (only defined in config.rs and defaulted at line 691, declared as a module in mod.rs:17). The with_cert_resolver calls in acme.rs:380/648 install entirely different resolvers (SAN-indexed / AcmeChallengeResolver / AlpnChallengeStaticResolver), not OnDemandTlsResolver. Because the resolve() hook is never wired to any TLS listener, no SNI from any client can reach it, ISSUANCE_TX stays None so the channel send is a no-op, and no ACME order is ever launched. The described live 'one-flag misconfiguration -> unauthenticated ACME amplification / Let's Encrypt rate-limit exhaustion' impact is not realizable in the current code. The vulnerable logic exists as latent/dead code, so this is a code-hygiene/latent-risk issue, not a live high-severity vulnerability. Downgraded from high to low.

