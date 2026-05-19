# Company env vars

These are the env vars **Vexarr** sets when producing a build of the
gateway. They get **baked into the binary at compile time** — they
never get read at runtime. Wrong value here means shipping a binary
that talks to the wrong backend.

Set them on the `cargo build` / `cargo run` command line, or in a
`.env` that you `source` before invoking cargo.

| Var | Required? | Default | Description |
|---|---|---|---|
| `AUTH_URL` | **required** | none (build fails) | URL of the keyx instance the gateway forwards api-key validation to. Production: `https://auth.vexarr.com`. Local stub testing: `http://127.0.0.1:9100`. |

That's it. One variable, no defaults.

## Examples

```sh
# Production release artefact
AUTH_URL=https://auth.vexarr.com cargo build --release --bin lynxx-gateway

# Local build pointed at keyx-stub
AUTH_URL=http://127.0.0.1:9100 cargo run --bin lynxx-gateway
```

## Why it has to be set at build time

So a shipped binary can't be redirected to a malicious auth backend by
flipping an env var on the host. The URL is part of the artefact.
