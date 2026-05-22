# syntax=docker/dockerfile:1.6
#
# Multi-stage build for the Lynxx gateway. The same image graph produces
# two named final stages — `gateway` and `ingress` — each holding only the
# binary it needs.
#
#   docker build --target gateway -t lynxx-gateway .
#   docker build --target ingress -t lynxx-ingress .

FROM rust:1-slim-bookworm AS builder
WORKDIR /build
RUN apt-get update && apt-get install -y --no-install-recommends \
        pkg-config libssl-dev ca-certificates \
    && rm -rf /var/lib/apt/lists/*

# ---- Cargo dependency cache layer -------------------------------------------
# Copy only the manifests first and build a stub binary so the dependency
# graph compiles into a layer that survives source edits.
# ---- Real build -------------------------------------------------------------
COPY Cargo.toml Cargo.lock ./
COPY src ./src
COPY bench ./bench
COPY migrations ./migrations
COPY tests ./tests
COPY scripts ./scripts
COPY assets ./assets
COPY dashboard-dist ./dashboard-dist

# BuildKit cache mounts: persist the cargo registry index/cache and the
# target/ directory across builds. Combined with the registry-side
# `cache-from`/`cache-to` in deploy-gcp.yml, repeat builds drop from
# ~12 min cold to ~2-3 min warm. Move the binaries off the cache mount
# before the layer ends or they'd be discarded.
ARG LYNXX_NODE_DASHBOARD_URL
ARG LYNXX_BUILD_HASH
ARG AUTH_URL
RUN apt-get update && apt-get install -y --no-install-recommends curl unzip && \
    rm -rf /var/lib/apt/lists/*
RUN --mount=type=cache,target=/usr/local/cargo/registry,sharing=locked \
    --mount=type=cache,target=/build/target,sharing=locked \
    LYNXX_BUILD_HASH=${LYNXX_BUILD_HASH} AUTH_URL=${AUTH_URL} \
    RUSTFLAGS="--cfg tokio_unstable" \
    ./scripts/build.sh --bin lynxx-gateway --bin lynxx-ingress && \
    mkdir -p /out && \
    cp target/release/lynxx-gateway target/release/lynxx-ingress /out/

# ---- Shared runtime base ----------------------------------------------------
FROM debian:bookworm-slim AS runtime-base
RUN apt-get update && apt-get install -y --no-install-recommends ca-certificates \
    && rm -rf /var/lib/apt/lists/*
RUN useradd -r -u 10001 -m lynxx

# ---- Gateway image ----------------------------------------------------------
FROM runtime-base AS gateway
COPY --from=builder /out/lynxx-gateway /usr/local/bin/
COPY --from=builder /build/migrations /etc/lynxx/migrations
COPY config.toml /etc/lynxx/config.toml
USER lynxx
WORKDIR /etc/lynxx
EXPOSE 28080 28081
ENTRYPOINT ["/usr/local/bin/lynxx-gateway"]

# ---- Ingress controller image ----------------------------------------------
FROM runtime-base AS ingress
COPY --from=builder /out/lynxx-ingress /usr/local/bin/
USER lynxx
ENTRYPOINT ["/usr/local/bin/lynxx-ingress"]
