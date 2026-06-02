# Lynxx Algorithms & Structures — Architecture

## Crate layout

```
crates/
├── algorithms/                    # Hot-path algorithms + backbone dispatch
│   ├── src/
│   │   ├── lib.rs               # pub mod goals; pub mod backbone;
│   │   ├── goals/               # Pure algorithm implementations (by domain)
│   │   │   ├── hash/
│   │   │   ├── encode/
│   │   │   ├── http_codec/
│   │   │   ├── rate_limit/      # incl. dagor, codel (papers)
│   │   │   ├── resilience/
│   │   │   ├── upstream_pick/   # incl. p2c (paper)
│   │   │   ├── optimized/       # Zero-alloc hot paths
│   │   │   └── …
│   │   └── backbone/            # Trait + adapter + tier factory
│   │       ├── traits/
│   │       ├── adapters/        # Wrap goals::* for traits
│   │       └── factory/         # Starter / Growth / Pro dispatch
│   ├── benches/                 # criterion, mirrors goals/ layout
│   ├── fuzz/                    # cargo-fuzz targets (workspace member)
│   └── docs/
│       ├── PROVENANCE.md
│       └── ARCHITECTURE.md
│
└── lynxx_structures/            # Shared data structures
    └── src/
        ├── lib.rs               # pub mod + pub use re-exports
        ├── arc_cache.rs         # Paper (ARC)
        ├── wtinylfu.rs          # Paper (W-TinyLFU)
        ├── clfus_cache.rs       # ATS
        └── …
```

## How the pieces fit

1. **`goals/`** — Source of truth for algorithm logic. Each subdirectory is a domain (`rate_limit`, `upstream_pick`, …). Every module is declared in that domain’s `mod.rs` and re-exported at the crate root of the domain via `pub use`.

2. **`backbone/`** — Subscription-tier dispatch. Adapters in `backbone/adapters/` implement traits by delegating to `goals/`. Factories (`TierLoadBalancer`, `TierRateLimiter`, …) pick Starter / Growth / Pro based on license. Restored paper/ATS algorithms are used from `goals/` directly or via adapters when they implement a backbone trait (e.g. `P2cLb` → `LoadBalancer`).

3. **`lynxx_structures/`** — Caches, locks, buffers, heaps. No backbone layer; gateway or `algorithms` import types from `lynxx_structures::`.

4. **`benches/`** — One criterion bench per algorithm, named `{domain}_{algo}` (e.g. `rate_limit_dagor`, `upstream_p2c`). Run via `crates/algorithms/bench-profile.sh` (`papers`, `ats`, `optimized` filters).

5. **`fuzz/`** — Separate workspace package `algorithms-fuzz` for parser/hash fuzzing.

6. **`lynxx_structures/benches/`** — Criterion benches for ATS/paper caches and locks (`structures_*` targets). Run via `crates/lynxx_structures/bench-profile.sh` or `bench-profile.sh structures` from algorithms.

## Import patterns

```rust
// Domain API (preferred for new code in goals)
use algorithms::goals::rate_limit::{CoDel, DagorController};
use algorithms::goals::upstream_pick::P2cBalancer;

// Backbone (gateway license tiers)
use algorithms::backbone::{Tier, create_hasher, TierLoadBalancer};

// Structures
use lynxx_structures::{ArcCache, WTinyLfu, ClfusCache};
```

## Testing

```bash
AUTH_URL=http://127.0.0.1:9100 cargo test -p algorithms -p lynxx_structures
AUTH_URL=http://127.0.0.1:9100 cargo test -p algorithms --test backbone_dispatch
```
