# Proxy bench summary

_Generated 2026-05-21T05:22:14Z from /Users/shreyansh/Documents/vexarr/lynxx/external/core/gateway.lynxx.vexarr.com/bench/proxy-bench/outputs — selection: `latest`._

## Headline ranking (sorted by sustained ceiling RPS)

| Proxy | Seq | Status | Ceiling RPS | Best p99 (ms) | Worst p99 (ms) | Errors | Ladder cut |
|---|---:|---|---:|---:|---:|---:|---:|
| direct | 1 | complete | 65460 | 0.0620 | 0.0960 | 0 | — |
| kong | 1 | complete | 54977 | 0.4870 | 11.22 | 348 | — |
| nginx | 1 | complete | 54233 | 0.2030 | 0.8850 | 0 | — |
| lynxx | 1 | complete | 49748 | 0.3930 | 61.38 | 0 | — |
| envoy | 1 | complete | 21144 | 0.5000 | 9.57 | 231310 | — |

## p99 (ms) by RPS level — iso-load grid

| RPS | direct | envoy | kong | lynxx | nginx |
|---:|---:|---:|---:|---:|---:|
| 10000 | 0.0960 | 0.5000 | 0.4870 | 0.3930 | 0.2030 |
| 25000 | 0.0890 | 9.57 | 1.15 | 0.9150 | 0.2380 |
| 50000 | 0.0800 | — | 3.01 | 35.94 | 0.5670 |
| 100000 | 0.0640 | — | 11.22 | 38.30 | 0.5420 |
| 200000 | 0.0640 | — | 10.89 | 37.31 | 0.8850 |
| 400000 | 0.0630 | — | 6.87 | 38.34 | 0.6560 |
| 600000 | 0.0620 | — | 9.41 | 38.08 | 0.5510 |
| 800000 | 0.0620 | — | 10.00 | 61.38 | 0.5900 |
| 1000000 | 0.0620 | — | 11.07 | — | 0.5670 |

## Achieved RPS — was the SUT the bottleneck?

_When achieved < target, the proxy is the bottleneck. When they match, the bench client could go higher._

| RPS target | direct | envoy | kong | lynxx | nginx |
|---:|---:|---:|---:|---:|---:|
| 10000 | 10000 | 10000 | 10000 | 10000 | 10000 |
| 25000 | 25000 | 21144 | 24999 | 24999 | 25000 |
| 50000 | 49999 | — | 49999 | 49157 | 49999 |
| 100000 | 62953 | — | 51646 | 49600 | 53493 |
| 200000 | 63510 | — | 53622 | 48643 | 54124 |
| 400000 | 64535 | — | 53249 | 49692 | 54233 |
| 600000 | 65307 | — | 53836 | 49748 | 53019 |
| 800000 | 65460 | — | 54977 | 43467 | 53707 |
| 1000000 | 65425 | — | 53975 | — | 53865 |
