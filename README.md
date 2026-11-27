# Lynxx Gateway ⚡

[![License: Apache-2.0 / MIT](https://img.shields.io/badge/License-Apache_2.0_|_MIT-blue.svg)](LICENSE)
[![Language: Rust](https://img.shields.io/badge/Language-Rust-orange.svg)](https://www.rust-lang.org/)
[![Security: STRIDE Modeled](https://img.shields.io/badge/Security-STRIDE_Modeled-green.svg)](THREAT_MODEL.md)

**Lynxx** is an ultra-resilient, high-throughput reverse proxy, API gateway, and cryptographic license verification infrastructure written in pure, asynchronous Rust with Tokio and Axum.

Designed from the ground up for zero-trust, sovereign, and tactical air-gapped environments, Lynxx delivers sub-millisecond proxy latency, raw TCP fast-path routing, real-time eBPF metrics collection, and tamper-resistant cryptographic activation validation.

---

## 🌟 Key Features

* **⚡ Raw-TCP Fast Path:** Bypasses intermediate user-space buffer allocations for maximum socket-to-socket throughput.
* **🛡️ Kernel-Level eBPF Telemetry:** Real-time socket polling and performance metrics directly from Linux kernel probes.
* **🔑 Cryptographic Digital Signatures:** Asymmetric Ed25519 digital signature verification for binary entitlement claims and license activation tokens with replay defenses.
* **🔒 Threat-Model Hardened:** Complete [STRIDE Threat Model](THREAT_MODEL.md) detailing trust boundaries, privilege escalation protections, and memory safety invariants.
* **📦 Zero External Dependencies:** Statically linkable into a standalone lightweight binary; requires no external database (such as PostgreSQL/Cassandra) or Lua scripting runtime.

---

## 🚀 Quickstart

### Prerequisites
* Rust 1.80+ (`cargo`)

### Build & Run
```bash
git clone https://github.com/shregar1/gateway.lynxx.vexarr.com.git
cd gateway.lynxx.vexarr.com
cargo build --release
cargo run --release
```

The gateway binds to `0.0.0.0:8000` by default.

---

## 📊 Comparison with Kong & Apigee

| Feature | Lynxx | Kong (OpenResty) | Apigee |
| :--- | :--- | :--- | :--- |
| **Runtime Language** | **Pure Rust (Tokio/Axum)** | Lua / C (Nginx) | Java / Cloud SaaS |
| **Memory Footprint** | **~15 MB RSS** | ~250+ MB RSS | Heavy JVM Memory |
| **External Database** | **None (Self-Contained)** | Postgres / Cassandra | Cloud / Cassandra |
| **Air-Gap Sovereign Support** | **Native Single Binary** | Requires DB Cluster | Cloud Dependent |
| **Kernel Fast-Path** | **Raw TCP + eBPF** | Standard Nginx Socket | Standard Web Socket |

---

## 📜 License
Licensed under Apache-2.0 or MIT.
