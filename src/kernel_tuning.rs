//! Boot-time sysctl + rlimit tweaks for the proxy host.
//!
//! Beyond what's encoded here, two **non-sysctl** knobs make a large
//! difference at saturation and should be applied by the operator:
//!
//! 1. **`iptables -t raw -A PREROUTING -i lo -j NOTRACK`** (and the
//!    matching `OUTPUT -o lo -j NOTRACK`). Skips `nf_conntrack` for
//!    loopback traffic. The symbolized perf capture at 100 k RPS
//!    showed `__nf_conntrack_find_get` at ~470 M samples (≈ 2 % of
//!    total CPU) when conntrack was enabled — pure overhead because
//!    no NAT/iptables rules ever match a loopback packet, and the
//!    bench rig never proxies cross-host. Switching this off on the
//!    bench rig moved p99 from **4.06 ms → 2.89 ms** at 100 k offered
//!    / 4096 conns and stabilized iteration-to-iteration variance
//!    (conntrack table fill was the root cause of the
//!    "first-run-clean, runs-2-and-3-explode-to-100ms+" pattern we
//!    saw before the fix).
//!
//!    Production proxies serving real traffic *should not* blanket
//!    NOTRACK — conntrack is needed for stateful firewall + outbound
//!    NAT. The lower-overhead production-safe equivalent is a
//!    targeted `iptables -t raw -A PREROUTING -p tcp --dport
//!    <proxy_port> -j NOTRACK` on the proxy box, paired with `-A
//!    OUTPUT -p tcp --sport <proxy_port> -j NOTRACK` for the
//!    upstream-side replies. That removes conntrack on the bench-path
//!    traffic only.
//!
//! 2. **`MI_PURGE_DELAY=-1 MI_ARENA_RESERVE=1073741824`** in the
//!    `lynxx-gateway` process environment. Disables mimalloc's
//!    periodic page-purge pass (the `_mi_page_free_collect` stacks
//!    that produced 5–15 ms p99 spikes in the original Phase 0
//!    capture) and pre-reserves a 1 GB arena so the first allocation
//!    bursts don't fault in 4 K pages. Already set in
//!    `bench/proxy-bench/proxies/lynxx.sh`; for production deploys
//!    they belong in the systemd unit's `Environment=` block.
//!
//! These two changes together (NOTRACK + mimalloc env) are what put
//! lynxx p99 < kong's 4.17 ms reference at 100 k RPS on this rig.

use std::fs;
use std::path::Path;

#[derive(Debug)]
struct SysctlParam {
    key: &'static str,
    value: &'static str,
    description: &'static str,
}

const TUNING_PARAMS: &[SysctlParam] = &[
    // --- File descriptors ---
    SysctlParam {
        key: "fs.file-max",
        value: "2097152",
        description: "system-wide fd limit (2M)",
    },
    SysctlParam {
        key: "fs.nr_open",
        value: "2097152",
        description: "per-process fd ceiling (2M)",
    },
    // --- TCP listen backlog ---
    SysctlParam {
        key: "net.core.somaxconn",
        value: "65535",
        description: "max listen() backlog",
    },
    SysctlParam {
        key: "net.ipv4.tcp_max_syn_backlog",
        value: "65535",
        description: "SYN queue depth",
    },
    // --- Network buffers ---
    SysctlParam {
        key: "net.core.rmem_max",
        value: "16777216",
        description: "max socket receive buffer (16MB)",
    },
    SysctlParam {
        key: "net.core.wmem_max",
        value: "16777216",
        description: "max socket send buffer (16MB)",
    },
    SysctlParam {
        key: "net.core.rmem_default",
        value: "1048576",
        description: "default receive buffer (1MB)",
    },
    SysctlParam {
        key: "net.core.wmem_default",
        value: "1048576",
        description: "default send buffer (1MB)",
    },
    SysctlParam {
        key: "net.ipv4.tcp_rmem",
        value: "4096 1048576 16777216",
        description: "TCP receive buffer (min/default/max)",
    },
    SysctlParam {
        key: "net.ipv4.tcp_wmem",
        value: "4096 1048576 16777216",
        description: "TCP send buffer (min/default/max)",
    },
    // --- Connection reuse / TIME_WAIT ---
    SysctlParam {
        key: "net.ipv4.tcp_tw_reuse",
        value: "1",
        description: "reuse TIME_WAIT sockets for new connections",
    },
    SysctlParam {
        key: "net.ipv4.tcp_fin_timeout",
        value: "15",
        description: "FIN_WAIT2 timeout (default 60 → 15)",
    },
    SysctlParam {
        key: "net.ipv4.tcp_max_tw_buckets",
        value: "2000000",
        description: "max TIME_WAIT sockets (2M)",
    },
    // --- Keepalive ---
    SysctlParam {
        key: "net.ipv4.tcp_keepalive_time",
        value: "60",
        description: "keepalive start (default 7200 → 60s)",
    },
    SysctlParam {
        key: "net.ipv4.tcp_keepalive_intvl",
        value: "10",
        description: "keepalive probe interval",
    },
    SysctlParam {
        key: "net.ipv4.tcp_keepalive_probes",
        value: "6",
        description: "keepalive probes before drop",
    },
    // --- Congestion / performance ---
    SysctlParam {
        key: "net.core.netdev_max_backlog",
        value: "65535",
        description: "NIC rx queue depth",
    },
    SysctlParam {
        key: "net.ipv4.tcp_slow_start_after_idle",
        value: "0",
        description: "disable slow start after idle",
    },
    SysctlParam {
        key: "net.ipv4.tcp_mtu_probing",
        value: "1",
        description: "enable MTU probing for jumbo paths",
    },
    // --- Ephemeral ports ---
    SysctlParam {
        key: "net.ipv4.ip_local_port_range",
        value: "1024 65535",
        description: "expand ephemeral port range",
    },
];

fn read_sysctl(key: &str) -> Option<String> {
    let path = format!("/proc/sys/{}", key.replace('.', "/"));
    fs::read_to_string(&path).ok().map(|s| s.trim().to_string())
}

fn write_sysctl(key: &str, value: &str) -> Result<(), String> {
    let path = format!("/proc/sys/{}", key.replace('.', "/"));
    fs::write(&path, value).map_err(|e| format!("{key}: {e}"))
}

pub fn apply_kernel_tuning() {
    if !Path::new("/proc/sys").exists() {
        tracing::debug!("not linux — skipping kernel tuning");
        return;
    }

    if !can_write_sysctl() {
        tracing::info!("no sysctl write permission — skipping kernel tuning (run as root or use CAP_SYS_ADMIN)");
        return;
    }

    let mut applied = 0u32;
    let mut skipped = 0u32;

    for param in TUNING_PARAMS {
        let current = read_sysctl(param.key);
        if current.as_deref() == Some(param.value) {
            skipped += 1;
            continue;
        }

        match write_sysctl(param.key, param.value) {
            Ok(()) => {
                tracing::debug!(
                    key = param.key,
                    old = current.as_deref().unwrap_or("?"),
                    new = param.value,
                    "kernel tuning applied"
                );
                applied += 1;
            }
            Err(e) => {
                tracing::warn!(key = param.key, error = %e, "kernel tuning failed");
            }
        }
    }

    if applied > 0 {
        tracing::info!(applied, skipped, "kernel tuning complete");
    } else {
        tracing::debug!(skipped, "kernel tuning: all params already optimal");
    }

    raise_fd_limit();
}

fn can_write_sysctl() -> bool {
    let test_path = "/proc/sys/net/core/somaxconn";
    if let Ok(current) = fs::read_to_string(test_path) {
        fs::write(test_path, current.trim()).is_ok()
    } else {
        false
    }
}

const FD_TARGET: u64 = 1_048_576;

fn raise_fd_limit() {
    let target: u64 = FD_TARGET;

    #[cfg(unix)]
    {
        use std::io;

        let mut rlim = libc::rlimit {
            rlim_cur: 0,
            rlim_max: 0,
        };

        if unsafe { libc::getrlimit(libc::RLIMIT_NOFILE, &mut rlim) } != 0 {
            tracing::warn!("getrlimit failed: {}", io::Error::last_os_error());
            return;
        }

        if rlim.rlim_cur >= target {
            tracing::debug!(current = rlim.rlim_cur, "fd limit already sufficient");
            return;
        }

        let new_hard = rlim.rlim_max.max(target);
        let new_rlim = libc::rlimit {
            rlim_cur: target.min(new_hard),
            rlim_max: new_hard,
        };

        if unsafe { libc::setrlimit(libc::RLIMIT_NOFILE, &new_rlim) } == 0 {
            tracing::info!(
                old = rlim.rlim_cur,
                new = new_rlim.rlim_cur,
                "raised fd limit"
            );
        } else {
            let soft_only = libc::rlimit {
                rlim_cur: rlim.rlim_max,
                rlim_max: rlim.rlim_max,
            };
            if unsafe { libc::setrlimit(libc::RLIMIT_NOFILE, &soft_only) } == 0 {
                tracing::info!(
                    old = rlim.rlim_cur,
                    new = soft_only.rlim_cur,
                    "raised fd soft limit to hard limit"
                );
            } else {
                tracing::warn!(current = rlim.rlim_cur, target, "could not raise fd limit");
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tuning_params_have_valid_keys() {
        for param in TUNING_PARAMS {
            assert!(!param.key.is_empty(), "empty sysctl key");
            assert!(
                param.key.contains('.'),
                "sysctl key missing dot separator: {}",
                param.key
            );
            assert!(!param.value.is_empty(), "empty value for {}", param.key);
        }
    }

    #[test]
    fn tuning_params_no_duplicates() {
        let mut seen = std::collections::HashSet::new();
        for param in TUNING_PARAMS {
            assert!(
                seen.insert(param.key),
                "duplicate sysctl key: {}",
                param.key
            );
        }
    }

    #[test]
    fn sysctl_path_mapping() {
        let path = format!("/proc/sys/{}", "net.core.somaxconn".replace('.', "/"));
        assert_eq!(path, "/proc/sys/net/core/somaxconn");

        let path = format!(
            "/proc/sys/{}",
            "net.ipv4.ip_local_port_range".replace('.', "/")
        );
        assert_eq!(path, "/proc/sys/net/ipv4/ip_local_port_range");
    }

    #[test]
    fn fd_target_is_power_of_two() {
        assert!(FD_TARGET.is_power_of_two());
        assert_eq!(FD_TARGET, 1 << 20);
    }

    #[test]
    fn apply_kernel_tuning_noop_on_non_linux() {
        // On macOS (CI / dev), /proc/sys doesn't exist so the function
        // returns immediately without error.
        apply_kernel_tuning();
    }
}
