//! Service-discovery providers.
//!
//! Out of the box Lynxx loads services + routes from `config.toml` and
//! its admin API. Providers extend that with *external* sources of
//! truth that the gateway watches and reconciles into its own
//! repository — same shape Traefik uses (`providers.docker`,
//! `providers.kubernetes`, etc.).
//!
//! Today only the Docker provider is implemented. Each provider:
//!
//! 1. Builds a fresh snapshot of `(services, routes)` from its source
//!    (Docker labels, K8s annotations, etc.).
//! 2. Diffs against the existing repository state.
//! 3. Calls the repository's CRUD methods to converge.
//! 4. Watches for change events and repeats.
//!
//! Provider-managed entities are tagged via the service `name` prefix
//! (`docker:my-app` etc.) so they're recognisable in the admin UI and
//! distinguishable from operator-created entries.

pub mod consul;
pub mod docker;
pub mod docker_swarm;
pub mod ecs;
pub mod etcd;
pub mod http_provider;
pub mod nomad;
pub mod redis_kv;
pub mod srv_dns;
pub mod zookeeper;

use std::net::IpAddr;

/// Reject a discovered upstream URL that could be used for SSRF or to reach
/// the gateway host itself.
///
/// Discovery sources are external and, in KV/catalog modes, attacker-
/// influenceable — a registered service could carry `url = file:///etc/passwd`
/// or `http://169.254.169.254/...` (cloud metadata) and the gateway would
/// happily proxy to it. We therefore require a discovered target to be a plain
/// `http`/`https` URL whose host is NOT loopback, link-local (which includes
/// the `169.254.169.254` metadata endpoint), unspecified, or a known
/// host-local name.
///
/// Private/RFC-1918 addresses are deliberately ALLOWED: legitimate service-
/// mesh upstreams (Consul/Nomad/K8s) live on `10/8`, `172.16/12`, `192.168/16`.
pub fn is_safe_upstream_url(url: &str) -> bool {
    let parsed = match url::Url::parse(url) {
        Ok(u) => u,
        Err(_) => return false,
    };
    if !matches!(parsed.scheme(), "http" | "https") {
        return false;
    }
    match parsed.host() {
        Some(url::Host::Ipv4(ip)) => is_safe_ip(IpAddr::V4(ip)),
        Some(url::Host::Ipv6(ip)) => is_safe_ip(IpAddr::V6(ip)),
        Some(url::Host::Domain(d)) => {
            let d = d.to_ascii_lowercase();
            if d.is_empty()
                || d == "localhost"
                || d.ends_with(".localhost")
                || d == "metadata.google.internal"
                || d == "metadata"
            {
                return false;
            }
            // A domain that is actually a literal IP gets the IP checks.
            match d.parse::<IpAddr>() {
                Ok(ip) => is_safe_ip(ip),
                Err(_) => true,
            }
        }
        None => false,
    }
}

fn is_safe_ip(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => {
            // `is_link_local` covers 169.254.0.0/16 incl. the metadata IP.
            !(v4.is_loopback() || v4.is_link_local() || v4.is_unspecified())
        }
        IpAddr::V6(v6) => {
            let link_local = (v6.segments()[0] & 0xffc0) == 0xfe80;
            !(v6.is_loopback() || v6.is_unspecified() || link_local)
        }
    }
}

#[cfg(test)]
mod ssrf_tests {
    use super::is_safe_upstream_url;

    #[test]
    fn rejects_non_http_schemes() {
        assert!(!is_safe_upstream_url("file:///etc/passwd"));
        assert!(!is_safe_upstream_url("unix:///var/run/docker.sock"));
        assert!(!is_safe_upstream_url("gopher://evil/"));
    }

    #[test]
    fn rejects_loopback_and_metadata() {
        assert!(!is_safe_upstream_url("http://127.0.0.1:9000/"));
        assert!(!is_safe_upstream_url("http://localhost:8080/"));
        assert!(!is_safe_upstream_url("http://169.254.169.254/latest/meta-data/"));
        assert!(!is_safe_upstream_url("http://metadata.google.internal/"));
        assert!(!is_safe_upstream_url("http://[::1]:80/"));
    }

    #[test]
    fn allows_normal_and_mesh_upstreams() {
        assert!(is_safe_upstream_url("http://10.0.3.7:8080/"));
        assert!(is_safe_upstream_url("http://192.168.1.20:3000/"));
        assert!(is_safe_upstream_url("https://api.internal.example.com/"));
        assert!(is_safe_upstream_url("http://upstream-svc:8000/"));
    }

    #[test]
    fn rejects_garbage() {
        assert!(!is_safe_upstream_url("not a url"));
        assert!(!is_safe_upstream_url(""));
    }
}
