//! TLS and TCP/IP fingerprinting.

pub mod ja4;
pub mod os_fingerprint;

pub use ja4::{Ja4Fingerprint, Ja4Input, TlsVersion, TransportProtocol};
