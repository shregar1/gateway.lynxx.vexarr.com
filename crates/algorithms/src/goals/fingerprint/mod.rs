//! TLS and TCP/IP fingerprinting.

pub mod ja4;

pub use ja4::{Ja4Fingerprint, Ja4Input, TlsVersion, TransportProtocol};
