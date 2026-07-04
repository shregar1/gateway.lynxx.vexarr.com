//! Crypto — nginx-origin password hashing algorithms.
//!
//! Implements the password verification schemes that nginx (and the broader
//! Apache/htpasswd ecosystem it interoperates with) relies on for HTTP basic
//! authentication and LDAP-style credential stores:
//!
//! - **APR1** (`$apr1$`): Apache's iterated-MD5 crypt scheme used in
//!   `htpasswd` files.
//! - **plain**: constant-time plaintext password comparison.
//! - **SHA / SSHA** (`{SHA}` / `{SSHA}`): LDAP base64-SHA1 schemes, with and
//!   without a salt.
//!
//! The underlying MD5 (RFC 1321) and SHA-1 (RFC 3174) primitives are
//! implemented from scratch in pure Rust — this crate carries no external
//! crypto dependencies.

pub mod md5;
pub mod sha1;

pub mod apr1;
pub mod plain_check;
pub mod sha_ssha;

pub use apr1::{apr1_hash, apr1_verify};
pub use plain_check::plain_check;
pub use sha_ssha::{sha_hash, sha_verify, ssha_hash};
