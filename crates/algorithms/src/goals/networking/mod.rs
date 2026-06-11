pub mod sni_check;
pub mod cname_flatten;
pub mod domain_dedup;
pub mod cert_selection;
pub mod sni_index;

pub use sni_check::{sni_matches, check_domain_fronting};
pub use cname_flatten::CnameChain;
pub use domain_dedup::dedup_domains;
pub use cert_selection::{CertCandidate, KeyType, select_cert};
pub use sni_index::SniIndex;
