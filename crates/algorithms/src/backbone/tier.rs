//! Runtime tier enum.
//!
//! Backbone primitives are dispatched by `Tier` at runtime rather than
//! by Cargo feature at compile time, so a single binary can serve every
//! subscription level. The factory constructs the adapter that matches
//! the current tier; non-tier adapters remain compiled but unreachable
//! through the factory entry points (lockdown by selection).

use std::fmt;
use std::str::FromStr;

/// Subscription tier that gates which backbone adapter is selected.
///
/// Variants are ordered by capability: `Starter < Growth < Pro`.
/// Higher tiers receive the more expensive / more advanced algorithm
/// for each backbone primitive.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Tier {
    /// Base algorithms — leaky-bucket, murmur2, CRC32 short-nibble, etc.
    Starter,
    /// Smarter algorithms — token bucket, SipHash-1-3, CRC32 long-table, Huffman.
    Growth,
    /// Highest-performance algorithms — gradient, XXH64, CRC32 slice-8, congestion control.
    Pro,
}

impl Tier {
    /// Stable lowercase identifier, suitable for log lines and admin APIs.
    pub fn as_str(self) -> &'static str {
        match self {
            Tier::Starter => "starter",
            Tier::Growth => "growth",
            Tier::Pro => "pro",
        }
    }

    /// Returns `true` if `self` is at least as capable as `min`.
    pub fn at_least(self, min: Tier) -> bool {
        self >= min
    }
}

impl Default for Tier {
    /// Safe fallback when no tier has been resolved yet.
    fn default() -> Self {
        Tier::Starter
    }
}

impl fmt::Display for Tier {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl FromStr for Tier {
    type Err = UnknownTier;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_ascii_lowercase().as_str() {
            "starter" => Ok(Tier::Starter),
            "growth" => Ok(Tier::Growth),
            "pro" => Ok(Tier::Pro),
            other => Err(UnknownTier(other.to_owned())),
        }
    }
}

#[derive(Debug)]
pub struct UnknownTier(pub String);

impl fmt::Display for UnknownTier {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "unknown tier: {}", self.0)
    }
}

impl std::error::Error for UnknownTier {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ordering_is_starter_growth_pro() {
        assert!(Tier::Starter < Tier::Growth);
        assert!(Tier::Growth < Tier::Pro);
    }

    #[test]
    fn at_least_is_inclusive() {
        assert!(Tier::Pro.at_least(Tier::Growth));
        assert!(Tier::Growth.at_least(Tier::Growth));
        assert!(!Tier::Starter.at_least(Tier::Growth));
    }

    #[test]
    fn as_str_roundtrips() {
        for t in [Tier::Starter, Tier::Growth, Tier::Pro] {
            assert_eq!(t.as_str().parse::<Tier>().unwrap(), t);
        }
    }

    #[test]
    fn from_str_is_case_insensitive() {
        assert_eq!("STARTER".parse::<Tier>().unwrap(), Tier::Starter);
        assert_eq!("Growth".parse::<Tier>().unwrap(), Tier::Growth);
    }

    #[test]
    fn from_str_rejects_unknown() {
        assert!("enterprise".parse::<Tier>().is_err());
    }

    #[test]
    fn default_is_starter() {
        assert_eq!(Tier::default(), Tier::Starter);
    }
}
