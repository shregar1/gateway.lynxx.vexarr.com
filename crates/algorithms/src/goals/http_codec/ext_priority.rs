/// RFC 9218 Extensible Priorities for HTTP.
///
/// Parses, serializes, and compares the structured-field based priority
/// scheme: `u=<urgency>, i` where urgency is 0-7 (lower = more urgent)
/// and `i` indicates incremental delivery.
use std::cmp::Ordering;

/// An extensible priority value per RFC 9218.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ExtPriority {
    /// Urgency level 0-7.  Lower means more urgent.  Default is 3.
    pub urgency: u8,
    /// Whether incremental delivery is requested.  Default is false.
    pub incremental: bool,
}

impl Default for ExtPriority {
    fn default() -> Self {
        Self {
            urgency: 3,
            incremental: false,
        }
    }
}

/// Parse a priority header value in the `"u=X, i"` format.
///
/// Tolerates extra whitespace and unknown parameters (per structured-fields
/// forward-compat rules).  Returns the default priority on parse failure.
pub fn parse_priority(header: &str) -> ExtPriority {
    let mut urgency: u8 = 3;
    let mut incremental = false;

    for param in header.split(',') {
        let param = param.trim();
        if let Some(rest) = param.strip_prefix("u=") {
            if let Ok(u) = rest.trim().parse::<u8>() {
                if u <= 7 {
                    urgency = u;
                }
            }
        } else if param == "i" || param == "i=?1" {
            incremental = true;
        } else if param == "i=?0" {
            incremental = false;
        }
    }

    ExtPriority {
        urgency,
        incremental,
    }
}

/// Serialize a priority into the `"u=X"` or `"u=X, i"` format.
pub fn serialize_priority(p: &ExtPriority) -> String {
    if p.incremental {
        format!("u={}, i", p.urgency)
    } else {
        format!("u={}", p.urgency)
    }
}

/// Compare two priorities.  Lower urgency number means higher priority
/// (i.e., `Less` in the ordering).  When urgencies are equal,
/// non-incremental streams come first (they are more latency-sensitive).
pub fn compare_priority(a: &ExtPriority, b: &ExtPriority) -> Ordering {
    match a.urgency.cmp(&b.urgency) {
        Ordering::Equal => {
            // Non-incremental (false) < incremental (true): non-incremental first.
            a.incremental.cmp(&b.incremental)
        }
        other => other,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_urgency_only() {
        let p = parse_priority("u=5");
        assert_eq!(p.urgency, 5);
        assert!(!p.incremental);
    }

    #[test]
    fn test_parse_urgency_and_incremental() {
        let p = parse_priority("u=2, i");
        assert_eq!(p.urgency, 2);
        assert!(p.incremental);
    }

    #[test]
    fn test_parse_defaults() {
        let p = parse_priority("");
        assert_eq!(p.urgency, 3);
        assert!(!p.incremental);
    }

    #[test]
    fn test_parse_clamps() {
        let p = parse_priority("u=99");
        // Out-of-range; fall back to default.
        assert_eq!(p.urgency, 3);
    }

    #[test]
    fn test_parse_bool_form() {
        let p = parse_priority("u=0, i=?1");
        assert_eq!(p.urgency, 0);
        assert!(p.incremental);
    }

    #[test]
    fn test_parse_unknown_params() {
        let p = parse_priority("u=1, i, x=42");
        assert_eq!(p.urgency, 1);
        assert!(p.incremental);
    }

    #[test]
    fn test_serialize_no_incremental() {
        let p = ExtPriority { urgency: 3, incremental: false };
        assert_eq!(serialize_priority(&p), "u=3");
    }

    #[test]
    fn test_serialize_incremental() {
        let p = ExtPriority { urgency: 0, incremental: true };
        assert_eq!(serialize_priority(&p), "u=0, i");
    }

    #[test]
    fn test_roundtrip() {
        let p = ExtPriority { urgency: 7, incremental: true };
        let s = serialize_priority(&p);
        let p2 = parse_priority(&s);
        assert_eq!(p, p2);
    }

    #[test]
    fn test_compare_different_urgency() {
        let a = ExtPriority { urgency: 1, incremental: false };
        let b = ExtPriority { urgency: 5, incremental: false };
        assert_eq!(compare_priority(&a, &b), Ordering::Less);
    }

    #[test]
    fn test_compare_same_urgency_incremental() {
        let a = ExtPriority { urgency: 3, incremental: false };
        let b = ExtPriority { urgency: 3, incremental: true };
        // Non-incremental comes first.
        assert_eq!(compare_priority(&a, &b), Ordering::Less);
    }

    #[test]
    fn test_compare_equal() {
        let a = ExtPriority { urgency: 3, incremental: true };
        let b = ExtPriority { urgency: 3, incremental: true };
        assert_eq!(compare_priority(&a, &b), Ordering::Equal);
    }
}
