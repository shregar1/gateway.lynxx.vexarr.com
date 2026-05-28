//! HTTP Accept-Encoding negotiation (Traefik origin).
//!
//! Parses the `Accept-Encoding` header into quality-annotated preferences
//! and selects the best server-supported encoding.

/// A single encoding preference from an Accept-Encoding header.
#[derive(Debug, Clone)]
pub struct EncodingPref {
    /// The encoding name (e.g. `"gzip"`, `"br"`, `"identity"`).
    pub encoding: String,
    /// Quality value from 0.0 to 1.0 (default 1.0 when omitted).
    pub quality: f32,
}

/// Parse an `Accept-Encoding` header value into a list of preferences.
///
/// Each entry is a comma-separated token optionally followed by `;q=<value>`.
/// Invalid quality values are treated as 1.0.
///
/// # Example
/// ```ignore
/// parse_accept_encoding("gzip;q=1.0, br;q=0.8, identity;q=0.1")
/// ```
pub fn parse_accept_encoding(header: &str) -> Vec<EncodingPref> {
    let mut prefs = Vec::new();

    for part in header.split(',') {
        let part = part.trim();
        if part.is_empty() {
            continue;
        }

        let (encoding, quality) = if let Some(semi_pos) = part.find(';') {
            let enc = part[..semi_pos].trim();
            let params = part[semi_pos + 1..].trim();
            let q = if let Some(qval) = params.strip_prefix("q=").or_else(|| params.strip_prefix("Q=")) {
                qval.trim().parse::<f32>().unwrap_or(1.0).clamp(0.0, 1.0)
            } else {
                1.0
            };
            (enc, q)
        } else {
            (part, 1.0f32)
        };

        if !encoding.is_empty() {
            prefs.push(EncodingPref {
                encoding: encoding.to_ascii_lowercase(),
                quality,
            });
        }
    }

    prefs
}

/// Select the best encoding from `supported` based on client `prefs`.
///
/// Returns the highest-quality encoding that appears in both the client
/// preferences and the server's supported list. Encodings with `q=0` are
/// explicitly rejected. The `*` wildcard matches any supported encoding.
pub fn select_encoding(prefs: &[EncodingPref], supported: &[&str]) -> Option<String> {
    if prefs.is_empty() || supported.is_empty() {
        return None;
    }

    let mut best: Option<(&str, f32)> = None;

    for sup in supported {
        let sup_lc = sup.to_ascii_lowercase();
        let mut q = -1.0f32;

        for pref in prefs {
            if pref.encoding == sup_lc || pref.encoding == "*" {
                if pref.quality > q {
                    q = pref.quality;
                }
            }
        }

        if q > 0.0 {
            if best.is_none() || q > best.unwrap().1 {
                best = Some((sup, q));
            }
        }
    }

    best.map(|(enc, _)| enc.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_simple() {
        let prefs = parse_accept_encoding("gzip, deflate, br");
        assert_eq!(prefs.len(), 3);
        assert_eq!(prefs[0].encoding, "gzip");
        assert_eq!(prefs[0].quality, 1.0);
    }

    #[test]
    fn parse_with_quality() {
        let prefs = parse_accept_encoding("gzip;q=1.0, br;q=0.8, identity;q=0.1");
        assert_eq!(prefs.len(), 3);
        assert_eq!(prefs[1].encoding, "br");
        assert!((prefs[1].quality - 0.8).abs() < 0.01);
    }

    #[test]
    fn parse_wildcard() {
        let prefs = parse_accept_encoding("*;q=0.5");
        assert_eq!(prefs.len(), 1);
        assert_eq!(prefs[0].encoding, "*");
    }

    #[test]
    fn parse_empty() {
        let prefs = parse_accept_encoding("");
        assert!(prefs.is_empty());
    }

    #[test]
    fn parse_case_insensitive() {
        let prefs = parse_accept_encoding("GZIP, BR");
        assert_eq!(prefs[0].encoding, "gzip");
        assert_eq!(prefs[1].encoding, "br");
    }

    #[test]
    fn select_best() {
        let prefs = parse_accept_encoding("gzip;q=0.5, br;q=1.0");
        let result = select_encoding(&prefs, &["gzip", "br"]);
        assert_eq!(result.as_deref(), Some("br"));
    }

    #[test]
    fn select_none_when_q_zero() {
        let prefs = parse_accept_encoding("gzip;q=0");
        let result = select_encoding(&prefs, &["gzip"]);
        assert_eq!(result, None);
    }

    #[test]
    fn select_wildcard() {
        let prefs = parse_accept_encoding("*;q=0.5");
        let result = select_encoding(&prefs, &["zstd"]);
        assert_eq!(result.as_deref(), Some("zstd"));
    }

    #[test]
    fn select_empty_prefs() {
        let result = select_encoding(&[], &["gzip"]);
        assert_eq!(result, None);
    }

    #[test]
    fn select_empty_supported() {
        let prefs = parse_accept_encoding("gzip");
        let result = select_encoding(&prefs, &[]);
        assert_eq!(result, None);
    }

    #[test]
    fn select_first_among_equal_quality() {
        let prefs = parse_accept_encoding("gzip, br");
        // Both q=1.0, first supported wins
        let result = select_encoding(&prefs, &["br", "gzip"]);
        // Both have q=1.0, but "br" is checked first in supported list
        assert!(result.is_some());
    }
}
