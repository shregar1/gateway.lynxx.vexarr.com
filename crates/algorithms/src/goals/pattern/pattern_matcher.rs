/// Pattern matcher supporting prefix, suffix, exact, and glob-like patterns.
///
/// Patterns:
/// - `exact:foo` — exact match
/// - `prefix:foo` or `foo*` — prefix match
/// - `suffix:foo` or `*foo` — suffix match
/// - `contains:foo` — substring match
/// - plain `foo` — treated as exact match

pub struct PatternMatcher {
    patterns: Vec<Pattern>,
}

enum Pattern {
    Exact(String),
    Prefix(String),
    Suffix(String),
    Contains(String),
}

impl PatternMatcher {
    pub fn new() -> Self {
        Self {
            patterns: Vec::new(),
        }
    }

    pub fn add_pattern(&mut self, pat: &str) {
        let pattern = if let Some(rest) = pat.strip_prefix("exact:") {
            Pattern::Exact(rest.to_owned())
        } else if let Some(rest) = pat.strip_prefix("prefix:") {
            Pattern::Prefix(rest.to_owned())
        } else if let Some(rest) = pat.strip_prefix("suffix:") {
            Pattern::Suffix(rest.to_owned())
        } else if let Some(rest) = pat.strip_prefix("contains:") {
            Pattern::Contains(rest.to_owned())
        } else if pat.ends_with('*') && !pat.starts_with('*') {
            Pattern::Prefix(pat[..pat.len() - 1].to_owned())
        } else if pat.starts_with('*') && !pat.ends_with('*') {
            Pattern::Suffix(pat[1..].to_owned())
        } else {
            Pattern::Exact(pat.to_owned())
        };
        self.patterns.push(pattern);
    }

    pub fn matches(&self, input: &str) -> bool {
        for pat in &self.patterns {
            let hit = match pat {
                Pattern::Exact(s) => input == s,
                Pattern::Prefix(s) => input.starts_with(s.as_str()),
                Pattern::Suffix(s) => input.ends_with(s.as_str()),
                Pattern::Contains(s) => input.contains(s.as_str()),
            };
            if hit {
                return true;
            }
        }
        false
    }
}

impl Default for PatternMatcher {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn exact_match() {
        let mut pm = PatternMatcher::new();
        pm.add_pattern("exact:hello");
        assert!(pm.matches("hello"));
        assert!(!pm.matches("hello!"));
    }

    #[test]
    fn prefix_match() {
        let mut pm = PatternMatcher::new();
        pm.add_pattern("/api/*");
        assert!(pm.matches("/api/v1"));
        assert!(pm.matches("/api/"));
        assert!(!pm.matches("/web/"));
    }

    #[test]
    fn suffix_match() {
        let mut pm = PatternMatcher::new();
        pm.add_pattern("*.json");
        assert!(pm.matches("data.json"));
        assert!(!pm.matches("data.xml"));
    }

    #[test]
    fn contains_match() {
        let mut pm = PatternMatcher::new();
        pm.add_pattern("contains:admin");
        assert!(pm.matches("/path/admin/page"));
        assert!(!pm.matches("/path/user/page"));
    }

    #[test]
    fn multi_pattern() {
        let mut pm = PatternMatcher::new();
        pm.add_pattern("/api/*");
        pm.add_pattern("*.html");
        assert!(pm.matches("/api/test"));
        assert!(pm.matches("index.html"));
        assert!(!pm.matches("/web/test.css"));
    }
}
