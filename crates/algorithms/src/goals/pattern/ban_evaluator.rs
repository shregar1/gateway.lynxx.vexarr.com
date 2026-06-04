/// Varnish-style predicate-based cache invalidation ("bans").
///
/// A ban is a conjunction of predicates evaluated against an object's
/// metadata. An object is invalidated if ANY ban in the list matches
/// (disjunction across bans, conjunction within a ban).

/// Comparison operator for a single predicate.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BanOp {
    Eq,
    Neq,
    Match,
    NoMatch,
    GreaterThan,
    LessThan,
}

/// A single predicate: `field <op> value`.
#[derive(Debug, Clone)]
pub struct BanPredicate {
    pub field: String,
    pub op: BanOp,
    pub value: String,
}

impl BanPredicate {
    /// Evaluate this predicate against an object looked up via `obj`.
    /// A missing field yields false (the predicate cannot hold).
    fn matches(&self, obj: &dyn Fn(&str) -> Option<String>) -> bool {
        let actual = match obj(&self.field) {
            Some(v) => v,
            None => return false,
        };

        match self.op {
            BanOp::Eq => actual == self.value,
            BanOp::Neq => actual != self.value,
            BanOp::Match => actual.contains(&self.value),
            BanOp::NoMatch => !actual.contains(&self.value),
            BanOp::GreaterThan => match (actual.parse::<i64>(), self.value.parse::<i64>()) {
                (Ok(a), Ok(b)) => a > b,
                _ => false,
            },
            BanOp::LessThan => match (actual.parse::<i64>(), self.value.parse::<i64>()) {
                (Ok(a), Ok(b)) => a < b,
                _ => false,
            },
        }
    }
}

/// A conjunction of predicates. ALL predicates must match for the ban
/// to apply.
#[derive(Debug, Clone)]
pub struct Ban {
    pub predicates: Vec<BanPredicate>,
}

impl Ban {
    pub fn new() -> Self {
        Self {
            predicates: Vec::new(),
        }
    }

    /// Append a predicate to this ban's conjunction.
    pub fn add(&mut self, field: &str, op: BanOp, value: &str) {
        self.predicates.push(BanPredicate {
            field: field.to_string(),
            op,
            value: value.to_string(),
        });
    }

    /// Evaluate all predicates against an object. Returns true only if
    /// EVERY predicate matches (conjunction). An empty ban matches.
    pub fn matches(&self, obj: &dyn Fn(&str) -> Option<String>) -> bool {
        self.predicates.iter().all(|p| p.matches(obj))
    }
}

impl Default for Ban {
    fn default() -> Self {
        Self::new()
    }
}

/// An ordered list of bans. An object is banned if ANY ban matches.
#[derive(Debug, Clone)]
pub struct BanList {
    bans: Vec<Ban>,
}

impl BanList {
    pub fn new() -> Self {
        Self { bans: Vec::new() }
    }

    pub fn add_ban(&mut self, ban: Ban) {
        self.bans.push(ban);
    }

    /// True if ANY ban matches the object (disjunction across bans).
    pub fn is_banned(&self, obj: &dyn Fn(&str) -> Option<String>) -> bool {
        self.bans.iter().any(|ban| ban.matches(obj))
    }

    pub fn len(&self) -> usize {
        self.bans.len()
    }

    pub fn is_empty(&self) -> bool {
        self.bans.is_empty()
    }
}

impl Default for BanList {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Build a lookup closure from a fixed set of field/value pairs.
    fn obj_from<'a>(pairs: &'a [(&'a str, &'a str)]) -> impl Fn(&str) -> Option<String> + 'a {
        move |field: &str| {
            pairs
                .iter()
                .find(|(k, _)| *k == field)
                .map(|(_, v)| v.to_string())
        }
    }

    #[test]
    fn single_predicate_eq() {
        let obj = obj_from(&[("req.url", "/index.html")]);
        let mut ban = Ban::new();
        ban.add("req.url", BanOp::Eq, "/index.html");
        assert!(ban.matches(&obj));
    }

    #[test]
    fn single_predicate_no_match() {
        let obj = obj_from(&[("req.url", "/index.html")]);
        let mut ban = Ban::new();
        ban.add("req.url", BanOp::Eq, "/other.html");
        assert!(!ban.matches(&obj));
    }

    #[test]
    fn missing_field_is_false() {
        let obj = obj_from(&[("req.url", "/index.html")]);
        let mut ban = Ban::new();
        ban.add("req.host", BanOp::Eq, "example.com");
        assert!(!ban.matches(&obj));
    }

    #[test]
    fn multi_predicate_conjunction_all_hold() {
        let obj = obj_from(&[("req.url", "/api/v1/users"), ("req.host", "example.com")]);
        let mut ban = Ban::new();
        ban.add("req.url", BanOp::Match, "/api/");
        ban.add("req.host", BanOp::Eq, "example.com");
        assert!(ban.matches(&obj));
    }

    #[test]
    fn multi_predicate_conjunction_one_fails() {
        let obj = obj_from(&[("req.url", "/api/v1/users"), ("req.host", "example.com")]);
        let mut ban = Ban::new();
        ban.add("req.url", BanOp::Match, "/api/");
        ban.add("req.host", BanOp::Eq, "other.com");
        assert!(!ban.matches(&obj));
    }

    #[test]
    fn banlist_disjunction_any_triggers() {
        let obj = obj_from(&[("req.url", "/images/logo.png")]);

        let mut ban_a = Ban::new();
        ban_a.add("req.url", BanOp::Match, "/css/");

        let mut ban_b = Ban::new();
        ban_b.add("req.url", BanOp::Match, "/images/");

        let mut list = BanList::new();
        list.add_ban(ban_a);
        list.add_ban(ban_b);

        assert_eq!(list.len(), 2);
        assert!(!list.is_empty());
        assert!(list.is_banned(&obj));
    }

    #[test]
    fn banlist_no_ban_matches() {
        let obj = obj_from(&[("req.url", "/index.html")]);

        let mut ban_a = Ban::new();
        ban_a.add("req.url", BanOp::Match, "/css/");

        let mut list = BanList::new();
        list.add_ban(ban_a);

        assert!(!list.is_banned(&obj));
    }

    #[test]
    fn empty_banlist_never_bans() {
        let obj = obj_from(&[("req.url", "/index.html")]);
        let list = BanList::new();
        assert!(list.is_empty());
        assert_eq!(list.len(), 0);
        assert!(!list.is_banned(&obj));
    }

    #[test]
    fn substring_match_and_nomatch() {
        let obj = obj_from(&[("obj.http.content-type", "text/html; charset=utf-8")]);

        let mut m = Ban::new();
        m.add("obj.http.content-type", BanOp::Match, "text/html");
        assert!(m.matches(&obj));

        let mut nm = Ban::new();
        nm.add("obj.http.content-type", BanOp::NoMatch, "application/json");
        assert!(nm.matches(&obj));

        let mut nm2 = Ban::new();
        nm2.add("obj.http.content-type", BanOp::NoMatch, "text/html");
        assert!(!nm2.matches(&obj));
    }

    #[test]
    fn neq_operator() {
        let obj = obj_from(&[("req.method", "GET")]);
        let mut ban = Ban::new();
        ban.add("req.method", BanOp::Neq, "POST");
        assert!(ban.matches(&obj));
    }

    #[test]
    fn numeric_greater_than() {
        let obj = obj_from(&[("obj.age", "120")]);

        let mut gt = Ban::new();
        gt.add("obj.age", BanOp::GreaterThan, "60");
        assert!(gt.matches(&obj));

        let mut gt_fail = Ban::new();
        gt_fail.add("obj.age", BanOp::GreaterThan, "200");
        assert!(!gt_fail.matches(&obj));
    }

    #[test]
    fn numeric_less_than() {
        let obj = obj_from(&[("obj.age", "30")]);

        let mut lt = Ban::new();
        lt.add("obj.age", BanOp::LessThan, "60");
        assert!(lt.matches(&obj));

        let mut lt_fail = Ban::new();
        lt_fail.add("obj.age", BanOp::LessThan, "10");
        assert!(!lt_fail.matches(&obj));
    }

    #[test]
    fn numeric_unparseable_is_false() {
        let obj = obj_from(&[("obj.age", "not-a-number")]);
        let mut gt = Ban::new();
        gt.add("obj.age", BanOp::GreaterThan, "60");
        assert!(!gt.matches(&obj));
    }
}
