/// Binary decision tree for combining boolean predicates into rules.
///
/// Each rule maps a path of boolean predicate values to an action.
/// Evaluation walks the tree testing predicates in order and returns
/// the action for the first matching rule.

pub struct MatcherTree {
    rules: Vec<(Vec<bool>, usize)>,
}

impl MatcherTree {
    pub fn new() -> Self {
        Self { rules: Vec::new() }
    }

    /// Add a rule: when predicates match `path`, return `action`.
    /// `path[i]` is the required value of predicate `i`.
    pub fn add_rule(&mut self, path: Vec<bool>, action: usize) {
        self.rules.push((path, action));
    }

    /// Evaluate predicates against all rules. Returns the action of
    /// the first matching rule, or None.
    pub fn evaluate(&self, predicates: &[bool]) -> Option<usize> {
        'outer: for (path, action) in &self.rules {
            if path.len() > predicates.len() {
                continue;
            }
            for (i, &required) in path.iter().enumerate() {
                if predicates[i] != required {
                    continue 'outer;
                }
            }
            return Some(*action);
        }
        None
    }
}

impl Default for MatcherTree {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn single_rule() {
        let mut mt = MatcherTree::new();
        mt.add_rule(vec![true, false], 42);
        assert_eq!(mt.evaluate(&[true, false]), Some(42));
        assert_eq!(mt.evaluate(&[false, false]), None);
    }

    #[test]
    fn first_match_wins() {
        let mut mt = MatcherTree::new();
        mt.add_rule(vec![true], 1);
        mt.add_rule(vec![true, false], 2);
        assert_eq!(mt.evaluate(&[true, false]), Some(1)); // first rule matches
    }

    #[test]
    fn no_match() {
        let mut mt = MatcherTree::new();
        mt.add_rule(vec![true, true, true], 1);
        assert_eq!(mt.evaluate(&[true, true, false]), None);
    }

    #[test]
    fn empty_path() {
        let mut mt = MatcherTree::new();
        mt.add_rule(vec![], 99); // matches everything
        assert_eq!(mt.evaluate(&[true, false]), Some(99));
    }

    #[test]
    fn predicates_shorter_than_path() {
        let mut mt = MatcherTree::new();
        mt.add_rule(vec![true, true, true], 1);
        assert_eq!(mt.evaluate(&[true, true]), None);
    }
}
