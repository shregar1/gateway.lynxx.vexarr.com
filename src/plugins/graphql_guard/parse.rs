//! AST walks: depth, alias count, complexity score, operation summary.
//!
//! Named-fragment spreads ARE resolved: the walk chases each `...Frag`
//! into its definition and scores/measures its selection set inline at the
//! spread site. Without this, depth and complexity limits are trivially
//! bypassed by hiding an expensive or deeply-nested selection inside a
//! fragment (the spread itself looks like a single cheap field). Fragment
//! cycles — which are spec-invalid but can be crafted by an attacker to blow
//! the stack — are broken via a per-path "visiting" set.

use std::collections::{HashMap, HashSet};

use graphql_parser::query::{Definition, Document, OperationDefinition, Selection, SelectionSet};

use super::config::GraphqlGuardConfig;

/// Argument names that, when present on a field, multiply that field's
/// subtree cost by the integer value (capped at 100). These are the
/// near-universal pagination conventions in GraphQL APIs.
const PAGINATION_ARGS: &[&str] = &["first", "limit", "last"];
const LIST_MULTIPLIER_CAP: u64 = 100;

#[derive(Debug, Default)]
pub struct QuerySummary {
    pub depth: usize,
    pub aliases: usize,
    pub complexity: u64,
    pub operation_name: Option<String>,
    pub operation_type: &'static str,
    pub root_field_names: HashSet<String>,
    pub all_field_names: HashSet<String>,
}

/// Parse `query` and walk the AST. Returns `None` on parse failure (the
/// caller is responsible for the GRAPHQL_PARSE_FAILED short-circuit) so the
/// parse error message can be relayed to the client.
pub fn analyze<'q>(
    query: &'q str,
    cfg: &GraphqlGuardConfig,
    operation_name_hint: Option<&str>,
) -> Result<QuerySummary, String> {
    let doc: Document<'q, String> =
        graphql_parser::parse_query::<String>(query).map_err(|e| e.to_string())?;

    // Named fragments, resolved during the walk so spreads are scored and
    // measured as if expanded inline.
    let fragments: HashMap<String, &SelectionSet<'q, String>> = doc
        .definitions
        .iter()
        .filter_map(|d| {
            if let Definition::Fragment(f) = d {
                Some((f.name.clone(), &f.selection_set))
            } else {
                None
            }
        })
        .collect();

    // Pick the operation. If multiple operations are defined, prefer the one
    // matching `operation_name_hint`; otherwise the first operation wins.
    let mut chosen: Option<(&OperationDefinition<'q, String>, &'static str)> = None;
    for def in &doc.definitions {
        if let Definition::Operation(op) = def {
            let name = match op {
                OperationDefinition::Query(q) => q.name.as_deref(),
                OperationDefinition::Mutation(m) => m.name.as_deref(),
                OperationDefinition::Subscription(s) => s.name.as_deref(),
                OperationDefinition::SelectionSet(_) => None,
            };
            let kind = match op {
                OperationDefinition::Query(_) | OperationDefinition::SelectionSet(_) => "query",
                OperationDefinition::Mutation(_) => "mutation",
                OperationDefinition::Subscription(_) => "subscription",
            };
            if let Some(hint) = operation_name_hint {
                if name == Some(hint) {
                    chosen = Some((op, kind));
                    break;
                }
            }
            if chosen.is_none() {
                chosen = Some((op, kind));
            }
        }
    }

    let Some((op, op_type)) = chosen else {
        return Err("document has no operation definitions".into());
    };

    let (selection_set, op_name) = match op {
        OperationDefinition::SelectionSet(s) => (s, None),
        OperationDefinition::Query(q) => (&q.selection_set, q.name.clone()),
        OperationDefinition::Mutation(m) => (&m.selection_set, m.name.clone()),
        OperationDefinition::Subscription(s) => (&s.selection_set, s.name.clone()),
    };

    let mut summary = QuerySummary {
        operation_name: op_name,
        operation_type: op_type,
        ..Default::default()
    };

    // Root fields, used by introspection block (only flags `__schema` /
    // `__type` at the top level — selecting `__typename` is a normal field
    // and stays allowed).
    for sel in &selection_set.items {
        if let Selection::Field(f) = sel {
            summary.root_field_names.insert(f.name.clone());
        }
    }

    // The walk computes max depth, alias count, total complexity, and a
    // global set of every field referenced (used by per-field rate limits).
    let mut visiting: HashSet<String> = HashSet::new();
    let depth = walk(selection_set, cfg, 1, &mut summary, &fragments, &mut visiting);
    summary.depth = depth;

    Ok(summary)
}

/// Recursive AST descent. Returns the deepest selection level reached under
/// this set, expressed as 1-based "this set counts as depth 1; nested set
/// counts as 2; ...". The complexity for the subtree is added into
/// `summary.complexity`; alias and field-name collection happen along the
/// way.
fn walk<'q>(
    set: &SelectionSet<'q, String>,
    cfg: &GraphqlGuardConfig,
    depth: usize,
    summary: &mut QuerySummary,
    fragments: &HashMap<String, &SelectionSet<'q, String>>,
    visiting: &mut HashSet<String>,
) -> usize {
    let mut max_depth = depth;

    for sel in &set.items {
        match sel {
            Selection::Field(field) => {
                summary.all_field_names.insert(field.name.clone());
                if field.alias.is_some() {
                    summary.aliases = summary.aliases.saturating_add(1);
                }
                let own_cost = cfg
                    .field_costs
                    .get(field.name.as_str())
                    .copied()
                    .unwrap_or(cfg.default_field_cost);

                // Capture the cost of the subtree before applying any list
                // multiplier — the multiplier scales the entire cost of
                // selecting this field N times over.
                let mut sub_summary = QuerySummary::default();
                let sub_depth = if field.selection_set.items.is_empty() {
                    depth
                } else {
                    walk(
                        &field.selection_set,
                        cfg,
                        depth + 1,
                        &mut sub_summary,
                        fragments,
                        visiting,
                    )
                };
                if sub_depth > max_depth {
                    max_depth = sub_depth;
                }

                // Merge nested data into the parent summary.
                summary.aliases = summary.aliases.saturating_add(sub_summary.aliases);
                for n in sub_summary.all_field_names {
                    summary.all_field_names.insert(n);
                }

                // Compute multiplier: the largest pagination-ish argument.
                let multiplier = list_multiplier(&field.arguments);
                let leaf_cost = own_cost.saturating_add(sub_summary.complexity);
                let scaled = leaf_cost.saturating_mul(multiplier);
                summary.complexity = summary.complexity.saturating_add(scaled);
            }
            Selection::InlineFragment(frag) => {
                let sub_depth =
                    walk(&frag.selection_set, cfg, depth, summary, fragments, visiting);
                if sub_depth > max_depth {
                    max_depth = sub_depth;
                }
            }
            Selection::FragmentSpread(spread) => {
                // Resolve the named fragment and score its selection set
                // inline at the spread site (same depth, like an inline
                // fragment). This is what stops depth/complexity limits from
                // being bypassed by hiding the payload in a fragment.
                let name = &spread.fragment_name;
                if visiting.contains(name) {
                    // Fragment cycle (spec-invalid). Stop descending to avoid
                    // unbounded recursion; charge a token cost and move on.
                    summary.complexity =
                        summary.complexity.saturating_add(cfg.default_field_cost);
                    continue;
                }
                if let Some(frag_set) = fragments.get(name) {
                    visiting.insert(name.clone());
                    let sub_depth = walk(frag_set, cfg, depth, summary, fragments, visiting);
                    visiting.remove(name);
                    if sub_depth > max_depth {
                        max_depth = sub_depth;
                    }
                } else {
                    // Spread of an undefined fragment — charge default cost.
                    summary.complexity =
                        summary.complexity.saturating_add(cfg.default_field_cost);
                }
            }
        }
    }

    max_depth
}

fn list_multiplier(args: &[(String, graphql_parser::query::Value<'_, String>)]) -> u64 {
    use graphql_parser::query::Value;
    let mut mul: u64 = 1;
    for (name, val) in args {
        if !PAGINATION_ARGS.iter().any(|p| name == p) {
            continue;
        }
        let n = match val {
            Value::Int(i) => i.as_i64().and_then(|v| u64::try_from(v).ok()),
            _ => None,
        };
        if let Some(n) = n {
            let capped = n.min(LIST_MULTIPLIER_CAP).max(1);
            if capped > mul {
                mul = capped;
            }
        }
    }
    mul
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cfg() -> GraphqlGuardConfig {
        GraphqlGuardConfig {
            field_costs: [("posts".to_string(), 3u64), ("users".to_string(), 5)]
                .into_iter()
                .collect(),
            default_field_cost: 1,
            ..Default::default()
        }
    }

    #[test]
    fn depth_counts_nested_sets() {
        let s = analyze("{ a { b { c { d } } } }", &cfg(), None).unwrap();
        // {a} -> 1, {b} -> 2, {c} -> 3, {d} -> 4
        assert_eq!(s.depth, 4);
    }

    #[test]
    fn aliases_counted() {
        let s = analyze("{ a: x b: x c: x }", &cfg(), None).unwrap();
        assert_eq!(s.aliases, 3);
    }

    #[test]
    fn complexity_uses_field_costs() {
        let s = analyze("{ users { id } posts { id } }", &cfg(), None).unwrap();
        // users(5) + id(1) + posts(3) + id(1) = 10
        assert_eq!(s.complexity, 10);
    }

    #[test]
    fn list_multiplier_scales_subtree() {
        let s = analyze("{ posts(first: 50) { id title } }", &cfg(), None).unwrap();
        // (posts=3 + id=1 + title=1) * 50 = 250
        assert_eq!(s.complexity, 250);
    }

    #[test]
    fn list_multiplier_capped_at_100() {
        let s = analyze("{ posts(first: 1000) { id } }", &cfg(), None).unwrap();
        assert_eq!(s.complexity, (3 + 1) * 100);
    }

    #[test]
    fn fragment_spread_depth_is_counted() {
        // Without fragment resolution this query looks shallow (depth ~2);
        // expanding `F` must reveal the true nesting.
        let q = "{ a { ...F } } fragment F on T { b { c { d } } }";
        let s = analyze(q, &cfg(), None).unwrap();
        // { a } =1, ...F at depth 2 -> b=2, c=3, d=4
        assert_eq!(s.depth, 4, "fragment contents must contribute to depth");
    }

    #[test]
    fn fragment_spread_complexity_is_counted() {
        // The spread must be charged the cost of the fragment's fields, not
        // just a single default cost.
        let q = "{ root { ...Costly } } fragment Costly on T { users { id } posts { id } }";
        let s = analyze(q, &cfg(), None).unwrap();
        // root(1) + [users(5)+id(1) + posts(3)+id(1)] = 1 + 10 = 11
        assert_eq!(s.complexity, 11);
    }

    #[test]
    fn fragment_cycle_terminates() {
        // Spec-invalid self-referential fragments must not hang the walk.
        let q = "{ ...A } fragment A on T { x ...B } fragment B on T { y ...A }";
        let s = analyze(q, &cfg(), None).unwrap();
        // Just assert it returns; field names should include x and y.
        assert!(s.all_field_names.contains("x"));
        assert!(s.all_field_names.contains("y"));
    }

    #[test]
    fn mutation_classified() {
        let s = analyze(
            "mutation Foo { deleteUser(id: \"1\") { ok } }",
            &cfg(),
            None,
        )
        .unwrap();
        assert_eq!(s.operation_type, "mutation");
        assert_eq!(s.operation_name.as_deref(), Some("Foo"));
    }
}
