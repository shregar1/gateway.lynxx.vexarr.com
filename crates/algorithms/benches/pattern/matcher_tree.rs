//! Benchmark: MatcherTree — binary decision tree for predicate matching
//! Group: pattern | Algo: matcher_tree

use criterion::{black_box, criterion_group, criterion_main, Criterion};
use algorithms::goals::pattern::matcher_tree::MatcherTree;

fn bench(c: &mut Criterion) {
    let mut g = c.benchmark_group("pattern/matcher_tree");

    g.bench_function("evaluate_5_rules", |b| {
        let mut mt = MatcherTree::new();
        mt.add_rule(vec![true, true, false], 0);
        mt.add_rule(vec![true, false, true], 1);
        mt.add_rule(vec![false, true, true], 2);
        mt.add_rule(vec![false, false, true], 3);
        mt.add_rule(vec![true, true, true], 4);

        let preds = vec![
            vec![true, true, false],
            vec![false, true, true],
            vec![true, true, true],
            vec![false, false, false],
        ];
        let mut idx = 0usize;
        b.iter(|| {
            idx = (idx + 1) % preds.len();
            black_box(mt.evaluate(&preds[idx]))
        })
    });

    g.bench_function("add_rule", |b| {
        b.iter(|| {
            let mut mt = MatcherTree::new();
            for i in 0..10 {
                mt.add_rule(vec![i % 2 == 0, i % 3 == 0], i);
            }
            black_box(&mt);
        })
    });

    g.finish();
}

criterion_group!(benches, bench);
criterion_main!(benches);
