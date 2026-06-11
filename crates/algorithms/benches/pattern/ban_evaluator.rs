//! Benchmark: ban_evaluator — Varnish predicate-based cache invalidation
//! Group: pattern | Algo: ban_evaluator

use criterion::{black_box, criterion_group, criterion_main, BenchmarkId, Criterion};
use algorithms::goals::pattern::{Ban, BanList, BanOp};

/// Canned object: a fixed set of field/value pairs looked up by name.
fn obj(field: &str) -> Option<String> {
    match field {
        "req.url" => Some("/api/v1/users/profile".to_string()),
        "req.host" => Some("example.com".to_string()),
        "req.method" => Some("GET".to_string()),
        "obj.http.content-type" => Some("text/html; charset=utf-8".to_string()),
        "obj.age" => Some("120".to_string()),
        _ => None,
    }
}

/// Build a ban with `n` predicates that all match the canned object.
fn make_ban(n: usize) -> Ban {
    let mut ban = Ban::new();
    for i in 0..n {
        match i % 5 {
            0 => ban.add("req.url", BanOp::Match, "/api/"),
            1 => ban.add("req.host", BanOp::Eq, "example.com"),
            2 => ban.add("req.method", BanOp::Neq, "POST"),
            3 => ban.add("obj.http.content-type", BanOp::Match, "text/html"),
            _ => ban.add("obj.age", BanOp::GreaterThan, "60"),
        }
    }
    ban
}

fn bench(c: &mut Criterion) {
    let mut g = c.benchmark_group("pattern/ban_evaluator");

    let lookup: &dyn Fn(&str) -> Option<String> = &obj;

    for &n in &[1usize, 5, 20] {
        let ban = make_ban(n);
        g.bench_with_input(BenchmarkId::new("ban_matches", n), &ban, |b, ban| {
            b.iter(|| black_box(ban.matches(lookup)))
        });
    }

    for &n in &[1usize, 5, 20] {
        let mut list = BanList::new();
        for _ in 0..n {
            // Each ban has 3 predicates; the last predicate of the last ban
            // matches so the full list must be scanned.
            list.add_ban(make_ban(3));
        }
        g.bench_with_input(BenchmarkId::new("banlist_is_banned", n), &list, |b, list| {
            b.iter(|| black_box(list.is_banned(lookup)))
        });
    }

    g.finish();
}

criterion_group!(benches, bench);
criterion_main!(benches);
