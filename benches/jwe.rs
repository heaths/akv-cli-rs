// Benchmarks for Jwe::decode vs Jwe::from_str
// Run with: cargo bench --bench jwe

use akv_cli::jose::{Encode as _, Jwe};
use criterion::{criterion_group, criterion_main, Criterion};
use std::{hint::black_box, str::FromStr};

// cspell:disable
// Valid JWE string from tests
const VALID_JWE: &str = "eyJhbGciOiJSU0EtT0FFUC0yNTYiLCJlbmMiOiJBMTI4R0NNIiwia2lkIjoidGVzdC1rZXktaWQiLCJ0eXAiOiJKV0UifQ.EjRWeA.mrze8A.ASNFZw.iavN7w";

// Invalid JWE string (not decodable)
const INVALID_JWE: &str = "eyJhbGciOiJSU0EtT0FFUC0yNTYiLCJlbmMiOiJBMTI4R0NNIiwia2lkIjoidGVzdC1rZXktaWQiLCJ0eXAiOiJKV0UifQ.invalid.invalid.invalid.invalid.invalid.invalid";
// cspell:enable

fn jwe_decode_vs_from_str(c: &mut Criterion) {
    let mut group = c.benchmark_group("valid");
    group.bench_function("Jwe::decode", |b| {
        b.iter(|| {
            let _ = black_box(Jwe::decode(black_box(VALID_JWE)));
        })
    });
    group.bench_function("Jwe::from_str", |b| {
        b.iter(|| {
            let _ = black_box(Jwe::from_str(black_box(VALID_JWE)));
        })
    });
    group.finish();

    let mut group = c.benchmark_group("invalid");
    group.bench_function("Jwe::decode", |b| {
        b.iter(|| {
            let _ = black_box(Jwe::decode(black_box(INVALID_JWE)));
        })
    });
    group.bench_function("Jwe::from_str", |b| {
        b.iter(|| {
            let _ = black_box(Jwe::from_str(black_box(INVALID_JWE)));
        })
    });
    group.finish();
}

criterion_group!(benches, jwe_decode_vs_from_str);
criterion_main!(benches);
