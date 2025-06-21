// Benchmarks for Jwe::decode vs Jwe::from_str
// Run with: cargo bench --bench jwe

use akv_cli::jose::Jwe;
use criterion::{criterion_group, criterion_main, Criterion};
use std::{hint::black_box, str::FromStr};

// cspell:disable
// Valid JWE string from tests
const VALID_JWE: &str = "eyJhbGciOiJSU0EtT0FFUC0yNTYiLCJlbmMiOiJBMTI4R0NNIiwia2lkIjoidGVzdC1rZXktaWQiLCJ0eXAiOiJKV0UifQ.EjRWeA.mrze8A.ASNFZw.iavN7w";

// Invalid JWE string (not decodable)
const INVALID_JWE: &str = "eyJhbGciOiJSU0EtT0FFUC0yNTYiLCJlbmMiOiJBMTI4R0NNIiwia2lkIjoidGVzdC1rZXktaWQiLCJ0eXAiOiJKV0UifQ.invalid.invalid.invalid.invalid.invalid.invalid";
// cspell:enable

fn jwe_from_str(c: &mut Criterion) {
    c.bench_function("Jwe::from_str valid", |b| {
        b.iter(|| {
            let _ = black_box(Jwe::from_str(black_box(VALID_JWE)));
        })
    });
    c.bench_function("Jwe::from_str invalid", |b| {
        b.iter(|| {
            let _ = black_box(Jwe::from_str(black_box(INVALID_JWE)));
        })
    });
}

criterion_group!(benches, jwe_from_str);
criterion_main!(benches);
