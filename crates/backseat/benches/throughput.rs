use criterion::{criterion_group, criterion_main, Criterion};

fn bench_throughput(_c: &mut Criterion) {
    // Placeholder
}

criterion_group!(benches, bench_throughput);
criterion_main!(benches);
