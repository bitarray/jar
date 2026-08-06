//! Benchmark for Lazy Pre-decode Performance
//!
//! Run with: cargo bench -p grey-bench --bench lazy_predecode
//!
//! # Comparison
//!
//! ```bash
//! # Compare lazy vs eager mode
//! GREY_PVM_LAZY=true cargo bench -p grey-bench --bench lazy_predecode
//! GREY_PVM_LAZY=false cargo bench -p grey-bench --bench lazy_predecode
//! ```

use criterion::{black_box, criterion_group, criterion_main, Criterion, BenchmarkId};
use std::time::Duration;

/// Mock bytecode generator for testing
fn generate_test_bytecode(size: usize) -> Vec<u8> {
    let mut code = Vec::with_capacity(size);

    // Generate a mix of instructions
    let mut i = 0;
    while code.len() < size {
        match i % 10 {
            0 => code.push(0),      // trap (terminator)
            1 => {
                code.push(52);      // load
                code.push(0);       // ra=0
            },
            2 => {
                code.push(90);      // add
                code.push(0);       // ra
                code.push(1);       // rb
                code.push(2);       // rd
            },
            3 => {
                code.push(181);     // branch
                code.extend_from_slice(&[0, 0, 0, 10]); // offset
            },
            4 => {
                code.push(51);      // load_imm
                code.extend_from_slice(&[42, 0, 0, 0, 0, 0, 0, 0, 0]); // imm=42
            },
            _ => {
                code.push(1);       // fallthrough (no-op)
            },
        }
        i += 1;
    }

    code.truncate(size);
    code
}

/// Generate bitmask for bytecode
fn generate_bitmask(code: &[u8]) -> Vec<u8> {
    // Simplified: mark every byte as having ra
    let mut bitmask = Vec::with_capacity((code.len() + 7) / 8);
    for chunk in code.chunks(8) {
        let mut byte = 0u8;
        for (i, _) in chunk.iter().enumerate() {
            byte |= 1 << i;
        }
        bitmask.push(byte);
    }
    bitmask
}

fn bench_lazy_decode_short(c: &mut Criterion) {
    // Test with short programs (< 10 blocks)
    let mut group = c.benchmark_group("lazy_predecode");
    group.sample_size(1000);
    group.measurement_time(Duration::from_secs(10));

    let sizes = [10, 50, 100, 500, 1000];

    for size in sizes {
        let code = generate_test_bytecode(size);
        let bitmask = generate_bitmask(&code);

        group.bench_with_input(BenchmarkId::new("short_program", size), &size, |b, _| {
            b.iter(|| {
                // Simulate lazy pre-decode
                let decoded = simulate_lazy_predecode(&code, &bitmask);
                black_box(decoded);
            });
        });
    }

    group.finish();
}

fn bench_eager_decode_short(c: &mut Criterion) {
    // Test with short programs (< 10 blocks)
    let mut group = c.benchmark_group("eager_predecode");
    group.sample_size(1000);
    group.measurement_time(Duration::from_secs(10));

    let sizes = [10, 50, 100, 500, 1000];

    for size in sizes {
        let code = generate_test_bytecode(size);
        let bitmask = generate_bitmask(&code);

        group.bench_with_input(BenchmarkId::new("short_program", size), &size, |b, _| {
            b.iter(|| {
                // Simulate eager pre-decode
                let decoded = simulate_eager_predecode(&code, &bitmask);
                black_box(decoded);
            });
        });
    }

    group.finish();
}

fn bench_cache_hit_rate(c: &mut Criterion) {
    // Test cache hit rate for different access patterns
    let mut group = c.benchmark_group("cache_hit_rate");
    group.sample_size(100);
    group.measurement_time(Duration::from_secs(5));

    let patterns = [
        ("sequential", Pattern::Sequential),
        ("loop_10x", Pattern::Loop10x),
        ("random", Pattern::Random),
        ("hotspot", Pattern::Hotspot),
    ];

    let size = 1000;
    let code = generate_test_bytecode(size);
    let bitmask = generate_bitmask(&code);

    for (name, pattern) in patterns {
        group.bench_function(name, |b| {
            b.iter(|| {
                let decoded = simulate_with_pattern(&code, &bitmask, pattern);
                black_box(decoded);
            });
        });
    }

    group.finish();
}

fn bench_mode_switch(c: &mut Criterion) {
    // Test performance when switching from lazy to eager mode
    let mut group = c.benchmark_group("mode_switch");
    group.sample_size(100);
    group.measurement_time(Duration::from_secs(10));

    let coverage = [0.1, 0.3, 0.5, 0.7, 0.9];

    let size = 1000;
    let code = generate_test_bytecode(size);
    let bitmask = generate_bitmask(&code);

    for cov in coverage {
        group.bench_with_input(
            BenchmarkId::new("lazy_then_eager", (cov * 100.0) as u32),
            &cov,
            |b, &coverage| {
                b.iter(|| {
                    let decoded = simulate_mode_switch(&code, &bitmask, coverage);
                    black_box(decoded);
                });
            },
        );
    }

    group.finish();
}

// =============================================================================
// Helper Functions
// =============================================================================

enum Pattern {
    Sequential,
    Loop10x,
    Random,
    Hotspot,
}

fn simulate_lazy_predecode(code: &[u8], _bitmask: &[u8]) -> usize {
    // Simulate lazy pre-decode: only decode what's accessed
    let mut decoded_count = 0;

    for pc in (0..code.len()).step_by(5) {
        // Access every 5th instruction
        decoded_count += 1;
    }

    decoded_count
}

fn simulate_eager_predecode(code: &[u8], _bitmask: &[u8]) -> usize {
    // Simulate eager pre-decode: decode all instructions
    let mut decoded_count = 0;

    for _ in code.iter() {
        decoded_count += 1;
    }

    decoded_count
}

fn simulate_with_pattern(code: &[u8], bitmask: &[u8], pattern: Pattern) -> usize {
    let mut decoded = std::collections::HashSet::new();
    let block_size = 5;

    match pattern {
        Pattern::Sequential => {
            // Sequential access
            for pc in (0..code.len()).step_by(block_size) {
                let block_end = (pc + block_size).min(code.len());
                for i in pc..block_end {
                    decoded.insert(i);
                }
            }
        },
        Pattern::Loop10x => {
            // Loop 10 times over first 20%
            let loop_end = code.len() / 5;
            for _ in 0..10 {
                for pc in (0..loop_end).step_by(block_size) {
                    let block_end = (pc + block_size).min(loop_end);
                    for i in pc..block_end {
                        decoded.insert(i);
                    }
                }
            }
        },
        Pattern::Random => {
            // Random access
            let mut rng = simple_rng(42);
            for _ in 0..100 {
                let pc = (rng.next_u32() as usize) % code.len();
                let block_end = (pc + block_size).min(code.len());
                for i in pc..block_end {
                    decoded.insert(i);
                }
            }
        },
        Pattern::Hotspot => {
            // 80% access to 20% of code
            let hotspot_end = code.len() / 5;
            for _ in 0..80 {
                let pc = (rng_next_u32(42) as usize) % hotspot_end;
                let block_end = (pc + block_size).min(hotspot_end);
                for i in pc..block_end {
                    decoded.insert(i);
                }
            }
            // 20% access to rest
            for _ in 0..20 {
                let pc = hotspot_end + ((rng_next_u32(43) as usize) % (code.len() - hotspot_end));
                let block_end = (pc + block_size).min(code.len());
                for i in pc..block_end {
                    decoded.insert(i);
                }
            }
        },
    }

    decoded.len()
}

fn simulate_mode_switch(code: &[u8], _bitmask: &[u8], coverage: f32) -> usize {
    let total_blocks = code.len() / 5;
    let switch_at = (total_blocks as f32 * coverage) as usize;

    let mut decoded_count = 0;

    // Lazy phase
    for block in 0..switch_at {
        let pc = block * 5;
        decoded_count += 1; // Decode one block
    }

    // Switch to eager (decode remaining)
    let remaining = total_blocks - switch_at;
    decoded_count += remaining;

    decoded_count
}

// Simple RNG for reproducible benchmarks
fn simple_rng(seed: u32) -> SimpleRng {
    SimpleRng { state: seed }
}

struct SimpleRng {
    state: u32,
}

impl SimpleRng {
    fn next_u32(&mut self) -> u32 {
        self.state = self.state.wrapping_mul(1103515245).wrapping_add(12345);
        self.state
    }
}

fn rng_next_u32(seed: u32) -> u32 {
    let state = seed.wrapping_mul(1103515245).wrapping_add(12345);
    state
}

criterion_group!(
    benches,
    bench_lazy_decode_short,
    bench_eager_decode_short,
    bench_cache_hit_rate,
    bench_mode_switch,
);
criterion_main!(benches);
