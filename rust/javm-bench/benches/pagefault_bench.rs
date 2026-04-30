//! Page fault cost benchmark.
//!
//! Measures the per-page cost of first-touch allocation: mmap a region with
//! MAP_NORESERVE (virtual only), then touch one byte per page to trigger
//! kernel page faults. This calibrates the per-page gas fee for grow_heap.
//!
//! Run: `cargo bench -p javm-bench --bench pagefault_bench`

use criterion::{BenchmarkId, Criterion, criterion_group, criterion_main};

const PAGE_SIZE: usize = 4096;

/// mmap a region, touch every page (one byte each), then munmap.
/// Returns the number of pages touched.
fn touch_pages(num_pages: usize) -> usize {
    let size = num_pages * PAGE_SIZE;
    let ptr = unsafe {
        libc::mmap(
            std::ptr::null_mut(),
            size,
            libc::PROT_READ | libc::PROT_WRITE,
            libc::MAP_ANONYMOUS | libc::MAP_PRIVATE | libc::MAP_NORESERVE,
            -1,
            0,
        )
    };
    assert_ne!(ptr, libc::MAP_FAILED, "mmap failed");

    // Touch one byte per page to trigger page faults
    let base = ptr as *mut u8;
    for i in 0..num_pages {
        unsafe {
            base.add(i * PAGE_SIZE).write_volatile(0x42);
        }
    }

    // Clean up
    unsafe {
        libc::munmap(ptr, size);
    }
    num_pages
}

/// Same as touch_pages but with random order (worse TLB behavior).
fn touch_pages_random(num_pages: usize) -> usize {
    let size = num_pages * PAGE_SIZE;
    let ptr = unsafe {
        libc::mmap(
            std::ptr::null_mut(),
            size,
            libc::PROT_READ | libc::PROT_WRITE,
            libc::MAP_ANONYMOUS | libc::MAP_PRIVATE | libc::MAP_NORESERVE,
            -1,
            0,
        )
    };
    assert_ne!(ptr, libc::MAP_FAILED, "mmap failed");

    // Build a shuffled index array (Fisher-Yates)
    let mut indices: Vec<usize> = (0..num_pages).collect();
    let mut seed: u32 = 0xDEADBEEF;
    for i in (1..num_pages).rev() {
        // xorshift32
        seed ^= seed << 13;
        seed ^= seed >> 17;
        seed ^= seed << 5;
        let j = (seed as usize) % (i + 1);
        indices.swap(i, j);
    }

    // Touch pages in random order
    let base = ptr as *mut u8;
    for &i in &indices {
        unsafe {
            base.add(i * PAGE_SIZE).write_volatile(0x42);
        }
    }

    unsafe {
        libc::munmap(ptr, size);
    }
    num_pages
}

fn bench_pagefault(c: &mut Criterion) {
    let sizes: &[(&str, usize)] = &[
        ("1K_pages_4MB", 1024),
        ("4K_pages_16MB", 4096),
        ("16K_pages_64MB", 16384),
        ("64K_pages_256MB", 65536),
    ];

    let mut group = c.benchmark_group("pagefault_seq");
    group.sample_size(10);
    for &(label, pages) in sizes {
        group.bench_with_input(BenchmarkId::from_parameter(label), &pages, |b, &pages| {
            b.iter(|| touch_pages(pages))
        });
    }
    group.finish();

    let mut group = c.benchmark_group("pagefault_rand");
    group.sample_size(10);
    for &(label, pages) in sizes {
        group.bench_with_input(BenchmarkId::from_parameter(label), &pages, |b, &pages| {
            b.iter(|| touch_pages_random(pages))
        });
    }
    group.finish();
}

criterion_group!(pagefault_benches, bench_pagefault);
criterion_main!(pagefault_benches);
