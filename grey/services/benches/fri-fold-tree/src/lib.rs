//! FRI fold tree walk benchmark — mirrors `p3_fri::verify`'s hot loop.
//!
//! Builds a synthetic flat-merkle-tree buffer (deterministic content; we
//! don't bother computing real internal-node hashes since the bench measures
//! access patterns + per-step ops, not commitment correctness). For each of
//! `NUM_QUERIES` queries:
//!   - Pick a random leaf index from the transcript
//!   - Walk the tree from leaf to root, `TRACE_LOG` levels
//!   - At each level: read scattered sibling, Poseidon2-mix, Goldilocks-fold
//!
//! Why this complements `mini-verifier`: mini-verifier hashes the same
//! 8-cell state buffer repeatedly (cache-warm). FRI walks scattered
//! indices in a flat 64 KiB tree buffer — exposes cache + allocator pressure
//! that the composite verifier didn't isolate.

#![cfg_attr(target_os = "none", no_std)]

use javm_builtins as _;

#[cfg(target_os = "none")]
extern crate alloc;

#[cfg(target_os = "none")]
mod bump_alloc {
    use core::alloc::{GlobalAlloc, Layout};
    use core::cell::UnsafeCell;

    const HEAP_SIZE: usize = 256 * 1024;

    pub struct BumpAlloc {
        heap: UnsafeCell<[u8; HEAP_SIZE]>,
        pos: UnsafeCell<usize>,
    }

    unsafe impl Sync for BumpAlloc {}

    unsafe impl GlobalAlloc for BumpAlloc {
        unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
            let pos = unsafe { &mut *self.pos.get() };
            let aligned = (*pos + layout.align() - 1) & !(layout.align() - 1);
            let next = aligned + layout.size();
            if next > HEAP_SIZE {
                return core::ptr::null_mut();
            }
            *pos = next;
            unsafe { (*self.heap.get()).as_mut_ptr().add(aligned) }
        }
        unsafe fn dealloc(&self, _ptr: *mut u8, _layout: Layout) {}
    }

    #[global_allocator]
    static ALLOC: BumpAlloc = BumpAlloc {
        heap: UnsafeCell::new([0; HEAP_SIZE]),
        pos: UnsafeCell::new(0),
    };
}

#[cfg(target_env = "polkavm")]
mod polkavm;

#[cfg(target_os = "none")]
use alloc::vec::Vec;

use gp::{add, canonical, mul, permute, sub, ONE, ZERO};

const TRACE_LOG: u32 = 12;
const N: usize = 1 << TRACE_LOG;
const TREE_SIZE: usize = 2 * N - 1;
const NUM_QUERIES: u32 = 30;
const SEED: u64 = 0x123456789abcdef0;
const MULTIPLIER: u64 = 0x9E3779B97F4A7C15;

pub fn fri_fold_tree_bench() -> u32 {
    let mut tree: Vec<u64> = Vec::with_capacity(TREE_SIZE);
    let mut x: u64 = SEED;
    let mut i = 0;
    while i < TREE_SIZE {
        x = mul(x, MULTIPLIER);
        tree.push(x);
        i += 1;
    }

    let mut offsets = [0usize; (TRACE_LOG + 1) as usize];
    let mut acc = 0;
    let mut sz = N;
    let mut l = 0;
    while l <= TRACE_LOG as usize {
        offsets[l] = acc;
        acc += sz;
        sz >>= 1;
        l += 1;
    }

    let mut state: [u64; 8] = [
        0xdeadbeef_00000000,
        0xdeadbeef_00000001,
        0xdeadbeef_00000002,
        0xdeadbeef_00000003,
        0xdeadbeef_00000004,
        0xdeadbeef_00000005,
        0xdeadbeef_00000006,
        0xdeadbeef_00000007,
    ];
    let mut k = 0;
    while k < 4 {
        permute(&mut state);
        k += 1;
    }

    let mut accum = ZERO;
    let mut q = 0;
    while q < NUM_QUERIES {
        let mut idx = (state[(q as usize) % 8] & ((N as u64) - 1)) as usize;
        let mut current = tree[idx];
        let mut level = 0;
        while level < TRACE_LOG as usize {
            let sibling = tree[offsets[level] + (idx ^ 1)];
            let mut h = state;
            h[0] = current;
            h[1] = sibling;
            permute(&mut h);
            let challenge = h[0];
            let one_minus_c = sub(ONE, challenge);
            current = add(mul(one_minus_c, current), mul(challenge, sibling));
            idx >>= 1;
            level += 1;
        }
        accum = add(accum, current);
        q += 1;
    }

    (canonical(accum) & 0xFFFF_FFFF) as u32
}
