//! Bench guest binary for `javm-guest-x86`.
//!
//! Same kernel modules + production RPCs as the production bin
//! (via `extern crate javm_guest_x86`), plus bench-only guest
//! functions whose FN_IDs live in [`nub_arch_x86::test_abi`].

#![cfg_attr(target_os = "none", no_std)]
#![cfg_attr(target_os = "none", no_main)]

#[cfg(target_os = "none")]
extern crate alloc;
#[cfg(target_os = "none")]
extern crate hyperlight_guest_bin;
#[cfg(target_os = "none")]
extern crate javm_guest_x86;

#[cfg(target_os = "none")]
mod bench_fns {
    use alloc::sync::Arc;
    use alloc::vec::Vec;
    use core::arch::x86_64::_rdtsc;
    use hyperlight_guest_bin::guest_function;
    use nub_arch_x86::test_abi::FN_ID_BENCH_ARC_PAGE_ALLOC;

    /// 4 KiB page-aligned block. `repr(C, align(4096))` makes the
    /// payload field of `ArcInner<Page>` page-aligned: Rust pads
    /// the refcount header up to `align(T)` when `align(T) >
    /// align(refcount)`, so the `data` field lands on a 4 KiB
    /// boundary at the cost of ~4080 bytes of header padding per
    /// Arc.
    #[repr(C, align(4096))]
    struct Page([u8; 4096]);

    impl Page {
        fn zero() -> Self {
            Self([0; 4096])
        }
    }

    /// Allocate `N` × `Arc<Page>` and report the total elapsed
    /// RDTSC cycle count.
    ///
    /// Input: `u32` LE = `N`.
    /// Output: `u64` LE = elapsed cycles.
    #[guest_function(fn_id = FN_ID_BENCH_ARC_PAGE_ALLOC)]
    pub fn bench_arc_page_alloc(input: &[u8]) -> Vec<u8> {
        let n = u32::from_le_bytes(input[0..4].try_into().expect("input is 4 bytes")) as usize;
        let mut arcs: Vec<Arc<Page>> = Vec::with_capacity(n);
        let start = unsafe { _rdtsc() };
        for _ in 0..n {
            arcs.push(Arc::new(Page::zero()));
        }
        let elapsed = unsafe { _rdtsc() } - start;
        // Free before returning so repeated bench calls don't grow
        // the talc heap unbounded.
        drop(arcs);
        elapsed.to_le_bytes().to_vec()
    }
}

#[cfg(not(target_os = "none"))]
fn main() {}
