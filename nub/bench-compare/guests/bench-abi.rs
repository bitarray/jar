// The uniform guest ABI, `include!`d verbatim into every wrapper.
//
// One export, no arguments, `u32` out. Every engine's
// `Backend::run` calls exactly this symbol, and the returned value is
// what the cross-engine equality check compares.
//
// The compute kernels themselves are untouched by any of this: they
// live in `nub/programs/*` as plain `pub fn name() -> u32` and are
// consumed here as an ordinary path dependency. That is the whole
// reason a fair comparison is cheap — one kernel, N entry shims.
//
// The PVM2 family does not use this file. There the kernel crate's own
// `#[nub_rt::endpoint(0)]` binary *is* the ABI, so `bench-build`
// builds that directly.

// A global allocator for the polkavm build.
//
// Three kernels (`ecrecover`, `poly-eval`, `fri-fold-tree`) use `alloc`
// internally, so on a freestanding target something has to provide
// `#[global_allocator]`. The native and wasm families link `std` and
// get one for free; the PVM2 family gets one from the kernel binary's
// own `nub_rt::bump_allocator!`. polkavm is the only build that has
// neither — it is `no_std` with `-Zbuild-std=core,alloc` — and without
// this it fails to link with "no global memory allocator found".
//
// Deliberately not `nub_rt::bump_allocator!`: `nub-rt` is the PVM2
// guest runtime, and its `_start` trampoline and `.nub.endpoints`
// section are gated on `target_os = "none"` + `riscv64`, which the
// polkavm target also matches. Depending on it here would inject the
// PVM2 entry ABI into a polkavm blob.
//
// A bump arena because these kernels run once and exit: allocation is a
// pointer bump and nothing is ever freed. The arena lives in `.bss`, so
// it costs nothing in the blob.
#[cfg(target_env = "polkavm")]
const GUEST_HEAP_BYTES: usize = 256 * 1024;

#[cfg(target_env = "polkavm")]
struct BumpAlloc {
    heap: core::cell::UnsafeCell<[u8; GUEST_HEAP_BYTES]>,
    pos: core::cell::UnsafeCell<usize>,
}

// SAFETY: guests are single-threaded — polkavm runs one instruction
// stream and a guest has no way to create a thread.
#[cfg(target_env = "polkavm")]
unsafe impl Sync for BumpAlloc {}

#[cfg(target_env = "polkavm")]
unsafe impl core::alloc::GlobalAlloc for BumpAlloc {
    unsafe fn alloc(&self, layout: core::alloc::Layout) -> *mut u8 {
        let pos = unsafe { &mut *self.pos.get() };
        let aligned = (*pos + layout.align() - 1) & !(layout.align() - 1);
        let next = aligned + layout.size();
        if next > GUEST_HEAP_BYTES {
            return core::ptr::null_mut();
        }
        *pos = next;
        unsafe { (*self.heap.get()).as_mut_ptr().add(aligned) }
    }

    unsafe fn dealloc(&self, _ptr: *mut u8, _layout: core::alloc::Layout) {}
}

#[cfg(target_env = "polkavm")]
#[global_allocator]
static GUEST_HEAP: BumpAlloc = BumpAlloc {
    heap: core::cell::UnsafeCell::new([0; GUEST_HEAP_BYTES]),
    pos: core::cell::UnsafeCell::new(0),
};

/// Define the `run` export for whichever target we are building.
macro_rules! bench_entry {
    ($kernel:path) => {
        /// The measured entry point.
        ///
        /// `#[no_mangle]` so the native backend can `dlsym` it and the
        /// wasm backend can find it in the export table;
        /// `#[polkavm_export]` additionally registers it in polkavm's
        /// export table, which is how polkavm enters a program (its
        /// `_start` is never used).
        #[cfg_attr(target_env = "polkavm", polkavm_derive::polkavm_export)]
        #[unsafe(no_mangle)]
        pub extern "C" fn run() -> u32 {
            $kernel()
        }
    };
}

// The sBPF global allocator.
//
// It cannot be the `.bss` arena above: the sBPF container has no
// writable segment at all — the strict v3 ELF parser accepts exactly
// two `PT_LOAD` headers, `PF_R` and `PF_X` — so a mutable global cannot
// even be expressed, and `sbpf-link` refuses to emit one.
//
// Instead the arena *is* the VM's heap region. The host maps writable
// memory at `MM_HEAP_START` and the guest bumps through it, keeping the
// cursor in the first 8 bytes of that region rather than in a static.
// This mirrors what Solana's own `BumpAllocator` does on-chain.
//
// The region size is the harness's choice, not Solana's on-chain
// policy (which defaults to 32 KiB) — `fri-fold-tree` alone needs
// 65,528 B. `backend/sbpf.rs` maps it and the report discloses it.
#[cfg(target_arch = "bpf")]
mod sbpf_heap {
    use core::alloc::{GlobalAlloc, Layout};

    /// `solana_sbpf::ebpf::MM_HEAP_START`.
    const HEAP_START: u64 = 3 * (1u64 << 32);
    /// Must match the region `backend/sbpf.rs` maps.
    const HEAP_LEN: u64 = 256 * 1024;
    /// The cursor lives in the first 8 bytes of the region.
    const CURSOR: u64 = HEAP_START;
    const BASE: u64 = HEAP_START + 8;

    pub struct HeapBump;

    unsafe impl GlobalAlloc for HeapBump {
        unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
            unsafe {
                let cursor = CURSOR as *mut u64;
                let pos = if *cursor == 0 { BASE } else { *cursor };
                let align = layout.align() as u64;
                let aligned = (pos + align - 1) & !(align - 1);
                let next = aligned + layout.size() as u64;
                if next > HEAP_START + HEAP_LEN {
                    return core::ptr::null_mut();
                }
                *cursor = next;
                aligned as *mut u8
            }
        }
        /// Bump arena: the kernels run once and exit, so nothing frees.
        unsafe fn dealloc(&self, _ptr: *mut u8, _layout: Layout) {}
    }

    #[global_allocator]
    static ALLOC: HeapBump = HeapBump;
}
