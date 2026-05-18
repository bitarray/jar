/*
Copyright 2025  The Hyperlight Authors.
Vendored & trimmed for nub. Stage F.2.3 dropped aarch64, libc/picolibc
stubs, the guest logger, mem_profile, and trace_guest. Subsequent
stages drop the CoW pagefault handler (F3.3) and swap the buddy
allocator for talc (F3.4).

Licensed under the Apache License, Version 2.0.
*/
#![no_std]

// === Dependencies ===
extern crate alloc;

use core::fmt::Write;

use arch::dispatch::dispatch_function;
use guest_function::register::GuestFunctionRegister;
use hyperlight_common::flatbuffer_wrappers::guest_error::ErrorCode;
// PEB type comes from upstream hyperlight_common because we feed it
// into the upstream `hyperlight-guest` crate's `GuestHandle::init`.
// `nub_host_common::mem::HyperlightPEB` is the same bytes-on-the-wire
// but a distinct nominal type — using the upstream alias here avoids
// a nominal-type mismatch.
use hyperlight_common::mem::HyperlightPEB;
use hyperlight_guest::exit::write_abort;
use hyperlight_guest::guest_handle::handle::GuestHandle;

// === Modules ===
#[path = "arch/amd64/mod.rs"]
mod arch;

pub mod exception;
pub mod guest_function {
    pub(super) mod call;
    pub mod definition;
    pub mod register;
}

pub mod error;
pub mod host_comm;
pub mod paging;

// === Globals ===
//
// F3.4: replaced upstream's `buddy_system_allocator::LockedHeap<32>`
// with `talc::TalcLock`. Talc is dlmalloc-style (linked-list +
// boundary tagging + binning) and copes much better with the bench
// workload's alloc/free churn — buddy's power-of-2 binning was
// fragmenting the heap badly enough that 16 KiB allocations failed
// after a few thousand iterations.
// Public iff the `heap-diag` feature is on, so the `nub-arch-x86`
// guest can read talc counters for the leak-hunting diagnostic in
// `Nub::heap_stats`. Default-private otherwise.
#[cfg(feature = "heap-diag")]
#[global_allocator]
pub static HEAP_ALLOCATOR: talc::TalcLock<spinning_top::RawSpinlock, talc::source::Manual> =
    talc::TalcLock::new(talc::source::Manual);
#[cfg(not(feature = "heap-diag"))]
#[global_allocator]
pub(crate) static HEAP_ALLOCATOR: talc::TalcLock<spinning_top::RawSpinlock, talc::source::Manual> =
    talc::TalcLock::new(talc::source::Manual);

pub static mut GUEST_HANDLE: GuestHandle = GuestHandle::new();
pub(crate) static mut REGISTERED_GUEST_FUNCTIONS: GuestFunctionRegister<GuestFunc> =
    GuestFunctionRegister::new();

const VERSION_STR: &str = env!("CARGO_PKG_VERSION");

// Embed the guest crate version as a proper ELF note so the
// host can verify ABI compatibility at load time. Keeps the
// upstream section name so existing `hyperlight-host` builds also
// accept this guest.
#[used]
#[unsafe(link_section = ".note.hyperlight-version")]
static HYPERLIGHT_VERSION_NOTE: nub_host_common::version_note::ElfNote<
    {
        nub_host_common::version_note::padded_name_size(
            nub_host_common::version_note::HYPERLIGHT_NOTE_NAME.len() + 1,
        )
    },
    { nub_host_common::version_note::padded_desc_size(VERSION_STR.len() + 1) },
> = nub_host_common::version_note::ElfNote::new(
    nub_host_common::version_note::HYPERLIGHT_NOTE_NAME,
    VERSION_STR,
    nub_host_common::version_note::HYPERLIGHT_NOTE_TYPE,
);

/// The size of one page in the host OS.
pub static mut OS_PAGE_SIZE: u32 = 0;

// === Panic Handler ===
// The cfg_attr attribute is used to avoid clippy failures as test pulls in std which pulls in a panic handler
#[cfg_attr(not(test), panic_handler)]
#[allow(clippy::panic)]
#[allow(dead_code)]
fn panic(info: &core::panic::PanicInfo) -> ! {
    _panic_handler(info)
}

/// A writer that sends all output to the hyperlight host
/// using output ports. This allows us to not impose a
/// buffering limit on error message size on the guest end,
/// though one exists for the host.
struct HyperlightAbortWriter;
impl core::fmt::Write for HyperlightAbortWriter {
    fn write_str(&mut self, s: &str) -> core::fmt::Result {
        write_abort(s.as_bytes());
        Ok(())
    }
}

#[inline(always)]
fn _panic_handler(info: &core::panic::PanicInfo) -> ! {
    let mut w = HyperlightAbortWriter;

    // begin abort sequence by writing the error code
    write_abort(&[ErrorCode::UnknownError as u8]);

    let write_res = write!(w, "{}", info);
    if write_res.is_err() {
        write_abort("panic: message format failed".as_bytes());
    }

    // write abort terminator to finish the abort
    // and signal to the host that the message can now be read
    write_abort(&[0xFF]);
    unreachable!();
}

// === Entrypoint ===

unsafe extern "C" {
    fn hyperlight_main();
}

extern "C" fn hyperlight_main_default() {
    // no-op
}

core::arch::global_asm!(
    ".weak hyperlight_main",
    ".set hyperlight_main, {}",
    sym hyperlight_main_default,
);

/// Architecture-nonspecific initialisation: set up the heap,
/// coordinate some addresses with the host, and run user
/// initialisation.
pub(crate) extern "C" fn generic_init(
    peb_address: u64,
    _seed: u64,
    ops: u64,
    _max_log_level: u64,
) -> u64 {
    unsafe {
        GUEST_HANDLE = GuestHandle::init(peb_address as *mut HyperlightPEB);
        #[allow(static_mut_refs)]
        let peb_ptr = GUEST_HANDLE.peb().unwrap();

        let heap_start = (*peb_ptr).guest_heap.ptr as *mut u8;
        let heap_size = (*peb_ptr).guest_heap.size as usize;
        // SAFETY: the host hands us a contiguous, exclusively-owned
        // writable region of `heap_size` bytes at `heap_start`. We
        // claim it once, here, before any allocator-backed code runs.
        HEAP_ALLOCATOR
            .try_lock()
            .expect("Failed to access HEAP_ALLOCATOR")
            .claim(heap_start, heap_size)
            .expect("talc heap claim");
        peb_ptr
    };

    unsafe {
        OS_PAGE_SIZE = ops as u32;
    }

    #[cfg(feature = "macros")]
    for registration in __private::GUEST_FUNCTION_INIT {
        registration();
    }

    unsafe {
        hyperlight_main();
    }

    dispatch_function as usize as u64
}

#[cfg(feature = "macros")]
#[doc(hidden)]
pub mod __private {
    pub use alloc::vec::Vec;

    pub use hyperlight_common::flatbuffer_wrappers::function_call::FunctionCall;
    pub use hyperlight_common::func::ResultType;
    pub use hyperlight_guest::error::HyperlightGuestError;
    pub use linkme;

    #[linkme::distributed_slice]
    pub static GUEST_FUNCTION_INIT: [fn()];

    pub trait FromResult {
        type Output;
        fn from_result(res: Result<Self::Output, HyperlightGuestError>) -> Self;
    }

    use alloc::string::String;

    use hyperlight_common::for_each_return_type;

    macro_rules! impl_maybe_unwrap {
        ($ty:ty, $enum:ident) => {
            impl FromResult for $ty {
                type Output = Self;
                fn from_result(res: Result<Self::Output, HyperlightGuestError>) -> Self {
                    // Unwrapping here is fine as this would only run in a guest
                    // and not in the host.
                    res.unwrap()
                }
            }

            impl FromResult for Result<$ty, HyperlightGuestError> {
                type Output = $ty;
                fn from_result(res: Result<Self::Output, HyperlightGuestError>) -> Self {
                    res
                }
            }
        };
    }

    for_each_return_type!(impl_maybe_unwrap);
}

#[cfg(feature = "macros")]
pub use hyperlight_guest_macro::{dispatch, guest_function, host_function, main};

pub use crate::guest_function::definition::GuestFunc;
