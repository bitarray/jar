//! Test-only helper: a single process-global talc lock, claimed once
//! at first use, available as `TalcAlloc` to every test.
//!
//! Tests run on multiple threads under `cargo test`; talc's internal
//! mutex serialises concurrent allocations. talc reclaims memory on
//! drop so the shared heap doesn't fill up across tests.

use crate::talc::{CacheTalcLock, Span, TalcAlloc, new_cache_talc_lock};

const TEST_HEAP_SIZE: usize = 1 << 20; // 1 MiB

static TALC: CacheTalcLock = new_cache_talc_lock();
static mut HEAP: [u8; TEST_HEAP_SIZE] = [0; TEST_HEAP_SIZE];
static INIT: std::sync::Once = std::sync::Once::new();

/// Return the shared talc allocator. Initialises on first call.
pub(crate) fn test_talc() -> TalcAlloc {
    INIT.call_once(|| unsafe {
        let span = Span::from_array(&raw mut HEAP);
        TALC.lock().claim(span).expect("test talc heap claim");
    });
    &TALC
}
