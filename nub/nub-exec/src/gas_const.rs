//! Shared gas / resource cost constants and the category-#2 memory
//! footprint multiplier.
//!
//! Single source of truth linked by **both** execution engines (the
//! interpreter and the x86 recompiler) so their charges cannot drift.
//! See `~/docs/spec-staging/gas-cost.md`.
//!
//! NOTE: the category-#3 constants ([`PAGE_IN_COST`], [`COW_COST`],
//! [`COMPILE_COST_PER_PAGE`], [`CALL_FRAME_COST`], [`HOST_CALL_FLOOR`],
//! [`MGMT_OP_COST`]) are **placeholders**. TODO(gas-calibration): calibrate
//! against the kernel page-fault / call-setup handler; these values are
//! subject to change. [`MAX_PAGES_PER_ACCESS`] is an invariant, not a tunable.

/// Base load/store latency at the smallest footprint tier (×1).
/// Same value as [`crate::gas_cost::DEFAULT_MEM_CYCLES`]; the #2 tier
/// scales it (see [`mem_cycles_for`]).
pub const MEM_CYCLES_BASE: u8 = 25;

/// #3 read-only page-in, charged **per declared 2 MiB unit at the CALL**
/// (no longer per touched unit at a fault): the cost of admitting one
/// read-only unit — code or a pinned DataCap intersected with a 2 MiB
/// cluster — into the working set. Folded into [`call_frame_cost`]; a
/// read at a fault charges nothing.
/// TODO(gas-calibration): placeholder, subject to change.
pub const PAGE_IN_COST: u64 = 64;

/// #3 copy-on-write (first write of a page): allocate + copy + map RW. The
/// **only** fault-driven #3 charge (read-only page-in moved to the CALL).
/// TODO(gas-calibration): placeholder (~4 KiB copy), subject to change.
pub const COW_COST: u64 = 256;

/// #3 JIT-compile cost per 4 KiB of callee code, charged at the CALL that
/// first materializes a callee Image (`O(code)`, bounded by `MAX_CODE_SIZE`).
/// Folded into [`call_frame_cost`]. Charged in full on every CALL — the
/// compiled image is memoized for *work*, never for gas — so a re-CALL into
/// a warm Image pays the same and gas stays independent of the node-local
/// compile cache. TODO(gas-calibration): placeholder, subject to change.
pub const COMPILE_COST_PER_PAGE: u64 = 512;

/// Max consensus 4 KiB pages a single scalar access can span.
///
/// **Invariant, not a tunable.** The widest PVM2 memory access is an
/// 8-byte scalar (`ld`/`sd`) and `8 < 4096`, so a (possibly misaligned,
/// via Zicclsm) access touches at most `ceil(8 / 4096) + 1 = 2`
/// consensus pages. Adding a wider access (e.g. a vector load/store)
/// MUST revisit this constant, or the worst-case-#3 reserve undercounts.
pub const MAX_PAGES_PER_ACCESS: u64 = 2;

/// #3 call-frame **base**: the fixed per-CALL frame-setup cost (callee
/// address-space page table + dispatch table + frame push), independent of
/// code size. The code-size (compile) and read-only-page-in components are
/// added on top by [`call_frame_cost`]. Charged at an in-kernel CALL
/// (`ecall.jar` OP_HOST_CALL).
/// TODO(gas-calibration): placeholder, subject to change.
pub const CALL_FRAME_COST: u64 = 1024;

/// Dynamic floor charged for a bubbled host call (`ecalli imm`).
/// TODO(gas-calibration): placeholder, subject to change.
pub const HOST_CALL_FLOOR: u64 = 100;

/// Dynamic cost of an in-kernel MGMT op (MOVE / COPY / DROP / ...):
/// O(1) content-addressed handle work.
/// TODO(gas-calibration): placeholder, subject to change.
pub const MGMT_OP_COST: u64 = 100;

/// Dynamic **floor** charged at every `ecall` block (the per-op base),
/// keyed only on the instruction type — which both engines know at the
/// ecall, so they charge identically: `ecalli` (host call) →
/// [`HOST_CALL_FLOOR`]; `ecall.jar` (MGMT / CALL) → [`MGMT_OP_COST`].
///
/// An in-kernel CALL (`ecall.jar` OP_HOST_CALL) pays this floor **plus**
/// [`call_frame_cost`] (compile + eager read-only page-in + frame setup),
/// charged by the kernel CALL dispatch once it has resolved the callee
/// Image. TODO(gas-calibration): placeholder. Both engines must keep using
/// this one function for the floor.
#[inline]
pub fn ecall_dynamic_cost(is_ecalli: bool) -> u64 {
    if is_ecalli {
        HOST_CALL_FLOOR
    } else {
        MGMT_OP_COST
    }
}

/// Category-#3 cost of materializing a callee sub-invocation at an
/// in-kernel CALL, charged to the **caller's** meter **in addition to** the
/// [`ecall_dynamic_cost`] floor, and computed **statically from the callee
/// Image** so both engines agree:
///
/// - **JIT compile** — `O(code)`: `ceil(code_len / PAGE_SIZE)` pages ×
///   [`COMPILE_COST_PER_PAGE`].
/// - **Eager read-only page-in** — one [`PAGE_IN_COST`] per declared 2 MiB
///   read-only `unit` (the callee's code region plus its pinned mappings) —
///   the cost that used to be charged lazily per touched unit at a fault.
/// - **Frame-setup base** — [`CALL_FRAME_COST`].
///
/// Always charged in full: the compiled image and its page table are
/// memoized as a node-local **performance** optimization, never a gas
/// discount — so a re-CALL into a warm Image pays identically and gas stays
/// independent of the cache (the architectural "eager compile + eager
/// RO-map at CALL" model; the implementation may stay lazy/demand-paged
/// without changing this charge). TODO(gas-calibration): placeholder
/// coefficients.
#[inline]
pub fn call_frame_cost(code_len: u32, ro_units: u32) -> u64 {
    let code_pages = (code_len as u64).div_ceil(crate::mem::PAGE_SIZE as u64);
    CALL_FRAME_COST
        .saturating_add(code_pages.saturating_mul(COMPILE_COST_PER_PAGE))
        .saturating_add((ro_units as u64).saturating_mul(PAGE_IN_COST))
}

/// Category-#2 memory-access-latency footprint multiplier (×1..4),
/// chosen from the Instance's total accessible 4 KiB page count. Tiers
/// from `~/docs/memory-gas.md` (mem_seq / mem_rand benchmarks). The
/// multiplier is static (resolved once at compile time) and folded into
/// each block's #1 cost, so it has zero runtime metering cost.
#[inline]
pub fn compute_scale(accessible_pages: u32) -> u8 {
    match accessible_pages {
        0..=2048 => 1,     // ≤ 8 MiB — fits L2/L3
        2049..=8192 => 2,  // ≤ 32 MiB — L3 edge
        8193..=65536 => 3, // ≤ 256 MiB — DRAM
        _ => 4,            // > 256 MiB — DRAM + headroom
    }
}

/// Effective per-load/store base latency after #2 footprint scaling:
/// `MEM_CYCLES_BASE × compute_scale(accessible_pages)` (saturating).
/// This is the `mem_cycles` value threaded into predecode / the gas
/// simulator in place of the flat [`MEM_CYCLES_BASE`].
#[inline]
pub fn mem_cycles_for(accessible_pages: u32) -> u8 {
    MEM_CYCLES_BASE.saturating_mul(compute_scale(accessible_pages))
}

/// Accessible 4 KiB page count for an Instance whose data extent is
/// `[data_base, mem_size)` — the #2 footprint. `mem_size` is the
/// high-water-mark over the Image's `memory_mappings`
/// (`javm_cap::image::ImageCap::data_overlays` — the single source of
/// truth both engines derive from), so the two engines compute an
/// identical page count. `data_base` is `javm_cap::layout::DATA_BASE`
/// (passed in — this crate has no `javm-cap` dependency).
#[inline]
pub fn accessible_pages(mem_size: u32, data_base: u32) -> u32 {
    mem_size.saturating_sub(data_base) / crate::mem::PAGE_SIZE
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn scale_tier_boundaries() {
        // Inclusive upper bounds per tier; comparison is by page count.
        assert_eq!(compute_scale(0), 1);
        assert_eq!(compute_scale(2048), 1);
        assert_eq!(compute_scale(2049), 2);
        assert_eq!(compute_scale(8192), 2);
        assert_eq!(compute_scale(8193), 3);
        assert_eq!(compute_scale(65536), 3);
        assert_eq!(compute_scale(65537), 4);
        assert_eq!(compute_scale(u32::MAX), 4);
    }

    #[test]
    fn mem_cycles_scales_with_footprint() {
        assert_eq!(mem_cycles_for(0), 25);
        assert_eq!(mem_cycles_for(2049), 50);
        assert_eq!(mem_cycles_for(8193), 75);
        assert_eq!(mem_cycles_for(65537), 100);
    }

    #[test]
    fn base_matches_gas_cost_default() {
        assert_eq!(MEM_CYCLES_BASE, crate::gas_cost::DEFAULT_MEM_CYCLES);
    }
}
