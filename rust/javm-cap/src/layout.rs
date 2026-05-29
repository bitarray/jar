//! PVM2 guest virtual-address-space layout (ABI constants).
//!
//! These constants define where a transpiler-emitted Image's code and
//! data regions map in the guest's 32-bit address space. They are part
//! of the PVM2 ABI contract: the transpiler (`javm-transpiler`) bakes
//! `PC = CODE_BASE + byte_offset` into endpoint entry PCs and native
//! `auipc`/`jalr` resolution, and every runtime (`nub-arch-x86`,
//! `nub-arch-local`, `javm`) maps `Image.code` read-only at `CODE_BASE`.
//!
//! The constants live here in `javm-cap` because it is the only crate
//! every producer (transpiler) and consumer (each runtime) depends on.
//! Code placement is a fixed protocol constant rather than an
//! Image-supplied mapping entry: an untrusted Image must not get to
//! choose where its code lands.

/// Guest virtual address where the (single) code region maps read-only.
/// A PVM PC is `CODE_BASE + byte_offset`.
///
/// Sits at 1 GiB, above the data layout (which grows from the low
/// address space upward) and below CTX. The high bit is clear so a
/// 32-bit `ra` spill round-trips identically under `lw`/`lwu`.
pub const CODE_BASE: u32 = 0x4000_0000;
