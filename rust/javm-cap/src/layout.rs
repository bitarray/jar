//! PVM2 guest virtual-address-space layout (ABI constants).
//!
//! These constants define where a transpiler-emitted Image's code and
//! data regions map in the guest's 32-bit address space. They are part
//! of the PVM2 ABI contract: the transpiler (`javm-transpiler`) bakes
//! `PC = CODE_BASE + byte_offset` into endpoint entry PCs and native
//! `auipc`/`jalr` resolution and lays data caps from [`DATA_BASE`] up,
//! and every runtime (`nub-arch-x86`, `nub-arch-local`, `javm`) maps
//! `Image.code` read-only at `CODE_BASE` and data at `DATA_BASE`.
//!
//! The constants live here in `javm-cap` because it is the only crate
//! every producer (transpiler) and consumer (each runtime) depends on.
//! Code placement is a fixed protocol constant rather than an
//! Image-supplied mapping entry: an untrusted Image must not get to
//! choose where its code lands.
//!
//! ```text
//!   [0,         CODE_BASE)  unmapped — NULL guard (catch PC=0 / null deref)
//!   [CODE_BASE, DATA_BASE)  CODE     — RO, ≤ MAX_CODE_SIZE bytes
//!   [DATA_BASE, 4 GiB)      DATA     — stack / ro / rw / heap, RO|RW
//! ```
//!
//! Code low (4 MiB) gives the null guard; data high (256 MiB) keeps the
//! whole data region contiguous above code instead of wrapping around
//! it. Both `[0, CODE_BASE)` and `[CODE_BASE + code, DATA_BASE)` are
//! unmapped, so a stray fetch or load there faults.

/// Guest virtual address where the (single) code region maps read-only.
/// A PVM PC is `CODE_BASE + byte_offset`. Sits at 4 MiB so `[0, 4 MiB)`
/// is an unmapped null guard.
pub const CODE_BASE: u32 = 0x0040_0000;

/// Guest virtual address where the data region begins. All data caps
/// (stack / ro / rw / heap) and instance overlays live in `[DATA_BASE,
/// 4 GiB)`. At 256 MiB, well clear of the largest permitted code region.
pub const DATA_BASE: u32 = 0x1000_0000;

/// Maximum byte length of the code region. Code occupies `[CODE_BASE,
/// CODE_BASE + code_len)` and must stay below `DATA_BASE`, so
/// `code_len ≤ DATA_BASE − CODE_BASE` = 252 MiB.
pub const MAX_CODE_SIZE: u32 = DATA_BASE - CODE_BASE;
