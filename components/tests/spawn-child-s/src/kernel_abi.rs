//! Inline-asm wrappers around the kernel's `ecall` interface.
//!
//! All host calls go through the RISC-V `ecall` instruction with a
//! preceding `csrw 0x800, zero` marker (the [`javm-transpiler`]
//! emits PVM opcode 3 — `ecall` — for this sequence). The kernel
//! reads the op code from `φ[11]` (a4) and the operands from
//! `φ[7..=10]` (a0..a3). On return, `φ[7]` (a0) carries the
//! kernel's response if any.
//!
//! V1: no quota threading. `host_mint_data_cap`'s `quota_id`
//! register slot is passed as 0 and ignored by `SigmaKernelAssist`
//! when the seeded quota is zero.

#![allow(dead_code, unsafe_op_in_unsafe_fn)]

const OP_MGMT_COPY: u64 = 1;
const OP_MGMT_CNODE_MINT: u64 = 5;
const OP_DERIVE_SPAWN: u64 = 18;
const OP_HOST_READ_DATA_CAP: u64 = 22;
const OP_HOST_MINT_DATA_CAP: u64 = 23;
const OP_HOST_CALL: u64 = 26;

/// `mgmt_cnode_mint(dst=φ[7], size_log=φ[8])`. Mints a fresh empty
/// `Cap::CNode` of `2^size_log` slots and places it at the given
/// slot in the running cnode.
#[inline]
pub unsafe fn mgmt_cnode_mint(dst: u8, size_log: u8) {
    core::arch::asm!(
        "csrw 0x800, zero",
        "ecall",
        inlateout("a0") dst as u64 => _,
        inlateout("a1") size_log as u64 => _,
        inlateout("a4") OP_MGMT_CNODE_MINT => _,
        lateout("a2") _,
        lateout("a3") _,
        lateout("a5") _,
        options(nostack, preserves_flags),
    );
}

/// `mgmt_copy(src=φ[7], dst=φ[8])`. Copies the target in `src` to
/// `dst` within the running cnode.
#[inline]
pub unsafe fn mgmt_copy(src: u8, dst: u8) {
    core::arch::asm!(
        "csrw 0x800, zero",
        "ecall",
        inlateout("a0") src as u64 => _,
        inlateout("a1") dst as u64 => _,
        inlateout("a4") OP_MGMT_COPY => _,
        lateout("a2") _,
        lateout("a3") _,
        lateout("a5") _,
        options(nostack, preserves_flags),
    );
}

/// `host_derive_spawn(image=φ[7], cnode=φ[8], dst=φ[9])`. Consume the
/// prepared `Cap::CNode` at `cnode`, mint a fresh `Cap::Instance`
/// referencing the `Cap::Image` at `image`, and place it at `dst`.
#[inline]
pub unsafe fn host_derive_spawn(image: u8, cnode: u8, dst: u8) {
    core::arch::asm!(
        "csrw 0x800, zero",
        "ecall",
        inlateout("a0") image as u64 => _,
        inlateout("a1") cnode as u64 => _,
        inlateout("a2") dst as u64 => _,
        inlateout("a4") OP_DERIVE_SPAWN => _,
        lateout("a3") _,
        lateout("a5") _,
        options(nostack, preserves_flags),
    );
}

/// `host_call(instance=φ[7], endpoint=φ[8])`. Push a child
/// `InstanceEntry` and transfer caller's `slot[0]` into the child's
/// `slot[0]`. Returns when the child halts; the child's `slot[0]`
/// is reflected back into the caller's `slot[0]`.
#[inline]
pub unsafe fn host_call(instance: u8, endpoint: u8) {
    core::arch::asm!(
        "csrw 0x800, zero",
        "ecall",
        inlateout("a0") instance as u64 => _,
        inlateout("a1") endpoint as u64 => _,
        inlateout("a4") OP_HOST_CALL => _,
        lateout("a2") _,
        lateout("a3") _,
        lateout("a5") _,
        options(nostack, preserves_flags),
    );
}

/// `host_read_data_cap(src=φ[7], dst_offset=φ[8], len=φ[9])` → φ[7].
/// Reads up to `len` bytes from the `Cap::Data` at slot `src` into
/// memory at `dst_offset`. Returns the actual byte count read.
#[inline]
pub unsafe fn host_read_data_cap(src: u8, dst_offset: u32, len: u64) -> u64 {
    let n_read: u64;
    core::arch::asm!(
        "csrw 0x800, zero",
        "ecall",
        inlateout("a0") src as u64 => n_read,
        inlateout("a1") dst_offset as u64 => _,
        inlateout("a2") len => _,
        inlateout("a4") OP_HOST_READ_DATA_CAP => _,
        lateout("a3") _,
        lateout("a5") _,
        options(nostack, preserves_flags),
    );
    n_read
}

/// `host_mint_data_cap(src_offset=φ[7], len=φ[8], quota_id=φ[9],
/// dst=φ[10])`. Reads `len` bytes at `src_offset` from memory,
/// strips trailing zeros to get canonical content, mints a fresh
/// `Cap::Data`, and places it at slot `dst`. V1: `quota_id`
/// argument is currently a no-op when the seeded quota is zero.
#[inline]
pub unsafe fn host_mint_data_cap(src_offset: u32, len: u64, quota_id: u64, dst: u8) {
    core::arch::asm!(
        "csrw 0x800, zero",
        "ecall",
        inlateout("a0") src_offset as u64 => _,
        inlateout("a1") len => _,
        inlateout("a2") quota_id => _,
        inlateout("a3") dst as u64 => _,
        inlateout("a4") OP_HOST_MINT_DATA_CAP => _,
        lateout("a5") _,
        options(nostack, preserves_flags),
    );
}
