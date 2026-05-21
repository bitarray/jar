//! Inline-asm wrappers around the kernel's `ecall` interface.
//! Identical to `spawn-child-s`'s wrappers — kept as a small local
//! copy until `subsoil` grows a shared ecall ABI module.

#![allow(dead_code, unsafe_op_in_unsafe_fn)]

const OP_MGMT_COPY: u64 = 1;
const OP_MGMT_CNODE_MINT: u64 = 5;
const OP_DERIVE_SPAWN: u64 = 18;
const OP_HOST_READ_DATA_CAP: u64 = 22;
const OP_HOST_MINT_DATA_CAP: u64 = 23;
const OP_HOST_CALL: u64 = 26;

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
