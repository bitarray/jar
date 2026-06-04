//! Inline-asm wrappers around the kernel's `ecall` interface for
//! the recursive-spawn bench guest. Trimmed to just the two
//! operations the bench uses: `host_derive_spawn` (op 18) and a
//! depth-passing form of `host_call` (op 26) that lands the caller's
//! `arg` in `a2` so the kernel can forward it as the child's φ[7].

#![allow(dead_code, unsafe_op_in_unsafe_fn)]

const OP_DERIVE_SPAWN: u64 = 18;
const OP_HOST_CALL: u64 = 26;

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

/// `host_call(instance, endpoint)` with a single u64 arg threaded
/// via `a2` (= φ[9]). The kernel's HOST_CALL handler maps φ[9..=10]
/// → child's φ[7..=8] and zeros higher arg slots; we only use one.
#[inline]
pub unsafe fn host_call_with_arg(instance: u8, endpoint: u8, arg: u64) {
    core::arch::asm!(
        "csrw 0x800, zero",
        "ecall",
        inlateout("a0") instance as u64 => _,
        inlateout("a1") endpoint as u64 => _,
        inlateout("a2") arg => _,
        inlateout("a4") OP_HOST_CALL => _,
        lateout("a3") _,
        lateout("a5") _,
        options(nostack, preserves_flags),
    );
}
