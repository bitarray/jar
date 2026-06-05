//! Inline-asm wrappers around the kernel's `ecall` interface for the
//! page-table-cache caller endpoint. Two ops: `derive_spawn` (op 18)
//! to mint the resident child once, and a return-value form of
//! `host_call` (op 26) that threads `arg` via `a2` (→ the callee's
//! `φ[7]`) and reads the callee's return value back out of `a0`.

#![allow(dead_code, unsafe_op_in_unsafe_fn)]

const OP_DERIVE_SPAWN: u64 = 18;
const OP_HOST_CALL: u64 = 26;

/// `derive_spawn(image=φ[7], cnode=φ[8], dst=φ[9])`: mint a fresh
/// `Cap::Instance` from the image in slot `image` (the kernel falls
/// back to the running frame's own image when that slot is empty) and
/// store it `Owned` in slot `dst`.
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

/// `host_call(instance=φ[7], endpoint=φ[8])` threading one u64 `arg`
/// via `a2` (= `φ[9]`, which the kernel maps onto the child's `φ[7]`).
/// Returns the callee's return value: the kernel writes it to the
/// caller's `φ[7]` (a0) before re-entering the caller right after this
/// `ecall`.
#[inline]
pub unsafe fn host_call_ret(instance: u8, endpoint: u8, arg: u64) -> u64 {
    let ret: u64;
    core::arch::asm!(
        "csrw 0x800, zero",
        "ecall",
        inlateout("a0") instance as u64 => ret,
        inlateout("a1") endpoint as u64 => _,
        inlateout("a2") arg => _,
        inlateout("a4") OP_HOST_CALL => _,
        lateout("a3") _,
        lateout("a5") _,
        options(nostack, preserves_flags),
    );
    ret
}
