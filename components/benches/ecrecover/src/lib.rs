//! secp256k1 ecrecover benchmark — runs a single ECDSA public key recovery.

#![cfg_attr(target_os = "none", no_std)]

use javm_builtins as _;

// ---------------------------------------------------------------------------
// Bump allocator — k256 needs alloc for internal operations.
// Single ecrecover uses bounded memory; no deallocation needed.
// ---------------------------------------------------------------------------

#[cfg(target_os = "none")]
extern crate alloc;

#[cfg(target_os = "none")]
mod bump_alloc {
    use core::alloc::{GlobalAlloc, Layout};
    use core::cell::UnsafeCell;

    const HEAP_SIZE: usize = 64 * 1024; // 64 KB

    pub struct BumpAlloc {
        heap: UnsafeCell<[u8; HEAP_SIZE]>,
        pos: UnsafeCell<usize>,
    }

    unsafe impl Sync for BumpAlloc {}

    unsafe impl GlobalAlloc for BumpAlloc {
        unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
            let pos = unsafe { &mut *self.pos.get() };
            let aligned = (*pos + layout.align() - 1) & !(layout.align() - 1);
            let next = aligned + layout.size();
            if next > HEAP_SIZE {
                return core::ptr::null_mut();
            }
            *pos = next;
            unsafe { (*self.heap.get()).as_mut_ptr().add(aligned) }
        }

        unsafe fn dealloc(&self, _ptr: *mut u8, _layout: Layout) {}
    }

    #[global_allocator]
    pub static ALLOC: BumpAlloc = BumpAlloc {
        heap: UnsafeCell::new([0; HEAP_SIZE]),
        pos: UnsafeCell::new(0),
    };
}

// ---------------------------------------------------------------------------
// Test vector (generated from a known private key, verified on host)
// ---------------------------------------------------------------------------

const MSG_HASH: [u8; 32] = [
    0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99,
    0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99,
];

const SIGNATURE: [u8; 64] = [
    0xff, 0x65, 0x1c, 0x65, 0xee, 0xde, 0xd4, 0x63, 0x83, 0xa4, 0xbd, 0xcd, 0x91, 0x70, 0xff, 0x65,
    0x9a, 0x4f, 0x61, 0x7b, 0xb6, 0x58, 0xa4, 0x6d, 0xd4, 0x56, 0xc5, 0x1e, 0xc8, 0xcc, 0x21, 0x1a,
    0x7d, 0xc4, 0xde, 0x91, 0xd0, 0xc8, 0x47, 0xbf, 0x5d, 0xef, 0x99, 0x5b, 0xd0, 0x43, 0x65, 0x81,
    0x36, 0xfe, 0x21, 0x35, 0xaf, 0xe6, 0x92, 0x82, 0xf7, 0xde, 0x87, 0x39, 0x90, 0xda, 0xcb, 0x77,
];

const RECOVERY_ID: u8 = 1;

const EXPECTED_PUBKEY: [u8; 33] = [
    0x02, 0x84, 0xbf, 0x75, 0x62, 0x26, 0x2b, 0xbd, 0x69, 0x40, 0x08, 0x57, 0x48, 0xf3, 0xbe, 0x6a,
    0xfa, 0x52, 0xae, 0x31, 0x71, 0x55, 0x18, 0x1e, 0xce, 0x31, 0xb6, 0x63, 0x51, 0xcc, 0xff, 0xa4,
    0xb0,
];

#[cfg(target_env = "polkavm")]
mod polkavm;

/// Perform ecrecover: recover the public key from a signature + message hash.
/// Returns 1 if the recovered key matches the expected public key, 0 otherwise.
pub fn ecrecover_bench() -> u32 {
    let sig = match k256::ecdsa::Signature::from_slice(&SIGNATURE) {
        Ok(s) => s,
        Err(_) => return 0,
    };
    let recid = k256::ecdsa::RecoveryId::new(RECOVERY_ID & 1 != 0, RECOVERY_ID & 2 != 0);

    match k256::ecdsa::VerifyingKey::recover_from_prehash(&MSG_HASH, &sig, recid) {
        Ok(key) => {
            let pubkey = key.to_encoded_point(true);
            let pubkey_bytes = pubkey.as_bytes();
            if pubkey_bytes.len() != EXPECTED_PUBKEY.len() {
                return 0;
            }
            let mut i = 0;
            while i < EXPECTED_PUBKEY.len() {
                if pubkey_bytes[i] != EXPECTED_PUBKEY[i] {
                    return 0;
                }
                i += 1;
            }
            1
        }
        Err(_) => 0,
    }
}
