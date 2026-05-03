//! Simple example chain: ed25519-signed balance transfers over an
//! account model.
//!
//! Vault.initialize body. Kernel-injected caps live in BareFrame;
//! persistent storage lives in `vault.slots`, accessed via the home
//! VaultRef.
//!
//! Startup:
//!   1. MGMT_COPY BareFrame[home VaultRef] → MainFrame[1] so we have
//!      a stable handle for foreign-frame ops.
//!   2. CALL BareFrame[CallerKernel] → role (verify or process).
//!   3. Map args into the heap region.
//!   4. Branch to verify_handler or process_handler.
//!
//! Verify handler:
//!   - Copy MintAttestCap and SetScore from BareFrame into MainFrame
//!     for plain ecalli access.
//!   - Validate ed25519 sig via mint_attest_cap. Bad sig → panic the
//!     invocation.
//!   - setScore (RC_OK in dispatch verify; RC_READONLY in transact
//!     verify — ignore).
//!
//! Process handler:
//!   - MGMT_COPY foreign(home_vault.slots[100]) → MainFrame[16]
//!     (account-map clone).
//!   - MGMT_MAP MainFrame[16] @ vaddr.
//!   - Apply debit/credit.
//!   - MGMT_DROP foreign(home_vault.slots[100]) — clear σ slot.
//!   - MGMT_COPY MainFrame[16] → foreign(home_vault.slots[100]) —
//!     write back.
//!   - Halt. The kernel's `foreign_cnode::set` reads MainFrame[16]'s
//!     post-execution pages from BackingStore and persists them.
//!
//! Transaction wire format (144 bytes):
//!   0..32   from pubkey
//!   32..64  to pubkey
//!   64..72  amount (u64 LE)
//!   72..80  nonce  (u64 LE)
//!   80..144 ed25519 signature
//!
//! Account-map layout (1 page = 64 records × 64 bytes):
//!   0..32   pubkey
//!   32..40  balance (u64 LE)
//!   40..48  nonce   (u64 LE — next expected)
//!   48..64  reserved

#![cfg_attr(target_env = "javm", no_std)]
#![cfg_attr(target_env = "javm", no_main)]

#[cfg(target_env = "javm")]
javm_builtins::javm_entry!(simple_chain_init);

#[cfg(not(target_env = "javm"))]
fn main() {}

// =============================================================================
// ABI constants — mirror jar-kernel/src/vm/host_abi.rs.
// =============================================================================

#[cfg(target_env = "javm")]
mod abi {
    // BareFrame slots (kernel-injected).
    pub const BARE_HOME_VAULT_SLOT: u8 = 7;
    pub const BARE_CALLER_KERNEL_SLOT: u8 = 8;
    #[allow(dead_code)]
    pub const BARE_EMIT_EVENT_SLOT: u8 = 11;
    pub const BARE_MINT_ATTEST_CAP_SLOT: u8 = 12;
    pub const BARE_SET_SCORE_SLOT: u8 = 13;

    // Where we relocate kernel caps in MainFrame for plain `ecalli`.
    pub const MAIN_HOME_VAULT_SLOT: u8 = 1;
    pub const MAIN_MINT_SLOT: u8 = 5;
    pub const MAIN_SETSCORE_SLOT: u8 = 6;
    pub const MAIN_ATTESTATION_DST_SLOT: u8 = 7;

    // Slot in vault.slots holding the account-map.
    pub const ACCOUNT_MAP_VAULT_SLOT: u8 = 100;
    /// Where we COPY-in the account-map for use during process.
    /// Above the manifest-claimed range (64=code, 65=stack, 66=ro,
    /// 67=rw, 68=heap, 69=args).
    pub const WORK_DATACAP_SLOT: u8 = 16;

    pub const RC_OK: u64 = 0;
    pub const ROLE_VERIFY: u64 = 0;
    pub const ROLE_PROCESS: u64 = 1;

    pub const TXN_LEN: usize = 144;
    pub const RECORD_LEN: usize = 64;
    pub const ACCOUNT_MAP_PAGES: u32 = 1;
    pub const ACCOUNT_MAP_RECORDS: usize = 64;

    // PVM ecall ops (for `csrw 0x800; ecall`).
    pub const OP_MGMT_MAP: u64 = 2;
    pub const OP_MGMT_DROP: u64 = 5;
    pub const OP_MGMT_COPY: u64 = 7;

    // Access bits for MGMT_MAP.
    pub const ACCESS_RW: u64 = 1;
}

#[cfg(target_env = "javm")]
use abi::*;

// =============================================================================
// Guest entry
// =============================================================================

#[cfg(target_env = "javm")]
#[unsafe(no_mangle)]
extern "C" fn simple_chain_init(args_len: u64) -> u64 {
    // 1. Promote home VaultRef from BareFrame to MainFrame so plain
    //    cap-refs reach `vault.slots` via slot 1.
    if !mgmt_copy_bare_to_main(BARE_HOME_VAULT_SLOT, MAIN_HOME_VAULT_SLOT) {
        panic_loop();
    }

    let args = javm_builtins::map_args(args_len);
    if args.len() < TXN_LEN {
        return RC_OK; // Schedule slot or pre-genesis block_init — nothing to do.
    }
    let txn = parse_txn(&args[..TXN_LEN]);

    match caller_role() {
        ROLE_VERIFY => verify_handler(&txn),
        ROLE_PROCESS => process_handler(&txn),
        _ => panic_loop(),
    }
}

/// Verify path: ed25519 sig check, then setScore. ro-σ.
#[cfg(target_env = "javm")]
fn verify_handler(txn: &Txn) -> u64 {
    if !mgmt_copy_bare_to_main(BARE_MINT_ATTEST_CAP_SLOT, MAIN_MINT_SLOT) {
        panic_loop();
    }
    if !mgmt_copy_bare_to_main(BARE_SET_SCORE_SLOT, MAIN_SETSCORE_SLOT) {
        panic_loop();
    }

    let msg = canonical_message(txn);
    if mint_attest_cap(MAIN_ATTESTATION_DST_SLOT, &txn.from, &msg, &txn.sig) != RC_OK {
        panic_loop();
    }

    let mut id = [0u8; 40];
    id[..32].copy_from_slice(&txn.from);
    id[32..40].copy_from_slice(&txn.nonce.to_le_bytes());
    let _ = set_score(&id, txn.amount);

    RC_OK
}

/// Process path: read account-map from σ via the home VaultRef,
/// apply the debit/credit, write the post-state back.
#[cfg(target_env = "javm")]
fn process_handler(txn: &Txn) -> u64 {
    // 1. COPY-in: foreign(home_vault.slots[100]) → MainFrame[16].
    if !mgmt_copy_foreign_to_main(
        MAIN_HOME_VAULT_SLOT,
        ACCOUNT_MAP_VAULT_SLOT,
        WORK_DATACAP_SLOT,
    ) {
        panic_loop();
    }

    // 2. MGMT_MAP MainFrame[16] @ a guest-chosen vaddr.
    let map_addr = mgmt_map(WORK_DATACAP_SLOT, ACCOUNT_MAP_BASE_PAGE, ACCOUNT_MAP_PAGES);
    let map = unsafe {
        core::slice::from_raw_parts_mut(map_addr as *mut u8, ACCOUNT_MAP_PAGES as usize * 4096)
    };

    // 3. Mutate the map.
    if !apply_transfer(map, txn) {
        panic_loop();
    }

    // 4. DROP the σ slot, then COPY MainFrame[16] back to it.
    if !mgmt_drop_foreign(MAIN_HOME_VAULT_SLOT, ACCOUNT_MAP_VAULT_SLOT) {
        panic_loop();
    }
    if !mgmt_copy_main_to_foreign(
        WORK_DATACAP_SLOT,
        MAIN_HOME_VAULT_SLOT,
        ACCOUNT_MAP_VAULT_SLOT,
    ) {
        panic_loop();
    }

    RC_OK
}

/// Read the kernel role from BareFrame[CallerKernel]. Returns
/// 0 (Verify) or 1 (Process).
#[cfg(target_env = "javm")]
fn caller_role() -> u64 {
    // Dynamic CALL via cap-ref to BareFrame[CALLER_KERNEL_SLOT].
    let cap_ref = (BARE_CALLER_KERNEL_SLOT as u64) << 8;
    let phi12 = cap_ref << 32;
    let mut role: u64;
    unsafe {
        core::arch::asm!(
            "csrw 0x800, zero",
            "ecall",
            in("a4") 0u64,        // op = Dynamic CALL
            in("a5") phi12,       // (subject_ref << 32) | 0
            lateout("a0") role,
            // The kernel writes φ[7]=a0 (role) AND φ[8]=a1 (status=0)
            // on `CallOutcome::Resume`. Declare a1 clobbered so the
            // compiler doesn't keep a live value in it across the
            // ecall.
            lateout("a1") _,
            lateout("a4") _,
            lateout("a5") _,
        );
    }
    role
}

#[cfg(target_env = "javm")]
fn panic_loop() -> ! {
    unsafe {
        core::arch::asm!("unimp", options(noreturn));
    }
}

// =============================================================================
// MGMT helpers
// =============================================================================

/// Address (in pages) where the account-map gets MGMT_MAP'd. Above
/// the manifest-laid-out [stack, ro, rw, heap, args] region.
#[cfg(target_env = "javm")]
const ACCOUNT_MAP_BASE_PAGE: u64 = 64;

/// MGMT_COPY subject_ref → object_ref. Returns true on success.
///
/// `ecall_copy` writes `RESULT_WHAT` (= `u64::MAX - 1`) to φ[7] on
/// failure and leaves φ[7] untouched on success. We initialize φ[7]
/// to 0 going in so the post-call value reliably distinguishes the
/// two cases.
#[cfg(target_env = "javm")]
fn mgmt_copy(subject_ref: u32, object_ref: u32) -> bool {
    let phi12 = ((subject_ref as u64) << 32) | (object_ref as u64);
    let mut rc: u64 = 0;
    unsafe {
        core::arch::asm!(
            "csrw 0x800, zero",
            "ecall",
            inout("a0") rc,
            in("a4") OP_MGMT_COPY,
            in("a5") phi12,
            lateout("a4") _,
            lateout("a5") _,
        );
    }
    rc == 0
}

#[cfg(target_env = "javm")]
fn mgmt_copy_bare_to_main(bare_slot: u8, main_slot: u8) -> bool {
    let subject_ref = (bare_slot as u32) << 8; // (slot, ind0=0) → BareFrame[slot]
    let object_ref = main_slot as u32; // direct MainFrame slot
    mgmt_copy(subject_ref, object_ref)
}

#[cfg(target_env = "javm")]
fn mgmt_copy_foreign_to_main(home_main_slot: u8, foreign_slot: u8, main_slot: u8) -> bool {
    let subject_ref = ((home_main_slot as u32) << 8) | (foreign_slot as u32);
    let object_ref = main_slot as u32;
    mgmt_copy(subject_ref, object_ref)
}

#[cfg(target_env = "javm")]
fn mgmt_copy_main_to_foreign(main_slot: u8, home_main_slot: u8, foreign_slot: u8) -> bool {
    let subject_ref = main_slot as u32;
    let object_ref = ((home_main_slot as u32) << 8) | (foreign_slot as u32);
    mgmt_copy(subject_ref, object_ref)
}

/// MGMT_DROP at foreign(home_main_slot → foreign_slot). Returns true
/// on success.
#[cfg(target_env = "javm")]
fn mgmt_drop_foreign(home_main_slot: u8, foreign_slot: u8) -> bool {
    let subject_ref = ((home_main_slot as u32) << 8) | (foreign_slot as u32);
    let phi12 = (subject_ref as u64) << 32;
    let mut rc: u64 = 0;
    unsafe {
        core::arch::asm!(
            "csrw 0x800, zero",
            "ecall",
            inout("a0") rc,
            in("a4") OP_MGMT_DROP,
            in("a5") phi12,
            lateout("a4") _,
            lateout("a5") _,
        );
    }
    rc == 0
}

/// MGMT_MAP MainFrame[slot] @ base_page * 4096, RW.
/// Returns the byte address of the mapping.
#[cfg(target_env = "javm")]
fn mgmt_map(slot: u8, base_page: u64, page_count: u32) -> u64 {
    let map_refs: u64 = (slot as u64) << 32;
    unsafe {
        core::arch::asm!(
            "csrw 0x800, zero",
            "ecall",
            in("a0") base_page,
            in("a1") 0u64,
            in("a2") page_count as u64,
            in("a3") ACCESS_RW,
            in("a4") OP_MGMT_MAP,
            in("a5") map_refs,
            lateout("a0") _,
            lateout("a1") _,
            lateout("a2") _,
            lateout("a3") _,
            lateout("a4") _,
            lateout("a5") _,
        );
    }
    base_page * 4096
}

// =============================================================================
// Transaction parsing
// =============================================================================

#[cfg(target_env = "javm")]
struct Txn {
    from: [u8; 32],
    to: [u8; 32],
    amount: u64,
    nonce: u64,
    sig: [u8; 64],
}

#[cfg(target_env = "javm")]
fn parse_txn(bytes: &[u8]) -> Txn {
    debug_assert!(bytes.len() >= TXN_LEN);
    let mut from = [0u8; 32];
    from.copy_from_slice(&bytes[0..32]);
    let mut to = [0u8; 32];
    to.copy_from_slice(&bytes[32..64]);
    let amount = u64::from_le_bytes(bytes[64..72].try_into().unwrap());
    let nonce = u64::from_le_bytes(bytes[72..80].try_into().unwrap());
    let mut sig = [0u8; 64];
    sig.copy_from_slice(&bytes[80..144]);
    Txn {
        from,
        to,
        amount,
        nonce,
        sig,
    }
}

#[cfg(target_env = "javm")]
fn canonical_message(t: &Txn) -> [u8; 80] {
    let mut buf = [0u8; 80];
    buf[0..32].copy_from_slice(&t.from);
    buf[32..64].copy_from_slice(&t.to);
    buf[64..72].copy_from_slice(&t.amount.to_le_bytes());
    buf[72..80].copy_from_slice(&t.nonce.to_le_bytes());
    buf
}

// =============================================================================
// Account-map application
// =============================================================================

#[cfg(target_env = "javm")]
fn apply_transfer(map: &mut [u8], t: &Txn) -> bool {
    let from_idx = match find_record(map, &t.from) {
        Some(i) => i,
        None => return false,
    };

    let from_balance = u64::from_le_bytes(map[from_idx + 32..from_idx + 40].try_into().unwrap());
    let from_nonce = u64::from_le_bytes(map[from_idx + 40..from_idx + 48].try_into().unwrap());

    if t.nonce != from_nonce || from_balance < t.amount {
        return false;
    }

    let new_from_balance = from_balance - t.amount;
    let new_from_nonce = from_nonce + 1;
    map[from_idx + 32..from_idx + 40].copy_from_slice(&new_from_balance.to_le_bytes());
    map[from_idx + 40..from_idx + 48].copy_from_slice(&new_from_nonce.to_le_bytes());

    let to_idx = match find_record(map, &t.to) {
        Some(i) => i,
        None => match find_empty(map) {
            Some(i) => {
                map[i..i + 32].copy_from_slice(&t.to);
                i
            }
            None => return false,
        },
    };
    let to_balance = u64::from_le_bytes(map[to_idx + 32..to_idx + 40].try_into().unwrap());
    let new_to_balance = to_balance.saturating_add(t.amount);
    map[to_idx + 32..to_idx + 40].copy_from_slice(&new_to_balance.to_le_bytes());

    true
}

#[cfg(target_env = "javm")]
fn find_record(map: &[u8], pubkey: &[u8; 32]) -> Option<usize> {
    for i in 0..ACCOUNT_MAP_RECORDS {
        let off = i * RECORD_LEN;
        if &map[off..off + 32] == pubkey {
            return Some(off);
        }
    }
    None
}

#[cfg(target_env = "javm")]
fn find_empty(map: &[u8]) -> Option<usize> {
    let zero = [0u8; 32];
    for i in 0..ACCOUNT_MAP_RECORDS {
        let off = i * RECORD_LEN;
        if map[off..off + 32] == zero {
            return Some(off);
        }
    }
    None
}

// =============================================================================
// ecalli wrappers (plain CALL on a MainFrame slot)
// =============================================================================

/// `mint_attest_cap(dst_slot, key, blob, sig)` — verify-only sig
/// check. CALLs the cap at MainFrame[MAIN_MINT_SLOT].
#[cfg(target_env = "javm")]
fn mint_attest_cap(dst_slot: u8, key: &[u8; 32], blob: &[u8], sig: &[u8; 64]) -> u64 {
    let mut rc: u64;
    unsafe {
        core::arch::asm!(
            "li t0, {slot}",
            "ecall",
            slot = const MAIN_MINT_SLOT as u32,
            in("a0") dst_slot as u64,
            in("a1") key.as_ptr() as u64,
            in("a2") blob.as_ptr() as u64,
            in("a3") blob.len() as u64,
            in("a4") sig.as_ptr() as u64,
            lateout("a0") rc,
            lateout("a1") _,
            lateout("a2") _,
            lateout("a3") _,
            lateout("a4") _,
            lateout("t0") _,
        );
    }
    rc
}

/// `setScore(identifier, score)`. CALLs MainFrame[MAIN_SETSCORE_SLOT].
#[cfg(target_env = "javm")]
fn set_score(identifier: &[u8], score: u64) -> u64 {
    let mut rc: u64;
    unsafe {
        core::arch::asm!(
            "li t0, {slot}",
            "ecall",
            slot = const MAIN_SETSCORE_SLOT as u32,
            in("a0") identifier.as_ptr() as u64,
            in("a1") identifier.len() as u64,
            in("a2") score,
            lateout("a0") rc,
            lateout("a1") _,
            lateout("a2") _,
            lateout("t0") _,
        );
    }
    rc
}
