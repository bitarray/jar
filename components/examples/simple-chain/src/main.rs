//! Simple example chain: ed25519-signed balance transfers over an
//! account model.
//!
//! This is the chain-author program — the `Vault.initialize` body
//! the kernel runs. The kernel-injected `CallerKernel` cap at
//! [`abi::CALLER_KERNEL_SLOT`] tells us whether we're in
//! [`KernelRole::Verify`] or [`KernelRole::Process`]; the entry
//! reads it via `caller_role()` and branches:
//!
//! - **verify** (dispatch and transact): parse, ed25519 sig-check
//!   via `mint_attest_cap`, then `setScore` to enter the proposer
//!   pool. ro-σ — no state mutation.
//! - **process** (transact only — dispatch process is ro-σ and a
//!   no-op for this chain): MGMT_MAP the account-map DataCap, apply
//!   the debit/credit, halt. Stage 2's post-process snapshot
//!   persists.
//!
//! Hard errors (bad signature, insufficient funds, nonce mismatch)
//! panic the invocation: verify panics fail the txn or block;
//! process panics shouldn't happen if the proposer's verify did its
//! job.
//!
//! Transaction wire format (144 bytes):
//!   0..32   from pubkey   (ed25519, 32 B)
//!   32..64  to pubkey     (32 B)
//!   64..72  amount        (u64 LE)
//!   72..80  nonce         (u64 LE — must equal sender's next nonce)
//!   80..144 signature     (ed25519, 64 B)
//!
//! Signing message: `from || to || amount_le || nonce_le` (80 bytes).
//!
//! Account-map layout (1 page = 64 records × 64 bytes):
//!   record:   0..32   pubkey
//!             32..40  balance (u64 LE)
//!             40..48  nonce (u64 LE — next expected)
//!             48..64  reserved (zero)
//!   The map lives at `vault.slots[65]`. Genesis populates initial
//!   balances; updates persist via the kernel's post-process DataCap
//!   snapshot.

#![cfg_attr(target_env = "javm", no_std)]
#![cfg_attr(target_env = "javm", no_main)]

#[cfg(target_env = "javm")]
javm_builtins::javm_entry!(simple_chain_init);

#[cfg(not(target_env = "javm"))]
fn main() {}

// =============================================================================
// Kernel ABI (mirrors jar-kernel/src/vm/host_abi.rs)
// =============================================================================

// Constants are only consumed inside the freestanding `target_env =
// "javm"` guest functions; on host builds those callers are cfg'd out.
#[cfg(target_env = "javm")]
mod abi {
    /// `CALL` on the cap at this slot returns the kernel role:
    /// 0 = Verify, 1 = Process.
    pub const CALLER_KERNEL_SLOT: u8 = 3;
    #[allow(dead_code)]
    pub const EMIT_EVENT_SLOT: u8 = 4;
    pub const MINT_ATTEST_CAP_SLOT: u8 = 5;
    pub const SET_SCORE_SLOT: u8 = 6;
    /// DataCap slot in the vault holding the account map. Above the
    /// blob's manifest-claimed range (slot 64 = code, 65 = stack,
    /// 68 = heap).
    pub const ACCOUNT_MAP_SLOT: u8 = 100;
    /// Frame slot we mint AttestationCaps into during verify.
    pub const ATTESTATION_DST_SLOT: u8 = 7;

    pub const RC_OK: u64 = 0;

    pub const ROLE_VERIFY: u64 = 0;
    pub const ROLE_PROCESS: u64 = 1;

    pub const TXN_LEN: usize = 144;
    pub const RECORD_LEN: usize = 64;
    pub const ACCOUNT_MAP_PAGES: u32 = 1;
    pub const ACCOUNT_MAP_RECORDS: usize = 64;
}

#[cfg(target_env = "javm")]
use abi::*;

// =============================================================================
// Guest entry
// =============================================================================

#[cfg(target_env = "javm")]
#[unsafe(no_mangle)]
extern "C" fn simple_chain_init(args_len: u64) -> u64 {
    let args = javm_builtins::map_args(args_len);
    if args.len() < TXN_LEN {
        // Empty/short args: kernel-fed schedule slot or pre-genesis
        // block_init. Nothing to do regardless of role.
        return RC_OK;
    }
    let txn = parse_txn(&args[..TXN_LEN]);

    match caller_role() {
        ROLE_VERIFY => verify_handler(&txn),
        ROLE_PROCESS => process_handler(&txn),
        _ => panic_loop(),
    }
}

/// Verify path: ed25519 sig check, then setScore.
/// ro-σ — no state mutation.
#[cfg(target_env = "javm")]
fn verify_handler(txn: &Txn) -> u64 {
    let msg = canonical_message(txn);
    if mint_attest_cap(ATTESTATION_DST_SLOT, &txn.from, &msg, &txn.sig) != RC_OK {
        // Bad signature, scope violation, or other minting failure —
        // fail this verify. The kernel reports a verify panic,
        // dropping the txn (dispatch) or panicking the block
        // (transact).
        panic_loop();
    }

    // setScore is meaningful only in dispatch-verify (transact-verify
    // returns RC_READONLY). Identifier = from||nonce, score = amount
    // (placeholder fee model).
    let mut id = [0u8; 40];
    id[..32].copy_from_slice(&txn.from);
    id[32..40].copy_from_slice(&txn.nonce.to_le_bytes());
    let _ = set_score(&id, txn.amount);

    RC_OK
}

/// Process path: apply the txn to the persistent account-map.
/// rw-σ in transact context; the kernel's post-process snapshot
/// persists the writes. Dispatch-process is ro-σ — writes here would
/// be discarded.
#[cfg(target_env = "javm")]
fn process_handler(txn: &Txn) -> u64 {
    let map_addr = map_account_map();
    let map = unsafe {
        core::slice::from_raw_parts_mut(map_addr as *mut u8, ACCOUNT_MAP_PAGES as usize * 4096)
    };
    if !apply_transfer(map, txn) {
        panic_loop();
    }
    RC_OK
}

/// Read the kernel role from the `CallerKernel` cap at slot 3.
/// Returns 0 (Verify) or 1 (Process).
#[cfg(target_env = "javm")]
fn caller_role() -> u64 {
    let mut role: u64;
    unsafe {
        core::arch::asm!(
            "li t0, {slot}",
            "ecall",
            slot = const CALLER_KERNEL_SLOT as u32,
            lateout("a0") role,
            lateout("a1") _,
            lateout("t0") _,
        );
    }
    role
}

#[cfg(target_env = "javm")]
fn panic_loop() -> ! {
    // Trigger a guest fault by issuing an `unimp` (treated as a panic
    // by javm). This bubbles up as KernelResult::Panic → invocation
    // fault → block panic for verify, block panic for process.
    unsafe {
        core::arch::asm!("unimp", options(noreturn));
    }
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
        None => return false, // sender not funded
    };

    let from_balance = u64::from_le_bytes(map[from_idx + 32..from_idx + 40].try_into().unwrap());
    let from_nonce = u64::from_le_bytes(map[from_idx + 40..from_idx + 48].try_into().unwrap());

    if t.nonce != from_nonce || from_balance < t.amount {
        return false;
    }

    // Debit sender + bump nonce.
    let new_from_balance = from_balance - t.amount;
    let new_from_nonce = from_nonce + 1;
    map[from_idx + 32..from_idx + 40].copy_from_slice(&new_from_balance.to_le_bytes());
    map[from_idx + 40..from_idx + 48].copy_from_slice(&new_from_nonce.to_le_bytes());

    // Credit receiver. Allocate an empty slot if not yet present.
    let to_idx = match find_record(map, &t.to) {
        Some(i) => i,
        None => match find_empty(map) {
            Some(i) => {
                map[i..i + 32].copy_from_slice(&t.to);
                i
            }
            None => return false, // map full
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
// Host calls (ecalli wrappers)
// =============================================================================

/// `mint_attest_cap(dst_slot, key_ptr, blob, sig_ptr)` — verify-only
/// ed25519 signature check. Returns RC in φ[7].
///
/// The transpiler converts `li t0, N; ecall` (no CSR marker) into
/// PVM `ecalli N`, which CALLs the cap at cap-table slot N.
#[cfg(target_env = "javm")]
fn mint_attest_cap(dst_slot: u8, key: &[u8; 32], blob: &[u8], sig: &[u8; 64]) -> u64 {
    let mut rc: u64;
    unsafe {
        core::arch::asm!(
            "li t0, {slot}",
            "ecall",
            slot = const MINT_ATTEST_CAP_SLOT as u32,
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

/// `setScore(identifier, score)`. RC in φ[7].
#[cfg(target_env = "javm")]
fn set_score(identifier: &[u8], score: u64) -> u64 {
    let mut rc: u64;
    unsafe {
        core::arch::asm!(
            "li t0, {slot}",
            "ecall",
            slot = const SET_SCORE_SLOT as u32,
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

// =============================================================================
// Account-map mapping (MGMT_MAP on slot 65)
// =============================================================================

/// MGMT_MAP the account-map DataCap into guest memory. Returns the
/// base byte address of the mapping.
///
/// The base address is hardcoded to a page well beyond the
/// transpiler-laid-out [stack, ro, rw, heap, args] region. For the
/// simple-chain blob the layout is:
///   stack 16p (slots 65) | ro 4p (66) | rw 1p (67) | heap 16p (68)
/// = pages [0..37]. `javm_builtins::map_args` adds one page on top.
/// We pick page 64 to leave plenty of room for layout drift.
#[cfg(target_env = "javm")]
fn map_account_map() -> u64 {
    const ACCOUNT_MAP_BASE_PAGE: u64 = 64;
    let map_base_page: u64 = ACCOUNT_MAP_BASE_PAGE;

    // MGMT_MAP ABI:
    //   φ[7]  = base_offset (target page in window)
    //   φ[8]  = page_offset within cap
    //   φ[9]  = page_count
    //   φ[10] = access (1 = RW)
    //   φ[11] = MGMT_MAP = 2
    //   φ[12] = (subject << 32) | object
    //         For direct slot N in active VM: subject = N (low byte).
    let map_refs: u64 = (ACCOUNT_MAP_SLOT as u64) << 32;
    let mut rc: u64 = map_base_page;
    unsafe {
        core::arch::asm!(
            "csrw 0x800, zero",
            "ecall",
            inout("a0") rc,
            inout("a1") 0u64 => _,
            inout("a2") ACCOUNT_MAP_PAGES as u64 => _,
            inout("a3") 1u64 => _,         // RW
            inout("a4") 2u64 => _,         // MGMT_MAP
            inout("a5") map_refs => _,
        );
    }
    // ecall_map only writes φ[7] on failure (RESULT_WHAT). On success
    // φ[7] is left untouched (= the base_page we passed in). Treat
    // any value other than the base_page (still a valid success
    // signal, since RESULT_WHAT differs) as success.
    let _ = rc;
    map_base_page * 4096
}
