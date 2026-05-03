//! Simple-chain genesis: one transact + one dispatch endpoint, both
//! using the simple-chain blob; pre-funded account-map DataCap; PoA
//! validator schedule.

use std::sync::Arc;

use jar_kernel::cap::{CodeCap, DataCap, RegCap};
use jar_kernel::{EventEndpointCap, KeyId, State, Vault};

/// Slot in the transact vault holding the account-map DataCap.
/// Chosen to be above the simple-chain blob's manifest-claimed slots
/// (64 = code, 65 = stack, 68 = heap).
pub const ACCOUNT_MAP_SLOT: u8 = 100;
/// Slot in every vault holding the init CodeCap (matches the
/// jar-kernel default + simple-chain's `_start` discovery convention).
pub const INIT_SLOT: u8 = 64;

/// Build a `State` with:
/// - `validators` populated for round-robin PoA.
/// - One transact endpoint at slot 0 of `transact_endpoints` (the
///   simple-chain Vault).
/// - One dispatch endpoint at slot 0 of `dispatch_endpoints` (same
///   Vault).
/// - The transact Vault's slot 65 prefilled with the genesis
///   account-map (each `(pubkey, balance)` becomes one 64-byte
///   record; nonce starts at 0).
pub fn build(validators: &[KeyId], accounts: &[(KeyId, u64)]) -> State {
    let mut state = State::empty();
    state.validators = validators.to_vec();

    // Allocate the chain Vault.
    let vault_id = state.next_vault_id();
    let mut vault = Vault::new();
    vault.init_cap = INIT_SLOT;

    // CodeCap at slot 64 — the simple-chain blob.
    let parsed = javm::program::parse_blob(crate::SIMPLE_CHAIN_BLOB)
        .expect("simple-chain JAR blob is well-formed");
    let code_entry = parsed
        .caps
        .iter()
        .find(|e| matches!(e.cap_type, javm::program::CapEntryType::Code))
        .expect("simple-chain blob has a CODE manifest entry");
    let code_blob = javm::program::cap_data(code_entry, parsed.data_section).to_vec();
    vault.slots.set(
        code_entry.cap_index,
        Some(RegCap::Code(CodeCap {
            blob: Arc::new(code_blob),
        })),
    );

    // Pre-populate manifest-declared DataCaps (stack, heap). The
    // transpiler-emitted prologue MGMT_MAPs each at PC=0 of every
    // invocation; the kernel must have a matching DataCap at the
    // declared cap_index. Initial content is the manifest's
    // `data_section` slice (zeroed for stack/heap entries that have
    // `data_len == 0`).
    for entry in &parsed.caps {
        if !matches!(entry.cap_type, javm::program::CapEntryType::Data) {
            continue;
        }
        let initial = if entry.data_len > 0 {
            javm::program::cap_data(entry, parsed.data_section).to_vec()
        } else {
            Vec::new()
        };
        vault.slots.set(
            entry.cap_index,
            Some(RegCap::Data(DataCap {
                content: Arc::new(initial),
                page_count: entry.page_count,
            })),
        );
    }

    // DataCap at slot 65 — pre-funded account map (1 page = 64
    // records × 64 bytes).
    let mut map = vec![0u8; 4096];
    for (i, (key, balance)) in accounts.iter().enumerate() {
        assert!(i < 64, "too many genesis accounts (max 64)");
        assert_eq!(key.0.len(), 32, "ed25519 pubkey must be 32 bytes");
        let off = i * 64;
        map[off..off + 32].copy_from_slice(&key.0);
        map[off + 32..off + 40].copy_from_slice(&balance.to_le_bytes());
        // nonce starts at 0 (already zeroed).
    }
    vault.slots.set(
        ACCOUNT_MAP_SLOT,
        Some(RegCap::Data(DataCap {
            content: Arc::new(map),
            page_count: 1,
        })),
    );

    state.vaults.insert(vault_id, Arc::new(vault));

    // Endpoints: one transact, one dispatch, both pointing at the
    // simple-chain vault. Generous gas/memory to keep the example
    // simple.
    let endpoint = EventEndpointCap {
        vault_id,
        gas_budget: 100_000_000,
        memory_budget: 256,
    };
    state.transact_endpoints.push(endpoint);
    state.dispatch_endpoints.push(endpoint);

    state
}
