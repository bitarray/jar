//! Simple-chain genesis: build an Image registered in `state.images`
//! holding the program template (Code + manifest file refs), and a
//! Vault that references the image with a pre-funded account-map
//! file referenced from its persistent storage cnode.

use std::sync::Arc;

use jar_kernel::cap::{CodeCap, FileCap, Image, QuotaCap, RegCap};
use jar_kernel::{EventEndpointCap, KeyId, State, Vault};

/// Slot in the Vault's storage cnode (NOT in the Frame) holding the
/// account-map FileCap. The guest reaches this via the home VaultRef
/// + foreign-frame mechanism.
pub const ACCOUNT_MAP_SLOT: u8 = 100;
/// Slot in the Vault's storage cnode holding the StorageQuotaCap
/// the program uses to bill new file/code mints.
pub const QUOTA_SLOT: u8 = 99;
/// Slot in the Image holding the init CodeCap (matches the
/// jar-kernel default + simple-chain's `_start` convention).
pub const INIT_SLOT: u8 = 64;

/// Build a `State` with:
/// - `validators` populated for round-robin PoA.
/// - A genesis StorageQuota (large pre-funded balance).
/// - An Image holding the simple-chain program (Code at slot 64,
///   manifest-derived stack/heap/ro/rw FileCaps at their declared slots).
/// - One Vault referencing the image, with the pre-funded
///   account-map FileCap at `vault.slots[ACCOUNT_MAP_SLOT]` and a
///   StorageQuotaCap at `vault.slots[QUOTA_SLOT]`.
/// - One transact endpoint and one dispatch endpoint, both
///   pointing at the same Vault.
pub fn build(validators: &[KeyId], accounts: &[(KeyId, u64)]) -> State {
    let mut state = State::empty();
    state.validators = validators.to_vec();

    // Genesis quota: covers all genesis-time interns + a generous
    // runtime budget for save/free churn.
    let genesis_quota = state.insert_storage_quota(u64::MAX / 2);

    let parsed = javm_legacy::program::parse_blob(crate::SIMPLE_CHAIN_BLOB)
        .expect("simple-chain JAR blob is well-formed");
    let code_entry = parsed
        .caps
        .iter()
        .find(|e| matches!(e.cap_type, javm_legacy::program::CapEntryType::Code))
        .expect("simple-chain blob has a CODE manifest entry");
    let code_sub_blob = javm_legacy::program::cap_data(code_entry, parsed.data_section).to_vec();
    let code_byte_count = code_sub_blob.len() as u64;
    let code_id = state
        .intern_code(code_sub_blob, genesis_quota)
        .expect("intern simple-chain code");
    // Image holds 1 σ-resident reference to this code blob.
    state.bump_code_refcount(code_id);

    // Build the Image: code at slot 64, manifest-derived data
    // file references at their declared slots (stack, ro, rw, heap).
    let mut image = Image {
        slots: jar_kernel::cap::CNode::default(),
        init_cap: INIT_SLOT,
    };
    image.slots.set(
        code_entry.cap_index,
        Some(RegCap::Code(CodeCap {
            code_id,
            byte_count: code_byte_count,
        })),
    );
    for entry in &parsed.caps {
        if !matches!(entry.cap_type, javm_legacy::program::CapEntryType::Data) {
            continue;
        }
        let initial = if entry.data_len > 0 {
            javm_legacy::program::cap_data(entry, parsed.data_section).to_vec()
        } else {
            Vec::new()
        };
        let byte_count = initial.len() as u64;
        let file_id = state
            .allocate_file(initial, entry.page_count, genesis_quota)
            .expect("genesis quota covers manifest data caps");
        // Image holds 1 σ-resident reference to this file.
        state.bump_file_refcount(file_id);
        image.slots.set(
            entry.cap_index,
            Some(RegCap::File(FileCap {
                file_id,
                byte_count,
            })),
        );
    }
    let image_id = state.next_image_id();
    state.images.insert(image_id, Arc::new(image));

    // Build the chain-author account-map as a σ-resident file.
    let mut map = vec![0u8; 4096];
    for (i, (key, balance)) in accounts.iter().enumerate() {
        assert!(i < 64, "too many genesis accounts (max 64)");
        assert_eq!(key.0.len(), 32, "ed25519 pubkey must be 32 bytes");
        let off = i * 64;
        map[off..off + 32].copy_from_slice(&key.0);
        map[off + 32..off + 40].copy_from_slice(&balance.to_le_bytes());
        // nonce starts at 0 (already zeroed).
    }
    let map_byte_count = map.len() as u64;
    let map_file_id = state
        .allocate_file(map, 1, genesis_quota)
        .expect("genesis quota covers account-map");
    // Vault.slots[ACCOUNT_MAP_SLOT] holds 1 σ-resident reference.
    state.bump_file_refcount(map_file_id);

    let mut vault = Vault::new(image_id);
    vault.slots.set(
        ACCOUNT_MAP_SLOT,
        Some(RegCap::File(FileCap {
            file_id: map_file_id,
            byte_count: map_byte_count,
        })),
    );
    // Reference the genesis StorageQuota so save/free operations have
    // a billing target. Bumps refcount on the quota entry.
    state.bump_quota_refcount(genesis_quota);
    vault.slots.set(
        QUOTA_SLOT,
        Some(RegCap::StorageQuota(QuotaCap {
            quota_id: genesis_quota,
        })),
    );
    let vault_id = state.next_vault_id();
    state.vaults.insert(vault_id, Arc::new(vault));

    // Endpoints: one transact, one dispatch, both pointing at the
    // simple-chain vault.
    let endpoint = EventEndpointCap {
        vault_id,
        gas_budget: 100_000_000,
        memory_budget: 256,
    };
    state.transact_endpoints.push(endpoint);
    state.dispatch_endpoints.push(endpoint);

    state
}
