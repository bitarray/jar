//! Simple-chain genesis: build an Image registered in `state.images`
//! holding the program template (Code + manifest data caps), and a
//! Vault that references the image with a pre-funded account-map in
//! its persistent storage cnode.

use std::sync::Arc;

use jar_kernel::cap::{CodeCap, DataCap, Image, RegCap};
use jar_kernel::{EventEndpointCap, KeyId, State, Vault};

/// Slot in the Vault's storage cnode (NOT in the Frame) holding the
/// account-map DataCap. The guest reaches this via the home VaultRef
/// + foreign-frame mechanism.
pub const ACCOUNT_MAP_SLOT: u8 = 100;
/// Slot in the Image holding the init CodeCap (matches the
/// jar-kernel default + simple-chain's `_start` convention).
pub const INIT_SLOT: u8 = 64;

/// Build a `State` with:
/// - `validators` populated for round-robin PoA.
/// - An Image holding the simple-chain program (Code at slot 64,
///   manifest-derived stack/heap/ro/rw at their declared slots).
/// - One Vault referencing the image, with the pre-funded
///   account-map at `vault.slots[ACCOUNT_MAP_SLOT]`.
/// - One transact endpoint and one dispatch endpoint, both
///   pointing at the same Vault.
pub fn build(validators: &[KeyId], accounts: &[(KeyId, u64)]) -> State {
    let mut state = State::empty();
    state.validators = validators.to_vec();

    let parsed = javm::program::parse_blob(crate::SIMPLE_CHAIN_BLOB)
        .expect("simple-chain JAR blob is well-formed");
    let code_entry = parsed
        .caps
        .iter()
        .find(|e| matches!(e.cap_type, javm::program::CapEntryType::Code))
        .expect("simple-chain blob has a CODE manifest entry");
    let code_sub_blob = javm::program::cap_data(code_entry, parsed.data_section).to_vec();

    // Build the Image: code at slot 64, manifest-derived data caps
    // at their declared slots (stack, ro, rw, heap).
    let mut image = Image {
        slots: jar_kernel::cap::CNode::default(),
        init_cap: INIT_SLOT,
    };
    image.slots.set(
        code_entry.cap_index,
        Some(RegCap::Code(CodeCap {
            blob: Arc::new(code_sub_blob),
        })),
    );
    for entry in &parsed.caps {
        if !matches!(entry.cap_type, javm::program::CapEntryType::Data) {
            continue;
        }
        let initial = if entry.data_len > 0 {
            javm::program::cap_data(entry, parsed.data_section).to_vec()
        } else {
            Vec::new()
        };
        image.slots.set(
            entry.cap_index,
            Some(RegCap::Data(DataCap {
                content: Arc::new(initial),
                page_count: entry.page_count,
            })),
        );
    }
    let image_id = state.next_image_id();
    state.images.insert(image_id, Arc::new(image));

    // Build the chain-author account-map for vault.slots.
    let mut map = vec![0u8; 4096];
    for (i, (key, balance)) in accounts.iter().enumerate() {
        assert!(i < 64, "too many genesis accounts (max 64)");
        assert_eq!(key.0.len(), 32, "ed25519 pubkey must be 32 bytes");
        let off = i * 64;
        map[off..off + 32].copy_from_slice(&key.0);
        map[off + 32..off + 40].copy_from_slice(&balance.to_le_bytes());
        // nonce starts at 0 (already zeroed).
    }

    let mut vault = Vault::new(image_id);
    vault.slots.set(
        ACCOUNT_MAP_SLOT,
        Some(RegCap::Data(DataCap {
            content: Arc::new(map),
            page_count: 1,
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
