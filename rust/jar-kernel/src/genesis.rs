//! Minimal genesis builder.
//!
//! Builds an σ with a few EventEndpointCap entries in
//! σ.transact_endpoints (mix of Schedule slots and event-receiving
//! slots) plus a dispatch endpoint in σ.dispatch_endpoints. Caps are
//! stored inline by value.
//!
//! Each endpoint Vault references an Image registered in
//! `state.images`. The Image holds the program's CodeCap at its
//! `init_cap` slot. Vaults sharing the same blob share their
//! Arc<Image> — Image dedup is automatic at the genesis layer.

use std::sync::Arc;

use crate::cap::Image;
use crate::types::{CodeCap, EventEndpointCap, ImageId, KResult, RegCap, State, VaultId};

/// Default smoke fixture: a PVM blob that ecallis IPC-slot (REPLY) → halts
/// immediately. Compiled at build time from `rust/jar-test-services/halt`.
/// Used by genesis (every Vault gets the halt blob until host calls land)
/// and by integration tests that need a well-formed CodeCap.
pub fn halt_blob() -> &'static [u8] {
    include_bytes!(env!("JAR_HALT_BLOB_PATH"))
}

/// Default slot for the init CodeCap.
const DEFAULT_INIT_CAP_SLOT: u8 = 64;

/// Build a minimal σ for testing.
pub struct GenesisBuilder {
    pub block_init_blob: Vec<u8>,
    pub transact_blob: Vec<u8>,
    pub block_final_blob: Vec<u8>,
    pub dispatch_blob: Vec<u8>,
}

impl Default for GenesisBuilder {
    fn default() -> Self {
        Self {
            block_init_blob: halt_blob().to_vec(),
            transact_blob: halt_blob().to_vec(),
            block_final_blob: halt_blob().to_vec(),
            // The slot_clear fixture was retired with the event-redesign;
            // halt is the universal default until chain-specific fixtures
            // exercise emit_event / setScore / mint_attest_cap.
            dispatch_blob: halt_blob().to_vec(),
        }
    }
}

pub struct GenesisOutput {
    pub state: State,
    pub block_init_vault: VaultId,
    pub transact_vault: VaultId,
    pub block_final_vault: VaultId,
    pub dispatch_vault: VaultId,
}

impl GenesisBuilder {
    pub fn build(self) -> KResult<GenesisOutput> {
        let GenesisBuilder {
            block_init_blob,
            transact_blob,
            block_final_blob,
            dispatch_blob,
        } = self;
        let mut state = State::empty();

        let bi_image = register_image_for_blob(&mut state, &block_init_blob);
        let t_image = register_image_for_blob(&mut state, &transact_blob);
        let bf_image = register_image_for_blob(&mut state, &block_final_blob);
        let d_image = register_image_for_blob(&mut state, &dispatch_blob);

        let bi_vault = alloc_vault_for_image(&mut state, bi_image);
        state.transact_endpoints.push(EventEndpointCap {
            vault_id: bi_vault,
            gas_budget: 100_000_000,
            memory_budget: 256,
        });

        let t_vault = alloc_vault_for_image(&mut state, t_image);
        state.transact_endpoints.push(EventEndpointCap {
            vault_id: t_vault,
            gas_budget: 100_000_000,
            memory_budget: 256,
        });

        let bf_vault = alloc_vault_for_image(&mut state, bf_image);
        state.transact_endpoints.push(EventEndpointCap {
            vault_id: bf_vault,
            gas_budget: 100_000_000,
            memory_budget: 256,
        });

        let d_vault = alloc_vault_for_image(&mut state, d_image);
        state.dispatch_endpoints.push(EventEndpointCap {
            vault_id: d_vault,
            gas_budget: 100_000_000,
            memory_budget: 256,
        });

        Ok(GenesisOutput {
            state,
            block_init_vault: bi_vault,
            transact_vault: t_vault,
            block_final_vault: bf_vault,
            dispatch_vault: d_vault,
        })
    }
}

/// Parse a JAR blob, extract its CODE sub-blob, build an Image
/// holding the CodeCap at `DEFAULT_INIT_CAP_SLOT`, and register it
/// in `state.images`. Returns the new ImageId.
fn register_image_for_blob(state: &mut State, jar_blob: &[u8]) -> ImageId {
    let parsed =
        javm::program::parse_blob(jar_blob).expect("genesis blob is a well-formed JAR blob");
    let code_entry = parsed
        .caps
        .iter()
        .find(|e| matches!(e.cap_type, javm::program::CapEntryType::Code))
        .expect("genesis blob has at least one CODE manifest entry");
    let code_sub_blob = javm::program::cap_data(code_entry, parsed.data_section).to_vec();

    let mut image = Image {
        slots: crate::cap::CNode::default(),
        init_cap: DEFAULT_INIT_CAP_SLOT,
    };
    image.slots.set(
        DEFAULT_INIT_CAP_SLOT,
        Some(RegCap::Code(CodeCap {
            blob: Arc::new(code_sub_blob),
        })),
    );

    let image_id = state.next_image_id();
    state.images.insert(image_id, Arc::new(image));
    image_id
}

/// Allocate a Vault referencing the given Image. `Vault.slots`
/// starts empty (no chain-author storage in the halt fixture).
fn alloc_vault_for_image(state: &mut State, image_id: ImageId) -> VaultId {
    let vault_id = state.next_vault_id();
    state.vaults.insert(
        vault_id,
        Arc::new(crate::types::Vault {
            image_id,
            slots: crate::cap::CNode::default(),
        }),
    );
    vault_id
}
