//! Minimal genesis builder.
//!
//! Builds an σ with a few EventEndpointCap entries in
//! σ.transact_endpoints (mix of Schedule slots and event-receiving
//! slots) plus a dispatch endpoint in σ.dispatch_endpoints. Caps are
//! stored inline by value — no cap_registry, no CapId.
//!
//! Each endpoint Vault gets a `RegCap::Code(CodeCap)` placed at the
//! Vault's `init_cap` slot.

use std::sync::Arc;

use crate::types::{CodeCap, EventEndpointCap, KResult, RegCap, State, VaultId};

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

        let bi_vault = alloc_vault_with_code(&mut state, block_init_blob);
        state.transact_endpoints.push(EventEndpointCap {
            vault_id: bi_vault,
            gas_budget: 100_000_000,
            memory_budget: 256,
        });

        let t_vault = alloc_vault_with_code(&mut state, transact_blob);
        state.transact_endpoints.push(EventEndpointCap {
            vault_id: t_vault,
            gas_budget: 100_000_000,
            memory_budget: 256,
        });

        let bf_vault = alloc_vault_with_code(&mut state, block_final_blob);
        state.transact_endpoints.push(EventEndpointCap {
            vault_id: bf_vault,
            gas_budget: 100_000_000,
            memory_budget: 256,
        });

        let d_vault = alloc_vault_with_code(&mut state, dispatch_blob);
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

/// Allocate a Vault and place an inline CodeCap (raw code sub-blob
/// extracted from `jar_blob`'s manifest) at `DEFAULT_INIT_CAP_SLOT`.
fn alloc_vault_with_code(state: &mut State, jar_blob: Vec<u8>) -> VaultId {
    let parsed =
        javm::program::parse_blob(&jar_blob).expect("genesis blob is a well-formed JAR blob");
    let code_entry = parsed
        .caps
        .iter()
        .find(|e| matches!(e.cap_type, javm::program::CapEntryType::Code))
        .expect("genesis blob has at least one CODE manifest entry");
    let code_sub_blob = javm::program::cap_data(code_entry, parsed.data_section).to_vec();

    let vault_id = state.next_vault_id();
    let mut v = crate::types::Vault::new();
    v.init_cap = DEFAULT_INIT_CAP_SLOT;
    v.slots.set(
        DEFAULT_INIT_CAP_SLOT,
        Some(RegCap::Code(CodeCap {
            blob: Arc::new(code_sub_blob),
        })),
    );
    state.vaults.insert(vault_id, Arc::new(v));
    vault_id
}
