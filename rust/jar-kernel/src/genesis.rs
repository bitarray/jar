//! Minimal genesis builder.
//!
//! Builds an σ with a few EventEndpointCap entries in σ.transact_endpoints
//! (mix of Schedule slots and event-receiving slots) plus a dispatch
//! endpoint in σ.dispatch_endpoints. Per the event-redesign, σ surfaces
//! are flat Vec<CapId>; no nested cap-graph.
//!
//! Each endpoint Vault gets a `RegisteredCap::Code(CodeCap)` placed at
//! the Vault's `init_cap` slot.

use std::sync::Arc;

use crate::state::cap_registry;
use crate::state::code_blobs;
use crate::types::{CapId, CodeCap, EventEndpointCap, KResult, RegisteredCap, State, VaultId};

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
            block_init_blob: code_blobs::halt_blob().to_vec(),
            transact_blob: code_blobs::halt_blob().to_vec(),
            block_final_blob: code_blobs::halt_blob().to_vec(),
            // The slot_clear fixture was retired with the event-redesign;
            // halt is the universal default until chain-specific fixtures
            // exercise emit_event / setScore / mint_attest_cap.
            dispatch_blob: code_blobs::halt_blob().to_vec(),
        }
    }
}

pub struct GenesisOutput {
    pub state: State,
    pub block_init_vault: VaultId,
    pub block_init_cap: CapId,
    pub transact_vault: VaultId,
    pub transact_entrypoint_cap: CapId,
    pub block_final_vault: VaultId,
    pub block_final_cap: CapId,
    pub dispatch_vault: VaultId,
    pub dispatch_entrypoint_cap: CapId,
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

        // Slot 0 of σ.transact_endpoints: Schedule(block_init).
        let bi_vault = alloc_vault_with_code(&mut state, block_init_blob);
        let bi_cap = cap_registry::alloc(
            &mut state,
            crate::types::CapRecord {
                cap: RegisteredCap::EventEndpoint(EventEndpointCap {
                    vault_id: bi_vault,
                    gas_budget: 100_000_000,
                    memory_budget: 256,
                }),
                issuer: None,
                narrowing: Vec::new(),
            },
        );
        state.transact_endpoints.push(bi_cap);

        // Slot 1 of σ.transact_endpoints: event-receiving transact endpoint.
        let t_vault = alloc_vault_with_code(&mut state, transact_blob);
        let t_cap = cap_registry::alloc(
            &mut state,
            crate::types::CapRecord {
                cap: RegisteredCap::EventEndpoint(EventEndpointCap {
                    vault_id: t_vault,
                    gas_budget: 100_000_000,
                    memory_budget: 256,
                }),
                issuer: None,
                narrowing: Vec::new(),
            },
        );
        state.transact_endpoints.push(t_cap);

        // Slot 2 of σ.transact_endpoints: Schedule(block_final).
        let bf_vault = alloc_vault_with_code(&mut state, block_final_blob);
        let bf_cap = cap_registry::alloc(
            &mut state,
            crate::types::CapRecord {
                cap: RegisteredCap::EventEndpoint(EventEndpointCap {
                    vault_id: bf_vault,
                    gas_budget: 100_000_000,
                    memory_budget: 256,
                }),
                issuer: None,
                narrowing: Vec::new(),
            },
        );
        state.transact_endpoints.push(bf_cap);

        // σ.dispatch_endpoints: a dispatch endpoint.
        let d_vault = alloc_vault_with_code(&mut state, dispatch_blob);
        let d_cap = cap_registry::alloc(
            &mut state,
            crate::types::CapRecord {
                cap: RegisteredCap::EventEndpoint(EventEndpointCap {
                    vault_id: d_vault,
                    gas_budget: 100_000_000,
                    memory_budget: 256,
                }),
                issuer: None,
                narrowing: Vec::new(),
            },
        );
        state.dispatch_endpoints.push(d_cap);

        Ok(GenesisOutput {
            state,
            block_init_vault: bi_vault,
            block_init_cap: bi_cap,
            transact_vault: t_vault,
            transact_entrypoint_cap: t_cap,
            block_final_vault: bf_vault,
            block_final_cap: bf_cap,
            dispatch_vault: d_vault,
            dispatch_entrypoint_cap: d_cap,
        })
    }
}

/// Allocate a Vault, register a CodeCap with the raw code sub-blob
/// extracted from `jar_blob`'s manifest, and place it at
/// `DEFAULT_INIT_CAP_SLOT`.
fn alloc_vault_with_code(state: &mut State, jar_blob: Vec<u8>) -> VaultId {
    use crate::state::cap_registry as reg;
    use crate::types::CapRecord;

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

    let code_cap_id = reg::alloc(
        state,
        CapRecord {
            cap: RegisteredCap::Code(CodeCap {
                blob: Arc::new(code_sub_blob),
            }),
            issuer: None,
            narrowing: Vec::new(),
        },
    );
    v.slots.set(DEFAULT_INIT_CAP_SLOT, Some(code_cap_id));
    state.vaults.insert(vault_id, Arc::new(v));
    vault_id
}
