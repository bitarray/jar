//! Minimal genesis builder.
//!
//! Builds an σ with: a `Schedule(block_init)` slot, a `Transact` slot, a
//! `Schedule(block_final)` slot — all in σ.transact_space_cnode in slot
//! order — plus a registered Dispatch entrypoint. This is the minimum
//! shape for kernel-mechanics tests; real chains add many more slots.
//!
//! Each entrypoint Vault gets a `Capability::Code(CodeCap)` placed at
//! `CODE_CAP_SLOT` of its CNode — the kernel reads the blob from there
//! at invocation time. There is no separate per-Vault `code_hash` field
//! and no kernel-internal `code_vault`; code is just another cap.

use std::sync::Arc;

use crate::types::{
    CNodeCap, CapId, Capability, CodeCap, DispatchCap, KResult, ScheduleCap, State, TransactCap,
    VaultId,
};

use crate::state::CODE_CAP_SLOT;
use crate::state::cap_registry;
use crate::state::cnode;
use crate::state::code_blobs;

/// Build a minimal σ for testing.
pub struct GenesisBuilder {
    pub block_init_blob: Vec<u8>,
    pub transact_blob: Vec<u8>,
    pub block_final_blob: Vec<u8>,
    pub dispatch_blob: Vec<u8>,
    pub default_quota_items: u64,
    pub default_quota_bytes: u64,
}

impl Default for GenesisBuilder {
    fn default() -> Self {
        Self {
            block_init_blob: code_blobs::halt_blob().to_vec(),
            transact_blob: code_blobs::halt_blob().to_vec(),
            block_final_blob: code_blobs::halt_blob().to_vec(),
            dispatch_blob: code_blobs::slot_clear_blob().to_vec(),
            default_quota_items: 1024,
            default_quota_bytes: 1 << 20,
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
            default_quota_items,
            default_quota_bytes,
        } = self;
        let mut state = State::empty();

        // Allocate the two σ-rooted CNodes.
        let transact_cnode = cnode::cnode_create(&mut state);
        let dispatch_cnode = cnode::cnode_create(&mut state);

        // Mint `CNode` reference caps for the two surfaces.
        let tcn_cap = cap_registry::alloc(
            &mut state,
            crate::types::CapRecord {
                cap: Capability::CNode(CNodeCap {
                    cnode_id: transact_cnode,
                }),
                issuer: None,
                narrowing: Vec::new(),
            },
        );
        let dcn_cap = cap_registry::alloc(
            &mut state,
            crate::types::CapRecord {
                cap: Capability::CNode(CNodeCap {
                    cnode_id: dispatch_cnode,
                }),
                issuer: None,
                narrowing: Vec::new(),
            },
        );
        state.transact_space_cnode = tcn_cap;
        state.dispatch_space_cnode = dcn_cap;

        // Slot 0: Schedule(block_init).
        let bi_vault = alloc_vault_with_code(
            &mut state,
            block_init_blob,
            default_quota_items,
            default_quota_bytes,
        );
        let bi_cap = cnode::mint_and_place(
            &mut state,
            Capability::Schedule(ScheduleCap {
                vault_id: bi_vault,
                born_in: transact_cnode,
            }),
            Vec::new(),
            transact_cnode,
            0,
        )?;

        // Slot 1: Transact(...).
        let t_vault = alloc_vault_with_code(
            &mut state,
            transact_blob,
            default_quota_items,
            default_quota_bytes,
        );
        let t_cap = cnode::mint_and_place(
            &mut state,
            Capability::Transact(TransactCap {
                vault_id: t_vault,
                born_in: transact_cnode,
            }),
            Vec::new(),
            transact_cnode,
            1,
        )?;

        // Slot 2: Schedule(block_final).
        let bf_vault = alloc_vault_with_code(
            &mut state,
            block_final_blob,
            default_quota_items,
            default_quota_bytes,
        );
        let bf_cap = cnode::mint_and_place(
            &mut state,
            Capability::Schedule(ScheduleCap {
                vault_id: bf_vault,
                born_in: transact_cnode,
            }),
            Vec::new(),
            transact_cnode,
            2,
        )?;

        // Dispatch entrypoint Vault and its registered Dispatch cap, born_in dispatch_cnode.
        let d_vault = alloc_vault_with_code(
            &mut state,
            dispatch_blob,
            default_quota_items,
            default_quota_bytes,
        );
        let d_cap = cnode::mint_and_place(
            &mut state,
            Capability::Dispatch(DispatchCap {
                vault_id: d_vault,
                born_in: dispatch_cnode,
            }),
            Vec::new(),
            dispatch_cnode,
            0,
        )?;

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

/// Allocate a Vault, register a CodeCap with the given blob, and place it
/// at `CODE_CAP_SLOT` of the Vault's CNode. Returns the new VaultId.
fn alloc_vault_with_code(
    state: &mut State,
    blob: Vec<u8>,
    quota_items: u64,
    quota_bytes: u64,
) -> VaultId {
    use crate::state::cap_registry as reg;
    use crate::types::CapRecord;

    let vault_id = state.next_vault_id();
    let mut v = crate::types::Vault::new();
    v.quota_items = quota_items;
    v.quota_bytes = quota_bytes;

    // Register the CodeCap and place it at CODE_CAP_SLOT.
    let code_cap_id = reg::alloc(
        state,
        CapRecord {
            cap: Capability::Code(CodeCap {
                blob: Arc::new(blob),
            }),
            issuer: None,
            narrowing: Vec::new(),
        },
    );
    v.slots.set(CODE_CAP_SLOT, Some(code_cap_id));
    state.vaults.insert(vault_id, Arc::new(v));
    vault_id
}
