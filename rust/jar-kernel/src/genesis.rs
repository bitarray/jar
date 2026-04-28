//! Minimal genesis builder.
//!
//! Builds an σ with: a no-op block_validation_cap Vault, a no-op
//! block_finalization_cap Vault, a registered Transact entrypoint, and a
//! registered Dispatch entrypoint. Keys are simple `[u8; 32]` ids.

use jar_types::{CapId, Capability, Hash, KResult, State, VaultId, VaultRights};

use crate::cap_registry;
use crate::cnode_ops;

/// Build a minimal σ for testing.
///
/// `policy_code_hash` — code hash for the no-op block-policy Vaults.
/// `transact_code_hash` — code for the registered Transact entrypoint Vault.
/// `dispatch_code_hash` — code for the registered Dispatch entrypoint Vault.
pub struct GenesisBuilder {
    pub policy_code_hash: Hash,
    pub transact_code_hash: Hash,
    pub dispatch_code_hash: Hash,
    pub default_quota_items: u64,
    pub default_quota_bytes: u64,
}

impl Default for GenesisBuilder {
    fn default() -> Self {
        Self {
            policy_code_hash: Hash::ZERO,
            transact_code_hash: Hash([1u8; 32]),
            dispatch_code_hash: Hash([2u8; 32]),
            default_quota_items: 1024,
            default_quota_bytes: 1 << 20,
        }
    }
}

pub struct GenesisOutput {
    pub state: State,
    pub block_validation_vault: VaultId,
    pub block_finalization_vault: VaultId,
    pub transact_vault: VaultId,
    pub transact_entrypoint_cap: CapId,
    pub dispatch_vault: VaultId,
    pub dispatch_entrypoint_cap: CapId,
}

impl GenesisBuilder {
    pub fn build(self) -> KResult<GenesisOutput> {
        let mut state = State::empty();

        // Allocate the four σ-rooted CNodes.
        let transact_cnode = cnode_ops::cnode_create(&mut state);
        let dispatch_cnode = cnode_ops::cnode_create(&mut state);

        // Mint `CNode` reference caps for the two surfaces.
        let tcn_cap = cap_registry::alloc(
            &mut state,
            jar_types::CapRecord {
                cap: Capability::CNode {
                    cnode_id: transact_cnode,
                },
                issuer: None,
                narrowing: Vec::new(),
            },
        );
        let dcn_cap = cap_registry::alloc(
            &mut state,
            jar_types::CapRecord {
                cap: Capability::CNode {
                    cnode_id: dispatch_cnode,
                },
                issuer: None,
                narrowing: Vec::new(),
            },
        );
        state.transact_space_cnode = tcn_cap;
        state.dispatch_space_cnode = dcn_cap;

        // Allocate the two block-policy Vaults + VaultRefs.
        let bv_vault = self.alloc_vault(&mut state, self.policy_code_hash);
        let bf_vault = self.alloc_vault(&mut state, self.policy_code_hash);
        let bv_cap = cap_registry::alloc(
            &mut state,
            jar_types::CapRecord {
                cap: Capability::VaultRef {
                    vault_id: bv_vault,
                    rights: VaultRights::INITIALIZE,
                },
                issuer: None,
                narrowing: Vec::new(),
            },
        );
        let bf_cap = cap_registry::alloc(
            &mut state,
            jar_types::CapRecord {
                cap: Capability::VaultRef {
                    vault_id: bf_vault,
                    rights: VaultRights::INITIALIZE,
                },
                issuer: None,
                narrowing: Vec::new(),
            },
        );
        state.block_validation_cap = bv_cap;
        state.block_finalization_cap = bf_cap;

        // Transact entrypoint Vault and its registered Transact cap, born_in transact_cnode.
        let t_vault = self.alloc_vault(&mut state, self.transact_code_hash);
        let t_cap = cnode_ops::mint_and_place(
            &mut state,
            Capability::Transact {
                vault_id: t_vault,
                born_in: transact_cnode,
            },
            Vec::new(),
            transact_cnode,
            0,
        )?;

        // Dispatch entrypoint Vault and its registered Dispatch cap, born_in dispatch_cnode.
        let d_vault = self.alloc_vault(&mut state, self.dispatch_code_hash);
        let d_cap = cnode_ops::mint_and_place(
            &mut state,
            Capability::Dispatch {
                vault_id: d_vault,
                born_in: dispatch_cnode,
            },
            Vec::new(),
            dispatch_cnode,
            0,
        )?;

        Ok(GenesisOutput {
            state,
            block_validation_vault: bv_vault,
            block_finalization_vault: bf_vault,
            transact_vault: t_vault,
            transact_entrypoint_cap: t_cap,
            dispatch_vault: d_vault,
            dispatch_entrypoint_cap: d_cap,
        })
    }

    fn alloc_vault(&self, state: &mut State, code_hash: Hash) -> VaultId {
        let id = state.next_vault_id();
        let mut v = jar_types::Vault::new(code_hash);
        v.quota_items = self.default_quota_items;
        v.quota_bytes = self.default_quota_bytes;
        state.vaults.insert(id, std::sync::Arc::new(v));
        id
    }
}

