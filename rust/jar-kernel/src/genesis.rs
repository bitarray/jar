//! Minimal genesis builder.
//!
//! Builds an σ with: a `Schedule(block_init)` slot, a `Transact` slot, a
//! `Schedule(block_final)` slot — all in σ.transact_space_cnode in slot
//! order — plus a registered Dispatch entrypoint. This is the minimum
//! shape for kernel-mechanics tests; real chains add many more slots.

use std::marker::PhantomData;

use jar_types::{CapId, Capability, Crypto, KResult, State, VaultId};

use crate::cap_registry;
use crate::cnode_ops;

/// Build a minimal σ for testing. Generic over the crypto suite — the
/// initial code hashes and resulting state types use `C::Hash` etc.
pub struct GenesisBuilder<C: Crypto> {
    pub block_init_code_hash: C::Hash,
    pub transact_code_hash: C::Hash,
    pub block_final_code_hash: C::Hash,
    pub dispatch_code_hash: C::Hash,
    pub default_quota_items: u64,
    pub default_quota_bytes: u64,
    _phantom: PhantomData<fn() -> C>,
}

impl<C: Crypto> Default for GenesisBuilder<C> {
    fn default() -> Self {
        // Distinct sentinel-byte code hashes so genesis state-roots differ
        // per-vault. Encoded as the lower bytes of a hash-width buffer; we
        // construct via `hash_from_bytes` to stay agnostic of the suite's
        // hash width.
        Self {
            block_init_code_hash: C::hash_from_bytes(&[0xA0u8; 32]).unwrap_or_default(),
            transact_code_hash: C::hash_from_bytes(&[0xA1u8; 32]).unwrap_or_default(),
            block_final_code_hash: C::hash_from_bytes(&[0xA2u8; 32]).unwrap_or_default(),
            dispatch_code_hash: C::hash_from_bytes(&[0xB0u8; 32]).unwrap_or_default(),
            default_quota_items: 1024,
            default_quota_bytes: 1 << 20,
            _phantom: PhantomData,
        }
    }
}

pub struct GenesisOutput<C: Crypto> {
    pub state: State<C>,
    pub block_init_vault: VaultId,
    pub block_init_cap: CapId,
    pub transact_vault: VaultId,
    pub transact_entrypoint_cap: CapId,
    pub block_final_vault: VaultId,
    pub block_final_cap: CapId,
    pub dispatch_vault: VaultId,
    pub dispatch_entrypoint_cap: CapId,
}

impl<C: Crypto> GenesisBuilder<C> {
    pub fn build(self) -> KResult<GenesisOutput<C>> {
        let mut state = State::<C>::empty();

        // Allocate the two σ-rooted CNodes.
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

        // Slot 0: Schedule(block_init).
        let bi_vault = self.alloc_vault(&mut state, self.block_init_code_hash);
        let bi_cap = cnode_ops::mint_and_place(
            &mut state,
            Capability::Schedule {
                vault_id: bi_vault,
                born_in: transact_cnode,
            },
            Vec::new(),
            transact_cnode,
            0,
        )?;

        // Slot 1: Transact(...).
        let t_vault = self.alloc_vault(&mut state, self.transact_code_hash);
        let t_cap = cnode_ops::mint_and_place(
            &mut state,
            Capability::Transact {
                vault_id: t_vault,
                born_in: transact_cnode,
            },
            Vec::new(),
            transact_cnode,
            1,
        )?;

        // Slot 2: Schedule(block_final).
        let bf_vault = self.alloc_vault(&mut state, self.block_final_code_hash);
        let bf_cap = cnode_ops::mint_and_place(
            &mut state,
            Capability::Schedule {
                vault_id: bf_vault,
                born_in: transact_cnode,
            },
            Vec::new(),
            transact_cnode,
            2,
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

    fn alloc_vault(&self, state: &mut State<C>, code_hash: C::Hash) -> VaultId {
        let id = state.next_vault_id();
        let mut v = jar_types::Vault::<C>::new(code_hash);
        v.quota_items = self.default_quota_items;
        v.quota_bytes = self.default_quota_bytes;
        state.vaults.insert(id, std::sync::Arc::new(v));
        id
    }
}
