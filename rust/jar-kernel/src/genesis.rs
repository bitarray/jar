//! Minimal genesis builder.
//!
//! Builds an σ with: a `Schedule(block_init)` slot, a `Transact` slot, a
//! `Schedule(block_final)` slot — all in σ.transact_space_cnode in slot
//! order — plus a registered Dispatch entrypoint. This is the minimum
//! shape for kernel-mechanics tests; real chains add many more slots.
//!
//! Each entrypoint Vault gets a `Capability::Code(CodeCap)` placed at
//! the Vault's `init_cap` slot — the kernel reads the blob from there
//! at invocation time. There is no separate per-Vault `code_hash` field
//! and no kernel-internal `code_vault`; code is just another cap.

use std::sync::Arc;

use crate::types::{
    CNodeCap, CapId, Capability, CodeCap, DispatchCap, KResult, ScheduleCap, State, TransactCap,
    VaultId,
};

use crate::state::cap_registry;
use crate::state::cnode;
use crate::state::code_blobs;

/// Default slot for the init CodeCap when genesis Vaults are constructed.
///
/// Slot 64 matches the convention emitted by the JAR-blob transpiler
/// (manifest CODE entries land at cap_index 64). It also avoids slot 0,
/// which javm reserves for the bare-Frame FrameRef in every VM
/// CapTable; a slot-0 placement would be silently overwritten when
/// `vm::new_vm_from_vault` walks `vault.slots` into VM 0's CapTable.
/// Real chains may pick any non-zero slot per Vault; this is the
/// fixture convention.
const DEFAULT_INIT_CAP_SLOT: u8 = 64;

/// Build a minimal σ for testing.
pub struct GenesisBuilder {
    pub block_init_blob: Vec<u8>,
    pub transact_blob: Vec<u8>,
    pub block_final_blob: Vec<u8>,
    pub dispatch_blob: Vec<u8>,
    pub default_quota_pages: u64,
}

impl Default for GenesisBuilder {
    fn default() -> Self {
        Self {
            block_init_blob: code_blobs::halt_blob().to_vec(),
            transact_blob: code_blobs::halt_blob().to_vec(),
            block_final_blob: code_blobs::halt_blob().to_vec(),
            dispatch_blob: code_blobs::slot_clear_blob().to_vec(),
            default_quota_pages: 256,
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
            default_quota_pages,
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
        let bi_vault = alloc_vault_with_code(&mut state, block_init_blob, default_quota_pages);
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
        let t_vault = alloc_vault_with_code(&mut state, transact_blob, default_quota_pages);
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
        let bf_vault = alloc_vault_with_code(&mut state, block_final_blob, default_quota_pages);
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
        let d_vault = alloc_vault_with_code(&mut state, dispatch_blob, default_quota_pages);
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

/// Allocate a Vault, register a CodeCap with the **raw code sub-blob**
/// extracted from `jar_blob`'s manifest, and place it at
/// `DEFAULT_INIT_CAP_SLOT` of the Vault's CNode. The Vault's `init_cap`
/// is set to that slot so `Vault.initialize` finds the sub-blob.
/// Returns the new VaultId.
///
/// The JAR blob is parsed at Vault-creation time only; the on-chain
/// representation is the persistent `Capability::Code` (the sub-blob
/// alone). Manifest DATA entries are ignored — `vault_init` works
/// against the persistent CapTable, not the JAR manifest, so any
/// initial DATA shape must be expressed as persistent
/// `Capability::Data` entries placed in `vault.slots` directly. The
/// fixtures shipped today (halt, slot_clear) don't use DATA caps, so
/// dropping the manifest's DATA entries is observably a no-op.
fn alloc_vault_with_code(state: &mut State, jar_blob: Vec<u8>, quota_pages: u64) -> VaultId {
    use crate::state::cap_registry as reg;
    use crate::types::CapRecord;

    // Extract the code sub-blob from the JAR manifest. Genesis fixtures
    // always have exactly one CODE entry; assert that invariant.
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
    v.quota_pages = quota_pages;

    // Register the persistent CodeCap (raw code sub-blob) at the init slot.
    let code_cap_id = reg::alloc(
        state,
        CapRecord {
            cap: Capability::Code(CodeCap {
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
