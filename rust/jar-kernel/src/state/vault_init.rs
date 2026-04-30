//! `Vault.initialize`: build a fresh javm CapTable from a Vault's
//! persistent CNode slots.
//!
//! For every occupied slot in `vault.slots`, this module looks up the
//! `CapRecord` and translates the persistent `Capability` shape into
//! the ephemeral `Cap<KernelCap>` shape that lives in a running VM's
//! Frame:
//!
//! | `vault.slots[N]`                                      | `cap_table[N]` |
//! |-------------------------------------------------------|----------------|
//! | empty                                                 | empty          |
//! | `Capability::Code(CodeCap{blob})`                     | `Cap::Code(...)` (compile blob) |
//! | `Capability::Data(DataCap{content, page_count})`      | `Cap::Data(...)` (fresh ephemeral pages, content-copied, **unmapped**) |
//! | `Capability::VaultRef(...)` / other Registered shapes | `Cap::Protocol(KernelCap::Registered { id, cap })` |
//! | Pinned (Dispatch / Transact / Schedule + Refs)        | `KernelError::Pinning` (defense in depth — `fc_set` already rejects placement) |
//! | Ephemeral-only (Gas / SelfId / Caller*)               | `KernelError::Internal` (kernel bug if such a cap lands here) |
//!
//! The DataCap path leaves the cap **unmapped**: the init program is
//! responsible for `MGMT_MAP`-ing each persistent DataCap at runtime.
//! Mapping at Vault.initialize time is deferred to a follow-up that
//! adds per-cap mapping hints to the persistent shape.
//!
//! Slot 0 of the resulting CapTable is reserved by javm for the
//! bare-Frame FrameRef (installed in `finalize_kernel`); occupying
//! `vault.slots[0]` is rejected up front to avoid a silent overwrite
//! at the kernel side. Genesis places the init CodeCap at slot 64 by
//! convention.

use std::sync::Arc;

use javm::cap::{Cap, CapTable};

use crate::cap::KernelCap;
use crate::types::{Capability, KResult, KernelError, State, VaultId};

/// Pre-built input to `javm::kernel::InvocationKernel::new_from_artifacts`,
/// produced by walking `vault.slots`. Mirrors
/// `javm::kernel::InvocationArtifacts<KernelCap>` but is constructed
/// from σ rather than a JAR blob.
pub type InitArtifacts = javm::kernel::InvocationArtifacts<KernelCap>;

/// Walk `vault.slots` and produce the artifacts needed to construct
/// an `InvocationKernel<KernelCap>` for `Vault.initialize`. The page
/// budget for the kernel's UntypedCap and BackingStore is the home
/// Vault's `quota_pages`, capped at `u32::MAX`.
///
/// Returns `KernelError::Pinning` if a pinned cap (Dispatch / Transact
/// / Schedule + Refs) is encountered in `vault.slots` (defense in
/// depth — `fc_set` already rejects this placement). Returns
/// `KernelError::Internal` if an ephemeral-only cap (Gas / SelfId /
/// Caller*) is encountered (kernel bug if this happens). Returns
/// `KernelError::Internal` if `vault.slots[0]` is occupied (slot 0 is
/// kernel-reserved for the bare-Frame FrameRef).
pub fn build_init_cap_table(
    state: &State,
    vault_id: VaultId,
    mut code_cache: Option<&mut javm::CodeCache>,
    backend: javm::PvmBackend,
) -> KResult<InitArtifacts> {
    let vault = state.vault(vault_id)?;
    let init_slot = vault.init_cap;
    let memory_pages: u32 = vault.quota_pages.min(u32::MAX as u64) as u32;
    let mem_cycles = javm::compute_mem_cycles(memory_pages);

    if vault.slots.get(0).is_some() {
        return Err(KernelError::Internal(format!(
            "vault {:?} slot 0 is occupied; slot 0 is reserved by javm for the bare-Frame FrameRef",
            vault_id
        )));
    }

    let mut backing = javm::backing::BackingStore::new(memory_pages).ok_or_else(|| {
        KernelError::Internal(format!(
            "BackingStore::new({}) failed for vault {:?}",
            memory_pages, vault_id
        ))
    })?;
    let untyped = Arc::new(javm::cap::UntypedCap::new(memory_pages));

    let mut cap_table: CapTable<KernelCap> = CapTable::new();
    let mut code_caps: Vec<Arc<javm::cap::CodeCap>> = Vec::new();
    let data_caps_to_map: Vec<(u32, u32, u32, javm::cap::Access)> = Vec::new();

    for slot in 0u8..=255 {
        let cap_id = match vault.slots.get(slot) {
            Some(id) => id,
            None => continue,
        };
        let record = state.cap_record(cap_id)?;
        let cap = translate_persistent(
            &record.cap,
            cap_id,
            &mut code_caps,
            mem_cycles,
            backend,
            code_cache.as_deref_mut(),
            &untyped,
            &mut backing,
        )?;
        cap_table.set(slot, cap);
    }

    let init_code_id = match cap_table.get(init_slot) {
        Some(Cap::Code(c)) => c.id,
        Some(_) => {
            return Err(KernelError::Internal(format!(
                "vault {:?} init slot {} does not hold a Code cap",
                vault_id, init_slot
            )));
        }
        None => {
            return Err(KernelError::Internal(format!(
                "vault {:?} has no cap at init slot {}",
                vault_id, init_slot
            )));
        }
    };

    Ok(InitArtifacts {
        cap_table,
        code_caps,
        init_code_id,
        untyped,
        backing,
        data_caps_to_map,
    })
}

#[allow(clippy::too_many_arguments)]
fn translate_persistent(
    cap: &Capability,
    cap_id: crate::types::CapId,
    code_caps: &mut Vec<Arc<javm::cap::CodeCap>>,
    mem_cycles: u8,
    backend: javm::PvmBackend,
    code_cache: Option<&mut javm::CodeCache>,
    untyped: &Arc<javm::cap::UntypedCap>,
    backing: &mut javm::backing::BackingStore,
) -> KResult<Cap<KernelCap>> {
    match cap {
        Capability::Code(c) => {
            if code_caps.len() >= javm::vm_pool::MAX_CODE_CAPS {
                return Err(KernelError::Internal(format!(
                    "vault holds more than {} CodeCap entries",
                    javm::vm_pool::MAX_CODE_CAPS
                )));
            }
            let id = code_caps.len() as u16;
            let code_cap =
                javm::kernel::compile_code_blob(&c.blob, id, mem_cycles, backend, code_cache)
                    .map_err(|e| KernelError::Internal(format!("compile_code_blob: {:?}", e)))?;
            code_caps.push(Arc::clone(&code_cap));
            Ok(Cap::Code(code_cap))
        }
        Capability::Data(d) => {
            let data_cap =
                javm::kernel::allocate_data_cap(&d.content, d.page_count, untyped, backing)
                    .map_err(|e| KernelError::Internal(format!("allocate_data_cap: {:?}", e)))?;
            // Cap is unmapped on purpose — the init program calls MGMT_MAP.
            Ok(Cap::Data(data_cap))
        }
        // Pinned variants must not appear in vault.slots — fc_set rejects
        // their placement. Defense in depth: reject here too.
        Capability::Dispatch(_)
        | Capability::Transact(_)
        | Capability::Schedule(_)
        | Capability::DispatchRef(_)
        | Capability::TransactRef(_) => Err(KernelError::Pinning(format!(
            "pinned cap {:?} found in vault.slots; cannot promote to Frame",
            std::mem::discriminant(cap)
        ))),
        // Ephemeral-only variants must never persist. Finding one here
        // is a kernel bug.
        Capability::Gas(_)
        | Capability::SelfId(_)
        | Capability::CallerVault(_)
        | Capability::CallerKernel(_) => Err(KernelError::Internal(format!(
            "ephemeral-only cap {:?} found persistently in vault.slots",
            std::mem::discriminant(cap)
        ))),
        // All other Registered shapes round-trip unchanged.
        Capability::VaultRef(_)
        | Capability::CNode(_)
        | Capability::Resource(_)
        | Capability::Meta(_)
        | Capability::AttestationCap(_)
        | Capability::AttestationAggregateCap(_)
        | Capability::ResultCap(_) => Ok(Cap::Protocol(KernelCap::Registered {
            id: cap_id,
            cap: cap.clone(),
        })),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cap::{CodeCap, DataCap, DispatchCap, VaultRefCap, VaultRights};
    use crate::state::cap_registry;
    use crate::state::cnode;
    use crate::types::{CapRecord, Vault};

    fn empty_state_with_vault(init_cap: u8, quota_pages: u64) -> (State, VaultId) {
        let mut state = State::empty();
        let vault_id = state.next_vault_id();
        let mut v = Vault::new();
        v.init_cap = init_cap;
        v.quota_pages = quota_pages;
        state.vaults.insert(vault_id, Arc::new(v));
        (state, vault_id)
    }

    fn place(state: &mut State, vault_id: VaultId, slot: u8, cap: Capability) {
        let cap_id = cap_registry::alloc(
            state,
            CapRecord {
                cap,
                issuer: None,
                narrowing: vec![],
            },
        );
        let arc = state.vaults.get(&vault_id).unwrap().clone();
        let mut v: Vault = (*arc).clone();
        v.slots.set(slot, Some(cap_id));
        state.vaults.insert(vault_id, Arc::new(v));
    }

    /// Extract the raw code sub-blob (jump_table + code + bitmask) from
    /// the CODE manifest entry of jar-kernel's halt smoke fixture.
    /// Persistent CodeCaps hold *code sub-blobs* under the CapTable-driven
    /// model — the JAR-blob wrapper is only used at Vault-creation time
    /// to bootstrap the per-Vault CNode. Genesis (commit 3.1) is what
    /// actually does that extraction; here we mirror the same logic for
    /// the test fixture.
    fn halt_code_sub_blob() -> Vec<u8> {
        let blob = crate::state::code_blobs::halt_blob();
        let parsed = javm::program::parse_blob(blob).expect("parse halt_blob");
        let code_entry = parsed
            .caps
            .iter()
            .find(|e| matches!(e.cap_type, javm::program::CapEntryType::Code))
            .expect("no CODE entry in halt_blob");
        javm::program::cap_data(code_entry, parsed.data_section).to_vec()
    }

    #[test]
    fn single_codecap_at_slot_64() {
        let (mut state, vault_id) = empty_state_with_vault(64, 16);
        place(
            &mut state,
            vault_id,
            64,
            Capability::Code(CodeCap {
                blob: Arc::new(halt_code_sub_blob()),
            }),
        );

        let artifacts =
            build_init_cap_table(&state, vault_id, None, javm::PvmBackend::Default).unwrap();

        assert_eq!(artifacts.code_caps.len(), 1);
        assert_eq!(artifacts.init_code_id, 0);
        assert!(matches!(artifacts.cap_table.get(64), Some(Cap::Code(_))));
        assert!(artifacts.data_caps_to_map.is_empty());
    }

    #[test]
    fn vaultref_passthrough() {
        let (mut state, vault_id) = empty_state_with_vault(64, 16);
        place(
            &mut state,
            vault_id,
            64,
            Capability::Code(CodeCap {
                blob: Arc::new(halt_code_sub_blob()),
            }),
        );
        place(
            &mut state,
            vault_id,
            100,
            Capability::VaultRef(VaultRefCap {
                vault_id: VaultId(99),
                rights: VaultRights::ALL,
            }),
        );

        let artifacts =
            build_init_cap_table(&state, vault_id, None, javm::PvmBackend::Default).unwrap();
        match artifacts.cap_table.get(100) {
            Some(Cap::Protocol(KernelCap::Registered {
                cap: Capability::VaultRef(vr),
                ..
            })) => {
                assert_eq!(vr.vault_id, VaultId(99));
            }
            other => panic!("expected Registered VaultRef at slot 100, got {:?}", other),
        }
    }

    #[test]
    fn datacap_propagated_unmapped() {
        let (mut state, vault_id) = empty_state_with_vault(64, 16);
        place(
            &mut state,
            vault_id,
            64,
            Capability::Code(CodeCap {
                blob: Arc::new(halt_code_sub_blob()),
            }),
        );
        place(
            &mut state,
            vault_id,
            65,
            Capability::Data(DataCap {
                content: Arc::new(b"hello".to_vec()),
                page_count: 1,
            }),
        );

        let artifacts =
            build_init_cap_table(&state, vault_id, None, javm::PvmBackend::Default).unwrap();
        match artifacts.cap_table.get(65) {
            Some(Cap::Data(d)) => {
                assert_eq!(d.page_count, 1);
                assert!(d.mappings.is_empty());
                assert!(d.active_in.is_none());
                assert!(!d.has_any_mapped());
            }
            other => panic!("expected unmapped Cap::Data at slot 65, got {:?}", other),
        }
    }

    #[test]
    fn missing_init_cap_errors() {
        let (state, vault_id) = empty_state_with_vault(64, 16); // no caps placed
        let err = build_init_cap_table(&state, vault_id, None, javm::PvmBackend::Default)
            .err()
            .expect("error expected");
        assert!(matches!(err, KernelError::Internal(_)));
    }

    #[test]
    fn wrong_shape_at_init_cap_errors() {
        let (mut state, vault_id) = empty_state_with_vault(64, 16);
        place(
            &mut state,
            vault_id,
            64,
            Capability::VaultRef(VaultRefCap {
                vault_id: VaultId(99),
                rights: VaultRights::ALL,
            }),
        );
        let err = build_init_cap_table(&state, vault_id, None, javm::PvmBackend::Default)
            .err()
            .expect("error expected");
        assert!(matches!(err, KernelError::Internal(_)));
    }

    #[test]
    fn pinned_cap_in_slot_rejected() {
        let (mut state, vault_id) = empty_state_with_vault(64, 16);
        place(
            &mut state,
            vault_id,
            64,
            Capability::Code(CodeCap {
                blob: Arc::new(halt_code_sub_blob()),
            }),
        );
        // Direct cap_registry placement bypasses fc_set's pinning check.
        // Test that build_init_cap_table catches it as defense in depth.
        let cn = cnode::cnode_create(&mut state);
        place(
            &mut state,
            vault_id,
            100,
            Capability::Dispatch(DispatchCap {
                vault_id: VaultId(0),
                born_in: cn,
            }),
        );

        let err = build_init_cap_table(&state, vault_id, None, javm::PvmBackend::Default)
            .err()
            .expect("Pinning expected");
        assert!(matches!(err, KernelError::Pinning(_)));
    }

    #[test]
    fn slot_zero_rejected() {
        let (mut state, vault_id) = empty_state_with_vault(64, 16);
        // Place a CodeCap at slot 0 (which is kernel-reserved). The
        // genesis builder migrated to slot 64; this is a test for
        // defense-in-depth against any caller that ignores the
        // convention.
        place(
            &mut state,
            vault_id,
            0,
            Capability::Code(CodeCap {
                blob: Arc::new(halt_code_sub_blob()),
            }),
        );

        let err = build_init_cap_table(&state, vault_id, None, javm::PvmBackend::Default)
            .err()
            .expect("error expected");
        assert!(matches!(err, KernelError::Internal(_)));
    }
}
