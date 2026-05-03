//! `Vault.initialize`: build a fresh javm CapTable from the Vault's
//! Image (the program template registered in `state.images`).
//!
//! Frame init is a CLONE of Image — `instantiate_from_image` walks
//! `image.slots` and translates each persistent `RegCap` into the
//! ephemeral `Cap` that lives in the new VM's CapTable:
//!
//! | `image.slots[N]`                                  | `cap_table[N]` |
//! |---------------------------------------------------|----------------|
//! | empty                                             | empty          |
//! | `RegCap::Code(CodeCap{code_id, …})`               | `Cap::Code(...)` (look up `state.code_blobs[code_id]`, compile bytes) |
//! | `RegCap::File(FileCap{file_id, …})`               | `Cap::Data(...)` (look up `state.data_blobs[file_id]`, allocate ephemeral pages, copy bytes, **unmapped**) |
//! | `RegCap::VaultRef(...)` / `Resource` / `ImageRef` / `StorageQuota` | `Cap::Protocol(...)` projection |
//!
//! The DataCap path leaves the cap **unmapped**: the init program is
//! responsible for `MGMT_MAP`-ing each persistent DataCap at runtime.
//!
//! Slot 0 of the resulting CapTable is reserved by javm for the
//! bare-Frame FrameRef; occupying `image.slots[0]` is rejected up
//! front. Image's `init_cap` names the slot whose `RegCap::Code` is
//! the entry program.
//!
//! `Vault.slots` is NOT consulted here — chain-author persistent
//! storage lives outside Frame and is reached by guests via the
//! home VaultRef + foreign-frame mechanism.

use std::sync::Arc;

use javm::cap::CapTable;

use crate::cap::{Cap, Image, ProtocolCap};
use crate::types::{KResult, KernelError, RegCap, State, VaultId};

/// Pre-built input to `javm::kernel::InvocationKernel::new_from_artifacts`,
/// produced by walking an `Image`'s slots.
pub type InitArtifacts = javm::kernel::InvocationArtifacts<ProtocolCap>;

/// Layer-2 spawn primitive — clone an Image into a fresh VM
/// CapTable. Used by `vault.initialize` (kernel-driven) and
/// (eventually) by `call(ImageRef)` (guest-driven sub-VM creation).
///
/// Walks `image.slots`, translates each `RegCap` into a fresh
/// ephemeral `Cap`, places at the same slot index in `cap_table`.
/// Image's `init_cap` slot must hold a Code cap; that's the entry
/// program.
///
/// Slot 0 must be empty in the source image — javm reserves it for
/// the bare-Frame FrameRef.
///
/// Reads code / file bytes from the σ-resident registries
/// (`state.code_blobs`, `state.data_blobs`).
pub fn instantiate_from_image(
    state: &State,
    image: &Image,
    memory_pages: u32,
    mut code_cache: Option<&mut javm::CodeCache>,
    backend: javm::PvmBackend,
) -> KResult<InitArtifacts> {
    let mem_cycles = javm::compute_mem_cycles(memory_pages);

    if image.slots.get(0).is_some() {
        return Err(KernelError::Internal(
            "image slot 0 is occupied; slot 0 is reserved by javm for the bare-Frame FrameRef"
                .into(),
        ));
    }

    let mut backing = javm::backing::BackingStore::new(memory_pages).ok_or_else(|| {
        KernelError::Internal(format!("BackingStore::new({}) failed", memory_pages))
    })?;
    let mut untyped = javm::cap::UntypedCap::new(memory_pages);

    let mut cap_table: CapTable<ProtocolCap> = CapTable::new();
    let mut code_caps: Vec<Arc<javm::cap::CodeCap>> = Vec::new();

    for slot in 0u8..=255 {
        let vc = match image.slots.get(slot) {
            Some(c) => c,
            None => continue,
        };
        let cap = translate_vault_cap(
            state,
            vc,
            &mut code_caps,
            mem_cycles,
            backend,
            code_cache.as_deref_mut(),
            &mut untyped,
            &mut backing,
        )?;
        cap_table.set(slot, cap);
    }

    let init_code_id = match cap_table.get(image.init_cap) {
        Some(Cap::Code(c)) => c.id,
        Some(_) => {
            return Err(KernelError::Internal(format!(
                "image init_cap slot {} does not hold a Code cap",
                image.init_cap
            )));
        }
        None => {
            return Err(KernelError::Internal(format!(
                "image has no cap at init_cap slot {}",
                image.init_cap
            )));
        }
    };

    Ok(InitArtifacts {
        cap_table,
        code_caps,
        init_code_id,
        untyped,
        backing,
    })
}

/// Resolve a Vault's image and run `instantiate_from_image`. Used
/// by the kernel-driven `vault.initialize` path
/// (`vm::new_vm_from_vault`).
pub fn build_init_cap_table(
    state: &State,
    vault_id: VaultId,
    memory_pages: u32,
    code_cache: Option<&mut javm::CodeCache>,
    backend: javm::PvmBackend,
) -> KResult<InitArtifacts> {
    let vault = state.vault(vault_id)?;
    let image = state.images.get(&vault.image_id).ok_or_else(|| {
        KernelError::Internal(format!(
            "vault {:?} references missing image {:?}",
            vault_id, vault.image_id
        ))
    })?;
    instantiate_from_image(state, image.as_ref(), memory_pages, code_cache, backend)
}

#[allow(clippy::too_many_arguments)]
fn translate_vault_cap(
    state: &State,
    cap: &RegCap,
    code_caps: &mut Vec<Arc<javm::cap::CodeCap>>,
    mem_cycles: u8,
    backend: javm::PvmBackend,
    code_cache: Option<&mut javm::CodeCache>,
    untyped: &mut javm::cap::UntypedCap,
    backing: &mut javm::backing::BackingStore,
) -> KResult<Cap> {
    match cap {
        RegCap::VaultRef(vr) => Ok(Cap::Protocol(ProtocolCap::VaultRef(*vr))),
        RegCap::Code(c) => {
            if code_caps.len() >= javm::vm_pool::MAX_CODE_CAPS {
                return Err(KernelError::Internal(format!(
                    "vault holds more than {} CodeCap entries",
                    javm::vm_pool::MAX_CODE_CAPS
                )));
            }
            let entry = state.code_blobs.get(&c.code_id).ok_or_else(|| {
                KernelError::Internal(format!(
                    "image references missing code_blob {:?}",
                    c.code_id
                ))
            })?;
            let id = code_caps.len() as u16;
            let code_cap =
                javm::kernel::compile_code_blob(&entry.blob, id, mem_cycles, backend, code_cache)
                    .map_err(|e| KernelError::Internal(format!("compile_code_blob: {:?}", e)))?;
            code_caps.push(Arc::clone(&code_cap));
            Ok(Cap::Code(code_cap))
        }
        RegCap::File(f) => {
            let entry = state.data_blobs.get(&f.file_id).ok_or_else(|| {
                KernelError::Internal(format!(
                    "image references missing data_blob {:?}",
                    f.file_id
                ))
            })?;
            let data_cap =
                javm::kernel::allocate_data_cap(&entry.content, entry.page_count, untyped, backing)
                    .map_err(|e| KernelError::Internal(format!("allocate_data_cap: {:?}", e)))?;
            // Cap is unmapped on purpose — the init program calls MGMT_MAP.
            Ok(Cap::Data(data_cap))
        }
        RegCap::Resource(r) => Ok(Cap::Protocol(ProtocolCap::Resource(r.clone()))),
        RegCap::ImageRef(ir) => Ok(Cap::Protocol(ProtocolCap::ImageRef(*ir))),
        RegCap::StorageQuota(q) => Ok(Cap::Protocol(ProtocolCap::StorageQuota(*q))),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cap::{CodeCap, FileCap, QuotaId, VaultRefCap, VaultRights};

    /// Per-test memory budget. Generous enough for the small fixtures.
    const TEST_MEM_PAGES: u32 = 16;

    /// Build an Image with `init_cap = init_slot` and the given caps
    /// placed at their slots. Convenience for testing
    /// `instantiate_from_image` directly.
    fn build_image(init_slot: u8, caps: &[(u8, RegCap)]) -> Image {
        let mut image = Image {
            slots: crate::cap::CNode::default(),
            init_cap: init_slot,
        };
        for (slot, cap) in caps {
            image.slots.set(*slot, Some(cap.clone()));
        }
        image
    }

    /// Extract the raw code sub-blob (jump_table + code + bitmask) from
    /// the CODE manifest entry of jar-kernel's halt smoke fixture.
    fn halt_code_sub_blob() -> Vec<u8> {
        let blob = crate::genesis::halt_blob();
        let parsed = javm::program::parse_blob(blob).expect("parse halt_blob");
        let code_entry = parsed
            .caps
            .iter()
            .find(|e| matches!(e.cap_type, javm::program::CapEntryType::Code))
            .expect("no CODE entry in halt_blob");
        javm::program::cap_data(code_entry, parsed.data_section).to_vec()
    }

    /// Build a State with a "genesis" QuotaEntry and intern the halt
    /// code blob, returning (state, RegCap::Code referencing the blob).
    fn state_with_halt_code() -> (State, RegCap) {
        let mut state = State::empty();
        let qid = state.insert_storage_quota(u64::MAX / 2);
        let blob = halt_code_sub_blob();
        let byte_count = blob.len() as u64;
        let code_id = state.intern_code(blob, qid).expect("intern_code");
        (
            state,
            RegCap::Code(CodeCap {
                code_id,
                byte_count,
            }),
        )
    }

    #[test]
    fn single_codecap_at_init_slot() {
        let (state, halt) = state_with_halt_code();
        let image = build_image(64, &[(64, halt)]);
        let artifacts = instantiate_from_image(
            &state,
            &image,
            TEST_MEM_PAGES,
            None,
            javm::PvmBackend::Default,
        )
        .unwrap();

        assert_eq!(artifacts.code_caps.len(), 1);
        assert_eq!(artifacts.init_code_id, 0);
        assert!(matches!(artifacts.cap_table.get(64), Some(Cap::Code(_))));
    }

    #[test]
    fn vaultref_passthrough() {
        let (state, halt) = state_with_halt_code();
        let image = build_image(
            64,
            &[
                (64, halt),
                (
                    100,
                    RegCap::VaultRef(VaultRefCap {
                        vault_id: VaultId(99),
                        rights: VaultRights::ALL,
                    }),
                ),
            ],
        );
        let artifacts = instantiate_from_image(
            &state,
            &image,
            TEST_MEM_PAGES,
            None,
            javm::PvmBackend::Default,
        )
        .unwrap();
        match artifacts.cap_table.get(100) {
            Some(Cap::Protocol(ProtocolCap::VaultRef(vr))) => {
                assert_eq!(vr.vault_id, VaultId(99));
            }
            other => panic!(
                "expected ProtocolCap::VaultRef at slot 100, got {:?}",
                other
            ),
        }
    }

    #[test]
    fn filecap_propagated_unmapped() {
        let (mut state, halt) = state_with_halt_code();
        let qid = QuotaId(0); // genesis quota allocated above
        let file_id = state
            .allocate_file(b"hello".to_vec(), 1, qid)
            .expect("allocate_file");
        let image = build_image(
            64,
            &[
                (64, halt),
                (
                    65,
                    RegCap::File(FileCap {
                        file_id,
                        byte_count: 5,
                    }),
                ),
            ],
        );
        let artifacts = instantiate_from_image(
            &state,
            &image,
            TEST_MEM_PAGES,
            None,
            javm::PvmBackend::Default,
        )
        .unwrap();
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
        let state = State::empty();
        let image = build_image(64, &[]); // no Code at init slot
        let err = instantiate_from_image(
            &state,
            &image,
            TEST_MEM_PAGES,
            None,
            javm::PvmBackend::Default,
        )
        .err()
        .expect("error expected");
        assert!(matches!(err, KernelError::Internal(_)));
    }

    #[test]
    fn wrong_shape_at_init_cap_errors() {
        let state = State::empty();
        let image = build_image(
            64,
            &[(
                64,
                RegCap::VaultRef(VaultRefCap {
                    vault_id: VaultId(99),
                    rights: VaultRights::ALL,
                }),
            )],
        );
        let err = instantiate_from_image(
            &state,
            &image,
            TEST_MEM_PAGES,
            None,
            javm::PvmBackend::Default,
        )
        .err()
        .expect("error expected");
        assert!(matches!(err, KernelError::Internal(_)));
    }

    #[test]
    fn slot_zero_rejected() {
        let (state, halt) = state_with_halt_code();
        let image = build_image(64, &[(0, halt.clone()), (64, halt)]);
        let err = instantiate_from_image(
            &state,
            &image,
            TEST_MEM_PAGES,
            None,
            javm::PvmBackend::Default,
        )
        .err()
        .expect("error expected");
        assert!(matches!(err, KernelError::Internal(_)));
    }

    /// build_init_cap_table looks up the Vault's image via its
    /// image_id from `state.images`.
    #[test]
    fn build_init_cap_table_resolves_vault_image() {
        let (mut state, halt) = state_with_halt_code();
        let image = build_image(64, &[(64, halt)]);
        let image_id = state.next_image_id();
        state.images.insert(image_id, Arc::new(image));
        let vault_id = state.next_vault_id();
        state.vaults.insert(
            vault_id,
            Arc::new(crate::types::Vault {
                image_id,
                slots: crate::cap::CNode::default(),
            }),
        );
        let artifacts = build_init_cap_table(
            &state,
            vault_id,
            TEST_MEM_PAGES,
            None,
            javm::PvmBackend::Default,
        )
        .unwrap();
        assert!(matches!(artifacts.cap_table.get(64), Some(Cap::Code(_))));
    }
}
