//! Vault.initialize: end-to-end coverage for the CNode-driven init path.
//!
//! Builds a Vault by hand (CodeCap holding a raw code sub-blob extracted
//! from `halt_blob`), runs the new `vm::new_vm_from_vault` constructor,
//! and asserts the resulting kernel has the expected shape: VM 0 + bare
//! Frame in the arena, the CodeCap visible at slot 64 of VM 0's
//! CapTable.

use std::sync::Arc;

use jar_kernel::cap::{CodeCap, VaultRefCap, VaultRights};
use jar_kernel::state::cap_registry;
use jar_kernel::vm::new_vm_from_vault;
use jar_kernel::{CapRecord, Capability, State, Vault, VaultId};

const INIT_SLOT: u8 = 64;
const INVOCATION_GAS: u64 = 100_000_000;

/// Extract the raw code sub-blob (jump_table + code + bitmask) from
/// the CODE manifest entry of jar-kernel's halt smoke fixture.
fn halt_code_sub_blob() -> Vec<u8> {
    let blob = jar_kernel::state::code_blobs::halt_blob();
    let parsed = javm::program::parse_blob(blob).expect("parse halt_blob");
    let code_entry = parsed
        .caps
        .iter()
        .find(|e| matches!(e.cap_type, javm::program::CapEntryType::Code))
        .expect("no CODE entry in halt_blob");
    javm::program::cap_data(code_entry, parsed.data_section).to_vec()
}

fn vault_with_init_code() -> (State, VaultId) {
    let mut state = State::empty();
    let vault_id = state.next_vault_id();
    let mut v = Vault::new();
    v.init_cap = INIT_SLOT;
    v.quota_pages = 16;
    state.vaults.insert(vault_id, Arc::new(v));

    let code_cap_id = cap_registry::alloc(
        &mut state,
        CapRecord {
            cap: Capability::Code(CodeCap {
                blob: Arc::new(halt_code_sub_blob()),
            }),
            issuer: None,
            narrowing: vec![],
        },
    );
    let arc = state.vaults.get(&vault_id).unwrap().clone();
    let mut v: Vault = (*arc).clone();
    v.slots.set(INIT_SLOT, Some(code_cap_id));
    state.vaults.insert(vault_id, Arc::new(v));

    (state, vault_id)
}

#[test]
fn new_vm_from_vault_smoke_test() {
    let (state, vault_id) = vault_with_init_code();

    let vm = new_vm_from_vault(&state, vault_id, INVOCATION_GAS, None)
        .expect("new_vm_from_vault succeeds");

    // Two arena entries: VM 0 (root) + bare Frame.
    assert_eq!(vm.vm_arena.len(), 2);
    // Single CodeCap in code_caps (the init CodeCap).
    assert_eq!(vm.code_caps.len(), 1);
    // Slot 64 of VM 0 holds the Code cap (init slot per the test fixture).
    assert!(matches!(
        vm.vm_arena.vm(0).cap_table.get(INIT_SLOT),
        Some(javm::cap::Cap::Code(_))
    ));
}

#[test]
fn initialize_callable_slot_read_returns_some_when_present() {
    // Drop a FrameRef into bare-Frame slot 4 directly, then read it
    // back via the new public helper. Mirrors what an init program
    // would do at runtime via MGMT_MOVE before halting.
    let (state, vault_id) = vault_with_init_code();
    let mut vm = new_vm_from_vault(&state, vault_id, INVOCATION_GAS, None).unwrap();
    let bare_idx = vm.bare_frame_id.index();
    let bare_id = vm.bare_frame_id;
    let frame_ref = javm::cap::FrameRefCap {
        vm_id: bare_id,
        rights: javm::cap::FrameRefRights::CALLABLE,
    };
    vm.vm_arena.vm_mut(bare_idx).cap_table.set(
        jar_kernel::vm::INITIALIZE_CALLABLE_SLOT,
        javm::cap::Cap::FrameRef(frame_ref),
    );
    let read = vm.read_bare_frame_slot(jar_kernel::vm::INITIALIZE_CALLABLE_SLOT);
    match read {
        Some(javm::cap::Cap::FrameRef(f)) => assert_eq!(f.vm_id, bare_id),
        other => panic!("expected FrameRef at slot 4, got {:?}", other),
    }
}

#[test]
fn initialize_callable_none_when_slot_4_empty() {
    let (state, vault_id) = vault_with_init_code();
    let vm = new_vm_from_vault(&state, vault_id, INVOCATION_GAS, None).unwrap();
    assert!(
        vm.read_bare_frame_slot(jar_kernel::vm::INITIALIZE_CALLABLE_SLOT)
            .is_none()
    );
}

#[test]
fn new_vm_from_vault_extra_persistent_cap_propagates() {
    let (mut state, vault_id) = vault_with_init_code();

    // Add a VaultRef at slot 100.
    let target_vault = VaultId(99);
    let vr_cap_id = cap_registry::alloc(
        &mut state,
        CapRecord {
            cap: Capability::VaultRef(VaultRefCap {
                vault_id: target_vault,
                rights: VaultRights::ALL,
            }),
            issuer: None,
            narrowing: vec![],
        },
    );
    let arc = state.vaults.get(&vault_id).unwrap().clone();
    let mut v: Vault = (*arc).clone();
    v.slots.set(100, Some(vr_cap_id));
    state.vaults.insert(vault_id, Arc::new(v));

    let vm = new_vm_from_vault(&state, vault_id, INVOCATION_GAS, None)
        .expect("new_vm_from_vault succeeds");

    // Slot 100 should hold the registered VaultRef.
    use jar_kernel::cap::KernelCap;
    match vm.vm_arena.vm(0).cap_table.get(100) {
        Some(javm::cap::Cap::Protocol(KernelCap::Registered {
            id,
            cap: Capability::VaultRef(vr),
        })) => {
            assert_eq!(*id, vr_cap_id);
            assert_eq!(vr.vault_id, target_vault);
        }
        other => panic!("expected Registered VaultRef at slot 100, got {:?}", other),
    }
}
