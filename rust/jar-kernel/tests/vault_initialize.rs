//! Vault.initialize: end-to-end coverage for the CNode-driven init path.
//!
//! Builds a Vault by hand (CodeCap holding a raw code sub-blob extracted
//! from `halt_blob`), runs the new `vm::new_vm_from_vault` constructor,
//! and asserts the resulting kernel has the expected shape: VM 0 + bare
//! Frame in the arena, the CodeCap visible at slot 64 of VM 0's
//! CapTable.

use std::sync::Arc;

use jar_kernel::cap::{CodeCap, VaultRefCap, VaultRights};
use jar_kernel::vm::new_vm_from_vault;
use jar_kernel::{RegCap, State, Vault, VaultId};

const INIT_SLOT: u8 = 64;
const INVOCATION_GAS: u64 = 100_000_000;
const TEST_MEM_PAGES: u32 = 16;

/// Extract the raw code sub-blob (jump_table + code + bitmask) from
/// the CODE manifest entry of jar-kernel's halt smoke fixture.
fn halt_code_sub_blob() -> Vec<u8> {
    let blob = jar_kernel::genesis::halt_blob();
    let parsed = javm::program::parse_blob(blob).expect("parse halt_blob");
    let code_entry = parsed
        .caps
        .iter()
        .find(|e| matches!(e.cap_type, javm::program::CapEntryType::Code))
        .expect("no CODE entry in halt_blob");
    javm::program::cap_data(code_entry, parsed.data_section).to_vec()
}

fn vault_with_init_code() -> (State, VaultId) {
    use jar_kernel::cap::Image;
    let mut state = State::empty();
    let mut image = Image {
        slots: jar_kernel::cap::CNode::default(),
        init_cap: INIT_SLOT,
    };
    image.slots.set(
        INIT_SLOT,
        Some(RegCap::Code(CodeCap {
            blob: Arc::new(halt_code_sub_blob()),
        })),
    );
    let image_id = state.next_image_id();
    state.images.insert(image_id, Arc::new(image));
    let vault_id = state.next_vault_id();
    state
        .vaults
        .insert(vault_id, Arc::new(Vault::new(image_id)));
    (state, vault_id)
}

#[test]
fn new_vm_from_vault_smoke_test() {
    let (state, vault_id) = vault_with_init_code();

    let vm = new_vm_from_vault(
        &state,
        vault_id,
        INVOCATION_GAS,
        TEST_MEM_PAGES,
        None,
        jar_kernel::KernelRole::Process,
        None,
    )
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
    // Drop a FrameRef into the BareFrame ARG/RESULT slot directly,
    // then read it back via the new public helper. Mirrors what an
    // init program would do at runtime via MGMT_MOVE before halting:
    // slot 4 is the synchronous arg-in / result-out channel, so a
    // post-halt FrameRef there represents the public Callable that
    // the init program produced.
    let (state, vault_id) = vault_with_init_code();
    let mut vm = new_vm_from_vault(
        &state,
        vault_id,
        INVOCATION_GAS,
        TEST_MEM_PAGES,
        None,
        jar_kernel::KernelRole::Process,
        None,
    )
    .unwrap();
    let bare_idx = vm.bare_frame_id.index();
    let bare_id = vm.bare_frame_id;
    let frame_ref = javm::cap::FrameRefCap {
        vm_id: bare_id,
        rights: javm::cap::FrameRefRights::CALLABLE,
    };
    vm.vm_arena.vm_mut(bare_idx).cap_table.set(
        javm::kernel::BARE_ARG_SLOT,
        javm::cap::Cap::FrameRef(frame_ref),
    );
    let read = vm.read_bare_frame_slot(javm::kernel::BARE_ARG_SLOT);
    match read {
        Some(javm::cap::Cap::FrameRef(f)) => assert_eq!(f.vm_id, bare_id),
        other => panic!("expected FrameRef at BARE_ARG_SLOT, got {:?}", other),
    }
}

#[test]
fn initialize_callable_none_when_slot_empty() {
    let (state, vault_id) = vault_with_init_code();
    let vm = new_vm_from_vault(
        &state,
        vault_id,
        INVOCATION_GAS,
        TEST_MEM_PAGES,
        None,
        jar_kernel::KernelRole::Process,
        None,
    )
    .unwrap();
    assert!(
        vm.read_bare_frame_slot(javm::kernel::BARE_ARG_SLOT)
            .is_none()
    );
}

#[test]
fn set_args_places_data_cap_at_bare_frame_slot_4() {
    // Verifies the Commit-2 wiring: after `kernel.set_args(payload)`,
    // the args bytes land in a fresh DATA cap at `BARE_ARG_SLOT`
    // (= 4), and `VM 0.φ[7]` holds the payload length. The kernel
    // does *not* map the cap — the guest does that via
    // `javm_builtins::map_args` at runtime.
    let (state, vault_id) = vault_with_init_code();
    let mut vm = new_vm_from_vault(
        &state,
        vault_id,
        INVOCATION_GAS,
        TEST_MEM_PAGES,
        None,
        jar_kernel::KernelRole::Process,
        None,
    )
    .unwrap();

    let payload = b"hello world".to_vec();
    vm.set_args(&payload).expect("set_args ok");

    // φ[7] of VM 0 holds the args length.
    assert_eq!(vm.vm_arena.vm(0).reg(7), payload.len() as u64);

    // Bare-Frame slot 4 holds a Data cap covering one page (sufficient
    // for "hello world" = 11 bytes).
    let bare_idx = vm.bare_frame_id.index();
    match vm
        .vm_arena
        .vm(bare_idx)
        .cap_table
        .get(javm::kernel::BARE_ARG_SLOT)
    {
        Some(javm::cap::Cap::Data(d)) => {
            assert_eq!(d.page_count, 1, "11 bytes fits in 1 page");
            assert!(
                d.active_in.is_none(),
                "args cap is unmapped — guest will MGMT_MAP it"
            );
        }
        other => panic!(
            "expected Data cap at bare-Frame slot 4, got {:?}",
            other.is_some()
        ),
    }
}

#[test]
fn set_args_rejects_double_call() {
    // `set_args` must be called at most once per kernel; the second
    // call should error because slot 4 is already populated.
    let (state, vault_id) = vault_with_init_code();
    let mut vm = new_vm_from_vault(
        &state,
        vault_id,
        INVOCATION_GAS,
        TEST_MEM_PAGES,
        None,
        jar_kernel::KernelRole::Process,
        None,
    )
    .unwrap();

    vm.set_args(b"first").expect("first set_args ok");
    let err = vm.set_args(b"second").expect_err("second set_args fails");
    assert!(matches!(err, javm::kernel::KernelError::InvalidBlob));
}

#[test]
fn new_vm_from_vault_image_vault_ref_propagates() {
    use jar_kernel::cap::Image;

    let mut state = State::empty();
    let target_vault = VaultId(99);

    // Build an Image with both the init Code AND a VaultRef in its
    // slots — the Image clone projects both into the Frame's
    // CapTable.
    let mut image = Image {
        slots: jar_kernel::cap::CNode::default(),
        init_cap: INIT_SLOT,
    };
    image.slots.set(
        INIT_SLOT,
        Some(RegCap::Code(CodeCap {
            blob: Arc::new(halt_code_sub_blob()),
        })),
    );
    image.slots.set(
        100,
        Some(RegCap::VaultRef(VaultRefCap {
            vault_id: target_vault,
            rights: VaultRights::ALL,
        })),
    );
    let image_id = state.next_image_id();
    state.images.insert(image_id, Arc::new(image));
    let vault_id = state.next_vault_id();
    state
        .vaults
        .insert(vault_id, Arc::new(Vault::new(image_id)));

    let vm = new_vm_from_vault(
        &state,
        vault_id,
        INVOCATION_GAS,
        TEST_MEM_PAGES,
        None,
        jar_kernel::KernelRole::Process,
        None,
    )
    .expect("new_vm_from_vault succeeds");

    use jar_kernel::cap::{Cap, ProtocolCap};
    match vm.vm_arena.vm(0).cap_table.get(100) {
        Some(Cap::Protocol(ProtocolCap::VaultRef(vr))) => {
            assert_eq!(vr.vault_id, target_vault);
            assert_eq!(vr.rights, VaultRights::ALL);
        }
        other => panic!(
            "expected ProtocolCap::VaultRef at slot 100, got {:?}",
            other
        ),
    }
}
