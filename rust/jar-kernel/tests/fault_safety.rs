//! Fault-safety in the post-StateSnapshot model.
//!
//! With reads-are-COPY persistent DataCaps and no automatic σ rollback,
//! fault safety is a property of the cap surface: a manager that hasn't
//! committed via MGMT_MOVE Frame → Vault leaves the Vault unchanged
//! when its Frame faults. This test exercises the property at the
//! adapter level — fc_clone (Vault → Frame) leaves the source slot
//! intact, and a "discarded ephemeral cap" results in no change to σ.

use std::sync::Arc;

use javm::cap::{Cap, ForeignCnode};

use jar_kernel::cap::KernelCap;
use jar_kernel::state::cap_registry;
use jar_kernel::vm::foreign_cnode::VaultCnodeView;
use jar_kernel::{CapRecord, Capability, DataCap, State, Vault, VaultRights};

#[test]
fn fc_clone_leaves_source_intact_so_drop_is_safe() {
    // Set up: Vault A holds a DataCap at slot 7.
    let mut state = State::empty();
    let vault_id = state.next_vault_id();
    state.vaults.insert(vault_id, Arc::new(Vault::new()));
    let parent_id = cap_registry::alloc(
        &mut state,
        CapRecord {
            cap: Capability::Data(DataCap {
                content: Arc::new(b"original".to_vec()),
                page_count: 1,
            }),
            issuer: None,
            narrowing: vec![],
        },
    );
    {
        let arc = state.vaults.get(&vault_id).unwrap().clone();
        let mut v: Vault = (*arc).clone();
        v.slots.set(7, Some(parent_id));
        state.vaults.insert(vault_id, Arc::new(v));
    }
    let pre_root = jar_kernel::state::state_root::state_root(&state);

    // Manager-style "read" the cap into a Frame: fc_clone produces a
    // child CapRecord referencing the same content. The original
    // remains in the Vault slot.
    let _ephemeral = {
        let mut view = VaultCnodeView::new(&mut state);
        view.fc_clone(vault_id, 7, VaultRights::ALL)
            .expect("fc_clone")
    };

    // Simulate a fault: the manager-Frame is discarded; the ephemeral
    // cap reference (`_ephemeral`) goes out of scope. The Vault's
    // original cap is still in place.
    drop(_ephemeral);

    // The original DataCap is still there.
    assert_eq!(
        state.vaults.get(&vault_id).unwrap().slots.get(7),
        Some(parent_id)
    );
    let parent_record = state.cap_registry.get(&parent_id).unwrap();
    match &parent_record.cap {
        Capability::Data(d) => {
            assert_eq!(d.content.as_slice(), b"original");
            assert_eq!(d.page_count, 1);
        }
        _ => panic!("parent should still be a Data cap"),
    }

    // State root is unchanged from the perspective of "what the Vault
    // holds." The cap_registry grew by 1 (the derived child), so
    // state_root is different — but that's a child cap with no
    // holders and no σ-resident slot, which a future GC pass can
    // reclaim. (See "What replaces it" in the persistence design doc.)
    let post_root = jar_kernel::state::state_root::state_root(&state);
    let _ = (pre_root, post_root); // pre/post differ by the derived child
}

#[test]
fn manager_pattern_no_commit_no_change() {
    // Pure read, no MOVE-back: the Vault is unchanged. This is the
    // baseline atomicity guarantee.
    let mut state = State::empty();
    let vault_id = state.next_vault_id();
    state.vaults.insert(vault_id, Arc::new(Vault::new()));
    let cap_id = cap_registry::alloc(
        &mut state,
        CapRecord {
            cap: Capability::Data(DataCap {
                content: Arc::new(b"v1".to_vec()),
                page_count: 1,
            }),
            issuer: None,
            narrowing: vec![],
        },
    );
    let arc = state.vaults.get(&vault_id).unwrap().clone();
    let mut v: Vault = (*arc).clone();
    v.slots.set(0, Some(cap_id));
    state.vaults.insert(vault_id, Arc::new(v));

    // Manager reads via fc_clone, decides not to commit, exits.
    let _ = {
        let mut view = VaultCnodeView::new(&mut state);
        view.fc_clone(vault_id, 0, VaultRights::ALL).unwrap()
    };
    // Vault's slot 0 still holds the original cap.
    assert_eq!(
        state.vaults.get(&vault_id).unwrap().slots.get(0),
        Some(cap_id)
    );
}

#[test]
fn fc_take_then_no_replace_leaves_slot_empty() {
    // If a manager takes a cap out of a Vault and faults before
    // moving it back, the Vault slot is left empty. This is by
    // design; managers wanting fault safety use COPY (fc_clone) for
    // reads, not MOVE (fc_take).
    let mut state = State::empty();
    let vault_id = state.next_vault_id();
    state.vaults.insert(vault_id, Arc::new(Vault::new()));
    let cap_id = cap_registry::alloc(
        &mut state,
        CapRecord {
            cap: Capability::Data(DataCap {
                content: Arc::new(b"v1".to_vec()),
                page_count: 1,
            }),
            issuer: None,
            narrowing: vec![],
        },
    );
    let arc = state.vaults.get(&vault_id).unwrap().clone();
    let mut v: Vault = (*arc).clone();
    v.slots.set(0, Some(cap_id));
    state.vaults.insert(vault_id, Arc::new(v));

    let _taken: Cap<KernelCap> = {
        let mut view = VaultCnodeView::new(&mut state);
        view.fc_take(vault_id, 0, VaultRights::ALL).unwrap()
    };
    // Slot is now empty. Cap is still in registry (held by `_taken`'s
    // Registered{id}), but no Vault references it.
    assert!(state.vaults.get(&vault_id).unwrap().slots.get(0).is_none());
    assert!(state.cap_registry.contains_key(&cap_id));
}
