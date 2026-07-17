//! The KVM substrate supports at most ONE live Hyperlight sandbox per
//! process: the guest-VA window is a single process-wide fixed
//! reservation and every sandbox `MAP_FIXED`-overlays its kernel-shadow
//! at the same VA inside it, so a second sandbox would silently corrupt
//! the first one's guest memory (see
//! `nub_host_kvm::HyperlightError::SandboxAlreadyCreated`).
//!
//! This test owns its process (integration tests are separate
//! binaries): the first construction — via the javm singleton — must
//! succeed and stay reusable, while a direct second substrate-level
//! construction must fail loudly.

use std::collections::BTreeMap;

use javm::{Javm, Nub, NubOptions};
use javm_cap::image::{EndpointDef, Image};
use javm_cap::{Cap, Key, NUM_REGS};

const TESTS_BLOB_PATH: &str = env!("JAVM_GUEST_X86_BLOB_TESTS");

/// Build a minimal PVM2 Image whose endpoint 0 runs `ecalli 42` at PC 0
/// (same program as `tests/smoke.rs`).
fn ecalli_42_image() -> Image {
    let mut img = Image::with_code(0x02A0_200Bu32.to_le_bytes().to_vec());
    let mut endpoints: BTreeMap<Key, EndpointDef> = BTreeMap::new();
    endpoints.insert(
        Key::from(0u8),
        EndpointDef {
            entry_pc: 0,
            arg_registers: 0,
            arg_cnode_size: 0,
            initial_regs: BTreeMap::new(),
        },
    );
    img.endpoints = endpoints;
    img
}

#[test]
fn second_sandbox_construction_fails_loudly() {
    // First construction: the javm singleton boots the tests blob.
    let nub = Nub::hyperlight_tests().expect("first sandbox construction");

    // Singleton re-borrow must keep working: it reuses the one live
    // sandbox and never constructs a second one.
    let _again = Nub::hyperlight_tests().expect("singleton re-borrow");

    // A direct second substrate-level construction must fail loudly,
    // even though the first sandbox is still live.
    let err = match nub::Nub::<Javm>::create_hyperlight(TESTS_BLOB_PATH, NubOptions::default()) {
        Ok(_) => panic!("second sandbox construction must fail"),
        Err(e) => e,
    };
    let msg = format!("{err:#}");
    assert!(
        msg.contains("at most one live sandbox per process"),
        "unexpected error message: {msg}"
    );

    // The rejected construction acquired nothing: the first sandbox
    // still publishes and invokes.
    let img = ecalli_42_image();
    let image_cap = Cap::image_with_slots(&img, &[], &[]).expect("image_with_slots");
    let image_h = nub.put_cap(&image_cap).expect("put_cap image");
    let cnode_h = nub.put_cap(&Cap::empty_cnode()).expect("put_cap cnode");
    let instance_cap = Cap::instance_with_mem(
        [0u8; 32],
        image_h,
        cnode_h,
        javm_cap::DataCap::from_bytes_sized(&[], 4096),
        [0u64; NUM_REGS],
        0,
        0,
    );
    let instance_h = nub.put_cap(&instance_cap).expect("put_cap instance");
    let result = nub
        .invoke_cached(instance_h, 0, [0; 4], 1_000)
        .expect("invoke_cached on the surviving sandbox");
    assert_eq!(result.exit_reason, 4, "expected HostCall");
    assert_eq!(result.exit_arg, 42, "expected ecalli imm");
}
