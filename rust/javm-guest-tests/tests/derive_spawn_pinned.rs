//! Regression: `host_derive_spawn` into a **pinned** dst slot must TRAP in
//! BOTH engines.
//!
//! Pre-fix the interpreter rejected a write to a pinned (read-only) slot
//! (`OpError::SlotPinned` → `ExitReason::Trap`) but the x86 recompiler wrote
//! the child instance ref into the pinned slot and continued — a silent
//! interp≠recomp consensus fork that no existing differential exercised
//! (`derive_spawn` is only fuzzed with non-pinned dsts). The recompiler now
//! carries a per-frame pinned-key set and traps on a pinned dst, matching the
//! interpreter; this test pins that agreement.
//!
//! The guest program is a single `ecalli OP_DERIVE_SPAWN`; the slot operands
//! are passed as invocation args (φ[7]=image_slot, φ[9]=dst), so no
//! register-setup code is needed.

use javm::kernel_assist::InProcessKernelAssist;
use javm::{CallResult, Vm};
use javm_cap::image::{EndpointDef, Image, PinnedCap};
use javm_cap::{CacheDirectory, Cap, CapHash, CapHashOrRef, SlotKey, NUM_REGS};
use javm_exec::ExitReason;
use std::collections::BTreeMap;

const OP_DERIVE_SPAWN: u32 = 18;
/// A slot holding the (pinned) child `Cap::Image` — the `derive_spawn`
/// `image_slot`. Pinned, but never written, so legal.
const IMAGE_SLOT: u8 = 3;
/// A pinned `Cap::Data` slot — an illegal `derive_spawn` dst.
const PINNED_DST: u8 = 66;
const GAS_BUDGET: u64 = 10_000_000_000;

/// custom-0 `ecalli imm` encoding (funct3=010, opcode=0x0b), mirroring the
/// transpiler's `encode_custom0_ecalli`.
fn ecalli(imm: u32) -> u32 {
    ((imm & 0xFFF) << 20) | (0b010 << 12) | 0b000_1011
}

/// The child image `image_slot` points at — minimal; never executed (the
/// spawn traps before the child runs).
fn child_image() -> Image {
    Image::empty()
}

/// Parent image: one `ecalli OP_DERIVE_SPAWN`. `image_slot` (slot 3) is a
/// pinned `Cap::Image`; the dst (slot 66) is a pinned `Cap::Data`.
fn parent_image(child_hash: CapHash) -> Image {
    let mut endpoints = BTreeMap::new();
    endpoints.insert(
        0u8,
        EndpointDef {
            // Code-region byte offset (the runtime adds CODE_BASE); the
            // single instruction sits at offset 0.
            entry_pc: 0,
            arg_registers: 0,
            arg_cnode_size: 0,
            initial_regs: BTreeMap::new(),
        },
    );
    let mut pinned_slots = BTreeMap::new();
    pinned_slots.insert(
        SlotKey::from(IMAGE_SLOT),
        PinnedCap::Image {
            content_hash: child_hash,
        },
    );
    pinned_slots.insert(
        SlotKey::from(PINNED_DST),
        PinnedCap::Data {
            content: vec![0xAB; 16],
            size: 4096,
        },
    );
    Image {
        code: ecalli(OP_DERIVE_SPAWN).to_le_bytes().to_vec(),
        endpoints,
        memory_mappings: Vec::new(),
        pinned_slots,
        initial_slots: BTreeMap::new(),
        yield_marker_slot: None,
    }
}

/// φ[7]=image_slot, φ[8]=cnode_slot(unused), φ[9]=dst — matching the 3-arg
/// cached `derive_spawn` ABI both engines use under `invoke_cached`.
const INVOKE_ARGS: [u64; 4] = [IMAGE_SLOT as u64, 0, PINNED_DST as u64, 0];

#[test]
fn interp_traps_on_derive_spawn_into_pinned() {
    let mut cache = CacheDirectory::new();

    let child_cap = Cap::image_with_slots(&child_image(), &[], &[]).expect("child image");
    let child_hash = cache.put_cap(&child_cap).expect("put child image");
    let data_hash = cache
        .put_cap(&Cap::data_inline_with_size(&[0xAB; 16], 4096))
        .expect("put pinned data");

    let parent = parent_image(child_hash);
    let pinned_hashes = [
        (SlotKey::from(IMAGE_SLOT), child_hash),
        (SlotKey::from(PINNED_DST), data_hash),
    ];
    let parent_cap = Cap::image_with_slots(&parent, &pinned_hashes, &[]).expect("parent image");
    let parent_hash = cache.put_cap(&parent_cap).expect("put parent image");

    // Root cnode binds the two slots so the interpreter resolves image_slot
    // and reaches the pinned-dst check.
    let mut cn = javm_cap::CNodeCap::new();
    cn.set(
        &SlotKey::from(IMAGE_SLOT),
        Some(CapHashOrRef::Hash(child_hash)),
    )
    .unwrap();
    cn.set(
        &SlotKey::from(PINNED_DST),
        Some(CapHashOrRef::Hash(data_hash)),
    )
    .unwrap();
    let cnode_hash = cache.put_cap(&Cap::CNode(cn)).expect("put cnode");

    let mem = parent.instance_mem_backing();
    let inst_hash = cache
        .put_cap(&Cap::instance_with_mem(
            [0u8; 32],
            parent_hash,
            cnode_hash,
            mem,
            [0u64; NUM_REGS],
            0,
            0,
        ))
        .expect("put instance");

    let mut vm = Vm::new(InProcessKernelAssist::new());
    let result = vm
        .invoke_cached(&mut cache, inst_hash, 0, INVOKE_ARGS, GAS_BUDGET)
        .expect("invoke_cached");
    match result {
        CallResult::Faulted { reason, .. } => assert_eq!(
            reason,
            ExitReason::Trap,
            "interpreter must Trap on derive_spawn into a pinned slot",
        ),
        other => panic!("expected Faulted(Trap), got {other:?}"),
    }
}

#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
#[test]
fn recomp_traps_on_derive_spawn_into_pinned() {
    use nub::Nub;

    // JIT codegen ABI: `ExitReason::Trap` surfaces as exit_reason 7.
    const EXIT_TRAP: u32 = 7;

    let mut nub = Nub::new_hyperlight().expect("Hyperlight sandbox");

    let child_cap = Cap::image_with_slots(&child_image(), &[], &[]).expect("child image");
    let child_hash = nub.put_cap(&child_cap).expect("put child image");
    let data_hash = nub
        .put_cap(&Cap::data_inline_with_size(&[0xAB; 16], 4096))
        .expect("put pinned data");

    let parent = parent_image(child_hash);
    let pinned_hashes = [
        (SlotKey::from(IMAGE_SLOT), child_hash),
        (SlotKey::from(PINNED_DST), data_hash),
    ];
    let parent_cap = Cap::image_with_slots(&parent, &pinned_hashes, &[]).expect("parent image");
    let image_h = nub.put_cap(&parent_cap).expect("put parent image");
    // The recompiler seeds frame.cnode (and its pinned set) from the image's
    // pinned/initial slots, so an empty root cnode is fine.
    let cnode_h = nub.put_cap(&Cap::empty_cnode()).expect("put cnode");

    let mem = parent.instance_mem_backing();
    let inst_h = nub
        .put_cap(&Cap::instance_with_mem(
            [0u8; 32],
            image_h,
            cnode_h,
            mem,
            [0u64; NUM_REGS],
            0,
            0,
        ))
        .expect("put instance");

    let result = nub
        .invoke_cached(inst_h, 0, INVOKE_ARGS, GAS_BUDGET)
        .expect("invoke_cached");
    assert_eq!(
        result.exit_reason, EXIT_TRAP,
        "recompiler must Trap (7) on derive_spawn into a pinned slot, got exit_reason={} arg={}",
        result.exit_reason, result.exit_arg,
    );
}
