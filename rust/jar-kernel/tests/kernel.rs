use jar_kernel::abi;
use jar_kernel::apply::{Block, Event};
use jar_kernel::kernel::Kernel;
use javm_cap::image::{EndpointDef, Image};
use std::collections::BTreeMap;

fn minimal_chain_image() -> Image {
    // PVM2 program: `ecalli 0` (HALT) at PC 0.
    //   custom-0 opcode (0b00010 << 2) | 0b11, funct3 = 0b010, all
    //   register fields zero: encodes as the 32-bit word 0x0000_200B.
    let mut endpoints = BTreeMap::new();
    endpoints.insert(
        0,
        EndpointDef {
            entry_pc: 0,
            arg_registers: 0,
            arg_cnode_size: 0,
            initial_regs: BTreeMap::new(),
        },
    );
    Image {
        code: 0x0000_200Bu32.to_le_bytes().to_vec(),
        endpoints,
        // Code is mapped at the fixed CODE_BASE; no data mappings.
        memory_mappings: Vec::new(),
        gas_slots: vec![abi::BARE_GAS_SLOT],
        quota_slots: vec![abi::BARE_QUOTA_SLOT],
        pinned_slots: BTreeMap::new(),
        initial_slots: BTreeMap::new(),
        yield_marker_slot: Some(abi::BARE_YIELD_CATCHER_SLOT),
    }
}

#[test]
fn kernel_from_genesis_yields_deterministic_state_root() {
    let k1 = Kernel::from_genesis(minimal_chain_image());
    let k2 = Kernel::from_genesis(minimal_chain_image());
    assert_eq!(k1.state_root(), k2.state_root());
}

#[test]
fn kernel_apply_advances_state_root_via_payload_publish() {
    // The minimal_chain_image program halts with 42 (or traps,
    // depending on bytecode validity). Regardless of the exit
    // status, the event payload gets published as a DataCap in σ
    // before the call — that publish alone changes state_root.
    let mut kernel = Kernel::from_genesis(minimal_chain_image());
    let root_0 = kernel.state_root();

    let block = Block {
        events: vec![Event {
            endpoint_idx: 0,
            payload: b"hello".to_vec(),
        }],
    };
    let outcomes = kernel.apply(&block, 10_000, 10_000).unwrap();
    let root_1 = kernel.state_root();

    assert_ne!(root_0, root_1);
    assert_eq!(outcomes.len(), 1);
}

#[test]
fn kernel_apply_replay_is_deterministic() {
    // Same chain image, same block → same post-apply root.
    let mut k1 = Kernel::from_genesis(minimal_chain_image());
    let mut k2 = Kernel::from_genesis(minimal_chain_image());
    let block = || Block {
        events: vec![Event {
            endpoint_idx: 0,
            payload: b"replay-determinism".to_vec(),
        }],
    };
    let _ = k1.apply(&block(), 10_000, 10_000).unwrap();
    let _ = k2.apply(&block(), 10_000, 10_000).unwrap();
    assert_eq!(k1.state_root(), k2.state_root());
}
