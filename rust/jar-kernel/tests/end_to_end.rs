//! End-to-end v3 chain demonstration.
//!
//! Exercises the full v3 stack:
//!   jar-cap (cap kinds, MGMT ops, Image, BMT)
//!     ↓
//!   javm-exec (PVM interpreter + recompiler)
//!     ↓
//!   javm (Vm + CallStack + KernelAssist + MGMT/host-call dispatch)
//!     ↓
//!   jar-kernel (σ + state_root + Kernel + Block apply)
//!
//! The chain Image used here is hand-authored PVM bytecode (no
//! Rust→javm pipeline yet — that's future work via the build-javm
//! step on the v3 transpiler). The chain HALTs with a known return
//! value when invoked, demonstrating successful Kernel::apply
//! round-trips and observable state-root evolution as σ.data_payloads
//! accumulates per-block event-payload entries.

use jar_cap::image::{EndpointDef, Image, MemoryMapping};
use jar_kernel::{Block, Event, EventOutcome, Kernel, abi};
use std::collections::BTreeMap;

/// Build a tiny chain image whose endpoint 0 program is:
///   load_imm_64 φ[7] = 42 ; ecalli 0 (HALT)
///
/// The chain doesn't do anything interesting — it just demonstrates
/// the kernel-apply round-trip succeeds (event delivered, program
/// runs, HALT observed, σ post-apply hash is well-defined).
fn hello_world_chain_image() -> Image {
    // Byte-PVM encoding:
    //   load_imm_64 φ[7] = 42 → opcode 20, reg 7, 8 imm bytes = [42, 0, 0, 0, 0, 0, 0, 0]
    //     bitmask: [1, 0,0,0,0,0,0,0,0,0]
    //   ecalli 0 → opcode 10, imm byte 0
    //     bitmask: [1, 0]
    // Need to embed the bitmask in the program; the chain Image
    // doesn't currently carry it (Stage 3 derives a trivial
    // "every byte is an instruction" bitmask via run_instance's
    // ImageCache::get_or_decode default). To exercise the real
    // load_imm_64 path we'd need to wire the kernel to feed
    // jar-cap's image_canonical_encoding through a parser that
    // recovers code + bitmask + jump_table.
    //
    // For this end-to-end test we use a minimal program that works
    // under the default bitmask: a single `ecalli 0` (HALT). The
    // bitmask interpretation "every byte starts a new instruction"
    // makes the imm byte after opcode-10 invalid as a standalone
    // instruction, but the interpreter exits on the first ecalli
    // it hits so this is fine.
    let code = vec![10u8, 0];

    let mut endpoints = BTreeMap::new();
    endpoints.insert(
        0u8,
        EndpointDef {
            entry_pc: 0,
            arg_registers: 0,
            arg_cnode_size: 0,
            initial_regs: BTreeMap::new(),
        },
    );

    Image {
        code,
        endpoints,
        memory_mappings: Vec::<MemoryMapping>::new(),
        gas_slots: vec![abi::BARE_GAS_SLOT],
        quota_slots: vec![abi::BARE_QUOTA_SLOT],
        pinned_slots: BTreeMap::new(),
        initial_slots: BTreeMap::new(),
        yield_marker_slot: Some(abi::BARE_YIELD_CATCHER_SLOT),
    }
}

#[test]
fn genesis_yields_stable_state_root_for_identical_images() {
    let k1 = Kernel::from_genesis(hello_world_chain_image());
    let k2 = Kernel::from_genesis(hello_world_chain_image());
    assert_eq!(k1.state_root(), k2.state_root());
}

#[test]
fn single_event_apply_halts_and_advances_state_root() {
    let mut k = Kernel::from_genesis(hello_world_chain_image());
    let root_pre = k.state_root();

    let block = Block {
        events: vec![Event {
            endpoint_idx: 0,
            payload: b"event-1".to_vec(),
        }],
    };
    let outcomes = k.apply(&block, 100_000, 1_000_000).unwrap();
    assert_eq!(outcomes.len(), 1);
    assert!(
        matches!(outcomes[0], EventOutcome::Halt { .. }),
        "expected Halt, got {:?}",
        outcomes[0]
    );

    let root_post = k.state_root();
    assert_ne!(
        root_pre, root_post,
        "applying an event must advance state_root (payload bytes registered in σ.data_payloads)"
    );
}

#[test]
fn multi_block_apply_advances_state_root_each_step() {
    let mut k = Kernel::from_genesis(hello_world_chain_image());
    let r0 = k.state_root();

    let _ = k
        .apply(
            &Block {
                events: vec![Event {
                    endpoint_idx: 0,
                    payload: b"block-1".to_vec(),
                }],
            },
            100_000,
            1_000_000,
        )
        .unwrap();
    let r1 = k.state_root();

    let _ = k
        .apply(
            &Block {
                events: vec![Event {
                    endpoint_idx: 0,
                    payload: b"block-2".to_vec(),
                }],
            },
            100_000,
            1_000_000,
        )
        .unwrap();
    let r2 = k.state_root();

    assert_ne!(r0, r1);
    assert_ne!(r1, r2);
    assert_ne!(r0, r2);
}

#[test]
fn identical_apply_sequences_produce_identical_state_roots() {
    let mut k1 = Kernel::from_genesis(hello_world_chain_image());
    let mut k2 = Kernel::from_genesis(hello_world_chain_image());

    let block_a = Block {
        events: vec![Event {
            endpoint_idx: 0,
            payload: b"alice-to-bob".to_vec(),
        }],
    };
    let block_b = Block {
        events: vec![Event {
            endpoint_idx: 0,
            payload: b"bob-to-carol".to_vec(),
        }],
    };

    k1.apply(&block_a, 100_000, 1_000_000).unwrap();
    k1.apply(&block_b, 100_000, 1_000_000).unwrap();
    k2.apply(&block_a, 100_000, 1_000_000).unwrap();
    k2.apply(&block_b, 100_000, 1_000_000).unwrap();

    assert_eq!(
        k1.state_root(),
        k2.state_root(),
        "deterministic apply: same image + same blocks → same root"
    );
}

#[test]
fn distinct_payloads_produce_distinct_state_roots() {
    // Two kernels, both apply a single event but with different
    // payload bytes. Post-apply state_roots must differ since
    // σ.data_payloads diverges on the payload hash.
    let mut k1 = Kernel::from_genesis(hello_world_chain_image());
    let mut k2 = Kernel::from_genesis(hello_world_chain_image());

    k1.apply(
        &Block {
            events: vec![Event {
                endpoint_idx: 0,
                payload: b"payload-a".to_vec(),
            }],
        },
        100_000,
        1_000_000,
    )
    .unwrap();
    k2.apply(
        &Block {
            events: vec![Event {
                endpoint_idx: 0,
                payload: b"payload-b".to_vec(),
            }],
        },
        100_000,
        1_000_000,
    )
    .unwrap();

    assert_ne!(k1.state_root(), k2.state_root());
}
