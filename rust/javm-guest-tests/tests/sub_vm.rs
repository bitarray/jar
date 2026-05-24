//! End-to-end sub-VM lifecycle test.
//!
//! Drives the M→`derive_spawn(S)`→`host_call(S)`→REPLY→HALT
//! lifecycle through `javm::Vm::invoke_cached` using the two
//! transpiled Image blobs built by `build.rs`:
//!
//! - `SPAWN_PARENT_M_BLOB` — Image M (the parent).
//! - `SPAWN_CHILD_S_BLOB` — Image S (the child).
//!
//! M's bytecode (see `components/tests/spawn-parent-m`) mints a
//! fresh prepared CNode, moves the harness-supplied input DataCap
//! into `slot[0]`, calls `derive_spawn(SLOT_IMAGE_S, SLOT_PREP, dst)`,
//! `host_call`s the resulting `Cap::Instance`, and reads the
//! reflected `slot[0]` after S halts.
//!
//! S's bytecode (see `components/tests/spawn-child-s`) reads its
//! `slot[0]` DataCap, computes the wrapping byte-sum, mints a
//! single-byte result DataCap, places it at `slot[0]`, and HALTs.

use allocate::Global;
use javm::kernel_assist::{InProcessKernelAssist, KernelAssist};
use javm::{CallResult, Vm};
use javm_cap::image::{Image, PinnedCap};
use javm_cap::{CacheDirectory, Cap, CapHashOrRef, SlotIdx, NUM_REGS};
use ssz::Decode;

const M_BLOB: &[u8] = include_bytes!(env!("SPAWN_PARENT_M_BLOB"));
const S_BLOB: &[u8] = include_bytes!(env!("SPAWN_CHILD_S_BLOB"));
const GAS_BUDGET: u64 = 10_000_000_000;
const INPUT_BYTES: &[u8] = b"hello";

/// Slot layout — must match `spawn-parent-m/src/main.rs`.
const SLOT_IMAGE_S: u8 = 3;
const SLOT_INPUT_DATA: u8 = 5;

#[test]
fn m_calls_s_round_trip() {
    let m_image = Image::from_ssz_bytes(M_BLOB).expect("decode M");
    let s_image = Image::from_ssz_bytes(S_BLOB).expect("decode S");

    let mut cache = CacheDirectory::new_in(Global);

    // Publish S's Image (plus its pinned + initial slots' data caps,
    // resolved via the same helper the bench harness uses).
    let s_image_hash = publish_image(&mut cache, &s_image);

    // Publish M's Image.
    let m_image_hash = publish_image(&mut cache, &m_image);

    // Publish the input DataCap (wrapping byte-sum target for S).
    let input_hash = cache
        .put_cap(&Cap::data_inline(INPUT_BYTES))
        .expect("put input data");

    // Build M's root cnode. Populate the harness-managed slots —
    // M's pinned + initial overlays go on top via
    // `publish_instance` below.
    let m_pinned = collect_pinned_hashes(&mut cache, &m_image);
    let m_initial = collect_initial_hashes(&mut cache, &m_image);

    let mut m_cnode = javm_cap::CNodeCap::new(8).expect("cnode");
    m_cnode
        .set(
            SlotIdx(SLOT_IMAGE_S as u32),
            Some(CapHashOrRef::Hash(s_image_hash)),
        )
        .expect("set image_s slot");
    m_cnode
        .set(
            SlotIdx(SLOT_INPUT_DATA as u32),
            Some(CapHashOrRef::Hash(input_hash)),
        )
        .expect("set input slot");
    // Overlay M's pinned + initial slot hashes (stack/ro/rw/heap).
    for (slot, h) in &m_pinned {
        m_cnode
            .set(*slot, Some(CapHashOrRef::Hash(*h)))
            .expect("set pinned");
    }
    for (slot, h) in &m_initial {
        if m_cnode.get(*slot).is_none() {
            m_cnode
                .set(*slot, Some(CapHashOrRef::Hash(*h)))
                .expect("set initial");
        }
    }
    let m_cnode_hash = cache.put_cap(&Cap::CNode(m_cnode)).expect("put cnode");

    // Build M's runtime memory layout from its image mappings.
    let (mem_size, overlays) = build_overlays(&m_image);
    let overlay_slices: Vec<(u32, &[u8])> =
        overlays.iter().map(|(s, b)| (*s, b.as_slice())).collect();

    // Seed φ from the endpoint's initial_regs (sp = stack_top, etc.).
    let endpoint = m_image.endpoints.get(&0).expect("M endpoint 0");
    let mut regs = [0u64; NUM_REGS];
    for (&i, &v) in &endpoint.initial_regs {
        if let Some(slot) = regs.get_mut(i as usize) {
            *slot = v;
        }
    }

    let m_instance_hash = cache
        .put_cap(&Cap::instance_with_overlays(
            [0u8; 32],
            m_image_hash,
            m_cnode_hash,
            &overlay_slices,
            mem_size,
            regs,
            0,
            0,
        ))
        .expect("put M instance");

    // Drive the apply. Seed a large storage quota at id 0 since
    // S's `host_mint_data_cap` debits the canonical-byte count; the
    // plan defers full quota wiring (test runs with a huge bucket).
    let mut vm = Vm::new(InProcessKernelAssist::new());
    vm.kernel_assist.storage_quota_set(0, u64::MAX / 2);
    let result = vm
        .invoke_cached(&mut cache, m_instance_hash, 0, [0; 4], GAS_BUDGET)
        .expect("invoke_cached");

    let return_value = match result {
        CallResult::Halt { return_value, .. } => return_value,
        other => panic!("expected Halt, got {other:?}"),
    };

    let expected: u64 = INPUT_BYTES.iter().fold(0u8, |acc, &b| acc.wrapping_add(b)) as u64;
    assert_eq!(
        return_value, expected,
        "M's return value should equal the wrapping byte-sum of {:?}",
        INPUT_BYTES,
    );
}

fn publish_image(cache: &mut CacheDirectory, image: &Image) -> javm_cap::CapHash {
    let pinned = collect_pinned_hashes(cache, image);
    let initial = collect_initial_hashes(cache, image);
    cache
        .put_cap(&Cap::image_with_slots(image, &pinned, &initial).expect("image_with_slots"))
        .expect("put image")
}

fn collect_pinned_hashes(
    cache: &mut CacheDirectory,
    image: &Image,
) -> Vec<(SlotIdx, javm_cap::CapHash)> {
    let mut out = Vec::new();
    for (slot, pinned) in &image.pinned_slots {
        let h = match pinned {
            PinnedCap::Data { content, size } => cache
                .put_cap(&Cap::data_inline_with_size(content, *size))
                .expect("put pinned data"),
            PinnedCap::Image { content_hash } => *content_hash,
        };
        out.push((*slot, h));
    }
    out
}

fn collect_initial_hashes(
    cache: &mut CacheDirectory,
    image: &Image,
) -> Vec<(SlotIdx, javm_cap::CapHash)> {
    let mut out = Vec::new();
    for (slot, init) in &image.initial_slots {
        let h = cache
            .put_cap(&Cap::data_inline_with_size(&init.content, init.size))
            .expect("put initial data");
        out.push((*slot, h));
    }
    out
}

fn build_overlays(image: &Image) -> (u32, Vec<(u32, Vec<u8>)>) {
    let mut mem_size: u32 = 0;
    let mut overlays = Vec::new();
    for mapping in &image.memory_mappings {
        let end = (mapping.start + mapping.size) as u32;
        if end > mem_size {
            mem_size = end;
        }
        let target = mapping.source.target();
        if let Some(PinnedCap::Data { content, .. }) = image.pinned_slots.get(&target) {
            if !content.is_empty() {
                overlays.push((mapping.start as u32, content.clone()));
            }
        } else if let Some(init) = image.initial_slots.get(&target) {
            if !init.content.is_empty() {
                overlays.push((mapping.start as u32, init.content.clone()));
            }
        }
    }
    (mem_size, overlays)
}
