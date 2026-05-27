use jar_kernel::abi;
use jar_kernel::genesis::genesis;
use javm_cap::image::Image;
use javm_cap::{Cap, CapHashOrRef};
use std::collections::BTreeMap;

fn empty_chain_image() -> Image {
    Image {
        code: vec![10u8, 0],
        // 2 bytes of code → 2 instruction-start bits → 0b0000_0011.
        packed_bitmask: vec![0x03],
        jump_table: Vec::new(),
        jump_table_offsets: Vec::new(),
        endpoints: BTreeMap::new(),
        memory_mappings: Vec::new(),
        gas_slots: vec![abi::BARE_GAS_SLOT],
        quota_slots: vec![abi::BARE_QUOTA_SLOT],
        pinned_slots: BTreeMap::new(),
        initial_slots: BTreeMap::new(),
        yield_marker_slot: Some(abi::BARE_YIELD_CATCHER_SLOT),
    }
}

#[test]
fn genesis_publishes_chain_instance() {
    let g = genesis(empty_chain_image()).expect("genesis");
    let inst = g
        .state
        .caps
        .get(CapHashOrRef::Hash(g.chain_instance_hash))
        .expect("chain instance present");
    assert!(matches!(&*inst, Cap::Instance(_)));
}

#[test]
fn genesis_populates_root_cnode_with_kernel_caps() {
    let g = genesis(empty_chain_image()).expect("genesis");
    let cn_arc = g
        .state
        .caps
        .get(CapHashOrRef::Hash(g.root_cnode_hash))
        .expect("root cnode present");
    let cn = match &*cn_arc {
        Cap::CNode(cn) => cn.clone(),
        _ => panic!("root cnode is not Cap::CNode"),
    };
    assert!(cn.get(abi::BARE_GAS_SLOT).is_some());
    assert!(cn.get(abi::BARE_QUOTA_SLOT).is_some());
    assert!(cn.get(abi::BARE_YIELD_CATCHER_SLOT).is_some());
    assert!(cn.get(abi::BARE_HOST_OPEN_SLOT).is_some());
    assert!(cn.get(abi::BARE_HOST_SAVE_SLOT).is_some());
}

#[test]
fn genesis_is_deterministic() {
    let g1 = genesis(empty_chain_image()).expect("g1");
    let g2 = genesis(empty_chain_image()).expect("g2");
    assert_eq!(g1.chain_instance_hash, g2.chain_instance_hash);
    assert_eq!(g1.chain_image_hash, g2.chain_image_hash);
    assert_eq!(g1.root_cnode_hash, g2.root_cnode_hash);
}
