//! Smoke tests demonstrating that the talc-friendly cap types work
//! with both `Global` (heap) and `TalcAlloc` (cache) allocators.

use core::ptr::NonNull;
use core::sync::atomic::AtomicU32;

use allocator_api2::alloc::Global;
use allocator_api2::vec::Vec as AVec;
use nub_host_common::cache::{CacheTalcLock, TalcAlloc};
use talc::source::Manual;

use crate::slot::SlotIdx;

use super::cap::{Cap, CapHashOrRef};
use super::cnode::{CNodeCap, CNodeSlotEntry};
use super::data::{DataCap, DataContent};
use super::entry::CacheEntry;
use super::image::{EndpointDef, ImageCap, ImageSlotEntry, MemoryMapping};
use super::instance::{InstanceCap, RwOverlay};
use super::page::{PageBytes, PageRef, PageSlot};

struct Arena {
    _backing: alloc::vec::Vec<u8>,
    talc: alloc::boxed::Box<CacheTalcLock>,
}
impl Arena {
    fn new(size: usize) -> Self {
        let backing = alloc::vec![0u8; size];
        let talc = alloc::boxed::Box::new(CacheTalcLock::new(Manual));
        let base = backing.as_ptr() as *mut u8;
        unsafe {
            let _ = talc.lock().claim(base, size).expect("claim");
        }
        Self {
            _backing: backing,
            talc,
        }
    }
    fn alloc(&self) -> TalcAlloc {
        unsafe { TalcAlloc::from_raw(NonNull::from(&*self.talc)) }
    }
}

fn make_image_cap_in<A: allocator_api2::alloc::Allocator + Clone>(alloc: A) -> ImageCap<A> {
    let mut code = AVec::new_in(alloc.clone());
    code.extend_from_slice(&[0xAB, 0xCD]);
    ImageCap {
        code,
        bitmask: AVec::new_in(alloc.clone()),
        jump_table: AVec::new_in(alloc.clone()),
        endpoints: AVec::new_in(alloc.clone()),
        mappings: AVec::new_in(alloc.clone()),
        pinned: AVec::new_in(alloc.clone()),
        initial: AVec::new_in(alloc),
        yield_marker_slot: None,
    }
}

#[test]
fn cap_default_uses_global() {
    // `Cap` without a type argument defaults to `Cap<Global>`.
    let _img: Cap<Global> = Cap::Image(make_image_cap_in(Global));
    let cnode: CNodeCap = CNodeCap::new_in(8, Global);
    assert_eq!(cnode.size_log, 8);
    assert_eq!(cnode.capacity(), 256);
}

#[test]
fn cap_talc_backed() {
    let arena = Arena::new(256 * 1024);
    let img: Cap<TalcAlloc> = Cap::Image(make_image_cap_in(arena.alloc()));
    match img {
        Cap::Image(i) => assert_eq!(i.code.as_slice(), &[0xAB, 0xCD]),
        _ => panic!("expected Image"),
    }
}

#[test]
fn cnode_lookup_after_set() {
    let cnode_alloc = Global;
    let mut cnode: CNodeCap<Global> = CNodeCap::new_in(8, cnode_alloc);
    cnode.slots.push(CNodeSlotEntry {
        slot: SlotIdx(7),
        target: CapHashOrRef::Hash([0x11; 32]),
    });
    cnode.slots.push(CNodeSlotEntry {
        slot: SlotIdx(42),
        target: CapHashOrRef::Ref(99),
    });
    cnode.slots.sort_by_key(|e| e.slot);

    assert_eq!(cnode.get(SlotIdx(7)), Some(CapHashOrRef::Hash([0x11; 32])));
    assert_eq!(cnode.get(SlotIdx(42)), Some(CapHashOrRef::Ref(99)));
    assert_eq!(cnode.get(SlotIdx(100)), None);
}

#[test]
fn data_inline_round_trip() {
    let mut bytes = AVec::new_in(Global);
    bytes.extend_from_slice(b"hello");
    let data: DataCap<Global> = DataCap {
        size: 5,
        content: DataContent::Inline(bytes),
    };
    match data.content {
        DataContent::Inline(b) => assert_eq!(b.as_slice(), b"hello"),
        _ => panic!("expected Inline"),
    }
}

#[test]
fn page_ref_shares_then_releases() {
    let arena = Arena::new(64 * 1024);
    let alloc = arena.alloc();
    let mut bytes = AVec::new_in(alloc);
    bytes.extend_from_slice(&[1, 2, 3, 4]);
    let pb = PageBytes {
        refcount: AtomicU32::new(1),
        hash: [0; 32],
        bytes,
    };
    let pr: PageRef<TalcAlloc> = PageRef::new_in(pb, alloc).expect("alloc page");
    assert_eq!(pr.refcount(), 1);

    let pages: AVec<PageSlot<TalcAlloc>, TalcAlloc> = {
        let mut v = AVec::new_in(alloc);
        v.push(PageSlot::Loaded(pr.clone()));
        v.push(PageSlot::Loaded(pr.clone()));
        v
    };
    assert_eq!(pr.refcount(), 3);

    drop(pages);
    assert_eq!(pr.refcount(), 1);
    drop(pr);
    // Allocation freed; arena could be exhausted by future allocs in
    // isolated tests but we don't check the underlying talc state here.
}

#[test]
fn instance_with_rw_overlay() {
    let arena = Arena::new(64 * 1024);
    let alloc = arena.alloc();
    let mut overlay_bytes = AVec::new_in(alloc);
    overlay_bytes.extend_from_slice(&[0xDE, 0xAD]);

    let mut overlays = AVec::new_in(alloc);
    overlays.push(RwOverlay {
        start: 0x1000,
        bytes: overlay_bytes,
    });

    let inst: InstanceCap<TalcAlloc> = InstanceCap {
        image_hash_chain: [0xAA; 32],
        image_hash: [0xBB; 32],
        root_cnode: CapHashOrRef::Hash([0xCC; 32]),
        rw_overlays: overlays,
        mem_size: 0x10000,
        regs: [0u64; super::cap::NUM_REGS],
        pc: 0,
        gas_remaining: 1_000_000,
    };
    assert_eq!(inst.image_hash, [0xBB; 32]);
    assert_eq!(inst.rw_overlays[0].start, 0x1000);
    assert_eq!(inst.rw_overlays[0].bytes.as_slice(), &[0xDE, 0xAD]);
}

#[test]
fn endpoint_def_empty_sentinel() {
    let e = EndpointDef::empty();
    assert_eq!(e.entry_pc, 0);
    for r in &e.initial_regs {
        assert_eq!(*r, 0);
    }
}

#[test]
fn memory_mapping_path_slice() {
    let mut path = [SlotIdx(0); super::cap::MAX_SOURCE_DEPTH];
    path[0] = SlotIdx(3);
    path[1] = SlotIdx(7);
    let m = MemoryMapping {
        start: 0x4000,
        size: 0x2000,
        source_path: path,
        source_path_len: 2,
    };
    assert_eq!(m.path(), &[SlotIdx(3), SlotIdx(7)]);
}

#[test]
fn image_slot_entry_compact() {
    let e = ImageSlotEntry {
        slot: SlotIdx(5),
        cap_hash: [0xEE; 32],
    };
    assert_eq!(e.slot, SlotIdx(5));
    assert_eq!(e.cap_hash, [0xEE; 32]);
}

#[test]
fn cache_entry_refcount_starts_at_one() {
    let cap: Cap<Global> = Cap::CNode(CNodeCap::new_in(4, Global));
    let entry = CacheEntry::new(cap);
    assert_eq!(
        entry
            .refcount
            .load(core::sync::atomic::Ordering::Relaxed),
        1
    );
}
