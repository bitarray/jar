//! Cap-level hashing for the talc-friendly cap shape.
//!
//! Computes the 32-byte cap identity digest by walking the new
//! Cap shape and feeding bytes to the existing [`crate::hash::Hash`]
//! and [`crate::bmt::Bmt`] primitives. The byte protocol matches
//! the legacy `crate::cap::Cap::hash` so a value's hash is stable
//! across the migration:
//!
//! - Instance: `H(0x10 || image_hash_chain || content_hash)`
//! - Image:    `H(0x20 || image_content_hash)`
//! - Data:     `H(0x30 || size_LE_u64 || data_content_hash)`
//! - CNode:    `H(0x40 || cnode_hash)`
//! - Type:     `H(0x50 || image_hash_chain)`
//!
//! The "content" hash for each kind is computed bottom-up from the
//! cap's current state (no separate stored field — we removed the
//! stale-prone `content_hash` cache from the new types).

use alloc::vec::Vec;
use allocator_api2::alloc::Allocator;

use crate::bmt::Bmt;
use crate::hash::{Blake2b256, Hash};

use super::cap::{Cap, CapHash, CapHashOrRef};
use super::cnode::CNodeCap;
use super::data::{DataCap, DataContent};
use super::image_cap::ImageCap;
use super::instance::InstanceCap;
use super::page::PageSlot;

/// Cap-level identity hash. Domain-separated by a leading kind byte
/// so two kinds carrying the same underlying digest stay distinct.
///
/// For `Instance` and `CNode`, callers may need to resolve any
/// `CapHashOrRef::Ref(_)` cnode slot targets to their committed
/// hashes first (Refs are cache-local and can't be hashed against
/// the spec's content-addressed protocol). The walker here treats
/// a `Ref` as a panic — callers should `settle` first or call
/// `hash_with_resolver` (added if/when needed).
pub fn cap_hash<A: Allocator + Clone>(cap: &Cap<A>) -> CapHash {
    match cap {
        Cap::Instance(inst) => instance_cap_hash(inst),
        Cap::Image(img) => {
            let content = image_content_hash(img);
            kind_tagged(0x20, &[&content])
        }
        Cap::Data(d) => {
            let content = data_content_hash(d);
            let mut tail = Vec::with_capacity(8 + 32);
            tail.extend_from_slice(&d.size.to_le_bytes());
            tail.extend_from_slice(&content);
            kind_tagged_bytes(0x30, &tail)
        }
        Cap::CNode(cn) => {
            let cn_hash = cnode_content_hash(cn);
            kind_tagged(0x40, &[&cn_hash])
        }
        Cap::Type(t) => kind_tagged(0x50, &[&t.image_hash_chain]),
    }
}

fn kind_tagged(tag: u8, parts: &[&[u8]]) -> CapHash {
    let total: usize = 1 + parts.iter().map(|p| p.len()).sum::<usize>();
    let mut buf = Vec::with_capacity(total);
    buf.push(tag);
    for p in parts {
        buf.extend_from_slice(p);
    }
    Blake2b256::hash(&buf)
}

fn kind_tagged_bytes(tag: u8, bytes: &[u8]) -> CapHash {
    let mut buf = Vec::with_capacity(1 + bytes.len());
    buf.push(tag);
    buf.extend_from_slice(bytes);
    Blake2b256::hash(&buf)
}

/// Content hash of an `ImageCap`. Concatenates the fields in a
/// canonical order and hashes the result. We don't use the SCALE
/// codec here — the talc-resident shape doesn't round-trip through
/// SCALE cleanly (different field types). Callers that need to
/// match a SCALE-derived hash from on-disk material should go via
/// `crate::image::Image` first.
fn image_content_hash<A: Allocator + Clone>(img: &ImageCap<A>) -> CapHash {
    let mut buf: Vec<u8> = Vec::new();
    extend_lp(&mut buf, img.code.as_slice());
    extend_lp(&mut buf, img.bitmask.as_slice());
    // jump_table: u32 entries as LE bytes.
    buf.extend_from_slice(&(img.jump_table.len() as u32).to_le_bytes());
    for jt in img.jump_table.iter() {
        buf.extend_from_slice(&jt.to_le_bytes());
    }
    // endpoints: dense; serialise count + per-endpoint fields.
    buf.extend_from_slice(&(img.endpoints.len() as u32).to_le_bytes());
    for ep in img.endpoints.iter() {
        buf.extend_from_slice(&ep.entry_pc.to_le_bytes());
        buf.extend_from_slice(&ep.stack_top.to_le_bytes());
        buf.extend_from_slice(&ep.arg_cnode_slot.get().to_le_bytes());
        buf.push(ep.arg_cnode_size);
        for r in &ep.initial_regs {
            buf.extend_from_slice(&r.to_le_bytes());
        }
    }
    buf.extend_from_slice(&(img.mappings.len() as u32).to_le_bytes());
    for m in img.mappings.iter() {
        buf.extend_from_slice(&m.start.to_le_bytes());
        buf.extend_from_slice(&m.size.to_le_bytes());
        buf.push(m.source_path_len);
        for s in &m.source_path[..m.source_path_len as usize] {
            buf.extend_from_slice(&s.get().to_le_bytes());
        }
    }
    extend_image_slots(&mut buf, img.pinned.as_slice());
    extend_image_slots(&mut buf, img.initial.as_slice());
    match img.yield_marker_slot {
        Some(s) => {
            buf.push(1);
            buf.extend_from_slice(&s.get().to_le_bytes());
        }
        None => buf.push(0),
    }
    Blake2b256::hash(&buf)
}

fn extend_lp(buf: &mut Vec<u8>, bytes: &[u8]) {
    buf.extend_from_slice(&(bytes.len() as u32).to_le_bytes());
    buf.extend_from_slice(bytes);
}

fn extend_image_slots(buf: &mut Vec<u8>, entries: &[super::image_cap::ImageSlotEntry]) {
    buf.extend_from_slice(&(entries.len() as u32).to_le_bytes());
    for e in entries {
        buf.extend_from_slice(&e.slot.get().to_le_bytes());
        buf.extend_from_slice(&e.cap_hash);
    }
}

/// Content hash of a `DataCap`. Inline: `H(bytes)`. Paged: BMT over
/// per-page hashes (Empty page uses the canonical zero-page hash).
fn data_content_hash<A: Allocator + Clone>(data: &DataCap<A>) -> CapHash {
    match &data.content {
        DataContent::Inline(bytes) => Blake2b256::hash(bytes.as_slice()),
        DataContent::Paged { pages, .. } => {
            let mut leaves: Vec<CapHash> = Vec::with_capacity(pages.len());
            for p in pages.iter() {
                let leaf = match p {
                    PageSlot::Empty => empty_page_hash(),
                    PageSlot::Loaded(pr) => pr.get().hash,
                    PageSlot::Missing(h) => *h,
                };
                leaves.push(leaf);
            }
            Bmt::root::<Blake2b256>(&leaves)
        }
    }
}

fn empty_page_hash() -> CapHash {
    // Canonical empty-leaf marker (same as BMT's "no leaves" case).
    Blake2b256::hash(&[])
}

/// Cnode merkle root. Leaves are sized to the cnode's `2^size_log`
/// slots; populated slots use `H(0x01 || slot_target_hash)`; empty
/// slots use `H(0x00)`. Matches the legacy InMemoryCNode hashing
/// protocol byte-for-byte.
fn cnode_content_hash<A: Allocator + Clone>(cn: &CNodeCap<A>) -> CapHash {
    let n = 1usize << cn.size_log;
    let mut leaves: Vec<CapHash> = Vec::with_capacity(n);
    let empty_leaf = Blake2b256::hash(&[0x00]);

    let mut next_populated_idx = 0;
    for slot in 0..n {
        let entry = cn.slots.get(next_populated_idx);
        if let Some(e) = entry
            && e.slot.get() as usize == slot
        {
            let target_hash = match e.target {
                CapHashOrRef::Hash(h) => h,
                CapHashOrRef::Ref(_) => {
                    panic!("cnode_content_hash: unresolved CapRef in slot table; settle first")
                }
            };
            let mut buf = Vec::with_capacity(1 + 32);
            buf.push(0x01);
            buf.extend_from_slice(&target_hash);
            leaves.push(Blake2b256::hash(&buf));
            next_populated_idx += 1;
            continue;
        }
        leaves.push(empty_leaf);
    }
    Bmt::root::<Blake2b256>(&leaves)
}

/// `InstanceCap` cap-level hash.
///
/// Computes `content_hash` from current state by feeding:
/// `image_hash || root_cnode_hash || rw_overlays_hash || regs || pc || gas`.
/// Then `H(0x10 || image_hash_chain || content_hash)`.
fn instance_cap_hash<A: Allocator + Clone>(inst: &InstanceCap<A>) -> CapHash {
    let root_cnode_hash = match inst.root_cnode {
        CapHashOrRef::Hash(h) => h,
        CapHashOrRef::Ref(_) => {
            panic!("instance_cap_hash: unresolved CapRef in root_cnode; settle first")
        }
    };
    let mut overlays_buf: Vec<u8> = Vec::new();
    overlays_buf.extend_from_slice(&(inst.rw_overlays.len() as u32).to_le_bytes());
    for o in inst.rw_overlays.iter() {
        overlays_buf.extend_from_slice(&o.start.to_le_bytes());
        extend_lp(&mut overlays_buf, o.bytes.as_slice());
    }
    let overlays_hash = Blake2b256::hash(&overlays_buf);

    let mut state_buf: Vec<u8> = Vec::with_capacity(32 + 32 + 32 + 8 * 13 + 8 + 8);
    state_buf.extend_from_slice(&inst.image_hash);
    state_buf.extend_from_slice(&root_cnode_hash);
    state_buf.extend_from_slice(&overlays_hash);
    for r in &inst.regs {
        state_buf.extend_from_slice(&r.to_le_bytes());
    }
    state_buf.extend_from_slice(&inst.pc.to_le_bytes());
    state_buf.extend_from_slice(&inst.gas_remaining.to_le_bytes());
    state_buf.extend_from_slice(&inst.mem_size.to_le_bytes());
    let content_hash = Blake2b256::hash(&state_buf);

    kind_tagged(0x10, &[&inst.image_hash_chain, &content_hash])
}

#[cfg(test)]
mod tests {
    use super::*;
    use allocator_api2::alloc::Global;
    use allocator_api2::vec::Vec as AVec;
    use core::sync::atomic::AtomicU32;

    use crate::cnode::CNodeSlotEntry;
    use crate::image_cap::ImageCap;
    use crate::instance::InstanceCap;
    use crate::page::{PageBytes, PageRef};
    use crate::slot::SlotIdx;

    #[test]
    fn type_cap_matches_old_protocol() {
        let chain = [0xAA; 32];
        let cap: Cap<Global> = Cap::Type(crate::cap::TypeCap {
            image_hash_chain: chain,
        });
        let mut expected_buf = alloc::vec![0x50u8];
        expected_buf.extend_from_slice(&chain);
        assert_eq!(cap_hash(&cap), Blake2b256::hash(&expected_buf));
    }

    #[test]
    fn data_inline_hash_includes_size() {
        let bytes_a: AVec<u8, Global> = {
            let mut v = AVec::new_in(Global);
            v.extend_from_slice(b"abc");
            v
        };
        let bytes_b: AVec<u8, Global> = {
            let mut v = AVec::new_in(Global);
            v.extend_from_slice(b"abc");
            v
        };
        let a: Cap<Global> = Cap::Data(DataCap {
            size: 3,
            content: DataContent::Inline(bytes_a),
        });
        let b: Cap<Global> = Cap::Data(DataCap {
            size: 4, // different size, same content_hash → different cap hash
            content: DataContent::Inline(bytes_b),
        });
        assert_ne!(cap_hash(&a), cap_hash(&b));
    }

    #[test]
    fn cnode_empty_vs_one_populated_differ() {
        let empty: CNodeCap<Global> = CNodeCap::new_in(2, Global).unwrap();
        let mut populated: CNodeCap<Global> = CNodeCap::new_in(2, Global).unwrap();
        populated.slots.push(CNodeSlotEntry {
            slot: SlotIdx(0),
            target: CapHashOrRef::Hash([0xEE; 32]),
        });
        let a: Cap<Global> = Cap::CNode(empty);
        let b: Cap<Global> = Cap::CNode(populated);
        assert_ne!(cap_hash(&a), cap_hash(&b));
    }

    #[test]
    fn cnode_with_ref_target_panics() {
        let mut cn: CNodeCap<Global> = CNodeCap::new_in(2, Global).unwrap();
        cn.slots.push(CNodeSlotEntry {
            slot: SlotIdx(0),
            target: CapHashOrRef::Ref(42),
        });
        let cap: Cap<Global> = Cap::CNode(cn);
        let result = std::panic::catch_unwind(|| cap_hash(&cap));
        assert!(result.is_err());
    }

    #[test]
    fn image_hash_depends_on_code() {
        let mut img_a = empty_image();
        let mut img_b = empty_image();
        img_a.code.extend_from_slice(b"foo");
        img_b.code.extend_from_slice(b"bar");
        let a: Cap<Global> = Cap::Image(img_a);
        let b: Cap<Global> = Cap::Image(img_b);
        assert_ne!(cap_hash(&a), cap_hash(&b));
    }

    fn empty_image() -> ImageCap<Global> {
        ImageCap {
            code: AVec::new_in(Global),
            bitmask: AVec::new_in(Global),
            jump_table: AVec::new_in(Global),
            endpoints: AVec::new_in(Global),
            mappings: AVec::new_in(Global),
            pinned: AVec::new_in(Global),
            initial: AVec::new_in(Global),
            yield_marker_slot: None,
        }
    }

    #[test]
    fn instance_hash_depends_on_pc() {
        let mut inst_a = empty_instance();
        let mut inst_b = empty_instance();
        inst_a.pc = 0x100;
        inst_b.pc = 0x200;
        let a: Cap<Global> = Cap::Instance(inst_a);
        let b: Cap<Global> = Cap::Instance(inst_b);
        assert_ne!(cap_hash(&a), cap_hash(&b));
    }

    fn empty_instance() -> InstanceCap<Global> {
        InstanceCap {
            image_hash_chain: [0; 32],
            image_hash: [0; 32],
            root_cnode: CapHashOrRef::Hash([0; 32]),
            rw_overlays: AVec::new_in(Global),
            mem_size: 0,
            regs: [0; crate::cap::NUM_REGS],
            pc: 0,
            gas_remaining: 0,
        }
    }

    #[test]
    fn data_paged_hash_uses_loaded_page_hashes() {
        let mut bytes = AVec::new_in(Global);
        bytes.extend_from_slice(&[1, 2, 3]);
        let pb_hash = Blake2b256::hash(b"page_a");
        let pb = PageBytes {
            refcount: AtomicU32::new(1),
            hash: pb_hash,
            bytes,
        };
        let pr: PageRef<Global> = PageRef::new_in(pb, Global).unwrap();
        let mut pages: AVec<PageSlot<Global>, Global> = AVec::new_in(Global);
        pages.push(PageSlot::Loaded(pr));
        let cap: Cap<Global> = Cap::Data(DataCap {
            size: 3,
            content: DataContent::Paged {
                page_size: 4096,
                pages,
            },
        });
        let h = cap_hash(&cap);
        // Sanity: identical Cap with a different page hash differs.
        let mut bytes2 = AVec::new_in(Global);
        bytes2.extend_from_slice(&[1, 2, 3]);
        let pb2 = PageBytes {
            refcount: AtomicU32::new(1),
            hash: Blake2b256::hash(b"page_b"),
            bytes: bytes2,
        };
        let pr2: PageRef<Global> = PageRef::new_in(pb2, Global).unwrap();
        let mut pages2: AVec<PageSlot<Global>, Global> = AVec::new_in(Global);
        pages2.push(PageSlot::Loaded(pr2));
        let cap2: Cap<Global> = Cap::Data(DataCap {
            size: 3,
            content: DataContent::Paged {
                page_size: 4096,
                pages: pages2,
            },
        });
        assert_ne!(h, cap_hash(&cap2));
    }
}
