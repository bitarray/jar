//! Cap-level hashing — delegates to SSZ `hash_tree_root`.
//!
//! Each cap variant gets its identity digest by walking the cap's SSZ
//! `HashTreeRoot` tree (SHA-256 chunking, merkleization, Union
//! `mix_in_selector` for variant domain separation). The five legacy
//! kind tags `0x10..0x50` are replaced by the SSZ Union selectors on
//! `Cap<A>` (0..4); the per-variant byte protocol is replaced by the
//! field-by-field SSZ encoding derived on `InstanceCap`, `ImageCap`,
//! `DataCap`, `CNodeCap`, and `TypeCap`.
//!
//! Cap-hash values changed in the SSZ migration (SHA-256 over the
//! merkleized cap shape vs Blake2b over hand-rolled byte
//! concatenations). The JAR chain has no live state — this is fine.
//!
//! **Substitution invariants** preserved by hand-written
//! `HashTreeRoot` impls (see [`crate::page::PageSlot`],
//! [`crate::page::PageBytes`], [`crate::cap::CapHashOrRef`]):
//!
//! - `PageSlot::Loaded(p)` hashes identically to
//!   `PageSlot::Missing(p.hash)` — a freshly-loaded page substitutes
//!   for a missing page without changing the enclosing cap's hash.
//! - `CapHashOrRef::Hash(h)` hashes to `h` exactly — a freshly-published
//!   cap blob substitutes for a `CapRef` reference without changing the
//!   enclosing cap's hash.
//!
//! **Unresolved refs panic**: `cap_hash` on a cap whose graph still
//! contains `CapHashOrRef::Ref(_)` targets will panic. Callers must
//! `settle` the cap graph first.
//!
//! **Image hash duplication**: `cap_hash(Cap::Image(...))` and
//! `image_content_hash` (over the SCALE `Image` shape) produce
//! different digests. They hash different types — the cap-resident
//! `ImageCap` has a flatter layout than `Image`. This is an
//! intentional boundary; the cache publishes by `cap_hash`, while
//! `image_content_hash` is used for the image-hash chain protocol in
//! `crate::image`.

use allocate::Allocator;

use super::cap::{Cap, CapHash};

/// 32-byte content hash of `cap`. Walks the cap tree via SSZ
/// `HashTreeRoot` with SHA-256 as the default digest.
pub fn cap_hash<A: Allocator + Clone>(cap: &Cap<A>) -> CapHash {
    ssz::hash_tree_root(cap)
}

#[cfg(test)]
mod tests {
    use super::*;
    use allocate::Global;
    use allocate::vec::Vec as AVec;

    use crate::cap::{CapHashOrRef, TypeCap};
    use crate::cnode::CNodeCap;
    use crate::data::{DataCap, DataContent};
    use crate::image_cap::ImageCap;
    use crate::instance::InstanceCap;
    use crate::page::{PageBytes, PageRef, PageSlot};
    use crate::slot::SlotIdx;

    #[test]
    fn type_cap_hash_deterministic() {
        let chain = [0xAA; 32];
        let a: Cap<Global> = Cap::Type(TypeCap {
            image_hash_chain: chain,
        });
        let b: Cap<Global> = Cap::Type(TypeCap {
            image_hash_chain: chain,
        });
        assert_eq!(cap_hash(&a), cap_hash(&b));
        // Different chain → different hash.
        let c: Cap<Global> = Cap::Type(TypeCap {
            image_hash_chain: [0xBB; 32],
        });
        assert_ne!(cap_hash(&a), cap_hash(&c));
    }

    #[test]
    fn cap_variants_have_distinct_hashes() {
        // The Union mix_in_selector ensures two caps whose payloads
        // happen to merkleize to the same root still differ at the
        // outer hash. Use the simplest distinguishable payloads.
        let t: Cap<Global> = Cap::Type(TypeCap {
            image_hash_chain: [0; 32],
        });
        let cn: Cap<Global> = Cap::CNode(CNodeCap::new_in(0, Global).unwrap());
        assert_ne!(cap_hash(&t), cap_hash(&cn));
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
        // Two caps with different inline byte lengths (same prefix)
        // hash differently because content storage IS the identifier.
        // Pad to distinct page-multiple sizes.
        let mut bytes_a_padded: AVec<u8, Global> = AVec::new_in(Global);
        bytes_a_padded.resize(crate::data::PAGE_SIZE, 0);
        bytes_a_padded[..bytes_a.len()].copy_from_slice(bytes_a.as_slice());
        let mut bytes_b_padded: AVec<u8, Global> = AVec::new_in(Global);
        bytes_b_padded.resize(crate::data::PAGE_SIZE * 2, 0);
        bytes_b_padded[..bytes_b.len()].copy_from_slice(bytes_b.as_slice());
        let a: Cap<Global> = Cap::Data(DataCap {
            content: DataContent::Inline(bytes_a_padded),
        });
        let b: Cap<Global> = Cap::Data(DataCap {
            content: DataContent::Inline(bytes_b_padded),
        });
        assert_ne!(cap_hash(&a), cap_hash(&b));
    }

    #[test]
    fn cnode_empty_vs_one_populated_differ() {
        let empty: CNodeCap<Global> = CNodeCap::new_in(2, Global).unwrap();
        let mut populated: CNodeCap<Global> = CNodeCap::new_in(2, Global).unwrap();
        populated
            .set(SlotIdx(0), Some(CapHashOrRef::Hash([0xEE; 32])))
            .unwrap();
        let a: Cap<Global> = Cap::CNode(empty);
        let b: Cap<Global> = Cap::CNode(populated);
        assert_ne!(cap_hash(&a), cap_hash(&b));
    }

    #[test]
    fn cnode_with_ref_target_panics() {
        let mut cn: CNodeCap<Global> = CNodeCap::new_in(2, Global).unwrap();
        cn.set(SlotIdx(0), Some(CapHashOrRef::Ref(42))).unwrap();
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
        let pb_hash = [0xA1; 32];
        let pb = PageBytes {
            hash: pb_hash,
            bytes,
        };
        let pr: PageRef<Global> = PageRef::new_in(pb, Global);
        let mut pages: AVec<PageSlot<Global>, Global> = AVec::new_in(Global);
        pages.push(PageSlot::Loaded(pr));
        let cap: Cap<Global> = Cap::Data(DataCap {
            content: DataContent::Paged {
                page_size: 4096,
                pages,
            },
        });
        let h = cap_hash(&cap);
        // Sanity: identical Cap shape with a different page hash differs.
        let mut bytes2 = AVec::new_in(Global);
        bytes2.extend_from_slice(&[1, 2, 3]);
        let pb2 = PageBytes {
            hash: [0xB2; 32],
            bytes: bytes2,
        };
        let pr2: PageRef<Global> = PageRef::new_in(pb2, Global);
        let mut pages2: AVec<PageSlot<Global>, Global> = AVec::new_in(Global);
        pages2.push(PageSlot::Loaded(pr2));
        let cap2: Cap<Global> = Cap::Data(DataCap {
            content: DataContent::Paged {
                page_size: 4096,
                pages: pages2,
            },
        });
        assert_ne!(h, cap_hash(&cap2));
    }

    #[test]
    fn loaded_page_substitutes_for_missing_with_same_hash() {
        // Substitution invariant: Loaded(p) and Missing(p.hash) must
        // produce the same enclosing-cap hash.
        let page_hash = [0xCD; 32];
        let mut bytes = AVec::new_in(Global);
        bytes.extend_from_slice(&[0xAA; 16]);
        let pb = PageBytes {
            hash: page_hash,
            bytes,
        };
        let pr: PageRef<Global> = PageRef::new_in(pb, Global);

        let mut pages_loaded: AVec<PageSlot<Global>, Global> = AVec::new_in(Global);
        pages_loaded.push(PageSlot::Loaded(pr));
        let cap_loaded: Cap<Global> = Cap::Data(DataCap {
            content: DataContent::Paged {
                page_size: 16,
                pages: pages_loaded,
            },
        });

        let mut pages_missing: AVec<PageSlot<Global>, Global> = AVec::new_in(Global);
        pages_missing.push(PageSlot::Missing(page_hash));
        let cap_missing: Cap<Global> = Cap::Data(DataCap {
            content: DataContent::Paged {
                page_size: 16,
                pages: pages_missing,
            },
        });

        assert_eq!(cap_hash(&cap_loaded), cap_hash(&cap_missing));
    }
}
