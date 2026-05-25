//! Cap-level hashing — delegates to SSZ `hash_tree_root`.
//!
//! Each cap variant gets its identity digest by walking the cap's SSZ
//! `HashTreeRoot` tree (SHA-256 chunking, merkleization, Union
//! `mix_in_selector` for variant domain separation). The five legacy
//! kind tags `0x10..0x50` are replaced by the SSZ Union selectors on
//! `Cap` (0..4); the per-variant byte protocol is replaced by the
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

use super::cap::{Cap, CapHash};

/// 32-byte content hash of `cap`. Walks the cap tree via SSZ
/// `HashTreeRoot` with SHA-256 as the default digest.
pub fn cap_hash(cap: &Cap) -> CapHash {
    ssz::hash_tree_root(cap)
}

#[cfg(test)]
mod tests {
    use super::*;

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
        let a: Cap = Cap::Type(TypeCap {
            image_hash_chain: chain,
        });
        let b: Cap = Cap::Type(TypeCap {
            image_hash_chain: chain,
        });
        assert_eq!(cap_hash(&a), cap_hash(&b));
        // Different chain → different hash.
        let c: Cap = Cap::Type(TypeCap {
            image_hash_chain: [0xBB; 32],
        });
        assert_ne!(cap_hash(&a), cap_hash(&c));
    }

    #[test]
    fn cap_variants_have_distinct_hashes() {
        // The Union mix_in_selector ensures two caps whose payloads
        // happen to merkleize to the same root still differ at the
        // outer hash. Use the simplest distinguishable payloads.
        let t: Cap = Cap::Type(TypeCap {
            image_hash_chain: [0; 32],
        });
        let cn: Cap = Cap::CNode(CNodeCap::new(0).unwrap());
        assert_ne!(cap_hash(&t), cap_hash(&cn));
    }

    #[test]
    fn data_inline_hash_includes_size() {
        let bytes_a: Vec<u8> = b"abc".to_vec();
        let bytes_b: Vec<u8> = b"abc".to_vec();
        // Two caps with different inline byte lengths (same prefix)
        // hash differently because content storage IS the identifier.
        // Pad to distinct page-multiple sizes.
        let mut bytes_a_padded: Vec<u8> = vec![0u8; crate::data::PAGE_SIZE];
        bytes_a_padded[..bytes_a.len()].copy_from_slice(bytes_a.as_slice());
        let mut bytes_b_padded: Vec<u8> = vec![0u8; crate::data::PAGE_SIZE * 2];
        bytes_b_padded[..bytes_b.len()].copy_from_slice(bytes_b.as_slice());
        let a: Cap = Cap::Data(DataCap {
            content: DataContent::Inline(bytes_a_padded),
        });
        let b: Cap = Cap::Data(DataCap {
            content: DataContent::Inline(bytes_b_padded),
        });
        assert_ne!(cap_hash(&a), cap_hash(&b));
    }

    #[test]
    fn cnode_empty_vs_one_populated_differ() {
        let empty: CNodeCap = CNodeCap::new(2).unwrap();
        let mut populated: CNodeCap = CNodeCap::new(2).unwrap();
        populated
            .set(SlotIdx(0), Some(CapHashOrRef::Hash([0xEE; 32])))
            .unwrap();
        let a: Cap = Cap::CNode(empty);
        let b: Cap = Cap::CNode(populated);
        assert_ne!(cap_hash(&a), cap_hash(&b));
    }

    #[test]
    fn cnode_with_ref_target_panics() {
        let mut cn: CNodeCap = CNodeCap::new(2).unwrap();
        cn.set(SlotIdx(0), Some(CapHashOrRef::Ref(42))).unwrap();
        let cap: Cap = Cap::CNode(cn);
        let result = std::panic::catch_unwind(|| cap_hash(&cap));
        assert!(result.is_err());
    }

    #[test]
    fn image_hash_depends_on_code() {
        let mut img_a = empty_image();
        let mut img_b = empty_image();
        img_a.code.extend_from_slice(b"foo");
        img_b.code.extend_from_slice(b"bar");
        let a: Cap = Cap::Image(img_a);
        let b: Cap = Cap::Image(img_b);
        assert_ne!(cap_hash(&a), cap_hash(&b));
    }

    fn empty_image() -> ImageCap {
        ImageCap {
            code: Vec::new(),
            bitmask: Vec::new(),
            jump_table: Vec::new(),
            endpoints: Vec::new(),
            mappings: Vec::new(),
            pinned: Vec::new(),
            initial: Vec::new(),
            yield_marker_slot: None,
        }
    }

    #[test]
    fn instance_hash_depends_on_pc() {
        let mut inst_a = empty_instance();
        let mut inst_b = empty_instance();
        inst_a.pc = 0x100;
        inst_b.pc = 0x200;
        let a: Cap = Cap::Instance(inst_a);
        let b: Cap = Cap::Instance(inst_b);
        assert_ne!(cap_hash(&a), cap_hash(&b));
    }

    fn empty_instance() -> InstanceCap {
        InstanceCap {
            image_hash_chain: [0; 32],
            image_hash: [0; 32],
            root_cnode: CapHashOrRef::Hash([0; 32]),
            rw_overlays: Vec::new(),
            mem_size: 0,
            regs: [0; crate::cap::NUM_REGS],
            pc: 0,
            gas_remaining: 0,
        }
    }

    #[test]
    fn data_paged_hash_uses_loaded_page_hashes() {
        let mut bytes = Vec::new();
        bytes.extend_from_slice(&[1, 2, 3]);
        let pb_hash = [0xA1; 32];
        let pb = PageBytes {
            hash: pb_hash,
            bytes,
        };
        let pr: PageRef = PageRef::new(pb);
        let pages: Vec<PageSlot> = vec![PageSlot::Loaded(pr)];
        let cap: Cap = Cap::Data(DataCap {
            content: DataContent::Paged {
                page_size: 4096,
                pages,
            },
        });
        let h = cap_hash(&cap);
        // Sanity: identical Cap shape with a different page hash differs.
        let bytes2: Vec<u8> = vec![1, 2, 3];
        let pb2 = PageBytes {
            hash: [0xB2; 32],
            bytes: bytes2,
        };
        let pr2: PageRef = PageRef::new(pb2);
        let pages2: Vec<PageSlot> = vec![PageSlot::Loaded(pr2)];
        let cap2: Cap = Cap::Data(DataCap {
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
        let bytes: Vec<u8> = vec![0xAA; 16];
        let pb = PageBytes {
            hash: page_hash,
            bytes,
        };
        let pr: PageRef = PageRef::new(pb);

        let pages_loaded: Vec<PageSlot> = vec![PageSlot::Loaded(pr)];
        let cap_loaded: Cap = Cap::Data(DataCap {
            content: DataContent::Paged {
                page_size: 16,
                pages: pages_loaded,
            },
        });

        let pages_missing: Vec<PageSlot> = vec![PageSlot::Missing(page_hash)];
        let cap_missing: Cap = Cap::Data(DataCap {
            content: DataContent::Paged {
                page_size: 16,
                pages: pages_missing,
            },
        });

        assert_eq!(cap_hash(&cap_loaded), cap_hash(&cap_missing));
    }
}
