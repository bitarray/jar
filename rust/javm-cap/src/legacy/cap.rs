//! The five v3 cap kinds.
//!
//! Per spec README §8:
//!
//! - **Cap::Instance** — Frame-bound stateful unit. AUTHORITY-BEARING.
//! - **Cap::Image** — Image spec reference (content-addressed).
//! - **Cap::Data** — Bytes (trailing-zero-stripped).
//! - **Cap::CNode** — Variable-size cap table (mintable).
//! - **Cap::Type** — Image_hash chain identifier (IDENTIFICATION-ONLY).
//!
//! All five kinds are uniformly copyable; copyability is a structural
//! property of v3 (no per-cap predicate). The enum has no generic
//! parameter and no `Cap::Protocol` variant; JAR-specific things are
//! `Cap::Instance` values with particular Images.

use super::cnode::{CNodeBackend, CnodeHash};
use alloc::string::String;
use alloc::sync::Arc;
use alloc::vec::Vec;
use core::fmt;

/// 32-byte digest used for all v3 cap identity / content hashes.
pub type CapHash = [u8; 32];

/// One of the five v3 cap kinds.
///
/// Cloning a `Cap` is cheap: variant data is either by-value (small
/// fixed bytes) or wrapped in `Arc` (the CNode backend).
#[derive(Clone, Debug)]
pub enum Cap {
    Instance(InstanceCap),
    Image(ImageCap),
    Data(DataCap),
    CNode(CNodeCap),
    Type(TypeCap),
}

/// Discriminant for `Cap`. Useful for matching, error messages, and
/// places where the payload is irrelevant.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum CapKind {
    Instance,
    Image,
    Data,
    CNode,
    Type,
}

impl Cap {
    pub fn kind(&self) -> CapKind {
        match self {
            Cap::Instance(_) => CapKind::Instance,
            Cap::Image(_) => CapKind::Image,
            Cap::Data(_) => CapKind::Data,
            Cap::CNode(_) => CapKind::CNode,
            Cap::Type(_) => CapKind::Type,
        }
    }

    /// Cap-level identity hash. Distinguishes between kinds via a
    /// 1-byte domain tag prepended to the variant's identity bytes,
    /// then run through Blake2b256:
    ///
    /// - Instance: `H(0x10 || image_hash_chain || content_hash)`
    /// - Image:    `H(0x20 || content_hash)`
    /// - Data:     `H(0x30 || size-LE-u64 || content_hash)`
    /// - CNode:    `H(0x40 || cnode_hash)`
    /// - Type:     `H(0x50 || image_hash_chain)`
    ///
    /// This makes Cap hashes unambiguous across kinds even when two
    /// kinds happen to wrap the same underlying 32-byte digest.
    pub fn hash(&self) -> CapHash {
        use crate::hash::{Blake2b256, Hash};
        let mut buf: Vec<u8> = Vec::with_capacity(1 + 32 + 32 + 8);
        match self {
            Cap::Instance(c) => {
                buf.push(0x10);
                buf.extend_from_slice(&c.image_hash_chain);
                buf.extend_from_slice(&c.content_hash);
            }
            Cap::Image(c) => {
                buf.push(0x20);
                buf.extend_from_slice(&c.content_hash);
            }
            Cap::Data(c) => {
                buf.push(0x30);
                buf.extend_from_slice(&c.size.to_le_bytes());
                buf.extend_from_slice(&c.content_hash);
            }
            Cap::CNode(c) => {
                buf.push(0x40);
                buf.extend_from_slice(&c.cnode_hash());
            }
            Cap::Type(c) => {
                buf.push(0x50);
                buf.extend_from_slice(&c.image_hash_chain);
            }
        }
        Blake2b256::hash(&buf)
    }
}

impl PartialEq for Cap {
    fn eq(&self, other: &Self) -> bool {
        self.hash() == other.hash()
    }
}

impl Eq for Cap {}

// --- Variant types ---

/// `Cap::Instance` payload.
///
/// - `image_hash_chain` is the cumulative chain hash (the Instance's
///   *type identity*; see `image::chain_genesis` / `chain_extend`).
/// - `content_hash` is the Instance's *value identity* — hash of its
///   current Image + cnode state. Changes whenever the Instance's
///   value diverges (per §9 case (b)). Two Instances with the same
///   `image_hash_chain` but different `content_hash` are siblings of
///   the same type with divergent state.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct InstanceCap {
    pub image_hash_chain: CapHash,
    pub content_hash: CapHash,
}

/// `Cap::Image` payload. The Image content is content-addressed by
/// `content_hash` (typically computed via `image::image_content_hash`).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct ImageCap {
    pub content_hash: CapHash,
}

/// `Cap::Data` payload. Trailing-zero-stripped content with explicit
/// stripped `size` (per spec §2). `content_hash` is the hash of the
/// stripped bytes (or the page-merkle root for large data).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct DataCap {
    pub size: u64,
    pub content_hash: CapHash,
}

/// `Cap::CNode` payload. Holds a reference-counted backend so the
/// `Cap` enum stays `Clone` cheaply. Mutation diverges only by
/// snapshotting first (see `CNodeBackend::snapshot`).
#[derive(Clone)]
pub struct CNodeCap {
    /// Reference-counted backend. `Send + Sync` is required by the
    /// trait so `Cap` itself is `Send + Sync` and can be shared
    /// across threads (kernel may be multi-threaded).
    /// To mutate without affecting existing clones, take a snapshot
    /// first.
    pub backend: Arc<dyn CNodeBackend<Cap> + Send + Sync>,
}

impl CNodeCap {
    pub fn new(backend: Arc<dyn CNodeBackend<Cap> + Send + Sync>) -> Self {
        Self { backend }
    }

    /// Content hash of the underlying cnode. Uses the cap-level
    /// `Cap::hash` to hash each non-empty slot.
    pub fn cnode_hash(&self) -> CnodeHash {
        let hasher = |c: &Cap| c.hash();
        self.backend.hash(&hasher)
    }
}

impl fmt::Debug for CNodeCap {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("CNodeCap")
            .field("size_log", &self.backend.size_log())
            .field("hash", &hex_short(&self.cnode_hash()))
            .finish()
    }
}

fn hex_short(bytes: &[u8]) -> String {
    let head: String = bytes.iter().take(4).map(|b| format!("{:02x}", b)).collect();
    format!("{}…", head)
}

/// `Cap::Type` payload. Opaque image_hash chain identifier;
/// IDENTIFICATION-ONLY. Possession does NOT grant authority (which
/// requires Cap::Instance with the same chain).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct TypeCap {
    pub image_hash_chain: CapHash,
}

#[cfg(test)]
mod tests {
    use super::super::cnode::InMemoryCNode;
    use super::*;

    fn instance_a() -> Cap {
        Cap::Instance(InstanceCap {
            image_hash_chain: [0xAA; 32],
            content_hash: [0xBB; 32],
        })
    }

    fn image_a() -> Cap {
        Cap::Image(ImageCap {
            content_hash: [0xAA; 32],
        })
    }

    fn data_a() -> Cap {
        Cap::Data(DataCap {
            size: 100,
            content_hash: [0xAA; 32],
        })
    }

    fn cnode_a() -> Cap {
        let cn: InMemoryCNode<Cap> = InMemoryCNode::new(2).unwrap();
        Cap::CNode(CNodeCap::new(Arc::new(cn)))
    }

    fn type_a() -> Cap {
        Cap::Type(TypeCap {
            image_hash_chain: [0xAA; 32],
        })
    }

    #[test]
    fn kind_matches_variant() {
        assert_eq!(instance_a().kind(), CapKind::Instance);
        assert_eq!(image_a().kind(), CapKind::Image);
        assert_eq!(data_a().kind(), CapKind::Data);
        assert_eq!(cnode_a().kind(), CapKind::CNode);
        assert_eq!(type_a().kind(), CapKind::Type);
    }

    #[test]
    fn equal_payload_different_kind_distinct_hash() {
        // Image and Type both wrap a single 32-byte hash. Their hashes
        // must differ thanks to the kind-byte domain separation.
        let h = image_a().hash();
        let t = type_a().hash();
        assert_ne!(h, t);
    }

    #[test]
    fn same_payload_same_hash() {
        let a = instance_a();
        let b = instance_a();
        assert_eq!(a.hash(), b.hash());
        assert_eq!(a, b);
    }

    #[test]
    fn different_chain_different_instance_hash() {
        let a = Cap::Instance(InstanceCap {
            image_hash_chain: [0xAA; 32],
            content_hash: [0xCC; 32],
        });
        let b = Cap::Instance(InstanceCap {
            image_hash_chain: [0xBB; 32],
            content_hash: [0xCC; 32],
        });
        assert_ne!(a.hash(), b.hash());
    }

    #[test]
    fn different_content_different_instance_hash() {
        let a = Cap::Instance(InstanceCap {
            image_hash_chain: [0xAA; 32],
            content_hash: [0xCC; 32],
        });
        let b = Cap::Instance(InstanceCap {
            image_hash_chain: [0xAA; 32],
            content_hash: [0xDD; 32],
        });
        assert_ne!(a.hash(), b.hash());
    }

    #[test]
    fn cnode_cap_can_hold_caps() {
        // Verify the type erasure works: CNodeBackend<Cap> can hold a
        // Cap of any variant, including another CNode.
        let mut cn: InMemoryCNode<Cap> = InMemoryCNode::new(2).unwrap();
        cn.set(crate::SlotIdx(0), Some(image_a())).unwrap();
        let outer = Cap::CNode(CNodeCap::new(Arc::new(cn)));
        assert_eq!(outer.kind(), CapKind::CNode);
        // Hashing recursively succeeds.
        let _h = outer.hash();
    }

    #[test]
    fn data_size_distinct_for_size_zero_vs_other() {
        let a = Cap::Data(DataCap {
            size: 0,
            content_hash: [0; 32],
        });
        let b = Cap::Data(DataCap {
            size: 1,
            content_hash: [0; 32],
        });
        assert_ne!(a.hash(), b.hash());
    }
}
