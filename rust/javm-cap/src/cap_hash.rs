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
