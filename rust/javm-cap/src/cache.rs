//! `TypedCache<A>` — two-tier cap store with refcount-based CoW.
//!
//! The cache holds caps in two maps:
//!
//! - **`blobs: HashMap<CapHash, TBox<CacheEntry<A>, A>, A>`** —
//!   content-addressed immutable caps. All five kinds (Type, Image,
//!   Data, CNode, Instance) can live here.
//! - **`instances: HashMap<CapRef, TBox<CacheEntry<A>, A>, A>`** —
//!   identity-keyed mutable working state. Only Data, CNode,
//!   Instance variants reach this map (after `get_mut` promotion).
//!
//! `A` is an [`allocate::Allocator`] (= `core::alloc::Allocator`).
//! For host-private use the default `Global` gives a heap-backed
//! cache. For the shared-memory state cache, `A = TalcAlloc` lands
//! everything — including the HashMap node storage — in the cache
//! region.
//!
//! Refcounting uses the same protocol as `Arc::make_mut`:
//! `fetch_sub(1, Release)` at mutation time; if `prev == 1` we have
//! sole ownership and move-promote (no copy), else we shallow-clone
//! into a fresh instance entry. See [`TypedCache::get_mut`] for details.

use core::sync::atomic::Ordering;

use allocate::Box as ABox;
use allocate::Vec as AVec;
use allocate::{Allocator, Global, HashMap};

use super::cap::{Cap, CapHash, CapHashOrRef, CapRef};
use super::cap_hash::cap_hash;
use super::cnode::CNodeCap;
use super::data::{DataCap, DataContent};
use super::entry::CacheEntry;
use super::image_cap::ImageConvertError;
use super::instance::{InstanceCap, RwOverlay};
use super::page::{PageBytes, PageRef, PageSlot};

/// Talc-friendly Box alias — `allocator_api2::Box` parameterised on
/// the cap's allocator.
type TBox<T, A> = ABox<T, A>;

#[derive(Debug, thiserror::Error)]
pub enum CacheError {
    #[error("blob not found for hash")]
    BlobMissing,
    #[error("instance not found for ref {0}")]
    InstanceMissing(CapRef),
    #[error("allocator refused allocation")]
    AllocFailure,
    #[error("get_mut called on Type/Image (only Data/CNode/Instance can be promoted)")]
    NonMutableKind,
    #[error("image conversion failed: {0}")]
    ImageConvertFailed(#[from] ImageConvertError),
    #[error("paged data: page length mismatch (expected={expected}, got={got})")]
    PageSizeMismatch { expected: u32, got: usize },
    #[error("cnode slot index out of range")]
    SlotOutOfRange,
}

pub struct TypedCache<A: Allocator + Clone = Global> {
    alloc: A,
    blobs: HashMap<CapHash, TBox<CacheEntry<A>, A>, A>,
    instances: HashMap<CapRef, TBox<CacheEntry<A>, A>, A>,
    next_ref: u64,
}

impl TypedCache<Global> {
    /// Construct an empty heap-backed cache. Equivalent to
    /// `TypedCache::new_in(Global)` for callers that don't want an
    /// allocator dependency.
    pub fn new() -> Self {
        Self::new_in(Global)
    }
}

impl Default for TypedCache<Global> {
    fn default() -> Self {
        Self::new()
    }
}

impl<A: Allocator + Clone> TypedCache<A> {
    /// Construct an empty cache that allocates cap content through
    /// `alloc`.
    pub fn new_in(alloc: A) -> Self {
        Self {
            blobs: HashMap::new_in(alloc.clone()),
            instances: HashMap::new_in(alloc.clone()),
            alloc,
            // CapRef 0 is reserved; ref allocation starts at 1.
            next_ref: 1,
        }
    }

    /// Number of entries in each tier. Useful for tests and metrics.
    pub fn blob_count(&self) -> usize {
        self.blobs.len()
    }
    pub fn instance_count(&self) -> usize {
        self.instances.len()
    }

    /// Whether the blobs tier holds an entry under `hash`.
    pub fn contains_blob(&self, hash: &CapHash) -> bool {
        self.blobs.contains_key(hash)
    }

    /// Iterate the cache's blob tier in sorted `CapHash` order. Useful
    /// for state-root computations that walk all content-addressed caps
    /// deterministically. `BTreeMap`'s iter is already sorted by key.
    pub fn iter_blobs(&self) -> impl Iterator<Item = (&CapHash, &Cap<A>)> {
        self.blobs.iter().map(|(h, b)| (h, &b.cap))
    }

    /// Get a shared reference to the cap stored under `key`.
    pub fn get(&self, key: CapHashOrRef) -> Option<&Cap<A>> {
        match key {
            CapHashOrRef::Hash(h) => self.blobs.get(&h).map(|b| &b.cap),
            CapHashOrRef::Ref(r) => self.instances.get(&r).map(|b| &b.cap),
        }
    }

    /// Get the current refcount for a cap. Returns `None` if the cap
    /// is absent.
    pub fn refcount(&self, key: CapHashOrRef) -> Option<u32> {
        let entry = match key {
            CapHashOrRef::Hash(h) => self.blobs.get(&h)?,
            CapHashOrRef::Ref(r) => self.instances.get(&r)?,
        };
        Some(entry.refcount.load(Ordering::Acquire))
    }

    /// Get the VA of the [`CacheEntry`] backing `key`. Returns `None`
    /// if the cap is absent.
    ///
    /// Useful for downstream layers that maintain a shared-memory
    /// directory mapping `CapHash` / `CapRef` to entry pointers: the
    /// guest scans the directory, reads the VA, and dereferences the
    /// `CacheEntry`'s `cap` field directly. Requires the cache to be
    /// backed by an allocator whose pointers are valid in the guest's
    /// address space (e.g. `TalcAlloc` over a region mapped at the
    /// same VA on host and guest).
    pub fn entry_va(&self, key: CapHashOrRef) -> Option<u64> {
        let entry: &CacheEntry<A> = match key {
            CapHashOrRef::Hash(h) => &**self.blobs.get(&h)?,
            CapHashOrRef::Ref(r) => &**self.instances.get(&r)?,
        };
        Some(entry as *const CacheEntry<A> as u64)
    }

    /// Test-only blob insert: takes `Cap<A>` already in this cache's
    /// allocator and stores it under `hash`. Idempotent (bumps refcount
    /// on a hit). Returns the post-insertion refcount.
    ///
    /// Not exposed in production builds because the `Cap<A>` argument
    /// leaks the cache's allocator onto the API surface — an outside
    /// caller could construct a `Cap<A>` against a *different* `A`
    /// instance (e.g., a foreign `TalcAlloc` over an unrelated arena)
    /// and hand it in. The cache would then hold cap content whose
    /// backing memory lives outside the cache's own arena, breaking
    /// invariants like "all Hyperlight shared-cache content lives in
    /// the MAP_SHARED region at `STATE_CACHE_VA`". Public publish goes
    /// through [`Self::put_cap`] / [`Self::put_cap_with_hash`], which
    /// take `&Cap<Global>` and deep-clone into `A` so the cache owns
    /// every allocation.
    #[cfg(test)]
    pub(crate) fn put_blob(&mut self, hash: CapHash, cap: Cap<A>) -> Result<u32, CacheError> {
        if let Some(existing) = self.blobs.get(&hash) {
            let prev = existing.refcount.fetch_add(1, Ordering::Relaxed);
            return Ok(prev + 1);
        }
        let entry = CacheEntry::new(cap);
        let boxed =
            ABox::try_new_in(entry, self.alloc.clone()).map_err(|_| CacheError::AllocFailure)?;
        self.blobs.insert(hash, boxed);
        Ok(1)
    }

    /// Insert a caller-built `Cap<Global>` by reference.
    ///
    /// Computes the cap's content hash via [`crate::cap_hash::cap_hash`],
    /// then either bumps the refcount of an already-present entry (no
    /// allocation) or deep-clones the cap into this cache's allocator and
    /// inserts it (one allocation pass through `A`).
    ///
    /// Returns the cap's content hash. Idempotent: re-put with identical
    /// content returns the same hash and increments refcount.
    pub fn put_cap(&mut self, cap: &Cap<Global>) -> Result<CapHash, CacheError> {
        let hash = crate::cap_hash::cap_hash(cap);
        self.put_cap_with_hash(hash, cap)?;
        Ok(hash)
    }

    /// Pre-hashed variant of [`Self::put_cap`].
    ///
    /// The caller asserts that `hash == cap_hash(cap)`; this lets the hot
    /// idempotent-re-put path skip the SSZ merkleize entirely (becomes a
    /// single BTreeMap lookup + refcount increment). In debug builds the
    /// hash is verified; in release the assertion is elided so the path
    /// stays cheap.
    ///
    /// On the cold path, referenced targets (cap-hashes the cap holds —
    /// Image's pinned/initial slot targets, CNode's slot targets,
    /// Instance's image_hash + root_cnode) are validated to exist and
    /// have their refcounts bumped to mirror the new holder. This
    /// matches the old `publish_image / publish_cnode /
    /// publish_instance_blob` refcount discipline.
    ///
    /// Returns the post-insertion refcount.
    pub fn put_cap_with_hash(
        &mut self,
        hash: CapHash,
        cap: &Cap<Global>,
    ) -> Result<u32, CacheError> {
        // Hot path: idempotent re-put. Bump refcount, return.
        if let Some(existing) = self.blobs.get(&hash) {
            let prev = existing.refcount.fetch_add(1, Ordering::Relaxed);
            return Ok(prev + 1);
        }
        debug_assert_eq!(
            crate::cap_hash::cap_hash(cap),
            hash,
            "put_cap_with_hash: claimed hash does not match cap content",
        );
        // Cold path. Validate referenced targets exist, then deep-clone
        // + insert + incref targets.
        let targets = collect_referenced_targets_global(cap);
        for t in &targets {
            match t {
                CapHashOrRef::Hash(h) => {
                    if !self.blobs.contains_key(h) {
                        return Err(CacheError::BlobMissing);
                    }
                }
                CapHashOrRef::Ref(r) => {
                    if !self.instances.contains_key(r) {
                        return Err(CacheError::InstanceMissing(*r));
                    }
                }
            }
        }
        let owned = deep_clone_into(cap, self.alloc.clone());
        let entry = CacheEntry::new(owned);
        let boxed =
            ABox::try_new_in(entry, self.alloc.clone()).map_err(|_| CacheError::AllocFailure)?;
        self.blobs.insert(hash, boxed);
        for t in &targets {
            self.incref(*t)?;
        }
        Ok(1)
    }

    /// Insert a cap as a fresh mutable instance entry. Returns the
    /// allocated `CapRef`. Refcount starts at 1.
    pub fn put_instance(&mut self, cap: Cap<A>) -> Result<CapRef, CacheError> {
        let entry = CacheEntry::new(cap);
        let boxed =
            ABox::try_new_in(entry, self.alloc.clone()).map_err(|_| CacheError::AllocFailure)?;
        let r = self.next_ref;
        self.next_ref = self
            .next_ref
            .checked_add(1)
            .expect("CapRef space exhausted");
        self.instances.insert(r, boxed);
        Ok(r)
    }

    /// Increment the refcount of the cap referenced by `key`.
    /// Used by callers when binding `key` into an additional slot.
    pub fn incref(&self, key: CapHashOrRef) -> Result<(), CacheError> {
        let entry = match key {
            CapHashOrRef::Hash(h) => self.blobs.get(&h).ok_or(CacheError::BlobMissing)?,
            CapHashOrRef::Ref(r) => self
                .instances
                .get(&r)
                .ok_or(CacheError::InstanceMissing(r))?,
        };
        entry.refcount.fetch_add(1, Ordering::Relaxed);
        Ok(())
    }

    /// Decrement the refcount of the cap referenced by `key`. If the
    /// count drops to zero, the entry is removed from its map (V1 has
    /// no eviction LRU; this is the only path that frees entries).
    /// Returns the new refcount (post-decrement).
    pub fn decref(&mut self, key: CapHashOrRef) -> Result<u32, CacheError> {
        let prev_count = {
            let entry = match key {
                CapHashOrRef::Hash(h) => self.blobs.get(&h).ok_or(CacheError::BlobMissing)?,
                CapHashOrRef::Ref(r) => self
                    .instances
                    .get(&r)
                    .ok_or(CacheError::InstanceMissing(r))?,
            };
            entry.refcount.fetch_sub(1, Ordering::Release)
        };
        if prev_count == 1 {
            // Last reference; remove entry. Drop runs the destructor
            // which frees the cap's content allocations.
            match key {
                CapHashOrRef::Hash(h) => {
                    self.blobs.remove(&h);
                }
                CapHashOrRef::Ref(r) => {
                    self.instances.remove(&r);
                }
            }
            Ok(0)
        } else {
            Ok(prev_count - 1)
        }
    }

    /// Promote `key` to a mutable working entry in `instances`,
    /// following the `Arc::make_mut` protocol.
    ///
    /// Behaviour:
    /// - If `key` is already a `Ref`, return its CapRef + mutable ref
    ///   (no work needed).
    /// - If `key` is a `Hash` and the blob's refcount is exactly 1
    ///   (sole owner): move-promote — remove the entry from `blobs`,
    ///   re-insert under a fresh CapRef in `instances`. No copy.
    /// - Otherwise: shallow-clone the cap's slot/page table into a
    ///   fresh instance entry; targets stay shared via hash/ref and
    ///   their refcounts are bumped.
    ///
    /// Returns the new (or existing) `CapRef` along with a mutable
    /// reference to the cap.
    pub fn get_mut(&mut self, key: CapHashOrRef) -> Result<CapRef, CacheError> {
        match key {
            CapHashOrRef::Ref(r) => {
                if !self.instances.contains_key(&r) {
                    return Err(CacheError::InstanceMissing(r));
                }
                Ok(r)
            }
            CapHashOrRef::Hash(h) => {
                // Image/Type are immutable by definition; reject
                // before touching the refcount.
                {
                    let entry = self.blobs.get(&h).ok_or(CacheError::BlobMissing)?;
                    match entry.cap {
                        Cap::Image(_) | Cap::Type(_) => return Err(CacheError::NonMutableKind),
                        _ => {}
                    }
                }
                let prev = {
                    let entry = self.blobs.get(&h).expect("present (we just observed it)");
                    entry.refcount.fetch_sub(1, Ordering::Release)
                };
                if prev == 1 {
                    // Sole owner. Move-promote: remove the entry,
                    // reset its refcount to 1, drop it into instances.
                    let boxed = self
                        .blobs
                        .remove(&h)
                        .expect("present (we just observed it)");
                    boxed.refcount.store(1, Ordering::Release);
                    let r = self.next_ref;
                    self.next_ref = self
                        .next_ref
                        .checked_add(1)
                        .expect("CapRef space exhausted");
                    self.instances.insert(r, boxed);
                    Ok(r)
                } else {
                    // Shared. Shallow-clone the cap into a new entry.
                    // Targets stay shared via hash/ref; refcounts on
                    // those targets must be bumped to reflect the new
                    // referencing entry.
                    let cloned = self.shallow_clone_blob(h)?;
                    let new_ref = self.put_instance(cloned)?;
                    // The new entry references the same targets as
                    // the original blob; bump their refcounts.
                    self.bump_targets(CapHashOrRef::Ref(new_ref))?;
                    Ok(new_ref)
                }
            }
        }
    }

    /// Mutable reference to the cap behind a known `CapRef`.
    /// Distinct from `get_mut` because it doesn't promote / clone.
    pub fn instance_mut(&mut self, r: CapRef) -> Option<&mut Cap<A>> {
        self.instances.get_mut(&r).map(|b| &mut b.cap)
    }

    /// Allocator handle (clone). Useful for callers that want to
    /// allocate caps externally before handing them to the cache.
    pub fn allocator(&self) -> A {
        self.alloc.clone()
    }

    // --- High-level publish helpers ---

    /// Publish an inline DataCap blob from a byte buffer. Allocates a
    /// fresh copy of `bytes` in this cache's allocator, hashes the
    /// resulting cap, and inserts it into `blobs`. Returns the hash
    /// (suitable for use as a `CapHashOrRef::Hash` target).
    ///
    /// Idempotent: re-publishing identical bytes returns the same hash
    /// and bumps the existing entry's refcount.
    ///
    /// Settle a cap reference: resolve any `CapHashOrRef::Ref` targets
    /// nested inside the cap to their content-addressed hashes,
    /// graduating descendants from `instances` to `blobs` as needed,
    /// then return the cap's hash.
    ///
    /// Behaviour by cap kind at `key`:
    ///
    /// - If `key` is already a `Hash`, return it unchanged (no work).
    /// - For an Instance ref: recursively settle `root_cnode` if it's
    ///   a `Ref`, replace with the resulting `Hash`, then hash the
    ///   InstanceCap. The instance entry **stays in `instances`** as
    ///   the live mutable state; the returned hash is a snapshot
    ///   identifier (callers can re-`put_cap` the snapshot to retain an
    ///   independent immutable copy).
    /// - For a CNode ref: recursively settle each Ref slot target,
    ///   replace with Hashes, hash the CNodeCap, then move the entry
    ///   from `instances` to `blobs` under the new hash.
    /// - For a Data ref: no nested refs to settle. Hash, then move
    ///   from `instances` to `blobs`.
    ///
    /// Returns the resolved `CapHash`.
    pub fn settle(&mut self, key: CapHashOrRef) -> Result<CapHash, CacheError> {
        match key {
            CapHashOrRef::Hash(h) => Ok(h),
            CapHashOrRef::Ref(r) => self.settle_ref(r),
        }
    }

    fn settle_ref(&mut self, r: CapRef) -> Result<CapHash, CacheError> {
        // First, recursively settle any nested Refs (mutating the cap
        // in place to replace Ref targets with Hash targets).
        self.settle_nested_refs(r)?;

        // Now the cap holds only Hash targets; we can hash it.
        let cap = &self
            .instances
            .get(&r)
            .ok_or(CacheError::InstanceMissing(r))?
            .cap;
        let hash = cap_hash(cap);

        // Graduate non-Instance entries from `instances` to `blobs`
        // under the computed hash. Instance entries stay live (they
        // are the working state); their snapshot hash is returned but
        // not separately stored.
        let is_instance = matches!(cap, Cap::Instance(_));
        if !is_instance {
            // Move the entry over. The refcount carries across; we
            // also need to handle the case where a blob with the same
            // hash already exists (incref + drop the instance entry).
            if self.blobs.contains_key(&hash) {
                // Merge into existing blob: incref it, drop the
                // instance entry. Targets stay referenced once via
                // the surviving entry (the instance's own target
                // refs need a decref to avoid double-counting).
                let targets = self.collect_targets(CapHashOrRef::Ref(r))?;
                self.blobs
                    .get(&hash)
                    .expect("checked above")
                    .refcount
                    .fetch_add(1, Ordering::Relaxed);
                self.instances.remove(&r);
                for t in targets {
                    self.decref(t)?;
                }
            } else {
                let boxed = self
                    .instances
                    .remove(&r)
                    .expect("present (we just observed it)");
                self.blobs.insert(hash, boxed);
            }
        }
        Ok(hash)
    }

    /// Walk the cap at instance ref `r` and replace any
    /// `CapHashOrRef::Ref` targets it directly holds with the
    /// `CapHashOrRef::Hash` produced by settling those refs.
    /// Recursive: settling a ref triggers settling of its own
    /// nested refs first.
    fn settle_nested_refs(&mut self, r: CapRef) -> Result<(), CacheError> {
        // Collect the list of Refs we need to settle before mutating.
        let nested: AVec<CapRef> = {
            let cap = &self
                .instances
                .get(&r)
                .ok_or(CacheError::InstanceMissing(r))?
                .cap;
            collect_ref_targets(cap)
        };

        // Settle each nested ref (returns the resolved Hash).
        let mut resolved: AVec<(CapRef, CapHash)> = AVec::new();
        for n in nested.iter() {
            let h = self.settle_ref(*n)?;
            resolved.push((*n, h));
        }

        // Rewrite the parent cap's Ref targets to use the resolved
        // Hashes.
        let cap = &mut self
            .instances
            .get_mut(&r)
            .ok_or(CacheError::InstanceMissing(r))?
            .cap;
        rewrite_ref_targets(cap, &resolved);
        Ok(())
    }

    // --- Internals ---

    /// Shallow-clone the blob at `hash` into a fresh `Cap<A>`. Only
    /// the directly-owned slot/page tables are duplicated; cross-
    /// references (CapHashOrRef in cnode slots, page hashes in
    /// DataCap) carry over by value.
    fn shallow_clone_blob(&self, hash: CapHash) -> Result<Cap<A>, CacheError> {
        let entry = self.blobs.get(&hash).ok_or(CacheError::BlobMissing)?;
        shallow_clone_cap(&entry.cap, self.alloc.clone())
    }

    /// For every cross-reference held by `key`'s cap, increment the
    /// target's refcount. Used after `shallow_clone_blob` produces a
    /// new entry that references the same targets as the original.
    fn bump_targets(&mut self, key: CapHashOrRef) -> Result<(), CacheError> {
        // Collect all target refs first to release the immutable
        // borrow on `self.instances` / `self.blobs`, then bump.
        let targets = self.collect_targets(key)?;
        for t in targets {
            self.incref(t)?;
        }
        Ok(())
    }

    fn collect_targets(&self, key: CapHashOrRef) -> Result<AVec<CapHashOrRef>, CacheError> {
        let cap = self.get(key).ok_or(match key {
            CapHashOrRef::Hash(_) => CacheError::BlobMissing,
            CapHashOrRef::Ref(r) => CacheError::InstanceMissing(r),
        })?;
        let mut out: AVec<CapHashOrRef> = AVec::new();
        match cap {
            Cap::CNode(cn) => {
                for (_, mo) in cn.slots.iter() {
                    if let ssz::MissingOr::Materialized(t) = mo {
                        out.push(*t);
                    }
                }
            }
            Cap::Instance(inst) => {
                out.push(CapHashOrRef::Hash(inst.image_hash));
                out.push(inst.root_cnode);
            }
            Cap::Data(_) | Cap::Image(_) | Cap::Type(_) => {
                // DataCap pages are owned (via PageRef.refcount) and
                // not addressable through the TypedCache; ImageCap holds
                // ImageSlotEntry referring to blobs which the cache
                // tracks separately at publish time, not at slot
                // mutation time; TypeCap has no targets.
            }
        }
        Ok(out)
    }
}

/// Collect the directly-referenced `CapRef`s held by `cap`. Used by
/// `settle` to know which sub-refs to resolve before hashing.
fn collect_ref_targets<A: Allocator + Clone>(cap: &Cap<A>) -> AVec<CapRef> {
    let mut out: AVec<CapRef> = AVec::new();
    match cap {
        Cap::CNode(cn) => {
            for (_, mo) in cn.slots.iter() {
                if let ssz::MissingOr::Materialized(CapHashOrRef::Ref(r)) = mo {
                    out.push(*r);
                }
            }
        }
        Cap::Instance(inst) => {
            if let CapHashOrRef::Ref(r) = inst.root_cnode {
                out.push(r);
            }
        }
        Cap::Data(_) | Cap::Image(_) | Cap::Type(_) => {}
    }
    out
}

/// Rewrite `cap`'s direct `CapHashOrRef::Ref(r)` targets to
/// `CapHashOrRef::Hash(h)` according to the `(r, h)` mapping in
/// `resolved`.
fn rewrite_ref_targets<A: Allocator + Clone>(cap: &mut Cap<A>, resolved: &[(CapRef, CapHash)]) {
    let lookup =
        |r: CapRef| -> Option<CapHash> { resolved.iter().find(|(k, _)| *k == r).map(|(_, h)| *h) };
    match cap {
        Cap::CNode(cn) => {
            for (_, mo) in cn.slots.iter_mut() {
                if let ssz::MissingOr::Materialized(t) = mo
                    && let CapHashOrRef::Ref(r) = *t
                    && let Some(h) = lookup(r)
                {
                    *t = CapHashOrRef::Hash(h);
                }
            }
        }
        Cap::Instance(inst) => {
            if let CapHashOrRef::Ref(r) = inst.root_cnode
                && let Some(h) = lookup(r)
            {
                inst.root_cnode = CapHashOrRef::Hash(h);
            }
        }
        Cap::Data(_) | Cap::Image(_) | Cap::Type(_) => {}
    }
}

/// Collect the cap targets a `Cap<Global>` directly holds — used by
/// [`TypedCache::put_cap_with_hash`] to incref each target on first put so
/// the refcount invariant (entry refcount == holder count) is preserved.
fn collect_referenced_targets_global(cap: &Cap<Global>) -> alloc::vec::Vec<CapHashOrRef> {
    let mut out: alloc::vec::Vec<CapHashOrRef> = alloc::vec::Vec::new();
    match cap {
        Cap::Image(img) => {
            for e in img.pinned.iter() {
                out.push(CapHashOrRef::Hash(e.cap_hash));
            }
            for e in img.initial.iter() {
                out.push(CapHashOrRef::Hash(e.cap_hash));
            }
        }
        Cap::CNode(cn) => {
            for (_, mo) in cn.slots.iter() {
                if let ssz::MissingOr::Materialized(t) = mo {
                    out.push(*t);
                }
            }
        }
        Cap::Instance(inst) => {
            out.push(CapHashOrRef::Hash(inst.image_hash));
            out.push(inst.root_cnode);
        }
        Cap::Data(_) | Cap::Type(_) => {}
    }
    out
}

/// Deep-clone a `Cap<Global>` into the cache's allocator `A`. Walks every
/// owned `Vec<T, Global>` in the cap tree and re-allocates through `alloc`;
/// for `DataContent::Paged` allocates a fresh `PageBytes<A>` per loaded
/// page (the inbound `PageRef<Global>` is dropped after copying out).
///
/// This is the cross-allocator counterpart to [`shallow_clone_cap`] — used
/// by `put_cap` to move a caller-built cap into cache-resident memory.
pub(crate) fn deep_clone_into<A: Allocator + Clone>(src: &Cap<Global>, alloc: A) -> Cap<A> {
    match src {
        Cap::Data(d) => {
            let content = match &d.content {
                DataContent::Inline(bytes) => {
                    // Page-aligned re-allocation through `alloc`: the
                    // resulting buffer can be mapped directly into a
                    // ring-3 PT without an intermediate copy. Source
                    // length is already a page-multiple (DataCap
                    // invariant); we mirror the same length on the
                    // target side.
                    debug_assert!(
                        bytes.len().is_multiple_of(crate::data::PAGE_SIZE),
                        "DataCap inline content must be page-multiple"
                    );
                    let mut new_bytes: AVec<u8, A> =
                        crate::data::alloc_page_aligned_zeroed::<A>(bytes.len(), alloc.clone());
                    new_bytes[..bytes.len()].copy_from_slice(bytes.as_slice());
                    DataContent::Inline(new_bytes)
                }
                DataContent::Paged { page_size, pages } => {
                    let mut new_pages: AVec<PageSlot<A>, A> =
                        AVec::with_capacity_in(pages.len(), alloc.clone());
                    for p in pages.iter() {
                        let new_slot = match p {
                            PageSlot::Empty => PageSlot::Empty,
                            PageSlot::Missing(h) => PageSlot::Missing(*h),
                            PageSlot::Loaded(pr) => {
                                // Page bytes are also page-aligned so
                                // they can be mapped directly.
                                let mut bytes: AVec<u8, A> = crate::data::alloc_page_aligned_zeroed::<
                                    A,
                                >(
                                    pr.bytes.len(), alloc.clone()
                                );
                                bytes[..pr.bytes.len()].copy_from_slice(pr.bytes.as_slice());
                                let pb = PageBytes {
                                    hash: pr.hash,
                                    bytes,
                                };
                                let new_pr = PageRef::<A>::new_in(pb, alloc.clone());
                                PageSlot::Loaded(new_pr)
                            }
                        };
                        new_pages.push(new_slot);
                    }
                    DataContent::Paged {
                        page_size: *page_size,
                        pages: new_pages,
                    }
                }
            };
            Cap::Data(DataCap { content })
        }
        Cap::Image(img) => {
            let mut code = AVec::with_capacity_in(img.code.len(), alloc.clone());
            code.extend_from_slice(img.code.as_slice());

            let mut bitmask = AVec::with_capacity_in(img.bitmask.len(), alloc.clone());
            bitmask.extend_from_slice(img.bitmask.as_slice());

            let mut jump_table = AVec::with_capacity_in(img.jump_table.len(), alloc.clone());
            for v in img.jump_table.iter() {
                jump_table.push(*v);
            }

            let mut endpoints = AVec::with_capacity_in(img.endpoints.len(), alloc.clone());
            for e in img.endpoints.iter() {
                endpoints.push(*e);
            }

            let mut mappings = AVec::with_capacity_in(img.mappings.len(), alloc.clone());
            for m in img.mappings.iter() {
                mappings.push(*m);
            }

            let mut pinned = AVec::with_capacity_in(img.pinned.len(), alloc.clone());
            for s in img.pinned.iter() {
                pinned.push(*s);
            }

            let mut initial = AVec::with_capacity_in(img.initial.len(), alloc.clone());
            for s in img.initial.iter() {
                initial.push(*s);
            }

            Cap::Image(crate::image_cap::ImageCap {
                code,
                bitmask,
                jump_table,
                endpoints,
                mappings,
                pinned,
                initial,
                yield_marker_slot: img.yield_marker_slot,
            })
        }
        Cap::CNode(cn) => {
            let mut slots: ssz::SparseList<CapHashOrRef, { crate::cnode::MAX_CNODE_SLOTS }, A> =
                ssz::SparseList::new_in(alloc.clone());
            for (idx, mo) in cn.slots.iter() {
                slots
                    .insert(idx, mo.clone())
                    .expect("source SparseList already satisfies the bound");
            }
            Cap::CNode(CNodeCap {
                size_log: cn.size_log,
                slots,
            })
        }
        Cap::Instance(inst) => {
            let mut new_overlays: AVec<RwOverlay<A>, A> =
                AVec::with_capacity_in(inst.rw_overlays.len(), alloc.clone());
            for o in inst.rw_overlays.iter() {
                let mut bytes: AVec<u8, A> = AVec::with_capacity_in(o.bytes.len(), alloc.clone());
                bytes.extend_from_slice(o.bytes.as_slice());
                new_overlays.push(RwOverlay {
                    start: o.start,
                    bytes,
                });
            }
            Cap::Instance(InstanceCap {
                image_hash_chain: inst.image_hash_chain,
                image_hash: inst.image_hash,
                root_cnode: inst.root_cnode,
                rw_overlays: new_overlays,
                mem_size: inst.mem_size,
                regs: inst.regs,
                pc: inst.pc,
                gas_remaining: inst.gas_remaining,
            })
        }
        Cap::Type(t) => Cap::Type(*t),
    }
}

/// Shallow-clone a cap: duplicate the slot/page table allocations
/// only, sharing all targets. Targets' refcounts must be bumped by
/// the caller after this returns.
/// Shallow-clone a `Cap<A>` into a fresh allocation. Only the
/// directly-owned slot/page tables are duplicated; cross-references
/// (CapHashOrRef in cnode slots, page hashes in DataCap) carry over
/// by value. The caller is responsible for bumping the refcounts of
/// any cross-referenced targets (host-side: `TypedCache::bump_targets`;
/// guest-side: state-cache's `cap_make_mut`).
pub fn shallow_clone_cap<A: Allocator + Clone>(
    cap: &Cap<A>,
    alloc: A,
) -> Result<Cap<A>, CacheError> {
    match cap {
        Cap::CNode(cn) => {
            // SparseList clones into a new allocator handle: the BTreeMap
            // storage uses Global regardless of A (std::collections has no
            // custom-allocator support on stable), but cloning the map's
            // values and stamping the new allocator handle gives us a
            // logically independent copy.
            let mut slots: ssz::SparseList<CapHashOrRef, { crate::cnode::MAX_CNODE_SLOTS }, A> =
                ssz::SparseList::new_in(alloc.clone());
            for (idx, mo) in cn.slots.iter() {
                slots
                    .insert(idx, mo.clone())
                    .expect("source SparseList already satisfies the bound");
            }
            Ok(Cap::CNode(CNodeCap {
                size_log: cn.size_log,
                slots,
            }))
        }
        Cap::Data(d) => {
            let content = match &d.content {
                DataContent::Inline(bytes) => {
                    debug_assert!(
                        bytes.len().is_multiple_of(crate::data::PAGE_SIZE),
                        "DataCap inline content must be page-multiple"
                    );
                    let mut new_bytes: AVec<u8, A> =
                        crate::data::alloc_page_aligned_zeroed::<A>(bytes.len(), alloc.clone());
                    new_bytes[..bytes.len()].copy_from_slice(bytes.as_slice());
                    DataContent::Inline(new_bytes)
                }
                DataContent::Paged { page_size, pages } => {
                    let mut new_pages: AVec<PageSlot<A>, A> =
                        AVec::with_capacity_in(pages.len(), alloc.clone());
                    for p in pages.iter() {
                        match p {
                            PageSlot::Empty => new_pages.push(PageSlot::Empty),
                            PageSlot::Missing(h) => new_pages.push(PageSlot::Missing(*h)),
                            PageSlot::Loaded(pr) => new_pages.push(PageSlot::Loaded(pr.clone())),
                        }
                    }
                    DataContent::Paged {
                        page_size: *page_size,
                        pages: new_pages,
                    }
                }
            };
            Ok(Cap::Data(DataCap { content }))
        }
        Cap::Instance(inst) => {
            let mut new_overlays: AVec<RwOverlay<A>, A> =
                AVec::with_capacity_in(inst.rw_overlays.len(), alloc.clone());
            for o in inst.rw_overlays.iter() {
                let mut bytes: AVec<u8, A> = AVec::with_capacity_in(o.bytes.len(), alloc.clone());
                bytes.extend_from_slice(o.bytes.as_slice());
                new_overlays.push(RwOverlay {
                    start: o.start,
                    bytes,
                });
            }
            Ok(Cap::Instance(InstanceCap {
                image_hash_chain: inst.image_hash_chain,
                image_hash: inst.image_hash,
                root_cnode: inst.root_cnode,
                rw_overlays: new_overlays,
                mem_size: inst.mem_size,
                regs: inst.regs,
                pc: inst.pc,
                gas_remaining: inst.gas_remaining,
            }))
        }
        Cap::Image(_) | Cap::Type(_) => Err(CacheError::NonMutableKind),
    }
}
