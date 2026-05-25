//! `CacheDirectory<S>` — two-tier cap store with refcount-based CoW.
//!
//! The cache holds caps in two maps:
//!
//! - **`blobs: HashMap<CapHash, Box<CacheEntry>, S>`** —
//!   content-addressed immutable caps. All five kinds (Type, Image,
//!   Data, CNode, Instance) can live here.
//! - **`instances: HashMap<CapRef, Box<CacheEntry>, S>`** —
//!   identity-keyed mutable working state. Only Data, CNode,
//!   Instance variants reach this map (after `get_mut` promotion).
//!
//! Cap content always lives on the global heap (= std heap on host, talc
//! on guest via `#[global_allocator]`). Two callers exist:
//! - Nub local backend: heap-backed cache in the host's global allocator.
//! - Nub Hyperlight backend: heap-resident cache in the guest's global
//!   allocator. The guest's cache lives in a `static Mutex<CacheDirectory<
//!   FixedState>>` and is initialised at link time via the [`new_const`]
//!   constructor.
//!
//! `S` is the `BuildHasher`. The heap-backed default is
//! [`DefaultHashBuilder`] (= `foldhash::fast::RandomState`,
//! per-process randomized). The guest uses
//! `foldhash::fast::FixedState` with a per-region random seed so that
//! both host and guest builds compute identical bucket assignments
//! against the same shared HashMap. Parameter order matches
//! `hashbrown::HashMap<K, V, S>`.
//!
//! Refcounting uses the same protocol as `Arc::make_mut`:
//! `fetch_sub(1, Release)` at mutation time; if `prev == 1` we have
//! sole ownership and move-promote (no copy), else we shallow-clone
//! into a fresh instance entry. See [`CacheDirectory::get_mut`] for details.

use alloc::boxed::Box;
use alloc::vec::Vec;
use core::hash::BuildHasher;
use core::sync::atomic::Ordering;

use allocate::collections::{DefaultHashBuilder, HashMap};

use super::cap::{Cap, CapHash, CapHashOrRef, CapRef};
use super::cap_hash::cap_hash;
use super::entry::CacheEntry;
use super::image_cap::ImageConvertError;

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

pub struct CacheDirectory<S = DefaultHashBuilder> {
    blobs: HashMap<CapHash, Box<CacheEntry>, S>,
    instances: HashMap<CapRef, Box<CacheEntry>, S>,
    next_ref: u64,
}

impl CacheDirectory<DefaultHashBuilder> {
    /// Construct an empty heap-backed cache using the default
    /// per-process-randomized hasher.
    pub fn new() -> Self {
        Self::with_hasher(DefaultHashBuilder::default())
    }
}

impl Default for CacheDirectory<DefaultHashBuilder> {
    fn default() -> Self {
        Self::new()
    }
}

impl<S: BuildHasher> CacheDirectory<S> {
    /// Construct an empty cache with an explicit hasher.
    pub fn with_hasher(hasher: S) -> Self
    where
        S: Clone,
    {
        Self {
            blobs: HashMap::with_hasher(hasher.clone()),
            instances: HashMap::with_hasher(hasher),
            // CapRef 0 is reserved; ref allocation starts at 1.
            next_ref: 1,
        }
    }
}

impl<S: Copy> CacheDirectory<S> {
    /// `const fn` constructor for static initialisation. Used by the
    /// guest's `state_cache::CACHE` static. Requires `S: Copy` so the
    /// same hasher value can seed both inner maps without invoking
    /// `Clone` (not allowed in `const fn` today).
    pub const fn new_const(hasher: S) -> Self {
        Self {
            blobs: HashMap::with_hasher(hasher),
            instances: HashMap::with_hasher(hasher),
            next_ref: 1,
        }
    }
}

impl<S: BuildHasher> CacheDirectory<S> {
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

    /// Iterate the cache's blob tier. Order is unspecified (the underlying
    /// HashMap is not sorted). Callers that need deterministic iteration
    /// (e.g. state-root computations) must collect + sort by `CapHash`.
    pub fn iter_blobs(&self) -> impl Iterator<Item = (&CapHash, &Cap)> {
        self.blobs.iter().map(|(h, b)| (h, &b.cap))
    }

    /// Get a shared reference to the cap stored under `key`.
    pub fn get(&self, key: CapHashOrRef) -> Option<&Cap> {
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
    /// directory mapping `CapHash` / `CapRef` to entry pointers.
    pub fn entry_va(&self, key: CapHashOrRef) -> Option<u64> {
        let entry: &CacheEntry = match key {
            CapHashOrRef::Hash(h) => &**self.blobs.get(&h)?,
            CapHashOrRef::Ref(r) => &**self.instances.get(&r)?,
        };
        Some(entry as *const CacheEntry as u64)
    }

    /// Blob insert: takes a `Cap` and stores it under `hash`. Idempotent
    /// (bumps refcount on a hit). Returns the post-insertion refcount.
    pub fn put_blob(&mut self, hash: CapHash, cap: Cap) -> Result<u32, CacheError> {
        if let Some(existing) = self.blobs.get(&hash) {
            let prev = existing.refcount.fetch_add(1, Ordering::Relaxed);
            return Ok(prev + 1);
        }
        let entry = CacheEntry::new(cap);
        let boxed = Box::new(entry);
        self.blobs.insert(hash, boxed);
        Ok(1)
    }

    /// Insert a caller-built `Cap` by reference.
    ///
    /// Computes the cap's content hash via [`crate::cap_hash::cap_hash`],
    /// then either bumps the refcount of an already-present entry (no
    /// allocation) or clones the cap and inserts it.
    ///
    /// Returns the cap's content hash. Idempotent: re-put with identical
    /// content returns the same hash and increments refcount.
    pub fn put_cap(&mut self, cap: &Cap) -> Result<CapHash, CacheError> {
        let hash = crate::cap_hash::cap_hash(cap);
        self.put_cap_with_hash(hash, cap)?;
        Ok(hash)
    }

    /// Pre-hashed variant of [`Self::put_cap`].
    ///
    /// The caller asserts that `hash == cap_hash(cap)`; this lets the hot
    /// idempotent-re-put path skip the SSZ merkleize entirely (becomes a
    /// single HashMap lookup + refcount increment). In debug builds the
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
    pub fn put_cap_with_hash(&mut self, hash: CapHash, cap: &Cap) -> Result<u32, CacheError> {
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
        // Cold path. Validate referenced targets exist, then clone
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
        let owned = cap.clone();
        let entry = CacheEntry::new(owned);
        let boxed = Box::new(entry);
        self.blobs.insert(hash, boxed);
        for t in &targets {
            self.incref(*t)?;
        }
        Ok(1)
    }

    /// Insert a cap as a fresh mutable instance entry. Returns the
    /// allocated `CapRef`. Refcount starts at 1.
    pub fn put_instance(&mut self, cap: Cap) -> Result<CapRef, CacheError> {
        let entry = CacheEntry::new(cap);
        let boxed = Box::new(entry);
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
    /// - Otherwise: clone the cap into a fresh instance entry; targets
    ///   stay shared via hash/ref and their refcounts are bumped.
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
                    // Shared. Clone the cap into a new entry.
                    // Targets stay shared via hash/ref; refcounts on
                    // those targets must be bumped to reflect the new
                    // referencing entry.
                    let cloned = self
                        .blobs
                        .get(&h)
                        .expect("present (we just observed it)")
                        .cap
                        .clone();
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
    pub fn instance_mut(&mut self, r: CapRef) -> Option<&mut Cap> {
        self.instances.get_mut(&r).map(|b| &mut b.cap)
    }

    // --- High-level publish helpers ---

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
        let nested: Vec<CapRef> = {
            let cap = &self
                .instances
                .get(&r)
                .ok_or(CacheError::InstanceMissing(r))?
                .cap;
            collect_ref_targets(cap)
        };

        // Settle each nested ref (returns the resolved Hash).
        let mut resolved: Vec<(CapRef, CapHash)> = Vec::new();
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

    /// For every cross-reference held by `key`'s cap, increment the
    /// target's refcount. Used after cloning a cap into a new entry
    /// that references the same targets as the original.
    fn bump_targets(&mut self, key: CapHashOrRef) -> Result<(), CacheError> {
        // Collect all target refs first to release the immutable
        // borrow on `self.instances` / `self.blobs`, then bump.
        let targets = self.collect_targets(key)?;
        for t in targets {
            self.incref(t)?;
        }
        Ok(())
    }

    fn collect_targets(&self, key: CapHashOrRef) -> Result<Vec<CapHashOrRef>, CacheError> {
        let cap = self.get(key).ok_or(match key {
            CapHashOrRef::Hash(_) => CacheError::BlobMissing,
            CapHashOrRef::Ref(r) => CacheError::InstanceMissing(r),
        })?;
        let mut out: Vec<CapHashOrRef> = Vec::new();
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
                // not addressable through the CacheDirectory; ImageCap holds
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
fn collect_ref_targets(cap: &Cap) -> Vec<CapRef> {
    let mut out: Vec<CapRef> = Vec::new();
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
fn rewrite_ref_targets(cap: &mut Cap, resolved: &[(CapRef, CapHash)]) {
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

/// Collect the cap targets a `Cap` directly holds — used by
/// [`CacheDirectory::put_cap_with_hash`] to incref each target on first put so
/// the refcount invariant (entry refcount == holder count) is preserved.
fn collect_referenced_targets_global(cap: &Cap) -> Vec<CapHashOrRef> {
    let mut out: Vec<CapHashOrRef> = Vec::new();
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
