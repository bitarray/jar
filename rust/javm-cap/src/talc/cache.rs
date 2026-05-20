//! `Cache<A>` — two-tier cap store with refcount-based CoW.
//!
//! The cache holds caps in two maps:
//!
//! - **`blobs: BTreeMap<CapHash, TBox<CacheEntry<A>, A>>`** — content-
//!   addressed immutable caps. All five kinds (Type, Image, Data,
//!   CNode, Instance) can live here.
//! - **`instances: BTreeMap<CapRef, TBox<CacheEntry<A>, A>>`** —
//!   identity-keyed mutable working state. Only Data, CNode,
//!   Instance variants reach this map (after `get_mut` promotion).
//!
//! `A` is an [`allocator_api2`] allocator. For host-private use the
//! default `Global` gives a heap-backed cache. For the shared-memory
//! state cache, `A = TalcAlloc` lands everything in the cache region.
//!
//! Refcounting uses the same protocol as `Arc::make_mut`:
//! `fetch_sub(1, Release)` at mutation time; if `prev == 1` we have
//! sole ownership and move-promote (no copy), else we shallow-clone
//! into a fresh instance entry. See [`Self::get_mut`] for details.

use alloc::collections::BTreeMap;
use core::sync::atomic::Ordering;

use allocator_api2::alloc::{Allocator, Global};
use allocator_api2::boxed::Box as ABox;
use allocator_api2::vec::Vec as AVec;

use crate::slot::SlotIdx;

use super::cap::{Cap, CapHash, CapHashOrRef, CapRef, NUM_REGS};
use super::cnode::{CNodeCap, CNodeSlotEntry};
use super::data::{DataCap, DataContent};
use super::entry::CacheEntry;
use super::hash::cap_hash;
use super::instance::{InstanceCap, RwOverlay};
use super::page::PageSlot;

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
}

pub struct Cache<A: Allocator + Clone = Global> {
    alloc: A,
    blobs: BTreeMap<CapHash, TBox<CacheEntry<A>, A>>,
    instances: BTreeMap<CapRef, TBox<CacheEntry<A>, A>>,
    next_ref: u64,
}

impl<A: Allocator + Clone> Cache<A> {
    /// Construct an empty cache that allocates cap content through
    /// `alloc`.
    pub fn new_in(alloc: A) -> Self {
        Self {
            alloc,
            blobs: BTreeMap::new(),
            instances: BTreeMap::new(),
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

    /// Insert a cap as a blob keyed by `hash`. If the hash is already
    /// present, increment its refcount instead of allocating a fresh
    /// entry. Returns the post-insertion refcount.
    pub fn put_blob(&mut self, hash: CapHash, cap: Cap<A>) -> Result<u32, CacheError> {
        if let Some(existing) = self.blobs.get(&hash) {
            let prev = existing.refcount.fetch_add(1, Ordering::Relaxed);
            return Ok(prev + 1);
        }
        let entry = CacheEntry::new(cap);
        let boxed = ABox::try_new_in(entry, self.alloc.clone())
            .map_err(|_| CacheError::AllocFailure)?;
        self.blobs.insert(hash, boxed);
        Ok(1)
    }

    /// Insert a cap as a fresh mutable instance entry. Returns the
    /// allocated `CapRef`. Refcount starts at 1.
    pub fn put_instance(&mut self, cap: Cap<A>) -> Result<CapRef, CacheError> {
        let entry = CacheEntry::new(cap);
        let boxed = ABox::try_new_in(entry, self.alloc.clone())
            .map_err(|_| CacheError::AllocFailure)?;
        let r = self.next_ref;
        self.next_ref = self.next_ref.checked_add(1).expect("CapRef space exhausted");
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
                CapHashOrRef::Hash(h) => {
                    self.blobs.get(&h).ok_or(CacheError::BlobMissing)?
                }
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
                    self.next_ref =
                        self.next_ref.checked_add(1).expect("CapRef space exhausted");
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
    pub fn publish_data_inline(&mut self, bytes: &[u8]) -> Result<CapHash, CacheError> {
        let mut buf: AVec<u8, A> = AVec::with_capacity_in(bytes.len(), self.alloc.clone());
        buf.extend_from_slice(bytes);
        let cap = Cap::Data(DataCap {
            size: bytes.len() as u64,
            content: DataContent::Inline(buf),
        });
        let hash = cap_hash(&cap);
        self.put_blob(hash, cap)?;
        Ok(hash)
    }

    /// Publish a CNodeCap blob with the given size and populated
    /// slots. Each `(SlotIdx, CapHashOrRef)` target must already exist
    /// in the cache (either as a blob or an instance); on success the
    /// cache bumps each target's refcount to reflect the new cnode's
    /// reference.
    ///
    /// `entries` may be in any order; the cnode's internal slot table
    /// is sorted by slot index. Returns the cnode's hash.
    pub fn publish_cnode(
        &mut self,
        size_log: u8,
        entries: &[(SlotIdx, CapHashOrRef)],
    ) -> Result<CapHash, CacheError> {
        // Validate targets exist before allocating, so we can fail
        // fast without leaving partial state.
        for (_, target) in entries {
            match target {
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

        let mut slots: AVec<CNodeSlotEntry, A> =
            AVec::with_capacity_in(entries.len(), self.alloc.clone());
        for (slot, target) in entries {
            slots.push(CNodeSlotEntry {
                slot: *slot,
                target: *target,
            });
        }
        slots.sort_by_key(|e| e.slot);

        let cap = Cap::CNode(CNodeCap { size_log, slots });
        let hash = cap_hash(&cap);
        let post = self.put_blob(hash, cap)?;
        if post == 1 {
            // Fresh entry: this cnode now holds a reference to each
            // target; reflect that in their refcounts.
            for (_, target) in entries {
                self.incref(*target)?;
            }
        }
        Ok(hash)
    }

    /// Publish an InstanceCap blob. The `image_hash` blob and the
    /// `root_cnode` blob must already exist in the cache; both have
    /// their refcounts incremented on success.
    ///
    /// `rw_overlays` is given as `(start, bytes)` pairs; each is
    /// copied into the cache's allocator.
    #[allow(clippy::too_many_arguments)]
    pub fn publish_instance_blob(
        &mut self,
        image_hash_chain: CapHash,
        image_hash: CapHash,
        root_cnode: CapHash,
        rw_overlays: &[(u32, &[u8])],
        mem_size: u32,
        regs: [u64; NUM_REGS],
        pc: u64,
        gas_remaining: u64,
    ) -> Result<CapHash, CacheError> {
        // Validate referenced blobs exist before allocating.
        if !self.blobs.contains_key(&image_hash) {
            return Err(CacheError::BlobMissing);
        }
        if !self.blobs.contains_key(&root_cnode) {
            return Err(CacheError::BlobMissing);
        }

        let mut overlays: AVec<RwOverlay<A>, A> =
            AVec::with_capacity_in(rw_overlays.len(), self.alloc.clone());
        for (start, bytes) in rw_overlays {
            let mut buf: AVec<u8, A> = AVec::with_capacity_in(bytes.len(), self.alloc.clone());
            buf.extend_from_slice(bytes);
            overlays.push(RwOverlay {
                start: *start,
                bytes: buf,
            });
        }

        let cap = Cap::Instance(InstanceCap {
            image_hash_chain,
            image_hash,
            root_cnode: CapHashOrRef::Hash(root_cnode),
            rw_overlays: overlays,
            mem_size,
            regs,
            pc,
            gas_remaining,
        });
        let hash = cap_hash(&cap);
        let post = self.put_blob(hash, cap)?;
        if post == 1 {
            self.incref(CapHashOrRef::Hash(image_hash))?;
            self.incref(CapHashOrRef::Hash(root_cnode))?;
        }
        Ok(hash)
    }

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
    ///   identifier (callers can `put_blob`-snapshot externally if
    ///   they want to keep an immutable copy).
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
                for slot in cn.slots.iter() {
                    out.push(slot.target);
                }
            }
            Cap::Instance(inst) => {
                out.push(CapHashOrRef::Hash(inst.image_hash));
                out.push(inst.root_cnode);
            }
            Cap::Data(_) | Cap::Image(_) | Cap::Type(_) => {
                // DataCap pages are owned (via PageRef.refcount) and
                // not addressable through the Cache; ImageCap holds
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
            for slot in cn.slots.iter() {
                if let CapHashOrRef::Ref(r) = slot.target {
                    out.push(r);
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
    let lookup = |r: CapRef| -> Option<CapHash> {
        resolved.iter().find(|(k, _)| *k == r).map(|(_, h)| *h)
    };
    match cap {
        Cap::CNode(cn) => {
            for slot in cn.slots.iter_mut() {
                if let CapHashOrRef::Ref(r) = slot.target
                    && let Some(h) = lookup(r)
                {
                    slot.target = CapHashOrRef::Hash(h);
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

/// Shallow-clone a cap: duplicate the slot/page table allocations
/// only, sharing all targets. Targets' refcounts must be bumped by
/// the caller after this returns.
fn shallow_clone_cap<A: Allocator + Clone>(
    cap: &Cap<A>,
    alloc: A,
) -> Result<Cap<A>, CacheError> {
    match cap {
        Cap::CNode(cn) => {
            let mut slots: AVec<CNodeSlotEntry, A> =
                AVec::with_capacity_in(cn.slots.len(), alloc.clone());
            for slot in cn.slots.iter() {
                slots.push(*slot);
            }
            Ok(Cap::CNode(CNodeCap {
                size_log: cn.size_log,
                slots,
            }))
        }
        Cap::Data(d) => {
            let content = match &d.content {
                DataContent::Inline(bytes) => {
                    let mut new_bytes: AVec<u8, A> =
                        AVec::with_capacity_in(bytes.len(), alloc.clone());
                    new_bytes.extend_from_slice(bytes.as_slice());
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
            Ok(Cap::Data(DataCap {
                size: d.size,
                content,
            }))
        }
        Cap::Instance(inst) => {
            let mut new_overlays: AVec<RwOverlay<A>, A> =
                AVec::with_capacity_in(inst.rw_overlays.len(), alloc.clone());
            for o in inst.rw_overlays.iter() {
                let mut bytes: AVec<u8, A> =
                    AVec::with_capacity_in(o.bytes.len(), alloc.clone());
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
