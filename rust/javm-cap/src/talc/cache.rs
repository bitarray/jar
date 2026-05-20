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

use super::cap::{Cap, CapHash, CapHashOrRef, CapRef};
use super::cnode::{CNodeCap, CNodeSlotEntry};
use super::data::{DataCap, DataContent};
use super::entry::CacheEntry;
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
