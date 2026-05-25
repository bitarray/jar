//! `CacheDirectory<S>` — two-tier cap store.
//!
//! - **`blobs: HashMap<CapHash, Arc<Cap>>`** — content-addressed
//!   immutable caps. Pure cache: the host populates it; the kernel
//!   reads. If a lookup misses, the host hasn't published the cap yet.
//!
//! - **`instances: HashMap<u64, (CapRef, Arc<Cap>)>`** — identity-keyed
//!   mutable working state. The stored `CapRef` is the directory's
//!   self-reference; its `Arc::strong_count` is the number of live
//!   external holders + 1.
//!
//! Two callers exist: the Nub local backend (host's `Global`) and the
//! Nub Hyperlight backend (guest's `Global` via talc). Both wrap
//! `CacheDirectory<S>` in their own static / field; the directory's
//! interior is `spin::Mutex`-protected so every public method takes
//! `&self`.
//!
//! ## Cow + lazy promote
//!
//! Promotion (blob → instance) is a cheap `Arc::clone`:
//!
//! ```ignore
//! let arc = blobs[&hash].clone();        // RC bump; no Cap copy.
//! let id = self.next_ref;
//! self.next_ref += 1;
//! let capref = CapRef::new(id);
//! instances.insert(id, (capref.clone(), arc));   // RC bump on capref.
//! capref
//! ```
//!
//! Mutation uses `Arc::make_mut`:
//!
//! ```ignore
//! let mut arc = cache.get_instance(&capref).unwrap();
//! let cap_mut = Arc::make_mut(&mut arc);   // clones iff strong > 1.
//! // ... mutate cap_mut ...
//! cache.set_instance(&capref, arc);
//! ```
//!
//! `Arc::make_mut` subsumes the legacy "sole-owner move-promote vs
//! shared shallow-clone" branch — same decision, in fewer lines.
//!
//! ## GC sweep
//!
//! `sweep_instances` reclaims entries whose stored `CapRef.strong_count`
//! is 1 (i.e., the directory is the sole holder). Removal drops the
//! entry's `Arc<Cap>`; if that was the last strong ref to the Cap, the
//! Cap drops; the Cap's `Ref(CapRef)` slot values drop too, decrementing
//! more entries' refcounts. The sweep loops until a pass finds nothing.
//!
//! Cycles are structurally impossible (data-flow principle:
//! `website/content/spec/discussions/data-flow-principle.md`), so the
//! sweep is guaranteed to make forward progress.
//!
//! ## blob retention
//!
//! V0 blobs accumulate; the host pre-publishes every cap the invocation
//! needs and lookups never miss. Future design: missing-blob lookups
//! pause the kernel and ask the host to publish. Until that lands,
//! `get_blob` returning `None` is treated as a hard failure by the
//! caller.

use alloc::sync::Arc;
use alloc::vec::Vec;
use core::hash::BuildHasher;

use hashbrown::{DefaultHashBuilder, HashMap};
use spin::Mutex;

use super::cap::{Cap, CapHash, CapHashOrRef, CapRef};
use super::image_cap::ImageConvertError;

#[derive(Debug, thiserror::Error)]
pub enum CacheError {
    #[error("blob not found for hash")]
    BlobMissing,
    #[error("instance not found for ref {0}")]
    InstanceMissing(u64),
    #[error("image conversion failed: {0}")]
    ImageConvertFailed(#[from] ImageConvertError),
    #[error("paged data: page length mismatch (expected={expected}, got={got})")]
    PageSizeMismatch { expected: u32, got: usize },
    #[error("cnode slot index out of range")]
    SlotOutOfRange,
}

pub struct CacheDirectory<S = DefaultHashBuilder> {
    inner: Mutex<DirectoryInner<S>>,
}

struct DirectoryInner<S> {
    blobs: HashMap<CapHash, Arc<Cap>, S>,
    instances: HashMap<u64, (CapRef, Arc<Cap>), S>,
    next_ref: u64,
}

impl CacheDirectory<DefaultHashBuilder> {
    /// Construct an empty cache using the default per-process-randomized
    /// hasher.
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
            inner: Mutex::new(DirectoryInner {
                blobs: HashMap::with_hasher(hasher.clone()),
                instances: HashMap::with_hasher(hasher),
                // CapRef id 0 is reserved; ids start at 1.
                next_ref: 1,
            }),
        }
    }
}

impl<S> CacheDirectory<S> {
    /// `const fn` constructor for static initialisation. Used by the
    /// guest's `state_cache::CACHE` static. Takes both hashers
    /// separately because `const fn` can't call `S::clone()` and not
    /// every `BuildHasher` (notably `foldhash::fast::FixedState`)
    /// implements `Copy`. Callers normally pass two identically-seeded
    /// instances so both maps hash to the same buckets.
    pub const fn new_const(blobs_hasher: S, instances_hasher: S) -> Self {
        Self {
            inner: Mutex::new(DirectoryInner {
                blobs: HashMap::with_hasher(blobs_hasher),
                instances: HashMap::with_hasher(instances_hasher),
                next_ref: 1,
            }),
        }
    }
}

impl<S: BuildHasher> CacheDirectory<S> {
    /// Number of blob entries.
    pub fn blob_count(&self) -> usize {
        self.inner.lock().blobs.len()
    }
    /// Number of instance entries (live or unswept).
    pub fn instance_count(&self) -> usize {
        self.inner.lock().instances.len()
    }

    /// Whether the blobs tier holds an entry under `hash`.
    pub fn contains_blob(&self, hash: &CapHash) -> bool {
        self.inner.lock().blobs.contains_key(hash)
    }

    /// Get an `Arc::clone` of the blob cap at `hash`, or `None` if
    /// absent.
    pub fn get_blob(&self, hash: &CapHash) -> Option<Arc<Cap>> {
        self.inner.lock().blobs.get(hash).cloned()
    }

    /// Get an `Arc::clone` of the instance cap at `capref`, or `None`
    /// if absent.
    pub fn get_instance(&self, capref: &CapRef) -> Option<Arc<Cap>> {
        self.inner
            .lock()
            .instances
            .get(&capref.id())
            .map(|(_, arc)| arc.clone())
    }

    /// Snapshot the blob tier into a `Vec<(CapHash, Arc<Cap>)>`. Order
    /// is unspecified (HashMap iteration); callers that need
    /// deterministic order (state-root computations) sort by hash.
    pub fn iter_blobs(&self) -> Vec<(CapHash, Arc<Cap>)> {
        self.inner
            .lock()
            .blobs
            .iter()
            .map(|(h, arc)| (*h, arc.clone()))
            .collect()
    }

    /// Polymorphic lookup that dispatches on the `CapHashOrRef` arm.
    /// Returns an `Arc::clone` of the matching cap.
    pub fn get(&self, key: CapHashOrRef) -> Option<Arc<Cap>> {
        match key {
            CapHashOrRef::Hash(h) => self.get_blob(&h),
            CapHashOrRef::Ref(r) => self.get_instance(&r),
        }
    }

    /// Replace the instance at `capref` with a fresh `Arc<Cap>`. The
    /// old `Arc<Cap>` drops outside the lock (so any cascading
    /// `Cap::drop → CapRef::drop` chain doesn't try to re-enter the
    /// directory while we hold the guard).
    pub fn set_instance(&self, capref: &CapRef, new_arc: Arc<Cap>) -> Result<(), CacheError> {
        let _old = {
            let mut g = self.inner.lock();
            let entry = g
                .instances
                .get_mut(&capref.id())
                .ok_or_else(|| CacheError::InstanceMissing(capref.id()))?;
            // Swap in the new Arc, keeping the existing self-ref CapRef.
            // The old Arc<Cap> is returned and dropped after the lock guard.
            core::mem::replace(&mut entry.1, new_arc)
        };
        Ok(())
    }

    /// Hash + insert into blobs. Idempotent: re-puts of identical
    /// content are a no-op. Returns the content hash.
    pub fn put_cap(&self, cap: &Cap) -> Result<CapHash, CacheError> {
        let hash = cap.cap_hash();
        self.put_cap_with_hash(hash, cap)?;
        Ok(hash)
    }

    /// Pre-hashed insert. Debug-asserts the claimed hash matches the
    /// cap; release trusts the caller (the SSZ merkleize is the hot
    /// cost on the publish path).
    pub fn put_cap_with_hash(&self, hash: CapHash, cap: &Cap) -> Result<(), CacheError> {
        debug_assert_eq!(
            cap.cap_hash(),
            hash,
            "put_cap_with_hash: claimed hash does not match cap content",
        );
        let mut g = self.inner.lock();
        g.blobs.entry(hash).or_insert_with(|| Arc::new(cap.clone()));
        Ok(())
    }

    /// Insert a freshly-built `Cap` as a new instance entry. Returns
    /// the `CapRef` handle. The directory keeps its own clone of the
    /// returned handle internally as the entry's self-reference; when
    /// all external clones drop, `sweep_instances` will reclaim the
    /// entry.
    pub fn put_instance(&self, cap: Cap) -> CapRef {
        self.put_instance_arc(Arc::new(cap))
    }

    /// `put_instance` variant that takes a pre-built `Arc<Cap>`. Used
    /// internally by [`Self::promote_blob_to_instance`] to share the
    /// blob's Arc rather than deep-copying.
    fn put_instance_arc(&self, arc: Arc<Cap>) -> CapRef {
        let mut g = self.inner.lock();
        let id = g.next_ref;
        g.next_ref = g.next_ref.checked_add(1).expect("CapRef space exhausted");
        let capref = CapRef::new(id);
        g.instances.insert(id, (capref.clone(), arc));
        capref
    }

    /// Lazily promote a blob to a fresh instance entry. The blob and
    /// the new instance entry share the same `Arc<Cap>` (no Cap
    /// data deep-copy); the next `Arc::make_mut` call on either side
    /// clones-on-write if both still hold the Arc.
    ///
    /// Returns `None` if the blob isn't published.
    pub fn promote_blob_to_instance(&self, hash: &CapHash) -> Option<CapRef> {
        let arc = self.get_blob(hash)?;
        Some(self.put_instance_arc(arc))
    }

    /// **GC pass.** Walk the instances tier and remove every entry
    /// whose stored `CapRef` has `strong_count == 1` (the directory is
    /// the sole holder — no external `CapRef` clone exists). Loop
    /// until a pass finds nothing to remove, so cascading drops can
    /// orphan more entries which then get reclaimed in the next
    /// iteration.
    ///
    /// Cycles are structurally impossible (data-flow principle), so
    /// the loop is guaranteed to terminate.
    pub fn sweep_instances(&self) {
        loop {
            let dead: Vec<u64> = {
                let g = self.inner.lock();
                g.instances
                    .iter()
                    .filter(|(_, (sr, _))| sr.strong_count() == 1)
                    .map(|(k, _)| *k)
                    .collect()
            };
            if dead.is_empty() {
                break;
            }
            for id in dead {
                let _removed = {
                    let mut g = self.inner.lock();
                    g.instances.remove(&id)
                };
                // _removed drops here, outside the lock. If its
                // Arc<Cap> was the last strong ref, Cap::drop runs and
                // cascades: nested CapRef::drop calls decrement other
                // entries' refcounts. Those entries get reclaimed on
                // the next pass.
            }
        }
    }

    /// Settle a `Ref`-keyed working entry: walk nested `Ref` targets,
    /// resolve each to a `Hash`, then hash the surviving cap. Non-
    /// Instance entries (Data / CNode) graduate from `instances` to
    /// `blobs` under the computed hash; Instance entries stay in
    /// instances (they're the live mutable state) and the returned
    /// hash is a snapshot identifier.
    ///
    /// For `Hash`-keyed input, returns it unchanged.
    pub fn settle(&self, key: CapHashOrRef) -> Result<CapHash, CacheError> {
        match key {
            CapHashOrRef::Hash(h) => Ok(h),
            CapHashOrRef::Ref(r) => self.settle_ref(&r),
        }
    }

    fn settle_ref(&self, capref: &CapRef) -> Result<CapHash, CacheError> {
        // Step 1: settle any nested Refs the cap holds, rewriting
        // them to Hash in place.
        loop {
            // Pull the cap out as an owned Arc<Cap> so we can read it
            // outside the lock.
            let arc = self
                .get_instance(capref)
                .ok_or_else(|| CacheError::InstanceMissing(capref.id()))?;
            let nested = collect_ref_targets(&arc);
            if nested.is_empty() {
                break;
            }
            // Settle each nested ref. settle_ref recurses cleanly
            // because nested refs are strictly downstream (data-flow
            // principle).
            let mut resolved: Vec<(CapRef, CapHash)> = Vec::with_capacity(nested.len());
            for n in &nested {
                let h = self.settle_ref(n)?;
                resolved.push((n.clone(), h));
            }
            // Mutate the cap to rewrite the nested Refs to Hash. Need
            // exclusive access to the Arc<Cap>; use Arc::make_mut on a
            // fresh clone so the change is visible to other holders of
            // the same id by replacing the directory's stored Arc.
            let mut new_arc = arc.clone();
            rewrite_ref_targets(Arc::make_mut(&mut new_arc), &resolved);
            self.set_instance(capref, new_arc)?;
        }

        // Step 2: hash the (now Ref-free) cap.
        let arc = self
            .get_instance(capref)
            .ok_or_else(|| CacheError::InstanceMissing(capref.id()))?;
        let hash = arc.cap_hash();

        // Step 3: graduate non-Instance entries to blobs. Instance
        // entries stay in instances (the snapshot hash is returned but
        // the live cell isn't removed — the kernel may keep mutating).
        let is_instance = matches!(&*arc, Cap::Instance(_));
        if !is_instance {
            // Insert into blobs if not already present; idempotent.
            self.put_cap_with_hash(hash, &arc)?;
            // Remove the instances entry. The local `capref`
            // parameter still has one strong ref to it (the caller's);
            // removing the directory's stored self-ref drops the
            // entry's `Arc<Cap>` (one of two strong refs — the other
            // is the local `arc` we're still holding). The cap data
            // stays alive in `blobs` via the put_cap_with_hash above.
            let _removed = {
                let mut g = self.inner.lock();
                g.instances.remove(&capref.id())
            };
            drop(_removed);
            drop(arc);
        }
        Ok(hash)
    }
}

// --- Helpers (free functions) ---

/// Collect the directly-referenced `CapRef`s held by `cap`. Used by
/// `settle` to know which sub-refs to resolve before hashing.
fn collect_ref_targets(cap: &Cap) -> Vec<CapRef> {
    let mut out: Vec<CapRef> = Vec::new();
    match cap {
        Cap::CNode(cn) => {
            for (_, mo) in cn.slots.iter() {
                if let ssz::MissingOr::Materialized(CapHashOrRef::Ref(r)) = mo {
                    out.push(r.clone());
                }
            }
        }
        Cap::Instance(inst) => {
            if let CapHashOrRef::Ref(r) = &inst.root_cnode {
                out.push(r.clone());
            }
        }
        Cap::Data(_) | Cap::Image(_) | Cap::Type(_) => {}
    }
    out
}

/// Rewrite `cap`'s direct `CapHashOrRef::Ref(r)` targets to
/// `CapHashOrRef::Hash(h)` according to the `(r, h)` mapping in
/// `resolved`. Matches CapRef by id.
fn rewrite_ref_targets(cap: &mut Cap, resolved: &[(CapRef, CapHash)]) {
    let lookup = |r: &CapRef| -> Option<CapHash> {
        resolved
            .iter()
            .find(|(k, _)| k.id() == r.id())
            .map(|(_, h)| *h)
    };
    match cap {
        Cap::CNode(cn) => {
            for (_, mo) in cn.slots.iter_mut() {
                if let ssz::MissingOr::Materialized(t) = mo
                    && let CapHashOrRef::Ref(r) = t
                    && let Some(h) = lookup(r)
                {
                    *t = CapHashOrRef::Hash(h);
                }
            }
        }
        Cap::Instance(inst) => {
            if let CapHashOrRef::Ref(r) = &inst.root_cnode
                && let Some(h) = lookup(r)
            {
                inst.root_cnode = CapHashOrRef::Hash(h);
            }
        }
        Cap::Data(_) | Cap::Image(_) | Cap::Type(_) => {}
    }
}
