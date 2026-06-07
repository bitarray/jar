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
//! Cap drops. Caps no longer hold `Ref(CapRef)` slot targets (a cnode
//! slot is a `Hash` or an inline `Owned` cap), so a drop never cascades
//! into other instance entries — the sweep is a single self-contained
//! pass per orphan. The loop is retained as a cheap fixed-point guard.
//!
//! The instances tier is currently **dormant**: the recompiler keeps
//! sub-VMs inline as `Owned` caps and never publishes a `CapRef`. The
//! tier (and `CapRef`) survive as the host-side key for the future
//! deferred-persist path.
//!
//! ## blob retention
//!
//! V0 blobs accumulate; the host pre-publishes every cap the invocation
//! needs and lookups never miss. Future design: missing-blob lookups
//! pause the kernel and ask the host to publish. Until that lands,
//! `get_blob` returning `None` is treated as a hard failure by the
//! caller.

use alloc::boxed::Box;
use alloc::sync::Arc;
use alloc::vec::Vec;
use core::hash::BuildHasher;

use hashbrown::{DefaultHashBuilder, HashMap};
use spin::Mutex;

use super::cap::image::ImageConvertError;
use super::cap::{Cap, CapHash};

/// Cache-local lifetime handle to a working `Cap::Instance` in
/// `CacheDirectory.instances`.
///
/// `Clone` bumps an inner `Arc` refcount; `Drop` decrements it. The
/// directory owns one `CapRef` per live entry alongside the data; when
/// external holders all drop their clones, [`CacheDirectory::sweep_instances`]
/// finds entries whose stored handle has `strong_count == 1` and removes
/// them. No callback-on-drop, no deadlock discipline.
///
/// Two separate `CacheDirectory` instances produce independent id
/// namespaces — `CapRef`s must not cross caches.
///
/// The constructor is module-private: every handle in production traces
/// back to [`CacheDirectory::put_instance`].
#[derive(Clone, Debug)]
pub struct CapRef {
    id: u64,
    /// Refcount tracker. The Arc's strong count is the number of
    /// live `CapRef` holders for this id (including the directory's
    /// own self-reference).
    rc: Arc<()>,
}

impl CapRef {
    fn new(id: u64) -> Self {
        Self {
            id,
            rc: Arc::new(()),
        }
    }

    /// The id this handle resolves to inside `CacheDirectory.instances`.
    pub fn id(&self) -> u64 {
        self.id
    }

    /// Number of live `CapRef` clones for this id, including the
    /// directory's own self-reference. `sweep_instances` reclaims
    /// entries whose stored handle has `strong_count == 1`.
    pub fn strong_count(&self) -> usize {
        Arc::strong_count(&self.rc)
    }
}

impl PartialEq for CapRef {
    fn eq(&self, other: &Self) -> bool {
        self.id == other.id
    }
}
impl Eq for CapRef {}

impl core::hash::Hash for CapRef {
    fn hash<H: core::hash::Hasher>(&self, state: &mut H) {
        self.id.hash(state)
    }
}

mod sealed {
    pub trait Sealed {}
    impl Sealed for alloc::boxed::Box<crate::cap::Cap> {}
}

/// Marker for `CapHashOrRef::Owned` payloads that participate in the
/// content-addressed **wire** form. Implemented only for `Box<Cap>` (the
/// default payload).
///
/// It is a deliberately *leaf* marker — implemented directly for
/// `Box<Cap>` with no supertrait that recurses into `Cap: Archive` — so
/// gating the wire impls (`HashTreeRoot` / `Encode` / `Decode` / rkyv
/// `Archive` / `Serialize`) of `CapHashOrRef<O>` on `O: WireOwned`
/// resolves by a single lookup, exactly as the original non-generic
/// impls did (which required nothing of the inline `Box<Cap>`). Gating on
/// `O: rkyv::Archive` instead would re-introduce the cyclic
/// `Box<Cap>: Archive → Cap: Archive` bound and overflow the solver.
///
/// Engine-private cache payloads (e.g. `Box<CachedCap>`) deliberately do
/// **not** implement it, so a cnode carrying one has no wire impl and
/// cannot be hashed or serialised — a compile error, strictly stronger
/// than the runtime `Owned` panic.
///
/// Sealed: only `javm-cap` implements it.
pub trait WireOwned: sealed::Sealed {}
impl WireOwned for Box<Cap> {}

/// Slot/field reference: a content-addressed blob in `cache.blobs`
/// (`Hash`), or a single-owner cap held **inline** by the running kernel
/// frame (`Owned`).
///
/// **`Owned(Box<Cap>)`** is the zero-copy ownership form: a cap the
/// kernel frame owns outright and moves between cnode slots (and between
/// frames, at HALT) with no cache round-trip and no data copy — the move
/// is a `Box` pointer swap. It is **runtime-only**: it never crosses the
/// wire and is never hashed. The recompiler mints it on `derive_spawn`
/// and moves it through `host_call`; it never `settle`s one (the
/// host-side `settle` arm folds it into a blob for the deferred persist
/// path).
///
/// **SSZ note**: `CapHashOrRef`'s `HashTreeRoot` impl is hand-rolled,
/// not derived. The pass-through semantics — `Hash(h)` hashes to `h` —
/// let a freshly-published cap substitute for a content reference without
/// changing the hash of any cap that holds it. The `Owned` arm panics:
/// callers must `settle` a cap graph before hashing it. `Encode` mirrors
/// `HashTreeRoot` (panic on the runtime-only arm); `Decode` only ever
/// produces `Hash` (the wire carries selector 0).
///
/// **Generic over the owned payload `O`** (default `Box<Cap>`). The wire
/// form (the cnode inside a serialised `Cap`) is always
/// `CapHashOrRef<Box<Cap>>`, so `Cap` and its hash are unaffected. An
/// engine may instantiate a *running frame's* cnode with a richer,
/// deliberately non-wire payload (e.g. `Box<CachedCap>`); the
/// serialisation impls below are gated on `O: rkyv::Archive`, so such a
/// payload makes the cnode non-hashable and non-serialisable at **compile
/// time** (a strictly stronger guarantee than the runtime `Owned` panic).
///
/// **Not `Copy`**: the `Owned(O)` arm carries the (usually heap-allocated)
/// payload, so the enum is `Clone`-only (when `O: Clone`).
///
/// **`PartialEq`/`Eq`/`Hash` are hand-written**: a `Box<Cap>` payload
/// blocks the derive (`Cap` is not `Eq`/`Hash`). The `Hash` arm
/// compares/hashes its 32-byte digest by value; the `Owned` arm uses
/// pointer identity of the inline payload (sound — the only holder,
/// `CNodeSlots = RadixMap<_, KEY_BYTES>`, keys by the 32-byte physical
/// key, never by value — and `O`-agnostic, so it needs no bound).
#[derive(Clone, Debug)]
pub enum CapHashOrRef<O = Box<Cap>> {
    Hash(CapHash),
    Owned(O),
}

impl<O> PartialEq for CapHashOrRef<O> {
    fn eq(&self, other: &Self) -> bool {
        match (self, other) {
            (CapHashOrRef::Hash(a), CapHashOrRef::Hash(b)) => a == b,
            // Owned is single-owner and never content-compared; pointer
            // identity of the inline payload is reflexive (Eq-sound) and
            // consistent with the pointer-keyed `Hash` impl below.
            (CapHashOrRef::Owned(a), CapHashOrRef::Owned(b)) => core::ptr::eq(a, b),
            _ => false,
        }
    }
}
impl<O> Eq for CapHashOrRef<O> {}

impl<O> core::hash::Hash for CapHashOrRef<O> {
    fn hash<H: core::hash::Hasher>(&self, state: &mut H) {
        match self {
            CapHashOrRef::Hash(h) => {
                0u8.hash(state);
                h.hash(state);
            }
            CapHashOrRef::Owned(o) => {
                1u8.hash(state);
                (o as *const O).hash(state);
            }
        }
    }
}

// Gated on `O: WireOwned` — the wire-payload marker. `Box<Cap>` (the
// content-addressed default) implements it; a non-wire payload such as
// `Box<CachedCap>` does not, so a cache-carrying cnode has no `HashTreeRoot`
// impl and cannot be content-hashed (a compile error, not a runtime panic).
impl<O: WireOwned> ssz::HashTreeRoot for CapHashOrRef<O> {
    fn hash_tree_root<D: ::ssz::digest::Digest<OutputSize = ::ssz::digest::typenum::U32>>(
        &self,
    ) -> [u8; 32] {
        match self {
            CapHashOrRef::Hash(h) => *h,
            CapHashOrRef::Owned(_) => {
                panic!("cap_hash: in-flight Owned cap in cap graph; settle first")
            }
        }
    }
}

impl<O: WireOwned> ssz::Encode for CapHashOrRef<O> {
    fn is_ssz_fixed_len() -> bool {
        false
    }
    fn ssz_fixed_len() -> usize {
        ssz::BYTES_PER_LENGTH_OFFSET
    }
    fn ssz_bytes_len(&self) -> usize {
        match self {
            CapHashOrRef::Hash(_) => 1 + 32,
            // Owned must be settled before serialisation; matches the
            // `HashTreeRoot` contract above. Reached only by buggy code.
            CapHashOrRef::Owned(_) => {
                panic!("ssz_bytes_len: in-flight Owned cap in cap graph; settle first")
            }
        }
    }
    fn ssz_append(&self, buf: &mut Vec<u8>) {
        match self {
            CapHashOrRef::Hash(h) => {
                buf.push(0);
                buf.extend_from_slice(h);
            }
            CapHashOrRef::Owned(_) => {
                panic!("ssz_append: in-flight Owned cap in cap graph; settle first")
            }
        }
    }
}

impl<O: WireOwned> ssz::Decode for CapHashOrRef<O> {
    fn is_ssz_fixed_len() -> bool {
        false
    }
    fn ssz_fixed_len() -> usize {
        ssz::BYTES_PER_LENGTH_OFFSET
    }
    fn from_ssz_bytes(bytes: &[u8]) -> Result<Self, ssz::DecodeError> {
        if bytes.is_empty() {
            return Err(ssz::DecodeError::UnexpectedEof {
                expected: 1,
                actual: 0,
            });
        }
        match bytes[0] {
            0 => {
                if bytes.len() != 1 + 32 {
                    return Err(ssz::DecodeError::UnexpectedEof {
                        expected: 1 + 32,
                        actual: bytes.len(),
                    });
                }
                let mut h = [0u8; 32];
                h.copy_from_slice(&bytes[1..1 + 32]);
                Ok(CapHashOrRef::Hash(h))
            }
            // Selector 0 (`Hash`) is the only wire form; `Owned` is
            // runtime-only and never serialises, so any other selector is
            // invalid wire bytes.
            v => Err(ssz::DecodeError::InvalidSelector(v)),
        }
    }
}

// --- rkyv: hand-rolled. ---
//
// `CapHashOrRef`'s archived form is the same as `CapHash`'s — a plain
// 32-byte digest. Serialize errors out on `Ref` (cache-local lifetime
// handles have no wire form); resolve panics defensively for the path
// where someone hand-built a Resolver and called resolve without going
// through Serialize. Deserialize always produces `Hash` because the
// archived form structurally can't carry a `Ref`.

/// Error returned by `<CapHashOrRef as rkyv::Serialize<_>>::serialize`
/// when the cap graph still holds a runtime-only target — a
/// [`CapHashOrRef::Owned`]. Callers must `settle` (or otherwise rewrite
/// the target to a hash) before rkyv-encoding the cap.
#[derive(Debug)]
pub struct CapHasRefError;

impl core::fmt::Display for CapHasRefError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str(
            "cap holds a runtime-only CapHashOrRef::Owned target; settle before rkyv encode",
        )
    }
}

impl core::error::Error for CapHasRefError {}

impl<O: WireOwned> rkyv::Archive for CapHashOrRef<O> {
    type Archived = <CapHash as rkyv::Archive>::Archived;
    type Resolver = <CapHash as rkyv::Archive>::Resolver;

    fn resolve(&self, resolver: Self::Resolver, out: rkyv::Place<Self::Archived>) {
        match self {
            CapHashOrRef::Hash(h) => <CapHash as rkyv::Archive>::resolve(h, resolver, out),
            // Unreachable if Serialize was called first (it errors on the
            // runtime-only arm). Defensive panic for the "hand-built
            // resolver" path.
            CapHashOrRef::Owned(_) => {
                panic!(
                    "CapHashOrRef::Owned in archive resolve; Serialize should have rejected first"
                )
            }
        }
    }
}

impl<O, S> rkyv::Serialize<S> for CapHashOrRef<O>
where
    O: WireOwned,
    S: rkyv::rancor::Fallible + ?Sized,
    <S as rkyv::rancor::Fallible>::Error: rkyv::rancor::Source,
    CapHash: rkyv::Serialize<S>,
{
    fn serialize(
        &self,
        serializer: &mut S,
    ) -> Result<Self::Resolver, <S as rkyv::rancor::Fallible>::Error> {
        match self {
            CapHashOrRef::Hash(h) => <CapHash as rkyv::Serialize<S>>::serialize(h, serializer),
            CapHashOrRef::Owned(_) => Err(rkyv::rancor::Source::new(CapHasRefError)),
        }
    }
}

// Use the concrete archived type `[u8; 32]` rather than
// `<CapHash as Archive>::Archived` to avoid a coherence-checker false
// conflict with rkyv's blanket `Deserialize for With<F, W>` impl
// (associated-type opacity).
impl<O, D> rkyv::Deserialize<CapHashOrRef<O>, D> for [u8; 32]
where
    D: rkyv::rancor::Fallible + ?Sized,
{
    fn deserialize(
        &self,
        _deserializer: &mut D,
    ) -> Result<CapHashOrRef<O>, <D as rkyv::rancor::Fallible>::Error> {
        Ok(CapHashOrRef::Hash(*self))
    }
}

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
            // `Owned` lives inline on the kernel frame, not in the
            // directory; the holder dereferences the `Box` directly.
            CapHashOrRef::Owned(_) => None,
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

    /// Settle an inline `Owned` cap to a content hash: recursively rewrite
    /// its nested `Owned` slot targets to `Hash`, flush a dirty `Data` cap's
    /// CoW overlay, content-address it into `blobs`, and return the hash.
    ///
    /// For `Hash`-keyed input, returns it unchanged.
    pub fn settle(&self, key: CapHashOrRef) -> Result<CapHash, CacheError> {
        match key {
            CapHashOrRef::Hash(h) => Ok(h),
            CapHashOrRef::Owned(b) => self.settle_owned(*b),
        }
    }

    /// Settle an inline `Owned` cap: recursively rewrite its nested slot
    /// targets (`Owned`) to `Hash`, flush a `Data` cap's CoW overlay so it
    /// is hashable, then content-address it into `blobs` and return the
    /// hash.
    ///
    /// The recompiler never calls this — it *moves* `Owned` caps and
    /// drops them at frame pop. It exists for the host-side deferred
    /// persist path (turn a finished frame's owned cap into a blob).
    fn settle_owned(&self, mut cap: Cap) -> Result<CapHash, CacheError> {
        // 1. Settle every nested slot target to a Hash, in place.
        self.settle_targets_in(&mut cap)?;
        // 2. Hashing requires an empty overlay; fold a dirty Data cap.
        if let Cap::Data(d) = &cap
            && !d.overlay.is_empty()
        {
            cap = Cap::Data(d.flush());
        }
        // 3. Content-address into blobs.
        let hash = cap.cap_hash();
        self.put_cap_with_hash(hash, &cap)?;
        Ok(hash)
    }

    /// Rewrite every direct slot target of `cap` (CNode slots, Instance
    /// `root_cnode`) from a runtime-only `Owned` to its settled `Hash`,
    /// recursing into nested `Owned` caps.
    fn settle_targets_in(&self, cap: &mut Cap) -> Result<(), CacheError> {
        match cap {
            Cap::CNode(cn) => {
                for (_, mo) in cn.slots.iter_mut() {
                    if let ssz::MissingOr::Materialized(t) = mo {
                        self.settle_target(t)?;
                    }
                }
            }
            Cap::Instance(inst) => self.settle_target(&mut inst.root_cnode)?,
            Cap::Data(_) | Cap::Image(_) => {}
        }
        Ok(())
    }

    /// Settle one slot target in place: `Hash` unchanged, `Owned`
    /// recursively via [`Self::settle_owned`].
    fn settle_target(&self, t: &mut CapHashOrRef) -> Result<(), CacheError> {
        match t {
            CapHashOrRef::Hash(_) => Ok(()),
            CapHashOrRef::Owned(_) => {
                let CapHashOrRef::Owned(b) = core::mem::replace(t, CapHashOrRef::Hash([0u8; 32]))
                else {
                    unreachable!("matched Owned above")
                };
                let h = self.settle_owned(*b)?;
                *t = CapHashOrRef::Hash(h);
                Ok(())
            }
        }
    }
}
