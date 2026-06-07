//! `CachedCap` — a cap plus its engine-private derived runtime cache.
//!
//! A resident sub-VM instance owns its memory (the overlay `Arc` pages) for as
//! long as it lives in a frame's cnode; its ring-3 page table
//! ([`FrameRuntime`]) stays valid for exactly that lifetime. So the page-table
//! cache belongs **with the cap**: `cache lifetime == cap lifetime`. A running
//! frame's cnode is a [`CNodeCap<Box<CachedCap>>`](javm_cap::CNodeCap), and a
//! `derive_spawn`'d instance lives in it as `CapHashOrRef::Owned(Box<CachedCap>)`
//! — its parked page table riding in [`CapCache`], dropped automatically when
//! the slot is overwritten or the frame pops. This replaces the parent-side
//! `child_runtimes` side-table: no slot-keying, no manual `derive_spawn`
//! invalidation, no per-frame `BTreeMap` allocation, and the cache follows the
//! instance through any future move (return-as-value, yield/resume).
//!
//! `CachedCap` has **no** rkyv/ssz impl. Because the wire impls of
//! [`CapHashOrRef`](javm_cap::CapHashOrRef) are gated on the
//! [`WireOwned`](javm_cap::cache::WireOwned) leaf marker (implemented only for
//! `Box<Cap>`), a `CNodeCap<Box<CachedCap>>` cannot be content-hashed or
//! serialised — a **compile error**, strictly stronger than the runtime
//! `Owned` panic. The cache is, by construction, guest-local.

use alloc::boxed::Box;

use javm_cap::cap::Cap;
use javm_cap::cap::instance::InstanceCap;
use javm_cap::{CNodeCap, ResidentCap};
use spin::Mutex as SpinMutex;

use crate::jit_cache::CompiledImage;
use crate::jit_run::FrameRuntime;

pub type ResidentCNode = CNodeCap<Box<CachedCap>>;
pub type ResidentInstance = InstanceCap<Box<CachedCap>>;

/// A cap paired with the derived runtime cache that rides with it inside a
/// running frame's cnode (`CapHashOrRef::Owned(Box<CachedCap>)`).
///
/// **`Clone` drops the cache.** A clone is a *distinct* instance (its own
/// memory after the next CoW), so it must start with a fresh, empty cache;
/// [`FrameRuntime`] is non-`Clone` anyway. The recompiler's cnode-inherit loop
/// already skips `Owned` slots (single-owner, move-only), so a clone of a
/// cache-carrying cnode never actually happens in the hot path — the impl
/// exists only to satisfy the `CNodeCap<O>: Clone` bound (which clones `Hash`
/// entries).
pub struct CachedCap {
    /// The underlying cap (an `Instance` for a resident sub-VM; any cap for a
    /// moved scratchpad slot).
    pub cap: Cap,
    /// The engine-private derived cache attached to this cap.
    pub cache: SpinMutex<CapCache>,
}

/// SAFETY: Hyperlight serialises guest execution and RPCs; these resident
/// caches never move across concurrently-running threads. The impl only lets
/// them live behind the static directory mutex.
unsafe impl Send for CachedCap {}
/// SAFETY: same single-threaded guest invariant as the `Send` impl above.
unsafe impl Sync for CachedCap {}

/// The derived runtime cache attached to a resident cap. `None` for a cap with
/// no cached runtime (freshly spawned, or a non-instance scratchpad cap).
#[derive(Default)]
pub enum CapCache {
    /// No cached runtime.
    #[default]
    None,
    /// A resident CNode's cache-carrying sparse slot map. The `cap` field keeps
    /// the public wire shape; this variant is authoritative while the CNode is
    /// resident in the guest.
    CNode(Box<ResidentCNode>),
    /// A published Image's compiled code arena and page-table template.
    Image(Box<CompiledImage>),
    /// A resident sub-VM instance's ring-3 page table, parked (re-armed for
    /// CoW) between CALLs so the next CALL of this same instance reuses the
    /// whole page table instead of rebuilding it.
    Instance(FrameRuntime),
}

impl CachedCap {
    /// Wrap a cap with an empty cache (a freshly `derive_spawn`'d instance, or
    /// a moved scratchpad cap).
    pub fn new(cap: Cap) -> Self {
        Self {
            cap,
            cache: SpinMutex::new(CapCache::None),
        }
    }

    /// Wrap a CNode with a resident cache-carrying slot map.
    pub fn cnode(cnode: ResidentCNode) -> Self {
        Self {
            cap: Cap::empty_cnode(),
            cache: SpinMutex::new(CapCache::CNode(Box::new(cnode))),
        }
    }

    /// Box a cap with an empty cache, ready to drop into a cnode slot as
    /// `CapHashOrRef::Owned`.
    pub fn boxed(cap: Cap) -> Box<Self> {
        Box::new(Self::new(cap))
    }

    /// Box a resident CNode, ready for an Instance's live `root_cnode`.
    pub fn boxed_cnode(cnode: ResidentCNode) -> Box<Self> {
        Box::new(Self::cnode(cnode))
    }
}

impl Clone for CachedCap {
    fn clone(&self) -> Self {
        // A clone is a distinct instance → fresh, empty cache.
        Self {
            cap: self.cap.clone(),
            cache: SpinMutex::new(CapCache::None),
        }
    }
}

impl ResidentCap for CachedCap {
    fn from_cap(cap: Cap) -> Self {
        Self::new(cap)
    }

    fn as_cap(&self) -> &Cap {
        &self.cap
    }

    fn into_cap(self) -> Cap {
        self.cap
    }
}

impl core::fmt::Debug for CachedCap {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        // `FrameRuntime` / `CompiledImage` are not `Debug`; report only the
        // cache variant.
        let cache = match &*self.cache.lock() {
            CapCache::None => "None",
            CapCache::CNode(_) => "CNode",
            CapCache::Image(_) => "Image",
            CapCache::Instance(_) => "Instance",
        };
        f.debug_struct("CachedCap")
            .field("cap", &self.cap)
            .field("cache", &cache)
            .finish()
    }
}
