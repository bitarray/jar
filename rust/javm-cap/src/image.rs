//! Image: the smallest unit of program specification.
//!
//! An `Image` is content-addressed (its `image_id` is the hash of
//! its serialized content). An Instance's `image_hash` is the
//! cumulative chain hash tracking the lineage of `set_image` /
//! `host_derive_spawn` extensions from genesis.
//!
//! ```text
//! genesis (host_derive_spawn from no source):
//!     image_hash = hash(image)
//!
//! after set_image(new):
//!     image_hash = hash(prev_chain || hash(new))
//!
//! after host_derive_spawn(new, cnode) by a spawner:
//!     spawned.image_hash = hash(spawner.image_hash || hash(new))
//!
//! after MGMT_COPY of a Cap::Instance:
//!     copy.image_hash = source.image_hash   (preserved)
//! ```
//!
//! This module provides the pure data structures + the chain-hash
//! computations. Image *content hashing* is done by serializing the
//! Image canonically and feeding the bytes to `H::hash`; we provide
//! a simple deterministic encoder here so the v3 implementation
//! has one canonical form.

use crate::hash::Hash;
use crate::slot::Key;
use alloc::collections::BTreeMap;
use alloc::vec::Vec;
use ssz_derive::{Decode, Encode};

/// Image: the program spec (code, endpoints, memory layout, slot
/// declarations, pinned ro caps).
///
/// `pinned_slots` and `yield_receiver_slot` reference cnode slots; the
/// kernel installs declared pinned content into the Instance's cnode
/// at `set_image` / `host_derive_spawn` time and treats them as
/// read-only thereafter.
///
/// **Validation model.** This is the untrusted SSZ wire form; converting
/// it to a [`crate::cap::image::ImageCap`] via
/// [`crate::cap::image::image_cap`] is the "deblob" that validates the
/// Image's *structure* eagerly (sizes, bounds, slot indices, path depth).
/// The `code` *bytes* are never screened — instruction *semantics* are
/// validated lazily, at execution. See [`crate::cap::image::ImageCap`] for
/// the full structure-eager / semantics-lazy rationale.
#[derive(Debug, Clone, PartialEq, Eq, Encode, Decode, ssz_derive::HashTreeRoot)]
pub struct Image {
    /// The (single) code region: raw RV+C+custom-0 bytes. Mapped RO at
    /// the fixed protocol constant [`crate::layout::CODE_BASE`] (PC =
    /// `CODE_BASE + byte_offset`) — the load address is *not* chosen by
    /// the Image, so an untrusted Image cannot place code arbitrarily.
    /// Code is mapped RO into the guest address space so the guest can
    /// read its own bytes (AUIPC+load PIC); the JIT executes the native
    /// translation. Empty for codeless images (kernel placeholders).
    pub code: CodeRef,
    /// Endpoints addressable by a [`Key`] selector (the same byte-string key
    /// type as a cnode slot; in the V1 single-byte ABI the selector is one
    /// byte). Sparse — only declared endpoints are present, with no fixed
    /// capacity. An absent key is an undefined endpoint.
    pub endpoints: BTreeMap<Key, EndpointDef>,
    /// Memory layout. Each entry maps a `Cap::Data` (resolved through
    /// the `source` slot path) into the address space at `[start, start
    /// + size)`. RO vs RW is derived from whether the target slot
    /// appears in `pinned_slots`. Code is mapped separately at
    /// [`crate::layout::CODE_BASE`] and is not described here.
    pub memory_mappings: Vec<MemoryMapping>,
    /// Pinned read-only caps (Cap::Data or Cap::Image) baked into
    /// the spec. The kernel rejects mutations to these slots.
    pub pinned_slots: BTreeMap<Key, PinnedCap>,
    /// Initial cnode state for non-pinned mutable slots. Only
    /// honored at standalone (root) Instance bootstrap — a
    /// parented Instance receives its cnode from the spawner.
    pub initial_slots: BTreeMap<Key, InitialDataCap>,
    /// Slot holding `Cap::Instance[YieldReceiver]` — the set of yield_keys this
    /// Instance catches. The kernel snapshots it at each downward CALL and
    /// consults the snapshot when routing a yield. None = catches no yields.
    pub yield_receiver_slot: Option<Key>,
    /// Cnode slots holding the `Cap::Instance[Gas{meter_key}]` unit handles
    /// the kernel debits while this Instance runs. Slots are consulted in order:
    /// empty declared slots are skipped, the first valid non-empty slot is the
    /// primary meter used in OOG payloads, and later valid slots are fallback
    /// reserves. Empty list = no Image-declared meter (the frame loans its
    /// caller's gas scope, or the host budget at root).
    pub gas_slots: Vec<Key>,
    /// Cnode slots holding the `Cap::Instance[Quota{quota_key}]` unit handles.
    /// Same convention as [`Self::gas_slots`].
    pub quota_slots: Vec<Key>,
    /// Payload arena: a single byte pool holding the code region and every
    /// data cap's non-zero pages, packed tightly. [`CodeRef`] indexes the
    /// contiguous code slice; each [`ArenaPageRef`] indexes a window holding
    /// one page's non-zero prefix (zero-padded back to `PAGE_SIZE` at decode).
    /// All-zero pages are **never** stored — they are elided and materialize
    /// as the canonical zero page at deblob, so blobs carry no `.bss`/
    /// leading-gap zeros, and trailing zeros within a page are dropped too.
    /// Identical pages may share one window (dedup); sharing is invisible to
    /// cap identity. Trailing field so the structural header decodes without
    /// touching the payload.
    pub arena: Vec<u8>,
}

/// Endpoint definition: entry PC + register conventions.
#[derive(Debug, Clone, PartialEq, Eq, Encode, Decode, ssz_derive::HashTreeRoot)]
pub struct EndpointDef {
    /// Bytecode address to jump to.
    pub entry_pc: u64,
    /// Number of register args supplied by the caller (0..=4
    /// per spec convention; we store as u8 for flexibility).
    pub arg_registers: u8,
    /// Size of the arg cnode the caller may attach.
    pub arg_cnode_size: u8,
    /// PVM registers to seed before entering the endpoint. Keyed
    /// by register index (0..=12). Common usage: φ\[1\] (RISC-V SP)
    /// ← `stack_top`. The kernel applies these on top of the
    /// calling-convention defaults (φ\[11\] = endpoint_idx).
    pub initial_regs: BTreeMap<u8, u64>,
}

/// One mapped region. The kernel resolves `source` (a cnode slot path
/// to a `Cap::Data`) at instance start and lays the bytes at `[start,
/// start + size)` in the address space. RO vs RW is derived from
/// whether the target slot is in `Image.pinned_slots`.
#[derive(Debug, Clone, PartialEq, Eq, Encode, Decode, ssz_derive::HashTreeRoot)]
pub struct MemoryMapping {
    pub start: u64,
    pub size: u64,
    /// Cnode path resolving to the `Cap::Data` whose bytes back this
    /// region.
    pub source: crate::slot::SlotPath,
}

/// Pinned slot content. Only content-addressed cap kinds can be
/// pinned (Data or Image). `Cap::Data` bytes are inlined in the
/// Image; a future optimisation can add a hash-only variant for
/// content that lives in σ.data_payloads.
#[derive(Debug, Clone, PartialEq, Eq, Encode, Decode, ssz_derive::HashTreeRoot)]
pub enum PinnedCap {
    #[ssz(selector = 0)]
    /// Pinned `Cap::Data` as a page-granular [`DataDesc`] over the Image
    /// [`arena`](Image::arena). All-zero pages are elided.
    Data { desc: DataDesc },
    #[ssz(selector = 1)]
    /// Pinned `Cap::Image` by content hash. Cap::Image is itself
    /// content-addressed; inlining a whole sub-Image makes less
    /// sense than for Data.
    Image { content_hash: [u8; 32] },
}

/// Initial `Cap::Data` content for a non-pinned mutable slot. Used at
/// standalone (root) Instance bootstrap to seed the cnode. A parented
/// Instance receives its slots from the spawner and ignores this field.
///
/// Now a [`DataDesc`] (page-granular sparse content over the Image arena);
/// a pure zero region (stack/heap) is `DataDesc { size, pages: [] }`.
pub type InitialDataCap = DataDesc;

/// A slice of the Image [`arena`](Image::arena) holding the contiguous
/// code region: `arena[arena_off .. arena_off + len]` are the raw
/// RV+C+custom-0 bytes, mapped RO at [`crate::layout::CODE_BASE`]. `len`
/// is the *exact* (non-page-rounded) code length — the recompiler and
/// `alloc_page_aligned_code` iterate exactly `len` bytes — while the arena
/// window itself is page-rounded. `CodeRef::default()` (`{0, 0}`) is a
/// codeless image.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Encode, Decode, ssz_derive::HashTreeRoot)]
pub struct CodeRef {
    pub arena_off: u32,
    pub len: u32,
}

/// One non-zero page of a [`DataDesc`]: logical page `page_index` is backed
/// by the arena window `arena[arena_off .. arena_off + len]`, zero-padded to
/// `PAGE_SIZE` when materialized. `len` (`1..=PAGE_SIZE`) stores only the
/// page's meaningful prefix — trailing zeros *within* the page are dropped,
/// so a sub-page-dense region costs `len` bytes, not a full page. Windows are
/// packed tightly (no `arena_off` alignment). Pages not named by any
/// `ArenaPageRef` are the canonical zero page (`PageSlot::Empty`).
///
/// Named distinctly from the cap-layer `PageRef = Arc<PageBytes>`: this is
/// a wire descriptor (offsets), not a refcounted runtime page.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Encode, Decode, ssz_derive::HashTreeRoot)]
pub struct ArenaPageRef {
    pub page_index: u32,
    pub arena_off: u32,
    pub len: u32,
}

/// Page-granular sparse content of a data cap. `size` is the full logical
/// extent in bytes (a `PAGE_SIZE` multiple); `pages` names only the
/// non-zero pages, sorted by `page_index` (strictly ascending, unique), each
/// backed by an arena window of its non-zero prefix (zero-padded back to
/// `PAGE_SIZE` at decode) — see [`ArenaPageRef`].
///
/// Decodes (via [`DataDesc::to_data_cap`]) to a `DataCap` whose identity is
/// over logical `{size, page_index -> content}` only — independent of arena
/// layout, page ordering, or page sharing. So eliding zero pages and
/// deduplicating identical pages never change a cap hash.
#[derive(Debug, Clone, Default, PartialEq, Eq, Encode, Decode, ssz_derive::HashTreeRoot)]
pub struct DataDesc {
    pub size: u64,
    pub pages: Vec<ArenaPageRef>,
}

impl Image {
    /// Empty Image: no code, no endpoints, no mappings, no slots.
    /// Useful for tests and as a starting point.
    pub fn empty() -> Self {
        Self {
            code: CodeRef::default(),
            endpoints: BTreeMap::new(),
            memory_mappings: Vec::new(),
            pinned_slots: BTreeMap::new(),
            initial_slots: BTreeMap::new(),
            yield_receiver_slot: None,
            gas_slots: Vec::new(),
            quota_slots: Vec::new(),
            arena: Vec::new(),
        }
    }

    /// An Image carrying only `code` (no slots/mappings/endpoints): the
    /// arena holds the page-rounded code at offset 0. Convenience for the
    /// test helpers that previously did `let mut img = Image::empty();
    /// img.code = bytes;` — set the other structural fields after.
    pub fn with_code(code: Vec<u8>) -> Self {
        ImageBuilder::new().code(code).build()
    }

    /// The raw code bytes: the `arena` window `[code.arena_off,
    /// code.arena_off + code.len)`. Empty slice for a codeless image (or
    /// an out-of-range `CodeRef`, which the deblob rejects separately).
    pub fn code_bytes(&self) -> &[u8] {
        let off = self.code.arena_off as usize;
        let len = self.code.len as usize;
        match off.checked_add(len) {
            Some(end) => self.arena.get(off..end).unwrap_or(&[]),
            None => &[],
        }
    }

    /// The Instance data extent in bytes: `mem_top − DATA_BASE`, page-rounded
    /// (the size of the RW memory `DataCap`). Code is RO direct-mapped at
    /// `CODE_BASE`, so it contributes nothing here.
    pub fn mem_extent(&self) -> u64 {
        let mut mem_top: u32 = 0;
        for mapping in &self.memory_mappings {
            let end = (mapping.start + mapping.size) as u32;
            if end > mem_top {
                mem_top = end;
            }
        }
        (mem_top as u64)
            .saturating_sub(crate::layout::DATA_BASE as u64)
            .next_multiple_of(crate::cap::data::PAGE_SIZE as u64)
    }

    /// Build the Instance's memory backing [`crate::DataCap`]: every mapping's source
    /// content (pinned **and** initial) folded at the mapping's offset above
    /// `DATA_BASE`. This is the same byte layout the legacy `data_overlays`
    /// produced, collapsed into one dense `DataCap`.
    ///
    /// Pinned content is included here (not kept separate) so the cache-free
    /// `nub-arch-local` engine can seed memory without resolving caps; both
    /// engines still mark the pinned VAs read-only at seed time, and the
    /// recompiler maps them as `PinnedCapRo` directly from these slabs, so the
    /// pinned-RO gas tier is preserved.
    ///
    /// Single source of truth for Instance memory layout: both engines seed
    /// from this backing, so they materialize byte-identical memory.
    ///
    /// **Precondition:** the Image must be deblob-validated
    /// ([`crate::cap::image::image_cap`], which runs [`DataDesc::validate`] on
    /// every slot) before this is called — it slices `self.arena` by each
    /// page-ref's `arena_off`, so an out-of-range ref on an *unvalidated*
    /// Image would panic. Producers ([`ImageBuilder`]) always emit in-bounds
    /// page-refs, and the deblob rejects malformed ones loudly.
    pub fn instance_mem_backing(&self) -> crate::cap::data::DataCap {
        use crate::cap::data::{DataCap, PAGE_SIZE};
        let size = self.mem_extent().max(PAGE_SIZE as u64);
        let mut backing = DataCap::from_bytes_sized(&[], size);
        let data_base = crate::layout::DATA_BASE as u64;
        for mapping in &self.memory_mappings {
            let Some(target) = mapping.source.target() else {
                continue;
            };
            let desc: &DataDesc =
                if let Some(PinnedCap::Data { desc }) = self.pinned_slots.get(target) {
                    desc
                } else if let Some(desc) = self.initial_slots.get(target) {
                    desc
                } else {
                    continue;
                };
            // Fold each named page at its absolute offset; omitted pages
            // stay `PageSlot::Empty` (zero). `put_page` canonicalizes
            // all-zero -> Empty, so this is byte-identical to the previous
            // contiguous `content.chunks(PAGE_SIZE)` fold for equal content.
            let base_off = mapping.start.saturating_sub(data_base);
            for pr in &desc.pages {
                let off = pr.arena_off as usize;
                let slice = &self.arena[off..off + pr.len as usize];
                backing.put_page(base_off + pr.page_index as u64 * PAGE_SIZE as u64, slice);
            }
        }
        backing
    }
}

impl DataDesc {
    /// Number of logical pages (`size / PAGE_SIZE`).
    pub fn page_count(&self) -> u64 {
        self.size / crate::cap::data::PAGE_SIZE as u64
    }

    /// Eagerly validate this descriptor against an arena of `arena_len`
    /// bytes: `size` a `PAGE_SIZE` multiple; every page-ref page-aligned,
    /// in-bounds, with `page_index < page_count`; pages strictly ascending
    /// by `page_index` (canonical, no duplicates). Untrusted wire input is
    /// checked here — a loud `Err`, never a panic — before any arena slice
    /// is taken in [`to_data_cap`](Self::to_data_cap).
    pub fn validate(&self, arena_len: usize) -> Result<(), DataDescError> {
        use crate::cap::data::PAGE_SIZE;
        if !self.size.is_multiple_of(PAGE_SIZE as u64) {
            return Err(DataDescError::SizeNotPageMultiple(self.size));
        }
        let page_count = self.page_count();
        let mut prev: Option<u32> = None;
        for pr in &self.pages {
            // A named page stores 1..=PAGE_SIZE non-zero-prefix bytes.
            if pr.len == 0 || pr.len as usize > PAGE_SIZE {
                return Err(DataDescError::BadLen(pr.len));
            }
            let end = (pr.arena_off as usize)
                .checked_add(pr.len as usize)
                .ok_or(DataDescError::OutOfRange(pr.arena_off))?;
            if end > arena_len {
                return Err(DataDescError::OutOfRange(pr.arena_off));
            }
            if pr.page_index as u64 >= page_count {
                return Err(DataDescError::PageIndexOutOfRange {
                    page_index: pr.page_index,
                    page_count,
                });
            }
            if prev.is_some_and(|p| pr.page_index <= p) {
                return Err(DataDescError::NotCanonical(pr.page_index));
            }
            prev = Some(pr.page_index);
        }
        Ok(())
    }

    /// Materialize the runtime [`DataCap`](crate::cap::data::DataCap): each
    /// named page is `Loaded` from its `PAGE_SIZE` arena window at its
    /// absolute `page_index`; omitted pages are the canonical zero page.
    /// The result is byte-identical (and hash-identical) to
    /// `DataCap::from_bytes_sized(equivalent_contiguous_content, size)`.
    ///
    /// Assumes [`validate`](Self::validate) has passed (the deblob gate); an
    /// out-of-range `arena_off` panics — the intended loud failure for a
    /// producer bug.
    pub fn to_data_cap(&self, arena: &[u8]) -> crate::cap::data::DataCap {
        crate::cap::data::DataCap::from_sparse_pages(
            self.size,
            self.pages.iter().map(|pr| {
                let off = pr.arena_off as usize;
                // `len` bytes (the non-zero prefix); `from_content`/`put_page_idx`
                // zero-pad back to a full `PAGE_SIZE` page.
                (pr.page_index, &arena[off..off + pr.len as usize])
            }),
        )
    }
}

/// Structural faults in a [`DataDesc`] relative to the Image arena,
/// surfaced eagerly at deblob (per the strict-interface rule: fail loud).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DataDescError {
    /// `size` is not a `PAGE_SIZE` multiple.
    SizeNotPageMultiple(u64),
    /// A page-ref `len` is 0 or exceeds `PAGE_SIZE`.
    BadLen(u32),
    /// A page-ref window `[arena_off, arena_off + len)` exceeds the arena.
    OutOfRange(u32),
    /// A `page_index` is `>= size / PAGE_SIZE`.
    PageIndexOutOfRange { page_index: u32, page_count: u64 },
    /// Pages are not strictly ascending by `page_index` (unsorted or duplicate).
    NotCanonical(u32),
}

/// Pack contiguous `content` (zero-filled to `target_size`) into a
/// [`DataDesc`] over `arena`, reusing `DataCap::from_bytes_sized`'s exact
/// canonicalization (all-zero pages elided, the `size` formula) so the
/// descriptor round-trips to a byte-identical `DataCap`. Identical pages
/// (keyed by content hash) share one `arena_off` via `dedup`.
fn pack_data(
    arena: &mut Vec<u8>,
    dedup: &mut BTreeMap<[u8; 32], (u32, u32)>,
    content: &[u8],
    target_size: u64,
) -> DataDesc {
    use crate::cap::data::DataCap;
    use crate::cap::page::PageSlot;
    let dc = DataCap::from_bytes_sized(content, target_size);
    let size = dc.content_len();
    let mut pages = Vec::new();
    for p in 0..dc.backing.page_count() {
        if let PageSlot::Loaded(pb) = dc.backing.page(p) {
            // A Loaded page is non-zero: store only its prefix up to the last
            // non-zero byte (trailing zeros within the page zero-pad back
            // identically at decode), packed tightly. Dedup identical pages by
            // their full-page content hash → shared (arena_off, len).
            let (arena_off, len) = *dedup.entry(pb.hash).or_insert_with(|| {
                let len = pb.bytes.iter().rposition(|&b| b != 0).map_or(1, |i| i + 1);
                let off = arena.len() as u32;
                arena.extend_from_slice(&pb.bytes[..len]);
                (off, len as u32)
            });
            pages.push(ArenaPageRef {
                page_index: p as u32,
                arena_off,
                len,
            });
        }
    }
    DataDesc { size, pages }
}

/// Canonical Image assembler. Callers supply logical content (code +
/// per-slot contiguous bytes + size, exactly as before the arena
/// redesign); [`build`](ImageBuilder::build) packs a single page-granular
/// `arena` deterministically: code laid contiguously at offset 0, then
/// each data cap (pinned then initial, in `Key` order) page-split with
/// all-zero pages elided and byte-identical pages deduplicated. The packing
/// is a pure function of the logical content, so equal logical Images
/// produce equal arenas and equal `image_content_hash`es regardless of
/// builder call order.
#[derive(Default)]
pub struct ImageBuilder {
    code: Vec<u8>,
    endpoints: BTreeMap<Key, EndpointDef>,
    memory_mappings: Vec<MemoryMapping>,
    pinned: BTreeMap<Key, PinnedSpec>,
    initial: BTreeMap<Key, (Vec<u8>, u64)>,
    yield_receiver_slot: Option<Key>,
    gas_slots: Vec<Key>,
    quota_slots: Vec<Key>,
}

enum PinnedSpec {
    Data { content: Vec<u8>, size: u64 },
    Image { content_hash: [u8; 32] },
}

impl ImageBuilder {
    pub fn new() -> Self {
        Self::default()
    }
    pub fn code(mut self, code: Vec<u8>) -> Self {
        self.code = code;
        self
    }
    pub fn endpoint(mut self, key: Key, ep: EndpointDef) -> Self {
        self.endpoints.insert(key, ep);
        self
    }
    pub fn mapping(mut self, m: MemoryMapping) -> Self {
        self.memory_mappings.push(m);
        self
    }
    pub fn pinned_data(mut self, key: Key, content: Vec<u8>, size: u64) -> Self {
        self.pinned.insert(key, PinnedSpec::Data { content, size });
        self
    }
    pub fn pinned_image(mut self, key: Key, content_hash: [u8; 32]) -> Self {
        self.pinned.insert(key, PinnedSpec::Image { content_hash });
        self
    }
    pub fn initial_data(mut self, key: Key, content: Vec<u8>, size: u64) -> Self {
        self.initial.insert(key, (content, size));
        self
    }
    pub fn yield_receiver_slot(mut self, slot: Option<Key>) -> Self {
        self.yield_receiver_slot = slot;
        self
    }
    pub fn gas_slots(mut self, slots: Vec<Key>) -> Self {
        self.gas_slots = slots;
        self
    }
    pub fn quota_slots(mut self, slots: Vec<Key>) -> Self {
        self.quota_slots = slots;
        self
    }

    pub fn build(self) -> Image {
        let mut arena: Vec<u8> = Vec::new();
        let mut dedup: BTreeMap<[u8; 32], (u32, u32)> = BTreeMap::new();

        // Data caps first, in deterministic Key order (pinned, then
        // initial). Each non-zero page is appended as its non-zero prefix
        // (trailing-zero-trimmed, packed tightly), with identical pages
        // deduplicated by content hash.
        let mut pinned_slots: BTreeMap<Key, PinnedCap> = BTreeMap::new();
        for (key, spec) in self.pinned {
            let pc = match spec {
                PinnedSpec::Data { content, size } => PinnedCap::Data {
                    desc: pack_data(&mut arena, &mut dedup, &content, size),
                },
                PinnedSpec::Image { content_hash } => PinnedCap::Image { content_hash },
            };
            pinned_slots.insert(key, pc);
        }
        let mut initial_slots: BTreeMap<Key, DataDesc> = BTreeMap::new();
        for (key, (content, size)) in self.initial {
            initial_slots.insert(key, pack_data(&mut arena, &mut dedup, &content, size));
        }

        // Code last: contiguous, stored at its EXACT length. The deblob
        // re-copies code into a fresh aligned slab, so its arena offset
        // needs no alignment.
        let code = if self.code.is_empty() {
            CodeRef::default()
        } else {
            let arena_off = arena.len() as u32;
            let len = self.code.len() as u32;
            arena.extend_from_slice(&self.code);
            CodeRef { arena_off, len }
        };

        Image {
            code,
            endpoints: self.endpoints,
            memory_mappings: self.memory_mappings,
            pinned_slots,
            initial_slots,
            yield_receiver_slot: self.yield_receiver_slot,
            gas_slots: self.gas_slots,
            quota_slots: self.quota_slots,
            arena,
        }
    }
}

/// Content hash of an Image: SSZ `hash_tree_root` (SHA-256 merkleization
/// of the derived SSZ container). The canonical encoding/merkleization is
/// defined by `Image`'s `ssz-derive` impl.
pub fn image_content_hash(image: &Image) -> [u8; 32] {
    ssz::hash_tree_root(image)
}

/// Genesis image-hash chain: a freshly-derived Instance (with no
/// prior chain) has `image_hash = image_content_hash`.
///
/// This is the case for the very first Instance the chain spec
/// produces. Subsequent Instances always derive from some spawner
/// via `chain_extend`.
pub fn chain_genesis<H: Hash>(image: &Image) -> H::Out
where
    H::Out: From<[u8; 32]>,
{
    image_content_hash(image).into()
}

/// Extend an image-hash chain with a new image:
/// `result = H(prev_chain || image_content_hash(new_image))`.
///
/// Used for both `set_image(new)` on an existing Instance and
/// `host_derive_spawn(new, cnode)` from a spawner.
pub fn chain_extend<H: Hash>(prev_chain: &H::Out, new_image: &Image) -> H::Out
where
    H::Out: AsRef<[u8]>,
{
    let new_image_hash = image_content_hash(new_image);
    H::hash_pair(prev_chain.as_ref(), &new_image_hash)
}
