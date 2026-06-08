//! `ImageCap` — Image cap.
//!
//! Stores a single code region, endpoints, mappings, and slot references as
//! separate `Vec<T>` allocations. Allocation count per ImageCap is
//! bounded regardless of content size; we accept that in exchange for
//! direct field accessors.

use alloc::vec::Vec;

use crate::slot::{Key, SlotPath};

use super::{CapHash, MAX_SOURCE_DEPTH, NUM_REGS};

/// # Validation model: structure is eager, semantics are lazy
///
/// An `ImageCap` is admitted from untrusted input under a two-layer
/// discipline:
///
/// - **Structure — validated eagerly** (here / in [`image_cap`], the
///   "deblob"). The metadata that frames execution: `code` *length*
///   (`≤ MAX_CODE_SIZE`), memory-mapping bounds, slot indices, source-path
///   depth, endpoint indices. A malformed structural field has no clean
///   execution point to fault on — it would diverge between engines or
///   panic the host — so it is rejected at construction. This is cheap
///   (`O(#endpoints + #mappings + #slots)`, it never scans the code) and
///   therefore compatible with lazy compilation.
///
/// - **Semantics — validated lazily** (at execution, by both engines
///   identically). The instruction stream itself: illegal/forbidden
///   encodings, and `jal`/branch/`jalr`/`entry_pc` targets. These are
///   **not** rejected at admission — any `code` bytes are accepted. A
///   forbidden encoding decodes as illegal and an off-`bb_start` target is
///   refused only *when reached*, as `ε = panic`. Lazy (not eager
///   deblob) because, without an instruction bitmask, a linear validator
///   can't tell code from data — eager rejection would reject legitimate
///   code-as-data; lazy also keeps admission version-independent (a future
///   ISA extension forks only at execution, never the cap set at
///   admission) and preserves lazy compilation. The consensus requirement
///   is that the two engines *agree* on what panics, not that the bytes
///   are pre-screened. The producer toolchain still rejects forbidden
///   encodings at build time as a diagnostic — that is UX, not a
///   consensus rule.
#[derive(Debug, ssz_derive::HashTreeRoot, rkyv::Archive, rkyv::Serialize, rkyv::Deserialize)]
pub struct ImageCap {
    /// The (single) code region: raw RV+C+custom-0 bytes, page-aligned
    /// so the kernel can direct-map it RO at the fixed protocol
    /// constant [`crate::layout::CODE_BASE`]. Empty for codeless
    /// images. See [`ImageCap::code_mapping`].
    pub code: Vec<u8>,
    /// Endpoint definitions, keyed by a [`Key`] selector. A sparse, sorted
    /// association list (`Dict`-style — kept sorted by key, no fixed capacity);
    /// an absent key is an undefined endpoint. There is no dense array and no
    /// `entry_pc == 0` sentinel, so an endpoint may legitimately start at code
    /// offset 0. (`Vec<(Key, _)>` rather than `BTreeMap` because the rkyv wire
    /// form has no `Ord` on the archived key.)
    pub endpoints: Vec<(Key, EndpointDef)>,
    /// Memory mappings.
    pub mappings: Vec<MemoryMapping>,
    /// Pinned read-only slots (Cap::Data / Cap::Image). Images only
    /// ever reference content-addressed caps, so the target is a
    /// plain `CapHash`.
    pub pinned: Vec<ImageSlotEntry>,
    /// Initial mutable slot state for non-pinned slots.
    pub initial: Vec<ImageSlotEntry>,
    /// Slot holding `Cap::Instance[YieldReceiver]` (the catch-set), if any.
    pub yield_receiver_slot: Option<Key>,
    /// Cnode slots holding the `Cap::Instance[Gas{meter_key}]` unit handles,
    /// consulted in order. See [`crate::image::Image::gas_slots`].
    pub gas_slots: Vec<Key>,
    /// Cnode slots holding the `Cap::Instance[Quota{quota_key}]` unit handles.
    pub quota_slots: Vec<Key>,
}

// Manual Clone: the derived impl would `Vec::clone` the `code` bytes,
// which goes through `Global::alloc` at the default 1-byte alignment
// for `[u8]`. The kernel direct-maps the code region into a ring-3 PT
// and asserts `phys.is_multiple_of(PAGE_SIZE)`, so a cloned buffer on
// an unaligned page would panic. Re-allocate `code` through
// `alloc_page_aligned_code` to preserve the invariant across clones
// (mirrors `DataContent`'s manual Clone). Other fields clone normally.
impl Clone for ImageCap {
    fn clone(&self) -> Self {
        Self {
            code: alloc_page_aligned_code(&self.code),
            endpoints: self.endpoints.clone(),
            mappings: self.mappings.clone(),
            pinned: self.pinned.clone(),
            initial: self.initial.clone(),
            yield_receiver_slot: self.yield_receiver_slot.clone(),
            gas_slots: self.gas_slots.clone(),
            quota_slots: self.quota_slots.clone(),
        }
    }
}

impl ImageCap {
    /// The executable code region as `(code_base, bytes)`. `code_base`
    /// is the fixed protocol constant [`crate::layout::CODE_BASE`], so a
    /// PVM PC is `code_base + byte_offset`. `None` if the image declares
    /// no code (empty region) — such an image cannot execute.
    pub fn code_mapping(&self) -> Option<(u32, &[u8])> {
        if self.code.is_empty() {
            return None;
        }
        Some((crate::layout::CODE_BASE, self.code.as_slice()))
    }

    /// True iff the memory mapping starting at guest VA `start` draws
    /// from a pinned (read-only) slot, so it must be laid read-only — a
    /// guest store to it faults. Mirrors the recompiler's pinned-vs-
    /// initial slot classification (`nub-arch-x86` `build_runtime`).
    /// Derived from [`Self::pinned`] at lay time, so a mapping carries no
    /// per-mapping permission field; the interpreter drivers (`javm`
    /// `build_entry`, `nub-arch-local`) call this so they classify
    /// identically to the recompiler.
    pub fn mapping_is_pinned(&self, start: u32) -> bool {
        self.mappings.iter().any(|m| {
            m.start as u32 == start
                && m.source
                    .steps()
                    .first()
                    .is_some_and(|root| self.pinned.iter().any(|p| &p.slot == root))
        })
    }
}

/// Endpoint definition. Dense `initial_regs` array; index `i`
/// corresponds to PVM register `φ[i]`. `0` is "use default" (same
/// semantics as the spec's old `BTreeMap<u8, u64>` when the key is
/// absent).
// `Key` is heap-spillable (`SmallVec`), so `EndpointDef` is no longer
// `Copy`; it threads through the cap layer by value/clone like the other
// `Key`-bearing structs.
#[derive(
    Clone,
    Debug,
    PartialEq,
    Eq,
    ssz_derive::Encode,
    ssz_derive::Decode,
    ssz_derive::HashTreeRoot,
    rkyv::Archive,
    rkyv::Serialize,
    rkyv::Deserialize,
)]
pub struct EndpointDef {
    pub entry_pc: u64,
    pub stack_top: u64,
    pub arg_cnode_slot: Key,
    pub arg_cnode_size: u8,
    pub initial_regs: [u64; NUM_REGS],
}

/// One mapped region. The kernel resolves `source` (a [`SlotPath`] to a
/// `Cap::Data`) at instance start, reads the bytes, and lays them at
/// `[start, start + size)`.
///
/// `source` is a variable-length [`SlotPath`] (was a fixed `[SlotIdx;
/// MAX_SOURCE_DEPTH]` + length), so `MemoryMapping` is now a
/// variable-length SSZ container with a fully derived codec — no hand-rolled
/// SSZ. The eager depth bound (`≤ MAX_SOURCE_DEPTH`) is enforced in
/// [`image_cap`] at deblob, not in the wire decode.
#[derive(
    Clone,
    Debug,
    PartialEq,
    Eq,
    ssz_derive::Encode,
    ssz_derive::Decode,
    ssz_derive::HashTreeRoot,
    rkyv::Archive,
    rkyv::Serialize,
    rkyv::Deserialize,
)]
pub struct MemoryMapping {
    pub start: u64,
    pub size: u64,
    /// Cnode path resolving to the `Cap::Data` whose bytes back this region.
    pub source: SlotPath,
}

impl MemoryMapping {
    /// The cnode path steps — the keys to walk to the `Cap::Data` backing
    /// this mapping. Non-empty for a well-formed mapping.
    pub fn path(&self) -> &[Key] {
        self.source.steps()
    }
}

/// `(slot_key, cap_hash)` pair used by Image's `pinned` and
/// `initial` arrays. References content-addressed caps only.
///
/// `Key` is heap-spillable, so this is no longer `Copy`.
#[derive(
    Clone,
    Debug,
    PartialEq,
    Eq,
    ssz_derive::Encode,
    ssz_derive::Decode,
    ssz_derive::HashTreeRoot,
    rkyv::Archive,
    rkyv::Serialize,
    rkyv::Deserialize,
)]
pub struct ImageSlotEntry {
    pub slot: Key,
    pub cap_hash: CapHash,
}

/// Failure modes when converting an SSZ-encoded [`crate::image::Image`]
/// into an [`ImageCap`]. The conversion is lossy in fields the v3 cap
/// shape no longer carries (`gas_slots`, `quota_slots`, per-endpoint
/// `arg_registers`) and constrained in others — these errors flag the
/// constraint violations.
#[derive(Debug, thiserror::Error)]
pub enum ImageConvertError {
    #[error("code region {0} bytes exceeds MAX_CODE_SIZE ({1})")]
    CodeTooLarge(usize, u32),
    #[error("code ref [{0}, {0}+{1}) out of arena bounds (arena {2} bytes)")]
    CodeRefOutOfRange(u32, u32, usize),
    #[error("data desc invalid: {0:?}")]
    DataDesc(crate::image::DataDescError),
    #[error("memory mapping source path empty")]
    SourcePathEmpty,
    #[error("memory mapping source path too deep (steps={0} > MAX_SOURCE_DEPTH)")]
    SourcePathTooDeep(usize),
    #[error("register index {0} >= NUM_REGS")]
    RegisterIndexOutOfRange(u8),
}

/// Build an [`ImageCap`] from the SSZ-encoded [`crate::image::Image`]
/// shape. The Data content referenced by pinned and initial slots must
/// already be published — pass the resolved `(SlotIdx, CapHash)` pairs
/// in `pinned_hashes` and `initial_hashes`. The builder sorts both lists
/// by slot index.
///
/// **Lossy fields (intentionally dropped):**
/// - `gas_slots` / `quota_slots`: gas is now tracked on
///   [`super::instance::InstanceCap::gas_remaining`]; the v3 cap shape
///   no longer pins gas/quota slots in the Image.
/// - per-endpoint `arg_registers`: the calling convention is implicit
///   in the new shape.
///
/// **Field mappings:**
/// - Endpoints are stored in a sparse `Key -> EndpointDef` map (no fixed
///   capacity). `stack_top` is extracted from the old `initial_regs[1]`
///   (RISC-V SP convention); `arg_cnode_slot` defaults to `Key::from(0)`.
/// - `MemoryMapping.source` (a [`SlotPath`]) is carried through verbatim;
///   paths that are empty or deeper than `MAX_SOURCE_DEPTH` error.
pub fn image_cap(
    image: &crate::image::Image,
    pinned_hashes: &[(Key, CapHash)],
    initial_hashes: &[(Key, CapHash)],
) -> Result<ImageCap, ImageConvertError> {
    // Structural invariant (eager): the code region maps RO at
    // `[CODE_BASE, DATA_BASE)`, so it must fit under `MAX_CODE_SIZE` —
    // otherwise a high code offset would alias the data region. The
    // *contents* of `code` are not validated here (instruction legality
    // is checked lazily, at execution); only its size is a structural
    // bound. Checked before the page-aligned copy so an oversized blob
    // is rejected without allocating it.
    let code_len = image.code.len as usize;
    if code_len > crate::layout::MAX_CODE_SIZE as usize {
        return Err(ImageConvertError::CodeTooLarge(
            code_len,
            crate::layout::MAX_CODE_SIZE,
        ));
    }
    // The code window `[arena_off, arena_off + len)` must lie within the
    // arena (untrusted wire input — fail loud, never slice out of range).
    let code_in_bounds = (image.code.arena_off as usize)
        .checked_add(code_len)
        .is_some_and(|end| end <= image.arena.len());
    if !code_in_bounds {
        return Err(ImageConvertError::CodeRefOutOfRange(
            image.code.arena_off,
            image.code.len,
            image.arena.len(),
        ));
    }
    // Every pinned/initial data descriptor must reference the arena
    // soundly (page-aligned, in-bounds, page_index < page_count, canonical
    // page order) before any downstream materialization slices the arena.
    for slot in image.pinned_slots.values() {
        if let crate::image::PinnedCap::Data { desc } = slot {
            desc.validate(image.arena.len())
                .map_err(ImageConvertError::DataDesc)?;
        }
    }
    for desc in image.initial_slots.values() {
        desc.validate(image.arena.len())
            .map_err(ImageConvertError::DataDesc)?;
    }
    // Code: page-aligned copy so the kernel can direct-map it RO at
    // `layout::CODE_BASE`.
    let code = alloc_page_aligned_code(image.code_bytes());

    // Endpoints: a sparse, sorted `Key -> EndpointDef` association list (no
    // fixed capacity, no dense `entry_pc == 0` sentinel — presence is what
    // defines an endpoint). `image.endpoints` is a BTreeMap, so iterating it
    // yields keys in sorted order and the resulting Vec stays sorted by Key.
    let mut endpoints = Vec::with_capacity(image.endpoints.len());
    for (key, ep) in &image.endpoints {
        let mut initial_regs = [0u64; NUM_REGS];
        for (&reg_idx, &val) in &ep.initial_regs {
            if (reg_idx as usize) >= NUM_REGS {
                return Err(ImageConvertError::RegisterIndexOutOfRange(reg_idx));
            }
            initial_regs[reg_idx as usize] = val;
        }
        // RISC-V SP convention: φ[1] = stack pointer.
        let stack_top = ep.initial_regs.get(&1).copied().unwrap_or(0);
        endpoints.push((
            key.clone(),
            EndpointDef {
                entry_pc: ep.entry_pc,
                stack_top,
                arg_cnode_slot: Key::from(0u8),
                arg_cnode_size: ep.arg_cnode_size,
                initial_regs,
            },
        ));
    }

    let mut mappings = Vec::with_capacity(image.memory_mappings.len());
    for m in &image.memory_mappings {
        let steps = m.source.steps();
        if steps.is_empty() {
            return Err(ImageConvertError::SourcePathEmpty);
        }
        if steps.len() > MAX_SOURCE_DEPTH {
            return Err(ImageConvertError::SourcePathTooDeep(steps.len()));
        }
        mappings.push(MemoryMapping {
            start: m.start,
            size: m.size,
            source: m.source.clone(),
        });
    }

    let pinned = build_image_slot_vec(pinned_hashes);
    let initial = build_image_slot_vec(initial_hashes);

    Ok(ImageCap {
        code,
        endpoints,
        mappings,
        pinned,
        initial,
        yield_receiver_slot: image.yield_receiver_slot.clone(),
        gas_slots: image.gas_slots.clone(),
        quota_slots: image.quota_slots.clone(),
    })
}

/// Copy `bytes` into a `Vec<u8>` whose backing allocation is
/// page-aligned and page-size-rounded (so the kernel can `va_to_pa` +
/// direct-map the code region RO), but whose **length is the real code
/// length** — not the padded capacity.
///
/// The length must stay exact: the recompiler iterates `code.len()`
/// bytes, so a page-padded length would make it compile thousands of
/// trailing zero bytes as bogus instructions (a ~page-sized fixed cost
/// per recompile that dominates small guests). The runtime rounds the
/// mapping size up to a page separately; the trailing capacity bytes
/// stay zeroed and mapped but are never executed.
fn alloc_page_aligned_code(bytes: &[u8]) -> Vec<u8> {
    let mut v = super::data::alloc_page_aligned_zeroed(bytes.len());
    v[..bytes.len()].copy_from_slice(bytes);
    // Keep the page-aligned allocation + zeroed tail (capacity), but
    // expose only the real code length. `truncate` never reallocates,
    // so the base pointer stays page-aligned for `va_to_pa`.
    v.truncate(bytes.len());
    v
}

fn build_image_slot_vec(pairs: &[(Key, CapHash)]) -> Vec<ImageSlotEntry> {
    let mut sorted: Vec<(Key, CapHash)> = pairs.to_vec();
    // `Key: Ord` is lexicographic-by-byte; canonical ordering keeps the
    // `ImageCap` hash insertion-order independent.
    sorted.sort_by(|(a, _), (b, _)| a.cmp(b));
    let mut out = Vec::with_capacity(sorted.len());
    for (slot, cap_hash) in sorted {
        out.push(ImageSlotEntry { slot, cap_hash });
    }
    out
}
