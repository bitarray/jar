//! `ImageCap` — Image cap.
//!
//! Stores code regions, endpoints, mappings, and slot references as
//! separate `Vec<T>` allocations. Allocation count per ImageCap is
//! bounded regardless of content size; we accept that in exchange for
//! direct field accessors.

use alloc::vec::Vec;

use crate::slot::SlotIdx;

use super::{CapHash, MAX_ENDPOINTS, MAX_SOURCE_DEPTH, NUM_REGS};

#[derive(Debug, ssz_derive::HashTreeRoot, rkyv::Archive, rkyv::Serialize, rkyv::Deserialize)]
pub struct ImageCap {
    /// The (single) code region: raw RV+C+custom-0 bytes, page-aligned
    /// so the kernel can direct-map it RO at the fixed protocol
    /// constant [`crate::layout::CODE_BASE`]. Empty for codeless
    /// images. See [`ImageCap::code_mapping`].
    pub code: Vec<u8>,
    /// Endpoint definitions. Stored as a dense array keyed by
    /// endpoint index — `endpoints[i].entry_pc == 0` means the
    /// endpoint at index `i` is not defined.
    pub endpoints: Vec<EndpointDef>,
    /// Memory mappings.
    pub mappings: Vec<MemoryMapping>,
    /// Pinned read-only slots (Cap::Data / Cap::Image). Images only
    /// ever reference content-addressed caps, so the target is a
    /// plain `CapHash`.
    pub pinned: Vec<ImageSlotEntry>,
    /// Initial mutable slot state for non-pinned slots.
    pub initial: Vec<ImageSlotEntry>,
    /// Slot holding `Cap::Instance[YieldCatcher]`, if any.
    pub yield_marker_slot: Option<SlotIdx>,
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
            yield_marker_slot: self.yield_marker_slot,
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
}

/// Endpoint definition. Dense `initial_regs` array; index `i`
/// corresponds to PVM register `φ[i]`. `0` is "use default" (same
/// semantics as the spec's old `BTreeMap<u8, u64>` when the key is
/// absent).
#[derive(
    Clone,
    Copy,
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
    pub arg_cnode_slot: SlotIdx,
    pub arg_cnode_size: u8,
    pub initial_regs: [u64; NUM_REGS],
}

impl EndpointDef {
    /// Empty endpoint — `entry_pc == 0` is the canonical sentinel
    /// for "not defined" (since a real entry PC is never zero — PC 0
    /// is reserved as the fallback PC in our convention).
    pub const fn empty() -> Self {
        Self {
            entry_pc: 0,
            stack_top: 0,
            arg_cnode_slot: SlotIdx(0),
            arg_cnode_size: 0,
            initial_regs: [0; NUM_REGS],
        }
    }
}

/// One mapped region. The kernel resolves `source_path` at instance
/// start, reads the bytes from the resulting `Cap::Data`, and lays
/// them at `[start, start + size)`. `source_path` is a fixed-cap
/// array (`source_path[..source_path_len]` is the live path);
/// `source_path_len` is the actual depth.
///
/// **SSZ note**: `Encode`/`Decode`/`HashTreeRoot` are hand-written
/// because the `source_path` field is `[SlotIdx; MAX_SOURCE_DEPTH]` —
/// an array of a local type, which Rust's orphan rules block from
/// receiving a blanket impl in either `ssz` or `javm-cap`. The encoded
/// form is field-by-field SSZ (`u64 || u64 || MAX_SOURCE_DEPTH×4 LE
/// bytes || u8`); all fields are fixed-length, so the container is
/// fixed-length too.
#[derive(Clone, Copy, Debug, PartialEq, Eq, rkyv::Archive, rkyv::Serialize, rkyv::Deserialize)]
pub struct MemoryMapping {
    pub start: u64,
    pub size: u64,
    pub source_path: [SlotIdx; MAX_SOURCE_DEPTH],
    pub source_path_len: u8,
}

impl MemoryMapping {
    /// SSZ fixed encoded length: 8 + 8 + (MAX_SOURCE_DEPTH * 4) + 1.
    const SSZ_LEN: usize = 8 + 8 + MAX_SOURCE_DEPTH * 4 + 1;
}

impl ssz::Encode for MemoryMapping {
    fn is_ssz_fixed_len() -> bool {
        true
    }
    fn ssz_fixed_len() -> usize {
        Self::SSZ_LEN
    }
    fn ssz_bytes_len(&self) -> usize {
        Self::SSZ_LEN
    }
    fn ssz_append(&self, buf: &mut alloc::vec::Vec<u8>) {
        buf.extend_from_slice(&self.start.to_le_bytes());
        buf.extend_from_slice(&self.size.to_le_bytes());
        for s in &self.source_path {
            buf.extend_from_slice(&s.get().to_le_bytes());
        }
        buf.push(self.source_path_len);
    }
}

impl ssz::Decode for MemoryMapping {
    fn is_ssz_fixed_len() -> bool {
        true
    }
    fn ssz_fixed_len() -> usize {
        Self::SSZ_LEN
    }
    fn from_ssz_bytes(bytes: &[u8]) -> Result<Self, ssz::DecodeError> {
        if bytes.len() != Self::SSZ_LEN {
            return Err(ssz::DecodeError::UnexpectedEof {
                expected: Self::SSZ_LEN,
                actual: bytes.len(),
            });
        }
        let start = u64::from_le_bytes(bytes[0..8].try_into().expect("len checked"));
        let size = u64::from_le_bytes(bytes[8..16].try_into().expect("len checked"));
        let mut source_path = [SlotIdx(0); MAX_SOURCE_DEPTH];
        for (i, slot) in source_path.iter_mut().enumerate() {
            let s = 16 + i * 4;
            let arr: [u8; 4] = bytes[s..s + 4].try_into().expect("len checked");
            *slot = SlotIdx(u32::from_le_bytes(arr));
        }
        let source_path_len = bytes[16 + MAX_SOURCE_DEPTH * 4];
        Ok(Self {
            start,
            size,
            source_path,
            source_path_len,
        })
    }
}

impl ssz::HashTreeRoot for MemoryMapping {
    fn hash_tree_root<D: ::ssz::digest::Digest<OutputSize = ::ssz::digest::typenum::U32>>(
        &self,
    ) -> [u8; 32] {
        // SSZ container root: merkleize the per-field roots with
        // limit = number of fields (6). All are fixed-size leaves.
        let path_root = {
            // Treat the fixed-length path array as a `Vector<u32,
            // MAX_SOURCE_DEPTH>` for hashing: pack to bytes, merkleize
            // with `ceil(N*4/32)` chunks.
            let mut buf: alloc::vec::Vec<u8> = alloc::vec::Vec::with_capacity(MAX_SOURCE_DEPTH * 4);
            for s in &self.source_path {
                buf.extend_from_slice(&s.get().to_le_bytes());
            }
            let chunks = ssz::pack_bytes(&buf);
            let limit = (MAX_SOURCE_DEPTH * 4).div_ceil(32).max(1);
            ssz::merkleize::<D>(&chunks, limit)
        };
        let roots = [
            ssz::HashTreeRoot::hash_tree_root::<D>(&self.start),
            ssz::HashTreeRoot::hash_tree_root::<D>(&self.size),
            path_root,
            ssz::HashTreeRoot::hash_tree_root::<D>(&self.source_path_len),
        ];
        ssz::merkleize::<D>(&roots, 4)
    }
}

impl MemoryMapping {
    /// Live slot indices (length = `source_path_len`) — the cnode path
    /// to the `Cap::Data` backing this mapping.
    pub fn path(&self) -> &[SlotIdx] {
        &self.source_path[..self.source_path_len as usize]
    }
}

/// `(slot_idx, cap_hash)` pair used by Image's `pinned` and
/// `initial` arrays. References content-addressed caps only.
#[derive(
    Clone,
    Copy,
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
    pub slot: SlotIdx,
    pub cap_hash: CapHash,
}

/// Failure modes when converting a SCALE-encoded [`crate::image::Image`]
/// into an [`ImageCap`]. The conversion is lossy in fields the v3 cap
/// shape no longer carries (`gas_slots`, `quota_slots`, per-endpoint
/// `arg_registers`) and constrained in others — these errors flag the
/// constraint violations.
#[derive(Debug, thiserror::Error)]
pub enum ImageConvertError {
    #[error("memory mapping source path empty")]
    SourcePathEmpty,
    #[error("memory mapping source path too deep (steps={0} > MAX_SOURCE_DEPTH)")]
    SourcePathTooDeep(usize),
    #[error("endpoint index {0} >= MAX_ENDPOINTS")]
    EndpointIndexOutOfRange(u8),
    #[error("register index {0} >= NUM_REGS")]
    RegisterIndexOutOfRange(u8),
}

/// Build an [`ImageCap`] from the SCALE-encoded [`crate::image::Image`]
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
/// - Endpoints are stored in a dense `MAX_ENDPOINTS`-sized array,
///   indexed by endpoint id. Empty slots use [`EndpointDef::empty`].
///   `stack_top` is extracted from the old `initial_regs[1]` (RISC-V
///   SP convention); `arg_cnode_slot` defaults to `SlotIdx(0)`.
/// - `MemoryMapping.source` (a `SlotPath`) becomes `source_path:
///   [SlotIdx; MAX_SOURCE_DEPTH]` + `source_path_len`; paths deeper
///   than `MAX_SOURCE_DEPTH` error.
pub fn image_cap(
    image: &crate::image::Image,
    pinned_hashes: &[(SlotIdx, CapHash)],
    initial_hashes: &[(SlotIdx, CapHash)],
) -> Result<ImageCap, ImageConvertError> {
    // Code: page-aligned copy so the kernel can direct-map it RO at
    // `layout::CODE_BASE`.
    let code = alloc_page_aligned_code(&image.code);

    // Endpoints: dense `MAX_ENDPOINTS`-sized array; empty entries have
    // `entry_pc == 0`.
    let mut endpoints = Vec::with_capacity(MAX_ENDPOINTS);
    for _ in 0..MAX_ENDPOINTS {
        endpoints.push(EndpointDef::empty());
    }
    for (&idx, ep) in &image.endpoints {
        if (idx as usize) >= MAX_ENDPOINTS {
            return Err(ImageConvertError::EndpointIndexOutOfRange(idx));
        }
        let mut initial_regs = [0u64; NUM_REGS];
        for (&reg_idx, &val) in &ep.initial_regs {
            if (reg_idx as usize) >= NUM_REGS {
                return Err(ImageConvertError::RegisterIndexOutOfRange(reg_idx));
            }
            initial_regs[reg_idx as usize] = val;
        }
        // RISC-V SP convention: φ[1] = stack pointer.
        let stack_top = ep.initial_regs.get(&1).copied().unwrap_or(0);
        endpoints[idx as usize] = EndpointDef {
            entry_pc: ep.entry_pc,
            stack_top,
            arg_cnode_slot: SlotIdx(0),
            arg_cnode_size: ep.arg_cnode_size,
            initial_regs,
        };
    }

    let mut mappings = Vec::with_capacity(image.memory_mappings.len());
    for m in &image.memory_mappings {
        let steps = &m.source.steps;
        if steps.is_empty() {
            return Err(ImageConvertError::SourcePathEmpty);
        }
        if steps.len() > MAX_SOURCE_DEPTH {
            return Err(ImageConvertError::SourcePathTooDeep(steps.len()));
        }
        let mut source_path = [SlotIdx(0); MAX_SOURCE_DEPTH];
        for (i, s) in steps.iter().enumerate() {
            source_path[i] = *s;
        }
        mappings.push(MemoryMapping {
            start: m.start,
            size: m.size,
            source_path,
            source_path_len: steps.len() as u8,
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
        yield_marker_slot: image.yield_marker_slot,
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

fn build_image_slot_vec(pairs: &[(SlotIdx, CapHash)]) -> Vec<ImageSlotEntry> {
    let mut sorted: Vec<(SlotIdx, CapHash)> = pairs.to_vec();
    sorted.sort_by_key(|(s, _)| *s);
    let mut out = Vec::with_capacity(sorted.len());
    for (slot, cap_hash) in &sorted {
        out.push(ImageSlotEntry {
            slot: *slot,
            cap_hash: *cap_hash,
        });
    }
    out
}
