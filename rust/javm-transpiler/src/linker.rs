//! ELF → JAVM `Image`.
//!
//! The ELF parsing and the whole RV→PVM2 rewrite live in
//! [`nub_linker`]: they are ISA work with no capability content. What
//! remains here is the JAVM-specific half — wrapping the resulting
//! [`ProgramBlob`] in the cap shape.

use crate::TranspileError;
use crate::layout::{PVM_PAGE_SIZE, cap_index};
use javm_cap::Key;
use javm_cap::abi::BARE_YIELD_RECEIVER_SLOT;
use javm_cap::image::{EndpointDef, Image, ImageBuilder, MemoryMapping};
use javm_cap::slot::SlotPath;
use nub_program::{ProgramBlob, RegionKind};

/// Link an RV ELF into a PVM2 [`Image`]. `Image::code` holds the raw
/// RV+C+custom-0 bytes, mapped read-only at `CODE_BASE` by the runtime.
pub fn link_elf(elf_data: &[u8]) -> Result<Image, TranspileError> {
    Ok(image_from_blob(&nub_linker::link_elf(elf_data)?))
}

/// Wrap a personality-free [`ProgramBlob`] in the JAVM cap shape.
///
/// Each data region becomes one `Cap::Data` at its conventional cnode
/// slot — `pinned_data` for the read-only region, `initial_data` for
/// the rest — plus a declarative `MemoryMapping` pointing at that slot.
/// Endpoints are re-keyed by [`Key`], and the bare-Frame yield-receiver
/// slot is set.
///
/// This is a pure shape transform: page splitting, all-zero-page
/// elision and content-dedup into the shared `arena` happen inside
/// [`ImageBuilder::build`].
///
/// **Ordering is load-bearing.** `ImageBuilder` packs the arena in
/// insertion order, so regions must be added in
/// [`nub_program::Regions::iter`] order (stack, ro, rw, heap) and the
/// code last, or the emitted bytes shift.
pub fn image_from_blob(program: &ProgramBlob) -> Image {
    let page_bytes = u64::from(PVM_PAGE_SIZE);
    let mut builder = ImageBuilder::new();
    let mut mappings: Vec<MemoryMapping> = Vec::new();

    for region in program.regions.iter() {
        let slot = Key::from(cap_index(region.kind));
        let size = u64::from(region.page_count) * page_bytes;
        mappings.push(MemoryMapping {
            start: region.start(),
            size,
            source: SlotPath::root(slot.clone()),
        });
        // Stack and heap are zero-initialized, so they carry no bytes.
        let bytes = program.region_data(region.kind).unwrap_or(&[]).to_vec();
        builder = if region.kind == RegionKind::Ro {
            builder.pinned_data(slot, bytes, size)
        } else {
            builder.initial_data(slot, bytes, size)
        };
    }

    builder = builder.code(program.code.clone());
    for (&index, endpoint) in &program.endpoints {
        builder = builder.endpoint(
            Key::from(index),
            EndpointDef {
                entry_pc: endpoint.entry_pc,
                arg_registers: endpoint.arg_registers,
                arg_cnode_size: endpoint.arg_meta,
                initial_regs: endpoint.initial_regs.clone(),
            },
        );
    }
    for mapping in mappings {
        builder = builder.mapping(mapping);
    }

    builder
        .yield_receiver_slot(Some(Key::from(BARE_YIELD_RECEIVER_SLOT)))
        .build()
}
