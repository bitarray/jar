//! Chain genesis: σ initialization + kernel-cap injection.
//!
//! `genesis` takes a chain `Image` and publishes into σ's cache:
//! - The chain Image (as a `Cap::Image` blob).
//! - The kernel-issued unit caps at well-known slots
//!   (Gas{0}, Quota{0}, YieldCatcher, factories, host entries).
//! - The chain's root cnode binding those caps + the image's pinned /
//!   initial slot data caps.
//! - The chain `Cap::Instance` referencing the chain image and root
//!   cnode.
//!
//! Per the v3 spec's "kernel-issued caps", each unit cap encodes its
//! identity (meter id, quota id) in `regs[0]` — InstanceCap no longer
//! has a free-standing `content_hash` field, so identity rides on
//! observable state. Kernel caps are immutable by convention
//! (userspace never invokes them via PVM), so `regs[0]` is stable.

use javm::{KernelImage, kernel_image_hash};
use javm_cap::image::Image;
use javm_cap::{CNodeCap, CacheDirectory, Cap, CapHash, CapHashOrRef, NUM_REGS, SlotKey};

use crate::abi;
use crate::error::KernelError;
use crate::state::State;

/// Output of `genesis`: the initial σ together with hashes identifying
/// the chain Image, root cnode, and chain Instance inside the cache.
pub struct Genesis {
    pub state: State,
    pub chain_instance_hash: CapHash,
    pub chain_image_hash: CapHash,
    pub root_cnode_hash: CapHash,
}

/// Mint and publish a kernel-issued unit cap into the cache. The
/// kernel-image label drives `image_hash_chain`; `id` encodes the
/// runtime identity (meter id, quota id, etc.) into `regs[0]`. Returns
/// the published cap's hash. The placeholder image blob is shared
/// across all kernel unit caps and resolved at publish time.
fn publish_kernel_unit_cap(
    cache: &mut CacheDirectory,
    image: KernelImage,
    placeholder_image_hash: CapHash,
    empty_cnode_hash: CapHash,
    id: u64,
) -> Result<CapHash, KernelError> {
    let mut regs = [0u64; NUM_REGS];
    regs[0] = id;
    let cap = Cap::instance_with_mem(
        kernel_image_hash(image),
        placeholder_image_hash,
        empty_cnode_hash,
        javm_cap::DataCap::empty(),
        regs,
        0,
        0,
    );
    Ok(cache.put_cap(&cap)?)
}

/// Stateless variant: no runtime identity (`regs[0] = 0`). Used for
/// factory and host-entry kernel caps where every chain Instance sees
/// the same well-known cap.
fn publish_kernel_stateless_cap(
    cache: &mut CacheDirectory,
    image: KernelImage,
    placeholder_image_hash: CapHash,
    empty_cnode_hash: CapHash,
) -> Result<CapHash, KernelError> {
    publish_kernel_unit_cap(cache, image, placeholder_image_hash, empty_cnode_hash, 0)
}

/// Construct chain genesis from a chain Image.
///
/// Publishes the chain image, the kernel-issued unit caps, the root
/// cnode (a variable-capacity `CNodeCap`, bounded by storage quota —
/// populated with kernel caps at `abi::BARE_*` slots plus pinned/initial
/// slot data caps from the image), and the chain Instance into σ. Returns
/// hashes for downstream callers.
pub fn genesis(chain_image: Image) -> Result<Genesis, KernelError> {
    let mut state = State::new();

    // 1. Build Cap::Data for each pinned/initial slot in the chain
    //    image; remember each slot's content hash so the Image can
    //    reference them, and so the root cnode can bind to them later.
    use javm_cap::image::PinnedCap;
    let mut chain_pinned_hashes: Vec<(SlotKey, CapHash)> = Vec::new();
    let mut chain_initial_hashes: Vec<(SlotKey, CapHash)> = Vec::new();
    for (slot, pinned) in &chain_image.pinned_slots {
        let h = match pinned {
            PinnedCap::Data { content, size } => state
                .caps
                .put_cap(&Cap::data_inline_with_size(content, *size))?,
            PinnedCap::Image { content_hash } => *content_hash,
        };
        chain_pinned_hashes.push((slot.clone(), h));
    }
    for (slot, init) in &chain_image.initial_slots {
        let h = state
            .caps
            .put_cap(&Cap::data_inline_with_size(&init.content, init.size))?;
        chain_initial_hashes.push((slot.clone(), h));
    }

    // 2. Publish the chain Image referencing the slot data by hash.
    let chain_image_hash = state.caps.put_cap(&Cap::image_with_slots(
        &chain_image,
        &chain_pinned_hashes,
        &chain_initial_hashes,
    )?)?;

    // 3. A shared placeholder Image cap referenced by all kernel-issued
    //    Instance caps. Using a tiny but well-formed Image (1 byte of
    //    code) sidesteps the image-cap validation (which only requires a
    //    non-empty code region) while keeping kernel caps content-
    //    hashable in a stable way. The same hash is reused for every
    //    kernel unit.
    let placeholder_image_hash = state.caps.put_cap(&Cap::image_with_slots(
        &placeholder_kernel_image(),
        &[],
        &[],
    )?)?;

    // 4. A shared empty cnode for kernel-issued Instance caps. They
    //    never invoke any of their own slots; the empty cnode keeps
    //    them well-formed.
    let empty_cnode_hash = state.caps.put_cap(&Cap::empty_cnode())?;

    // 5. Publish each kernel-issued unit cap.
    let gas_hash = publish_kernel_unit_cap(
        &mut state.caps,
        KernelImage::Gas,
        placeholder_image_hash,
        empty_cnode_hash,
        0,
    )?;
    let quota_hash = publish_kernel_unit_cap(
        &mut state.caps,
        KernelImage::Quota,
        placeholder_image_hash,
        empty_cnode_hash,
        0,
    )?;
    let yield_catcher_hash = publish_kernel_stateless_cap(
        &mut state.caps,
        KernelImage::YieldCatcher,
        placeholder_image_hash,
        empty_cnode_hash,
    )?;
    let set_gas_meter_hash = publish_kernel_stateless_cap(
        &mut state.caps,
        KernelImage::SetGasMeter,
        placeholder_image_hash,
        empty_cnode_hash,
    )?;
    let set_storage_quota_hash = publish_kernel_stateless_cap(
        &mut state.caps,
        KernelImage::SetStorageQuota,
        placeholder_image_hash,
        empty_cnode_hash,
    )?;
    let mint_gas_hash = publish_kernel_stateless_cap(
        &mut state.caps,
        KernelImage::MintGas,
        placeholder_image_hash,
        empty_cnode_hash,
    )?;
    let mint_quota_hash = publish_kernel_stateless_cap(
        &mut state.caps,
        KernelImage::MintQuota,
        placeholder_image_hash,
        empty_cnode_hash,
    )?;
    let create_yc_hash = publish_kernel_stateless_cap(
        &mut state.caps,
        KernelImage::CreateYieldCatcher,
        placeholder_image_hash,
        empty_cnode_hash,
    )?;
    let host_open_hash = publish_kernel_stateless_cap(
        &mut state.caps,
        KernelImage::HostOpen,
        placeholder_image_hash,
        empty_cnode_hash,
    )?;
    let host_save_hash = publish_kernel_stateless_cap(
        &mut state.caps,
        KernelImage::HostSave,
        placeholder_image_hash,
        empty_cnode_hash,
    )?;

    // 6. Build the chain's root cnode entries. Kernel caps go at the
    //    well-known abi::BARE_* slots; pinned/initial slot data caps
    //    are republished alongside (they were also republished by
    //    chain image step above, but the cnode references them by hash
    //    so we just locate the hashes).
    let mut entries: Vec<(SlotKey, CapHashOrRef)> = vec![
        (
            SlotKey::from(abi::BARE_GAS_SLOT),
            CapHashOrRef::Hash(gas_hash),
        ),
        (
            SlotKey::from(abi::BARE_QUOTA_SLOT),
            CapHashOrRef::Hash(quota_hash),
        ),
        (
            SlotKey::from(abi::BARE_YIELD_CATCHER_SLOT),
            CapHashOrRef::Hash(yield_catcher_hash),
        ),
        (
            SlotKey::from(abi::BARE_SET_GAS_METER_SLOT),
            CapHashOrRef::Hash(set_gas_meter_hash),
        ),
        (
            SlotKey::from(abi::BARE_SET_STORAGE_QUOTA_SLOT),
            CapHashOrRef::Hash(set_storage_quota_hash),
        ),
        (
            SlotKey::from(abi::BARE_MINT_GAS_SLOT),
            CapHashOrRef::Hash(mint_gas_hash),
        ),
        (
            SlotKey::from(abi::BARE_MINT_QUOTA_SLOT),
            CapHashOrRef::Hash(mint_quota_hash),
        ),
        (
            SlotKey::from(abi::BARE_CREATE_YIELD_CATCHER_SLOT),
            CapHashOrRef::Hash(create_yc_hash),
        ),
        (
            SlotKey::from(abi::BARE_HOST_OPEN_SLOT),
            CapHashOrRef::Hash(host_open_hash),
        ),
        (
            SlotKey::from(abi::BARE_HOST_SAVE_SLOT),
            CapHashOrRef::Hash(host_save_hash),
        ),
    ];

    // Pinned + initial slots: the hashes were already recorded above
    // (step 1) when we built the Cap::Data blobs. Reuse them directly.
    for (slot, h) in &chain_pinned_hashes {
        entries.push((slot.clone(), CapHashOrRef::Hash(*h)));
    }
    for (slot, h) in &chain_initial_hashes {
        entries.push((slot.clone(), CapHashOrRef::Hash(*h)));
    }

    // 7. Publish the root cnode.
    let root_cnode_hash = {
        let mut cnode = CNodeCap::new();
        for (slot, target) in &entries {
            cnode
                .set(slot, Some(target.clone()))
                .map_err(KernelError::from)?;
        }
        state.caps.put_cap(&Cap::CNode(cnode))?
    };

    // 8. Build the chain Instance's memory image from the image's memory
    //    mappings via the canonical `Image::instance_mem_backing()` (every
    //    mapping's source content folded at its offset above DATA_BASE).
    let chain_mem = chain_image.instance_mem_backing();

    // 9. Publish the chain Instance. `image_hash_chain` mirrors the
    //    image's content hash directly at genesis (no prior chain).
    //    `regs` start at zeros (chain doesn't have a unit-id; events
    //    drive it via cnode slot[0]).
    let chain_instance_hash = state.caps.put_cap(&Cap::instance_with_mem(
        chain_image_hash,
        chain_image_hash,
        root_cnode_hash,
        chain_mem,
        [0u64; NUM_REGS],
        0,
        0,
    ))?;

    Ok(Genesis {
        state,
        chain_instance_hash,
        chain_image_hash,
        root_cnode_hash,
    })
}

// Instance memory overlays are derived by `Image::data_overlays()` in
// javm-cap — the single source of truth shared with the recompiler
// bench harness and the conformance oracle.

/// A minimal well-formed Image used as a placeholder for kernel-
/// issued unit caps. The image is never actually invoked — kernel
/// caps short-circuit at the host-call layer.
fn placeholder_kernel_image() -> Image {
    use std::collections::BTreeMap;
    Image {
        // Single TRAP byte. Never actually invoked: kernel caps
        // short-circuit at the host-call layer.
        code: vec![0u8],
        endpoints: BTreeMap::new(),
        memory_mappings: Vec::new(),
        pinned_slots: BTreeMap::new(),
        initial_slots: BTreeMap::new(),
        yield_marker_slot: None,
    }
}
