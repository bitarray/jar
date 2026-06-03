//! Kernel-assisted Image registry.
//!
//! Certain `Cap::Instance` values are recognized by their `image_hash_chain`
//! as kernel-internal (Gas/Quota unit handles, factories, yield markers). The
//! kernel short-circuits their state access — no bytecode dispatch. From
//! userspace they still look like ordinary `Cap::Instance` values.
//!
//! This registry lives in `javm-cap` (not the engine crates) so every layer —
//! the recompiler/interpreter host, the chain genesis, the fuzz harness — agrees
//! on the well-known `image_hash` for each kernel Image. The hashes are
//! `Blake2b256(b"kernel:<name>")` placeholders; a later chain-genesis pass can
//! finalize the canonical encoding (the labels are the source of truth).

use crate::cap::CapHash;
use crate::hash::{Blake2b256, Hash};

/// Identifies which kernel-assisted Image a given `image_hash_chain` refers to.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum KernelImage {
    GasMeter,
    StorageQuota,
    YieldCatcher,
    /// Per-Instance `Gas{meter_key}` unit handle. State: a `meter_key: Key`
    /// packed into the handle's registers (see
    /// [`crate::slot::key_to_regs`]).
    Gas,
    /// Per-Instance `Quota{quota_key}` unit handle.
    Quota,
    SetGasMeter,
    SetStorageQuota,
    MintGas,
    MintQuota,
    CreateYieldCatcher,
    OogMarker,
    StorageExhaustedMarker,
    /// Per-Instance `File{file_id}` handle.
    File,
    /// Per-Instance HostOpen handle.
    HostOpen,
    /// Per-Instance HostSave handle.
    HostSave,
}

/// All kernel Images, for registry iteration.
pub const ALL_KERNEL_IMAGES: [KernelImage; 15] = [
    KernelImage::GasMeter,
    KernelImage::StorageQuota,
    KernelImage::YieldCatcher,
    KernelImage::Gas,
    KernelImage::Quota,
    KernelImage::SetGasMeter,
    KernelImage::SetStorageQuota,
    KernelImage::MintGas,
    KernelImage::MintQuota,
    KernelImage::CreateYieldCatcher,
    KernelImage::OogMarker,
    KernelImage::StorageExhaustedMarker,
    KernelImage::File,
    KernelImage::HostOpen,
    KernelImage::HostSave,
];

const fn const_kernel_image_label(kind: KernelImage) -> &'static [u8] {
    match kind {
        KernelImage::GasMeter => b"kernel:gasmeter",
        KernelImage::StorageQuota => b"kernel:storagequota",
        KernelImage::YieldCatcher => b"kernel:yieldcatcher",
        KernelImage::Gas => b"kernel:gas",
        KernelImage::Quota => b"kernel:quota",
        KernelImage::SetGasMeter => b"kernel:set_gas_meter",
        KernelImage::SetStorageQuota => b"kernel:set_storage_quota",
        KernelImage::MintGas => b"kernel:mint_gas",
        KernelImage::MintQuota => b"kernel:mint_quota",
        KernelImage::CreateYieldCatcher => b"kernel:create_yield_catcher",
        KernelImage::OogMarker => b"kernel:oog_marker",
        KernelImage::StorageExhaustedMarker => b"kernel:storage_exhausted_marker",
        KernelImage::File => b"kernel:file",
        KernelImage::HostOpen => b"kernel:host_open",
        KernelImage::HostSave => b"kernel:host_save",
    }
}

/// The well-known `image_hash` for a kernel-assisted Image.
pub fn kernel_image_hash(kind: KernelImage) -> CapHash {
    Blake2b256::hash(const_kernel_image_label(kind))
}

/// Look up a kernel-assisted Image by its `image_hash_chain`. `None` for a
/// user Image (the common case). Linear scan over ~15 entries — only called at
/// Instance entry / yield routing, not on the hot path.
pub fn recognize_kernel_image(hash: CapHash) -> Option<KernelImage> {
    ALL_KERNEL_IMAGES
        .into_iter()
        .find(|kind| kernel_image_hash(*kind) == hash)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hashes_are_deterministic_and_distinct() {
        for (i, a) in ALL_KERNEL_IMAGES.iter().enumerate() {
            assert_eq!(kernel_image_hash(*a), kernel_image_hash(*a));
            for b in &ALL_KERNEL_IMAGES[i + 1..] {
                assert_ne!(
                    kernel_image_hash(*a),
                    kernel_image_hash(*b),
                    "{a:?} vs {b:?}"
                );
            }
        }
    }

    #[test]
    fn recognize_round_trips_and_rejects_unknown() {
        assert_eq!(
            recognize_kernel_image(kernel_image_hash(KernelImage::Gas)),
            Some(KernelImage::Gas)
        );
        assert_eq!(
            recognize_kernel_image(Blake2b256::hash(b"user:image")),
            None
        );
    }
}
