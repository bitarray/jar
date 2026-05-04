//! Capabilities — the `RegCap` enum (cap shapes occupying
//! `vault.slots`), the `ProtocolCap` enum (jar-kernel's impl of
//! `javm::ProtocolCap`), and the `Cap` alias (the complete Frame cap
//! type `javm::Cap<ProtocolCap>` — what's actually in a cap-table cell).
//!
//! The persistence boundary is explicit:
//! - every `RegCap` embeds into a Frame [`Cap`];
//! - only Frame caps that carry `ProtocolCap::Reg(_)` persist back to
//!   `RegCap`;
//! - executable `Cap::Code` is frame-only and distinct from
//!   persistent `RegCap::Code`.

pub mod protocol;
pub mod regcap;

pub use protocol::{AttestCursor, KERNEL_CAP_SLOT, ProtocolCap};
pub use regcap::*;

/// The complete Frame cap type — a cap-table cell holding any of
/// `Empty`, `Code`, `Data`, `FrameRef`, or `Protocol(ProtocolCap)`.
/// Pattern-match on this when inspecting slot contents; reach for
/// `ProtocolCap` only when you've already destructured the `Protocol`
/// arm.
pub type Cap = javm::cap::Cap<ProtocolCap>;

/// Error returned when attempting to persist a Frame cap whose referent
/// is invocation-local or otherwise not a Vault-storable `RegCap`.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct NonPersistableCap;

impl core::fmt::Display for NonPersistableCap {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("frame cap cannot be persisted as RegCap")
    }
}

impl std::error::Error for NonPersistableCap {}

impl From<RegCap> for Cap {
    fn from(cap: RegCap) -> Self {
        Cap::Protocol(ProtocolCap::Reg(cap))
    }
}

impl TryFrom<&Cap> for RegCap {
    type Error = NonPersistableCap;

    fn try_from(cap: &Cap) -> Result<Self, Self::Error> {
        match cap {
            Cap::Protocol(ProtocolCap::Reg(reg)) => Ok(reg.clone()),
            _ => Err(NonPersistableCap),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::{Hash, KeyId, VaultId};

    fn sample_reg_caps() -> Vec<RegCap> {
        vec![
            RegCap::VaultRef(VaultRefCap {
                vault_id: VaultId(7),
                rights: VaultRights::ALL,
            }),
            RegCap::Code(CodeCap {
                code_id: CodeId([1; 32]),
                byte_count: 64,
            }),
            RegCap::File(FileCap {
                file_id: FileId(9),
                byte_count: 128,
            }),
            RegCap::ImageRef(ImageRefCap {
                image_id: ImageId(3),
                rights: ImageRefRights::ALL,
            }),
            RegCap::Resource(ResourceCap(ResourceKind::CreateVault { quota_pages: 4 })),
            RegCap::StorageQuota(QuotaCap {
                quota_id: QuotaId(5),
            }),
        ]
    }

    #[test]
    fn every_regcap_embeds_and_roundtrips_through_frame_cap() {
        for reg in sample_reg_caps() {
            let frame: Cap = reg.clone().into();
            assert_eq!(RegCap::try_from(&frame), Ok(reg));
        }
    }

    #[test]
    fn frame_only_caps_reject_persistence() {
        let frame_only = [
            Cap::Protocol(ProtocolCap::SelfId(SelfCap {
                vault_id: VaultId(1),
            })),
            Cap::Protocol(ProtocolCap::CallerKernel(CallerKernelCap {
                role: crate::types::KernelRole::Verify,
            })),
            Cap::Protocol(ProtocolCap::Attestation(AttestationCap {
                key: KeyId::from_bytes(b"k"),
                blob_hash: Hash::ZERO,
            })),
            Cap::Untyped(javm::cap::UntypedCap::new(1)),
            Cap::Data(javm::cap::DataCap::new(0, 1)),
            Cap::Gas(javm::cap::GasCap { remaining: 1 }),
            Cap::CNode(Box::<javm::cap::CapTable<ProtocolCap>>::default()),
        ];

        for cap in &frame_only {
            assert_eq!(RegCap::try_from(cap), Err(NonPersistableCap));
        }
    }
}
