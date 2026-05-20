//! σ — the v3 chain state.
//!
//! Stage C.2 lands the canonical state shape, plus a deterministic
//! state-root computed as `blake2b256(SCALE_encode(σ))`. Per the
//! user's direction the initial impl uses simple raw hashing rather
//! than per-registry composed BMTs (Stage 6 optimization).
//!
//! Components:
//! - `data_blobs` — content-addressed data with refcount.
//! - `code_blobs` — Image bytecode keyed by content hash.
//! - `vaults`     — chain-resident `Cap::Instance`s.
//! - `validators` — PoA validator key set (placeholder for now).
//! - `counters`   — monotonic id allocators.
//!
//! Kernel-internal tables (`gas_meters`, `storage_quotas`,
//! `yield_catchers`) are NOT in σ — they live in
//! [`crate::SigmaKernelAssist`] and are ephemeral per-block.

use scale::Encode;
use std::collections::BTreeMap;

use javm_cap::legacy::InstanceCap;
use javm_cap::{Blake2b256, CapHash, Hash};

/// SCALE-encodable shadow of `javm_cap::legacy::InstanceCap`. Stored in σ
/// instead of the cap struct directly so we can derive Encode/Decode
/// without modifying javm-cap.
#[derive(Clone, Debug, Default, PartialEq, Eq, Encode, scale::Decode)]
pub struct VaultRecord {
    pub image_hash_chain: CapHash,
    pub content_hash: CapHash,
}

impl From<InstanceCap> for VaultRecord {
    fn from(ic: InstanceCap) -> Self {
        Self {
            image_hash_chain: ic.image_hash_chain,
            content_hash: ic.content_hash,
        }
    }
}

impl From<VaultRecord> for InstanceCap {
    fn from(v: VaultRecord) -> Self {
        Self {
            image_hash_chain: v.image_hash_chain,
            content_hash: v.content_hash,
        }
    }
}

/// Monotonic file identifier in `data_blobs`.
pub type FileId = u64;
/// Monotonic image (code) identifier in `code_blobs`.
pub type CodeId = u64;
/// Monotonic vault (chain Instance) identifier.
pub type VaultId = u64;
/// PoA validator key (placeholder — 32-byte public key).
pub type ValidatorKey = [u8; 32];

/// A row in the `data_blobs` registry.
///
/// `refcount` tracks how many σ-side references (FileCaps held in
/// vault cnodes, etc.) point at this blob. When it drops to 0 the
/// row is removed and the StorageQuota that paid for it is
/// refunded (Stage C.7).
#[derive(Clone, Debug, PartialEq, Eq, Encode, scale::Decode)]
pub struct DataBlob {
    pub content_hash: CapHash,
    pub size: u64,
    pub refcount: u32,
    /// The StorageQuota that paid for this blob, for refund-on-drop
    /// accounting. (Stage C.7 wires this; for now writers record but
    /// no enforcement reads it.)
    pub backing_quota: u64,
}

/// Monotonic id counters for σ-resident registries.
#[derive(Clone, Debug, Default, PartialEq, Eq, Encode, scale::Decode)]
pub struct IdCounters {
    pub next_file_id: FileId,
    pub next_code_id: CodeId,
    pub next_vault_id: VaultId,
}

impl IdCounters {
    pub fn allocate_file_id(&mut self) -> FileId {
        let id = self.next_file_id;
        self.next_file_id += 1;
        id
    }
    pub fn allocate_code_id(&mut self) -> CodeId {
        let id = self.next_code_id;
        self.next_code_id += 1;
        id
    }
    pub fn allocate_vault_id(&mut self) -> VaultId {
        let id = self.next_vault_id;
        self.next_vault_id += 1;
        id
    }
}

/// The chain's σ-resident state.
///
/// Sort-stable encoding: all `BTreeMap`s iterate in sorted-key order
/// (deterministic). Field order in the SCALE encoding is fixed by
/// the struct declaration.
#[derive(Clone, Debug, Default, PartialEq, Eq, Encode, scale::Decode)]
pub struct State {
    /// Per-file metadata (refcount, backing quota). The bytes themselves
    /// live in `data_payloads` (keyed by content_hash so multiple
    /// FileBlobs sharing the same content dedup naturally).
    pub data_blobs: BTreeMap<FileId, DataBlob>,
    /// Canonical content-addressed byte payloads. Lookup target for
    /// `KernelAssist::data_lookup`; populated by `data_store` and
    /// by HALT-time write-back.
    pub data_payloads: BTreeMap<CapHash, Vec<u8>>,
    pub code_blobs: BTreeMap<CodeId, Vec<u8>>,
    pub vaults: BTreeMap<VaultId, VaultRecord>,
    pub validators: Vec<ValidatorKey>,
    pub counters: IdCounters,
}

impl State {
    pub fn new() -> Self {
        Self::default()
    }
}

/// State-root: `blake2b256(SCALE_encode(σ))`.
///
/// Stage 6 will replace this with a per-registry composed BMT for
/// incremental updates. For the initial v3 impl, simple raw hash
/// is correct and trivially deterministic.
pub fn state_root(state: &State) -> CapHash {
    Blake2b256::hash(&state.encode())
}

#[cfg(test)]
mod tests {
    use super::*;
    use scale::Decode;

    #[test]
    fn empty_state_root_is_deterministic() {
        let s1 = State::new();
        let s2 = State::new();
        assert_eq!(state_root(&s1), state_root(&s2));
    }

    #[test]
    fn state_round_trip_via_scale() {
        let mut s = State::new();
        s.data_blobs.insert(
            1,
            DataBlob {
                content_hash: [0xAA; 32],
                size: 64,
                refcount: 1,
                backing_quota: 0,
            },
        );
        s.code_blobs.insert(1, vec![1, 2, 3, 4]);
        s.counters.next_file_id = 2;
        let bytes = s.encode();
        let (decoded, n) = State::decode(&bytes).unwrap();
        assert_eq!(n, bytes.len());
        assert_eq!(decoded, s);
    }

    #[test]
    fn state_root_changes_with_insertion() {
        let mut s = State::new();
        let r0 = state_root(&s);
        s.data_blobs.insert(
            1,
            DataBlob {
                content_hash: [0xAA; 32],
                size: 64,
                refcount: 1,
                backing_quota: 0,
            },
        );
        let r1 = state_root(&s);
        assert_ne!(r0, r1);
    }

    #[test]
    fn state_root_invariant_under_insertion_order() {
        // BTreeMap iterates in sorted-key order; inserting in
        // different orders should produce the same encoding (and
        // thus the same state_root).
        let mut s_a = State::new();
        let mut s_b = State::new();
        for (id, byte) in [(3u64, 0xCCu8), (1, 0xAA), (2, 0xBB)] {
            s_a.data_blobs.insert(
                id,
                DataBlob {
                    content_hash: [byte; 32],
                    size: id,
                    refcount: 1,
                    backing_quota: 0,
                },
            );
        }
        for (id, byte) in [(1u64, 0xAAu8), (2, 0xBB), (3, 0xCC)] {
            s_b.data_blobs.insert(
                id,
                DataBlob {
                    content_hash: [byte; 32],
                    size: id,
                    refcount: 1,
                    backing_quota: 0,
                },
            );
        }
        assert_eq!(state_root(&s_a), state_root(&s_b));
    }

    #[test]
    fn id_counters_allocate_monotonically() {
        let mut c = IdCounters::default();
        assert_eq!(c.allocate_file_id(), 0);
        assert_eq!(c.allocate_file_id(), 1);
        assert_eq!(c.allocate_vault_id(), 0);
        assert_eq!(c.next_file_id, 2);
    }
}
