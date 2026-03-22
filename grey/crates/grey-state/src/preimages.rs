//! Preimage integration sub-transition (Section 12, eq 12.35-12.38).
//!
//! Processes preimage lookups submitted in the block extrinsic.
//! Each preimage provides data for a previously solicited (hash, length) request.

use grey_types::{Hash, ServiceId, Timeslot};
use std::collections::BTreeMap;

/// Error type for preimage validation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PreimageError {
    PreimagesNotSortedUnique,
    PreimageUnneeded,
}

impl PreimageError {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::PreimagesNotSortedUnique => "preimages_not_sorted_unique",
            Self::PreimageUnneeded => "preimage_unneeded",
        }
    }
}

/// Per-service preimage state (preimage-relevant subset of service account).
pub struct PreimageAccountData {
    /// p: Preimage blobs (hash → data).
    pub blobs: BTreeMap<Hash, Vec<u8>>,
    /// l: Preimage requests ((hash, length) → timeslots).
    pub requests: BTreeMap<(Hash, u32), Vec<Timeslot>>,
}

/// Per-service statistics output from preimage processing.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct PreimageServiceRecord {
    pub provided_count: u32,
    pub provided_size: u64,
}

/// Apply the preimage integration sub-transition.
///
/// Validates and integrates preimage data into service accounts.
/// Returns per-service statistics on success, or an error.
pub fn process_preimages(
    accounts: &mut BTreeMap<ServiceId, PreimageAccountData>,
    preimages: &[(ServiceId, Vec<u8>)],
    current_timeslot: Timeslot,
) -> Result<BTreeMap<ServiceId, PreimageServiceRecord>, PreimageError> {
    // Compute hashes for all preimages upfront.
    let hashed: Vec<(ServiceId, Hash, u32)> = preimages
        .iter()
        .map(|(sid, blob)| (*sid, grey_crypto::blake2b_256(blob), blob.len() as u32))
        .collect();

    // eq 12.37: Each preimage must be "needed":
    //   1. A request (hash, length) exists in the service account
    //   2. The blob is not already stored (hash not in blobs)
    for (sid, hash, length) in &hashed {
        let account = accounts
            .get(sid)
            .ok_or(PreimageError::PreimageUnneeded)?;

        if !account.requests.contains_key(&(*hash, *length)) {
            return Err(PreimageError::PreimageUnneeded);
        }

        if account.blobs.contains_key(hash) {
            return Err(PreimageError::PreimageUnneeded);
        }
    }

    // eq 12.36: Preimages must be sorted by (service_id, hash(blob)), no duplicates.
    for w in hashed.windows(2) {
        let (s0, h0, _) = &w[0];
        let (s1, h1, _) = &w[1];
        if (s0, h0) >= (s1, h1) {
            return Err(PreimageError::PreimagesNotSortedUnique);
        }
    }

    // eq 12.38: Apply changes — store blobs, update request timeslots, track stats.
    let mut stats: BTreeMap<ServiceId, PreimageServiceRecord> = BTreeMap::new();

    for (sid, blob) in preimages {
        let hash = grey_crypto::blake2b_256(blob);
        let length = blob.len() as u32;

        let account = accounts.get_mut(sid).unwrap();

        // Store blob
        account.blobs.insert(hash, blob.clone());

        // Update request: record the timeslot when preimage was provided
        if let Some(timeslots) = account.requests.get_mut(&(hash, length)) {
            *timeslots = vec![current_timeslot];
        }

        // Update per-service statistics
        let record = stats.entry(*sid).or_default();
        record.provided_count += 1;
        record.provided_size += blob.len() as u64;
    }

    Ok(stats)
}
