//! Preimage integration sub-transition (Section 12, eq 12.35-12.38).
//!
//! Processes preimage lookups submitted in the block extrinsic.
//! Each preimage provides data for a previously solicited (hash, length) request.

use grey_types::{Hash, ServiceId, Timeslot};
use std::collections::BTreeMap;

stf_error! {
    /// Error type for preimage validation.
    #[derive(Debug, Clone, PartialEq, Eq)]
    pub enum PreimageError {
        PreimagesNotSortedUnique => "preimages_not_sorted_unique",
        PreimageUnneeded => "preimage_unneeded",
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
        let account = accounts.get(sid).ok_or(PreimageError::PreimageUnneeded)?;

        if !account.requests.contains_key(&(*hash, *length)) {
            return Err(PreimageError::PreimageUnneeded);
        }

        if account.blobs.contains_key(hash) {
            return Err(PreimageError::PreimageUnneeded);
        }
    }

    // eq 12.36: Preimages must be sorted by (service_id, hash(blob)), no duplicates.
    if !crate::is_strictly_sorted_by_key(&hashed, |x| (x.0, x.1)) {
        return Err(PreimageError::PreimagesNotSortedUnique);
    }

    // eq 12.38: Apply changes — store blobs, update request timeslots, track stats.
    let mut stats: BTreeMap<ServiceId, PreimageServiceRecord> = BTreeMap::new();

    for ((sid, hash, length), (_, blob)) in hashed.iter().zip(preimages.iter()) {
        let account = accounts.get_mut(sid).unwrap();

        // Store blob
        account.blobs.insert(*hash, blob.clone());

        // Update request: record the timeslot when preimage was provided
        if let Some(timeslots) = account.requests.get_mut(&(*hash, *length)) {
            *timeslots = vec![current_timeslot];
        }

        // Update per-service statistics
        let record = stats.entry(*sid).or_default();
        record.provided_count += 1;
        record.provided_size += blob.len() as u64;
    }

    Ok(stats)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_account(hash: Hash, len: u32) -> PreimageAccountData {
        let mut requests = BTreeMap::new();
        requests.insert((hash, len), vec![0]);
        PreimageAccountData {
            blobs: BTreeMap::new(),
            requests,
        }
    }

    #[test]
    fn test_process_preimages_basic() {
        let blob = b"hello";
        let hash = grey_crypto::blake2b_256(blob);
        let mut accounts = BTreeMap::new();
        accounts.insert(1u32, make_account(hash, blob.len() as u32));

        let result = process_preimages(&mut accounts, &[(1, blob.to_vec())], 10);
        assert!(result.is_ok());
        let stats = result.unwrap();
        assert_eq!(stats[&1].provided_count, 1);
        assert_eq!(stats[&1].provided_size, 5);
        // Blob should be stored
        assert!(accounts[&1].blobs.contains_key(&hash));
    }

    #[test]
    fn test_process_preimages_unneeded_no_request() {
        let mut accounts = BTreeMap::new();
        accounts.insert(
            1,
            PreimageAccountData {
                blobs: BTreeMap::new(),
                requests: BTreeMap::new(), // no requests
            },
        );
        let result = process_preimages(&mut accounts, &[(1, vec![0xAA])], 10);
        assert_eq!(result, Err(PreimageError::PreimageUnneeded));
    }

    #[test]
    fn test_process_preimages_unneeded_already_stored() {
        let blob = b"data";
        let hash = grey_crypto::blake2b_256(blob);
        let mut account = make_account(hash, blob.len() as u32);
        account.blobs.insert(hash, blob.to_vec()); // already stored

        let mut accounts = BTreeMap::new();
        accounts.insert(1, account);

        let result = process_preimages(&mut accounts, &[(1, blob.to_vec())], 10);
        assert_eq!(result, Err(PreimageError::PreimageUnneeded));
    }

    #[test]
    fn test_process_preimages_not_sorted() {
        let blob_a = b"aaa";
        let blob_b = b"bbb";
        let hash_a = grey_crypto::blake2b_256(blob_a);
        let hash_b = grey_crypto::blake2b_256(blob_b);

        let mut accounts = BTreeMap::new();
        let mut account = make_account(hash_a, blob_a.len() as u32);
        account
            .requests
            .insert((hash_b, blob_b.len() as u32), vec![0]);
        accounts.insert(1, account);

        // Submit in wrong order (both for service 1, but hash order wrong)
        let preimages = if hash_a < hash_b {
            vec![(1, blob_b.to_vec()), (1, blob_a.to_vec())]
        } else {
            vec![(1, blob_a.to_vec()), (1, blob_b.to_vec())]
        };
        let result = process_preimages(&mut accounts, &preimages, 10);
        assert_eq!(result, Err(PreimageError::PreimagesNotSortedUnique));
    }

    #[test]
    fn test_process_preimages_unknown_service() {
        let mut accounts = BTreeMap::new();
        // No service 99 in accounts
        let result = process_preimages(&mut accounts, &[(99, vec![0xAA])], 10);
        assert_eq!(result, Err(PreimageError::PreimageUnneeded));
    }

    #[test]
    fn test_process_preimages_empty() {
        let mut accounts = BTreeMap::new();
        let result = process_preimages(&mut accounts, &[], 10);
        assert!(result.is_ok());
        assert!(result.unwrap().is_empty());
    }

    #[test]
    fn test_preimage_error_as_str() {
        assert_eq!(
            PreimageError::PreimagesNotSortedUnique.as_str(),
            "preimages_not_sorted_unique"
        );
        assert_eq!(
            PreimageError::PreimageUnneeded.as_str(),
            "preimage_unneeded"
        );
    }
}

#[cfg(test)]
mod proptests {
    use super::*;
    use proptest::prelude::*;

    proptest! {
        /// Empty preimages always succeed regardless of account state.
        #[test]
        fn empty_preimages_always_ok(timeslot in 0u32..10000) {
            let mut accounts = BTreeMap::new();
            let result = process_preimages(&mut accounts, &[], timeslot);
            prop_assert!(result.is_ok());
            prop_assert!(result.unwrap().is_empty());
        }

        /// Unknown service always returns PreimageUnneeded.
        #[test]
        fn unknown_service_rejected(
            service_id in 0u32..1000,
            blob in proptest::collection::vec(any::<u8>(), 1..50),
            timeslot in 0u32..10000,
        ) {
            let mut accounts = BTreeMap::new();
            // No accounts at all
            let result = process_preimages(&mut accounts, &[(service_id, blob)], timeslot);
            prop_assert_eq!(result, Err(PreimageError::PreimageUnneeded));
        }

        /// A valid preimage stores the blob and returns correct stats.
        #[test]
        fn valid_preimage_stored_and_counted(
            service_id in 0u32..100,
            blob in proptest::collection::vec(any::<u8>(), 1..100),
            timeslot in 1u32..10000,
        ) {
            let hash = grey_crypto::blake2b_256(&blob);
            let len = blob.len() as u32;
            let mut requests = BTreeMap::new();
            requests.insert((hash, len), vec![0]);
            let account = PreimageAccountData {
                blobs: BTreeMap::new(),
                requests,
            };
            let mut accounts = BTreeMap::new();
            accounts.insert(service_id, account);

            let blob_len = blob.len() as u64;
            let result = process_preimages(&mut accounts, &[(service_id, blob.clone())], timeslot);
            prop_assert!(result.is_ok());

            let stats = result.unwrap();
            prop_assert_eq!(stats[&service_id].provided_count, 1);
            prop_assert_eq!(stats[&service_id].provided_size, blob_len);

            // Blob should be stored in account
            prop_assert!(accounts[&service_id].blobs.contains_key(&hash));
            prop_assert_eq!(&accounts[&service_id].blobs[&hash], &blob);
        }

        /// Already-stored blob returns PreimageUnneeded.
        #[test]
        fn already_stored_rejected(
            service_id in 0u32..100,
            blob in proptest::collection::vec(any::<u8>(), 1..50),
            timeslot in 0u32..10000,
        ) {
            let hash = grey_crypto::blake2b_256(&blob);
            let len = blob.len() as u32;
            let mut requests = BTreeMap::new();
            requests.insert((hash, len), vec![0]);
            let mut blobs = BTreeMap::new();
            blobs.insert(hash, blob.clone()); // already stored
            let account = PreimageAccountData { blobs, requests };
            let mut accounts = BTreeMap::new();
            accounts.insert(service_id, account);

            let result = process_preimages(&mut accounts, &[(service_id, blob)], timeslot);
            prop_assert_eq!(result, Err(PreimageError::PreimageUnneeded));
        }

        /// No request for the blob's hash → PreimageUnneeded.
        #[test]
        fn no_request_rejected(
            service_id in 0u32..100,
            blob in proptest::collection::vec(any::<u8>(), 1..50),
            timeslot in 0u32..10000,
        ) {
            let account = PreimageAccountData {
                blobs: BTreeMap::new(),
                requests: BTreeMap::new(), // no requests
            };
            let mut accounts = BTreeMap::new();
            accounts.insert(service_id, account);

            let result = process_preimages(&mut accounts, &[(service_id, blob)], timeslot);
            prop_assert_eq!(result, Err(PreimageError::PreimageUnneeded));
        }
    }
}
