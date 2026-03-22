//! Recent block history sub-transition (Section 7, eq 7.5-7.8).
//!
//! Maintains the sliding window of recent block information.

use grey_types::constants::RECENT_HISTORY_SIZE;
use grey_types::state::{RecentBlockInfo, RecentBlocks};
use grey_types::Hash;
use std::collections::BTreeMap;

/// Input data for the history sub-transition.
pub struct HistoryInput {
    /// Hash of the current block header.
    pub header_hash: Hash,
    /// State root of the parent block.
    pub parent_state_root: Hash,
    /// Accumulation-result root for this block.
    pub accumulate_root: Hash,
    /// Work packages reported in this block: (package_hash, exports_root).
    pub work_packages: Vec<(Hash, Hash)>,
}

/// Apply the history sub-transition.
///
/// Updates the recent block history β by appending new block info
/// and maintaining the sliding window of H entries.
/// Also updates the MMR peaks for the accumulation log.
pub fn update_history(recent_blocks: &mut RecentBlocks, input: &HistoryInput) {
    // Fix up the state_root of the previous entry (eq 7.5)
    // The previous block's state_root wasn't known at the time, so we set it now.
    if let Some(last) = recent_blocks.headers.last_mut() {
        last.state_root = input.parent_state_root;
    }

    // Update MMR peaks (eq 7.7): append the new accumulation root using Keccak
    mmr_append(&mut recent_blocks.accumulation_log, input.accumulate_root);

    // Compute MMR super-peak (eq E.10) for the beefy_root
    let beefy_root = mmr_super_peak(&recent_blocks.accumulation_log);

    // Build reported packages map
    let mut reported_packages = BTreeMap::new();
    for (hash, exports_root) in &input.work_packages {
        reported_packages.insert(*hash, *exports_root);
    }

    // Append new block info (eq 7.8)
    let info = RecentBlockInfo {
        header_hash: input.header_hash,
        state_root: Hash::ZERO, // Will be fixed by the next block
        accumulation_root: beefy_root,
        reported_packages,
    };

    recent_blocks.headers.push(info);

    // Keep only the last H entries
    while recent_blocks.headers.len() > RECENT_HISTORY_SIZE {
        recent_blocks.headers.remove(0);
    }
}

/// Append a leaf to a Merkle Mountain Range (eq E.8).
///
/// Uses Keccak-256 for hashing as specified in Section 7 (eq 7.7).
fn mmr_append(peaks: &mut Vec<Option<Hash>>, leaf: Hash) {
    let mut carry = leaf;
    let mut i = 0;

    loop {
        if i >= peaks.len() {
            peaks.push(Some(carry));
            break;
        }

        match peaks[i] {
            None => {
                peaks[i] = Some(carry);
                break;
            }
            Some(existing) => {
                // Merge: H_K(existing || carry)
                let mut combined = [0u8; 64];
                combined[..32].copy_from_slice(&existing.0);
                combined[32..].copy_from_slice(&carry.0);
                carry = grey_crypto::keccak_256(&combined);
                peaks[i] = None;
                i += 1;
            }
        }
    }
}

/// Compute the MMR super-peak MR (eq E.10).
///
/// Filters out None entries from the peaks, then recursively combines:
/// - MR([]) = H_0 (zero hash)
/// - MR([h]) = h
/// - MR(h) = H_K("peak" || MR(h[..n-1]) || h[n-1])
pub fn mmr_super_peak(peaks: &[Option<Hash>]) -> Hash {
    // Collect non-None peaks
    let non_none: Vec<Hash> = peaks.iter().filter_map(|p| *p).collect();
    mr_recursive(&non_none)
}

fn mr_recursive(hashes: &[Hash]) -> Hash {
    match hashes.len() {
        0 => Hash::ZERO,
        1 => hashes[0],
        _ => {
            let last = hashes[hashes.len() - 1];
            let rest_root = mr_recursive(&hashes[..hashes.len() - 1]);
            // H_K("peak" || MR(rest) || last)
            let mut data = Vec::with_capacity(4 + 32 + 32);
            data.extend_from_slice(b"peak");
            data.extend_from_slice(&rest_root.0);
            data.extend_from_slice(&last.0);
            grey_crypto::keccak_256(&data)
        }
    }
}
