//! Reed-Solomon erasure coding in GF(2^16) for JAM data availability (Appendix H).
//!
//! Uses the Lin-Chung-Han 2014 algorithm with Cantor basis FFT via `reed-solomon-simd`.
//! Rate: configurable (342:1023 for full spec, 2:6 for tiny spec).

/// Erasure coding parameters for a specific protocol variant.
#[derive(Clone, Copy, Debug)]
pub struct ErasureParams {
    /// Number of original (systematic) data shards.
    pub data_shards: usize,
    /// Total number of shards (data + recovery).
    pub total_shards: usize,
}

impl ErasureParams {
    /// Full specification: 342 data shards, 1023 total (V=1023 validators).
    pub const FULL: Self = Self {
        data_shards: 342,
        total_shards: 1023,
    };

    /// Tiny specification: 2 data shards, 6 total (V=6 validators).
    pub const TINY: Self = Self {
        data_shards: 2,
        total_shards: 6,
    };

    /// Number of recovery (parity) shards.
    pub fn recovery_shards(&self) -> usize {
        self.total_shards - self.data_shards
    }

    /// Size of one piece in bytes (data_shards * 2).
    pub fn piece_size(&self) -> usize {
        self.data_shards * 2
    }
}

/// Errors from erasure coding operations.
#[derive(Debug, thiserror::Error)]
pub enum ErasureError {
    /// Not enough chunks to recover (need at least data_shards).
    #[error("insufficient chunks: have {have}, need {need}")]
    InsufficientChunks { have: usize, need: usize },
    /// Invalid chunk index (>= total_shards).
    #[error("invalid chunk index: {0}")]
    InvalidIndex(usize),
    /// Chunk size mismatch.
    #[error("chunk size mismatch")]
    SizeMismatch,
    /// RS encoding failed.
    #[error("encoding failed: {0}")]
    EncodingFailed(String),
    /// RS recovery failed.
    #[error("recovery failed: {0}")]
    RecoveryFailed(String),
}

/// Encode a data blob into `total_shards` coded chunks (eq H.4).
///
/// Following the Gray Paper specification:
/// 1. Split data into data_shards chunks of 2k bytes
/// 2. Transpose: view as k rows of data_shards GF(2^16) symbols
/// 3. RS-encode each row independently (data_shards → total_shards symbols)
/// 4. Transpose back: total_shards chunks of k symbols (2k bytes each)
pub fn encode(params: &ErasureParams, data: &[u8]) -> Result<Vec<Vec<u8>>, ErasureError> {
    let piece_size = params.piece_size();
    let k = if data.is_empty() {
        1
    } else {
        data.len().div_ceil(piece_size)
    };
    let padded_len = k * piece_size;

    // Zero-pad data
    let mut padded = data.to_vec();
    padded.resize(padded_len, 0);

    // Step 1: split_{2k}(d) — split into data_shards chunks of 2k bytes
    let shard_bytes = k * 2;
    let data_chunks: Vec<&[u8]> = (0..params.data_shards)
        .map(|i| &padded[i * shard_bytes..(i + 1) * shard_bytes])
        .collect();

    // Steps 2-4: transpose, RS-encode each row, transpose back.
    // Process each of the k symbol positions independently.
    let recovery_count = params.recovery_shards();
    let mut result: Vec<Vec<u8>> = (0..params.total_shards)
        .map(|_| Vec::with_capacity(shard_bytes))
        .collect();

    for sym_pos in 0..k {
        // Extract one 2-byte symbol from each data chunk at this position
        let row: Vec<&[u8]> = data_chunks
            .iter()
            .map(|chunk| &chunk[sym_pos * 2..sym_pos * 2 + 2])
            .collect();

        // RS-encode this row: data_shards symbols → recovery_count parity symbols
        let parity = reed_solomon_simd::encode(params.data_shards, recovery_count, &row)
            .map_err(|e| ErasureError::EncodingFailed(e.to_string()))?;

        // Distribute: data symbols go to shards 0..data_shards,
        // parity symbols go to shards data_shards..total_shards
        for (j, sym) in row.iter().enumerate() {
            result[j].extend_from_slice(sym);
        }
        for (j, sym) in parity.iter().enumerate() {
            result[params.data_shards + j].extend_from_slice(sym);
        }
    }

    Ok(result)
}

/// Recover original data from any `data_shards` of the `total_shards` chunks (eq H.5).
///
/// Each element is `(shard_data, shard_index)` where index is in `0..total_shards`.
/// `original_len` is the length of the original unpadded data.
pub fn recover(
    params: &ErasureParams,
    chunks: &[(Vec<u8>, usize)],
    original_len: usize,
) -> Result<Vec<u8>, ErasureError> {
    if chunks.len() < params.data_shards {
        return Err(ErasureError::InsufficientChunks {
            have: chunks.len(),
            need: params.data_shards,
        });
    }

    for (_, idx) in chunks {
        if *idx >= params.total_shards {
            return Err(ErasureError::InvalidIndex(*idx));
        }
    }

    if chunks.is_empty() {
        return Ok(vec![]);
    }

    let shard_bytes = chunks[0].0.len();
    let k = shard_bytes / 2;
    let piece_size = params.piece_size();

    // Fast path: if all original (data) shards are present, just concatenate
    let all_originals: Option<Vec<&[u8]>> = {
        let mut originals = vec![None; params.data_shards];
        for (data, idx) in chunks {
            if *idx < params.data_shards {
                originals[*idx] = Some(data.as_slice());
            }
        }
        if originals.iter().all(|o| o.is_some()) {
            Some(originals.into_iter().map(|o| o.unwrap()).collect())
        } else {
            None
        }
    };

    let recovered_data_shards: Vec<Vec<u8>>;
    let data_shards_ref: Vec<&[u8]> = if let Some(ref originals) = all_originals {
        originals.clone()
    } else {
        // Recover missing data shards using k independent RS decodings
        recovered_data_shards = recover_data_shards(params, chunks, k)?;
        recovered_data_shards.iter().map(|s| s.as_slice()).collect()
    };

    // Reconstruct data by concatenating data shards (eq H.5).
    // The original split_{2k}(d) produced data_shards contiguous chunks,
    // so recovery is just concatenation in shard order.
    let mut result = Vec::with_capacity(k * piece_size);
    for shard in data_shards_ref.iter().take(params.data_shards) {
        result.extend_from_slice(shard);
    }

    result.truncate(original_len);
    Ok(result)
}

/// Recover all data_shards original shards by doing k independent 2-byte RS decodings.
fn recover_data_shards(
    params: &ErasureParams,
    chunks: &[(Vec<u8>, usize)],
    k: usize,
) -> Result<Vec<Vec<u8>>, ErasureError> {
    let mut data_shards: Vec<Vec<u8>> = (0..params.data_shards)
        .map(|_| Vec::with_capacity(k * 2))
        .collect();

    for sym_pos in 0..k {
        // Extract 2-byte symbols at this position from available chunks
        let originals: std::collections::HashMap<usize, [u8; 2]> = chunks
            .iter()
            .filter(|(_, idx)| *idx < params.data_shards)
            .map(|(data, idx)| (*idx, [data[sym_pos * 2], data[sym_pos * 2 + 1]]))
            .collect();

        let recoveries: Vec<(usize, [u8; 2])> = chunks
            .iter()
            .filter(|(_, idx)| *idx >= params.data_shards)
            .map(|(data, idx)| {
                (
                    *idx - params.data_shards,
                    [data[sym_pos * 2], data[sym_pos * 2 + 1]],
                )
            })
            .collect();

        let restored = reed_solomon_simd::decode(
            params.data_shards,
            params.recovery_shards(),
            originals.iter().map(|(i, d)| (*i, d.as_slice())),
            recoveries.iter().map(|(i, d)| (*i, d.as_slice())),
        )
        .map_err(|e| ErasureError::RecoveryFailed(e.to_string()))?;

        // Fill in all data shard symbols at this position
        for j in 0..params.data_shards {
            if let Some(sym) = originals.get(&j) {
                data_shards[j].extend_from_slice(sym);
            } else if let Some(sym) = restored.get(&j) {
                data_shards[j].extend_from_slice(sym);
            }
        }
    }

    Ok(data_shards)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_erasure_params_recovery_shards() {
        assert_eq!(ErasureParams::FULL.recovery_shards(), 1023 - 342);
        assert_eq!(ErasureParams::TINY.recovery_shards(), 6 - 2);
    }

    #[test]
    fn test_erasure_params_piece_size() {
        assert_eq!(ErasureParams::FULL.piece_size(), 342 * 2);
        assert_eq!(ErasureParams::TINY.piece_size(), 2 * 2);
    }

    #[test]
    fn test_encode_tiny_basic() {
        let params = ErasureParams::TINY;
        let data = vec![0xAA; params.piece_size()]; // exactly one piece
        let chunks = encode(&params, &data).expect("encode failed");
        assert_eq!(chunks.len(), params.total_shards);
        // All chunks should have the same size
        let chunk_len = chunks[0].len();
        for chunk in &chunks {
            assert_eq!(chunk.len(), chunk_len);
        }
    }

    #[test]
    fn test_encode_recover_roundtrip_all_shards() {
        let params = ErasureParams::TINY;
        let data = b"Hello, erasure coding!".to_vec();
        let chunks = encode(&params, &data).expect("encode failed");

        // Recover using all shards
        let indexed: Vec<(Vec<u8>, usize)> = chunks
            .into_iter()
            .enumerate()
            .map(|(i, c)| (c, i))
            .collect();
        let recovered = recover(&params, &indexed, data.len()).expect("recover failed");
        assert_eq!(recovered, data);
    }

    #[test]
    fn test_encode_recover_with_only_data_shards() {
        let params = ErasureParams::TINY;
        let data = vec![0x42; params.piece_size() * 3]; // 3 pieces
        let chunks = encode(&params, &data).expect("encode failed");

        // Recover using only the first data_shards chunks (no parity needed)
        let indexed: Vec<(Vec<u8>, usize)> = chunks
            .into_iter()
            .enumerate()
            .take(params.data_shards)
            .map(|(i, c)| (c, i))
            .collect();
        let recovered = recover(&params, &indexed, data.len()).expect("recover failed");
        assert_eq!(recovered, data);
    }

    #[test]
    fn test_encode_recover_with_parity_shards() {
        let params = ErasureParams::TINY;
        let data = vec![0xBE; params.piece_size() * 2]; // 2 pieces
        let chunks = encode(&params, &data).expect("encode failed");

        // Drop data shard 0, use data shard 1 + first parity shard
        let indexed: Vec<(Vec<u8>, usize)> = vec![
            (chunks[1].clone(), 1),                                   // data shard 1
            (chunks[params.data_shards].clone(), params.data_shards), // first parity
        ];
        let recovered = recover(&params, &indexed, data.len()).expect("recover failed");
        assert_eq!(recovered, data);
    }

    #[test]
    fn test_encode_recover_all_parity_shards() {
        let params = ErasureParams::TINY;
        let data = vec![0xCD; params.piece_size()]; // 1 piece
        let chunks = encode(&params, &data).expect("encode failed");

        // Recover using only parity shards (drop all data shards)
        let indexed: Vec<(Vec<u8>, usize)> = chunks
            .into_iter()
            .enumerate()
            .skip(params.data_shards)
            .take(params.data_shards) // need data_shards parity shards
            .map(|(i, c)| (c, i))
            .collect();
        let recovered = recover(&params, &indexed, data.len()).expect("recover failed");
        assert_eq!(recovered, data);
    }

    #[test]
    fn test_recover_insufficient_chunks() {
        let params = ErasureParams::TINY;
        let data = vec![0x11; params.piece_size()];
        let chunks = encode(&params, &data).expect("encode failed");

        // Only 1 chunk, need 2
        let indexed = vec![(chunks[0].clone(), 0)];
        let result = recover(&params, &indexed, data.len());
        assert!(matches!(
            result,
            Err(ErasureError::InsufficientChunks { have: 1, need: 2 })
        ));
    }

    #[test]
    fn test_recover_invalid_index() {
        let params = ErasureParams::TINY;
        let data = vec![0x22; params.piece_size()];
        let chunks = encode(&params, &data).expect("encode failed");

        let indexed = vec![
            (chunks[0].clone(), 0),
            (chunks[1].clone(), 999), // invalid index
        ];
        let result = recover(&params, &indexed, data.len());
        assert!(matches!(result, Err(ErasureError::InvalidIndex(999))));
    }

    #[test]
    fn test_encode_empty_data() {
        let params = ErasureParams::TINY;
        let chunks = encode(&params, &[]).expect("encode empty failed");
        assert_eq!(chunks.len(), params.total_shards);
    }

    #[test]
    fn test_recover_empty_chunks() {
        let params = ErasureParams::TINY;
        let result = recover(&params, &[], 0);
        assert!(matches!(
            result,
            Err(ErasureError::InsufficientChunks { .. })
        ));
    }

    #[test]
    fn test_encode_non_aligned_data() {
        // Data that doesn't perfectly fill piece_size multiples
        let params = ErasureParams::TINY;
        let data = vec![0xFF; params.piece_size() + 1]; // one byte over
        let chunks = encode(&params, &data).expect("encode failed");

        let indexed: Vec<(Vec<u8>, usize)> = chunks
            .into_iter()
            .enumerate()
            .map(|(i, c)| (c, i))
            .collect();
        let recovered = recover(&params, &indexed, data.len()).expect("recover failed");
        assert_eq!(recovered, data);
    }

    #[test]
    fn test_encode_recover_large_data() {
        let params = ErasureParams::TINY;
        // 10 pieces worth of data
        let data: Vec<u8> = (0..params.piece_size() * 10)
            .map(|i| (i % 256) as u8)
            .collect();
        let chunks = encode(&params, &data).expect("encode failed");

        // Recover using mixed data and parity shards
        let indexed: Vec<(Vec<u8>, usize)> = vec![
            (chunks[0].clone(), 0),                                   // data shard 0
            (chunks[params.data_shards].clone(), params.data_shards), // parity shard 0
        ];
        let recovered = recover(&params, &indexed, data.len()).expect("recover failed");
        assert_eq!(recovered, data);
    }

    #[test]
    fn test_error_display() {
        let e = ErasureError::InsufficientChunks { have: 1, need: 3 };
        assert_eq!(e.to_string(), "insufficient chunks: have 1, need 3");

        let e = ErasureError::InvalidIndex(42);
        assert_eq!(e.to_string(), "invalid chunk index: 42");

        let e = ErasureError::SizeMismatch;
        assert_eq!(e.to_string(), "chunk size mismatch");

        let e = ErasureError::EncodingFailed("oops".into());
        assert_eq!(e.to_string(), "encoding failed: oops");

        let e = ErasureError::RecoveryFailed("fail".into());
        assert_eq!(e.to_string(), "recovery failed: fail");
    }

    mod proptests {
        use super::*;
        use proptest::prelude::*;

        /// Generate random data of 1..=max_pieces piece-sizes.
        fn random_data(max_pieces: usize) -> impl Strategy<Value = Vec<u8>> {
            let piece = ErasureParams::TINY.piece_size();
            (1..=max_pieces)
                .prop_flat_map(move |n| proptest::collection::vec(any::<u8>(), n * piece))
        }

        proptest! {
            /// Encode then decode with all shards always recovers the original data.
            #[test]
            fn roundtrip_all_shards(data in random_data(5)) {
                let params = ErasureParams::TINY;
                let chunks = encode(&params, &data).expect("encode");
                let indexed: Vec<(Vec<u8>, usize)> =
                    chunks.into_iter().enumerate().map(|(i, c)| (c, i)).collect();
                let recovered = recover(&params, &indexed, data.len()).expect("recover");
                prop_assert_eq!(recovered, data);
            }

            /// Recovery works with exactly data_shards chunks (minimum required).
            #[test]
            fn roundtrip_minimum_shards(data in random_data(3)) {
                let params = ErasureParams::TINY;
                let chunks = encode(&params, &data).expect("encode");
                // Take only the first data_shards chunks
                let indexed: Vec<(Vec<u8>, usize)> = chunks
                    .into_iter()
                    .enumerate()
                    .take(params.data_shards)
                    .map(|(i, c)| (c, i))
                    .collect();
                let recovered = recover(&params, &indexed, data.len()).expect("recover");
                prop_assert_eq!(recovered, data);
            }

            /// Recovery works with any data_shards-of-total_shards combination.
            #[test]
            fn roundtrip_random_shard_selection(
                data in random_data(3),
                seed in any::<u64>(),
            ) {
                let params = ErasureParams::TINY;
                let chunks = encode(&params, &data).expect("encode");

                // Select data_shards random indices from 0..total_shards
                use std::collections::BTreeSet;
                let mut selected = BTreeSet::new();
                let mut rng_state = seed;
                while selected.len() < params.data_shards {
                    // Simple PRNG for deterministic selection
                    rng_state = rng_state.wrapping_mul(6364136223846793005).wrapping_add(1);
                    let idx = (rng_state >> 33) as usize % params.total_shards;
                    selected.insert(idx);
                }

                let indexed: Vec<(Vec<u8>, usize)> = selected
                    .into_iter()
                    .map(|i| (chunks[i].clone(), i))
                    .collect();
                let recovered = recover(&params, &indexed, data.len()).expect("recover");
                prop_assert_eq!(recovered, data);
            }

            /// Corrupting one chunk and using the remaining still recovers.
            #[test]
            fn recovery_after_single_corruption(
                data in random_data(2),
                corrupt_idx in 0..6usize, // 0..total_shards for TINY
            ) {
                let params = ErasureParams::TINY;
                let chunks = encode(&params, &data).expect("encode");

                // Skip the corrupted chunk, use all others
                let indexed: Vec<(Vec<u8>, usize)> = chunks
                    .into_iter()
                    .enumerate()
                    .filter(|(i, _)| *i != corrupt_idx)
                    .map(|(i, c)| (c, i))
                    .collect();

                // We have total_shards - 1 = 5 chunks, need data_shards = 2
                prop_assert!(indexed.len() >= params.data_shards);
                let recovered = recover(&params, &indexed, data.len()).expect("recover");
                prop_assert_eq!(recovered, data);
            }

            /// Corrupting up to recovery_shards chunks still allows recovery
            /// from the remaining k = data_shards chunks.
            ///
            /// For TINY: recovery_shards = 4, so we can lose up to 4 chunks
            /// and still recover from any 2 of the remaining.
            #[test]
            fn recovery_after_multi_corruption(
                data in random_data(3),
                n_corrupt in 1usize..4, // 1..recovery_shards for TINY
                seed in any::<u64>(),
            ) {
                let params = ErasureParams::TINY;
                let chunks = encode(&params, &data).expect("encode");

                // Select n_corrupt random indices to corrupt
                use std::collections::BTreeSet;
                let mut corrupted = BTreeSet::new();
                let mut rng_state = seed;
                while corrupted.len() < n_corrupt {
                    rng_state = rng_state.wrapping_mul(6364136223846793005).wrapping_add(1);
                    let idx = (rng_state >> 33) as usize % params.total_shards;
                    corrupted.insert(idx);
                }

                // Use all non-corrupted chunks
                let indexed: Vec<(Vec<u8>, usize)> = chunks
                    .into_iter()
                    .enumerate()
                    .filter(|(i, _)| !corrupted.contains(i))
                    .map(|(i, c)| (c, i))
                    .collect();

                // Remaining chunks should be enough for recovery
                prop_assert!(indexed.len() >= params.data_shards,
                    "not enough remaining chunks: have {}, need {}",
                    indexed.len(), params.data_shards);

                let recovered = recover(&params, &indexed, data.len()).expect("recover");
                prop_assert_eq!(recovered, data);
            }

            /// Corrupting a chunk by flipping bits and including it in recovery
            /// produces wrong data (not the original), proving that the
            /// corrupted chunk is not silently accepted.
            #[test]
            fn corrupted_chunk_produces_wrong_recovery(
                data in random_data(2),
                corrupt_idx in 0..6usize, // 0..total_shards for TINY
                flip_byte in any::<u8>(),
            ) {
                // Need at least 2 distinct bytes for meaningful corruption
                let flip_byte = if flip_byte == 0 { 1 } else { flip_byte };

                let params = ErasureParams::TINY;
                let chunks = encode(&params, &data).expect("encode");

                // Build indexed chunks with one corrupted
                let mut indexed: Vec<(Vec<u8>, usize)> = chunks
                    .into_iter()
                    .enumerate()
                    .map(|(i, mut c)| {
                        if i == corrupt_idx && !c.is_empty() {
                            c[0] ^= flip_byte; // flip bits in first byte
                        }
                        (c, i)
                    })
                    .collect();

                // Use all shards (including corrupted one)
                // With all data shards present, the fast-path concatenates them
                // directly, so corrupting a data shard changes the output.
                // Corrupting a parity shard is harmless (parity is ignored when
                // all data shards are present).
                if corrupt_idx < params.data_shards {
                    let recovered = recover(&params, &indexed, data.len()).expect("recover");
                    prop_assert_ne!(recovered, data,
                        "corrupting data shard {} should change recovered data", corrupt_idx);
                }
                // Parity shard corruption is silently ignored by the fast path —
                // this is correct behavior, not a bug.
            }
        }
    }
}
