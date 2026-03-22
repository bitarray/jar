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
#[derive(Debug)]
pub enum ErasureError {
    /// Not enough chunks to recover (need at least data_shards).
    InsufficientChunks { have: usize, need: usize },
    /// Invalid chunk index (>= total_shards).
    InvalidIndex(usize),
    /// Chunk size mismatch.
    SizeMismatch,
    /// RS encoding failed.
    EncodingFailed(String),
    /// RS recovery failed.
    RecoveryFailed(String),
}

impl std::fmt::Display for ErasureError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::InsufficientChunks { have, need } => {
                write!(f, "insufficient chunks: have {have}, need {need}")
            }
            Self::InvalidIndex(idx) => write!(f, "invalid chunk index: {idx}"),
            Self::SizeMismatch => write!(f, "chunk size mismatch"),
            Self::EncodingFailed(e) => write!(f, "encoding failed: {e}"),
            Self::RecoveryFailed(e) => write!(f, "recovery failed: {e}"),
        }
    }
}

impl std::error::Error for ErasureError {}

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
        (data.len() + piece_size - 1) / piece_size
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
    for j in 0..params.data_shards {
        result.extend_from_slice(data_shards_ref[j]);
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
        let originals: Vec<(usize, [u8; 2])> = chunks
            .iter()
            .filter(|(_, idx)| *idx < params.data_shards)
            .map(|(data, idx)| (*idx, [data[sym_pos * 2], data[sym_pos * 2 + 1]]))
            .collect();

        let recoveries: Vec<(usize, [u8; 2])> = chunks
            .iter()
            .filter(|(_, idx)| *idx >= params.data_shards)
            .map(|(data, idx)| (
                *idx - params.data_shards,
                [data[sym_pos * 2], data[sym_pos * 2 + 1]],
            ))
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
            if let Some(sym) = originals.iter().find(|(idx, _)| *idx == j) {
                data_shards[j].extend_from_slice(&sym.1);
            } else if let Some(sym) = restored.get(&j) {
                data_shards[j].extend_from_slice(sym);
            }
        }
    }

    Ok(data_shards)
}
