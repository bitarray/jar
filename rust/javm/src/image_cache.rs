//! Image bytecode predecode cache.
//!
//! Predecoding a `javm_exec::PvmProgram` is expensive (basic-block
//! analysis, gas cost computation, instruction predecoding); doing it
//! per CALL would dominate the per-invocation cost. The cache is
//! keyed by Image content_hash so identical Images share a single
//! `Predecoded` (the bytecode is content-addressed; identical content
//! always produces identical decoded state).
//!
//! Stage 3 stores predecoded `PvmProgram` directly. A future
//! optimization can swap in JIT-compiled bytes for the same key and
//! serve both paths from one cache.

use std::collections::HashMap;
use std::sync::Arc;

use javm_cap::CapHash;
use javm_exec::{PvmProgram, gas_cost::DEFAULT_MEM_CYCLES};

use crate::error::VmError;

/// Map from `Image::content_hash` to a parsed `PvmProgram`. The
/// `PvmProgram` is wrapped in `Arc` so the same predecoded body can be
/// referenced from multiple in-flight InstanceEntries (siblings) and
/// from concurrent threads (the kernel may eventually be
/// multi-threaded).
#[derive(Default, Debug)]
pub struct ImageCache {
    entries: HashMap<CapHash, Arc<PvmProgram>>,
}

impl ImageCache {
    pub fn new() -> Self {
        Self::default()
    }

    /// Number of cached images.
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Look up by content hash. `None` if not yet cached.
    pub fn get(&self, content_hash: &CapHash) -> Option<Arc<PvmProgram>> {
        self.entries.get(content_hash).cloned()
    }

    /// Cache a precomputed program under the given content hash.
    pub fn insert(&mut self, content_hash: CapHash, program: Arc<PvmProgram>) {
        self.entries.insert(content_hash, program);
    }

    /// Look up or compute: if the image's content_hash is in the
    /// cache, return the cached program; otherwise parse `code`,
    /// `bitmask`, `jump_table` into a `PvmProgram`, cache it, and
    /// return it.
    pub fn get_or_decode(
        &mut self,
        content_hash: CapHash,
        code: Vec<u8>,
        bitmask: Vec<u8>,
        jump_table: Vec<u32>,
    ) -> Result<Arc<PvmProgram>, VmError> {
        if let Some(prog) = self.entries.get(&content_hash) {
            return Ok(prog.clone());
        }
        let prog = PvmProgram::new(code, bitmask, jump_table, DEFAULT_MEM_CYCLES)
            .map_err(|e| VmError::InvalidBytecode(format!("{:?}", e)))?;
        let arc = Arc::new(prog);
        self.entries.insert(content_hash, arc.clone());
        Ok(arc)
    }

    /// Drop all cached programs. Used at block boundaries by the
    /// chain orchestrator if it wants to free memory.
    pub fn clear(&mut self) {
        self.entries.clear();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn trivial_prog() -> (Vec<u8>, Vec<u8>, Vec<u32>) {
        // Single trap instruction (opcode 0); bitmask marks it as an
        // instruction start.
        (vec![0u8], vec![1u8], vec![])
    }

    #[test]
    fn miss_then_hit() {
        let mut cache = ImageCache::new();
        let h = [1u8; 32];
        assert!(cache.get(&h).is_none());

        let (code, bm, jt) = trivial_prog();
        let p = cache.get_or_decode(h, code, bm, jt).unwrap();
        assert_eq!(cache.len(), 1);
        assert!(Arc::ptr_eq(&p, &cache.get(&h).unwrap()));
    }

    #[test]
    fn get_or_decode_reuses_existing_entry() {
        let mut cache = ImageCache::new();
        let h = [2u8; 32];
        let (c1, b1, j1) = trivial_prog();
        let (c2, b2, j2) = trivial_prog();
        let p1 = cache.get_or_decode(h, c1, b1, j1).unwrap();
        let p2 = cache.get_or_decode(h, c2, b2, j2).unwrap();
        // Same Arc — the cache returned the cached entry, not a
        // freshly-decoded one.
        assert!(Arc::ptr_eq(&p1, &p2));
        assert_eq!(cache.len(), 1);
    }

    #[test]
    fn clear_drops_entries() {
        let mut cache = ImageCache::new();
        let (c, b, j) = trivial_prog();
        cache.get_or_decode([3u8; 32], c, b, j).unwrap();
        assert_eq!(cache.len(), 1);
        cache.clear();
        assert!(cache.is_empty());
    }

    #[test]
    fn invalid_bytecode_returns_err() {
        let mut cache = ImageCache::new();
        // bitmask len mismatch with code: PvmProgram::new returns
        // `ProgramError::BitmaskLenMismatch`.
        let res = cache.get_or_decode([4u8; 32], vec![0u8, 0u8], vec![1u8], vec![]);
        assert!(matches!(res, Err(VmError::InvalidBytecode(_))));
    }
}
