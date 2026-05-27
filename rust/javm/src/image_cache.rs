//! Image bytecode predecode cache.
//!
//! Predecoding an image is expensive (basic-block analysis, gas cost
//! computation, instruction predecoding); doing it per CALL would
//! dominate the per-invocation cost. The cache is keyed by Image
//! content_hash so identical Images share a single predecoded body
//! (the bytecode is content-addressed; identical content always
//! produces identical decoded state).
//!
//! Stores both ISAs side by side under one map: PVM legacy as
//! [`javm_exec::PvmProgram`] and PVM2 (RV) as [`javm_exec::rv_interp::RvProgram`].
//! The kind is discriminated at decode time by the Image's
//! `jump_table_offsets` field (non-empty == PVM2). See the migration
//! plan in `~/docs/pvm-isa/discussions/`.

use std::collections::HashMap;
use std::sync::Arc;

use javm_cap::CapHash;
use javm_exec::{PvmProgram, gas_cost::DEFAULT_MEM_CYCLES, rv_interp::RvProgram};

use crate::error::VmError;

/// Cached predecoded program — one variant per ISA.
#[derive(Clone, Debug)]
pub enum CachedProgram {
    Pvm(Arc<PvmProgram>),
    Pvm2(Arc<RvProgram>),
}

/// Map from `Image::content_hash` to the predecoded body. The body is
/// wrapped in `Arc` so the same predecoded program can be referenced
/// from multiple in-flight InstanceEntries (siblings) and from
/// concurrent threads.
#[derive(Default, Debug)]
pub struct ImageCache {
    entries: HashMap<CapHash, CachedProgram>,
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
    pub fn get(&self, content_hash: &CapHash) -> Option<CachedProgram> {
        self.entries.get(content_hash).cloned()
    }

    /// Cache a precomputed program under the given content hash.
    pub fn insert(&mut self, content_hash: CapHash, program: CachedProgram) {
        self.entries.insert(content_hash, program);
    }

    /// Look up or compute a PVM (legacy) program.
    pub fn get_or_decode_pvm(
        &mut self,
        content_hash: CapHash,
        code: Vec<u8>,
        bitmask: Vec<u8>,
        jump_table: Vec<u32>,
    ) -> Result<CachedProgram, VmError> {
        if let Some(prog) = self.entries.get(&content_hash) {
            return Ok(prog.clone());
        }
        let prog = PvmProgram::new(code, bitmask, jump_table, DEFAULT_MEM_CYCLES)
            .map_err(|e| VmError::InvalidBytecode(format!("{:?}", e)))?;
        let cached = CachedProgram::Pvm(Arc::new(prog));
        self.entries.insert(content_hash, cached.clone());
        Ok(cached)
    }

    /// Look up or compute a PVM2 (RV) program.
    pub fn get_or_decode_pvm2(
        &mut self,
        content_hash: CapHash,
        code: Vec<u8>,
        jump_table: Vec<u32>,
        jump_table_offsets: Vec<u32>,
    ) -> Result<CachedProgram, VmError> {
        if let Some(prog) = self.entries.get(&content_hash) {
            return Ok(prog.clone());
        }
        let prog = RvProgram::new(code, jump_table, jump_table_offsets);
        let cached = CachedProgram::Pvm2(Arc::new(prog));
        self.entries.insert(content_hash, cached.clone());
        Ok(cached)
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

    fn trivial_pvm_prog() -> (Vec<u8>, Vec<u8>, Vec<u32>) {
        // Single trap instruction (opcode 0); bitmask marks it as an
        // instruction start.
        (vec![0u8], vec![1u8], vec![])
    }

    #[test]
    fn miss_then_hit_pvm() {
        let mut cache = ImageCache::new();
        let h = [1u8; 32];
        assert!(cache.get(&h).is_none());

        let (code, bm, jt) = trivial_pvm_prog();
        let p = cache.get_or_decode_pvm(h, code, bm, jt).unwrap();
        assert_eq!(cache.len(), 1);
        match (&p, &cache.get(&h).unwrap()) {
            (CachedProgram::Pvm(a), CachedProgram::Pvm(b)) => assert!(Arc::ptr_eq(a, b)),
            _ => panic!("expected Pvm variant"),
        }
    }

    #[test]
    fn get_or_decode_reuses_existing_entry() {
        let mut cache = ImageCache::new();
        let h = [2u8; 32];
        let (c1, b1, j1) = trivial_pvm_prog();
        let (c2, b2, j2) = trivial_pvm_prog();
        let p1 = cache.get_or_decode_pvm(h, c1, b1, j1).unwrap();
        let p2 = cache.get_or_decode_pvm(h, c2, b2, j2).unwrap();
        // Same Arc — the cache returned the cached entry, not a
        // freshly-decoded one.
        match (&p1, &p2) {
            (CachedProgram::Pvm(a), CachedProgram::Pvm(b)) => assert!(Arc::ptr_eq(a, b)),
            _ => panic!("expected Pvm variant"),
        }
        assert_eq!(cache.len(), 1);
    }

    #[test]
    fn clear_drops_entries() {
        let mut cache = ImageCache::new();
        let (c, b, j) = trivial_pvm_prog();
        cache.get_or_decode_pvm([3u8; 32], c, b, j).unwrap();
        assert_eq!(cache.len(), 1);
        cache.clear();
        assert!(cache.is_empty());
    }

    #[test]
    fn invalid_bytecode_returns_err() {
        let mut cache = ImageCache::new();
        // bitmask len mismatch with code: PvmProgram::new returns
        // `ProgramError::BitmaskLenMismatch`.
        let res = cache.get_or_decode_pvm([4u8; 32], vec![0u8, 0u8], vec![1u8], vec![]);
        assert!(matches!(res, Err(VmError::InvalidBytecode(_))));
    }

    #[test]
    fn miss_then_hit_pvm2() {
        let mut cache = ImageCache::new();
        let h = [5u8; 32];
        // A trivial PVM2 blob: trap (custom-0 funct3=000, opcode 0x0B).
        let code = vec![0x0B, 0x00, 0x00, 0x00];
        let p = cache.get_or_decode_pvm2(h, code, vec![], vec![0]).unwrap();
        assert_eq!(cache.len(), 1);
        match (&p, &cache.get(&h).unwrap()) {
            (CachedProgram::Pvm2(a), CachedProgram::Pvm2(b)) => assert!(Arc::ptr_eq(a, b)),
            _ => panic!("expected Pvm2 variant"),
        }
    }
}
