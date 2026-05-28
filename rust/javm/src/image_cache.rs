//! Image bytecode predecode cache.
//!
//! Predecoding an image is expensive (basic-block analysis, gas cost
//! computation, instruction predecoding); doing it per CALL would
//! dominate the per-invocation cost. The cache is keyed by Image
//! content_hash so identical Images share a single predecoded body
//! (the bytecode is content-addressed; identical content always
//! produces identical decoded state).

use std::collections::HashMap;
use std::sync::Arc;

use javm_cap::CapHash;
use javm_exec::rv_interp::RvProgram;

/// Map from `Image::content_hash` to the predecoded body. The body is
/// wrapped in `Arc` so the same predecoded program can be referenced
/// from multiple in-flight InstanceEntries (siblings) and from
/// concurrent threads.
#[derive(Default, Debug)]
pub struct ImageCache {
    entries: HashMap<CapHash, Arc<RvProgram>>,
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
    pub fn get(&self, content_hash: &CapHash) -> Option<Arc<RvProgram>> {
        self.entries.get(content_hash).cloned()
    }

    /// Cache a precomputed program under the given content hash.
    pub fn insert(&mut self, content_hash: CapHash, program: Arc<RvProgram>) {
        self.entries.insert(content_hash, program);
    }

    /// Look up or compute the predecoded program for an image.
    pub fn get_or_decode(
        &mut self,
        content_hash: CapHash,
        code: Vec<u8>,
        jump_table: Vec<u32>,
        jump_table_offsets: Vec<u32>,
    ) -> Arc<RvProgram> {
        if let Some(prog) = self.entries.get(&content_hash) {
            return prog.clone();
        }
        let prog = Arc::new(RvProgram::new(code, jump_table, jump_table_offsets));
        self.entries.insert(content_hash, prog.clone());
        prog
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

    fn trivial_blob() -> (Vec<u8>, Vec<u32>, Vec<u32>) {
        // Single `trap` instruction (custom-0 funct3=000, opcode 0x0B).
        (vec![0x0B, 0x00, 0x00, 0x00], vec![], vec![0])
    }

    #[test]
    fn miss_then_hit() {
        let mut cache = ImageCache::new();
        let h = [1u8; 32];
        assert!(cache.get(&h).is_none());

        let (code, jt, jto) = trivial_blob();
        let p = cache.get_or_decode(h, code, jt, jto);
        assert_eq!(cache.len(), 1);
        assert!(Arc::ptr_eq(&p, &cache.get(&h).unwrap()));
    }

    #[test]
    fn get_or_decode_reuses_existing_entry() {
        let mut cache = ImageCache::new();
        let h = [2u8; 32];
        let (c1, jt1, jto1) = trivial_blob();
        let (c2, jt2, jto2) = trivial_blob();
        let p1 = cache.get_or_decode(h, c1, jt1, jto1);
        let p2 = cache.get_or_decode(h, c2, jt2, jto2);
        assert!(Arc::ptr_eq(&p1, &p2));
        assert_eq!(cache.len(), 1);
    }

    #[test]
    fn clear_drops_entries() {
        let mut cache = ImageCache::new();
        let (code, jt, jto) = trivial_blob();
        cache.get_or_decode([3u8; 32], code, jt, jto);
        assert_eq!(cache.len(), 1);
        cache.clear();
        assert!(cache.is_empty());
    }
}
