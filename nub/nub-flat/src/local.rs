//! [`FlatLocal`] — the in-process half of the flat personality.
//!
//! A map from content hash to published program, and an `invoke` that
//! lowers onto the PVM2 interpreter. That is the entire host-side
//! obligation: compare with `javm::JavmLocal`, which additionally
//! resolves a capability graph.
//!
//! Everything real is already in `nub-arch-local`
//! ([`PreparedProgram`]); this type only stores bytes and looks them up.

use std::collections::HashMap;

use anyhow::{Result, anyhow};
use nub::{InvocationResult, LocalKernel, ObjHash};
use nub_arch_local::PreparedProgram;
use nub_program::ProgramBlob;

use crate::hash::content_hash;

/// Host-side store: published programs, keyed by content hash.
#[derive(Default)]
pub struct FlatLocal {
    /// Publication is permanent — see [`LocalKernel::put_object`]. This
    /// map is only ever inserted into.
    programs: HashMap<ObjHash, ProgramBlob>,
    /// No state transition to record: a flat invocation mutates nothing
    /// the host can observe, so the root stays zero. A personality with
    /// persistent state would hash it here.
    state_root: ObjHash,
}

impl FlatLocal {
    /// Decode and validate a published program.
    fn decode(bytes: &[u8]) -> Result<ProgramBlob> {
        ProgramBlob::from_bytes(bytes).map_err(|e| anyhow!("decode program: {e}"))
    }

    /// Number of published programs. Handy in tests.
    pub fn len(&self) -> usize {
        self.programs.len()
    }

    pub fn is_empty(&self) -> bool {
        self.programs.is_empty()
    }
}

impl LocalKernel for FlatLocal {
    fn put_object(&mut self, bytes: &[u8]) -> Result<ObjHash> {
        let program = Self::decode(bytes)?;
        let hash = content_hash(bytes);
        self.programs.insert(hash, program);
        Ok(hash)
    }

    fn put_object_with_hash(&mut self, hash: ObjHash, bytes: &[u8]) -> Result<()> {
        let program = Self::decode(bytes)?;
        debug_assert_eq!(
            hash,
            content_hash(bytes),
            "claimed hash does not match the content"
        );
        self.programs.insert(hash, program);
        Ok(())
    }

    fn invoke(
        &mut self,
        root: ObjHash,
        endpoint: u32,
        args: [u64; 4],
        initial_gas: u64,
    ) -> Result<InvocationResult> {
        let program = self
            .programs
            .get(&root)
            .ok_or_else(|| anyhow!("no program published under {}", hex(&root)))?;
        let endpoint = u8::try_from(endpoint)
            .map_err(|_| anyhow!("endpoint {endpoint} out of range (flat programs use u8)"))?;
        let prepared = PreparedProgram::new(program, endpoint, args)
            .map_err(|e| anyhow!("prepare endpoint {endpoint}: {e}"))?;
        let mut handler = nub_arch_local::ExitingEcallHandler;
        Ok(nub_arch_local::run_program(
            &prepared.spec(),
            &mut handler,
            initial_gas,
        ))
    }

    fn state_root(&self) -> ObjHash {
        self.state_root
    }
}

fn hex(h: &ObjHash) -> String {
    h.iter().map(|b| format!("{b:02x}")).collect()
}
