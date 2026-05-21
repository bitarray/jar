//! Kernel-internal call stack.
//!
//! Per v3 spec §3 "The Instance status state machine and kernel call
//! stack":
//!
//! - **InstanceEntry** — pushed by CALL. Introduces a fresh invocation
//!   of an Instance. Carries that invocation's PC, regs, and reference
//!   to the in-flight Instance state.
//!
//! - **ReferenceEntry** — pushed by host_yield. Refers to an
//!   InstanceEntry earlier in the stack; the referenced entry's PC and
//!   regs are shared (the ReferenceEntry is just a "this position
//!   also depends on entry N" pointer for yield-resume routing).
//!
//! Invariants (enforced via `enforce_invariants` in debug builds):
//! - Exactly one entry is `Running` — the top of the stack.
//! - All others are `Waiting`.
//! - A `ReferenceEntry` at position `i` has
//!   `target_position < i` and the target is an `InstanceEntry`.
//!
//! State storage: an `InstanceEntry` owns its in-flight working root
//! cnode and references into a shared `Cache` for the underlying
//! Image and Instance content. The Vm consults the stack top to find
//! the actively executing Instance; it consults lower entries during
//! yield-marker routing.

use std::sync::Arc;

use javm_cap::{CNodeCap, CapHash, CapHashOrRef, SlotIdx};
use javm_exec::{GasCounter, Mem, PvmProgram, Regs};

use crate::error::VmError;

/// Per the spec §18 default; the chain spec may override.
pub const DEFAULT_MAX_DEPTH: usize = 256;

/// Status of a stack entry. Exactly one entry is `Running` (the top);
/// all others are `Waiting`. Block-end faults any remaining `Waiting`
/// entries per spec §3.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum EntryStatus {
    Running,
    Waiting,
}

/// In-flight state of an Instance currently on the call stack.
///
/// Owns the working root cnode, regs, and memory of this invocation.
/// The Vm updates these in place as the interpreter runs. The
/// `program` is shared (Arc) — multiple in-flight entries can share
/// the same predecoded bytecode (e.g. siblings of the same image).
pub struct InstanceEntry {
    /// Reference back to the Cache entry this invocation is running.
    /// Carried across the apply so the post-HALT settle can hash the
    /// final working state into a `CapHash`.
    pub instance_ref: CapHashOrRef,
    /// Cached for quick read of the Instance's type identity.
    pub image_hash_chain: CapHash,
    /// Cached for quick read of the bound Image hash.
    pub image_hash: CapHash,
    /// Predecoded bytecode (keyed by `image_hash` in `ImageCache`).
    pub program: Arc<PvmProgram>,
    /// MainFrame cnode — the active CapTable. Owned by this entry; on
    /// HALT it's commit-merged back into the cache.
    pub root_cnode: CNodeCap,
    /// `Image.yield_marker_slot`, cached for yield routing.
    pub yield_marker_slot: Option<SlotIdx>,
    /// Sorted slot indices declared pinned by this Image. Cached for
    /// fast `is_pinned` checks.
    pub pinned_slots: Vec<SlotIdx>,
    /// Working registers.
    pub regs: Regs,
    /// Working memory (mapped RW overlays + ephemeral).
    pub mem: Mem,
    /// Local gas counter — pulls from `KernelAssist::gas_meter_*`
    /// against the active gas slot.
    pub gas: GasCounter,
    /// Running vs. Waiting.
    pub status: EntryStatus,
}

impl std::fmt::Debug for InstanceEntry {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("InstanceEntry")
            .field("image_hash_chain", &short_hex(&self.image_hash_chain))
            .field("image_hash", &short_hex(&self.image_hash))
            .field("pc", &self.regs.pc)
            .field("status", &self.status)
            .field("cnode.size_log", &self.root_cnode.size_log)
            .finish_non_exhaustive()
    }
}

/// Stack entry that refers to an InstanceEntry earlier on the stack.
/// Pushed by `host_yield` after a yield marker matches the target's
/// YieldCatcher; the target resumes when this entry rotates to the top
/// (via CALL_RESUME or HALT-unwind).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ReferenceEntry {
    /// Index of the InstanceEntry this reference resumes.
    pub target_position: usize,
    /// Running vs. Waiting.
    pub status: EntryStatus,
}

/// One slot on the call stack.
///
/// `InstanceEntry` is boxed because its working state (cnode + mem +
/// regs) is significantly larger than a `ReferenceEntry` (3 words);
/// keeping the enum's stack-side discriminant compact matters when
/// the stack approaches the max-depth limit (256 by default).
#[derive(Debug)]
pub enum Entry {
    Instance(Box<InstanceEntry>),
    Reference(ReferenceEntry),
}

impl Entry {
    pub fn status(&self) -> EntryStatus {
        match self {
            Entry::Instance(e) => e.status,
            Entry::Reference(e) => e.status,
        }
    }

    pub fn set_status(&mut self, s: EntryStatus) {
        match self {
            Entry::Instance(e) => e.status = s,
            Entry::Reference(e) => e.status = s,
        }
    }

    pub fn is_instance(&self) -> bool {
        matches!(self, Entry::Instance(_))
    }

    pub fn as_instance(&self) -> Option<&InstanceEntry> {
        match self {
            Entry::Instance(e) => Some(e.as_ref()),
            _ => None,
        }
    }

    pub fn as_instance_mut(&mut self) -> Option<&mut InstanceEntry> {
        match self {
            Entry::Instance(e) => Some(e.as_mut()),
            _ => None,
        }
    }
}

/// The kernel-internal call stack.
///
/// The stack drives control transfer (CALL/yield/HALT) and provides
/// the structural invocation boundary that gives v3 its fault
/// atomicity and yield-resume linearity (§3 "Why hierarchy is the
/// invocation boundary").
pub struct CallStack {
    entries: Vec<Entry>,
    max_depth: usize,
}

impl CallStack {
    pub fn new(max_depth: usize) -> Self {
        Self {
            entries: Vec::new(),
            max_depth,
        }
    }

    pub fn with_default_depth() -> Self {
        Self::new(DEFAULT_MAX_DEPTH)
    }

    pub fn len(&self) -> usize {
        self.entries.len()
    }

    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    pub fn entries(&self) -> &[Entry] {
        &self.entries
    }

    /// Mutable slice into entries — used by the driver to save live
    /// regs/mem/gas back into a *specific* InstanceEntry by position
    /// after the interpreter exits (e.g. saving the yielder's state
    /// while a ReferenceEntry sits on top).
    pub fn entries_mut(&mut self) -> &mut [Entry] {
        &mut self.entries
    }

    /// Push a fresh InstanceEntry. Transitions any prior top from
    /// `Running` to `Waiting`; the new entry becomes `Running`.
    pub fn push_instance(&mut self, mut entry: InstanceEntry) -> Result<(), VmError> {
        if self.entries.len() >= self.max_depth {
            return Err(VmError::CallStackFull);
        }
        if let Some(top) = self.entries.last_mut() {
            top.set_status(EntryStatus::Waiting);
        }
        entry.status = EntryStatus::Running;
        self.entries.push(Entry::Instance(Box::new(entry)));
        Ok(())
    }

    /// Push a ReferenceEntry pointing at an InstanceEntry earlier on
    /// the stack. The reference becomes `Running`; the prior top
    /// drops to `Waiting`.
    pub fn push_reference(&mut self, target_position: usize) -> Result<(), VmError> {
        if self.entries.len() >= self.max_depth {
            return Err(VmError::CallStackFull);
        }
        if target_position >= self.entries.len() {
            return Err(VmError::ReferenceOutOfRange(target_position));
        }
        if !self.entries[target_position].is_instance() {
            return Err(VmError::ReferenceNonInstance(target_position));
        }
        if let Some(top) = self.entries.last_mut() {
            top.set_status(EntryStatus::Waiting);
        }
        self.entries.push(Entry::Reference(ReferenceEntry {
            target_position,
            status: EntryStatus::Running,
        }));
        Ok(())
    }

    /// Pop the top entry. The next entry (if any) is promoted from
    /// `Waiting` to `Running`.
    pub fn pop(&mut self) -> Option<Entry> {
        let popped = self.entries.pop();
        if let Some(top) = self.entries.last_mut() {
            top.set_status(EntryStatus::Running);
        }
        popped
    }

    /// The currently-Running top of the stack.
    pub fn running(&self) -> Option<&Entry> {
        self.entries.last()
    }

    pub fn running_mut(&mut self) -> Option<&mut Entry> {
        self.entries.last_mut()
    }

    /// Resolve a ReferenceEntry's effective `InstanceEntry`.
    ///
    /// If the top is an InstanceEntry, returns it; if it's a
    /// ReferenceEntry, follows the `target_position` link.
    pub fn running_instance(&self) -> Option<&InstanceEntry> {
        match self.entries.last()? {
            Entry::Instance(e) => Some(e.as_ref()),
            Entry::Reference(r) => match self.entries.get(r.target_position)? {
                Entry::Instance(e) => Some(e.as_ref()),
                Entry::Reference(_) => None, // shouldn't happen — invariants
            },
        }
    }

    pub fn running_instance_mut(&mut self) -> Option<&mut InstanceEntry> {
        let last_idx = self.entries.len().checked_sub(1)?;
        let target_idx = match &self.entries[last_idx] {
            Entry::Instance(_) => last_idx,
            Entry::Reference(r) => r.target_position,
        };
        match self.entries.get_mut(target_idx)? {
            Entry::Instance(e) => Some(e.as_mut()),
            Entry::Reference(_) => None,
        }
    }

    /// Debug-build assertion of the v3 stack invariants. Real callers
    /// should rely on the push/pop primitives to maintain them; this
    /// is for testing the construction primitives themselves.
    pub fn enforce_invariants(&self) -> Result<(), VmError> {
        if self.entries.is_empty() {
            return Ok(());
        }
        // Exactly one Running, at the top.
        for (i, e) in self.entries.iter().enumerate() {
            let expected = if i == self.entries.len() - 1 {
                EntryStatus::Running
            } else {
                EntryStatus::Waiting
            };
            if e.status() != expected {
                return Err(VmError::Invariant(
                    "exactly one Running entry, at the stack top",
                ));
            }
        }
        // ReferenceEntries must target an earlier InstanceEntry.
        for (i, e) in self.entries.iter().enumerate() {
            if let Entry::Reference(r) = e {
                if r.target_position >= i {
                    return Err(VmError::ReferenceOutOfRange(r.target_position));
                }
                if !matches!(self.entries[r.target_position], Entry::Instance(_)) {
                    return Err(VmError::ReferenceNonInstance(r.target_position));
                }
            }
        }
        Ok(())
    }
}

impl std::fmt::Debug for CallStack {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CallStack")
            .field("len", &self.entries.len())
            .field("max_depth", &self.max_depth)
            .finish()
    }
}

fn short_hex(bytes: &[u8]) -> String {
    bytes.iter().take(4).map(|b| format!("{:02x}", b)).collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use javm_exec::PvmProgram;

    fn make_entry(tag: u8) -> InstanceEntry {
        let prog = Arc::new(PvmProgram::new(vec![0u8], vec![1u8], vec![], 25).unwrap());
        let cnode = CNodeCap::new(8).unwrap();
        InstanceEntry {
            instance_ref: CapHashOrRef::Hash([tag; 32]),
            image_hash_chain: [tag; 32],
            image_hash: [tag.wrapping_add(0x10); 32],
            program: prog,
            root_cnode: cnode,
            yield_marker_slot: None,
            pinned_slots: Vec::new(),
            regs: Regs::new(),
            mem: Mem::new(),
            gas: GasCounter::new(1000),
            status: EntryStatus::Waiting,
        }
    }

    #[test]
    fn empty_stack_invariants_hold() {
        let s = CallStack::with_default_depth();
        assert!(s.is_empty());
        assert!(s.running().is_none());
        s.enforce_invariants().unwrap();
    }

    #[test]
    fn push_instance_makes_it_running() {
        let mut s = CallStack::with_default_depth();
        s.push_instance(make_entry(1)).unwrap();
        assert_eq!(s.len(), 1);
        assert_eq!(s.running().unwrap().status(), EntryStatus::Running);
        s.enforce_invariants().unwrap();
    }

    #[test]
    fn push_two_instances_top_running_rest_waiting() {
        let mut s = CallStack::with_default_depth();
        s.push_instance(make_entry(1)).unwrap();
        s.push_instance(make_entry(2)).unwrap();
        assert_eq!(s.len(), 2);
        assert_eq!(s.entries()[0].status(), EntryStatus::Waiting);
        assert_eq!(s.entries()[1].status(), EntryStatus::Running);
        s.enforce_invariants().unwrap();
    }

    #[test]
    fn pop_promotes_next() {
        let mut s = CallStack::with_default_depth();
        s.push_instance(make_entry(1)).unwrap();
        s.push_instance(make_entry(2)).unwrap();
        let popped = s.pop().unwrap();
        assert_eq!(popped.status(), EntryStatus::Running);
        // The remaining entry is now Running.
        assert_eq!(s.running().unwrap().status(), EntryStatus::Running);
        s.enforce_invariants().unwrap();
    }

    #[test]
    fn pop_last_leaves_empty() {
        let mut s = CallStack::with_default_depth();
        s.push_instance(make_entry(1)).unwrap();
        s.pop().unwrap();
        assert!(s.is_empty());
        s.enforce_invariants().unwrap();
    }

    #[test]
    fn push_reference_targets_earlier_instance() {
        let mut s = CallStack::with_default_depth();
        s.push_instance(make_entry(1)).unwrap();
        s.push_instance(make_entry(2)).unwrap();
        s.push_reference(0).unwrap();
        assert_eq!(s.len(), 3);
        // The reference is Running; both instances are Waiting.
        assert!(matches!(s.entries()[0].status(), EntryStatus::Waiting));
        assert!(matches!(s.entries()[1].status(), EntryStatus::Waiting));
        assert!(matches!(s.entries()[2].status(), EntryStatus::Running));
        s.enforce_invariants().unwrap();
    }

    #[test]
    fn push_reference_out_of_range_rejected() {
        let mut s = CallStack::with_default_depth();
        s.push_instance(make_entry(1)).unwrap();
        let res = s.push_reference(5);
        assert!(matches!(res, Err(VmError::ReferenceOutOfRange(5))));
    }

    #[test]
    fn push_reference_targeting_reference_rejected() {
        let mut s = CallStack::with_default_depth();
        s.push_instance(make_entry(1)).unwrap();
        s.push_reference(0).unwrap();
        // The top is a ReferenceEntry at position 1; targeting it
        // should be rejected.
        let res = s.push_reference(1);
        assert!(matches!(res, Err(VmError::ReferenceNonInstance(1))));
    }

    #[test]
    fn push_beyond_max_depth_rejected() {
        let mut s = CallStack::new(2);
        s.push_instance(make_entry(1)).unwrap();
        s.push_instance(make_entry(2)).unwrap();
        let res = s.push_instance(make_entry(3));
        assert!(matches!(res, Err(VmError::CallStackFull)));
    }

    #[test]
    fn running_instance_resolves_through_reference() {
        let mut s = CallStack::with_default_depth();
        s.push_instance(make_entry(1)).unwrap();
        s.push_reference(0).unwrap();
        let ic = s.running_instance().unwrap();
        // The reference points at entry 0 (tag=1).
        assert_eq!(ic.image_hash_chain, [1u8; 32]);
    }
}
