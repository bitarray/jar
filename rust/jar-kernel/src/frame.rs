//! Ephemeral Frame cap-table for one running invocation.
//!
//! Frames hold caps for the duration of a single VM execution. When the VM
//! REPLY/HALT/FAULTs the Frame is discarded. Frames may hold ephemeral caps
//! (DispatchRef / TransactRef) that persistent CNodes cannot.

use std::collections::BTreeMap;

use crate::types::CapId;

#[derive(Clone, Default)]
pub struct Frame {
    /// Frame-local cap-id slots indexed 0..=255.
    pub slots: BTreeMap<u8, CapId>,
}

impl Frame {
    pub fn new() -> Self {
        Self {
            slots: BTreeMap::new(),
        }
    }

    pub fn get(&self, slot: u8) -> Option<CapId> {
        self.slots.get(&slot).copied()
    }

    pub fn set(&mut self, slot: u8, cap: CapId) {
        self.slots.insert(slot, cap);
    }

    pub fn clear(&mut self, slot: u8) {
        self.slots.remove(&slot);
    }
}
