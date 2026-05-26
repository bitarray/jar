//! Single-pass pipeline gas model (JAR v0.8.0).
//!
//! O(n) single-pass model tracking per-register completion cycles.
//! Replaces the full ROB-based pipeline simulation.
//!
//! Tracks `reg_done[13]` (cycle when each register is ready) and decode
//! throughput (4 slots/cycle). No ROB, no priority loop, no EU contention.
//! See `docs/gas-metering-design.md` for detailed comparison.

use crate::gas_cost::FastCost;

/// Single-pass pipeline gas simulator. O(1) per instruction, stack-allocated.
pub struct GasSimulator {
    reg_done: [u32; 13],
    cycle: u32,
    decode_used: u8,
    max_done: u32,
}

impl Default for GasSimulator {
    fn default() -> Self {
        Self::new()
    }
}

impl GasSimulator {
    pub fn new() -> Self {
        Self {
            reg_done: [0; 13],
            cycle: 0,
            decode_used: 0,
            max_done: 0,
        }
    }

    /// Fast path: feed an instruction using direct register indices instead of
    /// bitmasks. Avoids the shift+OR bitmask construction and trailing_zeros
    /// extraction loop. For typical 2-source, 1-dest instructions.
    /// `src1`/`src2` are source register indices (0..12, or 0xFF for "none").
    /// `dst` is destination register index (0..12, or 0xFF for "none").
    #[inline(always)]
    pub fn feed_direct(&mut self, cycles: u8, decode_slots: u8, src1: u8, src2: u8, dst: u8) {
        // Match Lean semantics: advance cycle only if ALL 4 decode slots are
        // already consumed. As long as ≥1 slot remains, the new instruction
        // begins decoding this cycle regardless of how many slots it needs.
        if self.decode_used >= 4 {
            self.cycle += 1;
            self.decode_used = decode_slots;
        } else {
            self.decode_used += decode_slots;
        }
        let mut start = self.cycle;
        if src1 < 13 {
            start = start.max(self.reg_done[src1 as usize]);
        }
        if src2 < 13 {
            start = start.max(self.reg_done[src2 as usize]);
        }
        let done = start + cycles as u32;
        if dst < 13 {
            self.reg_done[dst as usize] = done;
        }
        self.max_done = self.max_done.max(done);
    }

    /// Process one instruction. O(1).
    #[inline]
    pub fn feed(&mut self, cost: &FastCost) {
        // Decode throughput: 4 slots per cycle.
        // Match Lean semantics: advance cycle only if ALL 4 slots consumed.
        if self.decode_used >= 4 {
            self.cycle += 1;
            self.decode_used = cost.decode_slots;
        } else {
            self.decode_used += cost.decode_slots;
        }

        // move_reg: zero-cycle frontend-only op, propagate reg_done
        if cost.is_move_reg {
            let src_reg = cost.src_mask.trailing_zeros() as usize;
            let dst_reg = cost.dst_mask.trailing_zeros() as usize;
            if src_reg < 13 && dst_reg < 13 {
                self.reg_done[dst_reg] = self.reg_done[src_reg];
            }
            return;
        }

        // Data dependencies: start = max(decode_cycle, max(reg_done[src_regs]))
        let mut start = self.cycle;
        let mut src = cost.src_mask;
        while src != 0 {
            let r = src.trailing_zeros() as usize;
            src &= src - 1;
            if r < 13 {
                start = start.max(self.reg_done[r]);
            }
        }

        // Completion
        let done = start + cost.cycles as u32;

        // Update destination registers
        let mut dst = cost.dst_mask;
        while dst != 0 {
            let r = dst.trailing_zeros() as usize;
            dst &= dst - 1;
            if r < 13 {
                self.reg_done[r] = done;
            }
        }

        // Track maximum completion cycle
        self.max_done = self.max_done.max(done);
    }

    /// Return block gas cost: max(max_done - 3, 1).
    #[inline]
    pub fn flush_and_get_cost(&self) -> u32 {
        if self.max_done > 3 {
            self.max_done - 3
        } else {
            1
        }
    }

    /// Reset for the next gas block.
    #[inline]
    pub fn reset(&mut self) {
        self.reg_done = [0; 13];
        self.cycle = 0;
        self.decode_used = 0;
        self.max_done = 0;
    }
}
