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

#[cfg(test)]
mod tests {
    use super::*;

    // === flush_and_get_cost ===

    #[test]
    fn test_empty_block_cost_is_one() {
        let sim = GasSimulator::new();
        assert_eq!(sim.flush_and_get_cost(), 1, "empty block should cost 1");
    }

    // === feed_direct ===

    #[test]
    fn test_single_alu_instruction() {
        // One ALU op: 1 cycle, 1 decode slot, r0 → r2
        let mut sim = GasSimulator::new();
        sim.feed_direct(1, 1, 0, 0xFF, 2); // src1=r0, no src2, dst=r2
        // max_done = 0 (start) + 1 (cycles) = 1
        // cost = max(1 - 3, 1) = 1
        assert_eq!(sim.flush_and_get_cost(), 1);
    }

    #[test]
    fn test_data_dependency_chain() {
        // Chain: r0 → r1 (1 cycle), r1 → r2 (1 cycle)
        // r1 is ready at cycle 1, r2 at cycle 2
        let mut sim = GasSimulator::new();
        sim.feed_direct(1, 1, 0, 0xFF, 1); // r1 done at cycle 1
        sim.feed_direct(1, 1, 1, 0xFF, 2); // depends on r1, r2 done at cycle 2
        // max_done = 2, cost = max(2 - 3, 1) = 1
        assert_eq!(sim.flush_and_get_cost(), 1);
    }

    #[test]
    fn test_long_dependency_chain() {
        // 5-deep chain, each 1 cycle: r0→r1→r2→r3→r4→r5
        let mut sim = GasSimulator::new();
        for i in 0..5u8 {
            sim.feed_direct(1, 1, i, 0xFF, i + 1);
        }
        // r5 done at cycle 5, cost = max(5 - 3, 1) = 2
        assert_eq!(sim.flush_and_get_cost(), 2);
    }

    #[test]
    fn test_independent_instructions_parallel() {
        // Two independent ALU ops: r0→r2 and r1→r3, both 1 cycle
        let mut sim = GasSimulator::new();
        sim.feed_direct(1, 1, 0, 0xFF, 2);
        sim.feed_direct(1, 1, 1, 0xFF, 3);
        // Both start at cycle 0, done at cycle 1
        // max_done = 1, cost = 1
        assert_eq!(sim.flush_and_get_cost(), 1);
    }

    #[test]
    fn test_multi_cycle_instruction() {
        // One 4-cycle instruction (e.g., multiply)
        let mut sim = GasSimulator::new();
        sim.feed_direct(4, 1, 0, 1, 2); // 4 cycles, src r0+r1, dst r2
        // max_done = 4, cost = max(4 - 3, 1) = 1
        assert_eq!(sim.flush_and_get_cost(), 1);
    }

    #[test]
    fn test_high_latency_chain() {
        // 4-cycle MUL → 1-cycle ALU dependent on result
        let mut sim = GasSimulator::new();
        sim.feed_direct(4, 1, 0, 1, 2); // MUL: r2 done at cycle 4
        sim.feed_direct(1, 1, 2, 0xFF, 3); // ALU: depends on r2, r3 done at cycle 5
        // max_done = 5, cost = max(5 - 3, 1) = 2
        assert_eq!(sim.flush_and_get_cost(), 2);
    }

    #[test]
    fn test_decode_throughput_limit() {
        // 5 independent 1-slot instructions: 4 fit in cycle 0, 5th bumps to cycle 1
        let mut sim = GasSimulator::new();
        for i in 0..5u8 {
            sim.feed_direct(1, 1, 0xFF, 0xFF, i); // no deps, 1 slot each
        }
        // First 4 decode in cycle 0 (done at 1), 5th decodes in cycle 1 (done at 2)
        // max_done = 2, cost = max(2 - 3, 1) = 1
        assert_eq!(sim.flush_and_get_cost(), 1);
    }

    #[test]
    fn test_no_src_no_dst() {
        // Instruction with no register deps (e.g., NOP-like)
        let mut sim = GasSimulator::new();
        sim.feed_direct(1, 1, 0xFF, 0xFF, 0xFF);
        // max_done = 1 (start 0 + 1 cycle)
        assert_eq!(sim.flush_and_get_cost(), 1);
    }

    #[test]
    fn test_two_sources() {
        // r2 = r0 + r1 where r0 available at cycle 0, r1 available at cycle 3
        let mut sim = GasSimulator::new();
        sim.feed_direct(3, 1, 0xFF, 0xFF, 1); // r1 done at cycle 3
        sim.feed_direct(1, 1, 0, 1, 2); // depends on r0 (ready 0) and r1 (ready 3)
        // r2 starts at max(0, 3) = 3, done at 4
        // max_done = 4, cost = max(4 - 3, 1) = 1
        assert_eq!(sim.flush_and_get_cost(), 1);
    }

    // === feed (bitmask-based) ===

    #[test]
    fn test_feed_move_reg_propagates_done() {
        // move_reg: zero-cycle, propagates reg_done from src to dst
        let mut sim = GasSimulator::new();
        sim.feed_direct(3, 1, 0xFF, 0xFF, 0); // r0 done at cycle 3
        sim.feed(&FastCost {
            cycles: 0,
            decode_slots: 1,
            exec_unit: 0,
            src_mask: 1 << 0, // r0
            dst_mask: 1 << 1, // r1
            is_terminator: false,
            is_move_reg: true,
        });
        // r1 should inherit r0's done time (3)
        sim.feed_direct(1, 1, 1, 0xFF, 2); // depends on r1
        // r2 starts at 3, done at 4
        // max_done = 4, cost = max(4 - 3, 1) = 1
        assert_eq!(sim.flush_and_get_cost(), 1);
    }

    #[test]
    fn test_feed_bitmask_multiple_sources() {
        let mut sim = GasSimulator::new();
        sim.feed_direct(2, 1, 0xFF, 0xFF, 0); // r0 done at 2
        sim.feed_direct(3, 1, 0xFF, 0xFF, 1); // r1 done at 3
        sim.feed(&FastCost {
            cycles: 1,
            decode_slots: 1,
            exec_unit: 1,                  // ALU
            src_mask: (1 << 0) | (1 << 1), // r0 + r1
            dst_mask: 1 << 2,              // r2
            is_terminator: false,
            is_move_reg: false,
        });
        // r2 starts at max(2, 3) = 3, done at 4
        // max_done = 4, cost = max(4 - 3, 1) = 1
        assert_eq!(sim.flush_and_get_cost(), 1);
    }

    // === reset ===

    #[test]
    fn test_reset_clears_state() {
        let mut sim = GasSimulator::new();
        sim.feed_direct(10, 1, 0xFF, 0xFF, 0); // large cost
        assert!(sim.flush_and_get_cost() > 1);
        sim.reset();
        assert_eq!(sim.flush_and_get_cost(), 1, "after reset, cost should be 1");
    }
}

#[cfg(test)]
mod proptests {
    use super::*;
    use proptest::prelude::*;

    proptest! {
        /// flush_and_get_cost always returns at least 1.
        #[test]
        fn cost_always_at_least_one(
            instrs in proptest::collection::vec(
                (1u8..20, 1u8..4, 0u8..13, 0u8..13),
                0..10,
            ),
        ) {
            let mut sim = GasSimulator::new();
            for (cycles, slots, src, dst) in &instrs {
                sim.feed_direct(*cycles, *slots, *src, 0xFF, *dst);
            }
            prop_assert!(sim.flush_and_get_cost() >= 1);
        }

        /// reset returns the simulator to the empty state (cost = 1).
        #[test]
        fn reset_restores_empty_state(
            instrs in proptest::collection::vec(
                (1u8..20, 1u8..4, 0u8..13, 0u8..13),
                1..10,
            ),
        ) {
            let mut sim = GasSimulator::new();
            for (cycles, slots, src, dst) in &instrs {
                sim.feed_direct(*cycles, *slots, *src, 0xFF, *dst);
            }
            sim.reset();
            prop_assert_eq!(sim.flush_and_get_cost(), 1);
        }

        /// Independent instructions (no register deps) never cost more than
        /// a dependency chain of the same length would.
        #[test]
        fn independent_no_more_than_chained(
            count in 1usize..8,
            cycles in 1u8..10,
        ) {
            // Independent: all use different dst, no src deps
            let mut indep = GasSimulator::new();
            for i in 0..count.min(13) {
                indep.feed_direct(cycles, 1, 0xFF, 0xFF, i as u8);
            }
            // Chained: r0 -> r1 -> r2 -> ...
            let mut chain = GasSimulator::new();
            for i in 0..count.min(12) {
                chain.feed_direct(cycles, 1, i as u8, 0xFF, (i + 1) as u8);
            }
            prop_assert!(indep.flush_and_get_cost() <= chain.flush_and_get_cost());
        }

        /// feed_direct with no sources and no dest (0xFF) is equivalent to
        /// a no-dep instruction — cost grows only from decode throughput.
        #[test]
        fn no_reg_deps_bounded_by_decode(
            count in 1usize..20,
            cycles in 1u8..5,
        ) {
            let mut sim = GasSimulator::new();
            for _ in 0..count {
                sim.feed_direct(cycles, 1, 0xFF, 0xFF, 0xFF);
            }
            // max_done = (cycle_when_last_decoded) + cycles
            // With 4 decode slots/cycle, last decode is at cycle floor((count-1)/4)
            // So max_done <= floor((count-1)/4) + cycles
            let expected_max = ((count - 1) / 4) as u32 + cycles as u32;
            let cost = sim.flush_and_get_cost();
            let expected_cost = if expected_max > 3 { expected_max - 3 } else { 1 };
            prop_assert_eq!(cost, expected_cost);
        }

        /// feed and feed_direct produce the same cost for single-source,
        /// single-dest instructions.
        #[test]
        fn feed_matches_feed_direct(
            cycles in 1u8..20,
            decode_slots in 1u8..4,
            src in 0u8..13,
            dst in 0u8..13,
        ) {
            let mut sim_direct = GasSimulator::new();
            sim_direct.feed_direct(cycles, decode_slots, src, 0xFF, dst);

            let mut sim_feed = GasSimulator::new();
            sim_feed.feed(&FastCost {
                cycles,
                decode_slots,
                exec_unit: 1,
                src_mask: 1u16 << src,
                dst_mask: 1u16 << dst,
                is_terminator: false,
                is_move_reg: false,
            });

            prop_assert_eq!(
                sim_direct.flush_and_get_cost(),
                sim_feed.flush_and_get_cost()
            );
        }

        /// Adding more instructions never decreases the cost.
        #[test]
        fn cost_monotonic_with_instructions(
            base_count in 1usize..6,
            extra_count in 1usize..4,
            cycles in 1u8..10,
        ) {
            let mut sim_base = GasSimulator::new();
            let mut sim_more = GasSimulator::new();
            for i in 0..base_count.min(12) {
                sim_base.feed_direct(cycles, 1, i as u8, 0xFF, (i + 1) as u8);
                sim_more.feed_direct(cycles, 1, i as u8, 0xFF, (i + 1) as u8);
            }
            let base_cost = sim_base.flush_and_get_cost();
            let last = base_count.min(12);
            for i in 0..extra_count.min(12 - last) {
                sim_more.feed_direct(cycles, 1, (last + i) as u8, 0xFF, (last + i + 1).min(12) as u8);
            }
            prop_assert!(sim_more.flush_and_get_cost() >= base_cost);
        }
    }
}
