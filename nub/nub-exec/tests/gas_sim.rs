use nub_exec::gas_cost::FastCost;
use nub_exec::gas_sim::GasSimulator;
use proptest::prelude::*;

// === flush_and_get_cost ===

#[test]
fn empty_block_cost_is_one() {
    let sim = GasSimulator::new();
    assert_eq!(sim.flush_and_get_cost(), 1, "empty block should cost 1");
}

// === feed_direct ===

#[test]
fn single_alu_instruction() {
    // One ALU op: 1 cycle, 1 decode slot, r0 → r2
    let mut sim = GasSimulator::new();
    sim.feed_direct(1, 1, 0, 0xFF, 2); // src1=r0, no src2, dst=r2
    assert_eq!(sim.flush_and_get_cost(), 1);
}

#[test]
fn data_dependency_chain() {
    // Chain: r0 → r1 (1 cycle), r1 → r2 (1 cycle)
    let mut sim = GasSimulator::new();
    sim.feed_direct(1, 1, 0, 0xFF, 1);
    sim.feed_direct(1, 1, 1, 0xFF, 2);
    assert_eq!(sim.flush_and_get_cost(), 1);
}

#[test]
fn long_dependency_chain() {
    // 5-deep chain, each 1 cycle: r0→r1→r2→r3→r4→r5
    let mut sim = GasSimulator::new();
    for i in 0..5u8 {
        sim.feed_direct(1, 1, i, 0xFF, i + 1);
    }
    assert_eq!(sim.flush_and_get_cost(), 2);
}

#[test]
fn independent_instructions_parallel() {
    let mut sim = GasSimulator::new();
    sim.feed_direct(1, 1, 0, 0xFF, 2);
    sim.feed_direct(1, 1, 1, 0xFF, 3);
    assert_eq!(sim.flush_and_get_cost(), 1);
}

#[test]
fn multi_cycle_instruction() {
    let mut sim = GasSimulator::new();
    sim.feed_direct(4, 1, 0, 1, 2);
    assert_eq!(sim.flush_and_get_cost(), 1);
}

#[test]
fn high_latency_chain() {
    let mut sim = GasSimulator::new();
    sim.feed_direct(4, 1, 0, 1, 2);
    sim.feed_direct(1, 1, 2, 0xFF, 3);
    assert_eq!(sim.flush_and_get_cost(), 2);
}

#[test]
fn decode_throughput_limit() {
    let mut sim = GasSimulator::new();
    for i in 0..5u8 {
        sim.feed_direct(1, 1, 0xFF, 0xFF, i);
    }
    assert_eq!(sim.flush_and_get_cost(), 1);
}

#[test]
fn no_src_no_dst() {
    let mut sim = GasSimulator::new();
    sim.feed_direct(1, 1, 0xFF, 0xFF, 0xFF);
    assert_eq!(sim.flush_and_get_cost(), 1);
}

#[test]
fn two_sources() {
    let mut sim = GasSimulator::new();
    sim.feed_direct(3, 1, 0xFF, 0xFF, 1);
    sim.feed_direct(1, 1, 0, 1, 2);
    assert_eq!(sim.flush_and_get_cost(), 1);
}

// === feed (bitmask-based) ===

#[test]
fn feed_move_reg_propagates_done() {
    let mut sim = GasSimulator::new();
    sim.feed_direct(3, 1, 0xFF, 0xFF, 0);
    sim.feed(&FastCost {
        cycles: 0,
        decode_slots: 1,
        exec_unit: 0,
        src_mask: 1 << 0,
        dst_mask: 1 << 1,
        is_terminator: false,
        is_move_reg: true,
    });
    sim.feed_direct(1, 1, 1, 0xFF, 2);
    assert_eq!(sim.flush_and_get_cost(), 1);
}

#[test]
fn feed_bitmask_multiple_sources() {
    let mut sim = GasSimulator::new();
    sim.feed_direct(2, 1, 0xFF, 0xFF, 0);
    sim.feed_direct(3, 1, 0xFF, 0xFF, 1);
    sim.feed(&FastCost {
        cycles: 1,
        decode_slots: 1,
        exec_unit: 1,
        src_mask: (1 << 0) | (1 << 1),
        dst_mask: 1 << 2,
        is_terminator: false,
        is_move_reg: false,
    });
    assert_eq!(sim.flush_and_get_cost(), 1);
}

#[test]
fn reset_clears_state() {
    let mut sim = GasSimulator::new();
    sim.feed_direct(10, 1, 0xFF, 0xFF, 0);
    assert!(sim.flush_and_get_cost() > 1);
    sim.reset();
    assert_eq!(sim.flush_and_get_cost(), 1, "after reset, cost should be 1");
}

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

    /// reset returns the simulator to the empty state.
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

    /// Independent instructions never cost more than a dependency chain.
    #[test]
    fn independent_no_more_than_chained(
        count in 1usize..8,
        cycles in 1u8..10,
    ) {
        let mut indep = GasSimulator::new();
        for i in 0..count.min(13) {
            indep.feed_direct(cycles, 1, 0xFF, 0xFF, i as u8);
        }
        let mut chain = GasSimulator::new();
        for i in 0..count.min(12) {
            chain.feed_direct(cycles, 1, i as u8, 0xFF, (i + 1) as u8);
        }
        prop_assert!(indep.flush_and_get_cost() <= chain.flush_and_get_cost());
    }

    #[test]
    fn no_reg_deps_bounded_by_decode(
        count in 1usize..20,
        cycles in 1u8..5,
    ) {
        let mut sim = GasSimulator::new();
        for _ in 0..count {
            sim.feed_direct(cycles, 1, 0xFF, 0xFF, 0xFF);
        }
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

// ---- x3/x4 host-spill gas cost ----------------------------------------

#[test]
fn spilled_operands_charge_memory_cost() {
    use nub_exec::gas_cost::{DEFAULT_MEM_CYCLES, RV_KIND_ADD, rv_feed_gas_kind, rv_slot_u8};
    use nub_exec::gas_sim::GasSimulator;

    // Block cost of a single `add rd, rs1, rs2`, parameterised by the RV regs.
    let cost = |rd: u8, rs1: u8, rs2: u8| -> u32 {
        let mut sim = GasSimulator::new();
        rv_feed_gas_kind(
            RV_KIND_ADD,
            rv_slot_u8(rs1),
            rv_slot_u8(rs2),
            rv_slot_u8(rd),
            &mut sim,
            DEFAULT_MEM_CYCLES,
        );
        sim.flush_and_get_cost()
    };

    let mem = DEFAULT_MEM_CYCLES as u32;
    // Baseline: all host-mapped registers (no spill) — the cheapest block.
    let base = cost(10, 5, 6);
    // A spilled operand raises the cost above the no-spill baseline.
    assert!(cost(10, 3, 6) > base, "spill must cost more than no-spill");
    // Each *additional* spilled operand position adds exactly `mem_cycles`
    // (the block-cost `-3` normalisation cancels between adjacent counts).
    assert_eq!(cost(10, 3, 4) - cost(10, 3, 6), mem, "2nd spilled operand");
    assert_eq!(cost(3, 3, 4) - cost(10, 3, 4), mem, "3rd spilled operand");
    // Conformant code (no x3/x4) is charged exactly the baseline.
    assert_eq!(cost(15, 14, 13), base);
}
