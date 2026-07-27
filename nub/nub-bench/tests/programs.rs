//! End-to-end coverage for the whole nub program pipeline.
//!
//! Guest crate → cross-compile → link → encode → decode → prepare →
//! interpret, asserted against pinned `(return_value, gas_used)`.
//!
//! These are the same numbers jar's `javm-bench/tests/workloads.rs`
//! pins for the capability path. The duplication is the point: the
//! flat path and the cap path must charge identically, so if these two
//! files ever disagree, one of the two lowerings has drifted.

use nub_bench::PROGRAMS;

#[test]
fn every_program_matches_its_pinned_value_and_gas() {
    for p in PROGRAMS {
        let blob = p.decode();
        let (value, gas) = nub_bench::run_interpreter(p.name, &blob);
        assert_eq!(
            value, p.expected_value,
            "[{}] return value drifted: got {value:#x}, expected {:#x}",
            p.name, p.expected_value,
        );
        assert_eq!(
            gas, p.expected_gas,
            "[{}] gas drifted: got {gas}, expected {}",
            p.name, p.expected_gas,
        );
    }
}

/// A blob must survive the round trip the build script and every
/// consumer rely on.
#[test]
fn every_blob_round_trips_through_the_codec() {
    for p in PROGRAMS {
        let blob = p.decode();
        let reencoded = blob.to_bytes();
        assert_eq!(
            reencoded.as_slice(),
            p.blob,
            "[{}] re-encoding is not byte-identical to the build output",
            p.name,
        );
        assert_eq!(
            nub_program::ProgramBlob::from_bytes(&reencoded).expect("re-decode"),
            blob,
            "[{}] decode(encode(x)) != x",
            p.name,
        );
    }
}

/// Every program declares endpoint 0 and lands its entry inside code.
#[test]
fn every_program_declares_a_well_formed_endpoint_zero() {
    for p in PROGRAMS {
        let blob = p.decode();
        let ep = blob
            .endpoints
            .get(&0)
            .unwrap_or_else(|| panic!("[{}] has no endpoint 0", p.name));
        assert!(
            (ep.entry_pc as usize) < blob.code.len(),
            "[{}] entry_pc {:#x} is past the {:#x}-byte code region",
            p.name,
            ep.entry_pc,
            blob.code.len(),
        );
        // The linker seeds SP with the top of the stack region.
        assert_eq!(
            ep.initial_regs.get(&nub_program::abi::SP_REG).copied(),
            Some(blob.regions.stack_top()),
            "[{}] SP is not seeded with the stack top",
            p.name,
        );
    }
}

/// Re-running a program in a fresh address space must be deterministic.
/// This is what makes the pinned gas numbers meaningful.
#[test]
fn repeated_runs_are_deterministic() {
    for p in PROGRAMS {
        let blob = p.decode();
        let first = nub_bench::run_interpreter(p.name, &blob);
        let second = nub_bench::run_interpreter(p.name, &blob);
        assert_eq!(first, second, "[{}] run is not deterministic", p.name);
    }
}
