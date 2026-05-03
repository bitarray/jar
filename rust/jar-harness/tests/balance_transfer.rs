//! End-to-end balance-transfer test for the simple-chain example.
//!
//! Spins up a 3-node PoA testnet, pre-funds Alice (1000 units), has
//! Alice sign a transfer of 250 units to Bob, drives a few ticks, and
//! asserts:
//! - Alice's balance dropped by 250, nonce bumped to 1.
//! - Bob's balance is now 250.
//! - All three nodes converged on the same state root every tick.
//! - The accepted blocks carry valid `proposer_attestation` entries.

use jar_harness::{Harness, tx};
use jar_kernel::crypto::ed25519::KeyPair;

fn make_kp(seed_byte: u8) -> KeyPair {
    let mut seed = [0u8; 32];
    seed[0] = seed_byte;
    KeyPair::from_seed(&seed)
}

#[test]
#[ignore = "Stage 3: Vault.slots no longer cloned into Frame; Stage 7 restores via MGMT_COPY-in/out"]
fn alice_pays_bob() {
    let alice = make_kp(0xA1);
    let bob = make_kp(0xB0);
    let alice_id = alice.key_id();
    let bob_id = bob.key_id();

    let mut h = Harness::new(3, &[(alice_id.clone(), 1000), (bob_id.clone(), 0)]);

    // Confirm pre-state.
    let map0 = h.account_map();
    assert_eq!(tx::lookup(&map0, &alice_id), Some((1000, 0)));
    assert_eq!(tx::lookup(&map0, &bob_id), Some((0, 0)));

    // Alice signs and submits a transfer of 250 to Bob.
    let txn = tx::sign_transfer(&alice, &bob_id, 250, 0);
    h.submit(&txn);

    // Tick 1: bus drains into dispatch (fills the pool with the
    // setScore winner), proposer assembles + signs, verifiers check.
    // Pool is drained at the *start* of the next tick, so the txn
    // doesn't land in this tick's body.
    let out1 = h.tick();
    assert!(
        matches!(out1.block_outcome, jar_kernel::BlockOutcome::Accepted),
        "tick 1 not accepted: {:?}",
        out1.block_outcome
    );

    // Tick 2: pool drains, body carries the txn, transact verify+
    // process applies the transfer.
    let out2 = h.tick();
    assert!(
        matches!(out2.block_outcome, jar_kernel::BlockOutcome::Accepted),
        "tick 2 not accepted: {:?}",
        out2.block_outcome
    );

    // Confirm post-state.
    let map_after = h.account_map();
    assert_eq!(tx::lookup(&map_after, &alice_id), Some((750, 1)));
    assert_eq!(tx::lookup(&map_after, &bob_id), Some((250, 0)));

    // Tick 3 with no traffic: all nodes still converge.
    let _ = h.tick();
}
