//! Multi-node integration harness for example JAR chains.
//!
//! Spins up N nodes sharing an `InMemoryBus`, drives a round-robin
//! PoA proposer schedule, and routes off-chain `emit_event` traffic
//! through each node's `Kernel::dispatch`. Used by integration tests
//! that need a realistic end-to-end chain.

#![forbid(unsafe_code)]

pub mod genesis;
pub mod tx;

use std::sync::Arc;
use std::sync::mpsc::Receiver;

use jar_kernel::crypto::ed25519::KeyPair;
use jar_kernel::runtime::{InMemoryBus, InMemoryHardware, NetMessage};
use jar_kernel::{AdvanceOutcome, Kernel, KeyId};

/// PVM blob bytes for the simple-chain Vault.initialize program.
pub const SIMPLE_CHAIN_BLOB: &[u8] = include_bytes!(env!("SIMPLE_CHAIN_BLOB_PATH"));

/// One node in the harness.
pub struct Node {
    pub kernel: Kernel<InMemoryHardware>,
    pub validator: Option<KeyPair>,
    pub inbox: Receiver<NetMessage>,
}

/// 3-node testnet around a shared bus.
pub struct Harness {
    pub nodes: Vec<Node>,
    pub bus: Arc<InMemoryBus>,
    pub validators: Vec<KeyPair>,
    pub slot: u64,
}

impl Harness {
    /// Build a harness with `num_validators` validator nodes (each
    /// holding its KeyPair). Genesis pre-funds `accounts`. The harness
    /// owns deterministic validator seeds (0..num_validators) for
    /// reproducible tests.
    pub fn new(num_validators: usize, accounts: &[(KeyId, u64)]) -> Self {
        let validators: Vec<KeyPair> = (0..num_validators)
            .map(|i| {
                let mut seed = [0u8; 32];
                seed[0] = (i as u8) + 1;
                KeyPair::from_seed(&seed)
            })
            .collect();
        let validator_keys: Vec<KeyId> = validators.iter().map(|kp| kp.key_id()).collect();

        let state = genesis::build(&validator_keys, accounts);

        let bus = InMemoryBus::new();
        let mut nodes = Vec::with_capacity(num_validators);
        for kp in &validators {
            let inbox = bus.add_inbox();
            let hw = InMemoryHardware::new(state.clone(), bus.clone()).with_key(kp.clone());
            let kernel = Kernel::new(None, hw).expect("kernel new");
            nodes.push(Node {
                kernel,
                validator: Some(kp.clone()),
                inbox,
            });
        }

        Self {
            nodes,
            bus,
            validators,
            slot: 0,
        }
    }

    /// Submit a signed transaction by emitting it onto the bus addressed
    /// at `dispatch_endpoints[0]`. Subsequent ticks will route it through
    /// each node's `Kernel::dispatch`.
    pub fn submit(&self, txn_bytes: &[u8]) {
        self.bus.broadcast(NetMessage::Emit {
            target_path: 0u32.to_le_bytes().to_vec(),
            blob: txn_bytes.to_vec(),
            attestation_traces: Vec::new(),
        });
    }

    /// Drive one slot of the chain:
    ///   1) Drain each node's bus inbox into `Kernel::dispatch`
    ///      (off-chain verify + setScore populates the pool).
    ///   2) The slot's round-robin proposer calls `advance(None,
    ///      Some(its_validator_key))` to assemble + sign + apply.
    ///   3) Verifiers call `advance(Some(block), None)` and assert
    ///      state-root convergence.
    pub fn tick(&mut self) -> AdvanceOutcome {
        self.slot += 1;

        // (1) drain inboxes
        for node in self.nodes.iter_mut() {
            while let Ok(msg) = node.inbox.try_recv() {
                match msg {
                    NetMessage::Emit {
                        target_path, blob, ..
                    } => {
                        // Drop dispatch faults silently — verify-side
                        // panics simply discard the txn.
                        let _ = node.kernel.dispatch(&target_path, &blob);
                    }
                }
            }
        }

        let n = self.nodes.len();
        let proposer_idx = ((self.slot - 1) as usize) % n;

        // (2) propose
        let proposer_key = self.validators[proposer_idx].key_id();
        let proposed = self.nodes[proposer_idx]
            .kernel
            .advance(None, Some(proposer_key))
            .expect("propose ok");

        // (3) verifiers
        let new_root = proposed.state_root;
        let new_hash = proposed.block_hash;
        for (i, node) in self.nodes.iter_mut().enumerate() {
            if i == proposer_idx {
                continue;
            }
            let ver = node
                .kernel
                .advance(Some(proposed.block.clone()), None)
                .expect("verifier advance ok");
            assert_eq!(
                ver.state_root, new_root,
                "node {} state_root diverged at slot {}",
                i, self.slot
            );
            assert_eq!(
                ver.block_hash, new_hash,
                "node {} block_hash diverged at slot {}",
                i, self.slot
            );
        }

        proposed
    }

    /// Read the current account-map content from node 0's σ. Returns
    /// the raw 4 KiB page (64 records of 64 bytes each).
    pub fn account_map(&self) -> Vec<u8> {
        let state = self.nodes[0].kernel.state();
        let vault_id = state
            .transact_endpoints
            .first()
            .expect("transact endpoint 0")
            .vault_id;
        let vault = state.vaults.get(&vault_id).expect("vault present");
        match vault.slots.get(genesis::ACCOUNT_MAP_SLOT) {
            Some(jar_kernel::cap::RegCap::Data(d)) => (*d.content).clone(),
            other => panic!(
                "expected RegCap::Data at slot {} got {:?}",
                genesis::ACCOUNT_MAP_SLOT,
                other
            ),
        }
    }
}
