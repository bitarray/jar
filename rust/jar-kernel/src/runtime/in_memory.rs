//! In-memory `Hardware` impl + same-process broadcast bus.
//!
//! For tests and the `jar` binary's testnet driver. Networking is a fan-out
//! `mpsc::Sender` set; each node has its own inbound `Receiver`.

use std::collections::{BTreeMap, BTreeSet};
use std::sync::{Arc, Mutex};

use crate::crypto_primitives::ed25519::KeyPair;
use crate::types::{BlockHash, Command, Hash, KeyId, Signature, SlotContent, State, VaultId};

use super::hardware::{Hardware, HwError, TracingEvent};

/// One inbound message arriving at a node.
#[derive(Clone, Debug)]
pub enum NetMessage {
    /// A new Dispatch event for an entrypoint.
    Dispatch {
        entrypoint: VaultId,
        payload: Vec<u8>,
        caps: Vec<u8>,
    },
    /// A lite-stream slot update.
    LiteUpdate {
        entrypoint: VaultId,
        content: SlotContent,
    },
}

/// In-process broadcast bus shared by all nodes in a testnet.
#[derive(Default)]
pub struct InMemoryBus {
    inboxes: Mutex<Vec<std::sync::mpsc::Sender<NetMessage>>>,
}

impl InMemoryBus {
    pub fn new() -> Arc<Self> {
        Arc::new(Self::default())
    }

    pub fn add_inbox(&self) -> std::sync::mpsc::Receiver<NetMessage> {
        let (tx, rx) = std::sync::mpsc::channel();
        self.inboxes.lock().unwrap().push(tx);
        rx
    }

    pub fn broadcast(&self, msg: NetMessage) {
        let mut guard = self.inboxes.lock().unwrap();
        // Send to every inbox; drop closed channels.
        guard.retain(|tx| tx.send(msg.clone()).is_ok());
    }
}

/// Hardware-side per-block bookkeeping. Tracks scores and finality flags
/// keyed by the kernel-computed `block_hash`. Phase 1 is informational
/// only — the testnet doesn't actually do fork choice.
#[derive(Clone, Default, Debug)]
pub struct ForkTree {
    pub scores: BTreeMap<BlockHash, u64>,
    pub finalized: BTreeSet<BlockHash>,
    pub head: Option<BlockHash>,
}

/// In-memory Hardware: holds a set of validator keys + bus reference +
/// genesis state + a state log keyed by `block_hash` + fork-tree
/// bookkeeping. One per node.
pub struct InMemoryHardware {
    keys: BTreeMap<KeyId, KeyPair>,
    bus: Arc<InMemoryBus>,
    trace: Mutex<Vec<TracingEvent>>,
    fork_tree: Mutex<ForkTree>,
    genesis: State,
    states: Mutex<BTreeMap<BlockHash, State>>,
    subscriptions: Mutex<BTreeSet<VaultId>>,
}

impl InMemoryHardware {
    /// Build hardware seeded with `genesis`. `bus` is shared across nodes
    /// in a testnet for in-process networking.
    pub fn new(genesis: State, bus: Arc<InMemoryBus>) -> Self {
        Self {
            keys: BTreeMap::new(),
            bus,
            trace: Mutex::new(Vec::new()),
            fork_tree: Mutex::new(ForkTree::default()),
            genesis,
            states: Mutex::new(BTreeMap::new()),
            subscriptions: Mutex::new(BTreeSet::new()),
        }
    }

    pub fn with_key(mut self, kp: KeyPair) -> Self {
        self.keys.insert(kp.key_id(), kp);
        self
    }

    /// Read access to recorded subscriptions — useful for tests.
    pub fn subscriptions_snapshot(&self) -> BTreeSet<VaultId> {
        self.subscriptions.lock().unwrap().clone()
    }

    /// Read access to recorded tracing events — useful for tests.
    pub fn drain_trace(&self) -> Vec<TracingEvent> {
        std::mem::take(&mut *self.trace.lock().unwrap())
    }
}

impl Hardware for InMemoryHardware {
    fn genesis_state(&self) -> State {
        self.genesis.clone()
    }

    fn state_at(&self, block_hash: &Hash) -> Option<State> {
        self.states.lock().unwrap().get(block_hash).cloned()
    }

    fn commit_state(&self, block_hash: BlockHash, state: State) {
        self.states.lock().unwrap().insert(block_hash, state);
    }

    fn holds_key(&self, key: &KeyId) -> bool {
        self.keys.contains_key(key)
    }

    fn sign(&self, key: &KeyId, blob: &[u8]) -> Result<Signature, HwError> {
        let kp = self.keys.get(key).ok_or(HwError::KeyAbsent)?;
        Ok(kp.sign(blob))
    }

    fn emit(&self, cmd: Command) {
        match cmd {
            Command::Dispatch {
                entrypoint,
                payload,
                caps,
            } => self.bus.broadcast(NetMessage::Dispatch {
                entrypoint,
                payload,
                caps,
            }),
            Command::BroadcastLite {
                entrypoint,
                content,
            } => self.bus.broadcast(NetMessage::LiteUpdate {
                entrypoint,
                content,
            }),
            Command::Score { block_hash, score } => {
                self.score(block_hash, score);
            }
            Command::Finalize { block_hash } => {
                self.finalize(block_hash);
            }
        }
    }

    fn subscribe(&self, vault_id: VaultId) {
        self.subscriptions.lock().unwrap().insert(vault_id);
    }

    fn score(&self, block_hash: BlockHash, score: u64) {
        let mut t = self.fork_tree.lock().unwrap();
        t.scores.insert(block_hash, score);
        match t.head {
            Some(head) if t.scores.get(&head).copied().unwrap_or(0) >= score => {}
            _ => t.head = Some(block_hash),
        }
    }

    fn finalize(&self, block_hash: BlockHash) {
        self.fork_tree.lock().unwrap().finalized.insert(block_hash);
    }

    fn head(&self) -> Option<BlockHash> {
        self.fork_tree.lock().unwrap().head
    }

    fn tracing_event(&self, ev: TracingEvent) {
        self.trace.lock().unwrap().push(ev);
    }
}
