//! In-memory `Hardware` impl + same-process broadcast bus.
//!
//! For tests and the `jar` binary's testnet driver. Networking is a fan-out
//! `mpsc::Sender` set; each node has its own inbound `Receiver`.

use std::collections::{BTreeMap, BTreeSet};
use std::sync::{Arc, Mutex};

use jar_crypto::ed25519::KeyPair;
use jar_types::{BlockHash, Command, KeyId, Signature, SlotContent, VaultId};

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
/// fork-tree bookkeeping.
pub struct InMemoryHardware {
    pub keys: BTreeMap<KeyId, KeyPair>,
    pub bus: Arc<InMemoryBus>,
    pub trace: Mutex<Vec<TracingEvent>>,
    pub fork_tree: Mutex<ForkTree>,
}

impl InMemoryHardware {
    pub fn new(bus: Arc<InMemoryBus>) -> Self {
        Self {
            keys: BTreeMap::new(),
            bus,
            trace: Mutex::new(Vec::new()),
            fork_tree: Mutex::new(ForkTree::default()),
        }
    }

    pub fn with_key(mut self, kp: KeyPair) -> Self {
        self.keys.insert(kp.key_id(), kp);
        self
    }
}

impl Hardware for InMemoryHardware {
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

    fn score(&self, block_hash: BlockHash, score: u64) {
        let mut t = self.fork_tree.lock().unwrap();
        t.scores.insert(block_hash, score);
        // Naive head choice: highest score wins. Phase 1 placeholder.
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
