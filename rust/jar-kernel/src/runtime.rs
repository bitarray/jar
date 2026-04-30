//! Runtime layer — `Hardware` trait, in-memory impl, per-node off-chain state.
//!
//! The kernel core is a pure function over σ. The runtime supplies the
//! per-node concerns: signing keys, network outbox, off-chain aggregation
//! slots, javm code cache, fork-tree bookkeeping. Crypto (hash, verify,
//! block_hash) is kernel-static — see `crate::crypto`.

use std::collections::{BTreeMap, BTreeSet};
use std::sync::{Arc, Mutex};

use crate::crypto::ed25519::KeyPair;
use crate::types::{BlockHash, Command, Hash, KeyId, Signature, SlotContent, State, VaultId};

// -----------------------------------------------------------------------------
// Hardware trait
// -----------------------------------------------------------------------------

#[derive(thiserror::Error, Debug, Clone, Eq, PartialEq)]
pub enum HwError {
    #[error("hardware does not hold the requested key")]
    KeyAbsent,
    #[error("hardware sign failed: {0}")]
    SignFailure(String),
    #[error("hardware does not have state at block {0:?}")]
    StateAbsent(Hash),
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum TracingEvent {
    InvocationFault { reason: String },
    BlockPanic { reason: String },
}

pub trait Hardware: Send + Sync {
    // ---- state custody ----

    /// The chain's genesis state. Hardware was configured with this at
    /// construction time. Returned by `Kernel::new(None, …)`.
    fn genesis_state(&self) -> State;

    /// Look up the state previously committed against `block_hash`. Returns
    /// `None` if the hardware doesn't have it (block was never seen, was
    /// pruned, etc.).
    fn state_at(&self, block_hash: &Hash) -> Option<State>;

    /// Persist `(block_hash → state)`. Called by `Kernel::advance` after a
    /// successful block apply.
    fn commit_state(&self, block_hash: BlockHash, state: State);

    // ---- secret-key custody ----

    /// Whether this node holds the secret half of `key`. Decides
    /// proposer-vs-verifier per AttestationCap.
    fn holds_key(&self, key: &KeyId) -> bool;

    /// Sign `blob` with the secret half of `key`. Producer-mode AttestationCap.
    fn sign(&self, key: &KeyId, blob: &[u8]) -> Result<Signature, HwError>;

    // ---- network ----

    /// Emit a `Command` produced by `apply_block` /
    /// `handle_inbound_dispatch`. The runtime applies it (network broadcast,
    /// fork-tree update, …).
    fn emit(&self, cmd: Command);

    /// Subscribe to a Dispatch entrypoint's lite stream. The kernel calls
    /// this for each top-level Dispatch entrypoint discovered in σ at
    /// construction; hardware uses it to pre-register network filters.
    fn subscribe(&self, vault_id: VaultId) {
        let _ = vault_id;
    }

    // ---- fork tree ----

    /// Record the consensus score of a candidate block. Hardware uses this
    /// for fork choice; semantics are hardware-internal.
    fn score(&self, block_hash: BlockHash, score: u64) {
        let _ = (block_hash, score);
    }

    /// Mark a block finalized. Hardware can prune non-finalized siblings.
    fn finalize(&self, block_hash: BlockHash) {
        let _ = block_hash;
    }

    /// Current chain head per hardware's fork choice. `None` at genesis or
    /// before any block has been scored.
    fn head(&self) -> Option<BlockHash> {
        None
    }

    // ---- observability ----

    fn tracing_event(&self, ev: TracingEvent) {
        let _ = ev;
    }
}

// -----------------------------------------------------------------------------
// NodeOffchain — per-node state outside σ
// -----------------------------------------------------------------------------

/// Per-node off-chain state, **not** in σ. Owned by `Kernel<H>`. Slots
/// persist across blocks but are lost on restart. Bootstrap is chain-
/// defined; we start with all slots `Empty`.
pub struct NodeOffchain {
    pub slots: BTreeMap<VaultId, SlotContent>,
    pub subscriptions: BTreeSet<VaultId>,
    /// javm code-cache; reused across handle_inbound_dispatch arrivals.
    pub code_cache: javm::CodeCache,
}

impl Default for NodeOffchain {
    fn default() -> Self {
        Self::new()
    }
}

impl NodeOffchain {
    pub fn new() -> Self {
        Self {
            slots: BTreeMap::new(),
            subscriptions: BTreeSet::new(),
            code_cache: javm::CodeCache::new(),
        }
    }

    pub fn slot(&self, ep: VaultId) -> &SlotContent {
        self.slots.get(&ep).unwrap_or(&SlotContent::Empty)
    }

    pub fn set_slot(&mut self, ep: VaultId, content: SlotContent) {
        if matches!(content, SlotContent::Empty) {
            self.slots.remove(&ep);
        } else {
            self.slots.insert(ep, content);
        }
    }
}

// -----------------------------------------------------------------------------
// In-memory Hardware impl + same-process broadcast bus
// -----------------------------------------------------------------------------

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
