//! In-memory `Hardware` impl + same-process broadcast bus.
//!
//! For tests and the `jar` binary's testnet driver. Networking is a fan-out
//! `mpsc::Sender` set; each node has its own inbound `Receiver`.

use std::collections::BTreeMap;
use std::sync::{Arc, Mutex};

use jar_crypto::{Ed25519Blake, blake2b_256, ed25519::KeyPair};
use jar_types::{Command, Crypto, Hash, KeyId, Signature, SlotContent, VaultId};

use super::hardware::{Hardware, HwError, TracingEvent};

/// One inbound message arriving at a node. Carries `SlotContent` tagged with
/// the Hardware impl (`InMemoryHardware`) — same fields as
/// `SlotContent<Ed25519Blake>`, but Rust treats parametric types as distinct
/// per-tag.
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
        content: SlotContent<InMemoryHardware>,
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

/// In-memory Hardware: holds a set of validator keys + bus reference.
pub struct InMemoryHardware {
    pub keys: BTreeMap<KeyId, KeyPair>,
    pub bus: Arc<InMemoryBus>,
    pub trace: Mutex<Vec<TracingEvent>>,
}

impl InMemoryHardware {
    pub fn new(bus: Arc<InMemoryBus>) -> Self {
        Self {
            keys: BTreeMap::new(),
            bus,
            trace: Mutex::new(Vec::new()),
        }
    }

    pub fn with_key(mut self, kp: KeyPair) -> Self {
        self.keys.insert(kp.key_id(), kp);
        self
    }
}

impl Crypto for InMemoryHardware {
    type Hash = Hash;
    type Signature = Signature;
    type KeyId = KeyId;

    fn hash_from_bytes(b: &[u8]) -> Option<Hash> {
        <Ed25519Blake as Crypto>::hash_from_bytes(b)
    }
    fn key_id_from_bytes(b: &[u8]) -> Option<KeyId> {
        <Ed25519Blake as Crypto>::key_id_from_bytes(b)
    }
    fn signature_from_bytes(b: &[u8]) -> Option<Signature> {
        <Ed25519Blake as Crypto>::signature_from_bytes(b)
    }
}

impl Hardware for InMemoryHardware {
    fn hash(&self, blob: &[u8]) -> Hash {
        blake2b_256(blob)
    }

    fn verify(&self, key: KeyId, msg: &[u8], sig: &Signature) -> bool {
        jar_crypto::ed25519::verify(key, msg, sig)
    }

    fn holds_key(&self, key: KeyId) -> bool {
        self.keys.contains_key(&key)
    }

    fn sign(&self, key: KeyId, blob: &[u8]) -> Result<Signature, HwError> {
        let kp = self.keys.get(&key).ok_or(HwError::KeyAbsent)?;
        Ok(kp.sign(blob))
    }

    fn emit(&self, cmd: Command<Self>) {
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
        }
    }

    fn tracing_event(&self, ev: TracingEvent) {
        self.trace.lock().unwrap().push(ev);
    }
}
