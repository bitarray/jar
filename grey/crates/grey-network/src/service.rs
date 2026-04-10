//! Network service using libp2p gossipsub and request-response.
//!
//! Provides:
//! - Gossipsub: block, finality, guarantee, assurance propagation
//! - Request-response: chunk fetch, block fetch for sync
//! - Peer tracking: validator index ↔ PeerId mapping

use libp2p::{
    Multiaddr, PeerId, Swarm, SwarmBuilder, gossipsub, identify, noise, request_response, tcp,
    yamux,
};
use std::collections::HashMap;
use std::collections::hash_map::DefaultHasher;
use std::hash::{Hash, Hasher};
use std::time::Duration;
use tokio::sync::{mpsc, oneshot};

/// Gossipsub topic for block announcements.
const BLOCKS_TOPIC: &str = "/jam/blocks/1";
/// Gossipsub topic for finality votes.
const FINALITY_TOPIC: &str = "/jam/finality/1";
/// Gossipsub topic for work report guarantees.
const GUARANTEES_TOPIC: &str = "/jam/guarantees/1";
/// Gossipsub topic for availability assurances.
const ASSURANCES_TOPIC: &str = "/jam/assurances/1";
/// Gossipsub topic for audit announcements.
const ANNOUNCEMENTS_TOPIC: &str = "/jam/announcements/1";
/// Gossipsub topic for Safrole ticket submissions.
const TICKETS_TOPIC: &str = "/jam/tickets/1";
/// Gossipsub topic for §17 equivocation evidence and countersignatures.
const EQUIVOCATION_TOPIC: &str = "/jam/equivocation/1";

/// Messages that the network service can send to the node.
#[derive(Debug)]
pub enum NetworkEvent {
    /// A new block was received from a peer.
    BlockReceived { data: Vec<u8>, source: PeerId },
    /// A finality vote was received from a peer.
    FinalityVote { data: Vec<u8>, source: PeerId },
    /// A work report guarantee was received from a peer.
    GuaranteeReceived { data: Vec<u8>, source: PeerId },
    /// An availability assurance was received from a peer.
    AssuranceReceived { data: Vec<u8>, source: PeerId },
    /// An audit announcement was received from a peer.
    AnnouncementReceived { data: Vec<u8>, source: PeerId },
    /// A ticket proof was received from a peer.
    TicketReceived { data: Vec<u8>, source: PeerId },
    /// Equivocation evidence or countersignature received from a peer.
    EquivocationReceived { data: Vec<u8>, source: PeerId },
    /// A chunk fetch request was received.
    ChunkRequest {
        report_hash: [u8; 32],
        chunk_index: u16,
        response_tx: oneshot::Sender<Option<Vec<u8>>>,
    },
    /// A block fetch request was received.
    BlockRequest {
        block_hash: [u8; 32],
        response_tx: oneshot::Sender<Option<Vec<u8>>>,
    },
    /// A new peer connected and identified as a validator.
    PeerIdentified {
        peer_id: PeerId,
        validator_index: Option<u16>,
    },
}

/// Commands that the node can send to the network service.
#[derive(Debug)]
pub enum NetworkCommand {
    /// Broadcast a block to the network.
    BroadcastBlock { data: Vec<u8> },
    /// Broadcast a finality vote.
    BroadcastFinalityVote { data: Vec<u8> },
    /// Broadcast a work report guarantee.
    BroadcastGuarantee { data: Vec<u8> },
    /// Broadcast an availability assurance.
    BroadcastAssurance { data: Vec<u8> },
    /// Broadcast an audit announcement.
    BroadcastAnnouncement { data: Vec<u8> },
    /// Broadcast a ticket proof.
    BroadcastTicket { data: Vec<u8> },
    /// Broadcast equivocation evidence or a countersignature.
    BroadcastEquivocation { data: Vec<u8> },
    /// Request a chunk from a specific peer.
    FetchChunk {
        peer: PeerId,
        report_hash: [u8; 32],
        chunk_index: u16,
        response_tx: oneshot::Sender<Option<Vec<u8>>>,
    },
    /// Request a block from a specific peer.
    FetchBlock {
        peer: PeerId,
        block_hash: [u8; 32],
        response_tx: oneshot::Sender<Option<Vec<u8>>>,
    },
}

/// Configuration for the network service.
pub struct NetworkConfig {
    /// IP address to listen on (e.g. "0.0.0.0" for all interfaces, "127.0.0.1" for loopback).
    pub listen_addr: String,
    /// Port to listen on.
    pub listen_port: u16,
    /// Peer addresses to connect to at startup.
    pub boot_peers: Vec<Multiaddr>,
    /// Validator index (for logging).
    pub validator_index: u16,
}

/// Peer tracking: map PeerId to validator info.
pub struct PeerTracker {
    /// PeerId → validator index (if known).
    peers: HashMap<PeerId, Option<u16>>,
    /// Validator index → PeerId (reverse lookup).
    validators: HashMap<u16, PeerId>,
}

impl PeerTracker {
    fn new() -> Self {
        Self {
            peers: HashMap::new(),
            validators: HashMap::new(),
        }
    }

    fn add_peer(&mut self, peer_id: PeerId) {
        self.peers.entry(peer_id).or_insert(None);
    }

    fn set_validator(&mut self, peer_id: PeerId, validator_index: u16) {
        self.peers.insert(peer_id, Some(validator_index));
        self.validators.insert(validator_index, peer_id);
    }

    fn remove_peer(&mut self, peer_id: &PeerId) {
        if let Some(Some(vi)) = self.peers.remove(peer_id) {
            self.validators.remove(&vi);
        }
    }

    fn peer_count(&self) -> usize {
        self.peers.len()
    }

    #[allow(dead_code)]
    fn get_peer_for_validator(&self, validator_index: u16) -> Option<&PeerId> {
        self.validators.get(&validator_index)
    }
}

/// Per-peer message rate tracker for gossipsub topics.
///
/// Tracks how many messages each peer has sent per topic within a sliding
/// window. When a peer exceeds the configured limit, a warning is logged.
struct PeerRateTracker {
    /// (PeerId, topic) → (count, window_start)
    counters: HashMap<(PeerId, &'static str), (u64, std::time::Instant)>,
    /// Time window for rate counting.
    window: Duration,
    /// Per-topic message limits per peer per window.
    limits: HashMap<&'static str, u64>,
}

impl PeerRateTracker {
    fn new(window: Duration) -> Self {
        let mut limits = HashMap::new();
        // Blocks: ~1 per 6s slot, allow some margin
        limits.insert(BLOCKS_TOPIC, 5);
        // Finality votes: V votes per round, allow generous headroom
        limits.insert(FINALITY_TOPIC, 50);
        // Guarantees: bounded by cores * validators
        limits.insert(GUARANTEES_TOPIC, 100);
        // Assurances: 1 per validator per slot
        limits.insert(ASSURANCES_TOPIC, 20);
        // Announcements: infrequent
        limits.insert(ANNOUNCEMENTS_TOPIC, 20);
        // Tickets: bounded by tickets_per_validator
        limits.insert(TICKETS_TOPIC, 50);
        // Equivocation: rare event, allow some countersig accumulation headroom
        limits.insert(EQUIVOCATION_TOPIC, 20);

        Self {
            counters: HashMap::new(),
            window,
            limits,
        }
    }

    /// Record a message from a peer on a topic. Returns true if within
    /// the rate limit, false if the peer exceeded the limit.
    fn record(&mut self, peer: &PeerId, topic: &'static str) -> bool {
        let now = std::time::Instant::now();
        let key = (*peer, topic);
        let entry = self.counters.entry(key).or_insert((0, now));

        // Reset window if expired
        if now.duration_since(entry.1) >= self.window {
            *entry = (0, now);
        }

        entry.0 += 1;

        let limit = self.limits.get(topic).copied().unwrap_or(100);
        entry.0 <= limit
    }

    /// Remove stale entries to bound memory usage.
    fn prune_stale(&mut self) {
        let now = std::time::Instant::now();
        self.counters
            .retain(|_, (_, start)| now.duration_since(*start) < self.window * 2);
    }
}

/// Read a length-prefixed message from an async reader.
/// Format: 4-byte LE length prefix, then that many bytes of payload.
async fn read_length_prefixed<T>(io: &mut T, max_size: usize) -> std::io::Result<Vec<u8>>
where
    T: futures::AsyncRead + Unpin + Send,
{
    use futures::AsyncReadExt;
    let mut len_buf = [0u8; 4];
    io.read_exact(&mut len_buf).await?;
    let len = u32::from_le_bytes(len_buf) as usize;
    if len > max_size {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "message too large",
        ));
    }
    let mut buf = vec![0u8; len];
    io.read_exact(&mut buf).await?;
    Ok(buf)
}

/// Write a length-prefixed message to an async writer and close.
async fn write_length_prefixed<T>(io: &mut T, data: &[u8]) -> std::io::Result<()>
where
    T: futures::AsyncWrite + Unpin + Send,
{
    use futures::AsyncWriteExt;
    let len = (data.len() as u32).to_le_bytes();
    io.write_all(&len).await?;
    io.write_all(data).await?;
    io.close().await?;
    Ok(())
}

/// JAM request-response protocol codec.
#[derive(Debug, Clone, Default)]
pub struct JamProtocol;

// Implement the request-response codec using async_trait
#[async_trait::async_trait]
impl request_response::Codec for JamProtocol {
    type Protocol = &'static str;
    type Request = Vec<u8>;
    type Response = Vec<u8>;

    async fn read_request<T>(
        &mut self,
        _protocol: &Self::Protocol,
        io: &mut T,
    ) -> std::io::Result<Self::Request>
    where
        T: futures::AsyncRead + Unpin + Send,
    {
        read_length_prefixed(io, 1024 * 1024).await
    }

    async fn read_response<T>(
        &mut self,
        _protocol: &Self::Protocol,
        io: &mut T,
    ) -> std::io::Result<Self::Response>
    where
        T: futures::AsyncRead + Unpin + Send,
    {
        read_length_prefixed(io, 10 * 1024 * 1024).await
    }

    async fn write_request<T>(
        &mut self,
        _protocol: &Self::Protocol,
        io: &mut T,
        req: Self::Request,
    ) -> std::io::Result<()>
    where
        T: futures::AsyncWrite + Unpin + Send,
    {
        write_length_prefixed(io, &req).await
    }

    async fn write_response<T>(
        &mut self,
        _protocol: &Self::Protocol,
        io: &mut T,
        resp: Self::Response,
    ) -> std::io::Result<()>
    where
        T: futures::AsyncWrite + Unpin + Send,
    {
        write_length_prefixed(io, &resp).await
    }
}

/// Create and run the network service.
///
/// Returns channels for communication with the network service.
/// Channel capacity for network events (network → node).
/// Sized for bursts: a full validator set can each send a block + vote + assurance
/// in a single slot. 1024 provides headroom without unbounded growth.
pub const EVENT_CHANNEL_CAPACITY: usize = 1024;

/// Channel capacity for network commands (node → network).
/// Node sends at a controlled rate (one broadcast per event processed).
pub const COMMAND_CHANNEL_CAPACITY: usize = 256;

/// Create and run the network service.
///
/// Returns:
/// - `event_rx`: receiver for network events (network → node)
/// - `cmd_tx`: sender for network commands (node → network)
/// - `event_tx_monitor`: clone of the event sender for queue depth monitoring
pub async fn start_network(
    config: NetworkConfig,
) -> Result<
    (
        mpsc::Receiver<NetworkEvent>,
        mpsc::Sender<NetworkCommand>,
        mpsc::Sender<NetworkEvent>,
    ),
    Box<dyn std::error::Error + Send + Sync>,
> {
    let (event_tx, event_rx) = mpsc::channel(EVENT_CHANNEL_CAPACITY);
    let event_tx_monitor = event_tx.clone();
    let (cmd_tx, cmd_rx) = mpsc::channel(COMMAND_CHANNEL_CAPACITY);

    // Build the swarm
    let mut swarm = build_swarm()?;

    // Subscribe to topics
    let blocks_topic = gossipsub::IdentTopic::new(BLOCKS_TOPIC);
    let finality_topic = gossipsub::IdentTopic::new(FINALITY_TOPIC);
    let guarantees_topic = gossipsub::IdentTopic::new(GUARANTEES_TOPIC);
    let assurances_topic = gossipsub::IdentTopic::new(ASSURANCES_TOPIC);
    let announcements_topic = gossipsub::IdentTopic::new(ANNOUNCEMENTS_TOPIC);
    let tickets_topic = gossipsub::IdentTopic::new(TICKETS_TOPIC);
    let equivocation_topic = gossipsub::IdentTopic::new(EQUIVOCATION_TOPIC);

    for (topic, name) in [
        (&blocks_topic, "blocks"),
        (&finality_topic, "finality"),
        (&guarantees_topic, "guarantees"),
        (&assurances_topic, "assurances"),
        (&announcements_topic, "announcements"),
        (&tickets_topic, "tickets"),
        (&equivocation_topic, "equivocation"),
    ] {
        swarm
            .behaviour_mut()
            .gossipsub
            .subscribe(topic)
            .map_err(|e| format!("Failed to subscribe to {name} topic: {e}"))?;
    }

    // Listen on the configured port
    let listen_addr: Multiaddr = format!("/ip4/{}/tcp/{}", config.listen_addr, config.listen_port)
        .parse()
        .map_err(|e| format!("Invalid listen address: {e}"))?;
    swarm.listen_on(listen_addr)?;

    let local_peer_id = *swarm.local_peer_id();
    tracing::info!(
        "Validator {} network started, peer_id={}",
        config.validator_index,
        local_peer_id
    );

    // Connect to boot peers
    for addr in &config.boot_peers {
        match swarm.dial(addr.clone()) {
            Ok(_) => tracing::info!(
                "Validator {} dialing boot peer: {}",
                config.validator_index,
                addr
            ),
            Err(e) => tracing::warn!(
                "Validator {} failed to dial {}: {}",
                config.validator_index,
                addr,
                e
            ),
        }
    }

    // Spawn the network event loop
    let validator_index = config.validator_index;
    let topics = TopicSet {
        blocks: blocks_topic,
        finality: finality_topic,
        guarantees: guarantees_topic,
        assurances: assurances_topic,
        announcements: announcements_topic,
        tickets: tickets_topic,
        equivocation: equivocation_topic,
    };
    tokio::spawn(async move {
        run_network_loop(swarm, event_tx, cmd_rx, topics, validator_index).await;
    });

    Ok((event_rx, cmd_tx, event_tx_monitor))
}

/// Behaviour combining gossipsub, identify, and request-response protocols.
#[derive(libp2p::swarm::NetworkBehaviour)]
struct JamBehaviour {
    gossipsub: gossipsub::Behaviour,
    identify: identify::Behaviour,
    reqres: request_response::Behaviour<JamProtocol>,
}

/// All gossipsub topics in one struct for passing around.
struct TopicSet {
    blocks: gossipsub::IdentTopic,
    finality: gossipsub::IdentTopic,
    guarantees: gossipsub::IdentTopic,
    assurances: gossipsub::IdentTopic,
    announcements: gossipsub::IdentTopic,
    tickets: gossipsub::IdentTopic,
    equivocation: gossipsub::IdentTopic,
}

fn build_swarm() -> Result<Swarm<JamBehaviour>, Box<dyn std::error::Error + Send + Sync>> {
    let swarm = SwarmBuilder::with_new_identity()
        .with_tokio()
        .with_tcp(
            tcp::Config::default(),
            noise::Config::new,
            yamux::Config::default,
        )?
        .with_behaviour(|key| {
            // Configure gossipsub
            let message_id_fn = |message: &gossipsub::Message| {
                let mut hasher = DefaultHasher::new();
                message.data.hash(&mut hasher);
                gossipsub::MessageId::from(hasher.finish().to_string())
            };

            let gossipsub_config = gossipsub::ConfigBuilder::default()
                .heartbeat_interval(Duration::from_secs(1))
                .validation_mode(gossipsub::ValidationMode::Strict)
                .message_id_fn(message_id_fn)
                .build()
                .expect("Valid gossipsub config");

            let gossipsub = gossipsub::Behaviour::new(
                gossipsub::MessageAuthenticity::Signed(key.clone()),
                gossipsub_config,
            )
            .expect("Valid gossipsub behaviour");

            let identify = identify::Behaviour::new(identify::Config::new(
                "/jam/0.1.0".to_string(),
                key.public(),
            ));

            // Request-response for chunk/block fetching
            let reqres = request_response::Behaviour::new(
                [("/jam/fetch/1", request_response::ProtocolSupport::Full)],
                request_response::Config::default().with_request_timeout(Duration::from_secs(10)),
            );

            JamBehaviour {
                gossipsub,
                identify,
                reqres,
            }
        })?
        .with_swarm_config(|c| c.with_idle_connection_timeout(Duration::from_secs(60)))
        .build();

    Ok(swarm)
}

async fn run_network_loop(
    mut swarm: Swarm<JamBehaviour>,
    event_tx: mpsc::Sender<NetworkEvent>,
    mut cmd_rx: mpsc::Receiver<NetworkCommand>,
    topics: TopicSet,
    validator_index: u16,
) {
    let mut peers = PeerTracker::new();

    // Priority-aware event sending. Under backpressure (>80% full), only
    // critical and high priority messages are accepted; lower priorities are
    // dropped to preserve liveness for finality and block propagation.
    //
    // Priority levels (from issue #178):
    //   Critical: finality votes (protocol liveness depends on these)
    //   High:     blocks, chunk/block requests (chain progress)
    //   Normal:   assurances, announcements (availability, audit)
    //   Low:      guarantees, tickets (can be re-requested)
    const BACKPRESSURE_THRESHOLD: usize = EVENT_CHANNEL_CAPACITY / 5; // 20% remaining

    /// Send an event with priority-based backpressure.
    /// - `critical` / `high`: always attempt to send, warn if channel full.
    /// - `normal` / `low`: drop early if channel is congested (below threshold).
    macro_rules! send_event {
        // High-priority: always attempt to send regardless of congestion.
        ($event:expr, critical) => {
            send_event!(@send $event, "CRITICAL");
        };
        ($event:expr, high) => {
            send_event!(@send $event, "high-priority");
        };
        // Lower-priority: drop proactively when channel is congested.
        ($event:expr, normal) => {
            send_event!(@backpressure $event, "normal-priority");
        };
        ($event:expr, low) => {
            send_event!(@backpressure $event, "low-priority");
        };
        // Internal: unconditional send attempt.
        (@send $event:expr, $label:expr) => {
            if let Err(mpsc::error::TrySendError::Full(_)) = event_tx.try_send($event) {
                tracing::warn!(
                    "Validator {} event channel full, dropping {} message",
                    validator_index,
                    $label,
                );
            }
        };
        // Internal: backpressure-aware send (drop if congested).
        (@backpressure $event:expr, $label:expr) => {
            if event_tx.capacity() < BACKPRESSURE_THRESHOLD {
                tracing::debug!(
                    "Validator {} event channel congested ({}/{}), dropping {} message",
                    validator_index,
                    EVENT_CHANNEL_CAPACITY - event_tx.capacity(),
                    EVENT_CHANNEL_CAPACITY,
                    $label,
                );
            } else {
                send_event!(@send $event, $label);
            }
        };
    }

    // Track pending request-response callbacks
    let mut pending_chunk_requests: HashMap<
        request_response::OutboundRequestId,
        oneshot::Sender<Option<Vec<u8>>>,
    > = HashMap::new();

    // Per-peer gossipsub message rate tracking (1-minute window)
    let mut rate_tracker = PeerRateTracker::new(Duration::from_secs(60));
    let mut rate_prune_interval = tokio::time::interval(Duration::from_secs(30));

    loop {
        tokio::select! {
            // Handle incoming swarm events
            event = swarm.next() => {
                use libp2p::swarm::SwarmEvent;
                let Some(event) = event else { break };
                match event {
                    SwarmEvent::Behaviour(JamBehaviourEvent::Gossipsub(
                        gossipsub::Event::Message { message, propagation_source, .. }
                    )) => {
                        let topic = message.topic.as_str();
                        // Macro to handle rate tracking + event dispatch per topic
                        macro_rules! dispatch_topic {
                            ($static_topic:expr, $event:ident, $priority:ident) => {{
                                if !rate_tracker.record(&propagation_source, $static_topic) {
                                    tracing::warn!(
                                        "Peer {} exceeding message rate limit on topic '{}'",
                                        propagation_source,
                                        $static_topic,
                                    );
                                }
                                send_event!(NetworkEvent::$event {
                                    data: message.data,
                                    source: propagation_source,
                                }, $priority);
                            }};
                        }
                        if topic == BLOCKS_TOPIC {
                            dispatch_topic!(BLOCKS_TOPIC, BlockReceived, high);
                        } else if topic == FINALITY_TOPIC {
                            dispatch_topic!(FINALITY_TOPIC, FinalityVote, critical);
                        } else if topic == GUARANTEES_TOPIC {
                            dispatch_topic!(GUARANTEES_TOPIC, GuaranteeReceived, low);
                        } else if topic == ASSURANCES_TOPIC {
                            dispatch_topic!(ASSURANCES_TOPIC, AssuranceReceived, normal);
                        } else if topic == ANNOUNCEMENTS_TOPIC {
                            dispatch_topic!(ANNOUNCEMENTS_TOPIC, AnnouncementReceived, normal);
                        } else if topic == TICKETS_TOPIC {
                            dispatch_topic!(TICKETS_TOPIC, TicketReceived, low);
                        } else if topic == EQUIVOCATION_TOPIC {
                            dispatch_topic!(EQUIVOCATION_TOPIC, EquivocationReceived, normal);
                        }
                    }
                    // Handle request-response events
                    SwarmEvent::Behaviour(JamBehaviourEvent::Reqres(
                        request_response::Event::Message { peer, message, .. }
                    )) => {
                        match message {
                            request_response::Message::Request { request, channel, .. } => {
                                // Decode request type from first byte and respond
                                let response = if !request.is_empty() {
                                    match request[0] {
                                        0x01 if request.len() >= 35 => {
                                            // Chunk fetch: [0x01][report_hash(32)][chunk_idx(2)]
                                            let mut report_hash = [0u8; 32];
                                            report_hash.copy_from_slice(&request[1..33]);
                                            let chunk_index = u16::from_le_bytes([request[33], request[34]]);

                                            let (tx, rx) = oneshot::channel();
                                            send_event!(NetworkEvent::ChunkRequest {
                                                report_hash,
                                                chunk_index,
                                                response_tx: tx,
                                            }, high);
                                            // Wait briefly for the node to respond
                                            rx.await.ok().flatten().unwrap_or_default()
                                        }
                                        0x02 if request.len() >= 33 => {
                                            // Block fetch: [0x02][block_hash(32)]
                                            let mut block_hash = [0u8; 32];
                                            block_hash.copy_from_slice(&request[1..33]);

                                            let (tx, rx) = oneshot::channel();
                                            send_event!(NetworkEvent::BlockRequest {
                                                block_hash,
                                                response_tx: tx,
                                            }, high);
                                            rx.await.ok().flatten().unwrap_or_default()
                                        }
                                        _ => {
                                            tracing::warn!("Unknown request type from {}", peer);
                                            vec![]
                                        }
                                    }
                                } else {
                                    vec![]
                                };
                                let _ = swarm.behaviour_mut().reqres.send_response(channel, response);
                            }
                            request_response::Message::Response { request_id, response } => {
                                if let Some(tx) = pending_chunk_requests.remove(&request_id) {
                                    let data = if response.is_empty() {
                                        None
                                    } else {
                                        Some(response)
                                    };
                                    let _ = tx.send(data);
                                }
                            }
                        }
                    }
                    SwarmEvent::Behaviour(JamBehaviourEvent::Reqres(
                        request_response::Event::OutboundFailure { request_id, error, .. }
                    )) => {
                        tracing::warn!(
                            "Validator {} request failed: {:?}",
                            validator_index,
                            error
                        );
                        if let Some(tx) = pending_chunk_requests.remove(&request_id) {
                            let _ = tx.send(None);
                        }
                    }
                    SwarmEvent::Behaviour(JamBehaviourEvent::Identify(
                        identify::Event::Received { peer_id, info, .. }
                    )) => {
                        // Extract validator index from the protocol info if available
                        let vi = parse_validator_index_from_agent(&info.agent_version);
                        peers.add_peer(peer_id);
                        if let Some(idx) = vi {
                            peers.set_validator(peer_id, idx);
                        }
                        send_event!(NetworkEvent::PeerIdentified {
                            peer_id,
                            validator_index: vi,
                        }, high);
                        tracing::info!(
                            "Validator {} identified peer {} (validator={:?}), total_peers={}",
                            validator_index,
                            peer_id,
                            vi,
                            peers.peer_count()
                        );
                    }
                    SwarmEvent::NewListenAddr { address, .. } => {
                        tracing::info!(
                            "Validator {} listening on {}",
                            validator_index,
                            address
                        );
                    }
                    SwarmEvent::ConnectionEstablished { peer_id, .. } => {
                        peers.add_peer(peer_id);
                        tracing::info!(
                            "Validator {} connected to peer {}, total_peers={}",
                            validator_index,
                            peer_id,
                            peers.peer_count()
                        );
                    }
                    SwarmEvent::ConnectionClosed { peer_id, .. } => {
                        peers.remove_peer(&peer_id);
                        tracing::debug!(
                            "Validator {} disconnected from peer {}, total_peers={}",
                            validator_index,
                            peer_id,
                            peers.peer_count()
                        );
                    }
                    SwarmEvent::ListenerError { error, .. } => {
                        tracing::error!(
                            "Validator {} listener error (fatal): {}",
                            validator_index,
                            error
                        );
                        break;
                    }
                    SwarmEvent::ListenerClosed { reason, .. } => {
                        tracing::error!(
                            "Validator {} listener closed (fatal): {:?}",
                            validator_index,
                            reason
                        );
                        break;
                    }
                    SwarmEvent::IncomingConnectionError { error, .. } => {
                        tracing::warn!(
                            "Validator {} incoming connection error: {}",
                            validator_index,
                            error
                        );
                    }
                    _ => {}
                }
            }

            // Handle outgoing commands
            cmd = cmd_rx.recv() => {
                let Some(cmd) = cmd else { break };
                // Macro to reduce boilerplate for broadcast commands.
                macro_rules! publish {
                    ($topic:expr, $data:expr, $name:expr) => {
                        if let Err(e) = swarm
                            .behaviour_mut()
                            .gossipsub
                            .publish($topic.clone(), $data)
                        {
                            tracing::warn!(
                                "Validator {} failed to publish {}: {}",
                                validator_index,
                                $name,
                                e
                            );
                        }
                    };
                }
                match cmd {
                    NetworkCommand::BroadcastBlock { data } => {
                        publish!(topics.blocks, data, "block");
                    }
                    NetworkCommand::BroadcastFinalityVote { data } => {
                        publish!(topics.finality, data, "finality vote");
                    }
                    NetworkCommand::BroadcastGuarantee { data } => {
                        publish!(topics.guarantees, data, "guarantee");
                    }
                    NetworkCommand::BroadcastAssurance { data } => {
                        publish!(topics.assurances, data, "assurance");
                    }
                    NetworkCommand::BroadcastAnnouncement { data } => {
                        publish!(topics.announcements, data, "announcement");
                    }
                    NetworkCommand::BroadcastTicket { data } => {
                        publish!(topics.tickets, data, "ticket");
                    }
                    NetworkCommand::BroadcastEquivocation { data } => {
                        publish!(topics.equivocation, data, "equivocation evidence");
                    }
                    NetworkCommand::FetchChunk { peer, report_hash, chunk_index, response_tx } => {
                        // Build request: [0x01][report_hash(32)][chunk_idx(2)]
                        let mut req = Vec::with_capacity(35);
                        req.push(0x01);
                        req.extend_from_slice(&report_hash);
                        req.extend_from_slice(&chunk_index.to_le_bytes());

                        let request_id = swarm.behaviour_mut().reqres.send_request(&peer, req);
                        pending_chunk_requests.insert(request_id, response_tx);
                    }
                    NetworkCommand::FetchBlock { peer, block_hash, response_tx } => {
                        let mut req = Vec::with_capacity(33);
                        req.push(0x02);
                        req.extend_from_slice(&block_hash);

                        let request_id = swarm.behaviour_mut().reqres.send_request(&peer, req);
                        pending_chunk_requests.insert(request_id, response_tx);
                    }
                }
            }

            // Periodic cleanup of stale rate-tracking entries
            _ = rate_prune_interval.tick() => {
                rate_tracker.prune_stale();
            }
        }
    }
}

/// Try to parse a validator index from the agent version string.
/// Expected format: "jam-validator-N" where N is the index.
fn parse_validator_index_from_agent(agent: &str) -> Option<u16> {
    agent
        .strip_prefix("jam-validator-")
        .and_then(|s| s.parse::<u16>().ok())
}

// Need to import StreamExt for swarm.next()
use futures::StreamExt;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_validator_index() {
        assert_eq!(parse_validator_index_from_agent("jam-validator-0"), Some(0));
        assert_eq!(
            parse_validator_index_from_agent("jam-validator-42"),
            Some(42)
        );
        assert_eq!(
            parse_validator_index_from_agent("jam-validator-1023"),
            Some(1023)
        );
        assert_eq!(parse_validator_index_from_agent("other"), None);
        assert_eq!(parse_validator_index_from_agent(""), None);
    }

    #[test]
    fn test_peer_tracker() {
        let mut tracker = PeerTracker::new();
        let peer1 = PeerId::random();
        let peer2 = PeerId::random();

        tracker.add_peer(peer1);
        assert_eq!(tracker.peer_count(), 1);

        tracker.set_validator(peer1, 5);
        assert_eq!(tracker.get_peer_for_validator(5), Some(&peer1));

        tracker.add_peer(peer2);
        tracker.set_validator(peer2, 10);
        assert_eq!(tracker.peer_count(), 2);

        tracker.remove_peer(&peer1);
        assert_eq!(tracker.peer_count(), 1);
        assert_eq!(tracker.get_peer_for_validator(5), None);
        assert_eq!(tracker.get_peer_for_validator(10), Some(&peer2));
    }

    #[test]
    fn test_peer_tracker_remove_nonexistent() {
        let mut tracker = PeerTracker::new();
        let peer = PeerId::random();
        // Removing a peer that was never added should not panic
        tracker.remove_peer(&peer);
        assert_eq!(tracker.peer_count(), 0);
    }

    #[test]
    fn test_peer_tracker_reassign_validator() {
        let mut tracker = PeerTracker::new();
        let peer = PeerId::random();
        tracker.add_peer(peer);

        // Assign to validator 5, then reassign to validator 10
        tracker.set_validator(peer, 5);
        assert_eq!(tracker.get_peer_for_validator(5), Some(&peer));

        tracker.set_validator(peer, 10);
        assert_eq!(tracker.get_peer_for_validator(10), Some(&peer));
        // Old mapping should be overwritten (peer maps to 10 now)
    }

    #[test]
    fn test_peer_tracker_duplicate_add() {
        let mut tracker = PeerTracker::new();
        let peer = PeerId::random();
        tracker.add_peer(peer);
        tracker.add_peer(peer); // duplicate add should not increase count
        assert_eq!(tracker.peer_count(), 1);
    }

    #[test]
    fn test_parse_validator_index_edge_cases() {
        // Max u16
        assert_eq!(
            parse_validator_index_from_agent("jam-validator-65535"),
            Some(65535)
        );
        // Overflow u16 (65536)
        assert_eq!(
            parse_validator_index_from_agent("jam-validator-65536"),
            None
        );
        // Negative-looking
        assert_eq!(parse_validator_index_from_agent("jam-validator--1"), None);
        // Trailing space
        assert_eq!(parse_validator_index_from_agent("jam-validator-5 "), None);
        // Just the prefix
        assert_eq!(parse_validator_index_from_agent("jam-validator-"), None);
    }

    #[test]
    fn test_rate_tracker_within_limit() {
        let mut tracker = PeerRateTracker::new(Duration::from_secs(60));
        let peer = PeerId::random();

        // First 5 block messages should be within limit
        for _ in 0..5 {
            assert!(tracker.record(&peer, BLOCKS_TOPIC));
        }
    }

    #[test]
    fn test_rate_tracker_exceeds_limit() {
        let mut tracker = PeerRateTracker::new(Duration::from_secs(60));
        let peer = PeerId::random();

        // Blocks limit is 5 per window
        for _ in 0..5 {
            assert!(tracker.record(&peer, BLOCKS_TOPIC));
        }
        // 6th should exceed the limit
        assert!(!tracker.record(&peer, BLOCKS_TOPIC));
    }

    #[test]
    fn test_rate_tracker_different_peers_independent() {
        let mut tracker = PeerRateTracker::new(Duration::from_secs(60));
        let peer_a = PeerId::random();
        let peer_b = PeerId::random();

        // Fill peer A's limit
        for _ in 0..5 {
            tracker.record(&peer_a, BLOCKS_TOPIC);
        }
        assert!(!tracker.record(&peer_a, BLOCKS_TOPIC));

        // Peer B should still have full allowance
        assert!(tracker.record(&peer_b, BLOCKS_TOPIC));
    }

    #[test]
    fn test_rate_tracker_different_topics_independent() {
        let mut tracker = PeerRateTracker::new(Duration::from_secs(60));
        let peer = PeerId::random();

        // Fill block limit
        for _ in 0..5 {
            tracker.record(&peer, BLOCKS_TOPIC);
        }
        assert!(!tracker.record(&peer, BLOCKS_TOPIC));

        // Finality topic should still be fine (limit 50)
        assert!(tracker.record(&peer, FINALITY_TOPIC));
    }

    #[test]
    fn test_rate_tracker_prune_stale() {
        let mut tracker = PeerRateTracker::new(Duration::from_millis(1));
        let peer = PeerId::random();

        tracker.record(&peer, BLOCKS_TOPIC);
        assert_eq!(tracker.counters.len(), 1);

        // Wait for window to expire
        std::thread::sleep(Duration::from_millis(5));
        tracker.prune_stale();
        assert_eq!(tracker.counters.len(), 0);
    }
}

#[cfg(test)]
mod proptests {
    use super::*;
    use proptest::prelude::*;

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(128))]

        /// parse_validator_index always returns None for strings without the prefix.
        #[test]
        fn parse_rejects_arbitrary_strings(s in "[a-z0-9 _-]{0,50}") {
            if !s.starts_with("jam-validator-") {
                prop_assert!(parse_validator_index_from_agent(&s).is_none());
            }
        }

        /// parse_validator_index roundtrips: formatting as "jam-validator-N"
        /// then parsing always recovers N.
        #[test]
        fn parse_roundtrips_valid_index(idx in 0u16..=u16::MAX) {
            let agent = format!("jam-validator-{idx}");
            prop_assert_eq!(parse_validator_index_from_agent(&agent), Some(idx));
        }

        /// PeerTracker: add then remove leaves count at zero.
        #[test]
        fn peer_tracker_add_remove_empty(n in 1usize..20) {
            let mut tracker = PeerTracker::new();
            let peers: Vec<PeerId> = (0..n).map(|_| PeerId::random()).collect();
            for p in &peers {
                tracker.add_peer(*p);
            }
            prop_assert_eq!(tracker.peer_count(), n);
            for p in &peers {
                tracker.remove_peer(p);
            }
            prop_assert_eq!(tracker.peer_count(), 0);
        }

        /// PeerTracker: set_validator is retrievable via get_peer_for_validator.
        #[test]
        fn peer_tracker_validator_lookup(idx in 0u16..1000) {
            let mut tracker = PeerTracker::new();
            let peer = PeerId::random();
            tracker.add_peer(peer);
            tracker.set_validator(peer, idx);
            prop_assert_eq!(tracker.get_peer_for_validator(idx), Some(&peer));
        }

        /// PeerTracker: removing a peer clears its validator mapping.
        #[test]
        fn peer_tracker_remove_clears_validator(idx in 0u16..1000) {
            let mut tracker = PeerTracker::new();
            let peer = PeerId::random();
            tracker.add_peer(peer);
            tracker.set_validator(peer, idx);
            tracker.remove_peer(&peer);
            prop_assert_eq!(tracker.get_peer_for_validator(idx), None);
            prop_assert_eq!(tracker.peer_count(), 0);
        }

        /// PeerRateTracker: first N messages within limit always pass.
        #[test]
        fn rate_tracker_allows_up_to_limit(count in 1u64..=5) {
            let mut tracker = PeerRateTracker::new(Duration::from_secs(60));
            let peer = PeerId::random();
            for _ in 0..count {
                prop_assert!(tracker.record(&peer, BLOCKS_TOPIC));
            }
        }

        /// PeerRateTracker: message N+1 over the limit is rejected.
        #[test]
        fn rate_tracker_rejects_over_limit(extra in 1u64..10) {
            let mut tracker = PeerRateTracker::new(Duration::from_secs(60));
            let peer = PeerId::random();
            // Fill to the blocks limit (5)
            for _ in 0..5 {
                tracker.record(&peer, BLOCKS_TOPIC);
            }
            // Every additional message should be rejected
            for _ in 0..extra {
                prop_assert!(!tracker.record(&peer, BLOCKS_TOPIC));
            }
        }
    }
}
