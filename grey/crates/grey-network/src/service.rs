//! Network service using libp2p gossipsub and request-response.
//!
//! Provides:
//! - Gossipsub: block, finality, guarantee, assurance propagation
//! - Request-response: chunk fetch, block fetch for sync
//! - Peer tracking: validator index ↔ PeerId mapping

use libp2p::{
    gossipsub, identify, noise, request_response, tcp, yamux, Multiaddr, PeerId, Swarm,
    SwarmBuilder,
};
use std::collections::hash_map::DefaultHasher;
use std::collections::HashMap;
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
        use futures::AsyncReadExt;
        let mut len_buf = [0u8; 4];
        io.read_exact(&mut len_buf).await?;
        let len = u32::from_le_bytes(len_buf) as usize;
        if len > 1024 * 1024 {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "request too large",
            ));
        }
        let mut buf = vec![0u8; len];
        io.read_exact(&mut buf).await?;
        Ok(buf)
    }

    async fn read_response<T>(
        &mut self,
        _protocol: &Self::Protocol,
        io: &mut T,
    ) -> std::io::Result<Self::Response>
    where
        T: futures::AsyncRead + Unpin + Send,
    {
        use futures::AsyncReadExt;
        let mut len_buf = [0u8; 4];
        io.read_exact(&mut len_buf).await?;
        let len = u32::from_le_bytes(len_buf) as usize;
        if len > 10 * 1024 * 1024 {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "response too large",
            ));
        }
        let mut buf = vec![0u8; len];
        io.read_exact(&mut buf).await?;
        Ok(buf)
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
        use futures::AsyncWriteExt;
        let len = (req.len() as u32).to_le_bytes();
        io.write_all(&len).await?;
        io.write_all(&req).await?;
        io.close().await?;
        Ok(())
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
        use futures::AsyncWriteExt;
        let len = (resp.len() as u32).to_le_bytes();
        io.write_all(&len).await?;
        io.write_all(&resp).await?;
        io.close().await?;
        Ok(())
    }
}

/// Create and run the network service.
///
/// Returns channels for communication with the network service.
pub async fn start_network(
    config: NetworkConfig,
) -> Result<
    (
        mpsc::UnboundedReceiver<NetworkEvent>,
        mpsc::UnboundedSender<NetworkCommand>,
    ),
    Box<dyn std::error::Error + Send + Sync>,
> {
    let (event_tx, event_rx) = mpsc::unbounded_channel();
    let (cmd_tx, cmd_rx) = mpsc::unbounded_channel();

    // Build the swarm
    let mut swarm = build_swarm()?;

    // Subscribe to topics
    let blocks_topic = gossipsub::IdentTopic::new(BLOCKS_TOPIC);
    let finality_topic = gossipsub::IdentTopic::new(FINALITY_TOPIC);
    let guarantees_topic = gossipsub::IdentTopic::new(GUARANTEES_TOPIC);
    let assurances_topic = gossipsub::IdentTopic::new(ASSURANCES_TOPIC);
    let announcements_topic = gossipsub::IdentTopic::new(ANNOUNCEMENTS_TOPIC);
    let tickets_topic = gossipsub::IdentTopic::new(TICKETS_TOPIC);

    swarm
        .behaviour_mut()
        .gossipsub
        .subscribe(&blocks_topic)
        .map_err(|e| format!("Failed to subscribe to blocks topic: {e}"))?;
    swarm
        .behaviour_mut()
        .gossipsub
        .subscribe(&finality_topic)
        .map_err(|e| format!("Failed to subscribe to finality topic: {e}"))?;
    swarm
        .behaviour_mut()
        .gossipsub
        .subscribe(&guarantees_topic)
        .map_err(|e| format!("Failed to subscribe to guarantees topic: {e}"))?;
    swarm
        .behaviour_mut()
        .gossipsub
        .subscribe(&assurances_topic)
        .map_err(|e| format!("Failed to subscribe to assurances topic: {e}"))?;
    swarm
        .behaviour_mut()
        .gossipsub
        .subscribe(&announcements_topic)
        .map_err(|e| format!("Failed to subscribe to announcements topic: {e}"))?;
    swarm
        .behaviour_mut()
        .gossipsub
        .subscribe(&tickets_topic)
        .map_err(|e| format!("Failed to subscribe to tickets topic: {e}"))?;

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
    };
    tokio::spawn(async move {
        run_network_loop(swarm, event_tx, cmd_rx, topics, validator_index).await;
    });

    Ok((event_rx, cmd_tx))
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
                .validation_mode(gossipsub::ValidationMode::Permissive)
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
                [(
                    "/jam/fetch/1",
                    request_response::ProtocolSupport::Full,
                )],
                request_response::Config::default()
                    .with_request_timeout(Duration::from_secs(10)),
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
    event_tx: mpsc::UnboundedSender<NetworkEvent>,
    mut cmd_rx: mpsc::UnboundedReceiver<NetworkCommand>,
    topics: TopicSet,
    validator_index: u16,
) {
    let mut peers = PeerTracker::new();
    // Track pending request-response callbacks
    let mut pending_chunk_requests: HashMap<
        request_response::OutboundRequestId,
        oneshot::Sender<Option<Vec<u8>>>,
    > = HashMap::new();

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
                        if topic == BLOCKS_TOPIC {
                            let _ = event_tx.send(NetworkEvent::BlockReceived {
                                data: message.data,
                                source: propagation_source,
                            });
                        } else if topic == FINALITY_TOPIC {
                            let _ = event_tx.send(NetworkEvent::FinalityVote {
                                data: message.data,
                                source: propagation_source,
                            });
                        } else if topic == GUARANTEES_TOPIC {
                            let _ = event_tx.send(NetworkEvent::GuaranteeReceived {
                                data: message.data,
                                source: propagation_source,
                            });
                        } else if topic == ASSURANCES_TOPIC {
                            let _ = event_tx.send(NetworkEvent::AssuranceReceived {
                                data: message.data,
                                source: propagation_source,
                            });
                        } else if topic == ANNOUNCEMENTS_TOPIC {
                            let _ = event_tx.send(NetworkEvent::AnnouncementReceived {
                                data: message.data,
                                source: propagation_source,
                            });
                        } else if topic == TICKETS_TOPIC {
                            let _ = event_tx.send(NetworkEvent::TicketReceived {
                                data: message.data,
                                source: propagation_source,
                            });
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
                                            let _ = event_tx.send(NetworkEvent::ChunkRequest {
                                                report_hash,
                                                chunk_index,
                                                response_tx: tx,
                                            });
                                            // Wait briefly for the node to respond
                                            rx.await.ok().flatten().unwrap_or_default()
                                        }
                                        0x02 if request.len() >= 33 => {
                                            // Block fetch: [0x02][block_hash(32)]
                                            let mut block_hash = [0u8; 32];
                                            block_hash.copy_from_slice(&request[1..33]);

                                            let (tx, rx) = oneshot::channel();
                                            let _ = event_tx.send(NetworkEvent::BlockRequest {
                                                block_hash,
                                                response_tx: tx,
                                            });
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
                        let _ = event_tx.send(NetworkEvent::PeerIdentified {
                            peer_id,
                            validator_index: vi,
                        });
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
                match cmd {
                    NetworkCommand::BroadcastBlock { data } => {
                        if let Err(e) = swarm.behaviour_mut().gossipsub.publish(
                            topics.blocks.clone(),
                            data,
                        ) {
                            tracing::warn!(
                                "Validator {} failed to publish block: {}",
                                validator_index,
                                e
                            );
                        }
                    }
                    NetworkCommand::BroadcastFinalityVote { data } => {
                        if let Err(e) = swarm.behaviour_mut().gossipsub.publish(
                            topics.finality.clone(),
                            data,
                        ) {
                            tracing::warn!(
                                "Validator {} failed to publish finality vote: {}",
                                validator_index,
                                e
                            );
                        }
                    }
                    NetworkCommand::BroadcastGuarantee { data } => {
                        if let Err(e) = swarm.behaviour_mut().gossipsub.publish(
                            topics.guarantees.clone(),
                            data,
                        ) {
                            tracing::warn!(
                                "Validator {} failed to publish guarantee: {}",
                                validator_index,
                                e
                            );
                        }
                    }
                    NetworkCommand::BroadcastAssurance { data } => {
                        if let Err(e) = swarm.behaviour_mut().gossipsub.publish(
                            topics.assurances.clone(),
                            data,
                        ) {
                            tracing::warn!(
                                "Validator {} failed to publish assurance: {}",
                                validator_index,
                                e
                            );
                        }
                    }
                    NetworkCommand::BroadcastAnnouncement { data } => {
                        if let Err(e) = swarm.behaviour_mut().gossipsub.publish(
                            topics.announcements.clone(),
                            data,
                        ) {
                            tracing::warn!(
                                "Validator {} failed to publish announcement: {}",
                                validator_index,
                                e
                            );
                        }
                    }
                    NetworkCommand::BroadcastTicket { data } => {
                        if let Err(e) = swarm.behaviour_mut().gossipsub.publish(
                            topics.tickets.clone(),
                            data,
                        ) {
                            tracing::warn!(
                                "Validator {} failed to publish ticket: {}",
                                validator_index,
                                e
                            );
                        }
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
        assert_eq!(parse_validator_index_from_agent("jam-validator-42"), Some(42));
        assert_eq!(parse_validator_index_from_agent("jam-validator-1023"), Some(1023));
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
}
