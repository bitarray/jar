//! Network service using libp2p gossipsub for block propagation.

use libp2p::{
    gossipsub, identify, noise, tcp, yamux, Multiaddr, PeerId, Swarm, SwarmBuilder,
};
use std::collections::hash_map::DefaultHasher;
use std::hash::{Hash, Hasher};
use std::time::Duration;
use tokio::sync::mpsc;

/// Gossipsub topic for block announcements.
const BLOCKS_TOPIC: &str = "/jam/blocks/1";

/// Gossipsub topic for finality votes.
const FINALITY_TOPIC: &str = "/jam/finality/1";

/// Messages that the network service can send to the node.
#[derive(Debug, Clone)]
pub enum NetworkEvent {
    /// A new block was received from a peer.
    BlockReceived { data: Vec<u8>, source: PeerId },
    /// A finality vote was received from a peer.
    FinalityVote { data: Vec<u8>, source: PeerId },
}

/// Commands that the node can send to the network service.
#[derive(Debug)]
pub enum NetworkCommand {
    /// Broadcast a block to the network.
    BroadcastBlock { data: Vec<u8> },
    /// Broadcast a finality vote.
    BroadcastFinalityVote { data: Vec<u8> },
}

/// Configuration for the network service.
pub struct NetworkConfig {
    /// Port to listen on.
    pub listen_port: u16,
    /// Peer addresses to connect to at startup.
    pub boot_peers: Vec<Multiaddr>,
    /// Validator index (for logging).
    pub validator_index: u16,
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

    // Listen on the configured port
    let listen_addr: Multiaddr = format!("/ip4/127.0.0.1/tcp/{}", config.listen_port)
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
    tokio::spawn(async move {
        run_network_loop(swarm, event_tx, cmd_rx, blocks_topic, finality_topic, validator_index)
            .await;
    });

    Ok((event_rx, cmd_tx))
}

/// Behaviour combining gossipsub and identify protocols.
#[derive(libp2p::swarm::NetworkBehaviour)]
struct JamBehaviour {
    gossipsub: gossipsub::Behaviour,
    identify: identify::Behaviour,
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

            JamBehaviour {
                gossipsub,
                identify,
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
    blocks_topic: gossipsub::IdentTopic,
    finality_topic: gossipsub::IdentTopic,
    validator_index: u16,
) {
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
                        }
                    }
                    SwarmEvent::NewListenAddr { address, .. } => {
                        tracing::info!(
                            "Validator {} listening on {}",
                            validator_index,
                            address
                        );
                    }
                    SwarmEvent::ConnectionEstablished { peer_id, .. } => {
                        tracing::info!(
                            "Validator {} connected to peer {}",
                            validator_index,
                            peer_id
                        );
                    }
                    SwarmEvent::ConnectionClosed { peer_id, .. } => {
                        tracing::debug!(
                            "Validator {} disconnected from peer {}",
                            validator_index,
                            peer_id
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
                            blocks_topic.clone(),
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
                            finality_topic.clone(),
                            data,
                        ) {
                            tracing::warn!(
                                "Validator {} failed to publish finality vote: {}",
                                validator_index,
                                e
                            );
                        }
                    }
                }
            }
        }
    }
}

// Need to import StreamExt for swarm.next()
use futures::StreamExt;
