//! `jar` — in-process N-node testnet driver for the JAR minimum kernel.
//!
//! Spawns N nodes in one process. Each node has its own σ + NodeOffchain +
//! `Kernel<InMemoryHardware>`. Networking is a same-process broadcast bus.
//! Block production rotates round-robin per slot.
//!
//! Usage:
//!
//! ```bash
//! cargo run -p jar -- testnet --nodes 3 --slots 10
//! ```

use clap::{Parser, Subcommand};
use jar_kernel::BlockOutcome;
use jar_kernel::Kernel;
use jar_kernel::genesis::GenesisBuilder;
use jar_kernel::runtime::{InMemoryBus, InMemoryHardware, NodeOffchain};
use jar_types::{Block, BlockHash, Hash, State};

/// Crypto suite + Hardware impl for the in-process testnet. Every parametric
/// type (`State`, `NodeOffchain`, `BlockHash`, …) is instantiated against
/// this.
type Hw = InMemoryHardware;

#[derive(Parser, Debug)]
#[command(name = "jar")]
#[command(about = "JAR minimum-kernel runner")]
struct Cli {
    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Subcommand, Debug)]
enum Cmd {
    /// Boot an N-node in-process testnet, propose `--slots` blocks round-robin.
    Testnet {
        #[arg(long, default_value_t = 3)]
        nodes: u32,
        #[arg(long, default_value_t = 5)]
        slots: u32,
    },
}

fn main() {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info,jar=debug")),
        )
        .init();

    let cli = Cli::parse();
    match cli.cmd {
        Cmd::Testnet { nodes, slots } => run_testnet(nodes, slots),
    }
}

fn run_testnet(num_nodes: u32, num_slots: u32) {
    let g = GenesisBuilder::<Hw>::default().build().expect("genesis ok");

    let bus = InMemoryBus::new();
    let mut nodes: Vec<NodeState> = Vec::new();
    for i in 0..num_nodes {
        nodes.push(NodeState {
            id: i,
            state: g.state.clone(),
            offchain: NodeOffchain::<Hw>::new(),
            kernel: Kernel::new(InMemoryHardware::new(bus.clone())),
            prior_block: BlockHash::<Hw>::default(),
        });
    }

    for slot_n in 1..=num_slots {
        let proposer_idx = (slot_n - 1) % num_nodes;
        let proposer = &mut nodes[proposer_idx as usize];

        // Drain proposer's slots into a fresh body. In a real chain the
        // proposer would prepend its event[0] (header gating) and append
        // event[-1] (finalization gating); for this milestone we let the
        // body be whatever the slot drain produced (zero events, in
        // practice — guests don't yet emit AggregatedTransacts).
        let body = proposer
            .kernel
            .drain_for_body(&proposer.offchain, &proposer.state)
            .expect("drain ok");
        let block_in = Block {
            parent: proposer.prior_block,
            body,
        };
        let out = proposer
            .kernel
            .apply_block(&proposer.state, proposer.prior_block, &block_in)
            .expect("apply_block ok");
        match &out.block_outcome {
            BlockOutcome::Accepted => {
                tracing::info!(
                    proposer = proposer_idx,
                    slot = slot_n,
                    state_root = ?out.state_root,
                    "accepted"
                );
            }
            BlockOutcome::Panicked(reason) => {
                tracing::error!(reason, "block panicked at proposer; aborting");
                return;
            }
        }

        // Apply the proposed block on every node (verifier mode).
        let new_root = out.state_root;
        let proposed_block = out.block.clone();
        for node in &mut nodes {
            let ver = node
                .kernel
                .apply_block(&node.state, node.prior_block, &proposed_block)
                .expect("verifier apply_block ok");
            assert!(matches!(ver.block_outcome, BlockOutcome::Accepted));
            assert_eq!(
                ver.state_root, new_root,
                "node {} diverged from proposer at slot {}",
                node.id, slot_n
            );
            node.state = ver.state_next;
            node.prior_block = Hash::ZERO; // we don't yet hash headers
        }
        tracing::info!(slot = slot_n, "all nodes converged on root {:?}", new_root);
    }
}

struct NodeState {
    id: u32,
    state: State<Hw>,
    offchain: NodeOffchain<Hw>,
    kernel: Kernel<Hw>,
    prior_block: BlockHash<Hw>,
}
