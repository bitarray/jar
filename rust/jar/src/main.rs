//! `jar` — in-process N-node testnet driver for the JAR minimum kernel.
//!
//! Spawns N nodes in one process. Each node owns its own
//! `Kernel<InMemoryHardware>` directly (no `Arc<H>`); a shared
//! `InMemoryBus` is the same-process broadcast wire. Block production
//! rotates round-robin per slot.
//!
//! Usage:
//!
//! ```bash
//! cargo run -p jar -- testnet --nodes 3 --slots 10
//! ```

use clap::{Parser, Subcommand};
use jar_kernel::genesis::GenesisBuilder;
use jar_kernel::runtime::{InMemoryBus, InMemoryHardware};
use jar_kernel::{BlockOutcome, Kernel};

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
    let g = GenesisBuilder::default().build().expect("genesis ok");

    let bus = InMemoryBus::new();
    let mut nodes: Vec<NodeState> = (0..num_nodes)
        .map(|i| NodeState {
            id: i,
            kernel: Kernel::new(None, InMemoryHardware::new(g.state.clone(), bus.clone()))
                .expect("kernel new ok"),
        })
        .collect();

    for slot_n in 1..=num_slots {
        let proposer_idx = ((slot_n - 1) % num_nodes) as usize;

        // Proposer builds the block.
        let proposed = {
            let proposer = &mut nodes[proposer_idx];
            let out = proposer.kernel.advance(None).expect("propose ok");
            match &out.block_outcome {
                BlockOutcome::Accepted => {
                    tracing::info!(
                        proposer = proposer_idx,
                        slot = slot_n,
                        state_root = ?out.state_root,
                        block_hash = ?out.block_hash,
                        "proposed"
                    );
                }
                BlockOutcome::Panicked(reason) => {
                    tracing::error!(reason, "block panicked at proposer; aborting");
                    return;
                }
            }
            out
        };

        // Verifiers replay the proposed block. (The proposer already
        // advanced; verifiers re-derive identical state and confirm.)
        let new_root = proposed.state_root;
        let new_hash = proposed.block_hash;
        for (i, node) in nodes.iter_mut().enumerate() {
            if i == proposer_idx {
                continue;
            }
            let ver = node
                .kernel
                .advance(Some(proposed.block.clone()))
                .expect("verifier advance ok");
            assert!(matches!(ver.block_outcome, BlockOutcome::Accepted));
            assert_eq!(
                ver.state_root, new_root,
                "node {} diverged from proposer at slot {}",
                node.id, slot_n
            );
            assert_eq!(
                ver.block_hash, new_hash,
                "node {} hash diverged from proposer at slot {}",
                node.id, slot_n
            );
        }
        tracing::info!(slot = slot_n, "all nodes converged on root {:?}", new_root);
    }
}

struct NodeState {
    id: u32,
    kernel: Kernel<InMemoryHardware>,
}
