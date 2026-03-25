use clap::{Parser, Subcommand};

mod cache;
mod git;
mod github;
mod hash;
mod lean;
mod replay;
mod review;
mod types;
mod workflow;

#[derive(Parser)]
#[command(name = "jar-genesis", about = "JAR Genesis tooling")]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Run a workflow action (called from GitHub Actions)
    Workflow {
        #[command(subcommand)]
        action: WorkflowAction,
    },
    /// Replay genesis state from git history
    Replay {
        /// Verification mode
        #[arg(long, default_value = "verify")]
        mode: ReplayMode,
    },
    /// Check if genesis cache is stale
    CheckCache {
        /// Path to genesis cache JSON file
        cache_file: String,
    },
    /// Collect reviews from a PR
    CollectReviews {
        /// PR number
        #[arg(long)]
        pr: u64,
        /// HEAD SHA of the PR
        #[arg(long)]
        head_sha: Option<String>,
        /// Comparison targets as JSON array
        #[arg(long)]
        targets: Option<String>,
    },
}

#[derive(Subcommand)]
enum WorkflowAction {
    /// Merge a PR (triggered by quorum or founder override)
    Merge {
        /// PR number
        #[arg(long)]
        pr: u64,
        /// Founder override (skip quorum check)
        #[arg(long, default_value = "false")]
        founder_override: bool,
    },
    /// Post comparison targets on a newly opened PR
    PrOpened {
        /// PR number
        #[arg(long)]
        pr: u64,
        /// PR created_at timestamp (ISO 8601)
        #[arg(long)]
        created_at: String,
    },
    /// Process a /review comment
    Review {
        /// PR number
        #[arg(long)]
        pr: u64,
        /// Comment author
        #[arg(long)]
        comment_author: String,
        /// Comment body
        #[arg(long)]
        comment_body: String,
    },
}

#[derive(Clone, clap::ValueEnum)]
enum ReplayMode {
    Verify,
    VerifyCache,
    Rebuild,
}

fn main() {
    let cli = Cli::parse();

    let result = match cli.command {
        Command::Workflow { action } => match action {
            WorkflowAction::Merge { pr, founder_override } => {
                workflow::merge::run(pr, founder_override)
            }
            WorkflowAction::PrOpened { pr, created_at } => {
                workflow::pr_opened::run(pr, &created_at)
            }
            WorkflowAction::Review { pr, comment_author, comment_body } => {
                workflow::review::run(pr, &comment_author, &comment_body)
            }
        },
        Command::Replay { mode } => match mode {
            ReplayMode::Verify => replay::verify(),
            ReplayMode::VerifyCache => replay::verify_cache(),
            ReplayMode::Rebuild => replay::rebuild(),
        },
        Command::CheckCache { cache_file } => cache::check(&cache_file),
        Command::CollectReviews { pr, head_sha, targets } => {
            review::collect_and_print(pr, head_sha.as_deref(), targets.as_deref())
        }
    };

    if let Err(e) = result {
        eprintln!("Error: {e}");
        std::process::exit(1);
    }
}
