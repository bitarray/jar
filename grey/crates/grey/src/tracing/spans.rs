use tracing::{span, Level};
use grey_types::Hash;

pub struct Spans;

impl Spans {
    pub fn rpc_request(method: &str) -> span::Span {
        span!(Level::INFO, "rpc_request", method = method)
    }

    pub fn block_processing(slot: u32, hash: &Hash) -> span::Span {
        span!(Level::INFO, "block_processing", slot = slot, block_hash = %hash)
    }

    pub fn block_authoring(slot: u32) -> span::Span {
        span!(Level::INFO, "block_authoring", slot = slot)
    }

    pub fn state_transition(slot: u32) -> span::Span {
        span!(Level::INFO, "state_transition", slot = slot)
    }

    pub fn pvm_execution(service_id: u32) -> span::Span {
        span!(Level::INFO, "pvm_execution", service_id = service_id)
    }

    pub fn guarantee_processing(guarantee_hash: &Hash) -> span::Span {
        span!(Level::INFO, "guarantee_processing", guarantee_hash = %guarantee_hash)
    }

    pub fn assurance_processing(assurance_hash: &Hash) -> span::Span {
        span!(Level::INFO, "assurance_processing", assurance_hash = %assurance_hash)
    }

    pub fn work_package_submission(hash: &Hash) -> span::Span {
        span!(Level::INFO, "work_package_submission", wp_hash = %hash)
    }

    pub fn network_message(topic: &str) -> span::Span {
        span!(Level::DEBUG, "network_message", topic = topic)
    }

    pub fn db_operation(operation: &str, key: &str) -> span::Span {
        span!(Level::DEBUG, "db_operation", operation = operation, key = key)
    }

    pub fn consensus_round(round: u64) -> span::Span {
        span!(Level::INFO, "consensus_round", round = round)
    }

    pub fn finality_vote(round: u64, voter: u16) -> span::Span {
        span!(Level::DEBUG, "finality_vote", round = round, voter = voter)
    }
}
