use serde::{Deserialize, Serialize};

/// A review verdict: merge or notMerge.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum Verdict {
    #[serde(rename = "merge")]
    Merge,
    #[serde(rename = "notMerge")]
    NotMerge,
}

/// A single review embedded in a SignedCommit.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct EmbeddedReview {
    pub reviewer: String,
    pub difficulty_ranking: Vec<String>,
    pub novelty_ranking: Vec<String>,
    pub design_quality_ranking: Vec<String>,
    pub verdict: Verdict,
}

/// A meta-review (thumbs up/down on another reviewer's review).
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct MetaReview {
    pub meta_reviewer: String,
    pub target_reviewer: String,
    pub approve: bool,
}

/// A signed commit: the full input to genesis_evaluate.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SignedCommit {
    pub id: String,
    pub pr_id: u64,
    pub author: String,
    pub merge_epoch: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub pr_created_at: Option<u64>,
    pub comparison_targets: Vec<String>,
    pub reviews: Vec<EmbeddedReview>,
    pub meta_reviews: Vec<MetaReview>,
    pub founder_override: bool,
}

/// Score for a commit (output of genesis_evaluate).
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CommitScore {
    pub difficulty: u64,
    pub novelty: u64,
    pub design_quality: u64,
}

/// A scored commit index (output of genesis_evaluate, stored in cache and trailers).
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CommitIndex {
    pub commit_hash: String,
    pub epoch: u64,
    pub score: CommitScore,
    pub contributor: String,
    pub weight_delta: u64,
    pub reviewers: Vec<String>,
    pub meta_reviews: Vec<MetaReview>,
    pub merge_votes: Vec<String>,
    pub reject_votes: Vec<String>,
    pub founder_override: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub warnings: Option<Vec<String>>,
}

/// Output of genesis_check_merge.
#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct MergeReadiness {
    pub ready: bool,
    pub merge_weight: u64,
    pub reject_weight: u64,
    pub total_weight: u64,
}

/// Output of genesis_select_targets.
#[derive(Debug, Clone, Deserialize)]
pub struct SelectTargetsOutput {
    pub targets: Vec<String>,
}

/// Output of genesis_ranking.
#[derive(Debug, Clone, Deserialize)]
pub struct RankingOutput {
    pub ranking: Vec<String>,
}

/// Output of genesis_validate.
#[derive(Debug, Clone, Deserialize)]
pub struct ValidateOutput {
    pub valid: bool,
    pub errors: Vec<String>,
}

/// Collected reviews from a PR (output of review::collect).
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CollectedReviews {
    pub reviews: Vec<EmbeddedReview>,
    pub meta_reviews: Vec<MetaReview>,
    pub warnings: Vec<String>,
}
