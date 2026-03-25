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
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CollectedReviews {
    pub reviews: Vec<EmbeddedReview>,
    pub meta_reviews: Vec<MetaReview>,
    pub warnings: Vec<String>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_verdict_serde_roundtrip() {
        let merge = serde_json::to_string(&Verdict::Merge).unwrap();
        assert_eq!(merge, "\"merge\"");
        let not_merge = serde_json::to_string(&Verdict::NotMerge).unwrap();
        assert_eq!(not_merge, "\"notMerge\"");

        let parsed: Verdict = serde_json::from_str("\"merge\"").unwrap();
        assert_eq!(parsed, Verdict::Merge);
        let parsed: Verdict = serde_json::from_str("\"notMerge\"").unwrap();
        assert_eq!(parsed, Verdict::NotMerge);
    }

    #[test]
    fn test_commit_index_camel_case() {
        let json = r#"{
            "commitHash": "abc123",
            "epoch": 1000,
            "score": {"difficulty": 85, "novelty": 100, "designQuality": 85},
            "contributor": "alice",
            "weightDelta": 88,
            "reviewers": ["bob"],
            "metaReviews": [],
            "mergeVotes": ["bob"],
            "rejectVotes": [],
            "founderOverride": false
        }"#;
        let idx: CommitIndex = serde_json::from_str(json).unwrap();
        assert_eq!(idx.commit_hash, "abc123");
        assert_eq!(idx.score.design_quality, 85);
        assert_eq!(idx.weight_delta, 88);
        assert!(!idx.founder_override);
        assert!(idx.warnings.is_none());
    }

    #[test]
    fn test_commit_index_with_warnings() {
        let json = r#"{
            "commitHash": "abc",
            "epoch": 1000,
            "score": {"difficulty": 0, "novelty": 0, "designQuality": 0},
            "contributor": "alice",
            "weightDelta": 0,
            "reviewers": [],
            "metaReviews": [],
            "mergeVotes": [],
            "rejectVotes": [],
            "founderOverride": false,
            "warnings": ["some warning"]
        }"#;
        let idx: CommitIndex = serde_json::from_str(json).unwrap();
        assert_eq!(idx.warnings.as_ref().unwrap().len(), 1);
    }

    #[test]
    fn test_commit_index_without_warnings_backward_compat() {
        // Old cache entries don't have the warnings field
        let json = r#"{
            "commitHash": "abc",
            "epoch": 1000,
            "score": {"difficulty": 0, "novelty": 0, "designQuality": 0},
            "contributor": "alice",
            "weightDelta": 0,
            "reviewers": [],
            "metaReviews": [],
            "mergeVotes": [],
            "rejectVotes": [],
            "founderOverride": false
        }"#;
        let idx: CommitIndex = serde_json::from_str(json).unwrap();
        assert!(idx.warnings.is_none());
    }

    #[test]
    fn test_embedded_review_serde() {
        let review = EmbeddedReview {
            reviewer: "alice".to_string(),
            difficulty_ranking: vec!["abc".to_string(), "def".to_string()],
            novelty_ranking: vec!["def".to_string(), "abc".to_string()],
            design_quality_ranking: vec!["abc".to_string(), "def".to_string()],
            verdict: Verdict::Merge,
        };
        let json = serde_json::to_string(&review).unwrap();
        assert!(json.contains("difficultyRanking"));
        assert!(json.contains("designQualityRanking"));
        let parsed: EmbeddedReview = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.reviewer, "alice");
    }

    #[test]
    fn test_signed_commit_serde() {
        let commit = SignedCommit {
            id: "abc123".to_string(),
            pr_id: 42,
            author: "alice".to_string(),
            merge_epoch: 1000,
            pr_created_at: Some(900),
            comparison_targets: vec!["target1".to_string()],
            reviews: vec![],
            meta_reviews: vec![],
            founder_override: false,
        };
        let json = serde_json::to_string(&commit).unwrap();
        assert!(json.contains("prId"));
        assert!(json.contains("mergeEpoch"));
        assert!(json.contains("prCreatedAt"));
        assert!(json.contains("founderOverride"));
    }

    #[test]
    fn test_signed_commit_without_pr_created_at() {
        // Legacy commits might not have prCreatedAt
        let json = r#"{
            "id": "abc",
            "prId": 1,
            "author": "alice",
            "mergeEpoch": 1000,
            "comparisonTargets": [],
            "reviews": [],
            "metaReviews": [],
            "founderOverride": false
        }"#;
        let commit: SignedCommit = serde_json::from_str(json).unwrap();
        assert!(commit.pr_created_at.is_none());
    }

    #[test]
    fn test_merge_readiness_serde() {
        let json = r#"{"ready": true, "mergeWeight": 1000, "rejectWeight": 0, "totalWeight": 1000}"#;
        let readiness: MergeReadiness = serde_json::from_str(json).unwrap();
        assert!(readiness.ready);
        assert_eq!(readiness.merge_weight, 1000);
    }
}
