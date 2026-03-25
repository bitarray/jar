use crate::hash;
use crate::types::{CollectedReviews, EmbeddedReview, MetaReview, Verdict};

/// Parse a `/review` comment body into an EmbeddedReview.
/// Returns None if the comment is malformed, with warnings added to the list.
pub fn parse_review_comment(
    body: &str,
    reviewer: &str,
    head_sha: &str,
    targets: &[String],
    warnings: &mut Vec<String>,
) -> Option<EmbeddedReview> {
    let body = hash::strip_carriage_returns(body);
    let lines: Vec<&str> = body.lines().collect();

    let mut difficulty = None;
    let mut novelty = None;
    let mut design = None;
    let mut verdict = None;

    for line in &lines {
        let line = line.trim();
        if let Some(rest) = line.strip_prefix("difficulty:") {
            difficulty = Some(parse_ranking(rest, reviewer, "difficulty", head_sha, targets, warnings));
        } else if let Some(rest) = line.strip_prefix("novelty:") {
            novelty = Some(parse_ranking(rest, reviewer, "novelty", head_sha, targets, warnings));
        } else if let Some(rest) = line.strip_prefix("design:") {
            design = Some(parse_ranking(rest, reviewer, "design", head_sha, targets, warnings));
        } else if let Some(rest) = line.strip_prefix("verdict:") {
            let v = rest.trim();
            verdict = match v {
                "merge" => Some(Verdict::Merge),
                "notMerge" => Some(Verdict::NotMerge),
                other => {
                    warnings.push(format!(
                        "reviewer {reviewer}: invalid verdict '{other}'"
                    ));
                    None
                }
            };
        }
    }

    let difficulty = difficulty?;
    let novelty = novelty?;
    let design = design?;
    let verdict = verdict?;

    Some(EmbeddedReview {
        reviewer: reviewer.to_string(),
        difficulty_ranking: difficulty,
        novelty_ranking: novelty,
        design_quality_ranking: design,
        verdict,
    })
}

/// Parse a ranking line: comma-separated short hashes, expanding each.
fn parse_ranking(
    line: &str,
    reviewer: &str,
    dimension: &str,
    head_sha: &str,
    targets: &[String],
    warnings: &mut Vec<String>,
) -> Vec<String> {
    let mut result = Vec::new();
    for item in line.split(',') {
        let item = item.trim();
        if item.is_empty() {
            continue;
        }
        // Normalize: strip URLs, replace currentPR
        let normalized = hash::normalize_commit_ref(item);
        let normalized = if normalized == "currentPR" {
            head_sha.to_string()
        } else {
            normalized
        };
        // Expand short hash
        // Build candidate list: targets + head_sha
        let mut candidates = targets.to_vec();
        candidates.push(head_sha.to_string());
        match hash::expand_short_hash(&normalized, &candidates) {
            Ok(full) => result.push(full),
            Err(e) => {
                warnings.push(format!(
                    "reviewer {reviewer}: {dimension} ranking: {e}"
                ));
                // Include the raw value so it occupies a position
                result.push(normalized);
            }
        }
    }
    result
}

/// Collect reviews from a PR and print as JSON.
pub fn collect_and_print(
    _pr: u64,
    _head_sha: Option<&str>,
    _targets: Option<&str>,
) -> Result<(), Box<dyn std::error::Error>> {
    // TODO: implement full collection via GitHub API
    let collected = CollectedReviews {
        reviews: vec![],
        meta_reviews: vec![],
        warnings: vec![],
    };
    println!("{}", serde_json::to_string_pretty(&collected)?);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    const HEAD_SHA: &str = "36d25a6a86c547b9d6b89971a501b966b89d5351";
    const TARGET_A: &str = "204e93abf18ab00e339d92787c6f807269517cdf";
    const TARGET_B: &str = "b012110bedc7f0ffca3ae37f38915afbc229c26e";

    fn targets() -> Vec<String> {
        vec![TARGET_A.to_string(), TARGET_B.to_string()]
    }

    #[test]
    fn test_parse_well_formed_review() {
        let body = "/review\ndifficulty: 204e93ab, currentPR, b012110b\nnovelty: currentPR, 204e93ab, b012110b\ndesign: 204e93ab, currentPR, b012110b\nverdict: merge\n\nGreat work!";
        let mut warnings = vec![];
        let review =
            parse_review_comment(body, "alice", HEAD_SHA, &targets(), &mut warnings).unwrap();
        assert!(warnings.is_empty(), "unexpected warnings: {warnings:?}");
        assert_eq!(review.difficulty_ranking, vec![TARGET_A, HEAD_SHA, TARGET_B]);
        assert_eq!(review.novelty_ranking, vec![HEAD_SHA, TARGET_A, TARGET_B]);
        assert_eq!(review.verdict, Verdict::Merge);
    }

    #[test]
    fn test_parse_review_with_carriage_returns() {
        let body = "/review\r\ndifficulty: 204e93ab, currentPR\r\nnovelty: currentPR, 204e93ab\r\ndesign: 204e93ab, currentPR\r\nverdict: merge\r\n";
        let mut warnings = vec![];
        let review =
            parse_review_comment(body, "bob", HEAD_SHA, &targets(), &mut warnings).unwrap();
        assert!(warnings.is_empty(), "unexpected warnings: {warnings:?}");
        assert_eq!(review.verdict, Verdict::Merge);
    }

    #[test]
    fn test_parse_review_with_github_urls() {
        let url_a = format!("https://github.com/jarchain/jar/commit/{TARGET_A}");
        let body = format!(
            "/review\ndifficulty: {url_a}, currentPR\nnovelty: currentPR, {url_a}\ndesign: {url_a}, currentPR\nverdict: merge"
        );
        let mut warnings = vec![];
        let review =
            parse_review_comment(&body, "carol", HEAD_SHA, &targets(), &mut warnings).unwrap();
        assert!(warnings.is_empty(), "unexpected warnings: {warnings:?}");
        assert_eq!(review.difficulty_ranking, vec![TARGET_A, HEAD_SHA]);
    }

    #[test]
    fn test_parse_review_invalid_verdict() {
        let body =
            "/review\ndifficulty: currentPR\nnovelty: currentPR\ndesign: currentPR\nverdict: maybe";
        let mut warnings = vec![];
        let review = parse_review_comment(body, "dave", HEAD_SHA, &targets(), &mut warnings);
        assert!(review.is_none());
        assert!(warnings.iter().any(|w| w.contains("invalid verdict")));
    }

    #[test]
    fn test_parse_review_missing_field() {
        let body = "/review\ndifficulty: currentPR\nnovelty: currentPR\nverdict: merge";
        let mut warnings = vec![];
        let review = parse_review_comment(body, "eve", HEAD_SHA, &targets(), &mut warnings);
        assert!(review.is_none()); // missing design
    }
}
