use crate::github;
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
            difficulty = Some(parse_ranking(
                rest, reviewer, "difficulty", head_sha, targets, warnings,
            ));
        } else if let Some(rest) = line.strip_prefix("novelty:") {
            novelty = Some(parse_ranking(
                rest, reviewer, "novelty", head_sha, targets, warnings,
            ));
        } else if let Some(rest) = line.strip_prefix("design:") {
            design = Some(parse_ranking(
                rest, reviewer, "design", head_sha, targets, warnings,
            ));
        } else if let Some(rest) = line.strip_prefix("verdict:") {
            let v = rest.trim();
            verdict = match v {
                "merge" => Some(Verdict::Merge),
                "notMerge" => Some(Verdict::NotMerge),
                other => {
                    warnings.push(format!("reviewer {reviewer}: invalid verdict '{other}'"));
                    None
                }
            };
        }
    }

    let difficulty = difficulty?;
    let novelty = novelty?;
    let design = design?;
    let verdict = verdict?;

    // Validate ranking counts: should be len(targets) + 1 (for currentPR)
    let expected = targets.len() + 1;
    for (name, ranking) in [
        ("difficulty", &difficulty),
        ("novelty", &novelty),
        ("design", &design),
    ] {
        if ranking.len() != expected {
            warnings.push(format!(
                "reviewer {reviewer}: {name} ranking has {} entries, expected {expected}",
                ranking.len()
            ));
        }
    }

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
        // Expand short hash against targets + head_sha
        let mut candidates = targets.to_vec();
        candidates.push(head_sha.to_string());
        match hash::expand_short_hash(&normalized, &candidates) {
            Ok(full) => result.push(full),
            Err(e) => {
                warnings.push(format!("reviewer {reviewer}: {dimension} ranking: {e}"));
                // Include the raw value so it occupies a position
                result.push(normalized);
            }
        }
    }
    result
}

/// Collect all reviews and meta-reviews from a PR via GitHub API.
pub fn collect(
    pr: u64,
    head_sha: &str,
    targets: &[String],
) -> Result<CollectedReviews, Box<dyn std::error::Error>> {
    let mut warnings = Vec::new();

    // Fetch all comments on the PR
    let repo = std::env::var("GITHUB_REPOSITORY").unwrap_or_else(|_| {
        let output = github::gh(&["repo", "view", "--json", "nameWithOwner", "--jq", ".nameWithOwner"])
            .expect("failed to get repo name");
        output.trim().to_string()
    });

    let comments_output = github::gh(&[
        "api",
        &format!("repos/{repo}/issues/{pr}/comments"),
        "--paginate",
        "--jq",
        r#"[.[] | select(.body | startswith("/review")) | {id: .id, author: .user.login, body: .body}]"#,
    ])?;

    let comments: Vec<serde_json::Value> = serde_json::from_str(comments_output.trim())?;

    // Parse reviews (last review per author wins)
    let mut reviews: Vec<EmbeddedReview> = Vec::new();
    let mut review_comment_ids: Vec<(String, u64)> = Vec::new(); // (reviewer, comment_id)

    for comment in &comments {
        let id = comment["id"].as_u64().unwrap_or(0);
        let author = comment["author"].as_str().unwrap_or("");
        let body = comment["body"].as_str().unwrap_or("");

        if let Some(review) = parse_review_comment(body, author, head_sha, targets, &mut warnings)
        {
            // Remove existing review from same reviewer
            reviews.retain(|r| r.reviewer != author);
            review_comment_ids.retain(|(r, _)| r != author);
            reviews.push(review);
            review_comment_ids.push((author.to_string(), id));
        }
    }

    // Collect meta-reviews: 👍/👎 reactions on latest /review comment per reviewer
    let mut meta_reviews: Vec<MetaReview> = Vec::new();

    for (target_reviewer, comment_id) in &review_comment_ids {
        let reactions_output = github::gh(&[
            "api",
            &format!("repos/{repo}/issues/comments/{comment_id}/reactions"),
            "--jq",
            r#"[.[] | select(.content == "+1" or .content == "-1") | {user: .user.login, content: .content}]"#,
        ]);

        let reactions: Vec<serde_json::Value> = match reactions_output {
            Ok(output) => serde_json::from_str(output.trim()).unwrap_or_default(),
            Err(_) => Vec::new(),
        };

        for reaction in &reactions {
            let meta_reviewer = reaction["user"].as_str().unwrap_or("");
            let content = reaction["content"].as_str().unwrap_or("");
            let approve = content == "+1";

            meta_reviews.push(MetaReview {
                meta_reviewer: meta_reviewer.to_string(),
                target_reviewer: target_reviewer.to_string(),
                approve,
            });
        }
    }

    Ok(CollectedReviews {
        reviews,
        meta_reviews,
        warnings,
    })
}

/// Collect reviews from a PR and print as JSON (CLI entry point).
pub fn collect_and_print(
    pr: u64,
    head_sha: Option<&str>,
    targets_json: Option<&str>,
) -> Result<(), Box<dyn std::error::Error>> {
    let head_sha = head_sha.unwrap_or("");
    let targets: Vec<String> = match targets_json {
        Some(json) => serde_json::from_str(json)?,
        None => Vec::new(),
    };

    let collected = collect(pr, head_sha, &targets)?;
    println!("{}", serde_json::to_string(&collected)?);
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
        assert_eq!(
            review.difficulty_ranking,
            vec![TARGET_A, HEAD_SHA, TARGET_B]
        );
        assert_eq!(
            review.novelty_ranking,
            vec![HEAD_SHA, TARGET_A, TARGET_B]
        );
        assert_eq!(review.verdict, Verdict::Merge);
    }

    #[test]
    fn test_parse_review_with_carriage_returns() {
        let body = "/review\r\ndifficulty: 204e93ab, currentPR\r\nnovelty: currentPR, 204e93ab\r\ndesign: 204e93ab, currentPR\r\nverdict: merge\r\n";
        let mut warnings = vec![];
        let review =
            parse_review_comment(body, "bob", HEAD_SHA, &targets(), &mut warnings).unwrap();
        // Ranking count warnings expected (2 entries, expected 3)
        assert_eq!(review.verdict, Verdict::Merge);
    }

    #[test]
    fn test_parse_review_with_github_urls() {
        let url_a = format!("https://github.com/jarchain/jar/commit/{TARGET_A}");
        let body = format!(
            "/review\ndifficulty: {url_a}, currentPR, b012110b\nnovelty: currentPR, {url_a}, b012110b\ndesign: {url_a}, currentPR, b012110b\nverdict: merge"
        );
        let mut warnings = vec![];
        let review =
            parse_review_comment(&body, "carol", HEAD_SHA, &targets(), &mut warnings).unwrap();
        assert!(
            warnings.is_empty(),
            "unexpected warnings: {warnings:?}"
        );
        assert_eq!(
            review.difficulty_ranking,
            vec![TARGET_A, HEAD_SHA, TARGET_B]
        );
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

    #[test]
    fn test_last_review_per_author_wins() {
        // Simulate two reviews from the same author by calling parse twice
        let body1 = "/review\ndifficulty: 204e93ab, currentPR, b012110b\nnovelty: 204e93ab, currentPR, b012110b\ndesign: 204e93ab, currentPR, b012110b\nverdict: notMerge";
        let body2 = "/review\ndifficulty: currentPR, 204e93ab, b012110b\nnovelty: currentPR, 204e93ab, b012110b\ndesign: currentPR, 204e93ab, b012110b\nverdict: merge";
        let mut warnings = vec![];
        let mut reviews: Vec<EmbeddedReview> = Vec::new();

        if let Some(r) = parse_review_comment(body1, "alice", HEAD_SHA, &targets(), &mut warnings)
        {
            reviews.retain(|r| r.reviewer != "alice");
            reviews.push(r);
        }
        if let Some(r) = parse_review_comment(body2, "alice", HEAD_SHA, &targets(), &mut warnings)
        {
            reviews.retain(|r| r.reviewer != "alice");
            reviews.push(r);
        }

        assert_eq!(reviews.len(), 1);
        assert_eq!(reviews[0].verdict, Verdict::Merge); // second review wins
        assert_eq!(reviews[0].difficulty_ranking[0], HEAD_SHA); // currentPR first
    }

    #[test]
    fn test_ranking_count_warning() {
        // Only 1 entry instead of expected 3 (2 targets + currentPR)
        let body =
            "/review\ndifficulty: currentPR\nnovelty: currentPR\ndesign: currentPR\nverdict: merge";
        let mut warnings = vec![];
        let review =
            parse_review_comment(body, "frank", HEAD_SHA, &targets(), &mut warnings).unwrap();
        assert_eq!(review.verdict, Verdict::Merge);
        assert_eq!(warnings.len(), 3); // one warning per dimension
        assert!(warnings[0].contains("1 entries, expected 3"));
    }
}
