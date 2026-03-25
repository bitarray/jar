use thiserror::Error;

#[derive(Debug, Error)]
pub enum HashError {
    #[error("no match for short hash '{0}'")]
    NoMatch(String),
    #[error("ambiguous short hash '{0}': matches {1:?}")]
    Ambiguous(String, Vec<String>),
    #[error("invalid hex: '{0}'")]
    InvalidHex(String),
}

/// Strip the GitHub commit URL prefix if present.
/// `https://github.com/owner/repo/commit/abc123...` → `abc123...`
pub fn normalize_commit_ref(s: &str) -> String {
    // Match pattern: https://github.com/<owner>/<repo>/commit/<hash>
    if let Some(idx) = s.find("/commit/") {
        s[idx + "/commit/".len()..].to_string()
    } else {
        s.to_string()
    }
}

/// Check if a string is a valid 40-character lowercase hex hash.
pub fn is_valid_hex_hash(s: &str) -> bool {
    s.len() == 40 && s.chars().all(|c| c.is_ascii_hexdigit() && !c.is_ascii_uppercase())
}

/// Strip carriage returns from a string.
pub fn strip_carriage_returns(s: &str) -> String {
    s.replace('\r', "")
}

/// Expand a short hash (typically 8 chars) to a full 40-char hash
/// by prefix-matching against a list of candidates.
pub fn expand_short_hash(short: &str, candidates: &[String]) -> Result<String, HashError> {
    // Already full length — pass through.
    if short.len() == 40 {
        if is_valid_hex_hash(short) {
            return Ok(short.to_string());
        }
        return Err(HashError::InvalidHex(short.to_string()));
    }

    // Validate hex.
    if !short.chars().all(|c| c.is_ascii_hexdigit()) {
        return Err(HashError::InvalidHex(short.to_string()));
    }

    let matches: Vec<String> = candidates
        .iter()
        .filter(|c| c.starts_with(short))
        .cloned()
        .collect();

    match matches.len() {
        0 => Err(HashError::NoMatch(short.to_string())),
        1 => Ok(matches.into_iter().next().unwrap()),
        _ => Err(HashError::Ambiguous(short.to_string(), matches)),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_expand_short_hash_unique_match() {
        let candidates = vec![
            "204e93abf18ab00e339d92787c6f807269517cdf".to_string(),
            "b012110bedc7f0ffca3ae37f38915afbc229c26e".to_string(),
        ];
        let result = expand_short_hash("204e93ab", &candidates).unwrap();
        assert_eq!(result, "204e93abf18ab00e339d92787c6f807269517cdf");
    }

    #[test]
    fn test_expand_short_hash_no_match() {
        let candidates = vec!["204e93abf18ab00e339d92787c6f807269517cdf".to_string()];
        let result = expand_short_hash("deadbeef", &candidates);
        assert!(matches!(result, Err(HashError::NoMatch(_))));
    }

    #[test]
    fn test_expand_short_hash_ambiguous() {
        let candidates = vec![
            "204e93abf18ab00e339d92787c6f807269517cdf".to_string(),
            "204e93ab0000000000000000000000000000000000".to_string(),
        ];
        let result = expand_short_hash("204e93ab", &candidates);
        assert!(matches!(result, Err(HashError::Ambiguous(_, _))));
    }

    #[test]
    fn test_expand_full_hash_passthrough() {
        let candidates = vec![];
        let hash = "204e93abf18ab00e339d92787c6f807269517cdf";
        let result = expand_short_hash(hash, &candidates).unwrap();
        assert_eq!(result, hash);
    }

    #[test]
    fn test_expand_invalid_hex() {
        let candidates = vec![];
        let result = expand_short_hash("not_hex!", &candidates);
        assert!(matches!(result, Err(HashError::InvalidHex(_))));
    }

    #[test]
    fn test_normalize_commit_ref_url() {
        let url = "https://github.com/jarchain/jar/commit/204e93abf18ab00e339d92787c6f807269517cdf";
        assert_eq!(
            normalize_commit_ref(url),
            "204e93abf18ab00e339d92787c6f807269517cdf"
        );
    }

    #[test]
    fn test_normalize_commit_ref_bare_hash() {
        let hash = "204e93abf18ab00e339d92787c6f807269517cdf";
        assert_eq!(normalize_commit_ref(hash), hash);
    }

    #[test]
    fn test_is_valid_hex_hash() {
        assert!(is_valid_hex_hash(
            "204e93abf18ab00e339d92787c6f807269517cdf"
        ));
        assert!(!is_valid_hex_hash("too_short"));
        assert!(!is_valid_hex_hash(
            "204E93ABF18AB00E339D92787C6F807269517CDF"
        )); // uppercase
        assert!(!is_valid_hex_hash(
            "204e93abf18ab00e339d92787c6f807269517cdX"
        )); // non-hex
    }

    #[test]
    fn test_strip_carriage_returns() {
        assert_eq!(strip_carriage_returns("merge\r"), "merge");
        assert_eq!(strip_carriage_returns("merge"), "merge");
        assert_eq!(strip_carriage_returns("a\rb\rc\r"), "abc");
    }
}
