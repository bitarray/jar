## Summary

Brief description of what this PR does and why.

## Changes

-

## Test Plan

- [ ] `cargo test --workspace` passes
- [ ] `cargo clippy --workspace --all-targets -- -D warnings` passes
- [ ] `cargo fmt --all --check` passes
- [ ] Conformance vectors pass (`cargo test -p grey-state`)

## Checklist

- [ ] Commit messages follow [Conventional Commits](https://www.conventionalcommits.org/)
- [ ] No `unwrap()` in non-test code
- [ ] All `unsafe` blocks have `// SAFETY:` comments
- [ ] JAM codec used for serialization (not SCALE)
