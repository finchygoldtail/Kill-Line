## What and why

<!-- What does this change, and what problem does it solve? Link issues: Fixes #123 -->

## How it was tested

<!-- Commands you ran; new or updated tests; the platforms you tried (Linux / Windows). -->

## Checklist

- [ ] `cargo fmt`, `cargo clippy --all-targets -- -D warnings` and `cargo test` pass
- [ ] Rule changes have a scenario test; false-positive fixes include the triggering observation
- [ ] No offensive code; attack scenarios are safe simulations
- [ ] No file contents or payloads are captured; secrets are redacted
- [ ] User-facing text never claims an agent is "safe"
- [ ] `CHANGELOG.md` updated under *Unreleased*
- [ ] Commits are signed off (`git commit -s`)
