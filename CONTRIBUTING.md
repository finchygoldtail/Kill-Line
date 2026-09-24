# Contributing to Kill Line

Thanks for helping. Kill Line is security software that runs with administrator rights and watches other programs, so we hold changes to a high bar. We also try to make contributing straightforward.

## Ways to help

- **Report a false positive**: Kill Line flagged something your agent was allowed to do. Use the *False positive* issue form. These are the most useful reports we get.
- **Report a detection gap**: an agent crossed a boundary and Kill Line stayed quiet. If it could be abused, report it privately instead (see [SECURITY.md](SECURITY.md)).
- **Share a policy**: a containment policy for an agent or framework you use. Post it in Discussions → *Show and tell*.
- **Code**: see the roadmap in [docs/ROADMAP.md](docs/ROADMAP.md), or pick an issue labelled `good first issue` or `help wanted`.
- **Docs**: corrections, clearer explanations, translations.

Questions and ideas belong in **Discussions**, not issues.

## Ground rules

1. **Defensive only.** No exploit code, sandbox-escape implementations, credential-stealing or exfiltration logic, or evasion or persistence techniques, and that includes tests. Attack scenarios are safe simulations only (reserved addresses, fake secrets, local listeners). We will close PRs that cross this line.
2. **No false certainty.** User-facing text must never claim that an agent is "safe". If visibility is lost, the status is GREY. Correlations are worded as possibilities. The `never_claims_safety` test enforces the wording.
3. **Privacy by default.** Never capture file contents or network payloads; DNS query names are the only exception. Redact secrets. Nothing may leave the machine unless the user explicitly asks.
4. **Small, reviewed changes.** Every change goes through a pull request and review. Kernel-facing code (`bpf/`, `crates/killline-sensor/`) needs a second reviewer.

## Development setup

### Linux

```sh
sudo apt install clang libbpf-dev            # eBPF toolchain
cargo build && cargo test                    # unit + scenario tests (no root needed)
sudo target/debug/killline run --policy policies/no-network.yaml -- python3 test-agent/test_agent.py normal
sudo test-lab/setup.sh && sudo test-lab/run-demo.sh 1      # Docker test lab
```

### Windows

Run a terminal **as Administrator**, because ETW needs it:

```powershell
cargo build -p killline-cli
cargo test -p killline-core
python scripts\windows_smoke.py target\debug\killline.exe
```

### Desktop app

See [desktop/README.md](desktop/README.md). Use `desktop/build.sh` on Linux and `desktop\build.ps1` on Windows.

## Before you open a pull request

```sh
cargo fmt --all
cargo clippy --all-targets -- -D warnings
cargo test
cargo deny check          # if you changed dependencies
```

- Add or update tests. Rule changes need a scenario test in `crates/killline-core/tests/scenarios.rs`.
- For a false-positive fix, add the observation that triggered it as a test.
- Keep dependencies minimal and explain any new one in the PR.
- Update `CHANGELOG.md` under *Unreleased*.

## Commit sign-off (DCO)

Sign off every commit to certify the [Developer Certificate of Origin](https://developercertificate.org/):

```sh
git commit -s -m "Explain what and why"
```

We also encourage **signed commits** (SSH or GPG): `git config commit.gpgsign true`.

## Licensing

A licence has not been chosen yet. By contributing, you agree that your contribution may be released under the licence the project adopts. That will be an OSI-approved licence, with the kernel-side eBPF code under a GPL-compatible one. If you can't agree to that, say so in your PR.

## Code of conduct

Everyone taking part agrees to the [Code of Conduct](CODE_OF_CONDUCT.md).
