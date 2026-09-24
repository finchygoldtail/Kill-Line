# Security model of KillLine itself

KillLine runs as root and parses data produced by a potentially hostile agent: paths, DNS packets, command lines and socket addresses. It is therefore treated as security-sensitive software.

## Principles

| Principle | How V1 applies it |
|---|---|
| **Observe-only kernel program** | The eBPF program never modifies, blocks or delays syscalls. It only copies metadata (paths, addresses, argv prefixes, the first 128 bytes of DNS queries) into a ring buffer. The verifier guarantees memory safety and termination |
| **Data minimisation** | File contents are never read. Network payloads are never read except DNS query names. Command lines are redacted before they reach the engine. Incident bundles contain metadata only |
| **Memory-safe userspace** | All parsing of agent-controlled data happens in Rust. `unsafe` is limited to FFI (`poll`, `pipe`, `kill`, `setuid`, `execvp`, unaligned ring-buffer reads), each with a `SAFETY` note |
| **Strict input validation** | Policies: 256 KiB cap, `deny_unknown_fields`, list and entry length limits, no control characters, validated domains, CIDRs and agent IDs. Container names are restricted to `[A-Za-z0-9_.-]`. Incident IDs are validated before being used as paths. DNS parsing is bounded and rejects compression pointers and non-hostname bytes |
| **Terminal-injection safety** | Every agent-controlled string (paths, comm, argv) has control characters replaced before printing, so an agent cannot inject ANSI escape sequences into the operator's terminal |
| **Robust output** | Writes to a closed stdout/pipe are ignored; they cannot crash the monitor |
| **Least privilege for the agent** | `killline run --user UID[:GID]` drops the agent's privileges (setgroups, setgid, setuid) *after* tracking starts. The test lab runs the agent as `65534`, read-only, with `cap_drop: ALL` and `no-new-privileges` |
| **No network, no telemetry** | KillLine makes no network connections. The only external command it runs is the local `docker` CLI (`inspect`; and `pause`/`kill` only if a response is configured) |
| **Local, private storage** | `/var/lib/killline` (or `$KILLLINE_HOME`), directories `0700`, files `0600`, atomic replace for snapshots |
| **Tamper evidence** | Hash-chained timeline (`killline verify <session>`); SHA-256 `checksums.txt` per incident (`killline verify <incident>`); monitor heartbeat → GREY when stale; drop counter → GREY |
| **Honest status** | Critical coverage gaps and drops always surface. Wording never claims safety; this is enforced by a test (`never_claims_safety`) |
| **Fail-closed option** | `response.on_degraded: freeze\|terminate` |

## Privileges KillLine needs

Root, or at minimum:

- `CAP_BPF` and `CAP_PERFMON`: load programs, attach tracepoints, create maps;
- `CAP_SYS_PTRACE` and `CAP_DAC_READ_SEARCH`: read `/proc/<pid>/root`, `cwd` and `fd` of other users' processes for path resolution and exe hashing;
- `CAP_KILL` (or root): the SIGSTOP/SIGKILL responses in process mode;
- access to the Docker CLI/socket for container mode. **Note:** Docker socket access is itself equivalent to root.

Running KillLine with fewer capabilities (a dedicated user with file capabilities) is supported by the design but not yet packaged.

## Supply chain

- `Cargo.lock` is committed; builds are reproducible from locked versions.
- Runtime dependencies are deliberately few: `aya` (BPF loading), `serde`/`serde_json`/`serde_yaml`, `sha2`/`hex`, `chrono`, `libc`, `clap`, `anyhow`. There is no async runtime, no HTTP client and no C library linked at runtime.
- `serde_yaml` 0.9 is archived upstream but stable. Replacing it (e.g. `serde_norway` or a restricted YAML subset parser) is tracked in the roadmap, because YAML parsing is attack surface for policies.
- The BPF object is compiled from source (`bpf/killline.bpf.c`) at build time; no prebuilt binary blobs are committed. `build.rs` fails the build if clang is present but compilation fails, so a broken build can never silently produce a monitor without its sensor.
- `deny.toml` configures `cargo deny` (advisories, licenses, bans, sources). CI runs `cargo deny check`, `cargo clippy -D warnings`, tests, and generates a CycloneDX SBOM (`cargo cyclonedx`).
- **Later:** signed releases (Sigstore/cosign), a documented secure update path (signed manifests, no auto-update by default), and reproducible-build verification.

## Reporting vulnerabilities

Until a formal process exists, please report privately to the maintainers rather than opening a public issue.
