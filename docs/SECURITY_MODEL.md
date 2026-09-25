# Security model of Kill Line itself

Kill Line runs as root and parses data produced by a potentially hostile agent: paths, DNS packets, command lines and socket addresses. It is therefore treated as security-sensitive software.

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
| **No network, no telemetry** | Kill Line makes no network connections. The only external command it runs is the local `docker` CLI (`inspect`; and `pause`/`kill` only if a response is configured) |
| **Local, private storage** | `/var/lib/killline` (or `$KILLLINE_HOME`), directories `0700`, files `0600`, atomic replace for snapshots |
| **Tamper evidence** | Hash-chained timeline (`killline verify <session>`); SHA-256 `checksums.txt` per incident (`killline verify <incident>`); monitor heartbeat → GREY when stale; drop counter → GREY |
| **Honest status** | Critical coverage gaps and drops always surface. Wording never claims safety; this is enforced by a test (`never_claims_safety`) |
| **Fail-closed option** | `response.on_degraded: freeze\|terminate` |

## The local dashboard (`killline ui`)

- Listens on **127.0.0.1 only**. There is no option to bind elsewhere.
- **Access token:** a random 128-bit token is generated per run and printed in the link (`#token`, a URL fragment, so it is never sent in requests or logs). The page sends it in an `X-KillLine-Token` header. Every API call without it gets 401. The custom header also forces a CORS preflight, which the server never approves, so other websites open in the same browser cannot read data or trigger actions.
- **DNS-rebinding defence:** requests whose `Host` header is not `127.0.0.1:<port>`, `localhost:<port>` or `[::1]:<port>` are rejected.
- **Strict CSP:** `default-src 'none'; script-src 'self'; style-src 'self'; connect-src 'self'; frame-ancestors 'none'`, plus `nosniff`, `no-referrer`, `no-store` and `X-Frame-Options: DENY`. All assets are embedded in the binary, with no CDN.
- **Rendering:** agent-controlled strings are inserted as text nodes only, never as HTML.
- **Requests:** POST bodies must be JSON and at most 16 KiB. IDs are validated before any filesystem use.
- **Operator actions** (freeze/resume/terminate/stop) are passed to the running monitor through a `control.json` file in the root-only session directory. The monitor, which owns the sensor and the tracked PIDs, executes the action and records it in the timeline.
- **Monitors started from the dashboard** run detached, so they keep running if the dashboard is closed.

## Privileges Kill Line needs

Root, or at minimum:

- `CAP_BPF` and `CAP_PERFMON`: load programs, attach tracepoints, create maps;
- `CAP_SYS_PTRACE` and `CAP_DAC_READ_SEARCH`: read `/proc/<pid>/root`, `cwd` and `fd` of other users' processes for path resolution and exe hashing;
- `CAP_KILL` (or root): the SIGSTOP/SIGKILL responses in process mode;
- access to the Docker CLI/socket for container mode. **Note:** Docker socket access is itself equivalent to root.

Running Kill Line with fewer capabilities (a dedicated user with file capabilities) is supported by the design but not yet packaged.

## Supply chain

- `Cargo.lock` is committed; builds are reproducible from locked versions.
- Runtime dependencies are deliberately few: `aya` (BPF loading), `serde`/`serde_json`/`serde_yaml`, `sha2`/`hex`, `chrono`, `libc`, `clap`, `anyhow`. There is no async runtime, no HTTP client and no C library linked at runtime.
- `serde_yaml` 0.9 is archived upstream but stable. Replacing it (e.g. `serde_norway` or a restricted YAML subset parser) is tracked in the roadmap, because YAML parsing is attack surface for policies.
- The BPF object is compiled from source (`bpf/killline.bpf.c`) at build time; no prebuilt binary blobs are committed. `build.rs` fails the build if clang is present but compilation fails, so a broken build can never silently produce a monitor without its sensor.
- `deny.toml` configures `cargo deny` (advisories, licenses, bans, sources). CI runs `cargo deny check`, `cargo clippy -D warnings`, tests, and generates a CycloneDX SBOM (`cargo cyclonedx`).
- **Later:** signed releases (Sigstore/cosign), a documented secure update path (signed manifests, no auto-update by default), and reproducible-build verification.

## Reporting vulnerabilities

Until a formal process exists, please report privately to the maintainers rather than opening a public issue.
