# Limitations (V1)

This page lists what Kill Line does not see or cannot guarantee. When a limitation affects visibility at runtime, Kill Line reports it as a coverage gap or turns GREY rather than staying silent.

## Visibility gaps (not hooked yet)

| Gap | Effect | Planned fix |
|---|---|---|
| `read`/`write`/`sendfile`/`splice` on already-open fds | Data volume is unknown; exfiltration size signals are not implemented | Byte counters per fd in-kernel |
| `io_uring` operations (`IORING_OP_OPENAT`, `CONNECT`, …) | An agent using io_uring can open files or connect **without** the syscall tracepoints firing | Hook `io_uring` submission (`io_uring_submit_req` tracepoint) or LSM hooks |
| `open_by_handle_at`, `name_to_handle_at` | Opens by file handle bypass path rules | Hook both; flag any use (requires `CAP_DAC_READ_SEARCH`) |
| `link`/`linkat`, `symlink`/`symlinkat` creation, `truncate` | Hard links to sensitive files, or link creation as preparation, are not flagged at creation time. Opening through a symlink **is** resolved | Hook creation |
| `clone`/`clone3` with `CLONE_NEW*` flags | New namespaces created at clone time are missed (only `unshare`/`setns` are seen) | Inspect clone flags |
| New mount API (`fsopen`, `fsmount`, `move_mount`, `open_tree`) | Mounts via the new API are missed | Hook them |
| `memfd_create` + `execveat` (fileless execution) | The exec is seen (path `/memfd:…`), and a hash is not available | Flag memfd execs explicitly |
| Capability *use* | Only `capset` is seen, not `cap_capable` checks | Optional kprobe |
| DNS answers | Allowlist-by-domain cannot confirm which IP a name resolved to (see below) | Parse `recvfrom`/`recvmsg` on port-53 sockets |
| TLS/DoH/DoT | Encrypted DNS appears only as HTTPS | Out of scope for content; destination rules still apply |
| MCP protocol | No visibility of tool names or arguments; the `mcp:` policy section is **parsed but not verified** | Optional MCP proxy/observer (see Roadmap) |
| gVisor, Kata, Firecracker, other VM sandboxes | Guest syscalls are invisible to host eBPF | In-guest sensor, or runtime-specific integration |
| Rootless Docker / Podman, Kubernetes | Not tested in V1 | Roadmap |

## Windows (ETW sensor) gaps

Windows support uses Event Tracing for Windows, which reports less than the Linux eBPF sensor. Each gap below is listed on the session's coverage report.

| Gap | Effect | Planned fix |
|---|---|---|
| Named-pipe opens | Opening `\\.\pipe\docker_engine` (or any other named pipe) is **not reported** by the Kernel-File provider, so the container-runtime rule does not fire on Windows. Observed on GitHub's Windows runners | A file-system minifilter or the Kernel-Object provider |
| Open results | Whether a file open succeeded or was refused is not observed ("result not observed") | Pair with the Kernel-File close/cleanup events |
| Command lines | Only the program path is recorded, not its arguments | Read the command line from the process (PEB) at start |
| Token and privilege changes, service creation, driver loads | Seen only as program executions (for example `sc.exe`) | Security-Auditing and Kernel-Audit-API providers |
| TCP attempts that never complete | Seen only once Windows retries the SYN (about 1 s later) | None needed; the attempt is still recorded |

Kill Line must run as Administrator on Windows.

## Accuracy limits

- **Detection, not prevention.** Rules fire on syscall *entry*. `freeze`/`terminate` act afterwards, typically within milliseconds. The first violating action is not blocked. Prevention needs BPF-LSM, seccomp or netfilter (Phase 3).
- **Userspace path resolution is racy.** Relative paths are resolved via `/proc/<pid>/cwd` or `/proc/<pid>/fd/<dirfd>` after the event. Symlinks are resolved inside `/proc/<pid>/root`, with a 1 s cache for intermediate directories (final component always checked). A process that swaps a symlink between its open and Kill Line's check can mislead the resolver. When the kernel permits `fentry/security_file_open`, kernel-resolved paths close this gap. Kill Line reports at startup when that hook is unavailable.
- **Userspace reads of syscall arguments are also racy (TOCTOU).** Another thread can change the path buffer after the tracepoint reads it. LSM-level hooks are the robust fix.
- **Unresolvable relative paths** (the process exited before resolution) are recorded as "unresolved" and not evaluated. The kernel-resolved event, when available, still covers successful opens.
- **Allowlist by domain** trusts a 300 s window after an allowed DNS query. A hard-coded attacker IP contacted inside that window is labelled "destination not verified", not RED. Use `mode: deny` or CIDR allowlists for high assurance.
- **UDP `connect()` success** only sets a destination; Kill Line words it that way.
- **`EINPROGRESS`** non-blocking connects are reported as "in progress"; completion is not observed.
- **Argument capture** is limited to the first 6 argv entries of 41 characters each, and is redacted heuristically. Redaction can miss unusual secret formats. It can also over-redact.
- **Executable hashes** are computed from userspace and may be missing for very short-lived programs or files deleted after exec.
- **`/proc/<pid>` rules** compare against the host PID for lexical paths. Kernel-resolved `/proc/self` paths use the namespace-local PID, so `/proc/*/…` indicator rules are applied only to lexical paths.
- **Anomaly heuristics** are simple sliding windows with fixed thresholds. They will produce both false positives (big builds) and false negatives (slow enumeration).
- **Correlations are temporal**, not causal, and are always worded "Possible …".

## Operational limits

- Requires Linux ≥ 5.8 (BPF ring buffer) with BTF (`/sys/kernel/btf/vmlinux`). Developed on 6.18.
- Must run as root (or with `CAP_BPF`, `CAP_PERFMON`, `CAP_SYS_PTRACE` for `/proc/<pid>/root`, and `CAP_DAC_READ_SEARCH`).
- **Throughput.** ~120k events/s sustained, bursts of ~27k records absorbed by the 16 MB ring buffer. Floods beyond that drop events. Kill Line reports the drops and turns GREY, and it can fail closed (`response.on_degraded`).
- The session timeline is buffered; a crash of Kill Line can lose up to ~1 s of timeline (the heartbeat will show GREY).
- The hash chain is **tamper-evident, not tamper-proof**: host root can rewrite the entire file. Anchoring the head hash externally (for example signing it) is on the roadmap.
- Container mode requires a separate PID namespace (not `--pid=host`).
- One agent per `killline` process in V1.
- x86_64 tested; arm64 compiles in principle (`-D__TARGET_ARCH_arm64`) but is untested.
