# Roadmap

The first milestone was: **prove we can independently detect a simple AI-agent containment boundary crossing in real time, and reconstruct exactly what happened.** It is done (V0.1, see CHANGELOG). What follows is ordered by value to that thesis, not by size.

## Next: close the known blind spots

1. **Hook the remaining bypass syscalls**: `io_uring` submissions, `open_by_handle_at`, `link`/`symlink` creation, `clone`/`clone3` namespace flags, new mount API, `memfd` exec, `truncate`.
2. **Kernel-resolved paths everywhere.** Use `fentry`/BPF-LSM (`security_file_open`, `security_socket_connect`, `security_bprm_check`) where the kernel permits it. Keep reporting the fallback clearly.
3. **DNS answers.** Parse `recvfrom`/`recvmsg` on port-53 sockets to map IP → name. Replace the 300 s attribution window with exact matching, and detect DNS rebinding to internal ranges.
4. **cgroup v2 scoping.** Prefer `bpf_get_current_cgroup_id()` on v2 hosts; keep PID namespaces as a fallback.
5. **Throughput.** Variable-size records, a dedicated drain thread, in-kernel aggregation of allowed runtime reads, configurable ring size.

## Then: active verification (differentiator)

6. **Canary probes (`killline attest`).** At session start, run harmless boundary probes inside the sandbox (IMDS connect, `docker.sock` connect, credential-path open, TEST-NET egress, write outside the workspace). Prove two things: that the **sandbox refuses them**, and that **KillLine sees them**. Output a signed attestation of the form "sandbox claim held for these boundaries at time T". We found no competitor doing this (see COMPETITIVE_LANDSCAPE.md).
7. **Signed evidence.** Sign the timeline head hash and incident checksums with a local key. Add optional anchoring to an append-only transparency log (still local by default).

## Phase 3: optional enforcement

8. BPF-LSM deny for file/connect/exec where available; nftables egress drop in the agent's netns; `cgroup.freeze` on v2. Always explicitly configured; monitor-only stays the default.
9. "Allow once" and interactive decisions in the TUI.

## Behavioural layer (after the hard layer is reliable)

10. Exfiltration signals: bytes read, archive creation followed by outbound transfer, outbound volume per destination.
11. Behaviour-shift detection: activity-class histograms before and after reading untrusted inputs, still worded as "possible".
12. Tool-call and prompt correlation, where agent frameworks expose events. Always kept separate from, and subordinate to, the OS-level truth.

## MCP

13. An optional local **MCP observer** (stdio/HTTP proxy). It records servers, exposed tools, invoked tools, redacted arguments and response metadata, and enforces `mcp.allow_servers` / `deny_unknown_servers`. It will be correlated with OS events from the MCP server processes (which KillLine already sees as descendants).

## Platform

14. Kubernetes DaemonSet mode, possibly with a Tetragon or Falco sensor backend behind the existing `Observation` interface.
15. Rootless Docker/Podman; arm64 CI.
16. In-guest sensor for microVM sandboxes (Firecracker/Kata); gVisor integration via its own event stream.
17. A local dashboard (TUI first; Tauri or web later) built on `session.json` and `timeline.jsonl`.

## Hygiene

18. Replace `serde_yaml` (archived) with a maintained or restricted parser; fuzz the policy and DNS parsers (`cargo fuzz`).
19. Signed releases, SBOM per release, reproducible builds, packaged least-privilege capabilities.
20. Licensing decision (the architecture keeps an open-source core possible: no proprietary services required).
