# Changelog

## Unreleased

### Added
- **Desktop app** (`desktop/`, Tauri 2, Linux): asks for administrator permission through polkit, starts the bundled engine, and shows the dashboard in a native window. A navigation guard restricts the window to the engine's own address, and the dashboard page gets no Tauri API access. It sends native notifications for new breaches and for loss of visibility, and the engine stops when the app closes (even if the app is killed). Ships as a `.deb` (with a polkit policy) and an AppImage; `desktop/build.sh`.
- `killline ui --announce-json --exit-with-stdin` for embedding.
- **`killline ui`**: a local, offline, dark dashboard served by the killline binary on 127.0.0.1, protected by a token and host checks, with a strict CSP. It has session list and status panels, live stats, a live timeline with read bursts collapsed, and an "every breach" list with crossed/held results. Incident drawers show the pre-breach timeline, process tree and checksum verification. There is a sensor-coverage view; you can start monitoring a container or process with a policy template (validated live) and freeze, resume, terminate or stop an agent.
- `killline inspect` collapses runs of similar file reads.
- Operator control channel (`control.json`) and `resume` response; sessions record whether the agent is frozen.
- Terminal demo recording (`docs/demo/killline-demo.cast`) and `test-lab/narrated-demo.sh`.

## 0.1.0: first vertical slice (2026-09-24)

Milestone: *independently detect a simple AI-agent containment boundary crossing in real time and reconstruct exactly what happened.*

### Added

- **eBPF sensor** (`bpf/killline.bpf.c`): observe-only. It covers syscall entry tracepoints for exec, open(at/at2)/creat, unlink/rmdir, rename, chmod, connect/bind/sendto/sendmsg/sendmmsg, socket, set*id, capset, unshare, setns, ptrace, kill/tgkill, bpf, init/finit_module, mount/umount, chroot and pivot_root, plus `sched_process_fork/exit` and optional `fentry/security_file_open`. Scoping is in-kernel, by PID tree or by the container's active PID namespace. Runtime-setup labelling (`docker exec`/`runc init`) cannot be forged by the agent. DNS question capture. Drop counter.
- **Syscall results** (`sys_exit_*`): each violation reports SUCCEEDED, refused by the OS, failed, in progress, or not observed.
- **Policy format v1** with strict validation, `validate-policy` diagnostics, and five templates.
- **Deterministic rule engine** with plain-English explanations, the expected-vs-actual boundary, the policy rule, and outcome sentences.
- **AMBER heuristics** (file enumeration, network scanning, exec bursts) and **"possible" correlations** (untrusted input, credential access before network activity, data collection before network activity, a preceding anomaly).
- **GREEN/AMBER/RED/GREY** session model with a heartbeat. GREY on dropped events, critical coverage gaps or monitor death.
- **Flight recorder**: hash-chained JSONL timeline per session; `killline verify`.
- **Incident bundles**: incident.json, timeline.jsonl, process_tree.json, network_events.json, filesystem_events.json, policy.yaml, system_metadata.json and checksums.txt. Local only, `0600`.
- **CLI**: `monitor`, `run` (race-free launch barrier, `--user`), `status [--watch]`, `sessions`, `incidents`, `inspect [--raw]`, `timeline [--all|--json]`, `verify`, `validate-policy`, `template`.
- **Optional responses**: `freeze` (docker pause / SIGSTOP) and `terminate`; `on_degraded` fail-closed option.
- **Redaction** of secrets in argv (flags, `KEY=value`, token shapes, URL credentials).
- **Harmless test agent** (9 modes), a **Docker Compose test lab**, and a demo script.
- **Benchmarks** (`bench/bench.sh`, `engine_bench`) and engine scenario tests covering the three demonstrations.
- Documentation: architecture, technical research, competitive landscape, threat model, policy format, security model, test lab, performance, limitations, roadmap.
