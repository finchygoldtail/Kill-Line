# Architecture

KillLine V1 is one binary, `killline`, built from three crates. It needs no daemon, no network access and no account.

```
                      kernel                                   │                 userspace (killline, root)
                                                               │
  agent syscalls ──► tracepoints ──► killline.bpf.c            │
  (sys_enter_*,      sched_fork/exit  ├─ in-kernel scoping     │   killline-sensor
   sys_exit_*)       fentry(optional) │   (tracked TGIDs /     │   ├─ Aya loader, coverage report
                                      │    target PID ns)      │   ├─ ring-buffer drain (poll)
                                      ├─ ringbuf 16 MB ────────┼──►├─ decode: paths (cwd/fd/realpath-in-root),
                                      └─ stats (drops) ────────┼──►│   sockaddr, DNS question, argv redaction,
                                                               │   │   exe SHA-256, attempt+result pairing
                                                               │   ▼  Observation
                                                               │   killline-core
                                                               │   ├─ Engine: deterministic policy rules
                                                               │   │   → Event {verdict, severity, rule,
                                                               │   │      expected, explanation, outcome}
                                                               │   ├─ AnomalyDetector (AMBER heuristics)
                                                               │   ├─ correlations ("Possible …")
                                                               │   ├─ Session (GREEN/AMBER/RED/GREY)
                                                               │   ├─ SessionStore: hash-chained JSONL
                                                               │   └─ PendingIncident → incident bundle
                                                               │   killline-cli
                                                               │   ├─ monitor / run loop, heartbeat
                                                               │   ├─ optional response (pause/SIGSTOP/kill)
                                                               │   └─ status, sessions, incidents, inspect,
                                                               │      timeline, verify, validate-policy
```

## Crates

| Crate | Responsibility | Depends on the kernel? |
|---|---|---|
| `killline-core` | Policy format and validation, `Observation` → `Event` evaluation, anomaly heuristics, correlation, session state, hash-chained store, incident bundles, redaction | **No.** Pure Rust; unit and scenario tests run anywhere |
| `killline-sensor` | eBPF program (built by `build.rs` from `bpf/`), loading and attach, coverage reporting, decoding, target resolution (Docker/PID), response actions | Yes |
| `killline-cli` | The `killline` command: monitoring loop, terminal UI, read-only views | Via the sensor |

The split keeps the security-critical decision logic small, dependency-light and testable without root. It also lets a different sensor (Tetragon, Falco, fanotify, a future Kubernetes DaemonSet) feed the same engine.

## Data flow for one event

1. The agent calls `openat(AT_FDCWD, "../../fake-secrets/api-key.txt", O_RDONLY)`.
2. `sys_enter_openat` fires. `track_state()` checks the `tracked` map, and in container mode the task's active PID namespace. Untracked tasks return immediately.
3. The program reserves a 616-byte record in the ring buffer and fills in timestamp (boot clock), PIDs, uid/gid, comm, flags and the path string. File contents are never read.
4. `sys_exit_openat` emits a 32-byte result record carrying the return value.
5. Userspace drains the ring buffer. `Decoder::feed` holds the entry until its result arrives, resolves the relative path against `/proc/<pid>/cwd`, normalises `..`, and resolves symlinks inside `/proc/<pid>/root`. The result is an `Observation { Open { path: "/fake-secrets/api-key.txt", access: Read, resolution, via }, outcome: Succeeded }`.
6. `Engine::process` applies rules in a fixed order: escape indicators, then runtime sockets, credentials, explicit deny, write allowlist, read allowlist, and finally runtime baseline. It produces an `Event` with verdict `Violation`, category `Credential`, rule `credentials.access=deny [/fake-secrets]`, a plain-English explanation and the outcome sentence. It then adds correlations from the recent history.
7. The CLI appends the event to the hash-chained timeline and updates the `Session` (now RED). If this is the first occurrence of this breach, it writes an incident bundle immediately and again ~5 s later with post-trigger context. It prints the alert block and optionally freezes or terminates the agent.

## Session lifecycle

- `killline monitor --container X` resolves the container's init PID and PID namespace with `docker inspect`. It seeds `tracked` with every current process in that namespace, loads and attaches the BPF programs, and records coverage gaps (critical gaps make the session GREY from the start).
- `killline run --policy p.yaml -- cmd` spawns `killline __launch`. That helper blocks on a pipe until the monitor has added its PID to `tracked`. It then drops privileges if `--user` was given and execs `cmd`, so no syscall of the agent goes unobserved.
- The loop runs once per second: heartbeat written to `session.json`, drop counter checked (GREY and optional fail-closed), pending incidents finalised, timeline flushed, liveness of the target checked.
- On exit (agent exits, `--duration`, SIGINT/SIGTERM), KillLine drains remaining events, finalises incidents and marks the session ended. If KillLine is killed instead, the stale heartbeat makes `killline status` report GREY.

## Status model

| Status | Condition | Wording |
|---|---|---|
| GREEN — CONTAINED | no violations, no anomalies, full critical coverage | "No monitored boundary violations detected." |
| AMBER — ANOMALOUS | anomalies but no violations | "No boundary violations detected, but behaviour is unusual." |
| RED — BOUNDARY BREACH | ≥1 violation (sticky for the session) | "A declared containment boundary was crossed." Each violation also states whether it SUCCEEDED or was refused |
| GREY — MONITORING DEGRADED | a critical telemetry source is missing, events were dropped, or the monitor stopped heart-beating | "KillLine's visibility is incomplete. Containment cannot be verified." |

RED takes precedence in the headline; degradation reasons are always shown alongside it.

## On-disk layout

```
$KILLLINE_HOME (default /var/lib/killline as root; 0700)
├── sessions/<YYYYMMDD-HHMMSS-random>/
│   ├── session.json      snapshot + heartbeat (atomic replace)
│   ├── timeline.jsonl    {"seq","prev","hash","event"} per line
│   └── policy.yaml       the exact policy text in force
└── incidents/incident-YYYY-MM-DD-NNN/
    ├── incident.json         trigger, boundary, expected/actual, outcome, response, notes
    ├── timeline.jsonl        up to 2000 events before + events ~5 s after
    ├── process_tree.json     nested tree with exe, redacted argv, sha256
    ├── network_events.json
    ├── filesystem_events.json
    ├── policy.yaml
    ├── system_metadata.json  kernel, OS, coverage, drops, timeline head hash
    └── checksums.txt         sha256sum-compatible
```

Files are `0600`, directories `0700`. Nothing is uploaded anywhere.

## Performance

See [PERFORMANCE.md](PERFORMANCE.md). In short: no measurable overhead on processes that are not monitored; about +1.5 µs per monitored `open`+`read`+`close`; ~120k events/s sustained userspace throughput; ~15 MB anonymous RSS plus the 16 MB ring buffer.
