# Threat model

## What KillLine protects

**Assets:** the host and everything the agent was *not* granted, including host files, credentials, cloud identity, other containers and agents, internal services, the container runtime, and the network beyond the agent's allowance. KillLine does not protect these assets directly. Its job is to make it **known, immediately and with evidence**, when the declared boundary around them is crossed.

**Security goal:** for a monitored agent session, KillLine should either

1. report every attempt to cross a declared boundary, with what was attempted, by which process, what the OS did with it, and what happened just before; **or**
2. report that it **could not verify** containment (GREY), and say why.

It must never report "no violations" when it has in fact lost visibility.

## Trust boundaries

```
┌──────────────────────────── host (trusted computing base) ──────────────────────────┐
│  kernel (trusted)  ── eBPF sensor (trusted, loaded by KillLine)                      │
│  KillLine monitor (trusted, root / CAP_BPF+CAP_PERFMON)                              │
│  Docker daemon / runc (partially trusted: used for lookup + optional response only) │
│                                                                                     │
│   ┌──────────── sandbox (untrusted by KillLine) ───────────┐                        │
│   │  agent processes (untrusted)                            │                        │
│   │  model weights, tools, MCP servers, dependencies        │                        │
│   │  (all untrusted)                                        │                        │
│   └─────────────────────────────────────────────────────────┘                        │
└─────────────────────────────────────────────────────────────────────────────────────┘
```

KillLine trusts the **kernel** and **its own process**. It does not trust the agent, its logs, its tools or the sandbox's claims about itself. It uses the container runtime only to find the container's init PID and namespace (`docker inspect`), and optionally to `pause`/`kill`.

## Adversaries and scenarios

| # | Adversary | Example | What KillLine does | Residual risk |
|---|---|---|---|---|
| A1 | **Malicious agent** (deliberately hostile model/agent) | Reads `~/.aws/credentials`, connects to an exfil host, probes `docker.sock` | Deterministic rules fire on the syscall; RED + incident; optional freeze/terminate | Detection is **after** the syscall entry, so the first attempt is not prevented (monitor mode). A fast agent can finish a single `open`+`read`+`send` before a response lands |
| A2 | **Compromised legitimate agent** | A coding agent hijacked through a malicious dependency | Same as A1; the process tree shows the dependency's `postinstall` lineage | Attacks that stay inside allowed boundaries (e.g. malicious edits to `/workspace`) are **not** boundary violations |
| A3 | **Prompt-injected agent** | Reads `untrusted/README.md`, then enumerates files and reads `.env` | AMBER (enumeration), RED (credential), with a "possible correlation" to the untrusted read | Correlation is temporal, not causal, and is worded that way. Injection that only produces allowed actions is invisible |
| A4 | **Malicious downloaded model** (pickle/GGUF payload executes on load) | Model load spawns a shell | exec of an unlisted binary, network attempts | Payloads that run inside the allowed interpreter and use only allowed files/network are not visible |
| A5 | **Poisoned dependency** | `pip install` runs `setup.py` that reads SSH keys | Credential rule; process lineage in the incident | Same as A2 |
| A6 | **Malicious MCP server** | A local MCP server (child process) reads the host's `~/.config` or opens a socket | Visible as the agent's descendant: file/network/process rules apply | V1 has **no MCP-protocol visibility** (tool names, arguments). Remote MCP servers appear only as network connections |
| A7 | **Sandbox misconfiguration** | Secrets mounted into the container; network not actually isolated; `docker.sock` mounted | The attempt's **outcome** shows SUCCEEDED, which proves the sandbox did not hold. This is the core use case | KillLine verifies the boundary as declared in its policy. If the policy is wrong, it verifies the wrong thing |
| A8 | **Accidental agent error** | Agent "helpfully" edits `/etc/hosts` or `rm -rf` outside the workspace | Write/delete outside `allow_write` → RED | None beyond A1 |
| A9 | **Compromised credential** | The agent was given a token that is broader than intended | KillLine doesn't see token scopes. It sees the *network destinations* the token is used against | Misuse of an allowed destination is invisible |
| A10 | **Host compromise** | Attacker has host root | **Out of scope.** Host root can unload BPF, kill KillLine, and rewrite logs | Tamper evidence only (see below) |
| A11 | **Evasion attempts against KillLine** | See next table | | |

## Evasion analysis (A11)

| Technique | Status in V1 |
|---|---|
| Kill the monitor (`kill -9`) | The agent cannot see the host PID from inside a container. In `run` mode a `kill` aimed at the monitor PID is a **Tamper** violation. If the monitor dies for any reason, its heartbeat goes stale and `killline status` reports **GREY: "Monitoring process unexpectedly stopped. Containment status cannot be verified."** BPF programs detach when the monitor dies, so there is no silent half-monitoring |
| Unload/modify BPF programs | Requires `CAP_BPF`/`CAP_SYS_ADMIN` on the host. Any `bpf()` call from the agent is flagged (Tamper, High) |
| Flood events to cause drops | Kernel drops are counted in a BPF map. Any drop → **GREY** with the count. Optional fail-closed: `response.on_degraded: freeze\|terminate`. Measured capacity: ~120k events/s sustained |
| Symlink / `..` / relative-path tricks | Lexical normalisation, kernel-resolved paths (fentry) when available, otherwise a userspace resolver inside the agent's root. **Race window remains** with the userspace resolver |
| Fork/daemonise/double-fork to leave the tree | Inheritance happens in-kernel at `sched_process_fork`; there is no userspace race |
| Enter the container from outside to get the "runtime setup" label | The agent cannot do this: processes it forks inherit its state; only processes whose parent is *not* tracked are adopted as runtime setup, and only until their first exec |
| Rename process (`comm`) | Not used for identity or rules; exec path is used |
| Use syscalls KillLine doesn't hook (e.g. `io_uring` file ops, `open_by_handle_at`, `sendfile` on already-open fds, `clone3` namespace flags, new mount API) | **Blind spots.** See LIMITATIONS; these are on the roadmap |
| DNS over HTTPS / hard-coded IPs | Hard-coded IPs are caught in `deny` mode and without prior allowed DNS in allowlist mode. DoH looks like HTTPS to an allowed or disallowed IP |
| Exfiltrate over an allowed channel | Not a boundary violation. Transfer-volume signals are on the roadmap |
| Tamper with KillLine's logs | The data directory is `0700` root-owned, outside any container. The timeline is hash-chained (`killline verify`) and incidents carry SHA-256 checksums. This is tamper-*evident* against partial edits, **not** tamper-proof against host root |
| Agent runs as root inside a privileged container | Most escape indicators are still visible (mount, setns, core_pattern, release_agent, docker.sock). A kernel exploit that yields host root is out of scope |
| gVisor / Kata / Firecracker sandboxes | Syscalls happen in a guest kernel or the gVisor Sentry, **invisible to host eBPF**. KillLine would only see the VMM/Sentry process. Not supported in V1 |

## What KillLine CAN detect (V1)

- Outbound network attempts (TCP/UDP connect, sendto with address) to any destination, including when no route exists.
- DNS queries (name) sent to port 53 from the agent.
- Cloud metadata access: AWS/Azure/GCP/OCI/Alibaba IPs, IPv6 IMDS, ECS/EKS credential endpoints, Azure WireServer, metadata hostnames.
- File opens/creates/deletes/renames/chmods outside the declared allowlists, explicit denies, credential locations, and escape-indicator paths. Every such event is labelled with its outcome.
- Execution of unlisted, denied or privilege-changing programs; setuid-to-root attempts; setuid-bit chmod.
- Namespace manipulation (unshare/setns), mounts, chroot, pivot_root, bpf(), ptrace attach, module loading (where the kernel has modules).
- Container runtime socket access (Docker, containerd, CRI-O, podman, buildkit) by open or connect.
- Signals to the KillLine monitor; monitor death (via heartbeat); telemetry loss (drops); missing kernel features.
- Behavioural anomalies: rapid file enumeration, network scanning, exec bursts. Possible correlations to untrusted inputs, credential access and data collection.

## What KillLine CANNOT detect (V1)

- Anything that happens **within** the allowed boundary (malicious edits to allowed files, misuse of allowed APIs).
- The **content** of files or network traffic, by design.
- Agent **intent**, or the **cause** of behaviour; correlations are hints.
- MCP tool calls, prompts or model outputs (no telemetry source yet).
- Activity inside gVisor or microVM guests.
- Syscalls listed as blind spots in LIMITATIONS.md.
- A compromised host, or an attacker with host root.

KillLine never says "your agent is safe". It says what it monitored, what it saw, and what it could not see.
