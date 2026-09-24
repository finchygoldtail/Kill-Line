# Technical research: how to watch an agent from outside

**Question.** What is the simplest reliable way for a separate, privileged process on a Linux host to see what an AI agent does? That means process creation, files, network, DNS, privilege changes, namespaces and container-escape signals. The agent must not be able to switch the monitoring off, and the monitor must not depend on the agent or its sandbox reporting honestly.

**Answer for V1.** Use one small eBPF program attached to **syscall tracepoints** and scheduler tracepoints. Scope it to the agent **inside the kernel**, by PID tree or container PID namespace. Pair each important syscall with its **return value**, so Kill Line can tell "the sandbox refused it" apart from "it succeeded". Add an optional LSM-adjacent hook (`fentry/security_file_open`) for paths the kernel has already resolved. Everything else in this document is a trade-off that was considered and either rejected or deferred.

This was validated on the development machine: a Linux 6.18 Firecracker VM with Docker 29.3, cgroup v1 (hybrid), and kernel BTF. See [Environment findings](#environment-findings) for what did and did not work there. That list is itself an argument for the design choices below.

---

## 1. Candidate telemetry sources

| Source | What it sees | Independent of the agent? | Overhead | Container scoping | Verdict for V1 |
|---|---|---|---|---|---|
| **eBPF on syscall tracepoints** (`syscalls/sys_enter_*`, `sys_exit_*`) | Every syscall's arguments and return value | Yes. The kernel runs it; the agent can't detach it without `CAP_BPF`/`CAP_SYS_ADMIN` | Low. In-kernel filtering; only the agent's events cross to userspace | In-kernel, by TGID map or PID namespace | **Chosen (primary)** |
| eBPF on `sched_process_fork/exit` | Process tree | Yes | Negligible | Same | **Chosen** (tracks descendants) |
| eBPF `fentry`/kprobe on LSM functions (`security_file_open`, …) | Kernel-resolved objects (post-symlink paths, `struct file`) | Yes | Low | Same | **Chosen, optional.** Not always permitted: it was refused on the dev VM (see below) |
| BPF-LSM (`lsm/…` programs) | Same as above, and can *deny* | Yes | Low | Same | **Deferred** to enforcement (Phase 3). Needs `CONFIG_BPF_LSM` and `lsm=…,bpf`, which the dev VM lacks |
| Linux audit (`auditd`, `AUDIT_*` rules) | Syscalls, file watches, execve | Yes | Medium to high: rule matching per syscall, backlog drops, one global daemon | Weak: no native container ID, the audit container-ID work never merged | **Rejected.** One global ruleset shared with the host's own audit policy, poor container scoping, and output that is hard to parse reliably |
| `ptrace` / seccomp-notify | Every syscall, and can block | Only if the tracer is not the agent | **High**: 2+ context switches per syscall. Breaks under `PR_SET_DUMPABLE=0`, debuggers, and nested sandboxes that already use seccomp | Per process | **Rejected for monitoring.** seccomp remains the right tool for the *sandbox* to enforce; it is not an observer |
| `fanotify` | File open/access/modify on mounts or filesystems | Yes | Medium; permission events add latency | By mount or filesystem, **not by process**. Every process on the mount generates events | **Rejected as primary.** Worth considering as a second, independent file source (see Roadmap) |
| `inotify` | Changes under watched directories | Yes | Low | By directory; no PID attribution | **Rejected.** No attribution to a process, so it can't answer "who" |
| procfs polling (`/proc/<pid>/fd`, `/proc/net/tcp`) | Snapshots | Yes | Cheap per poll, but misses anything short-lived | By PID | **Used only for enrichment** (cwd, fd paths, exe hashes, namespace seeding). Never used for detection |
| nftables/iptables `LOG`/`NFLOG` in the agent's netns | Packets that reach netfilter | Yes | Low | Per network namespace | **Rejected for detection.** With `--network none`, `connect()` fails with `ENETUNREACH` *before* netfilter, so the attempt is invisible. Good for enforcement later |
| Container runtime events (`docker events`, containerd) | Lifecycle only | Partly: the runtime is part of the thing being verified | None | Yes | **Used only for lifecycle** (`docker inspect` for PID and namespace). The runtime's own view is exactly the "sandbox says it is secure" signal Kill Line is meant not to trust |
| cgroups (`cgroup.procs`, `bpf_get_current_cgroup_id`) | Membership | Yes | None | By cgroup | **Deferred.** Excellent on cgroup v2 hosts. The dev VM is cgroup v1 hybrid, where the v2 cgroup ID of every process is the root, so it cannot scope. See §3 |

### Why not wrap Falco, Tetragon or Tracee?

These tools are mature and capable. The research in [COMPETITIVE_LANDSCAPE.md](COMPETITIVE_LANDSCAPE.md) notes that rebuilding their plumbing is not a moat. For the V1 proof, we chose a small purpose-built sensor (about 700 lines of C) because:

1. **One binary, no daemon, local-first.** `killline run -- agent` must work on a laptop or CI runner without deploying Falco, a gRPC output, rules files and plugins, or a Tetragon agent and CRDs.
2. **Semantics we needed and did not find off the shelf:**
   - pairing each attempt with its **return value**, to separate "the sandbox held" from "the boundary was crossed";
   - the **runtime-setup exemption** for processes entering the container from outside (`docker exec` → `runc init`), with the guarantee that the agent's own children can never obtain it (§3);
   - per-session, hash-chained **flight recording**.

   Each of these is expressible in Tetragon, but only with a policy per boundary and a custom collector.
3. **The sensor is an interface, not the product.** `killline-core` consumes `Observation`s and knows nothing about eBPF. A Tetragon- or Falco-backed sensor can be added behind the same interface. The roadmap lists this as the expected next step for Kubernetes.

We will revisit this decision if maintaining our own eBPF program across kernels becomes the bottleneck.

---

## 2. Coverage by requirement

| Requirement | How Kill Line V1 sees it | Notes / blind spots |
|---|---|---|
| Process creation, parent/child | `sys_enter_execve(at)` (path + first 6 argv, 42 bytes each), `sched_process_fork/exit`, `sys_exit_execve` for success | argv is truncated and redacted. Executable SHA-256 is computed from userspace via `/proc/<pid>/root`, so it is best effort for very short-lived processes |
| Filesystem access | `sys_enter_open/openat/openat2/creat` + result, `unlink(at)/rmdir`, `rename(at)(2)`, `chmod/fchmodat/fchmod` | `read()`/`write()` on already-open fds, `mmap`, `io_uring` opens, `name_to_handle_at`/`open_by_handle_at`, `link`/`symlink` creation, `truncate`: **not yet hooked** (see LIMITATIONS) |
| Symlink / `..` tricks | Lexical normalisation, plus the kernel-resolved path from `fentry/security_file_open` when permitted; otherwise a **userspace resolver** that walks the path inside `/proc/<pid>/root` without leaving the agent's root | The userspace resolver is racy: a link can be swapped between the open and the check (TOCTOU) |
| Network connections | `sys_enter_connect/bind/sendto/sendmsg/sendmmsg` + results for connect/bind | Sees *attempts* even when there is no route (`--network none`). Traffic on an already-connected socket is not decoded. Raw sockets are flagged at `socket()` |
| DNS | Payload of UDP/TCP messages to port 53 (first 128 bytes, question name only), from `sendto/sendmsg/sendmmsg`, including connected sockets (tracked by `(tgid, fd)`) | DoH/DoT and custom resolvers are invisible as DNS; they appear only as a TCP connection. DNS **answers** are not observed (see §4) |
| Socket creation | `sys_enter_socket` | Recorded; only `AF_PACKET` or raw INET sockets are flagged |
| Credential-sensitive files | Path rules over file events. **Contents are never read** | |
| Privilege escalation | `setuid/setreuid/setresuid/setgid/…`, `capset`, exec of `sudo/su/pkexec/…`, setuid-bit chmod | Kernel exploits that gain root without these syscalls are out of scope |
| Namespace changes | `unshare`, `setns` (+ results) | `clone(CLONE_NEW*)` flags are **not yet** inspected |
| Mounts | `mount`, `umount2`, `chroot`, `pivot_root` | `fsopen/fsmount/move_mount` (new mount API) are not yet hooked |
| Container escape signals | Docker/containerd/CRI-O/podman socket via `connect()` or `open()`, `/proc/*/root`, `core_pattern`, `release_agent`, `/dev/sd*`, `/proc/kcore`, `setns`, `mount`, `bpf()`, module loading | These are detection **indicators**, not proofs of escape |
| Linux capabilities | `capset` arguments (effective/permitted low 32 bits) | Capability *use* (`cap_capable`) is not traced |
| Tamper | `kill/tgkill` targeting the monitor PID, `bpf()`, `ptrace`; monitor heartbeat → GREY when stale | An agent with host root can unload BPF programs; see THREAT_MODEL |
| System calls generally | ~45 tracepoints | Not a full syscall audit, by design |

---

## 3. Agent identity: which process is "the agent"?

Candidates considered: PID tree, container ID, cgroup, PID namespace, runtime wrapper, environment token, session ID.

| Method | Robustness | Problem |
|---|---|---|
| **Environment token** (`KILLLINE_SESSION=…`) | Weak | The agent can unset or forge it. It relies on the agent's cooperation, which the design forbids |
| Process name / comm | Weak | `prctl(PR_SET_NAME)` changes it freely |
| **PID tree** (seed PIDs + in-kernel fork inheritance) | Strong for `run` mode | Needs the root PID before the agent's first syscall. Solved by the launch barrier: `killline run` starts a helper that waits on a pipe until the kernel map contains its PID, then execs the agent. Daemonising or double-forking does not escape, because inheritance happens in `sched_process_fork` |
| **cgroup v2 ID** (`bpf_get_current_cgroup_id`) | Strongest for containers on cgroup v2 hosts | Unusable on cgroup v1/hybrid hosts (the dev VM), where every process reports the v2 root. Planned as the preferred method when v2 is detected |
| **PID namespace** (active namespace: `task->thread_pid->numbers[level].ns`) | Strong for containers | Must use the *active* namespace, not `nsproxy->pid_ns_for_children`: the latter also matches runc's intermediate process after `setns()`, before it is actually in the container |

**V1 uses PID trees, and PID namespaces for containers.** A single BPF hash map, `tracked`, holds the TGIDs:

- **Seeded** from `/proc` at start: every process in the container's PID namespace, or the given PID and its descendants.
- **Inherited** in `sched_process_fork`: children take their parent's state.
- **Adopted** on first sight for processes that appear in the container's PID namespace from outside (`docker exec`). These are marked `TRACK_ADOPTED`, and their events carry `runtime_setup` **until their first `execve`**. Before that exec the process is `runc init` doing container setup (`capset`, `setgroups`, opening `/proc/self/...`). Those events are recorded but not evaluated against the agent's policy. At `execve` the label is dropped and the exec itself is evaluated.
- **Label cannot be forged by the agent:** an adopted process whose parent is already tracked is labelled `TRACK_FORKED`, not `TRACK_ADOPTED`. Anything the agent forks inherits the parent's state. The exemption therefore only applies to processes that genuinely entered from outside.
- The monitor's own TGID is excluded in-kernel.

Result: agent A and agent B in different containers or PID trees never share a `tracked` entry, and unrelated host activity is dropped in the kernel before it costs anything.

---

## 4. Attempt vs. outcome

A key design decision, and in our view the most valuable signal: every file, exec, connect, bind, unlink, rename, chmod, mount, unshare, setns, ptrace, chroot and pivot_root **entry** is held in userspace until its `sys_exit_*` **result** arrives (a 32-byte record; paired by thread ID, 250 ms timeout). Each violation then reads as one of:

- **SUCCEEDED**: the boundary was actually crossed. The sandbox did not stop it.
- **REFUSED by the OS** (`EACCES`, `EPERM`, `EROFS`): the sandbox held this time, but the agent *tried*.
- **failed** (e.g. `ENOENT`, `ENETUNREACH`): the attempt went nowhere.
- **in progress** (`EINPROGRESS`): non-blocking connect; completion is not observed in V1.
- **not observed**: no result hook for this call (DNS payloads, sends).

This is "trust the sandbox, verify the boundary" in concrete form. In the test lab, the fake-secret read shows as **SUCCEEDED**. That exposes a sandbox misconfiguration: the secret was mounted into the container. The outbound connection shows as **failed: ENETUNREACH**, because the internal Docker network held.

It also removes a class of false positives. Python tries to write `__pycache__/*.pyc` into read-only `/usr/local/lib`; those attempts fail with `EROFS`/`EACCES`. Failed bytecode-cache writes are recorded as benign; a *successful* one is still evaluated.

---

## 5. Domains, DNS rebinding and IP changes

Policies may list domains (`network.allow: [github.com]`). Connections, however, are to IPs. Options:

1. **Resolve allowed domains in the monitor.** Rejected: Kill Line would make its own network requests, violating "no unnecessary network access". It would also disagree with the agent's resolver (CDNs, split-horizon DNS, rebinding).
2. **Observe DNS answers** (hook `recvfrom/recvmsg` on port-53 sockets and parse A/AAAA records). This is correct, and planned. It is not in V1.
3. **V1: attribution window.** A DNS *query* for an allowed domain is allowed and remembered. A connection to an IP not in `allow_cidr` within 300 s of such a query is **allowed but labelled "destination not verified"**. A connection with no preceding allowed query is a violation.

Known consequences, also listed in LIMITATIONS:

- In allowlist mode, a query for `github.com` followed by a connection to an attacker IP (e.g. a hard-coded address) within the window is not flagged.
- DoH/DoT bypasses DNS observation entirely.
- DNS rebinding (an allowed name resolving to an internal IP) is not detected until answers are parsed.

For high assurance, use `mode: deny` or CIDR-only allowlists.

---

## 6. Language and stack

| Option | For | Against |
|---|---|---|
| **Rust** (userspace) + **C** (BPF) + **Aya** loader | Memory-safe userspace for a root daemon that parses hostile input (paths, DNS packets, argv). Single static-ish binary. Aya is pure Rust: no libbpf C dependency at runtime, and it performs CO-RE relocations itself | The Aya ecosystem is younger than libbpf |
| Rust + Aya with **BPF written in Rust** | One language | Needs nightly Rust and `bpf-linker`. More fragile toolchain for contributors and distros |
| Rust + libbpf-rs | The most battle-tested loader | Links C libbpf and libelf. Skeleton generation adds a build step |
| **Go** + cilium/ebpf | Excellent BPF library (used by Tetragon and Cilium). Fast to develop | GC pauses in a hot event loop, and a larger binary. Nothing Go offers is decisive here |
| Python (bcc) | Fastest to prototype | Rejected per requirements: bcc needs kernel headers and LLVM at runtime, and Python is a poor fit for a privileged, low-level core |

**Chosen:** Rust userspace, BPF in C compiled by clang (`-target bpf`, CO-RE via `preserve_access_index` against a minimal hand-written header, not a 3 MB `vmlinux.h`), loaded by **Aya 0.13** on **stable Rust**. We challenged the initial Rust+Aya plan: Go with cilium/ebpf would have been equally viable. Rust won on memory safety for hostile-input parsing and on having no GC in the hot path. Writing the BPF in C rather than Rust avoids nightly and `bpf-linker`.

**Storage:** an append-only, **hash-chained JSONL** timeline per session, not SQLite. Reasons: integrity checking is trivial (`killline verify`); there is no C dependency; it is greppable, `jq`-able and easy to hand to an incident reviewer. SQLite remains a good option later for cross-session *indexing*, built from the JSONL, which stays the source of truth.

**GUI:** `killline status --watch` renders the requested dashboard panel in a terminal. A Tauri or web dashboard is deferred until the CLI and data model settle.

---

## Environment findings

Observed on the development VM (Linux 6.18.44, Firecracker, Docker 29.3.1, cgroup v1 hybrid, running as root):

| Finding | Consequence |
|---|---|
| Syscall and sched tracepoints attach fine; kernel BTF present | Primary design works |
| `fentry/security_file_open` load → **EPERM** (even an empty fentry program) | Kill Line reports the coverage gap at startup and falls back to the userspace symlink resolver. This is the "tell the user when a kernel feature is unavailable" requirement working as intended |
| `sys_enter_init_module` / `finit_module` **do not exist** (`CONFIG_MODULES` off) | Reported as a coverage gap (non-critical, since modules cannot be loaded anyway) |
| Tracepoint context size is per-syscall: reading `args[1]` in `sys_enter_setuid` is rejected by the verifier (`EACCES`) | Handlers are arity-specific |
| cgroup v1 hybrid: every process's v2 cgroup ID is the root | cgroup-based scoping unusable here → PID namespace scoping |
| `CONFIG_BPF_LSM` off | No in-kernel blocking on this host; enforcement uses the cgroup freezer (`docker pause`) or signals |
| Outbound TCP from the host is intercepted by a transparent proxy | "Connect succeeded" on the host does not prove internet reachability. The test agent uses TEST-NET-3 and `.invalid` names so no real system is contacted |
