//! Deterministic policy evaluation.
//!
//! Every observation becomes exactly one timeline [`Event`] with a verdict and
//! a plain-English explanation. The behavioural layer ([`crate::anomaly`])
//! and the correlation layer run afterwards and never downgrade a verdict.

use crate::anomaly::AnomalyDetector;
use crate::event::*;
use crate::pathmatch;
use crate::policy::*;
use chrono::{DateTime, Duration, Utc};
use std::collections::{HashMap, VecDeque};
use std::net::IpAddr;

/// Executables that exist to change privilege or escape confinement.
const PRIVILEGE_TOOLS: &[&str] = &[
    "sudo", "su", "doas", "pkexec", "runuser", "setpriv", "nsenter", "unshare", "capsh", "chroot",
    "mount", "umount", "insmod", "modprobe", "newgrp", "sg", "docker", "podman", "nerdctl", "ctr",
    "crictl", "kubectl",
];

const CLONE_NEWNS: u64 = 0x0002_0000;
const CLONE_NEWCGROUP: u64 = 0x0200_0000;
const CLONE_NEWUTS: u64 = 0x0400_0000;
const CLONE_NEWIPC: u64 = 0x0800_0000;
const CLONE_NEWUSER: u64 = 0x1000_0000;
const CLONE_NEWPID: u64 = 0x2000_0000;
const CLONE_NEWNET: u64 = 0x4000_0000;
const NS_FLAGS: u64 = CLONE_NEWNS
    | CLONE_NEWCGROUP
    | CLONE_NEWUTS
    | CLONE_NEWIPC
    | CLONE_NEWUSER
    | CLONE_NEWPID
    | CLONE_NEWNET;

/// How long after an allowed-domain DNS query a connection to an unlisted IP
/// is attributed to that domain (V1 does not observe DNS answers).
const DNS_ATTRIBUTION_SECS: i64 = 300;
const HISTORY: usize = 4096;
const CORRELATION_SECS: i64 = 120;

/// A compact record of recent events kept for correlation.
#[derive(Debug, Clone)]
struct Recent {
    seq: u64,
    ts: DateTime<Utc>,
    verdict: Verdict,
    summary: String,
    untrusted_read: Option<String>,
    credential: bool,
    file_read: bool,
}

pub struct Engine {
    policy: CompiledPolicy,
    session_id: String,
    agent_id: String,
    monitor_pid: Option<u32>,
    seq: u64,
    allowed_dns: VecDeque<(DateTime<Utc>, String)>,
    /// Last lexical open per thread, used to de-duplicate the kernel's
    /// confirmation of the same open.
    last_open: HashMap<u32, (String, u64, Verdict)>,
    history: VecDeque<Recent>,
    anomaly: AnomalyDetector,
}

struct Decision {
    category: Category,
    action: &'static str,
    severity: Severity,
    verdict: Verdict,
    rule: Option<String>,
    expected: Option<String>,
    explanation: String,
}

impl Decision {
    fn allowed(category: Category, action: &'static str, explanation: impl Into<String>) -> Self {
        Decision {
            category,
            action,
            severity: Severity::Info,
            verdict: Verdict::Allowed,
            rule: None,
            expected: None,
            explanation: explanation.into(),
        }
    }
    fn violation(
        category: Category,
        action: &'static str,
        severity: Severity,
        rule: impl Into<String>,
        expected: impl Into<String>,
        explanation: impl Into<String>,
    ) -> Self {
        Decision {
            category,
            action,
            severity,
            verdict: Verdict::Violation,
            rule: Some(rule.into()),
            expected: Some(expected.into()),
            explanation: explanation.into(),
        }
    }
    fn anomaly(
        category: Category,
        action: &'static str,
        severity: Severity,
        explanation: impl Into<String>,
    ) -> Self {
        Decision {
            category,
            action,
            severity,
            verdict: Verdict::Anomaly,
            rule: None,
            expected: None,
            explanation: explanation.into(),
        }
    }
}

impl Engine {
    pub fn new(policy: CompiledPolicy, session_id: &str, monitor_pid: Option<u32>) -> Engine {
        let anomaly = AnomalyDetector::new(policy.source.anomaly.clone());
        Engine {
            agent_id: policy.source.agent.clone(),
            policy,
            session_id: session_id.to_string(),
            monitor_pid,
            seq: 0,
            allowed_dns: VecDeque::new(),
            last_open: HashMap::new(),
            history: VecDeque::new(),
            anomaly,
        }
    }

    pub fn policy(&self) -> &CompiledPolicy {
        &self.policy
    }

    fn next_seq(&mut self) -> u64 {
        self.seq += 1;
        self.seq
    }

    /// Create a KillLine-originated event (coverage, drops, responses).
    pub fn notice(
        &mut self,
        category: Category,
        action: &str,
        severity: Severity,
        explanation: String,
    ) -> Event {
        let verdict = if category == Category::Tamper {
            Verdict::Violation
        } else {
            Verdict::Notice
        };
        Event {
            seq: self.next_seq(),
            timestamp: Utc::now(),
            session_id: self.session_id.clone(),
            agent_id: self.agent_id.clone(),
            category,
            action: action.to_string(),
            severity,
            verdict,
            allowed: verdict != Verdict::Violation,
            process: None,
            observation: None,
            outcome: None,
            policy_rule: None,
            expected: None,
            explanation,
            correlations: vec![],
            confirms_seq: None,
        }
    }

    /// Evaluate one observation. Returns the event for it, followed by any
    /// behavioural-anomaly events it triggered.
    pub fn process(&mut self, obs: Observation) -> Vec<Event> {
        let mut confirms = None;
        if let ObsKind::Open {
            path, resolution, ..
        } = &obs.kind
        {
            if resolution == "kernel" {
                if let Some((p, seq, verdict)) = self.last_open.get(&obs.process.tid) {
                    if p == path {
                        if *verdict == Verdict::Allowed {
                            // The kernel confirms an allowed open: nothing new.
                            return vec![];
                        }
                        confirms = Some(*seq);
                    }
                }
            }
        }

        let mut d = self.decide(&obs);
        if d.verdict == Verdict::Violation {
            if let Some(o) = &obs.outcome {
                if let (
                    ObsKind::Open {
                        path,
                        access: FileAccess::Write,
                        ..
                    },
                    true,
                ) = (&obs.kind, matches!(o, Outcome::Failed { .. }))
                {
                    if BENIGN_FAILED_WRITES
                        .iter()
                        .any(|p| pathmatch::matches(p, path))
                    {
                        d = Decision::allowed(
                            Category::Filesystem,
                            "file.write_blocked_benign",
                            format!(
                                "Interpreter cache write to {} was refused ({}). Recorded as benign: bytecode caches are \
                                 not agent output. The boundary held.",
                                path,
                                o.short()
                            ),
                        );
                    }
                }
            }
        }
        if d.verdict == Verdict::Violation {
            let sentence = match (&obs.kind, &obs.outcome) {
                (ObsKind::Net { op: NetOp::Connect, .. } | ObsKind::UnixConnect { .. }, Some(Outcome::Succeeded)) => {
                    "Result: connect() SUCCEEDED — a connection was established (for UDP, connect() only sets the \
                     destination; no data is sent by it)."
                        .to_string()
                }
                _ => outcome_sentence(obs.outcome.as_ref()),
            };
            d.explanation = format!("{} {}", d.explanation, sentence);
        }
        if let Some(prev) = confirms {
            d.explanation = format!(
                "The kernel confirms the file was actually opened (see event #{}). {}",
                prev, d.explanation
            );
        }
        let seq = self.next_seq();
        let mut ev = Event {
            seq,
            timestamp: obs.timestamp,
            session_id: self.session_id.clone(),
            agent_id: self.agent_id.clone(),
            category: d.category,
            action: if confirms.is_some() {
                "file.opened"
            } else {
                d.action
            }
            .to_string(),
            severity: d.severity,
            verdict: d.verdict,
            allowed: d.verdict != Verdict::Violation,
            process: Some(obs.process.clone()),
            observation: Some(obs.kind.clone()),
            outcome: obs.outcome.clone(),
            policy_rule: d.rule,
            expected: d.expected,
            explanation: d.explanation,
            correlations: vec![],
            confirms_seq: confirms,
        };

        if let ObsKind::Open {
            path, resolution, ..
        } = &obs.kind
        {
            if resolution != "kernel" {
                self.last_open
                    .insert(obs.process.tid, (path.clone(), seq, ev.verdict));
            }
        }
        if let ObsKind::Exit = obs.kind {
            self.last_open.remove(&obs.process.tid);
        }

        if ev.verdict == Verdict::Violation && confirms.is_none() {
            ev.correlations = self.correlate(&ev);
        }
        self.remember(&ev);

        let mut out = vec![ev];
        if self.policy.source.anomaly.enabled && !obs.runtime_setup {
            let runtime = match &obs.kind {
                ObsKind::Open { path, .. } => self.policy.runtime_read.matches(path),
                _ => false,
            };
            for a in self.anomaly.observe(&obs, runtime) {
                let seq = self.next_seq();
                let mut e = Event {
                    seq,
                    timestamp: obs.timestamp,
                    session_id: self.session_id.clone(),
                    agent_id: self.agent_id.clone(),
                    category: Category::Anomaly,
                    action: a.action.to_string(),
                    severity: Severity::Medium,
                    verdict: Verdict::Anomaly,
                    allowed: true,
                    process: Some(obs.process.clone()),
                    observation: None,
                    outcome: None,
                    policy_rule: None,
                    expected: None,
                    explanation: a.explanation,
                    correlations: vec![],
                    confirms_seq: None,
                };
                e.correlations = self.correlate(&e);
                self.remember(&e);
                out.push(e);
            }
        }
        out
    }

    fn remember(&mut self, ev: &Event) {
        let (untrusted_read, credential, file_read) = match &ev.observation {
            Some(ObsKind::Open { path, access, .. }) => (
                self.policy
                    .untrusted
                    .first_match(path)
                    .map(|_| path.clone()),
                ev.category == Category::Credential,
                *access != FileAccess::Write && ev.action != "file.runtime_read",
            ),
            _ => (None, ev.category == Category::Credential, false),
        };
        self.history.push_back(Recent {
            seq: ev.seq,
            ts: ev.timestamp,
            verdict: ev.verdict,
            summary: if credential {
                ev.resource_summary()
            } else {
                String::new()
            },
            untrusted_read,
            credential,
            file_read,
        });
        while self.history.len() > HISTORY {
            self.history.pop_front();
        }
    }

    /// Link a violation or anomaly to what happened shortly before it.
    /// Always phrased as a possibility: correlation is not causation.
    fn correlate(&self, ev: &Event) -> Vec<Correlation> {
        let mut out = Vec::new();
        let since = ev.timestamp - Duration::seconds(CORRELATION_SECS);
        let recent: Vec<&Recent> = self.history.iter().filter(|r| r.ts >= since).collect();

        if let Some(r) = recent.iter().rev().find(|r| r.untrusted_read.is_some()) {
            let secs = (ev.timestamp - r.ts).num_milliseconds() as f64 / 1000.0;
            out.push(Correlation {
                summary: format!(
                    "Possible correlation: this happened {:.1}s after the agent read untrusted input {}. \
                     This may indicate indirect prompt injection; KillLine cannot prove causation.",
                    secs,
                    r.untrusted_read.as_deref().unwrap_or("")
                ),
                related_seq: vec![r.seq],
            });
        }

        let is_network = matches!(
            ev.category,
            Category::Network | Category::Dns | Category::CloudMetadata
        );
        if is_network {
            let creds: Vec<&&Recent> = recent.iter().filter(|r| r.credential).collect();
            if let Some(last) = creds.last() {
                let secs = (ev.timestamp - last.ts).num_milliseconds() as f64 / 1000.0;
                out.push(Correlation {
                    summary: format!(
                        "Possible exfiltration pattern: {} credential-sensitive access(es) preceded this network \
                         attempt (most recent {:.1}s earlier: {}).",
                        creds.len(),
                        secs,
                        last.summary
                    ),
                    related_seq: creds.iter().map(|r| r.seq).collect(),
                });
            }
            let reads: Vec<&&Recent> = recent
                .iter()
                .filter(|r| r.file_read && !r.credential)
                .collect();
            if reads.len() >= 100 {
                out.push(Correlation {
                    summary: format!(
                        "Possible data-collection pattern: {} file reads in the {}s before this network attempt.",
                        reads.len(),
                        CORRELATION_SECS
                    ),
                    related_seq: vec![reads[0].seq, reads[reads.len() - 1].seq],
                });
            }
        }

        if ev.verdict == Verdict::Violation {
            if let Some(a) = recent.iter().rev().find(|r| r.verdict == Verdict::Anomaly) {
                out.push(Correlation {
                    summary: format!("Follows a behavioural anomaly (event #{}).", a.seq),
                    related_seq: vec![a.seq],
                });
            }
        }
        out
    }

    fn decide(&mut self, obs: &Observation) -> Decision {
        let p = &obs.process;
        if obs.runtime_setup {
            return Decision::allowed(
                Category::Process,
                "runtime.setup",
                format!(
                    "Container runtime setup by {} (pid {}) before its first exec, e.g. `docker exec` entering the \
                     container: {}. Recorded, not evaluated against the agent's policy.",
                    p.comm,
                    p.pid,
                    obs.kind.summary()
                ),
            );
        }
        match &obs.kind {
            ObsKind::Exec { path, exists, .. } => {
                let missing = matches!(obs.outcome, Some(Outcome::Failed { errno: 2, .. }));
                self.decide_exec(path, *exists && !missing)
            }
            ObsKind::Fork { child_pid } => Decision::allowed(
                Category::Process,
                "process.fork",
                format!("{} (pid {}) created child process {}.", p.comm, p.pid, child_pid),
            ),
            ObsKind::Exit => Decision::allowed(Category::Process, "process.exit", format!("{} (pid {}) exited.", p.comm, p.pid)),
            ObsKind::Open { path, access, resolution, via, .. } => {
                let mut d = self.decide_file(p, path, *access, resolution);
                if let Some(v) = via {
                    d.explanation = format!("{} (Requested as {}, a symlink that resolves to {}.)", d.explanation, v, path);
                }
                d
            }
            ObsKind::Unlink { path } => self.decide_mutation(p, path, "file.delete", "delete"),
            ObsKind::Rename { from, to } => {
                let a = self.decide_mutation(p, from, "file.rename", "rename");
                if a.verdict == Verdict::Violation {
                    a
                } else {
                    self.decide_mutation(p, to, "file.rename", "rename a file to")
                }
            }
            ObsKind::Chmod { path, mode } => {
                if mode & 0o6000 != 0 && self.policy.source.processes.deny_privileged {
                    return Decision::violation(
                        Category::Privilege,
                        "file.chmod_setuid",
                        Severity::High,
                        "processes.deny_privileged",
                        "No privilege changes",
                        format!(
                            "The agent tried to set the setuid/setgid bit on {} (mode {:o}). \
                             This is a common way to create a path to root.",
                            path, mode
                        ),
                    );
                }
                self.decide_mutation(p, path, "file.chmod", "change permissions of")
            }
            ObsKind::Net { op, addr, port } => self.decide_net(*op, addr, *port, obs.timestamp),
            ObsKind::UnixConnect { path, abstract_ns } => {
                if !abstract_ns && RUNTIME_SOCKETS.iter().any(|s| pathmatch::normalize(path) == *s) {
                    if self.policy.source.container_runtime.access == Access::Allow {
                        return Decision::allowed(Category::ContainerRuntime, "runtime.socket", format!("Connected to container runtime socket {} (allowed by policy).", path));
                    }
                    return Decision::violation(
                        Category::ContainerRuntime,
                        "runtime.socket_connect",
                        Severity::Critical,
                        "container_runtime.access=deny",
                        "No access to container runtime sockets",
                        format!(
                            "The agent tried to talk to the container runtime through {}. Access to this socket \
                             is equivalent to root on the host and is a well-known container escape route.",
                            path
                        ),
                    );
                }
                Decision::allowed(Category::Network, "unix.connect", format!("Connected to local Unix socket {}.", path))
            }
            ObsKind::Dns { query, server } => self.decide_dns(query.as_deref(), *server, obs.timestamp),
            ObsKind::Socket { family, sock_type, .. } => {
                let t = sock_type & 0xf;
                if *family == 17 || ((*family == 2 || *family == 10) && t == 3) {
                    let d = "The agent created a raw/packet socket, which can sniff or forge network traffic.";
                    if self.policy.source.processes.deny_privileged {
                        return Decision::violation(Category::Privilege, "socket.raw", Severity::High, "processes.deny_privileged", "No raw network access", d);
                    }
                    return Decision::anomaly(Category::Network, "socket.raw", Severity::Medium, d);
                }
                Decision::allowed(Category::Network, "socket.create", format!("Created a socket (family {}, type {}).", family, t))
            }
            ObsKind::Mount { source, target, .. } => self.privileged(
                Category::ContainerEscape,
                "fs.mount",
                Severity::Critical,
                format!("The agent attempted to mount {} on {}. Mounting from inside a sandbox is a container-escape indicator.", source, target),
            ),
            ObsKind::Umount { target } => self.privileged(
                Category::ContainerEscape,
                "fs.umount",
                Severity::High,
                format!("The agent attempted to unmount {}.", target),
            ),
            ObsKind::Chroot { path } => self.privileged(
                Category::ContainerEscape,
                "fs.chroot",
                Severity::High,
                format!("The agent called chroot({}).", path),
            ),
            ObsKind::PivotRoot { new_root, .. } => self.privileged(
                Category::ContainerEscape,
                "fs.pivot_root",
                Severity::Critical,
                format!("The agent called pivot_root({}).", new_root),
            ),
            ObsKind::SetId { call, args } => {
                let to_root = args.contains(&0);
                if to_root && p.uid != 0 {
                    return self.privileged(
                        Category::Privilege,
                        "privilege.become_root",
                        Severity::Critical,
                        format!("A non-root process (uid {}) called {}({:?}) in an attempt to become root.", p.uid, call, args),
                    );
                }
                Decision::allowed(Category::Privilege, "privilege.setid", format!("{} called {}({:?}).", p.comm, call, args))
            }
            ObsKind::Capset { effective, .. } => {
                let d = format!("The agent changed its Linux capabilities (effective set {:#x}).", effective);
                if self.policy.source.processes.deny_privileged {
                    Decision::anomaly(Category::Privilege, "privilege.capset", Severity::Medium, d)
                } else {
                    Decision::allowed(Category::Privilege, "privilege.capset", d)
                }
            }
            ObsKind::Unshare { flags } => {
                if flags & NS_FLAGS != 0 {
                    return self.privileged(
                        Category::Namespace,
                        "namespace.unshare",
                        Severity::High,
                        format!("The agent tried to create new namespaces (unshare flags {:#x}). Namespace manipulation can be used to gain capabilities or escape confinement.", flags),
                    );
                }
                Decision::allowed(Category::Namespace, "namespace.unshare", format!("unshare(flags={:#x}) without namespace flags.", flags))
            }
            ObsKind::Setns { nstype } => self.privileged(
                Category::Namespace,
                "namespace.setns",
                Severity::Critical,
                format!("The agent tried to join another namespace (setns type {:#x}). Entering another namespace is a container-escape indicator.", nstype),
            ),
            ObsKind::Ptrace { request, target_pid } => {
                if *request == 0 {
                    return Decision::allowed(Category::Privilege, "ptrace.traceme", "The process asked to be traced by its parent (PTRACE_TRACEME).");
                }
                self.privileged(
                    Category::Privilege,
                    "ptrace.attach",
                    Severity::High,
                    format!("The agent used ptrace (request {}) on pid {}. Tracing other processes allows reading their memory and hijacking them.", request, target_pid),
                )
            }
            ObsKind::Kill { target_pid, signal } => {
                if let Some(m) = self.monitor_pid {
                    if *target_pid == m as i64 {
                        return Decision::violation(
                            Category::Tamper,
                            "tamper.signal_monitor",
                            Severity::Critical,
                            "monitor.integrity",
                            "The agent must not interfere with KillLine",
                            format!("The agent sent signal {} to the KillLine monitor process.", signal),
                        );
                    }
                }
                if *target_pid == -1 {
                    return Decision::anomaly(Category::Process, "process.kill_all", Severity::Medium, format!("The agent sent signal {} to every process it is allowed to signal (kill -1).", signal));
                }
                Decision::allowed(Category::Process, "process.signal", format!("Sent signal {} to pid {}.", signal, target_pid))
            }
            ObsKind::Bpf { cmd } => self.privileged(
                Category::Tamper,
                "tamper.bpf",
                Severity::High,
                format!("The agent invoked the bpf() system call (command {}). eBPF can be used to observe or interfere with the kernel, including monitoring tools.", cmd),
            ),
            ObsKind::ModuleLoad => self.privileged(
                Category::Privilege,
                "privilege.module_load",
                Severity::Critical,
                "The agent tried to load a kernel module.".to_string(),
            ),
        }
    }

    fn privileged(
        &self,
        category: Category,
        action: &'static str,
        severity: Severity,
        explanation: String,
    ) -> Decision {
        if self.policy.source.processes.deny_privileged {
            Decision::violation(
                category,
                action,
                severity,
                "processes.deny_privileged",
                "No privileged or namespace operations",
                explanation,
            )
        } else {
            Decision::anomaly(category, action, severity, explanation)
        }
    }

    fn decide_exec(&self, path: &str, exists: bool) -> Decision {
        let proc = &self.policy.source.processes;
        let base = path.rsplit('/').next().unwrap_or(path);
        let name_match = |e: &String| {
            if e.contains('/') {
                pathmatch::normalize(e) == pathmatch::normalize(path)
            } else {
                pathmatch::matches(&format!("/{}", e), &format!("/{}", base))
            }
        };
        if let Some(rule) = proc.deny.iter().find(|e| name_match(e)) {
            return Decision::violation(
                Category::Process,
                "process.exec_denied",
                Severity::High,
                format!("processes.deny[{}]", rule),
                format!("{} must never run", rule),
                format!(
                    "The agent started {}, which this policy explicitly forbids.",
                    path
                ),
            );
        }
        if proc.deny_privileged && PRIVILEGE_TOOLS.contains(&base) {
            return Decision::violation(
                Category::Privilege,
                "process.exec_privileged",
                Severity::High,
                "processes.deny_privileged",
                "No privilege-changing tools",
                format!(
                    "The agent started {}, a tool used to change privileges or escape confinement.",
                    path
                ),
            );
        }
        if !exists {
            return Decision::allowed(
                Category::Process,
                "process.exec_not_found",
                format!(
                    "Tried to execute {}, which does not exist (typically a PATH search).",
                    path
                ),
            );
        }
        if !proc.allow.is_empty() && !proc.allow.iter().any(name_match) {
            return Decision::violation(
                Category::Process,
                "process.exec_unexpected",
                Severity::Medium,
                "processes.allow",
                format!("Only these programs: {}", proc.allow.join(", ")),
                format!(
                    "The agent started {}, which is not in the list of allowed programs.",
                    path
                ),
            );
        }
        Decision::allowed(
            Category::Process,
            "process.exec",
            format!("Started {}.", path),
        )
    }

    fn is_other_proc(path: &str, pid: u32) -> bool {
        let mut it = path.split('/').skip(1);
        if it.next() != Some("proc") {
            return false;
        }
        match it.next() {
            Some(n) => n
                .parse::<u32>()
                .map(|n| n != pid && n != 0)
                .unwrap_or(false),
            None => false,
        }
    }

    fn decide_file(
        &self,
        p: &ProcessInfo,
        path: &str,
        access: FileAccess,
        resolution: &str,
    ) -> Decision {
        let pol = &self.policy;
        let how = match resolution {
            "kernel" => " (kernel-resolved path)",
            "userspace-realpath" => " (symlink resolved)",
            _ => "",
        };
        let verb = match access {
            FileAccess::Read | FileAccess::Path => "read",
            FileAccess::Write => "write",
            FileAccess::List => "list",
        };
        if path.is_empty() || !path.starts_with('/') {
            return Decision::allowed(
                Category::Filesystem,
                "file.open_unresolved",
                format!(
                    "Opened relative path '{}' that KillLine could not resolve from outside the process. \
                     If the open succeeded, the kernel-resolved path is recorded separately.",
                    path
                ),
            );
        }

        // /proc/<pid>/... rules are only meaningful for lexical paths: the
        // kernel renders /proc/self as the namespace-local pid.
        let proc_ok = resolution != "kernel" && path.starts_with("/proc/");
        if let Some(pat) = pol.escape_indicators.first_match(path) {
            let skip =
                pat.starts_with("/proc/*/") && !(proc_ok && Self::is_other_proc(path, p.pid));
            if !skip {
                let what = ESCAPE_INDICATORS
                    .iter()
                    .find(|(p, _)| *p == pat)
                    .map(|(_, w)| *w)
                    .unwrap_or("");
                return Decision::violation(
                    Category::ContainerEscape,
                    "escape.sensitive_path",
                    Severity::Critical,
                    format!("escape_indicator[{}]", pat),
                    "No access to kernel or host control interfaces",
                    format!(
                        "The agent tried to {} {}{} — {}. Access to this from inside a sandbox is a recognised container-escape indicator.",
                        verb, path, how, what
                    ),
                );
            }
        }

        if pol.runtime_sockets.matches(path) && pol.source.container_runtime.access == Access::Deny
        {
            return Decision::violation(
                Category::ContainerRuntime,
                "runtime.socket_open",
                Severity::Critical,
                "container_runtime.access=deny",
                "No access to container runtime sockets",
                format!("The agent tried to open the container runtime socket {}{}. This is equivalent to root on the host.", path, how),
            );
        }

        if pol.source.credentials.access == Access::Deny && !pol.credential_allow.matches(path) {
            if let Some(rule) = pol.credential_paths.first_match(path) {
                let skip =
                    rule.starts_with("/proc/*/") && !(proc_ok && Self::is_other_proc(path, p.pid));
                if !skip {
                    return Decision::violation(
                        Category::Credential,
                        "credential.access",
                        Severity::Critical,
                        format!("credentials.access=deny [{}]", rule),
                        "No access to credentials",
                        format!(
                            "The agent tried to {} {}{}, a credential-sensitive location. This policy does not allow \
                             credential access. (KillLine records only that access was attempted; it never reads the contents.)",
                            verb, path, how
                        ),
                    );
                }
            }
        }

        if let Some(rule) = pol.deny.first_match(path) {
            return Decision::violation(
                Category::Filesystem,
                "file.denied_path",
                Severity::High,
                format!("filesystem.deny[{}]", rule),
                format!("No access to {}", rule),
                format!(
                    "The agent tried to {} {}{}. This location is explicitly denied by policy.",
                    verb, path, how
                ),
            );
        }

        if access == FileAccess::Write {
            if pol.write_allow.matches(path) || pol.runtime_write.matches(path) {
                return Decision::allowed(
                    Category::Filesystem,
                    "file.write",
                    format!("Opened {} for writing.", path),
                );
            }
            return Decision::violation(
                Category::Filesystem,
                "file.write_outside_boundary",
                Severity::High,
                "filesystem.allow_write",
                format!("Writes only under: {}", list_or_none(&pol.source.filesystem.allow_write, &pol.source.filesystem.allow)),
                format!("The agent tried to write to {}{}, which is outside the paths this policy allows it to modify.", path, how),
            );
        }

        if pol.read_allow.matches(path) {
            return Decision::allowed(
                Category::Filesystem,
                if access == FileAccess::List {
                    "file.list"
                } else {
                    "file.read"
                },
                format!("Opened {} for reading.", path),
            );
        }
        if pol.runtime_read.matches(path) {
            return Decision::allowed(
                Category::Filesystem,
                "file.runtime_read",
                format!("Read runtime file {}.", path),
            );
        }
        Decision::violation(
            Category::Filesystem,
            "file.read_outside_boundary",
            Severity::Medium,
            "filesystem.allow_read",
            format!("Reads only under: {}", list_or_none(&pol.source.filesystem.allow_read, &pol.source.filesystem.allow)),
            format!("The agent tried to {} {}{}, which is outside the paths this policy allows it to read.", verb, path, how),
        )
    }

    fn decide_mutation(
        &self,
        p: &ProcessInfo,
        path: &str,
        action: &'static str,
        verb: &str,
    ) -> Decision {
        let d = self.decide_file(p, path, FileAccess::Write, "lexical");
        if d.verdict == Verdict::Violation {
            let mut d = d;
            d.action = action;
            d.explanation = format!("The agent tried to {} {}. {}", verb, path, d.explanation);
            return d;
        }
        Decision::allowed(Category::Filesystem, action, format!("{} {}", verb, path))
    }

    fn decide_net(&mut self, op: NetOp, addr: &IpAddr, port: u16, now: DateTime<Utc>) -> Decision {
        let addr = addr.to_canonical();
        let pol = &self.policy;
        let dest = match addr {
            IpAddr::V6(v6) => format!("[{}]:{}", v6, port),
            IpAddr::V4(v4) => format!("{}:{}", v4, port),
        };

        if op == NetOp::Bind {
            if addr.is_loopback() || port == 0 {
                return Decision::allowed(
                    Category::Network,
                    "net.bind",
                    format!("Bound a socket to {}.", dest),
                );
            }
            if pol.network_mode == NetworkMode::Deny {
                return Decision::violation(
                    Category::Network,
                    "net.listen",
                    Severity::Medium,
                    "network.mode=deny",
                    "No network access",
                    format!("The agent tried to open a network listener on {}. This policy does not allow any network access.", dest),
                );
            }
            return Decision::allowed(
                Category::Network,
                "net.bind",
                format!("Bound a socket to {}.", dest),
            );
        }

        if let Some((_, what)) = METADATA_IPS
            .iter()
            .find(|(ip, _)| ip.parse::<IpAddr>().ok() == Some(addr))
        {
            if pol.source.cloud_metadata.access == Access::Allow {
                return Decision::allowed(
                    Category::CloudMetadata,
                    "metadata.connect",
                    format!("Connected to {} ({}), allowed by policy.", dest, what),
                );
            }
            return Decision::violation(
                Category::CloudMetadata,
                "metadata.access",
                Severity::Critical,
                "cloud_metadata.access=deny",
                "No access to cloud instance metadata",
                format!(
                    "The agent tried to reach {} — {}. Metadata services hand out cloud credentials, \
                     so access from an agent is highly suspicious.",
                    dest, what
                ),
            );
        }

        if addr.is_loopback() {
            if pol.source.network.allow_localhost || pol.network_mode == NetworkMode::Allow {
                return Decision::allowed(
                    Category::Network,
                    "net.localhost",
                    format!("Connected to local service {}.", dest),
                );
            }
            return Decision::violation(
                Category::Network,
                "net.localhost",
                Severity::Medium,
                "network.allow_localhost=false",
                "No network access, including localhost",
                format!("The agent tried to connect to a local service at {}. This policy does not allow localhost connections.", dest),
            );
        }

        let verb = if op == NetOp::Connect {
            "connect to"
        } else {
            "send data to"
        };
        match pol.network_mode {
            NetworkMode::Allow => Decision::allowed(Category::Network, "net.connect", format!("Connected to {}.", dest)),
            NetworkMode::Deny => Decision::violation(
                Category::Network,
                "net.outbound",
                Severity::High,
                "network.mode=deny",
                "No outbound network access",
                format!(
                    "The monitored agent attempted to {} {}. This policy does not allow any network access.",
                    verb, dest
                ),
            ),
            NetworkMode::Allowlist => {
                if pol.cidrs.iter().any(|c| c.contains(&addr)) {
                    return Decision::allowed(Category::Network, "net.connect", format!("Connected to {} (in allowed CIDR range).", dest));
                }
                if let Some((ts, dom)) = self
                    .allowed_dns
                    .iter()
                    .rev()
                    .find(|(ts, _)| (now - *ts).num_seconds() <= DNS_ATTRIBUTION_SECS)
                {
                    return Decision::allowed(
                        Category::Network,
                        "net.connect_attributed",
                        format!(
                            "Connected to {}. Destination not verified: KillLine V1 does not see DNS answers; \
                             the agent resolved allowed domain {} {}s earlier.",
                            dest,
                            dom,
                            (now - *ts).num_seconds()
                        ),
                    );
                }
                Decision::violation(
                    Category::Network,
                    "net.outbound_unlisted",
                    Severity::High,
                    "network.allow",
                    format!("Only: {}", pol.source.network.allow.join(", ")),
                    format!(
                        "The agent tried to {} {}, which is not an allowed destination, and no allowed domain \
                         was resolved beforehand.",
                        verb, dest
                    ),
                )
            }
        }
    }

    fn decide_dns(
        &mut self,
        query: Option<&str>,
        server: Option<IpAddr>,
        ts: DateTime<Utc>,
    ) -> Decision {
        let name = query
            .unwrap_or("<unparsed>")
            .trim_end_matches('.')
            .to_ascii_lowercase();
        let via = server.map(|s| format!(" via {}", s)).unwrap_or_default();
        if METADATA_HOSTS.contains(&name.as_str())
            && self.policy.source.cloud_metadata.access == Access::Deny
        {
            return Decision::violation(
                Category::CloudMetadata,
                "metadata.dns",
                Severity::Critical,
                "cloud_metadata.access=deny",
                "No access to cloud instance metadata",
                format!(
                    "The agent tried to resolve the cloud metadata hostname {}{}.",
                    name, via
                ),
            );
        }
        match self.policy.network_mode {
            NetworkMode::Allow => Decision::allowed(Category::Dns, "dns.query", format!("DNS lookup {}{}.", name, via)),
            NetworkMode::Deny => Decision::violation(
                Category::Dns,
                "dns.query",
                Severity::High,
                "network.mode=deny",
                "No network access (including DNS)",
                format!("The agent attempted a DNS lookup for {}{}. This policy does not allow any network access.", name, via),
            ),
            NetworkMode::Allowlist => {
                if self.policy.domains.iter().any(|d| domain_matches(d, &name)) {
                    self.allowed_dns.push_back((ts, name.clone()));
                    while self.allowed_dns.len() > 256 {
                        self.allowed_dns.pop_front();
                    }
                    return Decision::allowed(Category::Dns, "dns.query", format!("DNS lookup {}{} (allowed domain).", name, via));
                }
                Decision::violation(
                    Category::Dns,
                    "dns.query_unlisted",
                    Severity::High,
                    "network.allow",
                    format!("Only: {}", self.policy.source.network.allow.join(", ")),
                    format!("The agent tried to resolve {}{}, which is not an allowed domain.", name, via),
                )
            }
        }
    }
}

/// Write attempts that interpreters make routinely. Only ignored when the
/// attempt FAILED; a successful write is still evaluated normally.
const BENIGN_FAILED_WRITES: &[&str] = &["**/__pycache__", "**/*.pyc"];

fn outcome_sentence(o: Option<&Outcome>) -> String {
    match o {
        Some(Outcome::Succeeded) => "Result: the operation SUCCEEDED — the boundary was actually crossed.".into(),
        Some(f @ Outcome::Failed { error, .. }) if f.refused() => format!(
            "Result: the operating system refused it ({}) — the sandbox held for this attempt, but the attempt itself breaches the policy.",
            error
        ),
        Some(Outcome::Failed { error, .. }) => format!("Result: the attempt failed ({}).", error),
        Some(Outcome::InProgress) => "Result: a non-blocking connection was started; whether it completed was not observed.".into(),
        None => "Result: not observed.".into(),
    }
}

fn list_or_none(a: &[String], b: &[String]) -> String {
    let v: Vec<&String> = a.iter().chain(b.iter()).collect();
    if v.is_empty() {
        "(none)".into()
    } else {
        v.iter().map(|s| s.as_str()).collect::<Vec<_>>().join(", ")
    }
}

pub fn domain_matches(rule: &str, name: &str) -> bool {
    if let Some(suffix) = rule.strip_prefix("*.") {
        name.ends_with(&format!(".{}", suffix))
    } else {
        rule == name
    }
}
