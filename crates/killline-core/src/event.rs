//! Event model.
//!
//! An [`Observation`] is what a sensor saw, before any policy decision.
//! An [`Event`] is an observation after evaluation: it carries a verdict,
//! a severity, the policy rule involved and a plain-English explanation.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::net::IpAddr;

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq)]
pub struct ProcessInfo {
    pub pid: u32,
    pub tid: u32,
    pub ppid: u32,
    pub uid: u32,
    pub gid: u32,
    pub comm: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub exe: Option<String>,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum FileAccess {
    Read,
    Write,
    /// Opened with O_DIRECTORY (typically a directory listing).
    List,
    /// Opened with O_PATH: a handle without read or write access.
    Path,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum NetOp {
    Connect,
    Send,
    Bind,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum ObsKind {
    Exec {
        path: String,
        /// Already redacted by the sensor before it reaches the engine.
        argv: Vec<String>,
        #[serde(skip_serializing_if = "Option::is_none")]
        sha256: Option<String>,
        /// False when the file did not exist at exec time (e.g. a PATH
        /// search probing directories); such attempts fail with ENOENT.
        #[serde(default = "yes", skip_serializing_if = "is_true")]
        exists: bool,
    },
    Fork {
        child_pid: u32,
    },
    Exit,
    /// A file-open attempt as the program requested it (may fail).
    Open {
        path: String,
        access: FileAccess,
        flags: u64,
        /// "kernel" = resolved by the kernel after symlinks; "lexical" =
        /// resolved by KillLine from syscall arguments; "userspace-realpath"
        /// = symlinks resolved by KillLine inside the agent's root (racy).
        resolution: String,
        /// The path as requested, when it differs from `path` because a
        /// symlink was followed.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        via: Option<String>,
    },
    Unlink {
        path: String,
    },
    Rename {
        from: String,
        to: String,
    },
    Chmod {
        path: String,
        mode: u32,
    },
    Net {
        op: NetOp,
        addr: IpAddr,
        port: u16,
    },
    UnixConnect {
        path: String,
        #[serde(default)]
        abstract_ns: bool,
    },
    Dns {
        #[serde(skip_serializing_if = "Option::is_none")]
        server: Option<IpAddr>,
        #[serde(skip_serializing_if = "Option::is_none")]
        query: Option<String>,
    },
    Socket {
        family: u32,
        sock_type: u32,
        protocol: u32,
    },
    Mount {
        source: String,
        target: String,
        flags: u64,
    },
    Umount {
        target: String,
    },
    SetId {
        call: String,
        args: Vec<i64>,
    },
    Capset {
        effective: u32,
        permitted: u32,
    },
    Unshare {
        flags: u64,
    },
    Setns {
        nstype: u64,
    },
    Ptrace {
        request: u64,
        target_pid: i64,
    },
    Kill {
        target_pid: i64,
        signal: u64,
    },
    Bpf {
        cmd: u64,
    },
    ModuleLoad,
    Chroot {
        path: String,
    },
    PivotRoot {
        new_root: String,
        put_old: String,
    },
}

/// What the operating system did with an attempted operation.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "result", rename_all = "snake_case")]
pub enum Outcome {
    /// The operation succeeded: a boundary crossing actually happened.
    Succeeded,
    /// The operation failed. For EACCES/EPERM/EROFS this usually means the
    /// sandbox or OS access controls held.
    Failed { errno: i32, error: String },
    /// A non-blocking connect was started (EINPROGRESS); completion is not
    /// observed in V1.
    InProgress,
}

impl Outcome {
    pub fn from_ret(ret: i64) -> Outcome {
        if ret >= 0 {
            Outcome::Succeeded
        } else if ret == -115 {
            Outcome::InProgress
        } else {
            let errno = (-ret) as i32;
            Outcome::Failed { errno, error: errno_name(errno) }
        }
    }

    /// Refused by permission/confinement checks (as opposed to, say, a
    /// missing file).
    pub fn refused(&self) -> bool {
        matches!(self, Outcome::Failed { errno, .. } if matches!(errno, 1 | 13 | 30))
    }

    pub fn short(&self) -> String {
        match self {
            Outcome::Succeeded => "succeeded".into(),
            Outcome::Failed { error, .. } => format!("failed: {}", error),
            Outcome::InProgress => "in progress".into(),
        }
    }
}

pub fn errno_name(e: i32) -> String {
    let name = match e {
        1 => "EPERM",
        2 => "ENOENT",
        9 => "EBADF",
        13 => "EACCES",
        17 => "EEXIST",
        18 => "EXDEV",
        20 => "ENOTDIR",
        21 => "EISDIR",
        22 => "EINVAL",
        30 => "EROFS",
        38 => "ENOSYS",
        97 => "EAFNOSUPPORT",
        98 => "EADDRINUSE",
        99 => "EADDRNOTAVAIL",
        101 => "ENETUNREACH",
        110 => "ETIMEDOUT",
        111 => "ECONNREFUSED",
        113 => "EHOSTUNREACH",
        _ => "",
    };
    let desc = std::io::Error::from_raw_os_error(e).to_string();
    let desc = desc.split(" (os error").next().unwrap_or("").to_string();
    if name.is_empty() {
        format!("errno {} ({})", e, desc)
    } else {
        format!("{} ({})", name, desc)
    }
}

fn yes() -> bool {
    true
}
fn is_true(b: &bool) -> bool {
    *b
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct Observation {
    pub timestamp: DateTime<Utc>,
    pub process: ProcessInfo,
    pub kind: ObsKind,
    /// Emitted by a process that entered the agent's container from outside
    /// (e.g. `docker exec` → runc init) before its first exec. Such events
    /// belong to the container runtime, not the agent; they are recorded but
    /// not evaluated. Processes forked by the agent never carry this flag.
    #[serde(default, skip_serializing_if = "is_false")]
    pub runtime_setup: bool,
    /// Result of the syscall, when KillLine observed it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub outcome: Option<Outcome>,
}

fn is_false(b: &bool) -> bool {
    !*b
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Hash)]
#[serde(rename_all = "snake_case")]
pub enum Category {
    Process,
    Filesystem,
    Network,
    Dns,
    Credential,
    Privilege,
    Namespace,
    ContainerEscape,
    ContainerRuntime,
    CloudMetadata,
    Tamper,
    Anomaly,
    Monitor,
    Response,
}

impl Category {
    pub fn boundary_name(&self) -> &'static str {
        match self {
            Category::Process => "Process Policy",
            Category::Filesystem => "Filesystem Boundary",
            Category::Network => "Network Isolation",
            Category::Dns => "Network Isolation (DNS)",
            Category::Credential => "Credential Isolation",
            Category::Privilege => "Privilege Boundary",
            Category::Namespace => "Namespace Boundary",
            Category::ContainerEscape => "Container Boundary",
            Category::ContainerRuntime => "Container Runtime Isolation",
            Category::CloudMetadata => "Cloud Metadata Isolation",
            Category::Tamper => "Monitor Integrity",
            Category::Anomaly => "Behaviour",
            Category::Monitor => "Monitoring",
            Category::Response => "Response",
        }
    }
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
#[serde(rename_all = "snake_case")]
pub enum Severity {
    Info,
    Low,
    Medium,
    High,
    Critical,
}

/// How an event affects the session.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum Verdict {
    /// Permitted by policy.
    Allowed,
    /// Crosses a declared boundary.
    Violation,
    /// Not a policy breach, but unusual behaviour worth attention.
    Anomaly,
    /// About KillLine itself (coverage, drops, responses).
    Notice,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct Correlation {
    /// Always phrased as a possibility, never as proof.
    pub summary: String,
    pub related_seq: Vec<u64>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct Event {
    pub seq: u64,
    pub timestamp: DateTime<Utc>,
    pub session_id: String,
    pub agent_id: String,
    pub category: Category,
    pub action: String,
    pub severity: Severity,
    pub verdict: Verdict,
    pub allowed: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub process: Option<ProcessInfo>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub observation: Option<ObsKind>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub outcome: Option<Outcome>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub policy_rule: Option<String>,
    /// What was expected by policy, in plain English.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub expected: Option<String>,
    /// Plain-English explanation of what happened.
    pub explanation: String,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub correlations: Vec<Correlation>,
    /// Set when this event only confirms an earlier event (e.g. the kernel
    /// confirming that a violating open succeeded). Not counted again.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub confirms_seq: Option<u64>,
}

impl Event {
    /// One-line human summary of the resource involved.
    pub fn resource_summary(&self) -> String {
        match &self.observation {
            Some(o) => o.summary(),
            None => String::new(),
        }
    }
}

impl ObsKind {
    pub fn summary(&self) -> String {
        match self {
            ObsKind::Exec { path, argv, .. } => {
                if argv.len() > 1 {
                    format!("{} {}", path, argv[1..].join(" "))
                } else {
                    path.clone()
                }
            }
            ObsKind::Fork { child_pid } => format!("child pid {}", child_pid),
            ObsKind::Exit => "process exited".into(),
            ObsKind::Open { path, access, .. } => format!("{:?} {}", access, path).to_lowercase_first(),
            ObsKind::Unlink { path } => format!("delete {}", path),
            ObsKind::Rename { from, to } => format!("rename {} -> {}", from, to),
            ObsKind::Chmod { path, mode } => format!("chmod {:o} {}", mode, path),
            ObsKind::Net { op, addr, port } => {
                let a = match addr {
                    IpAddr::V6(v6) => format!("[{}]", v6),
                    IpAddr::V4(v4) => v4.to_string(),
                };
                format!("{:?} {}:{}", op, a, port).to_lowercase_first()
            }
            ObsKind::UnixConnect { path, abstract_ns } => {
                if *abstract_ns {
                    format!("unix socket @{}", path)
                } else {
                    format!("unix socket {}", path)
                }
            }
            ObsKind::Dns { server, query } => format!(
                "DNS query {}{}",
                query.as_deref().unwrap_or("<unknown name>"),
                server.map(|s| format!(" via {}", s)).unwrap_or_default()
            ),
            ObsKind::Socket { family, sock_type, .. } => {
                format!("socket(family={}, type={})", family, sock_type & 0xf)
            }
            ObsKind::Mount { source, target, .. } => format!("mount {} on {}", source, target),
            ObsKind::Umount { target } => format!("umount {}", target),
            ObsKind::SetId { call, args } => format!("{}({:?})", call, args),
            ObsKind::Capset { effective, .. } => format!("capset effective={:#x}", effective),
            ObsKind::Unshare { flags } => format!("unshare(flags={:#x})", flags),
            ObsKind::Setns { nstype } => format!("setns(nstype={:#x})", nstype),
            ObsKind::Ptrace { request, target_pid } => {
                format!("ptrace(request={}, pid={})", request, target_pid)
            }
            ObsKind::Kill { target_pid, signal } => format!("kill(pid={}, sig={})", target_pid, signal),
            ObsKind::Bpf { cmd } => format!("bpf(cmd={})", cmd),
            ObsKind::ModuleLoad => "kernel module load".into(),
            ObsKind::Chroot { path } => format!("chroot {}", path),
            ObsKind::PivotRoot { new_root, .. } => format!("pivot_root {}", new_root),
        }
    }
}

trait LowerFirst {
    fn to_lowercase_first(self) -> String;
}

impl LowerFirst for String {
    fn to_lowercase_first(self) -> String {
        let mut c = self.chars();
        match c.next() {
            Some(f) => f.to_lowercase().collect::<String>() + c.as_str(),
            None => self,
        }
    }
}
