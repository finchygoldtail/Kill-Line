//! Containment policy: the explicit contract an agent is expected to honour.
//!
//! See docs/POLICY_FORMAT.md for the full reference.

use crate::pathmatch::{self, PatternSet};
use anyhow::{bail, Context, Result};
use serde::{Deserialize, Serialize};
use std::net::IpAddr;
use std::path::Path;

/// Which operating system's conventions (paths, built-in lists) apply.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum Platform {
    Linux,
    Windows,
}

impl Platform {
    pub fn current() -> Platform {
        if cfg!(windows) {
            Platform::Windows
        } else {
            Platform::Linux
        }
    }
}

/// Maximum accepted policy size. Policies are small; refuse anything large.
const MAX_POLICY_BYTES: u64 = 256 * 1024;
const MAX_LIST_ENTRIES: usize = 1024;
const MAX_ENTRY_LEN: usize = 1024;

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Policy {
    #[serde(default = "one")]
    pub version: u32,
    /// Agent identifier this contract applies to.
    pub agent: String,
    /// Optional human-readable name for the policy (e.g. "strict-no-network").
    #[serde(default)]
    pub name: Option<String>,
    #[serde(default)]
    pub description: Option<String>,
    #[serde(default)]
    pub filesystem: FilesystemPolicy,
    #[serde(default)]
    pub network: NetworkPolicy,
    #[serde(default)]
    pub processes: ProcessPolicy,
    #[serde(default)]
    pub credentials: CredentialPolicy,
    #[serde(default)]
    pub cloud_metadata: AccessToggle,
    #[serde(default)]
    pub container_runtime: AccessToggle,
    #[serde(default)]
    pub inter_agent_communication: InterAgentPolicy,
    #[serde(default)]
    pub mcp: Option<McpPolicy>,
    #[serde(default)]
    pub response: ResponsePolicy,
    #[serde(default)]
    pub anomaly: AnomalyPolicy,
    /// Paths holding untrusted input (downloaded docs, third-party repos).
    /// Reads of these are used for "possible correlation" hints.
    #[serde(default)]
    pub untrusted_inputs: Vec<String>,
}

fn one() -> u32 {
    1
}
fn yes() -> bool {
    true
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FilesystemPolicy {
    /// Shorthand: paths that may be read and written.
    #[serde(default)]
    pub allow: Vec<String>,
    #[serde(default)]
    pub allow_read: Vec<String>,
    #[serde(default)]
    pub allow_write: Vec<String>,
    /// Always a violation, even if also matched by an allow rule.
    #[serde(default)]
    pub deny: Vec<String>,
    /// Read-only paths every Linux program needs (shared libraries, locale,
    /// /proc/self, ...). `default` enables Kill Line's built-in list,
    /// `none` disables it so every read must be explicitly allowed.
    #[serde(default)]
    pub runtime_read: RuntimeRead,
}

impl Default for FilesystemPolicy {
    fn default() -> Self {
        FilesystemPolicy {
            allow: vec![],
            allow_read: vec![],
            allow_write: vec![],
            deny: vec![],
            runtime_read: RuntimeRead::Default,
        }
    }
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Default)]
#[serde(rename_all = "snake_case")]
pub enum RuntimeRead {
    #[default]
    Default,
    None,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Default)]
#[serde(rename_all = "snake_case")]
pub enum NetworkMode {
    /// No network access at all.
    #[default]
    Deny,
    /// Only destinations in allow / allow_cidr.
    Allowlist,
    /// Any destination (metadata and runtime rules still apply).
    Allow,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(deny_unknown_fields)]
pub struct NetworkPolicy {
    #[serde(default)]
    pub mode: Option<NetworkMode>,
    /// Allowed domain names (exact or `*.example.com`).
    #[serde(default)]
    pub allow: Vec<String>,
    #[serde(default)]
    pub allow_cidr: Vec<String>,
    /// Allow connections to 127.0.0.0/8 and ::1 inside the agent's own
    /// network namespace.
    #[serde(default)]
    pub allow_localhost: bool,
}

impl NetworkPolicy {
    pub fn effective_mode(&self) -> NetworkMode {
        match self.mode {
            Some(m) => m,
            None if !self.allow.is_empty() || !self.allow_cidr.is_empty() => NetworkMode::Allowlist,
            None => NetworkMode::Deny,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProcessPolicy {
    /// Allowed executables (basename or absolute path). Empty = any.
    #[serde(default)]
    pub allow: Vec<String>,
    #[serde(default)]
    pub deny: Vec<String>,
    /// Flag privilege changes: setuid-to-root, capset, sudo/su, etc.
    #[serde(default = "yes")]
    pub deny_privileged: bool,
}

impl Default for ProcessPolicy {
    fn default() -> Self {
        ProcessPolicy {
            allow: vec![],
            deny: vec![],
            deny_privileged: true,
        }
    }
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Default)]
#[serde(rename_all = "snake_case")]
pub enum Access {
    #[default]
    Deny,
    Allow,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(deny_unknown_fields)]
pub struct AccessToggle {
    #[serde(default)]
    pub access: Access,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(deny_unknown_fields)]
pub struct CredentialPolicy {
    #[serde(default)]
    pub access: Access,
    /// Additional sensitive locations on top of the built-in list.
    #[serde(default)]
    pub extra_paths: Vec<String>,
    /// Credential paths the agent is explicitly permitted to read.
    #[serde(default)]
    pub allow_paths: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(deny_unknown_fields)]
pub struct InterAgentPolicy {
    #[serde(default)]
    pub allow: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(deny_unknown_fields)]
pub struct McpPolicy {
    #[serde(default)]
    pub allow_servers: Vec<String>,
    #[serde(default)]
    pub deny_unknown_servers: bool,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Default)]
#[serde(rename_all = "snake_case")]
pub enum ResponseAction {
    /// Record and alert only (default).
    #[default]
    Alert,
    /// Freeze the agent (docker pause / SIGSTOP) for inspection.
    Freeze,
    /// Terminate the agent.
    Terminate,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(deny_unknown_fields)]
pub struct ResponsePolicy {
    #[serde(default)]
    pub violation: ResponseAction,
    /// What to do when Kill Line loses visibility (dropped events). `freeze`
    /// makes monitoring fail closed: an agent cannot flood its way out of
    /// view. Default: alert.
    #[serde(default)]
    pub on_degraded: ResponseAction,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AnomalyPolicy {
    #[serde(default = "yes")]
    pub enabled: bool,
    /// Distinct non-runtime files opened within the window that counts as
    /// rapid filesystem enumeration.
    #[serde(default = "default_burst_files")]
    pub file_burst_threshold: usize,
    #[serde(default = "default_window")]
    pub window_secs: u64,
    /// Distinct network destinations within the window that looks like scanning.
    #[serde(default = "default_scan")]
    pub network_scan_threshold: usize,
    /// Process executions within the window that looks like a fork storm.
    #[serde(default = "default_exec")]
    pub exec_burst_threshold: usize,
}

fn default_burst_files() -> usize {
    150
}
fn default_window() -> u64 {
    10
}
fn default_scan() -> usize {
    20
}
fn default_exec() -> usize {
    50
}

impl Default for AnomalyPolicy {
    fn default() -> Self {
        AnomalyPolicy {
            enabled: true,
            file_burst_threshold: default_burst_files(),
            window_secs: default_window(),
            network_scan_threshold: default_scan(),
            exec_burst_threshold: default_exec(),
        }
    }
}

/// Built-in credential-sensitive locations. Access is recorded, contents
/// are never read.
pub const DEFAULT_CREDENTIAL_PATHS: &[&str] = &[
    "~/.ssh",
    "~/.aws",
    "~/.azure",
    "~/.config/gcloud",
    "~/.kube",
    "~/.docker/config.json",
    "~/.netrc",
    "~/.git-credentials",
    "~/.npmrc",
    "~/.pypirc",
    "~/.gnupg",
    "~/.config/gh/hosts.yml",
    "~/.password-store",
    "**/.env",
    "**/.env.*",
    "**/credentials.json",
    "**/service-account*.json",
    "**/id_rsa*",
    "**/id_ecdsa*",
    "**/id_ed25519*",
    "/etc/shadow",
    "/etc/gshadow",
    "/etc/sudoers",
    "/etc/kubernetes",
    "/var/run/secrets",
    "/run/secrets",
    "/proc/*/environ",
];

/// Container runtime control sockets. Reaching one is equivalent to host root.
pub const RUNTIME_SOCKETS: &[&str] = &[
    "/var/run/docker.sock",
    "/run/docker.sock",
    "/run/containerd/containerd.sock",
    "/var/run/containerd/containerd.sock",
    "/run/crio/crio.sock",
    "/var/run/crio/crio.sock",
    "/run/podman/podman.sock",
    "/var/run/cri-dockerd.sock",
    "/run/buildkit/buildkitd.sock",
];

/// Paths whose access from inside an agent sandbox is a recognised container
/// escape *indicator*. This is a detection list only.
pub const ESCAPE_INDICATORS: &[(&str, &str)] = &[
    (
        "/proc/sys/kernel/core_pattern",
        "kernel core_pattern handler (runs on the host)",
    ),
    ("/proc/sysrq-trigger", "kernel SysRq trigger"),
    ("/proc/sys/kernel/modprobe", "kernel modprobe helper path"),
    ("/proc/*/root", "another process's root filesystem"),
    ("/proc/*/mem", "another process's memory"),
    ("/proc/kcore", "kernel memory image"),
    ("/proc/kallsyms", "kernel symbol table"),
    (
        "/sys/fs/cgroup/**/release_agent",
        "cgroup release_agent (host-side helper)",
    ),
    (
        "/sys/fs/cgroup/**/notify_on_release",
        "cgroup release notification",
    ),
    ("/sys/kernel/uevent_helper", "kernel uevent helper"),
    ("/dev/mem", "physical memory device"),
    ("/dev/kmem", "kernel memory device"),
    ("/dev/sd*", "raw block device"),
    ("/dev/nvme*", "raw block device"),
    ("/dev/vd*", "raw block device"),
    ("/dev/xvd*", "raw block device"),
    ("/dev/dm-*", "raw block device"),
];

/// Read-only locations a normal Linux process touches. Enabled with
/// `runtime_read: default`. Deny and credential rules take precedence.
pub const RUNTIME_READ_PATHS: &[&str] = &[
    "/usr",
    "/lib",
    "/lib32",
    "/lib64",
    "/libx32",
    "/bin",
    "/sbin",
    "/opt",
    "/etc/ld.so.cache",
    "/etc/ld.so.preload",
    "/etc/ld.so.conf",
    "/etc/ld.so.conf.d",
    "/etc/localtime",
    "/etc/timezone",
    "/etc/nsswitch.conf",
    "/etc/passwd",
    "/etc/group",
    "/etc/host.conf",
    "/etc/hosts",
    "/etc/resolv.conf",
    "/etc/gai.conf",
    "/etc/mime.types",
    "/etc/ssl",
    "/etc/ca-certificates",
    "/etc/pki",
    "/etc/python3*",
    "/etc/alternatives",
    "/etc/locale.alias",
    "/etc/inputrc",
    "/etc/bash.bashrc",
    "/etc/profile",
    "/etc/terminfo",
    "/proc/self",
    "/proc/thread-self",
    "/proc/meminfo",
    "/proc/cpuinfo",
    "/proc/stat",
    "/proc/filesystems",
    "/proc/mounts",
    "/proc/version",
    "/proc/loadavg",
    "/proc/uptime",
    "/proc/sys/kernel/ngroups_max",
    "/proc/sys/kernel/cap_last_cap",
    "/proc/sys/kernel/osrelease",
    "/proc/sys/kernel/pid_max",
    "/sys/kernel/mm/transparent_hugepage",
    "/proc/sys/vm/overcommit_memory",
    "/proc/sys/kernel/random",
    "/sys/devices/system/cpu",
    "/sys/fs/cgroup/cpu.max",
    "/dev/null",
    "/dev/zero",
    "/dev/random",
    "/dev/urandom",
    "/dev/tty",
    "/dev/pts",
    "/dev/shm",
    "/dev/fd",
    "/dev/stdin",
    "/dev/stdout",
    "/dev/stderr",
];

/// Paths every program may write regardless of policy.
pub const RUNTIME_WRITE_PATHS: &[&str] = &[
    "/dev/null",
    "/dev/tty",
    "/dev/pts",
    "/dev/stdout",
    "/dev/stderr",
    "/dev/fd",
];

/// The built-in lists for one platform.
pub struct Builtins {
    pub runtime_read: &'static [&'static str],
    pub credentials: &'static [&'static str],
    pub runtime_write: &'static [&'static str],
    pub escape: &'static [(&'static str, &'static str)],
    pub runtime_sockets: &'static [&'static str],
    pub privilege_tools: &'static [&'static str],
}

pub const LINUX_BUILTINS: Builtins = Builtins {
    runtime_read: RUNTIME_READ_PATHS,
    credentials: DEFAULT_CREDENTIAL_PATHS,
    runtime_write: RUNTIME_WRITE_PATHS,
    escape: ESCAPE_INDICATORS,
    runtime_sockets: RUNTIME_SOCKETS,
    privilege_tools: LINUX_PRIVILEGE_TOOLS,
};

pub const WINDOWS_BUILTINS: Builtins = Builtins {
    runtime_read: WINDOWS_RUNTIME_READ_PATHS,
    credentials: WINDOWS_CREDENTIAL_PATHS,
    runtime_write: WINDOWS_RUNTIME_WRITE_PATHS,
    escape: WINDOWS_ESCAPE_INDICATORS,
    runtime_sockets: WINDOWS_RUNTIME_PIPES,
    privilege_tools: WINDOWS_PRIVILEGE_TOOLS,
};

/// Executables that exist to change privilege or escape confinement (Linux).
pub const LINUX_PRIVILEGE_TOOLS: &[&str] = &[
    "sudo", "su", "doas", "pkexec", "runuser", "setpriv", "nsenter", "unshare", "capsh", "chroot",
    "mount", "umount", "insmod", "modprobe", "newgrp", "sg", "docker", "podman", "nerdctl", "ctr",
    "crictl", "kubectl",
];

// ---------------- Windows built-ins (canonical, lowercase) ----------------

/// Credential-sensitive locations on Windows. `~/` means any user profile.
pub const WINDOWS_CREDENTIAL_PATHS: &[&str] = &[
    "~/.ssh",
    "~/.aws",
    "~/.azure",
    "~/.kube",
    "~/.docker/config.json",
    "~/.git-credentials",
    "~/.netrc",
    "~/_netrc",
    "~/.npmrc",
    "~/.pypirc",
    "~/appdata/roaming/gcloud",
    "~/appdata/roaming/github cli/hosts.yml",
    "~/appdata/roaming/microsoft/credentials",
    "~/appdata/local/microsoft/credentials",
    "~/appdata/roaming/microsoft/protect",
    "~/appdata/roaming/microsoft/crypto",
    "~/appdata/local/google/chrome/user data/*/login data",
    "~/appdata/local/google/chrome/user data/*/network/cookies",
    "~/appdata/local/microsoft/edge/user data/*/login data",
    "~/appdata/local/microsoft/edge/user data/*/network/cookies",
    "~/appdata/roaming/mozilla/firefox/profiles/*/logins.json",
    "~/appdata/roaming/mozilla/firefox/profiles/*/key4.db",
    "**/.env",
    "**/.env.*",
    "**/credentials.json",
    "**/service-account*.json",
    "**/id_rsa*",
    "**/id_ecdsa*",
    "**/id_ed25519*",
    "/*:/windows/system32/config/sam",
    "/*:/windows/system32/config/security",
    "/*:/windows/system32/config/system",
    "/*:/windows/ntds/ntds.dit",
];

/// Container-runtime control pipes on Windows (Docker Desktop, containerd,
/// Podman). Reaching one grants control of containers and often the host.
pub const WINDOWS_RUNTIME_PIPES: &[&str] = &[
    "/pipe/docker_engine",
    "/pipe/docker_engine_linux",
    "/pipe/dockerdesktoplinuxengine",
    "/pipe/dockerdesktopengine",
    "/pipe/docker_cli",
    "/pipe/containerd-containerd",
    "/pipe/podman-machine-default",
];

pub const WINDOWS_ESCAPE_INDICATORS: &[(&str, &str)] = &[
    ("/device/physicalmemory", "physical memory device"),
    ("/physicaldrive*", "raw disk device"),
    ("/device/harddisk*/dr*", "raw disk device"),
];

pub const WINDOWS_RUNTIME_READ_PATHS: &[&str] = &[
    "/*:/windows",
    "/*:/program files",
    "/*:/program files (x86)",
    "/*:/programdata/microsoft",
    "~/appdata/local/programs",
    "/device",
    "/pipe",
];

pub const WINDOWS_RUNTIME_WRITE_PATHS: &[&str] = &["/device", "/pipe"];

/// Programs used to change privilege, persist, tamper with logs, or leave
/// the sandbox on Windows. Matched without the `.exe` suffix.
pub const WINDOWS_PRIVILEGE_TOOLS: &[&str] = &[
    "runas",
    "psexec",
    "psexec64",
    "paexec",
    "schtasks",
    "sc",
    "bcdedit",
    "vssadmin",
    "wevtutil",
    "takeown",
    "reg",
    "regedit",
    "mimikatz",
    "procdump",
    "docker",
    "kubectl",
    "podman",
    "nerdctl",
    "wsl",
    "wslhost",
    "wslconfig",
];

/// Well-known cloud instance-metadata endpoints.
pub const METADATA_IPS: &[(&str, &str)] = &[
    (
        "169.254.169.254",
        "AWS / Azure / GCP / OCI instance metadata",
    ),
    ("fd00:ec2::254", "AWS instance metadata (IPv6)"),
    ("169.254.170.2", "AWS ECS task metadata / credentials"),
    ("169.254.170.23", "AWS EKS Pod Identity agent"),
    ("168.63.129.16", "Azure WireServer"),
    ("100.100.100.200", "Alibaba Cloud metadata"),
];

pub const METADATA_HOSTS: &[&str] = &[
    "metadata.google.internal",
    "metadata.goog",
    "metadata",
    "instance-data",
    "instance-data.ec2.internal",
];

/// A policy with all shorthand expanded, ready for fast evaluation.
#[derive(Debug, Clone)]
pub struct CompiledPolicy {
    pub source: Policy,
    pub platform: Platform,
    /// Programs whose execution counts as a privilege change on this platform.
    pub privilege_tools: &'static [&'static str],
    /// Escape-indicator patterns with a description.
    pub escape_info: &'static [(&'static str, &'static str)],
    pub read_allow: PatternSet,
    pub write_allow: PatternSet,
    pub deny: PatternSet,
    pub runtime_read: PatternSet,
    pub runtime_write: PatternSet,
    pub credential_paths: PatternSet,
    pub credential_allow: PatternSet,
    pub untrusted: PatternSet,
    pub escape_indicators: PatternSet,
    pub runtime_sockets: PatternSet,
    pub cidrs: Vec<Cidr>,
    pub domains: Vec<String>,
    pub network_mode: NetworkMode,
}

impl Policy {
    pub fn load(path: &Path) -> Result<Policy> {
        let meta =
            std::fs::metadata(path).with_context(|| format!("reading {}", path.display()))?;
        if meta.len() > MAX_POLICY_BYTES {
            bail!(
                "policy file is larger than {} bytes; refusing to parse",
                MAX_POLICY_BYTES
            );
        }
        let text =
            std::fs::read_to_string(path).with_context(|| format!("reading {}", path.display()))?;
        Policy::parse(&text)
    }

    pub fn parse(text: &str) -> Result<Policy> {
        if text.len() as u64 > MAX_POLICY_BYTES {
            bail!("policy is larger than {} bytes", MAX_POLICY_BYTES);
        }
        let p: Policy = serde_yaml::from_str(text).context("policy is not valid Kill Line YAML")?;
        Ok(p)
    }

    /// Structural and semantic validation. Errors make the policy unusable;
    /// warnings describe things Kill Line cannot fully verify.
    pub fn validate(&self) -> Vec<Diagnostic> {
        let mut d = Vec::new();
        if self.version != 1 {
            d.push(Diagnostic::error(format!(
                "unsupported policy version {}",
                self.version
            )));
        }
        if self.agent.trim().is_empty() {
            d.push(Diagnostic::error("`agent` must not be empty"));
        }
        if !self
            .agent
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || "-_.".contains(c))
        {
            d.push(Diagnostic::error(
                "`agent` may only contain letters, digits, '-', '_' and '.'",
            ));
        }
        let lists: Vec<(&str, &Vec<String>)> = vec![
            ("filesystem.allow", &self.filesystem.allow),
            ("filesystem.allow_read", &self.filesystem.allow_read),
            ("filesystem.allow_write", &self.filesystem.allow_write),
            ("filesystem.deny", &self.filesystem.deny),
            ("credentials.extra_paths", &self.credentials.extra_paths),
            ("credentials.allow_paths", &self.credentials.allow_paths),
            ("untrusted_inputs", &self.untrusted_inputs),
        ];
        for (name, list) in &lists {
            check_list(&mut d, name, list);
            for p in list.iter() {
                if !(p.starts_with('/')
                    || p.starts_with("~/")
                    || p.starts_with("~\\")
                    || p.starts_with("**/")
                    || pathmatch::is_windows_absolute(p))
                {
                    d.push(Diagnostic::error(format!(
                        "{}: '{}' must be an absolute path (/x or C:\\x), start with ~/ or **/",
                        name, p
                    )));
                }
            }
        }
        check_list(&mut d, "network.allow", &self.network.allow);
        check_list(&mut d, "network.allow_cidr", &self.network.allow_cidr);
        check_list(&mut d, "processes.allow", &self.processes.allow);
        check_list(&mut d, "processes.deny", &self.processes.deny);
        for c in &self.network.allow_cidr {
            if Cidr::parse(c).is_none() {
                d.push(Diagnostic::error(format!(
                    "network.allow_cidr: '{}' is not a valid CIDR",
                    c
                )));
            }
        }
        for dom in &self.network.allow {
            let valid = !dom.is_empty()
                && dom
                    .trim_start_matches("*.")
                    .chars()
                    .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '.');
            if !valid {
                d.push(Diagnostic::error(format!(
                    "network.allow: '{}' is not a valid domain",
                    dom
                )));
            }
        }
        let mode = self.network.effective_mode();
        if mode == NetworkMode::Deny
            && (!self.network.allow.is_empty() || !self.network.allow_cidr.is_empty())
        {
            d.push(Diagnostic::error(
                "network.mode is `deny` but allow rules are present",
            ));
        }
        if mode == NetworkMode::Allowlist && !self.network.allow.is_empty() {
            d.push(Diagnostic::warning(
                "domain allowlists are verified by observing DNS queries; connections to IPs \
                 not in allow_cidr are reported as AMBER 'unverified destination' rather than \
                 RED, because Kill Line V1 does not see DNS answers (see docs/LIMITATIONS.md)",
            ));
        }
        if mode == NetworkMode::Allow {
            d.push(Diagnostic::warning(
                "network.mode is `allow`: outbound traffic is not a boundary",
            ));
        }
        if self.filesystem.allow.is_empty()
            && self.filesystem.allow_read.is_empty()
            && self.filesystem.allow_write.is_empty()
        {
            d.push(Diagnostic::warning(
                "no filesystem allow rules: every non-runtime file access will be a violation",
            ));
        }
        if self.credentials.access == Access::Allow {
            d.push(Diagnostic::warning(
                "credentials.access is `allow`: credential reads are not a boundary",
            ));
        }
        if self.cloud_metadata.access == Access::Allow {
            d.push(Diagnostic::warning("cloud_metadata.access is `allow`"));
        }
        if self.container_runtime.access == Access::Allow {
            d.push(Diagnostic::warning(
                "container_runtime.access is `allow`: access to the Docker socket is equivalent to host root",
            ));
        }
        if self.mcp.is_some() {
            d.push(Diagnostic::warning(
                "mcp: section is parsed but NOT verified in V1 (Kill Line has no MCP telemetry source yet). \
                 MCP servers launched as local processes still appear as process/file/network events.",
            ));
        }
        if self.inter_agent_communication.allow {
            d.push(Diagnostic::info("inter_agent_communication.allow is true"));
        } else {
            d.push(Diagnostic::info(
                "inter_agent_communication: verified only for network connections and runtime sockets; \
                 shared files and generic Unix sockets are recorded but not classified (V1)",
            ));
        }
        if self.response.violation != ResponseAction::Alert {
            d.push(Diagnostic::info(format!(
                "response.violation is `{:?}`: Kill Line will act on the agent after the event \
                 (it does not prevent the triggering syscall)",
                self.response.violation
            )));
        }
        d
    }

    pub fn compile(&self) -> Result<CompiledPolicy> {
        self.compile_for(Platform::current())
    }

    /// Compile for a specific platform (tests use this to check Windows
    /// rules on any host).
    pub fn compile_for(&self, platform: Platform) -> Result<CompiledPolicy> {
        let errors: Vec<_> = self
            .validate()
            .into_iter()
            .filter(|d| d.level == Level::Error)
            .collect();
        if !errors.is_empty() {
            bail!(
                "policy is invalid:\n{}",
                errors
                    .iter()
                    .map(|e| format!("  - {}", e.message))
                    .collect::<Vec<_>>()
                    .join("\n")
            );
        }
        let win = platform == Platform::Windows;
        let expand_one = |p: &str| -> Vec<String> {
            if win {
                pathmatch::expand_home_windows(p)
            } else {
                pathmatch::expand_home(p)
            }
        };
        let expand =
            |v: &[String]| -> Vec<String> { v.iter().flat_map(|p| expand_one(p)).collect() };
        let mut read_allow = expand(&self.filesystem.allow);
        read_allow.extend(expand(&self.filesystem.allow_read));
        let mut write_allow = expand(&self.filesystem.allow);
        write_allow.extend(expand(&self.filesystem.allow_write));
        // Writable implies readable.
        read_allow.extend(write_allow.clone());
        let b = if win {
            &WINDOWS_BUILTINS
        } else {
            &LINUX_BUILTINS
        };
        let (runtime_list, cred_list, write_list, escape_info, sockets, tools) = (
            b.runtime_read,
            b.credentials,
            b.runtime_write,
            b.escape,
            b.runtime_sockets,
            b.privilege_tools,
        );
        let runtime_read: Vec<String> = match self.filesystem.runtime_read {
            RuntimeRead::Default => runtime_list.iter().flat_map(|p| expand_one(p)).collect(),
            RuntimeRead::None => vec![],
        };
        let mut credential_paths: Vec<String> =
            cred_list.iter().flat_map(|p| expand_one(p)).collect();
        credential_paths.extend(expand(&self.credentials.extra_paths));
        Ok(CompiledPolicy {
            source: self.clone(),
            platform,
            privilege_tools: tools,
            escape_info,
            read_allow: PatternSet::new(read_allow),
            write_allow: PatternSet::new(write_allow),
            deny: PatternSet::new(expand(&self.filesystem.deny)),
            runtime_read: PatternSet::new(runtime_read),
            runtime_write: PatternSet::new(write_list.iter()),
            credential_paths: PatternSet::new(credential_paths),
            credential_allow: PatternSet::new(expand(&self.credentials.allow_paths)),
            untrusted: PatternSet::new(expand(&self.untrusted_inputs)),
            escape_indicators: PatternSet::new(escape_info.iter().map(|(p, _)| *p)),
            runtime_sockets: PatternSet::new(sockets.iter()),
            cidrs: self
                .network
                .allow_cidr
                .iter()
                .filter_map(|c| Cidr::parse(c))
                .collect(),
            domains: self
                .network
                .allow
                .iter()
                .map(|d| d.to_ascii_lowercase())
                .collect(),
            network_mode: self.network.effective_mode(),
        })
    }

    pub fn display_name(&self) -> String {
        self.name.clone().unwrap_or_else(|| "unnamed-policy".into())
    }
}

fn check_list(d: &mut Vec<Diagnostic>, name: &str, list: &[String]) {
    if list.len() > MAX_LIST_ENTRIES {
        d.push(Diagnostic::error(format!(
            "{} has more than {} entries",
            name, MAX_LIST_ENTRIES
        )));
    }
    for e in list {
        if e.len() > MAX_ENTRY_LEN {
            d.push(Diagnostic::error(format!(
                "{}: entry longer than {} bytes",
                name, MAX_ENTRY_LEN
            )));
        }
        if e.chars().any(|c| c.is_control()) {
            d.push(Diagnostic::error(format!(
                "{}: entry contains control characters",
                name
            )));
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Level {
    Error,
    Warning,
    Info,
}

#[derive(Debug, Clone, Serialize)]
pub struct Diagnostic {
    pub level: Level,
    pub message: String,
}

impl Diagnostic {
    fn error(m: impl Into<String>) -> Self {
        Diagnostic {
            level: Level::Error,
            message: m.into(),
        }
    }
    fn warning(m: impl Into<String>) -> Self {
        Diagnostic {
            level: Level::Warning,
            message: m.into(),
        }
    }
    fn info(m: impl Into<String>) -> Self {
        Diagnostic {
            level: Level::Info,
            message: m.into(),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Cidr {
    pub addr: IpAddr,
    pub prefix: u8,
}

impl Cidr {
    pub fn parse(s: &str) -> Option<Cidr> {
        let (a, p) = match s.split_once('/') {
            Some((a, p)) => (a, Some(p)),
            None => (s, None),
        };
        let addr: IpAddr = a.parse().ok()?;
        let max = if addr.is_ipv4() { 32 } else { 128 };
        let prefix = match p {
            Some(p) => p.parse::<u8>().ok()?,
            None => max,
        };
        if prefix > max {
            return None;
        }
        Some(Cidr { addr, prefix })
    }

    pub fn contains(&self, ip: &IpAddr) -> bool {
        match (self.addr, ip) {
            (IpAddr::V4(net), IpAddr::V4(ip)) => {
                let mask = if self.prefix == 0 {
                    0
                } else {
                    u32::MAX << (32 - self.prefix)
                };
                (u32::from(net) & mask) == (u32::from(*ip) & mask)
            }
            (IpAddr::V6(net), IpAddr::V6(ip)) => {
                let mask = if self.prefix == 0 {
                    0
                } else {
                    u128::MAX << (128 - self.prefix)
                };
                (u128::from(net) & mask) == (u128::from(*ip) & mask)
            }
            _ => false,
        }
    }
}

/// Bundled policy templates.
pub const TEMPLATES: &[(&str, &str)] = &[
    (
        "offline-research",
        include_str!("../../../policies/offline-research.yaml"),
    ),
    (
        "coding-agent",
        include_str!("../../../policies/coding-agent.yaml"),
    ),
    (
        "untrusted-model-test",
        include_str!("../../../policies/untrusted-model-test.yaml"),
    ),
    (
        "model-evaluation",
        include_str!("../../../policies/model-evaluation.yaml"),
    ),
    (
        "no-network",
        include_str!("../../../policies/no-network.yaml"),
    ),
    (
        "windows-no-network",
        include_str!("../../../policies/windows-no-network.yaml"),
    ),
    (
        "windows-coding-agent",
        include_str!("../../../policies/windows-coding-agent.yaml"),
    ),
];

/// Templates meant for the platform Kill Line is running on.
pub fn templates_for(platform: Platform) -> Vec<(&'static str, &'static str)> {
    TEMPLATES
        .iter()
        .copied()
        .filter(|(n, _)| n.starts_with("windows-") == (platform == Platform::Windows))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn all_templates_are_valid() {
        for (name, text) in TEMPLATES {
            let p = Policy::parse(text).unwrap_or_else(|e| panic!("{}: {:#}", name, e));
            let platform = if name.starts_with("windows-") {
                Platform::Windows
            } else {
                Platform::Linux
            };
            p.compile_for(platform)
                .unwrap_or_else(|e| panic!("{}: {:#}", name, e));
        }
    }

    #[test]
    fn rejects_unknown_fields_and_bad_values() {
        assert!(Policy::parse("agent: a\nnetwrk: {mode: deny}\n").is_err());
        let p = Policy::parse("agent: a\nnetwork: {mode: deny, allow: [github.com]}\n").unwrap();
        assert!(p.compile().is_err());
        let p = Policy::parse("agent: a\nfilesystem: {allow: [relative/path]}\n").unwrap();
        assert!(p.compile().is_err());
        let p = Policy::parse("agent: 'a b'\n").unwrap();
        assert!(p.compile().is_err());
    }

    #[test]
    fn cidr() {
        let c = Cidr::parse("10.0.0.0/24").unwrap();
        assert!(c.contains(&"10.0.0.7".parse().unwrap()));
        assert!(!c.contains(&"10.0.1.7".parse().unwrap()));
        assert!(Cidr::parse("10.0.0.0/33").is_none());
        let c6 = Cidr::parse("fd00::/8").unwrap();
        assert!(c6.contains(&"fd12::1".parse().unwrap()));
    }
}
