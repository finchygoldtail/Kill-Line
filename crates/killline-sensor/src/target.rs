//! Resolve what "the agent" is: a container, a PID tree, or a command we
//! launch ourselves.

use anyhow::{bail, Context, Result};
use std::process::Command;

#[derive(Debug, Clone)]
pub struct ContainerInfo {
    pub id: String,
    pub name: String,
    pub init_pid: u32,
    pub pidns: u32,
}

/// Namespace inode of /proc/<pid>/ns/<kind>, e.g. "pid:[4026532201]".
pub fn ns_inode(pid: u32, kind: &str) -> Result<u32> {
    let link = std::fs::read_link(format!("/proc/{}/ns/{}", pid, kind))
        .with_context(|| format!("reading /proc/{}/ns/{}", pid, kind))?;
    let s = link.to_string_lossy();
    let inner = s.split('[').nth(1).and_then(|x| x.strip_suffix(']')).context("unexpected ns link format")?;
    Ok(inner.parse()?)
}

fn valid_container_ref(s: &str) -> bool {
    !s.is_empty() && s.len() <= 128 && s.chars().all(|c| c.is_ascii_alphanumeric() || "_.-".contains(c))
}

/// Look a container up through the Docker CLI. KillLine only reads
/// (`docker inspect`); it never changes container configuration.
pub fn docker_container(name: &str) -> Result<ContainerInfo> {
    if !valid_container_ref(name) {
        bail!("invalid container name or id");
    }
    let out = Command::new("docker")
        .args(["inspect", "--type", "container", "--format", "{{.Id}} {{.Name}} {{.State.Pid}} {{.State.Running}}", name])
        .output()
        .context("running `docker inspect` (is the Docker CLI installed?)")?;
    if !out.status.success() {
        bail!("docker inspect failed: {}", String::from_utf8_lossy(&out.stderr).trim());
    }
    let text = String::from_utf8_lossy(&out.stdout);
    let f: Vec<&str> = text.split_whitespace().collect();
    if f.len() != 4 {
        bail!("unexpected docker inspect output");
    }
    if f[3] != "true" {
        bail!("container {} is not running", name);
    }
    let init_pid: u32 = f[2].parse()?;
    let host_pidns = ns_inode(1, "pid").ok();
    let pidns = ns_inode(init_pid, "pid")?;
    if Some(pidns) == host_pidns {
        bail!("container {} shares the host PID namespace (--pid=host); container scoping is impossible. Use --pid instead.", name);
    }
    Ok(ContainerInfo { id: f[0].to_string(), name: f[1].trim_start_matches('/').to_string(), init_pid, pidns })
}

/// All current processes in a PID namespace (to seed tracking).
pub fn pids_in_ns(pidns: u32) -> Vec<u32> {
    let mut out = Vec::new();
    if let Ok(rd) = std::fs::read_dir("/proc") {
        for e in rd.flatten() {
            if let Ok(pid) = e.file_name().to_string_lossy().parse::<u32>() {
                if ns_inode(pid, "pid").ok() == Some(pidns) {
                    out.push(pid);
                }
            }
        }
    }
    out
}

/// A PID and all its current descendants.
pub fn pid_tree(root: u32) -> Vec<u32> {
    let mut parent_of = Vec::new();
    if let Ok(rd) = std::fs::read_dir("/proc") {
        for e in rd.flatten() {
            if let Ok(pid) = e.file_name().to_string_lossy().parse::<u32>() {
                if let Ok(stat) = std::fs::read_to_string(format!("/proc/{}/stat", pid)) {
                    // Field 4 after the parenthesised comm.
                    if let Some(rest) = stat.rsplit_once(')').map(|(_, r)| r) {
                        if let Some(ppid) = rest.split_whitespace().nth(1).and_then(|p| p.parse::<u32>().ok()) {
                            parent_of.push((pid, ppid));
                        }
                    }
                }
            }
        }
    }
    let mut out = vec![root];
    let mut i = 0;
    while i < out.len() {
        let p = out[i];
        for (c, pp) in &parent_of {
            if *pp == p && !out.contains(c) {
                out.push(*c);
            }
        }
        i += 1;
    }
    out
}
