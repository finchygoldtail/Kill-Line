//! Resolve what "the agent" is: a container, a PID tree, or a command we
//! launch ourselves.

#[cfg(target_os = "linux")]
use anyhow::Context;
use anyhow::{bail, Result};
#[cfg(target_os = "linux")]
use std::process::Command;

#[derive(Debug, Clone)]
pub struct ContainerInfo {
    pub id: String,
    pub name: String,
    pub init_pid: u32,
    pub pidns: u32,
}

#[cfg(target_os = "linux")]
/// Namespace inode of /proc/<pid>/ns/<kind>, e.g. "pid:[4026532201]".
pub fn ns_inode(pid: u32, kind: &str) -> Result<u32> {
    let link = std::fs::read_link(format!("/proc/{}/ns/{}", pid, kind))
        .with_context(|| format!("reading /proc/{}/ns/{}", pid, kind))?;
    let s = link.to_string_lossy();
    let inner = s
        .split('[')
        .nth(1)
        .and_then(|x| x.strip_suffix(']'))
        .context("unexpected ns link format")?;
    Ok(inner.parse()?)
}

#[cfg(target_os = "linux")]
fn valid_container_ref(s: &str) -> bool {
    !s.is_empty()
        && s.len() <= 128
        && s.chars()
            .all(|c| c.is_ascii_alphanumeric() || "_.-".contains(c))
}

#[cfg(target_os = "linux")]
/// Look a container up through the Docker CLI. Kill Line only reads
/// (`docker inspect`); it never changes container configuration.
pub fn docker_container(name: &str) -> Result<ContainerInfo> {
    if !valid_container_ref(name) {
        bail!("invalid container name or id");
    }
    let out = Command::new("docker")
        .args([
            "inspect",
            "--type",
            "container",
            "--format",
            "{{.Id}} {{.Name}} {{.State.Pid}} {{.State.Running}}",
            name,
        ])
        .output()
        .context("running `docker inspect` (is the Docker CLI installed?)")?;
    if !out.status.success() {
        bail!(
            "docker inspect failed: {}",
            String::from_utf8_lossy(&out.stderr).trim()
        );
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
    Ok(ContainerInfo {
        id: f[0].to_string(),
        name: f[1].trim_start_matches('/').to_string(),
        init_pid,
        pidns,
    })
}

#[cfg(target_os = "linux")]
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

#[cfg(target_os = "linux")]
/// A PID and all its current descendants.
pub fn pid_tree(root: u32) -> Vec<u32> {
    let mut parent_of = Vec::new();
    if let Ok(rd) = std::fs::read_dir("/proc") {
        for e in rd.flatten() {
            if let Ok(pid) = e.file_name().to_string_lossy().parse::<u32>() {
                if let Ok(stat) = std::fs::read_to_string(format!("/proc/{}/stat", pid)) {
                    // Field 4 after the parenthesised comm.
                    if let Some(rest) = stat.rsplit_once(')').map(|(_, r)| r) {
                        if let Some(ppid) = rest
                            .split_whitespace()
                            .nth(1)
                            .and_then(|p| p.parse::<u32>().ok())
                        {
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

#[cfg(not(target_os = "linux"))]
pub fn docker_container(_name: &str) -> Result<ContainerInfo> {
    bail!("container monitoring is Linux-only in this version; monitor a process with --pid or `killline run` instead")
}

/// Does a process with this PID exist?
pub fn pid_exists(pid: u32) -> bool {
    #[cfg(target_os = "linux")]
    {
        std::path::Path::new(&format!("/proc/{}", pid)).exists()
    }
    #[cfg(windows)]
    {
        snapshot().iter().any(|(p, _, _)| *p == pid)
    }
    #[cfg(not(any(target_os = "linux", windows)))]
    {
        let _ = pid;
        false
    }
}

/// (pid, parent pid, exe name) of every process, from a Toolhelp snapshot.
#[cfg(windows)]
pub fn snapshot() -> Vec<(u32, u32, String)> {
    use windows_sys::Win32::Foundation::{CloseHandle, INVALID_HANDLE_VALUE};
    use windows_sys::Win32::System::Diagnostics::ToolHelp::{
        CreateToolhelp32Snapshot, Process32FirstW, Process32NextW, PROCESSENTRY32W,
        TH32CS_SNAPPROCESS,
    };
    let mut out = Vec::new();
    // SAFETY: standard Toolhelp iteration; the snapshot handle is closed.
    unsafe {
        let snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
        if snap == INVALID_HANDLE_VALUE {
            return out;
        }
        let mut e: PROCESSENTRY32W = std::mem::zeroed();
        e.dwSize = std::mem::size_of::<PROCESSENTRY32W>() as u32;
        let mut ok = Process32FirstW(snap, &mut e);
        while ok != 0 {
            let len = e
                .szExeFile
                .iter()
                .position(|&c| c == 0)
                .unwrap_or(e.szExeFile.len());
            out.push((
                e.th32ProcessID,
                e.th32ParentProcessID,
                String::from_utf16_lossy(&e.szExeFile[..len]),
            ));
            ok = Process32NextW(snap, &mut e);
        }
        CloseHandle(snap);
    }
    out
}

/// A PID and all its current descendants.
#[cfg(windows)]
pub fn pid_tree(root: u32) -> Vec<u32> {
    let procs = snapshot();
    let mut out = vec![root];
    let mut i = 0;
    while i < out.len() {
        let p = out[i];
        for (c, pp, _) in &procs {
            // PID 0/4 are the idle and System processes; never descend from them.
            if *pp == p && *c > 4 && !out.contains(c) {
                out.push(*c);
            }
        }
        i += 1;
    }
    out
}
