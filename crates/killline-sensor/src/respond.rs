//! Optional enforcement (Phase 3). Off by default.
//!
//! These actions happen *after* the triggering system call: Kill Line
//! observes, it does not prevent. Freezing preserves state for inspection.

use anyhow::{bail, Context, Result};
use std::process::Command;

#[derive(Debug, Clone)]
pub enum Handle {
    Container(String),
    Pids,
}

fn docker(args: &[&str]) -> Result<()> {
    let out = Command::new("docker")
        .args(args)
        .output()
        .context("running docker")?;
    if !out.status.success() {
        bail!(
            "docker {}: {}",
            args.join(" "),
            String::from_utf8_lossy(&out.stderr).trim()
        );
    }
    Ok(())
}

fn signal_all(pids: &[u32], sig: i32) -> usize {
    let me = std::process::id();
    let mut n = 0;
    for &p in pids {
        if p <= 1 || p == me {
            continue;
        }
        // SAFETY: plain kill(2).
        if unsafe { libc::kill(p as i32, sig) } == 0 {
            n += 1;
        }
    }
    n
}

/// Freeze the agent. Containers use the cgroup freezer via `docker pause`;
/// process trees get SIGSTOP (twice, to catch children forked in between).
pub fn freeze(h: &Handle, pids: &dyn Fn() -> Vec<u32>) -> Result<String> {
    match h {
        Handle::Container(id) => {
            docker(&["pause", id])?;
            Ok(format!("container {} paused (cgroup freezer)", short(id)))
        }
        Handle::Pids => {
            let n = signal_all(&pids(), libc::SIGSTOP) + signal_all(&pids(), libc::SIGSTOP);
            Ok(format!("sent SIGSTOP to {} process(es)", n))
        }
    }
}

pub fn terminate(h: &Handle, pids: &dyn Fn() -> Vec<u32>) -> Result<String> {
    match h {
        Handle::Container(id) => {
            docker(&["kill", id])?;
            Ok(format!("container {} killed", short(id)))
        }
        Handle::Pids => {
            let n = signal_all(&pids(), libc::SIGKILL) + signal_all(&pids(), libc::SIGKILL);
            Ok(format!("sent SIGKILL to {} process(es)", n))
        }
    }
}

/// Undo a freeze: `docker unpause`, or SIGCONT to the tracked processes.
pub fn resume(h: &Handle, pids: &dyn Fn() -> Vec<u32>) -> Result<String> {
    match h {
        Handle::Container(id) => {
            docker(&["unpause", id])?;
            Ok(format!("container {} unpaused", short(id)))
        }
        Handle::Pids => {
            let n = signal_all(&pids(), libc::SIGCONT);
            Ok(format!("sent SIGCONT to {} process(es)", n))
        }
    }
}

fn short(id: &str) -> &str {
    &id[..id.len().min(12)]
}
