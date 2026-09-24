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

#[derive(Clone, Copy, PartialEq, Eq)]
enum ProcAction {
    Suspend,
    Resume,
    Kill,
}

/// Apply an action to every tracked process; returns how many succeeded.
fn act_all(pids: &[u32], action: ProcAction) -> usize {
    let me = std::process::id();
    pids.iter()
        .filter(|&&p| p > 4 && p != me)
        .filter(|&&p| act_one(p, action))
        .count()
}

#[cfg(unix)]
fn act_one(pid: u32, action: ProcAction) -> bool {
    let sig = match action {
        ProcAction::Suspend => libc::SIGSTOP,
        ProcAction::Resume => libc::SIGCONT,
        ProcAction::Kill => libc::SIGKILL,
    };
    // SAFETY: plain kill(2).
    unsafe { libc::kill(pid as i32, sig) == 0 }
}

#[cfg(windows)]
fn act_one(pid: u32, action: ProcAction) -> bool {
    use windows_sys::Win32::Foundation::{CloseHandle, HANDLE};
    use windows_sys::Win32::System::Threading::{
        OpenProcess, TerminateProcess, PROCESS_SUSPEND_RESUME, PROCESS_TERMINATE,
    };
    #[link(name = "ntdll")]
    extern "system" {
        fn NtSuspendProcess(h: HANDLE) -> i32;
        fn NtResumeProcess(h: HANDLE) -> i32;
    }
    let access = if action == ProcAction::Kill {
        PROCESS_TERMINATE
    } else {
        PROCESS_SUSPEND_RESUME
    };
    // SAFETY: handle is checked and closed; the ntdll calls take a process handle.
    unsafe {
        let h = OpenProcess(access, 0, pid);
        if h.is_null() {
            return false;
        }
        let ok = match action {
            ProcAction::Suspend => NtSuspendProcess(h) >= 0,
            ProcAction::Resume => NtResumeProcess(h) >= 0,
            ProcAction::Kill => TerminateProcess(h, 1) != 0,
        };
        CloseHandle(h);
        ok
    }
}

#[cfg(not(any(unix, windows)))]
fn act_one(_pid: u32, _action: ProcAction) -> bool {
    false
}

/// Freeze the agent. Containers use the cgroup freezer via `docker pause`;
/// process trees are suspended (SIGSTOP on Linux, NtSuspendProcess on
/// Windows), twice to catch children created in between.
pub fn freeze(h: &Handle, pids: &dyn Fn() -> Vec<u32>) -> Result<String> {
    match h {
        Handle::Container(id) => {
            docker(&["pause", id])?;
            Ok(format!("container {} paused (cgroup freezer)", short(id)))
        }
        Handle::Pids => {
            let n = act_all(&pids(), ProcAction::Suspend) + act_all(&pids(), ProcAction::Suspend);
            Ok(format!("suspended {} process(es)", n))
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
            let n = act_all(&pids(), ProcAction::Kill) + act_all(&pids(), ProcAction::Kill);
            Ok(format!("terminated {} process(es)", n))
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
            let n = act_all(&pids(), ProcAction::Resume);
            Ok(format!("resumed {} process(es)", n))
        }
    }
}

fn short(id: &str) -> &str {
    &id[..id.len().min(12)]
}
