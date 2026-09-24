//! `killline run`: start the agent only after the sensor is tracking it.
//!
//! The parent spawns `killline __launch --wait-fd N -- cmd…`, adds the child's
//! PID to the kernel tracking map, then writes one byte to the pipe. The child
//! only then drops privileges and execs the agent, so not a single syscall of
//! the agent happens unobserved.

use anyhow::{bail, Context, Result};
use std::ffi::CString;
use std::os::fd::{FromRawFd, OwnedFd};
use std::process::{Child, Command};

pub struct Launched {
    pub child: Child,
    release: Option<OwnedFd>,
}

impl Launched {
    pub fn release(&mut self) -> Result<()> {
        if let Some(fd) = self.release.take() {
            let mut f = std::fs::File::from(fd);
            use std::io::Write;
            f.write_all(b"1").context("releasing the agent")?;
        }
        Ok(())
    }
}

pub fn spawn(command: &[String], uid: Option<u32>, gid: Option<u32>) -> Result<Launched> {
    let mut fds = [0i32; 2];
    // SAFETY: valid array of two ints. The read end must survive exec in the
    // child, so no O_CLOEXEC on it; the write end is CLOEXEC.
    if unsafe { libc::pipe(fds.as_mut_ptr()) } != 0 {
        bail!("pipe: {}", std::io::Error::last_os_error());
    }
    unsafe { libc::fcntl(fds[1], libc::F_SETFD, libc::FD_CLOEXEC) };
    let exe = std::env::current_exe().context("locating killline binary")?;
    let mut cmd = Command::new(exe);
    cmd.arg("__launch").arg("--wait-fd").arg(fds[0].to_string());
    if let Some(u) = uid {
        cmd.arg("--uid").arg(u.to_string());
    }
    if let Some(g) = gid {
        cmd.arg("--gid").arg(g.to_string());
    }
    cmd.arg("--").args(command);
    let child = cmd.spawn().context("spawning agent launcher")?;
    // SAFETY: we own both fds; the parent no longer needs the read end.
    unsafe { libc::close(fds[0]) };
    let release = unsafe { OwnedFd::from_raw_fd(fds[1]) };
    Ok(Launched {
        child,
        release: Some(release),
    })
}

/// Runs in the child: wait for the monitor, drop privileges, exec.
pub fn exec_after_release(
    wait_fd: i32,
    uid: Option<u32>,
    gid: Option<u32>,
    command: &[String],
) -> Result<i32> {
    let mut b = [0u8; 1];
    // SAFETY: reading into a 1-byte buffer from an inherited fd.
    let n = unsafe { libc::read(wait_fd, b.as_mut_ptr() as *mut _, 1) };
    unsafe { libc::close(wait_fd) };
    if n != 1 {
        bail!("monitor did not release the agent (it may have failed to start)");
    }
    if let Some(g) = gid {
        // SAFETY: plain syscalls; failures are checked.
        if unsafe { libc::setgroups(0, std::ptr::null()) } != 0 || unsafe { libc::setgid(g) } != 0 {
            bail!("setgid({}) failed: {}", g, std::io::Error::last_os_error());
        }
    }
    if let Some(u) = uid {
        if unsafe { libc::setuid(u) } != 0 {
            bail!("setuid({}) failed: {}", u, std::io::Error::last_os_error());
        }
    }
    let args: Vec<CString> = command
        .iter()
        .map(|a| CString::new(a.as_str()))
        .collect::<Result<_, _>>()?;
    let mut argv: Vec<*const libc::c_char> = args.iter().map(|a| a.as_ptr()).collect();
    argv.push(std::ptr::null());
    // SAFETY: argv is NULL-terminated and outlives the call.
    unsafe { libc::execvp(args[0].as_ptr(), argv.as_ptr()) };
    bail!("exec {}: {}", command[0], std::io::Error::last_os_error())
}
