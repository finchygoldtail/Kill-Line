//! KillLine eBPF sensor.
//!
//! Loads the kernel program, scopes it to one agent (a PID tree or a
//! container's PID namespace), and yields decoded [`Observation`]s. It also
//! reports its own coverage and any dropped events, so the monitor can go
//! GREY instead of pretending to see everything.

pub mod decode;
pub mod raw;
pub mod respond;
pub mod target;

use anyhow::{anyhow, bail, Context, Result};
use aya::maps::{Array, HashMap as BpfHashMap, MapData, RingBuf};
use aya::programs::{FEntry, TracePoint};
use aya::{Btf, Ebpf, EbpfLoader};
use killline_core::event::Observation;
use killline_core::session::CoverageItem;
use raw::KlConfig;
use std::os::fd::AsRawFd;

// The object crate parses ELF headers in place, so the bytes must be aligned.
static BPF_OBJECT: &[u8] = aya::include_bytes_aligned!(concat!(env!("OUT_DIR"), "/killline.bpf.o"));

/// (program, tracepoint category, tracepoint name, critical, what is lost without it)
const TRACEPOINTS: &[(&str, &str, &str, bool, &str)] = &[
    ("kl_fork", "sched", "sched_process_fork", true, "child processes would not be tracked"),
    ("kl_exit", "sched", "sched_process_exit", true, "process exits"),
    ("kl_execve", "syscalls", "sys_enter_execve", true, "program execution"),
    ("kl_execveat", "syscalls", "sys_enter_execveat", false, "execveat() program execution"),
    ("kl_open", "syscalls", "sys_enter_open", false, "legacy open() calls"),
    ("kl_creat", "syscalls", "sys_enter_creat", false, "creat() calls"),
    ("kl_openat", "syscalls", "sys_enter_openat", true, "file opens"),
    ("kl_openat2", "syscalls", "sys_enter_openat2", false, "openat2() calls"),
    ("kl_unlinkat", "syscalls", "sys_enter_unlinkat", false, "file deletion"),
    ("kl_unlink", "syscalls", "sys_enter_unlink", false, "file deletion"),
    ("kl_rmdir", "syscalls", "sys_enter_rmdir", false, "directory deletion"),
    ("kl_renameat2", "syscalls", "sys_enter_renameat2", false, "renames"),
    ("kl_renameat", "syscalls", "sys_enter_renameat", false, "renames"),
    ("kl_rename", "syscalls", "sys_enter_rename", false, "renames"),
    ("kl_fchmodat", "syscalls", "sys_enter_fchmodat", false, "permission changes"),
    ("kl_chmod", "syscalls", "sys_enter_chmod", false, "permission changes"),
    ("kl_fchmod", "syscalls", "sys_enter_fchmod", false, "permission changes"),
    ("kl_connect", "syscalls", "sys_enter_connect", true, "outbound connections"),
    ("kl_sendto", "syscalls", "sys_enter_sendto", true, "UDP sends and DNS queries"),
    ("kl_sendmsg", "syscalls", "sys_enter_sendmsg", true, "sendmsg() traffic"),
    ("kl_sendmmsg", "syscalls", "sys_enter_sendmmsg", false, "sendmmsg() DNS queries"),
    ("kl_bind", "syscalls", "sys_enter_bind", false, "listening sockets"),
    ("kl_socket", "syscalls", "sys_enter_socket", false, "socket creation"),
    ("kl_setuid", "syscalls", "sys_enter_setuid", false, "setuid"),
    ("kl_setreuid", "syscalls", "sys_enter_setreuid", false, "setreuid"),
    ("kl_setresuid", "syscalls", "sys_enter_setresuid", false, "setresuid"),
    ("kl_setgid", "syscalls", "sys_enter_setgid", false, "setgid"),
    ("kl_setregid", "syscalls", "sys_enter_setregid", false, "setregid"),
    ("kl_setresgid", "syscalls", "sys_enter_setresgid", false, "setresgid"),
    ("kl_capset", "syscalls", "sys_enter_capset", false, "capability changes"),
    ("kl_unshare", "syscalls", "sys_enter_unshare", false, "namespace creation"),
    ("kl_setns", "syscalls", "sys_enter_setns", false, "namespace entry"),
    ("kl_ptrace", "syscalls", "sys_enter_ptrace", false, "ptrace"),
    ("kl_kill", "syscalls", "sys_enter_kill", false, "signals (tamper detection)"),
    ("kl_tgkill", "syscalls", "sys_enter_tgkill", false, "thread signals"),
    ("kl_bpf", "syscalls", "sys_enter_bpf", false, "bpf() use"),
    ("kl_init_module", "syscalls", "sys_enter_init_module", false, "kernel module loading"),
    ("kl_finit_module", "syscalls", "sys_enter_finit_module", false, "kernel module loading"),
    ("kl_mount", "syscalls", "sys_enter_mount", false, "mounts"),
    ("kl_umount", "syscalls", "sys_enter_umount", false, "unmounts"),
    ("kl_chroot", "syscalls", "sys_enter_chroot", false, "chroot"),
    ("kl_pivot_root", "syscalls", "sys_enter_pivot_root", false, "pivot_root"),
];

/// Syscall-result hooks: whether an attempt was refused or succeeded.
const RESULT_HOOKS: &[&str] = &[
    "open", "creat", "openat", "openat2", "execve", "execveat", "connect", "bind", "unlinkat", "unlink", "rmdir",
    "renameat2", "renameat", "rename", "fchmodat", "chmod", "mount", "unshare", "setns", "ptrace", "chroot",
    "pivot_root",
];

pub struct Sensor {
    bpf: Ebpf,
    ring: RingBuf<MapData>,
    decoder: decode::Decoder,
    coverage: Vec<CoverageItem>,
}

/// Which processes belong to the monitored agent.
#[derive(Debug, Clone)]
pub struct Scope {
    /// PIDs to track from the start (their descendants are added in-kernel).
    pub pids: Vec<u32>,
    /// Container mode: adopt every process in this PID namespace.
    pub pidns: Option<u32>,
}

impl Sensor {
    pub fn built_with_bpf() -> bool {
        !BPF_OBJECT.is_empty()
    }

    pub fn start(scope: &Scope) -> Result<Sensor> {
        if !Self::built_with_bpf() {
            bail!("this build of KillLine has no eBPF program (clang/libbpf-dev were missing at build time)");
        }
        raise_memlock();
        let btf = Btf::from_sys_fs().context(
            "kernel BTF (/sys/kernel/btf/vmlinux) is unavailable; KillLine needs a kernel built with CONFIG_DEBUG_INFO_BTF",
        )?;
        let mut bpf = EbpfLoader::new()
            .btf(Some(&btf))
            .load(BPF_OBJECT)
            .context("loading the eBPF program (are you root / do you have CAP_BPF + CAP_PERFMON?)")?;

        // Configure scope *before* attaching so no event is evaluated without it.
        {
            let mut cfg: Array<_, KlConfig> = Array::try_from(bpf.map_mut("config").ok_or_else(|| anyhow!("config map missing"))?)?;
            cfg.set(0, KlConfig { target_pidns: scope.pidns.unwrap_or(0), monitor_tgid: std::process::id() }, 0)?;
        }
        {
            let mut tracked: BpfHashMap<_, u32, u8> =
                BpfHashMap::try_from(bpf.map_mut("tracked").ok_or_else(|| anyhow!("tracked map missing"))?)?;
            for pid in &scope.pids {
                tracked.insert(pid, 1, 0)?;
            }
        }

        let mut coverage = Vec::new();
        for (prog, cat, name, critical, what) in TRACEPOINTS {
            let res = (|| -> Result<()> {
                let tp: &mut TracePoint = bpf.program_mut(prog).ok_or_else(|| anyhow!("program {} missing", prog))?.try_into()?;
                tp.load()?;
                tp.attach(cat, name)?;
                Ok(())
            })();
            coverage.push(CoverageItem {
                name: format!("{}/{}", cat, name),
                active: res.is_ok(),
                critical: *critical,
                detail: res.err().map(|e| format!("unavailable ({}): {} not observed", root_cause(&e), what)),
            });
        }
        let mut failed_results = Vec::new();
        for name in RESULT_HOOKS {
            let prog = format!("kl_ret_{}", name);
            let res = (|| -> Result<()> {
                let tp: &mut TracePoint = bpf.program_mut(&prog).ok_or_else(|| anyhow!("program {} missing", prog))?.try_into()?;
                tp.load()?;
                tp.attach("syscalls", &format!("sys_exit_{}", name))?;
                Ok(())
            })();
            if let Err(e) = res {
                failed_results.push(format!("{} ({})", name, root_cause(&e)));
            }
        }
        let core_results_ok = !failed_results.iter().any(|f| f.starts_with("openat ") || f.starts_with("connect ") || f.starts_with("execve "));
        coverage.push(CoverageItem {
            name: "syscall results (sys_exit_*)".into(),
            active: core_results_ok,
            critical: false,
            detail: if failed_results.is_empty() {
                None
            } else {
                Some(format!(
                    "partially unavailable: {}; blocked-vs-succeeded is not known for those calls",
                    failed_results.join(", ")
                ))
            },
        });

        let res = (|| -> Result<()> {
            let p: &mut FEntry = bpf.program_mut("kl_file_open").ok_or_else(|| anyhow!("kl_file_open missing"))?.try_into()?;
            p.load("security_file_open", &btf)?;
            p.attach()?;
            Ok(())
        })();
        coverage.push(CoverageItem {
            name: "fentry/security_file_open".into(),
            active: res.is_ok(),
            critical: false,
            detail: res.err().map(|e| {
                format!(
                    "unavailable ({}): kernel-resolved paths are not observed; falling back to userspace \
                     symlink resolution, which is racy",
                    root_cause(&e)
                )
            }),
        });

        let ring = RingBuf::try_from(bpf.take_map("events").ok_or_else(|| anyhow!("events map missing"))?)?;
        let mut decoder = decode::Decoder::new();
        decoder.results_enabled = core_results_ok;
        Ok(Sensor { bpf, ring, decoder, coverage })
    }

    pub fn coverage(&self) -> &[CoverageItem] {
        &self.coverage
    }

    /// Wait up to `timeout_ms` for events, then drain up to `max` of them.
    pub fn poll(&mut self, timeout_ms: i32, max: usize, out: &mut Vec<Observation>) -> Result<usize> {
        let mut pfd = libc::pollfd { fd: self.ring.as_raw_fd(), events: libc::POLLIN, revents: 0 };
        // SAFETY: one valid pollfd.
        let rc = unsafe { libc::poll(&mut pfd, 1, timeout_ms) };
        if rc < 0 {
            let e = std::io::Error::last_os_error();
            if e.kind() != std::io::ErrorKind::Interrupted {
                return Err(e.into());
            }
        }
        let mut n = 0;
        while n < max {
            let Some(item) = self.ring.next() else { break };
            self.decoder.feed(&item, out);
            drop(item);
            n += 1;
        }
        self.decoder.flush_stale(std::time::Duration::from_millis(250), out);
        Ok(n)
    }

    /// Events the kernel could not deliver because the ring buffer was full.
    pub fn dropped(&self) -> Result<u64> {
        let stats: Array<_, u64> = Array::try_from(self.bpf.map("stats").ok_or_else(|| anyhow!("stats map missing"))?)?;
        Ok(stats.get(&0, 0)?)
    }

    pub fn tracked_pids(&self) -> Result<Vec<u32>> {
        let tracked: BpfHashMap<_, u32, u8> =
            BpfHashMap::try_from(self.bpf.map("tracked").ok_or_else(|| anyhow!("tracked map missing"))?)?;
        Ok(tracked.keys().filter_map(|k| k.ok()).collect())
    }

    pub fn track(&mut self, pid: u32) -> Result<()> {
        let mut tracked: BpfHashMap<_, u32, u8> =
            BpfHashMap::try_from(self.bpf.map_mut("tracked").ok_or_else(|| anyhow!("tracked map missing"))?)?;
        tracked.insert(pid, 1, 0)?;
        Ok(())
    }
}

fn root_cause(e: &anyhow::Error) -> String {
    let mut s = e.to_string();
    if let Some(src) = e.chain().last() {
        s = src.to_string();
    }
    s
}

fn raise_memlock() {
    // Kernels < 5.11 account BPF memory against RLIMIT_MEMLOCK.
    let r = libc::rlimit { rlim_cur: libc::RLIM_INFINITY, rlim_max: libc::RLIM_INFINITY };
    // SAFETY: valid rlimit struct.
    unsafe { libc::setrlimit(libc::RLIMIT_MEMLOCK, &r) };
}
