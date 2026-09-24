//! Turn raw kernel records into [`Observation`]s: resolve relative paths,
//! parse socket addresses and DNS queries, hash executables and redact
//! command lines.

use crate::raw::*;
use chrono::{DateTime, TimeZone, Utc};
use killline_core::event::*;
use killline_core::pathmatch;
use killline_core::redact::redact_argv;
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::io::Read;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

const AT_FDCWD: i64 = -100;
const O_ACCMODE: u64 = 3;
const O_CREAT: u64 = 0o100;
const O_TRUNC: u64 = 0o1000;
const O_APPEND: u64 = 0o2000;
const O_DIRECTORY: u64 = 0o200000;
const O_PATH: u64 = 0o10000000;
const FMODE_WRITE: u64 = 0x2;

/// Executables larger than this are not hashed.
const MAX_HASH_BYTES: u64 = 256 * 1024 * 1024;

/// A syscall entry waiting for its return value.
struct Pending {
    primary: Option<Observation>,
    /// Kernel-resolved open events of the same syscall, released after it.
    companions: Vec<Observation>,
    since: std::time::Instant,
}

/// Entry records whose syscall has a result hook.
fn has_result(r: &RawEvent) -> bool {
    matches!(
        r.kind,
        KL_EXEC
            | KL_OPEN
            | KL_CONNECT
            | KL_BIND
            | KL_UNLINK
            | KL_RENAME
            | KL_MOUNT
            | KL_UNSHARE
            | KL_SETNS
            | KL_PTRACE
            | KL_CHROOT
            | KL_PIVOT_ROOT
    ) || (r.kind == KL_CHMOD && r.a2 != 1)
}

pub struct Decoder {
    pending: HashMap<u32, Pending>,
    /// False if the result hooks could not be attached: then nothing is held.
    pub results_enabled: bool,
    /// realtime_ns - boottime_ns, to convert kernel timestamps.
    boot_offset_ns: i128,
    hash_cache: HashMap<(String, u64, i64), String>,
    /// (tgid, fd) -> DNS server address, from connect() to port 53.
    dns_servers: HashMap<(u32, i64), IpAddr>,
    /// (pid, directory) recently verified not to be a symlink.
    dir_cache: HashMap<(u32, String), std::time::Instant>,
}

/// How long a "directory is not a symlink" result is trusted. Symlink
/// resolution from userspace is racy anyway; this bounds the extra window.
const DIR_CACHE_TTL: std::time::Duration = std::time::Duration::from_secs(1);

fn clock_ns(clock: libc::clockid_t) -> i128 {
    let mut ts = libc::timespec {
        tv_sec: 0,
        tv_nsec: 0,
    };
    // SAFETY: valid pointer to a timespec.
    unsafe { libc::clock_gettime(clock, &mut ts) };
    ts.tv_sec as i128 * 1_000_000_000 + ts.tv_nsec as i128
}

impl Default for Decoder {
    fn default() -> Self {
        Self::new()
    }
}

impl Decoder {
    pub fn new() -> Decoder {
        let offset = clock_ns(libc::CLOCK_REALTIME) - clock_ns(libc::CLOCK_BOOTTIME);
        Decoder {
            pending: HashMap::new(),
            results_enabled: true,
            boot_offset_ns: offset,
            hash_cache: HashMap::new(),
            dns_servers: HashMap::new(),
            dir_cache: HashMap::new(),
        }
    }

    fn realpath(&mut self, pid: u32, path: &str) -> Option<String> {
        if self.dir_cache.len() > 50_000 {
            self.dir_cache.clear();
        }
        let cache = &mut self.dir_cache;
        realpath_in_root_cached(
            pid,
            path,
            &mut |dir: &str, check: &mut dyn FnMut() -> bool| {
                let key = (pid, dir.to_string());
                if let Some(t) = cache.get(&key) {
                    if t.elapsed() < DIR_CACHE_TTL {
                        return false;
                    }
                }
                let is_link = check();
                if !is_link {
                    cache.insert(key, std::time::Instant::now());
                }
                is_link
            },
        )
    }

    /// Feed one ring-buffer record. Completed observations are appended to
    /// `out`; entries with a result hook are held until their result arrives.
    pub fn feed(&mut self, bytes: &[u8], out: &mut Vec<Observation>) {
        let Some(kind) = record_kind(bytes) else {
            return;
        };
        if kind == KL_RESULT {
            if let Some((tid, ret)) = result_fields(bytes) {
                if let Some(p) = self.pending.remove(&tid) {
                    if let Some(mut o) = p.primary {
                        o.outcome = Some(Outcome::from_ret(ret));
                        out.push(o);
                    }
                    out.extend(p.companions);
                }
            }
            return;
        }
        let Some(raw) = RawEvent::from_bytes(bytes) else {
            return;
        };
        let obs = self.decode(&raw);
        if self.results_enabled && has_result(&raw) {
            if let Some(prev) = self.pending.remove(&raw.tid) {
                // The previous syscall's result was lost; release it as-is.
                Self::release(prev, out);
            }
            self.pending.insert(
                raw.tid,
                Pending {
                    primary: obs,
                    companions: vec![],
                    since: std::time::Instant::now(),
                },
            );
            return;
        }
        if raw.kind == KL_FILE_OPENED {
            if let Some(p) = self.pending.get_mut(&raw.tid) {
                if let Some(o) = obs {
                    p.companions.push(o);
                }
                return;
            }
        }
        if let Some(o) = obs {
            out.push(o);
        }
    }

    fn release(p: Pending, out: &mut Vec<Observation>) {
        if let Some(o) = p.primary {
            out.push(o);
        }
        out.extend(p.companions);
    }

    /// Release entries whose result did not arrive in time (outcome unknown).
    pub fn flush_stale(&mut self, max_age: std::time::Duration, out: &mut Vec<Observation>) {
        let stale: Vec<u32> = self
            .pending
            .iter()
            .filter(|(_, p)| p.since.elapsed() >= max_age)
            .map(|(t, _)| *t)
            .collect();
        for t in stale {
            if let Some(p) = self.pending.remove(&t) {
                Self::release(p, out);
            }
        }
    }

    fn timestamp(&self, ts_ns: u64) -> DateTime<Utc> {
        let ns = ts_ns as i128 + self.boot_offset_ns;
        Utc.timestamp_nanos(ns as i64)
    }

    pub fn decode(&mut self, r: &RawEvent) -> Option<Observation> {
        let process = ProcessInfo {
            pid: r.tgid,
            tid: r.tid,
            ppid: r.ppid,
            uid: r.uid,
            gid: r.gid,
            comm: cstr(&r.comm),
            exe: None,
        };
        let pid = r.tgid;
        let kind = match r.kind {
            KL_EXEC => {
                let raw_path = cstr(&r.path);
                let (path, _) = resolve_at(pid, r.dfd, &raw_path);
                let mut argv = Vec::new();
                for i in 0..ARG_SLOTS {
                    let s = cstr(&r.path2[i * ARG_SLOT..(i + 1) * ARG_SLOT]);
                    if s.is_empty() {
                        break;
                    }
                    argv.push(s);
                }
                let exists = !path.starts_with('/')
                    || std::fs::symlink_metadata(format!("/proc/{}/root{}", pid, path)).is_ok()
                    || !std::path::Path::new(&format!("/proc/{}", pid)).exists();
                let sha256 = if exists {
                    self.hash_exe(pid, &path)
                } else {
                    None
                };
                ObsKind::Exec {
                    path,
                    argv: redact_argv(&argv),
                    sha256,
                    exists,
                }
            }
            KL_FORK => ObsKind::Fork {
                child_pid: r.a0 as u32,
            },
            KL_EXIT => ObsKind::Exit,
            KL_OPEN => {
                let raw_path = cstr(&r.path);
                let (path, mut resolution) = resolve_at(pid, r.dfd, &raw_path);
                let mut via = None;
                if resolution == "lexical" {
                    if let Some(real) = self.realpath(pid, &path) {
                        if real != path {
                            via = Some(path.clone());
                            resolution = "userspace-realpath".into();
                            return Some(Observation {
                                timestamp: self.timestamp(r.ts_ns),
                                process,
                                kind: ObsKind::Open {
                                    path: real,
                                    access: access_from_flags(r.a0),
                                    flags: r.a0,
                                    resolution,
                                    via,
                                },
                                runtime_setup: r.flags & KL_F_RUNTIME_SETUP != 0,
                                outcome: None,
                            });
                        }
                    }
                }
                ObsKind::Open {
                    path,
                    access: access_from_flags(r.a0),
                    flags: r.a0,
                    resolution,
                    via,
                }
            }
            KL_FILE_OPENED => {
                let path = cstr(&r.path);
                if path.is_empty() {
                    return None;
                }
                let path = path.strip_suffix(" (deleted)").unwrap_or(&path).to_string();
                let access = if r.a1 & FMODE_WRITE != 0 {
                    FileAccess::Write
                } else if r.a0 & O_PATH != 0 {
                    FileAccess::Path
                } else {
                    FileAccess::Read
                };
                ObsKind::Open {
                    path,
                    access,
                    flags: r.a0,
                    resolution: "kernel".into(),
                    via: None,
                }
            }
            KL_CONNECT | KL_SENDTO | KL_BIND => {
                let op = match r.kind {
                    KL_CONNECT => NetOp::Connect,
                    KL_SENDTO => NetOp::Send,
                    _ => NetOp::Bind,
                };
                match r.family as i32 {
                    libc::AF_INET | libc::AF_INET6 => {
                        let addr = ip_from(r.family, &r.addr);
                        if op == NetOp::Connect && r.port == 53 {
                            self.dns_servers.insert((pid, r.dfd), addr);
                            if self.dns_servers.len() > 4096 {
                                self.dns_servers.clear();
                            }
                        }
                        ObsKind::Net {
                            op,
                            addr,
                            port: r.port,
                        }
                    }
                    libc::AF_UNIX if op == NetOp::Connect || op == NetOp::Send => {
                        let alen = (r.a1 as usize).saturating_sub(2).min(108);
                        let bytes = &r.path[..alen.clamp(1, 108)];
                        let abstract_ns = bytes.first() == Some(&0);
                        let path = if abstract_ns {
                            cstr(&bytes[1..])
                        } else {
                            cstr(bytes)
                        };
                        if path.is_empty() && !abstract_ns {
                            return None;
                        }
                        ObsKind::UnixConnect { path, abstract_ns }
                    }
                    _ => return None,
                }
            }
            KL_DNS => {
                let len = (r.a2 as usize).min(ARGS_LEN);
                let query = parse_dns_query(&r.path2[..len]);
                let server = if r.family != 0 {
                    Some(ip_from(r.family, &r.addr))
                } else {
                    self.dns_servers.get(&(pid, r.dfd)).copied()
                };
                ObsKind::Dns { server, query }
            }
            KL_SOCKET => ObsKind::Socket {
                family: r.a0 as u32,
                sock_type: r.a1 as u32,
                protocol: r.a2 as u32,
            },
            KL_UNLINK => ObsKind::Unlink {
                path: resolve_at(pid, r.dfd, &cstr(&r.path)).0,
            },
            KL_RENAME => ObsKind::Rename {
                from: resolve_at(pid, r.dfd, &cstr(&r.path)).0,
                to: resolve_at(pid, r.dfd, &cstr(&r.path2)).0,
            },
            KL_CHMOD => {
                let path = if r.a2 == 1 {
                    fd_path(pid, r.dfd).unwrap_or_default()
                } else {
                    resolve_at(pid, r.dfd, &cstr(&r.path)).0
                };
                ObsKind::Chmod {
                    path,
                    mode: r.a0 as u32,
                }
            }
            KL_MOUNT => ObsKind::Mount {
                source: cstr(&r.path2),
                target: cstr(&r.path),
                flags: r.a0,
            },
            KL_UMOUNT => ObsKind::Umount {
                target: cstr(&r.path),
            },
            KL_SETUID => {
                let (call, n) = match r.a0 {
                    1 => ("setuid", 1),
                    2 => ("setreuid", 2),
                    3 => ("setresuid", 3),
                    4 => ("setgid", 1),
                    5 => ("setregid", 2),
                    6 => ("setresgid", 3),
                    _ => ("setid", 3),
                };
                let all = [
                    r.a1 as u32 as i32 as i64,
                    r.a2 as u32 as i32 as i64,
                    r.dfd as u32 as i32 as i64,
                ];
                ObsKind::SetId {
                    call: call.into(),
                    args: all[..n].to_vec(),
                }
            }
            KL_CAPSET => ObsKind::Capset {
                effective: r.a0 as u32,
                permitted: r.a1 as u32,
            },
            KL_UNSHARE => ObsKind::Unshare { flags: r.a0 },
            KL_SETNS => ObsKind::Setns { nstype: r.a1 },
            KL_PTRACE => ObsKind::Ptrace {
                request: r.a0,
                target_pid: r.a1 as i32 as i64,
            },
            KL_KILL => ObsKind::Kill {
                target_pid: r.a0 as i32 as i64,
                signal: r.a1,
            },
            KL_BPF => ObsKind::Bpf { cmd: r.a0 },
            KL_MODULE => ObsKind::ModuleLoad,
            KL_CHROOT => ObsKind::Chroot {
                path: cstr(&r.path),
            },
            KL_PIVOT_ROOT => ObsKind::PivotRoot {
                new_root: cstr(&r.path),
                put_old: cstr(&r.path2),
            },
            _ => return None,
        };
        Some(Observation {
            timestamp: self.timestamp(r.ts_ns),
            process,
            kind,
            runtime_setup: r.flags & KL_F_RUNTIME_SETUP != 0,
            outcome: None,
        })
    }

    /// SHA-256 of the executable as seen from the process's own root.
    /// Best effort: short-lived processes may be gone before we look.
    fn hash_exe(&mut self, pid: u32, path: &str) -> Option<String> {
        use std::os::unix::fs::MetadataExt;
        if !path.starts_with('/') {
            return None;
        }
        let host_path = format!("/proc/{}/root{}", pid, path);
        let meta = std::fs::metadata(&host_path).ok()?;
        if !meta.is_file() || meta.len() > MAX_HASH_BYTES {
            return None;
        }
        let key = (path.to_string(), meta.ino(), meta.mtime());
        if let Some(h) = self.hash_cache.get(&key) {
            return Some(h.clone());
        }
        let mut f = std::fs::File::open(&host_path).ok()?;
        let mut h = Sha256::new();
        let mut buf = vec![0u8; 64 * 1024];
        loop {
            let n = f.read(&mut buf).ok()?;
            if n == 0 {
                break;
            }
            h.update(&buf[..n]);
        }
        let hex = hex::encode(h.finalize());
        if self.hash_cache.len() > 4096 {
            self.hash_cache.clear();
        }
        self.hash_cache.insert(key, hex.clone());
        Some(hex)
    }
}

fn access_from_flags(flags: u64) -> FileAccess {
    if flags & O_PATH != 0 {
        FileAccess::Path
    } else if flags & O_ACCMODE != 0 || flags & (O_CREAT | O_TRUNC | O_APPEND) != 0 {
        FileAccess::Write
    } else if flags & O_DIRECTORY != 0 {
        FileAccess::List
    } else {
        FileAccess::Read
    }
}

fn ip_from(family: u16, b: &[u8; 16]) -> IpAddr {
    if family as i32 == libc::AF_INET {
        IpAddr::V4(Ipv4Addr::new(b[0], b[1], b[2], b[3]))
    } else {
        IpAddr::V6(Ipv6Addr::from(*b)).to_canonical()
    }
}

fn fd_path(pid: u32, fd: i64) -> Option<String> {
    std::fs::read_link(format!("/proc/{}/fd/{}", pid, fd))
        .ok()
        .map(|p| p.to_string_lossy().into_owned())
}

/// Resolve a path argument of an *at() syscall to an absolute path.
/// Returns (path, resolution). Racy by nature: the process may have changed
/// directory or closed the fd by the time we look. The kernel-resolved
/// `security_file_open` event covers successful opens independently.
pub fn resolve_at(pid: u32, dfd: i64, path: &str) -> (String, String) {
    if path.starts_with('/') {
        return (pathmatch::normalize(path), "lexical".into());
    }
    if path.is_empty() {
        return (String::new(), "unresolved".into());
    }
    let base = if dfd == AT_FDCWD {
        std::fs::read_link(format!("/proc/{}/cwd", pid))
            .ok()
            .map(|p| p.to_string_lossy().into_owned())
    } else {
        fd_path(pid, dfd)
    };
    match base {
        Some(b) if b.starts_with('/') => (pathmatch::resolve(&b, path), "lexical".into()),
        _ => (path.to_string(), "unresolved".into()),
    }
}

/// Resolve symlinks in `path` as the agent would see them, i.e. inside its
/// own root filesystem (/proc/<pid>/root), without ever following a link
/// out of that root. Returns None if the process is gone. Racy: the link can
/// change between the agent's open and this lookup. /proc and /dev/fd are
/// skipped because their "magic" links would resolve relative to KillLine.
pub fn realpath_in_root(pid: u32, path: &str) -> Option<String> {
    realpath_in_root_cached(pid, path, &mut |_, check| check())
}

/// `dir_is_link(prefix, check)` decides whether an intermediate directory is
/// a symlink, calling `check` to actually lstat it (callers may cache).
/// The final component is always checked.
pub fn realpath_in_root_cached(
    pid: u32,
    path: &str,
    dir_is_link: &mut dyn FnMut(&str, &mut dyn FnMut() -> bool) -> bool,
) -> Option<String> {
    if path.starts_with("/proc/")
        || path == "/proc"
        || path.starts_with("/dev/fd")
        || path.starts_with("/dev/std")
    {
        return None;
    }
    let root = format!("/proc/{}/root", pid);
    let mut todo: std::collections::VecDeque<String> = path
        .split('/')
        .filter(|c| !c.is_empty())
        .map(String::from)
        .collect();
    let mut cur: Vec<String> = Vec::new();
    let mut hops = 0;
    let mut missing = false;
    while let Some(c) = todo.pop_front() {
        match c.as_str() {
            "." => continue,
            ".." => {
                cur.pop();
                continue;
            }
            _ => {}
        }
        cur.push(c);
        if missing {
            continue;
        }
        let rel = cur.join("/");
        let host = format!("{}/{}", root, rel);
        let is_last = todo.is_empty();
        let mut meta = None;
        let mut check = || {
            let m = std::fs::symlink_metadata(&host);
            let link = matches!(&m, Ok(m) if m.file_type().is_symlink());
            meta = Some(m.is_ok());
            link
        };
        let is_link = if is_last {
            check()
        } else {
            dir_is_link(&rel, &mut check)
        };
        if is_link {
            hops += 1;
            if hops > 40 {
                return None;
            }
            let target = std::fs::read_link(&host).ok()?;
            let t = target.to_string_lossy().into_owned();
            cur.pop();
            if t.starts_with('/') {
                cur.clear();
            }
            for (i, comp) in t.split('/').filter(|c| !c.is_empty()).enumerate() {
                todo.insert(i, comp.to_string());
            }
        } else if meta == Some(false) {
            if !std::path::Path::new(&root).exists() {
                return None;
            }
            missing = true;
        }
    }
    Some(format!("/{}", cur.join("/")))
}

/// Extract the first question name from a DNS query packet.
pub fn parse_dns_query(p: &[u8]) -> Option<String> {
    if p.len() < 13 {
        return None;
    }
    let qdcount = u16::from_be_bytes([p[4], p[5]]);
    if qdcount == 0 {
        return None;
    }
    let mut i = 12;
    let mut labels = Vec::new();
    loop {
        let len = *p.get(i)? as usize;
        if len == 0 {
            break;
        }
        if len > 63 {
            return None; // compression pointers are not valid in a question
        }
        let label = p.get(i + 1..i + 1 + len)?;
        if !label
            .iter()
            .all(|c| c.is_ascii_alphanumeric() || *c == b'-' || *c == b'_')
        {
            return None;
        }
        labels.push(String::from_utf8_lossy(label).into_owned());
        i += 1 + len;
        if labels.len() > 127 {
            return None;
        }
    }
    if labels.is_empty() {
        None
    } else {
        Some(labels.join(".").to_ascii_lowercase())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dns_parse() {
        let mut q = vec![0x12, 0x34, 1, 0, 0, 1, 0, 0, 0, 0, 0, 0];
        for l in ["example", "com"] {
            q.push(l.len() as u8);
            q.extend_from_slice(l.as_bytes());
        }
        q.extend_from_slice(&[0, 0, 1, 0, 1]);
        assert_eq!(parse_dns_query(&q).as_deref(), Some("example.com"));
        assert_eq!(parse_dns_query(&q[..14]), None);
    }

    #[test]
    fn flags() {
        assert_eq!(access_from_flags(0), FileAccess::Read);
        assert_eq!(access_from_flags(1), FileAccess::Write);
        assert_eq!(access_from_flags(0o100 | 1), FileAccess::Write);
        assert_eq!(access_from_flags(O_DIRECTORY), FileAccess::List);
    }
}
