//! Windows sensor: Event Tracing for Windows (ETW).
//!
//! A real-time ETW session (administrator rights; no kernel driver) with
//! four manifest providers:
//!
//! | Provider | What we use |
//! |---|---|
//! | Microsoft-Windows-Kernel-Process | process start/stop (image, parent) |
//! | Microsoft-Windows-Kernel-File | file create/open, delete, rename (path) |
//! | Microsoft-Windows-Kernel-Network | TCP connects, UDP sends (addresses) |
//! | Microsoft-Windows-DNS-Client | DNS query names |
//!
//! Scoping is by process tree: the seed PIDs plus every descendant, learned
//! from ProcessStart events (ParentProcessID). ETW callbacks run on the
//! session's thread and hand observations to the monitor over a bounded
//! queue; anything that cannot be delivered is counted as lost. Events lost
//! inside ETW itself are read from the session (ControlTrace query), so the
//! monitor can go GREY.
//!
//! Known V1 gaps (reported as coverage notes): file-open results, process
//! command lines, and TCP attempts that never complete are not observed.

use crate::Scope;
use anyhow::{anyhow, Result};
use chrono::{DateTime, TimeZone, Utc};
use ferrisetw::parser::Parser;
use ferrisetw::provider::Provider;
use ferrisetw::schema_locator::SchemaLocator;
use ferrisetw::trace::{TraceProperties, UserTrace};
use ferrisetw::EventRecord;
use killline_core::event::*;
use killline_core::pathmatch::canonical_windows;
use killline_core::session::CoverageItem;
use std::collections::{HashMap, HashSet};
use std::net::IpAddr;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::mpsc::{sync_channel, Receiver, SyncSender, TrySendError};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

const KERNEL_PROCESS: &str = "22fb2cd6-0e7b-422b-a0c7-2fad1fd0e716";
const KERNEL_FILE: &str = "edd08927-9cc4-4e65-b970-c2560fb5c289";
const KERNEL_NETWORK: &str = "7dd42a49-5329-4832-8dfd-43d979153a88";
const DNS_CLIENT: &str = "1c95126e-7eea-49a9-a3fe-a378b03ddb4d";

const QUEUE: usize = 200_000;

struct Shared {
    tx: SyncSender<Observation>,
    tracked: Mutex<HashSet<u32>>,
    names: Mutex<HashMap<u32, (u32, String)>>,
    /// (\device\harddiskvolume3, c:) pairs, lowercase.
    devices: Vec<(String, String)>,
    queue_lost: AtomicU64,
    probe: bool,
    /// Rate limiting for per-packet network events: (pid, dest) -> last emit.
    recent_net: Mutex<HashMap<(u32, IpAddr, u16, bool), Instant>>,
    recent_dns: Mutex<HashMap<(u32, String), Instant>>,
    stopped: AtomicBool,
}

pub struct Sensor {
    rx: Receiver<Observation>,
    shared: Arc<Shared>,
    trace: Option<UserTrace>,
    session: String,
    coverage: Vec<CoverageItem>,
}

/// ETW timestamps are FILETIMEs: 100 ns ticks since 1601-01-01 UTC.
fn to_utc(filetime: i64) -> DateTime<Utc> {
    const EPOCH_DIFF: i64 = 116_444_736_000_000_000;
    Utc.timestamp_nanos((filetime - EPOCH_DIFF).saturating_mul(100))
}

/// Map `\Device\HarddiskVolumeN` prefixes to drive letters.
fn device_map() -> Vec<(String, String)> {
    use windows_sys::Win32::Storage::FileSystem::QueryDosDeviceW;
    let mut out = Vec::new();
    for letter in b'A'..=b'Z' {
        let drive: Vec<u16> = format!("{}:", letter as char)
            .encode_utf16()
            .chain(Some(0))
            .collect();
        let mut buf = [0u16; 1024];
        // SAFETY: valid NUL-terminated input and an output buffer of the given length.
        let n = unsafe { QueryDosDeviceW(drive.as_ptr(), buf.as_mut_ptr(), buf.len() as u32) };
        if n > 0 {
            let end = buf.iter().position(|&c| c == 0).unwrap_or(buf.len());
            let target = String::from_utf16_lossy(&buf[..end]).to_lowercase();
            out.push((
                target,
                format!("{}:", (letter as char).to_ascii_lowercase()),
            ));
        }
    }
    // Longest device names first, so \device\harddiskvolume10 is not
    // matched by \device\harddiskvolume1.
    out.sort_by_key(|a| std::cmp::Reverse(a.0.len()));
    out
}

impl Shared {
    /// Kernel path (`\Device\HarddiskVolume3\Users\x`) to canonical form.
    fn path(&self, raw: &str) -> String {
        let lower = raw.to_lowercase();
        for (dev, drive) in &self.devices {
            if let Some(rest) = lower.strip_prefix(dev.as_str()) {
                if rest.is_empty() || rest.starts_with('\\') {
                    return canonical_windows(&format!("{}{}", drive, rest));
                }
            }
        }
        canonical_windows(raw)
    }

    fn is_tracked(&self, pid: u32) -> bool {
        self.tracked.lock().unwrap().contains(&pid)
    }

    fn process(&self, pid: u32) -> ProcessInfo {
        let names = self.names.lock().unwrap();
        let (ppid, comm) = names.get(&pid).cloned().unwrap_or((0, String::new()));
        ProcessInfo {
            pid,
            tid: 0,
            ppid,
            uid: 0,
            gid: 0,
            comm,
            exe: None,
        }
    }

    fn emit(&self, timestamp: DateTime<Utc>, process: ProcessInfo, kind: ObsKind) {
        let obs = Observation {
            timestamp,
            process,
            kind,
            runtime_setup: false,
            outcome: None,
        };
        match self.tx.try_send(obs) {
            Ok(()) => {}
            Err(TrySendError::Full(_)) | Err(TrySendError::Disconnected(_)) => {
                self.queue_lost.fetch_add(1, Ordering::Relaxed);
            }
        }
    }

    fn probe(&self, what: &str, record: &EventRecord, schema: Option<&ferrisetw::schema::Schema>) {
        if !self.probe {
            return;
        }
        let mut fields = Vec::new();
        if let Some(schema) = schema {
            let p = Parser::create(record, schema);
            for name in [
                "ProcessID",
                "ParentProcessID",
                "ImageName",
                "FileName",
                "FilePath",
                "CreateOptions",
                "PID",
                "daddr",
                "dport",
                "saddr",
                "sport",
                "size",
                "QueryName",
                "QueryStatus",
                "QueryResults",
                "Status",
            ] {
                if let Ok(v) = p.try_parse::<String>(name) {
                    fields.push(format!("{}={:?}", name, v));
                } else if let Ok(v) = p.try_parse::<IpAddr>(name) {
                    fields.push(format!("{}={}", name, v));
                } else if let Ok(v) = p.try_parse::<u32>(name) {
                    fields.push(format!("{}={}", name, v));
                } else if let Ok(v) = p.try_parse::<u16>(name) {
                    fields.push(format!("{}={}(be:{})", name, v, u16::from_be(v)));
                }
            }
            eprintln!(
                "[etw-probe] {} id={} task={:?} opcode={:?} hdr_pid={} {}",
                what,
                record.event_id(),
                schema.task_name(),
                schema.opcode_name(),
                record.process_id(),
                fields.join(" ")
            );
        } else {
            eprintln!(
                "[etw-probe] {} id={} hdr_pid={} (no schema)",
                what,
                record.event_id(),
                record.process_id()
            );
        }
    }

    fn on_process(&self, record: &EventRecord, loc: &SchemaLocator) {
        let Ok(schema) = loc.event_schema(record) else {
            return;
        };
        let p = Parser::create(record, &schema);
        let ts = to_utc(record.raw_timestamp());
        match record.event_id() {
            1 => {
                let (Ok(pid), Ok(ppid)) = (
                    p.try_parse::<u32>("ProcessID"),
                    p.try_parse::<u32>("ParentProcessID"),
                ) else {
                    return;
                };
                let image: String = p.try_parse("ImageName").unwrap_or_default();
                let path = self.path(&image);
                let comm = path.rsplit('/').next().unwrap_or("").to_string();
                self.names.lock().unwrap().insert(pid, (ppid, comm.clone()));
                if !self.is_tracked(ppid) {
                    return;
                }
                self.probe("process", record, Some(&schema));
                self.tracked.lock().unwrap().insert(pid);
                let parent = self.process(ppid);
                self.emit(ts, parent, ObsKind::Fork { child_pid: pid });
                let real = image_to_win32(&image, &self.devices);
                let sha256 = real.as_deref().and_then(hash_file);
                let proc_info = ProcessInfo {
                    pid,
                    tid: 0,
                    ppid,
                    uid: 0,
                    gid: 0,
                    comm: comm.clone(),
                    exe: Some(path.clone()),
                };
                self.emit(
                    ts,
                    proc_info,
                    ObsKind::Exec {
                        path,
                        argv: vec![comm],
                        sha256,
                        exists: true,
                    },
                );
            }
            2 => {
                let Ok(pid) = p.try_parse::<u32>("ProcessID") else {
                    return;
                };
                if self.tracked.lock().unwrap().remove(&pid) {
                    let info = self.process(pid);
                    self.emit(ts, info, ObsKind::Exit);
                }
            }
            _ => {}
        }
    }

    fn on_file(&self, record: &EventRecord, loc: &SchemaLocator) {
        let pid = record.process_id();
        if !self.is_tracked(pid) {
            return;
        }
        let Ok(schema) = loc.event_schema(record) else {
            return;
        };
        self.probe("file", record, Some(&schema));
        let p = Parser::create(record, &schema);
        let ts = to_utc(record.raw_timestamp());
        let raw: String = p
            .try_parse::<String>("FileName")
            .or_else(|_| p.try_parse::<String>("FilePath"))
            .unwrap_or_default();
        if raw.is_empty() {
            return;
        }
        let path = self.path(&raw);
        let info = self.process(pid);
        let kind = match record.event_id() {
            // Create: disposition is the top byte of CreateOptions
            // (1 = FILE_OPEN, anything else creates or overwrites).
            12 => {
                let opts: u32 = p.try_parse("CreateOptions").unwrap_or(1 << 24);
                let disposition = opts >> 24;
                let access = if disposition != 1 {
                    FileAccess::Write
                } else if opts & 0x1 != 0 {
                    FileAccess::List
                } else {
                    FileAccess::Read
                };
                ObsKind::Open {
                    path,
                    access,
                    flags: opts as u64,
                    resolution: "kernel".into(),
                    via: None,
                }
            }
            30 => ObsKind::Open {
                path,
                access: FileAccess::Write,
                flags: 0,
                resolution: "kernel".into(),
                via: None,
            },
            26 => ObsKind::Unlink { path },
            27 => ObsKind::Rename {
                from: path.clone(),
                to: path,
            },
            _ => return,
        };
        self.emit(ts, info, kind);
    }

    fn on_network(&self, record: &EventRecord, loc: &SchemaLocator) {
        let Ok(schema) = loc.event_schema(record) else {
            return;
        };
        let p = Parser::create(record, &schema);
        let pid = p
            .try_parse::<u32>("PID")
            .unwrap_or_else(|_| record.process_id());
        if !self.is_tracked(pid) {
            return;
        }
        self.probe("network", record, Some(&schema));
        // Kernel-Network event IDs: TCP connect 12 (IPv4) / 28 (IPv6);
        // UDP send 42 (IPv4) / 58 (IPv6).
        let op = match record.event_id() {
            12 | 28 => NetOp::Connect,
            42 | 58 => NetOp::Send,
            _ => return,
        };
        let (Ok(addr), Ok(port)) = (p.try_parse::<IpAddr>("daddr"), p.try_parse::<u16>("dport"))
        else {
            return;
        };
        // Ports are logged in network byte order.
        let port = u16::from_be(port);
        let key = (pid, addr, port, op == NetOp::Send);
        {
            let mut recent = self.recent_net.lock().unwrap();
            let now = Instant::now();
            if recent
                .get(&key)
                .is_some_and(|t| now.duration_since(*t) < Duration::from_secs(10))
            {
                return;
            }
            if recent.len() > 10_000 {
                recent.clear();
            }
            recent.insert(key, now);
        }
        let info = self.process(pid);
        self.emit(
            to_utc(record.raw_timestamp()),
            info,
            ObsKind::Net {
                op,
                addr: addr.to_canonical(),
                port,
            },
        );
    }

    fn on_dns(&self, record: &EventRecord, loc: &SchemaLocator) {
        let pid = record.process_id();
        if !self.is_tracked(pid) || record.event_id() != 3006 {
            return;
        }
        let Ok(schema) = loc.event_schema(record) else {
            return;
        };
        self.probe("dns", record, Some(&schema));
        let p = Parser::create(record, &schema);
        let Ok(name) = p.try_parse::<String>("QueryName") else {
            return;
        };
        let name = name.trim_end_matches('.').to_ascii_lowercase();
        {
            let mut recent = self.recent_dns.lock().unwrap();
            let now = Instant::now();
            let key = (pid, name.clone());
            if recent
                .get(&key)
                .is_some_and(|t| now.duration_since(*t) < Duration::from_secs(2))
            {
                return;
            }
            if recent.len() > 10_000 {
                recent.clear();
            }
            recent.insert(key, now);
        }
        let info = self.process(pid);
        self.emit(
            to_utc(record.raw_timestamp()),
            info,
            ObsKind::Dns {
                server: None,
                query: Some(name),
            },
        );
    }
}

/// `\Device\HarddiskVolume3\x\y.exe` → `C:\x\y.exe` for hashing.
fn image_to_win32(image: &str, devices: &[(String, String)]) -> Option<String> {
    let lower = image.to_lowercase();
    for (dev, drive) in devices {
        if lower.starts_with(dev.as_str()) {
            return Some(format!("{}{}", drive, &image[dev.len()..]));
        }
    }
    let b = image.as_bytes();
    (b.len() > 2 && b[1] == b':').then(|| image.to_string())
}

fn hash_file(path: &str) -> Option<String> {
    use sha2::{Digest, Sha256};
    use std::io::Read;
    let meta = std::fs::metadata(path).ok()?;
    if !meta.is_file() || meta.len() > 256 * 1024 * 1024 {
        return None;
    }
    let mut f = std::fs::File::open(path).ok()?;
    let mut h = Sha256::new();
    let mut buf = vec![0u8; 64 * 1024];
    loop {
        let n = f.read(&mut buf).ok()?;
        if n == 0 {
            break;
        }
        h.update(&buf[..n]);
    }
    Some(hex::encode(h.finalize()))
}

/// Events lost inside the ETW session, or an error if it no longer exists
/// (for example because another administrator stopped it).
fn session_lost_events(name: &str) -> std::result::Result<u64, u32> {
    use windows_sys::Win32::System::Diagnostics::Etw::{
        ControlTraceW, CONTROLTRACE_HANDLE, EVENT_TRACE_CONTROL_QUERY, EVENT_TRACE_PROPERTIES,
    };
    let head = std::mem::size_of::<EVENT_TRACE_PROPERTIES>();
    let wide: Vec<u16> = name.encode_utf16().chain(Some(0)).collect();
    // u64 storage keeps the struct 8-byte aligned; the tail holds the name.
    let mut storage = vec![0u64; (head + 2048).div_ceil(8)];
    // SAFETY: the buffer is aligned and large enough for the properties
    // struct followed by the logger name, as ControlTraceW requires.
    unsafe {
        let props = storage.as_mut_ptr() as *mut EVENT_TRACE_PROPERTIES;
        (*props).Wnode.BufferSize = (storage.len() * 8) as u32;
        (*props).LoggerNameOffset = head as u32;
        let rc = ControlTraceW(
            CONTROLTRACE_HANDLE { Value: 0 },
            wide.as_ptr(),
            props,
            EVENT_TRACE_CONTROL_QUERY,
        );
        if rc != 0 {
            return Err(rc);
        }
        Ok((*props).EventsLost as u64 + (*props).RealTimeBuffersLost as u64)
    }
}

impl Sensor {
    pub fn built_with_bpf() -> bool {
        false
    }

    pub fn available() -> bool {
        true
    }

    pub fn start(scope: &Scope) -> Result<Sensor> {
        let (tx, rx) = sync_channel(QUEUE);
        let mut names = HashMap::new();
        for (pid, ppid, exe) in crate::target::snapshot() {
            names.insert(pid, (ppid, exe.to_lowercase()));
        }
        let me = std::process::id();
        let shared = Arc::new(Shared {
            tx,
            tracked: Mutex::new(scope.pids.iter().copied().filter(|p| *p != me).collect()),
            names: Mutex::new(names),
            devices: device_map(),
            queue_lost: AtomicU64::new(0),
            probe: std::env::var_os("KILLLINE_ETW_PROBE").is_some(),
            recent_net: Mutex::new(HashMap::new()),
            recent_dns: Mutex::new(HashMap::new()),
            stopped: AtomicBool::new(false),
        });

        let s1 = shared.clone();
        let process = Provider::by_guid(KERNEL_PROCESS)
            .any(0x10) // WINEVENT_KEYWORD_PROCESS
            .add_callback(move |r: &EventRecord, l: &SchemaLocator| s1.on_process(r, l))
            .build();
        let s2 = shared.clone();
        let file = Provider::by_guid(KERNEL_FILE)
            // CREATE | DELETE_PATH | RENAME_SETLINK_PATH | CREATE_NEW_FILE
            .any(0x80 | 0x400 | 0x800 | 0x1000)
            .add_callback(move |r: &EventRecord, l: &SchemaLocator| s2.on_file(r, l))
            .build();
        let s3 = shared.clone();
        let network = Provider::by_guid(KERNEL_NETWORK)
            .any(0x10 | 0x20) // IPV4 | IPV6
            .add_callback(move |r: &EventRecord, l: &SchemaLocator| s3.on_network(r, l))
            .build();
        let s4 = shared.clone();
        let dns = Provider::by_guid(DNS_CLIENT)
            .add_callback(move |r: &EventRecord, l: &SchemaLocator| s4.on_dns(r, l))
            .build();

        let session = format!("KillLine-{}", me);
        let props = TraceProperties {
            buffer_size: 64, // KB per buffer
            min_buffer: 16,
            max_buffer: 512,
            flush_timer: Duration::from_secs(1),
            ..Default::default()
        };
        let trace = UserTrace::new()
            .named(session.clone())
            .set_trace_properties(props)
            .enable(process)
            .enable(file)
            .enable(network)
            .enable(dns)
            .start_and_process()
            .map_err(|e| {
                anyhow!(
                    "starting the ETW session failed ({:?}). Kill Line must run as Administrator on Windows.",
                    e
                )
            })?;

        let coverage = vec![
            CoverageItem { name: "etw/Microsoft-Windows-Kernel-Process".into(), active: true, critical: true, detail: Some("process start/stop; command lines are not captured (V1)".into()) },
            CoverageItem { name: "etw/Microsoft-Windows-Kernel-File".into(), active: true, critical: true, detail: Some("file create/open, delete, rename; whether an open succeeded is not observed (V1)".into()) },
            CoverageItem { name: "etw/Microsoft-Windows-Kernel-Network".into(), active: true, critical: true, detail: Some("TCP connections and UDP sends; TCP attempts that never complete may not appear (V1)".into()) },
            CoverageItem { name: "etw/Microsoft-Windows-DNS-Client".into(), active: true, critical: false, detail: Some("DNS query names".into()) },
            CoverageItem { name: "privilege and namespace syscalls".into(), active: false, critical: false, detail: Some("not observed on Windows (V1): token changes, service creation and driver loads are only seen as program executions".into()) },
        ];
        Ok(Sensor {
            rx,
            shared,
            trace: Some(trace),
            session,
            coverage,
        })
    }

    pub fn coverage(&self) -> &[CoverageItem] {
        &self.coverage
    }

    pub fn poll(
        &mut self,
        timeout_ms: i32,
        max: usize,
        out: &mut Vec<Observation>,
    ) -> Result<usize> {
        let mut n = 0;
        if let Ok(o) = self
            .rx
            .recv_timeout(Duration::from_millis(timeout_ms.max(0) as u64))
        {
            out.push(o);
            n += 1;
        }
        while n < max {
            match self.rx.try_recv() {
                Ok(o) => {
                    out.push(o);
                    n += 1;
                }
                Err(_) => break,
            }
        }
        Ok(n)
    }

    /// Events lost in ETW plus events the sensor could not queue.
    pub fn dropped(&self) -> Result<u64> {
        let queue = self.shared.queue_lost.load(Ordering::Relaxed);
        match session_lost_events(&self.session) {
            Ok(etw) => Ok(etw + queue),
            Err(code) => {
                self.shared.stopped.store(true, Ordering::Relaxed);
                Err(anyhow!("ETW session query failed (error {})", code))
            }
        }
    }

    /// A reason the sensor can no longer see, if any.
    pub fn health(&self) -> Option<String> {
        if self.shared.stopped.load(Ordering::Relaxed)
            || session_lost_events(&self.session).is_err()
        {
            Some(format!(
                "The ETW session {} is gone (stopped by someone else?). Kill Line can no longer see the agent.",
                self.session
            ))
        } else {
            None
        }
    }

    pub fn tracked_pids(&self) -> Result<Vec<u32>> {
        Ok(self
            .shared
            .tracked
            .lock()
            .unwrap()
            .iter()
            .copied()
            .collect())
    }

    pub fn track(&mut self, pid: u32) -> Result<()> {
        self.shared.tracked.lock().unwrap().insert(pid);
        Ok(())
    }
}

impl Drop for Sensor {
    fn drop(&mut self) {
        if let Some(t) = self.trace.take() {
            let _ = t.stop();
        }
    }
}
