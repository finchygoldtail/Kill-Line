//! Wire format shared with bpf/killline.bpf.c. Keep the two in sync.

pub const PATH_LEN: usize = 256;
pub const ARGS_LEN: usize = 256;
pub const ARG_SLOT: usize = 42;
pub const ARG_SLOTS: usize = 6;

pub const KL_EXEC: u32 = 1;
pub const KL_FORK: u32 = 2;
pub const KL_EXIT: u32 = 3;
pub const KL_OPEN: u32 = 4;
pub const KL_FILE_OPENED: u32 = 5;
pub const KL_CONNECT: u32 = 6;
pub const KL_SENDTO: u32 = 7;
pub const KL_DNS: u32 = 8;
pub const KL_BIND: u32 = 9;
pub const KL_SOCKET: u32 = 10;
pub const KL_UNLINK: u32 = 11;
pub const KL_RENAME: u32 = 12;
pub const KL_CHMOD: u32 = 13;
pub const KL_MOUNT: u32 = 14;
pub const KL_UMOUNT: u32 = 15;
pub const KL_SETUID: u32 = 16;
pub const KL_CAPSET: u32 = 17;
pub const KL_UNSHARE: u32 = 18;
pub const KL_SETNS: u32 = 19;
pub const KL_PTRACE: u32 = 20;
pub const KL_KILL: u32 = 21;
pub const KL_BPF: u32 = 22;
pub const KL_MODULE: u32 = 23;
pub const KL_CHROOT: u32 = 24;
pub const KL_PIVOT_ROOT: u32 = 25;

pub const KL_RESULT: u32 = 26;

pub const KL_F_RUNTIME_SETUP: u32 = 1;

#[repr(C)]
#[derive(Clone, Copy)]
pub struct RawEvent {
    pub ts_ns: u64,
    pub kind: u32,
    pub tgid: u32,
    pub tid: u32,
    pub ppid: u32,
    pub uid: u32,
    pub gid: u32,
    pub dfd: i64,
    pub a0: u64,
    pub a1: u64,
    pub a2: u64,
    pub family: u16,
    pub port: u16,
    pub flags: u32,
    pub addr: [u8; 16],
    pub comm: [u8; 16],
    pub path: [u8; PATH_LEN],
    pub path2: [u8; ARGS_LEN],
}

const _: () = assert!(std::mem::size_of::<RawEvent>() == 616);

#[repr(C)]
#[derive(Clone, Copy)]
pub struct KlConfig {
    pub target_pidns: u32,
    pub monitor_tgid: u32,
}

// SAFETY: plain-old-data with no padding-dependent invariants.
unsafe impl aya::Pod for KlConfig {}

impl RawEvent {
    /// Decode from ring-buffer bytes. Returns None for short records.
    pub fn from_bytes(b: &[u8]) -> Option<RawEvent> {
        if b.len() < std::mem::size_of::<RawEvent>() {
            return None;
        }
        // SAFETY: length checked; RawEvent is repr(C) POD; unaligned read.
        Some(unsafe { std::ptr::read_unaligned(b.as_ptr() as *const RawEvent) })
    }
}

/// Kind field of any ring-buffer record (offset 8 in both layouts).
pub fn record_kind(b: &[u8]) -> Option<u32> {
    Some(u32::from_ne_bytes(b.get(8..12)?.try_into().ok()?))
}

/// (tid, return value) of a KL_RESULT record.
pub fn result_fields(b: &[u8]) -> Option<(u32, i64)> {
    let tid = u32::from_ne_bytes(b.get(16..20)?.try_into().ok()?);
    let ret = i64::from_ne_bytes(b.get(24..32)?.try_into().ok()?);
    Some((tid, ret))
}

/// NUL-terminated byte buffer to a lossy UTF-8 string.
pub fn cstr(b: &[u8]) -> String {
    let end = b.iter().position(|&c| c == 0).unwrap_or(b.len());
    String::from_utf8_lossy(&b[..end]).into_owned()
}
