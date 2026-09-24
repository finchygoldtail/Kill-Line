//! Kill Line sensors.
//!
//! One interface, one implementation per operating system:
//! - Linux: eBPF (syscall tracepoints) — `ebpf.rs`;
//! - Windows: Event Tracing for Windows (ETW) — `etw.rs`.
//!
//! Both scope observation to one agent (a process tree, or on Linux a
//! container), yield [`killline_core::event::Observation`]s, and report
//! their own coverage and event loss so the monitor can go GREY instead of
//! pretending to see everything.

pub mod respond;
pub mod target;

#[cfg(target_os = "linux")]
pub mod decode;
#[cfg(target_os = "linux")]
mod ebpf;
#[cfg(target_os = "linux")]
pub mod raw;
#[cfg(target_os = "linux")]
pub use ebpf::Sensor;

#[cfg(windows)]
mod etw;
#[cfg(windows)]
pub use etw::Sensor;

/// Which processes belong to the monitored agent.
#[derive(Debug, Clone)]
pub struct Scope {
    /// PIDs to track from the start (their descendants are added as they
    /// are created).
    pub pids: Vec<u32>,
    /// Linux container mode: adopt every process in this PID namespace.
    pub pidns: Option<u32>,
}

/// Name of the telemetry source, for metadata and the UI.
pub fn sensor_name() -> &'static str {
    if cfg!(windows) {
        "etw (Kernel-Process, Kernel-File, Kernel-Network, DNS-Client)"
    } else {
        "ebpf (tracepoints + fentry/security_file_open)"
    }
}
