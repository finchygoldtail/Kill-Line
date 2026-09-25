//! Session state: status, counters and the process table.

use crate::event::*;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, HashSet};

/// Seconds without a heartbeat before a live session is considered
/// unverifiable (GREY).
pub const HEARTBEAT_STALE_SECS: i64 = 10;

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "UPPERCASE")]
pub enum Status {
    Green,
    Amber,
    Red,
    Grey,
}

impl Status {
    pub fn label(&self) -> &'static str {
        match self {
            Status::Green => "GREEN — CONTAINED",
            Status::Amber => "AMBER — ANOMALOUS",
            Status::Red => "RED — BOUNDARY BREACH",
            Status::Grey => "GREY — MONITORING DEGRADED",
        }
    }
    /// What the status does and does not mean. Never claims safety.
    pub fn meaning(&self) -> &'static str {
        match self {
            Status::Green => "No monitored boundary violations detected.",
            Status::Amber => "No boundary violations detected, but behaviour is unusual.",
            Status::Red => "A declared containment boundary was crossed.",
            Status::Grey => "Kill Line's visibility is incomplete. Containment cannot be verified.",
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct ProcessRecord {
    pub pid: u32,
    pub ppid: u32,
    pub comm: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub exe: Option<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub argv: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sha256: Option<String>,
    pub uid: u32,
    pub first_seen: DateTime<Utc>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub exited: Option<DateTime<Utc>>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct CoverageItem {
    pub name: String,
    pub active: bool,
    /// Whether losing this source makes the session GREY.
    pub critical: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub detail: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LastViolation {
    pub seq: u64,
    pub timestamp: DateTime<Utc>,
    pub boundary: String,
    pub summary: String,
    pub explanation: String,
    pub process: String,
    pub policy_rule: Option<String>,
    pub expected: Option<String>,
    #[serde(default)]
    pub outcome: Option<Outcome>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Session {
    pub session_id: String,
    pub agent: String,
    pub policy: String,
    /// "container:<name>" or "process:<pid>" / "run:<cmd>".
    pub target: String,
    pub started: DateTime<Utc>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ended: Option<DateTime<Utc>>,
    pub status: Status,
    pub events: u64,
    pub violations: u64,
    /// Violations whose syscall was observed to succeed.
    #[serde(default)]
    pub violations_succeeded: u64,
    /// Violations the operating system refused (the sandbox held).
    #[serde(default)]
    pub violations_blocked: u64,
    pub anomalies: u64,
    pub processes_seen: u64,
    pub files_accessed: u64,
    pub network_attempts: u64,
    pub dropped_events: u64,
    #[serde(default)]
    pub degraded_reasons: Vec<String>,
    #[serde(default)]
    pub coverage: Vec<CoverageItem>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub last_violation: Option<LastViolation>,
    #[serde(default)]
    pub incidents: Vec<String>,
    pub response_mode: String,
    #[serde(default)]
    pub response_taken: Vec<String>,
    /// The agent is currently frozen by Kill Line.
    #[serde(default)]
    pub frozen: bool,
    pub monitor_pid: u32,
    pub heartbeat: DateTime<Utc>,
    #[serde(skip)]
    pub process_table: BTreeMap<u32, ProcessRecord>,
    #[serde(skip)]
    files: HashSet<u64>,
}

impl Session {
    pub fn new(
        session_id: &str,
        agent: &str,
        policy: &str,
        target: &str,
        response_mode: &str,
    ) -> Session {
        let now = Utc::now();
        Session {
            session_id: session_id.into(),
            agent: agent.into(),
            policy: policy.into(),
            target: target.into(),
            started: now,
            ended: None,
            status: Status::Green,
            events: 0,
            violations: 0,
            violations_succeeded: 0,
            violations_blocked: 0,
            anomalies: 0,
            processes_seen: 0,
            files_accessed: 0,
            network_attempts: 0,
            dropped_events: 0,
            degraded_reasons: vec![],
            coverage: vec![],
            last_violation: None,
            incidents: vec![],
            response_mode: response_mode.into(),
            response_taken: vec![],
            frozen: false,
            monitor_pid: std::process::id(),
            heartbeat: now,
            process_table: BTreeMap::new(),
            files: HashSet::new(),
        }
    }

    pub fn degrade(&mut self, reason: impl Into<String>) {
        let r = reason.into();
        if !self.degraded_reasons.contains(&r) {
            self.degraded_reasons.push(r);
        }
        self.recompute();
    }

    pub fn recompute(&mut self) {
        self.status = if self.violations > 0 {
            Status::Red
        } else if !self.degraded_reasons.is_empty() {
            Status::Grey
        } else if self.anomalies > 0 {
            Status::Amber
        } else {
            Status::Green
        };
    }

    /// Status as seen by a reader of the on-disk snapshot: a live session
    /// whose monitor has stopped heart-beating cannot be verified.
    pub fn effective_status(&self, now: DateTime<Utc>) -> (Status, Vec<String>) {
        let mut reasons = self.degraded_reasons.clone();
        let mut status = self.status;
        if self.ended.is_none() && (now - self.heartbeat).num_seconds() > HEARTBEAT_STALE_SECS {
            reasons.push(format!(
                "Monitoring process (pid {}) unexpectedly stopped; last heartbeat {}s ago. Containment status cannot be verified.",
                self.monitor_pid,
                (now - self.heartbeat).num_seconds()
            ));
            if status != Status::Red {
                status = Status::Grey;
            }
        }
        (status, reasons)
    }

    /// Update counters and the process table from an evaluated event.
    pub fn apply(&mut self, ev: &Event) {
        self.events += 1;
        if let Some(p) = &ev.process {
            if !self.process_table.contains_key(&p.pid) {
                self.processes_seen += 1;
                self.process_table.insert(
                    p.pid,
                    ProcessRecord {
                        pid: p.pid,
                        ppid: p.ppid,
                        comm: p.comm.clone(),
                        exe: p.exe.clone(),
                        argv: vec![],
                        sha256: None,
                        uid: p.uid,
                        first_seen: ev.timestamp,
                        exited: None,
                    },
                );
            }
            match &ev.observation {
                Some(ObsKind::Exec {
                    path, argv, sha256, ..
                }) => {
                    if let Some(r) = self.process_table.get_mut(&p.pid) {
                        r.exe = Some(path.clone());
                        r.argv = argv.clone();
                        r.sha256 = sha256.clone();
                    }
                }
                Some(ObsKind::Exit) => {
                    if let Some(r) = self.process_table.get_mut(&p.pid) {
                        r.exited = Some(ev.timestamp);
                    }
                }
                Some(ObsKind::Open { path, .. }) => {
                    use std::hash::{Hash, Hasher};
                    let mut h = std::collections::hash_map::DefaultHasher::new();
                    path.hash(&mut h);
                    if self.files.insert(h.finish()) {
                        self.files_accessed += 1;
                    }
                }
                Some(ObsKind::Net { op, .. }) if *op != NetOp::Bind => self.network_attempts += 1,
                Some(ObsKind::Dns { .. }) => self.network_attempts += 1,
                _ => {}
            }
            if let Some(r) = self.process_table.get_mut(&p.pid) {
                r.comm = p.comm.clone();
            }
        }
        if ev.confirms_seq.is_none() {
            match ev.verdict {
                Verdict::Violation => {
                    self.violations += 1;
                    match &ev.outcome {
                        Some(Outcome::Succeeded) => self.violations_succeeded += 1,
                        Some(Outcome::Failed { .. }) => self.violations_blocked += 1,
                        _ => {}
                    }
                    self.last_violation = Some(LastViolation {
                        seq: ev.seq,
                        timestamp: ev.timestamp,
                        boundary: ev.category.boundary_name().to_string(),
                        summary: ev.resource_summary(),
                        explanation: ev.explanation.clone(),
                        process: ev
                            .process
                            .as_ref()
                            .map(|p| format!("{} (pid {})", p.comm, p.pid))
                            .unwrap_or_else(|| "-".into()),
                        policy_rule: ev.policy_rule.clone(),
                        expected: ev.expected.clone(),
                        outcome: ev.outcome.clone(),
                    });
                }
                Verdict::Anomaly => self.anomalies += 1,
                _ => {}
            }
        }
        self.recompute();
    }

    pub fn runtime(&self, now: DateTime<Utc>) -> String {
        let end = self.ended.unwrap_or(now);
        let s = (end - self.started).num_seconds().max(0);
        format!("{:02}:{:02}:{:02}", s / 3600, (s / 60) % 60, s % 60)
    }
}
