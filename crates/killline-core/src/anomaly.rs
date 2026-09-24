//! Behavioural layer (AMBER).
//!
//! Deliberately simple, deterministic sliding-window heuristics. They run only
//! after the hard policy checks and never replace them. No machine learning.

use crate::event::{NetOp, ObsKind, Observation};
use crate::policy::AnomalyPolicy;
use chrono::{DateTime, Duration, Utc};
use std::collections::{HashMap, HashSet, VecDeque};

pub struct AnomalyFinding {
    pub action: &'static str,
    pub explanation: String,
}

pub struct AnomalyDetector {
    cfg: AnomalyPolicy,
    files: VecDeque<(DateTime<Utc>, String)>,
    /// Occurrence count per path inside the window, maintained incrementally.
    file_counts: HashMap<String, u32>,
    dests: VecDeque<(DateTime<Utc>, String)>,
    execs: VecDeque<DateTime<Utc>>,
    last_fired: [Option<DateTime<Utc>>; 3],
}

impl AnomalyDetector {
    pub fn new(cfg: AnomalyPolicy) -> Self {
        AnomalyDetector { cfg, files: VecDeque::new(), file_counts: HashMap::new(), dests: VecDeque::new(), execs: VecDeque::new(), last_fired: [None; 3] }
    }

    fn window(&self) -> Duration {
        Duration::seconds(self.cfg.window_secs as i64)
    }

    /// Fire at most once per three windows per detector, so a sustained
    /// burst produces one AMBER event rather than thousands.
    fn cooled(&mut self, idx: usize, now: DateTime<Utc>) -> bool {
        match self.last_fired[idx] {
            Some(t) if now - t < self.window() * 3 => false,
            _ => {
                self.last_fired[idx] = Some(now);
                true
            }
        }
    }

    pub fn observe(&mut self, obs: &Observation, runtime_path: bool) -> Vec<AnomalyFinding> {
        let now = obs.timestamp;
        let horizon = now - self.window();
        let mut out = Vec::new();
        match &obs.kind {
            ObsKind::Open { path, .. } if !runtime_path => {
                self.files.push_back((now, path.clone()));
                *self.file_counts.entry(path.clone()).or_insert(0) += 1;
                while self.files.len() > 100_000 || self.files.front().map(|(t, _)| *t < horizon).unwrap_or(false) {
                    if let Some((_, old)) = self.files.pop_front() {
                        if let Some(c) = self.file_counts.get_mut(&old) {
                            *c -= 1;
                            if *c == 0 {
                                self.file_counts.remove(&old);
                            }
                        }
                    }
                }
                let distinct = self.file_counts.len();
                if distinct >= self.cfg.file_burst_threshold && self.cooled(0, now) {
                    let mut dirs: Vec<&str> = self
                        .file_counts
                        .keys()
                        .filter_map(|p| p.rsplit_once('/').map(|(d, _)| if d.is_empty() { "/" } else { d }))
                        .collect::<HashSet<_>>()
                        .into_iter()
                        .collect();
                    dirs.sort();
                    dirs.truncate(5);
                    out.push(AnomalyFinding {
                        action: "anomaly.file_enumeration",
                        explanation: format!(
                            "Behavioural anomaly: the agent touched {} distinct files in {}s (threshold {}), \
                             e.g. under {}. Rapid enumeration often precedes credential hunting or data collection. \
                             This is not a policy violation by itself.",
                            distinct,
                            self.cfg.window_secs,
                            self.cfg.file_burst_threshold,
                            dirs.join(", ")
                        ),
                    });
                }
            }
            ObsKind::Net { op: NetOp::Connect | NetOp::Send, addr, port } => {
                self.dests.push_back((now, format!("{}:{}", addr, port)));
                while self.dests.front().map(|(t, _)| *t < horizon).unwrap_or(false) {
                    self.dests.pop_front();
                }
                let distinct = self.dests.iter().map(|(_, d)| d.as_str()).collect::<HashSet<&str>>().len();
                if distinct >= self.cfg.network_scan_threshold && self.cooled(1, now) {
                    out.push(AnomalyFinding {
                        action: "anomaly.network_scan",
                        explanation: format!(
                            "Behavioural anomaly: {} distinct network destinations contacted in {}s. \
                             This pattern resembles network scanning.",
                            distinct,
                            self.cfg.window_secs
                        ),
                    });
                }
            }
            ObsKind::Exec { .. } => {
                self.execs.push_back(now);
                while self.execs.front().map(|t| *t < horizon).unwrap_or(false) {
                    self.execs.pop_front();
                }
                if self.execs.len() >= self.cfg.exec_burst_threshold && self.cooled(2, now) {
                    out.push(AnomalyFinding {
                        action: "anomaly.exec_burst",
                        explanation: format!(
                            "Behavioural anomaly: {} programs started in {}s.",
                            self.execs.len(),
                            self.cfg.window_secs
                        ),
                    });
                }
            }
            _ => {}
        }
        out
    }
}
