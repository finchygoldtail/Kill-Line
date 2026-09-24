//! Forensic incident bundles.
//!
//! Written locally when a boundary is crossed. Contains metadata about what
//! happened — never file contents, and command lines are already redacted.

use crate::event::{Category, Event};
use crate::session::{ProcessRecord, Session};
use crate::store::{self, private_dir, write_private};
use anyhow::{Context, Result};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};

pub const FILES: &[&str] = &[
    "incident.json",
    "timeline.jsonl",
    "process_tree.json",
    "network_events.json",
    "filesystem_events.json",
    "policy.yaml",
    "system_metadata.json",
];

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Incident {
    pub incident_id: String,
    pub session_id: String,
    pub agent: String,
    pub created: DateTime<Utc>,
    pub boundary: String,
    pub expected: Option<String>,
    pub actual: String,
    pub explanation: String,
    pub process: Option<String>,
    pub policy_rule: Option<String>,
    pub trigger: Event,
    pub response: Vec<String>,
    pub finalized: bool,
    /// Events recorded after the trigger (until finalisation).
    pub events_after_trigger: usize,
    pub timeline_head_hash: String,
    pub notes: Vec<String>,
}

/// An incident being assembled: written at trigger time, rewritten when
/// post-trigger context has been collected.
pub struct PendingIncident {
    pub dir: PathBuf,
    pub incident: Incident,
    pub before: Vec<Event>,
    pub after: Vec<Event>,
    pub deadline: DateTime<Utc>,
}

pub fn next_incident_id(root: &Path, now: DateTime<Utc>) -> Result<(String, PathBuf)> {
    let base = store::incidents_dir(root);
    private_dir(&base)?;
    let day = now.format("%Y-%m-%d").to_string();
    for n in 1..10000 {
        let id = format!("incident-{}-{:03}", day, n);
        let dir = base.join(&id);
        // create_dir is atomic: two monitors cannot claim the same id.
        match fs::create_dir(&dir) {
            Ok(()) => {
                use std::os::unix::fs::PermissionsExt;
                fs::set_permissions(&dir, fs::Permissions::from_mode(0o700))?;
                return Ok((id, dir));
            }
            Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => continue,
            Err(e) => return Err(e).context("creating incident directory"),
        }
    }
    anyhow::bail!("too many incidents today")
}

impl PendingIncident {
    pub fn new(root: &Path, session: &Session, trigger: &Event, before: Vec<Event>, head: &str) -> Result<PendingIncident> {
        let now = Utc::now();
        let (id, dir) = next_incident_id(root, now)?;
        let incident = Incident {
            incident_id: id,
            session_id: session.session_id.clone(),
            agent: session.agent.clone(),
            created: now,
            boundary: trigger.category.boundary_name().to_string(),
            expected: trigger.expected.clone(),
            actual: trigger.resource_summary(),
            explanation: trigger.explanation.clone(),
            process: trigger.process.as_ref().map(|p| format!("{} (pid {}, uid {})", p.comm, p.pid, p.uid)),
            policy_rule: trigger.policy_rule.clone(),
            trigger: trigger.clone(),
            response: vec![],
            finalized: false,
            events_after_trigger: 0,
            timeline_head_hash: head.to_string(),
            notes: vec![
                "KillLine observes system calls from outside the agent. It reports what it saw, not intent.".into(),
                "Correlations are possible links, not proof of causation.".into(),
                "File contents are never captured. Command-line arguments are redacted by default.".into(),
                "timeline_head_hash anchors this bundle to the session's hash-chained timeline.".into(),
            ],
        };
        Ok(PendingIncident { dir, incident, before, after: vec![], deadline: now + chrono::Duration::seconds(5) })
    }

    pub fn write(&self, session: &Session, policy_text: &str, system: &serde_json::Value) -> Result<()> {
        let d = &self.dir;
        let all: Vec<&Event> = self.before.iter().chain(self.after.iter()).collect();
        let mut tl = String::new();
        for e in &all {
            tl.push_str(&serde_json::to_string(e)?);
            tl.push('\n');
        }
        let mut inc = self.incident.clone();
        inc.events_after_trigger = self.after.len();
        inc.response = session.response_taken.clone();
        write_private(&d.join("incident.json"), serde_json::to_string_pretty(&inc)?.as_bytes())?;
        write_private(&d.join("timeline.jsonl"), tl.as_bytes())?;
        write_private(&d.join("process_tree.json"), serde_json::to_string_pretty(&process_tree(&session.process_table))?.as_bytes())?;
        let net: Vec<&&Event> = all
            .iter()
            .filter(|e| matches!(e.category, Category::Network | Category::Dns | Category::CloudMetadata | Category::ContainerRuntime))
            .collect();
        write_private(&d.join("network_events.json"), serde_json::to_string_pretty(&net)?.as_bytes())?;
        let fs_ev: Vec<&&Event> = all
            .iter()
            .filter(|e| matches!(e.category, Category::Filesystem | Category::Credential | Category::ContainerEscape))
            .collect();
        write_private(&d.join("filesystem_events.json"), serde_json::to_string_pretty(&fs_ev)?.as_bytes())?;
        write_private(&d.join("policy.yaml"), policy_text.as_bytes())?;
        write_private(&d.join("system_metadata.json"), serde_json::to_string_pretty(system)?.as_bytes())?;
        write_checksums(d)?;
        Ok(())
    }
}

pub fn write_checksums(dir: &Path) -> Result<()> {
    let mut out = String::new();
    for f in FILES {
        let bytes = fs::read(dir.join(f)).with_context(|| format!("reading {}", f))?;
        out.push_str(&format!("{}  {}\n", hex::encode(Sha256::digest(&bytes)), f));
    }
    write_private(&dir.join("checksums.txt"), out.as_bytes())
}

/// Verify checksums.txt; returns the files that do not match.
pub fn verify_checksums(dir: &Path) -> Result<Vec<String>> {
    let text = fs::read_to_string(dir.join("checksums.txt"))?;
    let mut bad = Vec::new();
    for line in text.lines() {
        let Some((sum, name)) = line.split_once("  ") else { continue };
        match fs::read(dir.join(name)) {
            Ok(b) if hex::encode(Sha256::digest(&b)) == sum => {}
            _ => bad.push(name.to_string()),
        }
    }
    Ok(bad)
}

#[derive(Debug, Serialize)]
pub struct TreeNode {
    #[serde(flatten)]
    pub process: ProcessRecord,
    pub children: Vec<TreeNode>,
}

pub fn process_tree(table: &BTreeMap<u32, ProcessRecord>) -> Vec<TreeNode> {
    fn build(pid: u32, table: &BTreeMap<u32, ProcessRecord>, depth: usize) -> TreeNode {
        let children = if depth > 64 {
            vec![]
        } else {
            table.values().filter(|p| p.ppid == pid && p.pid != pid).map(|p| build(p.pid, table, depth + 1)).collect()
        };
        TreeNode { process: table[&pid].clone(), children }
    }
    table
        .values()
        .filter(|p| !table.contains_key(&p.ppid) || p.ppid == p.pid)
        .map(|p| build(p.pid, table, 0))
        .collect()
}

pub fn list_incidents(root: &Path) -> Result<Vec<Incident>> {
    let d = store::incidents_dir(root);
    let mut out = Vec::new();
    if !d.exists() {
        return Ok(out);
    }
    for e in fs::read_dir(d)? {
        let e = e?;
        if let Ok(t) = fs::read_to_string(e.path().join("incident.json")) {
            if let Ok(i) = serde_json::from_str::<Incident>(&t) {
                out.push(i);
            }
        }
    }
    out.sort_by(|a, b| a.incident_id.cmp(&b.incident_id));
    Ok(out)
}

pub fn incident_dir(root: &Path, id: &str) -> Result<PathBuf> {
    if !id.chars().all(|c| c.is_ascii_alphanumeric() || c == '-') {
        anyhow::bail!("invalid incident id");
    }
    let d = store::incidents_dir(root).join(id);
    if !d.join("incident.json").exists() {
        anyhow::bail!("no incident '{}' in {}", id, store::incidents_dir(root).display());
    }
    Ok(d)
}
