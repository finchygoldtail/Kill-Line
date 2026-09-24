//! Local, append-only event store.
//!
//! Layout under the data directory:
//!
//! ```text
//! sessions/<session-id>/session.json    status snapshot (atomically replaced)
//! sessions/<session-id>/timeline.jsonl  hash-chained flight recorder
//! sessions/<session-id>/policy.yaml     the policy in force
//! incidents/incident-YYYY-MM-DD-NNN/    forensic bundles
//! ```
//!
//! Each timeline line is `{"seq":…,"prev":…,"hash":…,"event":{…}}` where
//! `hash = sha256(prev + "\n" + event_json)`. Editing, removing or reordering
//! a line breaks the chain from that point, which `killline verify` reports.
//! The chain is tamper-evident, not tamper-proof: an attacker with write
//! access can rewrite the whole file. See docs/SECURITY_MODEL.md.

use crate::event::Event;
use crate::session::Session;
use anyhow::{bail, Context, Result};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::fs::{self, File, OpenOptions};
use std::io::{BufRead, BufReader, BufWriter, Write};
use std::os::unix::fs::{DirBuilderExt, OpenOptionsExt};
use std::path::{Path, PathBuf};

pub const GENESIS: &str = "0000000000000000000000000000000000000000000000000000000000000000";

pub fn data_dir() -> PathBuf {
    if let Ok(d) = std::env::var("KILLLINE_HOME") {
        return PathBuf::from(d);
    }
    let is_root = unsafe_geteuid() == 0;
    if is_root {
        PathBuf::from("/var/lib/killline")
    } else if let Ok(h) = std::env::var("HOME") {
        PathBuf::from(h).join(".local/share/killline")
    } else {
        PathBuf::from("./killline-data")
    }
}

fn unsafe_geteuid() -> u32 {
    // Avoid a libc dependency in core: read the effective uid from procfs.
    fs::read_to_string("/proc/self/status")
        .ok()
        .and_then(|s| {
            s.lines()
                .find(|l| l.starts_with("Uid:"))
                .and_then(|l| l.split_whitespace().nth(2).and_then(|v| v.parse().ok()))
        })
        .unwrap_or(u32::MAX)
}

/// Create a directory readable only by its owner (forensic data can reveal
/// paths and host details).
pub fn private_dir(p: &Path) -> Result<()> {
    fs::DirBuilder::new()
        .recursive(true)
        .mode(0o700)
        .create(p)
        .with_context(|| format!("creating {}", p.display()))
}

pub fn write_private(path: &Path, bytes: &[u8]) -> Result<()> {
    let tmp = path.with_extension("tmp");
    {
        let mut f = OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .mode(0o600)
            .open(&tmp)?;
        f.write_all(bytes)?;
        f.sync_all().ok();
    }
    fs::rename(&tmp, path)?;
    Ok(())
}

#[derive(Debug, Serialize, Deserialize)]
pub struct ChainRecord {
    pub seq: u64,
    pub prev: String,
    pub hash: String,
    pub event: serde_json::Value,
}

pub fn chain_hash(prev: &str, event_json: &str) -> String {
    let mut h = Sha256::new();
    h.update(prev.as_bytes());
    h.update(b"\n");
    h.update(event_json.as_bytes());
    hex::encode(h.finalize())
}

pub struct SessionStore {
    pub dir: PathBuf,
    /// Buffered; the monitor flushes at least once per second and before
    /// every incident bundle, so a crash loses at most ~1s of timeline.
    timeline: BufWriter<File>,
    last_hash: String,
}

impl SessionStore {
    pub fn create(root: &Path, session_id: &str, policy_text: &str) -> Result<SessionStore> {
        let dir = root.join("sessions").join(session_id);
        if dir.exists() {
            bail!("session directory {} already exists", dir.display());
        }
        private_dir(&dir)?;
        write_private(&dir.join("policy.yaml"), policy_text.as_bytes())?;
        let timeline = OpenOptions::new()
            .append(true)
            .create_new(true)
            .mode(0o600)
            .open(dir.join("timeline.jsonl"))?;
        Ok(SessionStore {
            dir,
            timeline: BufWriter::with_capacity(256 * 1024, timeline),
            last_hash: GENESIS.to_string(),
        })
    }

    pub fn append(&mut self, ev: &Event) -> Result<()> {
        let event_json = serde_json::to_string(ev)?;
        let hash = chain_hash(&self.last_hash, &event_json);
        let line = format!(
            "{{\"seq\":{},\"prev\":\"{}\",\"hash\":\"{}\",\"event\":{}}}\n",
            ev.seq, self.last_hash, hash, event_json
        );
        self.timeline.write_all(line.as_bytes())?;
        self.last_hash = hash;
        Ok(())
    }

    pub fn head(&self) -> &str {
        &self.last_hash
    }

    pub fn flush(&mut self) -> Result<()> {
        self.timeline.flush()?;
        Ok(())
    }

    pub fn save_session(&self, s: &Session) -> Result<()> {
        write_private(
            &self.dir.join("session.json"),
            serde_json::to_string_pretty(s)?.as_bytes(),
        )
    }
}

pub fn sessions_dir(root: &Path) -> PathBuf {
    root.join("sessions")
}

pub fn incidents_dir(root: &Path) -> PathBuf {
    root.join("incidents")
}

pub fn list_sessions(root: &Path) -> Result<Vec<Session>> {
    let mut out = Vec::new();
    let d = sessions_dir(root);
    if !d.exists() {
        return Ok(out);
    }
    for e in fs::read_dir(d)? {
        let e = e?;
        if let Ok(text) = fs::read_to_string(e.path().join("session.json")) {
            if let Ok(s) = serde_json::from_str::<Session>(&text) {
                out.push(s);
            }
        }
    }
    out.sort_by_key(|s| s.started);
    Ok(out)
}

/// Find a session by full id or unique prefix.
pub fn find_session(root: &Path, id: &str) -> Result<Session> {
    let all = list_sessions(root)?;
    let m: Vec<_> = all
        .into_iter()
        .filter(|s| s.session_id.starts_with(id))
        .collect();
    match m.len() {
        0 => bail!("no session matching '{}'", id),
        1 => Ok(m.into_iter().next().unwrap()),
        _ => bail!("'{}' matches more than one session", id),
    }
}

pub fn read_timeline(path: &Path) -> Result<Vec<Event>> {
    let f = File::open(path).with_context(|| format!("opening {}", path.display()))?;
    let mut out = Vec::new();
    for line in BufReader::new(f).lines() {
        let line = line?;
        if line.trim().is_empty() {
            continue;
        }
        let rec: ChainRecord = serde_json::from_str(&line)?;
        out.push(serde_json::from_value(rec.event)?);
    }
    Ok(out)
}

#[derive(Debug, Serialize)]
pub struct VerifyReport {
    pub records: u64,
    pub ok: bool,
    pub head: String,
    pub first_error: Option<String>,
}

/// Verify the hash chain of a timeline file.
pub fn verify_timeline(path: &Path) -> Result<VerifyReport> {
    let text = fs::read_to_string(path).with_context(|| format!("reading {}", path.display()))?;
    let mut prev = GENESIS.to_string();
    let mut n = 0u64;
    let mut last_seq = 0u64;
    for (i, line) in text.lines().enumerate() {
        if line.trim().is_empty() {
            continue;
        }
        let fail = |m: String| VerifyReport {
            records: n,
            ok: false,
            head: String::new(),
            first_error: Some(format!("line {}: {}", i + 1, m)),
        };
        // Recover the exact event JSON as written: it is everything after
        // `"event":` up to the final closing brace.
        let Some(idx) = line.find(",\"event\":") else {
            return Ok(fail("malformed record".into()));
        };
        let event_json = &line[idx + 9..line.len() - 1];
        let rec: ChainRecord = match serde_json::from_str(line) {
            Ok(r) => r,
            Err(e) => return Ok(fail(format!("unparseable: {}", e))),
        };
        if rec.prev != prev {
            return Ok(fail(
                "previous-hash link broken (record removed, inserted or reordered)".into(),
            ));
        }
        if chain_hash(&prev, event_json) != rec.hash {
            return Ok(fail("hash mismatch (record modified)".into()));
        }
        if rec.seq <= last_seq && n > 0 {
            return Ok(fail("sequence number not increasing".into()));
        }
        last_seq = rec.seq;
        prev = rec.hash;
        n += 1;
    }
    Ok(VerifyReport {
        records: n,
        ok: true,
        head: prev,
        first_error: None,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::event::*;
    use chrono::Utc;

    fn ev(seq: u64) -> Event {
        Event {
            seq,
            timestamp: Utc::now(),
            session_id: "s".into(),
            agent_id: "a".into(),
            category: Category::Process,
            action: "process.exec".into(),
            severity: Severity::Info,
            verdict: Verdict::Allowed,
            allowed: true,
            process: None,
            observation: None,
            outcome: None,
            policy_rule: None,
            expected: None,
            explanation: "x".into(),
            correlations: vec![],
            confirms_seq: None,
        }
    }

    #[test]
    fn chain_detects_tampering() {
        let root = std::env::temp_dir().join(format!("kl-test-{}", std::process::id()));
        let _ = fs::remove_dir_all(&root);
        let mut s = SessionStore::create(&root, "sess1", "agent: a\n").unwrap();
        for i in 1..=5 {
            s.append(&ev(i)).unwrap();
        }
        s.flush().unwrap();
        let tl = s.dir.join("timeline.jsonl");
        let r = verify_timeline(&tl).unwrap();
        assert!(r.ok && r.records == 5);

        let text = fs::read_to_string(&tl).unwrap();
        fs::write(
            &tl,
            text.replacen("\"explanation\":\"x\"", "\"explanation\":\"y\"", 1),
        )
        .unwrap();
        assert!(!verify_timeline(&tl).unwrap().ok);

        let lines: Vec<&str> = text.lines().collect();
        let removed = [lines[0], lines[2], lines[3], lines[4]].join("\n");
        fs::write(&tl, removed).unwrap();
        assert!(!verify_timeline(&tl).unwrap().ok);
        let _ = fs::remove_dir_all(&root);
    }
}
