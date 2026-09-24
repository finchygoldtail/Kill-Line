//! Terminal rendering. Wording rule: never claim the agent is "safe".

use anyhow::{bail, Result};
use chrono::{Local, Utc};
use killline_core::event::{Event, FileAccess, ObsKind, Outcome, Verdict};
use killline_core::incident::{self, list_incidents};
use killline_core::policy::ResponseAction;
use killline_core::session::{Session, Status};
use killline_core::store::{self, find_session, list_sessions, read_timeline, verify_timeline};
use std::path::Path;
use std::sync::atomic::{AtomicBool, Ordering};

static COLOR: AtomicBool = AtomicBool::new(false);

/// println! that never panics: a closed terminal or pipe must not take the
/// monitor down with it.
macro_rules! say {
    () => {{
        use std::io::Write;
        let _ = writeln!(std::io::stdout());
    }};
    ($($t:tt)*) => {{
        use std::io::Write;
        let _ = writeln!(std::io::stdout(), $($t)*);
    }};
}

pub const RED: &str = "\x1b[1;31m";
pub const AMBER: &str = "\x1b[1;33m";
pub const GREEN: &str = "\x1b[1;32m";
pub const GREY: &str = "\x1b[1;37m";
pub const DIM: &str = "\x1b[2m";
pub const BOLD: &str = "\x1b[1m";

pub fn set_color(on: bool) {
    COLOR.store(on, Ordering::Relaxed);
}

pub fn paint(s: &str, code: &str) -> String {
    if COLOR.load(Ordering::Relaxed) {
        format!("{}{}\x1b[0m", code, s)
    } else {
        s.to_string()
    }
}

fn status_color(s: Status) -> &'static str {
    match s {
        Status::Green => GREEN,
        Status::Amber => AMBER,
        Status::Red => RED,
        Status::Grey => GREY,
    }
}

/// Strip control characters from anything that originated in the agent
/// (paths, comm, argv) so it cannot inject terminal escape sequences.
pub fn clean(s: &str) -> String {
    s.chars()
        .map(|c| if c.is_control() { '?' } else { c })
        .collect()
}

fn time(ev: &Event) -> String {
    ev.timestamp
        .with_timezone(&Local)
        .format("%H:%M:%S%.3f")
        .to_string()
}

fn rule() -> String {
    "═".repeat(60)
}

pub fn banner_start(s: &Session, policy_path: &str) {
    say!("{}", paint("KillLine monitoring started", BOLD));
    say!();
    say!("Agent:     {}", clean(&s.agent));
    say!("Target:    {}", clean(&s.target));
    say!("Policy:    {} ({})", clean(&s.policy), clean(policy_path));
    say!("Session:   {}", s.session_id);
    say!("Response:  {}", response_text(&s.response_mode));
    say!();
    say!(
        "Status:    {}",
        paint(s.status.label(), status_color(s.status))
    );
    say!("           {}", paint(s.status.meaning(), DIM));
    say!();
}

fn response_text(mode: &str) -> &'static str {
    match mode {
        "freeze" => "freeze agent on first violation",
        "terminate" => "terminate agent on first violation",
        _ => "alert only (monitor mode; nothing is blocked)",
    }
}

pub fn banner_end(s: &Session, reason: &str) {
    say!();
    say!("{}", paint(&rule(), status_color(s.status)));
    say!("KillLine monitoring stopped ({})", reason);
    say!(
        "Status:            {}",
        paint(s.status.label(), status_color(s.status))
    );
    say!("                   {}", s.status.meaning());
    say!("Runtime:           {}", s.runtime(Utc::now()));
    say!("Events recorded:   {}", s.events);
    say!("Processes:         {}", s.processes_seen);
    say!("Files accessed:    {}", s.files_accessed);
    say!("Network attempts:  {}", s.network_attempts);
    say!("Policy violations: {}{}", s.violations, breakdown(s));
    say!("Anomalies:         {}", s.anomalies);
    if s.dropped_events > 0 {
        say!(
            "Dropped events:    {}",
            paint(&s.dropped_events.to_string(), RED)
        );
    }
    for r in &s.degraded_reasons {
        say!("Degraded:          {}", paint(r, GREY));
    }
    if !s.incidents.is_empty() {
        say!("Incidents:         {}", s.incidents.join(", "));
    }
    say!("Timeline:          killline timeline {}", s.session_id);
    say!("{}", paint(&rule(), status_color(s.status)));
}

fn breakdown(s: &Session) -> String {
    if s.violations == 0 {
        return String::new();
    }
    let unknown = s.violations - s.violations_succeeded - s.violations_blocked;
    format!(
        "  ({} succeeded, {} failed or refused by the OS, {} result not observed)",
        s.violations_succeeded, s.violations_blocked, unknown
    )
}

pub fn status_change(s: &Session) {
    say!();
    say!(
        "Status:    {}",
        paint(s.status.label(), status_color(s.status))
    );
    say!("           {}", paint(s.status.meaning(), DIM));
    for r in &s.degraded_reasons {
        say!("           {}", paint(r, GREY));
    }
}

/// Short verb + object for a timeline line.
pub fn describe(ev: &Event) -> String {
    let what = clean(&ev.resource_summary());
    match (&ev.observation, ev.action.as_str()) {
        (Some(ObsKind::Exec { .. }), _) => format!("Spawned: {}", what),
        (Some(ObsKind::Open { path, access, .. }), a) => {
            let verb = match (a, access) {
                ("file.opened", _) => "Opened",
                (_, FileAccess::Write) => "Write",
                (_, FileAccess::List) => "List",
                _ => "Read",
            };
            format!("{}: {}", verb, clean(path))
        }
        (Some(ObsKind::Dns { .. }), _) => format!("Attempted {}", what),
        (Some(ObsKind::Net { .. }), _) => format!("Network {}", what),
        (Some(_), _) => what,
        (None, _) => clean(&ev.explanation),
    }
}

fn marker(ev: &Event) -> String {
    match ev.verdict {
        Verdict::Violation => paint("✖", RED),
        Verdict::Anomaly => paint("▲", AMBER),
        Verdict::Notice => paint("•", GREY),
        Verdict::Allowed => paint("·", DIM),
    }
}

fn proc_tag(ev: &Event) -> String {
    ev.process
        .as_ref()
        .map(|p| format!("[{} {}]", clean(&p.comm), p.pid))
        .unwrap_or_default()
}

fn outcome_tag(o: Option<&Outcome>) -> String {
    match o {
        Some(Outcome::Succeeded) => String::new(),
        Some(Outcome::InProgress) => paint(" (in progress)", DIM),
        Some(Outcome::Failed { error, .. }) => paint(
            &format!(" (failed: {})", error.split(' ').next().unwrap_or("")),
            DIM,
        ),
        None => String::new(),
    }
}

/// How the operating system responded, for alert blocks.
fn outcome_line(o: Option<&Outcome>) -> String {
    match o {
        Some(Outcome::Succeeded) => paint("SUCCEEDED — the boundary was actually crossed", RED),
        Some(f @ Outcome::Failed { error, .. }) if f.refused() => paint(
            &format!("REFUSED by the OS ({}) — the sandbox held this time", error),
            AMBER,
        ),
        Some(Outcome::Failed { error, .. }) => format!("failed ({})", error),
        Some(Outcome::InProgress) => {
            "connection started (non-blocking); completion not observed".into()
        }
        None => "not observed".into(),
    }
}

pub fn timeline_line(ev: &Event) -> String {
    format!(
        "{} {} {:<22} {}{}",
        paint(&time(ev), DIM),
        marker(ev),
        proc_tag(ev),
        describe(ev),
        outcome_tag(ev.outcome.as_ref())
    )
}

pub fn is_noise(ev: &Event) -> bool {
    matches!(
        ev.action.as_str(),
        "file.runtime_read"
            | "process.fork"
            | "process.exit"
            | "process.exec_not_found"
            | "socket.create"
            | "privilege.setid"
            | "file.open_unresolved"
            | "runtime.setup"
            | "file.write_blocked_benign"
    )
}

/// Live output while monitoring.
pub fn print_event(ev: &Event, verbose: u8) {
    if ev.verdict == Verdict::Violation || ev.verdict == Verdict::Anomaly {
        return; // printed as alert blocks
    }
    let show = match verbose {
        0 if ev.action == "process.exec_not_found" => false,
        0 => {
            matches!(
                ev.observation,
                Some(ObsKind::Exec { .. }) | Some(ObsKind::Net { .. }) | Some(ObsKind::Dns { .. })
            ) || ev.verdict == Verdict::Notice
        }
        1 => !is_noise(ev),
        _ => true,
    };
    if show {
        say!("{}", timeline_line(ev));
    }
}

pub fn alert_block(s: &Session, ev: &Event, response: &ResponseAction, incident: &str) {
    let r = rule();
    say!();
    say!("{}", paint(&r, RED));
    say!("{}", paint(" RED — KILLLINE TRIGGERED", RED));
    say!("{}", paint(&r, RED));
    say!(" Agent:     {}", clean(&s.agent));
    say!(" Boundary:  {}", paint(ev.category.boundary_name(), BOLD));
    if let Some(e) = &ev.expected {
        say!(" Expected:  {}", e);
    }
    say!(" Actual:    {}", describe(ev));
    if let Some(p) = &ev.process {
        let exe = p
            .exe
            .as_deref()
            .map(|e| format!(", {}", clean(e)))
            .unwrap_or_default();
        say!(
            " Process:   {} (pid {}, uid {}{})",
            clean(&p.comm),
            p.pid,
            p.uid,
            exe
        );
    }
    if let Some(rl) = &ev.policy_rule {
        say!(" Rule:      {}", rl);
    }
    let resp = match response {
        ResponseAction::Alert => "Alert generated (monitor mode — the action was not blocked)",
        ResponseAction::Freeze => "Alert generated; freezing agent",
        ResponseAction::Terminate => "Alert generated; terminating agent",
    };
    say!(" Result:    {}", outcome_line(ev.outcome.as_ref()));
    say!(" Response:  {}", resp);
    say!(" Time:      {}", time(ev));
    say!();
    say!(" {}", clean(&ev.explanation));
    for c in &ev.correlations {
        say!(" {} {}", paint("↳", AMBER), c.summary);
    }
    say!();
    say!(" Incident:  {}   (killline inspect {})", incident, incident);
    say!("{}", paint(&r, RED));
}

/// A violation identical to one already reported in this session.
pub fn repeat_line(ev: &Event) {
    say!(
        "{} {}",
        timeline_line(ev),
        paint("(repeat violation; recorded in timeline)", RED)
    );
}

pub fn anomaly_block(ev: &Event) {
    say!();
    say!(
        "{} {}",
        paint("AMBER — BEHAVIOURAL ANOMALY", AMBER),
        paint(&time(ev), DIM)
    );
    say!(" {}", clean(&ev.explanation));
    for c in &ev.correlations {
        say!(" {} {}", paint("↳", AMBER), c.summary);
    }
}

fn pick_session(root: &Path, id: Option<&str>) -> Result<Session> {
    match id {
        Some(id) => find_session(root, id),
        None => list_sessions(root)?
            .pop()
            .ok_or_else(|| anyhow::anyhow!("no sessions recorded in {}", root.display())),
    }
}

pub fn status(root: &Path, id: Option<&str>, watch: bool) -> Result<i32> {
    loop {
        let s = pick_session(root, id)?;
        let (st, reasons) = s.effective_status(Utc::now());
        if watch {
            print!("\x1b[2J\x1b[H");
        }
        say!("{}", paint("KILLLINE", BOLD));
        say!();
        say!("Agent:             {}", clean(&s.agent));
        say!("Target:            {}", clean(&s.target));
        say!("Session:           {}", s.session_id);
        say!("Status:            {}", paint(st.label(), status_color(st)));
        say!("                   {}", st.meaning());
        say!(
            "Runtime:           {}{}",
            s.runtime(Utc::now()),
            if s.ended.is_some() { " (ended)" } else { "" }
        );
        say!("Processes:         {}", s.processes_seen);
        say!("Files accessed:    {}", s.files_accessed);
        say!("Network attempts:  {}", s.network_attempts);
        say!("Policy violations: {}{}", s.violations, breakdown(&s));
        say!("Anomalies:         {}", s.anomalies);
        say!("Dropped events:    {}", s.dropped_events);
        for r in &reasons {
            say!("Degraded:          {}", paint(r, GREY));
        }
        if let Some(v) = &s.last_violation {
            say!();
            say!("{}", paint("RED — KILLLINE TRIGGERED", RED));
            say!("{}", v.boundary);
            say!("{} → {}", clean(&v.process), clean(&v.summary));
            say!("Result: {}", outcome_line(v.outcome.as_ref()));
            if let Some(e) = &v.expected {
                say!("Policy: {}", e);
            }
            if let Some(i) = s.incidents.last() {
                say!("Incident: {}  (killline inspect {})", i, i);
            }
        }
        say!();
        say!("Timeline: killline timeline {}", s.session_id);
        if !watch {
            return Ok(match st {
                Status::Green => 0,
                Status::Amber => 3,
                Status::Grey => 4,
                Status::Red => 10,
            });
        }
        std::thread::sleep(std::time::Duration::from_secs(1));
    }
}

pub fn sessions(root: &Path) -> Result<i32> {
    let all = list_sessions(root)?;
    if all.is_empty() {
        say!("No sessions recorded in {}", root.display());
        return Ok(0);
    }
    say!(
        "{:<30} {:<18} {:<28} {:>8} {:>6} {:>5}  {}",
        "SESSION",
        "AGENT",
        "STATUS",
        "RUNTIME",
        "EVENTS",
        "VIOL",
        "TARGET"
    );
    let now = Utc::now();
    for s in all {
        let (st, _) = s.effective_status(now);
        say!(
            "{:<30} {:<18} {:<28} {:>8} {:>6} {:>5}  {}",
            s.session_id,
            clean(&s.agent),
            paint(&format!("{:<28}", st.label()), status_color(st)),
            s.runtime(now),
            s.events,
            s.violations,
            clean(&s.target)
        );
    }
    Ok(0)
}

pub fn incidents(root: &Path) -> Result<i32> {
    let all = list_incidents(root)?;
    if all.is_empty() {
        say!(
            "No incidents recorded in {}",
            store::incidents_dir(root).display()
        );
        return Ok(0);
    }
    say!(
        "{:<26} {:<20} {:<16} {:<30} {}",
        "INCIDENT",
        "TIME",
        "AGENT",
        "BOUNDARY",
        "ACTUAL"
    );
    for i in all {
        say!(
            "{:<26} {:<20} {:<16} {:<30} {}",
            i.incident_id,
            i.created.with_timezone(&Local).format("%Y-%m-%d %H:%M:%S"),
            clean(&i.agent),
            i.boundary,
            clean(&i.actual)
        );
    }
    Ok(0)
}

pub fn inspect(root: &Path, id: &str, raw: bool) -> Result<i32> {
    let dir = incident::incident_dir(root, id)?;
    let inc: incident::Incident =
        serde_json::from_str(&std::fs::read_to_string(dir.join("incident.json"))?)?;
    if raw {
        say!("{}", serde_json::to_string_pretty(&inc.trigger)?);
        return Ok(0);
    }
    let r = rule();
    say!("{}", paint(&r, RED));
    say!("{}", paint(&format!(" {}", inc.incident_id), RED));
    say!("{}", paint(&r, RED));
    say!(" Agent:     {}", clean(&inc.agent));
    say!(" Session:   {}", inc.session_id);
    say!(" Boundary:  {}", inc.boundary);
    if let Some(e) = &inc.expected {
        say!(" Expected:  {}", e);
    }
    say!(" Actual:    {}", clean(&inc.actual));
    if let Some(p) = &inc.process {
        say!(" Process:   {}", clean(p));
    }
    if let Some(rl) = &inc.policy_rule {
        say!(" Rule:      {}", rl);
    }
    say!(" Result:    {}", outcome_line(inc.trigger.outcome.as_ref()));
    say!(
        " Time:      {}",
        inc.trigger
            .timestamp
            .with_timezone(&Local)
            .format("%Y-%m-%d %H:%M:%S%.3f")
    );
    for resp in &inc.response {
        say!(" Response:  {}", resp);
    }
    say!();
    say!(" {}", clean(&inc.explanation));
    for c in &inc.trigger.correlations {
        say!(" {} {}", paint("↳", AMBER), c.summary);
    }

    // What happened immediately before (and after) the breach.
    let tl = read_timeline_file(&dir.join("timeline.jsonl"))?;
    let trig = inc.trigger.seq;
    let before: Vec<&Event> = tl.iter().filter(|e| e.seq < trig && !is_noise(e)).collect();
    let after: Vec<&Event> = tl
        .iter()
        .filter(|e| e.seq > trig && !is_noise(e))
        .take(15)
        .collect();
    say!();
    say!(
        "{}",
        paint(
            " Timeline (most recent notable events before the breach; similar reads collapsed)",
            BOLD
        )
    );
    let groups = collapse(&before);
    for g in groups.iter().rev().take(25).rev() {
        say!("   {}", g);
    }
    say!(
        "   {}",
        paint(
            &format!(
                "{}  KILLLINE TRIGGERED — {}",
                time(&inc.trigger),
                inc.boundary
            ),
            RED
        )
    );
    for e in after {
        say!("   {}", timeline_line(e));
    }
    say!();
    let bad = incident::verify_checksums(&dir)?;
    if bad.is_empty() {
        say!(
            " Bundle:    {} ({} files, checksums OK)",
            dir.display(),
            incident::FILES.len() + 1
        );
    } else {
        say!(
            " Bundle:    {} {}",
            dir.display(),
            paint(&format!("CHECKSUM MISMATCH: {}", bad.join(", ")), RED)
        );
    }
    say!(" Raw event: killline inspect {} --raw", inc.incident_id);
    for n in &inc.notes {
        say!(" {}", paint(&format!("Note: {}", n), DIM));
    }
    Ok(0)
}

/// Collapse runs of allowed file accesses by the same process in the same
/// directory into one line, so a burst of reads cannot push the context that
/// matters (e.g. the untrusted document read) out of view.
fn collapse(events: &[&Event]) -> Vec<String> {
    let dir_of = |e: &Event| -> Option<(u32, String)> {
        match (&e.observation, e.verdict) {
            (Some(ObsKind::Open { path, .. }), Verdict::Allowed) => {
                let d = path.rsplit_once('/').map(|(d, _)| d.to_string())?;
                Some((e.process.as_ref().map(|p| p.pid).unwrap_or(0), d))
            }
            _ => None,
        }
    };
    let mut out = Vec::new();
    let mut i = 0;
    while i < events.len() {
        let key = dir_of(events[i]);
        let mut j = i + 1;
        if key.is_some() {
            while j < events.len() && dir_of(events[j]) == key {
                j += 1;
            }
        }
        let n = j - i;
        if n >= 4 {
            let (_, dir) = key.unwrap();
            out.push(format!(
                "{} {} {:<22} {}",
                paint(&time(events[i]), DIM),
                marker(events[i]),
                proc_tag(events[i]),
                paint(
                    &format!(
                        "… {} file accesses under {}/ (until {})",
                        n,
                        clean(&dir),
                        time(events[j - 1])
                    ),
                    DIM
                )
            ));
        } else {
            for e in &events[i..j] {
                out.push(timeline_line(e));
            }
        }
        i = j;
    }
    out
}

fn read_timeline_file(p: &Path) -> Result<Vec<Event>> {
    let text = std::fs::read_to_string(p)?;
    text.lines()
        .filter(|l| !l.trim().is_empty())
        .map(|l| Ok(serde_json::from_str(l)?))
        .collect()
}

pub fn timeline(root: &Path, id: Option<&str>, all: bool, json: bool) -> Result<i32> {
    let s = pick_session(root, id)?;
    let path = store::sessions_dir(root)
        .join(&s.session_id)
        .join("timeline.jsonl");
    if json {
        print!("{}", std::fs::read_to_string(&path)?);
        return Ok(0);
    }
    let events = read_timeline(&path)?;
    say!(
        "Session {}  agent {}  {}",
        s.session_id,
        clean(&s.agent),
        paint(
            s.effective_status(Utc::now()).0.label(),
            status_color(s.status)
        )
    );
    let mut hidden = 0;
    for e in &events {
        if !all && is_noise(e) {
            hidden += 1;
            continue;
        }
        say!("{}", timeline_line(e));
        if e.verdict == Verdict::Violation && e.confirms_seq.is_none() {
            say!(
                "{}",
                paint(
                    &format!(
                        "             KILLLINE TRIGGERED — {}",
                        e.category.boundary_name()
                    ),
                    RED
                )
            );
            say!("             {}", clean(&e.explanation));
            for c in &e.correlations {
                say!("             {} {}", paint("↳", AMBER), c.summary);
            }
        }
    }
    if hidden > 0 {
        say!(
            "{}",
            paint(
                &format!("({} runtime/bookkeeping events hidden; use --all)", hidden),
                DIM
            )
        );
    }
    Ok(0)
}

pub fn verify(root: &Path, id: &str) -> Result<i32> {
    if id.starts_with("incident-") {
        let dir = incident::incident_dir(root, id)?;
        let bad = incident::verify_checksums(&dir)?;
        if bad.is_empty() {
            say!("{}: all checksums match", id);
            return Ok(0);
        }
        say!(
            "{}: {}",
            id,
            paint(&format!("MODIFIED: {}", bad.join(", ")), RED)
        );
        return Ok(1);
    }
    let s = find_session(root, id)?;
    let path = store::sessions_dir(root)
        .join(&s.session_id)
        .join("timeline.jsonl");
    let r = verify_timeline(&path)?;
    if r.ok {
        say!(
            "{}: hash chain intact ({} records, head {})",
            s.session_id,
            r.records,
            &r.head[..16]
        );
        Ok(0)
    } else {
        say!(
            "{}: {}",
            s.session_id,
            paint(
                &format!(
                    "CHAIN BROKEN after {} records: {}",
                    r.records,
                    r.first_error.unwrap_or_default()
                ),
                RED
            )
        );
        bail!("timeline integrity check failed")
    }
}
