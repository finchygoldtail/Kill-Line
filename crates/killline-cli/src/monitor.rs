//! The monitoring loop: sensor → engine → flight recorder → alerts/incidents.

use crate::launch;
use crate::views::{self, paint};
use anyhow::{Context, Result};
use chrono::Utc;
use killline_core::engine::Engine;
use killline_core::event::{Category, Event, Severity, Verdict};
use killline_core::incident::PendingIncident;
use killline_core::policy::{Policy, ResponseAction};
use killline_core::session::{Session, Status};
use killline_core::store::{private_dir, SessionStore};
use killline_sensor::respond::{self, Handle};
use killline_sensor::{target, Scope, Sensor};
use std::collections::VecDeque;
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};

static STOP: AtomicBool = AtomicBool::new(false);

extern "C" fn on_signal(_: i32) {
    STOP.store(true, Ordering::SeqCst);
}

pub enum Target {
    Container(String),
    Pid(u32),
    Launch {
        command: Vec<String>,
        uid: Option<u32>,
        gid: Option<u32>,
    },
}

pub struct Options {
    pub root: PathBuf,
    pub target: Target,
    pub policy: PathBuf,
    pub response: Option<ResponseAction>,
    pub verbose: u8,
    pub duration: Option<u64>,
}

const MAX_INCIDENTS_PER_SESSION: usize = 25;
const QUIET_TICKS_BEFORE_EXIT: u32 = if cfg!(windows) { 3 } else { 1 };
const CONTEXT_EVENTS: usize = 2000;

fn session_id() -> String {
    let mut b = [0u8; 6];
    if let Ok(mut f) = std::fs::File::open("/dev/urandom") {
        use std::io::Read;
        let _ = f.read_exact(&mut b);
    }
    format!(
        "{}-{}",
        Utc::now().format("%Y%m%d-%H%M%S"),
        b.iter().map(|x| format!("{:02x}", x)).collect::<String>()
    )
}

fn system_metadata(session: &Session, head: &str) -> serde_json::Value {
    let host = crate::platform::host_info();
    serde_json::json!({
        "killline_version": killline_core::VERSION,
        "kernel": host.kernel,
        "os": host.os,
        "hostname": host.hostname,
        "boot_id": host.boot_id,
        "monitor_pid": std::process::id(),
        "sensor": killline_sensor::sensor_name(),
        "coverage": session.coverage,
        "dropped_events": session.dropped_events,
        "degraded_reasons": session.degraded_reasons,
        "timeline_head_hash": head,
        "generated": Utc::now(),
    })
}

/// The dashboard asks the monitor to act by dropping `control.json` into the
/// session directory (root-only, 0700). The monitor owns the sensor and the
/// tracked PIDs, so it is the one that executes the action.
fn take_control_request(dir: &std::path::Path) -> Option<String> {
    let p = dir.join("control.json");
    let text = std::fs::read_to_string(&p).ok()?;
    let _ = std::fs::remove_file(&p);
    let v: serde_json::Value = serde_json::from_str(&text).ok()?;
    let a = v.get("action")?.as_str()?;
    matches!(a, "freeze" | "resume" | "terminate" | "stop").then(|| a.to_string())
}

pub fn run(opts: Options) -> Result<i32> {
    let policy_text = std::fs::read_to_string(&opts.policy)
        .with_context(|| format!("reading {}", opts.policy.display()))?;
    let policy = Policy::load(&opts.policy)?;
    let compiled = policy.compile()?;
    let response = opts.response.unwrap_or(policy.response.violation);

    // Resolve the agent's identity.
    let mut launched = None;
    let (scope, handle, target_label, liveness_pid) = match &opts.target {
        Target::Container(name) => {
            let c = target::docker_container(name)?;
            #[cfg(target_os = "linux")]
            let pids = target::pids_in_ns(c.pidns);
            #[cfg(not(target_os = "linux"))]
            let pids: Vec<u32> = vec![];
            let label = format!("container:{} ({})", c.name, &c.id[..12]);
            (
                Scope {
                    pids,
                    pidns: Some(c.pidns),
                },
                Handle::Container(c.id.clone()),
                label,
                c.init_pid,
            )
        }
        Target::Pid(pid) => {
            let pids = target::pid_tree(*pid);
            if !target::pid_exists(*pid) {
                anyhow::bail!("no process {}", pid);
            }
            (
                Scope { pids, pidns: None },
                Handle::Pids,
                format!("process:{}", pid),
                *pid,
            )
        }
        Target::Launch { command, uid, gid } => {
            let l = launch::spawn(command, *uid, *gid)?;
            let pid = l.child.id();
            launched = Some(l);
            (
                Scope {
                    pids: vec![pid],
                    pidns: None,
                },
                Handle::Pids,
                format!("run:{}", command.join(" ")),
                pid,
            )
        }
    };

    let mut sensor = match Sensor::start(&scope) {
        Ok(s) => s,
        Err(e) => {
            if let Some(mut l) = launched {
                let _ = l.child.kill();
            }
            return Err(e);
        }
    };

    let sid = session_id();
    private_dir(&opts.root)?;
    let mut store = SessionStore::create(&opts.root, &sid, &policy_text)?;
    let mut session = Session::new(
        &sid,
        &policy.agent,
        &policy.display_name(),
        &target_label,
        &format!("{:?}", response).to_lowercase(),
    );
    session.coverage = sensor.coverage().to_vec();
    let mut engine = Engine::new(compiled, &sid, Some(std::process::id()));

    crate::platform::install_stop_handler(on_signal);

    let mut out_events: Vec<Event> = Vec::new();
    for c in sensor.coverage().to_vec() {
        if !c.active {
            let sev = if c.critical {
                Severity::High
            } else {
                Severity::Low
            };
            let msg = format!(
                "Telemetry source {} is {}",
                c.name,
                c.detail.clone().unwrap_or_default()
            );
            if c.critical {
                session.degrade(msg.clone());
            }
            out_events.push(engine.notice(Category::Monitor, "monitor.coverage_gap", sev, msg));
        }
    }
    out_events.push(engine.notice(
        Category::Monitor,
        "monitor.started",
        Severity::Info,
        format!(
            "Kill Line monitoring started for {} with policy {}. Tracking {} process(es).",
            target_label,
            policy.display_name(),
            scope.pids.len()
        ),
    ));

    views::banner_start(&session, &opts.policy.display().to_string());
    if policy.response.on_degraded != ResponseAction::Alert {
        use std::io::Write;
        let _ = writeln!(
            std::io::stdout(),
            "Fail-closed: the agent will be {} if Kill Line loses visibility (dropped events).\n",
            if policy.response.on_degraded == ResponseAction::Freeze {
                "frozen"
            } else {
                "terminated"
            }
        );
    }
    for c in sensor.coverage() {
        if !c.active {
            let color = if c.critical { views::RED } else { views::DIM };
            use std::io::Write;
            let _ = writeln!(
                std::io::stdout(),
                "{}",
                paint(
                    &format!(
                        "  coverage: {} — {}",
                        c.name,
                        c.detail.as_deref().unwrap_or("")
                    ),
                    color
                )
            );
        }
    }

    if let Some(l) = launched.as_mut() {
        l.release()?;
    }

    let started = Instant::now();
    let mut last_tick = Instant::now();
    let mut last_drops = 0u64;
    let mut recent: VecDeque<Event> = VecDeque::new();
    let mut pending: Vec<PendingIncident> = Vec::new();
    let mut responded = false;
    let mut responded_degraded = false;
    let on_degraded = policy.response.on_degraded;
    let mut obs = Vec::new();
    let mut last_status = session.status;
    let mut exit_reason = "stopped by user".to_string();
    let mut quiet_ticks = 0u32;
    let mut reported: std::collections::HashSet<String> = std::collections::HashSet::new();

    loop {
        // Record everything the loop produced so far.
        for ev in out_events.drain(..) {
            session.apply(&ev);
            store.append(&ev)?;
            views::print_event(&ev, opts.verbose);
            for p in pending.iter_mut() {
                p.after.push(ev.clone());
            }
            recent.push_back(ev.clone());
            if recent.len() > CONTEXT_EVENTS {
                recent.pop_front();
            }
            let is_new_violation = ev.verdict == Verdict::Violation && ev.confirms_seq.is_none();
            if is_new_violation {
                // One incident per distinct breach; repeats go to the timeline
                // and into the open incident's post-trigger context.
                let key = format!(
                    "{:?}|{:?}|{}",
                    ev.category,
                    ev.policy_rule,
                    ev.resource_summary()
                );
                if !reported.insert(key) {
                    views::repeat_line(&ev);
                } else if session.incidents.len() < MAX_INCIDENTS_PER_SESSION {
                    store.flush()?;
                    let inc = PendingIncident::new(
                        &opts.root,
                        &session,
                        &ev,
                        recent.iter().cloned().collect(),
                        store.head(),
                    )?;
                    let id = inc.incident.incident_id.clone();
                    session.incidents.push(id.clone());
                    inc.write(
                        &session,
                        &policy_text,
                        &system_metadata(&session, store.head()),
                    )?;
                    views::alert_block(&session, &ev, &response, &id);
                    pending.push(inc);
                } else {
                    views::alert_block(
                        &session,
                        &ev,
                        &response,
                        "(incident limit reached; see timeline)",
                    );
                }
            }
            if ev.verdict == Verdict::Anomaly {
                views::anomaly_block(&ev);
            }
        }
        // Optional enforcement, once, after the first violation.
        if !responded && session.violations > 0 && response != ResponseAction::Alert {
            responded = true;
            let pids = || sensor.tracked_pids().unwrap_or_default();
            let result = match response {
                ResponseAction::Freeze => respond::freeze(&handle, &pids),
                ResponseAction::Terminate => respond::terminate(&handle, &pids),
                ResponseAction::Alert => unreachable!(),
            };
            if result.is_ok() && response == ResponseAction::Freeze {
                session.frozen = true;
            }
            let (sev, msg) = match result {
                Ok(m) => (Severity::Info, format!("Response executed: {}.", m)),
                Err(e) => (
                    Severity::High,
                    format!("Response FAILED: {:#}. The agent is still running.", e),
                ),
            };
            session.response_taken.push(msg.clone());
            out_events.push(engine.notice(Category::Response, "response.executed", sev, msg));
            continue;
        }

        // Fail-closed option: act when visibility is lost.
        if !responded_degraded && session.dropped_events > 0 && on_degraded != ResponseAction::Alert
        {
            responded_degraded = true;
            let pids = || sensor.tracked_pids().unwrap_or_default();
            let result = match on_degraded {
                ResponseAction::Freeze => respond::freeze(&handle, &pids),
                ResponseAction::Terminate => respond::terminate(&handle, &pids),
                ResponseAction::Alert => unreachable!(),
            };
            let msg = match result {
                Ok(m) => format!(
                    "Visibility lost (dropped events); response.on_degraded executed: {}.",
                    m
                ),
                Err(e) => format!("Visibility lost; response.on_degraded FAILED: {:#}.", e),
            };
            session.response_taken.push(msg.clone());
            out_events.push(engine.notice(
                Category::Response,
                "response.on_degraded",
                Severity::High,
                msg,
            ));
            continue;
        }
        if session.status != last_status {
            if session.status != Status::Red {
                views::status_change(&session);
            }
            last_status = session.status;
        }

        if STOP.load(Ordering::SeqCst) {
            break;
        }
        if let Some(d) = opts.duration {
            if started.elapsed() >= Duration::from_secs(d) {
                exit_reason = format!("duration of {}s reached", d);
                break;
            }
        }

        obs.clear();
        sensor.poll(100, 4096, &mut obs)?;
        for o in obs.drain(..) {
            out_events.extend(engine.process(o));
        }

        // Operator requests from the dashboard (`killline ui`).
        if let Some(action) = take_control_request(&store.dir) {
            let pids = || sensor.tracked_pids().unwrap_or_default();
            let result = match action.as_str() {
                "freeze" => respond::freeze(&handle, &pids).inspect(|_| session.frozen = true),
                "resume" => respond::resume(&handle, &pids).inspect(|_| session.frozen = false),
                "terminate" => respond::terminate(&handle, &pids),
                "stop" => {
                    exit_reason = "stopped from the dashboard".into();
                    STOP.store(true, Ordering::SeqCst);
                    Ok("monitoring will stop".into())
                }
                other => Err(anyhow::anyhow!("unknown action '{}'", other)),
            };
            let (sev, msg) = match result {
                Ok(m) => (
                    Severity::Info,
                    format!("Operator action from dashboard: {} ({}).", action, m),
                ),
                Err(e) => (
                    Severity::High,
                    format!("Operator action '{}' FAILED: {:#}.", action, e),
                ),
            };
            if action != "stop" {
                session.response_taken.push(msg.clone());
            }
            out_events.push(engine.notice(Category::Response, "response.operator", sev, msg));
            store.save_session(&session)?;
            continue;
        }

        if last_tick.elapsed() >= Duration::from_secs(1) {
            last_tick = Instant::now();
            session.heartbeat = Utc::now();
            if let Some(reason) = sensor.health() {
                if !session.degraded_reasons.contains(&reason) {
                    out_events.push(engine.notice(
                        Category::Monitor,
                        "monitor.sensor_lost",
                        Severity::High,
                        reason.clone(),
                    ));
                }
                session.degrade(reason);
            }
            let drops = sensor.dropped().unwrap_or(0);
            if drops > last_drops {
                let msg = format!(
                    "{} event(s) were dropped by the kernel ring buffer. Some agent activity was not observed.",
                    drops
                );
                session.dropped_events = drops;
                session.degrade(format!("{} events dropped (ring buffer full)", drops));
                out_events.push(engine.notice(
                    Category::Monitor,
                    "monitor.events_dropped",
                    Severity::High,
                    msg,
                ));
                last_drops = drops;
            }
            // Finalise incidents whose post-trigger window has elapsed.
            let now = Utc::now();
            let mut i = 0;
            while i < pending.len() {
                if pending[i].deadline <= now {
                    let p = pending.remove(i);
                    let mut p = p;
                    p.incident.finalized = true;
                    p.write(
                        &session,
                        &policy_text,
                        &system_metadata(&session, store.head()),
                    )?;
                } else {
                    i += 1;
                }
            }
            store.flush()?;
            store.save_session(&session)?;

            // Is the agent still there?
            let alive = match &mut launched {
                Some(l) => l.child.try_wait().ok().flatten().is_none(),
                None => target::pid_exists(liveness_pid),
            };
            if !alive && pending.is_empty() {
                // Drain what is left before stopping. ETW (Windows) delivers
                // in buffers flushed about once a second, so wait for a few
                // quiet seconds there; the eBPF ring buffer is immediate.
                obs.clear();
                sensor.poll(0, usize::MAX, &mut obs)?;
                for o in obs.drain(..) {
                    out_events.extend(engine.process(o));
                }
                if out_events.is_empty() {
                    quiet_ticks += 1;
                    if quiet_ticks >= QUIET_TICKS_BEFORE_EXIT {
                        exit_reason = "agent exited".into();
                        break;
                    }
                } else {
                    quiet_ticks = 0;
                }
            }
        }
    }

    // Shutdown: record, finalise, report.
    let ev = engine.notice(
        Category::Monitor,
        "monitor.stopped",
        Severity::Info,
        format!("Kill Line monitoring stopped: {}.", exit_reason),
    );
    session.apply(&ev);
    store.append(&ev)?;
    for mut p in pending.drain(..) {
        p.after.push(ev.clone());
        p.incident.finalized = true;
        p.write(
            &session,
            &policy_text,
            &system_metadata(&session, store.head()),
        )?;
    }
    session.ended = Some(Utc::now());
    session.heartbeat = Utc::now();
    store.flush()?;
    store.save_session(&session)?;
    views::banner_end(&session, &exit_reason);
    let code = match &mut launched {
        Some(l) => l.child.wait().ok().and_then(|s| s.code()).unwrap_or(0),
        None => 0,
    };
    let _ = code;
    Ok(match session.status {
        Status::Green => 0,
        Status::Amber => 3,
        Status::Grey => 4,
        Status::Red => 10,
    })
}
