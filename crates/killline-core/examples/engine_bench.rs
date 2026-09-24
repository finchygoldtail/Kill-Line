//! Userspace throughput: engine + session + hash-chained store, no kernel.
//!   cargo run --release -p killline-core --example engine_bench
use chrono::Utc;
use killline_core::engine::Engine;
use killline_core::event::*;
use killline_core::policy::Policy;
use killline_core::session::Session;
use killline_core::store::SessionStore;
use std::time::Instant;

fn main() {
    let n: usize = std::env::args()
        .nth(1)
        .and_then(|s| s.parse().ok())
        .unwrap_or(200_000);
    let p = Policy::parse("agent: bench\nfilesystem: {allow: [/work]}\nnetwork: {mode: deny}\n")
        .unwrap();
    let mut engine = Engine::new(
        p.compile_for(killline_core::policy::Platform::Linux)
            .unwrap(),
        "bench",
        None,
    );
    let mut session = Session::new("bench", "bench", "p", "t", "alert");
    let root = std::env::temp_dir().join(format!("kl-bench-{}", std::process::id()));
    let mut store = SessionStore::create(&root, "s", "agent: bench\n").unwrap();
    let obs: Vec<Observation> = (0..n)
        .map(|i| Observation {
            timestamp: Utc::now(),
            process: ProcessInfo {
                pid: 1,
                tid: 1,
                comm: "python3".into(),
                ..Default::default()
            },
            kind: ObsKind::Open {
                path: if i % 2 == 0 {
                    format!("/work/f{}", i % 100)
                } else {
                    "/usr/lib/libc.so.6".into()
                },
                access: FileAccess::Read,
                flags: 0,
                resolution: "lexical".into(),
                via: None,
            },
            runtime_setup: false,
            outcome: Some(Outcome::Succeeded),
        })
        .collect();
    let t = Instant::now();
    let mut evs = Vec::new();
    for o in obs.iter().cloned() {
        evs.extend(engine.process(o));
    }
    let t_engine = t.elapsed();
    let t = Instant::now();
    for e in &evs {
        session.apply(e);
    }
    let t_session = t.elapsed();
    let t = Instant::now();
    for e in &evs {
        store.append(e).unwrap();
    }
    store.flush().unwrap();
    let t_store = t.elapsed();
    let per = |d: std::time::Duration| d.as_secs_f64() * 1e6 / n as f64;
    println!("events: {}", evs.len());
    println!("engine:  {:.2} us/event", per(t_engine));
    println!("session: {:.2} us/event", per(t_session));
    println!(
        "store:   {:.2} us/event (JSON + SHA-256 chain + write)",
        per(t_store)
    );
    println!(
        "total:   {:.0} events/s single-threaded",
        n as f64 / (t_engine + t_session + t_store).as_secs_f64()
    );
    let _ = std::fs::remove_dir_all(&root);
}
