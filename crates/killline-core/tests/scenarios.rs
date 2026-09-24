//! End-to-end engine scenarios using synthetic observations. These need no
//! root, kernel or Docker and pin down the deterministic behaviour.

use chrono::{DateTime, Duration, Utc};
use killline_core::engine::Engine;
use killline_core::event::*;
use killline_core::policy::Policy;
use killline_core::session::{Session, Status};

const POLICY: &str = r#"
agent: test-agent
name: strict-no-network
filesystem:
  allow_read: [/workspace, /app]
  allow_write: [/workspace/output, /tmp]
  deny: [/root, /home, /etc/shadow, /var/run/secrets]
network:
  mode: deny
processes:
  allow: [python3, python]
  deny: [sudo, nc]
credentials:
  access: deny
  extra_paths: [/fake-secrets]
untrusted_inputs: [/workspace/untrusted]
anomaly:
  file_burst_threshold: 100
  window_secs: 10
"#;

struct Harness {
    engine: Engine,
    session: Session,
    t: DateTime<Utc>,
    events: Vec<Event>,
}

impl Harness {
    fn new(policy: &str) -> Harness {
        let p = Policy::parse(policy).unwrap();
        let c = p.compile().unwrap();
        Harness {
            engine: Engine::new(c, "s1", Some(4242)),
            session: Session::new("s1", &p.agent, "p", "test", "alert"),
            t: Utc::now(),
            events: vec![],
        }
    }

    fn obs(&mut self, kind: ObsKind, outcome: Option<Outcome>) -> Vec<Event> {
        self.t += Duration::milliseconds(10);
        let o = Observation {
            timestamp: self.t,
            process: ProcessInfo {
                pid: 100,
                tid: 100,
                ppid: 1,
                uid: 65534,
                gid: 65534,
                comm: "python3".into(),
                exe: None,
            },
            kind,
            runtime_setup: false,
            outcome,
        };
        let evs = self.engine.process(o);
        for e in &evs {
            self.session.apply(e);
        }
        self.events.extend(evs.clone());
        evs
    }

    fn open(&mut self, path: &str, access: FileAccess) -> Event {
        self.obs(
            ObsKind::Open {
                path: path.into(),
                access,
                flags: 0,
                resolution: "lexical".into(),
                via: None,
            },
            Some(Outcome::Succeeded),
        )
        .remove(0)
    }

    fn sleep(&mut self, secs: i64) {
        self.t += Duration::seconds(secs);
    }
}

fn net(addr: &str, port: u16) -> ObsKind {
    ObsKind::Net {
        op: NetOp::Connect,
        addr: addr.parse().unwrap(),
        port,
    }
}

#[test]
fn normal_python_work_is_green() {
    let mut h = Harness::new(POLICY);
    h.obs(
        ObsKind::Exec {
            path: "/usr/local/bin/python3".into(),
            argv: vec!["python3".into()],
            sha256: None,
            exists: true,
        },
        Some(Outcome::Succeeded),
    );
    for p in [
        "/etc/ld.so.cache",
        "/usr/lib/x86_64-linux-gnu/libc.so.6",
        "/usr/local/lib/python3.12/os.py",
        "/proc/self/maps",
        "/dev/urandom",
    ] {
        assert_eq!(
            h.open(p, FileAccess::Read).verdict,
            Verdict::Allowed,
            "{}",
            p
        );
    }
    assert!(h.open("/workspace/task.md", FileAccess::Read).allowed);
    assert!(
        h.open("/workspace/output/report.txt", FileAccess::Write)
            .allowed
    );
    assert_eq!(h.session.status, Status::Green);
    assert_eq!(h.session.violations, 0);
}

#[test]
fn demo1_outbound_network_is_red_with_plain_english() {
    let mut h = Harness::new(POLICY);
    let e = h
        .obs(
            net("203.0.113.42", 443),
            Some(Outcome::Failed {
                errno: 101,
                error: errno_name(101),
            }),
        )
        .remove(0);
    assert_eq!(e.verdict, Verdict::Violation);
    assert_eq!(e.category, Category::Network);
    assert_eq!(e.policy_rule.as_deref(), Some("network.mode=deny"));
    assert!(e
        .explanation
        .contains("attempted to connect to 203.0.113.42:443"));
    assert!(e.explanation.contains("does not allow any network access"));
    assert!(e.explanation.contains("ENETUNREACH"));
    assert_eq!(h.session.status, Status::Red);
}

#[test]
fn demo2_credential_file_is_red_and_contents_never_referenced() {
    let mut h = Harness::new(POLICY);
    let e = h.open("/fake-secrets/api-key.txt", FileAccess::Read);
    assert_eq!(e.category, Category::Credential);
    assert_eq!(e.severity, Severity::Critical);
    assert!(e.explanation.contains("never reads the contents"));
    assert!(e.explanation.contains("SUCCEEDED"));
    // Outside the workspace but not a credential: filesystem boundary.
    let e = h.open("/srv/other/data.txt", FileAccess::Read);
    assert_eq!(e.category, Category::Filesystem);
    assert_eq!(e.verdict, Verdict::Violation);
}

#[test]
fn symlinks_and_dotdot_do_not_evade_path_rules() {
    let mut h = Harness::new(POLICY);
    let e = h
        .obs(
            ObsKind::Open {
                path: "/fake-secrets/api-key.txt".into(),
                access: FileAccess::Read,
                flags: 0,
                resolution: "userspace-realpath".into(),
                via: Some("/workspace/output/innocent.txt".into()),
            },
            Some(Outcome::Succeeded),
        )
        .remove(0);
    assert_eq!(e.verdict, Verdict::Violation);
    assert!(e
        .explanation
        .contains("Requested as /workspace/output/innocent.txt"));
    // Lexical normalisation is done by the sensor; the engine sees clean paths.
    assert_eq!(
        killline_core::pathmatch::normalize("/workspace/../root/.ssh/id_rsa"),
        "/root/.ssh/id_rsa"
    );
}

#[test]
fn metadata_endpoints_including_ipv4_mapped_ipv6() {
    let mut h = Harness::new(POLICY);
    for a in [
        "169.254.169.254",
        "::ffff:169.254.169.254",
        "fd00:ec2::254",
        "168.63.129.16",
    ] {
        let e = h.obs(net(a, 80), None).remove(0);
        assert_eq!(e.category, Category::CloudMetadata, "{}", a);
        assert_eq!(e.severity, Severity::Critical);
    }
    let e = h
        .obs(
            ObsKind::Dns {
                server: None,
                query: Some("metadata.google.internal".into()),
            },
            None,
        )
        .remove(0);
    assert_eq!(e.category, Category::CloudMetadata);
}

#[test]
fn docker_socket_is_critical_via_connect_and_open() {
    let mut h = Harness::new(POLICY);
    let e = h
        .obs(
            ObsKind::UnixConnect {
                path: "/var/run/docker.sock".into(),
                abstract_ns: false,
            },
            None,
        )
        .remove(0);
    assert_eq!(e.category, Category::ContainerRuntime);
    assert_eq!(e.severity, Severity::Critical);
    let e = h.open("/run/containerd/containerd.sock", FileAccess::Write);
    assert_eq!(e.category, Category::ContainerRuntime);
    // Ordinary unix sockets are recorded, not violations.
    let e = h
        .obs(
            ObsKind::UnixConnect {
                path: "/var/run/nscd/socket".into(),
                abstract_ns: false,
            },
            None,
        )
        .remove(0);
    assert_eq!(e.verdict, Verdict::Allowed);
}

#[test]
fn escape_indicators() {
    let mut h = Harness::new(POLICY);
    assert_eq!(
        h.open("/proc/sys/kernel/core_pattern", FileAccess::Write)
            .category,
        Category::ContainerEscape
    );
    assert_eq!(
        h.open("/sys/fs/cgroup/memory/x/release_agent", FileAccess::Write)
            .category,
        Category::ContainerEscape
    );
    assert_eq!(
        h.open("/proc/1/root/etc/passwd", FileAccess::Read).category,
        Category::ContainerEscape
    );
    // Own /proc entries are fine.
    assert_ne!(
        h.open("/proc/100/environ", FileAccess::Read).category,
        Category::Credential
    );
    assert_eq!(
        h.open("/proc/555/environ", FileAccess::Read).category,
        Category::Credential
    );
    let e = h
        .obs(
            ObsKind::Setns {
                nstype: 0x2000_0000,
            },
            None,
        )
        .remove(0);
    assert_eq!(e.category, Category::Namespace);
    let e = h
        .obs(
            ObsKind::Mount {
                source: "/dev/sda1".into(),
                target: "/mnt".into(),
                flags: 0,
            },
            None,
        )
        .remove(0);
    assert_eq!(e.category, Category::ContainerEscape);
}

#[test]
fn privilege_and_tamper() {
    let mut h = Harness::new(POLICY);
    let e = h
        .obs(
            ObsKind::SetId {
                call: "setuid".into(),
                args: vec![0],
            },
            None,
        )
        .remove(0);
    assert_eq!(e.action, "privilege.become_root");
    let e = h
        .obs(
            ObsKind::Kill {
                target_pid: 4242,
                signal: 9,
            },
            None,
        )
        .remove(0);
    assert_eq!(e.category, Category::Tamper);
    assert_eq!(e.verdict, Verdict::Violation);
    let e = h
        .obs(
            ObsKind::Chmod {
                path: "/workspace/output/x".into(),
                mode: 0o4755,
            },
            None,
        )
        .remove(0);
    assert_eq!(e.action, "file.chmod_setuid");
}

#[test]
fn process_policy() {
    let mut h = Harness::new(POLICY);
    let ex = |p: &str, exists| ObsKind::Exec {
        path: p.into(),
        argv: vec![],
        sha256: None,
        exists,
    };
    assert_eq!(
        h.obs(ex("/usr/bin/nc", true), None)[0].action,
        "process.exec_denied"
    );
    assert_eq!(
        h.obs(ex("/usr/bin/sudo", true), None)[0].action,
        "process.exec_denied"
    );
    assert_eq!(
        h.obs(ex("/usr/bin/sh", true), None)[0].action,
        "process.exec_unexpected"
    );
    assert_eq!(
        h.obs(ex("/usr/bin/su", true), None)[0].action,
        "process.exec_privileged"
    );
    // PATH-search probes that fail with ENOENT are not violations...
    let e = h
        .obs(
            ex("/root/.local/bin/sh", true),
            Some(Outcome::Failed {
                errno: 2,
                error: errno_name(2),
            }),
        )
        .remove(0);
    assert_eq!(e.action, "process.exec_not_found");
    // ...unless the program is explicitly denied.
    let e = h.obs(ex("/nope/sudo", false), None).remove(0);
    assert_eq!(e.verdict, Verdict::Violation);
}

#[test]
fn runtime_setup_is_recorded_not_evaluated() {
    let mut h = Harness::new(POLICY);
    let o = Observation {
        timestamp: Utc::now(),
        process: ProcessInfo {
            pid: 7,
            comm: "runc:[2:INIT]".into(),
            ..Default::default()
        },
        kind: ObsKind::Open {
            path: "/self/setgroups".into(),
            access: FileAccess::Path,
            flags: 0,
            resolution: "lexical".into(),
            via: None,
        },
        runtime_setup: true,
        outcome: None,
    };
    let e = h.engine.process(o).remove(0);
    assert_eq!(e.action, "runtime.setup");
    assert!(e.allowed);
}

#[test]
fn benign_failed_bytecode_writes_are_not_violations_but_successful_ones_are() {
    let mut h = Harness::new(POLICY);
    let p = "/usr/local/lib/python3.12/__pycache__/os.cpython-312.pyc.1234";
    let e = h
        .obs(
            ObsKind::Open {
                path: p.into(),
                access: FileAccess::Write,
                flags: 0o101,
                resolution: "lexical".into(),
                via: None,
            },
            Some(Outcome::Failed {
                errno: 30,
                error: errno_name(30),
            }),
        )
        .remove(0);
    assert_eq!(e.action, "file.write_blocked_benign");
    let e = h
        .obs(
            ObsKind::Open {
                path: p.into(),
                access: FileAccess::Write,
                flags: 0o101,
                resolution: "lexical".into(),
                via: None,
            },
            Some(Outcome::Succeeded),
        )
        .remove(0);
    assert_eq!(e.verdict, Verdict::Violation);
}

#[test]
fn demo3_behaviour_shift_goes_amber_then_red_with_possible_correlation() {
    let mut h = Harness::new(POLICY);
    h.open("/workspace/src/a.py", FileAccess::Read);
    h.open("/workspace/output/r.txt", FileAccess::Write);
    assert_eq!(h.session.status, Status::Green);
    h.sleep(5);
    h.open("/workspace/untrusted/README.md", FileAccess::Read);
    h.sleep(2);
    let mut saw_amber = false;
    for i in 0..120 {
        let evs = h.obs(
            ObsKind::Open {
                path: format!("/workspace/corpus/doc-{}.txt", i),
                access: FileAccess::Read,
                flags: 0,
                resolution: "lexical".into(),
                via: None,
            },
            Some(Outcome::Succeeded),
        );
        if evs.iter().any(|e| e.verdict == Verdict::Anomaly) {
            saw_amber = true;
            assert_eq!(h.session.status, Status::Amber);
            let a = evs.iter().find(|e| e.verdict == Verdict::Anomaly).unwrap();
            assert!(a
                .correlations
                .iter()
                .any(|c| c.summary.starts_with("Possible correlation")));
        }
    }
    assert!(saw_amber);
    let cred = h.open("/fake-secrets/api-key.txt", FileAccess::Read);
    assert_eq!(h.session.status, Status::Red);
    assert!(cred.correlations.iter().any(|c| c
        .summary
        .contains("untrusted input /workspace/untrusted/README.md")));
    let n = h.obs(net("203.0.113.42", 443), None).remove(0);
    let text: Vec<&str> = n.correlations.iter().map(|c| c.summary.as_str()).collect();
    assert!(
        text.iter()
            .any(|t| t.starts_with("Possible exfiltration pattern")),
        "{:?}",
        text
    );
    assert!(text
        .iter()
        .any(|t| t.starts_with("Follows a behavioural anomaly")));
}

#[test]
fn allowlist_mode_uses_dns_attribution_honestly() {
    let policy = r#"
agent: coder
filesystem: { allow: [/workspace] }
network:
  allow: [github.com, "*.githubusercontent.com"]
  allow_cidr: [10.0.0.0/24]
"#;
    let mut h = Harness::new(policy);
    assert!(h.obs(net("10.0.0.5", 443), None)[0].allowed);
    let e = h.obs(net("140.82.112.3", 443), None).remove(0);
    assert_eq!(
        e.verdict,
        Verdict::Violation,
        "direct IP without prior allowed DNS"
    );
    assert!(
        h.obs(
            ObsKind::Dns {
                server: None,
                query: Some("raw.githubusercontent.com".into())
            },
            None
        )[0]
        .allowed
    );
    let e = h.obs(net("185.199.108.133", 443), None).remove(0);
    assert!(e.allowed);
    assert!(e.explanation.contains("not verified"));
    let e = h
        .obs(
            ObsKind::Dns {
                server: None,
                query: Some("evil.example".into()),
            },
            None,
        )
        .remove(0);
    assert_eq!(e.verdict, Verdict::Violation);
}

#[test]
fn never_claims_safety() {
    let mut h = Harness::new(POLICY);
    h.open("/workspace/a", FileAccess::Read);
    h.obs(net("203.0.113.42", 443), None);
    h.open("/root/.ssh/id_rsa", FileAccess::Read);
    for e in &h.events {
        let t = e.explanation.to_lowercase();
        assert!(
            !t.contains("is safe") && !t.contains("are safe") && !t.contains("secure"),
            "{}",
            e.explanation
        );
    }
    for s in [Status::Green, Status::Amber, Status::Red, Status::Grey] {
        assert!(!s.meaning().to_lowercase().contains("safe"));
    }
}

#[test]
fn stale_heartbeat_is_grey_not_green() {
    let mut s = Session::new("s", "a", "p", "t", "alert");
    s.heartbeat = Utc::now() - Duration::seconds(60);
    let (st, reasons) = s.effective_status(Utc::now());
    assert_eq!(st, Status::Grey);
    assert!(reasons[0].contains("cannot be verified"));
    s.degrade("ring buffer drops");
    assert_eq!(s.status, Status::Grey);
}
