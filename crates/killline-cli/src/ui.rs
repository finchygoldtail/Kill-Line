//! `killline ui`: a local dashboard served from this binary.
//!
//! Security model:
//! - binds to 127.0.0.1 only; nothing is served to the network;
//! - every API call needs the per-run token (sent as `X-KillLine-Token`), so
//!   other websites open in the same browser cannot read forensic data or
//!   control agents (a custom header also forces a CORS preflight, which this
//!   server never approves);
//! - the Host header must be the loopback address, which defeats DNS
//!   rebinding;
//! - a strict Content-Security-Policy; all assets are embedded, no CDN.

use crate::views;
use anyhow::{anyhow, bail, Context, Result};
use chrono::Utc;
use killline_core::event::{Event, Verdict};
use killline_core::incident;
use killline_core::policy::{Level, Policy, TEMPLATES};
use killline_core::store::{self, find_session, list_sessions, read_timeline, verify_timeline};
use serde_json::{json, Value};
use std::io::Read;
use std::path::{Path, PathBuf};
use tiny_http::{Header, Method, Request, Response, Server};

const INDEX_HTML: &str = include_str!("../ui/index.html");
const APP_JS: &str = include_str!("../ui/app.js");
const APP_CSS: &str = include_str!("../ui/app.css");
const MAX_BODY: usize = 16 * 1024;

struct Ctx {
    root: PathBuf,
    token: String,
    port: u16,
}

fn random_token() -> String {
    let mut b = [0u8; 16];
    if let Ok(mut f) = std::fs::File::open("/dev/urandom") {
        let _ = f.read_exact(&mut b);
    }
    b.iter().map(|x| format!("{:02x}", x)).collect()
}

pub fn serve(
    root: PathBuf,
    port: u16,
    open: bool,
    announce_json: bool,
    exit_with_stdin: bool,
) -> Result<i32> {
    let server = Server::http(("127.0.0.1", port))
        .map_err(|e| anyhow!("cannot listen on 127.0.0.1:{}: {}", port, e))?;
    let port = server
        .server_addr()
        .to_ip()
        .map(|a| a.port())
        .unwrap_or(port);
    let ctx = Ctx {
        root,
        token: random_token(),
        port,
    };
    let url = format!("http://127.0.0.1:{}/#{}", port, ctx.token);
    if announce_json {
        use std::io::Write;
        println!(
            "{}",
            json!({"url": url, "port": port, "token": ctx.token, "data_dir": ctx.root.display().to_string()})
        );
        let _ = std::io::stdout().flush();
    } else {
        println!("KillLine dashboard running at:\n\n    {}\n", url);
        println!("Local only (127.0.0.1). The link contains an access token; do not share it.");
        println!("Data directory: {}", ctx.root.display());
        println!("Press Ctrl+C to stop the dashboard. Running monitors keep running.");
    }
    if exit_with_stdin {
        std::thread::spawn(|| {
            let mut sink = [0u8; 64];
            let mut stdin = std::io::stdin();
            while matches!(stdin.read(&mut sink), Ok(n) if n > 0) {}
            std::process::exit(0);
        });
    }
    if open {
        let _ = std::process::Command::new("xdg-open")
            .arg(&url)
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .spawn();
    }
    for req in server.incoming_requests() {
        handle(&ctx, req);
    }
    Ok(0)
}

fn header(name: &str, value: &str) -> Header {
    Header::from_bytes(name.as_bytes(), value.as_bytes()).expect("static header")
}

fn security_headers() -> Vec<Header> {
    vec![
        header(
            "Content-Security-Policy",
            "default-src 'none'; script-src 'self'; style-src 'self'; connect-src 'self'; img-src 'self' data:; \
             frame-ancestors 'none'; base-uri 'none'; form-action 'none'",
        ),
        header("X-Content-Type-Options", "nosniff"),
        header("Referrer-Policy", "no-referrer"),
        header("Cache-Control", "no-store"),
        header("X-Frame-Options", "DENY"),
    ]
}

fn respond(req: Request, status: u16, ctype: &str, body: Vec<u8>) {
    let mut r = Response::from_data(body).with_status_code(status);
    r.add_header(header("Content-Type", ctype));
    for h in security_headers() {
        r.add_header(h);
    }
    let _ = req.respond(r);
}

fn json_resp(req: Request, status: u16, v: &Value) {
    respond(
        req,
        status,
        "application/json",
        serde_json::to_vec(v).unwrap_or_default(),
    );
}

fn get_header<'a>(req: &'a Request, name: &'static str) -> Option<&'a str> {
    req.headers()
        .iter()
        .find(|h| h.field.equiv(name))
        .map(|h| h.value.as_str())
}

fn ct_eq(a: &str, b: &str) -> bool {
    a.len() == b.len()
        && a.bytes()
            .zip(b.bytes())
            .fold(0u8, |acc, (x, y)| acc | (x ^ y))
            == 0
}

fn handle(ctx: &Ctx, mut req: Request) {
    // DNS-rebinding defence: only loopback Host headers.
    let host_ok = get_header(&req, "Host")
        .map(|h| {
            let p = format!(":{}", ctx.port);
            h == format!("127.0.0.1{}", p)
                || h == format!("localhost{}", p)
                || h == format!("[::1]{}", p)
        })
        .unwrap_or(false);
    if !host_ok {
        return respond(req, 421, "text/plain", b"misdirected request".to_vec());
    }
    let url = req.url().to_string();
    let (path, query) = url.split_once('?').unwrap_or((&url, ""));
    let path = path.to_string();
    let query = query.to_string();

    // Static assets need no token (they contain no data).
    if req.method() == &Method::Get {
        match path.as_str() {
            "/" | "/index.html" => {
                return respond(
                    req,
                    200,
                    "text/html; charset=utf-8",
                    INDEX_HTML.as_bytes().to_vec(),
                )
            }
            "/app.js" => {
                return respond(
                    req,
                    200,
                    "text/javascript; charset=utf-8",
                    APP_JS.as_bytes().to_vec(),
                )
            }
            "/app.css" => {
                return respond(
                    req,
                    200,
                    "text/css; charset=utf-8",
                    APP_CSS.as_bytes().to_vec(),
                )
            }
            _ => {}
        }
    }
    if !path.starts_with("/api/") {
        return respond(req, 404, "text/plain", b"not found".to_vec());
    }
    let token_ok = get_header(&req, "X-KillLine-Token")
        .map(|t| ct_eq(t, &ctx.token))
        .unwrap_or(false);
    if !token_ok {
        return json_resp(
            req,
            401,
            &json!({"error": "Missing or wrong access token. Open the link printed by `killline ui`."}),
        );
    }

    let body = if req.method() == &Method::Post {
        let ct = get_header(&req, "Content-Type").unwrap_or("");
        if !ct.starts_with("application/json") {
            return json_resp(req, 415, &json!({"error": "expected application/json"}));
        }
        let mut buf = Vec::new();
        let n = req
            .as_reader()
            .take(MAX_BODY as u64 + 1)
            .read_to_end(&mut buf);
        if n.is_err() || buf.len() > MAX_BODY {
            return json_resp(req, 413, &json!({"error": "request too large"}));
        }
        match serde_json::from_slice::<Value>(&buf) {
            Ok(v) => Some(v),
            Err(_) => return json_resp(req, 400, &json!({"error": "invalid JSON"})),
        }
    } else {
        None
    };

    let result = route(ctx, req.method().clone(), &path, &query, body);
    match result {
        Ok(v) => json_resp(req, 200, &v),
        Err(e) => json_resp(req, 400, &json!({"error": format!("{:#}", e)})),
    }
}

fn param<'a>(query: &'a str, key: &str) -> Option<&'a str> {
    query
        .split('&')
        .find_map(|kv| kv.strip_prefix(key).and_then(|r| r.strip_prefix('=')))
}

fn valid_id(s: &str) -> Result<&str> {
    if s.is_empty() || s.len() > 64 || !s.chars().all(|c| c.is_ascii_alphanumeric() || c == '-') {
        bail!("invalid id");
    }
    Ok(s)
}

fn route(ctx: &Ctx, method: Method, path: &str, query: &str, body: Option<Value>) -> Result<Value> {
    let parts: Vec<&str> = path.trim_start_matches("/api/").split('/').collect();
    match (method, parts.as_slice()) {
        (Method::Get, ["overview"]) => overview(ctx),
        (Method::Get, ["sessions"]) => sessions(ctx),
        (Method::Get, ["sessions", id]) => session(ctx, valid_id(id)?),
        (Method::Get, ["sessions", id, "timeline"]) => timeline(ctx, valid_id(id)?, query),
        (Method::Get, ["sessions", id, "verify"]) => {
            let s = find_session(&ctx.root, valid_id(id)?)?;
            let r = verify_timeline(&store::sessions_dir(&ctx.root).join(&s.session_id).join("timeline.jsonl"))?;
            Ok(serde_json::to_value(r)?)
        }
        (Method::Post, ["sessions", id, "control"]) => control(ctx, valid_id(id)?, body.unwrap_or_default()),
        (Method::Get, ["incidents"]) => Ok(serde_json::to_value(incident::list_incidents(&ctx.root)?)?),
        (Method::Get, ["incidents", id]) => incident_detail(ctx, valid_id(id)?),
        (Method::Get, ["containers"]) => containers(),
        (Method::Get, ["templates"]) => Ok(json!(TEMPLATES
            .iter()
            .map(|(n, t)| json!({"name": n, "description": Policy::parse(t).ok().and_then(|p| p.description), "text": t}))
            .collect::<Vec<_>>())),
        (Method::Post, ["validate"]) => validate(body.unwrap_or_default()),
        (Method::Post, ["monitor"]) => start_monitor(ctx, body.unwrap_or_default()),
        _ => bail!("unknown endpoint"),
    }
}

fn overview(ctx: &Ctx) -> Result<Value> {
    let docker = std::process::Command::new("docker")
        .args(["version", "--format", "{{.Server.Version}}"])
        .output()
        .ok()
        .filter(|o| o.status.success())
        .map(|o| String::from_utf8_lossy(&o.stdout).trim().to_string());
    Ok(json!({
        "version": killline_core::VERSION,
        "data_dir": ctx.root.display().to_string(),
        "kernel": std::fs::read_to_string("/proc/sys/kernel/osrelease").unwrap_or_default().trim(),
        "hostname": std::fs::read_to_string("/proc/sys/kernel/hostname").unwrap_or_default().trim(),
        "ebpf_built": killline_sensor::Sensor::built_with_bpf(),
        "btf": Path::new("/sys/kernel/btf/vmlinux").exists(),
        "docker": docker,
        "now": Utc::now(),
    }))
}

fn session_json(s: &killline_core::session::Session) -> Value {
    let now = Utc::now();
    let (status, reasons) = s.effective_status(now);
    let mut v = serde_json::to_value(s).unwrap_or_default();
    v["effective_status"] = json!(status);
    v["status_label"] = json!(status.label());
    v["status_meaning"] = json!(status.meaning());
    v["effective_reasons"] = json!(reasons);
    v["runtime"] = json!(s.runtime(now));
    v["live"] = json!(
        s.ended.is_none()
            && (now - s.heartbeat).num_seconds() <= killline_core::session::HEARTBEAT_STALE_SECS
    );
    v
}

fn sessions(ctx: &Ctx) -> Result<Value> {
    let mut all = list_sessions(&ctx.root)?;
    all.reverse();
    Ok(json!(all.iter().map(session_json).collect::<Vec<_>>()))
}

fn session(ctx: &Ctx, id: &str) -> Result<Value> {
    Ok(session_json(&find_session(&ctx.root, id)?))
}

fn event_json(e: &Event) -> Value {
    let mut v = serde_json::to_value(e).unwrap_or_default();
    v["summary"] = json!(views::describe(e));
    v["boundary"] = json!(e.category.boundary_name());
    v["noise"] = json!(views::is_noise(e));
    v
}

fn timeline(ctx: &Ctx, id: &str, query: &str) -> Result<Value> {
    let s = find_session(&ctx.root, id)?;
    let events = read_timeline(
        &store::sessions_dir(&ctx.root)
            .join(&s.session_id)
            .join("timeline.jsonl"),
    )?;
    let filter = param(query, "filter").unwrap_or("notable");
    let limit: usize = param(query, "limit")
        .and_then(|l| l.parse().ok())
        .unwrap_or(400)
        .min(5000);
    let total = events.len();
    let selected: Vec<&Event> = events
        .iter()
        .filter(|e| match filter {
            "all" => true,
            "alerts" => matches!(
                e.verdict,
                Verdict::Violation | Verdict::Anomaly | Verdict::Notice
            ),
            _ => !views::is_noise(e),
        })
        .collect();
    let start = selected.len().saturating_sub(limit);
    Ok(json!({
        "total": total,
        "matching": selected.len(),
        "events": selected[start..].iter().map(|e| event_json(e)).collect::<Vec<_>>(),
    }))
}

fn incident_detail(ctx: &Ctx, id: &str) -> Result<Value> {
    let dir = incident::incident_dir(&ctx.root, id)?;
    let inc: incident::Incident =
        serde_json::from_str(&std::fs::read_to_string(dir.join("incident.json"))?)?;
    let tl_text = std::fs::read_to_string(dir.join("timeline.jsonl")).unwrap_or_default();
    let events: Vec<Event> = tl_text
        .lines()
        .filter_map(|l| serde_json::from_str(l).ok())
        .collect();
    let trig = inc.trigger.seq;
    let before: Vec<Value> = events
        .iter()
        .filter(|e| e.seq < trig && !views::is_noise(e))
        .map(event_json)
        .collect();
    let after: Vec<Value> = events
        .iter()
        .filter(|e| e.seq > trig && !views::is_noise(e))
        .take(30)
        .map(event_json)
        .collect();
    let bad = incident::verify_checksums(&dir)?;
    let tree: Value = std::fs::read_to_string(dir.join("process_tree.json"))
        .ok()
        .and_then(|t| serde_json::from_str(&t).ok())
        .unwrap_or(Value::Null);
    let mut files: Vec<String> = incident::FILES.iter().map(|s| s.to_string()).collect();
    files.push("checksums.txt".into());
    Ok(json!({
        "incident": inc,
        "trigger": event_json(&inc.trigger),
        "before": before,
        "after": after,
        "checksums_ok": bad.is_empty(),
        "modified_files": bad,
        "bundle_dir": dir.display().to_string(),
        "files": files,
        "process_tree": tree,
    }))
}

fn control(ctx: &Ctx, id: &str, body: Value) -> Result<Value> {
    let action = body
        .get("action")
        .and_then(|a| a.as_str())
        .context("missing action")?;
    if !matches!(action, "freeze" | "resume" | "terminate" | "stop") {
        bail!("unknown action");
    }
    let s = find_session(&ctx.root, id)?;
    let (_, _) = s.effective_status(Utc::now());
    if s.ended.is_some() {
        bail!("this session has ended; there is no running monitor to act on");
    }
    if (Utc::now() - s.heartbeat).num_seconds() > killline_core::session::HEARTBEAT_STALE_SECS {
        bail!("the monitor for this session is not responding (no heartbeat); it cannot act");
    }
    let dir = store::sessions_dir(&ctx.root).join(&s.session_id);
    store::write_private(
        &dir.join("control.json"),
        serde_json::to_string(&json!({"action": action}))?.as_bytes(),
    )?;
    Ok(json!({"requested": action}))
}

fn containers() -> Result<Value> {
    let out = std::process::Command::new("docker")
        .args(["ps", "--format", "{{.Names}}\t{{.Image}}\t{{.Status}}"])
        .output();
    let Ok(out) = out else {
        return Ok(json!({"available": false, "containers": []}));
    };
    if !out.status.success() {
        return Ok(
            json!({"available": false, "error": String::from_utf8_lossy(&out.stderr).trim(), "containers": []}),
        );
    }
    let list: Vec<Value> = String::from_utf8_lossy(&out.stdout)
        .lines()
        .filter_map(|l| {
            let f: Vec<&str> = l.split('\t').collect();
            (f.len() == 3).then(|| json!({"name": f[0], "image": f[1], "status": f[2]}))
        })
        .collect();
    Ok(json!({"available": true, "containers": list}))
}

fn policy_from_body(body: &Value) -> Result<(String, String)> {
    if let Some(t) = body.get("template").and_then(|t| t.as_str()) {
        let (_, text) = TEMPLATES
            .iter()
            .find(|(n, _)| *n == t)
            .ok_or_else(|| anyhow!("no template '{}'", t))?;
        return Ok((text.to_string(), format!("template:{}", t)));
    }
    if let Some(text) = body.get("policy_text").and_then(|t| t.as_str()) {
        return Ok((text.to_string(), "custom".into()));
    }
    bail!("choose a policy template or provide policy text")
}

fn validate(body: Value) -> Result<Value> {
    let (text, _) = policy_from_body(&body)?;
    let diags = match Policy::parse(&text) {
        Ok(p) => p.validate(),
        Err(e) => {
            return Ok(
                json!({"valid": false, "diagnostics": [{"level": "error", "message": format!("{:#}", e)}]}),
            )
        }
    };
    let valid = !diags.iter().any(|d| d.level == Level::Error);
    Ok(json!({"valid": valid, "diagnostics": diags}))
}

/// Start `killline monitor` in the background for a container or PID.
fn start_monitor(ctx: &Ctx, body: Value) -> Result<Value> {
    let (text, source) = policy_from_body(&body)?;
    let policy = Policy::parse(&text)?;
    policy.compile()?;
    let mut args: Vec<String> = vec![
        "--no-color".into(),
        "--data-dir".into(),
        ctx.root.display().to_string(),
        "monitor".into(),
    ];
    let label;
    if let Some(c) = body
        .get("container")
        .and_then(|c| c.as_str())
        .filter(|c| !c.is_empty())
    {
        killline_sensor::target::docker_container(c)?;
        args.extend(["--container".into(), c.to_string()]);
        label = format!("container {}", c);
    } else if let Some(p) = body.get("pid").and_then(|p| p.as_u64()) {
        if !Path::new(&format!("/proc/{}", p)).exists() {
            bail!("no process with pid {}", p);
        }
        args.extend(["--pid".into(), p.to_string()]);
        label = format!("pid {}", p);
    } else {
        bail!("choose a container or enter a process id");
    }
    if let Some(r) = body.get("response").and_then(|r| r.as_str()) {
        if !matches!(r, "alert" | "freeze" | "terminate") {
            bail!("invalid response");
        }
        args.extend(["--response".into(), r.to_string()]);
    }
    let pdir = ctx.root.join("ui-policies");
    store::private_dir(&pdir)?;
    let stamp = Utc::now().format("%Y%m%d-%H%M%S%.3f").to_string();
    let ppath = pdir.join(format!("{}.yaml", stamp));
    store::write_private(&ppath, text.as_bytes())?;
    let ldir = ctx.root.join("logs");
    store::private_dir(&ldir)?;
    let log = std::fs::File::create(ldir.join(format!("monitor-{}.log", stamp)))?;
    args.extend(["--policy".into(), ppath.display().to_string()]);

    let before: std::collections::HashSet<String> = list_sessions(&ctx.root)?
        .into_iter()
        .map(|s| s.session_id)
        .collect();
    let mut cmd = std::process::Command::new(std::env::current_exe()?);
    cmd.args(&args)
        .stdin(std::process::Stdio::null())
        .stdout(log.try_clone()?)
        .stderr(log);
    // Detach into its own session so it outlives the dashboard.
    use std::os::unix::process::CommandExt;
    unsafe {
        cmd.pre_exec(|| {
            libc::setsid();
            Ok(())
        });
    }
    let mut child = cmd.spawn().context("starting killline monitor")?;
    for _ in 0..50 {
        std::thread::sleep(std::time::Duration::from_millis(100));
        if let Some(s) = list_sessions(&ctx.root)?
            .into_iter()
            .find(|s| !before.contains(&s.session_id))
        {
            std::thread::spawn(move || {
                let _ = child.wait();
            });
            return Ok(json!({"session_id": s.session_id, "target": label, "policy": source}));
        }
        if let Ok(Some(status)) = child.try_wait() {
            bail!(
                "the monitor exited immediately ({}); see {}",
                status,
                ldir.display()
            );
        }
    }
    std::thread::spawn(move || {
        let _ = child.wait();
    });
    bail!(
        "the monitor did not start within 5 seconds; see {}",
        ldir.display()
    )
}
