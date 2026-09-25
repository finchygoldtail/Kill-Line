//! Kill Line desktop app.
//!
//! The dashboard is served by the Kill Line backend (`killline ui`), which
//! must run as root to load the eBPF sensor. This app:
//!
//! 1. shows a bundled start screen;
//! 2. starts the backend through polkit (`pkexec`), so the system asks for
//!    administrator permission, and reads the one-line JSON announcement
//!    `{"url","port","token"}` from its stdout;
//! 3. navigates the window to the dashboard on 127.0.0.1. A navigation
//!    guard allows only the start screen and that exact origin;
//! 4. polls the backend and raises native notifications for new breaches;
//! 5. on exit, closes the backend's stdin. The backend was started with
//!    `--exit-with-stdin`, which is how an unprivileged app can stop a root
//!    process it launched.
//!
//! The remote dashboard page gets no access to Tauri APIs (IPC is only
//! granted to the bundled start screen).

#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

use serde::Serialize;
use std::collections::HashMap;
use std::io::{BufRead, BufReader, Read, Write};
use std::net::TcpStream;
use std::path::PathBuf;
use std::process::{Child, ChildStdin, Command, Stdio};
use std::sync::atomic::{AtomicU16, Ordering};
use std::sync::{mpsc, Mutex};
use std::time::Duration;
use tauri::{AppHandle, Manager, RunEvent, State, Url, WebviewUrl, WebviewWindowBuilder};
use tauri_plugin_notification::NotificationExt;

/// Port of the running backend; 0 when none. Read by the navigation guard.
static BACKEND_PORT: AtomicU16 = AtomicU16::new(0);

struct Backend {
    child: Child,
    /// Held open for the backend's lifetime; dropping it stops the backend.
    _stdin: ChildStdin,
    url: String,
}

#[derive(Default)]
struct AppState {
    backend: Mutex<Option<Backend>>,
}

#[derive(Serialize)]
struct Started {
    url: String,
}

/// Running with full privileges: root on Linux, an elevated token on Windows.
#[cfg(unix)]
fn is_root() -> bool {
    // SAFETY: geteuid has no preconditions.
    unsafe { libc::geteuid() == 0 }
}

#[cfg(windows)]
fn is_root() -> bool {
    use windows_sys::Win32::Foundation::{CloseHandle, HANDLE};
    use windows_sys::Win32::Security::{GetTokenInformation, TokenElevation, TOKEN_ELEVATION, TOKEN_QUERY};
    use windows_sys::Win32::System::Threading::{GetCurrentProcess, OpenProcessToken};
    // SAFETY: standard token query; the handle is closed.
    unsafe {
        let mut token: HANDLE = std::ptr::null_mut();
        if OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token) == 0 {
            return false;
        }
        let mut elev = TOKEN_ELEVATION { TokenIsElevated: 0 };
        let mut len = 0u32;
        let ok = GetTokenInformation(
            token,
            TokenElevation,
            &mut elev as *mut _ as *mut _,
            std::mem::size_of::<TOKEN_ELEVATION>() as u32,
            &mut len,
        );
        CloseHandle(token);
        ok != 0 && elev.TokenIsElevated != 0
    }
}

/// Find the killline CLI: $KILLLINE_BIN, the bundled sidecar next to this
/// executable, then the usual install locations.
fn find_killline() -> Option<PathBuf> {
    if let Ok(p) = std::env::var("KILLLINE_BIN") {
        let p = PathBuf::from(p);
        if p.is_file() {
            return Some(p);
        }
    }
    if let Ok(exe) = std::env::current_exe() {
        if let Some(dir) = exe.parent() {
            let side = dir.join(if cfg!(windows) { "killline.exe" } else { "killline" });
            if side.is_file() {
                return Some(side);
            }
        }
    }
    ["/usr/bin/killline", "/usr/local/bin/killline"]
        .iter()
        .map(PathBuf::from)
        .find(|p| p.is_file())
}

#[tauri::command]
async fn start_backend(app: AppHandle, state: State<'_, AppState>) -> Result<Started, String> {
    if let Some(b) = state.backend.lock().unwrap().as_mut() {
        if b.child.try_wait().ok().flatten().is_none() {
            return Ok(Started { url: b.url.clone() });
        }
    }
    if !cfg!(any(target_os = "linux", windows)) {
        return Err("Kill Line runs on Linux and Windows. macOS support is on the roadmap.".into());
    }
    if cfg!(windows) && !is_root() {
        return Err("Kill Line needs administrator rights on Windows. Right-click Kill Line and choose \"Run as administrator\".".into());
    }
    let bin = find_killline()
        .ok_or("The Kill Line engine (killline) was not found. Reinstall Kill Line.")?;
    let args = ["ui", "--port", "0", "--announce-json", "--exit-with-stdin"];
    let mut cmd = if is_root() {
        let mut c = Command::new(&bin);
        c.args(args);
        c
    } else {
        let mut c = Command::new("pkexec");
        c.arg(&bin).args(args);
        c
    };
    #[cfg(windows)]
    {
        use std::os::windows::process::CommandExt;
        const CREATE_NO_WINDOW: u32 = 0x0800_0000;
        cmd.creation_flags(CREATE_NO_WINDOW);
    }
    cmd.stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    let mut child = cmd.spawn().map_err(|e| {
        if e.kind() == std::io::ErrorKind::NotFound {
            "pkexec (polkit) is not installed, so Kill Line cannot ask for administrator permission. Install the pkexec package, or run `sudo killline ui`.".to_string()
        } else {
            format!("Could not start Kill Line: {}", e)
        }
    })?;
    let stdin = child.stdin.take().ok_or("no stdin")?;
    let stdout = child.stdout.take().ok_or("no stdout")?;
    let mut stderr = child.stderr.take().ok_or("no stderr")?;

    // Read the announcement line. The user may take a while to type their
    // password, so wait up to three minutes.
    let (tx, rx) = mpsc::channel();
    std::thread::spawn(move || {
        let mut line = String::new();
        let mut r = BufReader::new(stdout);
        let _ = r.read_line(&mut line);
        let _ = tx.send(line);
        // Keep draining so the backend never blocks on a full pipe.
        let mut sink = Vec::new();
        let _ = r.read_to_end(&mut sink);
    });
    let line = match rx.recv_timeout(Duration::from_secs(180)) {
        Ok(l) if !l.trim().is_empty() => l,
        _ => {
            let status = child.wait().ok();
            let mut err = String::new();
            let _ = stderr.read_to_string(&mut err);
            return Err(match status.and_then(|s| s.code()) {
                _ if err.contains("Error getting authority") => "The system permission service (polkit) is not running, so Kill Line cannot ask for administrator permission. Start Kill Line from a terminal with `sudo killline ui` instead.".into(),
                _ if err.contains("No authentication agent") => "No password prompt could be shown: this desktop has no polkit authentication agent. Start Kill Line from a terminal with `sudo killline ui` instead.".into(),
                Some(126) => "The permission prompt was cancelled, so the kernel sensor was not loaded.".into(),
                Some(127) => "Administrator permission was not granted, so the kernel sensor could not be loaded.".into(),
                _ if err.trim().is_empty() => "The Kill Line engine stopped before it was ready.".into(),
                _ => format!("The Kill Line engine stopped: {}", err.trim()),
            });
        }
    };
    let v: serde_json::Value = serde_json::from_str(line.trim())
        .map_err(|_| "Unexpected output from the Kill Line engine.".to_string())?;
    let url = v["url"].as_str().unwrap_or_default().to_string();
    let port = v["port"].as_u64().unwrap_or(0) as u16;
    let token = v["token"].as_str().unwrap_or_default().to_string();
    if port == 0 || !url.starts_with(&format!("http://127.0.0.1:{}/#", port)) || token.len() != 32 {
        let _ = child.kill();
        return Err(
            "The Kill Line engine announced an unexpected address; refusing to connect.".into(),
        );
    }
    BACKEND_PORT.store(port, Ordering::SeqCst);
    *state.backend.lock().unwrap() = Some(Backend {
        child,
        _stdin: stdin,
        url: url.clone(),
    });
    start_notifier(app, port, token);
    Ok(Started { url })
}

/// Minimal HTTP GET against the local backend (no extra dependencies).
fn api_get(port: u16, token: &str, path: &str) -> Option<serde_json::Value> {
    let mut s = TcpStream::connect(("127.0.0.1", port)).ok()?;
    s.set_read_timeout(Some(Duration::from_secs(3))).ok()?;
    let req = format!(
        "GET /api/{} HTTP/1.1\r\nHost: 127.0.0.1:{}\r\nX-KillLine-Token: {}\r\nConnection: close\r\n\r\n",
        path, port, token
    );
    s.write_all(req.as_bytes()).ok()?;
    let mut buf = Vec::new();
    s.read_to_end(&mut buf).ok()?;
    let text = String::from_utf8_lossy(&buf);
    let (_, body) = text.split_once("\r\n\r\n")?;
    serde_json::from_str(body).ok()
}

/// Native desktop notifications when any session records a new breach or
/// loses visibility.
fn start_notifier(app: AppHandle, port: u16, token: String) {
    std::thread::spawn(move || {
        let mut seen: HashMap<String, (u64, String)> = HashMap::new();
        let mut first = true;
        while BACKEND_PORT.load(Ordering::SeqCst) == port {
            if let Some(serde_json::Value::Array(list)) = api_get(port, &token, "sessions") {
                for s in list {
                    let id = s["session_id"].as_str().unwrap_or_default().to_string();
                    let viol = s["violations"].as_u64().unwrap_or(0);
                    let status = s["effective_status"]
                        .as_str()
                        .unwrap_or_default()
                        .to_string();
                    let agent = s["agent"].as_str().unwrap_or("agent");
                    let prev = seen.insert(id.clone(), (viol, status.clone()));
                    if first {
                        continue;
                    }
                    let (pv, ps) = prev.unwrap_or((0, String::new()));
                    if viol > pv {
                        let lv = &s["last_violation"];
                        let new = viol - pv;
                        let latest = format!(
                            "{} → {}",
                            lv["boundary"].as_str().unwrap_or("Boundary crossed"),
                            lv["summary"].as_str().unwrap_or("")
                        );
                        let body = if new > 1 {
                            format!("{} new breaches. Latest: {}", new, latest)
                        } else {
                            latest
                        };
                        let _ = app
                            .notification()
                            .builder()
                            .title(format!("Kill Line triggered: {}", agent))
                            .body(body)
                            .show();
                    } else if status == "GREY" && ps != "GREY" && !ps.is_empty() {
                        let _ = app
                            .notification()
                            .builder()
                            .title(format!("Kill Line: monitoring degraded for {}", agent))
                            .body("Kill Line's visibility is incomplete. Containment cannot be verified.")
                            .show();
                    }
                }
                first = false;
            }
            std::thread::sleep(Duration::from_secs(2));
        }
    });
}

/// Only the bundled start screen and the backend's exact origin may load in
/// the window. Everything else (links, redirects) is refused.
fn allowed(url: &Url) -> bool {
    match url.scheme() {
        "tauri" => true,
        "http" | "https" if url.host_str() == Some("tauri.localhost") => true,
        "http" => {
            let port = BACKEND_PORT.load(Ordering::SeqCst);
            port != 0 && url.host_str() == Some("127.0.0.1") && url.port() == Some(port)
        }
        _ => false,
    }
}

fn stop_backend(app: &AppHandle) {
    BACKEND_PORT.store(0, Ordering::SeqCst);
    if let Some(state) = app.try_state::<AppState>() {
        if let Some(mut b) = state.backend.lock().unwrap().take() {
            // Dropping stdin tells a root backend to exit; kill() covers the
            // case where we started it ourselves (already root).
            drop(b._stdin);
            let _ = b.child.kill();
            let _ = b.child.wait();
        }
    }
}

fn main() {
    let app = tauri::Builder::default()
        .plugin(tauri_plugin_notification::init())
        .manage(AppState::default())
        .invoke_handler(tauri::generate_handler![start_backend])
        .setup(|app| {
            WebviewWindowBuilder::new(app, "main", WebviewUrl::App("index.html".into()))
                .title("Kill Line")
                .inner_size(1360.0, 900.0)
                .min_inner_size(900.0, 600.0)
                .background_color(tauri::window::Color(7, 9, 11, 255))
                .on_navigation(|url| allowed(url))
                .build()?;
            Ok(())
        })
        .build(tauri::generate_context!())
        .expect("error while building Kill Line");
    app.run(|handle, event| {
        if let RunEvent::Exit = event {
            stop_backend(handle);
        }
    });
}
