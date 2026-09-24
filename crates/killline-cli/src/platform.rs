//! The few places where the CLI differs between Linux and Windows.

use std::process::Command;

pub fn stdout_is_tty() -> bool {
    use std::io::IsTerminal;
    std::io::stdout().is_terminal()
}

/// Call `handler` on Ctrl+C / SIGTERM (or console close on Windows).
pub fn install_stop_handler(handler: extern "C" fn(i32)) {
    #[cfg(unix)]
    // SAFETY: installing a handler that only stores to an atomic.
    unsafe {
        libc::signal(libc::SIGINT, handler as *const () as libc::sighandler_t);
        libc::signal(libc::SIGTERM, handler as *const () as libc::sighandler_t);
    }
    #[cfg(windows)]
    {
        use std::sync::OnceLock;
        use windows_sys::Win32::System::Console::SetConsoleCtrlHandler;
        static HANDLER: OnceLock<extern "C" fn(i32)> = OnceLock::new();
        let _ = HANDLER.set(handler);
        unsafe extern "system" fn on_ctrl(kind: u32) -> i32 {
            if let Some(h) = HANDLER.get() {
                h(kind as i32);
            }
            1
        }
        // SAFETY: registers a static routine that only stores to an atomic.
        unsafe {
            SetConsoleCtrlHandler(Some(on_ctrl), 1);
        }
    }
}

pub struct HostInfo {
    pub kernel: String,
    pub hostname: String,
    pub os: String,
    pub boot_id: String,
}

pub fn host_info() -> HostInfo {
    #[cfg(target_os = "linux")]
    {
        let read = |p: &str| {
            std::fs::read_to_string(p)
                .map(|s| s.trim().to_string())
                .unwrap_or_default()
        };
        let os = read("/etc/os-release")
            .lines()
            .find(|l| l.starts_with("PRETTY_NAME="))
            .map(|l| {
                l.trim_start_matches("PRETTY_NAME=")
                    .trim_matches('"')
                    .to_string()
            })
            .unwrap_or_default();
        HostInfo {
            kernel: format!("Linux {}", read("/proc/sys/kernel/osrelease")),
            hostname: read("/proc/sys/kernel/hostname"),
            os,
            boot_id: read("/proc/sys/kernel/random/boot_id"),
        }
    }
    #[cfg(not(target_os = "linux"))]
    {
        HostInfo {
            kernel: std::env::consts::OS.to_string(),
            hostname: std::env::var("COMPUTERNAME").unwrap_or_default(),
            os: if cfg!(windows) {
                "Windows".into()
            } else {
                std::env::consts::OS.into()
            },
            boot_id: String::new(),
        }
    }
}

/// Let a child process outlive this one (its own session / process group).
pub fn detach(cmd: &mut Command) {
    #[cfg(unix)]
    {
        use std::os::unix::process::CommandExt;
        // SAFETY: setsid is async-signal-safe.
        unsafe {
            cmd.pre_exec(|| {
                libc::setsid();
                Ok(())
            });
        }
    }
    #[cfg(windows)]
    {
        use std::os::windows::process::CommandExt;
        const DETACHED_PROCESS: u32 = 0x0000_0008;
        const CREATE_NEW_PROCESS_GROUP: u32 = 0x0000_0200;
        const CREATE_NO_WINDOW: u32 = 0x0800_0000;
        cmd.creation_flags(DETACHED_PROCESS | CREATE_NEW_PROCESS_GROUP | CREATE_NO_WINDOW);
    }
}

pub fn open_url(url: &str) {
    let mut cmd = if cfg!(windows) {
        let mut c = Command::new("rundll32");
        c.arg("url.dll,FileProtocolHandler").arg(url);
        c
    } else {
        let mut c = Command::new("xdg-open");
        c.arg(url);
        c
    };
    let _ = cmd
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .spawn();
}
