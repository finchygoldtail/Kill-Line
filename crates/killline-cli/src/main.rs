//! killline — independent containment verification for autonomous AI agents.

mod launch;
mod monitor;
mod ui;
mod views;

use anyhow::{bail, Result};
use clap::{Parser, Subcommand};
use killline_core::policy::{Level, Policy, ResponseAction, TEMPLATES};
use killline_core::store;
use std::path::PathBuf;

#[derive(Parser)]
#[command(
    name = "killline",
    version,
    about = "Independent containment verification for autonomous AI agents.\nTrust the sandbox. Verify the boundary."
)]
struct Cli {
    /// Data directory (default: /var/lib/killline as root, else ~/.local/share/killline; or $KILLLINE_HOME)
    #[arg(long, global = true)]
    data_dir: Option<PathBuf>,
    /// Disable coloured output
    #[arg(long, global = true)]
    no_color: bool,
    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Clone, Copy, clap::ValueEnum)]
enum Response {
    Alert,
    Freeze,
    Terminate,
}

impl From<Response> for ResponseAction {
    fn from(r: Response) -> Self {
        match r {
            Response::Alert => ResponseAction::Alert,
            Response::Freeze => ResponseAction::Freeze,
            Response::Terminate => ResponseAction::Terminate,
        }
    }
}

#[derive(Subcommand)]
enum Cmd {
    /// Monitor a running container or process tree against a policy
    Monitor {
        /// Docker container name or id
        #[arg(long, conflicts_with = "pid")]
        container: Option<String>,
        /// Existing process id (it and all descendants are monitored)
        #[arg(long)]
        pid: Option<u32>,
        #[arg(long)]
        policy: PathBuf,
        /// Override the policy's response (default comes from the policy: alert)
        #[arg(long, value_enum)]
        response: Option<Response>,
        /// -v: show every non-runtime event; -vv: show everything
        #[arg(short, long, action = clap::ArgAction::Count)]
        verbose: u8,
        /// Stop after this many seconds
        #[arg(long)]
        duration: Option<u64>,
    },
    /// Launch a command under monitoring (it and all its descendants)
    Run {
        #[arg(long)]
        policy: PathBuf,
        #[arg(long, value_enum)]
        response: Option<Response>,
        /// Run the command as this uid[:gid] (recommended: never run agents as root)
        #[arg(long)]
        user: Option<String>,
        #[arg(short, long, action = clap::ArgAction::Count)]
        verbose: u8,
        #[arg(required = true, last = true)]
        command: Vec<String>,
    },
    /// Open the local dashboard (127.0.0.1 only; token-protected)
    Ui {
        /// Port on 127.0.0.1 (0 picks a free one)
        #[arg(long, default_value_t = 7727)]
        port: u16,
        /// Open the dashboard in the default browser
        #[arg(long)]
        open: bool,
        /// Print one JSON line {"url","port","token"} instead of the banner (for the desktop app)
        #[arg(long, hide = true)]
        announce_json: bool,
        /// Exit when stdin closes (lets an unprivileged parent stop a root backend)
        #[arg(long, hide = true)]
        exit_with_stdin: bool,
    },
    /// Show the status panel of a session (default: most recent)
    Status {
        session: Option<String>,
        /// Refresh every second
        #[arg(long)]
        watch: bool,
    },
    /// List monitoring sessions
    Sessions,
    /// List incidents
    Incidents,
    /// Show an incident and the causal timeline leading up to it
    Inspect {
        incident: String,
        /// Print the raw triggering event as JSON
        #[arg(long)]
        raw: bool,
    },
    /// Print a session's forensic timeline
    Timeline {
        session: Option<String>,
        /// Include runtime-library reads and process fork/exit noise
        #[arg(long)]
        all: bool,
        /// Emit raw JSON lines
        #[arg(long)]
        json: bool,
    },
    /// Verify a session timeline's hash chain or an incident's checksums
    Verify { id: String },
    /// Check a policy file and explain what KillLine can and cannot verify
    ValidatePolicy { file: PathBuf },
    /// Print a bundled policy template (omit NAME to list them)
    Template { name: Option<String> },
    #[command(hide = true, name = "__launch")]
    Launch {
        #[arg(long)]
        wait_fd: i32,
        #[arg(long)]
        uid: Option<u32>,
        #[arg(long)]
        gid: Option<u32>,
        #[arg(required = true, last = true)]
        command: Vec<String>,
    },
}

fn main() {
    let cli = Cli::parse();
    views::set_color(
        !cli.no_color && std::env::var_os("NO_COLOR").is_none() && unsafe { libc::isatty(1) } == 1,
    );
    let root = cli.data_dir.clone().unwrap_or_else(store::data_dir);
    let code = match run(cli, root) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("killline: error: {:#}", e);
            2
        }
    };
    std::process::exit(code);
}

fn run(cli: Cli, root: PathBuf) -> Result<i32> {
    match cli.cmd {
        Cmd::Monitor {
            container,
            pid,
            policy,
            response,
            verbose,
            duration,
        } => {
            let target = match (container, pid) {
                (Some(c), None) => monitor::Target::Container(c),
                (None, Some(p)) => monitor::Target::Pid(p),
                _ => bail!("specify exactly one of --container or --pid"),
            };
            monitor::run(monitor::Options {
                root,
                target,
                policy,
                response: response.map(Into::into),
                verbose,
                duration,
            })
        }
        Cmd::Run {
            policy,
            response,
            user,
            verbose,
            command,
        } => {
            let (uid, gid) = match user {
                None => (None, None),
                Some(u) => {
                    let (a, b) = u
                        .split_once(':')
                        .map(|(a, b)| (a, Some(b)))
                        .unwrap_or((&u, None));
                    let uid: u32 = a
                        .parse()
                        .map_err(|_| anyhow::anyhow!("--user takes a numeric uid[:gid]"))?;
                    let gid: u32 = match b {
                        Some(g) => g
                            .parse()
                            .map_err(|_| anyhow::anyhow!("--user takes a numeric uid[:gid]"))?,
                        None => uid,
                    };
                    (Some(uid), Some(gid))
                }
            };
            monitor::run(monitor::Options {
                root,
                target: monitor::Target::Launch { command, uid, gid },
                policy,
                response: response.map(Into::into),
                verbose,
                duration: None,
            })
        }
        Cmd::Ui {
            port,
            open,
            announce_json,
            exit_with_stdin,
        } => ui::serve(root, port, open, announce_json, exit_with_stdin),
        Cmd::Status { session, watch } => views::status(&root, session.as_deref(), watch),
        Cmd::Sessions => views::sessions(&root),
        Cmd::Incidents => views::incidents(&root),
        Cmd::Inspect { incident, raw } => views::inspect(&root, &incident, raw),
        Cmd::Timeline { session, all, json } => {
            views::timeline(&root, session.as_deref(), all, json)
        }
        Cmd::Verify { id } => views::verify(&root, &id),
        Cmd::ValidatePolicy { file } => {
            let p = Policy::load(&file)?;
            let diags = p.validate();
            let errors = diags.iter().filter(|d| d.level == Level::Error).count();
            println!("Policy:  {}", file.display());
            println!("Agent:   {}", p.agent);
            println!("Name:    {}", p.display_name());
            println!("Network: {:?}", p.network.effective_mode());
            println!("Response on violation: {:?}", p.response.violation);
            for d in &diags {
                let tag = match d.level {
                    Level::Error => views::paint("ERROR  ", views::RED),
                    Level::Warning => views::paint("WARNING", views::AMBER),
                    Level::Info => views::paint("INFO   ", views::DIM),
                };
                println!("  {} {}", tag, d.message);
            }
            if errors > 0 {
                println!(
                    "{}",
                    views::paint(&format!("INVALID: {} error(s)", errors), views::RED)
                );
                Ok(1)
            } else {
                println!("{}", views::paint("VALID", views::GREEN));
                Ok(0)
            }
        }
        Cmd::Template { name } => match name {
            None => {
                for (n, _) in TEMPLATES {
                    println!("{}", n);
                }
                Ok(0)
            }
            Some(n) => match TEMPLATES.iter().find(|(t, _)| *t == n) {
                Some((_, text)) => {
                    print!("{}", text);
                    Ok(0)
                }
                None => bail!("no template '{}'", n),
            },
        },
        Cmd::Launch {
            wait_fd,
            uid,
            gid,
            command,
        } => launch::exec_after_release(wait_fd, uid, gid, &command),
    }
}
