//! `moat-launch` — start a command inside a Moat protected session.
//!
//! ```text
//! moat-launch --profile coding-session -- claude
//! ```
//!
//! The daemon creates the session cgroup, places the process in it before exec, drops to *your* uid (taken from the
//! kernel, not from this request) and returns the session id. If no valid policy for the profile is installed, the
//! launch is refused with the reason; it never silently runs unprotected.

use std::collections::BTreeMap;
use std::os::fd::AsRawFd;
use std::os::unix::net::UnixStream;
use std::path::PathBuf;
use std::process::ExitCode;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

use clap::Parser;
use moatd::control::{replies, send, Reply, Request};
use moatd::pty;

#[derive(Parser)]
#[command(name = "moat-launch", version, about = "Run a command inside a Moat protected session")]
struct Cli {
    #[arg(long)]
    profile: String,
    #[arg(long, default_value = "/run/moat/control.sock")]
    socket: PathBuf,
    /// Keep access to user-session brokers (systemd --user, D-Bus, Docker, SSH agent). Weakens the boundary.
    #[arg(long)]
    allow_brokers: bool,
    /// Give the workload its own PTY (job control, Ctrl-C/Ctrl-Z, resize) relayed to this terminal.
    /// Default: on when stdin and stdout are terminals.
    #[arg(long, conflicts_with = "no_pty")]
    pty: bool,
    /// Pass this terminal's descriptors through unchanged (no PTY proxy).
    #[arg(long)]
    no_pty: bool,
    #[arg(last = true, required = true)]
    argv: Vec<String>,
}

fn main() -> ExitCode {
    let cli = Cli::parse();
    let s = match UnixStream::connect(&cli.socket) {
        Ok(s) => s,
        Err(e) => {
            eprintln!("moat-launch: moatd is not reachable at {} ({e}). Refusing to run unprotected.", cli.socket.display());
            return ExitCode::from(125);
        }
    };
    let env: BTreeMap<String, String> = std::env::vars().collect();
    let use_pty = !cli.no_pty && (cli.pty || (pty::is_tty(0) && pty::is_tty(1)));
    let pair = if use_pty {
        match pty::open_pty() {
            Ok(p) => {
                pty::copy_winsize(0, p.master.as_raw_fd());
                Some(p)
            }
            Err(e) => {
                eprintln!("moat-launch: cannot allocate a PTY ({e}); use --no-pty to pass this terminal through");
                return ExitCode::from(125);
            }
        }
    } else {
        None
    };
    let req = Request::Launch {
        profile: cli.profile.clone(),
        argv: cli.argv.clone(),
        cwd: std::env::current_dir().unwrap_or_else(|_| "/".into()),
        env,
        isolate_brokers: !cli.allow_brokers,
        controlling_tty: pair.is_some(),
    };
    let fds = match &pair {
        Some(p) => {
            let s = p.slave.as_raw_fd();
            [s, s, s]
        }
        None => [0, 1, 2],
    };
    if let Err(e) = send(&s, &req, &fds) {
        eprintln!("moat-launch: {e}");
        return ExitCode::from(125);
    }
    // Our copy of the slave must close, or the relay never sees the workload hang up.
    let mut relay: Option<(Option<pty::RawMode>, Arc<AtomicBool>, std::thread::JoinHandle<()>)> = None;
    if let Some(p) = pair {
        drop(p.slave);
        let raw = if pty::is_tty(0) { pty::RawMode::enter(0).ok() } else { None };
        let stop = Arc::new(AtomicBool::new(false));
        match pty::relay(p.master, stop.clone()) {
            Ok(h) => relay = Some((raw, stop, h)),
            Err(e) => {
                drop(raw);
                eprintln!("moat-launch: PTY relay failed: {e}");
                return ExitCode::from(125);
            }
        }
    }
    let finish = |relay: Option<(Option<pty::RawMode>, Arc<AtomicBool>, std::thread::JoinHandle<()>)>| {
        if let Some((raw, stop, out)) = relay {
            // Drain the workload's last output (EIO arrives once every slave copy is closed), then restore the tty.
            let deadline = std::time::Instant::now() + std::time::Duration::from_secs(2);
            while !out.is_finished() && std::time::Instant::now() < deadline {
                std::thread::sleep(std::time::Duration::from_millis(20));
            }
            stop.store(true, Ordering::Relaxed);
            drop(raw);
        }
    };
    for r in replies(&s) {
        match r {
            Reply::Started { session_id, cgroup, boundary, .. } => {
                if std::env::var_os("MOAT_QUIET").is_none() {
                    eprintln!("moat: session {session_id} ({}, boundary {boundary}, {cgroup})", cli.profile);
                }
            }
            Reply::Refused { reason } => {
                finish(relay.take());
                eprintln!("moat-launch: refused: {reason}");
                return ExitCode::from(126);
            }
            Reply::Exited { code, signal, .. } => {
                finish(relay.take());
                return match (code, signal) {
                    (Some(c), _) => ExitCode::from(c.clamp(0, 255) as u8),
                    (None, Some(sig)) => ExitCode::from((128 + sig).clamp(0, 255) as u8),
                    _ => ExitCode::from(1),
                };
            }
            Reply::Error { message } => {
                finish(relay.take());
                eprintln!("moat-launch: {message}");
                return ExitCode::from(125);
            }
            _ => {}
        }
    }
    finish(relay.take());
    eprintln!("moat-launch: connection to moatd lost");
    ExitCode::from(125)
}
