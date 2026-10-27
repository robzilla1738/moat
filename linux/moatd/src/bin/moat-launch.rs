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
use std::os::unix::net::UnixStream;
use std::path::PathBuf;
use std::process::ExitCode;

use clap::Parser;
use moatd::control::{replies, send, Reply, Request};

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
    let req = Request::Launch {
        profile: cli.profile.clone(),
        argv: cli.argv.clone(),
        cwd: std::env::current_dir().unwrap_or_else(|_| "/".into()),
        env,
        isolate_brokers: !cli.allow_brokers,
    };
    if let Err(e) = send(&s, &req, &[0, 1, 2]) {
        eprintln!("moat-launch: {e}");
        return ExitCode::from(125);
    }
    for r in replies(&s) {
        match r {
            Reply::Started { session_id, cgroup, boundary, .. } => {
                if std::env::var_os("MOAT_QUIET").is_none() {
                    eprintln!("moat: session {session_id} ({}, boundary {boundary}, {cgroup})", cli.profile);
                }
            }
            Reply::Refused { reason } => {
                eprintln!("moat-launch: refused: {reason}");
                return ExitCode::from(126);
            }
            Reply::Exited { code, signal, .. } => {
                return match (code, signal) {
                    (Some(c), _) => ExitCode::from(c.clamp(0, 255) as u8),
                    (None, Some(sig)) => ExitCode::from((128 + sig).clamp(0, 255) as u8),
                    _ => ExitCode::from(1),
                };
            }
            Reply::Error { message } => {
                eprintln!("moat-launch: {message}");
                return ExitCode::from(125);
            }
            _ => {}
        }
    }
    eprintln!("moat-launch: connection to moatd lost");
    ExitCode::from(125)
}
