//! Daemon loop: control socket + periodic reconciliation (inbox, recovery state, counters).

use std::fs;
use std::os::fd::{AsRawFd, OwnedFd};
use std::os::unix::fs::PermissionsExt;
use std::os::unix::net::{UnixListener, UnixStream};
use std::os::unix::process::ExitStatusExt;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use chrono::Utc;

use crate::cgroup::start_generation;
use crate::control::{peer, recv_request, send, Reply, Request};
use crate::endpoint::{Endpoint, SessionInfo};
use crate::launch::{spawn, BrokerIsolation, LaunchSpec};
use crate::nft::NftBackend;

pub fn serve<B: NftBackend + Send + 'static>(ep: Endpoint<B>, socket: PathBuf, tick: Duration) -> std::io::Result<()> {
    let ep = Arc::new(Mutex::new(ep));
    if let Some(d) = socket.parent() {
        fs::create_dir_all(d)?;
    }
    let _ = fs::remove_file(&socket);
    let l = UnixListener::bind(&socket)?;
    // Any local user may ask for a session that restricts *themselves*.
    fs::set_permissions(&socket, fs::Permissions::from_mode(0o666))?;
    {
        let ep = ep.clone();
        std::thread::spawn(move || loop {
            {
                let mut e = ep.lock().unwrap();
                e.drain_inbox();
                e.reconcile();
                e.poll_counters();
            }
            std::thread::sleep(tick);
        });
    }
    for conn in l.incoming() {
        let Ok(s) = conn else { continue };
        let ep = ep.clone();
        std::thread::spawn(move || handle(ep, s));
    }
    Ok(())
}

fn handle<B: NftBackend + Send + 'static>(ep: Arc<Mutex<Endpoint<B>>>, s: UnixStream) {
    let Ok(p) = peer(&s) else { return };
    let (req, fds) = match recv_request(&s) {
        Ok(x) => x,
        Err(e) => {
            let _ = send(&s, &Reply::Error { message: e.to_string() }, &[]);
            return;
        }
    };
    match req {
        Request::Status => {
            let st = ep.lock().unwrap().status();
            let _ = send(&s, &Reply::Status { status: serde_json::to_value(st).unwrap() }, &[]);
        }
        Request::Sessions => {
            let st = ep.lock().unwrap().status();
            let _ = send(&s, &Reply::Sessions { sessions: serde_json::to_value(st.sessions).unwrap() }, &[]);
        }
        Request::Close { session_id } => {
            let mut e = ep.lock().unwrap();
            let owner = e.sessions.get(&session_id).map(|(i, _)| i.uid);
            match owner {
                Some(u) if u == p.uid || p.uid == 0 => {
                    e.end_session(&session_id, None, Some(9));
                    let _ = send(&s, &Reply::Closed { session_id }, &[]);
                }
                Some(_) => {
                    let _ = send(&s, &Reply::Refused { reason: "only the session owner or root may close it".into() }, &[]);
                }
                None => {
                    let _ = send(&s, &Reply::Error { message: "no such session".into() }, &[]);
                }
            }
        }
        Request::Launch { profile, argv, cwd, env, isolate_brokers } => launch(ep, s, p, profile, argv, cwd, env, isolate_brokers, fds),
    }
}

#[allow(clippy::too_many_arguments)]
fn launch<B: NftBackend + Send + 'static>(
    ep: Arc<Mutex<Endpoint<B>>>,
    s: UnixStream,
    p: crate::control::Peer,
    profile: String,
    argv: Vec<String>,
    cwd: PathBuf,
    env: std::collections::BTreeMap<String, String>,
    isolate_brokers: bool,
    fds: Vec<OwnedFd>,
) {
    let mut it = fds.into_iter();
    let stdio = [it.next(), it.next(), it.next()];
    let started = {
        let mut e = ep.lock().unwrap();
        if let Some(reason) = e.launch_refusal(&profile, p.uid) {
            e.refuse(&profile, p.uid, &reason);
            let _ = send(&s, &Reply::Refused { reason }, &[]);
            return;
        }
        let id = Endpoint::<B>::new_session_id();
        let cg = match e.cgroups.create_session(&profile, &id) {
            Ok(c) => c,
            Err(err) => {
                let reason = format!("cannot create session cgroup: {err}");
                e.refuse(&profile, p.uid, &reason);
                let _ = send(&s, &Reply::Refused { reason }, &[]);
                return;
            }
        };
        let spec = LaunchSpec {
            argv,
            cwd,
            env,
            uid: p.uid,
            gid: p.gid,
            cgroup_procs: cg.path.join("cgroup.procs"),
            isolation: if isolate_brokers { BrokerIsolation::strict() } else { BrokerIsolation::default() },
            session_id: id.clone(),
            profile: profile.clone(),
            stdio,
        };
        match spawn(spec) {
            Ok(child) => {
                let pid = child.id();
                let info = SessionInfo {
                    id: id.clone(),
                    profile: profile.clone(),
                    uid: p.uid,
                    root_pid: pid,
                    root_start: start_generation(pid).unwrap_or(0),
                    cgroup: cg.rel.clone(),
                    started_at: Utc::now(),
                };
                let _ =
                    send(&s, &Reply::Started { session_id: id.clone(), pid, cgroup: cg.rel.clone(), boundary: "linux_cgroup".into() }, &[]);
                e.register_session(info, cg);
                (id, child)
            }
            Err(err) => {
                let _ = e.cgroups.close_session(&cg);
                let reason = format!("launch failed: {err}");
                e.refuse(&profile, p.uid, &reason);
                let _ = send(&s, &Reply::Refused { reason }, &[]);
                return;
            }
        }
    };
    let (id, mut child) = started;
    let _keep = s.as_raw_fd();
    let status = child.wait();
    let (code, sig) = match status {
        Ok(st) => (st.code(), st.signal()),
        Err(_) => (None, None),
    };
    // The session ends with its root process; remaining descendants are killed so nothing lingers unattributed.
    ep.lock().unwrap().end_session(&id, code, sig);
    let _ = send(&s, &Reply::Exited { session_id: id, code, signal: sig }, &[]);
}
