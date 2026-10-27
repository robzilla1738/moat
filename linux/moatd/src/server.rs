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

use crate::caller::{self, Caller, SessionCgroupRef};
use crate::cgroup::start_generation;
use crate::control::{pass_credentials, peer, recv_request, send, Reply, Request};
use crate::endpoint::{Endpoint, SessionInfo};
use crate::launch::{spawn, BrokerIsolation, LaunchSpec};
use crate::nft::NftBackend;

pub fn serve<B: NftBackend + Send + 'static>(ep: Endpoint<B>, socket: PathBuf, tick: Duration) -> std::io::Result<()> {
    serve_with(ep, socket, tick, None)
}

/// `serve`, plus the observe-only ordinary-app inventory (W10) sampled every `inventory` interval when set. The
/// inventory reads /proc outside the endpoint lock and only appends spool records; it never touches enforcement.
pub fn serve_with<B: NftBackend + Send + 'static>(
    ep: Endpoint<B>,
    socket: PathBuf,
    tick: Duration,
    inventory: Option<Duration>,
) -> std::io::Result<()> {
    let ep = Arc::new(Mutex::new(ep));
    if let Some(every) = inventory {
        let ep = ep.clone();
        std::thread::spawn(move || {
            let src = crate::inventory::ProcFs::default();
            let mut inv = crate::inventory::Inventory::new();
            {
                let mut e = ep.lock().unwrap();
                e.spool.append(crate::spool::Event::CoverageChanged {
                    level: format!("ordinary_inventory:{}", crate::inventory::COVERAGE),
                    detail: crate::inventory::Inventory::coverage_note().into(),
                });
            }
            loop {
                let events = inv.tick(&src);
                if !events.is_empty() {
                    let mut e = ep.lock().unwrap();
                    for ev in events {
                        let record = serde_json::to_value(&ev).unwrap_or(serde_json::Value::Null);
                        e.spool.append(crate::spool::Event::Inventory { coverage: crate::inventory::COVERAGE.into(), record });
                    }
                }
                std::thread::sleep(every);
            }
        });
    }
    // SIGTERM/SIGINT: record a clean shutdown in the spool, then exit. Enforcement state stays in the kernel; the
    // next start re-verifies and reconciles it.
    {
        use nix::sys::signal::{SigSet, Signal};
        let mut set = SigSet::empty();
        set.add(Signal::SIGTERM);
        set.add(Signal::SIGINT);
        set.thread_block().map_err(std::io::Error::from)?;
        let ep = ep.clone();
        std::thread::spawn(move || {
            if set.wait().is_ok() {
                if let Ok(e) = ep.lock() {
                    e.spool.mark_clean();
                }
                std::process::exit(0);
            }
        });
    }
    if let Some(d) = socket.parent() {
        fs::create_dir_all(d)?;
    }
    let _ = fs::remove_file(&socket);
    let l = UnixListener::bind(&socket)?;
    pass_credentials(&l)?;
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

/// Who is calling, from kernel facts only (connect-time peer + request sender). See `caller`.
fn caller_of<B: NftBackend + Send + 'static>(ep: &Endpoint<B>, connect_pid: i32, sender_pid: Option<i32>) -> Caller {
    let root = ep.cgroups.root_name.clone();
    let sessions: Vec<SessionCgroupRef> = ep
        .sessions
        .values()
        .map(|(i, _)| SessionCgroupRef { id: i.id.clone(), profile: i.profile.clone(), rel: i.cgroup.clone() })
        .collect();
    let c = caller::inspect(connect_pid, &root, &sessions);
    let snd = sender_pid.map(|p| if p == connect_pid { c.clone() } else { caller::inspect(p, &root, &sessions) });
    caller::combine(c, snd)
}

fn handle<B: NftBackend + Send + 'static>(ep: Arc<Mutex<Endpoint<B>>>, s: UnixStream) {
    // Make sure credentials are attached to whatever arrives from now on (accepted sockets normally inherit the
    // listener's SO_PASSCRED; this is belt and braces). Requests that arrive without them are refused below.
    let _ = pass_credentials(&s);
    let Ok(p) = peer(&s) else { return };
    let (req, fds, sender) = match recv_request(&s) {
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
            let who = caller_of(&e, p.pid, sender.map(|x| x.pid));
            if let Err(reason) = caller::decide_close(&who, &session_id) {
                let _ = send(&s, &Reply::Refused { reason }, &[]);
                return;
            }
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
        Request::Launch { profile, argv, cwd, env, isolate_brokers, controlling_tty } => {
            // W04: a contained caller can never obtain a less restricted session through this socket.
            let decision = {
                let mut e = ep.lock().unwrap();
                if sender.is_some_and(|x| x.uid != p.uid) {
                    let reason = "the request was sent by a different user than the one that connected".to_string();
                    e.refuse(&profile, p.uid, &reason);
                    let _ = send(&s, &Reply::Refused { reason }, &[]);
                    return;
                }
                let who = caller_of(&e, p.pid, sender.map(|x| x.pid));
                match caller::decide_launch(&who, &profile) {
                    Ok(d) => d,
                    Err(reason) => {
                        e.refuse(&profile, p.uid, &reason);
                        let _ = send(&s, &Reply::Refused { reason }, &[]);
                        return;
                    }
                }
            };
            let isolate_brokers = isolate_brokers || decision.force_isolation;
            launch(ep, s, p, profile, argv, cwd, env, isolate_brokers, controlling_tty, fds)
        }
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
    controlling_tty: bool,
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
        // Proxied profile: open the session's egress-proxy listener and install its redirect before the workload
        // exists, so no connection can precede it. Tools that honour proxy variables use CONNECT on it directly.
        let mut env = env;
        match e.prepare_session_proxy(&id, &profile) {
            Ok(Some(port)) => {
                let url = format!("http://127.0.0.1:{port}");
                env.insert("MOAT_EGRESS_PROXY".into(), url.clone());
                for k in ["HTTPS_PROXY", "https_proxy", "HTTP_PROXY", "http_proxy"] {
                    env.entry(k.into()).or_insert_with(|| url.clone());
                }
                env.entry("NO_PROXY".into()).or_insert_with(|| "localhost,127.0.0.1,::1".into());
                env.entry("no_proxy".into()).or_insert_with(|| "localhost,127.0.0.1,::1".into());
            }
            Ok(None) => {}
            Err(reason) => {
                let _ = e.cgroups.close_session(&cg);
                e.refuse(&profile, p.uid, &reason);
                let _ = send(&s, &Reply::Refused { reason }, &[]);
                return;
            }
        }
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
            controlling_tty,
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
                e.close_session_proxy(&id);
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
