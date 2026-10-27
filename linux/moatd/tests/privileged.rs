//! Privileged integration tests for the protected-session boundary (real cgroup v2, real setuid drop).
//!
//! Run as root: `sudo -E MOAT_PRIV_TESTS=1 cargo test -p moatd --test privileged -- --test-threads=1`.
//! Skipped (pass trivially, printing why) otherwise. CI runs them on ubuntu-latest.

use std::collections::BTreeMap;
use std::fs;
use std::io::Read;
use std::os::fd::{FromRawFd, OwnedFd};
use std::path::PathBuf;

use moatd::cgroup::Cgroups;
use moatd::launch::{spawn, BrokerIsolation, LaunchSpec};

const NOBODY: u32 = 65534;

fn enabled() -> bool {
    let on =
        std::env::var("MOAT_PRIV_TESTS").is_ok() && nix::unistd::getuid().is_root() && moatd::cgroup::is_cgroup2("/sys/fs/cgroup".as_ref());
    if !on {
        eprintln!("skipping: set MOAT_PRIV_TESTS=1 and run as root on a cgroup v2 host");
    }
    on
}

fn cg(name: &str) -> Cgroups {
    let c = Cgroups { mount: "/sys/fs/cgroup".into(), root_name: format!("moat-test-{name}.slice") };
    c.ensure_profiles(&["lab".into()]).unwrap();
    c
}

/// Run argv as nobody inside a fresh session; return (stdout, exit code).
fn run_in_session(c: &Cgroups, id: &str, argv: &[&str], iso: BrokerIsolation, env: BTreeMap<String, String>) -> (String, i32) {
    let s = c.create_session("lab", id).unwrap();
    let mut fds = [0; 2];
    assert_eq!(unsafe { libc::pipe2(fds.as_mut_ptr(), libc::O_CLOEXEC) }, 0);
    let (r, w) = unsafe { (OwnedFd::from_raw_fd(fds[0]), OwnedFd::from_raw_fd(fds[1])) };
    let mut child = spawn(LaunchSpec {
        argv: argv.iter().map(|s| s.to_string()).collect(),
        cwd: "/".into(),
        env,
        uid: NOBODY,
        gid: NOBODY,
        cgroup_procs: s.path.join("cgroup.procs"),
        isolation: iso,
        session_id: id.into(),
        profile: "lab".into(),
        stdio: [None, Some(w), None],
        controlling_tty: false,
    })
    .unwrap();
    let st = child.wait().unwrap();
    drop(child);
    let mut out = String::new();
    fs::File::from(r).read_to_string(&mut out).unwrap();
    c.close_session(&s).unwrap();
    (out, st.code().unwrap_or(-1))
}

fn cleanup(c: &Cgroups) {
    let _ = fs::remove_dir(c.root().join("p-lab"));
    let _ = fs::remove_dir(c.root());
}

#[test]
fn placed_in_cgroup_before_exec_and_children_inherit() {
    if !enabled() {
        return;
    }
    let c = cg("inherit");
    let (out, code) = run_in_session(
        &c,
        "s1",
        &["/bin/sh", "-c", "cat /proc/self/cgroup; sh -c 'cat /proc/self/cgroup'"],
        BrokerIsolation::default(),
        BTreeMap::new(),
    );
    assert_eq!(code, 0, "{out}");
    let lines: Vec<&str> = out.lines().collect();
    assert_eq!(lines.len(), 2, "{out}");
    for l in lines {
        assert_eq!(l, "0::/moat-test-inherit.slice/p-lab/s-s1");
    }
    cleanup(&c);
}

#[test]
fn workload_cannot_move_itself_out() {
    if !enabled() {
        return;
    }
    let c = cg("escape");
    let script = "echo $$ > /sys/fs/cgroup/cgroup.procs 2>/dev/null && echo ESCAPED-ROOT; \
                  echo $$ > /sys/fs/cgroup/moat-test-escape.slice/cgroup.procs 2>/dev/null && echo ESCAPED-PARENT; \
                  mkdir /sys/fs/cgroup/moat-test-escape.slice/p-lab/s-e1/sub 2>/dev/null && echo DELEGATED; \
                  cat /proc/self/cgroup";
    let (out, _) = run_in_session(&c, "e1", &["/bin/sh", "-c", script], BrokerIsolation::default(), BTreeMap::new());
    assert!(!out.contains("ESCAPED"), "{out}");
    assert!(!out.contains("DELEGATED"), "{out}");
    assert!(out.contains("0::/moat-test-escape.slice/p-lab/s-e1"), "{out}");
    cleanup(&c);
}

#[test]
fn no_new_privs_and_uid_drop() {
    if !enabled() {
        return;
    }
    let c = cg("nnp");
    let (out, _) = run_in_session(
        &c,
        "n1",
        &["/bin/sh", "-c", "grep -E '^(NoNewPrivs|Uid|Groups):' /proc/self/status"],
        BrokerIsolation::default(),
        BTreeMap::new(),
    );
    assert!(out.contains("NoNewPrivs:\t1"), "{out}");
    assert!(out.lines().any(|l| l.starts_with("Uid:") && l.split_whitespace().skip(1).all(|u| u == "65534")), "{out}");
    assert!(out.lines().any(|l| l.trim() == "Groups:"), "supplementary groups dropped: {out}");
    cleanup(&c);
}

#[test]
fn inherited_descriptors_do_not_cross() {
    if !enabled() {
        return;
    }
    let c = cg("fds");
    // A descriptor without CLOEXEC in the supervisor (like a preexisting socket) must not reach the workload.
    let f = fs::File::open("/etc/hostname").unwrap();
    let leaked = unsafe { libc::dup(std::os::fd::AsRawFd::as_raw_fd(&f)) };
    assert!(leaked > 2);
    let (out, _) = run_in_session(&c, "f1", &["/bin/sh", "-c", "ls /proc/self/fd"], BrokerIsolation::default(), BTreeMap::new());
    let fds: Vec<i32> = out.split_whitespace().filter_map(|x| x.parse().ok()).collect();
    assert!(!fds.contains(&leaked), "leaked fd {leaked} visible: {fds:?}");
    unsafe { libc::close(leaked) };
    cleanup(&c);
}

#[test]
fn brokers_hidden_and_env_stripped() {
    if !enabled() {
        return;
    }
    let c = cg("brokers");
    let rundir = PathBuf::from(format!("/run/user/{NOBODY}"));
    fs::create_dir_all(&rundir).unwrap();
    fs::write(rundir.join("bus"), "fake user bus").unwrap();
    let agent = PathBuf::from("/tmp/moat-test-agent.sock");
    fs::write(&agent, "fake agent").unwrap();
    let mut env = BTreeMap::new();
    env.insert("SSH_AUTH_SOCK".to_string(), agent.to_string_lossy().to_string());
    env.insert("DBUS_SESSION_BUS_ADDRESS".to_string(), format!("unix:path={}/bus", rundir.display()));
    env.insert("PATH".to_string(), "/usr/bin:/bin".to_string());
    let script = format!(
        "cat {}/bus 2>/dev/null && echo SAW-BUS; cat {} 2>/dev/null | grep -q agent && echo SAW-AGENT; env | grep -E 'SSH_AUTH_SOCK|DBUS_SESSION' && echo SAW-ENV; echo MOAT=$MOAT_SESSION_ID",
        rundir.display(),
        agent.display()
    );
    let (out, _) = run_in_session(&c, "b1", &["/bin/sh", "-c", &script], BrokerIsolation::strict(), env);
    assert!(!out.contains("SAW-"), "{out}");
    assert!(out.contains("MOAT=b1"), "{out}");
    // the host view is untouched
    assert_eq!(fs::read_to_string(rundir.join("bus")).unwrap(), "fake user bus");
    let _ = fs::remove_file(&agent);
    let _ = fs::remove_dir_all(&rundir);
    cleanup(&c);
}

#[test]
fn closing_a_session_kills_detached_children() {
    if !enabled() {
        return;
    }
    let c = cg("detach");
    let s = c.create_session("lab", "d1").unwrap();
    let mut child = spawn(LaunchSpec {
        argv: vec!["/bin/sh".into(), "-c".into(), "(setsid sleep 300 &) ; sleep 0.2".into()],
        cwd: "/".into(),
        env: BTreeMap::new(),
        uid: NOBODY,
        gid: NOBODY,
        cgroup_procs: s.path.join("cgroup.procs"),
        isolation: BrokerIsolation::default(),
        session_id: "d1".into(),
        profile: "lab".into(),
        stdio: [None, None, None],
        controlling_tty: false,
    })
    .unwrap();
    child.wait().unwrap();
    // the detached sleeper is still in the session cgroup (setsid does not change cgroups)
    assert!(!c.procs(&s).is_empty());
    c.close_session(&s).unwrap();
    assert!(!s.path.exists());
    cleanup(&c);
}
