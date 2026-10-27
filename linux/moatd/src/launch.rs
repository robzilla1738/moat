//! Spawning a workload inside its session boundary.
//!
//! The order in the child, between fork and exec, is what makes the boundary exist before any workload code runs:
//!
//! 1. join the session cgroup (write `0` to its `cgroup.procs`) while still root;
//! 2. optionally enter a private mount namespace and hide broker sockets (user D-Bus/systemd, Docker, SSH agent),
//!    because a local broker can act on the workload's behalf outside the cgroup;
//! 3. drop supplementary groups, gid, uid to the requesting user;
//! 4. set `no_new_privs` so setuid helpers (sudo, pkexec) cannot regain privileges;
//! 5. mark every inherited descriptor above stderr close-on-exec, so no preexisting socket crosses the boundary;
//! 6. exec the requested argv directly (no shell).
//!
//! What remains outside this boundary is documented in docs/platforms/linux.md (abstract-namespace Unix sockets,
//! the system resolver as a DNS broker, other brokers reachable by path that the profile does not hide).

use std::collections::BTreeMap;
use std::ffi::CString;
use std::os::fd::{AsRawFd, OwnedFd};
use std::os::unix::process::CommandExt;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};

use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq, Default)]
pub struct BrokerIsolation {
    /// Hide /run/user/<uid> (user systemd manager and session D-Bus, which can start processes outside the session).
    pub hide_user_runtime_dir: bool,
    /// Hide Docker/Podman sockets.
    pub hide_container_sockets: bool,
    /// Remove SSH_AUTH_SOCK and hide the agent socket path.
    pub hide_ssh_agent: bool,
}

impl BrokerIsolation {
    pub fn strict() -> Self {
        BrokerIsolation { hide_user_runtime_dir: true, hide_container_sockets: true, hide_ssh_agent: true }
    }
    pub fn any(&self) -> bool {
        self.hide_user_runtime_dir || self.hide_container_sockets || self.hide_ssh_agent
    }
}

pub const CONTAINER_SOCKETS: [&str; 4] = ["/run/docker.sock", "/var/run/docker.sock", "/run/podman/podman.sock", "/run/containerd/containerd.sock"];

/// Environment variables never passed into a protected session.
pub const STRIPPED_ENV: [&str; 6] = ["DBUS_SESSION_BUS_ADDRESS", "SSH_AUTH_SOCK", "DOCKER_HOST", "LD_PRELOAD", "LD_LIBRARY_PATH", "MOAT_SESSION_TOKEN"];

#[derive(Debug)]
pub struct LaunchSpec {
    pub argv: Vec<String>,
    pub cwd: PathBuf,
    pub env: BTreeMap<String, String>,
    pub uid: u32,
    pub gid: u32,
    pub cgroup_procs: PathBuf,
    pub isolation: BrokerIsolation,
    pub session_id: String,
    pub profile: String,
    /// stdin, stdout, stderr. None = /dev/null.
    pub stdio: [Option<OwnedFd>; 3],
}

fn errno(ctx: &str) -> std::io::Error {
    let e = std::io::Error::last_os_error();
    std::io::Error::new(e.kind(), format!("{ctx}: {e}"))
}

/// Paths to cover with an empty read-only tmpfs / /dev/null inside the session's mount namespace.
pub fn hidden_paths(iso: &BrokerIsolation, uid: u32, env: &BTreeMap<String, String>) -> (Vec<PathBuf>, Vec<PathBuf>) {
    let mut dirs = Vec::new();
    let mut files = Vec::new();
    if iso.hide_user_runtime_dir {
        let p = PathBuf::from(format!("/run/user/{uid}"));
        if p.is_dir() {
            dirs.push(p);
        }
    }
    if iso.hide_container_sockets {
        for s in CONTAINER_SOCKETS {
            if Path::new(s).exists() {
                files.push(PathBuf::from(s));
            }
        }
    }
    if iso.hide_ssh_agent {
        if let Some(sock) = env.get("SSH_AUTH_SOCK") {
            let p = PathBuf::from(sock);
            if p.exists() {
                files.push(p);
            }
        }
    }
    (dirs, files)
}

/// Spawn the workload. Must be called as root. Returns the child (the session root process).
pub fn spawn(spec: LaunchSpec) -> std::io::Result<Child> {
    if spec.uid == 0 {
        return Err(std::io::Error::new(std::io::ErrorKind::PermissionDenied, "protected sessions cannot run as root"));
    }
    if spec.argv.is_empty() {
        return Err(std::io::Error::new(std::io::ErrorKind::InvalidInput, "empty argv"));
    }
    let (hide_dirs, hide_files) = hidden_paths(&spec.isolation, spec.uid, &spec.env);
    let procs = CString::new(spec.cgroup_procs.as_os_str().as_encoded_bytes()).unwrap();
    let hide_dirs: Vec<CString> = hide_dirs.iter().map(|p| CString::new(p.as_os_str().as_encoded_bytes()).unwrap()).collect();
    let hide_files: Vec<CString> = hide_files.iter().map(|p| CString::new(p.as_os_str().as_encoded_bytes()).unwrap()).collect();
    let isolate = spec.isolation.any();
    let (uid, gid) = (spec.uid, spec.gid);

    let mut cmd = Command::new(&spec.argv[0]);
    cmd.args(&spec.argv[1..]).current_dir(&spec.cwd).env_clear();
    for (k, v) in &spec.env {
        if !STRIPPED_ENV.contains(&k.as_str()) {
            cmd.env(k, v);
        }
    }
    cmd.env("MOAT_SESSION_ID", &spec.session_id).env("MOAT_SESSION_PROFILE", &spec.profile);
    let [i, o, e] = spec.stdio;
    cmd.stdin(i.map(Stdio::from).unwrap_or_else(Stdio::null));
    cmd.stdout(o.map(Stdio::from).unwrap_or_else(Stdio::null));
    cmd.stderr(e.map(Stdio::from).unwrap_or_else(Stdio::null));

    // SAFETY: only async-signal-safe libc calls between fork and exec; all allocations happened above.
    unsafe {
        cmd.pre_exec(move || {
            // 1. join the session cgroup before anything else runs.
            let fd = libc::open(procs.as_ptr(), libc::O_WRONLY | libc::O_CLOEXEC);
            if fd < 0 {
                return Err(errno("open cgroup.procs"));
            }
            let zero = b"0";
            if libc::write(fd, zero.as_ptr().cast(), 1) != 1 {
                libc::close(fd);
                return Err(errno("join session cgroup"));
            }
            libc::close(fd);
            // 2. broker isolation in a private mount namespace.
            if isolate {
                if libc::unshare(libc::CLONE_NEWNS) != 0 {
                    return Err(errno("unshare mount namespace"));
                }
                let root = c"/";
                if libc::mount(std::ptr::null(), root.as_ptr(), std::ptr::null(), libc::MS_REC | libc::MS_PRIVATE, std::ptr::null()) != 0 {
                    return Err(errno("make mounts private"));
                }
                let tmpfs = c"tmpfs";
                let opts = c"mode=000,size=4k";
                for d in &hide_dirs {
                    if libc::mount(tmpfs.as_ptr(), d.as_ptr(), tmpfs.as_ptr(), libc::MS_RDONLY | libc::MS_NOSUID | libc::MS_NODEV | libc::MS_NOEXEC, opts.as_ptr().cast()) != 0 {
                        return Err(errno("hide broker directory"));
                    }
                }
                let devnull = c"/dev/null";
                for f in &hide_files {
                    if libc::mount(devnull.as_ptr(), f.as_ptr(), std::ptr::null(), libc::MS_BIND, std::ptr::null()) != 0 {
                        return Err(errno("hide broker socket"));
                    }
                }
            }
            // 3. drop privileges.
            if libc::setgroups(0, std::ptr::null()) != 0 {
                return Err(errno("setgroups"));
            }
            if libc::setresgid(gid, gid, gid) != 0 {
                return Err(errno("setresgid"));
            }
            if libc::setresuid(uid, uid, uid) != 0 {
                return Err(errno("setresuid"));
            }
            // 4. no setuid escalation.
            if libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) != 0 {
                return Err(errno("no_new_privs"));
            }
            // 5. nothing inherited beyond stdio survives exec.
            let r = libc::syscall(libc::SYS_close_range, 3u32, u32::MAX, libc::CLOSE_RANGE_CLOEXEC);
            if r != 0 {
                for fd in 3..1024 {
                    let fl = libc::fcntl(fd, libc::F_GETFD);
                    if fl >= 0 {
                        libc::fcntl(fd, libc::F_SETFD, fl | libc::FD_CLOEXEC);
                    }
                }
            }
            Ok(())
        });
    }
    cmd.spawn()
}

/// Raw fd helper for diagnostics.
pub fn fd_num(f: &OwnedFd) -> i32 {
    f.as_raw_fd()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hidden_paths_respect_flags() {
        let mut env = BTreeMap::new();
        env.insert("SSH_AUTH_SOCK".to_string(), "/definitely/not/here".to_string());
        let (d, f) = hidden_paths(&BrokerIsolation::default(), 1000, &env);
        assert!(d.is_empty() && f.is_empty());
        let (_, f) = hidden_paths(&BrokerIsolation::strict(), 1000, &env);
        assert!(!f.iter().any(|p| p.to_str() == Some("/definitely/not/here")), "nonexistent paths are skipped");
    }

    #[test]
    fn refuses_root_and_empty_argv() {
        let spec = |uid, argv: Vec<String>| LaunchSpec {
            argv,
            cwd: "/".into(),
            env: BTreeMap::new(),
            uid,
            gid: uid,
            cgroup_procs: "/nonexistent".into(),
            isolation: BrokerIsolation::default(),
            session_id: "t".into(),
            profile: "p".into(),
            stdio: [None, None, None],
        };
        assert_eq!(spawn(spec(0, vec!["true".into()])).unwrap_err().kind(), std::io::ErrorKind::PermissionDenied);
        assert!(spawn(spec(1000, vec![])).is_err());
    }
}
