//! Spawning a workload inside its session boundary.
//!
//! The order in the child, between fork and exec, is what makes the boundary exist before any workload code runs:
//!
//! 0. leave the daemon's own service sandbox: when moatd runs under systemd with `ProtectSystem=`, `ProtectHome=`
//!    or `PrivateTmp=`, it lives in a private mount namespace in which the user's home is read-only and /tmp is
//!    private. The workload must see the user's real filesystem (it edits a project), so the child joins PID 1's
//!    mount namespace and re-enters its working directory there (W11, D-SYSTEMD-WORKSPACE). The daemon itself stays
//!    sandboxed. This changes no network or broker boundary: those come from the cgroup and from step 2;
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

pub const CONTAINER_SOCKETS: [&str; 4] =
    ["/run/docker.sock", "/var/run/docker.sock", "/run/podman/podman.sock", "/run/containerd/containerd.sock"];

/// Environment variables never passed into a protected session.
pub const STRIPPED_ENV: [&str; 6] =
    ["DBUS_SESSION_BUS_ADDRESS", "SSH_AUTH_SOCK", "DOCKER_HOST", "LD_PRELOAD", "LD_LIBRARY_PATH", "MOAT_SESSION_TOKEN"];

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
    /// Make stdin (a PTY slave from `moat-launch --pty`) the controlling terminal: `setsid` + `TIOCSCTTY`.
    pub controlling_tty: bool,
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

/// PID 1's mount namespace, when this process runs in a different one (a systemd service sandbox, a test's private
/// mount namespace). `None` when they are the same or when /proc does not let us compare (then nothing changes).
pub fn host_mount_namespace() -> std::io::Result<Option<OwnedFd>> {
    let Ok(me) = std::fs::read_link("/proc/self/ns/mnt") else { return Ok(None) };
    // Reading PID 1's namespace link is a ptrace-mode access check: under the systemd unit (reduced capability
    // bounding set) it needs CAP_SYS_PTRACE. Failing to compare is an error, never a silent "same namespace".
    let init = std::fs::read_link("/proc/1/ns/mnt")
        .map_err(|e| std::io::Error::new(e.kind(), format!("cannot compare with the host mount namespace (/proc/1/ns/mnt): {e}")))?;
    if me == init {
        return Ok(None);
    }
    let f = std::fs::File::open("/proc/1/ns/mnt")
        .map_err(|e| std::io::Error::new(e.kind(), format!("moatd runs in a private mount namespace and cannot open the host's: {e}")))?;
    Ok(Some(OwnedFd::from(f)))
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
    let host_mnt = host_mount_namespace()?;
    let host_mnt_fd = host_mnt.as_ref().map(|f| f.as_raw_fd());
    let cwd_c = CString::new(spec.cwd.as_os_str().as_encoded_bytes())
        .map_err(|_| std::io::Error::new(std::io::ErrorKind::InvalidInput, "cwd contains a NUL byte"))?;
    let ctty = spec.controlling_tty;
    if ctty && spec.stdio[0].is_none() {
        return Err(std::io::Error::new(std::io::ErrorKind::InvalidInput, "controlling_tty needs a terminal on stdin"));
    }

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
            // The session cgroup is opened in the daemon's own mount namespace, before switching, so no mount in
            // the namespace the workload will see can redirect the cgroup join.
            let procs_fd = libc::open(procs.as_ptr(), libc::O_WRONLY | libc::O_CLOEXEC);
            if procs_fd < 0 {
                return Err(errno("open cgroup.procs"));
            }
            // 0. the user's real filesystem, not the daemon's service sandbox.
            if let Some(fd) = host_mnt_fd {
                if libc::setns(fd, libc::CLONE_NEWNS) != 0 {
                    return Err(errno("enter the host mount namespace"));
                }
                if libc::chdir(cwd_c.as_ptr()) != 0 {
                    return Err(errno("enter the working directory in the host mount namespace"));
                }
            }
            // 1. join the session cgroup before anything else runs.
            let fd = procs_fd;
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
                    if libc::mount(
                        tmpfs.as_ptr(),
                        d.as_ptr(),
                        tmpfs.as_ptr(),
                        libc::MS_RDONLY | libc::MS_NOSUID | libc::MS_NODEV | libc::MS_NOEXEC,
                        opts.as_ptr().cast(),
                    ) != 0
                    {
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
            // 4b. interactive: own session with the caller-allocated PTY slave (fd 0) as controlling terminal, so the
            //     workload is the terminal's foreground process group. After the privilege drop, so the session and
            //     terminal belong to the caller's uid.
            if ctty {
                if libc::setsid() < 0 {
                    return Err(errno("setsid"));
                }
                if libc::ioctl(0, libc::TIOCSCTTY, 0) != 0 {
                    return Err(errno("TIOCSCTTY"));
                }
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
    let child = cmd.spawn();
    drop(host_mnt);
    child
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
            controlling_tty: false,
        };
        assert_eq!(spawn(spec(0, vec!["true".into()])).unwrap_err().kind(), std::io::ErrorKind::PermissionDenied);
        assert!(spawn(spec(1000, vec![])).is_err());
    }
}
