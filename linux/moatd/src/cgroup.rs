//! cgroup v2 protected-session supervisor.
//!
//! Layout under the cgroup v2 mount (default `/sys/fs/cgroup`):
//!
//! ```text
//! moat.slice/                    root-owned, 0755
//!   p-<profile>/                 one per available session profile; matched by nftables at level 2
//!     s-<session-id>/            one per protected session; the workload is placed here BEFORE exec
//! ```
//!
//! Self-escape: moving a process between cgroups requires write access to `cgroup.procs` of the common ancestor of
//! the source and destination. Every directory here is root-owned with root-owned `cgroup.procs`, the session runs
//! as a non-root user with `no_new_privs`, and the common ancestor with any other cgroup is the root cgroup, which
//! is root-owned. Root workloads are refused because root can move itself anywhere.

use std::fs;
use std::io;
use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::path::{Path, PathBuf};

use crate::nft::sanitize;

#[derive(Clone, Debug)]
pub struct Cgroups {
    pub mount: PathBuf,
    pub root_name: String,
}

impl Default for Cgroups {
    fn default() -> Self {
        Cgroups { mount: "/sys/fs/cgroup".into(), root_name: "moat.slice".into() }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SessionCgroup {
    pub path: PathBuf,
    /// Path relative to the mount, as nftables and /proc/<pid>/cgroup show it (without leading slash).
    pub rel: String,
}

pub fn is_cgroup2(mount: &Path) -> bool {
    mount.join("cgroup.controllers").exists()
}

/// Validate a session id: short, lowercase alphanumerics and dashes.
pub fn valid_session_id(id: &str) -> bool {
    !id.is_empty() && id.len() <= 64 && id.chars().all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-')
}

impl Cgroups {
    pub fn root(&self) -> PathBuf {
        self.mount.join(&self.root_name)
    }

    fn ensure_dir(p: &Path) -> io::Result<()> {
        match fs::create_dir(p) {
            Ok(()) => {}
            Err(e) if e.kind() == io::ErrorKind::AlreadyExists => {}
            Err(e) => return Err(e),
        }
        // cgroupfs ignores most mode bits on create; set what it honors.
        let _ = fs::set_permissions(p, fs::Permissions::from_mode(0o755));
        Ok(())
    }

    /// Create `moat.slice` and one directory per profile. Must run before the nftables ruleset loads.
    pub fn ensure_profiles(&self, profiles: &[String]) -> io::Result<()> {
        Self::ensure_dir(&self.root())?;
        for p in profiles {
            Self::ensure_dir(&self.root().join(format!("p-{}", sanitize(p))))?;
        }
        Ok(())
    }

    pub fn create_session(&self, profile: &str, session_id: &str) -> io::Result<SessionCgroup> {
        if !valid_session_id(session_id) {
            return Err(io::Error::new(io::ErrorKind::InvalidInput, "invalid session id"));
        }
        let prof = self.root().join(format!("p-{}", sanitize(profile)));
        if !prof.exists() {
            return Err(io::Error::new(io::ErrorKind::NotFound, format!("profile cgroup for {profile} missing; policy not applied?")));
        }
        let path = prof.join(format!("s-{session_id}"));
        fs::create_dir(&path)?;
        let rel = path.strip_prefix(&self.mount).map(|p| p.to_string_lossy().to_string()).unwrap_or_default();
        Ok(SessionCgroup { path, rel })
    }

    /// Process ids currently in a session cgroup.
    pub fn procs(&self, s: &SessionCgroup) -> Vec<u32> {
        fs::read_to_string(s.path.join("cgroup.procs")).unwrap_or_default().lines().filter_map(|l| l.trim().parse().ok()).collect()
    }

    /// Every session directory under `moat.slice/p-*/s-*`: (profile dir name without `p-`, session id, cgroup).
    pub fn list_sessions(&self) -> Vec<(String, String, SessionCgroup)> {
        let mut out = Vec::new();
        for p in fs::read_dir(self.root()).into_iter().flatten().flatten() {
            let pname = p.file_name().to_string_lossy().to_string();
            let Some(profile) = pname.strip_prefix("p-") else { continue };
            if !p.path().is_dir() {
                continue;
            }
            for s in fs::read_dir(p.path()).into_iter().flatten().flatten() {
                let sname = s.file_name().to_string_lossy().to_string();
                let Some(id) = sname.strip_prefix("s-") else { continue };
                if !s.path().is_dir() {
                    continue;
                }
                let rel = format!("{}/{pname}/{sname}", self.root_name);
                out.push((profile.to_string(), id.to_string(), SessionCgroup { path: s.path(), rel }));
            }
        }
        out.sort_by(|a, b| a.1.cmp(&b.1));
        out
    }

    /// Kill every process in the session (cgroup.kill, kernel >= 5.14), then remove the directory.
    pub fn close_session(&self, s: &SessionCgroup) -> io::Result<()> {
        let kill = s.path.join("cgroup.kill");
        if kill.exists() {
            let _ = fs::write(&kill, "1");
        } else {
            for pid in self.procs(s) {
                let _ = nix::sys::signal::kill(nix::unistd::Pid::from_raw(pid as i32), nix::sys::signal::Signal::SIGKILL);
            }
        }
        for _ in 0..50 {
            if self.procs(s).is_empty() {
                break;
            }
            std::thread::sleep(std::time::Duration::from_millis(20));
        }
        fs::remove_dir(&s.path)
    }

    /// Check the escape-prevention preconditions for running a session as `uid`. Returns problems found.
    pub fn audit_escape_paths(&self, uid: u32) -> Vec<String> {
        let mut problems = Vec::new();
        if uid == 0 {
            problems.push("protected sessions cannot run as root: root can move itself out of any cgroup".into());
        }
        for p in [self.mount.clone(), self.root()] {
            for f in [p.clone(), p.join("cgroup.procs")] {
                match fs::metadata(&f) {
                    Ok(m) => {
                        if m.uid() == uid && uid != 0 {
                            problems.push(format!("{} is owned by the session user", f.display()));
                        }
                        if m.mode() & 0o002 != 0 {
                            problems.push(format!("{} is world-writable", f.display()));
                        }
                    }
                    Err(e) => problems.push(format!("{}: {e}", f.display())),
                }
            }
        }
        problems
    }
}

/// Which cgroup (v2 path, relative, no leading slash) a process is in, from /proc/<pid>/cgroup.
pub fn cgroup_of(pid: u32) -> Option<String> {
    let s = fs::read_to_string(format!("/proc/{pid}/cgroup")).ok()?;
    s.lines().find_map(|l| l.strip_prefix("0::")).map(|p| p.trim_start_matches('/').to_string())
}

/// Process start time in clock ticks since boot (field 22 of /proc/<pid>/stat): the start generation that turns a
/// reusable PID into a process instance.
pub fn start_generation(pid: u32) -> Option<u64> {
    let s = fs::read_to_string(format!("/proc/{pid}/stat")).ok()?;
    // comm may contain spaces/parens; fields resume after the last ')'.
    let rest = &s[s.rfind(')')? + 2..];
    rest.split_whitespace().nth(19)?.parse().ok()
}

pub fn boot_id() -> String {
    fs::read_to_string("/proc/sys/kernel/random/boot_id").map(|s| s.trim().to_string()).unwrap_or_else(|_| "unknown-boot".into())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn layout_on_a_fake_mount() {
        let d = tempfile::tempdir().unwrap();
        let cg = Cgroups { mount: d.path().into(), root_name: "moat.slice".into() };
        cg.ensure_profiles(&["coding-session".into(), "local-inference".into()]).unwrap();
        cg.ensure_profiles(&["coding-session".into()]).unwrap(); // idempotent
        let s = cg.create_session("coding-session", "abc-1").unwrap();
        assert_eq!(s.rel, "moat.slice/p-coding-session/s-abc-1");
        assert!(cg.create_session("coding-session", "abc-1").is_err(), "duplicate session id");
        assert!(cg.create_session("nope", "x").is_err(), "profile not applied");
        assert!(cg.create_session("coding-session", "../escape").is_err());
    }

    #[test]
    fn root_sessions_are_refused() {
        let d = tempfile::tempdir().unwrap();
        let cg = Cgroups { mount: d.path().into(), root_name: "moat.slice".into() };
        cg.ensure_profiles(&[]).unwrap();
        assert!(cg.audit_escape_paths(0).iter().any(|p| p.contains("root")));
    }

    #[test]
    fn proc_identity_helpers() {
        let me = std::process::id();
        assert!(start_generation(me).unwrap() > 0);
        assert!(cgroup_of(me).is_some());
        assert!(!boot_id().is_empty());
    }
}
