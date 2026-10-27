//! W04: who is calling the control socket, decided from kernel facts, and what a contained caller may ask for.
//!
//! The control socket is world-connectable (any user may ask for a session that restricts *themselves*), so the
//! question that matters is whether the caller is itself inside a protected session. That is answered from the
//! kernel, never from the request:
//!
//! * the connect-time peer (`SO_PEERCRED`), and
//! * the process that actually sent the request (`SCM_CREDENTIALS`, attached by the kernel because the server sets
//!   `SO_PASSCRED`, and explicitly by `moat-launch`; the kernel refuses a forged pid from an unprivileged sender).
//!
//! Both pids are mapped to their cgroup v2 path (`/proc/<pid>/cgroup`). If either sits under the Moat slice the
//! caller is contained. A pre-opened connection handed to a workload is caught by the second check: the connection
//! was opened outside, but the request is sent from inside.
//!
//! Nested launch rule: a contained caller may only start a session with **the same profile** as its own, always
//! with full broker isolation, and may only close its own session. Anything it cannot be matched to (an unknown
//! cgroup under the slice, a vanished process, missing sender credentials) is refused.

use crate::cgroup::{cgroup_of, start_generation};

/// What the kernel says about one calling process.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Caller {
    /// Not inside the Moat slice.
    Uncontained,
    /// Inside a known protected session.
    Session { session_id: String, profile: String },
    /// Inside the Moat slice but not a session this daemon knows (or not attributable): treated as contained with
    /// no authority at all.
    UnknownContained { cgroup: String },
    /// The process could not be inspected consistently (exited, PID reused, no credentials).
    Unverifiable { why: String },
}

/// A running session as the authority check needs it: id, profile and cgroup path relative to the cgroup mount.
#[derive(Debug, Clone)]
pub struct SessionCgroupRef {
    pub id: String,
    pub profile: String,
    pub rel: String,
}

/// Classify a cgroup path (relative, no leading slash) against the Moat slice and the known sessions.
pub fn classify(cgroup_rel: &str, root_name: &str, sessions: &[SessionCgroupRef]) -> Caller {
    let p = cgroup_rel.trim_start_matches('/');
    let in_slice = p == root_name || p.starts_with(&format!("{root_name}/"));
    if !in_slice {
        return Caller::Uncontained;
    }
    for s in sessions {
        if p == s.rel || p.starts_with(&format!("{}/", s.rel)) {
            return Caller::Session { session_id: s.id.clone(), profile: s.profile.clone() };
        }
    }
    Caller::UnknownContained { cgroup: p.to_string() }
}

/// Inspect a live pid: cgroup read between two identical start-generation reads, so a PID that exited and was
/// reused while we looked is not misattributed.
pub fn inspect(pid: i32, root_name: &str, sessions: &[SessionCgroupRef]) -> Caller {
    if pid <= 0 {
        return Caller::Unverifiable { why: "no process id".into() };
    }
    let pid = pid as u32;
    let Some(g1) = start_generation(pid) else { return Caller::Unverifiable { why: format!("process {pid} is gone") } };
    let Some(cg) = cgroup_of(pid) else { return Caller::Unverifiable { why: format!("cannot read the cgroup of {pid}") } };
    match start_generation(pid) {
        Some(g2) if g2 == g1 => classify(&cg, root_name, sessions),
        _ => Caller::Unverifiable { why: format!("process {pid} changed while being inspected") },
    }
}

/// The combined view of the connect-time peer and the request sender.
pub fn combine(connect_peer: Caller, sender: Option<Caller>) -> Caller {
    let Some(sender) = sender else {
        return Caller::Unverifiable { why: "the request carried no sender credentials".into() };
    };
    for c in [&connect_peer, &sender] {
        if matches!(c, Caller::Unverifiable { .. } | Caller::UnknownContained { .. }) {
            return c.clone();
        }
    }
    match (&connect_peer, &sender) {
        (Caller::Uncontained, Caller::Uncontained) => Caller::Uncontained,
        (Caller::Session { .. }, Caller::Uncontained) => connect_peer,
        (Caller::Uncontained, Caller::Session { .. }) => sender,
        (Caller::Session { session_id: a, .. }, Caller::Session { session_id: b, .. }) if a == b => sender,
        _ => Caller::UnknownContained { cgroup: "connection opened in one session, request sent from another".into() },
    }
}

/// What the launch path must do for this caller.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LaunchDecision {
    /// Force full broker isolation regardless of what the request asked.
    pub force_isolation: bool,
    /// Set for nested launches: the parent session.
    pub parent_session: Option<String>,
}

/// May `caller` start a session with `profile`? Never lets a contained caller obtain a less restricted session.
pub fn decide_launch(caller: &Caller, profile: &str) -> Result<LaunchDecision, String> {
    match caller {
        Caller::Uncontained => Ok(LaunchDecision { force_isolation: false, parent_session: None }),
        Caller::Session { session_id, profile: own } if own == profile => {
            Ok(LaunchDecision { force_isolation: true, parent_session: Some(session_id.clone()) })
        }
        Caller::Session { session_id, profile: own } => Err(format!(
            "a process inside protected session {session_id} ({own}) cannot start a session with another profile ({profile}); \
             nested launches keep the caller's profile"
        )),
        Caller::UnknownContained { cgroup } => Err(format!("the caller is contained ({cgroup}) and has no launch authority")),
        Caller::Unverifiable { why } => Err(format!("cannot verify the caller: {why}")),
    }
}

/// May `caller` close session `target`?
pub fn decide_close(caller: &Caller, target: &str) -> Result<(), String> {
    match caller {
        Caller::Uncontained => Ok(()),
        Caller::Session { session_id, .. } if session_id == target => Ok(()),
        Caller::Session { session_id, .. } => Err(format!("a process inside session {session_id} may only close its own session")),
        Caller::UnknownContained { cgroup } => Err(format!("the caller is contained ({cgroup}) and may not close sessions")),
        Caller::Unverifiable { why } => Err(format!("cannot verify the caller: {why}")),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sessions() -> Vec<SessionCgroupRef> {
        vec![
            SessionCgroupRef { id: "s1".into(), profile: "coding-session".into(), rel: "moat.slice/p-coding-session/s-s1".into() },
            SessionCgroupRef { id: "s2".into(), profile: "lab-allow".into(), rel: "moat.slice/p-lab-allow/s-s2".into() },
        ]
    }

    #[test]
    fn classification_uses_the_cgroup_path() {
        let s = sessions();
        assert_eq!(classify("user.slice/user-1000.slice/session-2.scope", "moat.slice", &s), Caller::Uncontained);
        assert_eq!(classify("moat.slicex/whatever", "moat.slice", &s), Caller::Uncontained, "prefix must be a path component");
        assert!(
            matches!(classify("/moat.slice/p-coding-session/s-s1", "moat.slice", &s), Caller::Session { ref session_id, .. } if session_id == "s1")
        );
        assert!(
            matches!(classify("moat.slice/p-coding-session/s-s1/child", "moat.slice", &s), Caller::Session { .. }),
            "descendant cgroups"
        );
        assert!(matches!(classify("moat.slice/p-coding-session/s-gone", "moat.slice", &s), Caller::UnknownContained { .. }));
        assert!(matches!(classify("moat.slice", "moat.slice", &s), Caller::UnknownContained { .. }));
    }

    #[test]
    fn contained_callers_cannot_broaden() {
        let inside = Caller::Session { session_id: "s1".into(), profile: "coding-session".into() };
        assert!(decide_launch(&inside, "lab-allow").is_err(), "different profile refused");
        let d = decide_launch(&inside, "coding-session").unwrap();
        assert!(d.force_isolation, "nested sessions always hide brokers");
        assert_eq!(d.parent_session.as_deref(), Some("s1"));
        assert!(decide_launch(&Caller::UnknownContained { cgroup: "x".into() }, "coding-session").is_err());
        assert!(decide_launch(&Caller::Unverifiable { why: "x".into() }, "coding-session").is_err());
        let d = decide_launch(&Caller::Uncontained, "lab-allow").unwrap();
        assert!(!d.force_isolation && d.parent_session.is_none());
    }

    #[test]
    fn pre_opened_connections_are_judged_by_the_sender() {
        let inside = Caller::Session { session_id: "s1".into(), profile: "coding-session".into() };
        // connection opened outside, request written from inside: contained
        assert_eq!(combine(Caller::Uncontained, Some(inside.clone())), inside);
        // connection opened inside, handed out: still contained
        assert_eq!(combine(inside.clone(), Some(Caller::Uncontained)), inside);
        // no sender credentials: unverifiable
        assert!(matches!(combine(Caller::Uncontained, None), Caller::Unverifiable { .. }));
        // two different sessions: no authority
        let other = Caller::Session { session_id: "s2".into(), profile: "lab-allow".into() };
        assert!(matches!(combine(inside, Some(other)), Caller::UnknownContained { .. }));
    }

    #[test]
    fn close_is_limited_to_the_callers_own_session() {
        let inside = Caller::Session { session_id: "s1".into(), profile: "coding-session".into() };
        assert!(decide_close(&inside, "s1").is_ok());
        assert!(decide_close(&inside, "s2").is_err());
        assert!(decide_close(&Caller::Uncontained, "s2").is_ok());
    }

    #[test]
    fn this_test_process_is_inspectable() {
        let me = std::process::id() as i32;
        match inspect(me, "moat.slice", &sessions()) {
            Caller::Uncontained | Caller::UnknownContained { .. } | Caller::Session { .. } => {}
            Caller::Unverifiable { why } => panic!("{why}"),
        }
        assert!(matches!(inspect(-1, "moat.slice", &sessions()), Caller::Unverifiable { .. }));
    }
}
