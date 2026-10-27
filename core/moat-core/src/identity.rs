//! Process-instance identity and an OS-derived process graph.
//!
//! The fundamental identity is a process instance tied to device, boot and start generation, never a PID alone
//! (roadmap §7). The graph keeps ancestry after a parent exits or a child is reparented, so a short-lived shell
//! cannot erase who started a `curl`.

use std::collections::{BTreeMap, HashMap};
use std::fmt;

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

/// A process instance. `start_generation` is the OS's per-process start discriminator: the start time in clock
/// ticks on Linux (`/proc/<pid>/stat` field 22) or the audit token pid version on macOS.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
#[serde(deny_unknown_fields)]
pub struct ProcessInstanceId {
    pub device_id: String,
    pub boot_id: String,
    pub pid: u32,
    pub start_generation: u64,
}

impl fmt::Display for ProcessInstanceId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}/{}/{}@{}", self.device_id, self.boot_id, self.pid, self.start_generation)
    }
}

/// Application identity. Family, actual executable and responsible application are separate facts.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq, Default)]
#[serde(deny_unknown_fields)]
pub struct AppIdentity {
    /// Recognized family (e.g. `claude-code`, `ollama`, `curl`). A hint until bound by signing or a launcher.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub family: Option<String>,
    /// Human display name.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub display_name: Option<String>,
    /// Absolute executable path as reported by the OS.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub executable: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub bundle_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub team_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub signing_id: Option<String>,
    /// Hex digest of the executable (cdhash on macOS, sha256 on Linux) when available.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub digest: Option<String>,
}

impl AppIdentity {
    pub fn display(&self) -> String {
        if let Some(d) = &self.display_name {
            return d.clone();
        }
        if let Some(f) = &self.family {
            return f.clone();
        }
        if let Some(e) = &self.executable {
            return e.rsplit('/').next().unwrap_or(e).to_string();
        }
        self.bundle_id.clone().unwrap_or_else(|| "unknown app".into())
    }

    pub fn executable_basename(&self) -> Option<&str> {
        self.executable.as_deref().map(|e| e.rsplit('/').next().unwrap_or(e))
    }

    /// Signed identity is the strongest form; filenames are hints.
    pub fn is_signed(&self) -> bool {
        self.team_id.is_some() && self.signing_id.is_some()
    }
}

/// What a protected session's boundary actually is. A label alone is an *instrumented* session, not containment.
#[derive(Serialize, Deserialize, Clone, Copy, Debug, PartialEq, Eq, Hash)]
#[serde(rename_all = "snake_case")]
pub enum Boundary {
    /// Linux cgroup v2 path established before exec, matched by nftables.
    LinuxCgroup,
    /// A tested macOS sandbox integration (not yet available; reserved).
    MacosSandbox,
    /// An external runtime (Anthropic Sandbox Runtime, nono, OpenShell) with its own enforcement.
    ExternalRuntime,
    /// Isolated VM.
    Vm,
    /// Session label only: attribution, no containment claim.
    InstrumentedOnly,
}

impl Boundary {
    pub fn is_containment(&self) -> bool {
        !matches!(self, Boundary::InstrumentedOnly)
    }
    pub fn label(&self) -> &'static str {
        match self {
            Boundary::LinuxCgroup => "Linux cgroup v2 + nftables",
            Boundary::MacosSandbox => "macOS sandbox",
            Boundary::ExternalRuntime => "external sandbox runtime",
            Boundary::Vm => "isolated VM",
            Boundary::InstrumentedOnly => "instrumented only (no containment)",
        }
    }
}

/// Session context attached to a flow.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct SessionRef {
    pub id: String,
    /// Session profile, e.g. `coding-session`.
    pub profile: String,
    pub boundary: Boundary,
    /// True only when membership comes from an authenticated launcher and OS evidence (e.g. cgroup path), never
    /// from an agent-reported run id or an environment variable.
    pub verified: bool,
}

/// One node in the process graph.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
pub struct ProcessNode {
    pub id: ProcessInstanceId,
    pub parent: Option<ProcessInstanceId>,
    pub app: AppIdentity,
    pub user: Option<String>,
    pub started_at: Option<DateTime<Utc>>,
    pub exited_at: Option<DateTime<Utc>>,
    /// Session this process belongs to, inherited from its parent at fork.
    pub session: Option<String>,
    /// True when an event was missed somewhere in this node's lifecycle chain.
    pub lineage_gap: bool,
}

/// A lifecycle event from an OS sensor (Endpoint Security on macOS, /proc or eBPF on Linux).
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum LifecycleEvent {
    Fork {
        parent: ProcessInstanceId,
        child: ProcessInstanceId,
        at: DateTime<Utc>,
    },
    Exec {
        process: ProcessInstanceId,
        app: AppIdentity,
        user: Option<String>,
        at: DateTime<Utc>,
    },
    Exit {
        process: ProcessInstanceId,
        at: DateTime<Utc>,
    },
    /// The sensor knows it lost events (buffer overflow, restart). Everything alive becomes uncertain.
    Gap {
        device_id: String,
        at: DateTime<Utc>,
    },
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
pub struct Ancestry {
    /// From the process itself up to the oldest known ancestor.
    pub chain: Vec<ProcessNode>,
    /// False when an unknown parent or a lifecycle gap interrupts the chain.
    pub complete: bool,
}

impl Ancestry {
    /// Display names oldest-first, e.g. `["Claude Code", "zsh", "curl"]`.
    pub fn names_oldest_first(&self) -> Vec<String> {
        self.chain.iter().rev().map(|n| n.app.display()).collect()
    }
}

/// Process graph with bounded retention of exited processes.
#[derive(Default, Debug)]
pub struct ProcessGraph {
    nodes: HashMap<ProcessInstanceId, ProcessNode>,
    /// (device, boot, pid) -> live instance. PID lookups only ever return a *live* instance.
    live_by_pid: HashMap<(String, String, u32), ProcessInstanceId>,
    sessions: BTreeMap<String, ProcessInstanceId>,
    max_exited: usize,
    exited_order: std::collections::VecDeque<ProcessInstanceId>,
}

impl ProcessGraph {
    pub fn new(max_exited: usize) -> Self {
        ProcessGraph { max_exited, ..Default::default() }
    }

    fn ensure(&mut self, id: &ProcessInstanceId) -> &mut ProcessNode {
        self.nodes.entry(id.clone()).or_insert_with(|| ProcessNode {
            id: id.clone(),
            parent: None,
            app: AppIdentity::default(),
            user: None,
            started_at: None,
            exited_at: None,
            session: None,
            lineage_gap: false,
        })
    }

    /// Bind a session to a root process. Only an authenticated launcher should call this, and only for a process
    /// it placed in its boundary *before* exec.
    pub fn bind_session(&mut self, session_id: &str, root: &ProcessInstanceId) {
        self.sessions.insert(session_id.to_string(), root.clone());
        self.ensure(root).session = Some(session_id.to_string());
    }

    pub fn apply(&mut self, ev: &LifecycleEvent) {
        match ev {
            LifecycleEvent::Fork { parent, child, at } => {
                let (session, gap, app, user) = {
                    let p = self.ensure(parent);
                    (p.session.clone(), p.lineage_gap, p.app.clone(), p.user.clone())
                };
                let key = (child.device_id.clone(), child.boot_id.clone(), child.pid);
                // A new instance with a reused PID is a different process: the old one must already have exited.
                if let Some(old) = self.live_by_pid.insert(key, child.clone()) {
                    if old != *child {
                        if let Some(n) = self.nodes.get_mut(&old) {
                            if n.exited_at.is_none() {
                                n.exited_at = Some(*at);
                                n.lineage_gap = true;
                            }
                        }
                    }
                }
                let c = self.ensure(child);
                c.parent = Some(parent.clone());
                c.session = session;
                c.lineage_gap = gap;
                c.app = app; // forked child runs the parent's image until exec
                c.user = user;
                c.started_at = Some(*at);
            }
            LifecycleEvent::Exec { process, app, user, at } => {
                let key = (process.device_id.clone(), process.boot_id.clone(), process.pid);
                self.live_by_pid.insert(key, process.clone());
                let n = self.ensure(process);
                n.app = app.clone();
                if user.is_some() {
                    n.user = user.clone();
                }
                if n.started_at.is_none() {
                    n.started_at = Some(*at);
                }
            }
            LifecycleEvent::Exit { process, at } => {
                let key = (process.device_id.clone(), process.boot_id.clone(), process.pid);
                if self.live_by_pid.get(&key) == Some(process) {
                    self.live_by_pid.remove(&key);
                }
                if let Some(n) = self.nodes.get_mut(process) {
                    n.exited_at = Some(*at);
                    self.exited_order.push_back(process.clone());
                }
                self.prune();
            }
            LifecycleEvent::Gap { device_id, .. } => {
                for n in self.nodes.values_mut() {
                    if &n.id.device_id == device_id && n.exited_at.is_none() {
                        n.lineage_gap = true;
                    }
                }
            }
        }
    }

    fn prune(&mut self) {
        while self.exited_order.len() > self.max_exited {
            if let Some(old) = self.exited_order.pop_front() {
                // Keep a node that still has a live descendant referencing it, so ancestry survives.
                let referenced = self.nodes.values().any(|n| n.exited_at.is_none() && n.parent.as_ref() == Some(&old));
                if referenced {
                    self.exited_order.push_back(old);
                    break;
                }
                self.nodes.remove(&old);
            }
        }
    }

    pub fn get(&self, id: &ProcessInstanceId) -> Option<&ProcessNode> {
        self.nodes.get(id)
    }

    /// Resolve a PID to its *current* live instance. Never returns an exited instance with the same PID.
    pub fn live_instance(&self, device: &str, boot: &str, pid: u32) -> Option<&ProcessInstanceId> {
        self.live_by_pid.get(&(device.to_string(), boot.to_string(), pid))
    }

    pub fn ancestry(&self, id: &ProcessInstanceId) -> Ancestry {
        let mut chain = Vec::new();
        let mut complete = true;
        let mut cur = self.nodes.get(id);
        let mut guard = 0;
        while let Some(n) = cur {
            chain.push(n.clone());
            if n.lineage_gap {
                complete = false;
            }
            guard += 1;
            if guard > 4096 {
                complete = false;
                break;
            }
            match &n.parent {
                Some(p) => match self.nodes.get(p) {
                    Some(pn) => cur = Some(pn),
                    None => {
                        complete = false;
                        cur = None;
                    }
                },
                None => {
                    // A root with no recorded parent is only "complete" if it is a session root or pid 1.
                    let is_session_root = self.sessions.values().any(|r| r == &n.id);
                    if !(is_session_root || n.id.pid == 1) {
                        complete = false;
                    }
                    cur = None;
                }
            }
        }
        if chain.is_empty() {
            complete = false;
        }
        Ancestry { chain, complete }
    }

    /// Session membership for a process, with whether lineage was intact.
    pub fn session_of(&self, id: &ProcessInstanceId) -> Option<(String, bool)> {
        let n = self.nodes.get(id)?;
        let s = n.session.clone()?;
        Some((s, !n.lineage_gap))
    }

    pub fn len(&self) -> usize {
        self.nodes.len()
    }

    pub fn is_empty(&self) -> bool {
        self.nodes.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn pid(p: u32, g: u64) -> ProcessInstanceId {
        ProcessInstanceId { device_id: "mbp".into(), boot_id: "b1".into(), pid: p, start_generation: g }
    }
    fn app(name: &str) -> AppIdentity {
        AppIdentity { display_name: Some(name.into()), executable: Some(format!("/usr/bin/{name}")), ..Default::default() }
    }
    fn t() -> DateTime<Utc> {
        "2026-10-26T12:00:00Z".parse().unwrap()
    }

    #[test]
    fn ancestry_survives_parent_exit() {
        let mut g = ProcessGraph::new(16);
        let root = pid(100, 1);
        g.apply(&LifecycleEvent::Exec { process: root.clone(), app: app("Claude Code"), user: Some("robert".into()), at: t() });
        g.bind_session("s1", &root);
        let sh = pid(101, 2);
        g.apply(&LifecycleEvent::Fork { parent: root.clone(), child: sh.clone(), at: t() });
        g.apply(&LifecycleEvent::Exec { process: sh.clone(), app: app("zsh"), user: None, at: t() });
        let curl = pid(102, 3);
        g.apply(&LifecycleEvent::Fork { parent: sh.clone(), child: curl.clone(), at: t() });
        g.apply(&LifecycleEvent::Exec { process: curl.clone(), app: app("curl"), user: None, at: t() });
        g.apply(&LifecycleEvent::Exit { process: sh.clone(), at: t() });
        let a = g.ancestry(&curl);
        assert_eq!(a.names_oldest_first(), vec!["Claude Code", "zsh", "curl"]);
        assert!(a.complete);
        assert_eq!(g.session_of(&curl), Some(("s1".into(), true)));
    }

    #[test]
    fn pid_reuse_is_a_different_instance() {
        let mut g = ProcessGraph::new(16);
        let a = pid(200, 10);
        g.apply(&LifecycleEvent::Exec { process: a.clone(), app: app("agent"), user: None, at: t() });
        g.bind_session("s-old", &a);
        g.apply(&LifecycleEvent::Exit { process: a.clone(), at: t() });
        let b = pid(200, 99);
        g.apply(&LifecycleEvent::Exec { process: b.clone(), app: app("other"), user: None, at: t() });
        assert_eq!(g.live_instance("mbp", "b1", 200), Some(&b));
        assert_eq!(g.session_of(&b), None, "a reused PID must not inherit the old session");
    }

    #[test]
    fn gap_marks_lineage_uncertain() {
        let mut g = ProcessGraph::new(16);
        let r = pid(1, 1);
        g.apply(&LifecycleEvent::Exec { process: r.clone(), app: app("launchd"), user: None, at: t() });
        let c = pid(5, 2);
        g.apply(&LifecycleEvent::Fork { parent: r.clone(), child: c.clone(), at: t() });
        g.apply(&LifecycleEvent::Gap { device_id: "mbp".into(), at: t() });
        assert!(!g.ancestry(&c).complete);
    }

    #[test]
    fn unknown_parent_is_incomplete() {
        let mut g = ProcessGraph::new(16);
        let c = pid(77, 2);
        g.apply(&LifecycleEvent::Exec { process: c.clone(), app: app("python3"), user: None, at: t() });
        assert!(!g.ancestry(&c).complete);
    }

    #[test]
    fn exited_nodes_are_bounded() {
        let mut g = ProcessGraph::new(4);
        for i in 0..50u32 {
            let p = pid(1000 + i, i as u64);
            g.apply(&LifecycleEvent::Exec { process: p.clone(), app: app("x"), user: None, at: t() });
            g.apply(&LifecycleEvent::Exit { process: p, at: t() });
        }
        assert!(g.len() <= 5);
    }
}
