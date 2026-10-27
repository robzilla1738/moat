//! The Linux endpoint: installed policy, enforcement reconciliation, protected sessions and the event spool.
//!
//! Failure behavior (docs/failure-table.md):
//! * controller unreachable → keep the last valid local policy; the spool buffers a bounded backlog;
//! * malformed/unsupported/replayed policy → reject atomically, keep the last working revision, record why;
//! * no valid policy → protected sessions are refused with an actionable reason;
//! * event disk full → enforcement continues; the spool records a gap;
//! * local isolation never reopens on its own.

use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};

use chrono::{DateTime, Utc};
use moat_core::capability::{Capability, CapabilityAdvertisement, Platform, Support};
use moat_core::compile::Snapshot;
use moat_core::signing::{verify_snapshot, verifying_key_from_hex, SignedSnapshot, TrustStore};
use serde::{Deserialize, Serialize};

use crate::cgroup::{Cgroups, SessionCgroup};
use crate::nft::{self, CgroupLayout, NftBackend, RenderReport};
use crate::recovery::RecoveryState;
use crate::spool::{Event, Spool};

pub const CURRENT: &str = "current.signed.json";

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct SessionInfo {
    pub id: String,
    pub profile: String,
    pub uid: u32,
    pub root_pid: u32,
    pub root_start: u64,
    pub cgroup: String,
    pub started_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Status {
    pub device_id: String,
    pub revision: Option<u64>,
    pub policy_name: Option<String>,
    pub policy_stale: bool,
    pub enforcement_active: bool,
    pub enforcement_disabled_locally: bool,
    pub isolation_active: bool,
    pub coverage: String,
    pub sessions: Vec<SessionInfo>,
    pub last_rejection: Option<String>,
    pub skipped_allows: Vec<(String, String)>,
    pub spool_next_seq: u64,
}

pub struct Endpoint<B: NftBackend> {
    pub state_dir: PathBuf,
    pub device_id: String,
    pub backend: B,
    pub cgroups: Cgroups,
    pub spool: Spool,
    pub adv: CapabilityAdvertisement,
    pub trust: TrustStore,
    current: Option<(SignedSnapshot, Snapshot, RenderReport)>,
    last_applied: Option<u64>,
    enforcement_active: bool,
    recovery: RecoveryState,
    pub sessions: BTreeMap<String, (SessionInfo, SessionCgroup)>,
    last_rejection: Option<String>,
    counters: BTreeMap<String, (u64, u64)>,
    /// What is believed to be in the kernel right now: (revision, isolation table present).
    installed: Option<u64>,
    /// Re-render at this time (earliest rule expiry), even if nothing else changed.
    rerender_at: Option<DateTime<Utc>>,
    /// Session ids present when the ruleset was rendered (session-bound grants depend on them).
    rendered_sessions: Vec<String>,
    isolation_installed: Option<Vec<ipnet::IpNet>>,
    uid_of: fn(&str) -> Option<u32>,
}

pub fn lookup_uid(name: &str) -> Option<u32> {
    nix::unistd::User::from_name(name).ok().flatten().map(|u| u.uid.as_raw())
}

pub fn load_trust(dir: &Path) -> TrustStore {
    let mut t = TrustStore::new();
    for e in fs::read_dir(dir).into_iter().flatten().flatten() {
        if e.path().extension().is_some_and(|x| x == "pub") {
            if let Ok(vk) = fs::read_to_string(e.path()).map_err(|e| e.to_string()).and_then(|s| verifying_key_from_hex(&s)) {
                t.trust(vk);
            }
        }
    }
    t
}

impl<B: NftBackend> Endpoint<B> {
    pub fn new(state_dir: PathBuf, device_id: String, backend: B, cgroups: Cgroups, spool: Spool, adv: CapabilityAdvertisement) -> Self {
        let trust = load_trust(&state_dir.join("trusted"));
        Endpoint {
            recovery: RecoveryState::load(&state_dir),
            state_dir,
            device_id,
            backend,
            cgroups,
            spool,
            adv,
            trust,
            current: None,
            last_applied: None,
            enforcement_active: false,
            sessions: BTreeMap::new(),
            last_rejection: None,
            counters: BTreeMap::new(),
            installed: None,
            rerender_at: None,
            rendered_sessions: Vec::new(),
            isolation_installed: None,
            uid_of: lookup_uid,
        }
    }

    pub fn with_uid_resolver(mut self, f: fn(&str) -> Option<u32>) -> Self {
        self.uid_of = f;
        self
    }

    fn layout(&self) -> CgroupLayout {
        CgroupLayout {
            root_name: self.cgroups.root_name.clone(),
            mount: self.cgroups.mount.clone(),
            sessions_enabled: self.adv.support(Capability::SessionEnforcement) != Support::Unsupported,
        }
    }

    /// Startup: advertise, reload the last applied snapshot (signature checked; expiry tolerated and reported as
    /// stale, because dropping to no policy would be weaker), then reconcile with the recovery state.
    pub fn startup(&mut self) {
        let adv = serde_json::to_value(&self.adv).unwrap();
        self.spool.append(Event::CapabilityAdvertised { advertisement: adv });
        if let Ok(text) = fs::read_to_string(self.state_dir.join(CURRENT)) {
            match serde_json::from_str::<SignedSnapshot>(&text) {
                Ok(signed) => {
                    // Verify signature/platform/policy at the snapshot's own issue time; staleness is reported.
                    let probe_time = Self::decode_issued_at(&signed).unwrap_or_else(Utc::now);
                    match verify_snapshot(&signed, &self.trust, Platform::Linux, None, probe_time) {
                        Ok(snap) => match nft::render(&snap, &self.device_id, &self.layout(), &self.uid_of) {
                            Ok((_, rep)) => {
                                self.last_applied = Some(snap.revision);
                                self.current = Some((signed, snap, rep));
                            }
                            Err(e) => self.last_rejection = Some(format!("stored snapshot no longer renders: {e}")),
                        },
                        Err(e) => self.last_rejection = Some(format!("stored snapshot rejected at startup: {e}")),
                    }
                }
                Err(e) => self.last_rejection = Some(format!("stored snapshot unreadable: {e}")),
            }
        }
        self.reconcile();
    }

    fn decode_issued_at(s: &SignedSnapshot) -> Option<DateTime<Utc>> {
        use base64::Engine;
        let bytes = base64::engine::general_purpose::STANDARD.decode(&s.payload).ok()?;
        let v: serde_json::Value = serde_json::from_slice(&bytes).ok()?;
        v["issued_at"].as_str()?.parse().ok()
    }

    pub fn policy_stale(&self) -> bool {
        self.current.as_ref().and_then(|(_, s, _)| s.not_after).map(|na| na <= Utc::now()).unwrap_or(false)
    }

    /// Bring the kernel in line with (policy, recovery state). Idempotent.
    pub fn reconcile(&mut self) {
        let rec = RecoveryState::load(&self.state_dir);
        if rec.enforcement_disabled != self.recovery.enforcement_disabled {
            let uid = rec.changed_by_uid.unwrap_or(0);
            self.spool.append(if rec.enforcement_disabled {
                Event::EnforcementDisabledLocally { by_uid: uid, reason: rec.reason.clone().unwrap_or_default() }
            } else {
                Event::EnforcementResumed { by_uid: uid }
            });
        }
        if rec.isolation.active != self.recovery.isolation.active {
            self.spool.append(Event::LocalIsolation { active: rec.isolation.active, by_uid: rec.changed_by_uid.unwrap_or(0) });
        }
        self.recovery = rec;
        // Isolation first: it is independent of policy and of the disable switch.
        if self.recovery.isolation.active {
            let want = self.recovery.isolation.keep.clone();
            let present = self.backend.list_json(nft::LOCAL_EMERGENCY_TABLE).is_ok();
            if self.isolation_installed.as_ref() != Some(&want) || !present {
                if self.isolation_installed.is_some() && !present {
                    self.spool.append(Event::CoverageChanged {
                        level: "emergency-isolation".into(),
                        detail: "isolation table was removed outside Moat; restored".into(),
                    });
                }
                if self.backend.apply(&nft::render_local_emergency(&want)).is_ok() {
                    self.isolation_installed = Some(want);
                }
            }
        } else if self.isolation_installed.is_some() || self.backend.list_json(nft::LOCAL_EMERGENCY_TABLE).is_ok() {
            let _ = self.backend.delete_table(nft::LOCAL_EMERGENCY_TABLE);
            self.isolation_installed = None;
        }
        if self.recovery.enforcement_disabled {
            if self.installed.is_some() || self.backend.list_json(nft::TABLE).is_ok() {
                let _ = self.backend.delete_table(nft::TABLE);
                self.installed = None;
            }
            self.set_enforcement(false, "enforcement disabled locally");
            return;
        }
        let Some((_, snap, _)) = &self.current else {
            self.set_enforcement(false, "no valid policy installed");
            return;
        };
        let snap = snap.clone();
        let sessions_now: Vec<String> = self.sessions.keys().cloned().collect();
        let due = self.rerender_at.map(|t| t <= Utc::now()).unwrap_or(false);
        if self.installed == Some(snap.revision) && !due && sessions_now == self.rendered_sessions {
            if self.backend.list_json(nft::TABLE).is_ok() {
                return;
            }
            self.spool.append(Event::CoverageChanged {
                level: "degraded".into(),
                detail: "Moat table was removed outside Moat; restoring".into(),
            });
        }
        match self.install(&snap) {
            Ok(_) => self.set_enforcement(true, "policy enforced"),
            Err(e) => {
                self.installed = None;
                self.last_rejection = Some(e.clone());
                self.set_enforcement(false, &e);
            }
        }
    }

    fn set_enforcement(&mut self, active: bool, detail: &str) {
        if active != self.enforcement_active {
            self.enforcement_active = active;
            self.spool.append(Event::CoverageChanged { level: self.coverage_label(), detail: detail.into() });
        }
    }

    fn install(&mut self, snap: &Snapshot) -> Result<RenderReport, String> {
        let (rules, rep) = nft::render(snap, &self.device_id, &self.layout(), &self.uid_of).map_err(|e| e.0)?;
        if self.adv.support(Capability::SessionEnforcement) != Support::Unsupported {
            self.cgroups.ensure_profiles(&rep.session_profiles).map_err(|e| format!("cannot create session cgroups: {e}"))?;
        }
        self.backend.check(&rules).map_err(|e| format!("nft rejected the ruleset: {e}"))?;
        self.backend.apply(&rules).map_err(|e| format!("nft apply failed: {e}"))?;
        self.installed = Some(snap.revision);
        self.rerender_at = nft::next_expiry(snap, Utc::now());
        self.rendered_sessions = self.sessions.keys().cloned().collect();
        Ok(rep)
    }

    /// Offer a new signed snapshot. Atomic: on any failure the previous revision stays in force.
    pub fn offer(&mut self, signed: SignedSnapshot) -> Result<u64, String> {
        let res = (|| {
            let snap = verify_snapshot(&signed, &self.trust, Platform::Linux, self.last_applied, Utc::now()).map_err(|e| e.to_string())?;
            let (_, rep) = nft::render(&snap, &self.device_id, &self.layout(), &self.uid_of).map_err(|e| e.0)?;
            if !self.recovery.enforcement_disabled {
                self.install(&snap)?;
            }
            Ok::<_, String>((snap, rep))
        })();
        match res {
            Ok((snap, rep)) => {
                let rev = snap.revision;
                let tmp = self.state_dir.join(format!("{CURRENT}.tmp"));
                fs::write(&tmp, serde_json::to_vec_pretty(&signed).unwrap()).map_err(|e| e.to_string())?;
                fs::rename(&tmp, self.state_dir.join(CURRENT)).map_err(|e| e.to_string())?;
                self.spool.append(Event::PolicyApplied {
                    revision: rev,
                    rollback_of: snap.rollback_of,
                    policy_digest: snap.policy_digest.clone(),
                    skipped_allows: rep.skipped_allows.iter().map(|(id, _)| id.clone()).collect(),
                });
                self.last_applied = Some(rev);
                self.current = Some((signed, snap, rep));
                if !self.recovery.enforcement_disabled {
                    self.set_enforcement(true, "policy enforced");
                }
                Ok(rev)
            }
            Err(e) => {
                self.last_rejection = Some(e.clone());
                self.spool.append(Event::PolicyRejected { reason: e.clone(), kept_revision: self.last_applied });
                Err(e)
            }
        }
    }

    /// Process every file in `<state>/inbox`, oldest name first.
    pub fn drain_inbox(&mut self) -> Vec<Result<u64, String>> {
        let inbox = self.state_dir.join("inbox");
        let mut files: Vec<PathBuf> = fs::read_dir(&inbox)
            .into_iter()
            .flatten()
            .flatten()
            .map(|e| e.path())
            .filter(|p| p.extension().is_some_and(|x| x == "json"))
            .collect();
        files.sort();
        let mut out = Vec::new();
        for f in files {
            let r = fs::read_to_string(&f)
                .map_err(|e| e.to_string())
                .and_then(|t| serde_json::from_str::<SignedSnapshot>(&t).map_err(|e| format!("malformed snapshot: {e}")));
            out.push(match r {
                Ok(s) => self.offer(s),
                Err(e) => {
                    self.spool.append(Event::PolicyRejected { reason: e.clone(), kept_revision: self.last_applied });
                    Err(e)
                }
            });
            let _ = fs::remove_file(&f);
        }
        out
    }

    /// Why a protected session for `profile` cannot start right now, if it cannot.
    pub fn launch_refusal(&self, profile: &str, uid: u32) -> Option<String> {
        if self.adv.support(Capability::SessionEnforcement) == Support::Unsupported {
            return Some(format!(
                "this device cannot enforce protected sessions: {}",
                self.adv.capabilities.get(&Capability::SessionEnforcement).and_then(|s| s.note.clone()).unwrap_or_default()
            ));
        }
        if self.recovery.enforcement_disabled {
            return Some("enforcement is disabled locally (moatd recover resume to re-enable)".into());
        }
        let Some((_, snap, rep)) = &self.current else {
            return Some("no valid policy is installed on this device; protected sessions are refused until one is".into());
        };
        if !self.enforcement_active {
            return Some(format!(
                "policy revision {} is not currently enforced: {}",
                snap.revision,
                self.last_rejection.clone().unwrap_or_default()
            ));
        }
        if snap.report.unavailable_session_profiles.iter().any(|p| p == profile) {
            return Some(format!("profile {profile} is not available on this platform"));
        }
        if !rep.session_profiles.iter().any(|p| p == profile) {
            return Some(format!("profile {profile} is not defined in policy revision {}", snap.revision));
        }
        let problems = self.cgroups.audit_escape_paths(uid);
        if !problems.is_empty() {
            return Some(format!("session boundary preconditions failed: {}", problems.join("; ")));
        }
        None
    }

    pub fn new_session_id() -> String {
        let mut b = [0u8; 6];
        if let Ok(mut f) = fs::File::open("/dev/urandom") {
            use std::io::Read;
            let _ = f.read_exact(&mut b);
        }
        format!("{}-{}", Utc::now().format("%Y%m%d%H%M%S"), hex::encode(b))
    }

    pub fn register_session(&mut self, info: SessionInfo, cg: SessionCgroup) {
        self.spool.append(Event::SessionStarted {
            session_id: info.id.clone(),
            profile: info.profile.clone(),
            cgroup: info.cgroup.clone(),
            uid: info.uid,
            root_pid: info.root_pid,
            root_start: info.root_start,
            boundary: "linux_cgroup".into(),
        });
        self.sessions.insert(info.id.clone(), (info, cg));
    }

    pub fn end_session(&mut self, id: &str, exit_code: Option<i32>, signal: Option<i32>) {
        if let Some((_, cg)) = self.sessions.remove(id) {
            let _ = self.cgroups.close_session(&cg);
            self.spool.append(Event::SessionEnded { session_id: id.into(), exit_code, signal });
        }
    }

    pub fn refuse(&mut self, profile: &str, uid: u32, reason: &str) {
        self.spool.append(Event::SessionLaunchRefused { profile: profile.into(), uid, reason: reason.into() });
    }

    /// Read nft counters and spool rule-scoped deltas.
    pub fn poll_counters(&mut self) {
        let Ok(j) = self.backend.list_json(nft::TABLE) else { return };
        let mut agg: BTreeMap<String, (u64, u64)> = BTreeMap::new();
        for c in nft::parse_counters(&j) {
            let e = agg.entry(c.comment).or_default();
            e.0 += c.packets;
            e.1 += c.bytes;
        }
        for (rule, (p, b)) in agg {
            let (pp, pb) = self.counters.get(&rule).copied().unwrap_or((0, 0));
            // Counters reset when the table is replaced; a smaller value means a new baseline.
            let (dp, db) = if p < pp { (p, b) } else { (p - pp, b.saturating_sub(pb)) };
            if dp > 0 && !rule.starts_with("observe:") {
                self.spool.append(Event::RuleCounter { rule: rule.clone(), packets: dp, bytes: db, scope: "rule".into() });
            }
            self.counters.insert(rule, (p, b));
        }
    }

    pub fn coverage_label(&self) -> String {
        if self.recovery.isolation.active {
            return "emergency-isolation".into();
        }
        if !self.enforcement_active {
            return "degraded".into();
        }
        if self.adv.support(Capability::SessionEnforcement) == Support::Unsupported {
            "monitoring".into()
        } else {
            "protected-session".into()
        }
    }

    pub fn status(&self) -> Status {
        Status {
            device_id: self.device_id.clone(),
            revision: self.current.as_ref().map(|c| c.1.revision),
            policy_name: self.current.as_ref().map(|c| c.1.policy_name.clone()),
            policy_stale: self.policy_stale(),
            enforcement_active: self.enforcement_active,
            enforcement_disabled_locally: self.recovery.enforcement_disabled,
            isolation_active: self.recovery.isolation.active,
            coverage: self.coverage_label(),
            sessions: self.sessions.values().map(|(i, _)| i.clone()).collect(),
            last_rejection: self.last_rejection.clone(),
            skipped_allows: self.current.as_ref().map(|c| c.2.skipped_allows.clone()).unwrap_or_default(),
            spool_next_seq: self.spool.next_seq(),
        }
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use crate::spool::SpoolConfig;
    use chrono::Duration;
    use moat_core::compile::{compile, CompileOptions};
    use moat_core::policy::Policy;
    use moat_core::signing::{generate_key, sign_snapshot};

    #[derive(Default)]
    pub struct FakeNft {
        pub applied: Vec<String>,
        pub deleted: Vec<String>,
        pub fail_check: bool,
        pub tables: BTreeMap<String, String>,
    }
    impl NftBackend for FakeNft {
        fn apply(&mut self, r: &str) -> Result<(), String> {
            let name = if r.contains("moat_local_emergency") { "moat_local_emergency" } else { "moat" };
            self.tables.insert(name.into(), r.into());
            self.applied.push(r.into());
            Ok(())
        }
        fn check(&mut self, _r: &str) -> Result<(), String> {
            if self.fail_check {
                Err("Error: syntax".into())
            } else {
                Ok(())
            }
        }
        fn delete_table(&mut self, t: &str) -> Result<(), String> {
            self.tables.remove(t);
            self.deleted.push(t.into());
            Ok(())
        }
        fn list_json(&mut self, t: &str) -> Result<String, String> {
            if !self.tables.contains_key(t) {
                return Err("No such file or directory".into());
            }
            Ok(r#"{"nftables":[{"rule":{"comment":"default:coding-session","expr":[{"counter":{"packets":5,"bytes":300}}]}}]}"#.into())
        }
    }

    pub struct Fixture {
        pub dir: tempfile::TempDir,
        pub key: ed25519_dalek::SigningKey,
    }

    fn uid(u: &str) -> Option<u32> {
        (u == "robert").then_some(1000)
    }

    pub fn fixture() -> (Fixture, Endpoint<FakeNft>) {
        let dir = tempfile::tempdir().unwrap();
        let key = generate_key();
        fs::create_dir_all(dir.path().join("trusted")).unwrap();
        fs::write(dir.path().join("trusted/signer.pub"), hex::encode(key.verifying_key().to_bytes())).unwrap();
        fs::create_dir_all(dir.path().join("cg/moat.slice")).unwrap();
        fs::write(dir.path().join("cg/cgroup.procs"), "").unwrap();
        fs::write(dir.path().join("cg/moat.slice/cgroup.procs"), "").unwrap();
        let ep = make(dir.path());
        (Fixture { dir, key }, ep)
    }

    fn make(dir: &Path) -> Endpoint<FakeNft> {
        let spool = Spool::open(SpoolConfig {
            dir: dir.join("spool"),
            device_id: "omarchy".into(),
            boot_id: "b".into(),
            max_bytes: 1 << 20,
            segment_bytes: 1 << 16,
        })
        .unwrap();
        Endpoint::new(
            dir.into(),
            "omarchy".into(),
            FakeNft::default(),
            Cgroups { mount: dir.join("cg"), root_name: "moat.slice".into() },
            spool,
            CapabilityAdvertisement::linux_nftables_cgroup(),
        )
        .with_uid_resolver(uid)
    }

    pub fn signed(key: &ed25519_dalek::SigningKey, rev: u64) -> SignedSnapshot {
        let p = Policy::parse(include_str!("../../../conformance/policies/home.toml")).unwrap();
        let s = compile(
            &p,
            &CapabilityAdvertisement::linux_nftables_cgroup(),
            &CompileOptions { revision: rev, rollback_of: None, issued_at: Utc::now() - Duration::seconds(5), not_after: None },
        )
        .unwrap();
        sign_snapshot(&s, key)
    }

    fn events(ep: &Endpoint<FakeNft>) -> Vec<Event> {
        ep.spool.read_after(0, 1000).into_iter().map(|r| r.event).collect()
    }

    #[test]
    fn no_policy_refuses_sessions() {
        let (_f, mut ep) = fixture();
        ep.startup();
        assert!(ep.launch_refusal("coding-session", 1000).unwrap().contains("no valid policy"));
        assert_eq!(ep.status().coverage, "degraded");
    }

    #[test]
    fn offer_applies_persists_and_survives_restart() {
        let (f, mut ep) = fixture();
        ep.startup();
        assert_eq!(ep.offer(signed(&f.key, 3)).unwrap(), 3);
        assert!(ep.backend.tables["moat"].contains("jump s_coding_session"));
        assert!(f.dir.path().join("cg/moat.slice/p-coding-session").is_dir(), "cgroups exist before load");
        // (the temp "cgroup mount" belongs to the test user, so use another uid as the session user)
        assert_eq!(ep.launch_refusal("coding-session", 4242), None);
        assert!(ep.launch_refusal("coding-session", 0).unwrap().contains("root"));
        assert!(ep.launch_refusal("made-up", 4242).unwrap().contains("not defined"));
        // replay rejected, revision kept
        assert!(ep.offer(signed(&f.key, 3)).unwrap_err().contains("replay") || ep.status().revision == Some(3));
        assert_eq!(ep.status().revision, Some(3));
        // restart: controller unreachable, last valid policy re-installed
        drop(ep);
        let mut ep2 = make(f.dir.path());
        ep2.startup();
        assert_eq!(ep2.status().revision, Some(3));
        assert!(ep2.status().enforcement_active);
        assert!(ep2.backend.tables["moat"].contains("jump s_coding_session"));
        let evs = events(&ep2);
        assert!(evs.iter().any(|e| matches!(e, Event::PolicyApplied { revision: 3, .. })));
        assert!(evs.iter().filter(|e| matches!(e, Event::Restart { .. })).count() >= 2);
    }

    #[test]
    fn bad_signature_and_failed_check_keep_previous() {
        let (f, mut ep) = fixture();
        ep.startup();
        ep.offer(signed(&f.key, 1)).unwrap();
        let other = generate_key();
        assert!(ep.offer(signed(&other, 2)).is_err());
        ep.backend.fail_check = true;
        let e = ep.offer(signed(&f.key, 2)).unwrap_err();
        assert!(e.contains("nft rejected"));
        assert_eq!(ep.status().revision, Some(1));
        assert!(events(&ep).iter().any(|e| matches!(e, Event::PolicyRejected { kept_revision: Some(1), .. })));
    }

    #[test]
    fn local_disable_and_isolation_are_sticky() {
        let (f, mut ep) = fixture();
        ep.startup();
        ep.offer(signed(&f.key, 1)).unwrap();
        let mut rec = RecoveryState::load(f.dir.path());
        rec.enforcement_disabled = true;
        rec.changed_by_uid = Some(0);
        rec.isolation.active = true;
        rec.isolation.keep = vec!["100.100.1.2/32".parse().unwrap()];
        rec.save(f.dir.path()).unwrap();
        ep.reconcile();
        assert!(!ep.backend.tables.contains_key("moat"));
        assert!(ep.backend.tables["moat_local_emergency"].contains("100.100.1.2/32"));
        assert!(ep.launch_refusal("coding-session", 1000).unwrap().contains("disabled locally"));
        // a new policy arrives: accepted and stored, but enforcement stays off and isolation stays up
        ep.offer(signed(&f.key, 2)).unwrap();
        assert!(!ep.backend.tables.contains_key("moat"));
        assert!(ep.backend.tables.contains_key("moat_local_emergency"));
        assert_eq!(ep.status().coverage, "emergency-isolation");
        // restart does not reopen
        drop(ep);
        let mut ep2 = make(f.dir.path());
        ep2.startup();
        assert!(ep2.backend.tables.contains_key("moat_local_emergency"));
        assert!(!ep2.backend.tables.contains_key("moat"));
        // explicit local resume
        let mut rec = RecoveryState::load(f.dir.path());
        rec.enforcement_disabled = false;
        rec.isolation.active = false;
        rec.save(f.dir.path()).unwrap();
        ep2.reconcile();
        assert!(ep2.backend.tables.contains_key("moat"));
        assert!(!ep2.backend.tables.contains_key("moat_local_emergency"));
        let evs = events(&ep2);
        assert!(evs.iter().any(|e| matches!(e, Event::EnforcementResumed { .. })));
    }

    #[test]
    fn inbox_and_counters() {
        let (f, mut ep) = fixture();
        ep.startup();
        let inbox = f.dir.path().join("inbox");
        fs::create_dir_all(&inbox).unwrap();
        fs::write(inbox.join("0001.json"), serde_json::to_vec(&signed(&f.key, 5)).unwrap()).unwrap();
        fs::write(inbox.join("0002.json"), b"{not json").unwrap();
        let r = ep.drain_inbox();
        assert_eq!(r[0], Ok(5));
        assert!(r[1].is_err());
        assert!(fs::read_dir(&inbox).unwrap().next().is_none());
        ep.poll_counters();
        ep.poll_counters(); // no delta the second time
        let n = events(&ep).iter().filter(|e| matches!(e, Event::RuleCounter { .. })).count();
        assert_eq!(n, 1);
        // reconcile is idempotent: no re-apply while the table is present
        let applied = ep.backend.applied.len();
        ep.reconcile();
        assert_eq!(ep.backend.applied.len(), applied);
        // tampering (table flushed outside Moat) is detected, restored and recorded
        ep.backend.tables.remove("moat");
        ep.reconcile();
        assert!(ep.backend.tables.contains_key("moat"));
        assert!(events(&ep).iter().any(|e| matches!(e, Event::CoverageChanged { detail, .. } if detail.contains("outside Moat"))));
    }

    #[test]
    fn unsupported_sessions_refuse_launch() {
        let (f, mut ep) = fixture();
        ep.adv = crate::probe::advertise(&crate::probe::HostFacts {
            nft_binary: true,
            netfilter_usable: true,
            cgroup2: false,
            ..Default::default()
        });
        ep.startup();
        ep.offer(signed(&f.key, 1)).unwrap();
        assert!(ep.launch_refusal("coding-session", 1000).unwrap().contains("cannot enforce protected sessions"));
        assert_eq!(ep.status().coverage, "monitoring");
    }
}
