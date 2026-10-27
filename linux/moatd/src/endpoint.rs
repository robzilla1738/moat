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
use crate::journal::{self, FsStore, Journal, Loaded, Phase, Store};
use crate::nft::{self, CgroupLayout, NftBackend, ProxiedSession, ProxyLayout, RenderReport};
use crate::proxy::{ProxyManager, ProxyPolicy};
use crate::recovery::RecoveryState;
use crate::spool::{Event, Spool};
use crate::trial::{self, TrialState};

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
    /// A revision on trial: reverts to `fallback_revision` at `deadline` unless confirmed.
    #[serde(default)]
    pub trial: Option<TrialState>,
    /// Live sessions whose TCP goes through the session egress proxy, with their loopback listener port.
    #[serde(default)]
    pub egress_proxy: BTreeMap<String, u16>,
    /// Session profiles that are proxied under the installed revision.
    #[serde(default)]
    pub proxied_profiles: Vec<String>,
    /// Durable activation state (W06): phase, rollback target, replay high-water and whether it is durable.
    #[serde(default)]
    pub activation: Option<ActivationStatus>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ActivationStatus {
    pub phase: Phase,
    pub active: Option<u64>,
    pub rollback_target: Option<u64>,
    pub replay_high_water: u64,
    /// `durable`: the journal on disk matches this. `uncertain`: the last journal write failed; startup reconciles
    /// from the snapshot files, which are durable.
    pub durability: String,
    pub detail: Option<String>,
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
    trial: Option<TrialState>,
    pub proxy: Option<ProxyManager>,
    store: Box<dyn Store>,
    journal: Journal,
    /// Set when the last journal write failed (the in-memory journal is then ahead of the disk).
    journal_uncertain: Option<String>,
    /// Last rollback failure reported, so a retried rollback does not flood the spool.
    rollback_error: Option<String>,
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
            trial: None,
            proxy: None,
            store: Box::new(FsStore),
            journal: Journal::default(),
            journal_uncertain: None,
            rollback_error: None,
        }
    }

    /// Replace the durable store (tests inject faults through it).
    pub fn with_store(mut self, s: Box<dyn Store>) -> Self {
        self.store = s;
        self
    }

    pub fn with_uid_resolver(mut self, f: fn(&str) -> Option<u32>) -> Self {
        self.uid_of = f;
        self
    }

    /// Run the session egress proxy (only takes effect when the advertisement keeps `session_hostname_proxy`).
    pub fn with_proxy(mut self, m: ProxyManager) -> Self {
        self.proxy = Some(m);
        self
    }

    fn proxy_enabled(&self) -> bool {
        self.proxy.is_some()
            && self.adv.has(Capability::SessionHostnameProxy)
            && self.adv.support(Capability::SessionEnforcement) != Support::Unsupported
    }

    fn layout(&self) -> CgroupLayout {
        let sessions_enabled = self.adv.support(Capability::SessionEnforcement) != Support::Unsupported;
        let proxy = match (&self.proxy, self.proxy_enabled()) {
            (Some(m), true) => Some(ProxyLayout {
                ports: m.ports,
                sessions: m
                    .sessions
                    .iter()
                    .map(|(id, p)| ProxiedSession { id: id.clone(), profile: p.session.profile.clone(), port: p.port })
                    .collect(),
            }),
            _ => None,
        };
        CgroupLayout { root_name: self.cgroups.root_name.clone(), mount: self.cgroups.mount.clone(), sessions_enabled, proxy }
    }

    /// Session ids the ruleset depends on: registered sessions plus sessions whose proxy is being set up.
    fn live_ids(&self) -> Vec<String> {
        let mut v: Vec<String> = self.sessions.keys().cloned().collect();
        if let Some(m) = &self.proxy {
            v.extend(m.sessions.keys().cloned());
        }
        v.sort();
        v.dedup();
        v
    }

    /// Before a session's workload starts: if its profile is proxied, open its listener and install the redirect,
    /// so its very first connection already goes through the proxy. Returns the listener port.
    pub fn prepare_session_proxy(&mut self, id: &str, profile: &str) -> Result<Option<u16>, String> {
        if !self.proxy_enabled() {
            return Ok(None);
        }
        let proxied = self.current.as_ref().map(|c| c.2.proxied_profiles.iter().any(|p| p == profile)).unwrap_or(false);
        if !proxied {
            return Ok(None);
        }
        let port = self.proxy.as_mut().unwrap().open(id, profile)?;
        self.reconcile();
        if self.installed.is_some() && self.rendered_sessions.iter().any(|s| s == id) {
            Ok(Some(port))
        } else {
            self.close_session_proxy(id);
            Err(format!(
                "could not install the egress-proxy redirect for this session: {}",
                self.last_rejection.clone().unwrap_or_else(|| "ruleset not applied".into())
            ))
        }
    }

    pub fn close_session_proxy(&mut self, id: &str) {
        if let Some(m) = self.proxy.as_mut() {
            m.close(id);
        }
    }

    fn drain_proxy_events(&mut self) {
        let evs = self.proxy.as_ref().map(|m| m.shared.drain_events()).unwrap_or_default();
        for e in evs {
            self.spool.append(e);
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
        self.trial = TrialState::load(&self.state_dir);
        self.recover_journal();
        self.stop_orphan_sessions();
        self.reconcile();
    }

    fn current_rev(&self) -> Option<u64> {
        self.current.as_ref().map(|c| c.1.revision)
    }

    /// Write the journal; on failure remember that the disk is behind (reported in status, reconciled on startup
    /// from the snapshot files, which are written before the phase that refers to them).
    fn persist_journal(&mut self) -> Result<(), String> {
        match self.journal.save(self.store.as_mut(), &self.state_dir) {
            Ok(()) => {
                self.journal_uncertain = None;
                Ok(())
            }
            Err(e) => {
                let why = format!("activation journal write failed: {e}");
                self.journal_uncertain = Some(why.clone());
                Err(why)
            }
        }
    }

    fn activation_event(&mut self, detail: String) {
        self.spool.append(Event::ActivationRecovery {
            phase: serde_json::to_value(self.journal.phase).ok().and_then(|v| v.as_str().map(String::from)).unwrap_or_default(),
            active_revision: self.journal.active,
            detail,
        });
    }

    /// Startup half of W06: the replay high-water is the maximum of every readable copy, and the journal decides
    /// what an interrupted activation or rollback means. Never a silent fresh permissive bootstrap.
    fn recover_journal(&mut self) {
        let mut notes = Vec::new();
        let mark = match fs::read_to_string(self.state_dir.join(trial::REPLAY_MARK)) {
            Ok(t) => match t.trim().parse::<u64>() {
                Ok(v) => Some(v),
                Err(_) => {
                    notes.push("replay high-water file corrupt; using the journal's copy".to_string());
                    None
                }
            },
            Err(_) => None,
        };
        let loaded = Journal::load(&self.state_dir);
        let mut j = match &loaded {
            Loaded::Ok(j) => j.clone(),
            _ => Journal::default(),
        };
        let cur = self.current_rev();
        let hw = [mark, Some(j.replay_high_water), cur, self.last_applied, self.trial.as_ref().map(|t| t.revision)]
            .into_iter()
            .flatten()
            .max()
            .unwrap_or(0);
        j.replay_high_water = hw;
        self.last_applied = (hw > 0).then_some(hw).or(self.last_applied);
        match loaded {
            Loaded::Missing => {
                // First start with a journal (or a fresh device): describe what the snapshot files say.
                j.active = cur;
                j.phase = match (cur, &self.trial) {
                    (None, _) => Phase::None,
                    (Some(r), Some(t)) if t.revision == r => Phase::Trial,
                    _ => Phase::Confirmed,
                };
                if j.phase == Phase::Trial {
                    j.rollback_target = self.trial.as_ref().map(|t| t.fallback_revision);
                    j.trial_deadline = self.trial.as_ref().map(|t| t.deadline);
                }
            }
            Loaded::Corrupt(why) => {
                let _ = fs::copy(self.state_dir.join(journal::FILE), self.state_dir.join(format!("{}.corrupt", journal::FILE)));
                j.phase = Phase::RecoveryRequired;
                j.active = cur;
                j.detail = Some(format!(
                    "{why}; enforcing the last verified snapshot ({}); a new signed revision clears this",
                    cur.map_or("none".into(), |r| format!("revision {r}"))
                ));
                notes.push(why);
            }
            Loaded::Ok(_) => match j.phase {
                Phase::Applying if cur.is_some() && cur == j.target => {
                    // The commit (current = target) happened; only the final phase write was lost.
                    let on_trial = self.trial.as_ref().is_some_and(|t| Some(t.revision) == j.target);
                    j.phase = if on_trial { Phase::Trial } else { Phase::Confirmed };
                    j.active = cur;
                    if on_trial {
                        j.rollback_target = self.trial.as_ref().map(|t| t.fallback_revision);
                        j.trial_deadline = self.trial.as_ref().map(|t| t.deadline);
                    } else {
                        j.rollback_target = None;
                        j.trial_deadline = None;
                        if self.trial.take().is_some() {
                            let _ = self.store.remove(&self.state_dir, trial::FILE);
                        }
                    }
                    notes.push(format!("activation of revision {} was committed before the restart; completed", cur.unwrap()));
                }
                Phase::Applying => {
                    // Interrupted before the commit: the kernel is uncertain, the disk still names the prior revision.
                    let target = j.target.unwrap_or(0);
                    if self.trial.as_ref().is_some_and(|t| t.revision == target) {
                        let _ = self.store.remove(&self.state_dir, trial::FILE);
                        self.trial = None;
                    }
                    if let Some(pt) = j.prior_trial.take() {
                        if self.store.write_atomic(&self.state_dir, trial::FILE, &serde_json::to_vec_pretty(&pt).unwrap()).is_ok() {
                            self.trial = Some(pt);
                        }
                    }
                    let _ = self.store.remove(&self.state_dir, journal::CANDIDATE);
                    j.active = cur;
                    j.phase = match (cur, &self.trial) {
                        (None, _) => Phase::None,
                        (Some(r), Some(t)) if t.revision == r => Phase::Trial,
                        _ => Phase::Confirmed,
                    };
                    if cur.is_none() && self.last_rejection.is_some() {
                        j.phase = Phase::RecoveryRequired;
                    }
                    notes.push(format!(
                        "activation of revision {target} was interrupted before it was committed; {} is reinstalled",
                        cur.map_or("no policy".into(), |r| format!("revision {r}"))
                    ));
                }
                _ => {}
            },
        }
        j.target = None;
        j.prior = None;
        if self.current.is_none() && self.last_rejection.is_some() && j.phase != Phase::RollbackRequired {
            // A stored snapshot exists but cannot be loaded: say so; leave the kernel as it is (not deleted, not
            // replaced with something weaker) until a new signed revision or a rollback restores a known state.
            j.phase = Phase::RecoveryRequired;
            j.detail = self.last_rejection.clone();
        }
        self.journal = j;
        if mark != Some(hw) {
            let _ = self.store.write_atomic(&self.state_dir, trial::REPLAY_MARK, hw.to_string().as_bytes());
        }
        let _ = self.persist_journal();
        for n in notes {
            self.activation_event(n);
        }
    }

    /// Restart contract for protected sessions (W06): sessions that were running when the previous daemon stopped
    /// are **not adopted**. Their control connection, egress proxy and session-bound grants are gone, so they are
    /// stopped (cgroup.kill) and reported. Until this runs they stay under their profile's chain, which is
    /// fail-closed (no session-bound grants, no proxy redirect).
    fn stop_orphan_sessions(&mut self) {
        for (profile, id, cg) in self.cgroups.list_sessions() {
            if self.sessions.contains_key(&id) {
                continue;
            }
            let killed = self.cgroups.close_session(&cg).is_ok();
            self.spool.append(Event::SessionNotAdopted {
                session_id: id,
                profile,
                reason: if killed {
                    "moatd restarted: sessions are not adopted across a daemon restart; stopped".into()
                } else {
                    "moatd restarted: sessions are not adopted; stopping failed".into()
                },
            });
        }
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
        // W05 stream contract: isolation ends every proxied stream and refuses new ones; on every tick each open
        // stream is re-checked at the current time, so an expired rule or grant ends it within one tick.
        if let Some(m) = &self.proxy {
            if m.shared.isolated.load(std::sync::atomic::Ordering::SeqCst) != self.recovery.isolation.active {
                m.shared.set_isolated(self.recovery.isolation.active);
            }
            m.shared.revalidate(Utc::now());
        }
        self.drain_proxy_events();
        self.tick_trial(Utc::now());
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
        let sessions_now: Vec<String> = self.live_ids();
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
        self.rendered_sessions = self.live_ids();
        if let Some(m) = &self.proxy {
            m.set_policy(Some(ProxyPolicy { policy: snap.policy.clone(), device_id: self.device_id.clone(), revision: snap.revision }));
        }
        Ok(rep)
    }

    /// Offer a new signed snapshot. Atomic: on any failure the previous revision stays in force.
    pub fn offer(&mut self, signed: SignedSnapshot) -> Result<u64, String> {
        self.offer_with(signed, None)
    }

    /// The revision a trial would fall back to: the last confirmed one.
    fn confirmed_revision(&self) -> Option<u64> {
        if self.trial.is_some() {
            Self::read_signed(&self.state_dir.join(trial::LAST_GOOD)).and_then(|s| Self::decode_revision(&s))
        } else {
            self.current.as_ref().map(|c| c.1.revision)
        }
    }

    fn read_signed(p: &Path) -> Option<SignedSnapshot> {
        fs::read_to_string(p).ok().and_then(|t| serde_json::from_str(&t).ok())
    }

    fn decode_revision(s: &SignedSnapshot) -> Option<u64> {
        use base64::Engine;
        let bytes = base64::engine::general_purpose::STANDARD.decode(&s.payload).ok()?;
        let v: serde_json::Value = serde_json::from_slice(&bytes).ok()?;
        v["revision"].as_u64()
    }

    fn reject(&mut self, e: String) -> Result<u64, String> {
        self.last_rejection = Some(e.clone());
        self.spool.append(Event::PolicyRejected { reason: e.clone(), kept_revision: self.current_rev() });
        Err(e)
    }

    /// Undo an activation that failed before its commit: the prior revision stays (or is restored), the journal
    /// returns to its previous phase, the replay high-water is **not** lowered.
    fn abort_activation(
        &mut self,
        before: Journal,
        prior_trial: Option<TrialState>,
        wrote_trial: bool,
        why: String,
    ) -> Result<u64, String> {
        if wrote_trial {
            let restored = match &prior_trial {
                Some(t) => self.store.write_atomic(&self.state_dir, trial::FILE, &serde_json::to_vec_pretty(t).unwrap()),
                None => self.store.remove(&self.state_dir, trial::FILE),
            };
            if restored.is_err() {
                // The trial file now names a revision that is not active; tick_trial ignores and removes such files.
                self.activation_event("could not restore the trial file after an aborted activation; it is ignored".into());
            }
        }
        let _ = self.store.remove(&self.state_dir, journal::CANDIDATE);
        let hw = self.journal.replay_high_water;
        self.journal = Journal { replay_high_water: hw.max(before.replay_high_water), ..before };
        let _ = self.persist_journal();
        self.reject(why)
    }

    /// Offer a snapshot, optionally on trial for `trial_secs` seconds (reverts unless confirmed).
    ///
    /// Durable sequence (journal.rs has the crash table): intent → replay high-water → staged candidate (+ rollback
    /// target and trial deadline) → kernel → commit → phase. Any failure before the commit leaves the prior revision
    /// in force; a failure at the commit restores the prior revision in the kernel or enters `recovery_required`.
    pub fn offer_with(&mut self, signed: SignedSnapshot, trial_secs: Option<u64>) -> Result<u64, String> {
        let fallback = self.confirmed_revision();
        if trial_secs.is_some() && fallback.is_none() {
            return self
                .reject("a trial needs a confirmed revision to fall back to; apply the first revision without --trial-secs".to_string());
        }
        if trial_secs == Some(0) {
            return self.reject("a trial needs a deadline of at least one second".to_string());
        }
        if trial_secs.is_some() && self.journal.phase == Phase::RollbackRequired {
            return self.reject("a rollback is still pending; a new trial cannot start until it completes".to_string());
        }
        let checked = (|| {
            let snap = verify_snapshot(&signed, &self.trust, Platform::Linux, self.last_applied, Utc::now()).map_err(|e| e.to_string())?;
            let (_, rep) = nft::render(&snap, &self.device_id, &self.layout(), &self.uid_of).map_err(|e| e.0)?;
            Ok::<_, String>((snap, rep))
        })();
        let (snap, rep) = match checked {
            Ok(x) => x,
            Err(e) => return self.reject(e),
        };
        let rev = snap.revision;
        let prior = self.current_rev();
        let prior_snap = self.current.as_ref().map(|c| c.1.clone());
        let prior_trial = self.trial.clone();
        let before = self.journal.clone();

        // 1. durable intent
        self.journal.phase = Phase::Applying;
        self.journal.target = Some(rev);
        self.journal.prior = prior;
        self.journal.prior_trial = prior_trial.clone();
        self.journal.replay_high_water = self.journal.replay_high_water.max(rev);
        self.journal.detail = None;
        if let Err(e) = self.persist_journal() {
            self.journal = before;
            self.journal_uncertain = None;
            return self.reject(format!("not durable: {e}; revision {} stays in force", prior.map_or("none".into(), |r| r.to_string())));
        }
        // 2. independent replay high-water (never lowered, even if this activation fails later)
        if let Err(e) = self.store.write_atomic(&self.state_dir, trial::REPLAY_MARK, self.journal.replay_high_water.to_string().as_bytes())
        {
            return self.abort_activation(before, prior_trial, false, format!("not durable: replay high-water write failed: {e}"));
        }
        self.last_applied = Some(self.last_applied.unwrap_or(0).max(rev));
        // 3. staged candidate; for a trial, the rollback target and the deadline are durable before the kernel changes
        if let Err(e) = self.store.write_atomic(&self.state_dir, journal::CANDIDATE, &serde_json::to_vec_pretty(&signed).unwrap()) {
            return self.abort_activation(before, prior_trial, false, format!("not durable: staging the candidate failed: {e}"));
        }
        let new_trial = trial_secs.map(|secs| {
            let now = Utc::now();
            TrialState {
                revision: rev,
                fallback_revision: fallback.unwrap_or(0),
                started_at: now,
                deadline: now + chrono::Duration::seconds(secs.min(7 * 24 * 3600) as i64),
                confirmed: false,
                revert_now: false,
                changed_by_uid: None,
            }
        });
        if let Some(t) = &new_trial {
            if self.trial.is_none() {
                if let Err(e) = self.store.copy_atomic(&self.state_dir, CURRENT, trial::LAST_GOOD) {
                    return self.abort_activation(
                        before,
                        prior_trial,
                        false,
                        format!("not durable: saving the rollback target failed: {e}"),
                    );
                }
            }
            if let Err(e) = self.store.write_atomic(&self.state_dir, trial::FILE, &serde_json::to_vec_pretty(t).unwrap()) {
                return self.abort_activation(before, prior_trial, true, format!("not durable: saving the trial deadline failed: {e}"));
            }
        }
        // 4. kernel
        if !self.recovery.enforcement_disabled {
            if let Err(e) = self.install(&snap) {
                // nft applies a ruleset as one transaction: a failed install leaves the prior table in place.
                return self.abort_activation(before, prior_trial, new_trial.is_some(), e);
            }
        }
        // 5. commit
        if let Err(e) = self.store.copy_atomic(&self.state_dir, journal::CANDIDATE, CURRENT) {
            let why = format!("revision {rev} was installed but could not be made durable ({e})");
            let restored = match (&prior_snap, self.recovery.enforcement_disabled) {
                (_, true) => Ok(()),
                (Some(p), false) => self.install(p).map(|_| ()),
                (None, false) => Err("there is no prior revision to restore".to_string()),
            };
            return match restored {
                Ok(()) => self.abort_activation(
                    before,
                    prior_trial,
                    new_trial.is_some(),
                    format!("not durable: {why}; revision {} restored", prior.map_or("none".into(), |r| r.to_string())),
                ),
                Err(re) => {
                    // The kernel holds a verified signed revision the disk does not: say so, keep it (never weaker).
                    self.current = Some((signed, snap, rep));
                    self.journal.phase = Phase::RecoveryRequired;
                    self.journal.active = Some(rev);
                    self.journal.target = None;
                    self.journal.detail = Some(format!("{why}; restoring the prior state failed: {re}"));
                    let _ = self.persist_journal();
                    let d = self.journal.detail.clone().unwrap();
                    self.activation_event(d.clone());
                    self.reject(format!("not durable: {d}"))
                }
            };
        }
        // 6. phase
        let _ = self.store.remove(&self.state_dir, journal::CANDIDATE);
        self.journal.active = Some(rev);
        self.journal.target = None;
        self.journal.prior = None;
        self.journal.prior_trial = None;
        match &new_trial {
            Some(t) => {
                self.journal.phase = Phase::Trial;
                self.journal.rollback_target = Some(t.fallback_revision);
                self.journal.trial_deadline = Some(t.deadline);
            }
            None => {
                // A revision applied without a trial ends any pending trial: it is confirmed by being applied.
                self.journal.phase = Phase::Confirmed;
                self.journal.rollback_target = None;
                self.journal.trial_deadline = None;
                if self.trial.is_some() && self.store.remove(&self.state_dir, trial::FILE).is_err() {
                    self.activation_event("stale trial file could not be removed; it is ignored (revision differs)".into());
                }
                self.trial = None;
            }
        }
        if let Err(e) = self.persist_journal() {
            self.activation_event(format!("{e}; revision {rev} is committed and is completed from the snapshot files on restart"));
        }
        self.spool.append(Event::PolicyApplied {
            revision: rev,
            rollback_of: snap.rollback_of,
            policy_digest: snap.policy_digest.clone(),
            skipped_allows: rep.skipped_allows.iter().map(|(id, _)| id.clone()).collect(),
        });
        self.current = Some((signed, snap, rep));
        if !self.recovery.enforcement_disabled {
            self.set_enforcement(true, "policy enforced");
        }
        if let Some(t) = new_trial {
            self.spool.append(Event::PolicyTrialStarted { revision: rev, fallback_revision: t.fallback_revision, deadline: t.deadline });
            self.trial = Some(t);
        }
        Ok(rev)
    }

    /// End or revert a pending trial. Reads the trial file each time so `moatd recover confirm|rollback` (root,
    /// local) takes effect on the next tick, and also when it was written while the daemon was stopped. A rollback
    /// that cannot complete stays `rollback_required` and is retried on every tick.
    pub fn tick_trial(&mut self, now: DateTime<Utc>) {
        if self.journal.phase == Phase::RollbackRequired {
            self.attempt_rollback();
            return;
        }
        let Some(t) = TrialState::load(&self.state_dir) else {
            self.trial = None;
            return;
        };
        if Some(t.revision) != self.current_rev() {
            // A trial file left behind for a revision that is not active (an interrupted write): never act on it.
            if self.store.remove(&self.state_dir, trial::FILE).is_ok() {
                self.activation_event(format!("ignored a trial file for revision {} that is not active", t.revision));
            }
            self.trial = None;
            return;
        }
        if t.confirmed {
            if let Err(e) = self.store.remove(&self.state_dir, trial::FILE) {
                // Retried next tick; the trial stays visible until the confirmation is durable.
                self.trial = Some(t);
                self.last_rejection = Some(format!("confirming revision {}: {e}", self.current_rev().unwrap_or(0)));
                return;
            }
            self.trial = None;
            self.journal.phase = Phase::Confirmed;
            self.journal.rollback_target = None;
            self.journal.trial_deadline = None;
            let _ = self.persist_journal();
            self.spool.append(Event::PolicyTrialConfirmed {
                revision: t.revision,
                by_uid: t.changed_by_uid,
                how: "moatd recover confirm".into(),
            });
            return;
        }
        if !t.due(now) {
            self.trial = Some(t);
            return;
        }
        let reason = if t.revert_now {
            "local rollback (moatd recover rollback)".to_string()
        } else {
            format!("trial not confirmed before {}", t.deadline.to_rfc3339())
        };
        // Rollback intent is durable before anything changes, and kept until restoration is durable.
        self.journal.phase = Phase::RollbackRequired;
        self.journal.active = Some(t.revision);
        self.journal.rollback_target = Some(t.fallback_revision);
        self.journal.detail = Some(reason);
        if let Err(e) = self.persist_journal() {
            // The trial file still holds the intent (it is only removed once the rollback is durable).
            self.activation_event(format!("{e}; the rollback intent is still held by the trial file"));
        }
        self.trial = Some(t);
        self.attempt_rollback();
    }

    fn attempt_rollback(&mut self) {
        let from = self.journal.active.unwrap_or(0);
        let to = self.journal.rollback_target.unwrap_or(0);
        let reason = self.journal.detail.clone().unwrap_or_else(|| "rollback".into());
        let res = (|| {
            let signed =
                Self::read_signed(&self.state_dir.join(trial::LAST_GOOD)).ok_or("the last confirmed snapshot is missing or unreadable")?;
            let at = Self::decode_issued_at(&signed).unwrap_or_else(Utc::now);
            let snap = verify_snapshot(&signed, &self.trust, Platform::Linux, None, at).map_err(|e| e.to_string())?;
            if snap.revision != to {
                return Err(format!("the stored rollback target is revision {}, expected {to}", snap.revision));
            }
            let (_, rep) = nft::render(&snap, &self.device_id, &self.layout(), &self.uid_of).map_err(|e| e.0)?;
            if !self.recovery.enforcement_disabled && self.installed != Some(to) {
                self.install(&snap)?;
            }
            Ok::<_, String>((signed, snap, rep))
        })();
        let (signed, snap, rep) = match res {
            Ok(x) => x,
            Err(e) => {
                let why = format!("rollback from revision {from} to {to} failed: {e}; revision {from} stays in force; retrying");
                self.last_rejection = Some(why.clone());
                if self.rollback_error.as_deref() != Some(why.as_str()) {
                    self.spool.append(Event::PolicyRollbackFailed { revision: from, reason: why.clone() });
                    self.rollback_error = Some(why);
                }
                return;
            }
        };
        // The kernel now enforces `to`; status says so even if the disk write below fails.
        self.current = Some((signed, snap.clone(), rep.clone()));
        if let Err(e) = self.store.copy_atomic(&self.state_dir, trial::LAST_GOOD, CURRENT) {
            let why = format!("rollback to revision {to} is enforced but not yet durable ({e}); retrying");
            self.last_rejection = Some(why.clone());
            if self.rollback_error.as_deref() != Some(why.as_str()) {
                self.spool.append(Event::PolicyRollbackFailed { revision: from, reason: why.clone() });
                self.rollback_error = Some(why);
            }
            return;
        }
        let _ = self.store.remove(&self.state_dir, trial::FILE);
        self.trial = None;
        self.rollback_error = None;
        self.journal.phase = Phase::Confirmed;
        self.journal.active = Some(to);
        self.journal.rollback_target = None;
        self.journal.trial_deadline = None;
        self.journal.detail = Some(format!("restored revision {to} ({reason})"));
        let _ = self.persist_journal();
        self.spool.append(Event::PolicyRolledBack { from_revision: from, to_revision: to, reason: reason.clone() });
        self.spool.append(Event::PolicyApplied {
            revision: to,
            rollback_of: Some(from),
            policy_digest: snap.policy_digest.clone(),
            skipped_allows: rep.skipped_allows.iter().map(|(id, _)| id.clone()).collect(),
        });
        self.last_rejection = Some(format!("Rolled back from revision {from} to {to} ({reason})."));
        // last_applied (the replay high-water mark) intentionally stays at the trial revision.
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
            // A sidecar `<name>.trial` holding a number of seconds puts the revision on trial.
            let trial_file = f.with_extension("trial");
            let trial_secs = fs::read_to_string(&trial_file).ok().and_then(|t| t.trim().parse::<u64>().ok());
            let _ = fs::remove_file(&trial_file);
            out.push(match r {
                Ok(s) => self.offer_with(s, trial_secs),
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
        self.close_session_proxy(id);
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
        if self.journal.phase == Phase::RecoveryRequired {
            return "recovery-required".into();
        }
        if self.journal.phase == Phase::RollbackRequired {
            return "rollback-pending".into();
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
            trial: self.trial.clone(),
            egress_proxy: self.proxy.as_ref().map(|m| m.sessions.iter().map(|(id, p)| (id.clone(), p.port)).collect()).unwrap_or_default(),
            proxied_profiles: self.current.as_ref().map(|c| c.2.proxied_profiles.clone()).unwrap_or_default(),
            activation: Some(ActivationStatus {
                phase: self.journal.phase,
                active: self.journal.active,
                rollback_target: self.journal.rollback_target,
                replay_high_water: self.journal.replay_high_water,
                durability: if self.journal_uncertain.is_some() { "uncertain".into() } else { "durable".into() },
                detail: self.journal_uncertain.clone().or_else(|| self.journal.detail.clone()),
            }),
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
        /// W06 fault injection: every apply fails (backend error).
        pub fail_apply: bool,
        /// W06 crash simulation: once set, the "process" is gone and the kernel is no longer changed.
        pub crashed: Option<std::sync::Arc<std::sync::atomic::AtomicBool>>,
    }
    impl NftBackend for FakeNft {
        fn apply(&mut self, r: &str) -> Result<(), String> {
            if self.crashed.as_ref().is_some_and(|c| c.load(std::sync::atomic::Ordering::SeqCst)) {
                return Err("process crashed".into());
            }
            if self.fail_apply {
                return Err("netlink: Error: Could not process rule: No buffer space available".into());
            }
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

    pub fn make(dir: &Path) -> Endpoint<FakeNft> {
        make_with(dir, FakeNft::default())
    }

    pub fn make_with(dir: &Path, backend: FakeNft) -> Endpoint<FakeNft> {
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
            backend,
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

    pub fn events(ep: &Endpoint<FakeNft>) -> Vec<Event> {
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

    pub fn applied_revision(ep: &Endpoint<FakeNft>) -> String {
        ep.backend.tables["moat"].lines().next().unwrap_or("").to_string()
    }

    #[test]
    fn first_revision_cannot_be_a_trial() {
        let (f, mut ep) = fixture();
        ep.startup();
        let e = ep.offer_with(signed(&f.key, 1), Some(60)).unwrap_err();
        assert!(e.contains("confirmed revision to fall back to"));
        assert_eq!(ep.status().revision, None);
    }

    #[test]
    fn trial_reverts_unless_confirmed_and_replay_mark_holds() {
        let (f, mut ep) = fixture();
        ep.startup();
        ep.offer(signed(&f.key, 1)).unwrap();
        ep.offer_with(signed(&f.key, 2), Some(60)).unwrap();
        let t = ep.status().trial.unwrap();
        assert_eq!((t.revision, t.fallback_revision), (2, 1));
        assert!(applied_revision(&ep).contains("revision 2 "));
        ep.tick_trial(Utc::now() + Duration::seconds(30));
        assert_eq!(ep.status().revision, Some(2), "not due yet");
        ep.tick_trial(Utc::now() + Duration::seconds(61));
        assert_eq!(ep.status().revision, Some(1));
        assert!(ep.status().trial.is_none());
        assert!(applied_revision(&ep).contains("revision 1 "), "fallback reinstalled in the kernel");
        assert!(ep.status().last_rejection.unwrap().contains("Rolled back from revision 2 to 1"));
        let evs = events(&ep);
        assert!(evs.iter().any(|e| matches!(e, Event::PolicyTrialStarted { revision: 2, fallback_revision: 1, .. })));
        assert!(evs.iter().any(|e| matches!(e, Event::PolicyRolledBack { from_revision: 2, to_revision: 1, .. })));
        assert!(evs.iter().any(|e| matches!(e, Event::PolicyApplied { revision: 1, rollback_of: Some(2), .. })));
        // the reverted revision cannot be replayed; a newer one is accepted
        assert!(ep.offer(signed(&f.key, 2)).is_err());
        assert_eq!(ep.offer(signed(&f.key, 3)).unwrap(), 3);
        // restart keeps the high-water mark
        drop(ep);
        let mut ep2 = make(f.dir.path());
        ep2.startup();
        assert!(ep2.offer(signed(&f.key, 3)).is_err());
    }

    #[test]
    fn confirmed_trial_stays_and_becomes_the_next_fallback() {
        let (f, mut ep) = fixture();
        ep.startup();
        ep.offer(signed(&f.key, 1)).unwrap();
        ep.offer_with(signed(&f.key, 2), Some(60)).unwrap();
        // a second trial while one is pending keeps the original confirmed fallback
        ep.offer_with(signed(&f.key, 3), Some(60)).unwrap();
        assert_eq!(ep.status().trial.unwrap().fallback_revision, 1);
        let mut t = TrialState::load(f.dir.path()).unwrap();
        t.confirmed = true;
        t.changed_by_uid = Some(0);
        t.save(f.dir.path()).unwrap();
        ep.reconcile();
        assert!(ep.status().trial.is_none());
        assert!(events(&ep).iter().any(|e| matches!(e, Event::PolicyTrialConfirmed { revision: 3, by_uid: Some(0), .. })));
        ep.tick_trial(Utc::now() + Duration::seconds(3600));
        assert_eq!(ep.status().revision, Some(3));
        ep.offer_with(signed(&f.key, 4), Some(60)).unwrap();
        assert_eq!(ep.status().trial.unwrap().fallback_revision, 3);
        ep.tick_trial(Utc::now() + Duration::seconds(61));
        assert_eq!(ep.status().revision, Some(3));
    }

    #[test]
    fn trial_past_deadline_reverts_on_restart_and_never_touches_isolation() {
        let (f, mut ep) = fixture();
        ep.startup();
        ep.offer(signed(&f.key, 1)).unwrap();
        ep.offer_with(signed(&f.key, 2), Some(60)).unwrap();
        let mut rec = RecoveryState::load(f.dir.path());
        rec.isolation.active = true;
        rec.save(f.dir.path()).unwrap();
        ep.reconcile();
        drop(ep);
        // the daemon was down past the deadline
        let mut t = TrialState::load(f.dir.path()).unwrap();
        t.deadline = Utc::now() - Duration::seconds(1);
        t.save(f.dir.path()).unwrap();
        let mut ep2 = make(f.dir.path());
        ep2.startup();
        assert_eq!(ep2.status().revision, Some(1));
        assert!(ep2.status().isolation_active);
        assert!(ep2.backend.tables.contains_key("moat_local_emergency"));
        // a non-trial apply ends a pending trial
        ep2.offer_with(signed(&f.key, 3), Some(60)).unwrap();
        ep2.offer(signed(&f.key, 4)).unwrap();
        assert!(ep2.status().trial.is_none());
        assert!(TrialState::load(f.dir.path()).is_none());
    }

    #[test]
    fn local_rollback_request_reverts_now() {
        let (f, mut ep) = fixture();
        ep.startup();
        ep.offer(signed(&f.key, 1)).unwrap();
        ep.offer_with(signed(&f.key, 2), Some(3600)).unwrap();
        let mut t = TrialState::load(f.dir.path()).unwrap();
        t.revert_now = true;
        t.save(f.dir.path()).unwrap();
        ep.reconcile();
        assert_eq!(ep.status().revision, Some(1));
        assert!(events(&ep).iter().any(|e| matches!(e, Event::PolicyRolledBack { reason, .. } if reason.contains("local rollback"))));
    }

    #[test]
    fn proxied_sessions_get_a_listener_and_redirect_before_launch() {
        let (f, mut ep) = fixture();
        let shared = std::sync::Arc::new(crate::proxy::Shared::new(Box::new(crate::proxy::system_resolver)));
        ep = ep.with_proxy(ProxyManager::new(shared, (25000, 25050)));
        ep.startup();
        ep.offer(signed(&f.key, 1)).unwrap();
        assert_eq!(ep.status().proxied_profiles, vec!["coding-session".to_string()]);
        // not proxied: no hostname rules in this profile
        assert_eq!(ep.prepare_session_proxy("x0", "local-inference").unwrap(), None);
        fs::create_dir_all(f.dir.path().join("cg/moat.slice/p-coding-session/s-x1")).unwrap();
        let port = ep.prepare_session_proxy("x1", "coding-session").unwrap().unwrap();
        assert!((25000..=25050).contains(&port));
        let t = &ep.backend.tables["moat"];
        assert!(t.contains(&format!("redirect to :{port}")), "{t}");
        assert_eq!(ep.status().egress_proxy.get("x1"), Some(&port));
        // the listener is real
        assert!(std::net::TcpStream::connect(("127.0.0.1", port)).is_ok());
        ep.end_session("x1", Some(0), None);
        assert!(ep.status().egress_proxy.is_empty());
        ep.reconcile();
        assert!(!ep.backend.tables["moat"].contains("redirect to"));
        // without the capability (probe downgraded it), nothing is proxied and hostname allows are left out
        ep.adv = CapabilityAdvertisement::linux_nftables_cgroup_ip_only();
        ep.offer(signed(&f.key, 2)).unwrap();
        assert!(ep.status().proxied_profiles.is_empty());
        assert!(ep.status().skipped_allows.iter().any(|(id, _)| id == "coding-allow-github"));
        assert_eq!(ep.prepare_session_proxy("x2", "coding-session").unwrap(), None);
    }
}

#[cfg(test)]
mod journal_faults;
