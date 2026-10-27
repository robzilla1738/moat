//! Device-side event spool.
//!
//! Append-only JSON-lines segments with a monotonic sequence number per device, a restart marker every time the
//! spool opens (saying whether the previous run shut down cleanly), and an explicit gap record whenever events were
//! dropped (disk quota, write error). Enforcement never depends on logging: a full spool drops events and says so;
//! it never blocks or loosens a decision.
//!
//! Fleet sync (docs/fleet-sync.md, W13). The spool is the endpoint's durable outbox:
//! * Disk use is bounded by `max_bytes`. When a write would exceed it, whole segments the controller already
//!   acknowledged are removed first (nothing is lost). If that is not enough, the oldest *unacknowledged* segment is
//!   evicted and an explicit `gap` record names exactly the unacknowledged sequence numbers it held. Evicting the
//!   oldest keeps the newest evidence; the gap and the risen `spool_low_seq` say what is gone. Only when not even
//!   that frees room (a write error, one oversized record) is the new event dropped, again with a gap record.
//! * Acknowledgements arrive as the contiguous high-water `acked_seq` in `<spool>/acked` (written by the sync agent
//!   or `moatd spool-ack`). It is durable, never lowered and never accepted beyond the last sequence written.
//! * `<spool>/sync-state.json` (`moat.spool_sync_state.v1`) carries what the sync body needs: `spool_low_seq` (the
//!   lowest sequence still held; everything below it is either acknowledged or covered by a gap record),
//!   `acked_seq`, `next_seq` and the endpoint's pending `local_change`, if any.

use std::fs::{self, File, OpenOptions};
use std::io::{BufRead, BufReader, Write};
use std::path::{Path, PathBuf};

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum Event {
    /// Spool opened. `clean_shutdown` is false after a crash or power loss.
    Restart {
        boot_id: String,
        previous_seq: Option<u64>,
        clean_shutdown: bool,
        version: String,
    },
    /// Events `from..=to` were lost. The UI must show this; completeness is never inferred.
    Gap {
        from: u64,
        to: u64,
        reason: String,
    },
    CapabilityAdvertised {
        advertisement: serde_json::Value,
    },
    PolicyApplied {
        revision: u64,
        rollback_of: Option<u64>,
        policy_digest: String,
        skipped_allows: Vec<String>,
    },
    PolicyRejected {
        reason: String,
        kept_revision: Option<u64>,
    },
    /// Rule-scoped counter delta. `scope` is always `rule`: nftables counters are not per flow.
    RuleCounter {
        rule: String,
        packets: u64,
        bytes: u64,
        scope: String,
    },
    SessionStarted {
        session_id: String,
        profile: String,
        cgroup: String,
        uid: u32,
        root_pid: u32,
        root_start: u64,
        boundary: String,
    },
    SessionLaunchRefused {
        profile: String,
        uid: u32,
        reason: String,
    },
    SessionEnded {
        session_id: String,
        exit_code: Option<i32>,
        signal: Option<i32>,
    },
    CoverageChanged {
        level: String,
        detail: String,
    },
    EnforcementDisabledLocally {
        by_uid: u32,
        reason: String,
    },
    EnforcementResumed {
        by_uid: u32,
    },
    LocalIsolation {
        active: bool,
        by_uid: u32,
    },
    /// A revision was installed on trial: it reverts to `fallback_revision` at `deadline` unless confirmed.
    PolicyTrialStarted {
        revision: u64,
        fallback_revision: u64,
        deadline: DateTime<Utc>,
    },
    /// The trial revision was confirmed locally (root) and stays in force.
    PolicyTrialConfirmed {
        revision: u64,
        by_uid: Option<u32>,
        how: String,
    },
    /// The trial revision was reverted. `to_revision` is the last confirmed revision, reinstalled from local state;
    /// the replay high-water mark stays at the trial revision.
    PolicyRolledBack {
        from_revision: u64,
        to_revision: u64,
        reason: String,
    },
    /// A rollback could not reinstall the fallback; the trial revision stays in force and the owner must act.
    PolicyRollbackFailed {
        revision: u64,
        reason: String,
    },
    /// The activation journal reconciled or could not reconcile state (W06): an interrupted activation, a lost
    /// phase write, a corrupt journal or replay mark, a stale trial file. `phase` uses moat.activation.v1 names.
    ActivationRecovery {
        phase: String,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        active_revision: Option<u64>,
        detail: String,
    },
    /// A protected session that was running when the previous daemon stopped; not adopted (stopped).
    SessionNotAdopted {
        session_id: String,
        profile: String,
        reason: String,
    },
    /// A proxied stream was ended by Moat (policy or grant no longer allows it, isolation, session closed).
    StreamTerminated {
        session_id: String,
        stream: u64,
        destination: String,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        hostname: Option<String>,
        admitted_by: String,
        reason: String,
    },
    /// The session proxy refused a connection because a resource bound was reached (never a silent bypass).
    ProxyLimit {
        session_id: String,
        resource: String,
        limit: u64,
    },
    /// Ordinary-app inventory record (W10, `crate::inventory::InventoryEvent`): an observed connection or a
    /// counted loss. `coverage` is always `observe_only`: nothing here was enforced or decided.
    Inventory {
        coverage: String,
        record: serde_json::Value,
    },
    /// One connection decided by the session egress proxy (TCP inside a protected session). `attempt` is a
    /// moat-core FlowAttempt whose hostname evidence names its source (sni / connect_proxy / http_host); `decision`
    /// carries verdict, winning rule and profile. No payload is inspected beyond the first TLS record or HTTP header.
    /// Policy changed under local owner authority (a revision signed by a key trusted as `local-owner`), not
    /// distributed by the controller. The controller holds fleet distribution to this device until the owner resolves
    /// it (docs/fleet-sync.md); it is never adopted by recency. `digest` is `sha256:<policy digest>`.
    LocalChange {
        revision: u64,
        digest: String,
        broadening: bool,
        authorized_by: String,
    },
    Flow {
        attempt: serde_json::Value,
        decision: serde_json::Value,
        measurement_source: String,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        transfer: Option<serde_json::Value>,
    },
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub struct Record {
    pub seq: u64,
    pub device_id: String,
    pub boot_id: String,
    pub at: DateTime<Utc>,
    pub event: Event,
}

#[derive(Debug, Clone)]
pub struct SpoolConfig {
    pub dir: PathBuf,
    pub device_id: String,
    pub boot_id: String,
    /// Total bytes across all segments.
    pub max_bytes: u64,
    pub segment_bytes: u64,
}

pub struct Spool {
    cfg: SpoolConfig,
    next_seq: u64,
    /// Contiguous high-water acknowledged by the controller (durable in `ACKED_FILE`).
    acked_seq: u64,
    /// First sequence number lost in the current drop run, if any.
    dropped_from: Option<(u64, String)>,
    current: Option<(PathBuf, File, u64)>,
}

const CLEAN_MARKER: &str = "clean-shutdown";
/// Written by the sync agent: the controller's contiguous `acked_seq` (decimal).
pub const ACKED_FILE: &str = "acked";
/// moatd's own durable copy of the accepted high-water (the agent's file may be lowered or garbled; this is not).
const ACKED_ACCEPTED: &str = "acked.accepted";
pub const SYNC_STATE_FILE: &str = "sync-state.json";
pub const SYNC_STATE_SCHEMA: &str = "moat.spool_sync_state.v1";

/// What the endpoint tells the controller about its spool on every sync (docs/fleet-sync.md).
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub struct SyncState {
    pub schema: String,
    pub device_id: String,
    pub boot_id: String,
    /// Lowest sequence still held. Records below it were acknowledged or are covered by a `gap` record.
    pub spool_low_seq: u64,
    pub acked_seq: u64,
    pub next_seq: u64,
    pub local_change: Option<LocalChangeReport>,
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub struct LocalChangeReport {
    pub revision: u64,
    pub digest: String,
    pub broadening: bool,
    pub authorized_by: String,
}

fn first_seq_in(path: &Path) -> Option<u64> {
    let f = File::open(path).ok()?;
    BufReader::new(f).lines().map_while(Result::ok).find_map(|l| serde_json::from_str::<Record>(&l).ok().map(|r| r.seq))
}

fn write_atomic(path: &Path, bytes: &[u8]) -> std::io::Result<()> {
    let tmp = path.with_extension("tmp");
    {
        let mut f = File::create(&tmp)?;
        f.write_all(bytes)?;
        f.sync_all()?;
    }
    fs::rename(tmp, path)
}

fn segments(dir: &Path) -> Vec<(u64, PathBuf)> {
    let mut v: Vec<(u64, PathBuf)> = fs::read_dir(dir)
        .into_iter()
        .flatten()
        .flatten()
        .filter_map(|e| {
            let n = e.file_name().to_string_lossy().to_string();
            let seq = n.strip_prefix("seg-")?.strip_suffix(".jsonl")?.parse().ok()?;
            Some((seq, e.path()))
        })
        .collect();
    v.sort();
    v
}

fn last_seq_in(path: &Path) -> Option<u64> {
    let f = File::open(path).ok()?;
    let mut last = None;
    for line in BufReader::new(f).lines().map_while(Result::ok) {
        // A torn final line after a crash is ignored, not fatal.
        if let Ok(r) = serde_json::from_str::<Record>(&line) {
            last = Some(r.seq);
        }
    }
    last
}

impl Spool {
    pub fn open(cfg: SpoolConfig) -> std::io::Result<Spool> {
        fs::create_dir_all(&cfg.dir)?;
        let segs = segments(&cfg.dir);
        let previous_seq = segs.iter().rev().find_map(|(_, p)| last_seq_in(p));
        let clean = cfg.dir.join(CLEAN_MARKER);
        let clean_shutdown = previous_seq.is_none() || clean.exists();
        let _ = fs::remove_file(&clean);
        let next_seq = previous_seq.map(|x| x + 1).unwrap_or(1);
        let acked_seq = fs::read_to_string(cfg.dir.join(ACKED_ACCEPTED))
            .ok()
            .and_then(|t| t.trim().parse::<u64>().ok())
            .unwrap_or(0)
            .min(next_seq.saturating_sub(1));
        let mut s = Spool { next_seq, acked_seq, cfg, dropped_from: None, current: None };
        let boot_id = s.cfg.boot_id.clone();
        s.append(Event::Restart { boot_id, previous_seq, clean_shutdown, version: env!("CARGO_PKG_VERSION").into() });
        Ok(s)
    }

    pub fn next_seq(&self) -> u64 {
        self.next_seq
    }

    fn total_bytes(&self) -> u64 {
        segments(&self.cfg.dir).iter().filter_map(|(_, p)| fs::metadata(p).ok()).map(|m| m.len()).sum()
    }

    fn write_line(&mut self, line: &str, seq: u64) -> std::io::Result<()> {
        let need_new = match &self.current {
            None => true,
            Some((_, _, size)) => *size + line.len() as u64 > self.cfg.segment_bytes,
        };
        if need_new {
            let path = self.cfg.dir.join(format!("seg-{seq:020}.jsonl"));
            let f = OpenOptions::new().create(true).append(true).open(&path)?;
            let size = f.metadata()?.len();
            self.current = Some((path, f, size));
        }
        let (_, f, size) = self.current.as_mut().unwrap();
        f.write_all(line.as_bytes())?;
        f.flush()?;
        *size += line.len() as u64;
        Ok(())
    }

    fn line_for(&self, ev: &Event) -> Result<(u64, String), String> {
        let seq = self.next_seq;
        let rec =
            Record { seq, device_id: self.cfg.device_id.clone(), boot_id: self.cfg.boot_id.clone(), at: Utc::now(), event: ev.clone() };
        Ok((seq, serde_json::to_string(&rec).map_err(|e| e.to_string())? + "\n"))
    }

    fn try_write(&mut self, ev: Event) -> Result<u64, String> {
        let (_, probe) = self.line_for(&ev)?;
        // Leave headroom for the sequence number growing by a few digits if eviction writes a gap first.
        let need = probe.len() as u64 + 8;
        if self.total_bytes() + need > self.cfg.max_bytes {
            self.make_room(need);
        }
        // Built after making room: an eviction gap takes the next sequence number.
        let (seq, line) = self.line_for(&ev)?;
        if self.total_bytes() + line.len() as u64 > self.cfg.max_bytes {
            return Err("spool disk quota reached".into());
        }
        self.write_line(&line, seq).map_err(|e| format!("spool write failed: {e}"))?;
        self.next_seq += 1;
        Ok(seq)
    }

    /// Append an event. Never blocks enforcement: on failure the event is counted as lost and a gap record is
    /// written as soon as space returns. Returns the sequence number, or None if the event was dropped.
    pub fn append(&mut self, ev: Event) -> Option<u64> {
        if let Some((from, reason)) = self.dropped_from.clone() {
            let to = self.next_seq - 1;
            // Reserve the gap's own sequence numbers: the lost range is from..=to.
            match self.try_write(Event::Gap { from, to, reason }) {
                Ok(_) => self.dropped_from = None,
                Err(_) => {
                    self.next_seq += 1; // this event is lost too
                    return None;
                }
            }
        }
        match self.try_write(ev) {
            Ok(s) => Some(s),
            Err(reason) => {
                self.dropped_from = Some((self.next_seq, reason));
                self.next_seq += 1;
                None
            }
        }
    }

    /// Records with seq > `after`, oldest first, at most `limit`.
    pub fn read_after(&self, after: u64, limit: usize) -> Vec<Record> {
        let mut out = Vec::new();
        for (_, p) in segments(&self.cfg.dir) {
            let Ok(f) = File::open(&p) else { continue };
            for line in BufReader::new(f).lines().map_while(Result::ok) {
                if let Ok(r) = serde_json::from_str::<Record>(&line) {
                    if r.seq > after {
                        out.push(r);
                        if out.len() >= limit {
                            return out;
                        }
                    }
                }
            }
        }
        out
    }

    /// The controller acknowledged everything up to `seq` (contiguous high-water): delete whole segments that are
    /// fully acknowledged. A value beyond the last sequence written is refused (the controller cannot have stored
    /// it); a lower value than one already accepted is ignored (acknowledgement never moves backwards).
    pub fn ack(&mut self, seq: u64) -> Result<(), String> {
        let last = self.next_seq.saturating_sub(1);
        if seq > last {
            return Err(format!("acknowledgement {seq} is beyond the last sequence written ({last}); ignored"));
        }
        if seq > self.acked_seq {
            write_atomic(&self.cfg.dir.join(ACKED_ACCEPTED), seq.to_string().as_bytes())
                .map_err(|e| format!("acknowledgement not durable: {e}"))?;
            self.acked_seq = seq;
        }
        self.remove_acked_segments();
        Ok(())
    }

    fn remove_acked_segments(&mut self) {
        let segs = segments(&self.cfg.dir);
        for (i, (_, p)) in segs.iter().enumerate() {
            let Some((next_first, _)) = segs.get(i + 1) else { break };
            if *next_first <= self.acked_seq + 1 && self.current.as_ref().map(|c| &c.0 != p).unwrap_or(true) {
                let _ = fs::remove_file(p);
            }
        }
    }

    /// Read `<spool>/acked` (the sync agent's copy of the controller's `acked_seq`) and accept it if valid.
    /// Returns an error description for a refused value, so the daemon can report it once.
    pub fn consume_ack_file(&mut self) -> Option<String> {
        let t = fs::read_to_string(self.cfg.dir.join(ACKED_FILE)).ok()?;
        match t.trim().parse::<u64>() {
            Ok(seq) => self.ack(seq).err(),
            Err(_) => Some(format!("{ACKED_FILE} is not a sequence number; ignored")),
        }
    }

    pub fn acked_seq(&self) -> u64 {
        self.acked_seq
    }

    /// Lowest sequence still held on disk (the next one to be written when the spool is empty).
    pub fn low_seq(&self) -> u64 {
        segments(&self.cfg.dir).iter().find_map(|(_, p)| first_seq_in(p)).unwrap_or(self.next_seq)
    }

    /// Free room for `need` more bytes: acknowledged segments first; then the oldest unacknowledged segment, with a
    /// gap record for exactly the unacknowledged sequences it held. Never the segment being written.
    fn make_room(&mut self, need: u64) {
        self.remove_acked_segments();
        loop {
            if self.total_bytes() + need <= self.cfg.max_bytes {
                return;
            }
            let segs = segments(&self.cfg.dir);
            let Some((_, oldest)) = segs.iter().find(|(_, p)| self.current.as_ref().map(|c| &c.0 != p).unwrap_or(true)) else {
                return;
            };
            let (Some(first), Some(last)) = (first_seq_in(oldest), last_seq_in(oldest)) else {
                let _ = fs::remove_file(oldest); // no readable record: nothing to lose
                continue;
            };
            if fs::remove_file(oldest).is_err() {
                return;
            }
            let from = first.max(self.acked_seq + 1);
            if from <= last {
                // Written straight away so the loss is recorded before anything newer; its own size is small and the
                // segment just removed was larger.
                let _ =
                    self.try_write_raw(Event::Gap { from, to: last, reason: "evicted before acknowledgement: spool disk quota".into() });
            }
        }
    }

    /// Write without making room (used for the eviction gap itself, so eviction cannot recurse).
    fn try_write_raw(&mut self, ev: Event) -> Result<u64, String> {
        let seq = self.next_seq;
        let rec = Record { seq, device_id: self.cfg.device_id.clone(), boot_id: self.cfg.boot_id.clone(), at: Utc::now(), event: ev };
        let line = serde_json::to_string(&rec).map_err(|e| e.to_string())? + "\n";
        self.write_line(&line, seq).map_err(|e| format!("spool write failed: {e}"))?;
        self.next_seq += 1;
        Ok(seq)
    }

    /// The fields the sync body carries (docs/fleet-sync.md).
    pub fn sync_state(&self, local_change: Option<LocalChangeReport>) -> SyncState {
        SyncState {
            schema: SYNC_STATE_SCHEMA.into(),
            device_id: self.cfg.device_id.clone(),
            boot_id: self.cfg.boot_id.clone(),
            spool_low_seq: self.low_seq(),
            acked_seq: self.acked_seq,
            next_seq: self.next_seq,
            local_change,
        }
    }

    /// Publish `sync-state.json` atomically for the sync agent.
    pub fn write_sync_state(&self, local_change: Option<LocalChangeReport>) -> std::io::Result<()> {
        let st = self.sync_state(local_change);
        write_atomic(&self.cfg.dir.join(SYNC_STATE_FILE), &serde_json::to_vec_pretty(&st).unwrap())
    }

    /// Record a clean shutdown without consuming the spool (signal handlers).
    pub fn mark_clean(&self) {
        let _ = File::create(self.cfg.dir.join(CLEAN_MARKER));
    }

    pub fn close(mut self) {
        self.current = None;
        let _ = File::create(self.cfg.dir.join(CLEAN_MARKER));
    }
}

/// Verify a contiguous record stream; returns the missing ranges that no gap record explains.
pub fn unexplained_gaps(records: &[Record]) -> Vec<(u64, u64)> {
    let mut out = Vec::new();
    let mut explained: Vec<(u64, u64)> = Vec::new();
    for r in records {
        if let Event::Gap { from, to, .. } = r.event {
            explained.push((from, to));
        }
    }
    for w in records.windows(2) {
        let (a, b) = (w[0].seq, w[1].seq);
        if b > a + 1 {
            let (from, to) = (a + 1, b - 1);
            let covered = (from..=to).all(|s| explained.iter().any(|(f, t)| s >= *f && s <= *t) || s == b);
            if !covered {
                out.push((from, to));
            }
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cfg(dir: &Path, max: u64) -> SpoolConfig {
        SpoolConfig { dir: dir.into(), device_id: "omarchy".into(), boot_id: "b1".into(), max_bytes: max, segment_bytes: 600 }
    }

    #[test]
    fn sequence_restart_and_clean_shutdown() {
        let d = tempfile::tempdir().unwrap();
        let mut s = Spool::open(cfg(d.path(), 1 << 20)).unwrap();
        s.append(Event::CoverageChanged { level: "active".into(), detail: "x".into() });
        s.close();
        let mut s = Spool::open(cfg(d.path(), 1 << 20)).unwrap();
        let recs = s.read_after(0, 100);
        assert_eq!(recs.iter().map(|r| r.seq).collect::<Vec<_>>(), vec![1, 2, 3]);
        match &recs[2].event {
            Event::Restart { previous_seq, clean_shutdown, .. } => {
                assert_eq!(*previous_seq, Some(2));
                assert!(*clean_shutdown);
            }
            e => panic!("{e:?}"),
        }
        // simulate a crash: no close()
        s.append(Event::CoverageChanged { level: "active".into(), detail: "y".into() });
        drop(s);
        let s = Spool::open(cfg(d.path(), 1 << 20)).unwrap();
        let last = s.read_after(0, 100).pop().unwrap();
        assert!(matches!(last.event, Event::Restart { clean_shutdown: false, previous_seq: Some(4), .. }));
    }

    fn rc(i: usize) -> Event {
        Event::RuleCounter { rule: format!("r{i}"), packets: 1, bytes: 60, scope: "rule".into() }
    }

    fn held(d: &Path) -> Vec<Record> {
        let s = Spool { cfg: cfg(d, 1 << 20), next_seq: 0, acked_seq: 0, dropped_from: None, current: None };
        s.read_after(0, 100_000)
    }

    /// The sync contract: every sequence from `spool_low_seq` up to the last written is held or covered by a held
    /// gap record; nothing goes missing silently.
    fn assert_contract(d: &Path, s: &Spool) {
        let recs = held(d);
        let low = s.low_seq();
        let gaps: Vec<(u64, u64)> =
            recs.iter().filter_map(|r| if let Event::Gap { from, to, .. } = r.event { Some((from, to)) } else { None }).collect();
        for seq in low..s.next_seq() {
            let present = recs.iter().any(|r| r.seq == seq);
            let explained = gaps.iter().any(|(f, t)| seq >= *f && seq <= *t);
            assert!(present || explained, "seq {seq} (low {low}) neither held nor covered by a gap");
        }
        assert!(unexplained_gaps(&recs).is_empty(), "{:?}", unexplained_gaps(&recs));
    }

    #[test]
    fn quota_evicts_the_oldest_unacknowledged_segment_with_an_exact_gap() {
        let d = tempfile::tempdir().unwrap();
        let mut s = Spool::open(cfg(d.path(), 1400)).unwrap();
        for i in 0..40 {
            assert!(s.append(rc(i)).is_some(), "eviction makes room; the newest evidence is kept");
            assert!(s.total_bytes() <= 1400, "disk use stays bounded ({} bytes)", s.total_bytes());
            assert_contract(d.path(), &s);
        }
        assert!(s.low_seq() > 1, "older records were evicted");
        let recs = held(d.path());
        let gap =
            recs.iter()
                .find_map(|r| if let Event::Gap { from, to, reason } = &r.event { Some((*from, *to, reason.clone())) } else { None });
        let (from, to, reason) = gap.expect("an eviction leaves a gap record");
        assert!(reason.contains("evicted before acknowledgement"), "{reason}");
        assert!(from >= 1 && from <= to);
        // the newest event is the last record held
        assert!(matches!(&recs.last().unwrap().event, Event::RuleCounter { rule, .. } if rule == "r39"));
    }

    #[test]
    fn acknowledged_segments_go_first_and_need_no_gap() {
        let d = tempfile::tempdir().unwrap();
        let mut s = Spool::open(cfg(d.path(), 1400)).unwrap();
        for i in 0..4 {
            s.append(rc(i));
        }
        let last = s.next_seq() - 1;
        s.ack(last).unwrap();
        for i in 4..9 {
            assert!(s.append(rc(i)).is_some());
        }
        assert!(s.total_bytes() <= 1400);
        // nothing unacknowledged was lost: no gap record anywhere, and low_seq never passes an unacknowledged record
        assert!(held(d.path()).iter().all(|r| !matches!(r.event, Event::Gap { .. })));
        assert!(s.low_seq() <= last + 1);
        assert_contract(d.path(), &s);
    }

    #[test]
    fn acknowledgement_is_durable_monotonic_and_bounded() {
        let d = tempfile::tempdir().unwrap();
        let mut s = Spool::open(cfg(d.path(), 1 << 20)).unwrap();
        for i in 0..5 {
            s.append(rc(i));
        }
        s.ack(4).unwrap();
        assert_eq!(s.acked_seq(), 4);
        s.ack(2).unwrap();
        assert_eq!(s.acked_seq(), 4, "acknowledgement never moves backwards");
        assert!(s.ack(10_000).is_err(), "the controller cannot have stored what was never written");
        assert_eq!(s.acked_seq(), 4);
        // the agent's file: garbage is refused, a valid value is accepted
        fs::write(d.path().join(ACKED_FILE), "not-a-number").unwrap();
        assert!(s.consume_ack_file().is_some());
        fs::write(d.path().join(ACKED_FILE), "5\n").unwrap();
        assert!(s.consume_ack_file().is_none());
        assert_eq!(s.acked_seq(), 5);
        s.close();
        // durable across a restart, and the agent lowering its file later changes nothing
        let mut s = Spool::open(cfg(d.path(), 1 << 20)).unwrap();
        assert_eq!(s.acked_seq(), 5);
        fs::write(d.path().join(ACKED_FILE), "1").unwrap();
        s.consume_ack_file();
        assert_eq!(s.acked_seq(), 5);
    }

    #[test]
    fn an_event_that_cannot_fit_is_dropped_with_a_gap() {
        let d = tempfile::tempdir().unwrap();
        let mut s = Spool::open(cfg(d.path(), 1400)).unwrap();
        let huge = Event::CoverageChanged { level: "x".into(), detail: "y".repeat(5000) };
        let lost = s.next_seq();
        assert!(s.append(huge).is_none());
        let seq = s.append(Event::CoverageChanged { level: "active".into(), detail: "back".into() }).unwrap();
        let recs = held(d.path());
        let gap = recs.iter().find(|r| matches!(r.event, Event::Gap { .. })).expect("gap record");
        if let Event::Gap { from, to, reason } = &gap.event {
            assert_eq!((*from, *to), (lost, lost));
            assert!(reason.contains("quota"));
            assert_eq!(seq, gap.seq + 1);
        }
        assert_contract(d.path(), &s);
    }

    #[test]
    fn sync_state_carries_low_seq_ack_and_local_change() {
        let d = tempfile::tempdir().unwrap();
        let mut s = Spool::open(cfg(d.path(), 1 << 20)).unwrap();
        s.append(rc(1));
        s.ack(1).unwrap();
        let lc = LocalChangeReport {
            revision: 9,
            digest: format!("sha256:{}", "a".repeat(64)),
            broadening: true,
            authorized_by: "local-owner:k".into(),
        };
        s.write_sync_state(Some(lc.clone())).unwrap();
        let st: SyncState = serde_json::from_slice(&fs::read(d.path().join(SYNC_STATE_FILE)).unwrap()).unwrap();
        assert_eq!(st.schema, SYNC_STATE_SCHEMA);
        assert_eq!(st.spool_low_seq, 1);
        assert_eq!(st.acked_seq, 1);
        assert_eq!(st.next_seq, 3);
        assert_eq!(st.local_change, Some(lc));
    }

    #[test]
    fn unexplained_gap_detection() {
        let mk = |seq: u64, event: Event| Record { seq, device_id: "d".into(), boot_id: "b".into(), at: Utc::now(), event };
        let ok = vec![
            mk(1, Event::CoverageChanged { level: "a".into(), detail: "".into() }),
            mk(5, Event::Gap { from: 2, to: 4, reason: "quota".into() }),
            mk(6, Event::CoverageChanged { level: "a".into(), detail: "".into() }),
        ];
        assert!(unexplained_gaps(&ok).is_empty());
        let bad = vec![ok[0].clone(), ok[2].clone()];
        assert_eq!(unexplained_gaps(&bad), vec![(2, 5)]);
    }

    #[test]
    fn torn_last_line_is_tolerated() {
        let d = tempfile::tempdir().unwrap();
        let mut s = Spool::open(cfg(d.path(), 1 << 20)).unwrap();
        s.append(Event::CoverageChanged { level: "a".into(), detail: "".into() });
        let p = s.current.as_ref().unwrap().0.clone();
        drop(s);
        let mut f = OpenOptions::new().append(true).open(&p).unwrap();
        f.write_all(b"{\"seq\":99,\"trunc").unwrap();
        let s = Spool::open(cfg(d.path(), 1 << 20)).unwrap();
        let last = s.read_after(0, 100).pop().unwrap();
        assert_eq!(last.seq, 3);
    }
}
