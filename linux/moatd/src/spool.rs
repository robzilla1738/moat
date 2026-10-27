//! Device-side event spool.
//!
//! Append-only JSON-lines segments with a monotonic sequence number per device, a restart marker every time the
//! spool opens (saying whether the previous run shut down cleanly), and an explicit gap record whenever events were
//! dropped (disk quota, write error). Enforcement never depends on logging: a full spool drops events and says so;
//! it never blocks or loosens a decision.

use std::fs::{self, File, OpenOptions};
use std::io::{BufRead, BufReader, Write};
use std::path::{Path, PathBuf};

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum Event {
    /// Spool opened. `clean_shutdown` is false after a crash or power loss.
    Restart { boot_id: String, previous_seq: Option<u64>, clean_shutdown: bool, version: String },
    /// Events `from..=to` were lost. The UI must show this; completeness is never inferred.
    Gap { from: u64, to: u64, reason: String },
    CapabilityAdvertised { advertisement: serde_json::Value },
    PolicyApplied { revision: u64, rollback_of: Option<u64>, policy_digest: String, skipped_allows: Vec<String> },
    PolicyRejected { reason: String, kept_revision: Option<u64> },
    /// Rule-scoped counter delta. `scope` is always `rule`: nftables counters are not per flow.
    RuleCounter { rule: String, packets: u64, bytes: u64, scope: String },
    SessionStarted { session_id: String, profile: String, cgroup: String, uid: u32, root_pid: u32, root_start: u64, boundary: String },
    SessionLaunchRefused { profile: String, uid: u32, reason: String },
    SessionEnded { session_id: String, exit_code: Option<i32>, signal: Option<i32> },
    CoverageChanged { level: String, detail: String },
    EnforcementDisabledLocally { by_uid: u32, reason: String },
    EnforcementResumed { by_uid: u32 },
    LocalIsolation { active: bool, by_uid: u32 },
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
    /// First sequence number lost in the current drop run, if any.
    dropped_from: Option<(u64, String)>,
    current: Option<(PathBuf, File, u64)>,
}

const CLEAN_MARKER: &str = "clean-shutdown";

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
        let mut s = Spool { next_seq: previous_seq.map(|x| x + 1).unwrap_or(1), cfg, dropped_from: None, current: None };
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

    fn try_write(&mut self, ev: Event) -> Result<u64, String> {
        let seq = self.next_seq;
        let rec = Record { seq, device_id: self.cfg.device_id.clone(), boot_id: self.cfg.boot_id.clone(), at: Utc::now(), event: ev };
        let line = serde_json::to_string(&rec).map_err(|e| e.to_string())? + "\n";
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

    /// The controller acknowledged everything up to `seq`: delete whole segments that are fully acknowledged.
    pub fn ack(&mut self, seq: u64) {
        let segs = segments(&self.cfg.dir);
        for (i, (_, p)) in segs.iter().enumerate() {
            let Some((next_first, _)) = segs.get(i + 1) else { break };
            if *next_first <= seq + 1 && self.current.as_ref().map(|c| &c.0 != p).unwrap_or(true) {
                let _ = fs::remove_file(p);
            }
        }
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

    #[test]
    fn quota_drops_and_records_gap() {
        let d = tempfile::tempdir().unwrap();
        let mut s = Spool::open(cfg(d.path(), 1400)).unwrap();
        let mut dropped = 0;
        for i in 0..30 {
            if s.append(Event::RuleCounter { rule: format!("r{i}"), packets: 1, bytes: 60, scope: "rule".into() }).is_none() {
                dropped += 1;
            }
        }
        assert!(dropped > 0);
        let all = s.read_after(0, 1000);
        let acked = all.last().unwrap().seq;
        // the controller acks; segments free up; the next append writes a gap first
        s.ack(acked);
        let before = s.read_after(acked, 10).len();
        assert_eq!(before, 0);
        // free everything older (ack removes non-current segments only)
        for (_, p) in segments(d.path()) {
            if s.current.as_ref().map(|c| c.0 != p).unwrap_or(true) {
                let _ = fs::remove_file(p);
            }
        }
        if let Some((_, f, _)) = s.current.as_mut() {
            f.set_len(0).unwrap();
        }
        s.current.as_mut().unwrap().2 = 0;
        let seq = s.append(Event::CoverageChanged { level: "active".into(), detail: "back".into() }).unwrap();
        let recs = s.read_after(0, 1000);
        let gap = recs.iter().find(|r| matches!(r.event, Event::Gap { .. })).expect("gap record");
        if let Event::Gap { from, to, reason } = &gap.event {
            assert!(from <= to);
            assert_eq!(*to + 1, gap.seq);
            assert!(reason.contains("quota"));
            assert_eq!(seq, gap.seq + 1);
        }
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
