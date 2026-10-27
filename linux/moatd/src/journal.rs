//! Durable activation journal for the Linux endpoint (W06, MASTER_ROADMAP §7.1).
//!
//! Disk and kernel updates cannot be one atomic transaction, so every activation is a sequence of steps, and the
//! journal records, durably and *before* each step that changes what is enforced, what the endpoint is trying to do.
//! On restart the daemon reconciles from the journal instead of guessing:
//!
//! | Step (offer)                              | Crash/failure here leaves                    | Startup / immediate outcome            |
//! |-------------------------------------------|----------------------------------------------|----------------------------------------|
//! | 1. journal `applying {target, prior}`     | prior intact                                 | rejected; prior stays                  |
//! | 2. replay high-water raised (own file)    | high-water may be raised; prior intact       | rejected; prior stays (revision burnt) |
//! | 3. candidate staged; rollback target and  | prior intact                                 | rejected; prior stays                  |
//! |    trial deadline written (trial only)    |                                              |                                        |
//! | 4. kernel install                         | kernel uncertain                             | prior reinstalled from `current`       |
//! | 5. commit: candidate renamed to `current` | kernel has target, disk says prior           | kernel restored to prior; or recovery  |
//! | 6. journal `trial` / `confirmed`          | everything durable except the phase          | completed from `current` on startup    |
//!
//! Rollback of an unconfirmed trial writes `rollback_required {from, to}` **before** touching the kernel and keeps it
//! (and the trial file) until the fallback is both installed and durable as `current`. A failed rollback is retried
//! on every tick and stays visible; it never becomes a silent "confirmed".
//!
//! The replay high-water mark is independent of the active revision: it is stored in its own file *and* in the
//! journal, startup takes the maximum of every readable copy, and rollback never lowers it.
//!
//! Every write is temp file + fsync + rename + directory fsync, through [`Store`] so tests can inject disk-full,
//! failed-rename, corrupt-write and crash faults at each step.

use std::fs::{self, File, OpenOptions};
use std::io::{self, Write};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

pub const FILE: &str = "activation.json";
pub const CANDIDATE: &str = "candidate.signed.json";
pub const SCHEMA: &str = "moatd.activation_journal.v1";

/// Phases use the `moat.activation.v1` vocabulary (contracts/schemas).
#[derive(Serialize, Deserialize, Clone, Copy, Debug, PartialEq, Eq, Default)]
#[serde(rename_all = "snake_case")]
pub enum Phase {
    /// No revision has ever been activated.
    #[default]
    None,
    /// An activation of `target` is in progress (durable intent written, not yet committed).
    Applying,
    /// `active` is on trial and reverts to `rollback_target` at `trial_deadline` unless confirmed.
    Trial,
    /// `active` is the confirmed revision.
    Confirmed,
    /// `rollback_target` must be reinstalled; retained until restoration is durable.
    RollbackRequired,
    /// State could not be reconciled automatically; see `detail`. Enforcement keeps the last verified state the
    /// endpoint could load and never falls back to a fresh permissive bootstrap.
    RecoveryRequired,
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
pub struct Journal {
    pub schema: String,
    pub phase: Phase,
    /// The revision believed enforced after the last completed step.
    #[serde(default)]
    pub active: Option<u64>,
    /// `applying`: the revision being activated.
    #[serde(default)]
    pub target: Option<u64>,
    /// `applying`: the revision active before it (None = none).
    #[serde(default)]
    pub prior: Option<u64>,
    /// `trial` / `rollback_required`: the confirmed revision to restore.
    #[serde(default)]
    pub rollback_target: Option<u64>,
    #[serde(default)]
    pub trial_deadline: Option<DateTime<Utc>>,
    /// `applying`: the trial that was pending before this activation, restored if the activation is interrupted.
    #[serde(default)]
    pub prior_trial: Option<crate::trial::TrialState>,
    /// Highest revision ever accepted for activation. Never lowered.
    pub replay_high_water: u64,
    #[serde(default)]
    pub detail: Option<String>,
    pub updated_at: DateTime<Utc>,
}

impl Default for Journal {
    fn default() -> Self {
        Journal {
            schema: SCHEMA.into(),
            phase: Phase::None,
            active: None,
            target: None,
            prior: None,
            rollback_target: None,
            trial_deadline: None,
            prior_trial: None,
            replay_high_water: 0,
            detail: None,
            updated_at: Utc::now(),
        }
    }
}

/// What reading the journal found.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Loaded {
    Missing,
    Ok(Journal),
    /// Present but unreadable or not a journal: reported, never treated as "no state".
    Corrupt(String),
}

impl Journal {
    pub fn load(dir: &Path) -> Loaded {
        match fs::read(dir.join(FILE)) {
            Err(e) if e.kind() == io::ErrorKind::NotFound => Loaded::Missing,
            Err(e) => Loaded::Corrupt(format!("activation journal unreadable: {e}")),
            Ok(b) => match serde_json::from_slice::<Journal>(&b) {
                Ok(j) if j.schema == SCHEMA => Loaded::Ok(j),
                Ok(j) => Loaded::Corrupt(format!("activation journal has unknown schema {}", j.schema)),
                Err(e) => Loaded::Corrupt(format!("activation journal corrupt: {e}")),
            },
        }
    }

    pub fn save(&mut self, store: &mut dyn Store, dir: &Path) -> io::Result<()> {
        self.updated_at = Utc::now();
        store.write_atomic(dir, FILE, &serde_json::to_vec_pretty(self).unwrap())
    }
}

/// Durable file operations. All writes are atomic replacements.
pub trait Store: Send {
    fn write_atomic(&mut self, dir: &Path, name: &str, bytes: &[u8]) -> io::Result<()>;
    fn remove(&mut self, dir: &Path, name: &str) -> io::Result<()>;
    fn copy_atomic(&mut self, dir: &Path, from: &str, to: &str) -> io::Result<()> {
        let b = fs::read(dir.join(from))?;
        self.write_atomic(dir, to, &b)
    }
}

fn fsync_dir(dir: &Path) -> io::Result<()> {
    File::open(dir)?.sync_all()
}

/// The real filesystem: temp + fsync + rename + directory fsync.
#[derive(Default)]
pub struct FsStore;

impl Store for FsStore {
    fn write_atomic(&mut self, dir: &Path, name: &str, bytes: &[u8]) -> io::Result<()> {
        let tmp: PathBuf = dir.join(format!("{name}.tmp"));
        {
            let mut f = OpenOptions::new().write(true).create(true).truncate(true).open(&tmp)?;
            f.write_all(bytes)?;
            f.sync_all()?;
        }
        if let Err(e) = fs::rename(&tmp, dir.join(name)) {
            let _ = fs::remove_file(&tmp);
            return Err(e);
        }
        fsync_dir(dir)
    }

    fn remove(&mut self, dir: &Path, name: &str) -> io::Result<()> {
        match fs::remove_file(dir.join(name)) {
            Ok(()) => fsync_dir(dir),
            Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(()),
            Err(e) => Err(e),
        }
    }
}

/// A fault to inject at the n-th matching operation on a named file.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FaultKind {
    /// ENOSPC while writing the temp file; the target is untouched.
    DiskFull,
    /// The temp file is written but the rename fails (EIO); the target is untouched.
    RenameFails,
    /// The process dies before the operation: nothing from here on happens (shared crash flag).
    Crash,
    /// The write "succeeds" but the file holds garbage (torn write on a filesystem without the guarantees).
    Corrupt,
}

#[derive(Debug, Clone)]
pub struct Fault {
    pub file: String,
    pub kind: FaultKind,
    /// Skip this many matching operations first.
    pub skip: usize,
}

/// Fault-injecting store for tests. After a `Crash` fault fires, every later operation fails, and the shared
/// `crashed` flag lets a fake kernel backend refuse further changes too.
pub struct FaultStore {
    pub inner: FsStore,
    pub faults: Vec<Fault>,
    pub crashed: Arc<AtomicBool>,
    pub log: Vec<String>,
}

impl FaultStore {
    pub fn new(crashed: Arc<AtomicBool>) -> Self {
        FaultStore { inner: FsStore, faults: Vec::new(), crashed, log: Vec::new() }
    }

    fn check(&mut self, op: &str, name: &str) -> io::Result<Option<FaultKind>> {
        if self.crashed.load(Ordering::SeqCst) {
            return Err(io::Error::other("process crashed"));
        }
        self.log.push(format!("{op} {name}"));
        let Some(i) = self.faults.iter().position(|f| f.file == name) else { return Ok(None) };
        if self.faults[i].skip > 0 {
            self.faults[i].skip -= 1;
            return Ok(None);
        }
        let f = self.faults.remove(i);
        if f.kind == FaultKind::Crash {
            self.crashed.store(true, Ordering::SeqCst);
            return Err(io::Error::other("process crashed"));
        }
        Ok(Some(f.kind))
    }
}

impl Store for FaultStore {
    fn write_atomic(&mut self, dir: &Path, name: &str, bytes: &[u8]) -> io::Result<()> {
        match self.check("write", name)? {
            None => self.inner.write_atomic(dir, name, bytes),
            Some(FaultKind::DiskFull) => Err(io::Error::from_raw_os_error(libc::ENOSPC)),
            Some(FaultKind::RenameFails) => {
                fs::write(dir.join(format!("{name}.tmp")), bytes)?;
                Err(io::Error::from_raw_os_error(libc::EIO))
            }
            Some(FaultKind::Corrupt) => self.inner.write_atomic(dir, name, &bytes[..bytes.len() / 2]),
            Some(FaultKind::Crash) => unreachable!(),
        }
    }

    fn remove(&mut self, dir: &Path, name: &str) -> io::Result<()> {
        match self.check("remove", name)? {
            None | Some(FaultKind::Corrupt) => self.inner.remove(dir, name),
            Some(_) => Err(io::Error::from_raw_os_error(libc::EIO)),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrip_missing_and_corrupt() {
        let d = tempfile::tempdir().unwrap();
        assert_eq!(Journal::load(d.path()), Loaded::Missing);
        let mut j = Journal { phase: Phase::Trial, active: Some(4), rollback_target: Some(3), replay_high_water: 4, ..Journal::default() };
        j.save(&mut FsStore, d.path()).unwrap();
        assert_eq!(Journal::load(d.path()), Loaded::Ok(j));
        fs::write(d.path().join(FILE), b"{\"schema\":").unwrap();
        assert!(matches!(Journal::load(d.path()), Loaded::Corrupt(_)));
    }

    #[test]
    fn faults_leave_the_previous_file_in_place() {
        let d = tempfile::tempdir().unwrap();
        let crashed = Arc::new(AtomicBool::new(false));
        let mut s = FaultStore::new(crashed.clone());
        s.write_atomic(d.path(), "x", b"one").unwrap();
        for kind in [FaultKind::DiskFull, FaultKind::RenameFails] {
            s.faults.push(Fault { file: "x".into(), kind, skip: 0 });
            assert!(s.write_atomic(d.path(), "x", b"two").is_err());
            assert_eq!(fs::read(d.path().join("x")).unwrap(), b"one");
        }
        s.faults.push(Fault { file: "x".into(), kind: FaultKind::Crash, skip: 1 });
        s.write_atomic(d.path(), "x", b"three").unwrap();
        assert!(s.write_atomic(d.path(), "x", b"four").is_err());
        assert!(crashed.load(Ordering::SeqCst));
        assert!(s.write_atomic(d.path(), "y", b"after").is_err(), "nothing happens after a crash");
        assert_eq!(fs::read(d.path().join("x")).unwrap(), b"three");
    }
}
