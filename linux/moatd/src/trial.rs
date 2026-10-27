//! Timed trial (canary) revisions on Linux, matching the macOS policy store.
//!
//! * `moatd apply --trial-secs N` installs a verified revision on trial. Unless it is confirmed before the deadline
//!   (`moatd recover confirm`, root, on the device), the daemon reinstalls the last confirmed revision.
//! * A trial needs a confirmed revision to fall back to. The first policy on a device cannot be a trial: reverting
//!   to "no policy" would remove enforcement, which is weaker, so it is refused instead.
//! * Rollback reinstalls the stored last-good snapshot (signature re-verified). The replay high-water mark stays at
//!   the trial revision, so the reverted revision cannot be replayed from the network.
//! * Rollback never touches local isolation or the local disable switch.
//! * The deadline is enforced by the running daemon. If `moatd` is stopped past the deadline, the trial revision
//!   stays in the kernel until the daemon starts again, and is reverted on that start.

use std::fs;
use std::path::Path;

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

pub const FILE: &str = "trial.json";
pub const LAST_GOOD: &str = "lastgood.signed.json";
pub const REPLAY_MARK: &str = "replay-mark";

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
pub struct TrialState {
    pub revision: u64,
    pub fallback_revision: u64,
    pub started_at: DateTime<Utc>,
    pub deadline: DateTime<Utc>,
    /// Set by `moatd recover confirm`; the daemon then ends the trial and keeps the revision.
    #[serde(default)]
    pub confirmed: bool,
    /// Set by `moatd recover rollback`; the daemon reverts on its next tick.
    #[serde(default)]
    pub revert_now: bool,
    #[serde(default)]
    pub changed_by_uid: Option<u32>,
}

impl TrialState {
    pub fn load(dir: &Path) -> Option<TrialState> {
        fs::read_to_string(dir.join(FILE)).ok().and_then(|s| serde_json::from_str(&s).ok())
    }

    pub fn save(&self, dir: &Path) -> std::io::Result<()> {
        let tmp = dir.join(format!("{FILE}.tmp"));
        fs::write(&tmp, serde_json::to_vec_pretty(self).unwrap())?;
        fs::rename(tmp, dir.join(FILE))
    }

    pub fn clear(dir: &Path) {
        let _ = fs::remove_file(dir.join(FILE));
    }

    pub fn due(&self, now: DateTime<Utc>) -> bool {
        !self.confirmed && (self.revert_now || self.deadline <= now)
    }
}

pub fn load_replay_mark(dir: &Path) -> Option<u64> {
    fs::read_to_string(dir.join(REPLAY_MARK)).ok().and_then(|s| s.trim().parse().ok())
}

pub fn save_replay_mark(dir: &Path, rev: u64) -> std::io::Result<()> {
    let tmp = dir.join(format!("{REPLAY_MARK}.tmp"));
    fs::write(&tmp, rev.to_string())?;
    fs::rename(tmp, dir.join(REPLAY_MARK))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrip_and_due() {
        let d = tempfile::tempdir().unwrap();
        assert!(TrialState::load(d.path()).is_none());
        let now = Utc::now();
        let t = TrialState {
            revision: 4,
            fallback_revision: 3,
            started_at: now,
            deadline: now + chrono::Duration::seconds(60),
            confirmed: false,
            revert_now: false,
            changed_by_uid: None,
        };
        t.save(d.path()).unwrap();
        assert_eq!(TrialState::load(d.path()), Some(t.clone()));
        assert!(!t.due(now));
        assert!(t.due(now + chrono::Duration::seconds(61)));
        assert!(TrialState { revert_now: true, ..t.clone() }.due(now));
        assert!(!TrialState { confirmed: true, ..t.clone() }.due(now + chrono::Duration::seconds(61)));
        save_replay_mark(d.path(), 9).unwrap();
        assert_eq!(load_replay_mark(d.path()), Some(9));
        TrialState::clear(d.path());
        assert!(TrialState::load(d.path()).is_none());
    }
}
