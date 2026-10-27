//! Local recovery state. Written by `moatd recover …` (root, on the device) and reconciled by the daemon.
//!
//! * Disabling enforcement removes the Moat table and keeps it removed until a local `resume`; protected sessions
//!   are refused meanwhile (their boundary would not exist).
//! * Local isolation is a separate whole-device table with only the chosen recovery paths. It does not reopen when a
//!   controller heartbeat disappears, when a new policy arrives or when the daemon restarts; only a local
//!   `clear-isolation` removes it.

use std::fs;
use std::path::Path;

use chrono::{DateTime, Utc};
use ipnet::IpNet;
use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq, Default)]
pub struct Isolation {
    pub active: bool,
    #[serde(default)]
    pub keep: Vec<IpNet>,
    pub since: Option<DateTime<Utc>>,
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq, Default)]
pub struct RecoveryState {
    pub enforcement_disabled: bool,
    #[serde(default)]
    pub reason: Option<String>,
    #[serde(default)]
    pub changed_by_uid: Option<u32>,
    #[serde(default)]
    pub changed_at: Option<DateTime<Utc>>,
    #[serde(default)]
    pub isolation: Isolation,
}

pub const FILE: &str = "recovery.json";

impl RecoveryState {
    pub fn load(dir: &Path) -> RecoveryState {
        fs::read_to_string(dir.join(FILE)).ok().and_then(|s| serde_json::from_str(&s).ok()).unwrap_or_default()
    }

    /// Atomic write (temp + rename).
    pub fn save(&self, dir: &Path) -> std::io::Result<()> {
        fs::create_dir_all(dir)?;
        let tmp = dir.join(format!("{FILE}.tmp"));
        fs::write(&tmp, serde_json::to_vec_pretty(self).unwrap())?;
        fs::rename(tmp, dir.join(FILE))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrip_and_default() {
        let d = tempfile::tempdir().unwrap();
        assert_eq!(RecoveryState::load(d.path()), RecoveryState::default());
        let s = RecoveryState {
            enforcement_disabled: true,
            reason: Some("broke ssh".into()),
            changed_by_uid: Some(0),
            changed_at: None,
            isolation: Isolation { active: true, keep: vec!["100.100.1.2/32".parse().unwrap()], since: None },
        };
        s.save(d.path()).unwrap();
        assert_eq!(RecoveryState::load(d.path()), s);
    }
}
