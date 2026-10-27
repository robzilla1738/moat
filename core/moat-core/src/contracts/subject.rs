//! `moat.subject.v1`: who a decision, grant or event is about, at the precision the producer can actually prove.
//!
//! Identities stay separate (MASTER_ROADMAP §5.1): device, boot, process instance (pid + start generation), task
//! boundary (launcher/kernel authenticated), executable identity, OS user. A field is present only when the
//! producer has that evidence; absence means unknown, never "any".

use serde::{Deserialize, Serialize};

use super::{cerr, check_id, finish, Contract, ContractError};

/// A process instance within one boot: pid plus the OS start discriminator (Linux `/proc/<pid>/stat` start time in
/// clock ticks; macOS audit-token pid version). A pid alone is never an identity.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
#[serde(deny_unknown_fields)]
pub struct ProcessGeneration {
    pub pid: u64,
    pub start_generation: u64,
}

/// Executable identity, strongest evidence first. A path or name alone is a weak match.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq, Default, Hash, PartialOrd, Ord)]
#[serde(deny_unknown_fields)]
pub struct ExecutableIdentity {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub team_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub signing_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub bundle_id: Option<String>,
    /// `sha256:` digest of the executable file (Linux) or the cdhash (macOS, as `cdhash:<hex>`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub digest: Option<String>,
    /// Absolute path as reported by the OS.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub path: Option<String>,
}

impl ExecutableIdentity {
    pub fn is_empty(&self) -> bool {
        self.team_id.is_none() && self.signing_id.is_none() && self.bundle_id.is_none() && self.digest.is_none() && self.path.is_none()
    }
    /// Code-signing identity: team plus signing id.
    pub fn is_signed(&self) -> bool {
        self.team_id.is_some() && self.signing_id.is_some()
    }
    pub(crate) fn check(&self, path: &str, errs: &mut Vec<ContractError>) {
        if self.is_empty() {
            errs.push(cerr(path, "an executable identity needs at least one of team_id+signing_id, bundle_id, digest, path"));
        }
        if self.team_id.is_some() != self.signing_id.is_some() {
            errs.push(cerr(path, "team_id and signing_id come together"));
        }
        if let Some(p) = &self.path {
            if !p.starts_with('/') || p.contains('\0') {
                errs.push(cerr(format!("{path}.path"), "path must be absolute"));
            }
        }
    }
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Subject {
    pub schema: String,
    pub device_id: String,
    /// Required whenever `process` or `task` is present: pids and task ids are only unique within one boot.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub boot_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub process: Option<ProcessGeneration>,
    /// Launcher/kernel-authenticated task (e.g. a Linux protected-session id). Never an agent-supplied label.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub task_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub executable: Option<ExecutableIdentity>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub user: Option<String>,
}

impl Subject {
    pub(crate) fn check(&self, path: &str, errs: &mut Vec<ContractError>) {
        check_id(&self.device_id, &format!("{path}.device_id"), errs);
        if let Some(b) = &self.boot_id {
            check_id(b, &format!("{path}.boot_id"), errs);
        }
        if (self.process.is_some() || self.task_id.is_some()) && self.boot_id.is_none() {
            errs.push(cerr(format!("{path}.boot_id"), "process and task identities need the boot they belong to"));
        }
        if let Some(t) = &self.task_id {
            check_id(t, &format!("{path}.task_id"), errs);
        }
        if let Some(e) = &self.executable {
            e.check(&format!("{path}.executable"), errs);
        }
    }
}

impl Contract for Subject {
    const SCHEMA: &'static str = "moat.subject.v1";
    fn validate(&self) -> Result<(), Vec<ContractError>> {
        let mut errs = Vec::new();
        self.check("$", &mut errs);
        finish(errs)
    }
}
