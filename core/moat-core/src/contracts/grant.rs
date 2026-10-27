//! `moat.grant.v1`: a temporary permission as a precise object (MASTER_ROADMAP §6.3).
//!
//! A grant names exactly one enforceable subject scope, one destination, one transport and port, an absolute
//! admission window, the base policy generation it was approved against, its issuer, the digest of the approval it
//! came from, a unique id and an idempotency key. Missing mandatory scope rejects the grant: there is no default
//! that widens it.

use std::net::IpAddr;

use serde::{Deserialize, Serialize};

use super::subject::{ExecutableIdentity, ProcessGeneration};
use super::{cerr, check_digest, check_id, check_time, finish, Contract, ContractError};

/// Longest admission window any grant may carry (24 hours), matching the signer's bounded-grant limit.
pub const MAX_GRANT_SECONDS: i64 = 24 * 3600;

#[derive(Serialize, Deserialize, Clone, Copy, Debug, PartialEq, Eq, Hash)]
#[serde(rename_all = "snake_case")]
pub enum GrantScopeKind {
    /// "Allow this app on this device": one device, an executable identity, across process restarts until expiry.
    AppOnDevice,
    /// "Allow this process instance": one device, one boot, one pid + start generation. A restarted process (new
    /// start generation) or a reboot does not match.
    ProcessInstance,
    /// "Allow this protected task until completion": one device, one boot, one launcher-authenticated task id.
    Task,
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct GrantScope {
    pub kind: GrantScopeKind,
    pub device_id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub boot_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub process: Option<ProcessGeneration>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub task_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub executable: Option<ExecutableIdentity>,
}

#[derive(Serialize, Deserialize, Clone, Copy, Debug, PartialEq, Eq, Hash)]
#[serde(rename_all = "snake_case")]
pub enum DestinationKind {
    Address,
    Hostname,
}

/// Exactly one address (canonical text form) or one hostname (lowercase, no wildcard).
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct GrantDestination {
    pub kind: DestinationKind,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub address: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub hostname: Option<String>,
}

#[derive(Serialize, Deserialize, Clone, Copy, Debug, PartialEq, Eq, Hash)]
#[serde(rename_all = "snake_case")]
pub enum GrantTransport {
    Tcp,
    Udp,
}

/// What happens to traffic admitted under the grant when the admission window ends (§3.1, §7.2).
#[derive(Serialize, Deserialize, Clone, Copy, Debug, PartialEq, Eq, Hash)]
#[serde(rename_all = "snake_case")]
pub enum StreamPolicy {
    /// "Allow new admissions until a deadline": streams opened before the deadline may continue.
    AdmissionOnly,
    /// "Permit an active stream only until a deadline": the backend must terminate admitted streams at the
    /// deadline. Only compiles where the backend advertises stream termination.
    TerminateAtDeadline,
}

#[derive(Serialize, Deserialize, Clone, Copy, Debug, PartialEq, Eq, Hash)]
#[serde(rename_all = "snake_case")]
pub enum IssuerRole {
    /// The native owner.
    Owner,
    /// A narrowly delegated issuer (e.g. an enrolled phone) whose limits the signer and endpoints enforce.
    Delegated,
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Issuer {
    pub principal: String,
    pub role: IssuerRole,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub key_id: Option<String>,
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Grant {
    pub schema: String,
    pub grant_id: String,
    /// Client-chosen key. A retried request with the same key returns the original grant, original expiry
    /// included; it never mints a fresh lease.
    pub idempotency_key: String,
    pub scope: GrantScope,
    pub destination: GrantDestination,
    pub transport: GrantTransport,
    pub port: u64,
    pub issued_at: String,
    pub not_before: String,
    /// New admissions stop at this instant. Absolute; never recomputed from a duration on retry or restart.
    pub admission_until: String,
    pub stream_policy: StreamPolicy,
    /// Effective digest of the base policy the approval was made against.
    pub base_policy_digest: String,
    pub issuer: Issuer,
    /// Digest of the approval request (incident evidence + requested scope) the human saw.
    pub approval_digest: String,
    /// Display text. Never parsed for authority.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
}

pub(crate) fn valid_hostname(h: &str) -> bool {
    h.len() <= 253
        && h.contains('.')
        && h.split('.').all(|l| {
            !l.is_empty()
                && l.len() <= 63
                && !l.starts_with('-')
                && !l.ends_with('-')
                && l.bytes().all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
        })
}

impl GrantScope {
    pub(crate) fn check(&self, path: &str, errs: &mut Vec<ContractError>) {
        check_id(&self.device_id, &format!("{path}.device_id"), errs);
        if let Some(b) = &self.boot_id {
            check_id(b, &format!("{path}.boot_id"), errs);
        }
        if let Some(t) = &self.task_id {
            check_id(t, &format!("{path}.task_id"), errs);
        }
        if let Some(e) = &self.executable {
            e.check(&format!("{path}.executable"), errs);
        }
        let need = |present: bool, field: &str, errs: &mut Vec<ContractError>| {
            if !present {
                errs.push(cerr(format!("{path}.{field}"), format!("required for scope kind {:?}", self.kind)));
            }
        };
        let forbid = |present: bool, field: &str, errs: &mut Vec<ContractError>| {
            if present {
                errs.push(cerr(format!("{path}.{field}"), format!("not allowed for scope kind {:?}", self.kind)));
            }
        };
        match self.kind {
            GrantScopeKind::AppOnDevice => {
                need(self.executable.is_some(), "executable", errs);
                forbid(self.boot_id.is_some(), "boot_id", errs);
                forbid(self.process.is_some(), "process", errs);
                forbid(self.task_id.is_some(), "task_id", errs);
            }
            GrantScopeKind::ProcessInstance => {
                need(self.boot_id.is_some(), "boot_id", errs);
                need(self.process.is_some(), "process", errs);
                forbid(self.task_id.is_some(), "task_id", errs);
            }
            GrantScopeKind::Task => {
                need(self.boot_id.is_some(), "boot_id", errs);
                need(self.task_id.is_some(), "task_id", errs);
                forbid(self.process.is_some(), "process", errs);
                forbid(self.executable.is_some(), "executable", errs);
            }
        }
    }
}

impl GrantDestination {
    pub(crate) fn check(&self, path: &str, errs: &mut Vec<ContractError>) {
        match self.kind {
            DestinationKind::Address => {
                if self.hostname.is_some() {
                    errs.push(cerr(format!("{path}.hostname"), "an address destination has no hostname"));
                }
                match self.address.as_deref().map(|a| (a, a.parse::<IpAddr>())) {
                    Some((a, Ok(ip))) if ip.to_string() == a => {}
                    Some((a, Ok(ip))) => errs.push(cerr(format!("{path}.address"), format!("{a:?} must be written canonically as {ip}"))),
                    _ => errs.push(cerr(format!("{path}.address"), "one IP address is required")),
                }
            }
            DestinationKind::Hostname => {
                if self.address.is_some() {
                    errs.push(cerr(format!("{path}.address"), "a hostname destination has no address"));
                }
                match self.hostname.as_deref() {
                    Some(h) if valid_hostname(h) => {}
                    _ => errs.push(cerr(format!("{path}.hostname"), "one lowercase hostname without wildcards is required")),
                }
            }
        }
    }
}

impl Contract for Grant {
    const SCHEMA: &'static str = "moat.grant.v1";
    fn validate(&self) -> Result<(), Vec<ContractError>> {
        let mut errs = Vec::new();
        check_id(&self.grant_id, "$.grant_id", &mut errs);
        check_id(&self.idempotency_key, "$.idempotency_key", &mut errs);
        self.scope.check("$.scope", &mut errs);
        self.destination.check("$.destination", &mut errs);
        if !(1..=65535).contains(&self.port) {
            errs.push(cerr("$.port", "port must be 1-65535"));
        }
        let issued = check_time(&self.issued_at, "$.issued_at", &mut errs);
        let nb = check_time(&self.not_before, "$.not_before", &mut errs);
        let until = check_time(&self.admission_until, "$.admission_until", &mut errs);
        if let (Some(i), Some(nb)) = (issued, nb) {
            if nb < i {
                errs.push(cerr("$.not_before", "a grant cannot start before it was issued"));
            }
        }
        if let (Some(nb), Some(u)) = (nb, until) {
            let secs = (u - nb).num_seconds();
            if secs <= 0 {
                errs.push(cerr("$.admission_until", "admission_until must be after not_before"));
            } else if secs > MAX_GRANT_SECONDS {
                errs.push(cerr("$.admission_until", format!("admission window exceeds {MAX_GRANT_SECONDS} seconds")));
            }
        }
        check_digest(&self.base_policy_digest, "$.base_policy_digest", &mut errs);
        check_digest(&self.approval_digest, "$.approval_digest", &mut errs);
        check_id(&self.issuer.principal, "$.issuer.principal", &mut errs);
        if let Some(k) = &self.issuer.key_id {
            check_id(k, "$.issuer.key_id", &mut errs);
        }
        if self.reason.as_ref().is_some_and(|r| r.len() > 200) {
            errs.push(cerr("$.reason", "reason is display text of at most 200 bytes"));
        }
        finish(errs)
    }
}

impl Grant {
    /// The authority-bearing content: everything except display text. Two grants with the same authority digest
    /// grant exactly the same thing.
    pub fn authority_digest(&self) -> String {
        let mut g = self.clone();
        g.reason = None;
        super::digest(&g)
    }
}
