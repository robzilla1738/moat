//! Backend identifiers derived from policy ids (W02: collision-free backend IDs).
//!
//! The Linux backend turns profile ids into cgroup directory names and nftables chain names, and uses rule ids as
//! nftables counter comments that evidence is attributed by. Those mappings are lossy (`coding.session`,
//! `coding_session` and `Coding-Session` all sanitize to `coding-session`), so two distinct policy objects could
//! share a cgroup, a chain or a counter. Instead of guessing, a policy whose ids collide after mapping — or whose rule
//! id collides with a counter name the backend reserves for itself — is rejected at compile time.

use std::collections::BTreeMap;

use crate::policy::{Policy, PolicyError};

/// Lowercase alphanumerics and dashes only (spliced into nftables string literals and filesystem paths).
pub fn sanitize(s: &str) -> String {
    s.chars().map(|c| if c.is_ascii_alphanumeric() || c == '-' { c.to_ascii_lowercase() } else { '-' }).collect()
}

/// The cgroup directory component for a profile: `p-<sanitized>`.
pub fn profile_dir_name(profile: &str) -> String {
    format!("p-{}", sanitize(profile))
}

/// The nftables chain for a profile.
pub fn chain_name(profile: &str) -> String {
    format!("s_{}", sanitize(profile).replace('-', "_"))
}

/// The nftables counter comment for a rule (what counters are attributed by).
pub fn rule_comment(id: &str) -> String {
    id.chars().filter(|c| c.is_ascii_alphanumeric() || "-_.:@ ".contains(*c)).take(120).collect()
}

/// Counter comments the Linux backend uses for its own lines.
pub const RESERVED_COMMENT_PREFIXES: [&str; 4] = ["default:", "observe:", "proxy:", "session:"];
pub const RESERVED_COMMENTS: [&str; 4] = ["egress-proxy-upstream", "loopback", "recovery path", "local-emergency-isolation"];

/// Every collision the Linux backend mapping would introduce, as policy errors.
pub fn linux_collisions(p: &Policy) -> Vec<PolicyError> {
    let mut errs = Vec::new();
    let mut dirs: BTreeMap<String, &str> = BTreeMap::new();
    let mut chains: BTreeMap<String, &str> = BTreeMap::new();
    for (i, prof) in p.profiles.iter().enumerate() {
        if let Some(other) = dirs.insert(profile_dir_name(&prof.id), &prof.id) {
            errs.push(PolicyError {
                path: format!("profiles[{i}].id"),
                message: format!("profile {:?} maps to the same cgroup directory as {other:?}; rename one", prof.id),
            });
        }
        if let Some(other) = chains.insert(chain_name(&prof.id), &prof.id) {
            if other != prof.id {
                errs.push(PolicyError {
                    path: format!("profiles[{i}].id"),
                    message: format!("profile {:?} maps to the same nftables chain as {other:?}; rename one", prof.id),
                });
            }
        }
    }
    let mut comments: BTreeMap<String, &str> = BTreeMap::new();
    for (i, r) in p.rules.iter().enumerate() {
        let c = rule_comment(&r.id);
        if RESERVED_COMMENT_PREFIXES.iter().any(|pre| c.starts_with(pre)) || RESERVED_COMMENTS.contains(&c.as_str()) {
            errs.push(PolicyError {
                path: format!("rules[{i}].id"),
                message: format!("rule id {:?} collides with a counter name the backend reserves; rename it", r.id),
            });
        }
        if let Some(other) = comments.insert(c, &r.id) {
            errs.push(PolicyError {
                path: format!("rules[{i}].id"),
                message: format!("rule {:?} would share a counter with {other:?}; rename one", r.id),
            });
        }
    }
    errs
}

#[cfg(test)]
mod tests {
    use super::*;

    fn home() -> Policy {
        Policy::parse(include_str!("../../../conformance/policies/home.toml")).unwrap()
    }

    #[test]
    fn shipped_policy_has_no_collisions() {
        assert!(linux_collisions(&home()).is_empty());
    }

    #[test]
    fn profile_ids_that_sanitize_alike_are_rejected() {
        let mut p = home();
        let mut dup = p.profiles.iter().find(|x| x.id == "coding-session").unwrap().clone();
        dup.id = "coding.session".into();
        dup.default = crate::policy::DefaultAction::Allow;
        p.profiles.push(dup);
        let e = linux_collisions(&p);
        assert!(e.iter().any(|x| x.message.contains("same cgroup directory")), "{e:?}");
    }

    #[test]
    fn rule_ids_cannot_impersonate_backend_counters() {
        let mut p = home();
        p.rules[0].id = "default:coding-session".into();
        assert!(!linux_collisions(&p).is_empty());
    }
}
