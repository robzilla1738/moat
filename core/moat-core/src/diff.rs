//! Policy diff with conservative broadening detection.
//!
//! Any change that could permit traffic that was previously blocked is *broadening* and requires a trusted local
//! owner action before the signer will sign it. When in doubt, a change is classified as broadening.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

use crate::policy::{Action, DefaultAction, Destinations, Layer, Policy, Rule};

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
pub struct RuleChange {
    pub id: String,
    pub before: Option<Rule>,
    pub after: Option<Rule>,
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq, Default)]
pub struct PolicyDiff {
    pub added: Vec<String>,
    pub removed: Vec<String>,
    pub changed: Vec<String>,
    pub profile_changes: Vec<String>,
    pub set_changes: Vec<String>,
    /// Plain-language reasons this diff broadens access. Empty = narrowing or neutral.
    pub broadening: Vec<String>,
    pub narrowing: Vec<String>,
}

impl PolicyDiff {
    pub fn is_broadening(&self) -> bool {
        !self.broadening.is_empty()
    }
    pub fn is_empty(&self) -> bool {
        self.added.is_empty() && self.removed.is_empty() && self.changed.is_empty() && self.profile_changes.is_empty() && self.set_changes.is_empty()
    }
}

fn restrictiveness(d: DefaultAction) -> u8 {
    match d {
        DefaultAction::Deny => 2,
        DefaultAction::Observe => 1,
        DefaultAction::Allow => 0,
    }
}

fn dest_superset(a: &Destinations, b: &Destinations) -> bool {
    // does `a` contain everything `b` names (syntactically)?
    a.any || (b.hosts.iter().all(|h| a.hosts.contains(h))
        && b.cidrs.iter().all(|c| a.cidrs.contains(c))
        && b.scopes.iter().all(|s| a.scopes.contains(s))
        && b.sets.iter().all(|s| a.sets.contains(s))
        && b.providers.iter().all(|p| a.providers.contains(p))
        && !b.any)
}

pub fn diff(old: &Policy, new: &Policy) -> PolicyDiff {
    let mut d = PolicyDiff::default();
    let o: BTreeMap<&str, &Rule> = old.rules.iter().map(|r| (r.id.as_str(), r)).collect();
    let n: BTreeMap<&str, &Rule> = new.rules.iter().map(|r| (r.id.as_str(), r)).collect();

    for (id, r) in &n {
        match o.get(id) {
            None => {
                d.added.push(id.to_string());
                if r.action == Action::Allow {
                    d.broadening.push(format!("new allow rule {id}"));
                } else {
                    d.narrowing.push(format!("new deny rule {id}"));
                }
            }
            Some(prev) if prev != r => {
                d.changed.push(id.to_string());
                if prev.action != r.action {
                    if r.action == Action::Allow {
                        d.broadening.push(format!("{id} changed from deny to allow"));
                    } else {
                        d.narrowing.push(format!("{id} changed from allow to deny"));
                    }
                    continue;
                }
                match r.action {
                    Action::Allow => {
                        let narrower_only = dest_superset(&prev.destinations, &r.destinations)
                            && prev.selector == r.selector
                            && prev.transport == r.transport
                            && prev.ports == r.ports
                            && match (prev.expires_at, r.expires_at) {
                                (_, None) => prev.expires_at.is_none(),
                                (None, Some(_)) => true,
                                (Some(a), Some(b)) => b <= a,
                            }
                            && r.layer.rank() >= prev.layer.rank();
                        if narrower_only {
                            d.narrowing.push(format!("allow rule {id} narrowed"));
                        } else {
                            d.broadening.push(format!("allow rule {id} changed (treated as broadening)"));
                        }
                    }
                    Action::Deny => {
                        let wider_or_same = dest_superset(&r.destinations, &prev.destinations)
                            && r.selector == prev.selector
                            && r.transport == prev.transport
                            && r.ports == prev.ports
                            && r.expires_at.is_none() == prev.expires_at.is_none()
                            && r.layer.rank() <= prev.layer.rank();
                        if wider_or_same {
                            d.narrowing.push(format!("deny rule {id} widened"));
                        } else {
                            d.broadening.push(format!("deny rule {id} changed (treated as broadening)"));
                        }
                    }
                }
            }
            _ => {}
        }
    }
    for (id, r) in &o {
        if !n.contains_key(id) {
            d.removed.push(id.to_string());
            if r.action == Action::Deny {
                d.broadening.push(format!("deny rule {id} removed{}", if r.layer == Layer::Emergency { " (emergency lifted)" } else { "" }));
            } else {
                d.narrowing.push(format!("allow rule {id} removed"));
            }
        }
    }
    for p in &new.profiles {
        match old.profile(&p.id) {
            None => {
                d.profile_changes.push(format!("profile {} added", p.id));
                if p.default != DefaultAction::Deny {
                    d.broadening.push(format!("new non-deny profile {}", p.id));
                }
            }
            Some(op) if op != p => {
                d.profile_changes.push(format!("profile {} changed", p.id));
                if restrictiveness(p.default) < restrictiveness(op.default) || op.applies_to != p.applies_to {
                    d.broadening.push(format!("profile {} default or scope loosened", p.id));
                }
            }
            _ => {}
        }
    }
    for p in &old.profiles {
        if new.profile(&p.id).is_none() {
            d.profile_changes.push(format!("profile {} removed", p.id));
            d.broadening.push(format!("profile {} removed (its flows fall back to another profile)", p.id));
        }
    }
    if old.fallback_profile != new.fallback_profile {
        d.profile_changes.push("fallback profile changed".into());
        d.broadening.push("fallback profile changed".into());
    }
    for (name, set) in &new.destination_sets {
        match old.destination_sets.get(name) {
            None => d.set_changes.push(format!("set {name} added")),
            Some(os) if os != set => {
                d.set_changes.push(format!("set {name} changed"));
                let grew = !dest_superset(&os.destinations, &set.destinations);
                let shrank = !dest_superset(&set.destinations, &os.destinations);
                let used_by_allow = new.rules.iter().any(|r| r.action == Action::Allow && r.destinations.sets.contains(name));
                let used_by_deny = new.rules.iter().any(|r| r.action == Action::Deny && r.destinations.sets.contains(name));
                if (grew && used_by_allow) || (shrank && used_by_deny) {
                    d.broadening.push(format!("destination set {name} changed in a way that can permit more"));
                }
            }
            _ => {}
        }
    }
    if old.device_groups != new.device_groups {
        d.set_changes.push("device groups changed".into());
        d.broadening.push("device group membership changed (treated as broadening)".into());
    }
    d
}

#[cfg(test)]
mod tests {
    use super::*;

    fn home() -> Policy {
        Policy::parse(include_str!("../../../conformance/policies/home.toml")).unwrap()
    }

    #[test]
    fn identical_is_empty() {
        let d = diff(&home(), &home());
        assert!(d.is_empty() && !d.is_broadening());
    }

    #[test]
    fn removing_safety_deny_is_broadening() {
        let mut n = home();
        n.rules.retain(|r| r.id != "safety-workloads-never-reach-controller");
        assert!(diff(&home(), &n).is_broadening());
    }

    #[test]
    fn adding_allow_is_broadening_and_deny_is_not() {
        let mut n = home();
        let mut r = n.rules.iter().find(|r| r.id == "coding-allow-npm").unwrap().clone();
        r.id = "coding-allow-pypi".into();
        n.rules.push(r.clone());
        assert!(diff(&home(), &n).is_broadening());
        let mut n2 = home();
        r.action = Action::Deny;
        r.on_unsupported = Default::default();
        n2.rules.push(r);
        let d = diff(&home(), &n2);
        assert!(!d.is_broadening(), "{:?}", d.broadening);
    }

    #[test]
    fn growing_allowed_set_is_broadening() {
        let mut n = home();
        n.destination_sets.get_mut("npm").unwrap().destinations.hosts.push("registry.yarnpkg.com".into());
        assert!(diff(&home(), &n).is_broadening());
    }

    #[test]
    fn loosening_profile_is_broadening() {
        let mut n = home();
        n.profiles.iter_mut().find(|p| p.id == "coding-session").unwrap().default = DefaultAction::Observe;
        assert!(diff(&home(), &n).is_broadening());
    }
}
