//! Structured semantic policy diff with conservative broadening detection (W02).
//!
//! A change is *broadening* when it could permit (allow or observe) traffic that the old policy denied, at any
//! time, for any subject. Broadening needs the stronger owner authorization before the signer signs it.
//!
//! The classifier is conservative by construction:
//! * every field of `Policy`, `Profile`, `Rule` and `DestinationSet` is destructured exhaustively, so adding a field
//!   without classifying it fails to compile (no "unknown change" can slip through as neutral);
//! * a rule change is narrowing only if the new rule provably matches a subset (allow) or superset (deny) of what the
//!   old rule matched, with precedence and lifetime no stronger (allow) or no weaker (deny); anything the subset
//!   checks cannot prove is broadening;
//! * profile selection is first match in list order (policy-semantics.md), so a reorder of selectable profiles with
//!   different defaults is broadening.
//!
//! `changes` is the structured output tools must parse. `broadening` / `narrowing` are human explanations kept for
//! display and backwards compatibility; never derive authority from their text.

use std::collections::{BTreeMap, BTreeSet};

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use crate::net::{PortRange, Transport};
use crate::policy::{Action, DefaultAction, DestinationSet, Destinations, OnUnsupported, Policy, Profile, Rule, Selector, SessionMatch};

#[derive(Serialize, Deserialize, Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
#[serde(rename_all = "snake_case")]
pub enum Direction {
    /// Could permit something the old policy denied. Needs owner authorization.
    Broadening,
    /// Provably permits nothing new.
    Narrowing,
    /// No effect on any verdict (descriptions, provenance text, rule order).
    Neutral,
}

#[derive(Serialize, Deserialize, Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
#[serde(rename_all = "snake_case")]
pub enum ChangeKind {
    RuleAdded,
    RuleRemoved,
    RuleModified,
    RuleOrderChanged,
    ProfileAdded,
    ProfileRemoved,
    ProfileModified,
    ProfileOrderChanged,
    FallbackChanged,
    DestinationSetAdded,
    DestinationSetRemoved,
    DestinationSetModified,
    DeviceGroupsChanged,
    PolicyMetadataChanged,
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
pub struct SemanticChange {
    /// `rule:<id>`, `profile:<id>`, `set:<name>`, `fallback_profile`, `device_groups`, `policy`.
    pub item: String,
    pub kind: ChangeKind,
    pub direction: Direction,
    /// Names of the fields that changed (for modifications).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub fields: Vec<String>,
    /// Human explanation. Display only.
    pub detail: String,
}

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
    /// Plain-language reasons this diff broadens access. Empty = narrowing or neutral. Display only.
    pub broadening: Vec<String>,
    pub narrowing: Vec<String>,
    /// Structured changes; the field tools and the signer must use.
    #[serde(default)]
    pub changes: Vec<SemanticChange>,
}

impl PolicyDiff {
    pub fn is_broadening(&self) -> bool {
        self.changes.iter().any(|c| c.direction == Direction::Broadening)
    }
    pub fn is_empty(&self) -> bool {
        self.changes.is_empty()
    }
    fn push(&mut self, item: String, kind: ChangeKind, direction: Direction, fields: Vec<String>, detail: String) {
        match direction {
            Direction::Broadening => self.broadening.push(detail.clone()),
            Direction::Narrowing => self.narrowing.push(detail.clone()),
            Direction::Neutral => {}
        }
        self.changes.push(SemanticChange { item, kind, direction, fields, detail });
    }
}

fn restrictiveness(d: DefaultAction) -> u8 {
    match d {
        DefaultAction::Deny => 2,
        DefaultAction::Observe => 1,
        DefaultAction::Allow => 0,
    }
}

// ---------------------------------------------------------------- subset relations ("does `n` match only what `o`
// matched?"). Each returns true only when it can prove it.

/// A list constraint where empty means "no constraint" and a non-empty list matches if any member matches.
fn list_subset<T: PartialEq>(o: &[T], n: &[T]) -> bool {
    o.is_empty() || (!n.is_empty() && n.iter().all(|x| o.contains(x)))
}

fn session_subset(o: &Option<SessionMatch>, n: &Option<SessionMatch>) -> bool {
    match (o, n) {
        (None, _) => true,
        (Some(_), None) => false,
        (Some(o), Some(n)) => {
            o == n || (o.any_protected && o.profiles.is_empty() && o.session_ids.is_empty())
                // same profile constraint, narrower instance list
                || (o.any_protected == n.any_protected
                    && o.profiles == n.profiles
                    && !o.session_ids.is_empty()
                    && !n.session_ids.is_empty()
                    && n.session_ids.iter().all(|s| o.session_ids.contains(s)))
        }
    }
}

fn selector_subset(o: &Selector, n: &Selector) -> bool {
    let Selector { device_groups, users, apps, ancestors, session } = o;
    list_subset(device_groups, &n.device_groups)
        && list_subset(users, &n.users)
        && list_subset(apps, &n.apps)
        && list_subset(ancestors, &n.ancestors)
        && session_subset(session, &n.session)
}

/// Syntactic destination subset: everything `n` names is named by `o` (set *contents* are compared separately).
fn dest_subset(o: &Destinations, n: &Destinations) -> bool {
    let Destinations { hosts, cidrs, scopes, sets, providers, any } = o;
    *any || (!n.any
        && n.hosts.iter().all(|h| hosts.contains(h))
        && n.cidrs.iter().all(|c| cidrs.iter().any(|oc| oc.contains(c)))
        && n.scopes.iter().all(|s| scopes.contains(s))
        && n.sets.iter().all(|s| sets.contains(s))
        && n.providers.iter().all(|p| providers.contains(p)))
}

fn transport_subset(o: Transport, n: Transport) -> bool {
    o == Transport::Any || o == n
}

fn ports_subset(o: &[PortRange], n: &[PortRange]) -> bool {
    o.is_empty() || (!n.is_empty() && n.iter().all(|r| o.iter().any(|or| or.contains(r.start) && or.contains(r.end))))
}

/// Lifetime: does `n` end no later than `o`? (None = never expires.)
fn ends_no_later(o: Option<DateTime<Utc>>, n: Option<DateTime<Utc>>) -> bool {
    match (o, n) {
        (None, _) => true,
        (Some(_), None) => false,
        (Some(a), Some(b)) => b <= a,
    }
}

/// Does rule `n` match a subset of the flows (at a subset of the times) rule `o` matched?
fn matches_subset(o: &Rule, n: &Rule) -> bool {
    selector_subset(&o.selector, &n.selector)
        && dest_subset(&o.destinations, &n.destinations)
        && transport_subset(o.transport, n.transport)
        && ports_subset(&o.ports, &n.ports)
        && ends_no_later(o.expires_at, n.expires_at)
}

fn changed_rule_fields(o: &Rule, n: &Rule) -> Vec<String> {
    let Rule {
        id: _,
        description,
        action,
        layer,
        selector,
        destinations,
        transport,
        ports,
        expires_at,
        provenance,
        requires,
        on_unsupported,
    } = o;
    let mut f = Vec::new();
    let mut chk = |name: &str, same: bool| {
        if !same {
            f.push(name.to_string());
        }
    };
    chk("description", *description == n.description);
    chk("action", *action == n.action);
    chk("layer", *layer == n.layer);
    chk("selector", *selector == n.selector);
    chk("destinations", *destinations == n.destinations);
    chk("transport", *transport == n.transport);
    chk("ports", *ports == n.ports);
    chk("expires_at", *expires_at == n.expires_at);
    chk("provenance", *provenance == n.provenance);
    chk("requires", *requires == n.requires);
    chk("on_unsupported", *on_unsupported == n.on_unsupported);
    f
}

/// Classify one modified rule (same id).
fn classify_rule(o: &Rule, n: &Rule) -> (Direction, String) {
    let id = &n.id;
    let fields = changed_rule_fields(o, n);
    let metadata_only = fields.iter().all(|f| f == "description" || f == "provenance");
    if metadata_only {
        return (Direction::Neutral, format!("rule {id} metadata changed ({})", fields.join(", ")));
    }
    match (o.action, n.action) {
        (Action::Deny, Action::Allow) => return (Direction::Broadening, format!("{id} changed from deny to allow")),
        (Action::Allow, Action::Deny) => return (Direction::Narrowing, format!("{id} changed from allow to deny")),
        _ => {}
    }
    let o_req: BTreeSet<_> = o.requires.iter().collect();
    let n_req: BTreeSet<_> = n.requires.iter().collect();
    match n.action {
        Action::Allow => {
            // An allow is narrower when it matches less, at the same or lower precedence, and is no more likely to
            // be compiled in (requires ⊇ old; on_unsupported never moves from reject to skip... both are stricter).
            let ok = matches_subset(o, n)
                && n.layer.rank() >= o.layer.rank()
                && n_req.is_superset(&o_req)
                && (o.on_unsupported == n.on_unsupported
                    || n.on_unsupported == OnUnsupported::SkipWithReport
                    || o.on_unsupported == OnUnsupported::SkipWithReport);
            if ok {
                (Direction::Narrowing, format!("allow rule {id} narrowed ({})", fields.join(", ")))
            } else {
                (Direction::Broadening, format!("allow rule {id} changed ({}); not provably narrower", fields.join(", ")))
            }
        }
        Action::Deny => {
            // A deny is no weaker when it matches at least as much, for at least as long, at the same or higher
            // precedence. Shortening its expiry, narrowing its scope or lowering its layer is broadening.
            let ok = matches_subset(n, o) && n.layer.rank() <= o.layer.rank();
            if ok {
                (Direction::Narrowing, format!("deny rule {id} kept or widened ({})", fields.join(", ")))
            } else {
                let mut why = Vec::new();
                if !ends_no_later(n.expires_at, o.expires_at) {
                    why.push("expires sooner");
                }
                if n.layer.rank() > o.layer.rank() {
                    why.push("lower precedence");
                }
                if !(selector_subset(&n.selector, &o.selector)
                    && dest_subset(&n.destinations, &o.destinations)
                    && transport_subset(n.transport, o.transport)
                    && ports_subset(&n.ports, &o.ports))
                {
                    why.push("matches less");
                }
                (Direction::Broadening, format!("deny rule {id} weakened ({}): {}", fields.join(", "), why.join(", ")))
            }
        }
    }
}

/// Profiles that take part in first-match selection for ordinary traffic (eval::profile_for).
fn selectable(p: &Policy) -> Vec<&Profile> {
    p.profiles.iter().filter(|x| !x.applies_to.is_everything() && x.applies_to.session.is_none()).collect()
}

pub fn diff(old: &Policy, new: &Policy) -> PolicyDiff {
    let mut d = PolicyDiff::default();
    // Exhaustive destructuring: a new Policy field must be classified here.
    let Policy { schema, name, description, device_groups, destination_sets, profiles: _, rules: _, fallback_profile } = old;

    if *schema != new.schema || *name != new.name || *description != new.description {
        d.push("policy".into(), ChangeKind::PolicyMetadataChanged, Direction::Neutral, vec![], "policy name/description changed".into());
    }

    // ------------------------------------------------------------------ rules
    let o: BTreeMap<&str, &Rule> = old.rules.iter().map(|r| (r.id.as_str(), r)).collect();
    let n: BTreeMap<&str, &Rule> = new.rules.iter().map(|r| (r.id.as_str(), r)).collect();
    for (id, r) in &n {
        match o.get(id) {
            None => {
                d.added.push(id.to_string());
                if r.action == Action::Allow {
                    d.push(format!("rule:{id}"), ChangeKind::RuleAdded, Direction::Broadening, vec![], format!("new allow rule {id}"));
                } else {
                    d.push(format!("rule:{id}"), ChangeKind::RuleAdded, Direction::Narrowing, vec![], format!("new deny rule {id}"));
                }
            }
            Some(prev) if prev != r => {
                d.changed.push(id.to_string());
                let (dir, detail) = classify_rule(prev, r);
                d.push(format!("rule:{id}"), ChangeKind::RuleModified, dir, changed_rule_fields(prev, r), detail);
            }
            _ => {}
        }
    }
    for (id, r) in &o {
        if !n.contains_key(id) {
            d.removed.push(id.to_string());
            if r.action == Action::Deny {
                let em = if r.layer == crate::policy::Layer::Emergency { " (emergency lifted)" } else { "" };
                d.push(format!("rule:{id}"), ChangeKind::RuleRemoved, Direction::Broadening, vec![], format!("deny rule {id} removed{em}"));
            } else {
                d.push(format!("rule:{id}"), ChangeKind::RuleRemoved, Direction::Narrowing, vec![], format!("allow rule {id} removed"));
            }
        }
    }
    let common = |rules: &[Rule]| {
        rules.iter().filter(|r| o.contains_key(r.id.as_str()) && n.contains_key(r.id.as_str())).map(|r| r.id.clone()).collect::<Vec<_>>()
    };
    if common(&old.rules) != common(&new.rules) {
        // Verdicts depend on layer and action, never on rule order; only the explanation's tie-break changes.
        d.push(
            "rules".into(),
            ChangeKind::RuleOrderChanged,
            Direction::Neutral,
            vec![],
            "rule order changed (explanation tie-break only)".into(),
        );
    }

    // ------------------------------------------------------------------ profiles
    for p in &new.profiles {
        match old.profile(&p.id) {
            None => {
                d.profile_changes.push(format!("profile {} added", p.id));
                if p.default != DefaultAction::Deny {
                    d.push(
                        format!("profile:{}", p.id),
                        ChangeKind::ProfileAdded,
                        Direction::Broadening,
                        vec![],
                        format!("new non-deny profile {}", p.id),
                    );
                } else {
                    d.push(
                        format!("profile:{}", p.id),
                        ChangeKind::ProfileAdded,
                        Direction::Narrowing,
                        vec![],
                        format!("new deny profile {}", p.id),
                    );
                }
            }
            Some(op) if op != p => {
                d.profile_changes.push(format!("profile {} changed", p.id));
                let Profile { id: _, description, default, learning, applies_to } = op;
                let mut fields = Vec::new();
                if *description != p.description {
                    fields.push("description".to_string());
                }
                if *learning != p.learning {
                    fields.push("learning".to_string());
                }
                if *default != p.default {
                    fields.push("default".to_string());
                }
                if *applies_to != p.applies_to {
                    fields.push("applies_to".to_string());
                }
                let dir = if *applies_to != p.applies_to || restrictiveness(p.default) < restrictiveness(*default) {
                    // Any scope change moves flows between profiles; without proving where they land, broadening.
                    Direction::Broadening
                } else if restrictiveness(p.default) > restrictiveness(*default) {
                    Direction::Narrowing
                } else {
                    // description / learning label: learning never changes a verdict (restrictive learning requires deny)
                    Direction::Neutral
                };
                let detail = match dir {
                    Direction::Broadening => format!("profile {} default or scope loosened ({})", p.id, fields.join(", ")),
                    Direction::Narrowing => format!("profile {} default tightened", p.id),
                    Direction::Neutral => format!("profile {} metadata changed ({})", p.id, fields.join(", ")),
                };
                d.push(format!("profile:{}", p.id), ChangeKind::ProfileModified, dir, fields, detail);
            }
            _ => {}
        }
    }
    for p in &old.profiles {
        if new.profile(&p.id).is_none() {
            d.profile_changes.push(format!("profile {} removed", p.id));
            d.push(
                format!("profile:{}", p.id),
                ChangeKind::ProfileRemoved,
                Direction::Broadening,
                vec![],
                format!("profile {} removed (its flows fall back to another profile)", p.id),
            );
        }
    }
    // First-match order among selectable profiles present in both policies.
    let o_sel: Vec<&Profile> = selectable(old).into_iter().filter(|p| new.profile(&p.id).is_some()).collect();
    let n_sel: Vec<&Profile> = selectable(new).into_iter().filter(|p| old.profile(&p.id).is_some()).collect();
    let o_order: Vec<&str> = o_sel.iter().map(|p| p.id.as_str()).collect();
    let n_order: Vec<&str> = n_sel.iter().map(|p| p.id.as_str()).collect();
    if o_order != n_order {
        let defaults: BTreeSet<u8> = o_sel.iter().chain(n_sel.iter()).map(|p| restrictiveness(p.default)).collect();
        if defaults.len() > 1 {
            d.profile_changes.push("profile order changed".into());
            d.push(
                "profiles".into(),
                ChangeKind::ProfileOrderChanged,
                Direction::Broadening,
                vec![],
                format!(
                    "profile selection order changed ({} -> {}); overlapping apps may now get a different default",
                    o_order.join(","),
                    n_order.join(",")
                ),
            );
        } else {
            d.push(
                "profiles".into(),
                ChangeKind::ProfileOrderChanged,
                Direction::Neutral,
                vec![],
                "profile order changed (all the same default)".into(),
            );
        }
    }
    if *fallback_profile != new.fallback_profile {
        d.profile_changes.push("fallback profile changed".into());
        let od = old.profile(fallback_profile).map(|p| p.default);
        let nd = new.profile(&new.fallback_profile).map(|p| p.default);
        let dir = match (od, nd) {
            (Some(a), Some(b)) if restrictiveness(b) >= restrictiveness(a) => Direction::Narrowing,
            _ => Direction::Broadening,
        };
        let detail = if dir == Direction::Broadening {
            "fallback profile changed".to_string()
        } else {
            "fallback profile changed to one at least as strict".to_string()
        };
        d.push("fallback_profile".into(), ChangeKind::FallbackChanged, dir, vec![], detail);
    }

    // ------------------------------------------------------------------ destination sets
    for (name, set) in &new.destination_sets {
        match destination_sets.get(name) {
            None => {
                d.set_changes.push(format!("set {name} added"));
                // A new set only matters through rules that reference it; those rule changes are classified above.
                d.push(format!("set:{name}"), ChangeKind::DestinationSetAdded, Direction::Neutral, vec![], format!("set {name} added"));
            }
            Some(os) if os != set => {
                d.set_changes.push(format!("set {name} changed"));
                let DestinationSet { description: _, destinations } = os;
                let grew = !dest_subset(destinations, &set.destinations);
                let shrank = !dest_subset(&set.destinations, destinations);
                let refs = |p: &Policy, a: Action| p.rules.iter().any(|r| r.action == a && r.destinations.sets.contains(name));
                let used_by_allow = refs(new, Action::Allow) || refs(old, Action::Allow);
                let used_by_deny = refs(new, Action::Deny) || refs(old, Action::Deny);
                let dir = if (grew && used_by_allow) || (shrank && used_by_deny) {
                    Direction::Broadening
                } else if grew || shrank {
                    Direction::Narrowing
                } else {
                    Direction::Neutral
                };
                let detail = match dir {
                    Direction::Broadening => format!("destination set {name} changed in a way that can permit more"),
                    _ => format!("destination set {name} changed"),
                };
                d.push(format!("set:{name}"), ChangeKind::DestinationSetModified, dir, vec![], detail);
            }
            _ => {}
        }
    }
    for name in destination_sets.keys() {
        if !new.destination_sets.contains_key(name) {
            d.set_changes.push(format!("set {name} removed"));
            // Validation requires referenced sets to exist, so references were removed too (classified as rule changes).
            d.push(format!("set:{name}"), ChangeKind::DestinationSetRemoved, Direction::Neutral, vec![], format!("set {name} removed"));
        }
    }
    if *device_groups != new.device_groups {
        d.set_changes.push("device groups changed".into());
        d.push(
            "device_groups".into(),
            ChangeKind::DeviceGroupsChanged,
            Direction::Broadening,
            vec![],
            "device group membership changed (treated as broadening)".into(),
        );
    }
    d
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::policy::Layer;

    fn home() -> Policy {
        Policy::parse(include_str!("../../../conformance/policies/home.toml")).unwrap()
    }

    fn with_deny() -> Policy {
        let src = format!(
            "{}\n{}",
            include_str!("../../../conformance/policies/home.toml"),
            "[[rules]]\nid = \"deny-x\"\naction = \"deny\"\nselector = {}\ndestinations = { cidrs = [\"203.0.113.0/24\"] }\nprovenance = { kind = \"git\", reference = \"t\" }\n"
        );
        Policy::parse(&src).unwrap()
    }

    fn rule<'a>(p: &'a mut Policy, id: &str) -> &'a mut Rule {
        p.rules.iter_mut().find(|r| r.id == id).unwrap()
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
        let d = diff(&home(), &n);
        assert!(d.is_broadening());
        assert_eq!(d.broadening, vec!["new allow rule coding-allow-pypi".to_string()], "signer compatibility");
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

    // D-DIFF-SHORTENED-DENY
    #[test]
    fn shortening_a_deny_is_broadening() {
        let mut old = with_deny();
        let id = "deny-x".to_string();
        rule(&mut old, &id).expires_at = Some("2026-12-31T00:00:00Z".parse().unwrap());
        let mut new = old.clone();
        rule(&mut new, &id).expires_at = Some("2026-11-01T00:00:00Z".parse().unwrap());
        let d = diff(&old, &new);
        assert!(d.is_broadening(), "{:?}", d.changes);
        assert!(d.broadening[0].contains("expires sooner"));
        // giving a permanent deny an expiry is broadening too; lengthening is not
        let perm = with_deny();
        assert!(diff(&perm, &old).is_broadening());
        assert!(!diff(&new, &old).is_broadening());
        assert!(!diff(&old, &perm).is_broadening());
    }

    // D-DIFF-REORDER
    #[test]
    fn reordering_selectable_profiles_with_different_defaults_is_broadening() {
        let src = format!(
            "{}\n{}",
            include_str!("../../../conformance/policies/home.toml"),
            r#"
[[profiles]]
id = "browsers-deny"
default = "deny"
applies_to = { apps = [{ family = "safari" }] }

[[profiles]]
id = "browsers-allow"
default = "allow"
applies_to = { apps = [{ family = "safari" }] }
"#
        );
        let old = Policy::parse(&src).unwrap();
        old.validate().unwrap();
        let mut new = old.clone();
        let a = new.profiles.iter().position(|p| p.id == "browsers-deny").unwrap();
        let b = new.profiles.iter().position(|p| p.id == "browsers-allow").unwrap();
        new.profiles.swap(a, b);
        let d = diff(&old, &new);
        assert!(d.is_broadening(), "{:?}", d.changes);
        assert!(d.changes.iter().any(|c| c.kind == ChangeKind::ProfileOrderChanged));
    }

    // D-DIFF-UNKNOWN-FIELDS: fields that used to be ignored now classify
    #[test]
    fn previously_ignored_fields_are_classified() {
        let mut new = home();
        let id = "coding-allow-github".to_string();
        // moving an allow up to the override layer lets it beat explicit denies
        let mut n1 = new.clone();
        rule(&mut n1, &id).layer = Layer::Override;
        assert!(diff(&home(), &n1).is_broadening());
        // dropping a capability requirement from an allow can let it compile in where it was omitted
        let mut old = home();
        rule(&mut old, &id).requires.push(crate::capability::Capability::ProcessIdentity);
        assert!(diff(&old, &home()).is_broadening());
        // description/provenance text is neutral
        rule(&mut new, &id).description = Some("changed".into());
        let d = diff(&home(), &new);
        assert!(!d.is_broadening() && !d.is_empty());
    }

    #[test]
    fn deny_narrowed_by_port_or_selector_is_broadening() {
        let old = with_deny();
        let mut n = old.clone();
        rule(&mut n, "deny-x").ports = vec![PortRange::single(443)];
        assert!(diff(&old, &n).is_broadening());
        let mut n = old.clone();
        rule(&mut n, "deny-x").destinations.cidrs = vec!["203.0.113.0/25".parse().unwrap()];
        assert!(diff(&old, &n).is_broadening());
        let mut n = old.clone();
        rule(&mut n, "deny-x").destinations.cidrs = vec!["203.0.0.0/16".parse().unwrap()];
        assert!(!diff(&old, &n).is_broadening(), "widening a deny's CIDR is narrowing");
    }

    #[test]
    fn structured_changes_carry_direction_and_fields() {
        let mut n = home();
        let id = "coding-allow-github".to_string();
        rule(&mut n, &id).ports.clear();
        let d = diff(&home(), &n);
        let c = d.changes.iter().find(|c| c.item == format!("rule:{id}")).unwrap();
        assert_eq!(c.kind, ChangeKind::RuleModified);
        assert_eq!(c.fields, vec!["ports".to_string()]);
    }
}
