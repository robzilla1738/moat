//! Service packs: versioned data naming the destinations a service needs, with an explanation for each.
//!
//! Endpoint allowlists reduce destinations; they are not data-loss prevention. Package download and publication
//! are separate *intentions*; Moat advertises enforcement of that distinction only where an application-aware
//! boundary can enforce it (hostname rules alone usually cannot). Pack updates produce reviewable diffs.

use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};

use crate::net::{validate_host_pattern, PortRange, Transport};
use crate::policy::{DestinationSet, Destinations};

pub const SERVICE_PACK_SCHEMA: &str = "moat.service_pack.v1";

#[derive(Serialize, Deserialize, Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
#[serde(rename_all = "snake_case")]
pub enum Necessity {
    Required,
    Optional,
}

#[derive(Serialize, Deserialize, Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
#[serde(rename_all = "snake_case")]
pub enum Intention {
    Fetch,
    Download,
    Publish,
    Api,
    Auth,
    Inference,
    Update,
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct PackDestination {
    pub host: String,
    pub necessity: Necessity,
    pub explanation: String,
    pub intention: Intention,
    #[serde(default)]
    pub ports: Vec<PortRange>,
    #[serde(default)]
    pub transport: Transport,
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ServicePack {
    pub schema: String,
    pub id: String,
    pub version: String,
    pub name: String,
    pub description: String,
    pub reviewed_against: String,
    pub destinations: Vec<PackDestination>,
}

impl ServicePack {
    pub fn parse(json: &str) -> Result<Self, String> {
        let p: ServicePack = serde_json::from_str(json).map_err(|e| e.to_string())?;
        if p.schema != SERVICE_PACK_SCHEMA {
            return Err(format!("unexpected schema {}", p.schema));
        }
        if p.destinations.is_empty() {
            return Err("a service pack needs destinations".into());
        }
        let mut seen = BTreeSet::new();
        for d in &p.destinations {
            validate_host_pattern(&d.host)?;
            if d.explanation.trim().len() < 8 {
                return Err(format!("{} needs an explanation", d.host));
            }
            if !seen.insert(&d.host) {
                return Err(format!("duplicate destination {}", d.host));
            }
        }
        Ok(p)
    }

    /// Expand to a destination set. `include_optional` and `intentions` let the owner choose; publication is
    /// excluded unless explicitly requested.
    pub fn to_destination_set(&self, include_optional: bool, intentions: Option<&[Intention]>) -> DestinationSet {
        let hosts = self
            .destinations
            .iter()
            .filter(|d| include_optional || d.necessity == Necessity::Required)
            .filter(|d| match intentions {
                Some(list) => list.contains(&d.intention),
                None => d.intention != Intention::Publish,
            })
            .map(|d| d.host.clone())
            .collect();
        DestinationSet {
            description: Some(format!("{} ({}@{})", self.name, self.id, self.version)),
            destinations: Destinations { hosts, ..Default::default() },
        }
    }

    pub fn explain(&self, host: &str) -> Option<&PackDestination> {
        self.destinations.iter().find(|d| crate::net::host_matches(&d.host, host))
    }
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq, Default)]
pub struct PackDiff {
    pub from: String,
    pub to: String,
    pub added: Vec<String>,
    pub removed: Vec<String>,
    pub changed: Vec<String>,
    /// True when the new version can permit destinations the old one did not. Requires review.
    pub expands_trust: bool,
}

pub fn diff_packs(old: &ServicePack, new: &ServicePack) -> PackDiff {
    let o: BTreeMap<&str, &PackDestination> = old.destinations.iter().map(|d| (d.host.as_str(), d)).collect();
    let n: BTreeMap<&str, &PackDestination> = new.destinations.iter().map(|d| (d.host.as_str(), d)).collect();
    let mut d = PackDiff { from: format!("{}@{}", old.id, old.version), to: format!("{}@{}", new.id, new.version), ..Default::default() };
    for (h, nd) in &n {
        match o.get(h) {
            None => {
                d.added.push(h.to_string());
                d.expands_trust = true;
            }
            Some(od) if od != nd => {
                d.changed.push(h.to_string());
                if (od.necessity == Necessity::Optional && nd.necessity == Necessity::Required)
                    || od.ports != nd.ports
                    || od.intention != nd.intention
                    || od.transport != nd.transport
                {
                    d.expands_trust = true;
                }
            }
            _ => {}
        }
    }
    for h in o.keys() {
        if !n.contains_key(h) {
            d.removed.push(h.to_string());
        }
    }
    d
}

pub fn builtin_service_packs() -> Vec<ServicePack> {
    [
        include_str!("../../../packs/services/github.json"),
        include_str!("../../../packs/services/npm.json"),
        include_str!("../../../packs/services/pypi.json"),
        include_str!("../../../packs/services/crates.json"),
        include_str!("../../../packs/services/anthropic.json"),
        include_str!("../../../packs/services/openai.json"),
        include_str!("../../../packs/services/google-ai.json"),
        include_str!("../../../packs/services/huggingface.json"),
        include_str!("../../../packs/services/ollama-registry.json"),
        include_str!("../../../packs/services/homebrew.json"),
    ]
    .iter()
    .map(|s| ServicePack::parse(s).expect("builtin service pack"))
    .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn builtins_parse_with_explanations() {
        let packs = builtin_service_packs();
        assert_eq!(packs.len(), 10);
        for p in &packs {
            for d in &p.destinations {
                assert!(!d.explanation.is_empty());
            }
        }
    }

    #[test]
    fn publication_excluded_by_default() {
        let gh = builtin_service_packs().into_iter().find(|p| p.id == "pypi").unwrap();
        let set = gh.to_destination_set(true, None);
        assert!(!set.destinations.hosts.contains(&"upload.pypi.org".to_string()));
        let set = gh.to_destination_set(true, Some(&[Intention::Publish]));
        assert_eq!(set.destinations.hosts, vec!["upload.pypi.org".to_string()]);
    }

    #[test]
    fn pack_updates_are_reviewable() {
        let old = builtin_service_packs().into_iter().find(|p| p.id == "npm").unwrap();
        let mut new = old.clone();
        new.version = "2026.11.1".into();
        new.destinations.push(PackDestination {
            host: "registry.yarnpkg.com".into(),
            necessity: Necessity::Optional,
            explanation: "Yarn mirror of the npm registry".into(),
            intention: Intention::Download,
            ports: vec![PortRange::single(443)],
            transport: Transport::Tcp,
        });
        let d = diff_packs(&old, &new);
        assert!(d.expands_trust);
        assert_eq!(d.added, vec!["registry.yarnpkg.com".to_string()]);
    }

    #[test]
    fn explains_a_destination() {
        let gh = builtin_service_packs().into_iter().find(|p| p.id == "github").unwrap();
        assert!(gh.explain("objects.githubusercontent.com").is_some());
        assert!(gh.explain("evil.example").is_none());
    }
}
