//! Cloud provider / ASN / region / GeoIP enrichment from batched datasets.
//!
//! Provider, ASN owner, service region and GeoIP location are *different facts*. Each fact carries its source,
//! update date and uncertainty. Datasets are downloaded in batches; nothing here sends an observed destination to
//! a public lookup service.

use std::net::IpAddr;

use ipnet::IpNet;
use serde::{Deserialize, Serialize};

use crate::net::{normalize_host, Confidence};

#[derive(Serialize, Deserialize, Clone, Copy, Debug, PartialEq, Eq, Hash)]
#[serde(rename_all = "snake_case")]
pub enum FactKind {
    CloudProvider,
    AsnOwner,
    ServiceRegion,
    GeoipLocation,
    Service,
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
pub struct Fact {
    pub kind: FactKind,
    pub value: String,
    pub source: String,
    /// Dataset date (YYYY-MM-DD) as published by the source.
    pub as_of: String,
    pub confidence: Confidence,
    pub caveat: String,
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct RangeEntry {
    pub cidr: IpNet,
    pub provider: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub service: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub region: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub asn: Option<u32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub asn_owner: Option<String>,
}

/// A batch-downloaded IP range dataset.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct RangeDataset {
    pub schema: String,
    pub source: String,
    pub as_of: String,
    /// True for fixtures/demo data that must never be presented as real attribution.
    #[serde(default)]
    pub sample: bool,
    pub entries: Vec<RangeEntry>,
}

/// A documented hostname pattern for a provider's regional endpoints, e.g. Alibaba OSS `oss-<region>.aliyuncs.com`.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct EndpointPattern {
    pub provider: String,
    pub service: String,
    /// Suffix after the region label, e.g. `.aliyuncs.com`.
    pub suffix: String,
    /// Prefix of the region label, e.g. `oss-` (the region follows).
    pub label_prefix: String,
    pub reference: String,
    /// Human region names for known ids.
    #[serde(default)]
    pub region_names: std::collections::BTreeMap<String, String>,
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
pub struct EndpointMatch {
    pub provider: String,
    pub service: String,
    pub region: String,
    pub region_name: Option<String>,
    pub reference: String,
}

/// Built-in documented endpoint patterns. These identify a *service region label for an observed hostname*; they
/// never identify who operates a bucket.
pub fn builtin_endpoint_patterns() -> Vec<EndpointPattern> {
    let mut ali = std::collections::BTreeMap::new();
    for (k, v) in [
        ("cn-beijing", "Beijing"),
        ("cn-hangzhou", "Hangzhou"),
        ("cn-shanghai", "Shanghai"),
        ("cn-shenzhen", "Shenzhen"),
        ("cn-hongkong", "Hong Kong"),
        ("ap-southeast-1", "Singapore"),
        ("us-west-1", "US (Silicon Valley)"),
        ("eu-central-1", "Germany (Frankfurt)"),
    ] {
        ali.insert(k.to_string(), v.to_string());
    }
    let mut aws = std::collections::BTreeMap::new();
    for (k, v) in [("us-east-1", "US East (N. Virginia)"), ("us-west-2", "US West (Oregon)"), ("eu-west-1", "Europe (Ireland)")] {
        aws.insert(k.to_string(), v.to_string());
    }
    vec![
        EndpointPattern {
            provider: "alibaba-cloud".into(),
            service: "OSS".into(),
            suffix: ".aliyuncs.com".into(),
            label_prefix: "oss-".into(),
            reference: "https://www.alibabacloud.com/help/en/oss/user-guide/regions-and-endpoints".into(),
            region_names: ali,
        },
        EndpointPattern {
            provider: "aws".into(),
            service: "S3".into(),
            suffix: ".amazonaws.com".into(),
            label_prefix: "s3.".into(),
            reference: "https://docs.aws.amazon.com/general/latest/gr/s3.html".into(),
            region_names: aws,
        },
    ]
}

/// Find a documented region endpoint in a hostname. Handles `oss-cn-beijing.aliyuncs.com`,
/// `bucket.oss-cn-beijing.aliyuncs.com`, `oss-cn-beijing-internal.aliyuncs.com` and `bucket.s3.us-east-1.amazonaws.com`.
pub fn match_endpoint(patterns: &[EndpointPattern], host: &str) -> Option<EndpointMatch> {
    let h = normalize_host(host);
    for p in patterns {
        let Some(rest) = h.strip_suffix(p.suffix.as_str()) else { continue };
        // rest = "...<label_prefix><region>[-internal]"
        let Some(idx) = rest.rfind(p.label_prefix.as_str()) else { continue };
        if idx > 0 && rest.as_bytes()[idx - 1] != b'.' {
            continue;
        }
        let mut region = &rest[idx + p.label_prefix.len()..];
        if region.contains('.') {
            continue;
        }
        region = region.strip_suffix("-internal").unwrap_or(region);
        if region.is_empty() || !region.chars().all(|c| c.is_ascii_alphanumeric() || c == '-') {
            continue;
        }
        return Some(EndpointMatch {
            provider: p.provider.clone(),
            service: p.service.clone(),
            region: region.to_string(),
            region_name: p.region_names.get(region).cloned(),
            reference: p.reference.clone(),
        });
    }
    None
}

#[derive(Default, Clone, Debug)]
pub struct Enricher {
    datasets: Vec<RangeDataset>,
    patterns: Vec<EndpointPattern>,
}

impl Enricher {
    pub fn new() -> Self {
        Enricher { datasets: Vec::new(), patterns: builtin_endpoint_patterns() }
    }

    pub fn with_dataset(mut self, d: RangeDataset) -> Self {
        self.datasets.push(d);
        self
    }

    pub fn add_dataset(&mut self, d: RangeDataset) {
        self.datasets.push(d);
    }

    pub fn patterns(&self) -> &[EndpointPattern] {
        &self.patterns
    }

    /// Most specific range entry per dataset containing `ip`.
    pub fn ranges_for(&self, ip: IpAddr) -> Vec<(&RangeDataset, &RangeEntry)> {
        let mut out = Vec::new();
        for d in &self.datasets {
            if let Some(e) = d.entries.iter().filter(|e| e.cidr.contains(&ip)).max_by_key(|e| e.cidr.prefix_len()) {
                out.push((d, e));
            }
        }
        out
    }

    pub fn provider_of_ip(&self, ip: IpAddr) -> Option<(String, Option<String>)> {
        self.ranges_for(ip).first().map(|(_, e)| (e.provider.clone(), e.region.clone()))
    }

    /// All facts for a destination, each with source and uncertainty.
    pub fn facts(&self, ip: Option<IpAddr>, host: Option<&str>) -> Vec<Fact> {
        let mut facts = Vec::new();
        if let Some(ip) = ip {
            for (d, e) in self.ranges_for(ip) {
                let sample = if d.sample { " (sample dataset: not real attribution)" } else { "" };
                facts.push(Fact {
                    kind: FactKind::CloudProvider,
                    value: e.provider.clone(),
                    source: d.source.clone(),
                    as_of: d.as_of.clone(),
                    confidence: if d.sample { Confidence::Low } else { Confidence::High },
                    caveat: format!("address listed in the provider's published ranges{sample}; does not identify the customer using it"),
                });
                if let Some(r) = &e.region {
                    facts.push(Fact {
                        kind: FactKind::ServiceRegion,
                        value: r.clone(),
                        source: d.source.clone(),
                        as_of: d.as_of.clone(),
                        confidence: Confidence::Medium,
                        caveat: format!("provider-declared service region for the range{sample}; not a physical location guarantee"),
                    });
                }
                if let (Some(asn), owner) = (e.asn, &e.asn_owner) {
                    facts.push(Fact {
                        kind: FactKind::AsnOwner,
                        value: format!("AS{asn}{}", owner.as_ref().map(|o| format!(" {o}")).unwrap_or_default()),
                        source: d.source.clone(),
                        as_of: d.as_of.clone(),
                        confidence: Confidence::Medium,
                        caveat: format!("the ASN announcing the range is not necessarily the service operator{sample}"),
                    });
                }
            }
        }
        if let Some(h) = host {
            if let Some(m) = match_endpoint(&self.patterns, h) {
                facts.push(Fact {
                    kind: FactKind::Service,
                    value: format!("{} {}", provider_display(&m.provider), m.service),
                    source: m.reference.clone(),
                    as_of: "documented pattern".into(),
                    confidence: Confidence::Medium,
                    caveat: "derived from the hostname; the bucket or account operator is unknown".into(),
                });
                facts.push(Fact {
                    kind: FactKind::ServiceRegion,
                    value: m.region_name.clone().unwrap_or_else(|| m.region.clone()),
                    source: m.reference,
                    as_of: "documented pattern".into(),
                    confidence: Confidence::Medium,
                    caveat: "the endpoint name indicates this region; it is not a GeoIP measurement".into(),
                });
            }
        }
        facts
    }
}

pub fn provider_display(id: &str) -> String {
    match id {
        "alibaba-cloud" => "Alibaba Cloud".into(),
        "aws" => "AWS".into(),
        "gcp" => "Google Cloud".into(),
        "azure" => "Microsoft Azure".into(),
        "cloudflare" => "Cloudflare".into(),
        other => other.to_string(),
    }
}

pub const RANGE_SCHEMA: &str = "moat.ranges.v1";

/// Import AWS `ip-ranges.json` (https://ip-ranges.amazonaws.com/ip-ranges.json).
pub fn import_aws_ip_ranges(json: &str) -> Result<RangeDataset, String> {
    #[derive(Deserialize)]
    struct P4 {
        ip_prefix: String,
        region: String,
        service: String,
    }
    #[derive(Deserialize)]
    struct P6 {
        ipv6_prefix: String,
        region: String,
        service: String,
    }
    #[derive(Deserialize)]
    struct Doc {
        #[serde(rename = "createDate")]
        create_date: String,
        prefixes: Vec<P4>,
        #[serde(default)]
        ipv6_prefixes: Vec<P6>,
    }
    let d: Doc = serde_json::from_str(json).map_err(|e| format!("not an AWS ip-ranges document: {e}"))?;
    let mut entries = Vec::new();
    for p in d.prefixes {
        entries.push(RangeEntry {
            cidr: p.ip_prefix.parse().map_err(|e| format!("{e}"))?,
            provider: "aws".into(),
            service: Some(p.service),
            region: Some(p.region),
            asn: None,
            asn_owner: None,
        });
    }
    for p in d.ipv6_prefixes {
        entries.push(RangeEntry {
            cidr: p.ipv6_prefix.parse().map_err(|e| format!("{e}"))?,
            provider: "aws".into(),
            service: Some(p.service),
            region: Some(p.region),
            asn: None,
            asn_owner: None,
        });
    }
    Ok(RangeDataset {
        schema: RANGE_SCHEMA.into(),
        source: "https://ip-ranges.amazonaws.com/ip-ranges.json".into(),
        as_of: d.create_date.chars().take(10).collect(),
        sample: false,
        entries,
    })
}

/// Import Google Cloud `cloud.json` (https://www.gstatic.com/ipranges/cloud.json).
pub fn import_gcp_cloud_json(json: &str) -> Result<RangeDataset, String> {
    #[derive(Deserialize)]
    struct P {
        #[serde(rename = "ipv4Prefix")]
        v4: Option<String>,
        #[serde(rename = "ipv6Prefix")]
        v6: Option<String>,
        scope: Option<String>,
        service: Option<String>,
    }
    #[derive(Deserialize)]
    struct Doc {
        #[serde(rename = "creationTime")]
        creation_time: String,
        prefixes: Vec<P>,
    }
    let d: Doc = serde_json::from_str(json).map_err(|e| format!("not a GCP cloud.json document: {e}"))?;
    let mut entries = Vec::new();
    for p in d.prefixes {
        let c = p.v4.or(p.v6).ok_or("prefix without address")?;
        entries.push(RangeEntry {
            cidr: c.parse().map_err(|e| format!("{e}"))?,
            provider: "gcp".into(),
            service: p.service,
            region: p.scope,
            asn: None,
            asn_owner: None,
        });
    }
    Ok(RangeDataset {
        schema: RANGE_SCHEMA.into(),
        source: "https://www.gstatic.com/ipranges/cloud.json".into(),
        as_of: d.creation_time.chars().take(10).collect(),
        sample: false,
        entries,
    })
}

/// Generic CSV: `cidr,provider,service,region,asn,asn_owner` (header required).
pub fn import_csv(text: &str, source: &str, as_of: &str) -> Result<RangeDataset, String> {
    let mut lines = text.lines().filter(|l| !l.trim().is_empty() && !l.starts_with('#'));
    let header = lines.next().ok_or("empty CSV")?;
    if !header.trim().starts_with("cidr,provider") {
        return Err("CSV header must start with cidr,provider".into());
    }
    let mut entries = Vec::new();
    for (n, l) in lines.enumerate() {
        let f: Vec<&str> = l.split(',').map(|s| s.trim()).collect();
        if f.len() < 2 {
            return Err(format!("line {}: need at least cidr,provider", n + 2));
        }
        let opt = |i: usize| f.get(i).filter(|s| !s.is_empty()).map(|s| s.to_string());
        entries.push(RangeEntry {
            cidr: f[0].parse().map_err(|e| format!("line {}: {e}", n + 2))?,
            provider: f[1].to_string(),
            service: opt(2),
            region: opt(3),
            asn: opt(4).and_then(|s| s.trim_start_matches("AS").parse().ok()),
            asn_owner: opt(5),
        });
    }
    Ok(RangeDataset { schema: RANGE_SCHEMA.into(), source: source.into(), as_of: as_of.into(), sample: false, entries })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn alibaba_oss_region() {
        let p = builtin_endpoint_patterns();
        let m = match_endpoint(&p, "oss-cn-beijing.aliyuncs.com").unwrap();
        assert_eq!(m.region, "cn-beijing");
        assert_eq!(m.region_name.as_deref(), Some("Beijing"));
        let m = match_endpoint(&p, "my-bucket.oss-cn-hangzhou-internal.aliyuncs.com").unwrap();
        assert_eq!(m.region, "cn-hangzhou");
        assert!(match_endpoint(&p, "notoss-cn-beijing.aliyuncs.com").is_none());
        assert!(match_endpoint(&p, "example.com").is_none());
        let m = match_endpoint(&p, "bucket.s3.us-east-1.amazonaws.com").unwrap();
        assert_eq!(m.provider, "aws");
    }

    #[test]
    fn facts_carry_source_and_caveats() {
        let ds = import_csv(
            "cidr,provider,service,region,asn,asn_owner\n203.0.113.0/24,alibaba-cloud,OSS,cn-beijing,AS64500,Example\n",
            "fixture",
            "2026-10-01",
        )
        .unwrap();
        let e = Enricher::new().with_dataset(ds);
        let f = e.facts(Some("203.0.113.7".parse().unwrap()), Some("oss-cn-beijing.aliyuncs.com"));
        assert!(f.iter().any(|x| x.kind == FactKind::CloudProvider && x.value == "alibaba-cloud"));
        assert!(f.iter().any(|x| x.kind == FactKind::AsnOwner));
        assert!(f.iter().all(|x| !x.caveat.is_empty() && !x.source.is_empty()));
    }

    #[test]
    fn imports_aws_format() {
        let j = r#"{"syncToken":"1","createDate":"2026-10-01-00-00-00","prefixes":[{"ip_prefix":"198.51.100.0/24","region":"us-east-1","service":"S3","network_border_group":"us-east-1"}],"ipv6_prefixes":[{"ipv6_prefix":"2001:db8::/32","region":"us-east-1","service":"S3","network_border_group":"us-east-1"}]}"#;
        let d = import_aws_ip_ranges(j).unwrap();
        assert_eq!(d.entries.len(), 2);
        assert_eq!(d.as_of, "2026-10-01");
    }

    #[test]
    fn imports_gcp_format() {
        let j = r#"{"syncToken":"1","creationTime":"2026-10-02T00:00:00","prefixes":[{"ipv4Prefix":"192.0.2.0/24","service":"Google Cloud","scope":"us-central1"}]}"#;
        let d = import_gcp_cloud_json(j).unwrap();
        assert_eq!(d.entries[0].region.as_deref(), Some("us-central1"));
    }
}
