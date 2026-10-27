//! Network vocabulary: transports, ports, address scopes and hostname evidence.

use std::fmt;
use std::net::IpAddr;
use std::str::FromStr;

use ipnet::IpNet;
use serde::{Deserialize, Deserializer, Serialize, Serializer};

#[derive(Serialize, Deserialize, Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord, Default)]
#[serde(rename_all = "snake_case")]
pub enum Transport {
    #[default]
    Any,
    Tcp,
    Udp,
}

impl Transport {
    pub fn matches(&self, actual: Transport) -> bool {
        matches!(self, Transport::Any) || *self == actual
    }
}

/// An inclusive port range. Serialized as `443` or `"8000-8999"`.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct PortRange {
    pub start: u16,
    pub end: u16,
}

impl PortRange {
    pub fn single(p: u16) -> Self {
        PortRange { start: p, end: p }
    }
    pub fn contains(&self, p: u16) -> bool {
        self.start <= p && p <= self.end
    }
}

impl fmt::Display for PortRange {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.start == self.end {
            write!(f, "{}", self.start)
        } else {
            write!(f, "{}-{}", self.start, self.end)
        }
    }
}

impl FromStr for PortRange {
    type Err = String;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let s = s.trim();
        if let Some((a, b)) = s.split_once('-') {
            let start: u16 = a.trim().parse().map_err(|_| format!("bad port range start: {s}"))?;
            let end: u16 = b.trim().parse().map_err(|_| format!("bad port range end: {s}"))?;
            if start > end {
                return Err(format!("port range start is after end: {s}"));
            }
            Ok(PortRange { start, end })
        } else {
            let p: u16 = s.parse().map_err(|_| format!("bad port: {s}"))?;
            Ok(PortRange::single(p))
        }
    }
}

impl Serialize for PortRange {
    fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        if self.start == self.end {
            s.serialize_u16(self.start)
        } else {
            s.serialize_str(&self.to_string())
        }
    }
}

impl<'de> Deserialize<'de> for PortRange {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        #[derive(Deserialize)]
        #[serde(untagged)]
        enum Raw {
            N(u64),
            S(String),
        }
        match Raw::deserialize(d)? {
            Raw::N(n) => {
                let p = u16::try_from(n).map_err(|_| serde::de::Error::custom(format!("port out of range: {n}")))?;
                Ok(PortRange::single(p))
            }
            Raw::S(s) => s.parse().map_err(serde::de::Error::custom),
        }
    }
}

/// Coarse address scopes. "Private services only" is built from these; it is never called air-gapped.
#[derive(Serialize, Deserialize, Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
#[serde(rename_all = "snake_case")]
pub enum NetScope {
    Loopback,
    LinkLocal,
    /// RFC 1918 / ULA addresses that are not the tailnet.
    Lan,
    /// Tailscale CGNAT range 100.64.0.0/10 and fd7a:115c:a1e0::/48.
    Tailnet,
    Multicast,
    Public,
}

impl NetScope {
    pub fn label(&self) -> &'static str {
        match self {
            NetScope::Loopback => "loopback",
            NetScope::LinkLocal => "link-local",
            NetScope::Lan => "LAN",
            NetScope::Tailnet => "tailnet",
            NetScope::Multicast => "multicast",
            NetScope::Public => "public Internet",
        }
    }
}

fn net(s: &str) -> IpNet {
    s.parse().expect("static network literal")
}

/// Classify an address. Pure function of the address; no lookups.
pub fn classify(ip: IpAddr) -> NetScope {
    if ip.is_loopback() {
        return NetScope::Loopback;
    }
    if ip.is_multicast() {
        return NetScope::Multicast;
    }
    match ip {
        IpAddr::V4(v4) => {
            if v4.is_link_local() {
                NetScope::LinkLocal
            } else if net("100.64.0.0/10").contains(&ip) {
                NetScope::Tailnet
            } else if v4.is_private() {
                NetScope::Lan
            } else if v4.is_unspecified() || v4.is_broadcast() {
                NetScope::LinkLocal
            } else {
                NetScope::Public
            }
        }
        IpAddr::V6(v6) => {
            if let Some(v4) = v6.to_ipv4_mapped() {
                return classify(IpAddr::V4(v4));
            }
            if net("fe80::/10").contains(&ip) {
                NetScope::LinkLocal
            } else if net("fd7a:115c:a1e0::/48").contains(&ip) {
                NetScope::Tailnet
            } else if net("fc00::/7").contains(&ip) {
                NetScope::Lan
            } else if v6.is_unspecified() {
                NetScope::LinkLocal
            } else {
                NetScope::Public
            }
        }
    }
}

/// Where a hostname for a connection came from. Hostname evidence is never treated as equivalent to an IP.
#[derive(Serialize, Deserialize, Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
#[serde(rename_all = "snake_case")]
pub enum HostnameSource {
    /// The OS flow API carried the hostname the app asked for (e.g. NEFilterFlow remote hostname).
    FlowApi,
    /// A policy proxy saw a CONNECT hostname.
    ConnectProxy,
    /// TLS SNI observed in cleartext.
    Sni,
    /// The Host header of a plain-HTTP request, seen by a policy proxy (first request on the connection only).
    HttpHost,
    /// Correlated from a DNS answer seen shortly before the connection.
    DnsAnswer,
    /// Reverse lookup or cache inference; weakest.
    Inferred,
}

#[derive(Serialize, Deserialize, Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
#[serde(rename_all = "snake_case")]
pub enum Confidence {
    Low,
    Medium,
    High,
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct HostnameEvidence {
    pub name: String,
    pub source: HostnameSource,
    pub confidence: Confidence,
}

/// Normalize a hostname for comparison: lowercase, no trailing dot.
pub fn normalize_host(h: &str) -> String {
    h.trim().trim_end_matches('.').to_ascii_lowercase()
}

/// Match a host pattern: exact (`api.github.com`) or wildcard suffix (`*.githubusercontent.com`, which does not
/// match the bare apex).
pub fn host_matches(pattern: &str, host: &str) -> bool {
    let p = normalize_host(pattern);
    let h = normalize_host(host);
    if let Some(suffix) = p.strip_prefix("*.") {
        h.len() > suffix.len() + 1 && h.ends_with(suffix) && h.as_bytes()[h.len() - suffix.len() - 1] == b'.'
    } else {
        p == h
    }
}

/// Validate a host pattern: letters, digits, hyphens, dots and an optional leading `*.`.
pub fn validate_host_pattern(p: &str) -> Result<(), String> {
    let body = p.strip_prefix("*.").unwrap_or(p);
    if body.is_empty() || body.len() > 253 {
        return Err(format!("invalid host pattern: {p:?}"));
    }
    if body.contains('*') {
        return Err(format!("wildcards are only allowed as a leading '*.': {p:?}"));
    }
    for label in body.split('.') {
        if label.is_empty()
            || label.len() > 63
            || !label.chars().all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_')
            || label.starts_with('-')
        {
            return Err(format!("invalid host pattern: {p:?}"));
        }
    }
    if body.parse::<IpAddr>().is_ok() {
        return Err(format!("use cidrs for addresses, not hosts: {p:?}"));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn classifies_scopes() {
        assert_eq!(classify("127.0.0.1".parse().unwrap()), NetScope::Loopback);
        assert_eq!(classify("::1".parse().unwrap()), NetScope::Loopback);
        assert_eq!(classify("192.168.1.20".parse().unwrap()), NetScope::Lan);
        assert_eq!(classify("10.0.0.5".parse().unwrap()), NetScope::Lan);
        assert_eq!(classify("100.101.102.103".parse().unwrap()), NetScope::Tailnet);
        assert_eq!(classify("fd7a:115c:a1e0::1".parse().unwrap()), NetScope::Tailnet);
        assert_eq!(classify("fd00::1".parse().unwrap()), NetScope::Lan);
        assert_eq!(classify("fe80::1".parse().unwrap()), NetScope::LinkLocal);
        assert_eq!(classify("169.254.1.1".parse().unwrap()), NetScope::LinkLocal);
        assert_eq!(classify("203.0.113.9".parse().unwrap()), NetScope::Public);
        assert_eq!(classify("2001:db8::1".parse().unwrap()), NetScope::Public);
        assert_eq!(classify("::ffff:192.168.0.1".parse().unwrap()), NetScope::Lan);
        assert_eq!(classify("224.0.0.251".parse().unwrap()), NetScope::Multicast);
    }

    #[test]
    fn host_wildcards() {
        assert!(host_matches("api.github.com", "API.GitHub.com."));
        assert!(host_matches("*.githubusercontent.com", "objects.githubusercontent.com"));
        assert!(!host_matches("*.githubusercontent.com", "githubusercontent.com"));
        assert!(!host_matches("*.githubusercontent.com", "evilgithubusercontent.com"));
        assert!(!host_matches("github.com", "api.github.com"));
    }

    #[test]
    fn host_pattern_validation() {
        assert!(validate_host_pattern("*.example.com").is_ok());
        assert!(validate_host_pattern("a*.example.com").is_err());
        assert!(validate_host_pattern("1.2.3.4").is_err());
        assert!(validate_host_pattern("").is_err());
        assert!(validate_host_pattern("bad host").is_err());
    }

    #[test]
    fn port_ranges_parse() {
        let p: PortRange = serde_json::from_str("443").unwrap();
        assert_eq!(p, PortRange::single(443));
        let p: PortRange = serde_json::from_str("\"8000-8100\"").unwrap();
        assert!(p.contains(8050) && !p.contains(8101));
        assert!(serde_json::from_str::<PortRange>("\"9-1\"").is_err());
        assert!(serde_json::from_str::<PortRange>("70000").is_err());
        assert_eq!(serde_json::to_string(&p).unwrap(), "\"8000-8100\"");
    }
}
