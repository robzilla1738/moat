//! nftables enforcement adapter.
//!
//! Renders a verified [`Snapshot`] into one atomic nftables transaction (`table inet moat`). Precedence is
//! reproduced by rule order with first-match terminal verdicts: higher layers first, and within a layer every deny
//! before any allow, then the profile default. This mirrors `moat_core::eval` for the flows nftables can see.
//!
//! What this adapter can and cannot do is stated, never papered over:
//! * Protected sessions are matched by cgroup v2 ancestry (`socket cgroupv2 level 2 "moat.slice/p-<profile>"`).
//!   The profile cgroups must exist before the ruleset loads (nftables resolves the path to an id at load time).
//! * Ordinary applications cannot be told apart by nftables. Rules that select apps or ancestors are rejected by
//!   the compiler for this adapter; if one ever reaches the renderer, a deny fails rendering and an allow is left
//!   out with a report (leaving out an allow can only make things stricter).
//! * Hostname destinations are IP-only here. A deny that needs a hostname or provider dataset fails rendering;
//!   an allow is left out with a report.
//! * Counters are per rule, not per flow.

use std::collections::BTreeSet;
use std::fmt::Write as _;
use std::io::Write as _;
use std::process::{Command, Stdio};

use ipnet::IpNet;
use moat_core::compile::Snapshot;
use moat_core::net::{NetScope, PortRange, Transport};
use moat_core::policy::{Action, DefaultAction, Destinations, Policy, Rule};
use serde::{Deserialize, Serialize};

pub const TABLE: &str = "moat";
pub const LOCAL_EMERGENCY_TABLE: &str = "moat_local_emergency";

/// Where protected-session cgroups live, relative to the cgroup v2 mount.
#[derive(Clone, Debug)]
pub struct CgroupLayout {
    pub root_name: String,
    /// cgroup v2 mount, used to check that a session cgroup exists before a rule names it (nftables resolves the
    /// path at load time, so naming a missing cgroup would fail the whole transaction).
    pub mount: std::path::PathBuf,
    /// False when this host cannot enforce protected sessions: no session chains are rendered (and the launcher
    /// refuses sessions), so the ruleset never references cgroups that nftables cannot resolve.
    pub sessions_enabled: bool,
    /// Session egress proxy, when this host runs it: hostname rules in session chains are then enforced by the
    /// proxy (TCP only) instead of being left out.
    pub proxy: Option<ProxyLayout>,
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct ProxyLayout {
    /// Loopback port range the session listeners use (outside the ephemeral range).
    pub ports: (u16, u16),
    pub sessions: Vec<ProxiedSession>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ProxiedSession {
    pub id: String,
    pub profile: String,
    pub port: u16,
}

impl Default for CgroupLayout {
    fn default() -> Self {
        CgroupLayout { root_name: "moat.slice".into(), mount: "/sys/fs/cgroup".into(), sessions_enabled: true, proxy: None }
    }
}

impl CgroupLayout {
    pub fn profile_dir(&self, profile: &str) -> String {
        format!("{}/p-{}", self.root_name, sanitize(profile))
    }
    pub fn session_dir(&self, profile: &str, session_id: &str) -> String {
        format!("{}/s-{}", self.profile_dir(profile), sanitize(session_id))
    }
    pub fn exists(&self, rel: &str) -> bool {
        self.mount.join(rel).is_dir()
    }
}

/// Lowercase alphanumerics and dashes only (defense in depth: spliced into nftables literals and paths). The core
/// compiler rejects policies whose ids collide under this mapping (`moat_core::backend_ids`).
pub use moat_core::backend_ids::{chain_name, sanitize};

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq, Default)]
pub struct RenderReport {
    /// Allow rules left out on this adapter, with the reason. Leaving out an allow is stricter, never weaker.
    pub skipped_allows: Vec<(String, String)>,
    /// Profiles that get a session chain (and need a cgroup before load).
    pub session_profiles: Vec<String>,
    /// Facts the UI should show next to this device's coverage.
    pub notes: Vec<String>,
    /// Session profiles whose TCP goes through the session egress proxy (they have hostname rules).
    #[serde(default)]
    pub proxied_profiles: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RenderError(pub String);

impl std::fmt::Display for RenderError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

/// CIDRs equivalent to `moat_core::net::classify` for a scope, plus exclusions.
fn scope_cidrs(s: NetScope) -> (Vec<&'static str>, Vec<&'static str>) {
    match s {
        NetScope::Loopback => (vec!["127.0.0.0/8", "::1/128"], vec![]),
        NetScope::LinkLocal => (vec!["169.254.0.0/16", "0.0.0.0/32", "255.255.255.255/32", "fe80::/10", "::/128"], vec![]),
        NetScope::Lan => (vec!["10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "fc00::/7"], vec!["fd7a:115c:a1e0::/48"]),
        NetScope::Tailnet => (vec!["100.64.0.0/10", "fd7a:115c:a1e0::/48"], vec![]),
        NetScope::Multicast => (vec!["224.0.0.0/4", "ff00::/8"], vec![]),
        // Public = not any of the above.
        NetScope::Public => (vec!["0.0.0.0/0", "::/0"], NON_PUBLIC.to_vec()),
    }
}

const NON_PUBLIC: [&str; 15] = [
    "127.0.0.0/8",
    "::1/128",
    "169.254.0.0/16",
    "0.0.0.0/32",
    "255.255.255.255/32",
    "fe80::/10",
    "::/128",
    "10.0.0.0/8",
    "172.16.0.0/12",
    "192.168.0.0/16",
    "fc00::/7",
    "100.64.0.0/10",
    "224.0.0.0/4",
    "ff00::/8",
    "::ffff:0:0/96",
];

/// One concrete address match: include set and exclude set, per family.
#[derive(Debug, Clone, PartialEq, Eq)]
struct AddrMatch {
    v6: bool,
    include: Vec<String>,
    exclude: Vec<String>,
}

/// Expand destinations into nft address matches. Returns Err(reason) if something cannot be expressed.
/// With `via_proxy`, hostname (and hostname-based provider) destinations are left to the session egress proxy and
/// produce no nftables match here.
fn expand(policy: &Policy, d: &Destinations, depth: u8, via_proxy: bool) -> Result<Vec<AddrMatch>, String> {
    let mut out = Vec::new();
    if d.any {
        return Ok(vec![AddrMatch { v6: false, include: vec![], exclude: vec![] }]);
    }
    if !d.hosts.is_empty() && !via_proxy {
        return Err(format!("hostname destinations ({}) need hostname enforcement, which nftables lacks", d.hosts.join(", ")));
    }
    let ip_providers = d.providers.iter().any(|p| p.mode == moat_core::policy::ProviderMode::KnownIps);
    if !d.providers.is_empty() && (!via_proxy || ip_providers) {
        return Err("provider destinations need a loaded provider IP dataset; not rendered on this adapter yet".into());
    }
    let (mut v4, mut v6): (Vec<String>, Vec<String>) = (vec![], vec![]);
    for c in &d.cidrs {
        match c {
            IpNet::V4(_) => v4.push(c.to_string()),
            IpNet::V6(_) => v6.push(c.to_string()),
        }
    }
    if !v4.is_empty() {
        out.push(AddrMatch { v6: false, include: v4, exclude: vec![] });
    }
    if !v6.is_empty() {
        out.push(AddrMatch { v6: true, include: v6, exclude: vec![] });
    }
    for s in &d.scopes {
        let (inc, exc) = scope_cidrs(*s);
        for fam6 in [false, true] {
            let pick = |v: &[&str]| v.iter().filter(|c| c.contains(':') == fam6).map(|c| c.to_string()).collect::<Vec<_>>();
            let i = pick(&inc);
            if !i.is_empty() {
                out.push(AddrMatch { v6: fam6, include: i, exclude: pick(&exc) });
            }
        }
    }
    if depth == 0 {
        for name in &d.sets {
            let set = policy.destination_sets.get(name).ok_or_else(|| format!("unknown destination set {name}"))?;
            let sub = expand(policy, &set.destinations, 1, via_proxy).map_err(|e| format!("set {name}: {e}"))?;
            out.extend(sub);
        }
    }
    Ok(out)
}

fn l4(transport: Transport, ports: &[PortRange]) -> String {
    let ports_s = if ports.is_empty() {
        String::new()
    } else {
        let list: Vec<String> =
            ports.iter().map(|p| if p.start == p.end { p.start.to_string() } else { format!("{}-{}", p.start, p.end) }).collect();
        format!(" th dport {{ {} }}", list.join(", "))
    };
    match (transport, ports.is_empty()) {
        (Transport::Tcp, _) => format!(" meta l4proto tcp{ports_s}"),
        (Transport::Udp, _) => format!(" meta l4proto udp{ports_s}"),
        (Transport::Any, true) => String::new(),
        (Transport::Any, false) => format!(" meta l4proto {{ tcp, udp }}{ports_s}"),
    }
}

fn verdict(a: Action) -> &'static str {
    match a {
        Action::Allow => "accept",
        // reject (not drop) so a blocked tool fails fast instead of hanging until a timeout.
        Action::Deny => "reject",
    }
}

fn comment(s: &str) -> String {
    let c: String = s.chars().filter(|c| c.is_ascii_alphanumeric() || "-_.:@ ".contains(*c)).take(120).collect();
    format!("comment \"{c}\"")
}

/// Render the nft lines (without chain wrapper) for one rule. `uid_of` resolves policy user names.
fn rule_lines(policy: &Policy, r: &Rule, uid_of: &dyn Fn(&str) -> Option<u32>, via_proxy: bool) -> Result<Vec<String>, String> {
    if !r.selector.apps.is_empty() || !r.selector.ancestors.is_empty() {
        return Err("app/ancestor selectors need per-app enforcement, which nftables lacks".into());
    }
    let mut user_m = String::new();
    if !r.selector.users.is_empty() {
        let mut uids = Vec::new();
        for u in &r.selector.users {
            uids.push(uid_of(u).ok_or_else(|| format!("unknown local user {u}"))?.to_string());
        }
        user_m = format!(" meta skuid {{ {} }}", uids.join(", "));
    }
    let l4m = l4(r.transport, &r.ports);
    let mut lines = Vec::new();
    for m in expand(policy, &r.destinations, 0, via_proxy)? {
        let fam = if m.v6 { "ip6" } else { "ip" };
        let mut addr = String::new();
        if !m.include.is_empty() {
            let _ = write!(addr, " {fam} daddr {{ {} }}", m.include.join(", "));
        }
        if !m.exclude.is_empty() {
            let _ = write!(addr, " {fam} daddr != {{ {} }}", m.exclude.join(", "));
        }
        lines.push(format!("{user_m}{addr}{l4m} counter {} {}", verdict(r.action), comment(&r.id)).trim_start().to_string());
    }
    Ok(lines)
}

fn default_line(d: DefaultAction, profile: &str) -> String {
    match d {
        DefaultAction::Deny => format!("counter reject {}", comment(&format!("default:{profile}"))),
        DefaultAction::Allow => format!("counter accept {}", comment(&format!("default:{profile}"))),
        DefaultAction::Observe => format!("counter accept {}", comment(&format!("observe:{profile}"))),
    }
}

/// Which rules apply to this device (device-group selectors evaluated here).
fn applies_to_device(policy: &Policy, r: &Rule, device_id: &str) -> bool {
    r.selector.device_groups.is_empty()
        || r.selector.device_groups.iter().any(|g| policy.device_groups.get(g).map(|m| m.iter().any(|x| x == device_id)).unwrap_or(false))
}

/// Order rules by precedence: layer rank, then deny before allow, then source order.
fn ordered<'a>(rules: impl Iterator<Item = &'a Rule>) -> Vec<&'a Rule> {
    let mut v: Vec<(usize, &Rule)> = rules.enumerate().collect();
    v.sort_by_key(|(i, r)| (r.layer.rank(), if r.action == Action::Deny { 0 } else { 1 }, *i));
    v.into_iter().map(|(_, r)| r).collect()
}

fn push_rules(
    out: &mut String,
    policy: &Policy,
    rules: &[&Rule],
    uid_of: &dyn Fn(&str) -> Option<u32>,
    report: &mut RenderReport,
    session_scope: Option<(&CgroupLayout, &str)>,
    via_proxy: bool,
) -> Result<(), RenderError> {
    for r in rules {
        let ids: &[String] = r.selector.session.as_ref().map(|s| s.session_ids.as_slice()).unwrap_or(&[]);
        match rule_lines(policy, r, uid_of, via_proxy) {
            Ok(lines) if !ids.is_empty() => {
                // Bound to session instances: match the session's own cgroup. Sessions that no longer exist (or
                // never existed here) are left out; leaving out an allow is stricter.
                let Some((layout, profile)) = session_scope else { continue };
                for id in ids {
                    let rel = layout.session_dir(profile, id);
                    if !layout.exists(&rel) {
                        report.notes.push(format!("{}: session {id} is not running on this device; grant not rendered", r.id));
                        continue;
                    }
                    for l in &lines {
                        let _ = writeln!(out, "    socket cgroupv2 level 3 \"{rel}\" {l}");
                    }
                }
            }
            Ok(lines) => {
                for l in lines {
                    let _ = writeln!(out, "    {l}");
                }
            }
            Err(why) if r.action == Action::Allow => {
                if !report.skipped_allows.iter().any(|(id, _)| id == &r.id) {
                    report.skipped_allows.push((r.id.clone(), why));
                }
            }
            Err(why) => return Err(RenderError(format!("deny rule {} cannot be enforced here: {why}", r.id))),
        }
    }
    Ok(())
}

/// Render the complete atomic nftables transaction for a snapshot.
pub fn render(
    snap: &Snapshot,
    device_id: &str,
    layout: &CgroupLayout,
    uid_of: &dyn Fn(&str) -> Option<u32>,
) -> Result<(String, RenderReport), RenderError> {
    render_at(snap, device_id, layout, uid_of, chrono::Utc::now())
}

/// The earliest future expiry among the snapshot's rules: the endpoint re-renders then, so an expired grant stops
/// matching even with no controller reachable.
pub fn next_expiry(snap: &Snapshot, now: chrono::DateTime<chrono::Utc>) -> Option<chrono::DateTime<chrono::Utc>> {
    snap.policy.rules.iter().filter_map(|r| r.expires_at).filter(|e| *e > now).min()
}

pub fn render_at(
    snap: &Snapshot,
    device_id: &str,
    layout: &CgroupLayout,
    uid_of: &dyn Fn(&str) -> Option<u32>,
    now: chrono::DateTime<chrono::Utc>,
) -> Result<(String, RenderReport), RenderError> {
    let p = &snap.policy;
    let mut report = RenderReport::default();
    let device_rules: Vec<&Rule> =
        p.rules.iter().filter(|r| applies_to_device(p, r, device_id)).filter(|r| r.expires_at.map(|e| e > now).unwrap_or(true)).collect();
    // Profiles a protected session may name. Unavailable profiles get no chain: the launcher refuses them and any
    // process found under moat.slice without a known profile is rejected.
    let unavailable: BTreeSet<&String> = snap.report.unavailable_session_profiles.iter().collect();
    let session_profiles: Vec<&moat_core::policy::Profile> =
        if layout.sessions_enabled { p.profiles.iter().filter(|pr| !unavailable.contains(&pr.id)).collect() } else { Vec::new() };
    if !layout.sessions_enabled {
        report.notes.push("protected sessions are not enforceable on this host; no session chains rendered".into());
    }

    let mut chains = String::new();
    for prof in &session_profiles {
        let rules = ordered(device_rules.iter().copied().filter(|r| match &r.selector.session {
            Some(sm) => sm.any_protected || sm.profiles.contains(&prof.id) || (sm.profiles.is_empty() && !sm.session_ids.is_empty()),
            None => true,
        }));
        // A profile with session-scoped hostname rules sends its TCP through the egress proxy when this host runs it.
        let proxied = layout.proxy.is_some()
            && rules
                .iter()
                .any(|r| r.selector.session.is_some() && p.implied_capabilities(r).contains(&moat_core::Capability::HostnameEnforcement));
        if proxied {
            report.proxied_profiles.push(prof.id.clone());
        }
        let _ = writeln!(chains, "  chain {} {{", chain_name(&prof.id));
        push_rules(&mut chains, p, &rules, uid_of, &mut report, Some((layout, &prof.id)), proxied)?;
        let _ = writeln!(chains, "    {}", default_line(prof.default, &prof.id));
        let _ = writeln!(chains, "  }}");
        report.session_profiles.push(prof.id.clone());
    }

    let mut out = String::new();
    let _ =
        writeln!(out, "# Generated by moatd from {} revision {} ({}). Do not edit.", snap.policy_name, snap.revision, snap.policy_digest);
    // add + delete + define in one transaction: atomic replacement, and a failure leaves the old table in place.
    let _ = writeln!(out, "table inet {TABLE}\ndelete table inet {TABLE}\ntable inet {TABLE} {{");
    let _ = writeln!(out, "  chain output {{\n    type filter hook output priority filter; policy accept;");
    // Session egress proxy plumbing: its upstream connections were already decided with the full policy; each live
    // proxied session may reach only its own listener; every other use of the proxy port range is refused.
    let mut nat = String::new();
    if let Some(px) = &layout.proxy {
        let _ = writeln!(out, "    meta mark 0x{:08x} counter accept {}", crate::proxy::UPSTREAM_MARK, comment("egress-proxy-upstream"));
        for s in &px.sessions {
            if !report.proxied_profiles.contains(&s.profile) {
                continue;
            }
            let rel = layout.session_dir(&s.profile, &s.id);
            if !layout.exists(&rel) {
                report.notes.push(format!("egress proxy for session {} not rendered: its cgroup is gone", s.id));
                continue;
            }
            let c = comment(&format!("proxy:{}", s.id));
            let _ = writeln!(out, "    socket cgroupv2 level 3 \"{rel}\" ip daddr 127.0.0.1 tcp dport {} accept {c}", s.port);
            let _ = writeln!(out, "    socket cgroupv2 level 3 \"{rel}\" ip6 daddr ::1 tcp dport {} accept {c}", s.port);
            let _ = writeln!(
                nat,
                "    socket cgroupv2 level 3 \"{rel}\" meta nfproto ipv4 meta l4proto tcp ip daddr != 127.0.0.0/8 counter redirect to :{} {c}",
                s.port
            );
            let _ = writeln!(
                nat,
                "    socket cgroupv2 level 3 \"{rel}\" meta nfproto ipv6 meta l4proto tcp ip6 daddr != ::1 counter redirect to :{} {c}",
                s.port
            );
        }
        let (a, b) = px.ports;
        let _ = writeln!(out, "    ip daddr 127.0.0.0/8 tcp dport {a}-{b} counter reject {}", comment("proxy:not-this-session"));
        let _ = writeln!(out, "    ip6 daddr ::1 tcp dport {a}-{b} counter reject {}", comment("proxy:not-this-session"));
        if !report.proxied_profiles.is_empty() {
            report.notes.push(format!(
                "hostname rules for {} are enforced for TCP by the session egress proxy (TLS SNI / HTTP CONNECT / HTTP Host, no TLS interception); UDP stays IP-only",
                report.proxied_profiles.join(", ")
            ));
        }
    }
    for prof in &session_profiles {
        let _ = writeln!(
            out,
            "    socket cgroupv2 level 2 \"{}\" jump {} {}",
            layout.profile_dir(&prof.id),
            chain_name(&prof.id),
            comment(&format!("session:{}", prof.id))
        );
    }
    // Anything under moat.slice without a known, available profile: restrictive.
    if layout.sessions_enabled {
        let _ = writeln!(out, "    socket cgroupv2 level 1 \"{}\" counter reject {}", layout.root_name, comment("session:unknown-profile"));
    }
    // Ordinary traffic: rules without a session selector, then the fallback profile default.
    let ordinary = ordered(device_rules.iter().copied().filter(|r| r.selector.session.is_none()));
    push_rules(&mut out, p, &ordinary, uid_of, &mut report, None, false)?;
    let fb = p.profile(&p.fallback_profile).ok_or_else(|| RenderError(format!("fallback profile {} missing", p.fallback_profile)))?;
    if p.profiles.iter().any(|pr| !pr.applies_to.apps.is_empty() || !pr.applies_to.ancestors.is_empty()) {
        report.notes.push(
            "profiles that select ordinary apps cannot be told apart by nftables; ordinary traffic follows the fallback profile".into(),
        );
    }
    let _ = writeln!(out, "    {}", default_line(fb.default, &fb.id));
    let _ = writeln!(out, "  }}");
    if layout.proxy.is_some() {
        let _ = writeln!(out, "  chain proxy_nat {{\n    type nat hook output priority -100; policy accept;");
        out.push_str(&nat);
        let _ = writeln!(out, "  }}");
    }
    out.push_str(&chains);
    let _ = writeln!(out, "}}");
    if fb.default == DefaultAction::Observe {
        report.notes.push(format!("ordinary traffic is observed under {} (permitted, not enforced)", fb.id));
    }
    report.notes.push("counters are per rule, not per flow".into());
    Ok((out, report))
}

/// A local, owner-initiated whole-device isolation table that survives policy changes and controller loss.
/// Only `moatd recover clear-isolation` removes it.
pub fn render_local_emergency(keep: &[IpNet]) -> String {
    let mut s =
        format!("table inet {LOCAL_EMERGENCY_TABLE}\ndelete table inet {LOCAL_EMERGENCY_TABLE}\ntable inet {LOCAL_EMERGENCY_TABLE} {{\n");
    s.push_str("  chain output {\n    type filter hook output priority -10; policy accept;\n");
    s.push_str("    oif lo accept comment \"loopback\"\n");
    for n in keep {
        let fam = if matches!(n, IpNet::V6(_)) { "ip6" } else { "ip" };
        let _ = writeln!(s, "    {fam} daddr {n} accept comment \"recovery path\"");
    }
    s.push_str("    counter reject comment \"local-emergency-isolation\"\n  }\n}\n");
    s
}

/// How rules reach the kernel. Real: `nft -f -`. Tests: recorded.
pub trait NftBackend {
    fn apply(&mut self, ruleset: &str) -> Result<(), String>;
    fn check(&mut self, ruleset: &str) -> Result<(), String>;
    fn delete_table(&mut self, table: &str) -> Result<(), String>;
    fn list_json(&mut self, table: &str) -> Result<String, String>;
}

pub struct NftCli {
    pub binary: String,
}

impl Default for NftCli {
    fn default() -> Self {
        NftCli { binary: "nft".into() }
    }
}

impl NftCli {
    fn run(&self, args: &[&str], stdin: Option<&str>) -> Result<String, String> {
        let mut c = Command::new(&self.binary);
        c.args(args).stdin(if stdin.is_some() { Stdio::piped() } else { Stdio::null() }).stdout(Stdio::piped()).stderr(Stdio::piped());
        let mut child = c.spawn().map_err(|e| format!("{}: {e}", self.binary))?;
        if let Some(s) = stdin {
            child.stdin.take().unwrap().write_all(s.as_bytes()).map_err(|e| e.to_string())?;
        }
        let o = child.wait_with_output().map_err(|e| e.to_string())?;
        if o.status.success() {
            Ok(String::from_utf8_lossy(&o.stdout).into())
        } else {
            Err(String::from_utf8_lossy(&o.stderr).trim().to_string())
        }
    }
}

impl NftBackend for NftCli {
    fn apply(&mut self, ruleset: &str) -> Result<(), String> {
        self.run(&["-f", "-"], Some(ruleset)).map(|_| ())
    }
    fn check(&mut self, ruleset: &str) -> Result<(), String> {
        self.run(&["-c", "-f", "-"], Some(ruleset)).map(|_| ())
    }
    fn delete_table(&mut self, table: &str) -> Result<(), String> {
        let s = format!("table inet {table}\ndelete table inet {table}\n");
        self.run(&["-f", "-"], Some(&s)).map(|_| ())
    }
    fn list_json(&mut self, table: &str) -> Result<String, String> {
        self.run(&["-j", "list", "table", "inet", table], None)
    }
}

/// A rule-scoped counter reading parsed from `nft -j list table`.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
pub struct RuleCounter {
    pub comment: String,
    pub packets: u64,
    pub bytes: u64,
}

pub fn parse_counters(json: &str) -> Vec<RuleCounter> {
    let mut out = Vec::new();
    let Ok(v) = serde_json::from_str::<serde_json::Value>(json) else { return out };
    for item in v["nftables"].as_array().into_iter().flatten() {
        let Some(rule) = item.get("rule") else { continue };
        let comment = rule["comment"].as_str().unwrap_or("").to_string();
        for e in rule["expr"].as_array().into_iter().flatten() {
            if let Some(c) = e.get("counter") {
                out.push(RuleCounter {
                    comment: comment.clone(),
                    packets: c["packets"].as_u64().unwrap_or(0),
                    bytes: c["bytes"].as_u64().unwrap_or(0),
                });
            }
        }
    }
    out
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use chrono::Utc;
    use moat_core::compile::{compile, CompileOptions};
    use moat_core::CapabilityAdvertisement;

    pub fn home_snapshot() -> Snapshot {
        let p = Policy::parse(include_str!("../../../conformance/policies/home.toml")).unwrap();
        compile(
            &p,
            &CapabilityAdvertisement::linux_nftables_cgroup(),
            &CompileOptions { revision: 4, rollback_of: None, issued_at: Utc::now(), not_after: None },
        )
        .unwrap()
    }
    fn uid(u: &str) -> Option<u32> {
        (u == "robert").then_some(1000)
    }

    #[test]
    fn renders_atomic_table_with_session_chains() {
        let (s, rep) = render(&home_snapshot(), "omarchy", &CgroupLayout::default(), &uid).unwrap();
        assert!(s.starts_with("# Generated"));
        assert!(s.contains("table inet moat\ndelete table inet moat\ntable inet moat {"));
        assert!(s.contains("socket cgroupv2 level 2 \"moat.slice/p-coding-session\" jump s_coding_session"));
        assert!(s.contains("socket cgroupv2 level 1 \"moat.slice\" counter reject"));
        assert!(rep.session_profiles.contains(&"local-inference".to_string()));
        // without the session egress proxy, hostname-based coding allows are left out (stricter) with a report.
        assert!(!s.contains("github"));
        assert!(rep.skipped_allows.iter().any(|(id, _)| id == "coding-allow-github"));
        assert!(!s.contains("proxy_nat"));
    }

    #[test]
    fn safety_deny_precedes_session_allows() {
        let (s, _) = render(&home_snapshot(), "omarchy", &CgroupLayout::default(), &uid).unwrap();
        let chain = s.split("chain s_private_services_only {").nth(1).unwrap();
        let deny = chain.find("safety-workloads-never-reach-controller").unwrap();
        let allow = chain.find("private-services-lan-tailnet").unwrap();
        assert!(deny < allow, "{chain}");
        assert!(chain.contains("ip daddr { 192.168.1.2/32, 100.100.1.2/32 } counter reject"));
        // LAN scope on IPv6 excludes the tailnet ULA, matching classify()
        assert!(chain.contains("ip6 daddr { fc00::/7 } ip6 daddr != { fd7a:115c:a1e0::/48 }"));
        assert!(chain.trim_end().ends_with("}"));
        assert!(chain.contains("counter reject comment \"default:private-services-only\""));
    }

    #[test]
    fn ordinary_traffic_follows_fallback_observe() {
        let (s, rep) = render(&home_snapshot(), "omarchy", &CgroupLayout::default(), &uid).unwrap();
        let out = s.split("chain output {").nth(1).unwrap().split("  }").next().unwrap();
        assert!(out.contains("counter accept comment \"observe:ordinary-desktop-learning\""));
        assert!(rep.notes.iter().any(|n| n.contains("permitted, not enforced")));
        // session-only rules never appear in the ordinary chain
        assert!(!out.contains("inference-loopback"));
    }

    fn rule(toml_rule: &str) -> Snapshot {
        let mut t = include_str!("../../../conformance/policies/home.toml").to_string();
        t.push_str(toml_rule);
        let p = Policy::parse(&t).unwrap();
        let mut snap = home_snapshot();
        snap.policy = p;
        snap
    }

    #[test]
    fn users_ports_transport_render() {
        let snap = rule("\n[[rules]]\nid = \"robert-no-smtp\"\naction = \"deny\"\nselector = { users = [\"robert\"] }\ndestinations = { scopes = [\"public\"] }\ntransport = \"tcp\"\nports = [25, \"465-587\"]\nprovenance = { kind = \"git\", reference = \"t\" }\n");
        let (s, _) = render(&snap, "omarchy", &CgroupLayout::default(), &uid).unwrap();
        assert!(s.contains("meta skuid { 1000 } ip daddr { 0.0.0.0/0 } ip daddr != {"), "{s}");
        assert!(s.contains("meta l4proto tcp th dport { 25, 465-587 } counter reject comment \"robert-no-smtp\""));
        // unknown user is an error, not a silently broader rule
        let snap = rule("\n[[rules]]\nid = \"x\"\naction = \"deny\"\nselector = { users = [\"mallory\"] }\ndestinations = { any = true }\nprovenance = { kind = \"git\", reference = \"t\" }\n");
        assert!(render(&snap, "omarchy", &CgroupLayout::default(), &uid).is_err());
    }

    #[test]
    fn unrenderable_deny_fails_and_allow_is_skipped() {
        let snap = rule("\n[[rules]]\nid = \"deny-host\"\naction = \"deny\"\ndestinations = { hosts = [\"evil.example\"] }\nprovenance = { kind = \"git\", reference = \"t\" }\n");
        let e = render(&snap, "omarchy", &CgroupLayout::default(), &uid).unwrap_err();
        assert!(e.0.contains("deny-host"));
        let snap = rule("\n[[rules]]\nid = \"allow-host\"\naction = \"allow\"\ndestinations = { hosts = [\"ok.example\"] }\nprovenance = { kind = \"git\", reference = \"t\" }\n");
        let (s, rep) = render(&snap, "omarchy", &CgroupLayout::default(), &uid).unwrap();
        assert!(!s.contains("allow-host"));
        assert_eq!(rep.skipped_allows[0].0, "allow-host");
    }

    #[test]
    fn device_groups_filter_rules() {
        let snap = rule("\n[[rules]]\nid = \"servers-only\"\naction = \"deny\"\nselector = { device_groups = [\"servers\"] }\ndestinations = { scopes = [\"multicast\"] }\nprovenance = { kind = \"git\", reference = \"t\" }\n");
        assert!(render(&snap, "mini", &CgroupLayout::default(), &uid).unwrap().0.contains("servers-only"));
        assert!(!render(&snap, "omarchy", &CgroupLayout::default(), &uid).unwrap().0.contains("servers-only"));
    }

    #[test]
    fn scope_tables_agree_with_classify() {
        use moat_core::net::classify;
        let samples = [
            "127.0.0.1",
            "::1",
            "169.254.3.4",
            "fe80::1",
            "10.1.2.3",
            "172.20.0.1",
            "192.168.1.9",
            "fd00::5",
            "100.100.1.2",
            "fd7a:115c:a1e0::9",
            "224.0.0.251",
            "ff02::fb",
            "8.8.8.8",
            "2606:4700::1111",
            "140.82.112.3",
        ];
        for s in samples {
            let ip: std::net::IpAddr = s.parse().unwrap();
            let want = classify(ip);
            for scope in [NetScope::Loopback, NetScope::LinkLocal, NetScope::Lan, NetScope::Tailnet, NetScope::Multicast, NetScope::Public]
            {
                let (inc, exc) = scope_cidrs(scope);
                let inside = |v: &[&str]| v.iter().any(|c| c.parse::<IpNet>().unwrap().contains(&ip));
                let hit = inside(&inc) && !inside(&exc);
                assert_eq!(hit, scope == want, "{s}: scope {scope:?} vs classify {want:?}");
            }
        }
    }

    #[test]
    fn session_bound_grants_render_only_for_live_sessions_and_expire() {
        let d = tempfile::tempdir().unwrap();
        let layout = CgroupLayout { root_name: "moat.slice".into(), mount: d.path().into(), sessions_enabled: true, proxy: None };
        let mut snap = home_snapshot();
        snap.policy = Policy::parse(include_str!("../../../conformance/policies/home-with-grant.toml")).unwrap();
        let before: chrono::DateTime<chrono::Utc> = "2026-10-26T12:30:00Z".parse().unwrap();
        // session not running here: grant left out with a note
        let (s, rep) = render_at(&snap, "omarchy", &layout, &uid, before).unwrap();
        assert!(!s.contains("grant-sess-1-oss"));
        assert!(rep.notes.iter().any(|n| n.contains("sess-1")));
        // session running: matched by its own cgroup, ahead of the profile default
        std::fs::create_dir_all(d.path().join("moat.slice/p-coding-session/s-sess-1")).unwrap();
        let (s, _) = render_at(&snap, "omarchy", &layout, &uid, before).unwrap();
        let chain = s.split("chain s_coding_session {").nth(1).unwrap();
        assert!(chain.contains("socket cgroupv2 level 3 \"moat.slice/p-coding-session/s-sess-1\" ip daddr { 203.0.113.50/32 } meta l4proto tcp th dport { 443 } counter accept"), "{chain}");
        assert!(chain.find("grant-sess-1-oss").unwrap() < chain.find("default:coding-session").unwrap());
        // not in other profiles' chains
        assert!(!s.split("chain s_local_inference {").nth(1).unwrap().split("  }").next().unwrap().contains("grant-sess-1-oss"));
        assert_eq!(next_expiry(&snap, before), Some("2026-10-26T13:00:00Z".parse().unwrap()));
        let after: chrono::DateTime<chrono::Utc> = "2026-10-26T13:00:01Z".parse().unwrap();
        assert!(!render_at(&snap, "omarchy", &layout, &uid, after).unwrap().0.contains("grant-sess-1-oss"));
        assert_eq!(next_expiry(&snap, after), None);
    }

    #[test]
    fn local_emergency_keeps_only_recovery_paths() {
        let s = render_local_emergency(&["100.100.1.2/32".parse().unwrap()]);
        assert!(s.contains("priority -10"));
        assert!(s.contains("ip daddr 100.100.1.2/32 accept"));
        assert!(s.trim_end().ends_with("}"));
        assert!(s.contains("counter reject"));
    }

    #[test]
    fn counters_parse() {
        let j = r#"{"nftables":[{"metainfo":{}},{"rule":{"family":"inet","table":"moat","chain":"output","handle":4,"comment":"default:coding-session","expr":[{"counter":{"packets":3,"bytes":180}},{"reject":null}]}}]}"#;
        let c = parse_counters(j);
        assert_eq!(c, vec![RuleCounter { comment: "default:coding-session".into(), packets: 3, bytes: 180 }]);
    }

    #[test]
    fn sanitize_blocks_injection() {
        assert_eq!(sanitize("a\"; flush ruleset"), "a---flush-ruleset");
    }

    #[test]
    fn session_proxy_redirects_only_its_own_session_and_fences_the_port_range() {
        let d = tempfile::tempdir().unwrap();
        std::fs::create_dir_all(d.path().join("moat.slice/p-coding-session/s-a1")).unwrap();
        let layout = CgroupLayout {
            root_name: "moat.slice".into(),
            mount: d.path().into(),
            sessions_enabled: true,
            proxy: Some(ProxyLayout {
                ports: (15000, 15999),
                sessions: vec![
                    ProxiedSession { id: "a1".into(), profile: "coding-session".into(), port: 15000 },
                    ProxiedSession { id: "gone".into(), profile: "coding-session".into(), port: 15001 },
                ],
            }),
        };
        let (s, rep) = render(&home_snapshot(), "omarchy", &layout, &uid).unwrap();
        assert_eq!(rep.proxied_profiles, vec!["coding-session".to_string()], "only profiles with hostname rules");
        assert!(rep.skipped_allows.is_empty(), "{:?}", rep.skipped_allows);
        let out = s.split("chain output {").nth(1).unwrap().split("\n  }").next().unwrap();
        let mark = out.find("meta mark 0x4d4f4154 counter accept").unwrap();
        let own =
            out.find("socket cgroupv2 level 3 \"moat.slice/p-coding-session/s-a1\" ip daddr 127.0.0.1 tcp dport 15000 accept").unwrap();
        let fence = out.find("ip daddr 127.0.0.0/8 tcp dport 15000-15999 counter reject").unwrap();
        let jump = out.find("jump s_coding_session").unwrap();
        assert!(mark < own && own < fence && fence < jump, "{out}");
        assert!(out.contains("ip6 daddr ::1 tcp dport 15000-15999 counter reject"));
        assert!(!s.contains("s-gone"), "sessions whose cgroup is gone are not referenced");
        let nat = s.split("chain proxy_nat {").nth(1).unwrap().split("\n  }").next().unwrap();
        assert!(nat.contains("type nat hook output priority -100"));
        assert!(nat.contains("socket cgroupv2 level 3 \"moat.slice/p-coding-session/s-a1\" meta nfproto ipv4 meta l4proto tcp ip daddr != 127.0.0.0/8 counter redirect to :15000"));
        assert!(nat.contains("meta nfproto ipv6 meta l4proto tcp ip6 daddr != ::1 counter redirect to :15000"));
        // hostname allows produce no nftables match (the proxy enforces them); IP rules and the safety deny remain
        let chain = s.split("chain s_coding_session {").nth(1).unwrap().split("\n  }").next().unwrap();
        assert!(!chain.contains("coding-allow-github"));
        assert!(chain.contains("safety-workloads-never-reach-controller"));
        assert!(chain.contains("counter reject comment \"default:coding-session\""));
        assert!(rep.notes.iter().any(|n| n.contains("no TLS interception")));
        // a profile without hostname rules is not proxied
        assert!(!nat.contains("p-local-inference"));
    }
}
