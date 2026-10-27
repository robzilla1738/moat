//! W05: a hostname the policy can refuse by name is refused before any DNS lookup, and the pre-lookup decision
//! never contradicts full evaluation for any address the name could resolve to.

use chrono::{DateTime, Utc};
use moat_core::enrichment::Enricher;
use moat_core::eval::{evaluate, hostname_admission, EvalContext, FlowAttempt, HostnameAdmission, Verdict};
use moat_core::identity::{AppIdentity, Boundary, SessionRef};
use moat_core::net::{Confidence, HostnameEvidence, HostnameSource, Transport};
use moat_core::policy::Policy;

const POLICY: &str = r#"
schema = "moat.policy.v1"
name = "names"
fallback_profile = "ordinary"
[destination_sets.lan_admin]
cidrs = ["192.168.1.2/32"]
[[profiles]]
id = "ordinary"
default = "observe"
[[profiles]]
id = "s"
default = "deny"
learning = "restrictive"
[[rules]]
id = "allow-gh"
action = "allow"
selector = { session = { profiles = ["s"] } }
destinations = { hosts = ["github.com", "*.githubusercontent.com"] }
transport = "tcp"
ports = [443]
provenance = { kind = "git", reference = "t" }
[[rules]]
id = "deny-bad"
action = "deny"
layer = "emergency"
selector = { session = { profiles = ["s"] } }
destinations = { hosts = ["*.bad.example"] }
transport = "tcp"
provenance = { kind = "git", reference = "t" }
[[rules]]
id = "allow-net"
action = "allow"
selector = { session = { profiles = ["s"] } }
destinations = { cidrs = ["203.0.113.0/24"] }
transport = "tcp"
ports = [8443]
provenance = { kind = "git", reference = "t" }
[[rules]]
id = "safety-admin"
action = "deny"
layer = "safety"
selector = { session = { any_protected = true } }
destinations = { sets = ["lan_admin"] }
transport = "tcp"
provenance = { kind = "built_in", reference = "t" }
"#;

fn at() -> DateTime<Utc> {
    "2026-10-27T15:00:00Z".parse().unwrap()
}

fn flow(host: &str, ip: &str, port: u16) -> FlowAttempt {
    FlowAttempt {
        id: "f".into(),
        device_id: "d".into(),
        user: None,
        process: None,
        app: AppIdentity::default(),
        ancestors: vec![],
        ancestry_complete: false,
        session: Some(SessionRef { id: "s1".into(), profile: "s".into(), boundary: Boundary::LinuxCgroup, verified: true }),
        remote_ip: ip.parse().unwrap(),
        remote_port: port,
        transport: Transport::Tcp,
        hostname: Some(HostnameEvidence { name: host.into(), source: HostnameSource::Sni, confidence: Confidence::Medium }),
        at: at(),
    }
}

#[test]
fn arbitrary_names_are_refused_without_lookup_and_agree_with_evaluation() {
    let p = Policy::parse(POLICY).unwrap();
    p.validate().unwrap();
    let e = Enricher::new();
    let ctx = EvalContext::new(&p, &e, "d");
    let addresses = ["127.0.0.1", "203.0.113.7", "198.51.100.1", "192.168.1.2", "10.0.0.1", "::1", "2001:db8::1"];
    let names = ["github.com", "raw.githubusercontent.com", "anything.example", "x.bad.example", "github.com.attacker.example"];
    for port in [443u16, 8443, 22] {
        for name in names {
            let a = hostname_admission(&ctx, &flow(name, "0.0.0.0", port));
            let verdicts: Vec<Verdict> = addresses.iter().map(|ip| evaluate(&ctx, &flow(name, ip, port)).verdict).collect();
            match &a {
                HostnameAdmission::DenyWithoutLookup { .. } => {
                    assert!(verdicts.iter().all(|v| *v == Verdict::Deny), "{name}:{port} refused before lookup but some address allows");
                }
                HostnameAdmission::ResolveAllowedName | HostnameAdmission::ResolveForAddressRules => {
                    assert!(verdicts.contains(&Verdict::Allow), "{name}:{port} would be resolved although nothing can allow it");
                }
            }
        }
    }
    // the cases that matter, explicitly
    assert!(matches!(hostname_admission(&ctx, &flow("anything.example", "0.0.0.0", 443)), HostnameAdmission::DenyWithoutLookup { .. }));
    assert!(matches!(hostname_admission(&ctx, &flow("x.bad.example", "0.0.0.0", 8443)), HostnameAdmission::DenyWithoutLookup { .. }));
    assert_eq!(hostname_admission(&ctx, &flow("github.com", "0.0.0.0", 443)), HostnameAdmission::ResolveAllowedName);
    assert_eq!(hostname_admission(&ctx, &flow("anything.example", "0.0.0.0", 8443)), HostnameAdmission::ResolveForAddressRules);
}
