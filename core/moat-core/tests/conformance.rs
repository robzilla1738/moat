//! Runs the implementation-independent conformance cases in /conformance against moat-core.

use std::fs;
use std::path::{Path, PathBuf};

use moat_core::compile::{compile, CompileOptions};
use moat_core::enrichment::Enricher;
use moat_core::eval::{evaluate, EvalContext, FlowAttempt, Verdict, Winner};
use moat_core::{CapabilityAdvertisement, Policy};
use serde_json::Value;

fn root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../../conformance")
}

fn cases(dir: &str) -> Vec<(PathBuf, Value)> {
    let mut v: Vec<_> = fs::read_dir(root().join("cases").join(dir))
        .unwrap()
        .map(|e| e.unwrap().path())
        .filter(|p| p.extension().map(|e| e == "json").unwrap_or(false))
        .map(|p| {
            let j: Value = serde_json::from_str(&fs::read_to_string(&p).unwrap()).unwrap();
            (p, j)
        })
        .collect();
    v.sort_by(|a, b| a.0.cmp(&b.0));
    v
}

fn load_policy(case_path: &Path, rel: &str) -> Policy {
    let p = case_path.parent().unwrap().join(rel);
    Policy::parse(&fs::read_to_string(p).unwrap()).unwrap()
}

#[test]
fn policy_cases() {
    let all = cases("policy");
    assert!(all.len() >= 15);
    let enricher = Enricher::new();
    for (path, c) in all {
        let name = c["name"].as_str().unwrap();
        let policy = load_policy(&path, c["policy"].as_str().unwrap());
        policy.validate().unwrap();
        let flow: FlowAttempt = serde_json::from_value(c["flow"].clone()).unwrap_or_else(|e| panic!("{name}: {e}"));
        let ctx = EvalContext::new(&policy, &enricher, &flow.device_id);
        let d = evaluate(&ctx, &flow);
        let exp = &c["expect"];
        let want = if exp["verdict"] == "allow" { Verdict::Allow } else { Verdict::Deny };
        assert_eq!(d.verdict, want, "{name}: {d:?}");
        if let Some(o) = exp.get("permitted_by_observation") {
            assert_eq!(d.permitted_by_observation, o.as_bool().unwrap(), "{name}");
        }
        if let Some(w) = exp.get("winner").and_then(|w| w.as_str()) {
            let got = match &d.winner {
                Winner::Rule { id, .. } => format!("rule:{id}"),
                Winner::ProfileDefault { profile, .. } => format!("profile:{profile}"),
            };
            assert_eq!(got, w, "{name}");
        }
        if let Some(list) = exp.get("overridden_contains").and_then(|v| v.as_array()) {
            for id in list {
                assert!(d.overridden.iter().any(|o| o.id == id.as_str().unwrap()), "{name}: missing overridden {id}");
            }
        }
        if let Some(n) = exp.get("notes_contain").and_then(|v| v.as_str()) {
            assert!(d.notes.iter().any(|x| x.contains(n)), "{name}: notes {:?}", d.notes);
        }
    }
}

#[test]
fn compile_cases() {
    let all = cases("compile");
    assert!(all.len() >= 4);
    let opts = CompileOptions {
        target_devices: vec![],
        revision: 1,
        rollback_of: None,
        issued_at: "2026-10-26T12:00:00Z".parse().unwrap(),
        not_after: None,
    };
    for (path, c) in all {
        let name = c["name"].as_str().unwrap();
        let policy = load_policy(&path, c["policy"].as_str().unwrap());
        let adv = match c["adapter"].as_str().unwrap() {
            "linux" => CapabilityAdvertisement::linux_nftables_cgroup(),
            "linux-ip-only" => CapabilityAdvertisement::linux_nftables_cgroup_ip_only(),
            "macos" => CapabilityAdvertisement::macos_network_extension(),
            "dns_resolver" => CapabilityAdvertisement::dns_resolver("adguard-home"),
            other => panic!("unknown adapter {other}"),
        };
        let exp = &c["expect"];
        // Optional: the devices the snapshot targets (issue #26). Absent means fleet-wide.
        let targets: Vec<String> =
            c.get("target_devices").and_then(|v| v.as_array()).into_iter().flatten().map(|d| d.as_str().unwrap().to_string()).collect();
        let opts = CompileOptions { target_devices: targets.clone(), ..opts.clone() };
        let res = compile(&policy, &adv, &opts);
        if exp["compiles"].as_bool().unwrap() {
            let s = res.unwrap_or_else(|e| panic!("{name}: {e:?}"));
            let mut want = targets.clone();
            want.sort();
            assert_eq!(s.devices, want, "{name}: the snapshot binds its target devices");
            for id in exp.get("omitted_contains").and_then(|v| v.as_array()).into_iter().flatten() {
                assert!(s.report.omitted.iter().any(|o| o.rule_id == id.as_str().unwrap()), "{name}: {id} not omitted");
            }
            for id in exp.get("kept_contains").and_then(|v| v.as_array()).into_iter().flatten() {
                assert!(s.policy.rules.iter().any(|r| r.id == id.as_str().unwrap()), "{name}: {id} not kept");
                assert!(!s.report.omitted.iter().any(|o| o.rule_id == id.as_str().unwrap()), "{name}: {id} omitted");
            }
            for id in exp.get("warned_contains").and_then(|v| v.as_array()).into_iter().flatten() {
                assert!(s.report.warnings.iter().any(|w| w.rule_id == id.as_str().unwrap()), "{name}: {id} not warned");
            }
            for id in exp.get("unavailable_profiles_contains").and_then(|v| v.as_array()).into_iter().flatten() {
                assert!(s.report.unavailable_session_profiles.iter().any(|o| o == id.as_str().unwrap()), "{name}");
            }
        } else {
            let e = res.err().unwrap_or_else(|| panic!("{name}: expected failure"));
            let needle = exp["error_contains"].as_str().unwrap();
            assert!(e.iter().any(|x| x.message.contains(needle)), "{name}: {e:?}");
        }
    }
}
