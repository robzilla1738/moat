//! The claim ledger (docs/claim-ledger.json) is checked, not just written: nothing is marked supported without
//! installed or real-workflow evidence, every defect a claim cites exists, and docs/STATUS.md lists every claim.

use std::collections::BTreeSet;

use serde_json::Value;

const LEDGER: &str = include_str!("../../../docs/claim-ledger.json");
const STATUS: &str = include_str!("../../../docs/STATUS.md");

const DISPOSITIONS: [&str; 5] =
    ["supported_installed", "implemented_unproven", "unsupported_rejected", "omitted_accepted", "unknown_degraded"];
const LEVELS: [&str; 6] = ["none", "semantic", "component", "native_ci", "installed", "real_workflow"];
const RESULTS: [&str; 3] = ["pass", "fail", "not_run"];

fn ledger() -> Value {
    serde_json::from_str(LEDGER).expect("claim ledger is valid JSON")
}

#[test]
fn ledger_has_the_expected_shape() {
    let l = ledger();
    assert_eq!(l["schema"], "moat.claim_ledger.v1");
    let envs = l["environments"].as_object().unwrap();
    let mut ids = BTreeSet::new();
    for c in l["claims"].as_array().unwrap() {
        let id = c["id"].as_str().unwrap();
        assert!(ids.insert(id), "duplicate claim {id}");
        for k in ["capability", "backend", "limits"] {
            assert!(c[k].as_str().is_some_and(|s| !s.is_empty()), "{id}: {k} is required");
        }
        assert!(DISPOSITIONS.contains(&c["disposition"].as_str().unwrap()), "{id}: bad disposition");
        assert!(LEVELS.contains(&c["evidence_level"].as_str().unwrap()), "{id}: bad evidence level");
        assert!(RESULTS.contains(&c["last_result"]["result"].as_str().unwrap()), "{id}: bad result");
        assert!(envs.contains_key(c["environment"].as_str().unwrap()), "{id}: unknown environment");
    }
}

#[test]
fn nothing_is_supported_without_installed_evidence() {
    let l = ledger();
    let open: BTreeSet<&str> =
        l["defects"].as_array().unwrap().iter().filter(|d| d["status"] == "open").map(|d| d["id"].as_str().unwrap()).collect();
    for c in l["claims"].as_array().unwrap() {
        if c["disposition"] != "supported_installed" {
            continue;
        }
        let id = c["id"].as_str().unwrap();
        let level = c["evidence_level"].as_str().unwrap();
        assert!(level == "installed" || level == "real_workflow", "{id}: supported needs installed or real-workflow evidence, has {level}");
        assert_eq!(c["last_result"]["result"], "pass", "{id}: supported needs a passing result");
        assert!(c["last_result"]["date"].as_str().is_some_and(|d| d.len() == 10), "{id}: supported needs a dated result");
        for d in c["open_defects"].as_array().unwrap() {
            assert!(!open.contains(d.as_str().unwrap()), "{id}: supported while defect {d} is open");
        }
    }
}

#[test]
fn cited_defects_exist_and_failures_cite_one() {
    let l = ledger();
    let known: BTreeSet<&str> = l["defects"].as_array().unwrap().iter().map(|d| d["id"].as_str().unwrap()).collect();
    for c in l["claims"].as_array().unwrap() {
        let id = c["id"].as_str().unwrap();
        let cited = c["open_defects"].as_array().unwrap();
        for d in cited {
            assert!(known.contains(d.as_str().unwrap()), "{id} cites unknown defect {d}");
        }
        if c["last_result"]["result"] == "fail" {
            assert!(!cited.is_empty(), "{id}: a failing claim must cite the defect");
        }
    }
}

#[test]
fn status_lists_every_claim_and_open_defect() {
    let l = ledger();
    for c in l["claims"].as_array().unwrap() {
        let id = c["id"].as_str().unwrap();
        assert!(STATUS.contains(&format!("`{id}`")), "docs/STATUS.md does not list claim {id}");
    }
    for d in l["defects"].as_array().unwrap() {
        let id = d["id"].as_str().unwrap();
        assert!(STATUS.contains(&format!("`{id}`")), "docs/STATUS.md does not list defect {id}");
    }
    assert!(!STATUS.to_lowercase().contains("everything buildable"), "G0: no 'everything built' language");
}
