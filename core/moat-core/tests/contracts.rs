//! W01: shared contract fixtures round-trip through Rust without scope loss, with the canonical digests recorded
//! in contracts/fixtures/manifest.json; invalid fixtures are rejected at the layer the manifest says.
//!
//! Regenerate digests after an intentional fixture change: `MOAT_UPDATE_FIXTURES=1 cargo test --test contracts`.

use std::path::{Path, PathBuf};

use chrono::Duration;
use moat_core::contracts::{self, ActivationState, CapabilityDispositions, Contract, Event, Freshness, Grant, Receipt, Subject};
use serde_json::Value;

fn root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../../contracts")
}

fn load(p: &Path) -> Value {
    serde_json::from_str(&std::fs::read_to_string(p).unwrap()).unwrap()
}

/// Parse with the type the schema id names; return the canonical text of the parsed object.
fn parse_as(schema: &str, v: &Value) -> Result<String, String> {
    fn go<T: Contract>(v: &Value) -> Result<String, String> {
        contracts::from_value::<T>(v.clone()).map(|t| contracts::to_canonical_string(&t)).map_err(|e| format!("{e:?}"))
    }
    match schema {
        "moat.subject.v1" => go::<Subject>(v),
        "moat.grant.v1" => go::<Grant>(v),
        "moat.capability_dispositions.v1" => go::<CapabilityDispositions>(v),
        "moat.activation.v1" => go::<ActivationState>(v),
        "moat.receipt.v1" => go::<Receipt>(v),
        "moat.event.v1" => go::<Event>(v),
        other => panic!("unknown schema {other}"),
    }
}

// ---- a small validator for the JSON-schema subset contracts/schemas use (type, const, enum, required, properties,
// additionalProperties:false, items, minimum, maximum, file $ref). The TypeScript test implements the same subset.

fn schema_errors(schema: &Value, v: &Value, path: &str, out: &mut Vec<String>) {
    if let Some(r) = schema.get("$ref").and_then(Value::as_str) {
        let s = load(&root().join("schemas").join(r));
        return schema_errors(&s, v, path, out);
    }
    if let Some(c) = schema.get("const") {
        if c != v {
            out.push(format!("{path}: expected {c}"));
        }
        return;
    }
    if let Some(e) = schema.get("enum").and_then(Value::as_array) {
        if !e.contains(v) {
            out.push(format!("{path}: {v} not in enum"));
        }
    }
    match schema.get("type").and_then(Value::as_str) {
        Some("object") => {
            let Some(o) = v.as_object() else { return out.push(format!("{path}: expected object")) };
            let props = schema.get("properties").and_then(Value::as_object);
            for r in schema.get("required").and_then(Value::as_array).into_iter().flatten() {
                if !o.contains_key(r.as_str().unwrap()) {
                    out.push(format!("{path}.{}: required", r.as_str().unwrap()));
                }
            }
            for (k, x) in o {
                match props.and_then(|p| p.get(k)) {
                    Some(ps) => schema_errors(ps, x, &format!("{path}.{k}"), out),
                    None if schema.get("additionalProperties") == Some(&Value::Bool(false)) => {
                        out.push(format!("{path}.{k}: unknown field"))
                    }
                    None => {}
                }
            }
        }
        Some("array") => {
            let Some(a) = v.as_array() else { return out.push(format!("{path}: expected array")) };
            if let Some(it) = schema.get("items") {
                for (i, x) in a.iter().enumerate() {
                    schema_errors(it, x, &format!("{path}[{i}]"), out);
                }
            }
        }
        Some("string") if !v.is_string() => out.push(format!("{path}: expected string")),
        Some("boolean") if !v.is_boolean() => out.push(format!("{path}: expected boolean")),
        Some("integer") => match v.as_u64() {
            Some(n) => {
                if schema.get("maximum").and_then(Value::as_u64).is_some_and(|m| n > m) {
                    out.push(format!("{path}: above maximum"));
                }
            }
            None => out.push(format!("{path}: expected non-negative integer")),
        },
        _ => {}
    }
}

fn schema_check(schema_id: &str, v: &Value) -> Vec<String> {
    let s = load(&root().join("schemas").join(format!("{schema_id}.schema.json")));
    let mut out = Vec::new();
    schema_errors(&s, v, "$", &mut out);
    out
}

#[test]
fn fixtures_round_trip_and_rejects_hold() {
    let manifest_path = root().join("fixtures/manifest.json");
    let mut manifest = load(&manifest_path);
    let update = std::env::var("MOAT_UPDATE_FIXTURES").is_ok();
    let mut failures = Vec::new();
    for f in manifest["fixtures"].as_array_mut().unwrap() {
        let file = f["file"].as_str().unwrap().to_string();
        let schema = f["schema"].as_str().unwrap().to_string();
        let v = load(&root().join("fixtures").join(&file));
        let structural = schema_check(&schema, &v);
        let parsed = parse_as(&schema, &v);
        match f["expect"].as_str().unwrap() {
            "accept" => {
                if !structural.is_empty() {
                    failures.push(format!("{file}: schema rejects a valid fixture: {structural:?}"));
                }
                let canon = match parsed {
                    Ok(c) => c,
                    Err(e) => {
                        failures.push(format!("{file}: rejected: {e}"));
                        continue;
                    }
                };
                // No scope loss: the parsed-and-reserialized object is byte-identical to the canonical input.
                let input_canon = String::from_utf8(contracts::canonical_bytes(&v)).unwrap();
                if canon != input_canon {
                    failures.push(format!("{file}: round trip changed content\n in:  {input_canon}\n out: {canon}"));
                }
                let d = contracts::digest_bytes(canon.as_bytes());
                if update {
                    f["canonical_sha256"] = Value::String(d);
                } else if f["canonical_sha256"].as_str() != Some(d.as_str()) {
                    failures.push(format!("{file}: digest {d} != manifest {}", f["canonical_sha256"]));
                }
                if let Some(fr) = f.get("freshness") {
                    let r: Receipt = contracts::from_value(v.clone()).unwrap();
                    let now = contracts::parse_time(fr["now"].as_str().unwrap()).unwrap();
                    let got = r.freshness(now, Duration::seconds(fr["max_age_seconds"].as_i64().unwrap()));
                    let want: Freshness = serde_json::from_value(fr["expect"].clone()).unwrap();
                    if got != want {
                        failures.push(format!("{file}: freshness {got:?}, want {want:?}"));
                    }
                }
            }
            "reject" => {
                if parsed.is_ok() {
                    failures.push(format!("{file}: accepted an invalid fixture ({})", f["reason"]));
                }
                match f["layer"].as_str().unwrap() {
                    // schema-layer rejects must be caught by the JSON schema (or the canonical value domain)
                    "schema" => {
                        let mut dom = Vec::new();
                        contracts::check_value_domain(&v, "$", &mut dom);
                        if structural.is_empty() && dom.is_empty() {
                            failures.push(format!("{file}: labeled schema-layer but the schema accepts it"));
                        }
                    }
                    // semantic-layer rejects pass the schema, so consumers know they need the semantic checks
                    "semantic" => {
                        if !structural.is_empty() {
                            failures.push(format!("{file}: labeled semantic but the schema already rejects it: {structural:?}"));
                        }
                    }
                    l => failures.push(format!("{file}: unknown layer {l}")),
                }
            }
            e => failures.push(format!("{file}: unknown expectation {e}")),
        }
    }
    if update {
        std::fs::write(&manifest_path, serde_json::to_string_pretty(&manifest).unwrap() + "\n").unwrap();
    }
    assert!(failures.is_empty(), "{}", failures.join("\n"));
}

#[test]
fn same_executable_on_two_devices_are_different_grants() {
    let a: Grant = contracts::parse(&std::fs::read_to_string(root().join("fixtures/valid/grant-app-on-device.json")).unwrap()).unwrap();
    let mut b = a.clone();
    b.scope.device_id = "mbp-2".into();
    assert_ne!(a.authority_digest(), b.authority_digest(), "device scope is part of a grant's authority");
    let mut c = a.clone();
    c.reason = Some("different display text".into());
    assert_eq!(a.authority_digest(), c.authority_digest(), "display text is not authority");
}

#[test]
fn old_receipt_labeled_healthy_is_stale() {
    let r: Receipt =
        contracts::parse(&std::fs::read_to_string(root().join("fixtures/valid/receipt-old-labeled-healthy.json")).unwrap()).unwrap();
    assert_eq!(r.health_label.as_deref(), Some("healthy"));
    let now = contracts::parse_time("2026-10-27T15:01:00Z").unwrap();
    assert_eq!(r.freshness(now, Duration::minutes(5)), Freshness::Stale);
    // a large stated uncertainty makes a borderline receipt stale, never fresher
    let mut r2: Receipt = contracts::parse(&std::fs::read_to_string(root().join("fixtures/valid/receipt-current.json")).unwrap()).unwrap();
    assert_eq!(r2.freshness(now, Duration::minutes(5)), Freshness::Fresh);
    r2.clock.uncertainty_ms = 10 * 60 * 1000;
    assert_eq!(r2.freshness(now, Duration::minutes(5)), Freshness::Stale);
}

#[test]
fn schemas_cover_every_rust_field() {
    // Every field the Rust types serialize for the valid fixtures is declared in the schema (otherwise the schema
    // would reject it); and every schema is valid JSON with a const schema id.
    for entry in std::fs::read_dir(root().join("schemas")).unwrap() {
        let p = entry.unwrap().path();
        let s = load(&p);
        let id = s["title"].as_str().unwrap();
        assert_eq!(s["properties"]["schema"]["const"], id);
        assert_eq!(p.file_name().unwrap().to_str().unwrap(), format!("{id}.schema.json"));
    }
}
