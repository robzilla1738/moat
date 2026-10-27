//! C ABI over `moat-core` for the macOS app and Network Extension.
//!
//! Every entry point takes one NUL-terminated UTF-8 JSON request and returns one newly allocated
//! NUL-terminated UTF-8 JSON response that the caller must release with [`moat_string_free`].
//! Responses always have the shape `{"ok": true, ...}` or `{"ok": false, "error": "..."}`; nothing panics
//! across the boundary (panics are caught and reported as errors).
//!
//! The FFI exposes *evaluation and verification only*. It never accepts scripts, never promotes trust,
//! and never mutates state on the Swift side: the caller owns persistence of the applied revision.

use std::ffi::{c_char, CStr, CString};
use std::panic::{catch_unwind, AssertUnwindSafe};

use chrono::{DateTime, Utc};
use serde::Deserialize;
use serde_json::{json, Value};

use moat_core::capability::{CapabilityAdvertisement, Platform};
use moat_core::enrichment::Enricher;
use moat_core::eval::{evaluate, EvalContext, FlowAttempt};
use moat_core::policy::Policy;
use moat_core::signing::{verify_snapshot_for_device, verifying_key_from_hex, SignedSnapshot, TrustStore};

/// Version of this ABI. Bumped on any breaking change to request or response shapes.
pub const ABI_VERSION: u32 = 1;

fn respond(v: Value) -> *mut c_char {
    let s = serde_json::to_string(&v).unwrap_or_else(|_| r#"{"ok":false,"error":"response did not serialize"}"#.to_string());
    // serde_json never emits interior NULs, but stay safe.
    CString::new(s.replace('\0', "")).map(CString::into_raw).unwrap_or(std::ptr::null_mut())
}

fn err(msg: impl Into<String>) -> Value {
    json!({"ok": false, "error": msg.into()})
}

/// Parse the request pointer and run `f`, converting every failure (including a panic) into an error response.
fn with_request(req: *const c_char, f: impl FnOnce(&str) -> Result<Value, String>) -> *mut c_char {
    if req.is_null() {
        return respond(err("null request"));
    }
    // SAFETY: the caller promises a valid NUL-terminated string for the duration of the call.
    let text = match unsafe { CStr::from_ptr(req) }.to_str() {
        Ok(t) => t.to_owned(),
        Err(_) => return respond(err("request is not UTF-8")),
    };
    match catch_unwind(AssertUnwindSafe(|| f(&text))) {
        Ok(Ok(v)) => respond(v),
        Ok(Err(e)) => respond(err(e)),
        Err(_) => respond(err("internal error (panic caught at FFI boundary)")),
    }
}

/// Pure-Rust implementations, also used by the unit tests.
pub mod api {
    use super::*;

    pub fn info() -> Value {
        json!({
            "ok": true,
            "abi_version": ABI_VERSION,
            "core_version": env!("CARGO_PKG_VERSION"),
            "capabilities": CapabilityAdvertisement::macos_network_extension(),
        })
    }

    #[derive(Deserialize)]
    #[serde(deny_unknown_fields)]
    struct VerifyRequest {
        signed: SignedSnapshot,
        /// Owner/controller verifying keys (hex). Trust is configured by the owner, never promoted here.
        trusted_keys: Vec<String>,
        #[serde(default)]
        revoked_key_ids: Vec<String>,
        #[serde(default)]
        last_applied: Option<u64>,
        /// This endpoint's device id. Required to accept a device-targeted snapshot (issue #26).
        #[serde(default)]
        device_id: Option<String>,
        #[serde(default)]
        now: Option<DateTime<Utc>>,
        #[serde(default = "default_platform")]
        platform: Platform,
    }

    fn default_platform() -> Platform {
        Platform::Macos
    }

    pub fn verify(text: &str) -> Result<Value, String> {
        let r: VerifyRequest = serde_json::from_str(text).map_err(|e| format!("bad verify request: {e}"))?;
        let mut trust = TrustStore::new();
        for k in &r.trusted_keys {
            trust.trust(verifying_key_from_hex(k)?);
        }
        for id in &r.revoked_key_ids {
            trust.revoke(id);
        }
        let now = r.now.unwrap_or_else(Utc::now);
        match verify_snapshot_for_device(&r.signed, &trust, r.platform, r.device_id.as_deref(), r.last_applied, now) {
            Ok(snap) => Ok(json!({"ok": true, "snapshot": snap})),
            Err(e) => Ok(json!({"ok": false, "error": e.to_string(), "verify_error": e})),
        }
    }

    #[derive(Deserialize)]
    #[serde(deny_unknown_fields)]
    struct EvaluateRequest {
        policy: Policy,
        device_id: String,
        flow: FlowAttempt,
    }

    pub fn evaluate_flow(text: &str) -> Result<Value, String> {
        let r: EvaluateRequest = serde_json::from_str(text).map_err(|e| format!("bad evaluate request: {e}"))?;
        r.policy.validate().map_err(|errs| errs.iter().map(|e| e.to_string()).collect::<Vec<_>>().join("; "))?;
        let enricher = Enricher::new();
        let ctx = EvalContext::new(&r.policy, &enricher, &r.device_id);
        let d = evaluate(&ctx, &r.flow);
        Ok(json!({"ok": true, "summary": d.summary(), "decision": d}))
    }

    pub fn parse_policy(text: &str) -> Result<Value, String> {
        #[derive(Deserialize)]
        #[serde(deny_unknown_fields)]
        struct Req {
            toml: String,
        }
        let r: Req = serde_json::from_str(text).map_err(|e| format!("bad parse request: {e}"))?;
        let p = Policy::parse(&r.toml).map_err(|e| e.to_string())?;
        p.validate().map_err(|errs| errs.iter().map(|e| e.to_string()).collect::<Vec<_>>().join("; "))?;
        Ok(json!({"ok": true, "policy": p}))
    }
}

/// `{}` → `{"ok":true,"abi_version":1,"core_version":"…","capabilities":{…}}`
#[no_mangle]
pub extern "C" fn moat_info() -> *mut c_char {
    match catch_unwind(api::info) {
        Ok(v) => respond(v),
        Err(_) => respond(err("internal error")),
    }
}

/// Verify a signed snapshot against owner-configured keys. See `include/moat_ffi.h`.
///
/// # Safety
/// `request` must be NULL or a valid NUL-terminated string that stays alive for the call.
#[no_mangle]
pub unsafe extern "C" fn moat_verify_snapshot(request: *const c_char) -> *mut c_char {
    with_request(request, api::verify)
}

/// Evaluate one flow attempt against a policy and explain the decision.
///
/// # Safety
/// `request` must be NULL or a valid NUL-terminated string that stays alive for the call.
#[no_mangle]
pub unsafe extern "C" fn moat_evaluate(request: *const c_char) -> *mut c_char {
    with_request(request, api::evaluate_flow)
}

/// Parse and validate TOML policy text (used by the recovery UI's "inspect policy" view).
///
/// # Safety
/// `request` must be NULL or a valid NUL-terminated string that stays alive for the call.
#[no_mangle]
pub unsafe extern "C" fn moat_parse_policy(request: *const c_char) -> *mut c_char {
    with_request(request, api::parse_policy)
}

/// Release a string returned by any `moat_*` function. Passing NULL is a no-op.
///
/// # Safety
/// `s` must be NULL or a pointer returned by this library that has not been freed yet.
#[no_mangle]
pub unsafe extern "C" fn moat_string_free(s: *mut c_char) {
    if !s.is_null() {
        // SAFETY: `s` was produced by CString::into_raw in this library.
        drop(unsafe { CString::from_raw(s) });
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use moat_core::compile::{compile, CompileOptions};
    use moat_core::signing::{generate_key, sign_snapshot};

    const POLICY: &str = include_str!("../../../conformance/policies/home.toml");

    fn call(f: unsafe extern "C" fn(*const c_char) -> *mut c_char, req: &str) -> Value {
        let c = CString::new(req).unwrap();
        let out = unsafe { f(c.as_ptr()) };
        assert!(!out.is_null());
        let s = unsafe { CStr::from_ptr(out) }.to_str().unwrap().to_string();
        unsafe { moat_string_free(out) };
        serde_json::from_str(&s).unwrap()
    }

    fn signed_macos(revision: u64) -> (String, SignedSnapshot) {
        let p = Policy::parse(POLICY).unwrap();
        let opts = CompileOptions { target_devices: vec![], revision, rollback_of: None, issued_at: Utc::now(), not_after: None };
        let snap = compile(&p, &CapabilityAdvertisement::macos_network_extension(), &opts).expect("compiles for macOS");
        let key = generate_key();
        (hex::encode(key.verifying_key().to_bytes()), sign_snapshot(&snap, &key))
    }

    #[test]
    fn info_reports_abi_and_untested_capabilities() {
        let out = moat_info();
        let v: Value = serde_json::from_str(unsafe { CStr::from_ptr(out) }.to_str().unwrap()).unwrap();
        unsafe { moat_string_free(out) };
        assert_eq!(v["ok"], true);
        assert_eq!(v["abi_version"], ABI_VERSION);
        // Honesty: nothing on macOS is claimed proven before a signed real-device install.
        assert_eq!(v["capabilities"]["capabilities"]["app_enforcement"]["support"], "untested");
        assert_eq!(v["capabilities"]["capabilities"]["session_enforcement"]["support"], "unsupported");
    }

    #[test]
    fn verify_accepts_trusted_and_rejects_unknown_key_and_replay() {
        let (pk, signed) = signed_macos(5);
        let ok = call(moat_verify_snapshot, &json!({"signed": signed, "trusted_keys": [pk]}).to_string());
        assert_eq!(ok["ok"], true, "{ok}");
        assert_eq!(ok["snapshot"]["revision"], 5);

        let (other, _) = signed_macos(1);
        let unknown = call(moat_verify_snapshot, &json!({"signed": signed, "trusted_keys": [other]}).to_string());
        assert_eq!(unknown["ok"], false);
        assert_eq!(unknown["verify_error"]["error"], "unknown_key");

        let replay = call(moat_verify_snapshot, &json!({"signed": signed, "trusted_keys": [pk], "last_applied": 5}).to_string());
        assert_eq!(replay["verify_error"]["error"], "replay");
    }

    #[test]
    fn verify_rejects_linux_snapshot_on_macos() {
        let (pk, signed) = signed_macos(2);
        let wrong = call(moat_verify_snapshot, &json!({"signed": signed, "trusted_keys": [pk], "platform": "linux"}).to_string());
        assert_eq!(wrong["verify_error"]["error"], "wrong_platform");
    }

    #[test]
    fn bad_input_is_an_error_not_a_crash() {
        assert_eq!(call(moat_evaluate, "not json")["ok"], false);
        assert_eq!(call(moat_verify_snapshot, "{\"unexpected\":1}")["ok"], false);
        assert_eq!(call(moat_parse_policy, &json!({"toml": "this is = = not toml"}).to_string())["ok"], false);
        let out = unsafe { moat_evaluate(std::ptr::null()) };
        let v: Value = serde_json::from_str(unsafe { CStr::from_ptr(out) }.to_str().unwrap()).unwrap();
        unsafe { moat_string_free(out) };
        assert_eq!(v["error"], "null request");
        unsafe { moat_string_free(std::ptr::null_mut()) };
    }

    #[test]
    fn evaluate_explains_a_decision() {
        let parsed = call(moat_parse_policy, &json!({"toml": POLICY}).to_string());
        assert_eq!(parsed["ok"], true, "{parsed}");
        let flow = json!({
            "id": "f1", "device_id": "mbp", "app": {"family": "unknown-tool", "executable": "/usr/local/bin/x"},
            "remote_ip": "203.0.113.9", "remote_port": 443, "transport": "tcp", "at": Utc::now(),
        });
        let out = call(moat_evaluate, &json!({"policy": parsed["policy"], "device_id": "mbp", "flow": flow}).to_string());
        assert_eq!(out["ok"], true, "{out}");
        assert!(out["decision"]["verdict"] == "allow" || out["decision"]["verdict"] == "deny");
        assert!(out["summary"].as_str().unwrap().contains("by"));
    }

    #[test]
    fn verify_passes_the_device_id_for_targeted_snapshots() {
        let p = Policy::parse(POLICY).unwrap();
        let opts = CompileOptions {
            target_devices: vec!["mbp-m1".into()],
            revision: 3,
            rollback_of: None,
            issued_at: Utc::now(),
            not_after: None,
        };
        let snap = compile(&p, &CapabilityAdvertisement::macos_network_extension(), &opts).expect("compiles for one Mac");
        let key = generate_key();
        let pk = hex::encode(key.verifying_key().to_bytes());
        let signed = sign_snapshot(&snap, &key);
        let ok = call(moat_verify_snapshot, &json!({"signed": signed, "trusted_keys": [pk], "device_id": "mbp-m1"}).to_string());
        assert_eq!(ok["ok"], true, "{ok}");
        let other = call(moat_verify_snapshot, &json!({"signed": signed, "trusted_keys": [pk], "device_id": "mbp-air"}).to_string());
        assert_eq!(other["verify_error"]["error"], "wrong_device", "{other}");
        let anon = call(moat_verify_snapshot, &json!({"signed": signed, "trusted_keys": [pk]}).to_string());
        assert_eq!(anon["verify_error"]["error"], "wrong_device", "{anon}");
    }
}
