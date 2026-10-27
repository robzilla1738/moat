//! C ABI over `moat-core` for the macOS app and Network Extension.
//!
//! Every entry point takes one NUL-terminated UTF-8 JSON request and returns one newly allocated
//! NUL-terminated UTF-8 JSON response that the caller must release with [`moat_string_free`].
//! Responses always have the shape `{"ok": true, ...}` or `{"ok": false, "error": "..."}`; nothing panics
//! across the boundary (panics are caught and reported as errors).
//!
//! The FFI exposes evaluation, verification and compilation (issue #32: the Mac app compiles a locally
//! owner-authorized rule with the same compiler the controller and `moatctl` use, then signs the exact payload bytes
//! returned here). It never holds or sees a signing key, never accepts scripts, never promotes trust, and never
//! mutates state on the Swift side: the caller owns the key, the owner-presence check and persistence of the applied
//! revision.

use std::ffi::{c_char, CStr, CString};
use std::panic::{catch_unwind, AssertUnwindSafe};

use chrono::{DateTime, Utc};
use serde::Deserialize;
use serde_json::{json, Value};

use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine;
use sha2::{Digest, Sha256};

use moat_core::capability::{CapabilityAdvertisement, Platform};
use moat_core::compile::{compile_with_grants, CompileOptions};
use moat_core::enrichment::Enricher;
use moat_core::eval::{evaluate, EvalContext, FlowAttempt};
use moat_core::policy::Policy;
use moat_core::signing::{
    key_id, verify_bytes, verify_snapshot_for_device, verifying_key_from_hex, SignedSnapshot, TrustStore, SIGNED_SCHEMA,
};

/// Version of this ABI. Bumped on any breaking change to request or response shapes.
/// Additions are not breaking: callers feature-detect them through `entry_points` in `moat_info`.
pub const ABI_VERSION: u32 = 1;

/// Every exported entry point, reported by `moat_info` so the app can check for one before calling it.
pub const ENTRY_POINTS: &[&str] = &[
    "moat_info",
    "moat_verify_snapshot",
    "moat_evaluate",
    "moat_parse_policy",
    "moat_compile",
    "moat_assemble_signed_snapshot",
    "moat_string_free",
];

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
            "entry_points": ENTRY_POINTS,
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
    #[derive(Deserialize)]
    #[serde(deny_unknown_fields)]
    struct CompileRequest {
        /// Policy text (TOML or JSON), exactly as the owner reviewed it. Exactly one of `policy_text` / `policy`.
        #[serde(default)]
        policy_text: Option<String>,
        #[serde(default)]
        policy: Option<Value>,
        /// Only adapters this library can describe truthfully. The Mac app passes "macos".
        adapter: String,
        revision: u64,
        #[serde(default)]
        rollback_of: Option<u64>,
        /// Required, so the caller's clock and the signed bytes agree and the result is reproducible.
        issued_at: DateTime<Utc>,
        #[serde(default)]
        not_after: Option<DateTime<Utc>>,
        /// `moat.grant.v1` objects to overlay; each keeps its exact scope (validated as contracts).
        #[serde(default)]
        grants: Vec<Value>,
        /// Compile for these devices only (the snapshot then installs only on them). Empty: fleet-wide.
        #[serde(default)]
        devices: Vec<String>,
    }

    fn adapter_adv(name: &str) -> Result<CapabilityAdvertisement, String> {
        match name {
            "macos" => Ok(CapabilityAdvertisement::macos_network_extension()),
            "linux" => Ok(CapabilityAdvertisement::linux_nftables_cgroup()),
            "linux-ip-only" => Ok(CapabilityAdvertisement::linux_nftables_cgroup_ip_only()),
            other => Err(format!("unknown adapter {other:?} (expected macos, linux or linux-ip-only)")),
        }
    }

    /// Compile a policy (plus optional grants) into the exact snapshot payload bytes an owner key signs.
    /// Compile errors are returned as `{"ok":false,"error":"…","errors":[{"path","message"}]}`; nothing is weakened
    /// to make a rule fit (an unsupported restrictive rule is refused, as in `moatctl compile`).
    pub fn compile_policy(text: &str) -> Result<Value, String> {
        let r: CompileRequest = serde_json::from_str(text).map_err(|e| format!("bad compile request: {e}"))?;
        let policy = match (&r.policy_text, &r.policy) {
            (Some(t), None) => Policy::parse(t).map_err(|e| e.to_string())?,
            (None, Some(v)) => serde_json::from_value(v.clone()).map_err(|e| format!("invalid policy JSON: {e}"))?,
            _ => return Err("give exactly one of policy_text or policy".into()),
        };
        let adv = adapter_adv(&r.adapter)?;
        if let Some(na) = r.not_after {
            if na <= r.issued_at {
                return Err("not_after must be later than issued_at".into());
            }
        }
        let mut grants = Vec::new();
        for (i, g) in r.grants.into_iter().enumerate() {
            grants.push(
                moat_core::contracts::from_value(g)
                    .map_err(|e| format!("grants[{i}]: {}", e.iter().map(|x| x.to_string()).collect::<Vec<_>>().join("; ")))?,
            );
        }
        let opts = CompileOptions {
            target_devices: r.devices,
            revision: r.revision,
            rollback_of: r.rollback_of,
            issued_at: r.issued_at,
            not_after: r.not_after,
        };
        match compile_with_grants(&policy, &grants, &adv, &opts) {
            Ok(snap) => {
                // These are the bytes `sign_snapshot` signs; the caller signs them unchanged.
                let bytes = serde_json::to_vec(&snap).map_err(|e| format!("snapshot did not serialize: {e}"))?;
                Ok(json!({
                    "ok": true,
                    "payload": B64.encode(&bytes),
                    "payload_sha256": hex_lower(&Sha256::digest(&bytes)),
                    "revision": snap.revision,
                    "platform": snap.platform,
                    "devices": snap.devices,
                    "policy_digest": snap.policy_digest,
                    "report": snap.report,
                }))
            }
            Err(errs) => Ok(json!({
                "ok": false,
                "error": errs.iter().map(|e| e.to_string()).collect::<Vec<_>>().join("; "),
                "errors": errs.iter().map(|e| json!({"path": e.path, "message": e.message})).collect::<Vec<_>>(),
            })),
        }
    }

    fn hex_lower(b: &[u8]) -> String {
        b.iter().map(|x| format!("{x:02x}")).collect()
    }

    #[derive(Deserialize)]
    #[serde(deny_unknown_fields)]
    struct AssembleRequest {
        /// Base64 payload exactly as returned by `moat_compile`.
        payload: String,
        /// Base64 Ed25519 signature the caller produced over the decoded payload bytes.
        signature: String,
        /// Hex Ed25519 public key of the signer (the owner key's raw 32-byte representation).
        public_key: String,
    }

    /// Wrap a payload and an externally produced signature into a `moat.signed_snapshot.v1` envelope, refusing a
    /// signature that does not verify over those exact bytes. This does not make the key trusted: the endpoint's
    /// `moat_verify_snapshot` still decides against owner-configured keys.
    pub fn assemble(text: &str) -> Result<Value, String> {
        let r: AssembleRequest = serde_json::from_str(text).map_err(|e| format!("bad assemble request: {e}"))?;
        let vk = verifying_key_from_hex(&r.public_key)?;
        let bytes = B64.decode(r.payload.trim()).map_err(|e| format!("payload is not base64: {e}"))?;
        if !verify_bytes(&bytes, r.signature.trim(), &vk) {
            return Ok(json!({"ok": false, "error": "signature does not verify over the payload bytes with this key"}));
        }
        let signed = SignedSnapshot {
            schema: SIGNED_SCHEMA.into(),
            key_id: key_id(&vk),
            payload: r.payload.trim().to_string(),
            signature: r.signature.trim().to_string(),
        };
        Ok(json!({"ok": true, "signed": signed}))
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

/// Compile a policy into the exact snapshot payload bytes to sign. See `include/moat_ffi.h`.
///
/// # Safety
/// `request` must be NULL or a valid NUL-terminated string that stays alive for the call.
#[no_mangle]
pub unsafe extern "C" fn moat_compile(request: *const c_char) -> *mut c_char {
    with_request(request, api::compile_policy)
}

/// Wrap a payload and its Ed25519 signature into a signed snapshot envelope after checking the signature.
///
/// # Safety
/// `request` must be NULL or a valid NUL-terminated string that stays alive for the call.
#[no_mangle]
pub unsafe extern "C" fn moat_assemble_signed_snapshot(request: *const c_char) -> *mut c_char {
    with_request(request, api::assemble)
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
    // --- issue #32: compile in the app, sign outside the library, verify on the endpoint -------------------------

    fn compile_req(extra: Value) -> Value {
        let mut req = json!({"policy_text": POLICY, "adapter": "macos", "revision": 7, "issued_at": "2026-10-27T12:00:00Z"});
        for (k, v) in extra.as_object().unwrap() {
            req[k] = v.clone();
        }
        req
    }

    /// Stands in for the Keychain owner key: signs bytes the library handed out, never giving the key to it.
    fn external_sign(payload_b64: &str) -> (String, String) {
        let key = generate_key();
        let bytes = B64.decode(payload_b64).unwrap();
        (hex::encode(key.verifying_key().to_bytes()), moat_core::signing::sign_bytes(&bytes, &key))
    }

    #[test]
    fn compile_returns_the_exact_bytes_moatctl_would_sign() {
        let out = call(moat_compile, &compile_req(json!({})).to_string());
        assert_eq!(out["ok"], true, "{out}");
        let bytes = B64.decode(out["payload"].as_str().unwrap()).unwrap();
        // Same compiler, same options: byte-identical to the core's own snapshot serialization.
        let opts = CompileOptions {
            target_devices: vec![],
            revision: 7,
            rollback_of: None,
            issued_at: "2026-10-27T12:00:00Z".parse().unwrap(),
            not_after: None,
        };
        let core = compile(&Policy::parse(POLICY).unwrap(), &CapabilityAdvertisement::macos_network_extension(), &opts).unwrap();
        assert_eq!(bytes, serde_json::to_vec(&core).unwrap());
        assert_eq!(out["payload_sha256"], hex::encode(Sha256::digest(&bytes)));
        assert_eq!(out["platform"], "macos");
        assert_eq!(out["revision"], 7);
        assert!(out["report"].is_object());
        // Deterministic: the same request yields the same bytes (the app can re-derive what it signed).
        assert_eq!(call(moat_compile, &compile_req(json!({})).to_string())["payload"], out["payload"]);
    }

    #[test]
    fn compiled_payload_signed_outside_verifies_only_for_the_targeted_mac() {
        let out = call(moat_compile, &compile_req(json!({"devices": ["mbp-m1"], "issued_at": Utc::now()})).to_string());
        assert_eq!(out["ok"], true, "{out}");
        assert_eq!(out["devices"], json!(["mbp-m1"]));
        let payload = out["payload"].as_str().unwrap();
        let (pk, sig) = external_sign(payload);
        let env = call(moat_assemble_signed_snapshot, &json!({"payload": payload, "signature": sig, "public_key": pk}).to_string());
        assert_eq!(env["ok"], true, "{env}");
        assert_eq!(env["signed"]["schema"], SIGNED_SCHEMA);
        let signed = &env["signed"];
        let ok = call(moat_verify_snapshot, &json!({"signed": signed, "trusted_keys": [pk], "device_id": "mbp-m1"}).to_string());
        assert_eq!(ok["ok"], true, "{ok}");
        assert_eq!(ok["snapshot"]["revision"], 7);
        let other = call(moat_verify_snapshot, &json!({"signed": signed, "trusted_keys": [pk], "device_id": "mbp-air"}).to_string());
        assert_eq!(other["verify_error"]["error"], "wrong_device", "{other}");
        // Assembling does not make the key trusted: an endpoint that trusts another key still refuses it.
        let (stranger, _) = external_sign(payload);
        let refused = call(moat_verify_snapshot, &json!({"signed": signed, "trusted_keys": [stranger], "device_id": "mbp-m1"}).to_string());
        assert_eq!(refused["verify_error"]["error"], "unknown_key", "{refused}");
        // And the revision the endpoint already applied cannot be replayed.
        let replay = call(
            moat_verify_snapshot,
            &json!({"signed": signed, "trusted_keys": [pk], "device_id": "mbp-m1", "last_applied": 7}).to_string(),
        );
        assert_eq!(replay["verify_error"]["error"], "replay", "{replay}");
    }

    #[test]
    fn assemble_refuses_a_signature_over_other_bytes() {
        let out = call(moat_compile, &compile_req(json!({})).to_string());
        let payload = out["payload"].as_str().unwrap();
        let (pk, sig) = external_sign(payload);
        let other = call(moat_compile, &compile_req(json!({"revision": 8})).to_string());
        let r = call(moat_assemble_signed_snapshot, &json!({"payload": other["payload"], "signature": sig, "public_key": pk}).to_string());
        assert_eq!(r["ok"], false, "{r}");
        let (pk2, _) = external_sign(payload);
        let r2 = call(moat_assemble_signed_snapshot, &json!({"payload": payload, "signature": sig, "public_key": pk2}).to_string());
        assert_eq!(r2["ok"], false, "{r2}");
        assert_eq!(
            call(moat_assemble_signed_snapshot, &json!({"payload": payload, "signature": sig, "public_key": "zz"}).to_string())["ok"],
            false
        );
    }

    #[test]
    fn compile_refuses_what_the_adapter_cannot_enforce_instead_of_weakening_it() {
        let strict = include_str!("../../../conformance/policies/home-strict.toml");
        let out = call(
            moat_compile,
            &json!({"policy_text": strict, "adapter": "linux-ip-only", "revision": 1, "issued_at": Utc::now()}).to_string(),
        );
        assert_eq!(out["ok"], false, "{out}");
        assert!(out["error"].as_str().unwrap().contains("hostname enforcement"), "{out}");
        assert!(out["errors"].as_array().is_some_and(|e| !e.is_empty()));
        assert!(out.get("payload").is_none(), "no payload to sign when compilation fails");
    }

    #[test]
    fn compile_rejects_malformed_requests() {
        let both = compile_req(json!({"policy": {"schema": "x"}}));
        assert_eq!(call(moat_compile, &both.to_string())["ok"], false);
        let mut neither = compile_req(json!({}));
        neither.as_object_mut().unwrap().remove("policy_text");
        assert_eq!(call(moat_compile, &neither.to_string())["ok"], false);
        assert_eq!(call(moat_compile, &compile_req(json!({"adapter": "windows"})).to_string())["ok"], false);
        assert_eq!(call(moat_compile, &compile_req(json!({"not_after": "2026-10-27T11:00:00Z"})).to_string())["ok"], false);
        assert_eq!(call(moat_compile, &compile_req(json!({"unexpected": true})).to_string())["ok"], false);
        assert_eq!(call(moat_compile, &compile_req(json!({"grants": [{"schema": "moat.grant.v1"}]})).to_string())["ok"], false);
        let mut no_time = compile_req(json!({}));
        no_time.as_object_mut().unwrap().remove("issued_at");
        assert_eq!(call(moat_compile, &no_time.to_string())["ok"], false, "issued_at is required");
        assert_eq!(call(moat_compile, &compile_req(json!({"policy_text": "name = = broken"})).to_string())["ok"], false);
    }

    #[test]
    fn compile_accepts_policy_json_from_parse_policy() {
        let parsed = call(moat_parse_policy, &json!({"toml": POLICY}).to_string());
        let mut req = compile_req(json!({"policy": parsed["policy"]}));
        req.as_object_mut().unwrap().remove("policy_text");
        let out = call(moat_compile, &req.to_string());
        assert_eq!(out["ok"], true, "{out}");
        assert_eq!(out["payload"], call(moat_compile, &compile_req(json!({})).to_string())["payload"]);
    }

    #[test]
    fn info_lists_the_compile_entry_points_without_breaking_abi_1() {
        let v = api::info();
        assert_eq!(v["abi_version"], 1, "additive change; the Mac app pins ABI 1");
        let eps: Vec<&str> = v["entry_points"].as_array().unwrap().iter().map(|e| e.as_str().unwrap()).collect();
        assert!(eps.contains(&"moat_compile") && eps.contains(&"moat_assemble_signed_snapshot"));
        // Every listed entry point is declared in the C header the Swift package imports.
        let header = include_str!("../include/moat_ffi.h");
        for e in eps {
            assert!(header.contains(&format!("{e}(")), "{e} missing from moat_ffi.h");
        }
    }
}
