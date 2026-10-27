//! Ed25519-signed, versioned snapshots with replay protection.
//!
//! * The payload is the exact JSON bytes that were signed (base64), so no canonicalization ambiguity exists.
//! * An endpoint accepts only revisions strictly greater than the last one it applied (replay protection).
//! * A rollback is a *new*, newly authorized revision containing an older configuration (`rollback_of`), so
//!   replay protection never prevents deliberate recovery.
//! * A malformed, unsupported, expired or wrongly signed snapshot is rejected atomically; the last working
//!   revision stays in force.

use std::collections::{BTreeMap, BTreeSet};

use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine;
use chrono::{DateTime, Duration, Utc};
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier as _, VerifyingKey};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::capability::Platform;
use crate::compile::{Snapshot, SNAPSHOT_SCHEMA};

pub const SIGNED_SCHEMA: &str = "moat.signed_snapshot.v1";

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct SignedSnapshot {
    pub schema: String,
    pub key_id: String,
    /// Base64 of the exact signed JSON bytes of a [`Snapshot`].
    pub payload: String,
    /// Base64 Ed25519 signature over the payload bytes.
    pub signature: String,
}

/// Key id: first 16 hex chars of sha256(public key bytes).
pub fn key_id(vk: &VerifyingKey) -> String {
    hex::encode(Sha256::digest(vk.as_bytes()))[..16].to_string()
}

pub fn generate_key() -> SigningKey {
    let mut rng = rand_core::OsRng;
    SigningKey::generate(&mut rng)
}

pub fn signing_key_from_hex(h: &str) -> Result<SigningKey, String> {
    let b = hex::decode(h.trim()).map_err(|e| format!("bad key hex: {e}"))?;
    let arr: [u8; 32] = b.try_into().map_err(|_| "signing key must be 32 bytes".to_string())?;
    Ok(SigningKey::from_bytes(&arr))
}

pub fn verifying_key_from_hex(h: &str) -> Result<VerifyingKey, String> {
    let b = hex::decode(h.trim()).map_err(|e| format!("bad key hex: {e}"))?;
    let arr: [u8; 32] = b.try_into().map_err(|_| "public key must be 32 bytes".to_string())?;
    VerifyingKey::from_bytes(&arr).map_err(|e| format!("invalid public key: {e}"))
}

pub fn sign_snapshot(s: &Snapshot, key: &SigningKey) -> SignedSnapshot {
    let bytes = serde_json::to_vec(s).expect("snapshot serializes");
    let sig = key.sign(&bytes);
    SignedSnapshot {
        schema: SIGNED_SCHEMA.into(),
        key_id: key_id(&key.verifying_key()),
        payload: B64.encode(&bytes),
        signature: B64.encode(sig.to_bytes()),
    }
}

/// Sign arbitrary bytes (used by approvals and owner authorizations).
pub fn sign_bytes(bytes: &[u8], key: &SigningKey) -> String {
    B64.encode(key.sign(bytes).to_bytes())
}

pub fn verify_bytes(bytes: &[u8], sig_b64: &str, vk: &VerifyingKey) -> bool {
    let Ok(raw) = B64.decode(sig_b64) else { return false };
    let Ok(arr) = <[u8; 64]>::try_from(raw.as_slice()) else { return false };
    vk.verify(bytes, &Signature::from_bytes(&arr)).is_ok()
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "error", rename_all = "snake_case")]
pub enum VerifyError {
    Malformed {
        detail: String,
    },
    UnknownKey {
        key_id: String,
    },
    RevokedKey {
        key_id: String,
    },
    BadSignature,
    WrongPlatform {
        expected: Platform,
        got: Platform,
    },
    Replay {
        revision: u64,
        last_applied: u64,
    },
    Expired {
        not_after: DateTime<Utc>,
    },
    FromTheFuture {
        issued_at: DateTime<Utc>,
    },
    InvalidPolicy {
        detail: String,
    },
    /// The snapshot was compiled for named devices (rules for other devices left out) and this endpoint is not one
    /// of them, or could not say which device it is.
    WrongDevice {
        expected: Option<String>,
        targets: Vec<String>,
    },
}

impl std::fmt::Display for VerifyError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            VerifyError::Malformed { detail } => write!(f, "malformed snapshot: {detail}"),
            VerifyError::UnknownKey { key_id } => write!(f, "signed by unknown key {key_id}"),
            VerifyError::RevokedKey { key_id } => write!(f, "signed by revoked key {key_id}"),
            VerifyError::BadSignature => write!(f, "signature does not verify"),
            VerifyError::WrongPlatform { expected, got } => write!(f, "snapshot is for {got:?}, this endpoint is {expected:?}"),
            VerifyError::Replay { revision, last_applied } => {
                write!(f, "revision {revision} is not newer than applied revision {last_applied} (replay rejected)")
            }
            VerifyError::Expired { not_after } => write!(f, "snapshot expired at {not_after}"),
            VerifyError::FromTheFuture { issued_at } => write!(f, "snapshot issued in the future ({issued_at})"),
            VerifyError::InvalidPolicy { detail } => write!(f, "snapshot policy is invalid: {detail}"),
            VerifyError::WrongDevice { expected: Some(d), targets } => {
                write!(f, "snapshot is for devices [{}], this endpoint is {d}", targets.join(", "))
            }
            VerifyError::WrongDevice { expected: None, targets } => write!(
                f,
                "snapshot is for devices [{}] and this endpoint did not say which device it is (refusing a device-targeted snapshot)",
                targets.join(", ")
            ),
        }
    }
}

#[derive(Default, Clone, Debug)]
pub struct TrustStore {
    keys: BTreeMap<String, VerifyingKey>,
    revoked: BTreeSet<String>,
}

impl TrustStore {
    pub fn new() -> Self {
        Self::default()
    }
    pub fn trust(&mut self, vk: VerifyingKey) -> String {
        let id = key_id(&vk);
        self.keys.insert(id.clone(), vk);
        id
    }
    pub fn revoke(&mut self, id: &str) {
        self.revoked.insert(id.to_string());
    }
    pub fn get(&self, id: &str) -> Option<&VerifyingKey> {
        self.keys.get(id)
    }
}

/// Verify a signed snapshot for an endpoint that does not state its device id. Device-targeted snapshots are
/// refused (they may lack another device's rules); use [`verify_snapshot_for_device`] on endpoints.
pub fn verify_snapshot(
    signed: &SignedSnapshot,
    trust: &TrustStore,
    platform: Platform,
    last_applied: Option<u64>,
    now: DateTime<Utc>,
) -> Result<Snapshot, VerifyError> {
    verify_snapshot_for_device(signed, trust, platform, None, last_applied, now)
}

/// Verify a signed snapshot for this endpoint (`device`). A snapshot that names target devices installs only on a
/// listed device (issue #26): it was compiled without the rules scoped to other devices.
pub fn verify_snapshot_for_device(
    signed: &SignedSnapshot,
    trust: &TrustStore,
    platform: Platform,
    device: Option<&str>,
    last_applied: Option<u64>,
    now: DateTime<Utc>,
) -> Result<Snapshot, VerifyError> {
    if signed.schema != SIGNED_SCHEMA {
        return Err(VerifyError::Malformed { detail: format!("unexpected schema {}", signed.schema) });
    }
    if trust.revoked.contains(&signed.key_id) {
        return Err(VerifyError::RevokedKey { key_id: signed.key_id.clone() });
    }
    let vk = trust.get(&signed.key_id).ok_or_else(|| VerifyError::UnknownKey { key_id: signed.key_id.clone() })?;
    let bytes = B64.decode(&signed.payload).map_err(|e| VerifyError::Malformed { detail: format!("payload: {e}") })?;
    if !verify_bytes(&bytes, &signed.signature, vk) {
        return Err(VerifyError::BadSignature);
    }
    let snap: Snapshot = serde_json::from_slice(&bytes).map_err(|e| VerifyError::Malformed { detail: e.to_string() })?;
    if snap.schema != SNAPSHOT_SCHEMA {
        return Err(VerifyError::Malformed { detail: format!("unexpected snapshot schema {}", snap.schema) });
    }
    if snap.platform != platform {
        return Err(VerifyError::WrongPlatform { expected: platform, got: snap.platform });
    }
    if !snap.devices.is_empty() && !device.is_some_and(|d| snap.devices.iter().any(|t| t == d)) {
        return Err(VerifyError::WrongDevice { expected: device.map(str::to_string), targets: snap.devices.clone() });
    }
    if let Some(last) = last_applied {
        if snap.revision <= last {
            return Err(VerifyError::Replay { revision: snap.revision, last_applied: last });
        }
    }
    if let Some(na) = snap.not_after {
        if na <= now {
            return Err(VerifyError::Expired { not_after: na });
        }
    }
    if snap.issued_at > now + Duration::minutes(10) {
        return Err(VerifyError::FromTheFuture { issued_at: snap.issued_at });
    }
    if let Err(errs) = snap.policy.validate() {
        return Err(VerifyError::InvalidPolicy { detail: errs.iter().map(|e| e.to_string()).collect::<Vec<_>>().join("; ") });
    }
    Ok(snap)
}

/// The endpoint's installed policy: the last working snapshot plus the highest applied revision.
#[derive(Clone, Debug, Default)]
pub struct EndpointPolicyState {
    pub current: Option<Snapshot>,
    pub last_applied: Option<u64>,
    pub rejected: Vec<(String, VerifyError)>,
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
pub struct ApplyReceipt {
    pub revision: u64,
    pub rollback_of: Option<u64>,
    pub policy_digest: String,
    pub applied_at: DateTime<Utc>,
}

impl EndpointPolicyState {
    /// Verify and atomically install. On failure the current snapshot is untouched.
    pub fn apply(
        &mut self,
        signed: &SignedSnapshot,
        trust: &TrustStore,
        platform: Platform,
        now: DateTime<Utc>,
    ) -> Result<ApplyReceipt, VerifyError> {
        match verify_snapshot(signed, trust, platform, self.last_applied, now) {
            Ok(s) => {
                let r = ApplyReceipt {
                    revision: s.revision,
                    rollback_of: s.rollback_of,
                    policy_digest: s.policy_digest.clone(),
                    applied_at: now,
                };
                self.last_applied = Some(s.revision);
                self.current = Some(s);
                Ok(r)
            }
            Err(e) => {
                self.rejected.push((signed.key_id.clone(), e.clone()));
                if self.rejected.len() > 32 {
                    self.rejected.remove(0);
                }
                Err(e)
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::capability::CapabilityAdvertisement;
    use crate::compile::{compile, CompileOptions};
    use crate::policy::Policy;

    fn snap(rev: u64, rollback_of: Option<u64>) -> Snapshot {
        let p = Policy::parse(include_str!("../../../conformance/policies/home.toml")).unwrap();
        compile(
            &p,
            &CapabilityAdvertisement::linux_nftables_cgroup(),
            &CompileOptions {
                target_devices: vec![],
                revision: rev,
                rollback_of,
                issued_at: "2026-10-26T12:00:00Z".parse().unwrap(),
                not_after: None,
            },
        )
        .unwrap()
    }
    fn now() -> DateTime<Utc> {
        "2026-10-26T12:05:00Z".parse().unwrap()
    }

    #[test]
    fn sign_verify_apply_and_replay() {
        let k = generate_key();
        let mut t = TrustStore::new();
        t.trust(k.verifying_key());
        let mut st = EndpointPolicyState::default();
        let s5 = sign_snapshot(&snap(5, None), &k);
        assert_eq!(st.apply(&s5, &t, Platform::Linux, now()).unwrap().revision, 5);
        // replaying the same or an older revision is rejected; state retained
        assert!(matches!(st.apply(&s5, &t, Platform::Linux, now()), Err(VerifyError::Replay { .. })));
        assert_eq!(st.current.as_ref().unwrap().revision, 5);
        // rollback is a new revision
        let s6 = sign_snapshot(&snap(6, Some(3)), &k);
        let r = st.apply(&s6, &t, Platform::Linux, now()).unwrap();
        assert_eq!((r.revision, r.rollback_of), (6, Some(3)));
    }

    #[test]
    fn tampering_and_unknown_keys_rejected() {
        let k = generate_key();
        let other = generate_key();
        let mut t = TrustStore::new();
        t.trust(k.verifying_key());
        let mut s = sign_snapshot(&snap(1, None), &k);
        let mut bytes = B64.decode(&s.payload).unwrap();
        let pos = bytes.iter().position(|b| *b == b'7').unwrap_or(10);
        bytes[pos] = b'8';
        s.payload = B64.encode(bytes);
        assert_eq!(verify_snapshot(&s, &t, Platform::Linux, None, now()), Err(VerifyError::BadSignature));
        let s2 = sign_snapshot(&snap(1, None), &other);
        assert!(matches!(verify_snapshot(&s2, &t, Platform::Linux, None, now()), Err(VerifyError::UnknownKey { .. })));
        let s3 = sign_snapshot(&snap(1, None), &k);
        assert!(matches!(verify_snapshot(&s3, &t, Platform::Macos, None, now()), Err(VerifyError::WrongPlatform { .. })));
        t.revoke(&key_id(&k.verifying_key()));
        assert!(matches!(verify_snapshot(&s3, &t, Platform::Linux, None, now()), Err(VerifyError::RevokedKey { .. })));
    }

    #[test]
    fn expiry_enforced() {
        let k = generate_key();
        let mut t = TrustStore::new();
        t.trust(k.verifying_key());
        let mut sn = snap(2, None);
        sn.not_after = Some("2026-10-26T12:01:00Z".parse().unwrap());
        let s = sign_snapshot(&sn, &k);
        assert!(matches!(verify_snapshot(&s, &t, Platform::Linux, None, now()), Err(VerifyError::Expired { .. })));
    }

    #[test]
    fn key_hex_roundtrip() {
        let k = generate_key();
        let k2 = signing_key_from_hex(&hex::encode(k.to_bytes())).unwrap();
        assert_eq!(k.verifying_key(), k2.verifying_key());
        let vk = verifying_key_from_hex(&hex::encode(k.verifying_key().to_bytes())).unwrap();
        assert!(verify_bytes(b"x", &sign_bytes(b"x", &k), &vk));
        assert!(!verify_bytes(b"y", &sign_bytes(b"x", &k), &vk));
    }

    #[test]
    fn a_device_targeted_snapshot_installs_only_on_a_named_device() {
        // Issue #26: a targeted snapshot was compiled without other devices' rules, so it must not install elsewhere.
        let p = Policy::parse(include_str!("../../../conformance/policies/home.toml")).unwrap();
        let opts = CompileOptions {
            target_devices: vec!["omarchy".into()],
            revision: 3,
            rollback_of: None,
            issued_at: "2026-10-26T12:00:00Z".parse().unwrap(),
            not_after: None,
        };
        let s = compile(&p, &CapabilityAdvertisement::linux_nftables_cgroup(), &opts).unwrap();
        let key = generate_key();
        let signed = sign_snapshot(&s, &key);
        let mut t = TrustStore::new();
        t.trust(key.verifying_key());
        let ok = verify_snapshot_for_device(&signed, &t, Platform::Linux, Some("omarchy"), None, now()).unwrap();
        assert_eq!(ok.devices, vec!["omarchy".to_string()]);
        let other = verify_snapshot_for_device(&signed, &t, Platform::Linux, Some("linux-2"), None, now()).unwrap_err();
        assert!(matches!(other, VerifyError::WrongDevice { expected: Some(ref d), .. } if d == "linux-2"), "{other:?}");
        let anon = verify_snapshot(&signed, &t, Platform::Linux, None, now()).unwrap_err();
        assert!(
            matches!(anon, VerifyError::WrongDevice { expected: None, .. }),
            "an endpoint that does not say who it is refuses: {anon:?}"
        );
        // The device list is inside the signed payload: editing it breaks the signature.
        let mut forged = signed.clone();
        let mut v: serde_json::Value = serde_json::from_slice(&B64.decode(&forged.payload).unwrap()).unwrap();
        v["devices"] = serde_json::json!(["omarchy", "linux-2"]);
        forged.payload = B64.encode(serde_json::to_vec(&v).unwrap());
        assert_eq!(
            verify_snapshot_for_device(&forged, &t, Platform::Linux, Some("linux-2"), None, now()).unwrap_err(),
            VerifyError::BadSignature
        );
        // An untargeted snapshot still installs on any device of the platform.
        let fleet = sign_snapshot(&snap(4, None), &key);
        assert!(verify_snapshot_for_device(&fleet, &t, Platform::Linux, Some("linux-2"), None, now()).is_ok());
        assert!(verify_snapshot(&fleet, &t, Platform::Linux, None, now()).is_ok());
    }
}
