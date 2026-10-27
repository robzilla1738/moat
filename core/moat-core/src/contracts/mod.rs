//! W01 canonical contracts (`contracts/` at the repository root is the normative source).
//!
//! Every component (Rust endpoint, Swift app, TypeScript controller/web) gives these objects the same meaning. The
//! JSON schemas in `contracts/schemas/` fix the structure; the semantic checks here fix what structure alone cannot
//! (mandatory scope by kind, monotonic high-water marks, freshness). Shared fixtures in `contracts/fixtures/` must
//! round-trip through every implementation with an identical canonical digest.
//!
//! Canonical serialization (contracts/CANONICAL.md):
//! * UTF-8 JSON, no insignificant whitespace, object keys sorted by code point;
//! * absent optional fields are omitted, never `null`;
//! * numbers are non-negative integers no larger than 2^53 - 1;
//! * timestamps are strings `YYYY-MM-DDTHH:MM:SSZ` (UTC, whole seconds);
//! * arrays that are sets are sorted ascending and duplicate-free in the input itself (validation rejects others);
//! * digest = `sha256:` + lowercase hex of the canonical bytes.
//!
//! Unknown fields are rejected (`deny_unknown_fields`) and an unknown `schema` string is rejected: a consumer that
//! does not understand a field must not act on an object whose meaning it cannot know. Producer-specific detail
//! that never affects authority goes in an event's `ext` object.

pub mod activation;
pub mod disposition;
pub mod event;
pub mod grant;
pub mod receipt;
pub mod subject;

use chrono::{DateTime, NaiveDateTime, Utc};
use serde::de::DeserializeOwned;
use serde::Serialize;
use serde_json::Value;
use sha2::{Digest, Sha256};

pub use activation::{ActivationPhase, ActivationState, Durability, GenerationRef};
pub use disposition::{CapabilityCell, CapabilityDispositions, Disposition, ItemDisposition, Omission};
pub use event::{Event, EventKind, EvidenceStage};
pub use grant::{Grant, GrantDestination, GrantScope, GrantScopeKind, StreamPolicy};
pub use receipt::{Freshness, Receipt};
pub use subject::{ExecutableIdentity, ProcessGeneration, Subject};

/// Largest integer every implementation (including JavaScript numbers) represents exactly.
pub const MAX_SAFE_INT: u64 = (1u64 << 53) - 1;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ContractError {
    pub path: String,
    pub message: String,
}

impl std::fmt::Display for ContractError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}: {}", self.path, self.message)
    }
}

impl std::error::Error for ContractError {}

pub(crate) fn cerr(path: impl Into<String>, msg: impl Into<String>) -> ContractError {
    ContractError { path: path.into(), message: msg.into() }
}

/// Implemented by every contract object: its schema id and its semantic checks.
pub trait Contract: Serialize + DeserializeOwned {
    const SCHEMA: &'static str;
    /// Semantic validation beyond the JSON schema. Structural problems are caught by deserialization.
    fn validate(&self) -> Result<(), Vec<ContractError>>;
}

/// Check that a JSON value is in the canonical value domain: no nulls, no floats, no negative or unsafe integers.
pub fn check_value_domain(v: &Value, path: &str, errs: &mut Vec<ContractError>) {
    match v {
        Value::Null => errs.push(cerr(path, "null is not allowed; omit the field")),
        Value::Number(n) => match n.as_u64() {
            Some(u) if u <= MAX_SAFE_INT => {}
            _ => errs.push(cerr(path, "numbers must be integers in 0..=2^53-1")),
        },
        Value::Array(a) => {
            for (i, x) in a.iter().enumerate() {
                check_value_domain(x, &format!("{path}[{i}]"), errs);
            }
        }
        Value::Object(o) => {
            for (k, x) in o {
                if k.is_empty() || !k.bytes().all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'_') {
                    errs.push(cerr(format!("{path}.{k}"), "keys must be [a-z0-9_]+"));
                }
                check_value_domain(x, &format!("{path}.{k}"), errs);
            }
        }
        Value::Bool(_) | Value::String(_) => {}
    }
}

/// Canonical bytes of an already-validated JSON value.
pub fn canonical_bytes(v: &Value) -> Vec<u8> {
    // serde_json's Value map is a BTreeMap here (the `preserve_order` feature is not enabled anywhere in the
    // workspace), so keys serialize sorted; compact output has no whitespace.
    serde_json::to_vec(v).expect("JSON value serializes")
}

pub fn digest_bytes(b: &[u8]) -> String {
    format!("sha256:{}", hex::encode(Sha256::digest(b)))
}

/// Canonical digest of a contract object.
pub fn digest<T: Serialize>(t: &T) -> String {
    digest_bytes(&canonical_bytes(&serde_json::to_value(t).expect("contract serializes")))
}

/// Parse, check the value domain and schema id, deserialize strictly and validate semantics.
pub fn parse<T: Contract>(text: &str) -> Result<T, Vec<ContractError>> {
    let v: Value = serde_json::from_str(text).map_err(|e| vec![cerr("$", format!("invalid JSON: {e}"))])?;
    from_value(v)
}

pub fn from_value<T: Contract>(v: Value) -> Result<T, Vec<ContractError>> {
    let mut errs = Vec::new();
    check_value_domain(&v, "$", &mut errs);
    match v.get("schema").and_then(Value::as_str) {
        Some(s) if s == T::SCHEMA => {}
        Some(s) => errs.push(cerr("$.schema", format!("unsupported schema {s:?}; this consumer understands {}", T::SCHEMA))),
        None => errs.push(cerr("$.schema", "missing schema id")),
    }
    if !errs.is_empty() {
        return Err(errs);
    }
    let t: T = serde_json::from_value(v).map_err(|e| vec![cerr("$", e.to_string())])?;
    t.validate()?;
    Ok(t)
}

/// Canonical text of a contract object.
pub fn to_canonical_string<T: Serialize>(t: &T) -> String {
    String::from_utf8(canonical_bytes(&serde_json::to_value(t).expect("contract serializes"))).expect("utf-8")
}

/// Parse a canonical timestamp (`YYYY-MM-DDTHH:MM:SSZ`). Any other spelling is rejected so every implementation
/// hashes the same bytes.
pub fn parse_time(s: &str) -> Option<DateTime<Utc>> {
    if s.len() != 20 || !s.ends_with('Z') {
        return None;
    }
    let n = NaiveDateTime::parse_from_str(&s[..19], "%Y-%m-%dT%H:%M:%S").ok()?;
    let t = n.and_utc();
    (format_time(t) == s).then_some(t)
}

pub fn format_time(t: DateTime<Utc>) -> String {
    t.format("%Y-%m-%dT%H:%M:%SZ").to_string()
}

pub(crate) fn check_time(s: &str, path: &str, errs: &mut Vec<ContractError>) -> Option<DateTime<Utc>> {
    let t = parse_time(s);
    if t.is_none() {
        errs.push(cerr(path, format!("{s:?} is not a canonical UTC timestamp YYYY-MM-DDTHH:MM:SSZ")));
    }
    t
}

pub(crate) fn check_id(s: &str, path: &str, errs: &mut Vec<ContractError>) {
    let ok = !s.is_empty()
        && s.len() <= 128
        && s.bytes().all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'.' | b':' | b'@' | b'/'));
    if !ok {
        errs.push(cerr(path, format!("{s:?} is not a valid identifier ([A-Za-z0-9-_.:@/]{{1,128}})")));
    }
}

pub(crate) fn check_digest(s: &str, path: &str, errs: &mut Vec<ContractError>) {
    let ok = s.len() == 71 && s.starts_with("sha256:") && s[7..].bytes().all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b));
    if !ok {
        errs.push(cerr(path, "digest must be sha256: followed by 64 lowercase hex digits"));
    }
}

pub(crate) fn check_sorted_unique<T: Ord + std::fmt::Debug>(xs: &[T], path: &str, errs: &mut Vec<ContractError>) {
    if xs.windows(2).any(|w| w[0] >= w[1]) {
        errs.push(cerr(path, "set arrays must be sorted ascending without duplicates"));
    }
}

pub(crate) fn finish(errs: Vec<ContractError>) -> Result<(), Vec<ContractError>> {
    if errs.is_empty() {
        Ok(())
    } else {
        Err(errs)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn timestamps_have_one_spelling() {
        assert!(parse_time("2026-10-27T15:00:00Z").is_some());
        for bad in
            ["2026-10-27T15:00:00.000Z", "2026-10-27T15:00:00+00:00", "2026-10-27 15:00:00Z", "2026-13-27T15:00:00Z", "2026-10-27T15:00Z"]
        {
            assert!(parse_time(bad).is_none(), "{bad}");
        }
    }

    #[test]
    fn canonical_bytes_sort_keys_and_strip_whitespace() {
        let v: Value = serde_json::from_str(r#"{ "b": 1, "a": { "d": [3, 1], "c": "x" } }"#).unwrap();
        assert_eq!(canonical_bytes(&v), br#"{"a":{"c":"x","d":[3,1]},"b":1}"#);
    }

    #[test]
    fn value_domain_rejects_null_float_negative_unsafe() {
        for bad in [r#"{"a":null}"#, r#"{"a":1.5}"#, r#"{"a":-1}"#, r#"{"a":9007199254740992}"#, r#"{"A":1}"#] {
            let v: Value = serde_json::from_str(bad).unwrap();
            let mut e = Vec::new();
            check_value_domain(&v, "$", &mut e);
            assert!(!e.is_empty(), "{bad}");
        }
    }
}
