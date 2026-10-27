/* moat_ffi.h: C ABI over moat-core (JSON in, JSON out). ABI version 1.
 *
 * Every function returns a newly allocated NUL-terminated UTF-8 JSON string, never NULL in
 * practice, that must be released with moat_string_free(). Responses are
 * {"ok":true,...} or {"ok":false,"error":"..."}. Panics are caught inside the library.
 *
 * The ABI evaluates, verifies and compiles. It never holds a signing key: moat_compile returns
 * the exact payload bytes, the caller signs them with the owner key (Keychain, user presence)
 * and moat_assemble_signed_snapshot wraps them after checking the signature. Trust keys are
 * supplied by the caller from owner configuration; the library never promotes trust and never
 * runs scripts. Additive entry points are listed in moat_info's "entry_points".
 */
#ifndef MOAT_FFI_H
#define MOAT_FFI_H

#ifdef __cplusplus
extern "C" {
#endif

/* {"ok":true,"abi_version":1,"core_version":"0.1.0","entry_points":[...],"capabilities":{...}} */
char *moat_info(void);

/* Request: {"signed":{SignedSnapshot},"trusted_keys":["<hex ed25519 pub>"],
 *           "revoked_key_ids":[...]?, "last_applied":N?, "device_id":"..."?, "now":"RFC3339"?,
 *           "platform":"macos"?}
 * A device-targeted snapshot is accepted only with a matching device_id.
 * Response: {"ok":true,"snapshot":{...}} or {"ok":false,"error":"...","verify_error":{"error":"replay",...}} */
char *moat_verify_snapshot(const char *request_json);

/* Request: {"policy":{Policy JSON},"device_id":"...","flow":{FlowAttempt}}
 * Response: {"ok":true,"summary":"blocked by ...","decision":{...}} */
char *moat_evaluate(const char *request_json);

/* Request: {"toml":"..."}  Response: {"ok":true,"policy":{...}} */
char *moat_parse_policy(const char *request_json);

/* Compile a policy (plus optional grants) with moat-core's compiler (issue #32).
 * Request: {"policy_text":"<TOML or JSON>" | "policy":{Policy JSON}, "adapter":"macos",
 *           "revision":N, "issued_at":"RFC3339", "not_after":"RFC3339"?, "rollback_of":N?,
 *           "grants":[moat.grant.v1...]?, "devices":["device-id"...]?}
 * Response: {"ok":true,"payload":"<base64 exact snapshot JSON bytes to sign>","payload_sha256":"..",
 *            "revision":N,"platform":"macos","devices":[...],"policy_digest":"..","report":{...}}
 *        or {"ok":false,"error":"...","errors":[{"path":"...","message":"..."}]}
 * A rule the adapter cannot enforce is refused, never weakened. */
char *moat_compile(const char *request_json);

/* Request: {"payload":"<base64 from moat_compile>","signature":"<base64 Ed25519 over the payload bytes>",
 *           "public_key":"<hex 32-byte Ed25519 public key>"}
 * Response: {"ok":true,"signed":{"schema":"moat.signed_snapshot.v1","key_id":"..","payload":"..","signature":".."}}
 *        or {"ok":false,"error":"signature does not verify ..."}. Does not make the key trusted. */
char *moat_assemble_signed_snapshot(const char *request_json);

void moat_string_free(char *s);

#ifdef __cplusplus
}
#endif

#endif /* MOAT_FFI_H */
