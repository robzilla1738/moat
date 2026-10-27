/* moat_ffi.h: C ABI over moat-core (JSON in, JSON out). ABI version 1.
 *
 * Every function returns a newly allocated NUL-terminated UTF-8 JSON string, never NULL in
 * practice, that must be released with moat_string_free(). Responses are
 * {"ok":true,...} or {"ok":false,"error":"..."}. Panics are caught inside the library.
 *
 * The ABI evaluates and verifies only. Trust keys are supplied by the caller from owner
 * configuration; the library never promotes trust and never runs scripts.
 */
#ifndef MOAT_FFI_H
#define MOAT_FFI_H

#ifdef __cplusplus
extern "C" {
#endif

/* {"ok":true,"abi_version":1,"core_version":"0.1.0","capabilities":{...}} */
char *moat_info(void);

/* Request: {"signed":{SignedSnapshot},"trusted_keys":["<hex ed25519 pub>"],
 *           "revoked_key_ids":[...]?, "last_applied":N?, "now":"RFC3339"?, "platform":"macos"?}
 * Response: {"ok":true,"snapshot":{...}} or {"ok":false,"error":"...","verify_error":{"error":"replay",...}} */
char *moat_verify_snapshot(const char *request_json);

/* Request: {"policy":{Policy JSON},"device_id":"...","flow":{FlowAttempt}}
 * Response: {"ok":true,"summary":"blocked by ...","decision":{...}} */
char *moat_evaluate(const char *request_json);

/* Request: {"toml":"..."}  Response: {"ok":true,"policy":{...}} */
char *moat_parse_policy(const char *request_json);

void moat_string_free(char *s);

#ifdef __cplusplus
}
#endif

#endif /* MOAT_FFI_H */
