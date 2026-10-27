import CMoatFFI
import Foundation
import MoatKit

/// Swift wrapper over the Rust moat-core C ABI (core/moat-ffi/include/moat_ffi.h).
///
/// Every call is JSON in, JSON out, and every returned string is released with `moat_string_free`.
public enum MoatCore {
    public struct FFIError: Error, CustomStringConvertible, Equatable {
        public var message: String
        public var description: String { message }
    }

    static func call(_ request: [String: Any], _ fn: (UnsafePointer<CChar>?) -> UnsafeMutablePointer<CChar>?) throws -> [String: Any] {
        let data = try JSONSerialization.data(withJSONObject: request, options: [])
        guard let text = String(data: data, encoding: .utf8) else { throw FFIError(message: "request is not UTF-8") }
        let out: UnsafeMutablePointer<CChar>? = text.withCString { fn($0) }
        guard let out else { throw FFIError(message: "moat-ffi returned NULL") }
        defer { moat_string_free(out) }
        let reply = String(cString: out)
        guard let obj = try JSONSerialization.jsonObject(with: Data(reply.utf8)) as? [String: Any] else {
            throw FFIError(message: "moat-ffi reply is not a JSON object")
        }
        return obj
    }

    /// ABI version, core version and the macOS capability advertisement.
    public static func info() throws -> [String: Any] {
        guard let out = moat_info() else { throw FFIError(message: "moat-ffi returned NULL") }
        defer { moat_string_free(out) }
        guard let obj = try JSONSerialization.jsonObject(with: Data(String(cString: out).utf8)) as? [String: Any] else {
            throw FFIError(message: "bad info reply")
        }
        return obj
    }

    public static var abiVersion: Int? { (try? info())?["abi_version"] as? Int }

    /// Parse and validate TOML policy text; returns the normalized policy JSON.
    public static func parsePolicy(toml: String) throws -> Data {
        let r = try call(["toml": toml]) { moat_parse_policy($0) }
        guard r["ok"] as? Bool == true, let p = r["policy"] else { throw FFIError(message: r["error"] as? String ?? "invalid policy") }
        return try JSONSerialization.data(withJSONObject: p, options: [.sortedKeys])
    }

    static let iso: ISO8601DateFormatter = {
        let f = ISO8601DateFormatter()
        f.formatOptions = [.withInternetDateTime, .withFractionalSeconds]
        return f
    }()
}

/// `SnapshotVerifier` backed by moat-core: signature, platform (macOS), replay, expiry and schema checks.
public struct CoreVerifier: SnapshotVerifier {
    public var trust: TrustConfig

    public init(trust: TrustConfig) {
        self.trust = trust
    }

    public func verify(signed: Data, lastApplied: UInt64?, now: Date) -> Result<VerifiedSnapshot, VerificationFailure> {
        guard let signedObj = try? JSONSerialization.jsonObject(with: signed) as? [String: Any] else {
            return .failure(VerificationFailure(kind: "malformed", message: "The snapshot file is not a signed Moat snapshot (JSON)."))
        }
        var req: [String: Any] = [
            "signed": signedObj,
            "trusted_keys": trust.keys,
            "revoked_key_ids": trust.revokedKeyIDs,
            "now": MoatCore.iso.string(from: now),
            "platform": "macos",
        ]
        if let lastApplied { req["last_applied"] = lastApplied }
        let r: [String: Any]
        do {
            r = try MoatCore.call(req) { moat_verify_snapshot($0) }
        } catch {
            return .failure(VerificationFailure(kind: "ffi", message: "\(error)"))
        }
        guard r["ok"] as? Bool == true, let snap = r["snapshot"] as? [String: Any] else {
            let kind = (r["verify_error"] as? [String: Any])?["error"] as? String ?? "invalid"
            return .failure(VerificationFailure(kind: kind, message: r["error"] as? String ?? "verification failed"))
        }
        guard let policy = snap["policy"] as? [String: Any],
              let policyJSON = try? JSONSerialization.data(withJSONObject: policy, options: [.sortedKeys]),
              let revision = (snap["revision"] as? NSNumber)?.uint64Value
        else {
            return .failure(VerificationFailure(kind: "malformed", message: "verified snapshot is missing fields"))
        }
        let report = snap["report"] as? [String: Any] ?? [:]
        let omitted = (report["omitted"] as? [[String: Any]] ?? []).map {
            OmittedRule(ruleID: $0["rule_id"] as? String ?? "?", reason: $0["reason"] as? String ?? "")
        }
        let summary = PolicySummary(
            revision: revision,
            rollbackOf: (snap["rollback_of"] as? NSNumber)?.uint64Value,
            policyName: snap["policy_name"] as? String ?? "",
            digest: snap["policy_digest"] as? String ?? "",
            appliedAt: now,
            ruleCount: (policy["rules"] as? [Any])?.count ?? 0,
            omitted: omitted)
        return .success(VerifiedSnapshot(summary: summary, policyJSON: policyJSON))
    }
}

/// `PolicyEvaluator` backed by moat-core's evaluator (precedence, explanation, observation labelling).
public final class CoreEvaluator: PolicyEvaluator, @unchecked Sendable {
    private let policy: Any

    public init(policyJSON: Data) throws {
        policy = try JSONSerialization.jsonObject(with: policyJSON)
    }

    public func evaluate(_ f: FlowFacts, deviceID: String) throws -> EvaluatedDecision {
        var app: [String: Any] = [:]
        if let v = f.bundleID { app["bundle_id"] = v }
        if let v = f.signingID { app["signing_id"] = v }
        if let v = f.teamID { app["team_id"] = v }
        if let v = f.executable { app["executable"] = v }
        var flow: [String: Any] = [
            "id": f.id,
            "device_id": deviceID,
            "app": app,
            "remote_ip": f.remoteIP,
            "remote_port": Int(f.remotePort),
            "transport": f.transport.rawValue,
            "at": MoatCore.iso.string(from: f.at),
        ]
        if let h = f.remoteHost, !h.isEmpty {
            let src = f.hostSource ?? .flowApi
            flow["hostname"] = ["name": h, "source": src.rawValue, "confidence": src == .flowApi ? "high" : "low"]
        }
        let r = try MoatCore.call(["policy": policy, "device_id": deviceID, "flow": flow]) { moat_evaluate($0) }
        guard r["ok"] as? Bool == true, let d = r["decision"] as? [String: Any], let verdict = d["verdict"] as? String else {
            throw MoatCore.FFIError(message: r["error"] as? String ?? "evaluation failed")
        }
        let winner = d["winner"] as? [String: Any]
        return EvaluatedDecision(
            verdict: verdict == "allow" ? .allow : .deny,
            summary: r["summary"] as? String ?? verdict,
            ruleID: winner?["kind"] as? String == "rule" ? winner?["id"] as? String : nil,
            permittedByObservation: d["permitted_by_observation"] as? Bool ?? false,
            notes: d["notes"] as? [String] ?? [])
    }
}
