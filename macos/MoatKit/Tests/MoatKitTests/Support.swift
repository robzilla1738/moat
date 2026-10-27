import Foundation
@testable import MoatKit

struct FakeEvaluator: PolicyEvaluator {
    var deny: Set<String> = ["evil.example"]
    var observe = false
    var fail = false
    struct Boom: Error {}

    func evaluate(_ f: FlowFacts, deviceID: String) throws -> EvaluatedDecision {
        if fail { throw Boom() }
        if let h = f.remoteHost, deny.contains(h) {
            return EvaluatedDecision(verdict: .deny, summary: "blocked by explicit rule deny-evil", ruleID: "deny-evil")
        }
        return EvaluatedDecision(verdict: .allow, summary: observe ? "permitted (observation, not enforced)" : "allowed by explicit rule ok",
                                 ruleID: observe ? nil : "ok", permittedByObservation: observe)
    }
}

/// Accepts payloads of the form "rev:<n>" (or "bad" to reject), enforcing replay like moat-core does.
struct FakeVerifier: SnapshotVerifier {
    func verify(signed: Data, lastApplied: UInt64?, now: Date) -> Result<VerifiedSnapshot, VerificationFailure> {
        let s = String(decoding: signed, as: UTF8.self)
        guard s.hasPrefix("rev:"), let n = UInt64(s.dropFirst(4)) else {
            return .failure(VerificationFailure(kind: "bad_signature", message: "signature does not verify"))
        }
        if let l = lastApplied, n <= l {
            return .failure(VerificationFailure(kind: "replay", message: "revision \(n) is not newer than applied revision \(l) (replay rejected)"))
        }
        return .success(VerifiedSnapshot(
            summary: PolicySummary(revision: n, policyName: "test", digest: "d\(n)", appliedAt: now, ruleCount: 3, omitted: []),
            policyJSON: Data("{\"rev\":\(n)}".utf8)))
    }
}

func flow(_ host: String?, ip: String = "203.0.113.5", port: UInt16 = 443, signing: String = "com.example.app") -> FlowFacts {
    FlowFacts(signingID: signing, teamID: "ABCDE12345", remoteHost: host, hostSource: host == nil ? nil : .flowApi, remoteIP: ip, remotePort: port, transport: .tcp)
}

func summary(_ rev: UInt64) -> PolicySummary {
    PolicySummary(revision: rev, policyName: "test", digest: "d", appliedAt: Date(), ruleCount: 1, omitted: [])
}
