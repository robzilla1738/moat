import Foundation
import XCTest
@testable import MoatKit

/// W07 acceptance: generation-bound evaluators, an expiry-aware cache, candidate failure, verified restoration,
/// trust reload, separate app/process identity, truthful isolation wording and unavailable process grants.
final class W07Tests: XCTestCase {
    // MARK: fakes

    /// Allows until `until`, denies after: a timed grant as moat-core would evaluate it at the flow's time.
    struct TimedEvaluator: PolicyEvaluator {
        var until: Date
        func evaluate(_ f: FlowFacts, deviceID: String) throws -> EvaluatedDecision {
            f.at < until ? EvaluatedDecision(verdict: .allow, summary: "allowed by grant", ruleID: "grant-1") : EvaluatedDecision(verdict: .deny, summary: "blocked by default")
        }
    }

    /// Blocks inside evaluate until released, then answers `verdict`.
    final class GateEvaluator: PolicyEvaluator, @unchecked Sendable {
        let entered = DispatchSemaphore(value: 0)
        let release = DispatchSemaphore(value: 0)
        let verdict: Verdict
        init(_ v: Verdict) { verdict = v }
        func evaluate(_ f: FlowFacts, deviceID: String) throws -> EvaluatedDecision {
            entered.signal()
            release.wait()
            return EvaluatedDecision(verdict: verdict, summary: "gate \(verdict.rawValue)", ruleID: "gate")
        }
    }

    struct ConstEvaluator: PolicyEvaluator {
        var verdict: Verdict
        func evaluate(_ f: FlowFacts, deviceID: String) throws -> EvaluatedDecision {
            EvaluatedDecision(verdict: verdict, summary: "const \(verdict.rawValue)", ruleID: "const")
        }
    }

    /// Accepts "rev:<n>" only while `key` is trusted.
    struct TrustVerifier: SnapshotVerifier {
        var trust: TrustConfig
        func verify(signed: Data, lastApplied: UInt64?, now: Date) -> Result<VerifiedSnapshot, VerificationFailure> {
            guard trust.keys.contains(String(repeating: "a", count: 64)) else {
                return .failure(VerificationFailure(kind: "untrusted_key", message: "signed by a key that is not trusted"))
            }
            return FakeVerifier().verify(signed: signed, lastApplied: lastApplied, now: now)
        }
    }

    // MARK: generations and cache

    func testConcurrentApplyCannotCacheAnObsoleteAllow() {
        let e = FilterEngine(deviceID: "mbp")
        let gate = GateEvaluator(.allow)
        e.install(summary(1), evaluator: gate)
        let done = expectation(description: "old evaluation finished")
        var oldAnswer: FlowDecision?
        DispatchQueue.global().async {
            oldAnswer = e.decide(flow("api.example"))
            done.fulfill()
        }
        XCTAssertEqual(gate.entered.wait(timeout: .now() + 5), .success)
        // a new generation (deny) is installed while the old one is still evaluating
        e.install(summary(2), evaluator: ConstEvaluator(verdict: .deny))
        gate.release.signal()
        wait(for: [done], timeout: 5)
        XCTAssertEqual(oldAnswer?.verdict, .allow, "the in-flight flow got the answer of the generation it started under")
        XCTAssertEqual(e.cachedDecisions, 0, "but that answer was not cached under the new generation")
        let next = e.decide(flow("api.example"))
        XCTAssertEqual(next.verdict, .deny)
        XCTAssertEqual(next.policyRevision, 2)
    }

    func testCacheNeverExtendsATimedPermission() {
        let t0 = Date(timeIntervalSince1970: 1_800_000_000)
        let until = t0.addingTimeInterval(10)
        let e = FilterEngine(deviceID: "mbp", cache: VerdictCache(capacity: 100, ttl: 30))
        e.install(summary(1), evaluator: TimedEvaluator(until: until), expiries: [until])
        XCTAssertEqual(e.decide(flow("api.example"), now: t0).verdict, .allow)
        XCTAssertEqual(e.decide(flow("api.example"), now: t0.addingTimeInterval(5)).verdict, .allow)
        XCTAssertEqual(e.decide(flow("api.example"), now: until).verdict, .deny, "the cached allow ends at the grant's deadline, not after the 30 s TTL")
        XCTAssertEqual(e.decide(flow("api.example"), now: until.addingTimeInterval(1)).verdict, .deny)
    }

    func testCacheEntriesBelongToOneGeneration() {
        var c = VerdictCache(capacity: 10, ttl: 60)
        let now = Date()
        c.put("k", FlowDecision(verdict: .allow, source: .policy, summary: "x"), generation: 1, now: now, boundary: nil)
        XCTAssertNotNil(c.get("k", generation: 1, now: now))
        XCTAssertNil(c.get("k", generation: 2, now: now), "an entry from another generation is never returned")
        c.put("b", FlowDecision(verdict: .allow, source: .policy, summary: "x"), generation: 1, now: now, boundary: now)
        XCTAssertNil(c.get("b", generation: 1, now: now), "nothing is cached past a boundary at or before now")
    }

    func testPolicyExpiriesAreReadFromTheNormalizedPolicy() {
        let json = Data(#"{"rules":[{"id":"a","expires_at":"2026-10-27T16:00:00Z"},{"id":"b"},{"id":"c","expires_at":"2026-10-27T15:30:00.250Z"}]}"#.utf8)
        let x = PolicyExpiries.from(policyJSON: json)
        XCTAssertEqual(x.count, 2)
        XCTAssertLessThan(x[0], x[1])
    }

    // MARK: candidates, durability and restoration

    func testFailedCandidateKeepsTheRunningEvaluatorAndState() throws {
        let h = ControlHandler(
            engine: FilterEngine(deviceID: "mbp"), store: PolicyStore(directory: nil, verifier: FakeVerifier()), version: "t", filterEnabled: { true },
            makeEvaluator: { json in
                if String(decoding: json, as: UTF8.self).contains("7") { throw FakeEvaluator.Boom() }
                return FakeEvaluator()
            })
        _ = try h.perform(.applySignedSnapshot(Data("rev:5".utf8), canarySeconds: 0)).get()
        let gen = h.engine.currentGeneration?.generation
        guard case let .failure(err) = h.perform(.applySignedSnapshot(Data("rev:7".utf8), canarySeconds: 0)) else { return XCTFail("bad candidate accepted") }
        XCTAssertTrue(err.message.contains("current policy is unchanged"))
        XCTAssertEqual(h.engine.currentGeneration?.generation, gen, "the running generation is untouched")
        XCTAssertEqual(h.store.installed?.summary.revision, 5)
        XCTAssertEqual(h.store.lastApplied, 5, "a rejected candidate does not move the replay high-water mark")
        XCTAssertEqual(h.engine.decide(flow("evil.example")).verdict, .deny, "still enforcing revision 5")
        XCTAssertEqual(h.status().coverage, .enforced)
    }

    func testAFailedWriteIsNeverReportedAsDurable() throws {
        let unwritable = URL(fileURLWithPath: "/dev/null/moat-\(UUID().uuidString)")
        let h = ControlHandler(engine: FilterEngine(deviceID: "mbp"), store: PolicyStore(directory: unwritable, verifier: FakeVerifier()), version: "t", filterEnabled: { true }, makeEvaluator: { _ in FakeEvaluator() })
        guard case let .failure(e) = h.perform(.applySignedSnapshot(Data("rev:3".utf8), canarySeconds: 0)) else { return XCTFail("non-durable apply reported as success") }
        XCTAssertTrue(e.message.contains("will not survive a restart"))
        XCTAssertEqual(h.engine.installedPolicy?.revision, 3, "enforced in memory")
        let s = h.status()
        XCTAssertEqual(s.durable, false)
        XCTAssertTrue(s.coverageNotes.first?.contains("not survive a restart") ?? false)
    }

    func testRestorationReverifiesAndRefusesTamperedState() throws {
        let dir = FileManager.default.temporaryDirectory.appendingPathComponent("moat-\(UUID().uuidString)")
        defer { try? FileManager.default.removeItem(at: dir) }
        do {
            let h = ControlHandler(engine: FilterEngine(deviceID: "mbp"), store: PolicyStore(directory: dir, verifier: FakeVerifier()), version: "t", filterEnabled: { true }, makeEvaluator: { _ in FakeEvaluator() })
            _ = try h.perform(.applySignedSnapshot(Data("rev:8".utf8), canarySeconds: 0)).get()
            _ = try h.perform(.applySignedSnapshot(Data("rev:9".utf8), canarySeconds: 0)).get()
        }
        // tamper with the installed policy body on disk (signature no longer matches the content)
        let url = dir.appendingPathComponent("state.json")
        var obj = try XCTUnwrap(JSONSerialization.jsonObject(with: Data(contentsOf: url)) as? [String: Any])
        var installed = try XCTUnwrap(obj["installed"] as? [String: Any])
        installed["policyJSON"] = Data(#"{"rev":9,"allow":"everything"}"#.utf8).base64EncodedString()
        obj["installed"] = installed
        try JSONSerialization.data(withJSONObject: obj).write(to: url)

        let h = ControlHandler(engine: FilterEngine(deviceID: "mbp"), store: PolicyStore(directory: dir, verifier: FakeVerifier()), version: "t", filterEnabled: { true }, makeEvaluator: { _ in FakeEvaluator() })
        h.restore()
        XCTAssertEqual(h.engine.installedPolicy?.revision, 8, "the tampered revision is not restored; the verified last known good is")
        XCTAssertTrue(h.status().restoration?.contains("could not be restored") ?? false)
    }

    func testRestorationWithNothingVerifiableIsAnExplicitFailureNotSilentEnforcement() throws {
        let dir = FileManager.default.temporaryDirectory.appendingPathComponent("moat-\(UUID().uuidString)")
        defer { try? FileManager.default.removeItem(at: dir) }
        do {
            let s = PolicyStore(directory: dir, verifier: FakeVerifier())
            _ = s.apply(signed: Data("rev:4".utf8))
        }
        let untrusting = TrustVerifier(trust: TrustConfig(keys: []))
        let h = ControlHandler(engine: FilterEngine(deviceID: "mbp"), store: PolicyStore(directory: dir, verifier: untrusting), version: "t", filterEnabled: { true }, makeEvaluator: { _ in FakeEvaluator() })
        h.restore()
        XCTAssertNil(h.engine.installedPolicy)
        let s = h.status()
        XCTAssertEqual(s.coverage, .degraded, "a failed restoration is degraded, never 'enforced' and never a quiet 'observing'")
        XCTAssertTrue(s.coverageNotes.first?.contains("No installed revision could be restored") ?? false)
    }

    func testTrustChangesReachTheRunningVerifier() throws {
        let key = String(repeating: "a", count: 64)
        var file: String? = "\(key)\n"
        let trust = TrustStore(path: "/test/trusted-keys", read: { _ in file })
        let h = ControlHandler(
            engine: FilterEngine(deviceID: "mbp"), store: PolicyStore(directory: nil, verifier: TrustVerifier(trust: TrustConfig(keys: []))), version: "t", filterEnabled: { true },
            makeEvaluator: { _ in FakeEvaluator() }, trust: trust, makeVerifier: { TrustVerifier(trust: $0) })
        _ = try h.perform(.applySignedSnapshot(Data("rev:2".utf8), canarySeconds: 0)).get()
        XCTAssertEqual(h.status().trustGeneration, 1)
        XCTAssertEqual(h.engine.installedPolicy?.revision, 2)
        // the owner removes the key from the root-owned file; the next tick reaches the running verifier
        file = "# key retired\n"
        h.tick()
        XCTAssertEqual(trust.generation, 2)
        XCTAssertNil(h.engine.installedPolicy, "a policy whose signer is no longer trusted stops being enforced as trusted")
        XCTAssertEqual(h.status().coverage, .degraded)
        guard case .failure = h.perform(.applySignedSnapshot(Data("rev:3".utf8), canarySeconds: 0)) else { return XCTFail("untrusted snapshot accepted after reload") }
        // the key comes back: an explicit reload re-verifies and restores
        file = "\(key)\n"
        let r = try ControlCoding.decoder.decode([String: Bool].self, from: h.perform(.reloadTrust).get())
        XCTAssertEqual(r["changed"], true)
        XCTAssertEqual(h.engine.installedPolicy?.revision, 2)
        XCTAssertEqual(h.engine.currentGeneration?.trustGeneration, 3)
    }

    // MARK: identity, wording, unavailable features

    func testActualProcessAndResponsibleAppStaySeparate() {
        var f = flow("api.example", signing: "com.example.App")
        f.process = ProcessIdentity(signingID: "com.example.App.Helper", executable: "/Applications/Example.app/Contents/Helpers/helper", pid: 812, pidVersion: 4)
        XCTAssertTrue(f.processDiffersFromApp)
        XCTAssertNotEqual(f.cacheKey, flow("api.example", signing: "com.example.App").cacheKey, "a different socket process never shares a cached verdict")
        let e = FilterEngine(deviceID: "mbp")
        e.decide(f)
        let rec = e.spool.recent(limit: 1)[0]
        XCTAssertEqual(rec.facts.signingID, "com.example.App")
        XCTAssertEqual(rec.facts.process?.signingID, "com.example.App.Helper")
        XCTAssertEqual(rec.facts.process?.pidVersion, 4)
        let old = try? ControlCoding.decoder.decode(FlowFacts.self, from: Data(#"{"id":"x","remoteIP":"203.0.113.1","remotePort":443,"transport":"tcp","at":"2026-10-27T15:00:00Z"}"#.utf8))
        XCTAssertNil(old?.process, "records without a process token decode as 'process unknown'")
    }

    func testIsolationWordingMatchesNewFlowScope() {
        XCTAssertTrue(CoverageLevel.isolated.claim.contains("new outbound connections"))
        XCTAssertFalse(CoverageLevel.isolated.claim.lowercased().contains("everything"))
        let e = FilterEngine(deviceID: "mbp")
        e.setIsolation(IsolationState(active: true, since: Date(), reason: "t"))
        XCTAssertTrue(e.coverage(filterEnabled: true).1.contains { $0.contains("already open") })
    }

    func testProcessScopedGrantsAndAncestryStayUnavailable() {
        let caps = Dictionary(uniqueKeysWithValues: CapabilityRow.macOSDesign.map { ($0.key, $0.support) })
        XCTAssertEqual(caps["process_scoped_grants"], .unsupported)
        XCTAssertEqual(caps["ancestor_attribution"], .unsupported)
        XCTAssertEqual(caps["existing_flow_revocation"], .unsupported)
    }
}
