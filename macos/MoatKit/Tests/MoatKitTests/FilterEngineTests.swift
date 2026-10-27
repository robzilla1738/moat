import XCTest
@testable import MoatKit

final class FilterEngineTests: XCTestCase {
    func testNoPolicyIsObservationNotEnforcement() {
        let e = FilterEngine(deviceID: "mbp")
        let d = e.decide(flow("evil.example"))
        XCTAssertEqual(d.verdict, .allow)
        XCTAssertEqual(d.source, .observationNoPolicy)
        XCTAssertTrue(d.isObservation)
        XCTAssertEqual(e.coverage(filterEnabled: true).0, .observed)
    }

    func testInstalledPolicyDecidesAndBlockedFlowsAreBlockedBeforeData() {
        let e = FilterEngine(deviceID: "mbp")
        e.install(summary(3), evaluator: FakeEvaluator())
        let d = e.decide(flow("evil.example"))
        XCTAssertEqual(d.verdict, .deny)
        XCTAssertEqual(d.source, .policy)
        XCTAssertEqual(d.ruleID, "deny-evil")
        XCTAssertEqual(d.policyRevision, 3)
        XCTAssertEqual(e.spool.recent(limit: 1).first?.measurement, .blockedBeforeData)
        XCTAssertEqual(e.decide(flow("fine.example")).verdict, .allow)
        XCTAssertEqual(e.spool.recent(limit: 1).first?.measurement, .unknown, "allowed flows never claim a byte count without a report")
        XCTAssertEqual(e.flowsSeen, 2)
        XCTAssertEqual(e.flowsDenied, 1)
        XCTAssertEqual(e.coverage(filterEnabled: true).0, .enforced)
    }

    func testObservingProfileIsLabelled() {
        let e = FilterEngine(deviceID: "mbp")
        e.install(summary(1), evaluator: FakeEvaluator(observe: true))
        let d = e.decide(flow("anything.example"))
        XCTAssertEqual(d.source, .observationProfile)
        XCTAssertTrue(d.isObservation)
    }

    func testIsolationDeniesEverythingButLoopback() {
        let e = FilterEngine(deviceID: "mbp")
        e.install(summary(1), evaluator: FakeEvaluator())
        _ = e.decide(flow("fine.example"))
        e.setIsolation(IsolationState(active: true, since: Date(), reason: "test"))
        let d = e.decide(flow("fine.example"))
        XCTAssertEqual(d.verdict, .deny, "cache must not leak a pre-isolation allow")
        XCTAssertEqual(d.source, .emergencyIsolation)
        XCTAssertEqual(e.decide(flow(nil, ip: "127.0.0.1", port: 8080)).verdict, .allow)
        XCTAssertEqual(e.decide(flow(nil, ip: "::1", port: 8080)).source, .loopback)
        XCTAssertEqual(e.coverage(filterEnabled: true).0, .isolated)
    }

    func testEvaluatorFailureUsesFallbackAndDegradesCoverage() {
        let e = FilterEngine(deviceID: "mbp")
        e.install(summary(1), evaluator: FakeEvaluator(fail: true), fallbackOnError: .deny)
        let d = e.decide(flow("fine.example"))
        XCTAssertEqual(d.verdict, .deny)
        XCTAssertEqual(d.source, .evaluatorError)
        let (cov, notes) = e.coverage(filterEnabled: true)
        XCTAssertEqual(cov, .degraded)
        XCTAssertTrue(notes.contains { $0.contains("evaluation error") })
    }

    func testFilterDisabledIsDegraded() {
        let e = FilterEngine(deviceID: "mbp")
        XCTAssertEqual(e.coverage(filterEnabled: false).0, .degraded)
    }

    func testReportAttachesMeasuredBytes() {
        let e = FilterEngine(deviceID: "mbp")
        let f = flow("fine.example")
        e.decide(f)
        e.report(flowID: f.id, outbound: 2048, inbound: 10)
        XCTAssertEqual(e.spool.recent(limit: 1).first?.measurement, .reported(outbound: 2048, inbound: 10))
    }

    func testCacheExpiresAndIsBounded() {
        var c = VerdictCache(capacity: 2, ttl: 10)
        let t = Date()
        let d = FlowDecision(verdict: .allow, source: .policy, summary: "x")
        c.put("a", d, generation: 1, now: t, boundary: nil)
        c.put("b", d, generation: 1, now: t, boundary: nil)
        c.put("c", d, generation: 1, now: t, boundary: nil)
        XCTAssertEqual(c.count, 2)
        XCTAssertNil(c.get("a", generation: 1, now: t), "oldest evicted")
        XCTAssertNotNil(c.get("c", generation: 1, now: t))
        XCTAssertNil(c.get("c", generation: 1, now: t.addingTimeInterval(11)), "expired")
    }

    func testByteFormat() {
        XCTAssertEqual(ByteFormat.string(512), "512 B")
        XCTAssertEqual(ByteFormat.string(2048), "2.0 KB")
        XCTAssertEqual(ByteFormat.string(18 * 1024 * 1024), "18 MB")
    }
}

final class EventSpoolTests: XCTestCase {
    func testOverflowBeforeReadIsAGap() {
        let s = EventSpool(capacity: 3)
        let d = FlowDecision(verdict: .allow, source: .policy, summary: "x")
        for _ in 0..<5 { s.append(facts: flow("a"), decision: d, measurement: .unknown) }
        XCTAssertEqual(s.recent(limit: 10).count, 3)
        XCTAssertEqual(s.gaps, [GapMarker(fromSeq: 1, toSeq: 2, reason: EventSpool.overflow)])
    }

    func testDrainedEventsDoNotBecomeGaps() {
        let s = EventSpool(capacity: 2)
        let d = FlowDecision(verdict: .allow, source: .policy, summary: "x")
        s.append(facts: flow("a"), decision: d, measurement: .unknown)
        s.append(facts: flow("a"), decision: d, measurement: .unknown)
        let r = s.drain(after: 0)
        XCTAssertEqual(r.records.map(\.seq), [1, 2])
        XCTAssertNil(r.gap)
        s.append(facts: flow("a"), decision: d, measurement: .unknown)
        XCTAssertTrue(s.gaps.isEmpty)
        let late = s.drain(after: 0)
        XCTAssertEqual(late.gap?.fromSeq, 1)
    }

    func testRestartIsAGap() {
        let s = EventSpool(capacity: 10, resumeAfter: 40, lastDeliveredBeforeRestart: 35)
        XCTAssertEqual(s.gaps.first, GapMarker(fromSeq: 36, toSeq: 40, reason: "extension restarted before these events were delivered"))
        XCTAssertEqual(s.append(facts: flow("a"), decision: FlowDecision(verdict: .allow, source: .policy, summary: ""), measurement: .unknown), 41)
    }
}
