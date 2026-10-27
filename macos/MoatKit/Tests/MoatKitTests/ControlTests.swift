import XCTest
@testable import MoatKit

final class ControlTests: XCTestCase {
    func makeHandler(dir: URL? = nil) -> ControlHandler {
        ControlHandler(
            engine: FilterEngine(deviceID: "mbp"), store: PolicyStore(directory: dir, verifier: FakeVerifier()), version: "test",
            filterEnabled: { true }, makeEvaluator: { _ in FakeEvaluator() })
    }

    func decode<T: Decodable>(_ r: Result<Data, ControlError>, _ t: T.Type) throws -> T {
        try ControlCoding.decoder.decode(T.self, from: r.get())
    }

    func testApplyInstallsIntoEngine() throws {
        let h = makeHandler()
        let s = try decode(h.perform(.applySignedSnapshot(Data("rev:4".utf8), canarySeconds: 0)), PolicySummary.self)
        XCTAssertEqual(s.revision, 4)
        XCTAssertEqual(h.engine.decide(flow("evil.example")).verdict, .deny)
        let status = try decode(h.perform(.status), StatusReport.self)
        XCTAssertEqual(status.coverage, .enforced)
        XCTAssertEqual(status.installed?.revision, 4)
    }

    func testRejectedApplyIsReportedAndAudited() {
        let h = makeHandler()
        guard case let .failure(e) = h.perform(.applySignedSnapshot(Data("bad".utf8), canarySeconds: 0)) else { return XCTFail() }
        XCTAssertTrue(e.message.contains("current policy is unchanged"))
        XCTAssertEqual(h.auditLog.last?.operation, "apply_signed_snapshot")
        XCTAssertEqual(h.auditLog.last?.ok, false)
    }

    func testReadOnlyOperationsAreNotAudited() {
        let h = makeHandler()
        _ = h.perform(.status)
        _ = h.perform(.recentFlows(limit: 10))
        XCTAssertTrue(h.auditLog.isEmpty)
    }

    func testBoundsAreEnforced() {
        let h = makeHandler()
        if case .success = h.perform(.recentFlows(limit: 0)) { XCTFail("limit 0 accepted") }
        if case .success = h.perform(.recentFlows(limit: 10_000)) { XCTFail("huge limit accepted") }
        if case .success = h.perform(.applySignedSnapshot(Data(count: ControlHandler.maxSnapshotBytes + 1), canarySeconds: 0)) { XCTFail("oversized accepted") }
        if case .success = h.perform(.applySignedSnapshot(Data("rev:1".utf8), canarySeconds: -1)) { XCTFail("negative canary accepted") }
    }

    func testIsolationNeedsTypedPhraseToExit() throws {
        let h = makeHandler()
        _ = try decode(h.perform(.enterIsolation(reason: "suspicious upload")), IsolationState.self)
        XCTAssertTrue(h.engine.currentIsolation.active)
        if case .success = h.perform(.exitIsolation(confirmation: "yes")) { XCTFail("exited without the phrase") }
        XCTAssertTrue(h.engine.currentIsolation.active)
        let off = try decode(h.perform(.exitIsolation(confirmation: "  Turn Isolation Off ")), IsolationState.self)
        XCTAssertFalse(off.active)
        XCTAssertFalse(h.engine.currentIsolation.active)
    }

    func testIsolationSurvivesRestartAndCanaryRollbackDoesNotLiftIt() throws {
        let dir = FileManager.default.temporaryDirectory.appendingPathComponent("moat-\(UUID().uuidString)")
        defer { try? FileManager.default.removeItem(at: dir) }
        let t = Date()
        do {
            let h = makeHandler(dir: dir)
            _ = h.perform(.applySignedSnapshot(Data("rev:1".utf8), canarySeconds: 0), now: t)
            _ = h.perform(.applySignedSnapshot(Data("rev:2".utf8), canarySeconds: 60), now: t)
            _ = h.perform(.enterIsolation(reason: "x"), now: t)
        }
        let h2 = makeHandler(dir: dir)
        h2.restore()
        XCTAssertTrue(h2.engine.currentIsolation.active, "isolation must survive an extension restart")
        h2.tick(now: t.addingTimeInterval(120))
        XCTAssertEqual(h2.store.installed?.summary.revision, 1, "canary rolled back")
        XCTAssertTrue(h2.engine.currentIsolation.active, "canary rollback must not reopen isolation")
        XCTAssertEqual(h2.engine.decide(flow("fine.example")).source, .emergencyIsolation)
    }

    final class Switch: @unchecked Sendable { var failLoads = false }

    func testCanaryRollbackThatCannotLoadIsRollbackPendingUntilOwnerRecovery() throws {
        let sw = Switch()
        let h = ControlHandler(
            engine: FilterEngine(deviceID: "mbp"), store: PolicyStore(directory: nil, verifier: FakeVerifier()), version: "test",
            filterEnabled: { true }, makeEvaluator: { _ in
                if sw.failLoads { throw ControlError("evaluator unavailable") }
                return FakeEvaluator()
            })
        let t = Date()
        _ = h.perform(.applySignedSnapshot(Data("rev:1".utf8), canarySeconds: 0), now: t)
        _ = h.perform(.applySignedSnapshot(Data("rev:2".utf8), canarySeconds: 60), now: t)
        sw.failLoads = true
        h.tick(now: t.addingTimeInterval(120))
        var status = try decode(h.perform(.status), StatusReport.self)
        XCTAssertEqual(status.coverage, .rollbackPending)
        XCTAssertEqual(status.installed?.revision, 2, "the trial revision is still the one enforced, and the report says so")
        XCTAssertTrue(status.coverageNotes.first?.contains("still enforced") == true, "\(status.coverageNotes)")
        XCTAssertTrue(status.coverage.needsOwnerAtDevice)
        sw.failLoads = false
        _ = try decode(h.perform(.rollbackToLastKnownGood), PolicySummary.self)
        status = try decode(h.perform(.status), StatusReport.self)
        XCTAssertEqual(status.coverage, .enforced)
    }

    func testCoverageLabelsRoundTripAndUnknownLabelsAreUnknown() throws {
        let dec = JSONDecoder()
        XCTAssertEqual(try dec.decode([CoverageLevel].self, from: Data(#"["recovery-required","rollback-pending","enforced"]"#.utf8)), [.recoveryRequired, .rollbackPending, .enforced])
        XCTAssertEqual(try dec.decode([CoverageLevel].self, from: Data(#"["fully-protected"]"#.utf8)), [.unknown], "a label this build does not know is never shown as healthy")
        XCTAssertEqual(String(decoding: try JSONEncoder().encode(CoverageLevel.rollbackPending), as: UTF8.self), #""rollback-pending""#)
    }

    func testRollbackWithoutLastKnownGoodFails() {
        let h = makeHandler()
        if case .success = h.perform(.rollbackToLastKnownGood) { XCTFail() }
    }

    func testOperationNamesAreAClosedSet() {
        let all: [ControlOperation] = [
            .status, .recentFlows(limit: 1), .applySignedSnapshot(Data(), canarySeconds: 0), .confirmCanary, .rollbackToLastKnownGood,
            .enterIsolation(reason: ""), .exitIsolation(confirmation: ""),
        ]
        XCTAssertEqual(Set(all.map(\.name)).count, 7)
        XCTAssertEqual(all.filter(\.isReadOnly).count, 2)
    }

    func testCallerRequirementRefusesUnsignedBuilds() {
        XCTAssertNil(CallerRequirement.make(appBundleID: "com.example.moat", teamID: nil))
        XCTAssertNil(CallerRequirement.make(appBundleID: "com.example.moat", teamID: "short"))
        XCTAssertNil(CallerRequirement.make(appBundleID: "bad\" or true", teamID: "ABCDE12345"))
        XCTAssertEqual(
            CallerRequirement.make(appBundleID: "com.example.moat", teamID: "ABCDE12345"),
            "anchor apple generic and identifier \"com.example.moat\" and certificate leaf[subject.OU] = \"ABCDE12345\"")
    }

    func testTrustConfigParsing() {
        let key = String(repeating: "ab", count: 32)
        let (c, problems) = TrustConfig.parse("# owner key\n\(key)\nrevoke 0123456789abcdef\nnot-a-key\n")
        XCTAssertEqual(c.keys, [key])
        XCTAssertEqual(c.revokedKeyIDs, ["0123456789abcdef"])
        XCTAssertEqual(problems.count, 1)
        XCTAssertFalse(TrustConfig.load(path: "/nonexistent/moat").problems.isEmpty)
    }
}
