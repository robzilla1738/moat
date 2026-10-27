import XCTest
@testable import MoatKit

final class PolicyStoreTests: XCTestCase {
    func testRejectionLeavesCurrentPolicyUntouched() {
        let s = PolicyStore(directory: nil, verifier: FakeVerifier())
        XCTAssertNoThrow(try s.apply(signed: Data("rev:5".utf8)).get())
        guard case .failure = s.apply(signed: Data("bad".utf8)) else { return XCTFail("should reject") }
        XCTAssertEqual(s.installed?.summary.revision, 5)
        XCTAssertNotNil(s.lastRejection)
    }

    func testReplayRejected() {
        let s = PolicyStore(directory: nil, verifier: FakeVerifier())
        _ = s.apply(signed: Data("rev:5".utf8))
        guard case let .failure(f) = s.apply(signed: Data("rev:5".utf8)) else { return XCTFail("replay accepted") }
        XCTAssertEqual(f.kind, "replay")
    }

    func testRollbackKeepsReplayHighWaterMark() {
        let s = PolicyStore(directory: nil, verifier: FakeVerifier())
        _ = s.apply(signed: Data("rev:5".utf8))
        _ = s.apply(signed: Data("rev:6".utf8))
        XCTAssertEqual(s.lastKnownGood?.summary.revision, 5)
        let r = s.rollbackToLastKnownGood()
        XCTAssertEqual(r?.revision, 5)
        XCTAssertEqual(r?.rollbackOf, 6)
        XCTAssertEqual(s.lastApplied, 6)
        guard case .failure = s.apply(signed: Data("rev:6".utf8)) else { return XCTFail("old snapshot replayed after rollback") }
        XCTAssertNoThrow(try s.apply(signed: Data("rev:7".utf8)).get())
    }

    func testCanaryRollsBackUnlessConfirmed() {
        let t = Date()
        let s = PolicyStore(directory: nil, verifier: FakeVerifier())
        _ = s.apply(signed: Data("rev:1".utf8), now: t)
        _ = s.apply(signed: Data("rev:2".utf8), canary: 600, now: t)
        XCTAssertNil(s.tick(now: t.addingTimeInterval(599)))
        XCTAssertEqual(s.tick(now: t.addingTimeInterval(601))?.revision, 1)
        XCTAssertEqual(s.installed?.summary.revision, 1)

        _ = s.apply(signed: Data("rev:3".utf8), canary: 600, now: t)
        XCTAssertTrue(s.confirmCanary())
        XCTAssertNil(s.tick(now: t.addingTimeInterval(3600)))
        XCTAssertEqual(s.installed?.summary.revision, 3)
    }

    func testUnconfirmedCanaryNeverBecomesLastKnownGood() {
        let s = PolicyStore(directory: nil, verifier: FakeVerifier())
        _ = s.apply(signed: Data("rev:1".utf8))
        _ = s.apply(signed: Data("rev:2".utf8), canary: 600)
        _ = s.apply(signed: Data("rev:3".utf8))
        XCTAssertEqual(s.lastKnownGood?.summary.revision, 1)
    }

    func testStatePersistsIncludingIsolation() throws {
        let dir = FileManager.default.temporaryDirectory.appendingPathComponent("moat-\(UUID().uuidString)")
        defer { try? FileManager.default.removeItem(at: dir) }
        do {
            let s = PolicyStore(directory: dir, verifier: FakeVerifier())
            _ = s.apply(signed: Data("rev:9".utf8))
            s.setIsolation(IsolationState(active: true, since: Date(), reason: "test"))
        }
        let again = PolicyStore(directory: dir, verifier: FakeVerifier())
        XCTAssertEqual(again.installed?.summary.revision, 9)
        XCTAssertEqual(again.lastApplied, 9)
        XCTAssertTrue(again.isolation.active)
    }
}
