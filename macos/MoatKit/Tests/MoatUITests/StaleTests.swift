import Foundation
import XCTest
@testable import MoatKit
@testable import MoatUI

/// W07: a lost XPC connection shows as stale/unknown, never as the last green badge.
final class StaleTests: XCTestCase {
    final class FlakyClient: ControlClient, @unchecked Sendable {
        let inner = DemoControlClient()
        var up = true
        func check() throws { if !up { throw ControlError("Cannot reach the Moat filter: connection interrupted") } }
        func status() async throws -> StatusReport { try check(); return try await inner.status() }
        func recentFlows(limit: Int) async throws -> [FlowRecord] { try check(); return try await inner.recentFlows(limit: limit) }
        func applySignedSnapshot(_ data: Data, canarySeconds: Int) async throws -> PolicySummary { try check(); return try await inner.applySignedSnapshot(data, canarySeconds: canarySeconds) }
        func confirmCanary() async throws { try check() }
        func rollbackToLastKnownGood() async throws -> PolicySummary { try check(); return try await inner.rollbackToLastKnownGood() }
        func enterIsolation(reason: String) async throws -> IsolationState { try check(); return try await inner.enterIsolation(reason: reason) }
        func exitIsolation(confirmation: String) async throws -> IsolationState { try check(); return try await inner.exitIsolation(confirmation: confirmation) }
        func reloadTrust() async throws -> Bool { try check(); return false }
    }

    @MainActor
    func testLostConnectionBecomesUnknownAndRecovers() async {
        let c = FlakyClient()
        let m = AppModel(client: c)
        await m.refresh()
        XCTAssertEqual(m.status?.coverage, .enforced)
        XCTAssertFalse(m.isStale)
        c.up = false
        await m.refresh()
        XCTAssertTrue(m.isStale)
        XCTAssertEqual(m.status?.coverage, .unknown, "the last green report is not shown as current")
        XCTAssertTrue(m.status?.coverageNotes.first?.contains("Lost contact") ?? false)
        XCTAssertEqual(m.lastGoodStatus?.coverage, .enforced, "the last real report is kept for reference")
        c.up = true
        await m.refresh()
        XCTAssertFalse(m.isStale)
        XCTAssertEqual(m.status?.coverage, .enforced)
    }
}
