import Foundation
import XCTest
@testable import MoatKit

/// W14 on this Mac: the MASTER_ROADMAP §9.4 poisoning cases against the local learning model, and pack cells.
final class LearningTests: XCTestCase {
    let t0 = Date(timeIntervalSince1970: 1_800_000_000)
    let exe = "/Applications/Tool.app/Contents/MacOS/tool"

    func rec(_ seq: UInt64, _ host: String, exe: String? = "/Applications/Tool.app/Contents/MacOS/tool", team: String? = "TEAM1", verdict: Verdict = .allow, at minutes: Double = 1) -> FlowRecord {
        let facts = FlowFacts(signingID: exe == nil ? nil : "com.example.tool", teamID: team, executable: exe, remoteHost: host, hostSource: .flowApi, remoteIP: "203.0.113.9", remotePort: 443, transport: .tcp, at: t0.addingTimeInterval(minutes * 60))
        return FlowRecord(seq: seq, facts: facts, decision: FlowDecision(verdict: verdict, source: .policy, summary: verdict == .deny ? "blocked" : "allowed"), measurement: verdict == .deny ? .blockedBeforeData : .unknown)
    }

    func scope(hours: Double = 1) -> CaptureScope {
        CaptureScope(id: "cap", signingID: "com.example.tool", executable: exe, teamID: "TEAM1", appName: "Tool", workflow: "npm install", networkContext: "home LAN", start: t0, end: t0.addingTimeInterval(hours * 3600))
    }

    let auth = OwnerAuthorization(keyID: "21fe31dfa154a261", signature: "sig")

    func testCaptureIsBoundedAndIdentityBound() {
        XCTAssertThrowsError(try Learning.validate(scope(hours: 9)))
        XCTAssertThrowsError(try Learning.validate(CaptureScope(id: "c", signingID: nil, executable: "tool", teamID: nil, appName: "Tool", workflow: "w", networkContext: "n", start: t0, end: t0.addingTimeInterval(60))), "a name is not identity")
        XCTAssertThrowsError(try Learning.validate(CaptureScope(id: "c", executable: exe, teamID: nil, appName: "Tool", workflow: " ", networkContext: "n", start: t0, end: t0.addingTimeInterval(60))))
        XCTAssertNoThrow(try Learning.validate(scope()))
    }

    func testMaliciousConnectionAndRepetitionConferNoTrust() throws {
        var records = (1 ... 200).map { rec(UInt64($0), "registry.npmjs.org") }
        records.append(rec(201, "evil.example"))
        records.append(rec(202, "other.example", team: "OTHER"))
        let c = Learning.candidate(id: "cand", scope: scope(), records: records, gaps: [], now: t0.addingTimeInterval(3600))
        XCTAssertEqual(c.entries.map(\.destination), ["evil.example", "registry.npmjs.org"], "only the exact identity")
        XCTAssertEqual(c.entries.first { $0.destination == "registry.npmjs.org" }?.occurrences, 200, "repetition is a count")
        XCTAssertEqual(Learning.acceptProblems(c, accepting: [], acknowledgeIncomplete: false).count, 1, "nothing is accepted by default")
        XCTAssertThrowsError(try Learning.accept(c, accepting: [1], acknowledgeIncomplete: false, previous: nil, authorization: nil, id: "b", now: t0), "no owner key, no baseline")
        let b = try Learning.accept(c, accepting: [1], acknowledgeIncomplete: false, previous: nil, authorization: auth, id: "b", now: t0)
        XCTAssertEqual(b.entries.map(\.destination), ["registry.npmjs.org"], "the malicious connection is not in the baseline")
        XCTAssertEqual(b.authorizedBy, auth.keyID)
        XCTAssertTrue(c.identityChanges.contains { $0.contains("team OTHER") }, "the same signing identifier under another team stays visible")
    }

    func testMissingEventsAndUnknownIdentityPreventACompleteClaim() {
        let records = [rec(10, "a.example"), rec(11, "b.example", exe: nil, team: nil)]
        let c = Learning.candidate(id: "cand", scope: scope(), records: records, gaps: [GapMarker(fromSeq: 5, toSeq: 9, reason: "spool full")], now: t0.addingTimeInterval(3600))
        XCTAssertFalse(c.complete)
        XCTAssertTrue(c.incompleteReasons.contains { $0.contains("no app identity") })
        XCTAssertTrue(c.incompleteReasons.contains { $0.contains("lost") })
        XCTAssertFalse(Learning.acceptProblems(c, accepting: [0], acknowledgeIncomplete: false).isEmpty, "incomplete needs an acknowledgement")
        XCTAssertTrue(Learning.acceptProblems(c, accepting: [0], acknowledgeIncomplete: true).isEmpty)
    }

    func testBaselinesAreImmutableAndDriftIsANewCandidate() throws {
        let c = Learning.candidate(id: "cand", scope: scope(), records: [rec(1, "s3.amazonaws.com")], gaps: [], now: t0.addingTimeInterval(3600))
        let b = try Learning.accept(c, accepting: [0], acknowledgeIncomplete: false, previous: nil, authorization: auth, id: "b1", now: t0.addingTimeInterval(3600))
        var book = LearningBook()
        try book.record(b)
        XCTAssertThrowsError(try book.record(b), "a recorded baseline is never replaced")
        let later = [rec(2, "exfil-bucket.s3.amazonaws.com", at: 120), rec(3, "s3.amazonaws.com", at: 121)]
        let d = try XCTUnwrap(Learning.drift(b, records: later, gaps: [], now: t0.addingTimeInterval(7300), id: "drift-b1"))
        XCTAssertEqual(d.kind, .drift)
        XCTAssertEqual(d.entries.map(\.destination), ["exfil-bucket.s3.amazonaws.com"], "a new host under a reviewed provider is listed on its own")
        XCTAssertEqual(Learning.diff(d, against: b).map(\.change), [.adds])
        XCTAssertEqual(book.baselines.first?.entries.map(\.destination), ["s3.amazonaws.com"], "the baseline did not change")
        let b2 = try Learning.accept(d, accepting: [0], acknowledgeIncomplete: false, previous: b, authorization: auth, id: "b2", now: t0.addingTimeInterval(7400))
        XCTAssertEqual(b2.supersedes, "b1")
        XCTAssertEqual(b2.entries.map(\.destination), ["s3.amazonaws.com", "exfil-bucket.s3.amazonaws.com"])
        try book.record(b2)
        XCTAssertEqual(book.active.map(\.id), ["b2"], "superseded, not edited")
        XCTAssertNil(Learning.drift(b2, records: later, gaps: [], now: t0.addingTimeInterval(7500), id: "x"), "no new activity, no drift")
    }

    func testTheOwnerPlanNamesExactlyTheSelectedEntries() {
        let c = Learning.candidate(id: "cand", scope: scope(), records: [rec(1, "a.example"), rec(2, "b.example")], gaps: [], now: t0.addingTimeInterval(3600))
        let text = Learning.planText(c, accepting: [1])
        XCTAssertTrue(text.contains("allow b.example:443/tcp"))
        XCTAssertFalse(text.contains("a.example"))
        XCTAssertNotEqual(Learning.ownerPlan(c, accepting: [0]).digest, Learning.ownerPlan(c, accepting: [1]).digest)
    }

    func testBundledPacksAndUnsupportedCellsOnThisMac() throws {
        let packs = WorkflowPack.bundled()
        XCTAssertEqual(packs.map(\.id), ["coding", "home-services", "local-inference"])
        let coding = try XCTUnwrap(packs.first { $0.id == "coding" })
        XCTAssertEqual(coding.modules.first?.hosts, ["github.com", "api.github.com", "codeload.github.com"])
        let cell = PackCell.evaluate(coding.modules[0], capabilities: CapabilityRow.macOSDesign)
        XCTAssertFalse(cell.takesEffect, "no protected sessions on macOS")
        XCTAssertEqual(cell.support, .unsupported)
        XCTAssertTrue(cell.missing.contains { $0.capability == "session_hostname_proxy" && $0.support == "not reported" })
        let ok = PackCell.evaluate(coding.modules[0], capabilities: [CapabilityRow(key: "session_enforcement", label: "", support: .supported), CapabilityRow(key: "session_hostname_proxy", label: "", support: .supported)])
        XCTAssertTrue(ok.takesEffect)
    }
}
