import CryptoKit
@testable import MoatKit
import XCTest

/// Compiler/assembler stand-in: "compiles" the policy text into payload bytes, and assembles only a signature that
/// verifies over exactly those bytes (the moat-core contract). The real FFI path is in MoatCoreBridgeTests.
final class FakeAuthoring: SnapshotAuthoring, @unchecked Sendable {
    var compiledTexts: [String] = []
    var omit: OmittedRule?
    var assembled = 0
    func compile(policyText: String, revision: UInt64, issuedAt: Date, deviceID: String?) throws -> CompiledSnapshot {
        compiledTexts.append(policyText)
        let payload = Data("{\"revision\":\(revision),\"devices\":[\"\(deviceID ?? "")\"],\"text\":\(policyText.count)}".utf8)
        let sha = SHA256.hash(data: payload).map { String(format: "%02x", $0) }.joined()
        return CompiledSnapshot(payload: payload, payloadSHA256: sha, revision: revision, policyDigest: "digest-r\(revision)", omitted: omit.map { [$0] } ?? [])
    }
    func assemble(payload: Data, signature: Data, publicKeyHex: String) throws -> Data {
        var raw = [UInt8]()
        var i = publicKeyHex.startIndex
        while i < publicKeyHex.endIndex { let j = publicKeyHex.index(i, offsetBy: 2); raw.append(UInt8(publicKeyHex[i ..< j], radix: 16)!); i = j }
        let pk = try Curve25519.Signing.PublicKey(rawRepresentation: Data(raw))
        guard pk.isValidSignature(signature, for: payload) else { throw StandaloneApplyError("signature does not verify over the payload bytes") }
        assembled += 1
        return try JSONSerialization.data(withJSONObject: ["schema": "moat.signed_snapshot.v1", "payload": payload.base64EncodedString(), "signature": signature.base64EncodedString()])
    }
}

/// The extension side of the typed control surface: reports status and accepts or rejects a signed snapshot.
final class FakeExtension: ControlClient, @unchecked Sendable {
    var installed: PolicySummary?
    var lastKnownGood: PolicySummary?
    var reject: String?
    var applied: [Data] = []
    func status() async throws -> StatusReport {
        StatusReport(extensionVersion: "0.1.0", coverage: .monitoring, coverageNotes: [], filterEnabled: true, isolation: .off, installed: installed, lastKnownGood: lastKnownGood, lastRejection: nil, flowsSeen: 0, flowsDenied: 0, telemetryGaps: [], capabilities: [])
    }
    func recentFlows(limit: Int) async throws -> [FlowRecord] { [] }
    func applySignedSnapshot(_ data: Data, canarySeconds: Int) async throws -> PolicySummary {
        if let reject { throw ControlError(reject) }
        applied.append(data)
        let env = try JSONSerialization.jsonObject(with: data) as! [String: Any]
        let payload = try JSONSerialization.jsonObject(with: Data(base64Encoded: env["payload"] as! String)!) as! [String: Any]
        let rev = (payload["revision"] as! NSNumber).uint64Value
        let s = PolicySummary(revision: rev, policyName: "this-mac", digest: "digest-r\(rev)", appliedAt: Date(), ruleCount: 1, omitted: [])
        installed = s
        return s
    }
    func confirmCanary() async throws {}
    func rollbackToLastKnownGood() async throws -> PolicySummary { throw ControlError("no") }
    func enterIsolation(reason: String) async throws -> IsolationState { .off }
    func exitIsolation(confirmation: String) async throws -> IsolationState { .off }
    func reloadTrust() async throws -> Bool { false }
}

final class StandaloneApplyTests: XCTestCase {
    let now = Date(timeIntervalSince1970: 1_793_000_000)
    var dir: URL!

    override func setUp() {
        dir = FileManager.default.temporaryDirectory.appendingPathComponent("moat-standalone-\(UUID().uuidString)")
    }

    func app() -> AppSummary {
        let r = FlowRecord(seq: 1, facts: FlowFacts(signingID: "com.example.app", teamID: "T1ABCDE234", remoteHost: "api.example.com", remoteIP: "203.0.113.9", remotePort: 443, transport: .tcp, at: now), decision: FlowDecision(verdict: .allow, source: .observationProfile, summary: "observed"), measurement: .unknown)
        return AppSummary.from([r])[0]
    }

    func make(_ ext: FakeExtension = FakeExtension(), authoring: FakeAuthoring = FakeAuthoring()) -> (StandaloneApplier, FakeAuthoring, FakeExtension, FakePresence, FakeStore) {
        let p = FakePresence()
        let s = FakeStore()
        s.presence = p
        let signer = OwnerSigner(store: s, presence: p)
        return (StandaloneApplier(authoring: authoring, signer: signer, client: ext, bookURL: dir.appendingPathComponent("book.json"), deviceID: "mbp-m1"), authoring, ext, p, s)
    }

    func plan(_ minutes: Double = 15) -> LocalRulePlan {
        LocalRulePlan(action: .deny, app: app(), host: "api.example.com", port: 443, expires: now.addingTimeInterval(minutes * 60))
    }

    func testCompileSignExactBytesAssembleAndInstallWithoutAController() async throws {
        let (applier, authoring, ext, presence, store) = make()
        let r = try await applier.apply(plan(), id: "local-1", now: now)
        XCTAssertEqual(r.summary.revision, 1)
        XCTAssertEqual(ext.applied.count, 1, "installed through the typed apply operation")
        XCTAssertEqual(authoring.assembled, 1)
        // the signature in the envelope verifies over the exact compiled payload
        let env = try JSONSerialization.jsonObject(with: ext.applied[0]) as! [String: Any]
        let payload = Data(base64Encoded: env["payload"] as! String)!
        let pk = try Curve25519.Signing.PublicKey(rawRepresentation: store.pub!)
        XCTAssertTrue(pk.isValidSignature(Data(base64Encoded: env["signature"] as! String)!, for: payload))
        XCTAssertEqual(presence.reasons.count, 1)
        XCTAssertTrue(presence.reasons[0].contains("revision 1"), "the OS prompt names the revision")
        XCTAssertTrue(presence.reasons[0].contains("Block"), "and the plan")
        let text = authoring.compiledTexts[0]
        XCTAssertTrue(text.hasPrefix(StandalonePolicyBook.observeBase))
        XCTAssertTrue(text.contains("selector = { devices = [\"mbp-m1\"], apps = [{ signing_id = \"com.example.app\""), "scoped to this Mac")
        let book = StandalonePolicyBook.load(dir.appendingPathComponent("book.json"))
        XCTAssertEqual(book.lastRevision, 1)
        XCTAssertEqual(book.lastAppliedDigest, "digest-r1")
        XCTAssertEqual(book.rules.map(\.id), ["local-1"])
        // a second rule builds on the first: revision 2, both rules present
        let r2 = try await applier.apply(plan(30), id: "local-2", now: now.addingTimeInterval(60))
        XCTAssertEqual(r2.summary.revision, 2)
        XCTAssertTrue(authoring.compiledTexts[1].contains("local-1") && authoring.compiledTexts[1].contains("local-2"))
    }

    func testAPolicyFromAnotherSignerIsNeverReplacedByTheStandaloneBase() async throws {
        let ext = FakeExtension()
        ext.installed = PolicySummary(revision: 14, policyName: "courson-home", digest: "controller-digest", appliedAt: now, ruleCount: 12, omitted: [])
        let (applier, authoring, _, presence, _) = make(ext)
        do {
            _ = try await applier.apply(plan(), id: "local-1", now: now)
            XCTFail("replaced a controller policy")
        } catch let e as StandaloneApplyError {
            XCTAssertTrue(e.message.contains("revision 14 from another signer"))
        }
        XCTAssertTrue(authoring.compiledTexts.isEmpty)
        XCTAssertTrue(presence.reasons.isEmpty, "nothing was offered for signature")
        XCTAssertTrue(ext.applied.isEmpty)
    }

    func testARuleTheCompilerLeavesOutIsRefusedNotReportedAsEnforced() async throws {
        let a = FakeAuthoring()
        a.omit = OmittedRule(ruleID: "local-1", reason: "needs session_enforcement")
        let (applier, _, ext, presence, _) = make(authoring: a)
        do {
            _ = try await applier.apply(plan(), id: "local-1", now: now)
            XCTFail("signed a snapshot without the rule")
        } catch let e as StandaloneApplyError {
            XCTAssertTrue(e.message.contains("left this rule out"))
        }
        XCTAssertTrue(presence.reasons.isEmpty)
        XCTAssertTrue(ext.applied.isEmpty)
        XCTAssertNil(StandalonePolicyBook.load(dir.appendingPathComponent("book.json")).lastRevision)
    }

    func testCancelledPresenceAppliesNothing() async throws {
        let (applier, _, ext, presence, _) = make()
        presence.allow = false
        do {
            _ = try await applier.apply(plan(), id: "local-1", now: now)
            XCTFail("applied without owner presence")
        } catch {}
        XCTAssertTrue(ext.applied.isEmpty)
        XCTAssertNil(StandalonePolicyBook.load(dir.appendingPathComponent("book.json")).lastRevision)
    }

    func testAnUntrustedOwnerKeyIsExplainedAndNothingIsRecorded() async throws {
        let ext = FakeExtension()
        ext.reject = "Rejected; the current policy is unchanged. signed by unknown key 0123456789abcdef"
        let (applier, _, _, _, store) = make(ext)
        do {
            _ = try await applier.apply(plan(), id: "local-1", now: now)
            XCTFail("reported success after a rejection")
        } catch let e as StandaloneApplyError {
            XCTAssertTrue(e.message.contains("does not trust this owner key"))
            XCTAssertTrue(e.message.contains(store.pub!.map { String(format: "%02x", $0) }.joined()), "shows the public key to add")
        }
        XCTAssertNil(StandalonePolicyBook.load(dir.appendingPathComponent("book.json")).lastRevision)
    }

    func testRevisionClimbsAboveWhatTheExtensionHoldsAndExpiredRulesAreDropped() async throws {
        let ext = FakeExtension()
        ext.lastKnownGood = PolicySummary(revision: 6, policyName: "this-mac", digest: "x", appliedAt: now, ruleCount: 0, omitted: [])
        let (applier, authoring, _, _, _) = make(ext)
        _ = try await applier.apply(plan(1), id: "short", now: now)
        XCTAssertEqual(ext.installed?.revision, 7, "never at or below a revision the extension already holds (replay)")
        _ = try await applier.apply(plan(30), id: "later", now: now.addingTimeInterval(5 * 60))
        XCTAssertFalse(authoring.compiledTexts[1].contains("\"short\""), "an expired local rule is not carried forward")
        XCTAssertEqual(StandalonePolicyBook.load(dir.appendingPathComponent("book.json")).rules.map(\.id), ["later"])
    }

    func testWideningPlansAreRefusedBeforeAnything() async throws {
        let (applier, authoring, _, presence, _) = make()
        let wide = LocalRulePlan(action: .allow, app: app(), host: "*.example.com", port: 443, expires: now.addingTimeInterval(60))
        do {
            _ = try await applier.apply(wide, id: "w", now: now)
            XCTFail("applied a wildcard")
        } catch {}
        XCTAssertTrue(authoring.compiledTexts.isEmpty)
        XCTAssertTrue(presence.reasons.isEmpty)
    }
}
