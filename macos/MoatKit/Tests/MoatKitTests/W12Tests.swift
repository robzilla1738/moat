import CryptoKit
import Security
@testable import MoatKit
import XCTest

/// In-memory stand-ins for the Keychain and LocalAuthentication. They model the boundary the OS enforces: the seed
/// is released only to a context the presence check returned.
final class FakeContext: OwnerPresenceContext {}

final class FakePresence: OwnerPresence {
    var allow = true
    var reasons: [String] = []
    var issued: [FakeContext] = []
    func authenticate(reason: String) async throws -> OwnerPresenceContext {
        reasons.append(reason)
        guard allow else { throw OwnerSigningError.presenceDenied("user cancelled") }
        let c = FakeContext()
        issued.append(c)
        return c
    }
}

final class FakeStore: ProtectedKeyStore {
    var seed: Data?
    var pub: Data?
    weak var presence: FakePresence?
    var reads = 0
    var requiresUserPresence: Bool { true }
    func publicKey() -> Data? { pub }
    func create(seed: Data, publicKey: Data) throws {
        if self.seed != nil { throw OwnerSigningError.keyExists }
        self.seed = seed
        pub = publicKey
    }
    func readSeed(context: OwnerPresenceContext) throws -> Data {
        reads += 1
        guard let p = presence, p.issued.contains(where: { $0 === context as AnyObject }) else { throw OwnerSigningError.presenceDenied("context was not authenticated") }
        guard let s = seed else { throw OwnerSigningError.noKey }
        return s
    }
    func delete() throws {
        seed = nil
        pub = nil
    }
}

final class OwnerSignerTests: XCTestCase {
    func make() -> (OwnerSigner, FakeStore, FakePresence) {
        let p = FakePresence()
        let s = FakeStore()
        s.presence = p
        return (OwnerSigner(store: s, presence: p), s, p)
    }

    let plan = OwnerPlan(subject: "local-rule:r1", digest: PlanDigest.of("rule"), display: "Block curl → example.org:443 until 2026-10-27T18:00:00Z")

    func testAuthorizationUsesTheControllerFormatAndVerifies() async throws {
        let (signer, store, presence) = make()
        let id = try signer.createKey()
        XCTAssertEqual(id, TrustConfig.keyID(hex: signer.publicKeyHex!), "key id = moat-core key_id")
        let a = try await signer.authorize(plan)
        XCTAssertEqual(a.keyID, id)
        XCTAssertTrue(OwnerSigner.verify(a, plan: plan, publicKey: store.pub!))
        XCTAssertEqual(String(data: OwnerAuthorization.message(subject: "s", digest: "d"), encoding: .utf8), "moat.owner_authorization.v1\ns\nd")
        XCTAssertEqual(presence.reasons.count, 1)
        XCTAssertTrue(presence.reasons[0].contains(plan.display), "the OS prompt shows the exact plan")
        let other = OwnerPlan(subject: plan.subject, digest: PlanDigest.of("another rule"), display: plan.display)
        XCTAssertFalse(OwnerSigner.verify(a, plan: other, publicKey: store.pub!), "a signature authorizes one exact digest")
    }

    func testDeniedPresenceSignsNothingAndNeverReadsTheSeed() async throws {
        let (signer, store, presence) = make()
        try signer.createKey()
        presence.allow = false
        do {
            _ = try await signer.authorize(plan)
            XCTFail("signed without owner presence")
        } catch let e as OwnerSigningError {
            guard case .presenceDenied = e else { return XCTFail("\(e)") }
        }
        XCTAssertEqual(store.reads, 0, "the seed is not touched when authentication fails")
    }

    func testEveryAuthorizationAsksAgain() async throws {
        let (signer, _, presence) = make()
        try signer.createKey()
        _ = try await signer.authorize(plan)
        _ = try await signer.authorize(plan)
        XCTAssertEqual(presence.reasons.count, 2, "no reuse window: each signature needs presence")
    }

    func testNoKeyAndNoSilentReplacement() async throws {
        let (signer, _, _) = make()
        do {
            _ = try await signer.authorize(plan)
            XCTFail("signed without a key")
        } catch let e as OwnerSigningError { XCTAssertEqual(e, .noKey) }
        try signer.createKey()
        XCTAssertThrowsError(try signer.createKey()) { XCTAssertEqual($0 as? OwnerSigningError, .keyExists) }
    }

    func testSignedEnvelopeVerifiesOverExactBytes() async throws {
        let (signer, store, _) = make()
        try signer.createKey()
        let payload = Data(#"{"schema":"moat.snapshot.v1","revision":7}"#.utf8)
        let env = try await signer.signPayload(payload, plan: plan)
        XCTAssertEqual(env.schema, "moat.signed_snapshot.v1")
        let pk = try Curve25519.Signing.PublicKey(rawRepresentation: store.pub!)
        XCTAssertTrue(pk.isValidSignature(Data(base64Encoded: env.signature)!, for: Data(base64Encoded: env.payload)!))
        XCTAssertEqual(Data(base64Encoded: env.payload), payload)
    }

    func testTheRealKeychainStoreRequiresUserPresence() {
        XCTAssertTrue(KeychainOwnerKeyStore.accessFlags.contains(.userPresence))
        XCTAssertTrue(KeychainOwnerKeyStore().requiresUserPresence)
        XCTAssertEqual(KeychainOwnerKeyStore.accessibility as String, kSecAttrAccessibleWhenUnlockedThisDeviceOnly as String)
    }
}

final class StandaloneTests: XCTestCase {
    let now = Date(timeIntervalSince1970: 1_793_000_000)

    func rec(_ seq: UInt64, sid: String?, team: String? = nil, exe: String? = nil, host: String, port: UInt16 = 443, deny: Bool = false, observe: Bool = false, rev: UInt64? = 1, ago: TimeInterval) -> FlowRecord {
        FlowRecord(
            seq: seq,
            facts: FlowFacts(signingID: sid, teamID: team, executable: exe, remoteHost: host, remoteIP: "203.0.113.\(seq % 250)", remotePort: port, transport: .tcp, at: now.addingTimeInterval(-ago)),
            decision: FlowDecision(verdict: deny ? .deny : .allow, source: observe ? .observationProfile : .policy, summary: deny ? "blocked by explicit rule r-deny" : "allowed", ruleID: deny ? "r-deny" : nil, policyRevision: rev),
            measurement: .unknown)
    }

    func testAppsAreIdentitiesAndUnknownStaysSeparate() {
        let apps = AppSummary.from([
            rec(1, sid: "com.example.app", team: "TEAM1", host: "a.example", ago: 100),
            rec(2, sid: "com.example.app", team: "TEAM2", host: "a.example", ago: 90),
            rec(3, sid: nil, exe: "/usr/bin/curl", host: "b.example", deny: true, ago: 80),
            rec(4, sid: nil, host: "c.example", ago: 10),
        ])
        XCTAssertEqual(apps.count, 4, "same signing id with another team is another app")
        XCTAssertEqual(apps.last?.id, AppSummary.unknownID)
        XCTAssertFalse(apps.last!.identityKnown)
        XCTAssertEqual(apps.first { $0.executable == "/usr/bin/curl" }?.blocked, 1)
    }

    func testExplanationsAreTheRecordedDecisions() {
        let rs = [rec(1, sid: nil, exe: "/usr/bin/curl", host: "b.example", deny: true, rev: 4, ago: 80), rec(2, sid: nil, exe: "/usr/bin/curl", host: "b.example", observe: true, ago: 200)]
        let app = AppSummary.from(rs)[0]
        let w = AppExplanation.latest(for: app, in: rs)
        XCTAssertEqual(w.count, 1, "latest decision per destination")
        XCTAssertEqual(w[0].verdict, "deny")
        XCTAssertEqual(w[0].ruleID, "r-deny")
        XCTAssertEqual(w[0].revision, 4)
    }

    func testWhatChangedSeparatesObservedFromCandidatesAndReportsGaps() {
        let rs = [
            rec(1, sid: "com.example.app", team: "T1", host: "api.example", rev: 1, ago: 7200),
            rec(5, sid: "com.example.app", team: "T9", host: "api.example", deny: true, rev: 2, ago: 300),
        ]
        let c = ChangeComparison.compare(rs, working: DateInterval(start: now.addingTimeInterval(-9000), end: now.addingTimeInterval(-3600)), failing: DateInterval(start: now.addingTimeInterval(-1800), end: now), gaps: [GapMarker(fromSeq: 2, toSeq: 4, reason: "spool full")])
        let kinds = Set(c.observed.map(\.kind))
        XCTAssertEqual(kinds, ["identity", "policy", "destination", "telemetry"])
        XCTAssertEqual(c.candidates.count, 3)
        XCTAssertTrue(c.candidates.allSatisfy { !$0.test.isEmpty })
        XCTAssertTrue(ChangeComparison.disclaimer.contains("none is claimed as the cause"))
        XCTAssertFalse(c.notCompared.isEmpty)
    }

    func testDiagnosticsNeverClaimCurrentWithoutContact() {
        let s = StatusReport(extensionVersion: "0.1.0", coverage: .enforced, coverageNotes: [], filterEnabled: true, isolation: .off, installed: nil, lastKnownGood: nil, lastRejection: nil, flowsSeen: 1, flowsDenied: 0, telemetryGaps: [GapMarker(fromSeq: 3, toSeq: 9, reason: "x")], capabilities: CapabilityRow.macOSDesign, durable: false)
        let d = DiagnosticsReport.from(status: s, lastContact: now.addingTimeInterval(-120), contactLostSince: now.addingTimeInterval(-60), now: now)
        XCTAssertEqual(d.items.first?.label, "Contact")
        XCTAssertTrue(d.items.first!.warn)
        XCTAssertTrue(d.items.contains { $0.label == "Saved to disk" && $0.warn })
        XCTAssertTrue(d.items.contains { $0.label == "Telemetry gaps" && $0.warn })
        XCTAssertFalse(d.downgraded.isEmpty, "untested/unsupported capabilities are listed")
        XCTAssertEqual(DiagnosticsReport.from(status: nil, lastContact: nil, contactLostSince: nil).items.first?.value, "has not reported")
    }

    func testFirstTenMinutesOnlyOnEvidence() {
        let s = StatusReport(extensionVersion: "0.1.0", coverage: .enforced, coverageNotes: [], filterEnabled: true, isolation: .off, installed: nil, lastKnownGood: nil, lastRejection: nil, flowsSeen: 1, flowsDenied: 0, telemetryGaps: [], capabilities: [])
        let flows = [rec(1, sid: nil, exe: "/usr/bin/curl", host: "b.example", deny: true, ago: 5)]
        var p = FirstTenMinutes.evaluate(status: s, flows: flows, stale: false, choseMode: true, deniedHost: "a.example", undone: true, sawRecovery: false)
        XCTAssertFalse(p.done.contains(.temporaryDeny), "a deny for another destination is not evidence")
        XCTAssertFalse(p.done.contains(.verifyUndo))
        XCTAssertFalse(p.offerFleet, "fleet is offered only after local usefulness")
        p = FirstTenMinutes.evaluate(status: s, flows: flows, stale: false, choseMode: true, deniedHost: "b.example", undone: true, sawRecovery: true)
        XCTAssertTrue(p.done.isSuperset(of: [.approve, .health, .choose, .seeConnection, .temporaryDeny, .verifyUndo, .recoveryCard]))
        XCTAssertTrue(p.offerFleet)
        let stale = FirstTenMinutes.evaluate(status: s, flows: [], stale: true, choseMode: false, deniedHost: nil, undone: false, sawRecovery: false)
        XCTAssertFalse(stale.done.contains(.health), "a stale report is not health")
        XCTAssertEqual(stale.next, .health)
    }

    func testLocalRulePlanIsNarrowAndRefusesWidening() {
        let app = AppSummary.from([rec(1, sid: "com.example.app", team: "T1", host: "api.example", ago: 10)])[0]
        let plan = LocalRulePlan(action: .deny, app: app, host: "api.example", port: 443, expires: now.addingTimeInterval(900))
        XCTAssertEqual(plan.problems(now: now), [])
        let toml = plan.ruleTOML(id: "local-1")
        XCTAssertTrue(toml.contains("signing_id = \"com.example.app\", team_id = \"T1\""))
        XCTAssertTrue(toml.contains("expires_at"))
        XCTAssertEqual(plan.ownerPlan(id: "local-1").digest, PlanDigest.of(toml))
        XCTAssertFalse(LocalRulePlan(action: .allow, app: app, host: "*.example", port: 443, expires: now.addingTimeInterval(60)).problems(now: now).isEmpty)
        XCTAssertFalse(LocalRulePlan(action: .allow, app: app, host: "api.example", port: 443, expires: now.addingTimeInterval(9 * 3600)).problems(now: now).isEmpty)
        let unknown = AppSummary.from([rec(1, sid: nil, host: "x", ago: 1)])[0]
        XCTAssertFalse(LocalRulePlan(action: .deny, app: unknown, host: "x", port: 443, expires: now.addingTimeInterval(60)).problems(now: now).isEmpty)
    }
}
