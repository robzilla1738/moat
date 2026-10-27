import CryptoKit
import XCTest
@testable import MoatCoreBridge
import MoatKit

/// The standalone path against the real moat-core FFI: compile → owner signature over the exact bytes → assemble →
/// the extension's verifier (trusted keys + device id) → the evaluator enforces the local rule.
final class StandaloneCoreTests: XCTestCase {
    let rule = """
    [[rules]]
    id = "local-1"
    description = "Local deny authored on this Mac"
    action = "deny"
    selector = { devices = ["mbp-m1"], apps = [{ signing_id = "com.example.app", team_id = "T1ABCDE234" }] }
    destinations = { hosts = ["api.example.com"] }
    transport = "tcp"
    ports = [443]
    expires_at = "\(ISO8601DateFormatter().string(from: Date().addingTimeInterval(3600)))"
    provenance = { kind = "owner_action", reference = "local-rule:local-1", author = "owner on this mac", audit_ref = "local-1" }
    """

    func hex(_ d: Data) -> String { d.map { String(format: "%02x", $0) }.joined() }

    func testFeatureDetection() {
        XCTAssertTrue(CoreSnapshotAuthoring.available, "moat-ffi exports moat_compile and moat_assemble_signed_snapshot")
    }

    func testCompileSignAssembleVerifyAndEnforce() throws {
        let a = CoreSnapshotAuthoring()
        let text = StandalonePolicyBook.observeBase + "\n\n" + rule + "\n"
        let c = try a.compile(policyText: text, revision: 3, issuedAt: Date(), deviceID: "mbp-m1")
        XCTAssertEqual(c.revision, 3)
        XCTAssertTrue(c.omitted.isEmpty)
        XCTAssertEqual(hex(Data(SHA256.hash(data: c.payload))), c.payloadSHA256)
        let key = Curve25519.Signing.PrivateKey()
        let pub = hex(key.publicKey.rawRepresentation)
        let signed = try a.assemble(payload: c.payload, signature: try key.signature(for: c.payload), publicKeyHex: pub)
        // the extension's verifier: trusted owner key and this Mac's device id
        let v = CoreVerifier(trust: TrustConfig(keys: [pub]), deviceID: "mbp-m1")
        let snap = try v.verify(signed: signed, lastApplied: 2, now: Date()).get()
        XCTAssertEqual(snap.summary.revision, 3)
        XCTAssertEqual(snap.summary.policyName, "this-mac")
        // and the evaluator enforces the local rule
        let ev = try CoreEvaluator(policyJSON: snap.policyJSON)
        let d = try ev.evaluate(FlowFacts(signingID: "com.example.app", teamID: "T1ABCDE234", remoteHost: "api.example.com", hostSource: .flowApi, remoteIP: "203.0.113.9", remotePort: 443, transport: .tcp), deviceID: "mbp-m1")
        XCTAssertEqual(d.verdict, .deny)
        XCTAssertEqual(d.ruleID, "local-1")
        // another app is observed, not blocked
        let other = try ev.evaluate(FlowFacts(signingID: "com.other.app", remoteHost: "api.example.com", hostSource: .flowApi, remoteIP: "203.0.113.9", remotePort: 443, transport: .tcp), deviceID: "mbp-m1")
        XCTAssertEqual(other.verdict, .allow)
    }

    func testRefusals() throws {
        let a = CoreSnapshotAuthoring()
        let c = try a.compile(policyText: StandalonePolicyBook.observeBase + "\n\n" + rule + "\n", revision: 3, issuedAt: Date(), deviceID: "mbp-m1")
        let key = Curve25519.Signing.PrivateKey()
        let pub = hex(key.publicKey.rawRepresentation)
        // a signature over other bytes is refused at assembly
        XCTAssertThrowsError(try a.assemble(payload: c.payload, signature: try key.signature(for: Data("other".utf8)), publicKeyHex: pub))
        let signed = try a.assemble(payload: c.payload, signature: try key.signature(for: c.payload), publicKeyHex: pub)
        // assembly does not make the key trusted
        XCTAssertThrowsError(try CoreVerifier(trust: TrustConfig(keys: []), deviceID: "mbp-m1").verify(signed: signed, lastApplied: nil, now: Date()).get())
        // a snapshot targeted at this Mac does not install on another device, nor without a device id
        XCTAssertThrowsError(try CoreVerifier(trust: TrustConfig(keys: [pub]), deviceID: "mbp-air").verify(signed: signed, lastApplied: nil, now: Date()).get())
        XCTAssertThrowsError(try CoreVerifier(trust: TrustConfig(keys: [pub])).verify(signed: signed, lastApplied: nil, now: Date()).get())
        // replay: not above the last applied revision
        XCTAssertThrowsError(try CoreVerifier(trust: TrustConfig(keys: [pub]), deviceID: "mbp-m1").verify(signed: signed, lastApplied: 3, now: Date()).get())
        // an invalid policy is refused by the compiler, not weakened
        XCTAssertThrowsError(try a.compile(policyText: "schema = \"moat.policy.v1\"\nname = 3\n", revision: 4, issuedAt: Date(), deviceID: nil))
    }
}
