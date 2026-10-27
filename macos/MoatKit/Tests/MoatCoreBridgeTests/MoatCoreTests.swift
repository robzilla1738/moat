import XCTest
@testable import MoatCoreBridge
import MoatKit

final class MoatCoreTests: XCTestCase {
    static let here = URL(fileURLWithPath: #filePath).deletingLastPathComponent()
    static let fixtures = here.appendingPathComponent("Fixtures")
    static let repoRoot = here.deletingLastPathComponent().deletingLastPathComponent().deletingLastPathComponent().deletingLastPathComponent()

    func fixture(_ name: String) throws -> Data { try Data(contentsOf: Self.fixtures.appendingPathComponent(name)) }
    func pubKey() throws -> String { String(decoding: try fixture("fixture-key.pub"), as: UTF8.self).trimmingCharacters(in: .whitespacesAndNewlines) }

    func testInfoReportsABIAndUntestedCapabilities() throws {
        let info = try MoatCore.info()
        XCTAssertEqual(info["abi_version"] as? Int, 1)
        let caps = (info["capabilities"] as? [String: Any])?["capabilities"] as? [String: Any]
        XCTAssertEqual((caps?["app_enforcement"] as? [String: Any])?["support"] as? String, "untested")
        XCTAssertEqual((caps?["session_enforcement"] as? [String: Any])?["support"] as? String, "unsupported")
    }

    func testVerifiesSignedMacSnapshotWithOmittedSessionRules() throws {
        let v = CoreVerifier(trust: TrustConfig(keys: [try pubKey()]))
        let r = v.verify(signed: try fixture("signed-r7.json"), lastApplied: nil, now: Date())
        let snap = try r.get()
        XCTAssertEqual(snap.summary.revision, 7)
        XCTAssertEqual(snap.summary.policyName, "courson-home")
        XCTAssertFalse(snap.summary.omitted.isEmpty, "session rules must be omitted with a reason on macOS")
        XCTAssertTrue(snap.summary.omitted.allSatisfy { !$0.reason.isEmpty })
    }

    func testRejectsUnknownKeyReplayAndWrongPlatform() throws {
        let signed = try fixture("signed-r7.json")
        let unknown = CoreVerifier(trust: TrustConfig(keys: [String(repeating: "00", count: 32)])).verify(signed: signed, lastApplied: nil, now: Date())
        guard case let .failure(f1) = unknown else { return XCTFail("unknown key accepted") }
        XCTAssertTrue(["unknown_key", "invalid", "ffi"].contains(f1.kind), f1.kind)

        let good = CoreVerifier(trust: TrustConfig(keys: [try pubKey()]))
        guard case let .failure(f2) = good.verify(signed: signed, lastApplied: 7, now: Date()) else { return XCTFail("replay accepted") }
        XCTAssertEqual(f2.kind, "replay")

        guard case let .failure(f3) = good.verify(signed: try fixture("signed-linux-r8.json"), lastApplied: nil, now: Date()) else {
            return XCTFail("linux snapshot accepted on macOS")
        }
        XCTAssertEqual(f3.kind, "wrong_platform")

        guard case let .failure(f4) = good.verify(signed: Data("nonsense".utf8), lastApplied: nil, now: Date()) else { return XCTFail() }
        XCTAssertEqual(f4.kind, "malformed")
    }

    func testRevokedKeyRejected() throws {
        let v = CoreVerifier(trust: TrustConfig(keys: [try pubKey()], revokedKeyIDs: ["8ae0a554c646084c"]))
        guard case let .failure(f) = v.verify(signed: try fixture("signed-r7.json"), lastApplied: nil, now: Date()) else { return XCTFail() }
        XCTAssertEqual(f.kind, "revoked_key")
    }

    func testEvaluatorExplainsDecisions() throws {
        let toml = try String(contentsOf: Self.repoRoot.appendingPathComponent("conformance/policies/home.toml"), encoding: .utf8)
        let policy = try MoatCore.parsePolicy(toml: toml)
        let ev = try CoreEvaluator(policyJSON: policy)
        let d = try ev.evaluate(FlowFacts(signingID: "com.example.tool", remoteHost: "example.org", hostSource: .flowApi, remoteIP: "203.0.113.9", remotePort: 443, transport: .tcp), deviceID: "mbp-m1")
        XCTAssertFalse(d.summary.isEmpty)
        // The home policy's fallback profile observes ordinary apps: allowed only by observation.
        XCTAssertEqual(d.verdict, .allow)
        XCTAssertTrue(d.permittedByObservation)
    }

    func testBadPolicyIsAnError() {
        XCTAssertThrowsError(try MoatCore.parsePolicy(toml: "schema = = broken"))
    }

    func testEndToEndThroughControlHandler() throws {
        let h = ControlHandler(
            engine: FilterEngine(deviceID: "mbp-m1"),
            store: PolicyStore(directory: nil, verifier: CoreVerifier(trust: TrustConfig(keys: [try pubKey()]))),
            version: "test", filterEnabled: { true }, makeEvaluator: { try CoreEvaluator(policyJSON: $0) })
        _ = try h.perform(.applySignedSnapshot(try fixture("signed-r7.json"), canarySeconds: 0)).get()
        let d = h.engine.decide(FlowFacts(signingID: "com.example.tool", remoteHost: "example.org", hostSource: .flowApi, remoteIP: "203.0.113.9", remotePort: 443, transport: .tcp))
        XCTAssertEqual(d.policyRevision, 7)
        XCTAssertNotEqual(d.source, .evaluatorError, d.notes.joined())
    }
}
