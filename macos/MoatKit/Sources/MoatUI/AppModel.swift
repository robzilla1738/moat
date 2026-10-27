import Foundation
import MoatKit
import SwiftUI

public enum Screen: String, CaseIterable, Identifiable {
    case overview, activity, policy, coverage, recovery
    public var id: String { rawValue }

    var title: String {
        switch self {
        case .overview: return "Overview"
        case .activity: return "Activity"
        case .policy: return "Policy"
        case .coverage: return "Coverage"
        case .recovery: return "Recovery"
        }
    }

    var symbol: String {
        switch self {
        case .overview: return "house"
        case .activity: return "waveform.path.ecg"
        case .policy: return "doc.text.magnifyingglass"
        case .coverage: return "shield.lefthalf.filled"
        case .recovery: return "lifepreserver"
        }
    }
}

/// The app's view model. All state comes from the extension's typed control surface; the UI never invents status.
@MainActor
public final class AppModel: ObservableObject {
    @Published public var status: StatusReport?
    @Published public var flows: [FlowRecord] = []
    @Published public var lastError: String?
    @Published public var notice: String?
    @Published public var busy = false
    @Published public var screen: Screen = .overview
    public let client: ControlClient
    public let isDemo: Bool

    public init(client: ControlClient, isDemo: Bool = false, screen: Screen = .overview) {
        self.client = client
        self.isDemo = isDemo
        self.screen = screen
    }

    /// True when `lastError` came from failing to reach the extension (cleared by the next good refresh).
    /// Errors from an owner action stay visible until dismissed.
    private var errorIsConnection = false

    /// When the extension last answered, and since when it has not (nil while connected).
    @Published public private(set) var lastContact: Date?
    @Published public private(set) var contactLostSince: Date?
    /// The last report the extension actually sent. `status` is this report while contact is current, and an
    /// explicitly stale copy (coverage unknown) once contact is lost: an old green badge is never shown as current.
    public private(set) var lastGoodStatus: StatusReport?

    public var isStale: Bool { contactLostSince != nil }

    public func refresh(now: Date = Date()) async {
        do {
            let s = try await client.status()
            let f = try await client.recentFlows(limit: 200)
            status = s
            lastGoodStatus = s
            flows = f
            lastContact = now
            contactLostSince = nil
            if errorIsConnection {
                lastError = nil
                errorIsConnection = false
            }
        } catch {
            lastError = "\(error)"
            errorIsConnection = true
            if contactLostSince == nil { contactLostSince = now }
            status = Self.staleCopy(of: lastGoodStatus, lastContact: lastContact, error: "\(error)")
        }
    }

    /// What to show when the extension stopped answering: the last report, with coverage unknown and why.
    static func staleCopy(of s: StatusReport?, lastContact: Date?, error: String) -> StatusReport? {
        guard var s else { return nil }
        let when = lastContact.map { ISO8601DateFormatter().string(from: $0) } ?? "unknown"
        s.coverage = .unknown
        s.coverageNotes.insert("Lost contact with the Moat filter (\(error)). Last report: \(when). Enforcement may continue in the extension, but nothing shown here is current.", at: 0)
        return s
    }

    private func run(_ label: String, _ f: () async throws -> Void) async {
        busy = true
        defer { busy = false }
        do {
            try await f()
            notice = label
            lastError = nil
        } catch {
            notice = nil
            lastError = "\(error)"
            errorIsConnection = false
        }
        await refresh()
    }

    public func apply(fileURL: URL, canarySeconds: Int) async {
        await run("Policy applied.") {
            let access = fileURL.startAccessingSecurityScopedResource()
            defer { if access { fileURL.stopAccessingSecurityScopedResource() } }
            let data = try Data(contentsOf: fileURL)
            _ = try await client.applySignedSnapshot(data, canarySeconds: canarySeconds)
        }
    }

    public func confirmCanary() async { await run("Canary confirmed; this revision is now last known good.") { try await client.confirmCanary() } }
    public func rollback() async { await run("Rolled back to the last known good revision.") { _ = try await client.rollbackToLastKnownGood() } }
    public func enterIsolation(reason: String) async { await run("Emergency isolation is on.") { _ = try await client.enterIsolation(reason: reason) } }
    public func exitIsolation(confirmation: String) async { await run("Isolation is off.") { _ = try await client.exitIsolation(confirmation: confirmation) } }
    public func reloadTrust() async {
        await run("Trusted keys re-read; the installed policy was re-verified.") { _ = try await client.reloadTrust() }
    }
}

/// A demo client backed by the *real* ControlHandler/FilterEngine/PolicyStore with a canned evaluator, so previews
/// and screenshots exercise the same code paths and labels as the extension.
public final class DemoControlClient: ControlClient, @unchecked Sendable {
    public let handler: ControlHandler

    struct DemoEvaluator: PolicyEvaluator {
        func evaluate(_ f: FlowFacts, deviceID: String) throws -> EvaluatedDecision {
            let host = f.remoteHost ?? f.remoteIP
            if host.hasSuffix("pastebin.com") || host.hasSuffix("transfer.sh") {
                return EvaluatedDecision(verdict: .deny, summary: "blocked by explicit rule deny-paste-and-drop", ruleID: "deny-paste-and-drop")
            }
            if f.signingID == "com.ollama.ollama", !host.hasSuffix("ollama.com") {
                return EvaluatedDecision(verdict: .deny, summary: "blocked by the local-inference profile default")
            }
            if f.signingID == "com.ollama.ollama" {
                return EvaluatedDecision(verdict: .allow, summary: "allowed by explicit rule model-registry-ollama", ruleID: "model-registry-ollama")
            }
            if host.hasSuffix("github.com") || host.hasSuffix("anthropic.com") {
                return EvaluatedDecision(verdict: .allow, summary: "allowed by explicit rule dev-services", ruleID: "dev-services")
            }
            return EvaluatedDecision(verdict: .allow, summary: "permitted (observation, not enforced) by the ordinary-desktop-learning profile default", permittedByObservation: true)
        }
    }

    struct DemoVerifier: SnapshotVerifier {
        func verify(signed: Data, lastApplied: UInt64?, now: Date) -> Result<VerifiedSnapshot, VerificationFailure> {
            let rev = (lastApplied ?? 41) + 1
            return .success(VerifiedSnapshot(
                summary: PolicySummary(
                    revision: rev, policyName: "courson-home", digest: "9f2c41d0a7b3e5c18d6f", appliedAt: now, ruleCount: 14,
                    omitted: [
                        OmittedRule(ruleID: "coding-session-github", reason: "session rule: macOS has no tested session boundary (session_enforcement unsupported)"),
                        OmittedRule(ruleID: "coding-session-anthropic", reason: "session rule: macOS has no tested session boundary (session_enforcement unsupported)"),
                    ]),
                policyJSON: Data("{}".utf8)))
        }
    }

    public init(now: Date = Date(), isolated: Bool = false) {
        let engine = FilterEngine(deviceID: "mbp-m1", spool: EventSpool(capacity: 500))
        let store = PolicyStore(directory: nil, verifier: DemoVerifier())
        handler = ControlHandler(engine: engine, store: store, version: "0.1.0 (demo)", filterEnabled: { true }, makeEvaluator: { _ in DemoEvaluator() })
        _ = handler.perform(.applySignedSnapshot(Data("demo".utf8), canarySeconds: 0), now: now.addingTimeInterval(-86400))
        _ = handler.perform(.applySignedSnapshot(Data("demo".utf8), canarySeconds: 0), now: now.addingTimeInterval(-3 * 3600))
        Self.seed(engine, now: now)
        if isolated {
            _ = handler.perform(.enterIsolation(reason: "Unexpected upload from a generated script"), now: now.addingTimeInterval(-240))
        }
    }

    static func seed(_ e: FilterEngine, now: Date) {
        let flows: [(String?, String?, String?, String, UInt16, Transport, TimeInterval)] = [
            ("com.anthropic.claude-code", "Q6L2SF6YDW", "api.anthropic.com", "160.79.104.10", 443, .tcp, 3600),
            ("com.github.GitHubClient", "VEKTX9H2N7", "api.github.com", "140.82.112.6", 443, .tcp, 3300),
            ("com.apple.Safari", "APPLECOMPUTER", "www.apple.com", "17.253.144.10", 443, .tcp, 2900),
            ("com.ollama.ollama", "3MU9H2V9Y9", "registry.ollama.com", "34.120.132.20", 443, .tcp, 2400),
            ("com.ollama.ollama", "3MU9H2V9Y9", "telemetry.example.net", "203.0.113.24", 443, .tcp, 1800),
            ("org.python.python", nil, "pastebin.com", "104.20.68.143", 443, .tcp, 960),
            ("com.spotify.client", "2FNC3A47ZF", "spclient.wg.spotify.com", "35.186.224.25", 443, .udp, 700),
            ("com.tinyspeck.slackmacgap", "BQR82RBBHL", "edgeapi.slack.com", "54.192.18.66", 443, .tcp, 420),
            ("com.ollama.ollama", "3MU9H2V9Y9", nil, "198.51.100.7", 11434, .tcp, 300),
            ("org.python.python", nil, "transfer.sh", "144.76.136.153", 443, .tcp, 90),
            ("com.anthropic.claude-code", "Q6L2SF6YDW", "api.anthropic.com", "160.79.104.10", 443, .tcp, 30),
        ]
        for (sid, team, host, ip, port, tr, ago) in flows {
            e.decide(FlowFacts(
                signingID: sid, teamID: team, executable: sid == "org.python.python" ? "/opt/homebrew/bin/python3" : nil,
                remoteHost: host, hostSource: host == nil ? nil : .flowApi, remoteIP: ip, remotePort: port, transport: tr,
                at: now.addingTimeInterval(-ago)), now: now.addingTimeInterval(-ago))
        }
        if let id = e.spool.recent(limit: 20).first(where: { $0.facts.remoteHost == "api.github.com" })?.facts.id {
            e.report(flowID: id, outbound: 18_432, inbound: 1_204_224)
        }
    }

    private func get<T: Decodable>(_ op: ControlOperation, _ t: T.Type) throws -> T {
        switch handler.perform(op) {
        case let .success(d): return try ControlCoding.decoder.decode(T.self, from: d)
        case let .failure(e): throw e
        }
    }

    public func status() async throws -> StatusReport { try get(.status, StatusReport.self) }
    public func recentFlows(limit: Int) async throws -> [FlowRecord] { try get(.recentFlows(limit: limit), [FlowRecord].self) }
    public func applySignedSnapshot(_ data: Data, canarySeconds: Int) async throws -> PolicySummary {
        try get(.applySignedSnapshot(data, canarySeconds: canarySeconds), PolicySummary.self)
    }
    public func confirmCanary() async throws { _ = try get(.confirmCanary, [String: Bool].self) }
    public func rollbackToLastKnownGood() async throws -> PolicySummary { try get(.rollbackToLastKnownGood, PolicySummary.self) }
    public func enterIsolation(reason: String) async throws -> IsolationState { try get(.enterIsolation(reason: reason), IsolationState.self) }
    public func exitIsolation(confirmation: String) async throws -> IsolationState { try get(.exitIsolation(confirmation: confirmation), IsolationState.self) }
    public func reloadTrust() async throws -> Bool { try get(.reloadTrust, [String: Bool].self)["changed"] ?? false }

    /// Synchronous snapshot of state for rendering without async (screenshots, previews).
    public func snapshot() -> (StatusReport, [FlowRecord]) {
        let s = handler.status()
        return (s, handler.engine.spool.recent(limit: 200))
    }
}
