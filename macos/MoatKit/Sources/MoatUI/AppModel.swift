import Foundation
import MoatKit
import SwiftUI

public enum Screen: String, CaseIterable, Identifiable {
    // Sidebar (MASTER_ROADMAP §9.1): Apps is the primary workspace.
    case apps, activity, tasks, rules, devices, coverage
    // Reached from those screens.
    case appDetail, whatChanged
    // W14: learning and workflow packs, reached from Rules.
    case learning, candidate, packs
    public var id: String { rawValue }

    public static let sidebar: [Screen] = [.apps, .activity, .tasks, .rules, .devices, .coverage]

    /// Launch-argument names, including the pre-W12 ones the screenshot script used.
    public static func named(_ s: String) -> Screen? {
        switch s {
        case "overview": return .apps
        case "policy": return .rules
        case "recovery": return .coverage
        default: return Screen(rawValue: s)
        }
    }

    func title(deviceCount: Int = 1) -> String {
        switch self {
        case .apps: return "Apps"
        case .activity: return "Activity"
        case .tasks: return "Tasks"
        case .rules: return "Rules"
        case .devices: return deviceCount <= 1 ? "This computer" : "Devices"
        case .coverage: return "Coverage & recovery"
        case .appDetail: return "App"
        case .whatChanged: return "What changed?"
        case .learning: return "Learn"
        case .candidate: return "Review"
        case .packs: return "Rule packs"
        }
    }

    var title: String { title() }

    var symbol: String {
        switch self {
        case .apps: return "square.grid.2x2"
        case .activity: return "waveform.path.ecg"
        case .tasks: return "terminal"
        case .rules: return "doc.text.magnifyingglass"
        case .devices: return "laptopcomputer"
        case .coverage: return "lifepreserver"
        case .appDetail: return "app.badge"
        case .whatChanged: return "arrow.left.arrow.right"
        case .learning: return "sparkles"
        case .candidate: return "checklist"
        case .packs: return "shippingbox"
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
    @Published public var screen: Screen = .apps
    /// The app shown by `.appDetail` (an `AppSummary.id`).
    @Published public var selectedAppID: String?
    /// Devices this Mac knows about. A standalone Mac is one device: the sidebar says "This computer".
    @Published public var deviceCount = 1
    /// Lifecycle events from other enrolled endpoints, filled only by fleet companion sync (W13). Empty when standalone.
    @Published public var fleetEvents: [EndpointLifecycleEvent] = []
    /// First-ten-minutes owner actions the app records (evidence for the checklist; never inferred from views).
    @Published public var choseMode = false
    @Published public var sawRecoveryCard = false
    @Published public var trialDenyHost: String?
    @Published public var trialUndone = false
    /// The local owner signer (Keychain + user presence). Nil in demo/screenshot runs that must not touch the Keychain.
    public var ownerSigner: OwnerSigner?
    @Published public var lastAuthorization: OwnerAuthorization?
    /// Standalone apply (compile with moat-core, sign with the owner key, install through the extension). Nil when this
    /// build has no policy compiler; the UI then says a rule can be authorized but not applied from this Mac alone.
    public var applier: StandaloneApplier?
    @Published public var lastApplied: StandaloneApplyResult?
    /// Why apply is not available in this run when there is no applier (no compiler in this build, or a demo run that
    /// never touches the Keychain). Shown verbatim.
    public var applyUnavailableReason: String = AppModel.standaloneApplyUnavailable
    /// W14 learning on this Mac: captures, candidates and immutable reviewed baselines (saved to `learningURL`).
    @Published public var learning = LearningBook()
    /// The candidate shown by `.candidate` (a capture candidate id, or a drift candidate id `drift-<baseline>`).
    @Published public var selectedCandidateID: String?
    public var learningURL: URL? {
        didSet { loadLearning() }
    }
    public lazy var packs: [WorkflowPack] = WorkflowPack.bundled()
    public let client: ControlClient
    public let isDemo: Bool

    public init(client: ControlClient, isDemo: Bool = false, screen: Screen = .apps, ownerSigner: OwnerSigner? = nil, applier: StandaloneApplier? = nil) {
        self.client = client
        self.isDemo = isDemo
        self.screen = screen
        self.ownerSigner = ownerSigner
        self.applier = applier
    }

    /// True when a locally authorized rule can be enforced from this Mac alone.
    public var canApplyStandalone: Bool { applier != nil }

    public var apps: [AppSummary] { AppSummary.from(flows) }
    public var selectedApp: AppSummary? { apps.first { $0.id == selectedAppID } }
    public var firstTen: FirstTenMinutes {
        FirstTenMinutes.evaluate(status: status, flows: flows, stale: isStale, choseMode: choseMode, deniedHost: trialDenyHost, undone: trialUndone, sawRecovery: sawRecoveryCard)
    }

    public func open(app id: String) {
        selectedAppID = id
        screen = .appDetail
    }

    /// Owner-authorize a narrow local rule plan with the Keychain key (OS user presence). With a standalone applier the
    /// signature is over the compiled snapshot itself and the extension installs it (verified against the trusted-keys
    /// file and this Mac's device id); without one the authorization is kept for audit and the rule is not applied.
    public func authorize(_ plan: LocalRulePlan, now: Date = Date()) async {
        let problems = plan.problems(now: now)
        guard problems.isEmpty else {
            lastError = problems.joined(separator: " ")
            return
        }
        let id = "local-\(Int(now.timeIntervalSince1970))"
        if let applier {
            do {
                let r = try await applier.apply(plan, id: id, now: now)
                lastApplied = r
                notice = "In use on this Mac as rules version \(r.summary.revision), signed with your owner key \(r.keyID). The rule ends at \(plan.expires.formatted(date: .omitted, time: .shortened))."
                lastError = nil
                await refresh(now: now)
            } catch {
                lastError = "\(error)"
            }
            return
        }
        guard let signer = ownerSigner else {
            lastError = "No local owner key is available in this run."
            return
        }
        do {
            if signer.keyID == nil { try signer.createKey() }
            lastAuthorization = try await signer.authorize(plan.ownerPlan(id: id))
            notice = "Approved with your owner key \(signer.keyID ?? ""). \(applyUnavailableReason)"
            lastError = nil
        } catch {
            lastError = "\(error)"
        }
    }

    // MARK: W14 learning

    private func loadLearning() {
        guard let url = learningURL, let data = try? Data(contentsOf: url), let book = try? JSONDecoder().decode(LearningBook.self, from: data) else { return }
        learning = book
    }

    private func saveLearning() {
        guard let url = learningURL, let data = try? JSONEncoder().encode(learning) else { return }
        try? FileManager.default.createDirectory(at: url.deletingLastPathComponent(), withIntermediateDirectories: true)
        try? data.write(to: url, options: .atomic)
    }

    /// Start a bounded capture for one app identity. It only reads what the filter records; rules stay enforced.
    public func startCapture(app: AppSummary, workflow: String, networkContext: String, hours: Double, now: Date = Date()) {
        guard app.identityKnown else {
            lastError = "macOS didn't report which program this is, and a recording needs to know exactly which app it is."
            return
        }
        let scope = CaptureScope(id: "cap-\(Int(now.timeIntervalSince1970))", signingID: app.signingID, executable: app.executable, teamID: app.teamID, appName: app.name, workflow: workflow, networkContext: networkContext, start: now, end: now.addingTimeInterval(hours * 3600))
        do {
            try Learning.validate(scope)
            learning.captures.insert(scope, at: 0)
            notice = "Recording \(app.name) for \(workflow). Your current rules stay on; nothing it reaches is trusted until you review it."
            lastError = nil
            saveLearning()
        } catch {
            lastError = "\(error)"
        }
    }

    /// Close a capture (early, or after its window) into a candidate for review.
    public func closeCapture(_ id: String, now: Date = Date()) {
        guard let i = learning.captures.firstIndex(where: { $0.id == id }) else { return }
        let scope = learning.captures.remove(at: i)
        let c = Learning.candidate(id: "cand-\(scope.id)", scope: scope, records: flows, gaps: status?.telemetryGaps ?? [], now: now)
        learning.candidates.insert(c, at: 0)
        selectedCandidateID = c.id
        screen = .candidate
        saveLearning()
    }

    /// Drift since approval, computed from the recorded flows: a new candidate per baseline; baselines never change.
    public func driftQueue(now: Date = Date()) -> [LearningCandidate] {
        learning.active.compactMap { Learning.drift($0, records: flows, gaps: status?.telemetryGaps ?? [], now: now, id: "drift-\($0.id)") }
    }

    public var selectedCandidate: LearningCandidate? {
        learning.candidates.first { $0.id == selectedCandidateID } ?? driftQueue().first { $0.id == selectedCandidateID }
    }

    public func open(candidate id: String) {
        selectedCandidateID = id
        screen = .candidate
    }

    /// Accept exactly the selected entries. The owner key signs the exact plan behind Touch ID or the password; a demo
    /// or screenshot run has no key and is refused rather than pretending.
    public func acceptCandidate(_ c: LearningCandidate, accepting: [Int], acknowledgeIncomplete: Bool, now: Date = Date()) async {
        let problems = Learning.acceptProblems(c, accepting: accepting, acknowledgeIncomplete: acknowledgeIncomplete)
        guard problems.isEmpty else {
            lastError = problems.joined(separator: " ")
            return
        }
        guard let signer = ownerSigner else {
            lastError = isDemo ? "Demo: no owner key is used, so nothing is accepted. In the real app, macOS asks for Touch ID or your password and shows this exact plan." : "No local owner key is available in this run."
            return
        }
        do {
            if signer.keyID == nil { _ = try signer.createKey() }
            let auth = try await signer.authorize(Learning.ownerPlan(c, accepting: accepting))
            let previous = learning.current(for: c.scope)
            let b = try Learning.accept(c, accepting: accepting, acknowledgeIncomplete: acknowledgeIncomplete, previous: previous, authorization: auth, id: "base-\(Int(now.timeIntervalSince1970))", now: now)
            try learning.record(b)
            notice = "Approved list saved (\(b.entries.count) places), signed with your owner key \(auth.keyID). It doesn't take effect just by being saved."
            lastError = nil
            screen = .learning
            saveLearning()
        } catch {
            lastError = "\(error)"
        }
    }

    public func discardCandidate(_ id: String) {
        learning.candidates.removeAll { $0.id == id }
        notice = "Discarded. Nothing was accepted; record again to see more."
        screen = .learning
        saveLearning()
    }

    public func retire(_ b: LearningBaseline, now: Date = Date()) {
        learning.retired[b.id] = ISO8601DateFormatter().string(from: now)
        saveLearning()
    }

    /// Demo runs: one capture candidate and one reviewed baseline built from the demo client's recorded flows.
    public func seedDemoLearning(now: Date = Date()) {
        guard isDemo, learning.captures.isEmpty, learning.candidates.isEmpty, learning.baselines.isEmpty else { return }
        let known = apps.filter { $0.identityKnown }
        guard let first = known.first else { return }
        let start = (flows.map(\.facts.at).min() ?? now).addingTimeInterval(-60)
        let scope = CaptureScope(id: "cap-demo", signingID: first.signingID, executable: first.executable, teamID: first.teamID, appName: first.name, workflow: "coding session", networkContext: "home LAN", start: start, end: min(now, start.addingTimeInterval(8 * 3600)))
        learning.candidates = [Learning.candidate(id: "cand-demo", scope: scope, records: flows, gaps: status?.telemetryGaps ?? [], now: now)]
        if known.count > 1, let second = known.dropFirst().first(where: { $0.destinations.count > 1 }) ?? known.dropFirst().first {
            let s2 = CaptureScope(id: "cap-demo-0", signingID: second.signingID, executable: second.executable, teamID: second.teamID, appName: second.name, workflow: "daily use", networkContext: "home LAN", start: start.addingTimeInterval(-7200), end: start.addingTimeInterval(-3600))
            let seen = Learning.candidate(id: "cand-demo-0", scope: s2, records: flows, gaps: [], now: start)
            // a reviewed baseline from before the recorded window, so the recorded activity shows up as drift
            let entries = Array(Learning.entries(flows.filter { Learning.matches($0.facts, s2) }).prefix(1))
            let b = LearningBaseline(id: "base-demo", candidateID: seen.id, scope: s2, entries: entries, digest: PlanDigest.of("demo"), complete: true, approvedAt: start, authorizedBy: "demo (no key)", supersedes: nil)
            try? learning.record(b)
        }
        if screen == .candidate, selectedCandidateID == nil { selectedCandidateID = "cand-demo" }
        learning.captures = [CaptureScope(id: "cap-demo-live", signingID: first.signingID, executable: first.executable, teamID: first.teamID, appName: first.name, workflow: "npm install", networkContext: "home LAN", start: now.addingTimeInterval(-600), end: now.addingTimeInterval(3000))]
    }

    /// Shown only when this build has no policy compiler (no applier): never replaced by a pretend success.
    public static let standaloneApplyUnavailable = "This build has no policy compiler, so the rule is approved but not put in use from this Mac; use your controller or moatctl for that."

    /// Demo and screenshot runs: no owner key is touched, nothing is signed or applied.
    public static let demoApplyNote = "Demo: no owner key is used and nothing is signed or put in use. In the real app, Moat builds the rule, your owner key signs exactly that, and the filter checks the signature before using it."

    /// Shown under the plan when standalone apply is available.
    public static let standaloneApplyHow = "Moat builds the rule, your owner key signs exactly that, and the filter checks it against your trusted keys before using it. No controller is needed."

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
            if isDemo { seedDemoLearning(now: now) }
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
