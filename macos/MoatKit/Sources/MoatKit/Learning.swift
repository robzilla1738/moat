import Foundation

// MARK: - W14 quiet learning on this Mac (MASTER_ROADMAP §9.4). Learning produces a proposal, never trust.
//
// Capture is bounded to one exact app identity (code-signing identifier + team, or the executable path when macOS
// reports no signing identifier), one named workflow and network context, a time
// window and a record budget, and only reads the flows the filter already recorded: existing rules stay enforced.
// A candidate lists exact destinations, each proposed; repetition is a count, never acceptance. A candidate is
// complete only without gaps and without connections of unknown identity in its window. Accepting needs the owner
// key behind user presence, records exactly the selected entries and produces an immutable baseline. New activity
// after approval is a new (drift) candidate; the baseline never changes.

public struct LearningEntry: Codable, Sendable, Equatable, Identifiable {
    public var destination: String
    public var port: UInt16
    public var transport: String
    public var occurrences: Int
    public var firstAt: Date
    public var lastAt: Date
    public var verdicts: [String]
    public var id: String { "\(destination)|\(port)|\(transport)" }
    /// Only ever refused: accepting it would not override a deny (denies keep precedence).
    public var deniedOnly: Bool { verdicts == ["deny"] }
}

public struct CaptureScope: Codable, Sendable, Equatable, Identifiable {
    public var id: String
    /// The code-signing identifier macOS reported (the primary identity), if any.
    public var signingID: String?
    /// The executable path, used as identity only when there is no signing identifier.
    public var executable: String?
    public var teamID: String?
    public var appName: String
    public var workflow: String
    public var networkContext: String
    public var start: Date
    public var end: Date
    public var maxRecords: Int

    public init(id: String, signingID: String? = nil, executable: String?, teamID: String?, appName: String, workflow: String, networkContext: String, start: Date, end: Date, maxRecords: Int = 5000) {
        self.id = id
        self.signingID = signingID
        self.executable = executable
        self.teamID = teamID
        self.appName = appName
        self.workflow = workflow
        self.networkContext = networkContext
        self.start = start
        self.end = end
        self.maxRecords = maxRecords
    }

    /// The exact identity in words: what the capture and any baseline are bound to.
    public var identityLabel: String {
        if let s = signingID, !s.isEmpty { return "\(s) · team \(teamID ?? "none")" }
        return "\(executable ?? "?") · team \(teamID ?? "none")"
    }
}

public struct LearningCandidate: Codable, Sendable, Equatable, Identifiable {
    public enum Kind: String, Codable, Sendable { case capture, drift }
    public var id: String
    public var kind: Kind
    public var scope: CaptureScope
    public var entries: [LearningEntry]
    public var incompleteReasons: [String]
    public var identityChanges: [String]
    public var baselineID: String?
    public var createdAt: Date
    public var complete: Bool { incompleteReasons.isEmpty }
}

public struct PermissionDiffRow: Equatable, Sendable, Identifiable {
    public enum Change: String, Sendable { case adds, inBaseline }
    public var index: Int
    public var entry: LearningEntry
    public var change: Change
    public var id: Int { index }
}

/// A reviewed baseline. Every field is a `let`: it is never edited, only superseded or retired.
public struct LearningBaseline: Codable, Sendable, Equatable, Identifiable {
    public let id: String
    public let candidateID: String
    public let scope: CaptureScope
    public let entries: [LearningEntry]
    public let digest: String
    public let complete: Bool
    public let approvedAt: Date
    /// The owner key that authorized it (user presence).
    public let authorizedBy: String
    public let supersedes: String?

    public init(id: String, candidateID: String, scope: CaptureScope, entries: [LearningEntry], digest: String, complete: Bool, approvedAt: Date, authorizedBy: String, supersedes: String?) {
        self.id = id
        self.candidateID = candidateID
        self.scope = scope
        self.entries = entries
        self.digest = digest
        self.complete = complete
        self.approvedAt = approvedAt
        self.authorizedBy = authorizedBy
        self.supersedes = supersedes
    }
}

public struct LearningError: Error, Equatable, CustomStringConvertible {
    public let description: String
    public init(_ d: String) { description = d }
}

public enum Learning {
    public static let maxCaptureHours: Double = 8
    public static let maxCaptureRecords = 20_000

    public static func validate(_ s: CaptureScope) throws {
        let signed = !(s.signingID ?? "").isEmpty
        guard signed || (s.executable ?? "").hasPrefix("/") else { throw LearningError("A capture is bound to one exact identity: a signing identifier or an executable path. A name alone is never identity.") }
        guard !s.workflow.trimmingCharacters(in: .whitespaces).isEmpty, !s.networkContext.trimmingCharacters(in: .whitespaces).isEmpty else {
            throw LearningError("Name the workflow and the network context: a normal session and a dependency install are different captures.")
        }
        let hours = s.end.timeIntervalSince(s.start) / 3600
        guard hours > 0, hours <= maxCaptureHours else { throw LearningError("A capture lasts at most \(Int(maxCaptureHours)) hours.") }
        guard s.maxRecords > 0, s.maxRecords <= maxCaptureRecords else { throw LearningError("A capture considers at most \(maxCaptureRecords) records.") }
    }

    /// Exact identity: the same signing identifier and team; without a signing identifier, the same executable path
    /// and team. Never a display name.
    public static func matches(_ f: FlowFacts, _ s: CaptureScope) -> Bool {
        guard (f.teamID ?? "") == (s.teamID ?? "") else { return false }
        if let sid = s.signingID, !sid.isEmpty { return f.signingID == sid }
        guard let exe = s.executable else { return false }
        return (f.signingID ?? "").isEmpty && f.executable == exe
    }

    public static func entries(_ records: [FlowRecord]) -> [LearningEntry] {
        var by: [String: LearningEntry] = [:]
        var order: [String] = []
        for r in records {
            let host = r.facts.remoteHost ?? r.facts.remoteIP
            let key = "\(host)|\(r.facts.remotePort)|\(r.facts.transport.rawValue)"
            let v = r.decision.verdict == .deny ? "deny" : (r.decision.isObservation ? "observed" : "allow")
            if var e = by[key] {
                e.occurrences += 1
                e.firstAt = min(e.firstAt, r.facts.at)
                e.lastAt = max(e.lastAt, r.facts.at)
                if !e.verdicts.contains(v) { e.verdicts.append(v) }
                by[key] = e
            } else {
                by[key] = LearningEntry(destination: host, port: r.facts.remotePort, transport: r.facts.transport.rawValue, occurrences: 1, firstAt: r.facts.at, lastAt: r.facts.at, verdicts: [v])
                order.append(key)
            }
        }
        return order.compactMap { by[$0] }.sorted { ($0.destination, $0.port) < ($1.destination, $1.port) }
    }

    /// Why the window's evidence cannot support a "complete" claim.
    public static func incompleteness(window: DateInterval, records: [FlowRecord], gaps: [GapMarker]) -> [String] {
        var reasons: [String] = []
        let inWindow = records.filter { window.contains($0.facts.at) }
        if let lo = inWindow.map(\.seq).min(), let hi = inWindow.map(\.seq).max() {
            for g in gaps where g.fromSeq <= hi + 1 && g.toSeq + 1 >= lo {
                reasons.append("events \(g.fromSeq)–\(g.toSeq) were lost (\(g.reason))")
            }
        } else if !gaps.isEmpty {
            reasons.append("the filter reported lost events and none were recorded in the window")
        }
        let unknown = inWindow.filter { !AppSummary.identity(of: $0.facts).known }.count
        if unknown > 0 { reasons.append("\(unknown) connection(s) in the window had no app identity and cannot be attributed") }
        return reasons
    }

    /// The same app family under another identity (same signing identifier with another team, or the same executable
    /// name elsewhere): listed, never inherited.
    public static func identityChanges(records: [FlowRecord], scope: CaptureScope, since: Date) -> [String] {
        let base = scope.executable.map { ($0 as NSString).lastPathComponent }
        var seen = Set<String>()
        var out: [String] = []
        for r in records where r.facts.at >= since && !matches(r.facts, scope) {
            let sameSigner = scope.signingID != nil && r.facts.signingID == scope.signingID
            let sameName = base != nil && r.facts.executable.map { ($0 as NSString).lastPathComponent } == base
            guard sameSigner || sameName else { continue }
            let label = "\(r.facts.signingID ?? r.facts.executable ?? "?") · team \(r.facts.teamID ?? "none")"
            if seen.insert(label).inserted { out.append(label) }
        }
        return out
    }

    public static func candidate(id: String, scope: CaptureScope, records: [FlowRecord], gaps: [GapMarker], now: Date) -> LearningCandidate {
        let window = DateInterval(start: scope.start, end: max(scope.start, min(now, scope.end)))
        let mine = records.filter { window.contains($0.facts.at) && matches($0.facts, scope) }.sorted { $0.seq < $1.seq }
        var reasons = incompleteness(window: window, records: records, gaps: gaps)
        if mine.count > scope.maxRecords { reasons.append("the record budget (\(scope.maxRecords)) was reached; later activity was not considered") }
        return LearningCandidate(id: id, kind: .capture, scope: scope, entries: entries(Array(mine.prefix(scope.maxRecords))), incompleteReasons: reasons, identityChanges: identityChanges(records: records, scope: scope, since: scope.start), baselineID: nil, createdAt: now)
    }

    public static func diff(_ c: LearningCandidate, against b: LearningBaseline?) -> [PermissionDiffRow] {
        let covered = Set(b?.entries.map(\.id) ?? [])
        return c.entries.enumerated().map { PermissionDiffRow(index: $0.offset, entry: $0.element, change: covered.contains($0.element.id) ? .inBaseline : .adds) }
    }

    /// The exact text the owner authorizes: identity, scope and the selected entries.
    public static func planText(_ c: LearningCandidate, accepting: [Int]) -> String {
        let picked = accepting.sorted().map { c.entries[$0] }
        var lines = ["moat.learning_baseline.v1", "candidate \(c.id)", "signing \(c.scope.signingID ?? "none")", "executable \(c.scope.executable ?? "none")", "team \(c.scope.teamID ?? "none")", "workflow \(c.scope.workflow)", "network \(c.scope.networkContext)", "complete \(c.complete)"]
        lines += picked.map { "allow \($0.destination):\($0.port)/\($0.transport)" }
        return lines.joined(separator: "\n")
    }

    public static func ownerPlan(_ c: LearningCandidate, accepting: [Int]) -> OwnerPlan {
        let n = accepting.count
        return OwnerPlan(subject: "learning-baseline:\(c.id)", digest: PlanDigest.of(planText(c, accepting: accepting)), display: "Accept \(n) reviewed destination\(n == 1 ? "" : "s") for \(c.scope.appName) (\(c.scope.workflow)) as a baseline")
    }

    /// Refusals before anything is signed: nothing is accepted by default; incomplete evidence needs an acknowledgement.
    public static func acceptProblems(_ c: LearningCandidate, accepting: [Int], acknowledgeIncomplete: Bool) -> [String] {
        var p: [String] = []
        if accepting.isEmpty { p.append("Select the entries you reviewed and want. Nothing is accepted by default.") }
        if accepting.contains(where: { $0 < 0 || $0 >= c.entries.count }) { p.append("The selection does not match this candidate.") }
        if !c.complete && !acknowledgeIncomplete { p.append("The evidence is incomplete. Acknowledge the gaps to accept a partial baseline.") }
        return p
    }

    public static func accept(_ c: LearningCandidate, accepting: [Int], acknowledgeIncomplete: Bool, previous: LearningBaseline?, authorization: OwnerAuthorization?, id: String, now: Date) throws -> LearningBaseline {
        let problems = acceptProblems(c, accepting: accepting, acknowledgeIncomplete: acknowledgeIncomplete)
        guard problems.isEmpty else { throw LearningError(problems.joined(separator: " ")) }
        guard let authorization else { throw LearningError("Accepting a baseline needs your owner key (Touch ID or password).") }
        let picked = Set(accepting).sorted().map { c.entries[$0] }
        // a drift candidate adds to the previous baseline; a capture stands alone
        let base = c.kind == .drift ? (previous?.entries ?? []) : []
        let all = base + picked.filter { e in !base.contains(where: { $0.id == e.id }) }
        return LearningBaseline(id: id, candidateID: c.id, scope: c.scope, entries: all, digest: PlanDigest.of(planText(c, accepting: accepting)), complete: c.complete, approvedAt: now, authorizedBy: authorization.keyID, supersedes: previous?.id)
    }

    /// New activity for the baseline's identity since approval that it does not cover becomes a NEW candidate.
    public static func drift(_ b: LearningBaseline, records: [FlowRecord], gaps: [GapMarker], now: Date, id: String) -> LearningCandidate? {
        let covered = Set(b.entries.map(\.id))
        let after = records.filter { $0.facts.at >= b.approvedAt && matches($0.facts, b.scope) }
        let fresh = entries(after).filter { !covered.contains($0.id) }
        let changes = identityChanges(records: records, scope: b.scope, since: b.approvedAt)
        guard !fresh.isEmpty || !changes.isEmpty else { return nil }
        let window = DateInterval(start: b.approvedAt, end: max(b.approvedAt, now))
        return LearningCandidate(id: id, kind: .drift, scope: b.scope, entries: fresh, incompleteReasons: incompleteness(window: window, records: records, gaps: gaps), identityChanges: changes, baselineID: b.id, createdAt: now)
    }
}

/// The owner's learning state on this Mac: captures, open candidates, immutable baselines and retirements.
public struct LearningBook: Codable, Sendable, Equatable {
    public var captures: [CaptureScope] = []
    public var candidates: [LearningCandidate] = []
    public private(set) var baselines: [LearningBaseline] = []
    public var retired: [String: String] = [:]
    public init() {}

    /// Baselines are append-only: a new one may supersede an older one, an existing one is never replaced.
    public mutating func record(_ b: LearningBaseline) throws {
        guard !baselines.contains(where: { $0.id == b.id }) else { throw LearningError("A reviewed baseline is immutable; new activity creates a new candidate.") }
        baselines.append(b)
        candidates.removeAll { $0.id == b.candidateID }
    }

    /// The current reviewed baseline for exactly this identity.
    public func current(for s: CaptureScope) -> LearningBaseline? {
        baselines.last { $0.scope.signingID == s.signingID && $0.scope.executable == s.executable && ($0.scope.teamID ?? "") == (s.teamID ?? "") && retired[$0.id] == nil }
    }

    public var active: [LearningBaseline] {
        baselines.filter { b in retired[b.id] == nil && !baselines.contains(where: { other in other.supersedes == b.id }) }
    }
}

// MARK: - Workflow packs (packs/workflows, bundled): effective delta and unsupported cells on this Mac

public struct WorkflowPackModule: Codable, Sendable, Equatable, Identifiable {
    public var id: String
    public var name: String
    public var optional: Bool
    public var rationale: String
    public var required_capabilities: [String]
    public var expected_breakage_if_omitted: String
    public var provenance: String
    public var rules: String

    /// Hosts the module's rule material names (the compiler stays authoritative).
    public var hosts: [String] {
        guard let r = rules.range(of: "hosts = ["), let end = rules[r.upperBound...].firstIndex(of: "]") else { return [] }
        return rules[r.upperBound..<end].split(separator: ",").map { $0.trimmingCharacters(in: CharacterSet(charactersIn: " \"")) }.filter { !$0.isEmpty }
    }
}

public struct WorkflowPack: Codable, Sendable, Equatable, Identifiable {
    public var id: String
    public var version: String
    public var name: String
    public var description: String
    public var profile: String
    public var modules: [WorkflowPackModule]

    public static func bundled() -> [WorkflowPack] {
        let urls = (Bundle.module.urls(forResourcesWithExtension: "json", subdirectory: "Packs") ?? []).sorted { $0.lastPathComponent < $1.lastPathComponent }
        return urls.compactMap { try? JSONDecoder().decode(WorkflowPack.self, from: Data(contentsOf: $0)) }
    }
}

/// One module × this Mac: whether its required capabilities are supported here. Anything but `supported` means the
/// rule is skipped on this Mac with a report (`on_unsupported = "skip_with_report"`).
public struct PackCell: Equatable, Sendable {
    public struct Missing: Equatable, Sendable {
        public var capability: String
        public var support: String
    }
    public var support: Support?
    public var missing: [Missing]
    public var takesEffect: Bool { support == .supported }

    public static func evaluate(_ m: WorkflowPackModule, capabilities: [CapabilityRow]) -> PackCell {
        let per: [(String, Support?)] = m.required_capabilities.map { k in (k, capabilities.first { $0.key == k }?.support) }
        let missing = per.filter { $0.1 != .supported }.map { Missing(capability: $0.0, support: $0.1?.rawValue ?? "not reported") }
        let support: Support? = missing.isEmpty ? .supported : (per.contains { $0.1 == .unsupported } ? .unsupported : per.contains { $0.1 == nil } ? nil : .untested)
        return PackCell(support: support, missing: missing)
    }
}
