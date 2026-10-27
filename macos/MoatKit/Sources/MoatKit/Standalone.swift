import Foundation

// MARK: - W12 standalone read models for the Mac (pure, testable; the UI only renders these)

/// One app as an identity the platform reported: signing identifier + team, else executable path. A label alone is
/// never identity: flows with neither are grouped as "identity unknown" and never merged into a known app.
public struct AppSummary: Identifiable, Equatable, Sendable {
    public struct Destination: Equatable, Sendable {
        public var host: String
        public var port: UInt16
        public var count: Int
        public var blocked: Int
        public var observed: Int
        public var firstSeen: Date
        public var lastSeen: Date
    }

    public var id: String
    public var name: String
    public var signingID: String?
    public var teamID: String?
    public var executable: String?
    public var identityKnown: Bool
    public var flows: Int
    public var blocked: Int
    public var observed: Int
    public var destinations: [Destination]
    public var firstSeen: Date
    public var lastSeen: Date
    public var ruleIDs: [String]
    public var revisions: [UInt64]

    public static let unknownID = "identity-unknown"

    public static func identity(of f: FlowFacts) -> (id: String, known: Bool) {
        if let s = f.signingID, !s.isEmpty { return ("sig:\(s)|\(f.teamID ?? "-")", true) }
        if let e = f.executable, !e.isEmpty { return ("exe:\(e)", true) }
        return (unknownID, false)
    }

    /// Group recorded flows by identity, newest activity first; unknown identity last.
    public static func from(_ records: [FlowRecord]) -> [AppSummary] {
        var by: [String: AppSummary] = [:]
        for r in records {
            let (id, known) = identity(of: r.facts)
            let blocked = r.decision.verdict == .deny ? 1 : 0
            let observed = r.decision.isObservation ? 1 : 0
            var a = by[id] ?? AppSummary(id: id, name: known ? r.facts.appLabel : "Identity unknown", signingID: r.facts.signingID, teamID: r.facts.teamID, executable: r.facts.executable, identityKnown: known, flows: 0, blocked: 0, observed: 0, destinations: [], firstSeen: r.facts.at, lastSeen: r.facts.at, ruleIDs: [], revisions: [])
            a.flows += 1
            a.blocked += blocked
            a.observed += observed
            a.firstSeen = min(a.firstSeen, r.facts.at)
            a.lastSeen = max(a.lastSeen, r.facts.at)
            if let rule = r.decision.ruleID, !a.ruleIDs.contains(rule) { a.ruleIDs.append(rule) }
            if let rev = r.decision.policyRevision, !a.revisions.contains(rev) { a.revisions.append(rev) }
            let host = r.facts.remoteHost ?? r.facts.remoteIP
            if let i = a.destinations.firstIndex(where: { $0.host == host && $0.port == r.facts.remotePort }) {
                a.destinations[i].count += 1
                a.destinations[i].blocked += blocked
                a.destinations[i].observed += observed
                a.destinations[i].firstSeen = min(a.destinations[i].firstSeen, r.facts.at)
                a.destinations[i].lastSeen = max(a.destinations[i].lastSeen, r.facts.at)
            } else {
                a.destinations.append(Destination(host: host, port: r.facts.remotePort, count: 1, blocked: blocked, observed: observed, firstSeen: r.facts.at, lastSeen: r.facts.at))
            }
            by[id] = a
        }
        return by.values.map { var a = $0; a.destinations.sort { $0.count > $1.count }; return a }
            .sorted { ($0.identityKnown ? 0 : 1, $1.lastSeen) < ($1.identityKnown ? 0 : 1, $0.lastSeen) }
    }
}

/// "Why the current rules apply" for one destination of an app: the extension's own recorded decision (from the
/// core evaluator). The Mac UI does not re-evaluate; it shows what was decided, by which rule, at which revision.
public struct AppExplanation: Equatable, Sendable {
    public var destination: String
    public var verdict: String
    public var summary: String
    public var ruleID: String?
    public var revision: UInt64?
    public var notes: [String]
    public var at: Date

    public static func latest(for app: AppSummary, in records: [FlowRecord]) -> [AppExplanation] {
        var seen = Set<String>()
        var out: [AppExplanation] = []
        for r in records.sorted(by: { $0.facts.at > $1.facts.at }) where AppSummary.identity(of: r.facts).id == app.id {
            let dest = "\(r.facts.remoteHost ?? r.facts.remoteIP):\(r.facts.remotePort)"
            guard seen.insert(dest).inserted else { continue }
            let verdict = r.decision.isObservation ? "observed (not enforced)" : r.decision.verdict.rawValue
            out.append(AppExplanation(destination: dest, verdict: verdict, summary: r.decision.summary, ruleID: r.decision.ruleID, revision: r.decision.policyRevision, notes: r.decision.notes, at: r.facts.at))
            if out.count >= 8 { break }
        }
        return out
    }
}

// MARK: - What changed?

public struct ChangeComparison: Equatable, Sendable {
    public struct Observed: Equatable, Sendable {
        public var kind: String
        public var title: String
        public var working: String
        public var failing: String
    }

    public struct Candidate: Equatable, Sendable {
        public var kind: String
        public var title: String
        public var why: String
        /// A reversible test the owner reviews. Never applied automatically.
        public var test: String
    }

    public var observed: [Observed]
    public var candidates: [Candidate]
    public var notCompared: [String]
    public static let disclaimer = "Observed changes are differences in recorded evidence. Candidates are possible explanations; none is claimed as the cause from timing alone. Every suggested test is reviewed by you and can be undone."

    /// Compare two intervals of recorded flows, optionally for one app. Gaps that touch either interval are reported.
    public static func compare(_ records: [FlowRecord], working: DateInterval, failing: DateInterval, appID: String? = nil, gaps: [GapMarker] = []) -> ChangeComparison {
        let scoped = records.filter { appID == nil || AppSummary.identity(of: $0.facts).id == appID }
        let a = scoped.filter { working.contains($0.facts.at) }
        let b = scoped.filter { failing.contains($0.facts.at) }
        var observed: [Observed] = []
        var candidates: [Candidate] = []

        func ids(_ rs: [FlowRecord]) -> Set<String> { Set(rs.map { "\($0.facts.signingID ?? $0.facts.executable ?? "unknown")\($0.facts.teamID.map { " (\($0))" } ?? "")" }) }
        let ia = ids(a), ib = ids(b)
        if ia != ib, !ib.isEmpty {
            observed.append(Observed(kind: "identity", title: "App or signer identity differs", working: ia.sorted().joined(separator: ", ").ifEmpty("none recorded"), failing: ib.sorted().joined(separator: ", ")))
            let fresh = ib.subtracting(ia)
            if !fresh.isEmpty { candidates.append(Candidate(kind: "identity", title: "The app was updated or replaced", why: "Seen only while failing: \(fresh.sorted().joined(separator: ", ")). Rules naming the old identity do not carry over.", test: "Review the new identity on its app page; no trust is inherited")) }
        }

        func revs(_ rs: [FlowRecord]) -> Set<UInt64> { Set(rs.compactMap { $0.decision.policyRevision }) }
        let ra = revs(a), rb = revs(b)
        if ra != rb, !rb.isEmpty {
            observed.append(Observed(kind: "policy", title: "Policy revision in force differs", working: ra.sorted().map { "r\($0)" }.joined(separator: ", ").ifEmpty("none recorded"), failing: rb.sorted().map { "r\($0)" }.joined(separator: ", ")))
            if let last = ra.max() { candidates.append(Candidate(kind: "policy", title: "A policy change after r\(last)", why: "Timing alone does not show the change caused the failure.", test: "Roll back to the last known good revision from Recovery (reversible: re-apply the newer snapshot)")) }
        }

        func dests(_ rs: [FlowRecord]) -> [String: Set<String>] {
            var m: [String: Set<String>] = [:]
            for r in rs { m["\(r.facts.remoteHost ?? r.facts.remoteIP):\(r.facts.remotePort)", default: []].insert(r.decision.verdict == .deny ? "blocked" : (r.decision.isObservation ? "observed" : "allowed")) }
            return m
        }
        let da = dests(a), db = dests(b)
        for (k, v) in db.sorted(by: { $0.key < $1.key }) {
            let before = da[k]
            if v.contains("blocked"), !(before?.contains("blocked") ?? false) {
                observed.append(Observed(kind: "destination", title: "Now blocked: \(k)", working: before.map { $0.sorted().joined(separator: "/") } ?? "not contacted", failing: v.sorted().joined(separator: "/")))
                candidates.append(Candidate(kind: "destination", title: "\(k) is blocked while failing", why: before == nil ? "It was not contacted while working: the app may use a new destination." : "It was allowed or observed while working.", test: "Plan a narrow, expiring allow for this app and destination (shows the exact plan; owner authentication required)"))
            } else if before == nil {
                observed.append(Observed(kind: "destination", title: "New destination: \(k)", working: "not contacted", failing: v.sorted().joined(separator: "/")))
            }
        }

        let touching = gaps.filter { g in
            let seqA = a.map(\.seq), seqB = b.map(\.seq)
            func hit(_ s: [UInt64]) -> Bool { guard let lo = s.min(), let hi = s.max() else { return false }; return g.fromSeq <= hi + 1 && g.toSeq + 1 >= lo }
            return hit(seqA) || hit(seqB)
        }
        if !touching.isEmpty {
            observed.append(Observed(kind: "telemetry", title: "Telemetry gaps (the comparison is incomplete)", working: "", failing: touching.map { "events \($0.fromSeq)–\($0.toSeq) lost (\($0.reason))" }.joined(separator: "; ")))
        }
        if a.isEmpty { observed.append(Observed(kind: "telemetry", title: "No records in the working interval", working: "none", failing: "\(b.count) records")) }
        return ChangeComparison(observed: observed, candidates: candidates, notCompared: ["Resolver, route and network-context changes (not recorded by the filter)", "Capability history (only the current report is kept)"])
    }
}

extension String {
    func ifEmpty(_ s: String) -> String { isEmpty ? s : self }
}

// MARK: - Diagnostics

public struct DiagnosticsReport: Equatable, Sendable {
    public struct Item: Equatable, Sendable, Identifiable {
        public var label: String
        public var value: String
        public var warn: Bool
        public var id: String { label }
    }

    public var items: [Item]
    public var downgraded: [CapabilityRow]

    /// Built only from the extension's own status report and the app's contact record.
    public static func from(status s: StatusReport?, lastContact: Date?, contactLostSince: Date?, now: Date = Date()) -> DiagnosticsReport {
        guard let s else {
            return DiagnosticsReport(items: [Item(label: "Filter", value: "has not reported", warn: true)], downgraded: [])
        }
        var items: [Item] = [
            Item(label: "Extension version", value: s.extensionVersion, warn: false),
            Item(label: "Filter enabled", value: s.filterEnabled ? "yes" : "no", warn: !s.filterEnabled),
            Item(label: "Coverage", value: s.coverage.label, warn: s.coverage == .degraded || s.coverage == .unknown),
            Item(label: "Installed policy", value: s.installed.map { "r\($0.revision) \($0.policyName) (\($0.digest.prefix(12)))" } ?? "none (observing)", warn: false),
            Item(label: "Last known good", value: s.lastKnownGood.map { "r\($0.revision)" } ?? "none", warn: false),
            Item(label: "Evaluator / trust generation", value: "\(s.evaluatorGeneration.map(String.init) ?? "–") / \(s.trustGeneration.map(String.init) ?? "–")", warn: false),
            Item(label: "Saved to disk", value: s.durable == false ? "no: will not survive a restart" : (s.durable == true ? "yes" : "not reported"), warn: s.durable == false),
            Item(label: "Restoration at start", value: s.restoration ?? "not reported", warn: false),
            Item(label: "Evidence age", value: lastContact.map { "\(Int(now.timeIntervalSince($0)))s" } ?? "never", warn: contactLostSince != nil),
            Item(label: "Telemetry gaps", value: s.telemetryGaps.isEmpty ? "none reported" : s.telemetryGaps.map { "\($0.fromSeq)–\($0.toSeq)" }.joined(separator: ", "), warn: !s.telemetryGaps.isEmpty),
            Item(label: "Compatibility tests", value: "none run from this Mac", warn: false),
        ]
        if let r = s.lastRejection { items.append(Item(label: "Last rejected snapshot", value: r, warn: true)) }
        if let since = contactLostSince { items.insert(Item(label: "Contact", value: "lost \(Int(now.timeIntervalSince(since)))s ago: nothing here is current", warn: true), at: 0) }
        return DiagnosticsReport(items: items, downgraded: s.capabilities.filter { $0.support != .supported })
    }
}

// MARK: - First ten minutes (MASTER_ROADMAP §9.2)

/// Each step is done only on evidence: the extension's status, recorded flows, or an explicit owner action recorded
/// by the app. Nothing is checked off because a screen was shown.
public struct FirstTenMinutes: Equatable, Sendable {
    public enum Step: String, CaseIterable, Sendable {
        case approve, health, choose, seeConnection, temporaryDeny, verifyUndo, recoveryCard, fleet

        public var title: String {
            switch self {
            case .approve: return "Approve the system extension"
            case .health: return "Confirm the filter is actually running"
            case .choose: return "Choose: observe apps, enforce selected apps, or launch a restricted task"
            case .seeConnection: return "See one real connection"
            case .temporaryDeny: return "Create a narrow temporary deny"
            case .verifyUndo: return "Verify the block, then undo it"
            case .recoveryCard: return "Keep your local recovery card"
            case .fleet: return "Optional: connect other devices"
            }
        }
    }

    public var done: Set<Step>

    public static func evaluate(status: StatusReport?, flows: [FlowRecord], stale: Bool, choseMode: Bool, deniedHost: String?, undone: Bool, sawRecovery: Bool) -> FirstTenMinutes {
        var d = Set<Step>()
        if let s = status, s.filterEnabled { d.insert(.approve) }
        if let s = status, !stale, s.coverage != .unknown, s.coverage != .degraded { d.insert(.health) }
        if choseMode { d.insert(.choose) }
        if flows.contains(where: { !$0.facts.isLoopback }) { d.insert(.seeConnection) }
        if let h = deniedHost, flows.contains(where: { ($0.facts.remoteHost ?? $0.facts.remoteIP) == h && $0.decision.verdict == .deny }) {
            d.insert(.temporaryDeny)
            if undone { d.insert(.verifyUndo) }
        }
        if sawRecovery { d.insert(.recoveryCard) }
        return FirstTenMinutes(done: d)
    }

    /// Fleet enrollment is offered only after local usefulness is established.
    public var offerFleet: Bool { [.health, .seeConnection, .recoveryCard].allSatisfy { done.contains($0) } }
    public var next: Step? { Step.allCases.first { $0 != .fleet && !done.contains($0) } }
}

// MARK: - Standalone rule plan

/// A narrow, expiring local rule the owner authors on this Mac. The plan text is what the OS prompt shows.
public struct LocalRulePlan: Equatable, Sendable {
    public enum Action: String, Sendable { case deny, allow }
    public var action: Action
    public var app: AppSummary
    public var host: String
    public var port: UInt16
    public var expires: Date

    public static let maxDuration: TimeInterval = 8 * 3600

    public init(action: Action, app: AppSummary, host: String, port: UInt16, expires: Date) {
        self.action = action
        self.app = app
        self.host = host
        self.port = port
        self.expires = expires
    }

    /// Problems that make the plan unauthorizable (never silently widened to make it "work").
    public func problems(now: Date = Date()) -> [String] {
        var p: [String] = []
        if !app.identityKnown { p.append("This app has no reported identity; a rule cannot name it.") }
        if host.isEmpty || host.contains("*") { p.append("Name one exact destination; wildcards are not allowed here.") }
        if expires <= now { p.append("The expiry is in the past.") }
        if expires.timeIntervalSince(now) > Self.maxDuration { p.append("Local rules last at most 8 hours; permanent rules belong in the full policy editor.") }
        return p
    }

    var selectorTOML: String {
        if let s = app.signingID { return "apps = [{ signing_id = \"\(s)\"\(app.teamID.map { ", team_id = \"\($0)\"" } ?? "") }]" }
        return "apps = [{ executable = \"\(app.executable ?? "")\" }]"
    }

    /// The exact rule material (moat.policy.v1 TOML) the plan adds.
    public func ruleTOML(id: String) -> String {
        let f = ISO8601DateFormatter()
        return """
        [[rules]]
        id = "\(id)"
        description = "Local \(action.rawValue) authored on this Mac"
        action = "\(action.rawValue)"
        selector = { \(selectorTOML) }
        destinations = { hosts = ["\(host)"] }
        transport = "tcp"
        ports = [\(port)]
        expires_at = "\(f.string(from: expires))"
        provenance = { kind = "local_owner", reference = "this mac" }
        """
    }

    public func ownerPlan(id: String) -> OwnerPlan {
        let toml = ruleTOML(id: id)
        let display = "\(action == .deny ? "Block" : "Allow") \(app.name) → \(host):\(port) until \(ISO8601DateFormatter().string(from: expires))"
        return OwnerPlan(subject: "local-rule:\(id)", digest: PlanDigest.of(toml), display: display)
    }
}
