import Foundation

/// The decision for one flow.
public enum Verdict: String, Codable, Sendable, Equatable {
    case allow
    case deny
}

public enum Transport: String, Codable, Sendable, Equatable {
    case tcp
    case udp
}

/// Where a hostname came from. Mirrors `moat_core::net::HostnameSource`.
public enum HostnameSource: String, Codable, Sendable {
    /// NEFilterFlow carried the hostname the app asked for (`remoteHostname`).
    case flowApi = "flow_api"
    case inferred
}

/// What the Network Extension can tell us about one outbound flow, before a verdict.
///
/// Identity comes from the flow's source-app audit token (signing identifier, team, path). The extension does not
/// see ancestry: without the Endpoint Security entitlement, `ancestryComplete` is always false and the UI says so.
public struct FlowFacts: Codable, Sendable, Equatable {
    public var id: String
    public var bundleID: String?
    public var signingID: String?
    public var teamID: String?
    public var executable: String?
    public var pid: Int32?
    public var remoteHost: String?
    public var hostSource: HostnameSource?
    public var remoteIP: String
    public var remotePort: UInt16
    public var transport: Transport
    public var at: Date

    public init(
        id: String = UUID().uuidString,
        bundleID: String? = nil,
        signingID: String? = nil,
        teamID: String? = nil,
        executable: String? = nil,
        pid: Int32? = nil,
        remoteHost: String? = nil,
        hostSource: HostnameSource? = nil,
        remoteIP: String,
        remotePort: UInt16,
        transport: Transport,
        at: Date = Date()
    ) {
        self.id = id
        self.bundleID = bundleID
        self.signingID = signingID
        self.teamID = teamID
        self.executable = executable
        self.pid = pid
        self.remoteHost = remoteHost
        self.hostSource = hostSource
        self.remoteIP = remoteIP
        self.remotePort = remotePort
        self.transport = transport
        self.at = at
    }

    /// The best human label for the app: signing identifier, then bundle id, then executable name.
    public var appLabel: String {
        if let s = signingID, !s.isEmpty { return s }
        if let b = bundleID, !b.isEmpty { return b }
        if let e = executable, !e.isEmpty { return (e as NSString).lastPathComponent }
        return "unknown app"
    }

    /// Key used by the verdict cache. Includes everything that can change a decision.
    public var cacheKey: String {
        [signingID ?? "", teamID ?? "", executable ?? "", remoteHost ?? "", remoteIP, String(remotePort), transport.rawValue]
            .joined(separator: "|")
    }

    public var isLoopback: Bool {
        remoteIP == "::1" || remoteIP.hasPrefix("127.") || remoteIP == "localhost"
    }
}

/// Why a verdict was reached. Shown verbatim in Activity; never invented by the UI.
public enum DecisionSource: String, Codable, Sendable, Equatable {
    /// The signed policy decided (rule or profile default), via moat-core.
    case policy
    /// No valid policy is installed: the flow is permitted and recorded. This is observation, not enforcement.
    case observationNoPolicy = "observation_no_policy"
    /// The policy's profile is in observe mode: permitted and recorded, not enforced.
    case observationProfile = "observation_profile"
    /// Emergency isolation is on: everything except loopback is denied until the owner turns it off locally.
    case emergencyIsolation = "emergency_isolation"
    /// Loopback is always permitted so local recovery and IPC keep working.
    case loopback
    /// The evaluator failed; the filter applied the installed policy's fallback and reports it.
    case evaluatorError = "evaluator_error"
}

public struct FlowDecision: Codable, Sendable, Equatable {
    public var verdict: Verdict
    public var source: DecisionSource
    /// e.g. "blocked by explicit rule deny-paste-sites" (from moat-core's summary).
    public var summary: String
    public var ruleID: String?
    public var policyRevision: UInt64?
    public var notes: [String]

    public init(verdict: Verdict, source: DecisionSource, summary: String, ruleID: String? = nil, policyRevision: UInt64? = nil, notes: [String] = []) {
        self.verdict = verdict
        self.source = source
        self.summary = summary
        self.ruleID = ruleID
        self.policyRevision = policyRevision
        self.notes = notes
    }

    /// True when the flow was let through without enforcement. The UI must label these "observed", not "allowed".
    public var isObservation: Bool {
        source == .observationNoPolicy || source == .observationProfile
    }
}

/// One recorded flow with its decision. What crosses the XPC boundary to the app.
public struct FlowRecord: Codable, Sendable, Equatable, Identifiable {
    public var seq: UInt64
    public var facts: FlowFacts
    public var decision: FlowDecision
    /// Transfer measurement. Moat never reports an intended upload size; for a flow denied at the first
    /// decision point the honest statement is "blocked before data was sent".
    public var measurement: Measurement

    public var id: UInt64 { seq }

    public init(seq: UInt64, facts: FlowFacts, decision: FlowDecision, measurement: Measurement) {
        self.seq = seq
        self.facts = facts
        self.decision = decision
        self.measurement = measurement
    }
}

public enum Measurement: Codable, Sendable, Equatable {
    /// Denied at the new-flow decision point: no payload bytes passed the filter.
    case blockedBeforeData
    /// Byte counters from an NEFilterReport, when the system delivered one.
    case reported(outbound: UInt64, inbound: UInt64)
    /// Allowed and no report was delivered: the amount sent is not known.
    case unknown

    public var label: String {
        switch self {
        case .blockedBeforeData: return "Blocked before data was sent"
        case let .reported(out, inb): return "\(ByteFormat.string(out)) out · \(ByteFormat.string(inb)) in (reported by macOS)"
        case .unknown: return "Amount sent not measured"
        }
    }
}

public enum ByteFormat {
    public static func string(_ n: UInt64) -> String {
        if n < 1024 { return "\(n) B" }
        let units = ["KB", "MB", "GB", "TB"]
        var v = Double(n) / 1024
        var i = 0
        while v >= 1024 && i < units.count - 1 {
            v /= 1024
            i += 1
        }
        return v >= 10 ? String(format: "%.0f %@", v, units[i]) : String(format: "%.1f %@", v, units[i])
    }
}

/// Coverage as the endpoint can honestly claim it. Mirrors `moat_core::coverage::CoverageLevel`.
public enum CoverageLevel: String, Codable, Sendable {
    case observed
    case enforced
    case degraded
    case isolated
    case unknown

    public var label: String {
        switch self {
        case .observed: return "Observing"
        case .enforced: return "Enforcing"
        case .degraded: return "Degraded"
        case .isolated: return "Isolated"
        case .unknown: return "Unknown"
        }
    }

    /// The one-line claim. Deliberately narrow: no containment, ancestry or fail-closed promises on macOS.
    public var claim: String {
        switch self {
        case .observed: return "Activity is visible. Nothing is being blocked."
        case .enforced: return "App rules from your signed policy are enforced by the content filter."
        case .degraded: return "Coverage is reduced. See what is wrong below."
        case .isolated: return "Emergency isolation: everything except loopback is blocked until you turn it off here."
        case .unknown: return "The filter has not reported. Moat cannot say what is covered."
        }
    }
}

public enum Support: String, Codable, Sendable {
    case supported, partial, untested, unsupported
}

public struct CapabilityRow: Codable, Sendable, Equatable, Identifiable {
    public var key: String
    public var label: String
    public var support: Support
    public var note: String?
    public var id: String { key }

    public init(key: String, label: String, support: Support, note: String? = nil) {
        self.key = key
        self.label = label
        self.support = support
        self.note = note
    }

    /// The design-time macOS capability set, mirroring `CapabilityAdvertisement::macos_network_extension()`.
    /// Everything is "untested" until proven on a real, signed install (docs/STATUS.md).
    public static let macOSDesign: [CapabilityRow] = [
        .init(key: "process_identity", label: "Process identity", support: .untested, note: "Source app audit token via NEFilterFlow"),
        .init(key: "app_enforcement", label: "App enforcement", support: .untested, note: "NEFilterDataProvider verdicts per flow"),
        .init(key: "hostname_enforcement", label: "Hostname rules", support: .partial, note: "Only when the flow exposes a hostname; IP otherwise"),
        .init(key: "byte_counters", label: "Byte counters", support: .partial, note: "NEFilterReport counters under specific reporting conditions"),
        .init(key: "ipv6_enforcement", label: "IPv6", support: .untested, note: nil),
        .init(key: "udp_enforcement", label: "UDP / QUIC", support: .untested, note: "QUIC requires device proof"),
        .init(key: "ancestor_attribution", label: "Process ancestry", support: .unsupported, note: "Needs the Endpoint Security entitlement"),
        .init(key: "session_enforcement", label: "Protected sessions", support: .unsupported, note: "No tested macOS session boundary; session rules are omitted with a report"),
        .init(key: "existing_flow_revocation", label: "Revoke open flows", support: .unsupported, note: "Not yet tested"),
    ]
}

/// What is installed, as the extension reports it.
public struct PolicySummary: Codable, Sendable, Equatable {
    public var revision: UInt64
    public var rollbackOf: UInt64?
    public var policyName: String
    public var digest: String
    public var appliedAt: Date
    public var ruleCount: Int
    /// Rules the compiler left out of the macOS snapshot, with reasons (e.g. session rules).
    public var omitted: [OmittedRule]

    public init(revision: UInt64, rollbackOf: UInt64? = nil, policyName: String, digest: String, appliedAt: Date, ruleCount: Int, omitted: [OmittedRule]) {
        self.revision = revision
        self.rollbackOf = rollbackOf
        self.policyName = policyName
        self.digest = digest
        self.appliedAt = appliedAt
        self.ruleCount = ruleCount
        self.omitted = omitted
    }
}

public struct OmittedRule: Codable, Sendable, Equatable, Identifiable {
    public var ruleID: String
    public var reason: String
    public var id: String { ruleID }
    public init(ruleID: String, reason: String) {
        self.ruleID = ruleID
        self.reason = reason
    }
}

/// The extension's answer to `status`.
public struct StatusReport: Codable, Sendable, Equatable {
    public var extensionVersion: String
    public var coverage: CoverageLevel
    public var coverageNotes: [String]
    public var filterEnabled: Bool
    public var isolation: IsolationState
    public var installed: PolicySummary?
    public var lastKnownGood: PolicySummary?
    public var lastRejection: String?
    public var flowsSeen: UInt64
    public var flowsDenied: UInt64
    public var telemetryGaps: [GapMarker]
    public var capabilities: [CapabilityRow]

    public init(
        extensionVersion: String,
        coverage: CoverageLevel,
        coverageNotes: [String],
        filterEnabled: Bool,
        isolation: IsolationState,
        installed: PolicySummary?,
        lastKnownGood: PolicySummary?,
        lastRejection: String?,
        flowsSeen: UInt64,
        flowsDenied: UInt64,
        telemetryGaps: [GapMarker],
        capabilities: [CapabilityRow]
    ) {
        self.extensionVersion = extensionVersion
        self.coverage = coverage
        self.coverageNotes = coverageNotes
        self.filterEnabled = filterEnabled
        self.isolation = isolation
        self.installed = installed
        self.lastKnownGood = lastKnownGood
        self.lastRejection = lastRejection
        self.flowsSeen = flowsSeen
        self.flowsDenied = flowsDenied
        self.telemetryGaps = telemetryGaps
        self.capabilities = capabilities
    }
}

public struct IsolationState: Codable, Sendable, Equatable {
    public var active: Bool
    public var since: Date?
    public var reason: String?

    public init(active: Bool, since: Date? = nil, reason: String? = nil) {
        self.active = active
        self.since = since
        self.reason = reason
    }

    public static let off = IsolationState(active: false)
}

/// A hole in the event sequence (spool overflow or extension restart). Shown, never hidden.
public struct GapMarker: Codable, Sendable, Equatable {
    public var fromSeq: UInt64
    public var toSeq: UInt64
    public var reason: String

    public init(fromSeq: UInt64, toSeq: UInt64, reason: String) {
        self.fromSeq = fromSeq
        self.toSeq = toSeq
        self.reason = reason
    }
}
