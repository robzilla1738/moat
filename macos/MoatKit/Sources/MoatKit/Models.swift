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

/// The process that actually opened the socket (NEFilterFlow.sourceProcessAuditToken), kept separate from the
/// responsible app. `pidVersion` is the audit token's per-process generation, so a reused pid is not the same process.
public struct ProcessIdentity: Codable, Sendable, Equatable {
    public var signingID: String?
    public var teamID: String?
    public var executable: String?
    public var pid: Int32?
    public var pidVersion: Int32?

    public init(signingID: String? = nil, teamID: String? = nil, executable: String? = nil, pid: Int32? = nil, pidVersion: Int32? = nil) {
        self.signingID = signingID
        self.teamID = teamID
        self.executable = executable
        self.pid = pid
        self.pidVersion = pidVersion
    }
}

/// What the Network Extension can tell us about one outbound flow, before a verdict.
///
/// `signingID`/`teamID`/`executable`/`pid` describe the *responsible app* (NEFilterFlow.sourceAppAuditToken): the
/// identity app rules match and Activity groups by. `process` is the process that actually opened the socket
/// (sourceProcessAuditToken), recorded as evidence and never merged into the app identity. When macOS does not
/// provide a separate process token, `process` is nil and the UI says the actual process is unknown. The extension
/// does not see ancestry: without the Endpoint Security entitlement, ancestry is unavailable and the UI says so.
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
    /// The actual socket process, when it differs from or is reported separately from the responsible app.
    public var process: ProcessIdentity?

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
        at: Date = Date(),
        process: ProcessIdentity? = nil
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
        self.process = process
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
        [signingID ?? "", teamID ?? "", executable ?? "", process?.signingID ?? "", process?.executable ?? "", remoteHost ?? "", remoteIP, String(remotePort), transport.rawValue]
            .joined(separator: "|")
    }

    /// True when macOS reported a socket process whose identity differs from the responsible app.
    public var processDiffersFromApp: Bool {
        guard let p = process else { return false }
        return (p.signingID != nil && p.signingID != signingID) || (p.executable != nil && p.executable != executable)
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
    /// Emergency isolation is on: every new outbound flow except loopback is denied until the owner turns it off locally.
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
    /// State could not be reconciled after a restart or failed activation; the owner must recover at the device.
    case recoveryRequired = "recovery-required"
    /// A trial rollback could not reinstall the fallback; the trial revision is still the one in force.
    case rollbackPending = "rollback-pending"
    case unknown

    /// An unrecognised label is shown as unknown, never as the closest-looking healthy state.
    public init(from decoder: Decoder) throws {
        let raw = try decoder.singleValueContainer().decode(String.self)
        self = CoverageLevel(rawValue: raw) ?? .unknown
    }

    /// Needs the owner at this device; no remote action or waiting clears it.
    public var needsOwnerAtDevice: Bool { self == .recoveryRequired || self == .rollbackPending }

    public var label: String {
        switch self {
        case .observed: return "Observing"
        case .enforced: return "Enforcing"
        case .degraded: return "Degraded"
        case .isolated: return "Isolated"
        case .recoveryRequired: return "Recovery required"
        case .rollbackPending: return "Rollback pending"
        case .unknown: return "Unknown"
        }
    }

    /// The one-line claim. Deliberately narrow: no containment, ancestry or fail-closed promises on macOS.
    public var claim: String {
        switch self {
        case .observed: return "Activity is visible. Nothing is being blocked."
        case .enforced: return "App rules from your signed policy are enforced by the content filter."
        case .degraded: return "Coverage is reduced. See what is wrong below."
        case .isolated: return "Emergency isolation: new outbound connections except loopback are blocked until you turn it off here. Connections already open are not cut."
        case .recoveryRequired: return "Moat could not reconcile its saved state. Recover here with owner authentication; nothing is guessed or reinstalled on its own."
        case .rollbackPending: return "A rollback could not reinstall the previous revision, so the trial revision is still enforced. Recover here with owner authentication."
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
        .init(key: "process_identity", label: "Process identity", support: .untested, note: "Responsible app and socket process audit tokens via NEFilterFlow, kept separate"),
        .init(key: "process_scoped_grants", label: "Process-scoped permissions", support: .unsupported, note: "Unavailable until process-generation capture and enforcement are proven; app-on-device permissions are offered instead"),
        .init(key: "isolation_new_flows", label: "Isolation (new connections)", support: .untested, note: "Blocks new outbound flows; already-open flows and inbound flows are not cut"),
        .init(key: "app_enforcement", label: "App enforcement", support: .untested, note: "NEFilterDataProvider verdicts per flow"),
        .init(key: "hostname_enforcement", label: "Hostname rules", support: .partial, note: "Only when the flow exposes a hostname; IP otherwise"),
        .init(key: "byte_counters", label: "Byte counters", support: .partial, note: "NEFilterReport counters under specific reporting conditions"),
        .init(key: "ipv6_enforcement", label: "IPv6", support: .untested, note: nil),
        .init(key: "udp_enforcement", label: "UDP / QUIC", support: .untested, note: "QUIC requires device proof"),
        .init(key: "ancestor_attribution", label: "Process ancestry", support: .unsupported, note: "Needs the Endpoint Security entitlement"),
        .init(key: "session_enforcement", label: "Protected sessions", support: .unsupported, note: "No tested macOS session boundary; session rules are omitted with a report"),
        .init(key: "existing_flow_revocation", label: "Revoke open flows", support: .unsupported, note: "Not implemented: a new verdict does not cut an open flow"),
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
    /// The evaluator generation decisions are made with, and the trust generation it was verified under.
    public var evaluatorGeneration: UInt64?
    public var trustGeneration: UInt64?
    /// False when the installed state is enforced in memory but could not be written to disk.
    public var durable: Bool?
    /// What happened when the extension restored its state at start (verified, fell back, or failed).
    public var restoration: String?

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
        capabilities: [CapabilityRow],
        evaluatorGeneration: UInt64? = nil,
        trustGeneration: UInt64? = nil,
        durable: Bool? = nil,
        restoration: String? = nil
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
        self.evaluatorGeneration = evaluatorGeneration
        self.trustGeneration = trustGeneration
        self.durable = durable
        self.restoration = restoration
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

/// Lifecycle events other Moat endpoints report (Linux moatd, W05/W06), as the fleet companion shows them. This Mac
/// does not emit them itself; they arrive from the controller's activity for enrolled devices. Every field is the
/// endpoint's own report: nothing here is inferred, and none of these events is an "allowed" or "protected" claim.
public struct EndpointLifecycleEvent: Codable, Sendable, Equatable, Identifiable {
    public enum Kind: String, Codable, Sendable {
        /// The session egress proxy ended an admitted stream (grant expiry, revocation, session end).
        case streamTerminated = "stream_terminated"
        /// The session proxy refused a connection at a resource limit (refused, never bypassed).
        case proxyLimit = "proxy_limit"
        /// The activation journal reconciled state after a restart or failed activation.
        case activationRecovery = "activation_recovery"
        /// A protected session could not be re-adopted after a daemon restart and was stopped.
        case sessionNotAdopted = "session_not_adopted"
        case other

        public init(from decoder: Decoder) throws {
            self = Kind(rawValue: try decoder.singleValueContainer().decode(String.self)) ?? .other
        }
    }

    public var kind: Kind
    public var deviceID: String
    public var seq: UInt64
    public var sessionID: String?
    /// Reason / phase / resource text exactly as the endpoint reported it.
    public var detail: String
    /// `activation_recovery` phase (e.g. `recovery_required`, `rolled_back`), when reported.
    public var phase: String?
    public var id: String { "\(deviceID)#\(seq)" }

    public init(kind: Kind, deviceID: String, seq: UInt64, sessionID: String? = nil, detail: String, phase: String? = nil) {
        self.kind = kind
        self.deviceID = deviceID
        self.seq = seq
        self.sessionID = sessionID
        self.detail = detail
        self.phase = phase
    }

    /// Build from one endpoint spool record's `event` object; nil for event types this view does not show.
    public static func from(event e: [String: Any], deviceID: String, seq: UInt64) -> EndpointLifecycleEvent? {
        guard let t = e["type"] as? String, let kind = Kind(rawValue: t) else { return nil }
        let s = { (k: String) in e[k].map { "\($0)" } }
        switch kind {
        case .streamTerminated:
            return .init(kind: kind, deviceID: deviceID, seq: seq, sessionID: s("session_id"), detail: [s("hostname") ?? s("destination"), s("reason")].compactMap { $0 }.joined(separator: ": "))
        case .proxyLimit:
            return .init(kind: kind, deviceID: deviceID, seq: seq, sessionID: s("session_id"), detail: "\(s("resource") ?? "resource") limit \(s("limit") ?? "?")")
        case .activationRecovery:
            return .init(kind: kind, deviceID: deviceID, seq: seq, detail: s("detail") ?? "", phase: s("phase"))
        case .sessionNotAdopted:
            return .init(kind: kind, deviceID: deviceID, seq: seq, sessionID: s("session_id"), detail: [s("profile"), s("reason")].compactMap { $0 }.joined(separator: ": "))
        case .other:
            return nil
        }
    }

    public var title: String {
        switch kind {
        case .streamTerminated: return "Stream ended by the session proxy"
        case .proxyLimit: return "Connection refused at a proxy limit"
        case .activationRecovery: return phase == "recovery_required" ? "Recovery required at the device" : "Activation recovered after a restart"
        case .sessionNotAdopted: return "Protected session stopped after a restart"
        case .other: return "Endpoint event"
        }
    }

    /// What the event does and does not mean, in one line.
    public var meaning: String {
        switch kind {
        case .streamTerminated: return "An admitted stream was closed when its permission ended. Other open connections are not implied closed."
        case .proxyLimit: return "Refused, not bypassed: the session could not open more connections."
        case .activationRecovery: return phase == "recovery_required" ? "The endpoint keeps its last verified policy and needs the owner at the device." : "The endpoint reconciled its activation journal; the revision it reports is in force."
        case .sessionNotAdopted: return "The session's boundary could not be re-established, so the session was stopped rather than left unprotected."
        case .other: return ""
        }
    }

    public var needsOwnerAtDevice: Bool { kind == .activationRecovery && phase == "recovery_required" }
}
