import Foundation

/// The result an evaluator returns for one flow under the installed policy.
public struct EvaluatedDecision: Sendable, Equatable {
    public var verdict: Verdict
    public var summary: String
    public var ruleID: String?
    /// The winning profile is in observe mode: the verdict is "allow" only because nothing is enforced.
    public var permittedByObservation: Bool
    public var notes: [String]

    public init(verdict: Verdict, summary: String, ruleID: String? = nil, permittedByObservation: Bool = false, notes: [String] = []) {
        self.verdict = verdict
        self.summary = summary
        self.ruleID = ruleID
        self.permittedByObservation = permittedByObservation
        self.notes = notes
    }
}

/// Evaluates flows against one installed policy. The production implementation calls moat-core through the
/// C ABI (MoatCoreBridge.CoreEvaluator); tests use fakes.
public protocol PolicyEvaluator: Sendable {
    func evaluate(_ flow: FlowFacts, deviceID: String) throws -> EvaluatedDecision
}

/// A small bounded TTL cache of decisions, cleared whenever the policy or isolation state changes.
public struct VerdictCache {
    public let capacity: Int
    public let ttl: TimeInterval
    private var entries: [String: (decision: FlowDecision, expires: Date)] = [:]
    private var order: [String] = []

    public init(capacity: Int = 4096, ttl: TimeInterval = 30) {
        self.capacity = max(1, capacity)
        self.ttl = ttl
    }

    public var count: Int { entries.count }

    public mutating func get(_ key: String, now: Date) -> FlowDecision? {
        guard let e = entries[key] else { return nil }
        if e.expires <= now {
            entries[key] = nil
            order.removeAll { $0 == key }
            return nil
        }
        return e.decision
    }

    public mutating func put(_ key: String, _ d: FlowDecision, now: Date) {
        if entries[key] == nil {
            order.append(key)
        }
        entries[key] = (d, now.addingTimeInterval(ttl))
        while entries.count > capacity, let oldest = order.first {
            order.removeFirst()
            entries[oldest] = nil
        }
    }

    public mutating func removeAll() {
        entries.removeAll()
        order.removeAll()
    }
}

/// The per-flow decision logic the Network Extension runs. Thread-safe; NEFilterDataProvider calls it from
/// arbitrary queues.
///
/// Order of precedence inside the extension (the policy's own precedence is moat-core's job):
/// 1. loopback is always permitted (local recovery and IPC keep working)
/// 2. emergency isolation denies everything else, and only a local owner action turns it off
/// 3. no installed policy: permit and record as *observation* (never presented as enforcement)
/// 4. the installed signed policy via moat-core
/// 5. evaluator failure: the configured fallback verdict, reported as degraded coverage
public final class FilterEngine: @unchecked Sendable {
    public let deviceID: String
    public let spool: EventSpool
    private let lock = NSLock()
    private var evaluator: PolicyEvaluator?
    private var installed: PolicySummary?
    private var isolation: IsolationState = .off
    private var cache: VerdictCache
    private var fallbackOnError: Verdict
    private var evaluatorErrors: UInt64 = 0
    private(set) public var flowsSeen: UInt64 = 0
    private(set) public var flowsDenied: UInt64 = 0

    public init(deviceID: String, spool: EventSpool = EventSpool(capacity: 2000), cache: VerdictCache = VerdictCache(), fallbackOnError: Verdict = .deny) {
        self.deviceID = deviceID
        self.spool = spool
        self.cache = cache
        self.fallbackOnError = fallbackOnError
    }

    // MARK: state changes

    public func install(_ summary: PolicySummary, evaluator: PolicyEvaluator, fallbackOnError: Verdict = .deny) {
        lock.lock()
        defer { lock.unlock() }
        installed = summary
        self.evaluator = evaluator
        self.fallbackOnError = fallbackOnError
        cache.removeAll()
    }

    public func uninstallPolicy() {
        lock.lock()
        defer { lock.unlock() }
        installed = nil
        evaluator = nil
        cache.removeAll()
    }

    public func setIsolation(_ state: IsolationState) {
        lock.lock()
        defer { lock.unlock() }
        isolation = state
        cache.removeAll()
    }

    public var currentIsolation: IsolationState {
        lock.lock()
        defer { lock.unlock() }
        return isolation
    }

    public var installedPolicy: PolicySummary? {
        lock.lock()
        defer { lock.unlock() }
        return installed
    }

    public var errorCount: UInt64 {
        lock.lock()
        defer { lock.unlock() }
        return evaluatorErrors
    }

    // MARK: decisions

    /// Decide a new flow and record it. Returns the decision the extension turns into an NEFilterNewFlowVerdict.
    @discardableResult
    public func decide(_ f: FlowFacts, now: Date = Date()) -> FlowDecision {
        let d = decision(for: f, now: now)
        lock.lock()
        flowsSeen &+= 1
        if d.verdict == .deny { flowsDenied &+= 1 }
        lock.unlock()
        spool.append(facts: f, decision: d, measurement: d.verdict == .deny ? .blockedBeforeData : .unknown)
        return d
    }

    private func decision(for f: FlowFacts, now: Date) -> FlowDecision {
        if f.isLoopback {
            return FlowDecision(verdict: .allow, source: .loopback, summary: "allowed: loopback is always permitted")
        }
        lock.lock()
        let iso = isolation
        let ev = evaluator
        let summary = installed
        let fallback = fallbackOnError
        if !iso.active, ev != nil, let hit = cache.get(f.cacheKey, now: now) {
            lock.unlock()
            return hit
        }
        lock.unlock()

        if iso.active {
            return FlowDecision(verdict: .deny, source: .emergencyIsolation, summary: "blocked by emergency isolation", policyRevision: summary?.revision)
        }
        guard let ev, let summary else {
            return FlowDecision(
                verdict: .allow, source: .observationNoPolicy,
                summary: "permitted (observation, no signed policy installed)",
                notes: ["Nothing is enforced until a signed policy is applied."])
        }
        let d: FlowDecision
        do {
            let r = try ev.evaluate(f, deviceID: deviceID)
            d = FlowDecision(
                verdict: r.verdict,
                source: r.permittedByObservation ? .observationProfile : .policy,
                summary: r.summary, ruleID: r.ruleID, policyRevision: summary.revision, notes: r.notes)
        } catch {
            lock.lock()
            evaluatorErrors &+= 1
            lock.unlock()
            return FlowDecision(
                verdict: fallback, source: .evaluatorError,
                summary: fallback == .deny ? "blocked: policy evaluation failed (fallback)" : "permitted: policy evaluation failed (fallback)",
                policyRevision: summary.revision, notes: ["\(error)"])
        }
        lock.lock()
        cache.put(f.cacheKey, d, now: now)
        lock.unlock()
        return d
    }

    /// Attach byte counters from an NEFilterReport to the recorded flow, when macOS delivers one.
    public func report(flowID: String, outbound: UInt64, inbound: UInt64) {
        spool.updateMeasurement(flowID: flowID, .reported(outbound: outbound, inbound: inbound))
    }

    /// Coverage the endpoint can honestly claim right now.
    public func coverage(filterEnabled: Bool) -> (CoverageLevel, [String]) {
        lock.lock()
        defer { lock.unlock() }
        var notes: [String] = []
        if !filterEnabled {
            return (.degraded, ["The content filter is not enabled in System Settings, so no traffic is seen."])
        }
        if isolation.active {
            return (.isolated, ["Isolation stays on until you turn it off here. It does not reopen if the controller goes away."])
        }
        if evaluatorErrors > 0 {
            notes.append("\(evaluatorErrors) flow(s) hit an evaluation error and used the fallback verdict.")
        }
        let gaps = spool.gaps
        if !gaps.isEmpty {
            notes.append("\(gaps.count) telemetry gap(s): some events were not recorded. Enforcement is independent of logging.")
        }
        guard installed != nil else {
            notes.insert("No signed policy is installed. Moat is observing only.", at: 0)
            return (.observed, notes)
        }
        notes.append("Process ancestry is not available on macOS without Endpoint Security; rules match the app that opened the socket.")
        return (evaluatorErrors > 0 ? .degraded : .enforced, notes)
    }
}
