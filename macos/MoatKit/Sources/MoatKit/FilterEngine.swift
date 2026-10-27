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

/// One installed policy generation: the evaluator, its summary and the time boundaries at which its answers can
/// change. Immutable: a new policy, a trust change or a restoration always produces a new generation, so nothing
/// computed under an older one can be mistaken for current.
public final class EvaluatorGeneration: @unchecked Sendable {
    public let generation: UInt64
    public let trustGeneration: UInt64
    public let summary: PolicySummary
    public let evaluator: PolicyEvaluator
    public let fallbackOnError: Verdict
    /// Every rule expiry in the policy, ascending. A decision can only be reused until the next one.
    public let expiries: [Date]

    public init(generation: UInt64, trustGeneration: UInt64, summary: PolicySummary, evaluator: PolicyEvaluator, fallbackOnError: Verdict, expiries: [Date]) {
        self.generation = generation
        self.trustGeneration = trustGeneration
        self.summary = summary
        self.evaluator = evaluator
        self.fallbackOnError = fallbackOnError
        self.expiries = expiries.sorted()
    }

    /// The first moment after `t` at which a timed rule starts or stops applying.
    public func nextBoundary(after t: Date) -> Date? {
        expiries.first { $0 > t }
    }
}

/// Rule expiries from a normalized moat-core policy (`rules[].expires_at`).
public enum PolicyExpiries {
    public static func from(policyJSON: Data) -> [Date] {
        guard let obj = try? JSONSerialization.jsonObject(with: policyJSON) as? [String: Any], let rules = obj["rules"] as? [[String: Any]] else { return [] }
        let frac = ISO8601DateFormatter()
        frac.formatOptions = [.withInternetDateTime, .withFractionalSeconds]
        let plain = ISO8601DateFormatter()
        return rules.compactMap { $0["expires_at"] as? String }.compactMap { frac.date(from: $0) ?? plain.date(from: $0) }.sorted()
    }
}

/// A small bounded cache of decisions. Entries belong to one evaluator generation and never outlive the next time
/// boundary of that generation's timed rules, so a cached allow cannot extend a grant past its deadline.
public struct VerdictCache {
    public let capacity: Int
    public let ttl: TimeInterval
    private var entries: [String: (decision: FlowDecision, generation: UInt64, expires: Date)] = [:]
    private var order: [String] = []

    public init(capacity: Int = 4096, ttl: TimeInterval = 30) {
        self.capacity = max(1, capacity)
        self.ttl = ttl
    }

    public var count: Int { entries.count }

    public mutating func get(_ key: String, generation: UInt64, now: Date) -> FlowDecision? {
        guard let e = entries[key] else { return nil }
        if e.expires <= now || e.generation != generation {
            entries[key] = nil
            order.removeAll { $0 == key }
            return nil
        }
        return e.decision
    }

    /// Store a decision for `generation` until `min(now + ttl, boundary)`. A boundary at or before `now` stores nothing.
    public mutating func put(_ key: String, _ d: FlowDecision, generation: UInt64, now: Date, boundary: Date?) {
        var expires = now.addingTimeInterval(ttl)
        if let b = boundary, b < expires { expires = b }
        guard expires > now else { return }
        if entries[key] == nil {
            order.append(key)
        }
        entries[key] = (d, generation, expires)
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
/// 2. emergency isolation denies every *new* outbound flow, and only a local owner action turns it off
/// 3. no installed policy: permit and record as *observation* (never presented as enforcement)
/// 4. the installed signed policy via moat-core, through one immutable evaluator generation
/// 5. evaluator failure: the configured fallback verdict, reported as degraded coverage
///
/// A decision is computed against the generation that was current when the flow arrived. It is cached only if that
/// generation is still current when the answer is ready, so a concurrent apply cannot leave an obsolete allow behind.
public final class FilterEngine: @unchecked Sendable {
    public let deviceID: String
    public let spool: EventSpool
    private let lock = NSLock()
    private var current: EvaluatorGeneration?
    private var generationCounter: UInt64 = 0
    private var isolation: IsolationState = .off
    private var cache: VerdictCache
    private var evaluatorErrors: UInt64 = 0
    private(set) public var flowsSeen: UInt64 = 0
    private(set) public var flowsDenied: UInt64 = 0

    public init(deviceID: String, spool: EventSpool = EventSpool(capacity: 2000), cache: VerdictCache = VerdictCache(), fallbackOnError: Verdict = .deny) {
        self.deviceID = deviceID
        self.spool = spool
        self.cache = cache
        _ = fallbackOnError
    }

    // MARK: state changes

    /// Install a new generation. Returns its number. The previous generation's cached answers are discarded.
    @discardableResult
    public func install(_ summary: PolicySummary, evaluator: PolicyEvaluator, fallbackOnError: Verdict = .deny, expiries: [Date] = [], trustGeneration: UInt64 = 0) -> UInt64 {
        lock.lock()
        defer { lock.unlock() }
        generationCounter &+= 1
        current = EvaluatorGeneration(generation: generationCounter, trustGeneration: trustGeneration, summary: summary, evaluator: evaluator, fallbackOnError: fallbackOnError, expiries: expiries)
        cache.removeAll()
        return generationCounter
    }

    public func uninstallPolicy() {
        lock.lock()
        defer { lock.unlock() }
        generationCounter &+= 1
        current = nil
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
        return current?.summary
    }

    /// The generation decisions are currently made with (nil when no policy is installed).
    public var currentGeneration: EvaluatorGeneration? {
        lock.lock()
        defer { lock.unlock() }
        return current
    }

    public var errorCount: UInt64 {
        lock.lock()
        defer { lock.unlock() }
        return evaluatorErrors
    }

    public var cachedDecisions: Int {
        lock.lock()
        defer { lock.unlock() }
        return cache.count
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
        let gen = current
        if !iso.active, let gen, let hit = cache.get(f.cacheKey, generation: gen.generation, now: now) {
            lock.unlock()
            return hit
        }
        lock.unlock()

        if iso.active {
            return FlowDecision(verdict: .deny, source: .emergencyIsolation, summary: "blocked by emergency isolation", policyRevision: gen?.summary.revision)
        }
        guard let gen else {
            return FlowDecision(
                verdict: .allow, source: .observationNoPolicy,
                summary: "permitted (observation, no signed policy installed)",
                notes: ["Nothing is enforced until a signed policy is applied."])
        }
        let d: FlowDecision
        do {
            var facts = f
            facts.at = now
            let r = try gen.evaluator.evaluate(facts, deviceID: deviceID)
            d = FlowDecision(
                verdict: r.verdict,
                source: r.permittedByObservation ? .observationProfile : .policy,
                summary: r.summary, ruleID: r.ruleID, policyRevision: gen.summary.revision, notes: r.notes)
        } catch {
            lock.lock()
            evaluatorErrors &+= 1
            lock.unlock()
            return FlowDecision(
                verdict: gen.fallbackOnError, source: .evaluatorError,
                summary: gen.fallbackOnError == .deny ? "blocked: policy evaluation failed (fallback)" : "permitted: policy evaluation failed (fallback)",
                policyRevision: gen.summary.revision, notes: ["\(error)"])
        }
        lock.lock()
        // Only cache if the generation that produced the answer is still the current one and nothing isolated us.
        if current?.generation == gen.generation, !isolation.active {
            cache.put(f.cacheKey, d, generation: gen.generation, now: now, boundary: gen.nextBoundary(after: now))
        }
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
            return (.isolated, ["New outbound connections are blocked until you turn isolation off here. It does not reopen if the controller goes away.", "Connections that were already open when isolation started, and incoming connections, are not cut by the content filter."])
        }
        if evaluatorErrors > 0 {
            notes.append("\(evaluatorErrors) flow(s) hit an evaluation error and used the fallback verdict.")
        }
        let gaps = spool.gaps
        if !gaps.isEmpty {
            notes.append("\(gaps.count) telemetry gap(s): some events were not recorded. Enforcement is independent of logging.")
        }
        guard current != nil else {
            notes.insert("No signed policy is installed. Moat is observing only.", at: 0)
            return (.observed, notes)
        }
        notes.append("Process ancestry is not available on macOS without Endpoint Security; rules match the app that opened the socket.")
        return (evaluatorErrors > 0 ? .degraded : .enforced, notes)
    }
}
