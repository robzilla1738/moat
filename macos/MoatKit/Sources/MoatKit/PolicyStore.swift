import Foundation

/// A snapshot that passed signature, platform, replay, expiry and schema checks.
public struct VerifiedSnapshot: Sendable, Equatable {
    public var summary: PolicySummary
    /// The normalized policy JSON the evaluator consumes (moat-core `Policy`).
    public var policyJSON: Data

    public init(summary: PolicySummary, policyJSON: Data) {
        self.summary = summary
        self.policyJSON = policyJSON
    }
}

public struct VerificationFailure: Error, Equatable, CustomStringConvertible {
    public var kind: String
    public var message: String
    public init(kind: String, message: String) {
        self.kind = kind
        self.message = message
    }
    public var description: String { message }
}

/// Verifies signed snapshots. Production: moat-core via the C ABI with owner-configured keys (MoatCoreBridge).
public protocol SnapshotVerifier: Sendable {
    func verify(signed: Data, lastApplied: UInt64?, now: Date) -> Result<VerifiedSnapshot, VerificationFailure>
}

/// The extension's installed-policy state, persisted in a root-owned directory.
///
/// * Apply is atomic: verify first, then write; a rejected snapshot leaves the current one untouched.
/// * The replay high-water mark (`lastApplied`) never goes down, including after a local rollback, so an older
///   signed snapshot replayed from the network is still rejected.
/// * A canary apply rolls back to the last known good revision unless confirmed before its deadline.
/// * Nothing here changes trust. Trusted keys are owner configuration read by the verifier.
public final class PolicyStore: @unchecked Sendable {
    public struct Entry: Codable, Equatable, Sendable {
        public var signed: Data
        public var summary: PolicySummary
        public var policyJSON: Data
    }

    struct State: Codable {
        var installed: Entry?
        var lastKnownGood: Entry?
        var lastApplied: UInt64?
        var canaryDeadline: Date?
        var isolation: IsolationState
        var lastRejection: String?
    }

    private let lock = NSLock()
    private let url: URL?
    private let verifier: SnapshotVerifier
    private var state: State

    /// - Parameter directory: where `state.json` lives. `nil` keeps state in memory only (tests).
    public init(directory: URL?, verifier: SnapshotVerifier) {
        self.verifier = verifier
        url = directory?.appendingPathComponent("state.json")
        if let url, let data = try? Data(contentsOf: url), let s = try? Self.decoder.decode(State.self, from: data) {
            state = s
        } else {
            state = State(installed: nil, lastKnownGood: nil, lastApplied: nil, canaryDeadline: nil, isolation: .off, lastRejection: nil)
        }
    }

    public var installed: Entry? { locked { state.installed } }
    public var lastKnownGood: Entry? { locked { state.lastKnownGood } }
    public var lastApplied: UInt64? { locked { state.lastApplied } }
    public var canaryDeadline: Date? { locked { state.canaryDeadline } }
    public var isolation: IsolationState { locked { state.isolation } }
    public var lastRejection: String? { locked { state.lastRejection } }

    /// Verify and install. `canary` > 0 arms an automatic rollback after that many seconds unless confirmed.
    public func apply(signed: Data, canary: TimeInterval = 0, now: Date = Date()) -> Result<PolicySummary, VerificationFailure> {
        lock.lock()
        defer { lock.unlock() }
        switch verifier.verify(signed: signed, lastApplied: state.lastApplied, now: now) {
        case let .failure(f):
            state.lastRejection = "Rejected at \(Self.stamp(now)): \(f.message)"
            persist()
            return .failure(f)
        case let .success(v):
            let entry = Entry(signed: signed, summary: v.summary, policyJSON: v.policyJSON)
            // Only a confirmed (non-canary) installed revision becomes last known good.
            if let cur = state.installed, state.canaryDeadline == nil {
                state.lastKnownGood = cur
            }
            state.installed = entry
            state.lastApplied = max(state.lastApplied ?? 0, v.summary.revision)
            state.canaryDeadline = canary > 0 ? now.addingTimeInterval(canary) : nil
            state.lastRejection = nil
            persist()
            return .success(v.summary)
        }
    }

    public func confirmCanary() -> Bool {
        lock.lock()
        defer { lock.unlock() }
        guard state.canaryDeadline != nil else { return false }
        state.canaryDeadline = nil
        persist()
        return true
    }

    /// Roll back when a canary deadline passed. Returns the reinstated summary, if a rollback happened.
    /// Never touches isolation.
    public func tick(now: Date = Date()) -> PolicySummary? {
        lock.lock()
        defer { lock.unlock() }
        guard let deadline = state.canaryDeadline, deadline <= now else { return nil }
        return rollbackLocked(now: now, why: "canary not confirmed before \(Self.stamp(deadline))")
    }

    /// Local owner recovery: reinstate the last known good revision.
    public func rollbackToLastKnownGood(now: Date = Date()) -> PolicySummary? {
        lock.lock()
        defer { lock.unlock() }
        return rollbackLocked(now: now, why: "local recovery")
    }

    private func rollbackLocked(now: Date, why: String) -> PolicySummary? {
        guard var good = state.lastKnownGood else {
            state.canaryDeadline = nil
            persist()
            return nil
        }
        good.summary.rollbackOf = state.installed?.summary.revision
        good.summary.appliedAt = now
        state.installed = good
        state.canaryDeadline = nil
        state.lastRejection = "Rolled back to revision \(good.summary.revision) (\(why))."
        // lastApplied (the replay high-water mark) intentionally stays where it is.
        persist()
        return good.summary
    }

    public func setIsolation(_ iso: IsolationState) {
        lock.lock()
        defer { lock.unlock() }
        state.isolation = iso
        persist()
    }

    // MARK: persistence

    private func persist() {
        guard let url else { return }
        do {
            try FileManager.default.createDirectory(at: url.deletingLastPathComponent(), withIntermediateDirectories: true)
            let data = try Self.encoder.encode(state)
            try data.write(to: url, options: [.atomic])
        } catch {
            // Enforcement does not depend on persistence succeeding; the next status report shows the failure.
            state.lastRejection = "Could not persist policy state: \(error.localizedDescription)"
        }
    }

    private func locked<T>(_ f: () -> T) -> T {
        lock.lock()
        defer { lock.unlock() }
        return f()
    }

    static let encoder: JSONEncoder = {
        let e = JSONEncoder()
        e.dateEncodingStrategy = .iso8601
        e.outputFormatting = [.sortedKeys]
        return e
    }()

    static let decoder: JSONDecoder = {
        let d = JSONDecoder()
        d.dateDecodingStrategy = .iso8601
        return d
    }()

    static func stamp(_ d: Date) -> String {
        ISO8601DateFormatter().string(from: d)
    }
}
