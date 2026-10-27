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
/// * The first revision on a Mac cannot be a canary: there is nothing to roll back to. The refusal writes nothing
///   (the same contract as moatd's `first_revision_cannot_be_a_trial`).
/// * Nothing here changes trust. Trusted keys are owner configuration read by the verifier.
public final class PolicyStore: @unchecked Sendable {
    public struct Entry: Codable, Equatable, Sendable {
        public var signed: Data
        public var summary: PolicySummary
        public var policyJSON: Data
        /// When this snapshot first passed verification. Restoration re-verifies it as of this time (signature and
        /// trust are checked as they are now; admission validity as it was when it was accepted).
        public var verifiedAt: Date?

        public init(signed: Data, summary: PolicySummary, policyJSON: Data, verifiedAt: Date? = nil) {
            self.signed = signed
            self.summary = summary
            self.policyJSON = policyJSON
            self.verifiedAt = verifiedAt
        }
    }

    /// The result of restoring persisted state at start or after a trust change.
    public enum Restoration: Equatable, Sendable {
        case nothingInstalled
        case verified(revision: UInt64)
        case fellBack(from: UInt64?, to: UInt64, reason: String)
        case failed(reason: String)

        public var label: String {
            switch self {
            case .nothingInstalled: return "No policy was installed."
            case let .verified(r): return "Restored revision \(r) after re-verifying its signature under the current trusted keys."
            case let .fellBack(from, to, reason): return "Revision \(from.map(String.init) ?? "?") could not be restored (\(reason)); revision \(to) was re-verified and restored instead."
            case let .failed(reason): return "No installed revision could be restored (\(reason)). Nothing is enforced; Moat is observing only until a valid signed policy is applied."
            }
        }
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
    private var verifier: SnapshotVerifier
    private var state: State
    private var persistError: String?

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
    /// What a canary applied now would roll back to: the installed revision when it is confirmed, otherwise (a canary
    /// is already pending) the last known good. `nil` means a canary has no fallback and must be refused.
    public var canaryFallback: Entry? { locked { state.canaryDeadline == nil ? state.installed : state.lastKnownGood } }
    /// The refusal for a canary without a fallback.
    public static let firstCanaryRefusal = "The first revision on this Mac cannot be a canary: there is no earlier revision to roll back to. Nothing was installed. Apply it without a canary; later changes can be trialled."
    public var lastRejection: String? { locked { state.lastRejection } }
    /// Set when the last state change could not be written to disk: it is enforced in memory but not durable.
    public var lastPersistError: String? { locked { persistError } }

    /// Replace the verifier (e.g. after the trusted keys changed). Does not re-verify anything by itself.
    public func setVerifier(_ v: SnapshotVerifier) {
        lock.lock()
        verifier = v
        lock.unlock()
    }

    /// Verify a candidate without changing any state. A rejection is recorded for status.
    public func prepare(signed: Data, now: Date = Date()) -> Result<Entry, VerificationFailure> {
        lock.lock()
        defer { lock.unlock() }
        switch verifier.verify(signed: signed, lastApplied: state.lastApplied, now: now) {
        case let .failure(f):
            state.lastRejection = "Rejected at \(Self.stamp(now)): \(f.message)"
            persist()
            return .failure(f)
        case let .success(v):
            return .success(Entry(signed: signed, summary: v.summary, policyJSON: v.policyJSON, verifiedAt: now))
        }
    }

    /// Install a prepared candidate. Call only after the evaluator for it was built successfully.
    /// Returns whether the new state was written to disk.
    @discardableResult
    public func commit(_ entry: Entry, canary: TimeInterval = 0, now: Date = Date()) -> Bool {
        lock.lock()
        defer { lock.unlock() }
        // Only a confirmed (non-canary) installed revision becomes last known good.
        if let cur = state.installed, state.canaryDeadline == nil {
            state.lastKnownGood = cur
        }
        state.installed = entry
        state.lastApplied = max(state.lastApplied ?? 0, entry.summary.revision)
        state.canaryDeadline = canary > 0 ? now.addingTimeInterval(canary) : nil
        state.lastRejection = nil
        return persist()
    }

    /// Re-verify an entry under the current verifier as of the time it was first accepted.
    private func reverify(_ e: Entry) -> String? {
        switch verifier.verify(signed: e.signed, lastApplied: nil, now: e.verifiedAt ?? e.summary.appliedAt) {
        case let .failure(f): return f.message
        case let .success(v):
            if v.summary.revision != e.summary.revision { return "stored revision \(e.summary.revision) does not match the signed revision \(v.summary.revision)" }
            if v.policyJSON != e.policyJSON { return "stored policy does not match the signed policy" }
            return nil
        }
    }

    /// Restore the installed entry only if it still verifies (signature, current trust, integrity); otherwise the last
    /// known good if that verifies; otherwise nothing, reported as a failure. Never installs unverified state.
    /// `usable` lets the caller also refuse an entry its evaluator cannot load.
    public func restoreVerified(usable: (Entry) -> String? = { _ in nil }) -> (Restoration, Entry?) {
        lock.lock()
        defer { lock.unlock() }
        guard let cur = state.installed else { return (.nothingInstalled, nil) }
        let why = reverify(cur) ?? usable(cur)
        if why == nil { return (.verified(revision: cur.summary.revision), cur) }
        if let good = state.lastKnownGood, reverify(good) == nil, usable(good) == nil {
            state.installed = good
            state.canaryDeadline = nil
            state.lastRejection = "Revision \(cur.summary.revision) failed re-verification (\(why!)); restored revision \(good.summary.revision)."
            persist()
            return (.fellBack(from: cur.summary.revision, to: good.summary.revision, reason: why!), good)
        }
        state.lastRejection = "Revision \(cur.summary.revision) failed re-verification (\(why!)) and no last known good revision verifies."
        persist()
        return (.failed(reason: why!), nil)
    }

    /// Verify and install in one step (no evaluator check). Prefer prepare + commit.
    public func apply(signed: Data, canary: TimeInterval = 0, now: Date = Date()) -> Result<PolicySummary, VerificationFailure> {
        if canary > 0, canaryFallback == nil {
            return .failure(VerificationFailure(kind: "first_canary", message: Self.firstCanaryRefusal))
        }
        switch prepare(signed: signed, now: now) {
        case let .failure(f): return .failure(f)
        case let .success(e):
            commit(e, canary: canary, now: now)
            return .success(e.summary)
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
            // Only reachable from state written before first canaries were refused: say so instead of going quiet.
            if state.canaryDeadline != nil, let cur = state.installed {
                state.lastRejection = "The canary deadline for revision \(cur.summary.revision) passed, but there is no earlier revision to roll back to; revision \(cur.summary.revision) stays enforced (\(why))."
            }
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

    /// Write state atomically. On failure the change stays in memory (enforcement does not depend on the disk) and
    /// `lastPersistError` says it is not durable; it is never reported as a durable success.
    @discardableResult
    private func persist() -> Bool {
        guard let url else { return true }
        do {
            try FileManager.default.createDirectory(at: url.deletingLastPathComponent(), withIntermediateDirectories: true)
            let data = try Self.encoder.encode(state)
            try data.write(to: url, options: [.atomic])
            persistError = nil
            return true
        } catch {
            persistError = "Could not persist policy state: \(error.localizedDescription). The change is enforced now but will not survive a restart."
            return false
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
