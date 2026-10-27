import Foundation

// MARK: - The privileged surface

/// The complete control surface the system extension exposes over XPC. Typed operations only: there is no
/// "run command", no free-form rule string, no script, and no operation that adds or changes trusted keys.
/// Policy content only enters as a *signed* snapshot that the extension verifies itself.
///
/// Every reply is `(json, error)`: JSON-encoded payload on success, a human-readable error otherwise.
@objc public protocol MoatControlXPC {
    func status(reply: @escaping (Data?, String?) -> Void)
    func recentFlows(limit: Int, reply: @escaping (Data?, String?) -> Void)
    func applySignedSnapshot(_ signed: Data, canarySeconds: Int, reply: @escaping (Data?, String?) -> Void)
    func confirmCanary(reply: @escaping (Data?, String?) -> Void)
    func rollbackToLastKnownGood(reply: @escaping (Data?, String?) -> Void)
    func enterIsolation(reason: String, reply: @escaping (Data?, String?) -> Void)
    func exitIsolation(confirmation: String, reply: @escaping (Data?, String?) -> Void)
    func reloadTrust(reply: @escaping (Data?, String?) -> Void)
}

/// The same operations as a closed Swift enum: what the handler executes and what the audit log records.
public enum ControlOperation: Equatable, Sendable {
    case status
    case recentFlows(limit: Int)
    case applySignedSnapshot(Data, canarySeconds: Int)
    case confirmCanary
    case rollbackToLastKnownGood
    case enterIsolation(reason: String)
    case exitIsolation(confirmation: String)
    /// Re-read the root-owned trusted-keys file and re-verify the installed policy under it. Adds no trust itself.
    case reloadTrust

    public var name: String {
        switch self {
        case .status: return "status"
        case .recentFlows: return "recent_flows"
        case .applySignedSnapshot: return "apply_signed_snapshot"
        case .confirmCanary: return "confirm_canary"
        case .rollbackToLastKnownGood: return "rollback_to_last_known_good"
        case .enterIsolation: return "enter_isolation"
        case .exitIsolation: return "exit_isolation"
        case .reloadTrust: return "reload_trust"
        }
    }

    /// Read-only operations do not change enforcement.
    public var isReadOnly: Bool {
        switch self {
        case .status, .recentFlows: return true
        default: return false
        }
    }
}

public struct ControlError: Error, Equatable, CustomStringConvertible {
    public var message: String
    public init(_ m: String) { message = m }
    public var description: String { message }
}

public struct AuditEntry: Codable, Equatable, Sendable {
    public var at: Date
    public var operation: String
    public var ok: Bool
    public var detail: String
}

/// Executes control operations against the extension's state. Holds no XPC types, so it is unit-tested directly.
public final class ControlHandler: @unchecked Sendable {
    /// Typed exactly by the owner in the recovery UI to leave isolation. Deliberately not a yes/no click.
    public static let exitPhrase = "turn isolation off"
    public static let maxRecentFlows = 500
    public static let maxSnapshotBytes = 4 * 1024 * 1024
    public static let maxCanarySeconds = 24 * 3600

    public let engine: FilterEngine
    public let store: PolicyStore
    public let version: String
    private let makeEvaluator: (Data) throws -> PolicyEvaluator
    private let filterEnabled: () -> Bool
    private let trust: TrustStore?
    private let makeVerifier: ((TrustConfig) -> SnapshotVerifier)?
    private let lock = NSLock()
    private var audit: [AuditEntry] = []
    private var loadError: String?
    private var restoration: String?

    private func setLoadError(_ e: String?) {
        lock.lock()
        loadError = e
        lock.unlock()
    }

    /// - Parameters:
    ///   - trust: the trusted-keys file as the running extension sees it; when set, `tick()` and `reloadTrust`
    ///     push changes to the verifier and re-verify what is installed.
    ///   - makeVerifier: builds the snapshot verifier for a trust configuration (production: moat-core).
    public init(engine: FilterEngine, store: PolicyStore, version: String, filterEnabled: @escaping () -> Bool, makeEvaluator: @escaping (Data) throws -> PolicyEvaluator, trust: TrustStore? = nil, makeVerifier: ((TrustConfig) -> SnapshotVerifier)? = nil) {
        self.engine = engine
        self.store = store
        self.version = version
        self.filterEnabled = filterEnabled
        self.makeEvaluator = makeEvaluator
        self.trust = trust
        self.makeVerifier = makeVerifier
        if let trust, let makeVerifier { store.setVerifier(makeVerifier(trust.config)) }
    }

    private var trustGeneration: UInt64 { trust?.generation ?? 0 }

    /// Restore persisted state into the engine at extension start. Isolation survives restarts. The installed
    /// policy is re-verified under the current trusted keys before it is enforced again; a candidate that no longer
    /// verifies (corrupt, untrusted, tampered) is not restored. See `PolicyStore.Restoration`.
    public func restore() {
        engine.setIsolation(store.isolation)
        reinstallVerified()
    }

    private func reinstallVerified() {
        var built: (Data, PolicyEvaluator)?
        let (outcome, entry) = store.restoreVerified(usable: { e in
            do {
                built = (e.policyJSON, try self.makeEvaluator(e.policyJSON))
                return nil
            } catch {
                return "its evaluator could not be loaded: \(error)"
            }
        })
        lock.lock()
        restoration = outcome.label
        lock.unlock()
        if let entry, let b = built, b.0 == entry.policyJSON {
            engine.install(entry.summary, evaluator: b.1, expiries: PolicyExpiries.from(policyJSON: entry.policyJSON), trustGeneration: trustGeneration)
            setLoadError(nil)
        } else if let entry {
            installIntoEngine(entry)
        } else if case .failed = outcome {
            engine.uninstallPolicy()
            setLoadError(outcome.label)
        }
    }

    /// Re-read the trusted keys; when they changed, give the verifier the new keys and re-verify the installed
    /// policy. Returns whether anything changed.
    @discardableResult
    public func reloadTrustIfChanged() -> Bool {
        guard let trust, let makeVerifier, trust.reloadIfChanged() else { return false }
        store.setVerifier(makeVerifier(trust.config))
        reinstallVerified()
        return true
    }

    public var auditLog: [AuditEntry] {
        lock.lock()
        defer { lock.unlock() }
        return audit
    }

    public func perform(_ op: ControlOperation, now: Date = Date()) -> Result<Data, ControlError> {
        let r = execute(op, now: now)
        if !op.isReadOnly {
            let detail: String
            switch r {
            case .success: detail = "ok"
            case let .failure(e): detail = e.message
            }
            lock.lock()
            audit.append(AuditEntry(at: now, operation: op.name, ok: (try? r.get()) != nil, detail: detail))
            if audit.count > 200 { audit.removeFirst(audit.count - 200) }
            lock.unlock()
        }
        return r
    }

    private func execute(_ op: ControlOperation, now: Date) -> Result<Data, ControlError> {
        switch op {
        case .status:
            return encode(status())
        case let .recentFlows(limit):
            guard limit > 0, limit <= Self.maxRecentFlows else { return .failure(ControlError("limit must be 1...\(Self.maxRecentFlows)")) }
            return encode(engine.spool.recent(limit: limit))
        case let .applySignedSnapshot(data, canary):
            guard data.count <= Self.maxSnapshotBytes else { return .failure(ControlError("snapshot is larger than \(Self.maxSnapshotBytes) bytes")) }
            guard canary >= 0, canary <= Self.maxCanarySeconds else { return .failure(ControlError("canary must be 0...\(Self.maxCanarySeconds) seconds")) }
            // Candidate first: verify, then build its evaluator. Only a candidate that passes both replaces the running
            // generation; a failed candidate leaves the previous evaluator and state exactly as they were.
            switch store.prepare(signed: data, now: now) {
            case let .failure(f):
                return .failure(ControlError("Rejected; the current policy is unchanged. \(f.message)"))
            case let .success(entry):
                let ev: PolicyEvaluator
                do {
                    ev = try makeEvaluator(entry.policyJSON)
                } catch {
                    return .failure(ControlError("Rejected; the current policy is unchanged. The verified policy could not be loaded by the evaluator: \(error)"))
                }
                let durable = store.commit(entry, canary: TimeInterval(canary), now: now)
                engine.install(entry.summary, evaluator: ev, expiries: PolicyExpiries.from(policyJSON: entry.policyJSON), trustGeneration: trustGeneration)
                setLoadError(nil)
                if !durable {
                    return .failure(ControlError("Revision \(entry.summary.revision) is enforced now, but it could not be saved and will not survive a restart. \(store.lastPersistError ?? "")"))
                }
                return encode(entry.summary)
            }
        case .confirmCanary:
            return store.confirmCanary() ? encode(["confirmed": true]) : .failure(ControlError("No canary rollout is pending."))
        case .rollbackToLastKnownGood:
            guard let good = store.lastKnownGood else {
                return .failure(ControlError("There is no last known good revision to roll back to."))
            }
            let ev: PolicyEvaluator
            do {
                ev = try makeEvaluator(good.policyJSON)
            } catch {
                return .failure(ControlError("The last known good revision could not be loaded; nothing changed: \(error)"))
            }
            guard let s = store.rollbackToLastKnownGood(now: now), let e = store.installed else {
                return .failure(ControlError("There is no last known good revision to roll back to."))
            }
            engine.install(e.summary, evaluator: ev, expiries: PolicyExpiries.from(policyJSON: e.policyJSON), trustGeneration: trustGeneration)
            return encode(s)
        case let .enterIsolation(reason):
            let trimmed = String(reason.prefix(200))
            let iso = IsolationState(active: true, since: now, reason: trimmed.isEmpty ? "owner request" : trimmed)
            store.setIsolation(iso)
            engine.setIsolation(iso)
            return encode(iso)
        case let .exitIsolation(confirmation):
            guard confirmation.trimmingCharacters(in: .whitespacesAndNewlines).lowercased() == Self.exitPhrase else {
                return .failure(ControlError("Type \"\(Self.exitPhrase)\" to leave isolation."))
            }
            store.setIsolation(.off)
            engine.setIsolation(.off)
            return encode(IsolationState.off)
        case .reloadTrust:
            let changed = reloadTrustIfChanged()
            return encode(["changed": changed])
        }
    }

    /// Called periodically by the extension: picks up trusted-key changes and performs a due canary rollback.
    public func tick(now: Date = Date()) {
        reloadTrustIfChanged()
        if store.tick(now: now) != nil, let e = store.installed {
            installIntoEngine(e)
        }
    }

    public func status() -> StatusReport {
        let enabled = filterEnabled()
        let (cov, notes) = engine.coverage(filterEnabled: enabled)
        var allNotes = notes
        lock.lock()
        let le = loadError
        let rest = restoration
        lock.unlock()
        if let le { allNotes.insert(le, at: 0) }
        if let pe = store.lastPersistError { allNotes.insert(pe, at: 0) }
        if let d = store.canaryDeadline {
            allNotes.append("Canary rollout: rolls back automatically at \(ISO8601DateFormatter().string(from: d)) unless confirmed.")
        }
        return StatusReport(
            extensionVersion: version,
            coverage: le != nil && cov == .observed ? .degraded : cov,
            coverageNotes: allNotes,
            filterEnabled: enabled,
            isolation: engine.currentIsolation,
            // what the filter enforces now (the engine's generation), not merely what is stored on disk
            installed: engine.installedPolicy,
            lastKnownGood: store.lastKnownGood?.summary,
            lastRejection: store.lastRejection,
            flowsSeen: engine.flowsSeen,
            flowsDenied: engine.flowsDenied,
            telemetryGaps: engine.spool.gaps,
            capabilities: CapabilityRow.macOSDesign,
            evaluatorGeneration: engine.currentGeneration?.generation,
            trustGeneration: trust?.generation,
            durable: store.lastPersistError == nil,
            restoration: rest)
    }

    /// Install an already-committed entry (canary rollback). If its evaluator cannot be built, the running generation
    /// is kept and the failure is reported; nothing silently drops to observation.
    private func installIntoEngine(_ e: PolicyStore.Entry) {
        do {
            engine.install(e.summary, evaluator: try makeEvaluator(e.policyJSON), expiries: PolicyExpiries.from(policyJSON: e.policyJSON), trustGeneration: trustGeneration)
            setLoadError(nil)
        } catch {
            setLoadError("Revision \(e.summary.revision) could not be loaded by the evaluator (\(error)); the filter keeps enforcing generation \(engine.currentGeneration.map { String($0.generation) } ?? "none") (revision \(engine.installedPolicy.map { String($0.revision) } ?? "none")).")
        }
    }

    private func encode<T: Encodable>(_ v: T) -> Result<Data, ControlError> {
        do {
            return .success(try ControlCoding.encoder.encode(v))
        } catch {
            return .failure(ControlError("encode: \(error)"))
        }
    }
}

public enum ControlCoding {
    public static let encoder: JSONEncoder = {
        let e = JSONEncoder()
        e.dateEncodingStrategy = .iso8601
        return e
    }()

    public static let decoder: JSONDecoder = {
        let d = JSONDecoder()
        d.dateDecodingStrategy = .iso8601
        return d
    }()
}

// MARK: - Caller validation

public enum CallerRequirement {
    /// Code-signing requirement the extension's XPC listener demands of every caller: the Moat app, signed with the
    /// same Developer ID team. Returns nil when the team is unknown (an unsigned build): the listener then refuses
    /// every connection rather than accepting unauthenticated callers.
    public static func make(appBundleID: String, teamID: String?) -> String? {
        guard let team = teamID, isValidTeamID(team), isValidBundleID(appBundleID) else { return nil }
        return "anchor apple generic and identifier \"\(appBundleID)\" and certificate leaf[subject.OU] = \"\(team)\""
    }

    public static func isValidTeamID(_ t: String) -> Bool {
        t.count == 10 && t.allSatisfy { $0.isASCII && ($0.isUppercase || $0.isNumber) }
    }

    public static func isValidBundleID(_ b: String) -> Bool {
        !b.isEmpty && b.allSatisfy { $0.isASCII && ($0.isLetter || $0.isNumber || $0 == "." || $0 == "-") }
    }
}

// MARK: - App-side client

/// What the app's model talks to. `XPCControlClient` in production; `DemoControlClient` for previews/screenshots.
public protocol ControlClient: Sendable {
    func status() async throws -> StatusReport
    func recentFlows(limit: Int) async throws -> [FlowRecord]
    func applySignedSnapshot(_ data: Data, canarySeconds: Int) async throws -> PolicySummary
    func confirmCanary() async throws
    func rollbackToLastKnownGood() async throws -> PolicySummary
    func enterIsolation(reason: String) async throws -> IsolationState
    func exitIsolation(confirmation: String) async throws -> IsolationState
    func reloadTrust() async throws -> Bool
}

/// Talks to the extension's NEMachServiceName. Untested on a real device until a signed build exists.
public final class XPCControlClient: ControlClient, @unchecked Sendable {
    private let machServiceName: String
    private let lock = NSLock()
    private var connection: NSXPCConnection?

    public init(machServiceName: String) {
        self.machServiceName = machServiceName
    }

    private func proxy(_ fail: @escaping (Error) -> Void) -> MoatControlXPC? {
        lock.lock()
        defer { lock.unlock() }
        if connection == nil {
            let c = NSXPCConnection(machServiceName: machServiceName, options: [])
            c.remoteObjectInterface = NSXPCInterface(with: MoatControlXPC.self)
            c.invalidationHandler = { [weak self] in
                self?.lock.lock()
                self?.connection = nil
                self?.lock.unlock()
            }
            c.resume()
            connection = c
        }
        return connection?.remoteObjectProxyWithErrorHandler(fail) as? MoatControlXPC
    }

    /// Every call is bounded: a filter that stops answering is reported as unreachable, not waited on forever.
    public static let callTimeout: TimeInterval = 10

    private func call<T: Decodable>(_ type: T.Type, _ body: @escaping (MoatControlXPC, @escaping (Data?, String?) -> Void) -> Void) async throws -> T {
        try await withCheckedThrowingContinuation { (cont: CheckedContinuation<T, Error>) in
            let once = Once()
            DispatchQueue.global().asyncAfter(deadline: .now() + Self.callTimeout) {
                once.run { cont.resume(throwing: ControlError("The Moat filter did not answer within \(Int(Self.callTimeout)) s.")) }
            }
            guard let p = proxy({ err in once.run { cont.resume(throwing: ControlError("Cannot reach the Moat filter: \(err.localizedDescription)")) } }) else {
                once.run { cont.resume(throwing: ControlError("Cannot reach the Moat filter.")) }
                return
            }
            body(p) { data, error in
                once.run {
                    if let error { return cont.resume(throwing: ControlError(error)) }
                    guard let data else { return cont.resume(throwing: ControlError("empty reply")) }
                    do {
                        cont.resume(returning: try ControlCoding.decoder.decode(T.self, from: data))
                    } catch {
                        cont.resume(throwing: ControlError("Unreadable reply: \(error)"))
                    }
                }
            }
        }
    }

    public func status() async throws -> StatusReport { try await call(StatusReport.self) { $0.status(reply: $1) } }
    public func recentFlows(limit: Int) async throws -> [FlowRecord] { try await call([FlowRecord].self) { $0.recentFlows(limit: limit, reply: $1) } }
    public func applySignedSnapshot(_ data: Data, canarySeconds: Int) async throws -> PolicySummary {
        try await call(PolicySummary.self) { $0.applySignedSnapshot(data, canarySeconds: canarySeconds, reply: $1) }
    }
    public func confirmCanary() async throws { _ = try await call([String: Bool].self) { $0.confirmCanary(reply: $1) } }
    public func rollbackToLastKnownGood() async throws -> PolicySummary { try await call(PolicySummary.self) { $0.rollbackToLastKnownGood(reply: $1) } }
    public func enterIsolation(reason: String) async throws -> IsolationState { try await call(IsolationState.self) { $0.enterIsolation(reason: reason, reply: $1) } }
    public func exitIsolation(confirmation: String) async throws -> IsolationState {
        try await call(IsolationState.self) { $0.exitIsolation(confirmation: confirmation, reply: $1) }
    }
    public func reloadTrust() async throws -> Bool {
        let r = try await call([String: Bool].self) { $0.reloadTrust(reply: $1) }
        return r["changed"] ?? false
    }
}

/// Runs a closure at most once (XPC can call both the error handler and the reply).
final class Once: @unchecked Sendable {
    private let lock = NSLock()
    private var done = false
    func run(_ f: () -> Void) {
        lock.lock()
        if done {
            lock.unlock()
            return
        }
        done = true
        lock.unlock()
        f()
    }
}

/// Adapts `ControlHandler` to `MoatControlXPC`. The extension exports one of these per accepted connection.
public final class ControlXPCService: NSObject, MoatControlXPC {
    private let handler: ControlHandler

    public init(handler: ControlHandler) {
        self.handler = handler
    }

    private func reply(_ r: Result<Data, ControlError>, _ reply: (Data?, String?) -> Void) {
        switch r {
        case let .success(d): reply(d, nil)
        case let .failure(e): reply(nil, e.message)
        }
    }

    public func status(reply: @escaping (Data?, String?) -> Void) { self.reply(handler.perform(.status), reply) }
    public func recentFlows(limit: Int, reply: @escaping (Data?, String?) -> Void) { self.reply(handler.perform(.recentFlows(limit: limit)), reply) }
    public func applySignedSnapshot(_ signed: Data, canarySeconds: Int, reply: @escaping (Data?, String?) -> Void) {
        self.reply(handler.perform(.applySignedSnapshot(signed, canarySeconds: canarySeconds)), reply)
    }
    public func confirmCanary(reply: @escaping (Data?, String?) -> Void) { self.reply(handler.perform(.confirmCanary), reply) }
    public func rollbackToLastKnownGood(reply: @escaping (Data?, String?) -> Void) { self.reply(handler.perform(.rollbackToLastKnownGood), reply) }
    public func enterIsolation(reason: String, reply: @escaping (Data?, String?) -> Void) { self.reply(handler.perform(.enterIsolation(reason: reason)), reply) }
    public func exitIsolation(confirmation: String, reply: @escaping (Data?, String?) -> Void) {
        self.reply(handler.perform(.exitIsolation(confirmation: confirmation)), reply)
    }
    public func reloadTrust(reply: @escaping (Data?, String?) -> Void) { self.reply(handler.perform(.reloadTrust), reply) }
}
