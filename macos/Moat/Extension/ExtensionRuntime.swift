import Foundation
import MoatCoreBridge
import MoatKit
import os

/// Process-wide state of the system extension: engine, policy store, control handler and XPC listener.
final class ExtensionRuntime: NSObject, NSXPCListenerDelegate {
    static let shared = ExtensionRuntime()

    static let supportDir = URL(fileURLWithPath: "/Library/Application Support/Moat", isDirectory: true)
    let log = Logger(subsystem: "moat.filter", category: "runtime")
    let engine: FilterEngine
    let store: PolicyStore
    let handler: ControlHandler
    private var listener: NSXPCListener?
    private var timer: DispatchSourceTimer?
    private let filterLock = NSLock()
    private var filterRunning = false

    override init() {
        let trust = TrustConfig.load()
        let deviceID = (try? String(contentsOf: Self.supportDir.appendingPathComponent("device-id"), encoding: .utf8))?
            .trimmingCharacters(in: .whitespacesAndNewlines) ?? ProcessInfo.processInfo.hostName
        engine = FilterEngine(deviceID: deviceID, spool: EventSpool(capacity: 5000))
        store = PolicyStore(directory: Self.supportDir.appendingPathComponent("state"), verifier: CoreVerifier(trust: trust.config))
        let version = Bundle.main.object(forInfoDictionaryKey: "CFBundleShortVersionString") as? String ?? "0"
        var running: () -> Bool = { false }
        handler = ControlHandler(engine: engine, store: store, version: version, filterEnabled: { running() }, makeEvaluator: { try CoreEvaluator(policyJSON: $0) })
        super.init()
        running = { [weak self] in self?.isFilterRunning ?? false }
        for p in trust.problems { log.error("trust: \(p, privacy: .public)") }
        handler.restore()
    }

    var isFilterRunning: Bool {
        filterLock.lock()
        defer { filterLock.unlock() }
        return filterRunning
    }

    func setFilterRunning(_ on: Bool) {
        filterLock.lock()
        filterRunning = on
        filterLock.unlock()
    }

    func startControlListener() {
        guard let service = Bundle.main.object(forInfoDictionaryKey: "NetworkExtension").flatMap({ ($0 as? [String: Any])?["NEMachServiceName"] as? String }) else {
            log.error("no NEMachServiceName; control surface disabled")
            return
        }
        let l = NSXPCListener(machServiceName: service)
        l.delegate = self
        l.resume()
        listener = l

        let t = DispatchSource.makeTimerSource(queue: .global(qos: .utility))
        t.schedule(deadline: .now() + 15, repeating: 15)
        t.setEventHandler { [weak self] in self?.handler.tick() }
        t.resume()
        timer = t
    }

    func listener(_ listener: NSXPCListener, shouldAcceptNewConnection c: NSXPCConnection) -> Bool {
        let team = Bundle.main.object(forInfoDictionaryKey: "MoatTeamID") as? String
        let app = Bundle.main.object(forInfoDictionaryKey: "MoatAppBundleID") as? String ?? ""
        guard let requirement = CallerRequirement.make(appBundleID: app, teamID: team) else {
            // Unsigned or misconfigured build: refuse every caller rather than accept unauthenticated ones.
            log.error("refusing XPC connection: no valid team ID / app bundle ID in Info.plist")
            return false
        }
        c.setCodeSigningRequirement(requirement)
        c.exportedInterface = NSXPCInterface(with: MoatControlXPC.self)
        c.exportedObject = ControlXPCService(handler: handler)
        c.resume()
        return true
    }
}
