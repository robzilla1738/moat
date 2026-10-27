import Foundation
import MoatKit
import NetworkExtension
import Security

/// NEFilterDataProvider: decides each new outbound socket flow at its first decision point.
///
/// * Identity: the responsible app's audit token -> signing identifier, team ID and executable path (Security
///   framework); the socket process's audit token is resolved separately and recorded as `FlowFacts.process`.
/// * A deny is a `.drop()` before any payload passes the filter, recorded as "blocked before data was sent".
/// * Allowed flows ask for a report; byte counts are attached only when macOS delivers one.
/// * Inbound flows are not filtered. Ancestry is not available here (no Endpoint Security).
final class FilterDataProvider: NEFilterDataProvider {
    private var runtime: ExtensionRuntime { ExtensionRuntime.shared }

    override func startFilter(completionHandler: @escaping (Error?) -> Void) {
        let outbound = NENetworkRule(remoteNetwork: nil, remotePrefix: 0, localNetwork: nil, localPrefix: 0, protocol: .any, direction: .outbound)
        let settings = NEFilterSettings(rules: [NEFilterRule(networkRule: outbound, action: .filterData)], defaultAction: .allow)
        apply(settings) { [weak self] error in
            self?.runtime.setFilterRunning(error == nil)
            if let error { self?.runtime.log.error("apply settings failed: \(error.localizedDescription, privacy: .public)") }
            completionHandler(error)
        }
    }

    override func stopFilter(with reason: NEProviderStopReason, completionHandler: @escaping () -> Void) {
        runtime.setFilterRunning(false)
        runtime.log.notice("filter stopped: \(reason.rawValue)")
        completionHandler()
    }

    override func handleNewFlow(_ flow: NEFilterFlow) -> NEFilterNewFlowVerdict {
        guard let socketFlow = flow as? NEFilterSocketFlow, let endpoint = socketFlow.remoteEndpoint as? NWHostEndpoint else {
            return .allow()
        }
        // Responsible app (what app rules match and Activity groups by) and the process that actually opened the
        // socket are different identities; keep both, never flatten them into one string.
        let identity = CodeIdentity.resolve(auditToken: flow.sourceAppAuditToken)
        var process: ProcessIdentity?
        if let token = flow.sourceProcessAuditToken {
            let p = CodeIdentity.resolve(auditToken: token)
            process = ProcessIdentity(signingID: p.signingID, teamID: p.teamID, executable: p.path, pid: p.pid, pidVersion: p.pidVersion)
        }
        let transport: Transport = socketFlow.socketProtocol == Int32(IPPROTO_UDP) ? .udp : .tcp
        let host = socketFlow.remoteHostname
        let facts = FlowFacts(
            id: flow.identifier.uuidString,
            bundleID: nil,
            signingID: identity.signingID,
            teamID: identity.teamID,
            executable: identity.path,
            pid: identity.pid,
            remoteHost: host,
            hostSource: host == nil ? nil : .flowApi,
            remoteIP: endpoint.hostname,
            remotePort: UInt16(endpoint.port) ?? 0,
            transport: transport,
            process: process)
        let decision = runtime.engine.decide(facts)
        switch decision.verdict {
        case .deny:
            return .drop()
        case .allow:
            let v = NEFilterNewFlowVerdict.allow()
            v.shouldReport = true
            return v
        }
    }

    override func handle(_ report: NEFilterReport) {
        let maybeFlow: NEFilterFlow? = report.flow
        guard let flow = maybeFlow else { return }
        runtime.engine.report(flowID: flow.identifier.uuidString, outbound: UInt64(report.bytesOutboundCount), inbound: UInt64(report.bytesInboundCount))
    }
}

/// Code identity from an audit token. Every field is optional: unsigned code has no team ID.
struct CodeIdentity {
    var signingID: String?
    var teamID: String?
    var path: String?
    var pid: Int32?
    /// audit_token_t word 7: the per-process generation, so a reused pid is a different process.
    var pidVersion: Int32?

    static func resolve(auditToken: Data?) -> CodeIdentity {
        guard let token = auditToken else { return CodeIdentity() }
        var out = CodeIdentity()
        // audit_token_t is eight 32-bit words; word 5 is the pid.
        if token.count >= 32 {
            out.pid = token.withUnsafeBytes { raw in raw.load(fromByteOffset: 20, as: Int32.self) }
            out.pidVersion = token.withUnsafeBytes { raw in raw.load(fromByteOffset: 28, as: Int32.self) }
        }
        var code: SecCode?
        let attrs = [kSecGuestAttributeAudit: token] as CFDictionary
        guard SecCodeCopyGuestWithAttributes(nil, attrs, [], &code) == errSecSuccess, let code else { return out }
        var staticCode: SecStaticCode?
        guard SecCodeCopyStaticCode(code, [], &staticCode) == errSecSuccess, let staticCode else { return out }
        var url: CFURL?
        if SecCodeCopyPath(staticCode, [], &url) == errSecSuccess, let url {
            out.path = (url as URL).path
        }
        var info: CFDictionary?
        if SecCodeCopySigningInformation(staticCode, SecCSFlags(rawValue: kSecCSSigningInformation), &info) == errSecSuccess,
           let dict = info as? [String: Any] {
            out.signingID = dict[kSecCodeInfoIdentifier as String] as? String
            out.teamID = dict[kSecCodeInfoTeamIdentifier as String] as? String
        }
        return out
    }
}
