import Foundation

/// Owner-configured verifying keys for signed snapshots.
///
/// Read from a root-owned file (default `/Library/Application Support/Moat/trusted-keys`), one hex Ed25519 public
/// key per line, `#` comments allowed, and an optional `revoke <key_id>` line. The owner edits it with
/// `sudo` (see macos/README.md). Nothing over XPC can add a key, and nothing promotes trust automatically.
public struct TrustConfig: Equatable, Sendable {
    public var keys: [String]
    public var revokedKeyIDs: [String]

    public static let defaultPath = "/Library/Application Support/Moat/trusted-keys"

    public init(keys: [String], revokedKeyIDs: [String] = []) {
        self.keys = keys
        self.revokedKeyIDs = revokedKeyIDs
    }

    public static func parse(_ text: String) -> (config: TrustConfig, problems: [String]) {
        var keys: [String] = []
        var revoked: [String] = []
        var problems: [String] = []
        for (i, raw) in text.split(separator: "\n", omittingEmptySubsequences: false).enumerated() {
            let line = raw.split(separator: "#", maxSplits: 1, omittingEmptySubsequences: false).first.map(String.init)?
                .trimmingCharacters(in: .whitespaces) ?? ""
            if line.isEmpty { continue }
            let parts = line.split(separator: " ").map(String.init)
            if parts.count == 2, parts[0] == "revoke" {
                revoked.append(parts[1])
            } else if parts.count == 1, isHexKey(parts[0]) {
                keys.append(parts[0].lowercased())
            } else {
                problems.append("line \(i + 1): expected a 64-character hex key or `revoke <key_id>`")
            }
        }
        return (TrustConfig(keys: keys, revokedKeyIDs: revoked), problems)
    }

    public static func load(path: String = defaultPath) -> (config: TrustConfig, problems: [String]) {
        guard let text = try? String(contentsOfFile: path, encoding: .utf8) else {
            return (TrustConfig(keys: []), ["no trusted keys file at \(path); every snapshot will be rejected"])
        }
        return parse(text)
    }

    static func isHexKey(_ s: String) -> Bool {
        s.count == 64 && s.allSatisfy { $0.isHexDigit }
    }
}
