import CryptoKit
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

    /// The signer key id moat-core uses: the first 16 hex characters of sha256 over the raw 32-byte public key.
    public static func keyID(hex: String) -> String? {
        guard isHexKey(hex) else { return nil }
        var bytes = [UInt8]()
        var i = hex.startIndex
        while i < hex.endIndex {
            let j = hex.index(i, offsetBy: 2)
            guard let b = UInt8(hex[i ..< j], radix: 16) else { return nil }
            bytes.append(b)
            i = j
        }
        return SHA256.hash(data: Data(bytes)).map { String(format: "%02x", $0) }.joined().prefix(16).description
    }

    /// Key ids of the trusted (not revoked) keys, for display. Reading never changes trust.
    public var activeKeyIDs: [String] {
        keys.compactMap { Self.keyID(hex: $0) }.filter { !revokedKeyIDs.contains($0) }
    }

    static func isHexKey(_ s: String) -> Bool {
        s.count == 64 && s.allSatisfy { $0.isHexDigit }
    }
}

/// The running extension's view of the trusted-keys file, with a generation number that increases whenever its
/// content changes. Reloading never adds trust by itself: it reads the root-owned file the owner edited.
public final class TrustStore: @unchecked Sendable {
    public let path: String
    private let lock = NSLock()
    private var fingerprint: String
    private var current: TrustConfig
    private var currentProblems: [String]
    private(set) public var generation: UInt64 = 1
    private let read: (String) -> String?

    /// - Parameter read: file reader (injected by tests); nil content means the file is missing.
    public init(path: String = TrustConfig.defaultPath, read: @escaping (String) -> String? = { try? String(contentsOfFile: $0, encoding: .utf8) }) {
        self.path = path
        self.read = read
        let text = read(path)
        fingerprint = Self.fingerprint(text)
        let parsed = text.map(TrustConfig.parse) ?? (TrustConfig(keys: []), ["no trusted keys file at \(path); every snapshot will be rejected"])
        current = parsed.0
        currentProblems = parsed.1
    }

    public var config: TrustConfig {
        lock.lock()
        defer { lock.unlock() }
        return current
    }

    public var problems: [String] {
        lock.lock()
        defer { lock.unlock() }
        return currentProblems
    }

    /// Re-read the file. Returns true (and bumps the generation) when its content changed.
    @discardableResult
    public func reloadIfChanged() -> Bool {
        let text = read(path)
        let fp = Self.fingerprint(text)
        lock.lock()
        defer { lock.unlock() }
        guard fp != fingerprint else { return false }
        fingerprint = fp
        let parsed = text.map(TrustConfig.parse) ?? (TrustConfig(keys: []), ["no trusted keys file at \(path); every snapshot will be rejected"])
        current = parsed.0
        currentProblems = parsed.1
        generation &+= 1
        return true
    }

    static func fingerprint(_ text: String?) -> String {
        guard let text else { return "missing" }
        return SHA256.hash(data: Data(text.utf8)).map { String(format: "%02x", $0) }.joined()
    }
}
