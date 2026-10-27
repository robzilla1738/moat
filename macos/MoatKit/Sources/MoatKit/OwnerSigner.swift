import CryptoKit
import Foundation
#if canImport(LocalAuthentication)
import LocalAuthentication
#endif
import Security

// MARK: - Local owner authority (W12)
//
// The owner's Ed25519 key for standalone rule authoring lives in the login Keychain behind an access control that
// requires user presence (`.userPresence`: Touch ID, Apple Watch or the account password, enforced by the OS when the
// item is read). Moat code never holds the seed outside one signing call and never exports it.
//
// A typed confirmation phrase is UI friction, not authentication (MASTER_ROADMAP §19.3): nothing in this file accepts
// one. Every signature needs (1) a LocalAuthentication evaluation whose prompt shows the exact plan being authorized
// and (2) the Keychain releasing the seed to that authenticated context.

public enum OwnerSigningError: Error, Equatable, CustomStringConvertible {
    case noKey
    case keyExists
    case presenceDenied(String)
    case keychain(Int32)
    case malformed(String)

    public var description: String {
        switch self {
        case .noKey: return "No local owner key exists on this Mac yet."
        case .keyExists: return "A local owner key already exists; it is never silently replaced."
        case let .presenceDenied(why): return "Owner authentication did not complete (\(why)). Nothing was signed."
        case let .keychain(s): return "The Keychain refused the owner key operation (OSStatus \(s))."
        case let .malformed(why): return "The owner key is malformed: \(why)"
        }
    }
}

/// An authenticated context from the OS. Production: an `LAContext` that passed `deviceOwnerAuthentication`.
public protocol OwnerPresenceContext: AnyObject {}

/// Asks the OS to verify the owner is present. The reason string is the exact plan shown in the system prompt.
public protocol OwnerPresence {
    func authenticate(reason: String) async throws -> OwnerPresenceContext
}

/// Where the seed lives. Reading requires an authenticated context; the public key is readable without one.
public protocol ProtectedKeyStore {
    /// The access-control requirement the store attaches to the seed item.
    var requiresUserPresence: Bool { get }
    func publicKey() -> Data?
    func create(seed: Data, publicKey: Data) throws
    func readSeed(context: OwnerPresenceContext) throws -> Data
    func delete() throws
}

/// What a signature authorizes, shown verbatim in the OS prompt and returned for audit.
public struct OwnerPlan: Equatable, Sendable {
    public var subject: String
    public var digest: String
    /// Human-readable exact plan (scope, destination, expiry). Shown in the authentication prompt.
    public var display: String
    public init(subject: String, digest: String, display: String) {
        self.subject = subject
        self.digest = digest
        self.display = display
    }
}

/// `moat.owner_authorization.v1` — byte-identical to the controller (controller/src/crypto.ts ownerAuthorizationString).
public struct OwnerAuthorization: Codable, Equatable, Sendable {
    public var keyID: String
    public var signature: String
    enum CodingKeys: String, CodingKey {
        case keyID = "key_id"
        case signature
    }

    public static func message(subject: String, digest: String) -> Data {
        Data("moat.owner_authorization.v1\n\(subject)\n\(digest)".utf8)
    }
}

/// `moat.signed_snapshot.v1` envelope (moat-core signing.rs): the payload is the exact signed bytes.
public struct SignedEnvelope: Codable, Equatable, Sendable {
    public var schema = "moat.signed_snapshot.v1"
    public var keyID: String
    public var payload: String
    public var signature: String
    enum CodingKeys: String, CodingKey {
        case schema
        case keyID = "key_id"
        case payload, signature
    }
}

public final class OwnerSigner {
    public let store: ProtectedKeyStore
    public let presence: OwnerPresence

    public init(store: ProtectedKeyStore, presence: OwnerPresence) {
        self.store = store
        self.presence = presence
    }

    public var publicKeyHex: String? { store.publicKey().map { $0.map { String(format: "%02x", $0) }.joined() } }
    /// moat-core key id: first 16 hex of sha256(raw public key).
    public var keyID: String? { publicKeyHex.flatMap { TrustConfig.keyID(hex: $0) } }

    /// Create the local owner key. Never replaces an existing key (rotation is an explicit delete + trust change).
    @discardableResult
    public func createKey() throws -> String {
        if store.publicKey() != nil { throw OwnerSigningError.keyExists }
        let k = Curve25519.Signing.PrivateKey()
        try store.create(seed: k.rawRepresentation, publicKey: k.publicKey.rawRepresentation)
        guard let id = keyID else { throw OwnerSigningError.malformed("no public key after creation") }
        return id
    }

    private func sign(_ message: Data, reason: String) async throws -> (Data, String) {
        guard store.publicKey() != nil, let keyID else { throw OwnerSigningError.noKey }
        let ctx: OwnerPresenceContext
        do {
            ctx = try await presence.authenticate(reason: reason)
        } catch let e as OwnerSigningError {
            throw e
        } catch {
            throw OwnerSigningError.presenceDenied("\(error)")
        }
        var seed = try store.readSeed(context: ctx)
        defer { seed.resetBytes(in: 0 ..< seed.count) }
        let key: Curve25519.Signing.PrivateKey
        do {
            key = try Curve25519.Signing.PrivateKey(rawRepresentation: seed)
        } catch {
            throw OwnerSigningError.malformed("\(error)")
        }
        guard key.publicKey.rawRepresentation == store.publicKey() else { throw OwnerSigningError.malformed("seed does not match the stored public key") }
        return (try key.signature(for: message), keyID)
    }

    /// Owner authorization for a plan (fleet proposals and standalone changes use the same format).
    public func authorize(_ plan: OwnerPlan) async throws -> OwnerAuthorization {
        let (sig, id) = try await sign(OwnerAuthorization.message(subject: plan.subject, digest: plan.digest), reason: "Authorize: \(plan.display)")
        return OwnerAuthorization(keyID: id, signature: sig.base64EncodedString())
    }

    /// Sign exact payload bytes (a compiled snapshot) as a `moat.signed_snapshot.v1` envelope.
    public func signPayload(_ payload: Data, plan: OwnerPlan) async throws -> SignedEnvelope {
        let (sig, id) = try await sign(payload, reason: "Sign policy: \(plan.display)")
        return SignedEnvelope(keyID: id, payload: payload.base64EncodedString(), signature: sig.base64EncodedString())
    }

    /// Verify an authorization against a public key (used by tests and by the UI to show what was signed).
    public static func verify(_ a: OwnerAuthorization, plan: OwnerPlan, publicKey: Data) -> Bool {
        guard let pk = try? Curve25519.Signing.PublicKey(rawRepresentation: publicKey), let sig = Data(base64Encoded: a.signature) else { return false }
        return pk.isValidSignature(sig, for: OwnerAuthorization.message(subject: plan.subject, digest: plan.digest))
    }
}

/// sha256 hex of canonical text (plan digests).
public enum PlanDigest {
    public static func of(_ text: String) -> String {
        "sha256:" + SHA256.hash(data: Data(text.utf8)).map { String(format: "%02x", $0) }.joined()
    }
}

// MARK: - Production implementations

#if canImport(LocalAuthentication)
extension LAContext: OwnerPresenceContext {}

/// `LAPolicy.deviceOwnerAuthentication`: biometrics or the account password. No reuse window: every signature asks.
public struct LocalAuthenticationPresence: OwnerPresence {
    public init() {}
    public func authenticate(reason: String) async throws -> OwnerPresenceContext {
        let ctx = LAContext()
        ctx.touchIDAuthenticationAllowableReuseDuration = 0
        ctx.localizedReason = reason
        var err: NSError?
        guard ctx.canEvaluatePolicy(.deviceOwnerAuthentication, error: &err) else {
            throw OwnerSigningError.presenceDenied(err?.localizedDescription ?? "owner authentication is not available")
        }
        do {
            _ = try await ctx.evaluatePolicy(.deviceOwnerAuthentication, localizedReason: reason)
        } catch {
            throw OwnerSigningError.presenceDenied(error.localizedDescription)
        }
        return ctx
    }
}

/// The seed as a generic-password item with `SecAccessControl(.userPresence)`, this-device-only, readable only when
/// unlocked. The OS enforces the presence check on read, independent of Moat's code.
public struct KeychainOwnerKeyStore: ProtectedKeyStore {
    public static let service = "org.moat.owner-key"
    public static let accessFlags: SecAccessControlCreateFlags = [.userPresence]
    public static let accessibility = kSecAttrAccessibleWhenUnlockedThisDeviceOnly
    public var requiresUserPresence: Bool { Self.accessFlags.contains(.userPresence) }
    let account: String

    public init(account: String = "owner-ed25519") {
        self.account = account
    }

    private func base(_ acct: String) -> [String: Any] {
        [kSecClass as String: kSecClassGenericPassword, kSecAttrService as String: Self.service, kSecAttrAccount as String: acct]
    }

    public func publicKey() -> Data? {
        var q = base(account + ".pub")
        q[kSecReturnData as String] = true
        var out: CFTypeRef?
        return SecItemCopyMatching(q as CFDictionary, &out) == errSecSuccess ? out as? Data : nil
    }

    public func create(seed: Data, publicKey: Data) throws {
        var cfErr: Unmanaged<CFError>?
        guard let ac = SecAccessControlCreateWithFlags(nil, Self.accessibility, Self.accessFlags, &cfErr) else {
            throw OwnerSigningError.keychain(Int32(errSecParam))
        }
        var item = base(account)
        item[kSecValueData as String] = seed
        item[kSecAttrAccessControl as String] = ac
        let s = SecItemAdd(item as CFDictionary, nil)
        if s == errSecDuplicateItem { throw OwnerSigningError.keyExists }
        guard s == errSecSuccess else { throw OwnerSigningError.keychain(s) }
        var pub = base(account + ".pub")
        pub[kSecValueData as String] = publicKey
        pub[kSecAttrAccessible as String] = Self.accessibility
        let s2 = SecItemAdd(pub as CFDictionary, nil)
        guard s2 == errSecSuccess else {
            SecItemDelete(base(account) as CFDictionary)
            throw OwnerSigningError.keychain(s2)
        }
    }

    public func readSeed(context: OwnerPresenceContext) throws -> Data {
        guard let la = context as? LAContext else { throw OwnerSigningError.presenceDenied("not an OS authentication context") }
        var q = base(account)
        q[kSecReturnData as String] = true
        q[kSecUseAuthenticationContext as String] = la
        var out: CFTypeRef?
        let s = SecItemCopyMatching(q as CFDictionary, &out)
        if s == errSecItemNotFound { throw OwnerSigningError.noKey }
        if s == errSecUserCanceled || s == errSecAuthFailed { throw OwnerSigningError.presenceDenied("OSStatus \(s)") }
        guard s == errSecSuccess, let d = out as? Data else { throw OwnerSigningError.keychain(s) }
        return d
    }

    public func delete() throws {
        for a in [account, account + ".pub"] {
            let s = SecItemDelete(base(a) as CFDictionary)
            guard s == errSecSuccess || s == errSecItemNotFound else { throw OwnerSigningError.keychain(s) }
        }
    }
}
#endif
