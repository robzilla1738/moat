import CryptoKit
import Foundation

// MARK: - Standalone apply (W12 follow-up, issue #32)
//
// A Mac with no controller enforces an owner-authored local rule like this:
//
//   1. The app composes the standalone policy (its base plus unexpired local rules) and moat-core compiles it for macOS
//      (`moat_compile`). An unsupported restrictive rule is refused by the compiler, never weakened, and a rule the
//      compiler leaves out is a refusal here too: the owner is never told a rule is enforced when it is not.
//   2. OwnerSigner signs the exact compiled payload bytes with the Keychain owner key, behind OS user presence. The
//      prompt shows the plan, the revision and the payload hash.
//   3. moat-core assembles the signed envelope and refuses a signature that does not verify over those bytes
//      (`moat_assemble_signed_snapshot`).
//   4. The extension installs it through the ordinary typed `apply_signed_snapshot` operation, which verifies again
//      against the root-owned trusted-keys file and this Mac's device id. The app cannot add trust: an owner key the
//      extension does not trust is rejected, and the app says how the owner adds it.
//
// The app never replaces a policy it did not author: when the extension enforces a revision from another signer (a
// controller), local apply is refused rather than overwriting that policy with the standalone base.

/// Compile and assemble, backed by moat-core in production (MoatCoreBridge.CoreSnapshotAuthoring) and by fakes in tests.
public protocol SnapshotAuthoring: Sendable {
    func compile(policyText: String, revision: UInt64, issuedAt: Date, deviceID: String?) throws -> CompiledSnapshot
    /// Returns the `moat.signed_snapshot.v1` JSON bytes. Throws when the signature does not verify over `payload`.
    func assemble(payload: Data, signature: Data, publicKeyHex: String) throws -> Data
}

public struct CompiledSnapshot: Equatable, Sendable {
    /// The exact bytes that get signed (decoded from the compiler's base64 `payload`).
    public var payload: Data
    public var payloadSHA256: String
    public var revision: UInt64
    public var policyDigest: String
    public var omitted: [OmittedRule]
    public init(payload: Data, payloadSHA256: String, revision: UInt64, policyDigest: String, omitted: [OmittedRule]) {
        self.payload = payload
        self.payloadSHA256 = payloadSHA256
        self.revision = revision
        self.policyDigest = policyDigest
        self.omitted = omitted
    }
}

public struct StandaloneApplyError: Error, Equatable, CustomStringConvertible {
    public var message: String
    public init(_ m: String) { message = m }
    public var description: String { message }
}

/// The standalone policy this Mac's owner maintains: a base and the local rules authored here.
public struct StandalonePolicyBook: Codable, Equatable, Sendable {
    public struct Rule: Codable, Equatable, Sendable {
        public var id: String
        public var toml: String
        public var expires: Date
        public var authorizedBy: String
    }

    public var base: String
    public var rules: [Rule]
    /// The last revision this book produced and the policy digest the extension reported for it.
    public var lastRevision: UInt64?
    public var lastAppliedDigest: String?

    /// Ordinary apps observed and permitted; local owner rules are the only restrictions. Used when the owner has not
    /// chosen another base.
    public static let observeBase = """
    schema = "moat.policy.v1"
    name = "this-mac"
    description = "Standalone Mac: ordinary apps observed; local owner rules apply on top."
    fallback_profile = "observe"

    [[profiles]]
    id = "observe"
    description = "Observe existing behavior. Traffic is permitted and recorded."
    default = "observe"
    learning = "observe"
    """

    public init(base: String = StandalonePolicyBook.observeBase, rules: [Rule] = [], lastRevision: UInt64? = nil, lastAppliedDigest: String? = nil) {
        self.base = base
        self.rules = rules
        self.lastRevision = lastRevision
        self.lastAppliedDigest = lastAppliedDigest
    }

    /// Unexpired rules only: an expired local rule is not carried into a new revision.
    public func live(now: Date) -> [Rule] { rules.filter { $0.expires > now } }

    public func policyText(now: Date) -> String {
        ([base] + live(now: now).map(\.toml)).joined(separator: "\n\n") + "\n"
    }

    public static func load(_ url: URL) -> StandalonePolicyBook {
        guard let d = try? Data(contentsOf: url) else { return StandalonePolicyBook() }
        let dec = JSONDecoder()
        dec.dateDecodingStrategy = .iso8601
        return (try? dec.decode(StandalonePolicyBook.self, from: d)) ?? StandalonePolicyBook()
    }

    public func save(_ url: URL) throws {
        let enc = JSONEncoder()
        enc.dateEncodingStrategy = .iso8601
        enc.outputFormatting = [.prettyPrinted, .sortedKeys]
        try FileManager.default.createDirectory(at: url.deletingLastPathComponent(), withIntermediateDirectories: true)
        try enc.encode(self).write(to: url, options: .atomic)
    }
}

public struct StandaloneApplyResult: Equatable, Sendable {
    public var summary: PolicySummary
    public var ruleID: String
    public var keyID: String
    public var payloadSHA256: String
}

public final class StandaloneApplier: @unchecked Sendable {
    public let authoring: SnapshotAuthoring
    public let signer: OwnerSigner
    public let client: ControlClient
    public let bookURL: URL
    public let deviceID: String?

    public init(authoring: SnapshotAuthoring, signer: OwnerSigner, client: ControlClient, bookURL: URL, deviceID: String?) {
        self.authoring = authoring
        self.signer = signer
        self.client = client
        self.bookURL = bookURL
        self.deviceID = deviceID
    }

    public static let untrustedKeyHelp = "The extension does not trust this owner key yet. Add it once with: echo <public key> | sudo tee -a \"/Library/Application Support/Moat/trusted-keys\", then try again."

    /// Compile, sign (user presence), assemble, install. Nothing is recorded as applied unless the extension's own
    /// verification and install succeeded; on any failure the book is unchanged.
    public func apply(_ plan: LocalRulePlan, id: String, now: Date = Date()) async throws -> StandaloneApplyResult {
        let problems = plan.problems(now: now)
        guard problems.isEmpty else { throw StandaloneApplyError(problems.joined(separator: " ")) }
        if signer.keyID == nil { try signer.createKey() }
        guard let pubHex = signer.publicKeyHex, let keyID = signer.keyID else { throw StandaloneApplyError("No local owner key is available.") }

        var book = StandalonePolicyBook.load(bookURL)
        let status = try await client.status()
        if let installed = status.installed, installed.digest != book.lastAppliedDigest {
            throw StandaloneApplyError("This Mac enforces revision \(installed.revision) from another signer (for example your controller). A local rule would replace that policy, so it is not applied here; add the rule through that policy instead.")
        }
        var scoped = plan
        if scoped.deviceID == nil { scoped.deviceID = deviceID }
        let ruleTOML = scoped.ruleTOML(id: id)
        book.rules = book.live(now: now) + [.init(id: id, toml: ruleTOML, expires: plan.expires, authorizedBy: keyID)]
        let revision = max(status.installed?.revision ?? 0, status.lastKnownGood?.revision ?? 0, book.lastRevision ?? 0) + 1

        let compiled = try authoring.compile(policyText: book.policyText(now: now), revision: revision, issuedAt: now, deviceID: deviceID)
        if let o = compiled.omitted.first(where: { $0.ruleID == id }) {
            throw StandaloneApplyError("moat-core left this rule out for macOS (\(o.reason)); it would not be enforced, so nothing was signed.")
        }
        guard compiled.revision == revision else { throw StandaloneApplyError("The compiler produced revision \(compiled.revision), not \(revision); nothing was signed.") }
        let hash = SHA256.hash(data: compiled.payload).map { String(format: "%02x", $0) }.joined()
        guard hash == compiled.payloadSHA256.replacingOccurrences(of: "sha256:", with: "") else {
            throw StandaloneApplyError("The compiled payload does not match its reported hash; nothing was signed.")
        }

        let base = scoped.ownerPlan(id: id)
        let snapPlan = OwnerPlan(subject: "snapshot:r\(revision)", digest: "sha256:\(hash)", display: "\(base.display) (revision \(revision), payload \(hash.prefix(12)))")
        let envelope = try await signer.signPayload(compiled.payload, plan: snapPlan)
        guard let sig = Data(base64Encoded: envelope.signature) else { throw StandaloneApplyError("The owner signature is malformed.") }
        let signed = try authoring.assemble(payload: compiled.payload, signature: sig, publicKeyHex: pubHex)

        let summary: PolicySummary
        do {
            summary = try await client.applySignedSnapshot(signed, canarySeconds: 0)
        } catch {
            let text = "\(error)"
            if text.lowercased().contains("untrusted") || text.lowercased().contains("not trusted") || text.contains("unknown key") {
                throw StandaloneApplyError("\(Self.untrustedKeyHelp) Public key: \(pubHex). (\(text))")
            }
            throw StandaloneApplyError("The extension did not confirm the install: \(text)")
        }
        book.lastRevision = summary.revision
        book.lastAppliedDigest = summary.digest
        try book.save(bookURL)
        return StandaloneApplyResult(summary: summary, ruleID: id, keyID: keyID, payloadSHA256: hash)
    }
}
