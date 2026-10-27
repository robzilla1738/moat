@testable import MoatKit
import XCTest

final class TrustConfigTests: XCTestCase {
    func testKeyIDMatchesMoatCore() {
        // moat-core: hex(sha256(public key bytes))[..16]
        XCTAssertEqual(TrustConfig.keyID(hex: "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a"), "21fe31dfa154a261")
        XCTAssertNil(TrustConfig.keyID(hex: "not-a-key"))
    }

    func testRevokedKeysAreNotActive() {
        let text = """
        # owner keys
        d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a
        revoke 21fe31dfa154a261
        """
        let (c, problems) = TrustConfig.parse(text)
        XCTAssertTrue(problems.isEmpty)
        XCTAssertEqual(c.keys.count, 1)
        XCTAssertEqual(c.activeKeyIDs, [])
        XCTAssertEqual(TrustConfig.parse("d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a").config.activeKeyIDs, ["21fe31dfa154a261"])
    }
}
