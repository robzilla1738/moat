import AppKit
import MoatKit
@testable import MoatUI
import SwiftUI
import XCTest

/// Renders every screen in dark and light with the demo client (backed by the real ControlHandler).
/// Set MOAT_SCREENSHOT_DIR to write PNGs (CI uploads them as an artifact; docs/screenshots/macos-*.png).
@MainActor
final class ScreenshotTests: XCTestCase {
    func model(_ screen: Screen, isolated: Bool = false) -> AppModel {
        let client = DemoControlClient(now: Date(), isolated: isolated)
        let (s, f) = client.snapshot()
        let m = AppModel(client: client, isDemo: true, screen: screen)
        m.status = s
        m.flows = f
        return m
    }

    func render(_ m: AppModel, _ scheme: ColorScheme, name: String) throws {
        let view = RootView(model: m, scrollable: false)
            .environment(\.colorScheme, scheme)
            .frame(width: 1280, height: 860)
            .clipped()
        let r = ImageRenderer(content: view)
        r.scale = 2
        guard let cg = r.cgImage else { return XCTFail("render produced no image for \(name)") }
        XCTAssertEqual(cg.width, 2560)
        if let dir = ProcessInfo.processInfo.environment["MOAT_SCREENSHOT_DIR"] {
            let rep = NSBitmapImageRep(cgImage: cg)
            let png = try XCTUnwrap(rep.representation(using: .png, properties: [:]))
            try FileManager.default.createDirectory(atPath: dir, withIntermediateDirectories: true)
            try png.write(to: URL(fileURLWithPath: dir).appendingPathComponent("macos-\(name).png"))
        }
    }

    func testRenderEveryScreenDarkAndLight() throws {
        for screen in Screen.allCases {
            try render(model(screen), .dark, name: "\(screen.rawValue)-dark")
            try render(model(screen), .light, name: "\(screen.rawValue)-light")
        }
    }

    func testRenderIsolatedState() throws {
        try render(model(.overview, isolated: true), .dark, name: "overview-isolated-dark")
        try render(model(.recovery, isolated: true), .light, name: "recovery-isolated-light")
    }
}

@MainActor
final class AppModelTests: XCTestCase {
    func testRefreshAndRecoveryActionsGoThroughTheControlSurface() async {
        let m = AppModel(client: DemoControlClient(), isDemo: true)
        await m.refresh()
        XCTAssertEqual(m.status?.coverage, .enforced)
        XCTAssertEqual(m.status?.installed?.revision, 43)
        XCTAssertFalse(m.flows.isEmpty)
        XCTAssertTrue(m.flows.contains { $0.decision.verdict == .deny })
        XCTAssertTrue(m.flows.contains { $0.decision.isObservation })

        await m.enterIsolation(reason: "test")
        XCTAssertEqual(m.status?.coverage, .isolated)
        await m.exitIsolation(confirmation: "nope")
        XCTAssertNotNil(m.lastError)
        XCTAssertEqual(m.status?.coverage, .isolated)
        await m.exitIsolation(confirmation: ControlHandler.exitPhrase)
        XCTAssertNil(m.lastError)
        XCTAssertEqual(m.status?.coverage, .enforced)

        await m.rollback()
        XCTAssertEqual(m.status?.installed?.revision, 42)
        XCTAssertEqual(m.status?.installed?.rollbackOf, 43)
    }

    func testDecisionPillsNeverCallObservationAllowed() {
        let obs = FlowDecision(verdict: .allow, source: .observationProfile, summary: "")
        XCTAssertEqual(obs.pill.0, "Observed")
        let iso = FlowDecision(verdict: .deny, source: .emergencyIsolation, summary: "")
        XCTAssertEqual(iso.pill.0, "Isolated")
    }
}
