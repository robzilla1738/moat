import AppKit
import MoatKit
@testable import MoatUI
import SwiftUI
import XCTest

/// Renders every screen's content, the menu bar panel and each onboarding step in dark and light with the demo
/// client (backed by the real ControlHandler). ImageRenderer cannot draw NavigationSplitView, scroll views or Liquid
/// Glass, so these renders check that every surface builds and lays out; the published screenshots are captured
/// from the real app window by macos/scripts/capture-screenshots.sh in CI.
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

    func render<V: View>(_ view: V, _ scheme: ColorScheme, width: CGFloat, height: CGFloat, name: String) throws {
        let framed = view
            .environment(\.colorScheme, scheme)
            .frame(width: width, height: height, alignment: .topLeading)
            .background(scheme == .dark ? Color.black : Color.white)
        let r = ImageRenderer(content: framed)
        r.scale = 2
        guard let cg = r.cgImage else { return XCTFail("render produced no image for \(name)") }
        XCTAssertEqual(CGFloat(cg.width), width * 2, name)
        if let dir = ProcessInfo.processInfo.environment["MOAT_SCREENSHOT_DIR"] {
            let rep = NSBitmapImageRep(cgImage: cg)
            let png = try XCTUnwrap(rep.representation(using: .png, properties: [:]))
            try FileManager.default.createDirectory(atPath: dir, withIntermediateDirectories: true)
            try png.write(to: URL(fileURLWithPath: dir).appendingPathComponent("render-\(name).png"))
        }
    }

    func testEveryScreenRendersDarkAndLight() throws {
        for screen in Screen.allCases {
            for (scheme, label) in [(ColorScheme.dark, "dark"), (.light, "light")] {
                try render(ScreenContent(model: model(screen)).padding(28), scheme, width: 1040, height: 900, name: "\(screen.rawValue)-\(label)")
            }
        }
    }

    func testIsolatedStateRenders() throws {
        try render(ScreenContent(model: model(.overview, isolated: true)).padding(28), .dark, width: 1040, height: 900, name: "overview-isolated-dark")
        try render(ScreenContent(model: model(.recovery, isolated: true)).padding(28), .light, width: 1040, height: 900, name: "recovery-isolated-light")
    }

    func testMenuBarPanelRenders() throws {
        try render(MenuBarContent(model: model(.overview), openMain: {}), .dark, width: 348, height: 520, name: "menubar-dark")
        try render(MenuBarContent(model: model(.overview, isolated: true), openMain: {}), .light, width: 348, height: 520, name: "menubar-isolated-light")
    }

    func testOnboardingStepsRender() throws {
        let state = OnboardingState(trustedKeyIDs: ["21fe31dfa154a261"])
        for step in OnboardingStep.allCases {
            try render(OnboardingView(state: state, step: step, finish: {}), .dark, width: 640, height: 600, name: "onboarding-\(step)")
        }
    }

    func testHeroHeadlinesAreNarrowClaims() {
        let s = DemoControlClient().snapshot().0
        XCTAssertEqual(OverviewHero.headline(s), "Enforcing.")
        XCTAssertFalse(s.coverage.claim.lowercased().contains("fail-closed"))
        XCTAssertFalse(s.coverage.claim.lowercased().contains("contain"))
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
