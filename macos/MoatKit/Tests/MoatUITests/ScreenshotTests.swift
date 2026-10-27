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
        try render(ScreenContent(model: model(.apps, isolated: true)).padding(28), .dark, width: 1040, height: 900, name: "apps-isolated-dark")
        try render(ScreenContent(model: model(.coverage, isolated: true)).padding(28), .light, width: 1040, height: 900, name: "coverage-isolated-light")
    }

    /// rollback-pending on this Mac plus lifecycle events from Linux endpoints (render check of the recovery cards).
    func testRecoveryLabelsAndFleetEventsRender() throws {
        let m = model(.coverage)
        m.status?.coverage = .rollbackPending
        m.status?.coverageNotes.insert("The canary rollback to revision 6 could not load; the trial revision 7 is still enforced.", at: 0)
        m.fleetEvents = [
            EndpointLifecycleEvent.from(event: ["type": "activation_recovery", "phase": "recovery_required", "detail": "journal could not reconcile"], deviceID: "omarchy", seq: 41)!,
            EndpointLifecycleEvent.from(event: ["type": "proxy_limit", "session_id": "s-1", "resource": "connections", "limit": 256], deviceID: "omarchy", seq: 42)!,
            EndpointLifecycleEvent.from(event: ["type": "stream_terminated", "session_id": "s-1", "hostname": "api.github.com", "reason": "grant expired"], deviceID: "omarchy", seq: 43)!,
            EndpointLifecycleEvent.from(event: ["type": "session_not_adopted", "session_id": "s-2", "profile": "coding-session", "reason": "cgroup missing"], deviceID: "mini", seq: 7)!,
        ]
        XCTAssertEqual(OverviewHero.headline(m.status!), "Rollback pending.")
        try render(ScreenContent(model: m).padding(28), .dark, width: 1040, height: 1400, name: "coverage-rollback-pending-dark")
    }

    func testLifecycleEventsAreReportedNotInferred() {
        XCTAssertNil(EndpointLifecycleEvent.from(event: ["type": "flow"], deviceID: "d", seq: 1), "only lifecycle events are shown here")
        let r = EndpointLifecycleEvent.from(event: ["type": "activation_recovery", "phase": "rolled_back", "detail": "x"], deviceID: "d", seq: 2)!
        XCTAssertFalse(r.needsOwnerAtDevice)
        let p = EndpointLifecycleEvent.from(event: ["type": "proxy_limit", "session_id": "s", "resource": "streams", "limit": 64], deviceID: "d", seq: 3)!
        XCTAssertEqual(p.detail, "streams limit 64")
        XCTAssertTrue(p.meaning.contains("not bypassed"))
    }

    func testMenuBarPanelRenders() throws {
        try render(MenuBarContent(model: model(.apps), openMain: {}), .dark, width: 348, height: 520, name: "menubar-dark")
        try render(MenuBarContent(model: model(.apps, isolated: true), openMain: {}), .light, width: 348, height: 520, name: "menubar-isolated-light")
    }

    func testOnboardingStepsRender() throws {
        let state = OnboardingState(trustedKeyIDs: ["21fe31dfa154a261"])
        for step in OnboardingStep.allCases {
            try render(OnboardingView(state: state, step: step, finish: {}), .dark, width: 640, height: 600, name: "onboarding-\(step)")
        }
    }

    func testAppDetailAndWhatChangedRender() throws {
        let m = model(.appDetail)
        m.selectedAppID = m.apps.first?.id
        XCTAssertNotNil(m.selectedApp, "demo flows produce app identities")
        try render(ScreenContent(model: m).padding(28), .dark, width: 1040, height: 1400, name: "appDetail-selected-dark")
        m.screen = .whatChanged
        try render(ScreenContent(model: m).padding(28), .light, width: 1040, height: 900, name: "whatChanged-light")
    }

    func testSidebarIsAppsFirstAndSaysThisComputer() {
        XCTAssertEqual(Screen.sidebar, [.apps, .activity, .tasks, .rules, .devices, .coverage])
        XCTAssertEqual(Screen.devices.title(deviceCount: 1), "This computer")
        XCTAssertEqual(Screen.devices.title(deviceCount: 3), "Devices")
        XCTAssertEqual(Screen.coverage.title, "Coverage & recovery")
        XCTAssertEqual(Screen.named("overview"), .apps)
        XCTAssertEqual(Screen.named("recovery"), .coverage)
    }

    func testAuthorizingWithoutAnOwnerKeyIsRefusedNotFaked() async {
        let m = model(.appDetail)
        guard let app = m.apps.first(where: { $0.identityKnown }) else { return XCTFail("no known app") }
        let plan = LocalRulePlan(action: .deny, app: app, host: app.destinations[0].host, port: app.destinations[0].port, expires: Date().addingTimeInterval(600))
        await m.authorize(plan)
        XCTAssertNil(m.lastAuthorization)
        XCTAssertNotNil(m.lastError)
        let wide = LocalRulePlan(action: .allow, app: app, host: "*", port: 443, expires: Date().addingTimeInterval(600))
        await m.authorize(wide)
        XCTAssertTrue(m.lastError?.contains("wildcards") ?? false)
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
