import AppKit
import Combine
import MoatKit
import MoatUI
import SwiftUI

/// Command-line switches for demo and screenshot runs (CI renders the real window with these).
struct LaunchOptions {
    var demo = false
    var isolated = false
    var screen: Screen = .overview
    /// "menubar" or "onboarding" render that surface in the main window for a screenshot.
    var special: String?
    var onboardingStep: OnboardingStep = .coverage
    var appearance: ColorScheme?
    var windowIDFile: String?
    var snapshotPath: String?

    var screenshotMode: Bool { windowIDFile != nil || snapshotPath != nil }

    static func parse(_ args: [String]) -> LaunchOptions {
        var o = LaunchOptions()
        func value(_ flag: String) -> String? {
            guard let i = args.firstIndex(of: flag), i + 1 < args.count else { return nil }
            return args[i + 1]
        }
        o.demo = args.contains("--demo")
        o.isolated = args.contains("--isolated")
        if let s = value("--screen") {
            if let sc = Screen(rawValue: s) { o.screen = sc } else { o.special = s }
        }
        if let st = value("--onboarding-step"), let step = OnboardingStep.allCases.first(where: { "\($0)" == st }) { o.onboardingStep = step }
        switch value("--appearance") {
        case "dark": o.appearance = .dark
        case "light": o.appearance = .light
        default: break
        }
        o.windowIDFile = value("--window-id-file")
        o.snapshotPath = value("--snapshot")
        return o
    }
}

@main
struct MoatApp: App {
    @AppStorage("appearance") private var appearance: Appearance = .system
    @StateObject private var model: AppModel
    @StateObject private var installer = ExtensionManager()
    @StateObject private var onboarding = OnboardingState()
    private let launch: LaunchOptions

    init() {
        let launch = LaunchOptions.parse(CommandLine.arguments)
        self.launch = launch
        let service = Bundle.main.object(forInfoDictionaryKey: "MoatMachServiceName") as? String ?? ""
        let client: ControlClient = launch.demo ? DemoControlClient(isolated: launch.isolated) : XPCControlClient(machServiceName: service)
        _model = StateObject(wrappedValue: AppModel(client: client, isDemo: launch.demo, screen: launch.screen))
        if launch.screenshotMode {
            NotificationCenter.default.addObserver(forName: NSApplication.didFinishLaunchingNotification, object: nil, queue: .main) { _ in
                ScreenshotReporter.report(launch)
            }
        }
    }

    var body: some Scene {
        Window("Moat", id: "main") {
            MainWindow(model: model, installer: installer, onboarding: onboarding, launch: launch)
                .preferredColorScheme(launch.appearance ?? appearance.colorScheme)
        }
        .defaultSize(width: 1180, height: 780)
        // Screenshot runs of the menu bar panel and onboarding size the window to the surface itself.
        .windowResizability(launch.special == nil ? .automatic : .contentSize)
        .windowToolbarStyle(.unified)
        .commands {
            CommandGroup(after: .appInfo) {
                Button("Set Up Moat…") { NotificationCenter.default.post(name: .moatShowOnboarding, object: nil) }
                Button("Refresh") { Task { await model.refresh() } }.keyboardShortcut("r")
            }
        }

        MenuBarExtra {
            MenuBarRoot(model: model)
                .preferredColorScheme(launch.appearance ?? appearance.colorScheme)
        } label: {
            MenuBarLabel(model: model, openMainOnAppear: launch.screenshotMode)
        }
        .menuBarExtraStyle(.window)

        Settings {
            Form {
                Picker("Appearance", selection: $appearance) {
                    ForEach(Appearance.allCases) { Text($0.label).tag($0) }
                }
                .pickerStyle(.segmented)
                Button("Show setup again") { NotificationCenter.default.post(name: .moatShowOnboarding, object: nil) }
            }
            .padding(24)
            .frame(width: 400)
        }
    }
}

extension Notification.Name {
    static let moatShowOnboarding = Notification.Name("moat.showOnboarding")
}

/// The status-item label. In screenshot runs it also opens the main window: a binary launched straight from a CI
/// shell is not activated, and SwiftUI then shows only the status item.
struct MenuBarLabel: View {
    @ObservedObject var model: AppModel
    var openMainOnAppear: Bool
    @Environment(\.openWindow) private var openWindow

    var body: some View {
        Label("Moat", systemImage: model.status?.coverage.systemImage ?? "shield.lefthalf.filled")
            .onAppear {
                guard openMainOnAppear else { return }
                NSApp.setActivationPolicy(.regular)
                openWindow(id: "main")
                NSApp.activate(ignoringOtherApps: true)
            }
    }
}

/// Menu bar panel host: opens and focuses the main window on request.
struct MenuBarRoot: View {
    @ObservedObject var model: AppModel
    @Environment(\.openWindow) private var openWindow

    var body: some View {
        MenuBarContent(model: model, openMain: {
            openWindow(id: "main")
            NSApp.activate(ignoringOtherApps: true)
        }, quit: { NSApp.terminate(nil) })
    }
}

struct MainWindow: View {
    @ObservedObject var model: AppModel
    @ObservedObject var installer: ExtensionManager
    @ObservedObject var onboarding: OnboardingState
    let launch: LaunchOptions
    @AppStorage("onboardingComplete") private var onboardingComplete = false
    @State private var showOnboarding = false
    @State private var onboardingStart: OnboardingStep = .welcome

    var body: some View {
        surface
            .task {
                // Poll the extension's typed status surface. The UI shows only what it reports.
                while !Task.isCancelled {
                    await model.refresh()
                    try? await Task.sleep(nanoseconds: 3_000_000_000)
                }
            }
            .sheet(isPresented: $showOnboarding) {
                OnboardingView(state: onboarding, step: onboardingStart) {
                    onboardingComplete = true
                    showOnboarding = false
                }
            }
            .onAppear(perform: appear)
            .onReceive(installer.objectWillChange.receive(on: RunLoop.main)) { _ in syncOnboarding() }
            .onReceive(NotificationCenter.default.publisher(for: .moatShowOnboarding)) { _ in
                onboardingStart = .welcome
                showOnboarding = true
            }
    }

    @ViewBuilder private var surface: some View {
        switch launch.special {
        case .some("menubar"):
            // The menu bar panel, hosted in a window so it can be captured (screenshots only).
            MenuBarContent(model: model, openMain: {}, quit: {})
                .frame(width: 348)
                .fixedSize()
        case .some("onboarding"):
            OnboardingView(state: onboarding, step: launch.onboardingStep) {}
        default:
            RootView(model: model)
                .frame(minWidth: 980, minHeight: 640)
        }
    }

    private func appear() {
        onboarding.activate = { installer.activate() }
        onboarding.enableFilter = { installer.enableFilter() }
        onboarding.recheckTrust = { onboarding.loadTrust() }
        onboarding.revealTrustFolder = {
            let url = URL(fileURLWithPath: TrustConfig.defaultPath).deletingLastPathComponent()
            NSWorkspace.shared.activateFileViewerSelecting([url])
        }
        if launch.demo {
            onboarding.extensionState = "Demo: macOS approval is not requested in demo mode"
            onboarding.filterState = "Demo: the content filter is not configured in demo mode"
            onboarding.trustProblems = ["Demo: no trusted-keys file is read in demo mode"]
        } else {
            installer.checkFilterConfiguration(isDemo: false)
            onboarding.loadTrust()
            syncOnboarding()
        }
        if !onboardingComplete, !launch.screenshotMode, launch.special == nil {
            onboardingStart = .welcome
            showOnboarding = true
        }
    }

    private func syncOnboarding() {
        guard !launch.demo else { return }
        onboarding.extensionState = installer.extensionState
        onboarding.extensionActive = installer.extensionActive
        onboarding.filterState = installer.filterState
        onboarding.filterEnabled = installer.filterEnabled
        onboarding.busy = installer.busy
        if installer.showSetup, onboardingComplete, !showOnboarding {
            // The filter is missing or off after setup: reopen setup at the approval step.
            installer.showSetup = false
            onboardingStart = .approve
            showOnboarding = true
        }
    }
}

/// Screenshot runs: size the window, then report its window number (for `screencapture -l`) and, as a fallback,
/// write an AppKit snapshot of the window contents.
enum ScreenshotReporter {
    static func report(_ o: LaunchOptions, attempt: Int = 0) {
        DispatchQueue.main.asyncAfter(deadline: .now() + 0.5) {
            let candidates = NSApp.windows.filter { $0.isVisible && !($0.className.contains("StatusBar")) && $0.frame.width > 200 }
            FileHandle.standardError.write(Data("moat screenshot: attempt \(attempt), windows: \(NSApp.windows.map { "\($0.className) \(Int($0.frame.width))x\(Int($0.frame.height)) visible=\($0.isVisible)" })\n".utf8))
            guard let w = candidates.first(where: { $0.canBecomeMain }) ?? candidates.first else {
                if attempt < 30 { report(o, attempt: attempt + 1) }
                return
            }
            if o.special == nil {
                w.setContentSize(NSSize(width: 1280, height: 820))
            } else if let content = w.contentView {
                // Menu bar panel and onboarding are fixed-size surfaces: fit the window to them so the capture is
                // the surface itself, not a default-sized window with the surface floating in the middle.
                content.layoutSubtreeIfNeeded()
                let fit = content.fittingSize
                if fit.width > 100, fit.height > 100 {
                    w.setContentSize(NSSize(width: ceil(fit.width), height: ceil(fit.height)))
                }
                if o.special == "menubar" {
                    w.titleVisibility = .hidden
                    w.titlebarAppearsTransparent = true
                    for b in [NSWindow.ButtonType.closeButton, .miniaturizeButton, .zoomButton] { w.standardWindowButton(b)?.isHidden = true }
                }
            }
            w.center()
            w.makeKeyAndOrderFront(nil)
            NSApp.activate(ignoringOtherApps: true)
            DispatchQueue.main.asyncAfter(deadline: .now() + 2.0) {
                if let path = o.snapshotPath, let view = w.contentView?.superview ?? w.contentView,
                   let rep = view.bitmapImageRepForCachingDisplay(in: view.bounds) {
                    view.cacheDisplay(in: view.bounds, to: rep)
                    try? rep.representation(using: .png, properties: [:])?.write(to: URL(fileURLWithPath: path))
                }
                if let path = o.windowIDFile {
                    try? "\(w.windowNumber)".write(toFile: path, atomically: true, encoding: .utf8)
                }
            }
        }
    }
}
