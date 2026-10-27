import MoatKit
import MoatUI
import SwiftUI

@main
struct MoatApp: App {
    @AppStorage("appearance") private var appearance: Appearance = .system
    @StateObject private var model: AppModel
    @StateObject private var installer = ExtensionManager()

    init() {
        let demo = CommandLine.arguments.contains("--demo")
        let service = Bundle.main.object(forInfoDictionaryKey: "MoatMachServiceName") as? String ?? ""
        let client: ControlClient = demo ? DemoControlClient() : XPCControlClient(machServiceName: service)
        _model = StateObject(wrappedValue: AppModel(client: client, isDemo: demo))
    }

    var body: some Scene {
        WindowGroup("Moat") {
            RootView(model: model)
                .frame(minWidth: 1040, minHeight: 700)
                .preferredColorScheme(appearance.colorScheme)
                .task {
                    // Poll the extension's typed status surface. The UI shows only what it reports.
                    while !Task.isCancelled {
                        await model.refresh()
                        try? await Task.sleep(nanoseconds: 3_000_000_000)
                    }
                }
                .sheet(isPresented: $installer.showSetup) {
                    SetupView(installer: installer)
                        .preferredColorScheme(appearance.colorScheme)
                }
                .onAppear { installer.checkFilterConfiguration(isDemo: model.isDemo) }
        }
        .windowStyle(.hiddenTitleBar)
        .commands {
            CommandGroup(after: .appInfo) {
                Button("Set Up Filter…") { installer.showSetup = true }
                Button("Refresh") { Task { await model.refresh() } }.keyboardShortcut("r")
            }
        }

        Settings {
            Form {
                Picker("Appearance", selection: $appearance) {
                    ForEach(Appearance.allCases) { Text($0.label).tag($0) }
                }
                .pickerStyle(.segmented)
            }
            .padding(24)
            .frame(width: 380)
        }
    }
}
