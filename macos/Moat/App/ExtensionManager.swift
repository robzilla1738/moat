import Foundation
import NetworkExtension
import SwiftUI
import SystemExtensions

/// Activates the Moat system extension and enables its content-filter configuration.
///
/// macOS asks the owner to approve both (System Settings › General › Login Items & Extensions, and the
/// "Allow Moat to filter network content" prompt). Nothing here bypasses those prompts.
final class ExtensionManager: NSObject, ObservableObject, OSSystemExtensionRequestDelegate {
    @Published var showSetup = false
    @Published var extensionState = "Not requested"
    @Published var filterState = "Unknown"
    @Published var busy = false

    var extensionID: String {
        Bundle.main.object(forInfoDictionaryKey: "MoatFilterBundleID") as? String ?? ""
    }

    func checkFilterConfiguration(isDemo: Bool) {
        guard !isDemo else { return }
        NEFilterManager.shared().loadFromPreferences { [weak self] error in
            DispatchQueue.main.async {
                guard let self else { return }
                if let error {
                    self.filterState = "Could not read filter settings: \(error.localizedDescription)"
                    self.showSetup = true
                    return
                }
                let m = NEFilterManager.shared()
                self.filterState = m.providerConfiguration == nil ? "Not configured" : (m.isEnabled ? "Enabled" : "Disabled")
                if m.providerConfiguration == nil || !m.isEnabled { self.showSetup = true }
            }
        }
    }

    func activate() {
        busy = true
        extensionState = "Requesting activation…"
        let req = OSSystemExtensionRequest.activationRequest(forExtensionWithIdentifier: extensionID, queue: .main)
        req.delegate = self
        OSSystemExtensionManager.shared.submitRequest(req)
    }

    func deactivate() {
        busy = true
        extensionState = "Requesting removal…"
        let req = OSSystemExtensionRequest.deactivationRequest(forExtensionWithIdentifier: extensionID, queue: .main)
        req.delegate = self
        OSSystemExtensionManager.shared.submitRequest(req)
    }

    func enableFilter() {
        busy = true
        let m = NEFilterManager.shared()
        m.loadFromPreferences { [weak self] error in
            if let error {
                DispatchQueue.main.async {
                    self?.filterState = "Could not load: \(error.localizedDescription)"
                    self?.busy = false
                }
                return
            }
            if m.providerConfiguration == nil {
                let c = NEFilterProviderConfiguration()
                c.filterSockets = true
                c.filterPackets = false
                c.filterDataProviderBundleIdentifier = self?.extensionID
                m.providerConfiguration = c
                m.localizedDescription = "Moat"
            }
            m.isEnabled = true
            m.saveToPreferences { error in
                DispatchQueue.main.async {
                    self?.filterState = error.map { "Not enabled: \($0.localizedDescription)" } ?? "Enabled"
                    self?.busy = false
                }
            }
        }
    }

    // MARK: OSSystemExtensionRequestDelegate

    func request(_ request: OSSystemExtensionRequest, actionForReplacingExtension existing: OSSystemExtensionProperties, withExtension ext: OSSystemExtensionProperties) -> OSSystemExtensionRequest.ReplacementAction {
        .replace
    }

    func requestNeedsUserApproval(_ request: OSSystemExtensionRequest) {
        extensionState = "Waiting for your approval in System Settings › General › Login Items & Extensions"
    }

    func request(_ request: OSSystemExtensionRequest, didFinishWithResult result: OSSystemExtensionRequest.Result) {
        busy = false
        switch result {
        case .completed: extensionState = "Active"
        case .willCompleteAfterReboot: extensionState = "Active after restart"
        @unknown default: extensionState = "Finished (\(result.rawValue))"
        }
    }

    func request(_ request: OSSystemExtensionRequest, didFailWithError error: Error) {
        busy = false
        extensionState = "Failed: \(error.localizedDescription)"
    }
}

struct SetupView: View {
    @ObservedObject var installer: ExtensionManager
    @Environment(\.dismiss) private var dismiss

    var body: some View {
        VStack(alignment: .leading, spacing: 18) {
            Text("Set up the Moat filter").font(.system(size: 22, weight: .semibold))
            Text("Moat uses a macOS content filter (a Network Extension) to see and decide outbound connections on this Mac. macOS will ask you to approve it. Until a signed policy is applied, Moat only observes.")
                .foregroundColor(.secondary).fixedSize(horizontal: false, vertical: true)
            step(1, "Activate the system extension", installer.extensionState, "Activate") { installer.activate() }
            step(2, "Enable the content filter", installer.filterState, "Enable") { installer.enableFilter() }
            Text("Inbound connections are not filtered. Process ancestry is not available without Endpoint Security. Nothing here bypasses macOS approval prompts.")
                .font(.footnote).foregroundColor(.secondary).fixedSize(horizontal: false, vertical: true)
            HStack {
                Button("Remove extension…", role: .destructive) { installer.deactivate() }
                Spacer()
                Button("Done") { dismiss() }.keyboardShortcut(.defaultAction)
            }
        }
        .padding(28)
        .frame(width: 520)
        .disabled(installer.busy)
    }

    private func step(_ n: Int, _ title: String, _ state: String, _ action: String, _ run: @escaping () -> Void) -> some View {
        HStack(alignment: .top, spacing: 12) {
            Text("\(n)").font(.headline).frame(width: 26, height: 26).background(Circle().fill(Color.accentColor.opacity(0.15)))
            VStack(alignment: .leading, spacing: 2) {
                Text(title).font(.headline)
                Text(state).font(.callout).foregroundColor(.secondary).fixedSize(horizontal: false, vertical: true)
            }
            Spacer()
            Button(action, action: run)
        }
    }
}
