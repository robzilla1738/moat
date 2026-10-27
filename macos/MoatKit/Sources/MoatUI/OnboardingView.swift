import MoatKit
import SwiftUI

/// State the onboarding shows. The app feeds it from the real ExtensionManager and the trusted-keys file; demo and
/// screenshot modes feed canned values. It never changes trust: the signer key is added by the owner with sudo.
@MainActor
public final class OnboardingState: ObservableObject {
    @Published public var extensionState: String
    @Published public var extensionActive: Bool
    @Published public var filterState: String
    @Published public var filterEnabled: Bool
    @Published public var busy = false
    @Published public var trustedKeyIDs: [String]
    @Published public var trustProblems: [String]
    public var activate: () -> Void
    public var enableFilter: () -> Void
    public var recheckTrust: () -> Void
    public var revealTrustFolder: () -> Void

    public init(
        extensionState: String = "Not requested", extensionActive: Bool = false,
        filterState: String = "Not configured", filterEnabled: Bool = false,
        trustedKeyIDs: [String] = [], trustProblems: [String] = [],
        activate: @escaping () -> Void = {}, enableFilter: @escaping () -> Void = {},
        recheckTrust: @escaping () -> Void = {}, revealTrustFolder: @escaping () -> Void = {}
    ) {
        self.extensionState = extensionState
        self.extensionActive = extensionActive
        self.filterState = filterState
        self.filterEnabled = filterEnabled
        self.trustedKeyIDs = trustedKeyIDs
        self.trustProblems = trustProblems
        self.activate = activate
        self.enableFilter = enableFilter
        self.recheckTrust = recheckTrust
        self.revealTrustFolder = revealTrustFolder
    }

    /// Re-read the owner's trusted-keys file (read-only).
    public func loadTrust(path: String = TrustConfig.defaultPath) {
        let (c, problems) = TrustConfig.load(path: path)
        trustedKeyIDs = c.activeKeyIDs
        trustProblems = problems
    }
}

public enum OnboardingStep: Int, CaseIterable, Identifiable, Sendable {
    case welcome, coverage, approve, filter, trust, done
    public var id: Int { rawValue }

    var title: String {
        switch self {
        case .welcome: return "Welcome"
        case .coverage: return "What Moat can claim"
        case .approve: return "Approve the extension"
        case .filter: return "Turn on the filter"
        case .trust: return "Trust your signer key"
        case .done: return "Ready"
        }
    }

    var symbol: String {
        switch self {
        case .welcome: return "shield.lefthalf.filled"
        case .coverage: return "checklist"
        case .approve: return "puzzlepiece.extension"
        case .filter: return "line.3.horizontal.decrease.circle"
        case .trust: return "key.horizontal"
        case .done: return "checkmark.seal"
        }
    }
}

/// First-run onboarding. Glass is used for the step indicator and the navigation controls only.
public struct OnboardingView: View {
    @ObservedObject var state: OnboardingState
    @State var step: OnboardingStep
    var finish: () -> Void
    @Environment(\.colorScheme) private var scheme
    @Environment(\.accessibilityReduceMotion) private var reduceMotion
    @Namespace private var ns

    public init(state: OnboardingState, step: OnboardingStep = .welcome, finish: @escaping () -> Void) {
        self.state = state
        _step = State(initialValue: step)
        self.finish = finish
    }

    public var body: some View {
        let p = Palette.of(scheme)
        VStack(spacing: 0) {
            indicator(p)
                .padding(.top, 22)
            ScrollView {
                VStack(alignment: .leading, spacing: 18) {
                    Label(step.title, systemImage: step.symbol)
                        .font(.title.weight(.bold))
                        .symbolRenderingMode(.hierarchical)
                        .foregroundStyle(p.text)
                        .accessibilityAddTraits(.isHeader)
                    content(p)
                }
                .padding(.horizontal, 40)
                .padding(.vertical, 26)
                .frame(maxWidth: .infinity, alignment: .leading)
                .id(step)
                .transition(reduceMotion ? AnyTransition.identity : AnyTransition.opacity.combined(with: .move(edge: .trailing)))
            }
            .moatScrollEdge()
            controls(p)
                .padding(.horizontal, 28)
                .padding(.bottom, 22)
        }
        .frame(width: 640, height: 600)
        .background(Backdrop())
        .environment(\.palette, p)
        .tint(p.accentStrong)
        .disabled(state.busy)
    }

    // MARK: indicator

    private func indicator(_ p: Palette) -> some View {
        MoatGlassContainer(spacing: 6) {
            HStack(spacing: 6) {
                ForEach(OnboardingStep.allCases) { s in
                    let current = s == step
                    let done = s.rawValue < step.rawValue
                    HStack(spacing: 6) {
                        Image(systemName: done ? "checkmark" : s.symbol).font(.caption.weight(.bold))
                        if current { Text(s.title).font(.caption.weight(.semibold)).lineLimit(1) }
                    }
                    // Light glass tints pale: the current step's label takes the accent there, white on the dark tint.
                    .foregroundStyle(current ? (scheme == .dark ? Color.white : p.accent) : (done ? p.accent : p.text2))
                    .padding(.horizontal, current ? 12 : 8)
                    .frame(height: 28)
                    .moatGlass(in: Capsule(), tint: current ? p.accent : nil)
                    .moatGlassID(s, in: ns, reduceMotion: reduceMotion)
                    .accessibilityElement(children: .ignore)
                    .accessibilityLabel("Step \(s.rawValue + 1) of \(OnboardingStep.allCases.count): \(s.title)\(done ? ", done" : current ? ", current" : "")")
                }
            }
        }
    }

    // MARK: content

    @ViewBuilder private func content(_ p: Palette) -> some View {
        switch step {
        case .welcome:
            para("Moat explains and controls what leaves this Mac: which app made a connection, what your signed policy decided, and how to stop it.", p)
            para("Setup takes three approvals, all yours: macOS asks you to allow the system extension, then to allow network filtering, and you choose which signing key may change policy.", p)
            fact("Nothing here bypasses a macOS approval prompt.", symbol: "hand.raised", p)
            fact("Until a signed policy is applied, Moat only observes.", symbol: "eye", p)
        case .coverage:
            para("Moat labels every claim honestly. On this Mac today:", p)
            coverageRow("Per-app decisions", "Untested", .blue, "Implemented in the content filter; not yet proven on a signed install.", p)
            coverageRow("Process ancestry", "Not available", .neutral, "Needs the Endpoint Security entitlement, which is not requested.", p)
            coverageRow("Protected sessions", "Not on macOS", .neutral, "Session rules are left out of this Mac's policy and reported. Linux supports them.", p)
            coverageRow("Fail-closed if the filter stops", "Not claimed", .amber, "Not measured on a real device yet.", p)
            coverageRow("VPN compatibility", "Not claimed", .amber, "No VPN combination has been tested yet.", p)
            coverageRow("Phones and the TV", "DNS-only", .violet, "Covered by the home resolver: no per-app identity, no byte counts, no direct-IP blocking.", p)
        case .approve:
            para("macOS runs Moat's filter as a system extension. Click Install, then approve it in System Settings › General › Login Items & Extensions › Network Extensions.", p)
            statusLine(state.extensionState, ok: state.extensionActive, p)
            MoatButton(title: state.extensionActive ? "Installed" : "Install extension", systemImage: "puzzlepiece.extension", kind: .primary, disabled: state.extensionActive) { state.activate() }
            fact("You can remove it later from Recovery or by moving Moat to the Trash.", symbol: "trash", p)
        case .filter:
            para("Next, macOS asks whether Moat may filter network content. Moat sees outbound connections only; inbound connections are not filtered.", p)
            statusLine(state.filterState, ok: state.filterEnabled, p)
            MoatButton(title: state.filterEnabled ? "Filter on" : "Turn on filter", systemImage: "line.3.horizontal.decrease.circle", kind: .primary, disabled: state.filterEnabled) { state.enableFilter() }
            fact("To switch Moat off at any time: System Settings › Network › Filters.", symbol: "switch.2", p)
        case .trust:
            para("Moat only installs policy signed by a key you trust. You add the public key yourself; Moat never adds or promotes a key on its own, and nothing over its control channel can change trust.", p)
            Text("sudo mkdir -p \"/Library/Application Support/Moat\"\nsudo sh -c 'cat signer.key.pub >> \"/Library/Application Support/Moat/trusted-keys\"'")
                .font(.system(.callout, design: .monospaced))
                .textSelection(.enabled)
                .padding(12)
                .frame(maxWidth: .infinity, alignment: .leading)
                .background(RoundedRectangle(cornerRadius: 12, style: .continuous).fill(p.surface))
                .overlay(RoundedRectangle(cornerRadius: 12, style: .continuous).strokeBorder(p.border, lineWidth: 1))
            if state.trustedKeyIDs.isEmpty {
                statusLine(state.trustProblems.first ?? "No trusted signer key yet. Every snapshot is rejected until you add one.", ok: false, p)
            } else {
                statusLine("Trusted signer key\(state.trustedKeyIDs.count == 1 ? "" : "s"): \(state.trustedKeyIDs.joined(separator: ", "))", ok: true, p)
            }
            HStack(spacing: 8) {
                MoatButton(title: "Check again", systemImage: "arrow.clockwise") { state.recheckTrust() }
                MoatButton(title: "Show folder", systemImage: "folder") { state.revealTrustFolder() }
            }
        case .done:
            para("Moat is set up as far as this Mac allows. The Overview shows exactly what is covered; anything untested stays labelled untested until it is proven here.", p)
            fact(state.extensionActive ? "System extension approved" : "System extension not approved yet", symbol: state.extensionActive ? "checkmark.circle.fill" : "exclamationmark.circle", p)
            fact(state.filterEnabled ? "Content filter on" : "Content filter off", symbol: state.filterEnabled ? "checkmark.circle.fill" : "exclamationmark.circle", p)
            fact(state.trustedKeyIDs.isEmpty ? "No trusted signer key: policy will be rejected" : "Signer key trusted", symbol: state.trustedKeyIDs.isEmpty ? "exclamationmark.circle" : "checkmark.circle.fill", p)
        }
    }

    private func para(_ text: String, _ p: Palette) -> some View {
        Text(text).font(.title3).foregroundStyle(p.text2).fixedSize(horizontal: false, vertical: true)
    }

    private func fact(_ text: String, symbol: String, _ p: Palette) -> some View {
        Label(text, systemImage: symbol).font(.body).foregroundStyle(p.text).fixedSize(horizontal: false, vertical: true)
    }

    private func statusLine(_ text: String, ok: Bool, _ p: Palette) -> some View {
        Label(text, systemImage: ok ? "checkmark.circle.fill" : "circle.dashed")
            .font(.callout.weight(.medium))
            .foregroundStyle(ok ? p.green : p.text2)
            .fixedSize(horizontal: false, vertical: true)
    }

    private func coverageRow(_ title: String, _ label: String, _ tone: Tone, _ note: String, _ p: Palette) -> some View {
        HStack(alignment: .top, spacing: 12) {
            VStack(alignment: .leading, spacing: 2) {
                Text(title).font(.body.weight(.semibold))
                Text(note).font(.callout).foregroundStyle(p.text2).fixedSize(horizontal: false, vertical: true)
            }
            Spacer(minLength: 8)
            Pill(text: label, tone: tone)
        }
        .padding(.vertical, 2)
        .accessibilityElement(children: .combine)
    }

    // MARK: controls

    private func controls(_ p: Palette) -> some View {
        HStack {
            if step != .welcome {
                Button { go(-1) } label: { Label("Back", systemImage: "chevron.left") }
                    .moatButtonStyle()
                    .controlSize(.large)
            }
            Spacer()
            if step == .done {
                Button("Open Moat", action: finish).moatButtonStyle(prominent: true).controlSize(.large).keyboardShortcut(.defaultAction)
            } else {
                Button("Skip setup", action: finish).buttonStyle(.plain).foregroundStyle(p.muted)
                Button { go(1) } label: { Label("Continue", systemImage: "chevron.right") }
                    .moatButtonStyle(prominent: true)
                    .controlSize(.large)
                    .keyboardShortcut(.defaultAction)
            }
        }
    }

    private func go(_ d: Int) {
        guard let next = OnboardingStep(rawValue: step.rawValue + d) else { return }
        withAnimation(reduceMotion ? nil : .snappy(duration: 0.32)) { step = next }
    }
}
