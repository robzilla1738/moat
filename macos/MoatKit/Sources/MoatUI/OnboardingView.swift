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
        case .coverage: return "What Moat can do here"
        case .approve: return "Allow Moat's filter"
        case .filter: return "Turn on filtering"
        case .trust: return "Choose who may change rules"
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

/// First-run onboarding: what Moat does in one or two sentences, then the three approvals, each with a clear next step.
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
                .padding(.top, Space.s6)
            ScrollView {
                VStack(alignment: .leading, spacing: Space.s5) {
                    Label(step.title, systemImage: step.symbol)
                        .font(.title.weight(.bold))
                        .symbolRenderingMode(.hierarchical)
                        .foregroundStyle(p.text)
                        .accessibilityAddTraits(.isHeader)
                    content(p)
                }
                .padding(.horizontal, Space.s10)
                .padding(.vertical, Space.s6)
                .frame(maxWidth: .infinity, alignment: .leading)
                .id(step)
                .transition(reduceMotion ? AnyTransition.identity : AnyTransition.opacity.combined(with: .move(edge: .trailing)))
            }
            .moatScrollEdge()
            controls(p)
                .padding(.horizontal, Space.s8)
                .padding(.bottom, Space.s6)
        }
        .frame(width: 640, height: 600)
        .background(Backdrop())
        .environment(\.palette, p)
        .tint(p.accentStrong)
        .disabled(state.busy)
    }

    // MARK: indicator

    private func indicator(_ p: Palette) -> some View {
        MoatGlassContainer(spacing: Space.s2) {
            HStack(spacing: Space.s2) {
                ForEach(OnboardingStep.allCases) { s in
                    let current = s == step
                    let done = s.rawValue < step.rawValue
                    HStack(spacing: Space.s2) {
                        Image(systemName: done ? "checkmark" : s.symbol).font(.caption.weight(.bold))
                        if current { Text(s.title).font(.caption.weight(.semibold)).lineLimit(1) }
                    }
                    // The current step's label takes the accent on the pale light tint and white on the dark one.
                    .foregroundStyle(current ? (scheme == .dark ? BrandColor.onTint : p.accent) : (done ? p.accent : p.text2))
                    .padding(.horizontal, current ? Space.s3 : Space.s2)
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
            para("Moat shows which apps on this Mac connect to the internet, and blocks what you haven't allowed.", p)
            para("Setup takes three approvals, all yours: allow Moat's filter, let it filter network traffic, and choose who may change your rules.", p)
            fact("Nothing here gets around a macOS approval prompt.", symbol: "hand.raised", p)
            fact("Until you install signed rules, Moat only watches.", symbol: "eye", p)
        case .coverage:
            para("Moat only claims what it has shown working. On this Mac today:", p)
            coverageRow("Blocking per app", "Not proven yet", .blue, "Built into the filter; not yet shown on a signed install.", p)
            coverageRow("Seeing which app started another", "Not available", .neutral, "Needs an Apple permission Moat doesn't request.", p)
            coverageRow("Protected tasks", "Not on macOS", .neutral, "Rules for tasks are left out of this Mac's rules and reported. Linux supports them.", p)
            coverageRow("Blocking if the filter stops", "Not claimed", .amber, "Not measured on a real device yet.", p)
            coverageRow("Working with VPNs", "Not claimed", .amber, "No VPN has been tested yet.", p)
            coverageRow("Phones and the TV", "Web filter only", .violet, "Covered by your home web filter: no per-app view, no data counts, and direct connections aren't blocked.", p)
        case .approve:
            para("macOS runs Moat's filter as a system extension. Click Install, then allow it in System Settings › General › Login Items & Extensions › Network Extensions.", p)
            statusLine(state.extensionState, ok: state.extensionActive, p)
            MoatButton(title: state.extensionActive ? "Installed" : "Install the filter", systemImage: "puzzlepiece.extension", kind: .primary, disabled: state.extensionActive) { state.activate() }
            fact("You can remove it later from Coverage & recovery, or by moving Moat to the Trash.", symbol: "trash", p)
        case .filter:
            para("Next, macOS asks whether Moat may filter network traffic. Moat only sees connections going out; connections coming in aren't filtered.", p)
            statusLine(state.filterState, ok: state.filterEnabled, p)
            MoatButton(title: state.filterEnabled ? "Filtering on" : "Turn on filtering", systemImage: "line.3.horizontal.decrease.circle", kind: .primary, disabled: state.filterEnabled) { state.enableFilter() }
            fact("To switch Moat off at any time: System Settings › Network › Filters.", symbol: "switch.2", p)
        case .trust:
            para("Moat only installs rules signed by a key you trust. You add that key yourself: Moat never adds one on its own, and nothing sent to it over the network can change who you trust.", p)
            Text(verbatim: "sudo mkdir -p \"/Library/Application Support/Moat\"\nsudo sh -c 'cat signer.key.pub >> \"/Library/Application Support/Moat/trusted-keys\"'")
                .font(.system(.callout, design: .monospaced))
                .textSelection(.enabled)
                .padding(Space.s3)
                .frame(maxWidth: .infinity, alignment: .leading)
                .background(RoundedRectangle(cornerRadius: Radius.inner, style: .continuous).fill(p.surface))
                .overlay(RoundedRectangle(cornerRadius: Radius.inner, style: .continuous).strokeBorder(p.border, lineWidth: 1))
            if state.trustedKeyIDs.isEmpty {
                statusLine(state.trustProblems.first ?? "No trusted key yet. Moat refuses every set of rules until you add one.", ok: false, p)
            } else {
                statusLine("Trusted key\(state.trustedKeyIDs.count == 1 ? "" : "s"): \(state.trustedKeyIDs.joined(separator: ", "))", ok: true, p)
            }
            HStack(spacing: Space.s2) {
                MoatButton(title: "Check again", systemImage: "arrow.clockwise") { state.recheckTrust() }
                MoatButton(title: "Show folder", systemImage: "folder") { state.revealTrustFolder() }
            }
        case .done:
            para("Moat is set up as far as this Mac allows. Apps shows exactly what is protected; anything not proven stays labelled until it is proven here.", p)
            fact(state.extensionActive ? "Filter allowed" : "Filter not allowed yet", symbol: state.extensionActive ? "checkmark.circle.fill" : "exclamationmark.circle", p)
            fact(state.filterEnabled ? "Filtering on" : "Filtering off", symbol: state.filterEnabled ? "checkmark.circle.fill" : "exclamationmark.circle", p)
            fact(state.trustedKeyIDs.isEmpty ? "No trusted key: rules will be refused" : "Key trusted", symbol: state.trustedKeyIDs.isEmpty ? "exclamationmark.circle" : "checkmark.circle.fill", p)
        }
    }

    private func para(_ text: String, _ p: Palette) -> some View {
        Text(verbatim: text).font(.title3).foregroundStyle(p.text2).fixedSize(horizontal: false, vertical: true)
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
        HStack(alignment: .top, spacing: Space.s3) {
            VStack(alignment: .leading, spacing: Space.s1) {
                Text(verbatim: title).font(.body.weight(.semibold))
                Text(verbatim: note).font(.callout).foregroundStyle(p.text2).fixedSize(horizontal: false, vertical: true)
            }
            Spacer(minLength: 8)
            Pill(text: label, tone: tone)
        }
        .padding(.vertical, Space.s1)
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
