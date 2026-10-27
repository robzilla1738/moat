import MoatKit
import SwiftUI

/// The main window: a NavigationSplitView with the system's floating glass sidebar on macOS 26, a glass toolbar
/// carrying status and the two global actions, and content that leads underneath.
public struct RootView: View {
    @ObservedObject var model: AppModel
    @Environment(\.colorScheme) private var scheme
    @State private var columns: NavigationSplitViewVisibility = .all
    @State private var confirmIsolate = false

    public init(model: AppModel) {
        self.model = model
    }

    public var body: some View {
        let p = Palette.of(scheme)
        NavigationSplitView(columnVisibility: $columns) {
            Sidebar(model: model)
                .navigationSplitViewColumnWidth(min: 210, ideal: 232, max: 300)
        } detail: {
            ScrollView {
                VStack(alignment: .leading, spacing: 0) {
                    if model.screen == .overview, let s = model.status {
                        OverviewHero(status: s)
                    }
                    ScreenContent(model: model, heroShown: model.screen == .overview && model.status != nil)
                        .padding(.horizontal, 32)
                        .padding(.top, model.screen == .overview ? 22 : 8)
                        .padding(.bottom, 40)
                        .frame(maxWidth: 1040, alignment: .leading)
                }
                .frame(maxWidth: .infinity, alignment: .leading)
            }
            .moatScrollEdge()
            .background(Backdrop())
            .navigationTitle(model.screen.title)
            .toolbar { toolbar }
        }
        .environment(\.palette, p)
        .tint(p.accent)
        .confirmationDialog("Isolate this Mac?", isPresented: $confirmIsolate) {
            Button("Isolate now", role: .destructive) { Task { await model.enterIsolation(reason: "Turned on from the Moat toolbar") } }
            Button("Cancel", role: .cancel) {}
        } message: {
            Text("All network access except loopback is blocked until you turn isolation off in Recovery. It does not reopen on its own.")
        }
    }

    @ToolbarContentBuilder private var toolbar: some ToolbarContent {
        ToolbarItem(placement: .navigation) {
            if let s = model.status {
                CoverageBadge(status: s)
            }
        }
        ToolbarItemGroup(placement: .primaryAction) {
            Button {
                Task { await model.refresh() }
            } label: {
                Label("Refresh", systemImage: "arrow.clockwise")
            }
            .help("Ask the filter for its current status")
            if model.status?.isolation.active == true {
                Button {
                    model.screen = .recovery
                } label: {
                    Label("Isolated", systemImage: "lock.shield.fill")
                }
                .help("Emergency isolation is on. Open Recovery to turn it off.")
            } else {
                Button(role: .destructive) {
                    confirmIsolate = true
                } label: {
                    Label("Isolate", systemImage: "lock.shield")
                }
                .help("Emergency isolation: block everything except loopback (asks first)")
            }
        }
    }
}

/// Coverage status shown in the toolbar (the toolbar supplies the glass on macOS 26).
struct CoverageBadge: View {
    @Environment(\.palette) private var p
    @Environment(\.accessibilityReduceMotion) private var reduceMotion
    let status: StatusReport

    var body: some View {
        HStack(spacing: 6) {
            Image(systemName: status.coverage.symbol)
                .foregroundStyle(status.coverage.tone.color(p))
                .moatPulse(status.coverage == .isolated || status.coverage == .degraded, reduceMotion: reduceMotion)
            Text(status.coverage.label).font(.callout.weight(.semibold))
            if let i = status.installed {
                Text("r\(i.revision)").font(.callout.monospacedDigit()).foregroundStyle(p.muted)
            }
        }
        .padding(.horizontal, 6)
        .accessibilityElement(children: .combine)
        .accessibilityLabel("Coverage: \(status.coverage.label). \(status.coverage.claim)")
    }
}

/// Quiet window backdrop behind the content (the content itself stays opaque and readable).
struct Backdrop: View {
    @Environment(\.palette) private var p
    @Environment(\.colorScheme) private var scheme
    @Environment(\.accessibilityReduceTransparency) private var reduceTransparency

    var body: some View {
        ZStack {
            p.bg
            if !reduceTransparency {
                RadialGradient(colors: [p.accent.opacity(scheme == .dark ? 0.16 : 0.10), .clear], center: UnitPoint(x: 0.85, y: -0.15), startRadius: 0, endRadius: 720)
                RadialGradient(colors: [p.accent2.opacity(scheme == .dark ? 0.10 : 0.07), .clear], center: UnitPoint(x: 0.0, y: 0.0), startRadius: 0, endRadius: 560)
            }
        }
        .ignoresSafeArea()
    }
}

/// The current screen's content without any window chrome. Also used directly by tests (ImageRenderer cannot draw
/// NavigationSplitView or glass), so it must stay pure SwiftUI.
public struct ScreenContent: View {
    @ObservedObject var model: AppModel
    var heroShown: Bool

    public init(model: AppModel, heroShown: Bool = false) {
        self.model = model
        self.heroShown = heroShown
    }

    public var body: some View {
        VStack(alignment: .leading, spacing: 22) {
            Banner(model: model)
            switch model.screen {
            case .overview: OverviewScreen(model: model, heroShown: heroShown)
            case .activity: ActivityScreen(model: model)
            case .policy: PolicyScreen(model: model)
            case .coverage: CoverageScreen(model: model)
            case .recovery: RecoveryScreen(model: model)
            }
        }
    }
}

struct Sidebar: View {
    @ObservedObject var model: AppModel
    @Environment(\.palette) private var p

    private var selection: Binding<Screen?> {
        Binding(get: { model.screen }, set: { if let s = $0 { model.screen = s } })
    }

    var body: some View {
        List(selection: selection) {
            Section("Monitor") {
                row(.overview)
                row(.activity)
            }
            Section("Control") {
                row(.policy)
                row(.recovery)
            }
            Section("Trust") {
                row(.coverage)
            }
        }
        .listStyle(.sidebar)
        .safeAreaInset(edge: .top, spacing: 0) {
            HStack(spacing: 10) {
                AppMark(size: 30)
                VStack(alignment: .leading, spacing: 0) {
                    Text("Moat").font(.headline)
                    Text("This Mac").font(.caption).foregroundStyle(p.muted)
                }
                Spacer()
            }
            .padding(.horizontal, 18)
            .padding(.vertical, 10)
            .accessibilityElement(children: .combine)
        }
        .safeAreaInset(edge: .bottom, spacing: 0) {
            if let s = model.status {
                VStack(alignment: .leading, spacing: 6) {
                    Pill(text: s.coverage.label, tone: s.coverage.tone, dot: true)
                    Text(s.installed.map { "Policy r\($0.revision) · \($0.policyName)" } ?? "No signed policy")
                        .font(.caption).foregroundStyle(p.text2).lineLimit(2)
                    if model.isDemo {
                        Label("Demo data", systemImage: "theatermasks").font(.caption.weight(.semibold)).foregroundStyle(p.amber)
                    }
                }
                .padding(12)
                .frame(maxWidth: .infinity, alignment: .leading)
                .moatGlass(in: RoundedRectangle(cornerRadius: 14, style: .continuous))
                .padding(12)
                .accessibilityElement(children: .combine)
            }
        }
    }

    private func row(_ s: Screen) -> some View {
        Label {
            HStack {
                Text(s.title)
                Spacer()
                if s == .recovery, model.status?.isolation.active == true {
                    Circle().fill(p.red).frame(width: 7, height: 7).accessibilityLabel("isolation on")
                }
                if s == .activity, let n = model.status?.flowsDenied, n > 0 {
                    Text("\(n)").font(.caption.monospacedDigit()).foregroundStyle(p.muted).accessibilityLabel("\(n) blocked")
                }
            }
        } icon: {
            Image(systemName: s.symbol)
        }
        .tag(s)
    }
}

/// The Moat mark: a shield on the brand gradient.
struct AppMark: View {
    @Environment(\.palette) private var p
    var size: CGFloat = 30

    var body: some View {
        ZStack {
            RoundedRectangle(cornerRadius: size * 0.3, style: .continuous)
                .fill(LinearGradient(colors: [p.accent, p.accent2], startPoint: .topLeading, endPoint: .bottomTrailing))
            Image(systemName: "shield.lefthalf.filled").font(.system(size: size * 0.5, weight: .bold)).foregroundStyle(.white)
        }
        .frame(width: size, height: size)
        .accessibilityHidden(true)
    }
}

struct Banner: View {
    @ObservedObject var model: AppModel
    @Environment(\.palette) private var p

    var body: some View {
        if let e = model.lastError {
            message(e, tone: .red, symbol: "xmark.octagon.fill")
        } else if let n = model.notice {
            message(n, tone: .green, symbol: "checkmark.circle.fill")
        }
    }

    private func message(_ text: String, tone: Tone, symbol: String) -> some View {
        HStack(alignment: .top, spacing: 10) {
            Image(systemName: symbol).foregroundStyle(tone.color(p)).accessibilityHidden(true)
            Text(text).font(.callout).foregroundStyle(p.text).fixedSize(horizontal: false, vertical: true)
            Spacer()
            Button {
                model.lastError = nil
                model.notice = nil
            } label: {
                Image(systemName: "xmark").font(.caption.weight(.bold)).foregroundStyle(p.muted)
            }
            .buttonStyle(.plain)
            .accessibilityLabel("Dismiss")
        }
        .padding(12)
        .background(RoundedRectangle(cornerRadius: 14, style: .continuous).fill(tone.color(p).opacity(0.12)))
        .overlay(RoundedRectangle(cornerRadius: 14, style: .continuous).strokeBorder(tone.color(p).opacity(0.3), lineWidth: 1))
        .accessibilityElement(children: .combine)
    }
}

struct ScreenHeader: View {
    @Environment(\.palette) private var p
    let eyebrow: String
    let title: String
    var dim: String?

    var body: some View {
        VStack(alignment: .leading, spacing: 6) {
            Text(eyebrow).font(.subheadline.weight(.semibold)).foregroundStyle(p.accent)
            Text(title).font(.largeTitle.weight(.bold)).foregroundStyle(p.text).fixedSize(horizontal: false, vertical: true)
                .accessibilityAddTraits(.isHeader)
            if let dim {
                Text(dim).font(.title3).foregroundStyle(p.text2).fixedSize(horizontal: false, vertical: true)
            }
        }
    }
}

struct EmptyStateView: View {
    @Environment(\.palette) private var p
    let symbol: String
    let title: String
    let text: String

    init(symbol: String = "antenna.radiowaves.left.and.right.slash", title: String = "Waiting for the filter", text: String) {
        self.symbol = symbol
        self.title = title
        self.text = text
    }

    var body: some View {
        VStack(spacing: 10) {
            Image(systemName: symbol).font(.system(size: 34, weight: .light)).foregroundStyle(p.muted).accessibilityHidden(true)
            Text(title).font(.title3.weight(.semibold))
            Text(text).font(.callout).foregroundStyle(p.text2).multilineTextAlignment(.center).fixedSize(horizontal: false, vertical: true)
        }
        .frame(maxWidth: .infinity)
        .padding(.vertical, 36)
        .padding(.horizontal, 24)
        .background(RoundedRectangle(cornerRadius: 18, style: .continuous).fill(p.surface))
        .overlay(RoundedRectangle(cornerRadius: 18, style: .continuous).strokeBorder(p.border, style: StrokeStyle(lineWidth: 1, dash: [5, 4])))
        .accessibilityElement(children: .combine)
    }
}
