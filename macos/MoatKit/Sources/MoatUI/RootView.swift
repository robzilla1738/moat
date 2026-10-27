import MoatKit
import SwiftUI

/// The main window: a native NavigationSplitView sidebar, a unified toolbar carrying status and the two global
/// actions, and the card content on a flat canvas.
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
                    ScreenContent(model: model)
                        .padding(.horizontal, Space.s8)
                        .padding(.top, Space.s5)
                        .padding(.bottom, Space.s10)
                        .frame(maxWidth: 1120, alignment: .leading)
                }
                .frame(maxWidth: .infinity, alignment: .leading)
            }
            .moatScrollEdge()
            .background(Backdrop())
            .navigationTitle(model.screen.title(deviceCount: model.deviceCount))
            .toolbar { toolbar }
        }
        .environment(\.palette, p)
        .tint(p.accentStrong)
        .confirmationDialog("Lock down this Mac?", isPresented: $confirmIsolate) {
            Button("Lock down now", role: .destructive) { Task { await model.enterIsolation(reason: "Turned on from the Moat toolbar") } }
            Button("Cancel", role: .cancel) {}
        } message: {
            Text("New connections from this Mac are blocked, except to itself, until you turn lockdown off in Coverage & recovery. It never turns off on its own. Connections already open stay open.")
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
                    model.screen = .coverage
                } label: {
                    Label("Locked down", systemImage: "lock.shield.fill")
                }
                .help("Emergency lockdown is on. Open Coverage & recovery to turn it off.")
            } else {
                Button(role: .destructive) {
                    confirmIsolate = true
                } label: {
                    Label("Lock down", systemImage: "lock.shield")
                }
                .help("Emergency lockdown: block new connections from this Mac (asks first)")
            }
        }
    }
}

/// Coverage status shown in the toolbar (the system draws the toolbar itself).
struct CoverageBadge: View {
    @Environment(\.palette) private var p
    @Environment(\.accessibilityReduceMotion) private var reduceMotion
    let status: StatusReport

    var body: some View {
        HStack(spacing: Space.s2) {
            Image(systemName: status.coverage.symbol)
                .foregroundStyle(status.coverage.tone.color(p))
                .moatPulse(status.coverage == .isolated || status.coverage == .degraded, reduceMotion: reduceMotion)
            Text(verbatim: status.coverage.label).font(.callout.weight(.semibold))
        }
        .padding(.horizontal, Space.s2)
        .accessibilityElement(children: .combine)
        .accessibilityLabel("Coverage: \(status.coverage.label). \(status.coverage.claim)")
    }
}

/// The canvas behind the cards: one flat, cool tone (no gradients, no translucency).
struct Backdrop: View {
    @Environment(\.palette) private var p

    var body: some View {
        p.bg.ignoresSafeArea()
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
        VStack(alignment: .leading, spacing: Space.s6) {
            Banner(model: model)
            switch model.screen {
            case .apps: AppsScreen(model: model, heroShown: heroShown)
            case .activity: ActivityScreen(model: model)
            case .tasks: TasksScreen(model: model)
            case .rules: PolicyScreen(model: model)
            case .devices: ThisComputerScreen(model: model)
            case .coverage: CoverageRecoveryScreen(model: model)
            case .appDetail: AppDetailScreen(model: model)
            case .whatChanged: WhatChangedScreen(model: model)
            case .learning: LearningScreen(model: model)
            case .candidate: CandidateReviewScreen(model: model)
            case .packs: PacksScreen(model: model)
            }
        }
    }
}

struct Sidebar: View {
    @ObservedObject var model: AppModel
    @Environment(\.palette) private var p

    private var selection: Binding<Screen?> {
        // Detail screens keep their parent highlighted in the sidebar.
        Binding(get: { model.screen == .appDetail || model.screen == .whatChanged ? .apps : [.learning, .candidate, .packs].contains(model.screen) ? .rules : model.screen }, set: { if let s = $0 { model.screen = s } })
    }

    var body: some View {
        List(selection: selection) {
            ForEach(Screen.sidebar) { row($0) }
        }
        .listStyle(.sidebar)
        .safeAreaInset(edge: .top, spacing: 0) {
            HStack(spacing: Space.s3) {
                AppMark(size: 30)
                VStack(alignment: .leading, spacing: 0) {
                    Text("Moat").font(.headline)
                    Text(model.deviceCount <= 1 ? "This computer" : "\(model.deviceCount) devices").font(.caption).foregroundStyle(p.muted)
                }
                Spacer()
            }
            .padding(.horizontal, Space.s5)
            .padding(.vertical, Space.s3)
            .accessibilityElement(children: .combine)
        }
        .safeAreaInset(edge: .bottom, spacing: 0) {
            if let s = model.status {
                VStack(alignment: .leading, spacing: Space.s2) {
                    Pill(text: s.coverage.label, tone: s.coverage.tone, dot: true)
                    Text(verbatim: s.installed.map { "Rules: \($0.policyName)" } ?? "No signed rules yet")
                        .font(.caption).foregroundStyle(p.text2).lineLimit(2)
                    if model.isDemo {
                        Label("Sample data", systemImage: "info.circle").font(.caption.weight(.semibold)).foregroundStyle(p.accent)
                    }
                }
                .padding(Space.s3)
                .frame(maxWidth: .infinity, alignment: .leading)
                .background(RoundedRectangle(cornerRadius: Radius.inner, style: .continuous).fill(p.surface))
                .overlay(RoundedRectangle(cornerRadius: Radius.inner, style: .continuous).strokeBorder(p.border, lineWidth: 1))
                .padding(Space.s3)
                .accessibilityElement(children: .combine)
            }
        }
    }

    private func row(_ s: Screen) -> some View {
        Label {
            HStack {
                Text(s.title(deviceCount: model.deviceCount))
                Spacer()
                if s == .coverage, model.status?.isolation.active == true {
                    Circle().fill(p.red).frame(width: Space.s2, height: Space.s2).accessibilityLabel("lockdown on")
                }
                if s == .activity, let n = model.status?.flowsDenied, n > 0 {
                    Text("\(n)").font(.caption.monospacedDigit()).foregroundStyle(.secondary).accessibilityLabel("\(n) blocked")
                }
            }
        } icon: {
            Image(systemName: s.symbol)
        }
        .tag(s)
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
        HStack(alignment: .top, spacing: Space.s3) {
            Image(systemName: symbol).foregroundStyle(tone.color(p)).accessibilityHidden(true)
            Text(verbatim: text).font(.callout).foregroundStyle(p.text).fixedSize(horizontal: false, vertical: true)
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
        .padding(Space.s3)
        .background(RoundedRectangle(cornerRadius: Radius.inner, style: .continuous).fill(tone.color(p).opacity(0.10)))
        .overlay(RoundedRectangle(cornerRadius: Radius.inner, style: .continuous).strokeBorder(tone.color(p).opacity(0.3), lineWidth: 1))
        .accessibilityElement(children: .combine)
    }
}

struct ScreenHeader: View {
    @Environment(\.palette) private var p
    let eyebrow: String
    let title: String
    var dim: String?

    var body: some View {
        VStack(alignment: .leading, spacing: Space.s2) {
            Text(eyebrow).font(.subheadline.weight(.semibold)).foregroundStyle(p.muted)
            Text(title).font(.system(size: TypeScale.x2l, weight: .bold)).foregroundStyle(p.text).fixedSize(horizontal: false, vertical: true)
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
        VStack(spacing: Space.s3) {
            Image(systemName: symbol).font(.system(size: TypeScale.x3l, weight: .light)).foregroundStyle(p.muted).accessibilityHidden(true)
            Text(title).font(.title3.weight(.semibold))
            Text(text).font(.callout).foregroundStyle(p.text2).multilineTextAlignment(.center).fixedSize(horizontal: false, vertical: true)
        }
        .frame(maxWidth: .infinity)
        .padding(.vertical, Space.s10)
        .padding(.horizontal, Space.s6)
        .background(RoundedRectangle(cornerRadius: Radius.card, style: .continuous).fill(p.surface))
        .overlay(RoundedRectangle(cornerRadius: Radius.card, style: .continuous).strokeBorder(p.borderStrong, style: StrokeStyle(lineWidth: 1, dash: [5, 4])))
        .accessibilityElement(children: .combine)
    }
}
