import MoatKit
import SwiftUI

/// The whole app window: sidebar + current screen. Drawn entirely in SwiftUI (no List / NavigationSplitView),
/// so `ImageRenderer` can produce faithful screenshots in CI.
public struct RootView: View {
    @ObservedObject var model: AppModel
    @Environment(\.colorScheme) private var scheme
    /// Screenshots render without a ScrollView (ImageRenderer cannot draw AppKit-backed scroll views).
    var scrollable: Bool

    public init(model: AppModel, scrollable: Bool = true) {
        self.model = model
        self.scrollable = scrollable
    }

    public var body: some View {
        let p = Palette.of(scheme)
        HStack(spacing: 0) {
            Sidebar(model: model)
                .frame(width: 228)
                .background(p.surface.opacity(scheme == .dark ? 0.55 : 0.8))
            Rectangle().fill(p.border).frame(width: 1)
            Group {
                if scrollable {
                    ScrollView { content.padding(28) }
                } else {
                    // Fixed frame, top-aligned: overflow is clipped at the bottom, like a window that needs scrolling.
                    GeometryReader { geo in
                        content.padding(28)
                            .frame(width: geo.size.width, height: geo.size.height, alignment: .topLeading)
                            .clipped()
                    }
                }
            }
            .frame(maxWidth: .infinity, maxHeight: .infinity, alignment: .topLeading)
        }
        .background(
            ZStack {
                p.bg
                RadialGradient(colors: [p.accent.opacity(scheme == .dark ? 0.10 : 0.07), .clear], center: UnitPoint(x: 0.75, y: -0.1), startRadius: 0, endRadius: 650)
                RadialGradient(colors: [p.accent2.opacity(0.06), .clear], center: UnitPoint(x: -0.1, y: 0.1), startRadius: 0, endRadius: 500)
            })
        .environment(\.palette, p)
        .foregroundColor(p.text)
    }

    @ViewBuilder private var content: some View {
        VStack(alignment: .leading, spacing: 20) {
            Banner(model: model)
            switch model.screen {
            case .overview: OverviewScreen(model: model)
            case .activity: ActivityScreen(model: model)
            case .policy: PolicyScreen(model: model)
            case .coverage: CoverageScreen(model: model)
            case .recovery: RecoveryScreen(model: model)
            }
        }
        .frame(maxWidth: 980, alignment: .leading)
    }
}

struct Sidebar: View {
    @ObservedObject var model: AppModel
    @Environment(\.palette) private var p

    var body: some View {
        VStack(alignment: .leading, spacing: 4) {
            HStack(spacing: 10) {
                ZStack {
                    RoundedRectangle(cornerRadius: 9, style: .continuous)
                        .fill(LinearGradient(colors: [p.accent, p.accent2], startPoint: .topLeading, endPoint: .bottomTrailing))
                        .frame(width: 30, height: 30)
                    Image(systemName: "shield.lefthalf.filled").font(.system(size: 15, weight: .bold)).foregroundColor(.white)
                }
                VStack(alignment: .leading, spacing: 0) {
                    Text("Moat").font(.system(size: 16, weight: .bold))
                    Text("This Mac").font(.system(size: 11.5)).foregroundColor(p.muted)
                }
            }
            .padding(.bottom, 18)
            .padding(.top, 6)

            ForEach(Screen.allCases) { s in
                let on = s == model.screen
                Button { model.screen = s } label: {
                    HStack(spacing: 10) {
                        Image(systemName: s.symbol).font(.system(size: 13, weight: .semibold)).frame(width: 18)
                        Text(s.title).font(.system(size: 13.5, weight: on ? .semibold : .medium))
                        Spacer()
                        if s == .recovery, model.status?.isolation.active == true {
                            Circle().fill(p.red).frame(width: 7, height: 7)
                        }
                    }
                    .foregroundColor(on ? p.text : p.text2)
                    .padding(.horizontal, 10)
                    .padding(.vertical, 8)
                    .background(RoundedRectangle(cornerRadius: 9, style: .continuous).fill(on ? p.surface3 : Color.clear))
                    .contentShape(Rectangle())
                }
                .buttonStyle(.plain)
            }
            Spacer()
            if let s = model.status {
                VStack(alignment: .leading, spacing: 6) {
                    Pill(text: s.coverage.label, tone: s.coverage.tone, dot: true)
                    Text(s.installed.map { "Policy r\($0.revision) · \($0.policyName)" } ?? "No signed policy")
                        .font(.system(size: 11.5)).foregroundColor(p.muted)
                    if model.isDemo {
                        Text("Demo data").font(.system(size: 11, weight: .semibold)).foregroundColor(p.amber)
                    }
                }
                .padding(12)
                .frame(maxWidth: .infinity, alignment: .leading)
                .background(RoundedRectangle(cornerRadius: 12, style: .continuous).fill(p.surface2))
                .overlay(RoundedRectangle(cornerRadius: 12, style: .continuous).strokeBorder(p.border, lineWidth: 1))
            }
        }
        .padding(16)
        .frame(maxHeight: .infinity, alignment: .top)
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
            Image(systemName: symbol).foregroundColor(tone.color(p))
            Text(text).font(.system(size: 13)).foregroundColor(p.text).fixedSize(horizontal: false, vertical: true)
            Spacer()
            Button { model.lastError = nil; model.notice = nil } label: {
                Image(systemName: "xmark").font(.system(size: 11, weight: .bold)).foregroundColor(p.muted)
            }.buttonStyle(.plain)
        }
        .padding(12)
        .background(RoundedRectangle(cornerRadius: 12, style: .continuous).fill(tone.color(p).opacity(0.1)))
        .overlay(RoundedRectangle(cornerRadius: 12, style: .continuous).strokeBorder(tone.color(p).opacity(0.25), lineWidth: 1))
    }
}

struct ScreenHeader: View {
    @Environment(\.palette) private var p
    let eyebrow: String
    let title: String
    var dim: String?

    var body: some View {
        VStack(alignment: .leading, spacing: 6) {
            Text(eyebrow.uppercased()).font(.system(size: 11, weight: .semibold)).tracking(1).foregroundColor(p.muted)
            (Text(title).foregroundColor(p.text) + Text(dim.map { " " + $0 } ?? "").foregroundColor(p.muted))
                .font(.system(size: 30, weight: .semibold))
                .fixedSize(horizontal: false, vertical: true)
        }
    }
}

struct EmptyStateView: View {
    @Environment(\.palette) private var p
    let text: String
    var body: some View {
        Card {
            HStack(spacing: 10) {
                Image(systemName: "antenna.radiowaves.left.and.right.slash").foregroundColor(p.muted)
                Text(text).foregroundColor(p.text2).font(.system(size: 13.5))
            }
        }
    }
}
