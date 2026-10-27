import MoatKit
import SwiftUI

struct PaletteKey: EnvironmentKey {
    static let defaultValue = Palette.dark
}

extension EnvironmentValues {
    var palette: Palette {
        get { self[PaletteKey.self] }
        set { self[PaletteKey.self] = newValue }
    }
}

/// Content surface. Content leads, so cards are quiet opaque surfaces, never glass.
struct Card<Content: View>: View {
    @Environment(\.palette) private var p
    @Environment(\.colorSchemeContrast) private var contrast
    var padding: CGFloat = 18
    @ViewBuilder var content: Content

    var body: some View {
        VStack(alignment: .leading, spacing: 12) { content }
            .padding(padding)
            .frame(maxWidth: .infinity, alignment: .leading)
            .background(RoundedRectangle(cornerRadius: 18, style: .continuous).fill(p.surface))
            .overlay(
                RoundedRectangle(cornerRadius: 18, style: .continuous)
                    .strokeBorder(contrast == .increased ? p.text.opacity(0.4) : p.border, lineWidth: 1))
    }
}

struct SectionTitle: View {
    @Environment(\.palette) private var p
    let text: String
    var trailing: String?

    var body: some View {
        HStack {
            Text(text)
                .font(.headline)
                .foregroundStyle(p.text)
                .accessibilityAddTraits(.isHeader)
            Spacer()
            if let trailing {
                Text(trailing).font(.subheadline).foregroundStyle(p.muted)
            }
        }
    }
}

enum Tone {
    case green, red, amber, violet, blue, neutral, accent

    func color(_ p: Palette) -> Color {
        switch self {
        case .green: return p.green
        case .red: return p.red
        case .amber: return p.amber
        case .violet: return p.violet
        case .blue: return p.blue
        case .neutral: return p.neutral
        case .accent: return p.accent
        }
    }
}

struct Pill: View {
    @Environment(\.palette) private var p
    let text: String
    var tone: Tone = .neutral
    var dot = false

    var body: some View {
        let c = tone.color(p)
        HStack(spacing: 5) {
            if dot { Circle().fill(c).frame(width: 6, height: 6).accessibilityHidden(true) }
            Text(text).font(.caption.weight(.semibold))
        }
        .foregroundStyle(c)
        .padding(.horizontal, 8)
        .padding(.vertical, 3)
        .background(Capsule().fill(c.opacity(0.13)))
        .overlay(Capsule().strokeBorder(c.opacity(0.28), lineWidth: 1))
        .accessibilityElement(children: .combine)
    }
}

struct Stat: View {
    @Environment(\.palette) private var p
    let label: String
    let value: String
    var sub: String?
    var tone: Tone?

    var body: some View {
        VStack(alignment: .leading, spacing: 4) {
            Text(label).font(.subheadline.weight(.medium)).foregroundStyle(p.muted)
            Text(value)
                .font(.system(.largeTitle, design: .rounded).weight(.semibold))
                .monospacedDigit()
                .foregroundStyle(tone.map { $0.color(p) } ?? p.text)
                .lineLimit(1)
                .minimumScaleFactor(0.6)
            if let sub { Text(sub).font(.caption).foregroundStyle(p.muted).lineLimit(2) }
        }
        .frame(maxWidth: .infinity, alignment: .leading)
        .padding(16)
        .background(RoundedRectangle(cornerRadius: 16, style: .continuous).fill(p.surface))
        .overlay(RoundedRectangle(cornerRadius: 16, style: .continuous).strokeBorder(p.border, lineWidth: 1))
        .accessibilityElement(children: .combine)
    }
}

/// A control button: `.glassProminent` (primary/danger) or `.glass` (secondary) on macOS 26, bordered styles before.
struct MoatButton: View {
    enum Kind { case primary, secondary, danger }
    let title: String
    var systemImage: String?
    var kind: Kind = .secondary
    var disabled = false
    let action: () -> Void

    var body: some View {
        Button(action: action) {
            if let systemImage {
                Label(title, systemImage: systemImage)
            } else {
                Text(title)
            }
        }
        .moatButtonStyle(prominent: kind != .secondary, destructive: kind == .danger)
        .controlSize(.large)
        .disabled(disabled)
    }
}

/// Segmented filter on a glass capsule. The selection highlight is an opaque tinted capsule that slides between
/// options (matched geometry), so glass is never stacked on glass. Reduce Motion: no slide.
struct Segmented<T: Hashable>: View {
    @Environment(\.palette) private var p
    @Environment(\.accessibilityReduceMotion) private var reduceMotion
    @Namespace private var ns
    let options: [(T, String)]
    @Binding var selection: T

    var body: some View {
        HStack(spacing: 2) {
            ForEach(Array(options.enumerated()), id: \.offset) { item in
                let opt = item.element
                let on = opt.0 == selection
                Button {
                    withAnimation(reduceMotion ? nil : .snappy(duration: 0.28)) { selection = opt.0 }
                } label: {
                    Text(opt.1)
                        .font(.callout.weight(on ? .semibold : .regular))
                        .foregroundStyle(on ? p.text : p.text2)
                        .padding(.horizontal, 14)
                        .padding(.vertical, 6)
                        .background {
                            if on {
                                Capsule().fill(p.accent.opacity(0.18))
                                    .overlay(Capsule().strokeBorder(p.accent.opacity(0.35), lineWidth: 1))
                                    .matchedGeometryEffect(id: "selection", in: ns)
                            }
                        }
                        .contentShape(Capsule())
                }
                .buttonStyle(.plain)
                .accessibilityAddTraits(on ? .isSelected : [])
            }
        }
        .padding(4)
        .moatGlass(in: Capsule())
    }
}

extension Support {
    var tone: Tone {
        switch self {
        case .supported: return .green
        case .partial: return .amber
        case .untested: return .blue
        case .unsupported: return .neutral
        }
    }
}

public extension CoverageLevel {
    /// SF Symbol for this coverage level (menu bar icon, toolbar badge).
    var systemImage: String { symbol }
}

extension CoverageLevel {
    var tone: Tone {
        switch self {
        case .enforced: return .green
        case .observed: return .blue
        case .degraded: return .amber
        case .isolated: return .red
        case .recoveryRequired, .rollbackPending: return .red
        case .unknown: return .neutral
        }
    }

    var symbol: String {
        switch self {
        case .enforced: return "checkmark.shield.fill"
        case .observed: return "eye.fill"
        case .degraded: return "exclamationmark.triangle.fill"
        case .isolated: return "lock.shield.fill"
        case .recoveryRequired: return "wrench.and.screwdriver.fill"
        case .rollbackPending: return "arrow.uturn.backward.circle.fill"
        case .unknown: return "questionmark.circle.fill"
        }
    }
}

extension FlowDecision {
    var pill: (String, Tone) {
        if isObservation { return ("Observed", .blue) }
        switch (verdict, source) {
        case (.deny, .emergencyIsolation): return ("Isolated", .red)
        case (.deny, _): return ("Blocked", .red)
        case (.allow, .loopback): return ("Loopback", .neutral)
        case (.allow, _): return ("Allowed", .green)
        }
    }
}

enum TimeText {
    static func ago(_ d: Date, now: Date = Date()) -> String {
        let s = max(0, Int(now.timeIntervalSince(d)))
        if s < 60 { return "\(s)s ago" }
        if s < 3600 { return "\(s / 60)m ago" }
        if s < 86400 { return "\(s / 3600)h ago" }
        return "\(s / 86400)d ago"
    }
}
