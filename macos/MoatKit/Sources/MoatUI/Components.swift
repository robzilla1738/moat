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

/// Card surface with a hairline border and soft shadow, like `.card` on the web.
struct Card<Content: View>: View {
    @Environment(\.palette) private var p
    var padding: CGFloat = 18
    @ViewBuilder var content: Content

    var body: some View {
        VStack(alignment: .leading, spacing: 12) { content }
            .padding(padding)
            .frame(maxWidth: .infinity, alignment: .leading)
            .background(RoundedRectangle(cornerRadius: 16, style: .continuous).fill(p.surface))
            .overlay(RoundedRectangle(cornerRadius: 16, style: .continuous).strokeBorder(p.border, lineWidth: 1))
            .shadow(color: Color.black.opacity(0.18), radius: 14, x: 0, y: 8)
    }
}

struct SectionTitle: View {
    @Environment(\.palette) private var p
    let text: String
    var trailing: String?

    var body: some View {
        HStack {
            Text(text.uppercased())
                .font(.system(size: 11, weight: .semibold))
                .tracking(0.8)
                .foregroundColor(p.muted)
            Spacer()
            if let trailing {
                Text(trailing).font(.system(size: 12)).foregroundColor(p.muted)
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
            if dot { Circle().fill(c).frame(width: 6, height: 6) }
            Text(text).font(.system(size: 11.5, weight: .semibold))
        }
        .foregroundColor(c)
        .padding(.horizontal, 8)
        .padding(.vertical, 3)
        .background(Capsule().fill(c.opacity(0.12)))
        .overlay(Capsule().strokeBorder(c.opacity(0.22), lineWidth: 1))
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
            Text(label.uppercased()).font(.system(size: 10.5, weight: .semibold)).tracking(0.7).foregroundColor(p.muted)
            Text(value)
                .font(.system(size: 28, weight: .semibold, design: .rounded))
                .monospacedDigit()
                .foregroundColor(tone.map { $0.color(p) } ?? p.text)
            if let sub { Text(sub).font(.system(size: 12)).foregroundColor(p.muted) }
        }
        .frame(maxWidth: .infinity, alignment: .leading)
        .padding(14)
        .background(RoundedRectangle(cornerRadius: 14, style: .continuous).fill(p.surface2))
        .overlay(RoundedRectangle(cornerRadius: 14, style: .continuous).strokeBorder(p.border, lineWidth: 1))
    }
}

/// A plain, fully SwiftUI-drawn button (renders identically in ImageRenderer screenshots).
struct MoatButton: View {
    @Environment(\.palette) private var p
    enum Kind { case primary, secondary, danger }
    let title: String
    var systemImage: String?
    var kind: Kind = .secondary
    var disabled = false
    let action: () -> Void

    var body: some View {
        Button(action: action) {
            HStack(spacing: 6) {
                if let systemImage { Image(systemName: systemImage).font(.system(size: 12, weight: .semibold)) }
                Text(title).font(.system(size: 13, weight: .semibold))
            }
            .padding(.horizontal, 14)
            .padding(.vertical, 8)
            .foregroundColor(fg)
            .background(RoundedRectangle(cornerRadius: 10, style: .continuous).fill(bg))
            .overlay(RoundedRectangle(cornerRadius: 10, style: .continuous).strokeBorder(border, lineWidth: 1))
            .opacity(disabled ? 0.45 : 1)
        }
        .buttonStyle(.plain)
        .disabled(disabled)
    }

    private var fg: Color {
        switch kind {
        case .primary: return .white
        case .secondary: return p.text
        case .danger: return p.red
        }
    }

    private var bg: Color {
        switch kind {
        case .primary: return p.accent
        case .secondary: return p.surface3
        case .danger: return p.red.opacity(0.1)
        }
    }

    private var border: Color {
        switch kind {
        case .primary: return p.accent
        case .secondary: return p.borderStrong
        case .danger: return p.red.opacity(0.3)
        }
    }
}

/// Segmented control drawn in SwiftUI.
struct Segmented<T: Hashable>: View {
    @Environment(\.palette) private var p
    let options: [(T, String)]
    @Binding var selection: T

    var body: some View {
        HStack(spacing: 2) {
            ForEach(Array(options.enumerated()), id: \.offset) { item in
                let opt = item.element
                let on = opt.0 == selection
                Button { selection = opt.0 } label: {
                    Text(opt.1)
                        .font(.system(size: 12.5, weight: on ? .semibold : .medium))
                        .foregroundColor(on ? p.text : p.muted)
                        .padding(.horizontal, 12)
                        .padding(.vertical, 6)
                        .background(RoundedRectangle(cornerRadius: 8, style: .continuous).fill(on ? p.surface : Color.clear))
                }
                .buttonStyle(.plain)
            }
        }
        .padding(3)
        .background(RoundedRectangle(cornerRadius: 10, style: .continuous).fill(p.surface3))
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

extension CoverageLevel {
    var tone: Tone {
        switch self {
        case .enforced: return .green
        case .observed: return .blue
        case .degraded: return .amber
        case .isolated: return .red
        case .unknown: return .neutral
        }
    }

    var symbol: String {
        switch self {
        case .enforced: return "checkmark.shield.fill"
        case .observed: return "eye.fill"
        case .degraded: return "exclamationmark.triangle.fill"
        case .isolated: return "lock.shield.fill"
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
