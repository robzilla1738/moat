import MoatKit
import SwiftUI

// The bento layer shared with the web UI (docs/design.md): the Moat mark, KPI tiles, a progress ring, a flow strip and
// a ranked list. Every chart here draws only values handed to it from the model (status counters, flow records,
// capability rows, app summaries); none of them invents, interpolates or pads a series.

/// The Moat mark from brand/moat-mark.svg: a keep inside a moat ring that opens only below the gate.
/// Drawn on a 24-unit grid, centred and scaled to fit.
public struct MoatMarkShape: Shape {
    public enum Part: Sendable { case ring, keep, all }
    public var part: Part

    public init(part: Part = .all) {
        self.part = part
    }

    public func path(in rect: CGRect) -> Path {
        let s = Double(min(rect.width, rect.height)) / 24
        let ox = Double(rect.midX) - 12 * s
        let oy = Double(rect.midY) - 12 * s
        func pt(_ x: Double, _ y: Double) -> CGPoint { CGPoint(x: ox + x * s, y: oy + y * s) }
        var p = Path()
        if part != .keep {
            // The ring: inner edge from just left of the gate all the way round, then the outer edge back.
            let di = asin(1.45 / 8.85)
            let dout = asin(1.45 / 10.75)
            let steps = 96
            let a0 = Double.pi / 2 + di
            let a1 = Double.pi / 2 + 2 * Double.pi - di
            for i in 0...steps {
                let t = a0 + (a1 - a0) * Double(i) / Double(steps)
                let q = pt(12 + 8.85 * cos(t), 12 + 8.85 * sin(t))
                if i == 0 { p.move(to: q) } else { p.addLine(to: q) }
            }
            let b0 = Double.pi / 2 + 2 * Double.pi - dout
            let b1 = Double.pi / 2 + dout
            for i in 0...steps {
                let t = b0 + (b1 - b0) * Double(i) / Double(steps)
                p.addLine(to: pt(12 + 10.75 * cos(t), 12 + 10.75 * sin(t)))
            }
            p.closeSubpath()
        }
        if part != .ring {
            // The keep: three merlons, walls, and a round-topped gate open at the bottom.
            let outline: [(Double, Double)] = [
                (7.2, 5.6), (9.4, 5.6), (9.4, 7.3), (10.9, 7.3), (10.9, 5.6), (13.1, 5.6), (13.1, 7.3), (14.6, 7.3),
                (14.6, 5.6), (16.8, 5.6), (16.8, 18), (13.45, 18), (13.45, 14.4),
            ]
            p.move(to: pt(outline[0].0, outline[0].1))
            for q in outline.dropFirst() { p.addLine(to: pt(q.0, q.1)) }
            for i in 1...24 {
                let t = -Double.pi * Double(i) / 24
                p.addLine(to: pt(12 + 1.45 * cos(t), 14.4 + 1.45 * sin(t)))
            }
            p.addLine(to: pt(10.55, 18))
            p.addLine(to: pt(7.2, 18))
            p.closeSubpath()
        }
        return p
    }
}

/// The app icon in miniature (sidebar, menu bar panel, onboarding): the mark on the brand gradient.
struct AppMark: View {
    var size: CGFloat = 30

    var body: some View {
        ZStack {
            RoundedRectangle(cornerRadius: size * 0.24, style: .continuous)
                .fill(LinearGradient(colors: [Color(hex: 0x8A8DF8), Color(hex: 0x5B5BEA), Color(hex: 0x4338CA)], startPoint: .topLeading, endPoint: .bottomTrailing))
            MoatMarkShape(part: .ring)
                .fill(LinearGradient(colors: [.white, .white, Color(hex: 0x7FE9D8)], startPoint: .top, endPoint: .bottom))
                .padding(size * 0.16)
            MoatMarkShape(part: .keep)
                .fill(Color.white)
                .padding(size * 0.16)
        }
        .frame(width: size, height: size)
        .accessibilityHidden(true)
    }
}

/// The mark alone in the brand tones (accent keep, accent-to-teal ring) for headers on the canvas.
struct BrandMark: View {
    @Environment(\.palette) private var p
    var size: CGFloat = 28

    var body: some View {
        ZStack {
            MoatMarkShape(part: .ring).fill(LinearGradient(colors: [p.accent, p.accent, p.teal], startPoint: .top, endPoint: .bottom))
            MoatMarkShape(part: .keep).fill(p.accent)
        }
        .frame(width: size, height: size)
        .accessibilityHidden(true)
    }
}

/// A progress ring for a real fraction (value of total). A total of 0 draws only the track.
struct ProgressRing: View {
    @Environment(\.palette) private var p
    let value: Int
    let total: Int
    var tone: Tone = .green
    var size: CGFloat = 56
    var lineWidth: CGFloat = 7
    var showsText = true

    var body: some View {
        let f = total > 0 ? min(1, max(0, Double(value) / Double(total))) : 0
        ZStack {
            Circle().stroke(p.surface3, lineWidth: lineWidth)
            Circle()
                .trim(from: 0, to: f)
                .stroke(tone.color(p), style: StrokeStyle(lineWidth: lineWidth, lineCap: .round))
                .rotationEffect(.degrees(-90))
            if showsText {
                Text(verbatim: "\(value)/\(total)")
                    .font(.system(size: size * 0.22, weight: .bold))
                    .monospacedDigit()
                    .foregroundStyle(p.text)
                    .lineLimit(1)
                    .minimumScaleFactor(0.6)
                    .padding(lineWidth)
            }
        }
        .frame(width: size, height: size)
        .accessibilityElement(children: .ignore)
        .accessibilityLabel("\(value) of \(total)")
    }
}

/// KPI tile: a quiet chip label with an icon, a big tabular figure, a sub line and an optional chart on the right.
struct KpiTile<Chart: View>: View {
    @Environment(\.palette) private var p
    @Environment(\.colorScheme) private var scheme
    let label: String
    let symbol: String
    var tone: Tone = .accent
    let value: String
    var unit: String?
    var sub: String?
    @ViewBuilder var chart: Chart

    var body: some View {
        VStack(alignment: .leading, spacing: 10) {
            HStack(spacing: 5) {
                Image(systemName: symbol).font(.caption.weight(.bold)).foregroundStyle(tone.color(p))
                Text(label).font(.caption.weight(.semibold)).foregroundStyle(p.text2)
            }
            .padding(.horizontal, 9)
            .padding(.vertical, 4)
            .background(Capsule().fill(p.surface3))
            HStack(alignment: .bottom, spacing: 10) {
                VStack(alignment: .leading, spacing: 2) {
                    HStack(alignment: .firstTextBaseline, spacing: 3) {
                        Text(value)
                            .font(.system(size: 28, weight: .bold))
                            .monospacedDigit()
                            .foregroundStyle(p.text)
                            .lineLimit(1)
                            .minimumScaleFactor(0.6)
                        if let unit { Text(unit).font(.callout.weight(.semibold)).foregroundStyle(p.muted) }
                    }
                    if let sub { Text(sub).font(.caption).foregroundStyle(p.muted).lineLimit(2).fixedSize(horizontal: false, vertical: true) }
                }
                Spacer(minLength: 0)
                chart
            }
        }
        .padding(16)
        .frame(maxWidth: .infinity, maxHeight: .infinity, alignment: .topLeading)
        .background(RoundedRectangle(cornerRadius: 14, style: .continuous).fill(p.surface))
        .overlay(RoundedRectangle(cornerRadius: 14, style: .continuous).strokeBorder(p.border, lineWidth: 1))
        .shadow(color: Color.black.opacity(scheme == .dark ? 0 : 0.05), radius: 2, x: 0, y: 1)
        .accessibilityElement(children: .combine)
    }
}

extension KpiTile where Chart == EmptyView {
    init(label: String, symbol: String, tone: Tone = .accent, value: String, unit: String? = nil, sub: String? = nil) {
        self.init(label: label, symbol: symbol, tone: tone, value: value, unit: unit, sub: sub) { EmptyView() }
    }
}

/// One tick per recorded flow, oldest on the left, coloured by verdict (allowed, observed, blocked). It is the record
/// list drawn as a strip, not a rate: nothing between records is implied.
struct FlowStrip: View {
    @Environment(\.palette) private var p
    let records: [FlowRecord]
    var height: CGFloat = 54

    var body: some View {
        GeometryReader { geo in
            let n = max(records.count, 1)
            let slot = geo.size.width / CGFloat(n)
            let w = max(2, min(8, slot * 0.55))
            ZStack(alignment: .bottomLeading) {
                ForEach(Array(records.enumerated()), id: \.offset) { item in
                    let r = item.element
                    let blocked = r.decision.verdict == .deny
                    let h = blocked ? geo.size.height : (r.decision.isObservation ? geo.size.height * 0.62 : geo.size.height * 0.8)
                    RoundedRectangle(cornerRadius: w / 2, style: .continuous)
                        .fill(blocked ? p.red : (r.decision.isObservation ? p.chart1 : p.chart2))
                        .frame(width: w, height: h)
                        .offset(x: CGFloat(item.offset) * slot + (slot - w) / 2)
                }
            }
            .frame(width: geo.size.width, height: geo.size.height, alignment: .bottomLeading)
        }
        .frame(height: height)
        .accessibilityElement(children: .ignore)
        .accessibilityLabel("\(records.count) recent flows: \(records.filter { $0.decision.verdict == .deny }.count) blocked, \(records.filter { $0.decision.isObservation }.count) observed")
    }
}

/// Legend swatch + label (status is never colour alone: the strip's meaning is spelled out next to it).
struct LegendItem: View {
    @Environment(\.palette) private var p
    let color: Color
    let text: String

    var body: some View {
        HStack(spacing: 6) {
            RoundedRectangle(cornerRadius: 3, style: .continuous).fill(color).frame(width: 10, height: 10)
            Text(text).font(.caption).foregroundStyle(p.text2)
        }
    }
}

/// Ranked rows with rank numbers; the first row carries a soft teal tint.
struct RankedRow: View {
    @Environment(\.palette) private var p
    let rank: Int
    let title: String
    let detail: String
    let value: String
    var valueSub: String?

    var body: some View {
        HStack(spacing: 10) {
            Text(verbatim: "#\(rank)").font(.callout.weight(.bold)).monospacedDigit().foregroundStyle(p.muted).frame(width: 30, alignment: .leading)
            VStack(alignment: .leading, spacing: 1) {
                Text(title).font(.callout.weight(.semibold)).foregroundStyle(p.text).lineLimit(1)
                Text(detail).font(.caption).foregroundStyle(p.muted).lineLimit(1)
            }
            Spacer(minLength: 6)
            VStack(alignment: .trailing, spacing: 0) {
                Text(value).font(.callout.weight(.bold)).monospacedDigit().foregroundStyle(p.text)
                if let valueSub { Text(valueSub).font(.caption2).foregroundStyle(p.muted) }
            }
        }
        .padding(.horizontal, 10)
        .padding(.vertical, 8)
        .background(RoundedRectangle(cornerRadius: 10, style: .continuous).fill(rank == 1 ? p.teal.opacity(0.10) : Color.clear))
        .accessibilityElement(children: .combine)
    }
}
