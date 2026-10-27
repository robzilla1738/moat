import MoatKit
import SwiftUI

// The Moat mark (brand/moat-mark.svg) for the sidebar, menu bar panel and onboarding. The decorative KPI tiles, flow
// strip and ranked list of the first bento pass were removed in the refinement pass (docs/design.md, "Each view's
// job"): none of them answered the question its view exists for.

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
                .fill(LinearGradient(colors: [BrandColor.iconTop, BrandColor.iconMid, BrandColor.iconBottom], startPoint: .topLeading, endPoint: .bottomTrailing))
            MoatMarkShape(part: .ring)
                .fill(LinearGradient(colors: [BrandColor.onTint, BrandColor.onTint, BrandColor.iconRingTeal], startPoint: .top, endPoint: .bottom))
                .padding(size * 0.16)
            MoatMarkShape(part: .keep)
                .fill(BrandColor.onTint)
                .padding(size * 0.16)
        }
        .frame(width: size, height: size)
        .accessibilityHidden(true)
    }
}
