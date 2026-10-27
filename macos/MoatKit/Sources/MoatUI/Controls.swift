import SwiftUI

// Control surfaces (docs/design.md). Moat's own controls are opaque: a solid fill with a hairline border, so text
// always sits on a known colour and Reduce Transparency needs no special case. The system still draws its own chrome
// (the sidebar, toolbar and menu bar) the native way. The `moatGlass*` names are historical; nothing here is
// translucent:
//
// * `moatGlass` draws a solid surface (tinted for prominent controls) with a border; Increase Contrast strengthens it;
// * `moatButtonStyle` uses the bordered button styles;
// * the morphing helpers are no-ops with Reduce Motion.

/// Glass for a control surface (capsule or rounded rectangle). `tint` colours prominent controls only.
struct MoatGlassModifier<S: InsettableShape>: ViewModifier {
    @Environment(\.colorSchemeContrast) private var contrast
    @Environment(\.palette) private var p
    let shape: S
    var tint: Color?
    var interactive: Bool

    func body(content: Content) -> some View {
        content
            .background(shape.fill(tint.map { $0.opacity(0.16) } ?? p.surface))
            .overlay(shape.strokeBorder(contrast == .increased ? p.text.opacity(0.55) : (tint.map { $0.opacity(0.35) } ?? p.border), lineWidth: 1))
    }
}

extension View {
    func moatGlass<S: InsettableShape>(in shape: S, tint: Color? = nil, interactive: Bool = false) -> some View {
        modifier(MoatGlassModifier(shape: shape, tint: tint, interactive: interactive))
    }

    /// Morphing identity inside a `MoatGlassContainer` (macOS 26). No-op elsewhere or with Reduce Motion.
    @ViewBuilder func moatGlassID<ID: Hashable & Sendable>(_ id: ID, in ns: Namespace.ID, reduceMotion: Bool) -> some View {
        if reduceMotion {
            self
        } else {
            if #available(macOS 26.0, *) {
                glassEffectID(id, in: ns)
            } else {
                self
            }
        }
    }

    /// Primary / secondary control buttons: bordered prominent / bordered.
    @ViewBuilder func moatButtonStyle(prominent: Bool = false, destructive: Bool = false) -> some View {
        if prominent {
            buttonStyle(.borderedProminent).tint(destructive ? BrandColor.destructive : nil)
        } else {
            buttonStyle(.bordered).tint(destructive ? BrandColor.destructive : nil)
        }
    }

    /// Soft scroll-edge effect under the toolbar (macOS 26); the classic hard edge elsewhere.
    @ViewBuilder func moatScrollEdge() -> some View {
        if #available(macOS 26.0, *) {
            scrollEdgeEffectStyle(.soft, for: .top)
        } else {
            self
        }
    }

    /// No artwork extends under the sidebar in the bento design; kept as a no-op for existing call sites.
    func moatBackgroundExtension() -> some View {
        self
    }

    /// Symbol animation that respects Reduce Motion.
    @ViewBuilder func moatPulse(_ active: Bool, reduceMotion: Bool) -> some View {
        if reduceMotion {
            self
        } else {
            symbolEffect(.pulse, options: .repeating, isActive: active)
        }
    }
}

/// `GlassEffectContainer` on macOS 26 (shapes blend and morph); a plain stack container elsewhere.
struct MoatGlassContainer<Content: View>: View {
    var spacing: CGFloat = 8
    @ViewBuilder var content: Content

    var body: some View {
        if #available(macOS 26.0, *) {
            GlassEffectContainer(spacing: spacing) { content }
        } else {
            content
        }
    }
}
