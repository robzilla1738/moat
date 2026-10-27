import SwiftUI

// Liquid Glass, used the way Apple's HIG asks: glass is the navigation and control layer (sidebar, toolbar,
// floating controls, the menu bar panel), never the content itself. Every helper here:
//
// * uses the native macOS 26 APIs (`glassEffect`, `GlassEffectContainer`, `glassEffectID`, `.glass` button styles,
//   `backgroundExtensionEffect`, scroll-edge effects) behind `#available(macOS 26.0, *)`;
// * falls back on macOS 14/15 to system materials and the bordered button styles;
// * honours Reduce Transparency (solid, opaque fills), Increase Contrast (stronger borders, no tinted glass) and
//   Reduce Motion (no morphing or symbol animation).

/// Glass for a control surface (capsule or rounded rectangle). `tint` colours prominent controls only.
struct MoatGlassModifier<S: InsettableShape>: ViewModifier {
    @Environment(\.accessibilityReduceTransparency) private var reduceTransparency
    @Environment(\.colorSchemeContrast) private var contrast
    @Environment(\.palette) private var p
    let shape: S
    var tint: Color?
    var interactive: Bool

    @ViewBuilder func body(content: Content) -> some View {
        if reduceTransparency {
            content
                .background(shape.fill(tint.map { $0.opacity(0.22) } ?? p.surface2))
                .overlay(shape.strokeBorder(contrast == .increased ? p.text.opacity(0.55) : p.borderStrong, lineWidth: 1))
        } else {
            if #available(macOS 26.0, *) {
                content
                    .glassEffect(glassStyle, in: shape)
                    .overlay(shape.strokeBorder(contrast == .increased ? p.text.opacity(0.45) : Color.clear, lineWidth: 1))
            } else {
                content
                    .background(shape.fill(.regularMaterial))
                    .background(shape.fill((tint ?? Color.clear).opacity(0.18)))
                    .overlay(shape.strokeBorder(contrast == .increased ? p.text.opacity(0.45) : p.border, lineWidth: 1))
            }
        }
    }

    @available(macOS 26.0, *)
    private var glassStyle: Glass {
        // Increase Contrast: untinted glass plus a visible border, so tint never carries meaning on its own.
        let base: Glass = contrast == .increased ? .regular : .regular.tint(tint)
        return base.interactive(interactive)
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

    /// Primary / secondary control buttons: `.glassProminent` / `.glass` on macOS 26.
    @ViewBuilder func moatButtonStyle(prominent: Bool = false, destructive: Bool = false) -> some View {
        if #available(macOS 26.0, *) {
            if prominent {
                buttonStyle(.glassProminent).tint(destructive ? Color.red : nil)
            } else {
                buttonStyle(.glass).tint(destructive ? Color.red : nil)
            }
        } else {
            if prominent {
                buttonStyle(.borderedProminent).tint(destructive ? Color.red : nil)
            } else {
                buttonStyle(.bordered).tint(destructive ? Color.red : nil)
            }
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

    /// Lets hero artwork extend under the floating glass sidebar (macOS 26).
    @ViewBuilder func moatBackgroundExtension() -> some View {
        if #available(macOS 26.0, *) {
            backgroundExtensionEffect()
        } else {
            self
        }
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

/// True when the native Liquid Glass APIs are available at runtime (shown in Settings and the About text).
enum LiquidGlass {
    static var available: Bool {
        if #available(macOS 26.0, *) { return true }
        return false
    }
}
