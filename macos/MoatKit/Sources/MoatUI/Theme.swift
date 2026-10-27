import SwiftUI

/// The Moat palette: the same tokens as the web UI, from brand/design-tokens.json (web/src/tokens.test.ts checks that
/// these hex values match). The app target also carries them as semantic colour sets with light and dark appearances
/// (macos/Moat/App/Assets.xcassets/Colors, generated); MoatUI keeps them in code so the package renders without an
/// asset catalog in `swift test`.
public struct Palette {
    public let bg: Color
    public let surface: Color
    public let surface2: Color
    public let surface3: Color
    public let border: Color
    public let borderStrong: Color
    public let text: Color
    public let text2: Color
    public let muted: Color
    public let accent: Color
    /// Solid fills that carry white text (prominent buttons, the selected sidebar row): AA with white in both appearances.
    public let accentStrong: Color
    /// Text and icons drawn on a solid accent fill.
    public let accentInk: Color
    /// Soft accent tint for selected rows, announcement banners and chips.
    public let accentSoft: Color
    /// Chart series: periwinkle (observed), teal (allowed), amber (heat).
    public let chart1: Color
    public let chart2: Color
    public let chart3: Color
    public let teal: Color
    public let green: Color
    public let red: Color
    public let amber: Color
    public let violet: Color
    public let blue: Color
    public let neutral: Color

    /// Secondary brand tone (teal); kept for existing call sites.
    public var accent2: Color { teal }

    public static let dark = Palette(
        bg: Color(hex: 0x0C0E14), surface: Color(hex: 0x151821), surface2: Color(hex: 0x1A1E29), surface3: Color(hex: 0x222734),
        border: Color(hex: 0x252A37), borderStrong: Color(hex: 0x353B4B),
        text: Color(hex: 0xECEEF5), text2: Color(hex: 0xC3C8D6), muted: Color(hex: 0x969DB0),
        accent: Color(hex: 0xA5A8FF), accentStrong: Color(hex: 0x5B5BEA), accentInk: Color(hex: 0x0C0E14), accentSoft: Color(hex: 0x23264A),
        chart1: Color(hex: 0x7C80F0), chart2: Color(hex: 0x3FBFA9), chart3: Color(hex: 0xE9A93A), teal: Color(hex: 0x5EEAD4),
        green: Color(hex: 0x4ADE80), red: Color(hex: 0xFF8A80), amber: Color(hex: 0xF5B84B), violet: Color(hex: 0xC4B5FD),
        blue: Color(hex: 0x93B4FF), neutral: Color(hex: 0xA1A8B8))

    public static let light = Palette(
        bg: Color(hex: 0xF3F4F8), surface: Color(hex: 0xFFFFFF), surface2: Color(hex: 0xF7F8FB), surface3: Color(hex: 0xEDEFF5),
        border: Color(hex: 0xE3E6EE), borderStrong: Color(hex: 0xCDD2DE),
        text: Color(hex: 0x0F1222), text2: Color(hex: 0x3A4055), muted: Color(hex: 0x5D6478),
        accent: Color(hex: 0x4F46E5), accentStrong: Color(hex: 0x4F46E5), accentInk: Color(hex: 0xFFFFFF), accentSoft: Color(hex: 0xEEF0FF),
        chart1: Color(hex: 0x8B8FF7), chart2: Color(hex: 0x5CC8B4), chart3: Color(hex: 0xF5B83D), teal: Color(hex: 0x115E59),
        green: Color(hex: 0x166534), red: Color(hex: 0xB91C1C), amber: Color(hex: 0x92400E), violet: Color(hex: 0x5B21B6),
        blue: Color(hex: 0x1D4ED8), neutral: Color(hex: 0x5D6478))

    public static func of(_ scheme: ColorScheme) -> Palette {
        scheme == .dark ? .dark : .light
    }
}

public extension Color {
    init(hex: UInt32) {
        self.init(
            .sRGB,
            red: Double((hex >> 16) & 0xFF) / 255,
            green: Double((hex >> 8) & 0xFF) / 255,
            blue: Double(hex & 0xFF) / 255,
            opacity: 1)
    }
}

/// User's appearance choice, persisted with @AppStorage("appearance").
public enum Appearance: String, CaseIterable, Identifiable {
    case system, dark, light
    public var id: String { rawValue }
    public var label: String {
        switch self {
        case .system: return "System"
        case .dark: return "Dark"
        case .light: return "Light"
        }
    }

    public var colorScheme: ColorScheme? {
        switch self {
        case .system: return nil
        case .dark: return .dark
        case .light: return .light
        }
    }
}
