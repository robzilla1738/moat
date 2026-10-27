import SwiftUI

/// The Moat palette: the same tokens as the web UI (web/src/styles.css), dark and light.
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
    public let accent2: Color
    public let green: Color
    public let red: Color
    public let amber: Color
    public let violet: Color
    public let blue: Color
    public let neutral: Color

    public static let dark = Palette(
        bg: Color(hex: 0x0A0B0D), surface: Color(hex: 0x111317), surface2: Color(hex: 0x171A1F), surface3: Color(hex: 0x1E2228),
        border: Color.white.opacity(0.075), borderStrong: Color.white.opacity(0.13),
        text: Color(hex: 0xECEEF2), text2: Color(hex: 0xB9BEC8), muted: Color(hex: 0x868D99),
        accent: Color(hex: 0x6D7CFF), accent2: Color(hex: 0x22D3EE),
        green: Color(hex: 0x3DDC97), red: Color(hex: 0xFF6B6B), amber: Color(hex: 0xF5B84B), violet: Color(hex: 0xA78BFA),
        blue: Color(hex: 0x6AA7FF), neutral: Color(hex: 0x9AA1AD))

    public static let light = Palette(
        bg: Color(hex: 0xF5F6F8), surface: Color(hex: 0xFFFFFF), surface2: Color(hex: 0xF7F8FA), surface3: Color(hex: 0xEEF0F3),
        border: Color(hex: 0x0F172A).opacity(0.08), borderStrong: Color(hex: 0x0F172A).opacity(0.14),
        text: Color(hex: 0x0E1116), text2: Color(hex: 0x3A414C), muted: Color(hex: 0x646C78),
        accent: Color(hex: 0x4F5DF5), accent2: Color(hex: 0x0EA5C6),
        green: Color(hex: 0x0F9D64), red: Color(hex: 0xDC3B3B), amber: Color(hex: 0xB77806), violet: Color(hex: 0x7C4DDB),
        blue: Color(hex: 0x2563EB), neutral: Color(hex: 0x5F6672))

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
