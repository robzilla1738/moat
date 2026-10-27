import MoatKit
import SwiftUI

/// The menu bar extra's panel (`MenuBarExtra` with `.window` style): quick status, recent blocks, and the emergency
/// isolate action. Isolating always takes a second, explicit confirmation; the Isolate button morphs into the
/// Cancel / Isolate now pair (glassEffectID inside a GlassEffectContainer on macOS 26).
public struct MenuBarContent: View {
    @ObservedObject var model: AppModel
    var openMain: () -> Void
    var quit: () -> Void
    @Environment(\.colorScheme) private var scheme
    @Environment(\.accessibilityReduceMotion) private var reduceMotion
    @State private var confirming = false
    @Namespace private var ns

    public init(model: AppModel, openMain: @escaping () -> Void, quit: @escaping () -> Void = {}) {
        self.model = model
        self.openMain = openMain
        self.quit = quit
    }

    public var body: some View {
        let p = Palette.of(scheme)
        VStack(alignment: .leading, spacing: 14) {
            header(p)
            if let s = model.status {
                Text(s.coverage.claim).font(.callout).foregroundStyle(p.text2).fixedSize(horizontal: false, vertical: true)
                recent(p)
            } else {
                Label("Waiting for the filter to report…", systemImage: "antenna.radiowaves.left.and.right")
                    .font(.callout).foregroundStyle(p.text2)
            }
            Divider()
            isolation(p)
            HStack(spacing: 8) {
                Button("Open Moat", action: openMain).moatButtonStyle(prominent: true).keyboardShortcut("o")
                Button {
                    Task { await model.refresh() }
                } label: {
                    Label("Refresh", systemImage: "arrow.clockwise")
                }
                .moatButtonStyle()
                Spacer()
                Button("Quit", action: quit).buttonStyle(.plain).foregroundStyle(p.muted).font(.callout)
            }
        }
        .padding(16)
        .frame(width: 348)
        .environment(\.palette, p)
        .tint(p.accentStrong)
    }

    private func header(_ p: Palette) -> some View {
        HStack(spacing: 10) {
            AppMark(size: 28)
            VStack(alignment: .leading, spacing: 1) {
                Text("Moat").font(.headline)
                Text(model.status?.installed.map { "Policy r\($0.revision) · \($0.policyName)" } ?? "No signed policy")
                    .font(.caption).foregroundStyle(p.muted).lineLimit(1)
            }
            Spacer()
            if let s = model.status {
                Pill(text: s.coverage.label, tone: s.coverage.tone, dot: true)
            }
        }
        .accessibilityElement(children: .combine)
    }

    private func recent(_ p: Palette) -> some View {
        let blocked = Array(model.flows.filter { $0.decision.verdict == .deny }.prefix(4))
        return VStack(alignment: .leading, spacing: 8) {
            HStack {
                Text("Recent blocks").font(.subheadline.weight(.semibold))
                Spacer()
                if let n = model.status?.flowsDenied { Text("\(n) total").font(.caption).foregroundStyle(p.muted) }
            }
            if blocked.isEmpty {
                Text("Nothing blocked recently.").font(.callout).foregroundStyle(p.muted)
            }
            ForEach(blocked) { r in
                HStack(spacing: 8) {
                    Image(systemName: "xmark.shield.fill").foregroundStyle(p.red).font(.callout).accessibilityHidden(true)
                    VStack(alignment: .leading, spacing: 1) {
                        Text(r.facts.appLabel).font(.callout.weight(.semibold)).lineLimit(1)
                        Text(verbatim: "\(r.facts.remoteHost ?? r.facts.remoteIP):\(r.facts.remotePort)")
                            .font(.system(.caption, design: .monospaced)).foregroundStyle(p.text2).lineLimit(1).truncationMode(.middle)
                    }
                    Spacer(minLength: 4)
                    Text(TimeText.ago(r.facts.at)).font(.caption).foregroundStyle(p.muted)
                }
                .accessibilityElement(children: .combine)
            }
        }
        .padding(12)
        .background(RoundedRectangle(cornerRadius: 14, style: .continuous).fill(p.surface))
        .overlay(RoundedRectangle(cornerRadius: 14, style: .continuous).strokeBorder(p.border, lineWidth: 1))
    }

    @ViewBuilder private func isolation(_ p: Palette) -> some View {
        if model.status?.isolation.active == true {
            HStack(spacing: 10) {
                Image(systemName: "lock.shield.fill").foregroundStyle(p.red).moatPulse(true, reduceMotion: reduceMotion)
                Text("Isolation is on. Turning it off needs the typed phrase in Recovery.").font(.callout).fixedSize(horizontal: false, vertical: true)
            }
        } else {
            VStack(alignment: .leading, spacing: 8) {
                if confirming {
                    Text("Block new outbound connections except loopback on this Mac until you turn it off? Open connections are not cut.")
                        .font(.callout.weight(.medium)).fixedSize(horizontal: false, vertical: true)
                }
                MoatGlassContainer(spacing: 8) {
                    HStack(spacing: 8) {
                        if confirming {
                            glassButton("Cancel", symbol: "xmark", tint: nil, p) { setConfirming(false) }
                                .moatGlassID("cancel", in: ns, reduceMotion: reduceMotion)
                            glassButton("Isolate now", symbol: "lock.shield.fill", tint: p.red, p) {
                                setConfirming(false)
                                Task { await model.enterIsolation(reason: "Turned on from the menu bar") }
                            }
                            .moatGlassID("isolate", in: ns, reduceMotion: reduceMotion)
                        } else {
                            glassButton("Isolate this Mac…", symbol: "lock.shield", tint: nil, p) { setConfirming(true) }
                                .moatGlassID("isolate", in: ns, reduceMotion: reduceMotion)
                        }
                    }
                }
            }
        }
    }

    private func setConfirming(_ v: Bool) {
        withAnimation(reduceMotion ? nil : .snappy(duration: 0.3)) { confirming = v }
    }

    private func glassButton(_ title: String, symbol: String, tint: Color?, _ p: Palette, action: @escaping () -> Void) -> some View {
        Button(action: action) {
            Label(title, systemImage: symbol)
                .font(.callout.weight(.semibold))
                .foregroundStyle(tint == nil ? p.text : Color.white)
                .padding(.horizontal, 14)
                .padding(.vertical, 8)
                .contentShape(Capsule())
        }
        .buttonStyle(.plain)
        .moatGlass(in: Capsule(), tint: tint, interactive: true)
    }
}
