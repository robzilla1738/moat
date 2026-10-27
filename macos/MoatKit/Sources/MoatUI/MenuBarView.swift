import MoatKit
import SwiftUI

/// The menu bar extra's panel (`MenuBarExtra` with `.window` style): "Is this Mac protected, and what did it just
/// block?" Status, the last few blocks, and the emergency lockdown, which always takes a second, explicit
/// confirmation (the Lock down button turns into the Cancel / Lock down now pair).
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
        VStack(alignment: .leading, spacing: Space.s4) {
            header(p)
            if let s = model.status {
                Text(verbatim: s.coverage.claim).font(.callout).foregroundStyle(p.text2).fixedSize(horizontal: false, vertical: true)
                recent(p)
            } else {
                Label("Waiting for the filter to report…", systemImage: "antenna.radiowaves.left.and.right")
                    .font(.callout).foregroundStyle(p.text2)
            }
            Divider()
            isolation(p)
            HStack(spacing: Space.s2) {
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
        .padding(Space.s4)
        .frame(width: 348)
        .environment(\.palette, p)
        .tint(p.accentStrong)
    }

    private func header(_ p: Palette) -> some View {
        HStack(spacing: Space.s3) {
            AppMark(size: 28)
            VStack(alignment: .leading, spacing: Space.s1) {
                Text("Moat").font(.headline)
                Text(verbatim: model.status?.installed.map { "Rules: \($0.policyName)" } ?? "No signed rules yet")
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
        return VStack(alignment: .leading, spacing: Space.s2) {
            HStack {
                Text("Recently blocked").font(.subheadline.weight(.semibold))
                Spacer()
                if let n = model.status?.flowsDenied { Text("\(n) total").font(.caption).foregroundStyle(p.muted) }
            }
            if blocked.isEmpty {
                Text("Nothing blocked recently.").font(.callout).foregroundStyle(p.muted)
            }
            ForEach(blocked) { r in
                HStack(spacing: Space.s2) {
                    Image(systemName: "xmark.shield.fill").foregroundStyle(p.red).font(.callout).accessibilityHidden(true)
                    VStack(alignment: .leading, spacing: Space.s1) {
                        Text(verbatim: r.facts.appLabel).font(.callout.weight(.semibold)).lineLimit(1)
                        Text(verbatim: "\(r.facts.remoteHost ?? r.facts.remoteIP):\(r.facts.remotePort)")
                            .font(.system(.caption, design: .monospaced)).foregroundStyle(p.text2).lineLimit(1).truncationMode(.middle)
                    }
                    Spacer(minLength: 4)
                    Text(TimeText.ago(r.facts.at)).font(.caption).foregroundStyle(p.muted)
                }
                .accessibilityElement(children: .combine)
            }
        }
        .padding(Space.s3)
        .background(RoundedRectangle(cornerRadius: Radius.card, style: .continuous).fill(p.surface))
        .overlay(RoundedRectangle(cornerRadius: Radius.card, style: .continuous).strokeBorder(p.border, lineWidth: 1))
    }

    @ViewBuilder private func isolation(_ p: Palette) -> some View {
        if model.status?.isolation.active == true {
            HStack(spacing: Space.s3) {
                Image(systemName: "lock.shield.fill").foregroundStyle(p.red).moatPulse(true, reduceMotion: reduceMotion)
                Text("Emergency lockdown is on. Turn it off in Coverage & recovery, with the typed phrase.").font(.callout).fixedSize(horizontal: false, vertical: true)
            }
        } else {
            VStack(alignment: .leading, spacing: Space.s2) {
                if confirming {
                    Text("Block new connections from this Mac, except to itself, until you turn it off? Connections already open stay open.")
                        .font(.callout.weight(.medium)).fixedSize(horizontal: false, vertical: true)
                }
                MoatGlassContainer(spacing: Space.s2) {
                    HStack(spacing: Space.s2) {
                        if confirming {
                            glassButton("Cancel", symbol: "xmark", tint: nil, p) { setConfirming(false) }
                                .moatGlassID("cancel", in: ns, reduceMotion: reduceMotion)
                            glassButton("Lock down now", symbol: "lock.shield.fill", tint: p.red, p) {
                                setConfirming(false)
                                Task { await model.enterIsolation(reason: "Turned on from the menu bar") }
                            }
                            .moatGlassID("isolate", in: ns, reduceMotion: reduceMotion)
                        } else {
                            glassButton("Lock down this Mac…", symbol: "lock.shield", tint: nil, p) { setConfirming(true) }
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
                .foregroundStyle(tint == nil ? p.text : BrandColor.onTint)
                .padding(.horizontal, Space.s4)
                .padding(.vertical, Space.s2)
                .contentShape(Capsule())
        }
        .buttonStyle(.plain)
        .moatGlass(in: Capsule(), tint: tint, interactive: true)
    }
}
