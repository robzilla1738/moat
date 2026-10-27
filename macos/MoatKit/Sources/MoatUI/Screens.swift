import MoatKit
import SwiftUI
import UniformTypeIdentifiers

// MARK: - Overview

struct OverviewScreen: View {
    @ObservedObject var model: AppModel
    @Environment(\.palette) private var p
    /// The window shows the full-bleed hero above this screen; standalone renders show the header instead.
    var heroShown = false

    var body: some View {
        if let s = model.status {
            let blocked = model.flows.filter { $0.decision.verdict == .deny }
            let observed = model.flows.filter { $0.decision.isObservation }.count
            VStack(alignment: .leading, spacing: 20) {
                if !heroShown {
                    ScreenHeader(eyebrow: "This computer", title: OverviewHero.headline(s), dim: s.coverage.claim)
                }
                HStack(spacing: 12) {
                    Stat(label: "Flows seen", value: "\(s.flowsSeen)", sub: "since the filter started")
                    Stat(label: "Blocked", value: "\(s.flowsDenied)", sub: "before data was sent", tone: .red)
                    Stat(label: "Observed", value: "\(observed)", sub: "permitted, not enforced", tone: .blue)
                    Stat(label: "Policy", value: s.installed.map { "r\($0.revision)" } ?? "none", sub: s.installed?.policyName ?? "observing only")
                }
                if s.isolation.active {
                    Card {
                        HStack(alignment: .top, spacing: 12) {
                            Image(systemName: "lock.shield.fill").font(.title2).foregroundStyle(p.red)
                            VStack(alignment: .leading, spacing: 4) {
                                Text("Emergency isolation is on").font(.title3.weight(.semibold))
                                Text(s.isolation.reason ?? "").foregroundStyle(p.text2).font(.body)
                                Text("It stays on until you turn it off in Recovery. It never reopens on its own.")
                                    .foregroundStyle(p.muted).font(.callout)
                            }
                            Spacer()
                            MoatButton(title: "Open Recovery", systemImage: "lifepreserver", kind: .danger) { model.screen = .coverage }
                        }
                    }
                }
                HStack(alignment: .top, spacing: 16) {
                    Card {
                        SectionTitle(text: "Recently blocked", trailing: "\(blocked.count) shown")
                        if blocked.isEmpty {
                            Label("Nothing blocked recently. Blocks appear here the moment the filter reports one.", systemImage: "checkmark.seal")
                                .foregroundStyle(p.text2).font(.callout)
                        }
                        ForEach(blocked.prefix(5)) { r in FlowRow(record: r, compact: true) }
                        MoatButton(title: "All activity", systemImage: "arrow.right") { model.screen = .activity }
                    }
                    VStack(spacing: 16) {
                        Card {
                            SectionTitle(text: "Coverage")
                            HStack(spacing: 10) {
                                Image(systemName: s.coverage.symbol).foregroundStyle(s.coverage.tone.color(p)).font(.title2)
                                Text(s.coverage.label).font(.title3.weight(.semibold))
                            }
                            ForEach(Array(s.coverageNotes.prefix(3).enumerated()), id: \.offset) { item in
                                Text(item.element).font(.callout).foregroundStyle(p.text2).fixedSize(horizontal: false, vertical: true)
                            }
                        }
                        Card {
                            SectionTitle(text: "Not covered here")
                            Text("Phones and the TV get DNS-only coverage from the controller's resolver: no per-app identity, no byte counts.")
                                .font(.callout).foregroundStyle(p.text2).fixedSize(horizontal: false, vertical: true)
                        }
                    }
                    .frame(width: 330)
                }
            }
        } else {
            EmptyStateView(text: "Connecting to the Moat filter…")
        }
    }

}

/// Full-bleed status hero at the top of Overview. Its artwork extends under the floating glass sidebar on macOS 26
/// (`backgroundExtensionEffect`); the text sits on an opaque-enough scrim for contrast.
struct OverviewHero: View {
    @Environment(\.palette) private var p
    @Environment(\.colorScheme) private var scheme
    @Environment(\.accessibilityReduceMotion) private var reduceMotion
    let status: StatusReport

    static func headline(_ s: StatusReport) -> String {
        switch s.coverage {
        case .enforced: return "Enforcing."
        case .observed: return "Observing."
        case .isolated: return "Isolated."
        case .degraded: return "Needs attention."
        case .recoveryRequired: return "Recovery required."
        case .rollbackPending: return "Rollback pending."
        case .unknown: return "No report."
        }
    }

    var body: some View {
        let tone = status.coverage.tone.color(p)
        ZStack(alignment: .bottomLeading) {
            ZStack {
                LinearGradient(colors: [tone.opacity(scheme == .dark ? 0.55 : 0.38), p.accent.opacity(0.42), p.accent2.opacity(0.30)],
                               startPoint: .topLeading, endPoint: .bottomTrailing)
                Image(systemName: status.coverage.symbol)
                    .font(.system(size: 230, weight: .ultraLight))
                    .foregroundStyle(.white.opacity(scheme == .dark ? 0.08 : 0.18))
                    .offset(x: 340, y: 30)
                    .accessibilityHidden(true)
            }
            .moatBackgroundExtension()
            LinearGradient(colors: [.clear, p.bg.opacity(scheme == .dark ? 0.75 : 0.6)], startPoint: .top, endPoint: .bottom)
                .accessibilityHidden(true)
            VStack(alignment: .leading, spacing: 8) {
                Label {
                    Text("This Mac · \(status.coverage.label)")
                } icon: {
                    Image(systemName: status.coverage.symbol).moatPulse(status.coverage == .isolated, reduceMotion: reduceMotion)
                }
                .font(.headline)
                .foregroundStyle(p.text)
                Text(Self.headline(status)).font(.system(.largeTitle, design: .rounded).weight(.heavy)).foregroundStyle(p.text)
                    .accessibilityAddTraits(.isHeader)
                Text(status.coverage.claim).font(.title3).foregroundStyle(p.text2).fixedSize(horizontal: false, vertical: true)
            }
            .padding(.horizontal, 32)
            .padding(.bottom, 26)
            .frame(maxWidth: 1040, alignment: .leading)
        }
        .frame(height: 250)
        .frame(maxWidth: .infinity)
        .clipped()
        .accessibilityElement(children: .combine)
    }
}

// MARK: - Activity

struct FlowRow: View {
    @Environment(\.palette) private var p
    let record: FlowRecord
    var compact = false

    var body: some View {
        let pill = record.decision.pill
        let label = pill.0
        let tone = pill.1
        HStack(alignment: .top, spacing: 12) {
            ZStack {
                RoundedRectangle(cornerRadius: 8, style: .continuous).fill(tone.color(p).opacity(0.12)).frame(width: 32, height: 32)
                Image(systemName: record.decision.verdict == .deny ? "xmark.shield" : (record.decision.isObservation ? "eye" : "checkmark.shield"))
                    .font(.body.weight(.semibold)).foregroundStyle(tone.color(p))
            }
            VStack(alignment: .leading, spacing: 3) {
                HStack(spacing: 8) {
                    Text(record.facts.appLabel).font(.body.weight(.semibold)).lineLimit(1)
                    Image(systemName: "arrow.right").font(.caption2.weight(.bold)).foregroundStyle(p.muted)
                    Text(destination).font(.system(.body, design: .monospaced)).foregroundStyle(p.text2).lineLimit(1)
                }
                Text(record.decision.summary).font(.callout).foregroundStyle(p.muted).lineLimit(compact ? 1 : 2)
                if !compact {
                    HStack(spacing: 10) {
                        Text(record.measurement.label)
                        if record.facts.teamID == nil { Text("no team ID (unsigned or ad-hoc)") }
                        Text("ancestry not available")
                    }
                    .font(.caption).foregroundStyle(p.muted)
                }
            }
            Spacer(minLength: 8)
            VStack(alignment: .trailing, spacing: 4) {
                Pill(text: label, tone: tone)
                Text(TimeText.ago(record.facts.at)).font(.caption).foregroundStyle(p.muted)
            }
        }
        .padding(.vertical, 6)
    }

    private var destination: String {
        let host = record.facts.remoteHost ?? record.facts.remoteIP
        let proto = record.facts.transport == .udp ? "/udp" : ""
        return "\(host):\(record.facts.remotePort)\(proto)"
    }
}

enum ActivityFilter: Hashable { case all, blocked, observed, allowed }

struct ActivityScreen: View {
    @ObservedObject var model: AppModel
    @Environment(\.palette) private var p
    @Environment(\.accessibilityReduceMotion) private var reduceMotion
    @State private var filter: ActivityFilter = .all
    @Namespace private var glassNS

    var body: some View {
        let rows = model.flows.filter {
            switch filter {
            case .all: return true
            case .blocked: return $0.decision.verdict == .deny
            case .observed: return $0.decision.isObservation
            case .allowed: return $0.decision.verdict == .allow && !$0.decision.isObservation
            }
        }
        VStack(alignment: .leading, spacing: 18) {
            ScreenHeader(eyebrow: "Activity", title: "What left this Mac.", dim: "Newest first.")
            HStack {
                MoatGlassContainer(spacing: 10) {
                    HStack(spacing: 10) {
                        Segmented(options: [(ActivityFilter.all, "All"), (ActivityFilter.blocked, "Blocked"), (ActivityFilter.observed, "Observed"), (ActivityFilter.allowed, "Allowed")], selection: $filter)
                            .moatGlassID("filter", in: glassNS, reduceMotion: reduceMotion)
                        if filter != .all {
                            Button {
                                withAnimation(reduceMotion ? nil : .snappy(duration: 0.28)) { filter = .all }
                            } label: {
                                Image(systemName: "xmark").font(.callout.weight(.semibold)).frame(width: 32, height: 32)
                            }
                            .buttonStyle(.plain)
                            .moatGlass(in: Circle(), interactive: true)
                            .moatGlassID("clear", in: glassNS, reduceMotion: reduceMotion)
                            .accessibilityLabel("Show all activity")
                            .help("Show all activity")
                        }
                    }
                }
                Spacer()
                if let gaps = model.status?.telemetryGaps, !gaps.isEmpty {
                    Pill(text: "\(gaps.count) telemetry gap\(gaps.count == 1 ? "" : "s")", tone: .amber, dot: true)
                }
            }
            Card(padding: 14) {
                if rows.isEmpty {
                    EmptyStateView(symbol: "line.3.horizontal.decrease.circle", title: "Nothing here yet",
                                   text: filter == .all ? "Flows appear as soon as the filter sees an outbound connection." : "No recent flows match this filter.")
                }
                ForEach(Array(rows.prefix(60).enumerated()), id: \.element.seq) { item in
                    if item.offset > 0 { Rectangle().fill(p.border).frame(height: 1) }
                    FlowRow(record: item.element)
                }
            }
            Text("Observed flows were permitted because their profile is observing; they were not checked against an allow rule. Byte counts appear only when macOS delivered a filter report.")
                .font(.callout).foregroundStyle(p.muted).fixedSize(horizontal: false, vertical: true)
        }
    }
}

// MARK: - Policy

struct PolicyScreen: View {
    @ObservedObject var model: AppModel
    @Environment(\.palette) private var p
    @State private var importing = false
    @State private var canary = true

    var body: some View {
        VStack(alignment: .leading, spacing: 18) {
            ScreenHeader(eyebrow: "Policy", title: "Signed policy.", dim: "Verified on this Mac before it is used.")
            HStack(spacing: 10) {
                MoatButton(title: "Learning", systemImage: "sparkles") { model.screen = .learning }
                MoatButton(title: "Workflow packs", systemImage: "shippingbox") { model.screen = .packs }
            }
            if let s = model.status {
                HStack(alignment: .top, spacing: 16) {
                    Card {
                        SectionTitle(text: "Installed")
                        if let i = s.installed {
                            summaryRows(i)
                        } else {
                            Text("No signed policy is installed. Moat is observing only.").foregroundStyle(p.text2).font(.body)
                        }
                        VStack(alignment: .leading, spacing: 10) {
                            MoatButton(title: "Apply signed snapshot…", systemImage: "square.and.arrow.down", kind: .primary) { importing = true }
                            Toggle("10-minute canary (reverts unless you keep it)", isOn: $canary)
                                .toggleStyle(.checkbox)
                                .font(.callout)
                        }
                    }
                    Card {
                        SectionTitle(text: "Last known good")
                        if let g = s.lastKnownGood {
                            summaryRows(g)
                        } else {
                            Text("None yet. The first confirmed revision becomes last known good when the next one is applied.")
                                .foregroundStyle(p.muted).font(.body).fixedSize(horizontal: false, vertical: true)
                        }
                    }
                }
                if s.coverageNotes.contains(where: { $0.hasPrefix("Canary rollout") }) {
                    Card {
                        HStack {
                            Image(systemName: "timer").foregroundStyle(p.amber)
                            Text(s.coverageNotes.first { $0.hasPrefix("Canary rollout") } ?? "").font(.body)
                            Spacer()
                            MoatButton(title: "Keep this revision", systemImage: "checkmark", kind: .primary) { Task { await model.confirmCanary() } }
                        }
                    }
                }
                if let r = s.lastRejection {
                    Card {
                        SectionTitle(text: "Last change")
                        Text(r).font(.body).foregroundStyle(p.text2).fixedSize(horizontal: false, vertical: true)
                    }
                }
                Card {
                    SectionTitle(text: "Left out on macOS", trailing: "\(s.installed?.omitted.count ?? 0) rules")
                    Text("These rules need a capability this Mac does not have. They are omitted and reported, never compiled into something weaker.")
                        .font(.callout).foregroundStyle(p.muted).fixedSize(horizontal: false, vertical: true)
                    ForEach(s.installed?.omitted ?? []) { o in
                        HStack(alignment: .top, spacing: 10) {
                            Text(o.ruleID).font(.system(.callout, design: .monospaced).weight(.semibold))
                            Text(o.reason).font(.callout).foregroundStyle(p.text2).fixedSize(horizontal: false, vertical: true)
                        }
                    }
                }
            } else {
                EmptyStateView(text: "Connecting to the Moat filter…")
            }
        }
        .fileImporter(isPresented: $importing, allowedContentTypes: [.json]) { result in
            if case let .success(url) = result {
                Task { await model.apply(fileURL: url, canarySeconds: canary ? 600 : 0) }
            }
        }
    }

    @ViewBuilder private func summaryRows(_ i: PolicySummary) -> some View {
        VStack(alignment: .leading, spacing: 6) {
            HStack(alignment: .firstTextBaseline, spacing: 8) {
                Text(verbatim: "r\(i.revision)").font(.system(.title, design: .rounded).weight(.semibold))
                Text(i.policyName).font(.body.weight(.medium)).foregroundStyle(p.text2)
                if let rb = i.rollbackOf { Pill(text: "rollback of r\(rb)", tone: .amber) }
            }
            Text("\(i.ruleCount) rules · digest \(String(i.digest.prefix(12)))").font(.system(.callout, design: .monospaced)).foregroundStyle(p.muted)
            Text("Applied \(TimeText.ago(i.appliedAt))").font(.callout).foregroundStyle(p.muted)
        }
    }
}

// MARK: - Coverage

struct CoverageScreen: View {
    @ObservedObject var model: AppModel
    @Environment(\.palette) private var p

    var body: some View {
        VStack(alignment: .leading, spacing: 18) {
            ScreenHeader(eyebrow: "Coverage", title: "What Moat can claim here.", dim: "Untested means not yet proven on a real, signed install.")
            if let s = model.status {
                Card {
                    SectionTitle(text: "Capabilities · macOS content filter")
                    ForEach(Array(s.capabilities.enumerated()), id: \.element.key) { item in
                        let c = item.element
                        if item.offset > 0 { Rectangle().fill(p.border).frame(height: 1) }
                        HStack(alignment: .top) {
                            VStack(alignment: .leading, spacing: 2) {
                                Text(c.label).font(.body.weight(.semibold))
                                if let n = c.note { Text(n).font(.callout).foregroundStyle(p.muted) }
                            }
                            Spacer()
                            Pill(text: c.support.rawValue.capitalized, tone: c.support.tone)
                        }
                        .padding(.vertical, 4)
                    }
                }
                Card {
                    SectionTitle(text: "Status notes")
                    ForEach(Array(s.coverageNotes.enumerated()), id: \.offset) { item in
                        HStack(alignment: .top, spacing: 8) {
                            Circle().fill(p.muted).frame(width: 4, height: 4).padding(.top, 7)
                            Text(item.element).font(.body).foregroundStyle(p.text2).fixedSize(horizontal: false, vertical: true)
                        }
                    }
                    if !s.telemetryGaps.isEmpty {
                        ForEach(Array(s.telemetryGaps.enumerated()), id: \.offset) { item in
                            Text("Events \(item.element.fromSeq)–\(item.element.toSeq) missing: \(item.element.reason)")
                                .font(.callout).foregroundStyle(p.amber)
                        }
                    }
                }
                Card {
                    SectionTitle(text: "Not claimed on macOS")
                    Text("Moat does not claim fail-closed behavior if the extension is disabled or crashes, process ancestry, protected-session containment, or compatibility with any particular VPN until each is proven on a real device. Session-scoped rules are left out of this Mac's policy and reported.")
                        .font(.callout).foregroundStyle(p.text2).fixedSize(horizontal: false, vertical: true)
                }
            } else {
                EmptyStateView(text: "Connecting to the Moat filter…")
            }
        }
    }
}

// MARK: - Recovery

struct RecoveryScreen: View {
    @ObservedObject var model: AppModel
    @Environment(\.palette) private var p
    @State private var confirmIsolate = false
    @State private var showExit = false
    @State private var phrase = ""

    var body: some View {
        VStack(alignment: .leading, spacing: 18) {
            ScreenHeader(eyebrow: "Recovery", title: "Local controls.", dim: "These work without the controller.")
            let iso = model.status?.isolation ?? .off
            Card {
                HStack(alignment: .top, spacing: 14) {
                    Image(systemName: iso.active ? "lock.shield.fill" : "lock.open")
                        .font(.title).foregroundStyle(iso.active ? p.red : p.muted).frame(width: 34)
                    VStack(alignment: .leading, spacing: 6) {
                        Text(iso.active ? "Emergency isolation is on" : "Emergency isolation").font(.title3.weight(.semibold))
                        Text(iso.active
                            ? "Everything except loopback is blocked. \(iso.reason ?? "")"
                            : "Blocks new outbound connections except loopback on this Mac, immediately. Connections already open are not cut. It stays on through restarts and never reopens because the controller disappeared.")
                            .font(.body).foregroundStyle(p.text2).fixedSize(horizontal: false, vertical: true)
                        if iso.active, showExit {
                            Text("Type \u{201C}\(ControlHandler.exitPhrase)\u{201D} to confirm.").font(.callout).foregroundStyle(p.muted)
                            HStack {
                                TextField(ControlHandler.exitPhrase, text: $phrase).textFieldStyle(.roundedBorder).frame(maxWidth: 260)
                                MoatButton(title: "Turn off", kind: .primary, disabled: phrase.isEmpty) {
                                    Task { await model.exitIsolation(confirmation: phrase); phrase = ""; showExit = false }
                                }
                            }
                        }
                    }
                    Spacer()
                    if iso.active {
                        if !showExit { MoatButton(title: "Turn off…", systemImage: "lock.open") { showExit = true } }
                    } else {
                        MoatButton(title: "Isolate this Mac", systemImage: "lock.shield", kind: .danger) { confirmIsolate = true }
                    }
                }
            }
            Card {
                HStack(alignment: .top, spacing: 14) {
                    Image(systemName: "arrow.uturn.backward.circle").font(.title).foregroundStyle(p.accent).frame(width: 34)
                    VStack(alignment: .leading, spacing: 6) {
                        Text("Roll back to last known good").font(.title3.weight(.semibold))
                        Text(model.status?.lastKnownGood.map { "Reinstates revision \($0.revision) (\($0.policyName)). Older signed snapshots from the network are still rejected as replays." }
                            ?? "No last known good revision yet.")
                            .font(.body).foregroundStyle(p.text2).fixedSize(horizontal: false, vertical: true)
                    }
                    Spacer()
                    MoatButton(title: "Roll back", systemImage: "arrow.uturn.backward", disabled: model.status?.lastKnownGood == nil) {
                        Task { await model.rollback() }
                    }
                }
            }
            Card {
                SectionTitle(text: "If the app cannot reach the filter")
                VStack(alignment: .leading, spacing: 8) {
                    step(1, "System Settings › Network › Filters: turn the Moat filter off. Traffic flows without Moat; nothing is enforced.")
                    step(2, "Run `systemextensionsctl list` in Terminal to see whether the extension is activated or waiting for approval.")
                    step(3, "To uninstall: quit Moat, move it to the Trash, and approve removal of the system extension when macOS asks. `brew uninstall --cask moat` does the same.")
                }
            }
        }
        .confirmationDialog("Isolate this Mac?", isPresented: $confirmIsolate) {
            Button("Isolate now", role: .destructive) { Task { await model.enterIsolation(reason: "Turned on from the Moat app") } }
            Button("Cancel", role: .cancel) {}
        } message: {
            Text("New outbound connections except loopback are blocked until you turn isolation off here. Connections already open are not cut.")
        }
    }

    private func step(_ n: Int, _ text: String) -> some View {
        HStack(alignment: .top, spacing: 10) {
            Text("\(n)").font(.caption2.weight(.bold)).foregroundStyle(p.accent)
                .frame(width: 20, height: 20).background(Circle().fill(p.accent.opacity(0.12)))
            Text(LocalizedStringKey(text)).font(.body).foregroundStyle(p.text2).fixedSize(horizontal: false, vertical: true)
        }
    }
}
