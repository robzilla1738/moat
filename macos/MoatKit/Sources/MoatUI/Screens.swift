import MoatKit
import SwiftUI
import UniformTypeIdentifiers

// MARK: - Status headline

/// The one-line answer to "is this Mac protected?" in the shared words (brand/vocabulary.json).
enum OverviewHero {
    static func headline(_ s: StatusReport) -> String {
        switch s.coverage {
        case .enforced: return "Protected."
        case .observed: return "Watching only."
        case .isolated: return "Locked down."
        case .degraded: return "Partly protected."
        case .recoveryRequired: return "Needs you at this Mac."
        case .rollbackPending: return "Undo didn't finish."
        case .unknown: return "Can't confirm."
        }
    }
}

// MARK: - Activity

struct FlowRow: View {
    @Environment(\.palette) private var p
    let record: FlowRecord
    var compact = false

    var body: some View {
        let pill = record.decision.pill
        HStack(alignment: .top, spacing: Space.s3) {
            ZStack {
                RoundedRectangle(cornerRadius: Radius.inner, style: .continuous).fill(pill.1.color(p).opacity(0.12)).frame(width: Space.s8, height: Space.s8)
                Image(systemName: record.decision.verdict == .deny ? "xmark.shield" : (record.decision.isObservation ? "eye" : "checkmark.shield"))
                    .font(.body.weight(.semibold)).foregroundStyle(pill.1.color(p))
            }
            .accessibilityHidden(true)
            VStack(alignment: .leading, spacing: Space.s1) {
                Text(verbatim: record.facts.appLabel).font(.body.weight(.semibold)).lineLimit(1)
                Text(verbatim: destination).font(.system(.callout, design: .monospaced)).foregroundStyle(p.text2).lineLimit(1).truncationMode(.middle)
                if !compact {
                    HStack(spacing: Space.s2) {
                        Text(verbatim: record.measurement.label)
                        if record.facts.teamID == nil { Text("Not signed") }
                    }
                    .font(.caption).foregroundStyle(p.muted)
                }
            }
            Spacer(minLength: Space.s2)
            VStack(alignment: .trailing, spacing: Space.s1) {
                Pill(text: pill.0, tone: pill.1)
                Text(TimeText.ago(record.facts.at)).font(.caption).foregroundStyle(p.muted)
            }
        }
        .padding(.vertical, Space.s1)
        .accessibilityElement(children: .combine)
    }

    private var destination: String {
        let host = record.facts.remoteHost ?? record.facts.remoteIP
        let proto = record.facts.transport == .udp ? "/udp" : ""
        return "\(host):\(record.facts.remotePort)\(proto)"
    }
}

enum ActivityFilter: Hashable { case all, blocked, observed, allowed }

/// Activity: "What did this Mac connect to, and what was blocked?"
struct ActivityScreen: View {
    @ObservedObject var model: AppModel
    @Environment(\.palette) private var p
    @State private var filter: ActivityFilter = .all

    var body: some View {
        let rows = model.flows.filter {
            switch filter {
            case .all: return true
            case .blocked: return $0.decision.verdict == .deny
            case .observed: return $0.decision.isObservation
            case .allowed: return $0.decision.verdict == .allow && !$0.decision.isObservation
            }
        }
        VStack(alignment: .leading, spacing: Space.s5) {
            ScreenHeader(eyebrow: "Activity", title: "What this Mac connected to", dim: "Newest first.")
            HStack {
                Segmented(options: [(ActivityFilter.all, "All"), (ActivityFilter.blocked, "Blocked"), (ActivityFilter.observed, "Watched only"), (ActivityFilter.allowed, "Allowed")], selection: $filter)
                Spacer()
                if let gaps = model.status?.telemetryGaps, !gaps.isEmpty {
                    Pill(text: gaps.count == 1 ? "1 gap in reports" : "\(gaps.count) gaps in reports", tone: .amber)
                }
            }
            Card(padding: Space.s4) {
                if rows.isEmpty {
                    EmptyStateView(symbol: "line.3.horizontal.decrease.circle", title: "Nothing here yet",
                                   text: filter == .all ? "Connections appear as soon as the filter sees an app reach out." : "No recent connections match this filter.")
                }
                ForEach(Array(rows.prefix(60).enumerated()), id: \.element.seq) { item in
                    if item.offset > 0 { Rectangle().fill(p.border).frame(height: 1) }
                    FlowRow(record: item.element)
                }
            }
            Text("“Watched only” means Moat let the connection through without checking a rule. Data amounts appear only when macOS reports them, and this Mac can't see which app started another.")
                .font(.callout).foregroundStyle(p.muted).fixedSize(horizontal: false, vertical: true)
        }
    }
}

// MARK: - Rules

/// Rules: "Which rules is this Mac using, and can I go back?"
struct PolicyScreen: View {
    @ObservedObject var model: AppModel
    @Environment(\.palette) private var p
    @State private var importing = false
    @State private var canary = true

    var body: some View {
        VStack(alignment: .leading, spacing: Space.s5) {
            ScreenHeader(eyebrow: "Rules", title: "Your rules", dim: "Moat checks the signature on your rules before this Mac uses them.")
            HStack(spacing: Space.s2) {
                MoatButton(title: "Learn what an app needs", systemImage: "sparkles") { model.screen = .learning }
                MoatButton(title: "Rule packs", systemImage: "shippingbox") { model.screen = .packs }
            }
            if let s = model.status {
                if let note = s.coverageNotes.first(where: { $0.hasPrefix("Canary rollout") }) {
                    Card {
                        HStack(alignment: .top, spacing: Space.s3) {
                            Image(systemName: "timer").foregroundStyle(p.amber).accessibilityHidden(true)
                            VStack(alignment: .leading, spacing: Space.s1) {
                                Text("Trying new rules").font(.headline)
                                Text(verbatim: note).font(.callout).foregroundStyle(p.text2).fixedSize(horizontal: false, vertical: true)
                            }
                            Spacer()
                            MoatButton(title: "Keep these rules", systemImage: "checkmark", kind: .primary) { Task { await model.confirmCanary() } }
                        }
                    }
                }
                HStack(alignment: .top, spacing: Space.s4) {
                    Card {
                        SectionTitle(text: "In use")
                        if let i = s.installed {
                            summaryRows(i)
                        } else {
                            Text("No signed rules yet, so Moat is only watching.").foregroundStyle(p.text2).font(.body)
                        }
                        VStack(alignment: .leading, spacing: Space.s2) {
                            MoatButton(title: "Install signed rules…", systemImage: "square.and.arrow.down", kind: .primary) { importing = true }
                            Toggle("Try for 10 minutes first (undoes itself unless you keep it)", isOn: $canary)
                                .toggleStyle(.checkbox)
                                .font(.callout)
                                .disabled(s.installed == nil)
                            if s.installed == nil {
                                Text("Your first rules can't be a trial: there is nothing to go back to.")
                                    .font(.callout).foregroundStyle(p.muted).fixedSize(horizontal: false, vertical: true)
                            }
                        }
                    }
                    Card {
                        SectionTitle(text: "Last good version")
                        if let g = s.lastKnownGood {
                            summaryRows(g)
                        } else {
                            Text("None yet. Your current rules become the last good version once you install the next ones.")
                                .foregroundStyle(p.muted).font(.body).fixedSize(horizontal: false, vertical: true)
                        }
                    }
                }
                if let r = s.lastRejection {
                    NoticeBanner(title: "Your last change was refused.", text: r)
                }
                let omitted = s.installed?.omitted ?? []
                if !omitted.isEmpty {
                    Card {
                        SectionTitle(text: "Rules this Mac can't apply", trailing: "\(omitted.count)")
                        Text("These need something this Mac can't do. They're left out and reported, never turned into something weaker.")
                            .font(.callout).foregroundStyle(p.muted).fixedSize(horizontal: false, vertical: true)
                        ForEach(omitted) { o in
                            ListRowView(title: o.ruleID, sub: o.reason, mono: true)
                        }
                    }
                }
            } else {
                EmptyStateView(text: "Connecting to the Moat filter…")
            }
        }
        .fileImporter(isPresented: $importing, allowedContentTypes: [.json]) { result in
            if case let .success(url) = result {
                Task { await model.apply(fileURL: url, canarySeconds: canary && model.status?.installed != nil ? 600 : 0) }
            }
        }
    }

    @ViewBuilder private func summaryRows(_ i: PolicySummary) -> some View {
        VStack(alignment: .leading, spacing: Space.s2) {
            HStack(alignment: .firstTextBaseline, spacing: Space.s2) {
                Text(verbatim: i.policyName).font(.title3.weight(.semibold))
                if let rb = i.rollbackOf { Pill(text: "Brought back version \(rb)", tone: .amber) }
            }
            Text("\(i.ruleCount) rules · installed \(TimeText.ago(i.appliedAt))").font(.callout).foregroundStyle(p.muted)
            TechnicalDetails {
                Text(verbatim: "Version \(i.revision) · digest \(String(i.digest.prefix(12)))").font(.system(.callout, design: .monospaced))
            }
        }
    }
}

// MARK: - Coverage

/// Coverage: "What can Moat really do on this Mac?"
struct CoverageScreen: View {
    @ObservedObject var model: AppModel
    @Environment(\.palette) private var p

    var body: some View {
        VStack(alignment: .leading, spacing: Space.s5) {
            ScreenHeader(eyebrow: "Coverage", title: "What Moat can do on this Mac", dim: "“Not proven yet” means built, but not yet shown working on a real, signed install.")
            if let s = model.status {
                if !s.telemetryGaps.isEmpty {
                    NoticeBanner(title: s.telemetryGaps.count == 1 ? "1 gap in reports" : "\(s.telemetryGaps.count) gaps in reports",
                                 text: s.telemetryGaps.map { "Reports \($0.fromSeq)–\($0.toSeq) are missing: \($0.reason)" }.joined(separator: "\n"))
                }
                Card {
                    SectionTitle(text: "Abilities")
                    ForEach(Array(s.capabilities.enumerated()), id: \.element.key) { item in
                        let c = item.element
                        if item.offset > 0 { Rectangle().fill(p.border).frame(height: 1) }
                        ListRowView(title: c.label, sub: c.note) { Pill(text: c.support.label, tone: c.support.tone) }
                    }
                }
                if !s.coverageNotes.isEmpty {
                    Card {
                        SectionTitle(text: "Notes from the filter")
                        ForEach(Array(s.coverageNotes.enumerated()), id: \.offset) { item in
                            Text(verbatim: item.element).font(.callout).foregroundStyle(p.text2).fixedSize(horizontal: false, vertical: true)
                        }
                    }
                }
                Card {
                    SectionTitle(text: "What Moat doesn't claim here")
                    Text("Until each is shown on a real device, Moat doesn't claim that traffic stops if the filter is turned off or crashes, that it can see which app started another, that tasks are kept inside a boundary, or that it works with any particular VPN. Rules for tasks are left out of this Mac's rules and reported.")
                        .font(.callout).foregroundStyle(p.text2).fixedSize(horizontal: false, vertical: true)
                }
            } else {
                EmptyStateView(text: "Connecting to the Moat filter…")
            }
        }
    }
}

// MARK: - Recovery

/// Recovery: "Something broke: how do I get back?" Every control here works without the controller.
struct RecoveryScreen: View {
    @ObservedObject var model: AppModel
    @Environment(\.palette) private var p
    @State private var confirmIsolate = false
    @State private var showExit = false
    @State private var phrase = ""

    var body: some View {
        VStack(alignment: .leading, spacing: Space.s5) {
            ScreenHeader(eyebrow: "Recovery", title: "Get back to working", dim: "These work on this Mac, even without your controller.")
            let iso = model.status?.isolation ?? .off
            Card {
                HStack(alignment: .top, spacing: Space.s4) {
                    Image(systemName: iso.active ? "lock.shield.fill" : "lock.open")
                        .font(.title).foregroundStyle(iso.active ? p.red : p.muted).frame(width: Space.s8)
                        .accessibilityHidden(true)
                    VStack(alignment: .leading, spacing: Space.s2) {
                        Text(iso.active ? "Emergency lockdown is on" : "Emergency lockdown").font(.title3.weight(.semibold))
                        Text(iso.active
                            ? "New connections from this Mac are blocked, except to itself. \(iso.reason ?? "")"
                            : "Blocks new connections from this Mac right away, except to itself. Connections already open stay open. It stays on through restarts and never turns off just because your controller is gone.")
                            .font(.body).foregroundStyle(p.text2).fixedSize(horizontal: false, vertical: true)
                        if iso.active, showExit {
                            Text("Type \u{201C}\(ControlHandler.exitPhrase)\u{201D} to confirm.").font(.callout).foregroundStyle(p.muted)
                            HStack {
                                TextField(ControlHandler.exitPhrase, text: $phrase).textFieldStyle(.roundedBorder).frame(maxWidth: 260)
                                MoatButton(title: "Turn off lockdown", kind: .primary, disabled: phrase.isEmpty) {
                                    Task { await model.exitIsolation(confirmation: phrase); phrase = ""; showExit = false }
                                }
                            }
                        }
                    }
                    Spacer()
                    if iso.active {
                        if !showExit { MoatButton(title: "Turn off…", systemImage: "lock.open") { showExit = true } }
                    } else {
                        MoatButton(title: "Lock down this Mac", systemImage: "lock.shield", kind: .danger) { confirmIsolate = true }
                    }
                }
            }
            Card {
                HStack(alignment: .top, spacing: Space.s4) {
                    Image(systemName: "arrow.uturn.backward.circle").font(.title).foregroundStyle(p.accent).frame(width: Space.s8)
                        .accessibilityHidden(true)
                    VStack(alignment: .leading, spacing: Space.s2) {
                        Text("Go back to the last good version").font(.title3.weight(.semibold))
                        Text(model.status?.lastKnownGood.map { "Brings back version \($0.revision) (\($0.policyName)). Older signed rules sent over the network are still refused." }
                            ?? "There's no last good version yet.")
                            .font(.body).foregroundStyle(p.text2).fixedSize(horizontal: false, vertical: true)
                    }
                    Spacer()
                    MoatButton(title: "Go back", systemImage: "arrow.uturn.backward", disabled: model.status?.lastKnownGood == nil) {
                        Task { await model.rollback() }
                    }
                }
            }
            Card {
                SectionTitle(text: "If Moat can't reach its filter")
                VStack(alignment: .leading, spacing: Space.s2) {
                    step(1, "System Settings › Network › Filters: turn the Moat filter off. Traffic then flows without Moat; nothing is blocked.")
                    step(2, "To see whether the filter is installed or waiting for your approval, run `systemextensionsctl list` in Terminal.")
                    step(3, "To uninstall: quit Moat, move it to the Trash, and allow the removal when macOS asks. `brew uninstall --cask moat` does the same.")
                }
            }
        }
        .confirmationDialog("Lock down this Mac?", isPresented: $confirmIsolate) {
            Button("Lock down now", role: .destructive) { Task { await model.enterIsolation(reason: "Turned on from the Moat app") } }
            Button("Cancel", role: .cancel) {}
        } message: {
            Text("New connections from this Mac are blocked, except to itself, until you turn lockdown off here. Connections already open stay open.")
        }
    }

    private func step(_ n: Int, _ text: String) -> some View {
        HStack(alignment: .top, spacing: Space.s2) {
            Text(verbatim: "\(n)").font(.caption2.weight(.bold)).foregroundStyle(p.accent)
                .frame(width: Space.s5, height: Space.s5).background(Circle().fill(p.accent.opacity(0.12)))
            Text(LocalizedStringKey(text)).font(.body).foregroundStyle(p.text2).fixedSize(horizontal: false, vertical: true)
        }
    }
}
