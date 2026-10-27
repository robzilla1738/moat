import MoatKit
import SwiftUI

// MARK: - W14: learning capture, candidate review, owner-authorized baselines, drift queue, workflow packs
// (same Card / Pill / glass language as the rest of the app)

struct LearningScreen: View {
    @ObservedObject var model: AppModel
    @Environment(\.palette) private var p

    var body: some View {
        let drift = model.driftQueue()
        VStack(alignment: .leading, spacing: 18) {
            Button { model.screen = .rules } label: { Label("Rules", systemImage: "chevron.left") }.buttonStyle(.plain).foregroundStyle(p.accent)
            ScreenHeader(eyebrow: "Learning", title: "Proposals, never trust.", dim: "Capture one workflow, review every destination it used, and accept only what you chose with your owner key.")
            CaptureControlCard(model: model)
            Card {
                SectionTitle(text: "Captures", trailing: "\(model.learning.captures.count) open")
                if model.learning.captures.isEmpty { Text("No capture running.").font(.callout).foregroundStyle(p.text2) }
                ForEach(model.learning.captures) { c in
                    HStack(alignment: .center, spacing: 10) {
                        VStack(alignment: .leading, spacing: 3) {
                            HStack(spacing: 6) {
                                Text(c.workflow).font(.callout.weight(.semibold))
                                Pill(text: Date() < c.end ? "capturing" : "window ended", tone: Date() < c.end ? .blue : .amber, dot: Date() < c.end)
                            }
                            Text("\(c.appName) · \(c.networkContext) · \(TimeText.windowEnd(c.end))").font(.caption).foregroundStyle(p.muted).lineLimit(1)
                            Text(c.identityLabel).font(.system(.caption, design: .monospaced)).foregroundStyle(p.text2).lineLimit(1).truncationMode(.middle)
                        }
                        Spacer()
                        MoatButton(title: "Close and review", systemImage: "checklist") { model.closeCapture(c.id) }
                    }
                }
            }
            Card {
                SectionTitle(text: "Candidates", trailing: "\(model.learning.candidates.count) to review")
                if model.learning.candidates.isEmpty { Text("Nothing waiting for review.").font(.callout).foregroundStyle(p.text2) }
                ForEach(model.learning.candidates) { c in CandidateRowView(model: model, candidate: c) }
            }
            Card {
                SectionTitle(text: "Drift review", trailing: "\(drift.count) in queue")
                Text("New activity after approval never changes a baseline. It arrives here as a new candidate, with identity changes listed.").font(.caption).foregroundStyle(p.muted)
                if drift.isEmpty { Text("No drift waiting.").font(.callout).foregroundStyle(p.text2) }
                ForEach(drift) { c in CandidateRowView(model: model, candidate: c) }
            }
            Card {
                SectionTitle(text: "Reviewed baselines", trailing: "immutable")
                if model.learning.baselines.isEmpty { Text("No baseline accepted yet.").font(.callout).foregroundStyle(p.text2) }
                ForEach(model.learning.baselines) { b in
                    HStack(alignment: .top, spacing: 10) {
                        VStack(alignment: .leading, spacing: 3) {
                            HStack(spacing: 6) {
                                Text(b.scope.appName).font(.callout.weight(.semibold))
                                if model.learning.retired[b.id] != nil { Pill(text: "retired", tone: .neutral) } else if model.learning.active.contains(where: { $0.id == b.id }) { Pill(text: "\(b.entries.count) entries", tone: .blue) } else { Pill(text: "superseded", tone: .neutral) }
                            }
                            Text("\(b.scope.workflow) · approved \(TimeText.ago(b.approvedAt)) · key \(b.authorizedBy)").font(.caption).foregroundStyle(p.muted).lineLimit(1)
                            Text(b.entries.map { "\($0.destination):\($0.port)" }.joined(separator: "  ·  ")).font(.system(.caption, design: .monospaced)).foregroundStyle(p.text2).lineLimit(2)
                        }
                        Spacer()
                        if model.learning.retired[b.id] == nil { MoatButton(title: "Retire", systemImage: "archivebox") { model.retire(b) } }
                    }
                }
                Text("Enforcing a reviewed baseline from this Mac alone is not available yet: propose it from your controller, where it becomes an owner-key-authorized broadening change. Denies keep precedence.").font(.caption).foregroundStyle(p.muted)
            }
        }
    }
}

struct CandidateRowView: View {
    @ObservedObject var model: AppModel
    let candidate: LearningCandidate
    @Environment(\.palette) private var p

    var body: some View {
        let base = model.learning.current(for: candidate.scope)
        let adds = Learning.diff(candidate, against: candidate.kind == .drift ? base : nil).filter { $0.change == .adds }.count
        Button { model.open(candidate: candidate.id) } label: {
            HStack(spacing: 10) {
                VStack(alignment: .leading, spacing: 3) {
                    HStack(spacing: 6) {
                        Text(candidate.scope.appName).font(.callout.weight(.semibold))
                        Pill(text: candidate.complete ? "complete" : "incomplete", tone: candidate.complete ? .green : .amber)
                        if candidate.kind == .drift { Pill(text: "drift", tone: .violet) }
                    }
                    Text("\(adds) would broaden · \(candidate.entries.count) proposed\(candidate.identityChanges.isEmpty ? "" : " · \(candidate.identityChanges.count) identity change") · \(candidate.scope.workflow)").font(.caption).foregroundStyle(p.text2).lineLimit(1)
                }
                Spacer()
                Image(systemName: "chevron.right").foregroundStyle(p.muted)
            }
            .contentShape(Rectangle())
        }
        .buttonStyle(.plain)
        .accessibilityElement(children: .combine)
    }
}

/// Start a bounded capture for one app identity, one named workflow and network context, at most eight hours.
struct CaptureControlCard: View {
    @ObservedObject var model: AppModel
    @Environment(\.palette) private var p
    @State private var appID = ""
    @State private var workflow = ""
    @State private var network = "home LAN"
    @State private var hours = 1

    var body: some View {
        let apps = model.apps.filter { $0.identityKnown }
        Card {
            HStack { SectionTitle(text: "Capture a workflow"); Pill(text: "bounded", tone: .blue) }
            Text("Records what one app does during one workflow so you can review it. Existing rules, including every deny, stay enforced while it runs.").font(.callout).foregroundStyle(p.text2).fixedSize(horizontal: false, vertical: true)
            Picker("App", selection: $appID) {
                Text("Choose an app").tag("")
                ForEach(apps) { a in Text(Self.pickerLabel(a)).tag(a.id) }
            }
            TextField("Workflow (e.g. npm install)", text: $workflow).textFieldStyle(.roundedBorder)
            TextField("Network context (e.g. home LAN)", text: $network).textFieldStyle(.roundedBorder)
            Stepper("For \(hours) hour\(hours == 1 ? "" : "s") (at most \(Int(Learning.maxCaptureHours)))", value: $hours, in: 1 ... Int(Learning.maxCaptureHours))
            HStack {
                MoatButton(title: "Start capture", systemImage: "record.circle", kind: .primary, disabled: appID.isEmpty || workflow.trimmingCharacters(in: .whitespaces).isEmpty) {
                    if let a = apps.first(where: { $0.id == appID }) { model.startCapture(app: a, workflow: workflow, networkContext: network, hours: Double(hours)) }
                }
                Text("A name alone is never identity: the capture is bound to the app's signing identifier and team.").font(.caption).foregroundStyle(p.muted)
            }
        }
    }
}

extension CaptureControlCard {
    static func pickerLabel(_ a: AppSummary) -> String {
        let who = a.teamID.map { "team " + $0 } ?? (a.executable ?? "unsigned")
        return a.name + " — " + who
    }
}

/// Candidate review: the permission diff and its evidence. Accepting needs the owner key behind Touch ID or the
/// password; nothing is selected by default.
struct CandidateReviewScreen: View {
    @ObservedObject var model: AppModel
    @Environment(\.palette) private var p
    @State private var selected: Set<Int> = []
    @State private var acknowledged = false

    var body: some View {
        if let c = model.selectedCandidate {
            let base = model.learning.current(for: c.scope)
            let rows = Learning.diff(c, against: c.kind == .drift ? base : nil)
            let problems = Learning.acceptProblems(c, accepting: Array(selected), acknowledgeIncomplete: acknowledged)
            VStack(alignment: .leading, spacing: 18) {
                Button { model.screen = .learning } label: { Label("Learning", systemImage: "chevron.left") }.buttonStyle(.plain).foregroundStyle(p.accent)
                ScreenHeader(eyebrow: c.kind == .drift ? "Drift since approval" : "From a capture · \(c.scope.workflow)", title: c.scope.appName, dim: c.scope.identityLabel)
                Card {
                    HStack { SectionTitle(text: "Evidence"); Pill(text: c.complete ? "complete" : "incomplete", tone: c.complete ? .green : .amber) }
                    if c.incompleteReasons.isEmpty {
                        Text("No gaps: no lost events and every connection in the window had an app identity.").font(.callout).foregroundStyle(p.green)
                    }
                    ForEach(c.incompleteReasons, id: \.self) { r in
                        HStack(alignment: .top, spacing: 8) {
                            Pill(text: r.contains("no app identity") ? "unknown identity" : "gap", tone: r.contains("no app identity") ? .red : .amber)
                            Text(r).font(.callout).fixedSize(horizontal: false, vertical: true)
                        }
                    }
                    ForEach(c.identityChanges, id: \.self) { x in
                        HStack(alignment: .top, spacing: 8) {
                            Pill(text: "not inherited", tone: .amber)
                            Text("Same name, different identity: \(x)").font(.callout).fixedSize(horizontal: false, vertical: true)
                        }
                    }
                    Text("Every entry is proposed. Occurring during capture, or occurring often, does not make it trusted.").font(.caption).foregroundStyle(p.muted)
                }
                Card {
                    SectionTitle(text: "Permission diff", trailing: "\(rows.filter { $0.change == .adds }.count) would broaden")
                    Text(c.kind == .drift ? "Against the current reviewed baseline." : "No reviewed baseline for this identity yet: every accepted entry is new.").font(.caption).foregroundStyle(p.muted)
                    ForEach(rows) { r in
                        Toggle(isOn: Binding(get: { selected.contains(r.index) }, set: { on in if on { selected.insert(r.index) } else { selected.remove(r.index) } })) {
                            VStack(alignment: .leading, spacing: 2) {
                                HStack(spacing: 6) {
                                    Text(r.change == .adds ? "+" : "=").font(.system(.callout, design: .monospaced).weight(.bold)).foregroundStyle(p.amber)
                                    Text("\(r.entry.destination):\(r.entry.port)").font(.system(.callout, design: .monospaced))
                                    Text("\(r.entry.transport) · seen \(r.entry.occurrences)×").font(.caption).foregroundStyle(p.muted)
                                }
                                if r.entry.deniedOnly { Text("Only ever refused. Accepting it does not override a deny: denies keep precedence.").font(.caption).foregroundStyle(p.red) }
                            }
                        }
                        .toggleStyle(.checkbox)
                    }
                    Text("Repetition is shown as a count and never accepts anything.").font(.caption).foregroundStyle(p.muted)
                }
                Card {
                    HStack { SectionTitle(text: "Accept into a reviewed baseline"); Pill(text: "owner key", tone: .blue) }
                    Text("\(selected.count) of \(c.entries.count) selected. macOS asks for Touch ID or your password and shows this exact plan. The baseline is recorded unchanged and is not enforced by being recorded.").font(.callout).foregroundStyle(p.text2).fixedSize(horizontal: false, vertical: true)
                    if !c.complete {
                        Toggle("I reviewed the gaps above and accept a partial baseline.", isOn: $acknowledged).toggleStyle(.checkbox).font(.callout)
                    }
                    HStack {
                        MoatButton(title: "Accept \(selected.count) with Touch ID or password", systemImage: "touchid", kind: .primary, disabled: !problems.isEmpty) {
                            Task { await model.acceptCandidate(c, accepting: Array(selected), acknowledgeIncomplete: acknowledged) }
                        }
                        if c.kind == .capture { MoatButton(title: "More evidence needed", systemImage: "arrow.uturn.backward") { model.discardCandidate(c.id) } }
                    }
                    ForEach(problems, id: \.self) { pr in Text(pr).font(.caption).foregroundStyle(p.muted) }
                    if model.isDemo { Text(AppModel.demoApplyNote).font(.caption).foregroundStyle(p.muted) }
                }
            }
        } else {
            EmptyStateView(symbol: "checklist", title: "No candidate selected", text: "Choose a candidate from Learning.")
        }
    }
}

/// Workflow packs: what each module would add and whether it takes effect on this Mac.
struct PacksScreen: View {
    @ObservedObject var model: AppModel
    @Environment(\.palette) private var p

    var body: some View {
        let caps = model.status?.capabilities ?? []
        VStack(alignment: .leading, spacing: 18) {
            Button { model.screen = .rules } label: { Label("Rules", systemImage: "chevron.left") }.buttonStyle(.plain).foregroundStyle(p.accent)
            ScreenHeader(eyebrow: "Workflow packs", title: "Maintained modules.", dim: "What each module would allow, and whether it takes effect on this Mac. A pack's signature is not your consent.")
            if model.packs.isEmpty { EmptyStateView(symbol: "shippingbox", title: "No packs in this build", text: "The maintained packs ship with Moat; this build has none.") }
            ForEach(model.packs) { pack in
                let cells = pack.modules.map { PackCell.evaluate($0, capabilities: caps) }
                Card {
                    SectionTitle(text: pack.name, trailing: "\(pack.id)@\(pack.version)")
                    Text(pack.description).font(.callout).foregroundStyle(p.text2).fixedSize(horizontal: false, vertical: true)
                    HStack(spacing: 18) {
                        Text("\(pack.modules.count) modules").font(.callout.weight(.semibold))
                        Text("\(Set(pack.modules.flatMap(\.hosts)).count) destinations").font(.callout.weight(.semibold))
                        Text("\(cells.filter { !$0.takesEffect }.count) unsupported on this Mac").font(.callout.weight(.semibold)).foregroundStyle(cells.contains { !$0.takesEffect } ? p.red : p.text)
                    }
                    ForEach(Array(pack.modules.enumerated()), id: \.offset) { item in
                        let m = item.element
                        let cell = cells[item.offset]
                        VStack(alignment: .leading, spacing: 4) {
                            HStack(spacing: 6) {
                                Text(m.name).font(.callout.weight(.semibold))
                                if m.optional { Pill(text: "optional", tone: .neutral) }
                                Spacer()
                                Pill(text: cell.takesEffect ? "takes effect here" : (cell.support?.rawValue ?? "not reported"), tone: cell.takesEffect ? .green : (cell.support == .unsupported ? .red : .amber))
                            }
                            Text(m.rationale).font(.caption).foregroundStyle(p.text2).fixedSize(horizontal: false, vertical: true)
                            Text("Adds: \(m.hosts.joined(separator: ", "))").font(.system(.caption, design: .monospaced)).foregroundStyle(p.text)
                            if !cell.takesEffect {
                                Text("Skipped on this Mac with a report: \(cell.missing.map { "\($0.capability.replacingOccurrences(of: "_", with: " ")) \($0.support)" }.joined(separator: ", ")).").font(.caption).foregroundStyle(p.amber).fixedSize(horizontal: false, vertical: true)
                            }
                            Text("If omitted: \(m.expected_breakage_if_omitted)").font(.caption).foregroundStyle(p.muted)
                        }
                        .padding(.top, 6)
                    }
                    Text("Enabling modules is a broadening proposal your owner key must authorize, made from your controller. Which modules are already enabled is known to the controller, not this Mac.").font(.caption).foregroundStyle(p.muted)
                }
            }
        }
    }
}
