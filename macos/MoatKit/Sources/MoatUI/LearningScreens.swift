import MoatKit
import SwiftUI

// MARK: - W14: Learn (record an app, review what it reached, approved lists, new since approval) and rule packs.
// The same words as the web (brand/vocabulary.json glossary): recording, review, approved list, rule packs.

struct LearningScreen: View {
    @ObservedObject var model: AppModel
    @Environment(\.palette) private var p

    var body: some View {
        let drift = model.driftQueue()
        VStack(alignment: .leading, spacing: Space.s5) {
            Button { model.screen = .rules } label: { Label("Rules", systemImage: "chevron.left") }.buttonStyle(.plain).foregroundStyle(p.accent)
            ScreenHeader(eyebrow: "Learn", title: "Learn what an app needs", dim: "Record an app doing one job, then tick what it may reach. Nothing is allowed until you review it and approve it with your owner key.")
            CaptureControlCard(model: model)
            Card {
                SectionTitle(text: "Recordings", trailing: "\(model.learning.captures.count) open")
                if model.learning.captures.isEmpty { Text("Nothing recording right now.").font(.callout).foregroundStyle(p.text2) }
                ForEach(model.learning.captures) { c in
                    HStack(alignment: .center, spacing: Space.s3) {
                        VStack(alignment: .leading, spacing: Space.s1) {
                            HStack(spacing: Space.s2) {
                                Text(verbatim: c.workflow).font(.callout.weight(.semibold))
                                Pill(text: Date() < c.end ? "Recording" : "Time's up", tone: Date() < c.end ? .blue : .amber, dot: Date() < c.end)
                            }
                            Text(verbatim: "\(c.appName) · \(c.networkContext) · \(TimeText.windowEnd(c.end))").font(.caption).foregroundStyle(p.muted).lineLimit(1)
                            Text(verbatim: c.identityLabel).font(.system(.caption, design: .monospaced)).foregroundStyle(p.text2).lineLimit(1).truncationMode(.middle)
                        }
                        Spacer()
                        MoatButton(title: "Stop and review", systemImage: "checklist") { model.closeCapture(c.id) }
                    }
                }
            }
            Card {
                SectionTitle(text: "Ready to review", trailing: "\(model.learning.candidates.count) to review")
                if model.learning.candidates.isEmpty { Text("Nothing waiting. Stop a recording to review it.").font(.callout).foregroundStyle(p.text2) }
                ForEach(model.learning.candidates) { c in CandidateRowView(model: model, candidate: c) }
            }
            Card {
                SectionTitle(text: "New since approval", trailing: "\(drift.count) in queue")
                Text("New activity never changes an approved list. It comes here as a new review, with other versions of the app listed.").font(.caption).foregroundStyle(p.muted)
                if drift.isEmpty { Text("Nothing new.").font(.callout).foregroundStyle(p.text2) }
                ForEach(drift) { c in CandidateRowView(model: model, candidate: c) }
            }
            Card {
                SectionTitle(text: "Approved lists", trailing: "never edited")
                if model.learning.baselines.isEmpty { Text("Nothing approved yet.").font(.callout).foregroundStyle(p.text2) }
                ForEach(model.learning.baselines) { b in
                    HStack(alignment: .top, spacing: Space.s3) {
                        VStack(alignment: .leading, spacing: Space.s1) {
                            HStack(spacing: Space.s2) {
                                Text(verbatim: b.scope.appName).font(.callout.weight(.semibold))
                                if model.learning.retired[b.id] != nil { Pill(text: "Retired", tone: .neutral) } else if model.learning.active.contains(where: { $0.id == b.id }) { Pill(text: "\(b.entries.count) places", tone: .blue) } else { Pill(text: "Replaced", tone: .neutral) }
                            }
                            Text(verbatim: "\(b.scope.workflow) · approved \(TimeText.ago(b.approvedAt)) · key \(b.authorizedBy)").font(.caption).foregroundStyle(p.muted).lineLimit(1)
                            Text(verbatim: b.entries.map { "\($0.destination):\($0.port)" }.joined(separator: "  ·  ")).font(.system(.caption, design: .monospaced)).foregroundStyle(p.text2).lineLimit(2)
                        }
                        Spacer()
                        if model.learning.retired[b.id] == nil { MoatButton(title: "Retire", systemImage: "archivebox") { model.retire(b) } }
                    }
                }
                Text("Turning an approved list on from this Mac alone isn't available yet: do it from your controller, where it needs your owner key because it allows more. Your blocks still win.").font(.caption).foregroundStyle(p.muted)
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
            HStack(spacing: Space.s3) {
                VStack(alignment: .leading, spacing: Space.s1) {
                    HStack(spacing: Space.s2) {
                        Text(verbatim: candidate.scope.appName).font(.callout.weight(.semibold))
                        Pill(text: candidate.complete ? "Complete" : "Incomplete", tone: candidate.complete ? .green : .amber)
                        if candidate.kind == .drift { Pill(text: "New since approval", tone: .violet) }
                    }
                    Text(verbatim: "\(adds) would allow more · \(candidate.entries.count) places\(candidate.identityChanges.isEmpty ? "" : " · \(candidate.identityChanges.count) other version") · \(candidate.scope.workflow)").font(.caption).foregroundStyle(p.text2).lineLimit(1)
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
            HStack { SectionTitle(text: "Record an app"); Pill(text: "Time-limited", tone: .blue, symbol: "clock") }
            Text("Moat watches one app do one job, so you can review what it reached. Your current rules, including every block, stay on while it records.").font(.callout).foregroundStyle(p.text2).fixedSize(horizontal: false, vertical: true)
            Picker("App", selection: $appID) {
                Text("Choose an app").tag("")
                ForEach(apps) { a in Text(verbatim: Self.pickerLabel(a)).tag(a.id) }
            }
            TextField("What it's doing (e.g. npm install)", text: $workflow).textFieldStyle(.roundedBorder)
            TextField("Network (e.g. home Wi-Fi)", text: $network).textFieldStyle(.roundedBorder)
            Stepper("For \(hours) hour\(hours == 1 ? "" : "s") (at most \(Int(Learning.maxCaptureHours)))", value: $hours, in: 1 ... Int(Learning.maxCaptureHours))
            HStack {
                MoatButton(title: "Start recording", systemImage: "record.circle", kind: .primary, disabled: appID.isEmpty || workflow.trimmingCharacters(in: .whitespaces).isEmpty) {
                    if let a = apps.first(where: { $0.id == appID }) { model.startCapture(app: a, workflow: workflow, networkContext: network, hours: Double(hours)) }
                }
                Text("Moat records the app by its signature, never by its name alone.").font(.caption).foregroundStyle(p.muted)
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
            VStack(alignment: .leading, spacing: Space.s5) {
                Button { model.screen = .learning } label: { Label("Learn", systemImage: "chevron.left") }.buttonStyle(.plain).foregroundStyle(p.accent)
                ScreenHeader(eyebrow: c.kind == .drift ? "New since approval" : "From a recording · \(c.scope.workflow)", title: c.scope.appName)
                Card {
                    HStack { SectionTitle(text: "What was recorded"); Pill(text: c.complete ? "Complete" : "Incomplete", tone: c.complete ? .green : .amber) }
                    if c.incompleteReasons.isEmpty {
                        Text("Nothing missing: no lost reports, and every connection came from a known app.").font(.callout).foregroundStyle(p.green)
                    }
                    ForEach(c.incompleteReasons, id: \.self) { r in
                        HStack(alignment: .top, spacing: Space.s2) {
                            Pill(text: r.contains("no app identity") ? "Unknown app" : "Gap", tone: r.contains("no app identity") ? .red : .amber)
                            Text(verbatim: r).font(.callout).fixedSize(horizontal: false, vertical: true)
                        }
                    }
                    ForEach(c.identityChanges, id: \.self) { x in
                        HStack(alignment: .top, spacing: Space.s2) {
                            Pill(text: "Separate app", tone: .amber)
                            Text(verbatim: "Same name, different signature: \(x). Nothing carries over.").font(.callout).fixedSize(horizontal: false, vertical: true)
                        }
                    }
                    Text("Seeing something during a recording, or seeing it often, never makes it trusted.").font(.caption).foregroundStyle(p.muted)
                }
                Card {
                    SectionTitle(text: "What it tried to reach", trailing: "\(rows.filter { $0.change == .adds }.count) would allow more")
                    Text(c.kind == .drift ? "Compared with this app's current approved list." : "This app has no approved list yet: every place you tick is new.").font(.caption).foregroundStyle(p.muted)
                    ForEach(rows) { r in
                        Toggle(isOn: Binding(get: { selected.contains(r.index) }, set: { on in if on { selected.insert(r.index) } else { selected.remove(r.index) } })) {
                            VStack(alignment: .leading, spacing: Space.s1) {
                                HStack(spacing: Space.s2) {
                                    Text(verbatim: r.change == .adds ? "+" : "=").font(.system(.callout, design: .monospaced).weight(.bold)).foregroundStyle(p.amber)
                                    Text(verbatim: "\(r.entry.destination):\(r.entry.port)").font(.system(.callout, design: .monospaced))
                                    Text(verbatim: "seen \(r.entry.occurrences) times").font(.caption).foregroundStyle(p.muted)
                                }
                                if r.entry.deniedOnly { Text("Only ever blocked. Ticking it doesn't override a block: blocks always win.").font(.caption).foregroundStyle(p.red) }
                            }
                        }
                        .toggleStyle(.checkbox)
                    }
                    Text("Seeing something many times never allows it.").font(.caption).foregroundStyle(p.muted)
                }
                Card {
                    HStack { SectionTitle(text: "Accept what you ticked"); Pill(text: "Owner key", tone: .blue, symbol: "key.fill") }
                    Text("\(selected.count) of \(c.entries.count) ticked. macOS asks for Touch ID or your password and shows exactly this. The approved list is saved as is and doesn't take effect just by being saved.").font(.callout).foregroundStyle(p.text2).fixedSize(horizontal: false, vertical: true)
                    if !c.complete {
                        Toggle("I reviewed the gaps above and accept a partial list.", isOn: $acknowledged).toggleStyle(.checkbox).font(.callout)
                    }
                    HStack {
                        MoatButton(title: "Accept \(selected.count) with Touch ID or password", systemImage: "touchid", kind: .primary, disabled: !problems.isEmpty) {
                            Task { await model.acceptCandidate(c, accepting: Array(selected), acknowledgeIncomplete: acknowledged) }
                        }
                        if c.kind == .capture { MoatButton(title: "Record more first", systemImage: "arrow.uturn.backward") { model.discardCandidate(c.id) } }
                    }
                    ForEach(problems, id: \.self) { pr in Text(verbatim: pr).font(.caption).foregroundStyle(p.muted) }
                    if model.isDemo { Text(verbatim: AppModel.demoApplyNote).font(.caption).foregroundStyle(p.muted) }
                }
            }
        } else {
            EmptyStateView(symbol: "checklist", title: "Nothing to review", text: "Choose a review from Learn.")
        }
    }
}

/// Rule packs: what each part would add and whether it applies on this Mac.
struct PacksScreen: View {
    @ObservedObject var model: AppModel
    @Environment(\.palette) private var p

    var body: some View {
        let caps = model.status?.capabilities ?? []
        VStack(alignment: .leading, spacing: Space.s5) {
            Button { model.screen = .rules } label: { Label("Rules", systemImage: "chevron.left") }.buttonStyle(.plain).foregroundStyle(p.accent)
            ScreenHeader(eyebrow: "Rule packs", title: "Ready-made rules", dim: "What each part would allow, and whether it applies on this Mac. Nothing is on until you choose.")
            if model.packs.isEmpty { EmptyStateView(symbol: "shippingbox", title: "No rule packs in this build", text: "Rule packs ship with Moat; this build has none.") }
            ForEach(model.packs) { pack in
                let cells = pack.modules.map { PackCell.evaluate($0, capabilities: caps) }
                Card {
                    SectionTitle(text: pack.name)
                    Text(verbatim: pack.description).font(.callout).foregroundStyle(p.text2).fixedSize(horizontal: false, vertical: true)
                    HStack(spacing: Space.s5) {
                        Text("\(pack.modules.count) parts").font(.callout.weight(.semibold))
                        Text("\(Set(pack.modules.flatMap(\.hosts)).count) places").font(.callout.weight(.semibold))
                        Text("\(cells.filter { !$0.takesEffect }.count) won't apply on this Mac").font(.callout.weight(.semibold)).foregroundStyle(cells.contains { !$0.takesEffect } ? p.red : p.text)
                    }
                    ForEach(Array(pack.modules.enumerated()), id: \.offset) { item in
                        let m = item.element
                        let cell = cells[item.offset]
                        VStack(alignment: .leading, spacing: Space.s1) {
                            HStack(spacing: Space.s2) {
                                Text(verbatim: m.name).font(.callout.weight(.semibold))
                                if m.optional { Pill(text: "Optional", tone: .neutral) }
                                Spacer()
                                Pill(text: cell.takesEffect ? "Applies here" : (cell.support?.label ?? "Not reported"), tone: cell.takesEffect ? .green : (cell.support == .unsupported ? .red : .amber))
                            }
                            Text(verbatim: m.rationale).font(.caption).foregroundStyle(p.text2).fixedSize(horizontal: false, vertical: true)
                            Text(verbatim: "Adds: \(m.hosts.joined(separator: ", "))").font(.system(.caption, design: .monospaced)).foregroundStyle(p.text)
                            if !cell.takesEffect {
                                Text(verbatim: "Won't apply on this Mac (skipped with a report): \(cell.missing.map { "\($0.capability.replacingOccurrences(of: "_", with: " ")) \($0.support)" }.joined(separator: ", ")).").font(.caption).foregroundStyle(p.amber).fixedSize(horizontal: false, vertical: true)
                            }
                            Text(verbatim: "If left off: \(m.expected_breakage_if_omitted)").font(.caption).foregroundStyle(p.muted)
                        }
                        .padding(.top, Space.s2)
                    }
                    Text("Turning parts on allows more, so it needs your owner key and is done from your controller. Your controller, not this Mac, knows which parts are already on.").font(.caption).foregroundStyle(p.muted)
                }
            }
        }
    }
}
