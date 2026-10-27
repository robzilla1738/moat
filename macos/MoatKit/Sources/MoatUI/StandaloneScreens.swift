import MoatKit
import SwiftUI

// MARK: - W12: Apps (the landing view), app detail, tasks, diagnostics, "What changed?"

/// The protection summary at the head of Apps: what this Mac's status means, which rules it uses and how fresh that
/// is. A problem is a banner, never a quiet line.
struct ProtectionCard: View {
    @ObservedObject var model: AppModel
    @Environment(\.palette) private var p

    var body: some View {
        if let s = model.status {
            let tone = s.coverage.tone.color(p)
            Card {
                HStack(alignment: .top, spacing: Space.s3) {
                    ZStack {
                        RoundedRectangle(cornerRadius: Radius.inner, style: .continuous).fill(tone.opacity(0.14)).frame(width: Space.s10, height: Space.s10)
                        Image(systemName: s.coverage.symbol).font(.title3.weight(.semibold)).foregroundStyle(tone)
                    }
                    .accessibilityHidden(true)
                    VStack(alignment: .leading, spacing: Space.s1) {
                        HStack(spacing: Space.s2) {
                            Text(verbatim: s.coverage.label).font(.headline).foregroundStyle(p.text)
                            if model.isStale { Pill(text: "Not current", tone: .amber) }
                        }
                        Text(verbatim: s.coverage.claim).font(.callout).foregroundStyle(p.text2).fixedSize(horizontal: false, vertical: true)
                        Text(verbatim: "\(s.installed.map { "Rules: \($0.policyName)" } ?? "No signed rules yet") · \(model.isStale ? "not checked recently" : "checked just now")")
                            .font(.caption).foregroundStyle(model.isStale ? p.amber : p.muted)
                    }
                    Spacer(minLength: 0)
                }
            }
            if s.isolation.active {
                NoticeBanner(title: "Emergency lockdown is on.", text: "New connections from this Mac are blocked until you turn it off in Coverage & recovery.", tone: .red)
            } else if s.coverage.needsOwnerAtDevice {
                NoticeBanner(title: "\(s.coverage.label).", text: s.coverage.claim, tone: .red)
            }
        }
    }
}

/// Apps: "Does anything need me, and what are my apps doing?" No counters or charts here.
struct AppsScreen: View {
    @ObservedObject var model: AppModel
    @Environment(\.palette) private var p
    var heroShown = false

    var body: some View {
        VStack(alignment: .leading, spacing: Space.s5) {
            ScreenHeader(eyebrow: "This computer", title: model.status.map { OverviewHero.headline($0) } ?? "Waiting for the filter", dim: "Apps on this Mac, recognised by their signature, never by their name alone.")
            ProtectionCard(model: model)
            FirstTenMinutesCard(model: model)
            let apps = model.apps
            if apps.isEmpty {
                EmptyStateView(symbol: "square.grid.2x2", title: "No apps yet", text: "Apps appear the moment one connects to the internet. Nothing is listed before then.")
            } else {
                HStack {
                    SectionTitle(text: "Apps", trailing: "\(apps.count)")
                    MoatButton(title: "Something stopped working?", systemImage: "arrow.left.arrow.right") { model.screen = .whatChanged }
                }
                LazyVGrid(columns: [GridItem(.adaptive(minimum: 300), spacing: Space.s4)], spacing: Space.s4) {
                    ForEach(apps) { a in
                        Button { model.open(app: a.id) } label: { AppTile(app: a) }.buttonStyle(.plain)
                    }
                }
            }
        }
    }
}

extension AppSummary {
    /// What this app is, in one plain line (the raw identifiers are under Technical details).
    var identityLine: String {
        if !identityKnown { return "Unknown app: macOS didn't report which program" }
        if let t = teamID { return "Signed by team \(t)" }
        return "Not signed: Moat knows it by its file"
    }
}

struct AppTile: View {
    @Environment(\.palette) private var p
    let app: AppSummary

    var body: some View {
        Card(padding: Space.s4) {
            HStack(spacing: Space.s3) {
                Image(systemName: app.identityKnown ? "app.badge" : "questionmark.app.dashed").font(.title2).foregroundStyle(app.identityKnown ? p.accent : p.amber)
                    .accessibilityHidden(true)
                VStack(alignment: .leading, spacing: Space.s1) {
                    Text(verbatim: app.name).font(.body.weight(.semibold)).lineLimit(1)
                    Text(verbatim: app.identityLine).font(.caption).foregroundStyle(p.muted).lineLimit(1)
                }
                Spacer()
                if app.blocked > 0 { Pill(text: "\(app.blocked) blocked", tone: .red) } else if app.observed == app.flows { Pill(text: "Watched only", tone: .blue) } else { Pill(text: "\(app.flows) connections", tone: .neutral) }
            }
            Text(verbatim: app.destinations.prefix(2).map { "\($0.host):\($0.port)" }.joined(separator: "  ·  ")).font(.system(.caption, design: .monospaced)).foregroundStyle(p.text2).lineLimit(1)
            Text("Active \(TimeText.ago(app.lastSeen))").font(.caption).foregroundStyle(p.muted)
        }
        .accessibilityElement(children: .combine)
    }
}

/// App detail: "What may this app do, and why?"
struct AppDetailScreen: View {
    @ObservedObject var model: AppModel
    @Environment(\.palette) private var p

    var body: some View {
        if let a = model.selectedApp {
            VStack(alignment: .leading, spacing: Space.s5) {
                Button { model.screen = .apps } label: { Label("Apps", systemImage: "chevron.left") }.buttonStyle(.plain).foregroundStyle(p.accent)
                ScreenHeader(eyebrow: a.identityLine, title: a.name)
                Card {
                    SectionTitle(text: "What it's allowed to do")
                    if a.ruleIDs.isEmpty {
                        Text(model.status?.installed == nil ? "No signed rules yet: everything is watched, nothing is blocked." : "No rule names this app, so this Mac's default applied (see below).").font(.callout).foregroundStyle(p.text2)
                    }
                    ForEach(a.ruleIDs, id: \.self) { r in
                        ListRowView(symbol: "list.bullet", tone: .accent, title: r, mono: true)
                    }
                    let omitted = model.status?.installed?.omitted ?? []
                    if !omitted.isEmpty {
                        NoticeBanner(title: "Some rules don't apply on this Mac.", text: omitted.map(\.ruleID).joined(separator: ", "))
                    }
                    let siblings = model.apps.filter { $0.id != a.id && $0.signingID != nil && $0.signingID == a.signingID }
                    ForEach(siblings) { s in
                        NoticeBanner(title: "Another version of this app", text: "Same signing name, different signer (team \(s.teamID ?? "none")). It's treated as a separate app; no permissions carry over.")
                    }
                    TechnicalDetails {
                        Text(verbatim: "File: \(a.executable ?? "not reported")")
                        Text(verbatim: "Signing identifier: \(a.signingID ?? "not reported")")
                        Text(verbatim: a.revisions.count > 1 ? "Decided under rule versions \(a.revisions.sorted().map { String($0) }.joined(separator: ", "))" : "No rule change while this app was active")
                        Text(verbatim: "Rules listed are the ones the filter recorded for this app; the full rule list isn't available here.")
                    }
                }
                Card {
                    SectionTitle(text: "Recent activity", trailing: "\(a.flows) connections · \(a.blocked) blocked")
                    ForEach(model.flows.filter { AppSummary.identity(of: $0.facts).id == a.id }.prefix(8)) { r in FlowRow(record: r, compact: true) }
                }
                Card {
                    SectionTitle(text: "Why it was allowed or blocked")
                    ForEach(Array(AppExplanation.latest(for: a, in: model.flows).enumerated()), id: \.offset) { item in
                        let w = item.element
                        VStack(alignment: .leading, spacing: Space.s1) {
                            Text(verbatim: w.destination).font(.system(.callout, design: .monospaced))
                            Text(verbatim: "\(w.verdict): \(w.summary)").font(.callout).foregroundStyle(p.text2)
                            ForEach(w.notes, id: \.self) { n in Text(verbatim: n).font(.caption).foregroundStyle(p.muted) }
                        }
                    }
                    Text("Each line is what the filter decided at the time, not a new check by this window.").font(.caption).foregroundStyle(p.muted)
                }
                RuleAuthoringCard(model: model, app: a)
            }
        } else {
            EmptyStateView(symbol: "app.dashed", title: "No app selected", text: "Choose an app from Apps.")
        }
    }
}

/// A temporary rule for one app: narrow, expiring, approved with the owner key behind Touch ID or the password.
struct RuleAuthoringCard: View {
    @ObservedObject var model: AppModel
    let app: AppSummary
    @Environment(\.palette) private var p
    @State private var host = ""
    @State private var minutes = 15
    @State private var action: LocalRulePlan.Action = .deny

    var body: some View {
        Card {
            SectionTitle(text: "Make a temporary rule")
            let dest = host.isEmpty ? (app.destinations.first?.host ?? "") : host
            let port = app.destinations.first { $0.host == dest }?.port ?? 443
            let plan = LocalRulePlan(action: action, app: app, host: dest, port: port, expires: Date().addingTimeInterval(TimeInterval(minutes * 60)))
            Picker("Action", selection: $action) {
                Text("Block").tag(LocalRulePlan.Action.deny)
                Text("Allow").tag(LocalRulePlan.Action.allow)
            }
            .pickerStyle(.segmented)
            Picker("Address", selection: $host) {
                ForEach(app.destinations.prefix(10), id: \.host) { d in Text(verbatim: "\(d.host):\(d.port)").tag(d.host) }
            }
            // The picker shows the address the plan uses (the most frequent one until the owner picks another).
            .onAppear { if host.isEmpty { host = app.destinations.first?.host ?? "" } }
            Stepper("For \(minutes) minutes", value: $minutes, in: 5 ... 480, step: 5)
            Text(verbatim: plan.ownerPlan(id: "preview").display).font(.system(.callout, design: .monospaced))
            ForEach(plan.problems(), id: \.self) { pr in Text(verbatim: pr).font(.caption).foregroundStyle(p.red) }
            HStack {
                MoatButton(title: model.canApplyStandalone ? "Approve and apply with Touch ID or password" : "Approve with Touch ID or password", systemImage: "touchid", kind: .primary, disabled: !plan.problems().isEmpty || (model.ownerSigner == nil && model.applier == nil)) {
                    model.trialDenyHost = action == .deny ? dest : model.trialDenyHost
                    Task { await model.authorize(plan) }
                }
                if let a = model.lastAuthorization { Pill(text: "Signed by key \(a.keyID)", tone: .green) }
                if let r = model.lastApplied { Pill(text: "In use as version \(r.summary.revision)", tone: .green) }
            }
            Text(verbatim: "macOS asks for your fingerprint or password and shows this exact rule. A typed phrase is never accepted instead. \(model.canApplyStandalone ? AppModel.standaloneApplyHow : model.applyUnavailableReason)").font(.caption).foregroundStyle(p.muted)
        }
    }
}

/// Tasks on macOS: the honest answer is that they are not protected here yet.
struct TasksScreen: View {
    @ObservedObject var model: AppModel
    @Environment(\.palette) private var p

    var body: some View {
        VStack(alignment: .leading, spacing: Space.s5) {
            ScreenHeader(eyebrow: "Tasks", title: "Tasks aren't protected on this Mac yet", dim: "Moat has no tested task boundary on macOS, so a task started here isn't kept inside one. Rules for tasks are left out of this Mac's rules and reported.")
            Card {
                SectionTitle(text: "Where tasks work")
                Text("Linux computers start protected tasks with moat-launch. They appear in your controller's Tasks view, with whether each boundary was confirmed.").font(.callout).foregroundStyle(p.text2)
                let omitted = model.status?.installed?.omitted ?? []
                if !omitted.isEmpty {
                    NoticeBanner(title: "Left out on this Mac", text: omitted.map(\.ruleID).joined(separator: ", "))
                }
            }
        }
    }
}

/// "This computer": what each part of Moat reports, for troubleshooting (the technical page).
struct ThisComputerScreen: View {
    @ObservedObject var model: AppModel
    @Environment(\.palette) private var p

    var body: some View {
        let d = DiagnosticsReport.from(status: model.status, lastContact: model.lastContact, contactLostSince: model.contactLostSince)
        VStack(alignment: .leading, spacing: Space.s5) {
            ScreenHeader(eyebrow: "Diagnostics", title: model.deviceCount <= 1 ? "This computer" : "Devices", dim: "Exactly what the filter reports, for troubleshooting.")
            Card {
                ForEach(d.items) { i in
                    HStack(alignment: .top) {
                        Text(verbatim: i.label).font(.callout).foregroundStyle(p.muted).frame(width: 220, alignment: .leading)
                        Text(verbatim: i.value).font(.system(.callout, design: .monospaced)).foregroundStyle(i.warn ? p.amber : p.text).fixedSize(horizontal: false, vertical: true)
                        Spacer()
                    }
                }
            }
            if !d.downgraded.isEmpty {
                Card {
                    SectionTitle(text: "Not available or not proven here")
                    ForEach(d.downgraded) { c in
                        ListRowView(title: c.label, sub: c.note) { Pill(text: c.support.label, tone: c.support == .unsupported ? .red : .amber) }
                    }
                }
            }
        }
    }
}

/// "Something stopped working: what's different?"
struct WhatChangedScreen: View {
    @ObservedObject var model: AppModel
    @Environment(\.palette) private var p
    @State private var workingHoursAgo = 24.0
    @State private var failingHoursAgo = 1.0

    var body: some View {
        let now = Date()
        let working = DateInterval(start: now.addingTimeInterval(-(workingHoursAgo + 2) * 3600), end: now.addingTimeInterval(-workingHoursAgo * 3600))
        let failing = DateInterval(start: now.addingTimeInterval(-failingHoursAgo * 3600), end: now)
        let c = ChangeComparison.compare(model.flows, working: working, failing: failing, appID: model.selectedAppID, gaps: model.status?.telemetryGaps ?? [])
        VStack(alignment: .leading, spacing: Space.s5) {
            ScreenHeader(eyebrow: model.selectedApp?.name ?? "All apps", title: "What changed?", dim: "Something stopped working? Compare a time it worked with a time it didn't. Real differences come first, then possible causes you can test.")
            Card {
                Stepper("Worked: 2 hours ending \(Int(workingHoursAgo)) h ago", value: $workingHoursAgo, in: 2 ... 168, step: 1)
                Stepper("Failed: the last \(Int(failingHoursAgo)) h", value: $failingHoursAgo, in: 1 ... 24, step: 1)
            }
            Card {
                SectionTitle(text: "What's different")
                if c.observed.isEmpty { Text("Nothing differs in what Moat recorded.").font(.callout).foregroundStyle(p.text2) }
                ForEach(Array(c.observed.enumerated()), id: \.offset) { item in
                    ListRowView(title: item.element.title, sub: "Worked: \(item.element.working.ifBlank("—")) · Failed: \(item.element.failing)")
                }
            }
            Card {
                SectionTitle(text: "Possible causes")
                ForEach(Array(c.candidates.enumerated()), id: \.offset) { item in
                    VStack(alignment: .leading, spacing: Space.s1) {
                        HStack { Pill(text: "Possible", tone: .amber); Text(verbatim: item.element.title).font(.callout.weight(.semibold)) }
                        Text(verbatim: item.element.why).font(.caption).foregroundStyle(p.text2)
                        Text(verbatim: "Try: \(item.element.test)").font(.caption).foregroundStyle(p.accent)
                    }
                }
                Text(verbatim: ChangeComparison.disclaimer).font(.caption).foregroundStyle(p.muted)
                TechnicalDetails(title: "Not compared") {
                    Text(verbatim: c.notCompared.joined(separator: "; "))
                }
            }
        }
    }
}

extension String {
    func ifBlank(_ s: String) -> String { isEmpty ? s : self }
}

/// Coverage & recovery: what this Mac can really do, then the controls that work without the controller.
struct CoverageRecoveryScreen: View {
    @ObservedObject var model: AppModel

    var body: some View {
        VStack(alignment: .leading, spacing: Space.s8) {
            if let s = model.status, s.coverage.needsOwnerAtDevice { NeedsOwnerCard(status: s) }
            CoverageScreen(model: model)
            RecoveryScreen(model: model)
            if !model.fleetEvents.isEmpty { FleetEventsCard(events: model.fleetEvents) }
        }
        .onAppear { model.sawRecoveryCard = true }
    }
}

/// The first ten minutes (§9.2), checked off only on evidence.
struct FirstTenMinutesCard: View {
    @ObservedObject var model: AppModel
    @Environment(\.palette) private var p

    var body: some View {
        let progress = model.firstTen
        if progress.next != nil {
            Card {
                SectionTitle(text: "Getting started", trailing: "\(progress.done.count) of \(FirstTenMinutes.Step.allCases.count - 1)")
                ForEach(FirstTenMinutes.Step.allCases.filter { $0 != .fleet }, id: \.self) { s in
                    HStack(spacing: Space.s2) {
                        Image(systemName: progress.done.contains(s) ? "checkmark.circle.fill" : (progress.next == s ? "circle.dotted" : "circle"))
                            .foregroundStyle(progress.done.contains(s) ? p.green : (progress.next == s ? p.accent : p.muted))
                            .accessibilityHidden(true)
                        Text(verbatim: s.title).font(.callout).foregroundStyle(progress.done.contains(s) ? p.text2 : p.text)
                    }
                }
                if progress.next == .choose {
                    HStack {
                        MoatButton(title: "Just watch for now", systemImage: "eye") { model.choseMode = true }
                        MoatButton(title: "Protect chosen apps", systemImage: "shield") { model.choseMode = true; model.screen = .rules }
                    }
                }
                Text("Steps are ticked only from what the filter reports and what you do, never because a screen was opened.").font(.caption).foregroundStyle(p.muted)
            }
        } else if progress.offerFleet {
            Card {
                SectionTitle(text: "This Mac is set up")
                Text("When you're ready, connect your other devices to a private controller. This Mac keeps its rules, history and recovery even when the controller is offline.").font(.callout).foregroundStyle(p.text2)
            }
        }
    }
}

/// recovery-required / rollback-pending on this Mac: say exactly what is in force and what the owner must do here.
struct NeedsOwnerCard: View {
    let status: StatusReport
    @Environment(\.palette) private var p

    var body: some View {
        VStack(alignment: .leading, spacing: Space.s2) {
            NoticeBanner(title: "\(status.coverage.label).", text: status.coverage.claim, tone: .red)
            if let r = status.installed {
                Text(verbatim: "In force now: rules version \(r.revision) (\(r.policyName)). Use Recovery below; nothing is reinstalled on its own, and no remote command clears this.")
                    .font(.callout).foregroundStyle(p.text2).fixedSize(horizontal: false, vertical: true)
            }
            TechnicalDetails {
                ForEach(status.coverageNotes.prefix(3), id: \.self) { n in Text(verbatim: n) }
            }
        }
    }
}

/// Lifecycle events reported by other enrolled devices (Linux), shown as the device reported them.
struct FleetEventsCard: View {
    let events: [EndpointLifecycleEvent]
    @Environment(\.palette) private var p

    var body: some View {
        Card {
            SectionTitle(text: "Other devices", trailing: "\(events.count)")
            ForEach(events.prefix(12)) { e in
                VStack(alignment: .leading, spacing: Space.s1) {
                    HStack(spacing: Space.s2) {
                        Pill(text: e.deviceID, tone: e.needsOwnerAtDevice ? .red : .neutral)
                        Text(verbatim: e.title).font(.callout.weight(.semibold)).foregroundStyle(p.text)
                    }
                    Text(verbatim: e.meaning).font(.caption).foregroundStyle(p.text2)
                    if !e.detail.isEmpty { Text(verbatim: e.detail).font(.system(.caption, design: .monospaced)).foregroundStyle(p.muted).lineLimit(2) }
                }
            }
            Text("Reported by each device; this Mac doesn't check another device's state.").font(.caption).foregroundStyle(p.muted)
        }
    }
}

/// The temporary-rule card on its own (Apps → app → "Make a temporary rule"), for the docs screenshot of the rule the
/// owner approves. It shows the first app with a reported identity, exactly as the app detail does.
public struct LocalRuleSheet: View {
    @ObservedObject var model: AppModel
    @Environment(\.colorScheme) private var scheme

    public init(model: AppModel) {
        self.model = model
    }

    public var body: some View {
        let p = Palette.of(scheme)
        VStack(alignment: .leading, spacing: Space.s4) {
            if let app = model.apps.first(where: { $0.identityKnown }) {
                ScreenHeader(eyebrow: app.identityLine, title: app.name)
                RuleAuthoringCard(model: model, app: app)
            } else {
                EmptyStateView(symbol: "app.dashed", title: "No app macOS recognised", text: "Rules are made for an app macOS recognised by its signature, never by its name alone.")
            }
        }
        .padding(Space.s6)
        .frame(width: 620, alignment: .topLeading)
        .background(p.bg)
        .environment(\.palette, p)
        .tint(p.accentStrong)
    }
}
