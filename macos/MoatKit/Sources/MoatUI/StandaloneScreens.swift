import MoatKit
import SwiftUI

// MARK: - W12: Apps-first standalone screens (same Card / Pill / glass language as the rest of the app)

/// One line: what is enforced, which policy is active, how fresh the evidence is.
struct StatusLine: View {
    @ObservedObject var model: AppModel
    @Environment(\.palette) private var p

    var body: some View {
        if let s = model.status {
            HStack(spacing: 8) {
                Circle().fill(s.coverage.tone.color(p)).frame(width: 8, height: 8).accessibilityHidden(true)
                Text(s.coverage.label).font(.callout.weight(.semibold))
                Text("·").foregroundStyle(p.muted)
                Text(s.installed.map { "Policy r\($0.revision) \($0.policyName)" } ?? "No signed policy (observing)").font(.callout).foregroundStyle(p.text2)
                Text("·").foregroundStyle(p.muted)
                Text(model.isStale ? "Evidence not current" : "Evidence just now").font(.callout).foregroundStyle(model.isStale ? p.amber : p.text2)
                Spacer()
            }
            .padding(.horizontal, 14)
            .padding(.vertical, 9)
            .moatGlass(in: Capsule())
            .accessibilityElement(children: .combine)
        }
    }
}

struct AppsScreen: View {
    @ObservedObject var model: AppModel
    @Environment(\.palette) private var p
    var heroShown = false

    var body: some View {
        VStack(alignment: .leading, spacing: 18) {
            if !heroShown {
                ScreenHeader(eyebrow: "This computer", title: model.status.map { OverviewHero.headline($0) } ?? "Waiting for the filter", dim: "Apps by the identity macOS reports. A name alone is never identity.")
            }
            StatusLine(model: model)
            FirstTenMinutesCard(model: model)
            let apps = model.apps
            if apps.isEmpty {
                EmptyStateView(symbol: "square.grid.2x2", title: "No app activity yet", text: "Apps appear the moment the filter reports a connection. Nothing is listed before there is evidence.")
            } else {
                HStack {
                    SectionTitle(text: "Apps", trailing: "\(apps.count) identities")
                    MoatButton(title: "What changed?", systemImage: "arrow.left.arrow.right") { model.screen = .whatChanged }
                }
                LazyVGrid(columns: [GridItem(.adaptive(minimum: 300), spacing: 14)], spacing: 14) {
                    ForEach(apps) { a in
                        Button { model.open(app: a.id) } label: { AppTile(app: a) }.buttonStyle(.plain)
                    }
                }
            }
        }
    }
}

struct AppTile: View {
    @Environment(\.palette) private var p
    let app: AppSummary

    var body: some View {
        Card(padding: 14) {
            HStack(spacing: 10) {
                Image(systemName: app.identityKnown ? "app.badge" : "questionmark.app.dashed").font(.title2).foregroundStyle(app.identityKnown ? p.accent : p.amber)
                VStack(alignment: .leading, spacing: 2) {
                    Text(app.name).font(.body.weight(.semibold)).lineLimit(1)
                    Text(app.teamID.map { "Team \($0)" } ?? (app.identityKnown ? "no team ID (unsigned or ad-hoc)" : "identity not reported")).font(.caption).foregroundStyle(p.muted).lineLimit(1)
                }
                Spacer()
                if app.blocked > 0 { Pill(text: "\(app.blocked) blocked", tone: .red) } else if app.observed == app.flows { Pill(text: "observed", tone: .blue) } else { Pill(text: "\(app.flows) seen", tone: .neutral) }
            }
            Text(app.destinations.prefix(3).map { "\($0.host):\($0.port)" }.joined(separator: "  ·  ")).font(.system(.caption, design: .monospaced)).foregroundStyle(p.text2).lineLimit(1)
            Text("Active \(TimeText.ago(app.lastSeen))").font(.caption).foregroundStyle(p.muted)
        }
        .accessibilityElement(children: .combine)
    }
}

struct AppDetailScreen: View {
    @ObservedObject var model: AppModel
    @Environment(\.palette) private var p
    @State private var planHost = ""
    @State private var minutes = 15.0

    var body: some View {
        if let a = model.selectedApp {
            VStack(alignment: .leading, spacing: 18) {
                Button { model.screen = .apps } label: { Label("Apps", systemImage: "chevron.left") }.buttonStyle(.plain).foregroundStyle(p.accent)
                ScreenHeader(eyebrow: a.identityKnown ? (a.teamID.map { "Team \($0)" } ?? "Unsigned or ad-hoc") : "Identity unknown", title: a.name, dim: a.executable ?? a.signingID ?? "macOS reported neither a signing identifier nor an executable")
                Card {
                    SectionTitle(text: "Current permissions", trailing: model.status?.installed.map { "r\($0.revision)" } ?? "no policy")
                    if a.ruleIDs.isEmpty {
                        Text(model.status?.installed == nil ? "No signed policy is installed: everything is observed, nothing enforced." : "No rule matched this app's recorded connections; its profile default applied (see Why).").font(.callout).foregroundStyle(p.text2)
                    }
                    ForEach(a.ruleIDs, id: \.self) { r in
                        HStack { Pill(text: "rule", tone: .accent); Text(r).font(.system(.callout, design: .monospaced)) }
                    }
                    let omitted = model.status?.installed?.omitted ?? []
                    if !omitted.isEmpty {
                        Text("Not enforced on this Mac: \(omitted.map(\.ruleID).joined(separator: ", "))").font(.caption).foregroundStyle(p.amber)
                    }
                    Text("Listed rules are the ones the filter's evaluator recorded for this app. The full rule list is not exposed over the control surface.").font(.caption).foregroundStyle(p.muted)
                }
                Card {
                    SectionTitle(text: "Recent changes")
                    if a.revisions.count > 1 {
                        Text("Decisions for this app were made under revisions \(a.revisions.sorted().map { "r\($0)" }.joined(separator: ", ")).").font(.callout)
                    } else {
                        Text("No policy change while this app was active in the recorded window.").font(.callout).foregroundStyle(p.text2)
                    }
                    let siblings = model.apps.filter { $0.id != a.id && $0.signingID != nil && $0.signingID == a.signingID }
                    ForEach(siblings) { s in
                        Text("Another identity with the same signing identifier: team \(s.teamID ?? "none"). It is a separate app; no permissions carry over.").font(.callout).foregroundStyle(p.amber)
                    }
                }
                Card {
                    SectionTitle(text: "Activity", trailing: "\(a.flows) recorded · \(a.blocked) blocked")
                    ForEach(model.flows.filter { AppSummary.identity(of: $0.facts).id == a.id }.prefix(12)) { r in FlowRow(record: r, compact: true) }
                }
                Card {
                    SectionTitle(text: "Why the current rules apply")
                    ForEach(Array(AppExplanation.latest(for: a, in: model.flows).enumerated()), id: \.offset) { item in
                        let w = item.element
                        VStack(alignment: .leading, spacing: 3) {
                            Text(w.destination).font(.system(.callout, design: .monospaced))
                            Text("\(w.verdict): \(w.summary)\(w.revision.map { " (r\($0))" } ?? "")").font(.callout).foregroundStyle(p.text2)
                            ForEach(w.notes, id: \.self) { n in Text(n).font(.caption).foregroundStyle(p.muted) }
                        }
                    }
                    Text("Each line is the filter's recorded decision from the moat-core evaluator, not a re-evaluation by this window.").font(.caption).foregroundStyle(p.muted)
                }
                RuleAuthoringCard(model: model, app: a)
            }
        } else {
            EmptyStateView(symbol: "app.dashed", title: "No app selected", text: "Choose an app from Apps.")
        }
    }
}

/// Standalone rule authoring: narrow, expiring, owner-authorized with the Keychain key behind user presence.
struct RuleAuthoringCard: View {
    @ObservedObject var model: AppModel
    let app: AppSummary
    @Environment(\.palette) private var p
    @State private var host = ""
    @State private var minutes = 15
    @State private var action: LocalRulePlan.Action = .deny

    var body: some View {
        Card {
            SectionTitle(text: "Narrow temporary rule")
            let dest = host.isEmpty ? (app.destinations.first?.host ?? "") : host
            let port = app.destinations.first { $0.host == dest }?.port ?? 443
            let plan = LocalRulePlan(action: action, app: app, host: dest, port: port, expires: Date().addingTimeInterval(TimeInterval(minutes * 60)))
            Picker("Action", selection: $action) {
                Text("Block").tag(LocalRulePlan.Action.deny)
                Text("Allow").tag(LocalRulePlan.Action.allow)
            }
            .pickerStyle(.segmented)
            Picker("Destination", selection: $host) {
                ForEach(app.destinations.prefix(10), id: \.host) { d in Text("\(d.host):\(d.port)").tag(d.host) }
            }
            Stepper("For \(minutes) minutes", value: $minutes, in: 5 ... 480, step: 5)
            Text(plan.ownerPlan(id: "preview").display).font(.system(.callout, design: .monospaced))
            ForEach(plan.problems(), id: \.self) { pr in Text(pr).font(.caption).foregroundStyle(p.red) }
            HStack {
                MoatButton(title: model.canApplyStandalone ? "Authorize and apply with Touch ID or password" : "Authorize with Touch ID or password", systemImage: "touchid", kind: .primary, disabled: !plan.problems().isEmpty || (model.ownerSigner == nil && model.applier == nil)) {
                    model.trialDenyHost = action == .deny ? dest : model.trialDenyHost
                    Task { await model.authorize(plan) }
                }
                if let a = model.lastAuthorization { Pill(text: "signed by \(a.keyID)", tone: .green) }
                if let r = model.lastApplied { Pill(text: "installed as revision \(r.summary.revision)", tone: .green) }
            }
            Text("macOS asks for your fingerprint or password and shows this exact plan. A typed phrase is never accepted as authorization. \(model.canApplyStandalone ? AppModel.standaloneApplyHow : model.applyUnavailableReason)").font(.caption).foregroundStyle(p.muted)
        }
    }
}

struct TasksScreen: View {
    @ObservedObject var model: AppModel
    @Environment(\.palette) private var p

    var body: some View {
        VStack(alignment: .leading, spacing: 18) {
            ScreenHeader(eyebrow: "Restricted tasks", title: "No task boundary on this Mac", dim: "macOS has no tested session boundary in Moat yet, so a task launched here is not contained. Session rules are omitted from this Mac's policy with a report.")
            Card {
                SectionTitle(text: "Where tasks are supported")
                Text("Linux endpoints launch protected sessions (cgroup v2 + nftables) through moat-launch. Their tasks appear in the controller's Tasks view with the boundary and its verification.").font(.callout).foregroundStyle(p.text2)
                let omitted = model.status?.installed?.omitted ?? []
                if !omitted.isEmpty {
                    Text("Omitted here: \(omitted.map(\.ruleID).joined(separator: ", "))").font(.caption).foregroundStyle(p.amber)
                }
            }
        }
    }
}

/// "This computer": component health and diagnostics, from the extension's own report.
struct ThisComputerScreen: View {
    @ObservedObject var model: AppModel
    @Environment(\.palette) private var p

    var body: some View {
        let d = DiagnosticsReport.from(status: model.status, lastContact: model.lastContact, contactLostSince: model.contactLostSince)
        VStack(alignment: .leading, spacing: 18) {
            ScreenHeader(eyebrow: "Diagnostics", title: model.deviceCount <= 1 ? "This computer" : "Devices", dim: "Versions, policy generations, evidence age and gaps as the filter reported them.")
            Card {
                ForEach(d.items) { i in
                    HStack(alignment: .top) {
                        Text(i.label).font(.callout).foregroundStyle(p.muted).frame(width: 220, alignment: .leading)
                        Text(i.value).font(.system(.callout, design: .monospaced)).foregroundStyle(i.warn ? p.amber : p.text).fixedSize(horizontal: false, vertical: true)
                        Spacer()
                    }
                }
            }
            if !d.downgraded.isEmpty {
                Card {
                    SectionTitle(text: "Not supported or unproven here")
                    ForEach(d.downgraded) { c in
                        HStack(alignment: .top) {
                            Pill(text: c.support.rawValue, tone: c.support == .unsupported ? .red : .amber)
                            Text(c.label).font(.callout.weight(.semibold))
                            if let n = c.note { Text(n).font(.caption).foregroundStyle(p.muted).fixedSize(horizontal: false, vertical: true) }
                        }
                    }
                }
            }
        }
    }
}

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
        VStack(alignment: .leading, spacing: 18) {
            ScreenHeader(eyebrow: model.selectedApp?.name ?? "All apps", title: "What changed?", dim: "Compare when it worked with when it failed. Observed differences first; explanations are possibilities, each with a reversible test.")
            Card {
                Stepper("Worked: 2 hours ending \(Int(workingHoursAgo)) h ago", value: $workingHoursAgo, in: 2 ... 168, step: 1)
                Stepper("Failed: the last \(Int(failingHoursAgo)) h", value: $failingHoursAgo, in: 1 ... 24, step: 1)
            }
            Card {
                SectionTitle(text: "Observed differences")
                if c.observed.isEmpty { Text("No difference in the recorded evidence.").font(.callout).foregroundStyle(p.text2) }
                ForEach(Array(c.observed.enumerated()), id: \.offset) { item in
                    VStack(alignment: .leading, spacing: 2) {
                        Text(item.element.title).font(.callout.weight(.semibold))
                        Text("Worked: \(item.element.working.ifBlank("—")) · Failed: \(item.element.failing)").font(.caption).foregroundStyle(p.text2)
                    }
                }
            }
            Card {
                SectionTitle(text: "Possible explanations")
                ForEach(Array(c.candidates.enumerated()), id: \.offset) { item in
                    VStack(alignment: .leading, spacing: 3) {
                        HStack { Pill(text: "possible", tone: .amber); Text(item.element.title).font(.callout.weight(.semibold)) }
                        Text(item.element.why).font(.caption).foregroundStyle(p.text2)
                        Text("Test: \(item.element.test)").font(.caption).foregroundStyle(p.accent)
                    }
                }
                Text(ChangeComparison.disclaimer).font(.caption).foregroundStyle(p.muted)
                Text("Not compared: \(c.notCompared.joined(separator: "; ")).").font(.caption).foregroundStyle(p.muted)
            }
        }
    }
}

extension String {
    func ifBlank(_ s: String) -> String { isEmpty ? s : self }
}

/// Coverage & recovery: what this Mac can claim, then the local recovery controls.
struct CoverageRecoveryScreen: View {
    @ObservedObject var model: AppModel

    var body: some View {
        VStack(alignment: .leading, spacing: 28) {
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
                SectionTitle(text: "First ten minutes", trailing: "\(progress.done.count) of \(FirstTenMinutes.Step.allCases.count - 1)")
                ForEach(FirstTenMinutes.Step.allCases.filter { $0 != .fleet }, id: \.self) { s in
                    HStack(spacing: 8) {
                        Image(systemName: progress.done.contains(s) ? "checkmark.circle.fill" : (progress.next == s ? "circle.dotted" : "circle"))
                            .foregroundStyle(progress.done.contains(s) ? p.green : (progress.next == s ? p.accent : p.muted))
                        Text(s.title).font(.callout).foregroundStyle(progress.done.contains(s) ? p.text2 : p.text)
                    }
                }
                if progress.next == .choose {
                    HStack {
                        MoatButton(title: "Observe apps", systemImage: "eye") { model.choseMode = true }
                        MoatButton(title: "Enforce selected apps", systemImage: "shield") { model.choseMode = true; model.screen = .rules }
                    }
                }
                Text("Steps are checked only from the filter's own reports and actions you take, never because a screen was opened.").font(.caption).foregroundStyle(p.muted)
            }
        } else if progress.offerFleet {
            Card {
                SectionTitle(text: "Local protection is working")
                Text("When you want, connect your other devices to a private controller. This Mac keeps its rules, history and recovery if the controller is offline.").font(.callout).foregroundStyle(p.text2)
            }
        }
    }
}

/// recovery-required / rollback-pending on this Mac: say exactly what is enforced and what the owner must do here.
struct NeedsOwnerCard: View {
    let status: StatusReport
    @Environment(\.palette) private var p

    var body: some View {
        Card {
            HStack(spacing: 8) {
                Image(systemName: status.coverage.symbol).foregroundStyle(p.red)
                SectionTitle(text: status.coverage.label)
            }
            Text(status.coverage.claim).font(.callout).foregroundStyle(p.text)
            if let r = status.installed {
                Text("Enforced now: revision \(r.revision)").font(.system(.callout, design: .monospaced)).foregroundStyle(p.text2)
            }
            ForEach(status.coverageNotes.prefix(3), id: \.self) { n in Text(n).font(.caption).foregroundStyle(p.text2) }
            Text("Use Recovery below. Nothing is reinstalled, and no remote command clears this.").font(.caption).foregroundStyle(p.muted)
        }
    }
}

/// Lifecycle events reported by other enrolled endpoints (Linux moatd), shown as the endpoint reported them.
struct FleetEventsCard: View {
    let events: [EndpointLifecycleEvent]
    @Environment(\.palette) private var p

    var body: some View {
        Card {
            SectionTitle(text: "Other devices", trailing: "\(events.count)")
            ForEach(events.prefix(12)) { e in
                VStack(alignment: .leading, spacing: 3) {
                    HStack(spacing: 6) {
                        Pill(text: e.deviceID, tone: e.needsOwnerAtDevice ? .red : .neutral)
                        Text(e.title).font(.callout.weight(.semibold)).foregroundStyle(p.text)
                    }
                    if !e.detail.isEmpty { Text(e.detail).font(.system(.caption, design: .monospaced)).foregroundStyle(p.text2).lineLimit(2) }
                    Text(e.meaning).font(.caption).foregroundStyle(p.muted)
                }
            }
            Text("Reported by each endpoint; this Mac does not verify another device's state.").font(.caption).foregroundStyle(p.muted)
        }
    }
}

