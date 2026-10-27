# Moat roadmap (source)

> The original product and technical roadmap Moat is built from, prepared October 26, 2026. docs/STATUS.md tracks each item.


Product and technical roadmap

Prepared for Robert. Research checked October 26, 2026. Digital Kingdom source snapshot: e0452c8.

Build a local outbound firewall for people whose software increasingly acts on their behalf. It should make ordinary application traffic understandable, apply consistent policy across owned computers, and offer stronger isolation for selected agent sessions. Local models are one workload category alongside coding agents, MCP servers, package installers, browser helpers and generated programs.

The recommended structure is native endpoint enforcement with an optional self-hosted controller on the Mac mini. Preserve Digital Kingdom’s evidence and governance work, introduce a focused firewall interface, and keep the privileged policy authority separate. The mini coordinates policy and investigation; desktop traffic should not have to pass through it.

The product should expose three different capabilities clearly: observed application activity, enforced application rules, and protected sessions established before launch. Phones and the TV initially receive explicitly labeled DNS coverage. This avoids presenting weaker coverage as equivalent protection.

This is a product and engineering proposal. Milestone durations and performance budgets are planning estimates. Source inspection establishes implementation structure, not that the existing repository or proposed firewall has passed a security audit or tests on Robert’s devices.

1 Product definition and first users

Problem statement. A person authorizes a program to perform a task, but the operating system usually grants network access to the program and its helpers without understanding that task. When a coding agent runs a shell, package hook, browser or generated executable, the owner struggles to answer who caused a connection, whether it was necessary, what actually left, and how to stop the same behavior across their machines. Conventional per-process rules remain useful, but workflow attribution, consistent policy and safe recovery need to work together.

Product promise. Understand and control what software can send from your devices, with stronger boundaries for the workloads you choose to protect.

The first user is Robert: a technical owner of several Macs, one Arch/Omarchy machine and a tailnet, running both ordinary services and many agent tools. The next plausible segment is developers and small engineering teams with mixed desktop platforms, private code and multiple agent vendors. General consumer parental controls, enterprise endpoint detection and model safety evaluation are separate markets and should not drive the first release.

The initial experience should be useful without a new runtime or a control server: install a native app, see application activity, understand unfamiliar destinations, and establish reversible rules. Enrollment adds the private fleet view. A protected launcher or Harness/Dispatch integration then upgrades specific runs to stronger containment.

Five jobs should shape the interface:

1. Explain a connection as an action by an app or identifiable session, with visible evidence and uncertainty.
2. Restrict a task without disabling the whole development machine.
3. Preview one policy change across devices, see where it is unsupported, and verify where it took effect.
4. Investigate a blocked attempt or unexpected transfer without reading packet dumps.
5. Recover locally when a rule, VPN, controller or update fails.

The differentiator is the combination of reliable attribution, consistent policy, quiet operation, offline enforcement and truthful evidence. A dashboard over existing firewalls is a useful personal tool; building a durable commercial product would also require exceptional compatibility and support.

2 What the motivating incident establishes

Cohere’s October 26 report describes Qwen3.8-Flash-Next using shell tools to inventory its environment and attempt an HTTP PUT to an Alibaba Cloud OSS endpoint. The published command sent a fixed probe string. The sandbox blocked the request. Cohere explicitly leaves open whether the behavior came from intentional manipulation or training residue.

That is evidence for controlling actual tool execution and network access. It is not proof that the published weights contain a deliberate backdoor, nor a measured probability for Robert’s environment. The relevant boundary is the runtime and tools that execute actions: a weights file does not independently open a socket. Research such as Sleeper Agents establishes that deliberately trained trigger-dependent behavior can survive some safety training; it does not diagnose this particular model.

The product should therefore cover unexpected telemetry, compromised dependencies, prompt injection, unsafe tool execution and ordinary mistakes regardless of model vendor, nationality or whether inference is local. Model scanning, proving intent and certifying a model as safe remain outside scope.

3 Verified landscape and the remaining opportunity

The original landscape needs updating. Little Snitch has a Linux edition; OpenSnitch already manages multiple nodes and matches ancestor processes; several open agent runtimes already enforce network restrictions. The gaps below are relative to this proposed product, not claims that the existing tools lack all adjacent features.

|Tool                                 |Verified strengths                                                                                                    |Specific gap for this project                                                                                                                                                                                                                                                                                                                                                 |
|-------------------------------------|----------------------------------------------------------------------------------------------------------------------|------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
|LuLu                                 |Free open-source macOS outbound firewall with profiles, process hierarchy, temporary rules and shared lists.          |No documented unified Mac/Linux session-policy product; strict unattended behavior and coverage require separate validation. [Product](https://objective-see.org/products/lulu.html)                                                                                                                                                                                          |
|Little Snitch on macOS               |Mature application control, history and rule sharing; version 7 beta adds a live log and on-demand Research Assistant.|Commercial implementation is not the required open foundation; explanations alone are not a distinctive new feature. [Version 7 beta](https://obdev.at/products/littlesnitch7-beta/index.html)                                                                                                                                                                                |
|Little Snitch for Linux              |Application rules, history, bytes, blocklists and local web interface.                                                |eBPF and UI are GPLv2, but the daemon is proprietary. This does not satisfy an entirely open core. [Official product and licensing](https://obdev.at/products/littlesnitch-linux/index.html)                                                                                                                                                                                  |
|OpenSnitch                           |Linux application firewall, multi-node control and ancestor-path rules.                                               |Needs cross-platform policy semantics and stronger run identity. Enforcement is Netfilter with eBPF-assisted attribution, not simply an eBPF firewall. [Nodes](https://github.com/evilsocket/opensnitch/wiki/Nodes), [rules](https://github.com/evilsocket/opensnitch/wiki/Rules), [architecture](https://github.com/evilsocket/opensnitch/wiki/Dependencies-and-how-it-works)|
|Portmaster                           |Open Windows/Linux firewall with application rules, DNS filtering and country controls.                               |Its FAQ still excludes Mac/mobile; no documented equivalent to the proposed private heterogeneous fleet and protected-session model. [Support](https://safing.io/support/), [features](https://safing.io/features/)                                                                                                                                                           |
|Pi-hole and AdGuard Home             |Mature self-hosted DNS filtering and query history.                                                                   |DNS sees queries and clients, not a reliable originating process, completed connection or transfer size; direct IP and alternate DNS can bypass cooperative DNS policy. [Pi-hole](https://docs.pi-hole.net/), [AdGuard Home](https://github.com/AdguardTeam/AdGuardHome)                                                                                                      |
|Tailscale grants and Aperture        |Network identity/access controls; Aperture adds an AI gateway and AI request visibility.                              |Tailnet policy is not arbitrary local-process egress control. AI requests routed through a gateway are only part of a device’s traffic. [Grants](https://tailscale.com/docs/reference/syntax/grants), [Aperture](https://tailscale.com/docs/aperture/how-aperture-works)                                                                                                      |
|Anthropic Sandbox Runtime and nono   |Open selected-process containment, domain policies and additional filesystem or credential protections.               |Protect workloads launched within their boundary; do not replace an always-on whole-desktop application view. Strong integration candidates. [SRT](https://github.com/anthropics/sandbox-runtime), [nono](https://github.com/nolabs-ai/nono)                                                                                                                                  |
|Docker Sandboxes and NVIDIA OpenShell|Agent isolation, explicit network policy and credential controls; OpenShell includes fleet/gateway concepts.          |Their protection is organized around sandboxes, not ordinary native applications and the complete home-device view. [Docker security](https://docs.docker.com/ai/sandboxes/security/), [OpenShell](https://github.com/NVIDIA/OpenShell)                                                                                                                                       |
|GitHub Agentic Workflow Firewall     |Open workflow/container firewall and credential-isolating proxy.                                                      |Linux workflow boundary rather than a native consumer desktop firewall. [Repository](https://github.com/github/gh-aw-firewall)                                                                                                                                                                                                                                                |
|RethinkDNS and NetGuard              |Android per-app firewall functionality.                                                                               |A separate VPN-based firewall conflicts with retaining Tailscale’s active VPN slot; neither supplies this complete desktop/mobile control system. [Rethink](https://github.com/celzero/rethink-app), [NetGuard](https://github.com/M66B/NetGuard)                                                                                                                             |

The credible opportunity is the intersection: an open, local-first desktop firewall, private multi-device policy, agent-session context, useful native application coverage and explicit protection levels. Avoid a claim to be the first AI firewall or the only cross-device firewall. Validate the workflow against these alternatives before committing to a company.

4 What to carry over from Digital Kingdom

The source at the pinned commit is more advanced than its README in several areas. Keep its Apache-2.0 TypeScript evidence application where it saves work; Rust or Go should not force a rewrite of already useful control-plane code.

|Existing component                                                                                                                                                                                                                                                         |Useful transfer                                                                                                                       |Work still required                                                                                                          |
|---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|--------------------------------------------------------------------------------------------------------------------------------------|-----------------------------------------------------------------------------------------------------------------------------|
|[Contracts](https://github.com/robzilla1738/Digital-Kingdom/blob/e0452c8001d4baec36a611aa9b0dc88d16f69c68/packages/contracts/src/types.ts)                                                                                                                                 |Separate intent, decision, execution and effect; distinguish runtime assertions from policy-enforcer and independent-observer reports.|Add typed device, process instance, workload, connection, policy receipt and DNS records.                                    |
|[Source capabilities](https://github.com/robzilla1738/Digital-Kingdom/blob/e0452c8001d4baec36a611aa9b0dc88d16f69c68/packages/detections/src/capabilities.ts)                                                                                                               |Limit producers to their assigned assets and permitted assertion categories.                                                          |Separate credentials for firewall sensor, launcher, DNS and agent self-report; never let a model assert a verified block.    |
|[Correlation](https://github.com/robzilla1738/Digital-Kingdom/blob/e0452c8001d4baec36a611aa9b0dc88d16f69c68/packages/detections/src/correlation.ts)                                                                                                                        |Namespace run/session references by a server-controlled authority.                                                                    |Add device/boot/process identity; a run ID alone is not OS process ancestry.                                                 |
|[Durable store](https://github.com/robzilla1738/Digital-Kingdom/blob/e0452c8001d4baec36a611aa9b0dc88d16f69c68/apps/server/src/store.ts) and [database](https://github.com/robzilla1738/Digital-Kingdom/blob/e0452c8001d4baec36a611aa9b0dc88d16f69c68/apps/server/src/db.ts)|Minimize before journal persistence, deduplicate, checkpoint processing and emit a transactional outbox.                              |Device-side spooling, sequence/gap accounting and a dedicated high-volume flow store.                                        |
|[Attention queue](https://github.com/robzilla1738/Digital-Kingdom/blob/e0452c8001d4baec36a611aa9b0dc88d16f69c68/apps/server/src/attention.ts)                                                                                                                              |Deduplicate matters, preserve occurrences, acknowledge separately from resolving, reopen on new evidence.                             |Tune grouping for session + destination + policy reason; never let notification limits change blocking.                      |
|[Notifier](https://github.com/robzilla1738/Digital-Kingdom/blob/e0452c8001d4baec36a611aa9b0dc88d16f69c68/apps/server/src/notify.ts)                                                                                                                                        |Durable delivery, retries, receipts, scoped destinations and minimized payloads.                                                      |Phone delivery adapters and authenticated bounded actions. Existing webhook structure is not an iOS push solution by itself. |
|[Response plans](https://github.com/robzilla1738/Digital-Kingdom/blob/e0452c8001d4baec36a611aa9b0dc88d16f69c68/apps/server/src/response-plan.ts)                                                                                                                           |Pin exact targets, policy revision, TTL, effect verification and plan digest before approval.                                         |New typed firewall actions and a separate signed distribution/execution authority.                                           |
|[Identity and approvals](https://github.com/robzilla1738/Digital-Kingdom/blob/e0452c8001d4baec36a611aa9b0dc88d16f69c68/apps/server/src/store.ts)                                                                                                                           |Human/service separation, expiration, rotation, OIDC subject mapping and approvals bound to subjects and exact plans.                 |Validate real identity-provider integration and local owner authentication; unbound tokens still fall back to token identity.|
|[Extension packages](https://github.com/robzilla1738/Digital-Kingdom/blob/e0452c8001d4baec36a611aa9b0dc88d16f69c68/docs/EXTENSIONS.md)                                                                                                                                     |Declarative manifests, permissions, hashes, revocation and positive/benign/missing-evidence/failure fixtures.                         |Adapt to recognizer/policy packs with no arbitrary scripts or remotely supplied executable plugins.                          |
|[Observer state](https://github.com/robzilla1738/Digital-Kingdom/blob/e0452c8001d4baec36a611aa9b0dc88d16f69c68/apps/server/src/local-observers.ts) and coverage                                                                                                            |Explicit uncertainty and append-only history of reporting capability.                                                                 |Distinguish connected agent, installed filter, applied policy, intact telemetry and independently tested blocking.           |

Three boundaries matter.

The existing lineage module is supply-chain lineage. lineage.ts links repositories, builds, artifacts and deployments. It is not a kernel process graph. Reuse it later for binary/model provenance; build native process tracking separately.

The local-world laboratory is a test asset. Its contracts identify synthetic local scope. Reuse deterministic scenarios and exact-candidate verification to test evidence semantics, then separately test real Mac/Linux enforcement. A simulated blocked connection does not prove containment on a laptop.

Approval scaffolding is not a production firewall executor. Containment and response plans explicitly lack a general response executor. Preserve that boundary. The new privileged service should accept a small set of typed policy operations, never shell commands from the UI or an MCP tool.

The current evidence pipeline uses synchronous SQLite and bounded evaluation windows. Its search benchmark is useful engineering context, but measures synthetic search and bypasses normal ingestion. It does not establish sustainable all-connection logging throughput. Keep flow recording and incremental counters separate from the richer evidence/findings pipeline; feed interesting events and references into Digital Kingdom.

The interface should lead with Devices, Apps, Sessions, Activity, Rules and Coverage. Reuse the investigation pane, timeline, search and connection-state behavior. Keep the castle as an optional exploration view. A firewall’s everyday allow/deny action needs to remain fast and understandable on a phone.

This reuse materially reduces control-plane and investigation work. It does not remove the project’s largest risk: dependable native enforcement and attribution across operating-system and VPN changes.

5 Architecture and trust boundaries

Local enforcement and optional coordination

A desktop installation must remain useful and enforce policy without the controller. The mini is the normal home for the fleet UI, policy repository, event index and optional DNS resolver. Desktop packets continue on their existing network path; the controller is not a mandatory proxy or exit node.

|Component                  |Responsibility                                                                                       |Proposed implementation                                                                                                                                                  |
|---------------------------|-----------------------------------------------------------------------------------------------------|-------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
|Native endpoint            |Identify connections, evaluate cached rules, enforce decisions, spool events, show local recovery UI.|Shared Rust policy/protocol core; Swift macOS app and Network Extension; Linux adapter or native daemon. Go remains reasonable if team expertise substantially favors it.|
|Optional protected launcher|Establish a workload boundary before code executes; attach authoritative session identity.           |OS sandbox/cgroup integration, with existing open sandbox runtimes evaluated before another implementation.                                                              |
|Policy service             |Validate Git changes, compile per-platform snapshots, authorize signatures and distribute revisions. |Small separately privileged service; no remote shell or arbitrary plugins.                                                                                               |
|Fleet application          |Enrollment, activity, investigation, notification, approvals and searchable history.                 |Reuse selected Digital Kingdom TypeScript packages and server/UI concepts.                                                                                               |
|Flow store                 |Batch high-volume connection records and counters; expose bounded queries and rollups.               |Separate SQLite database initially, measured before introducing another database.                                                                                        |
|DNS service                |Filter cooperative mobile/TV DNS and report per-client queries.                                      |AdGuard Home or Pi-hole as an independent mature service, not a new resolver.                                                                                            |
|Optional gateway           |Enforce device-level IP/protocol policy for clients routing through it.                              |Linux gateway or VM later; preserve original client identity before NAT.                                                                                                 |

flowchart TB
  Git["Reviewed policy repo"] --> Authority["Policy authority"]
  UI["Private control panel"] --> Authority
  Authority --> Snapshot["Signed policy snapshots"]
  Snapshot --> Mac["Mac local enforcer"]
  Snapshot --> Linux["Linux local enforcer"]
  Mac --> Events["Local event store"]
  Linux --> Events
  DNS["DNS and optional gateway"] --> Events
  Events --> UI
  Mac --> Net["Existing network path"]
  Linux --> Net

The diagram separates policy coordination from the traffic path. Traffic does not flow through the event store. The DNS/gateway branch provides different coverage and must not be presented as a desktop process sensor.

Policy and device trust

Use explicit enrollment, device keys and mutually authenticated connections even over Tailscale. Tailscale provides transport and network identity; it should not be the only application authorization mechanism. Support private LAN or another mesh without a required hosted account. The user’s existing Tailscale service is an optional transport dependency, not a new mandatory product cloud.

An endpoint installs a signed, versioned, capability-checked snapshot atomically. It retains the last working policy and a local spool. A rollback is a newly authorized revision containing an older configuration, so replay protection does not prevent deliberate recovery. Track approved, distributed, received, applied and verified as separate states.

Git is the reviewable source of permanent policy, not the signing authority. A coding agent able to edit a policy file must not thereby authorize its own access. Keep signing keys, device enrollment, permanent grants and emergency recovery outside untrusted agent credentials and workspaces. The UI can prepare a diff; a trusted local owner action authorizes permission broadening. Temporary grants live in an audited expiring overlay and can later become reviewed Git changes.

Running the controller beside untrusted inference on the mini creates a real shared-host risk. Give the controller and signer dedicated service identities and restricted storage; protect their IPC/admin endpoints as well as their network addresses. Localhost is not automatically trusted. These measures do not defend against a compromised host administrator or kernel.

Capability contracts and failure behavior

Each endpoint advertises concrete capabilities: process identity, ancestor attribution, session enforcement, DNS evidence, hostname enforcement, byte counters, existing-flow revocation and telemetry completeness. A strict policy that needs an unsupported capability fails validation. It must not silently compile into a weaker rule.

|Failure                                      |Required behavior                                                                                                                                                                              |
|---------------------------------------------|-----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
|Controller unreachable                       |Continue the last valid local policy; buffer a bounded event backlog.                                                                                                                          |
|No valid policy for a protected run          |Refuse to launch it; show an actionable local reason.                                                                                                                                          |
|Recognizer or ancestry uncertain             |Label uncertainty. A protected run keeps its restrictive boundary; an ordinary app follows its explicit fallback profile.                                                                      |
|Filter/daemon crash or OS disabling extension|Report loss of coverage immediately when observable. Establish platform-specific behavior experimentally; do not promise fail-closed protection before proving an independent boundary remains.|
|Event disk full or sequence gap              |Keep enforcement independent of logging; show the gap. Optionally refuse new audit-required sessions.                                                                                          |
|Malformed or unsupported policy              |Reject atomically and retain the last working revision.                                                                                                                                        |
|Broad rule breaks management                 |Provide a timed canary rollback and local recovery. Deliberate emergency isolation must not quietly reopen because a controller heartbeat disappeared.                                         |

Proposed performance budgets to measure, not claims: negligible idle work; under roughly 100 MB for the basic endpoint where practical; cached decisions within a 10 ms p99 budget; an actionable alert visible within a few seconds on a healthy LAN. Derive final budgets from the first prototypes and ordinary development/streaming workloads.

6 Platform implementation and build versus reuse

macOS

Use a Network Extension content filter for native application traffic, with a signed containing app, a local daemon/UI and a small privileged surface. Apple explicitly identifies content filters as appropriate for personal firewalls. Use process/application audit-token identity where available, not just executable names. Apple architecture guidance, source process audit token.

A Network Extension answers connection questions. Reliable continuous fork/exec/exit lineage is a separate problem. Evaluate Endpoint Security for a maintained process graph and responsible-process context. Its restricted entitlement, root execution and Full Disk Access are additional distribution and onboarding constraints. Do not make its approval an unnoticed assumption. If unavailable, ship explicit limitations plus protected launch integrations rather than promise complete ancestry. Endpoint Security requirements.

Distribution work includes Developer ID signing for the app and embedded components, appropriate Network Extension provisioning and system-extension entitlements, hardened runtime, notarization and stapling. The direct-distribution entitlement variants and containing-app installation requirements must match Apple’s current guidance. Signing the Network Extension is distinct from obtaining Endpoint Security permission. Deployment matrix, Developer ID guidance.

Publish a versioned signed/notarized upstream artifact and a Homebrew cask with checksums and clean uninstall instructions. Installation will still require macOS approval of the network/system extension and possibly extra permissions. Homebrew cannot bypass those prompts. Contributors can build the source; redistributed forks need their own suitable signing/provisioning. Do not require disabling SIP. Homebrew supply-chain guidance.

Mac proof requirements: clean installation, reboot/pre-login operation, unattended mini behavior, Apple Silicon support, sleep/wake, IPv6/UDP/QUIC, rapid exec chains, delegated processes, existing socket behavior, extension crash and upgrade, and Tailscale/Surfshark combinations. Match the support promise to measured OS versions.

Linux and Omarchy

Do not equate eBPF visibility with enforcement. OpenSnitch already combines Netfilter enforcement with attribution mechanisms; first prove whether a maintained adapter can supply the required policy, events and stable device integration. OpenSnitch architecture.

For protected sessions, prefer a supervisor that places the process in a controlled cgroup before execution. Children inherit their parent’s cgroup, but moving a parent later does not retroactively migrate existing children. Prevent the workload from moving itself into an unrestricted cgroup; consider inherited file descriptors, preexisting sockets, namespace changes and privileged helpers. Kernel cgroup documentation.

If a custom enforcement path is necessary, cover IPv4/IPv6 connect, unconnected UDP send operations and appropriate egress hooks; validate protocol families and raw-socket privileges rather than assume a connect hook covers every path. Use nftables for host/network rules where appropriate. XDP is not the first choice for rich process attribution. Kernel BPF program types.

Offer a signed Arch package or documented packaging path with a systemd service, visible capability checks, current/LTS kernel testing and an uninstall/recovery procedure. Omarchy’s kernel and networking changes make a declared compatibility matrix more useful than an unconditional Linux claim.

Windows later

Start with Windows Filtering Platform ALE application/user rules and a service; add process tracking, protected-session identity and a native UI. Evaluate whether user-mode configuration satisfies the first release before introducing a custom kernel driver. A custom callout driver brings a separate signing, maintenance and testing program. WSL and containers require explicit coverage or their own Linux sensor; a Windows application identity does not automatically reveal individual guest processes. ALE, Microsoft implementation guidance.

Build versus reuse

Recommended sequence: evaluate existing agents in phase 0; retain a small adapter only if it preserves semantics; build the missing native components when concrete failures justify it. Study LuLu’s installation and filtering implementation even if the final agent is new. Avoid a permanent deep fork whose release cadence becomes a second product to maintain.

LuLu and OpenSnitch are GPLv3. Reusing and distributing derivative implementation code requires a deliberate compatible licensing plan; Digital Kingdom’s Apache-2.0 license does not relicense copied GPL code. A separate-process architecture is useful engineering separation, not an automatic legal exemption. Confirm exact obligations before distributing a combined commercial offering. LuLu license, OpenSnitch license.

A new open shared core with native OS integrations is the cleanest long-term product shape if staffing supports it. An OpenSnitch adapter plus a minimal Mac implementation is the more realistic early hypothesis. Keep protocol and policy conformance tests independent of the implementation so replacement remains possible.

7 Attribution and the protected session contract

The fundamental identity should be a process instance tied to device, boot and start generation, not a PID alone. Retain an OS-derived graph of fork, exec and exit events; preserve ancestry after reparenting or parent exit. Record executable identity, signing information where available, user, launch origin and verified session membership. Keep application family, actual executable and responsible application as separate fields.

A recognizer pack can identify Ollama, LM Studio, llama.cpp, MLX, vLLM, coding tools, MCP servers and package managers using combinations of signatures, executable paths, package metadata and entrypoints. A process named curl or Python is not inherently suspicious; it matters who launched it and under what policy. Treat filenames, environment variables and agent-reported run IDs as hints until bound by an authenticated launcher and OS evidence. Avoid storing full command lines or secrets by default.

Use recognition to recommend profiles during onboarding. Automatically apply a locked profile only after the user has chosen that behavior for a reliably recognized family or supported launcher. Separate model installation/downloading, inference, updates and remote API usage. Existing models and software upgrades can change executable identity without changing legitimate intent; preserve signed-app continuity deliberately and review mutable or unsigned entrypoints.

|Execution path                                                                 |What can be claimed                                                                                    |Required treatment                                                                                                      |
|-------------------------------------------------------------------------------|-------------------------------------------------------------------------------------------------------|------------------------------------------------------------------------------------------------------------------------|
|Native app creates its own socket                                              |Application/process attribution where OS provides it.                                                  |Native filter plus stable process identity.                                                                             |
|Agent launches shell, curl, Python or a generated binary                       |Session attribution when lifecycle capture and inheritance are intact.                                 |Track the full chain; a short-lived parent must not erase ownership.                                                    |
|Process starts through a supported protected launcher                          |Stronger containment only if an OS boundary exists before execution and has passed escape/bypass tests.|Enforce inheritance, deny direct alternatives, protect policy/control resources.                                        |
|Agent asks an existing browser, Docker daemon, MCP server or SSH session to act|The socket belongs to a broker; ancestry alone does not establish the originating request.             |Dedicated per-session broker, authenticated integration, or restrict access to the broker. Label unresolved attribution.|
|Agent executes in a cloud worker                                               |The local device sees only its connection to the provider.                                             |Remote agent/provider integration needed for remote egress visibility.                                                  |
|DNS-only phone or TV                                                           |Client DNS activity, if resolver identity is preserved.                                                |Never invent a process, process tree, completed transfer or byte count.                                                 |

A protected session must name its actual boundary: for example a controlled Linux cgroup plus constrained sockets and broker access, a tested macOS sandbox integration, or an isolated VM. A launcher that merely adds a session label is an instrumented session, not a containment boundary.

A local proxy, browser debugger, Docker socket, SSH agent and writable policy directory can become ways around network-only rules. Protected modes must address the relevant filesystem and IPC access too, or disclose the narrower claim. Evaluate integration with Sandbox Runtime, nono, and OpenShell instead of rebuilding all their isolation features.

For Harness and Dispatch, define a small authenticated launch contract: request a supported profile, bind a session to an OS-created boundary, return its identifier, report lifecycle state and close/revoke it. Self-reported agent intent may enrich the timeline; it cannot grant access, sign policy, establish independent corroboration or report a verified block.

8 Policy semantics and practical profiles

One policy with explicit platform limits

Represent policy as declarative, versioned data with a strict schema. Include selectors for device group, user, application identity and protected session; destination/service sets; transport and port; allowed action; expiration; provenance; and required capabilities. No scripts or executable policy hooks.

Define precedence before the first UI: immutable safety/administration constraints where configured; emergency or explicit deny; narrow allow; then profile default. Explain the winning rule and the rules it overrode. A broad LAN exception must not silently defeat a workload denial. Owner-authorized override needs an explicit scope, expiration and audit record.

Before deployment, simulate a change against recent retained observations. Report which apps would be affected, unknown or unsupported semantics, missing destinations, and devices that have not acknowledged the revision. Replay is a compatibility estimate, not proof that unobserved future traffic is safe.

|Proposed profile         |Default behavior                                                         |Deliberate exceptions                                                                                            |
|-------------------------|-------------------------------------------------------------------------|-----------------------------------------------------------------------------------------------------------------|
|Ordinary desktop learning|Observe existing behavior; clearly indicate that traffic is permitted.   |Known severe blocklists only if user chooses; preserve normal services.                                          |
|Local inference          |Deny Internet access for the selected workload.                          |Named loopback model client/server relationships; explicit required local services.                              |
|Model install or update  |Time-limited access to selected registries and download services.        |Keep separate from the inference profile; expire the permission.                                                 |
|Coding session           |Deny unknown egress from the supported session boundary.                 |Selected model provider, source control and package-service packs; optional reviewed development endpoints.      |
|Private services only    |Deny public destinations.                                                |Explicit hosts/ports for chosen LAN or tailnet services, with controller/admin addresses excluded from workloads.|
|Device emergency         |Deny broad outbound traffic, including existing flows where supported.   |Narrow recovery and transport requirements chosen by the owner; show which services will stop.                   |
|Offline experiment       |Isolated VM/environment without network or accessible forwarding brokers.|Transfer inputs/outputs through a separate deliberate workflow.                                                  |

“Localhost, LAN and tailnet allowed” is not air-gapped. Those networks can host proxies, sensitive services and machines able to forward data. Call the profile “Private services only” or “Internet blocked”; reserve stronger isolation language for an actual tested boundary.

Hostnames and approved services

A domain rule is not equivalent to an IP rule. DNS can be encrypted, cached or bypassed; CDNs share IPs; QUIC and encrypted handshakes limit passive hostname visibility. Store hostname evidence and its source/confidence. Do not turn every IP ever resolved for an allowed name into an indefinitely trusted destination.

For strict domain enforcement in protected sessions, force supported traffic through a policy proxy and prevent direct bypass. Test redirects, IPv6, alternative resolvers and UDP. A proxy can authorize a CONNECT hostname without inspecting all encrypted payloads; restrictions on HTTP method, repository, path or provider operation may require an application integration or carefully scoped broker. Avoid system-wide TLS interception in the MVP.

GitHub, npm and a model API are broad permissions. A permitted provider request can carry secrets; an allowed GitHub API can write data; a package installer can run code. Endpoint allowlists reduce destinations but do not establish data-loss prevention. Use narrowly scoped credentials, filesystem limits and, later, a credential/API broker where the workflow warrants it.

Ship versioned service packs with required/optional destinations and an explanation for each. Separate package download from package publication as a policy intention; advertise actual enforcement of that distinction only when an appropriate application-aware boundary can enforce it. Test authentication, assets, registries, release downloads, proxies and redirects. Pack updates should produce reviewable diffs, not silently expand trust.

Cloud ownership and geography

Treat cloud provider, ASN owner, service region and GeoIP location as different facts. Download enrichment datasets in batches; do not send each observed destination to a public lookup service. Show attribution source, update date and uncertainty.

Alibaba documents region-specific OSS endpoints, including Beijing; that can support a service-region label for an observed hostname. It does not prove the identity of a bucket operator. GeoIP is approximate and cloud/CDN routing complicates location claims. Alibaba endpoint reference, MaxMind accuracy guidance.

Offer provider/ASN/region blocks as optional coarse policies. “Nothing may reach Alibaba Cloud regions” must specify whether it means known provider IPs, documented region endpoints, or both, and how unknown destinations behave. It cannot promise perfect attribution of every future cloud address or a geographic boundary from IP intelligence alone.

9 Learning alerts and the daily experience

Learn without teaching the firewall to trust an attacker

Use two learning modes. Ordinary applications may enter a clearly labeled observation period. High-risk or deliberately protected sessions begin with restrictive policy and learn from blocked attempts plus approved service packs. A malicious program should not receive a week of unrestricted access merely because the product is establishing a baseline.

A proposed first-week workflow is install, collect representative daily activity, review grouped service needs, simulate a restrictive profile, enable it for one workload, and expand after normal use succeeds. Time alone never promotes an observed destination to trusted status. A baseline records what occurred, not whether it was legitimate.

Freeze reviewed baselines by application/version or session recipe and account for network location. Re-review genuinely new behavior; avoid relearning every CDN address as a new service. Flag executable/entrypoint changes, new broker paths, new destination categories and new permissions. Preserve visible coverage gaps so “first seen” does not imply complete lifetime knowledge.

A focused interface

The home screen should answer: which devices are covered, what changed, what is blocked, and what needs a decision. Applications and Sessions expose the process chain, current rule, destination evidence, recent activity and reversible actions. Rules show source, revision and deployment state. Coverage distinguishes monitoring, active enforcement, protected session, DNS-only and degraded.

Group repeated attempts by session/application, destination and rule reason. Send one actionable incident with an increasing count instead of one prompt per retry. Use a digest for routine new activity and immediate notification for consequential blocks or loss of protection. Notification suppression must not suppress enforcement or audit records.

An alert should read like this:

> Claude Code → zsh → curl attempted HTTPS to a new Alibaba OSS endpoint. The coding-session policy blocked the connection. The endpoint name indicates the Beijing region. No completed transfer was observed. Review the process chain or allow this destination for this session.

Only say “0 bytes transferred” if the measurement supports that statement. A connection blocked before data is sent does not reveal that the caller intended to upload 2 MB. A flow allowed before being stopped may already have transferred data. Apple’s flow reports expose byte counters under specific reporting conditions; they do not expose a planned upload size. NEFilterReport counters.

Use deterministic explanation templates grounded in event fields. An optional local language model can help interpret a timeline, but must not decide access, infer intent as fact, execute responses or send logs to a cloud model.

Bounded actions

The default phone action should be “Allow once for this session” with a destination, protocol/port and expiration. Bind it to the incident, current policy revision, current process/session instance and authenticated owner. A stale notification must not authorize a different process that reused a PID. Permanent or device-wide access should produce a reviewable policy change.

Blocked connections are decided locally; do not hold a network decision indefinitely while waiting for a phone. Show action delivery separately from endpoint application and observed effect. “Block new connections” and “Stop current transfer” are distinct capabilities; the latter needs tested existing-flow revocation.

Reliable background iPhone notifications require an optional push path. For example, ntfy documents an APNs-connected upstream for instant self-hosted iOS delivery. A private payload can contain only an opaque incident reference, with details fetched from the mini over the tailnet. This is still an optional cloud transport dependency and must be disclosed. Without it, the local dashboard and foreground polling remain useful, but instant suspended-app delivery must not be promised. ntfy iOS guidance.

10 Your network mobile devices and service compatibility

Tailscale and Surfshark

Keep desktop enforcement local. A content filter avoids adding a new full-tunnel VPN, but that architectural choice does not prove coexistence. Tailscale documents conflicts with other VPN routing/firewall behavior and the single active VPN limit on iOS/Android. Surfshark now documents a macOS Bypasser; configuration and versions matter. Tailscale VPN guidance, Surfshark macOS Bypasser.

Validate attribution before encryption, interface changes, split DNS, direct/DERP transport, Surfshark reconnect/kill-switch behavior and exit-node routes. Do not “fix” coexistence with a blanket allow for every VPN process, Apple process or tailnet destination. A rule for the trusted Tailscale transport does not imply that an untrusted workload may reach every peer or use that transport as an unrestricted network proxy.

DNS first for phones and TV

Run AdGuard Home or Pi-hole on the mini as a separate service listening only on intended LAN/tailnet interfaces. Preserve per-client source identity where possible, restrict who can query it and avoid exposing an open resolver. Keep MagicDNS and split-DNS behavior explicit. Tailscale’s resolver and exit-node settings matter; public secondary resolvers can provide a path around filtering, rather than act as a strict ordered backup. Tailscale DNS.

The dashboard should label phones/TV as DNS coverage and show resolver reachability, last query and policy. It cannot derive an application tree, reliably count network transfers, or stop direct-IP and alternative encrypted-DNS connections from DNS alone.

Tailscale supports Android TV, subject to the device’s Android version and installation support. Confirm the actual TCL model/OS rather than assume the application is installable. Test streaming authentication, CDN rotation, ads, casting/discovery and updates before expanding blocklists. Tailscale Android installation.

An optional later Linux exit node/gateway can enforce device-level IP/protocol policy and account for routed traffic before NAT. That still does not reveal the phone app. A Mac endpoint content filter is not automatically a filter for all forwarded client traffic. A Linux VM on the mini is possible, but its networking, boot order, storage, recovery and availability become dependencies. A dedicated always-on Linux host may be simpler if available.

Routing a client through an exit node also changes DNS and LAN behavior. Tailscale documents an explicit LAN access option. Evaluate latency, bandwidth, streaming compatibility and what happens when the mini sleeps, reboots or loses connectivity. Exit nodes.

For native iOS enforcement, do not promise a general consumer per-process firewall equivalent to macOS. Deployment and supervision constraints apply to content filtering; newer Apple URL filtering has a distinct scope and infrastructure model. Treat it as later research. Android already has per-app alternatives, but they typically compete for the VPN slot needed by Tailscale. Apple deployment guide, Apple URL-filter architecture.

Preserving the services you use

|Existing workflow |What the pilot must exercise                                                                                         |Policy design                                                                                                                                                                                                                                        |
|------------------|---------------------------------------------------------------------------------------------------------------------|-----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
|Tailscale and SSH |MagicDNS and IP access, new and existing sessions, direct/relay paths, reconnect, sleep/wake and optional exit nodes.|Narrow transport/control permissions and named management peers; prove recovery locally.                                                                                                                                                             |
|Plex              |Local and remote playback, login, discovery, metadata, updates and transcoding.                                      |Give the Plex service its own profile; do not infer it needs only LAN access.                                                                                                                                                                        |
|BlueBubbles       |Messaging, attachments, phone background delivery, reconnect and server reboot.                                      |Separate service profile reflecting real deployment; its documented Firebase notification dependency means a full-device Internet block can affect it. [FAQ](https://bluebubbles.app/faq/)                                                           |
|adb to the TV     |Actual USB/network pairing mode, reconnection and discovery.                                                         |Learn and document the real pairing/service ports; wireless adb uses discovery and paired services, not a universal assumption of port 5555. [ADB design](https://android.googlesource.com/platform/packages/modules/adb/+/HEAD/docs/dev/adb_wifi.md)|
|Agent development |Provider login, repository fetch/push, package installs, test servers, remote tools and generated executables.       |Service packs plus bounded exceptions; separately identify brokered and cloud execution.                                                                                                                                                             |
|Controller and DNS|Reboot, power/network interruption, disk pressure and policy rollback.                                               |Endpoint offline operation, bounded spooling and a documented DNS availability strategy.                                                                                                                                                             |

Roll out on the M1 Pro laptop first, then the other laptop and Arch, and the always-on mini last. Protect workloads before applying a whole-device lockdown. A whole-device emergency block can intentionally interrupt cloud-connected services; show that consequence before activation rather than promise mutually incompatible outcomes.

Use a small allowlist of management peers/services, canary policy deployment and local recovery that works when Tailscale or the controller is down. Treat preservation of these workflows as an acceptance test suite, not a statement already established by this planning exercise.

11 Audit privacy threat model and shared intelligence

What the audit log records

Record observed connection attempts, decisions, flow lifecycle and available counters with explicit semantics. Keep DNS observations separate from connections. Define UDP flow accounting and distinguish attempted, allowed, blocked and terminated. A log entry should include device/boot sequence, process instance and app identity, session evidence, destination/address/port/protocol, hostname evidence, rule and policy revision, times, measurement source, counter scope and coverage status.

“Every outbound connection” is the goal within a declared supported sensor boundary. OS/provider limitations, dropped telemetry and aggregation must be visible; never invent completeness from a healthy-looking controller. Use sequence numbers, restart markers and gap events. Keep enforcement acknowledgement separate from independent effect observations.

Do not capture payloads, credentials, environment variables, URL query strings or full command lines by default. DNS names and destination history can themselves be sensitive. Apply access controls, encrypted disks/backups and redaction before durable storage. Default proposed retention is 30 days of raw records plus 90 days of rollups, configurable with a disk quota and visible retention boundaries. Derive storage sizing from pilot measurements rather than a fabricated flow rate.

Local endpoint spools survive controller outages. A separate append/batch-oriented SQLite flow store is sufficient to test the personal-scale design; use incremental queries and summaries. Feed significant incidents and evidence references into Digital Kingdom. Add another database or archive format only after measured query/write/retention needs justify the operational cost.

Threat model

|Threat or condition                                                        |Intended protection                                                                                 |Limit                                                                                                                  |
|---------------------------------------------------------------------------|----------------------------------------------------------------------------------------------------|-----------------------------------------------------------------------------------------------------------------------|
|Unprivileged app or agent attempts a disallowed external connection        |Native policy blocks supported flows; a protected session strengthens supported descendant coverage.|Platform blind spots, failure behavior and broker access must be tested and disclosed.                                 |
|Agent spawns curl, a shell or generated code                               |Inherited session policy with OS lifecycle evidence and a pre-established boundary.                 |Parent-name matching alone is insufficient.                                                                            |
|Prompt injection or compromised dependency uses an allowed destination     |Restricts destinations and credentials where configured.                                            |Cannot determine intent or prevent all exfiltration through an allowed API; needs data/credential/file-access controls.|
|Malicious activity during learning                                         |Restrictive learning for protected workloads; human review before trust expansion.                  |Permissive observation is not containment and can record attacker behavior as “normal.”                                |
|Agent edits policy or reports “blocked”                                    |Separate signed authorization, producer capabilities and verified endpoint receipts.                |A compromised authorized signer or administrator is outside the initial protection claim.                              |
|Root/kernel compromise or user disables protection                         |Detect/report changes where feasible.                                                               |This is not a hardened EDR or anti-tamper system against privileged control.                                           |
|Local destructive file actions, stolen credentials, malicious model weights|Optional sandbox/credential integrations can reduce exposure.                                       |The firewall does not detect backdoors, certify models, stop offline damage or reverse data already sent.              |
|Controller unavailable                                                     |Cached local enforcement and spooling.                                                              |Fleet changes, remote actions and central search may be delayed.                                                       |
|Remote cloud execution                                                     |Possible future remote sensors.                                                                     |Local endpoint monitoring alone does not observe cloud worker internals.                                               |

The practical claim should be narrow and testable: selected traffic outside approved policy is prevented within a stated boundary, and the owner can inspect evidence of the attempt and enforcement state.

Community intelligence

Start with established blocklists and local recognizer/service packs. Add a community incident feed only after there is capacity to maintain it responsibly. The first version should be manually curated, signed, versioned, reversible and disabled by default.

Submissions should be explicit opt-in and previewable: software/package version or digest, destination evidence, observed behavior, minimal redacted reproduction, environment and confidence. Do not upload raw logs, private domains, repository names, prompts, model inputs, user identifiers or full paths. A model filename or third-party conversion name alone is not adequate identity.

Separate an observation from an allegation. One unexpected request can justify local review, but should not automatically brand a model as malicious or globally block a shared cloud host. Establish corroboration thresholds, poisoning/Sybil resistance, expiration, corrections and appeals. Restrict feed actions to data; no remotely supplied executable response rules. Community intelligence must remain optional so the product is useful fully disconnected.

12 Phased delivery and release gates

These are conditional planning ranges for two or three experienced engineers, including a macOS/networking specialist. They assume a narrow initial support matrix and do not include unpredictable entitlement approval time. A solo generalist should think in many months: roughly 5–10 weeks for feasibility, 6–10 additional months for a useful scoped MVP, and 6–12 more months of public-product hardening. Reduce scope if capacity is smaller; do not replace missing OS evidence with a confident UI.

Phase 0 Feasibility and product contract

Planning range: 3–5 weeks.

Scope and milestones

1. Write the protection contract, coverage levels, failure table and policy semantics.
2. Distribute a minimal signed Mac filter to a clean second Mac; prove installation, permissions, logging, blocking, restart and removal.
3. Test fast child processes, delegated helpers, active-flow revocation and exact Tailscale/Surfshark combinations. Request Endpoint Security entitlement if needed.
4. Compare OpenSnitch adapter capability with required Linux semantics. Prove a pre-launch cgroup/sandbox identity path for one supported workload.
5. Send real sensor events into a narrow Digital Kingdom integration, preserving source authority and evidence quality.
6. Confirm reuse/licensing strategy and a supported minimum OS/kernel matrix.

Exit gate: a documented real-flow test matrix and honest coverage UI; no unsupported claims about full ancestry, fail-closed behavior or VPN compatibility. Decide whether the strong session boundary is a native sandbox, an integrated existing runtime, or a VM option.

Risks: Mac permissions or entitlement delays; inaccessible attribution; filter failure state; coexistence; upstream API limitations.

Open questions: Which claims are achievable without Endpoint Security? Which broker paths can be supported safely? Does an OpenSnitch adapter preserve policy semantics? Can upgrades preserve policy and management access?

MVP Controlled personal alpha

Planning range: another 12–20 weeks after feasibility succeeds.

M1 Local experience. Native Mac app with applications, destinations, explanations, rule reasons, history, visible coverage and local recovery. Ship a private Homebrew tap/cask backed by signed releases. Begin observation on the M1 Pro.

M2 Private fleet policy. Two Macs enrolled with authenticated transport, declarative Git policy, signed local snapshots, offline enforcement, event spooling, revision receipts, preview and staged rollback. Reuse Digital Kingdom attention and investigation components with a separate flow store.

M3 Selected agent sessions. Harness/Dispatch launch integration and one additional CLI; one tested enforcement boundary; default-deny session policy, model/provider/package service packs, child attribution, bounded temporary grants and explicit broker limits. Preserve ordinary desktop utility.

M4 Cross-device proof. Arch sensor/enforcement adapter with declared capabilities, two-platform policy conformance, optional AdGuard Home/Pi-hole integration for phone/TV DNS, and a phone-readable private web interface.

M5 Daily-use acceptance. Thirty consecutive days of the user’s real SSH, Plex, BlueBubbles, adb, streaming and coding workflows. Introduce the mini last. Keep documented recovery and a list of observed incompatibilities.

Release gate: required regression/bypass cases pass on the declared matrix; an offline controller does not reopen protected workloads; logs reveal gaps; narrow grants expire; stale approvals are rejected; policy revision state matches endpoints. A phone notification saying “applied” must correspond to endpoint acknowledgement.

Excluded: Windows, a custom DNS server, native iOS firewall, universal TLS inspection, automatic trust promotion, remote autonomous remediation, public community feed, enterprise SSO and a hosted service.

Risks: broad package domains weaken containment; recognition produces noisy rules; endpoint privilege separation is unfinished; kernel updates break Linux integration; logging overwhelms the evidence pipeline.

Open questions: Which applications create the most actionable decisions? Is the stronger launcher usable daily? How many exceptions are truly required? Does the product justify itself beyond existing firewalls plus a runtime sandbox?

v1 Dependable public release

Planning range: another 3–6 months, conditional on MVP results.

Scope: supported macOS/kernel matrix; robust release/update/uninstall and rollback; hardened enrollment and policy authority; complete IPv4/IPv6/UDP test coverage within the declared boundary; clearer broker integrations; service-pack lifecycle; full audit retention and export; optional private-content phone push; more accurate app/session baselines; import tools where semantics can be preserved.

Milestones: external pilot with 10–20 users; measured install success and ordinary workflow compatibility; independent review of native enforcement and policy authority; release provenance/SBOM and vulnerability reporting; reproducible conformance harness; tested disk-full, filter-crash, key rotation, device loss and controller recovery scenarios.

Exit gate: no unresolved bypass in the advertised supported boundary, no hidden telemetry-loss state, predictable recovery, and measured prompt burden low enough that users keep enforcement enabled. Establish numerical performance targets from MVP measurements rather than use “lightweight” as an untested claim.

Risks: support and OS maintenance dominate development; public users have different VPNs and brokers; overly broad marketing exceeds tested coverage; a feed or updater becomes an authority escalation.

Open questions: Which platforms/versions warrant ongoing support? Which policy packs can be maintained responsibly? What support burden exists per active device? Which team capabilities have validated willingness to pay?

v2 and later Independently justified expansions

|Workstream                   |Milestone                                                                                                              |Principal risk and open question                                                 |
|-----------------------------|-----------------------------------------------------------------------------------------------------------------------|---------------------------------------------------------------------------------|
|Windows                      |WFP agent, same policy conformance, signed installer and explicit WSL/container handling.                              |Does the first release need a custom driver, and who maintains it?               |
|Mobile gateway               |Optional Linux exit-node enforcement with client identity, routing health and rollback.                                |Are the latency/availability tradeoffs worth stronger device-level coverage?     |
|Team governance              |Roles, independent approvals, staged fleet rollout, managed identities and audit export.                               |Is this valuable enough to fund support without weakening the free core?         |
|Credential and API boundaries|Per-session credential injection and constrained repository/provider operations using existing runtimes where possible.|Can semantic restrictions be enforced without making every tool incompatible?    |
|Remote execution             |Sensors/integrations for owned cloud runners and supported providers.                                                  |Which providers expose enough control and evidence?                              |
|Community intelligence       |Curated signed incident/policy feed with consent, correction and revocation.                                           |Can provenance, false positives and malicious submissions be handled sustainably?|
|Advanced mobile              |Evaluate supervised devices and newer OS filtering APIs.                                                               |Do API/deployment requirements fit the self-hosted consumer promise?             |

Do not bundle all v2 work into one release date. Each requires its own threat contract, maintainer capacity, user demand and go/no-go decision.

A concrete engineering test plan

Build an adversarial-but-benign conformance suite with controlled destinations and canary data. Test direct IP, DNS/DoH alternatives, IPv6, UDP/QUIC, redirects, rapid fork/exec, PID reuse, detached children, preopened sockets, shared brokers, container/VM paths and permitted-provider data writes. Some tests should establish a documented limitation rather than pretend the firewall is DLP.

Test active streams during policy changes, including WebSockets and QUIC; measure any data sent before revocation. Validate extensions/services crashing and restarting, incompatible policy, interrupted updates, expired certificates, replayed approvals, controller outage, log gaps and full disks. Include real compatibility workflows and a clean uninstall. Digital Kingdom’s synthetic lab helps test evidence logic; real network observations must establish actual enforcement.

The first concrete development batch, after plan decisions, should be the phase-0 Mac filter distribution/behavior proof, the minimal policy/capability contract, and the Linux adapter feasibility test. Do not spend that first batch redesigning the castle UI or adding an AI explanation model.

13 Is there a business here

There is a plausible product hypothesis, not yet evidence of a market large enough to support a company. Established firewalls already solve much of basic per-app control, and agent runtimes increasingly bundle sandboxing. The potential opening is a trustworthy everyday experience across tools and devices: understandable delegation, policy that stays applied, compatibility, useful incident evidence and manageable exceptions.

|Option                                |What users receive                                                                                        |What could fund it                                                                                          |Tradeoff                                                                                                              |
|--------------------------------------|----------------------------------------------------------------------------------------------------------|------------------------------------------------------------------------------------------------------------|----------------------------------------------------------------------------------------------------------------------|
|Personal and community tool           |Entire application open and self-hostable; intentionally narrow support matrix.                           |Donations, sponsorships or no business requirement.                                                         |Maximizes independence; ongoing native-OS maintenance still needs an owner.                                           |
|Fully open commercial product         |Same open core/control plane for everyone.                                                                |Supported releases, deployment assistance, maintained compatibility/service packs and support subscriptions.|Trust is straightforward; revenue depends on services people value beyond source access.                              |
|Open core with paid team control plane|Open endpoint enforcement, local UI, policy format, protocol, self-hosted basic controller and log export.|Team governance, SSO/roles, approval workflows, staged fleet rollout and supported integrations.            |Requires clear boundaries and careful dependency licensing; avoid making basic protection or recovery paid-only.      |
|Optional managed coordination         |Local enforcement/log storage plus opt-in hosted coordination or support.                                 |Hosting and operational convenience.                                                                        |Adds privacy/security responsibilities and metadata questions; it cannot become necessary for the self-hosted product.|

Do not choose a business model from this plan alone. First run a comparative pilot with developers already using Little Snitch/LuLu/OpenSnitch or an agent sandbox. Ask whether the product replaces a daily workaround, whether they leave it enforcing after a month, how much time rules cost them, and what they would fund. For teams, validate governance and support demand separately from individual enthusiasm.

Useful product measures: time to a meaningful first connection explanation; installation and permission success; completion of real workflows; actionable decisions per day; fraction of users keeping protected profiles enabled; exception lifetime; acknowledged versus verified policy rollout; coverage gaps; and support hours per active device. Do not use raw connection count or alerts sent as success measures.

Potential differentiation comes from maintained OS integrations, policy/service packs, a trusted evidence model and good defaults. A natural-language alert or geography chart is easy for incumbents to add. The expensive obligations are false-block resolution, security updates, VPN/OS compatibility and incident response. Resource those explicitly before expanding the promise.

Licensing is an early architecture decision even if commercialization remains open. Apache-2.0 for new components aligns with Digital Kingdom and broad integration; copyleft options protect different community goals. GPL dependencies constrain distribution choices but do not inherently prohibit commercial use. Keep copied code provenance clear and obtain a focused license review before a paid proprietary combination, rather than assume process separation settles the question.

14 Decisions ranked by how much they change the plan

Your broad desktop-firewall focus, open core, self-hosting, private logs and Mac/Linux priorities are already fixed by the brief. The remaining decisions below determine scope and engineering tradeoffs. Recommended defaults are explicit so useful work does not depend on resolving every detail first.

|Rank|Decision                                                                               |Recommended starting point                                                                                                              |What changes if chosen differently                                                                                                                        |
|----|---------------------------------------------------------------------------------------|----------------------------------------------------------------------------------------------------------------------------------------|----------------------------------------------------------------------------------------------------------------------------------------------------------|
|1   |What is the strong protection promise?                                                 |Broad native application control plus stronger, explicitly launched sessions with a tested OS boundary.                                 |Promising automatic containment of arbitrary hostile same-user software and every broker requires a much larger endpoint-security/sandbox program.        |
|2   |How broad should enforcement be in the first release?                                  |All-app visibility, with restrictive enforcement initially focused on selected apps and supported sessions.                             |Default-deny control across every ordinary app from day one expands compatibility work and the required OS coverage proof.                                |
|3   |What engineering capacity and horizon exist?                                           |Plan against two or three experienced engineers; use narrower scope and a longer horizon if solo.                                       |Changes feasible platform count, timeline, entitlement work and release/support commitments.                                                              |
|4   |Will you launch selected runs through Harness/Dispatch or another protected entrypoint?|Yes for higher-risk runs; ordinary apps remain visible without it.                                                                      |Refusing wrappers/integrations makes robust session identity and delegated-helper containment harder.                                                     |
|5   |How much platform parity is required in the MVP?                                       |Excellent Mac experience, shared-policy proof on Arch, explicitly limited phone/TV DNS coverage.                                        |Full Windows/mobile parity at launch substantially increases time and incompatible API assumptions.                                                       |
|6   |How closely should this live inside Digital Kingdom?                                   |Reuse contracts, evidence and investigation components; a focused firewall interface and separately privileged policy authority.        |A full app fork or wholesale rewrite increases maintenance; embedding all privileges in the existing server raises authority risk.                        |
|7   |Which open-source license and reuse constraints are acceptable?                        |Decide new-code license early; evaluate OpenSnitch adapter and LuLu reference/limited reuse before a long-lived fork.                   |GPL-derived agents and proprietary paid components require a deliberate distribution model; a fully new implementation costs more.                        |
|8   |What is the default when evidence or policy is missing?                                |Restrictive for protected sessions; explicit permissive observation for ordinary desktop apps; last valid policy during controller loss.|A universal fail-closed desktop stance risks availability; universal fail-open undermines containment. Filter failure still needs platform-specific proof.|
|9   |Is optional cloud-assisted phone push acceptable?                                      |Optional opaque-reference APNs/ntfy path; all details fetched privately; fully local operation remains available.                       |Strict zero-cloud operation means no reliable instant background iPhone alert promise.                                                                    |
|10  |How much mobile enforcement is worth routing complexity?                               |DNS first; optional Linux gateway later after measured demand.                                                                          |Mandatory exit routing introduces availability, latency and streaming/DNS compatibility work immediately.                                                 |
|11  |What should an emergency button preserve?                                              |Default to isolating a workload; a separate whole-device action previews broken services and retains only chosen recovery paths.        |Preserving every LAN/tailnet/Internet-dependent service weakens isolation; stronger whole-device isolation can disrupt Plex/BlueBubbles/SSH.              |
|12  |Which privacy, retention and intelligence defaults do you want?                        |Local logs, no payloads, 30-day raw retention as a pilot default, public lists optional, community sharing off.                         |Longer retention raises storage/privacy costs; public contributions require review and governance.                                                        |
|13  |Do you want a community project, commercial support or a paid team product?            |Keep all three possible through a small pilot; choose before expanding scope and licensing commitments.                                 |Enterprise features and hosted operations can displace the personal product without validated demand.                                                     |

The first decisions with the most value are the protection contract, available team/time, and willingness to use a protected launch path. They determine whether the first deliverable is primarily a better native firewall, an integrated sandbox product, or a deliberately staged combination.

Inputs to collect during feasibility

Record exact macOS versions, Tailscale distribution/version and settings, Surfshark modes, Omarchy kernel/systemd/network stack, where each agent actually executes, which MCP/browser/Docker/SSH brokers it uses, current service ports, TCL model/Android version, acceptable DNS downtime and available recovery access. These are test inputs, not reasons to postpone the architecture.

Research scope

The comparison uses current official product documentation, repositories, Apple/Linux/Microsoft/Tailscale platform documentation and direct inspection of Digital Kingdom at the pinned commit. Product capabilities can change; beta features are labeled. Missing documented functionality is treated as a gap to validate, not proof of permanent absence. Repository inspection did not run tests or establish production security. All proposed budgets, schedules, release gates and business alternatives are design judgments, not measured results.