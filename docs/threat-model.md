# Threat model

Moat's claim is narrow and testable: **selected traffic outside approved policy is prevented within a stated
boundary, and the owner can inspect evidence of the attempt and the enforcement state.** Boundaries per platform are
in the [protection contract](protection-contract.md).

## Assets

* Data on the owner's machines that an agent or tool could send out (code, credentials, documents, model inputs).
* The integrity of policy: who may broaden access, and whether endpoints run what the owner approved.
* The evidence trail: what happened, under which revision, with which coverage, and where the gaps are.

## Actors

| Actor | Trust |
| --- | --- |
| Owner (Robert), using the owner key on a trusted device | Trusted. The only party that authorizes broadening and permanent grants. |
| Policy signer service (separate identity) | Trusted to sign what the owner authorized and narrowing changes; refuses unbounded grants. |
| Controller (Mac mini) | Coordinates, stores, notifies. Cannot authorize broadening without the owner key. Not in the traffic path. |
| Endpoint enforcer (`moatd`, `MoatFilter`) | Trusted to enforce and to report receipts within its advertised capabilities. |
| Protected launcher (`moat-launch`) | Trusted to create the boundary before exec and to report session lifecycle. |
| Agents, coding tools, MCP servers, package installers, generated programs | **Untrusted.** May be prompt-injected or compromised. |
| DNS resolver (AdGuard Home / Pi-hole) | Trusted only for DNS observations from cooperative clients. |
| Root, the kernel, a compromised administrator | Outside the initial claim. |

## Threats and what Moat does

| Threat or condition | Intended protection | Limit (stated, not hidden) |
| --- | --- | --- |
| Unprivileged app or agent attempts a disallowed external connection | Native policy blocks supported flows; a protected session strengthens descendant coverage. | Platform blind spots, failure behavior and broker access must be tested and disclosed. |
| Agent spawns curl, a shell or generated code | Linux: inherited cgroup session policy with the boundary established before exec. | macOS: no ancestry without Endpoint Security; rules match the socket-owning app. Parent-name matching is never used as proof. |
| Agent asks a broker (browser, Docker, SSH agent, D-Bus, MCP server) to act | Linux sessions hide broker sockets in a private mount namespace; `--allow-brokers` weakens this explicitly. | Abstract Unix sockets, the system resolver and loopback services remain brokers. Attribution through a broker is labeled unresolved. |
| Prompt injection or compromised dependency uses an **allowed** destination | Restricts destinations; service packs keep allowlists explicit. | Not DLP. An allowed GitHub/npm/model API can carry data. Needs credential, filesystem and API controls. |
| Malicious activity during learning | Restrictive profiles default to deny; time never promotes trust; human review before expansion. | Observation is not containment and records attacker behavior as "normal". |
| Agent edits policy or reports "blocked" | Signed snapshots; broadening needs the owner key; producer authority (`authority.rs`): self-reports may only assert intent. | A compromised signer or owner device is outside the claim. |
| Stale or replayed approval ("allow once") | Bound to incident, revision, session instance and owner; rejected when stale. | — |
| Replayed or downgraded snapshot | Replay protection by revision; platform check; local rollback keeps the high-water mark. | — |
| Session workload lies in the SNI or `Host` to reach an allowed name's address space | Linux session egress proxy resolves the name itself and connects to the resolved address, never the dialed one; resolved addresses are evaluated too, so safety rules still win. | Domain fronting through an allowed host's CDN; a hostile resolver; ECH (only the outer name is visible). UDP has no hostname evidence. |
| Session workload borrows another session's proxy (and its grants) | Each session may reach only its own listener; nftables rejects the rest of the proxy port range. | Root can set the upstream mark and bypass it (root is outside the claim). |
| Broad revision locks the owner out | Linux and macOS trial revisions revert to the last confirmed revision unless confirmed locally; isolation untouched. | Linux countdown needs `moatd` running; a stopped daemon reverts at its next start. |
| Root/kernel compromise, or the user disables protection | Detect/report where feasible (coverage *degraded*, table restoration on Linux). | Not an EDR or anti-tamper system. |
| Controller unavailable | Endpoints keep the last valid policy and spool locally. | Fleet changes, remote actions and search are delayed. |
| Remote/cloud agent execution | — | Local endpoints see only the connection to the provider. |
| Shared host: untrusted inference on the mini beside the controller | Separate service identities for controller and signer; authenticated admin endpoints (localhost is not trusted); safety rule keeps workloads off controller addresses. | Does not defend against a compromised host administrator or kernel. |

## Non-goals

TLS interception, payload inspection, automatic trust promotion, remotely supplied executable responses, model
certification, reversing data already sent, and protecting against the owner's own privileged actions.

## Agent-specific rules

* An agent token can **prepare a diff**; it cannot approve, sign, broaden, grant, or mark anything verified.
* Agent-reported run IDs, intents and environment variables are **hints** until bound by the launcher and OS evidence.
* Signing keys, enrollment and recovery stay out of agent workspaces (`moatctl keygen` warns; the signer runs as its
  own service).
