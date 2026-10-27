# Threat model

Moat's claim is narrow and testable: **selected traffic outside approved policy is prevented within a stated
boundary, and the owner can inspect evidence of the attempt and the enforcement state.** Boundaries per platform are
in the [protection contract](protection-contract.md).

> **Evidence today.** Every "what Moat does" entry below is implemented and tested on GitHub CI runners or in unit
> tests, at the level the [claim ledger](STATUS.md) records. None is proven on a real device: nothing is
> `supported_installed`. Where a protection exists only as design, or only on one platform, the row says so.
> The case-by-case test mapping is the [adversarial matrix](adversarial-matrix.md).

## Assets

* Data on the owner's machines that an agent or tool could send out (code, credentials, documents, model inputs).
* The integrity of policy: who may broaden access, and whether endpoints run what the owner approved.
* The evidence trail: what happened, under which revision, with which coverage, and where the gaps are.

## Actors

| Actor | Trust |
| --- | --- |
| Owner (Robert), using the owner key on a trusted device | Trusted. The only party that authorizes broadening and permanent grants. On the Mac the owner key lives in the Keychain behind user presence (W12). |
| Delegated issuer (e.g. a phone browser key) | Trusted only within an owner-signed `moat.delegation.v1`: named kinds, devices and maximum lifetime (W03). |
| Policy signer service (separate identity) | Trusted to sign what the owner authorized, narrowing changes and in-scope delegated grants; refuses unbounded grants. Controller-attested grants are off by default ([#56](https://github.com/robzilla1738/moat/issues/56)). |
| Controller (Mac mini) | Coordinates, stores, notifies. Cannot authorize broadening without the owner key. Not in the traffic path. |
| Endpoint enforcer (`moatd`, `MoatFilter`) | Trusted to enforce and to report receipts within its advertised capabilities. |
| Protected launcher (`moat-launch`) | Trusted to create the boundary before exec and to report session lifecycle. |
| Agents, coding tools, MCP servers, package installers, generated programs | **Untrusted.** May be prompt-injected or compromised. |
| DNS resolver (AdGuard Home / Pi-hole) | Trusted only for DNS observations from cooperative clients. Read-only adapters. |
| Digital Kingdom | A downstream consumer. Moat is registered as one `agent_observer` source and may only report its own endpoints' decisions (W16). |
| GitHub Actions / Sigstore (release pipeline) | Trusted to say which workflow built which bytes (W15). **Not** policy authority; the owner policy key never enters CI. |
| Root, the kernel, a compromised administrator | Outside the initial claim. |

## Threats and what Moat does

| Threat or condition | What Moat does (evidence) | Limit (stated, not hidden) |
| --- | --- | --- |
| Unprivileged app or agent attempts a disallowed external connection | Native policy blocks supported flows; a protected session strengthens descendant coverage (Linux netns, macOS component tests). | Never run on Omarchy or a signed Mac. Platform blind spots, failure behavior and broker access are disclosed. |
| Agent spawns curl, a shell or generated code | Linux: inherited cgroup session policy with the boundary established before exec (`privileged.rs`, netns). | macOS: no ancestry without Endpoint Security ([#3](https://github.com/robzilla1738/moat/issues/3)); rules match the socket-owning app. Parent-name matching is never used as proof. |
| **Contained caller asks Moat for a looser session** | Caller identity comes from the kernel; a caller inside a session may only relaunch its own profile; raw and pre-opened control-socket requests are judged by the real sender (W04, #20; netns `W04:` checks). | External brokers (docker, ssh-agent) are outside the claim. |
| Agent asks a broker (browser, Docker, SSH agent, D-Bus, MCP server) to act | Linux sessions hide broker sockets in a private mount namespace; `--allow-brokers` weakens this explicitly. | Abstract Unix sockets, the system resolver and loopback services remain brokers. SSH and browser-automation cases are device-only rows. |
| Prompt injection or compromised dependency uses an **allowed** destination | Restricts destinations; service and workflow packs keep allowlists explicit. | Not DLP. An allowed GitHub/npm/model API can carry data. Needs credential, filesystem and API controls. |
| **DNS used to leak a name before a deny** | Session proxy asks the policy first and makes no lookup for a name no rule can allow (W05, #22; netns "W05: no DNS query left the host for a forbidden name"). | A profile whose address rules could allow any address still has to resolve (recorded as `address_rules_exposure`). The workload's own resolver traffic is governed by its DNS rules. |
| Session workload lies in the SNI, `CONNECT` or `Host` to reach an allowed name's address space | The proxy resolves the name itself and connects only to what it resolved; resolved addresses are evaluated too, so safety rules still win; a visible `CONNECT` host vs SNI mismatch is refused (#46). | Fronting through an **encrypted** Host behind an allowed SNI (reaches only that name's own server); a hostile resolver; ECH (outer name only). UDP has no hostname evidence. |
| Admitted stream outlives its permission | Open proxied streams are re-checked and ended on expiry, a narrowing revision, isolation, task end and daemon stop (W05; measured delays in linux-endpoint 40537109945). | Bounded by one tick plus socket buffers, not zero. Direct nftables flows stall rather than close. macOS has no existing-flow revocation claim. |
| Session workload borrows another session's proxy (and its grants) | Each session may reach only its own listener; nftables rejects the rest of the proxy port range. | Root can set the upstream mark and bypass it (root is outside the claim). |
| Malicious activity during learning | Captures are bounded to one device, executable identity, workflow and window; candidates list gaps and unknown identity; the owner accepts entry by entry with the owner key; baselines are immutable; drift creates a new candidate (W14, #43, #61). | Observation is not containment and records attacker behavior as "normal". No capture from a real device yet; alert volume unmeasured. |
| Agent edits policy, reports "blocked", or forges an outcome downstream | Signed snapshots; broadening needs the owner key; the conservative structured diff treats anything it cannot prove narrowing as broadening (W02, #16); producer authority (`authority.rs`) lets self-reports assert intent only; the DK feed re-checks authority before sending (`authorityProblem`). | A compromised signer or owner device is outside the claim. |
| Stale, replayed or re-scoped approval ("allow once") | Grants carry exact device, task/executable, destination, transport and port, are bound to the base policy digest and the incident/revision the owner saw, and are idempotent per key (W03, #15, #17). A stale approval is refused with 409. | Only bounded grants; process-generation grants are refused because no endpoint enforces them. |
| Replayed or downgraded snapshot | Replay protection by revision with an independent, never-lowered high-water mark that survives rollback and corrupt state (W06; `corrupt_replay_mark_falls_back_to_the_journal_copy`); platform and device-target checks. | Losing every copy of the mark at once is outside the claim. |
| **Persistence failure presented as durable activation** | Linux journals every step before it changes enforcement and reports `not durable` (W06, #23; real disk-full episode in CI netns). macOS never reports a failed write as durable (W07, #19). | No power-loss test on real storage. |
| Broad revision locks the owner out | Trial/canary revisions revert to the last confirmed revision unless confirmed locally; the first revision cannot be a trial on either platform (Linux W06, macOS #62); isolation untouched. | Linux countdown needs `moatd` running; a stopped daemon reverts at its next start. |
| Daemon restart while sessions run | Sessions are stopped and reported `session_not_adopted`, never re-attached with a changed boundary (W06). | Restart ends agent runs ([#55](https://github.com/robzilla1738/moat/issues/55)). |
| Offline endpoint and controller disagree | Contiguous acks with declared gaps; a local owner change made offline holds fleet distribution to that device until the owner resolves it (W13, #42). | Component tests only; no two real endpoints through an outage. |
| Notification routes the owner to the wrong incident, or floods them into approving | References are opaque and bound to one incident (W08, #14); unchanged incidents notify once and bursts collapse into one summary per window (#60). Acknowledging or muting never allows anything. | Interruption rate unmeasured on real use. |
| Root/kernel compromise, or the user disables protection | Detect/report where feasible (coverage *degraded*, table restoration on Linux, filter-off reporting on macOS). | Not an EDR or anti-tamper system. |
| Controller unavailable | Endpoints keep the last valid policy and spool locally; the sync agent resends everything above the controller's acknowledgement. | Fleet changes, remote actions and search are delayed. |
| Tampered release artifact | `SHA256SUMS`, keyless Sigstore signature, per-asset build-provenance attestations, SBOM coverage gate (W15, #50; release 40569608036). | Integrity metadata, not policy authority. No Developer ID, notarization or signed Arch package. |
| Remote/cloud agent execution | — | Local endpoints see only the connection to the provider. |
| Shared host: untrusted inference on the mini beside the controller | Separate service identities for controller and signer; authenticated admin endpoints (localhost is not trusted); safety rule keeps workloads off controller addresses. | Does not defend against a compromised host administrator or kernel. |

## Non-goals

TLS interception, payload inspection, automatic trust promotion, remotely supplied executable responses, model
certification, reversing data already sent, and protecting against the owner's own privileged actions.

## Agent-specific rules

* An agent token can **prepare a diff**; it cannot approve, sign, broaden, grant, or mark anything verified.
* Agent-reported run IDs, intents and environment variables are **hints** until bound by the launcher and OS evidence.
  Agent intent text is not forwarded to Digital Kingdom.
* Signing keys, enrollment and recovery stay out of agent workspaces (`moatctl keygen` warns; the signer runs as its
  own service, `moat-controller signer-serve`).
