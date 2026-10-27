# Adversarial regression matrix (MASTER_ROADMAP §15.2)

Every required case from §15.2, mapped to the test that exercises it, the environment it runs in, and what is still
missing. The machine-readable copy is the `adversarial_matrix` array in [`claim-ledger.json`](claim-ledger.json),
checked by `core/moat-core/tests/claim_ledger.rs` (every row has a status; every `ci` row names at least one test;
every named unit test exists in the source tree).

Status:

* **ci**: runs on every PR. Environments: `unit` (cargo test), `ci-netns` (linux-endpoint job, real nftables and
  cgroup v2 in network namespaces on a GitHub runner), `ci-installed` (packaged systemd unit on a GitHub runner),
  `ci-node` (controller tests), `ci-macos` (unsigned macOS build/tests).
* **gap**: could run in CI but no test exists yet. Owner named. Nothing in a gap row may be claimed.
* **device**: needs real hardware, a signed install, a real VPN/app or a real network; listed here so it is not
  forgotten and never claimed from CI. These are on the "Needs Robert" list in [STATUS](STATUS.md).

Netns check names are the exact `PASS` strings printed by `linux/tests/netns-enforcement.sh` (prefix `netns:`),
`linux/tests/installed-unit.sh` (prefix `installed:`) and `linux/tests/ordinary-inventory.sh` (prefix `inventory:`).
Unit tests are Rust test function names.

## Subject / authority

| Case | Status | Tests | Notes |
| --- | --- | --- | --- |
| Same executable on two devices | ci (unit) | `same_executable_on_two_devices_does_not_share_a_grant`, `same_executable_on_two_devices_are_different_grants`, `a_device_targeted_snapshot_installs_only_on_a_named_device` | Grant scope and targeted snapshots. |
| Reused PID / task ID | ci (unit) | `pid_reuse_is_a_different_instance`, `restarted_process_cannot_reuse_a_process_grant`, `task_grant_is_bound_to_device_and_task` | Inventory identities carry start generation (`a_new_connection_is_reported_once_with_its_process_identity`). |
| Process restart | ci (unit) | `restarted_process_cannot_reuse_a_process_grant` | |
| Fake agent label | ci (unit) | `agents_cannot_assert_blocks_or_authorize`, `unverified_session_does_not_get_session_rules`, conformance `unverified-session-is-a-hint` | A label is a hint, never authority. |
| Weaker nested launch | ci (unit + ci-netns + ci-installed) | `contained_callers_cannot_broaden`; netns `blocked $(launch lab-deny nested_broader)`; installed `containment: a nested launch of the broader w11-open profile is refused` | |
| Raw / pre-opened control socket | ci (unit + ci-netns) | `pre_opened_connections_are_judged_by_the_sender`, `raw_writes_still_carry_kernel_credentials`, `peer_credentials_are_kernel_supplied`; netns `blocked $(launch lab-deny raw_from_inside)` | |

## Policy semantics

| Case | Status | Tests | Notes |
| --- | --- | --- | --- |
| Profile overlap / order | ci (unit) | `reordering_selectable_profiles_with_different_defaults_is_broadening`, `generator_produces_both_broadening_and_safe_changes` (differential) | |
| Timed denies | ci (unit) | `shortening_a_deny_is_broadening`, `expired_rules_are_dropped_and_reported`, `expired_rule_is_ignored` | |
| Defaults | ci (unit) | `ordinary_traffic_follows_fallback_observe`, `deny_everything_else`, `tightening_ordinary_profile_reports_newly_blocked` | |
| Safety / override precedence | ci (unit + conformance) | `safety_deny_precedes_session_allows`, `rejects_override_without_expiry`, conformance `safety-beats-lan-allow`, `safety-beats-tailnet-allow` | |
| Missing identity | ci (unit + ci-netns) | `unknown_parent_is_incomplete`, `a_socket_without_a_visible_owner_is_unknown_not_guessed`, conformance `unknown-session-profile-restrictive` | Unknown never becomes a match. |
| Unsupported capability | ci (unit + conformance) | `unsupported_restrictive_profile_fails_compilation`, `an_unsupported_cell_on_a_targeted_device_is_still_rejected`, conformance `linux-ip-only-rejects-strict-hostname-rules`, `linux-targeted-at-a-mac-device-still-refuses` | |
| Destination-set changes | ci (unit) | `growing_allowed_set_is_broadening`, `previously_ignored_fields_are_classified` | |

## Destinations

| Case | Status | Tests | Notes |
| --- | --- | --- | --- |
| IPv4 / IPv6 | ci (ci-netns) | netns IPv6 and IPv4 allow/deny checks; inventory `IPv6 connection observed`; conformance `coding-ipv6-denied` | |
| Raw IP | ci (ci-netns + conformance) | netns `blocked $(launch lab-hosts ip_no_sni)`; conformance `coding-direct-ip-denied` | |
| DNS before deny | ci (unit + ci-netns) | `a_name_the_policy_refuses_is_never_looked_up`, `arbitrary_names_are_refused_without_lookup_and_agree_with_evaluation`; netns `W05: no DNS query left the host for a forbidden name (CONNECT, SNI, Host)` | |
| Alternate resolver | ci (conformance) | `coding-alternate-resolver-denied` | Direct UDP/53 to a public resolver from a session falls to the deny default. A resolver on an *allowed* IP is allowed by that IP rule (documented). |
| Host / IP mismatch | ci (ci-netns + conformance) | netns `proxy: spoofed SNI to another IP still reaches the resolved host, never the dialed one`; `transparent_sni_connects_to_the_resolved_host_not_the_dialed_ip`; conformance `proxy-sni-resolving-to-controller-denied` | |
| Shared infrastructure | ci (unit + ci-netns) | `a_host_mismatch_inside_a_connect_tunnel_is_refused_before_the_upstream_is_dialed`, `tunnel_mismatch_compares_only_visible_names`; netns `proxy: CONNECT allowed.lab carrying TLS SNI denied.lab is refused (host/SNI mismatch)`, `proxy: CONNECT tunnel whose SNI matches the CONNECT host reaches the real host (control)`, `proxy LIMIT (documented): an encrypted Host behind an allowed SNI reaches only the allowed name's own server` | A visible mismatch (CONNECT host vs TLS SNI or plain-HTTP Host inside the tunnel) is refused before the upstream is dialed. **Limit, shown not fixed:** the HTTP Host inside TLS is invisible without interception, so an allowed SNI with another encrypted Host reaches the allowed name's own server; if that server is shared CDN infrastructure it may route elsewhere. Only the first request's Host is checked on a plain-HTTP keep-alive connection. |
| Redirects | ci (conformance) | `proxy-redirect-target-judged-anew`, `proxy-connect-unlisted-host-denied` | A redirect target is a new connection judged on its own SNI/CONNECT; the allowed origin grants nothing. Live netns redirect: not yet (same code path). |
| Encrypted / absent hostname evidence | ci (unit + ci-netns) | `hostname_rule_without_evidence_notes_it`, conformance `proxy-no-sni-denied`; netns `blocked $(launch lab-hosts ip_no_sni)` | ECH: device (needs a real ECH client). |

## Protocols

| Case | Status | Tests | Notes |
| --- | --- | --- | --- |
| TCP | ci (ci-netns) | netns allow/deny checks, `blocked $(launch lab-deny tcp4_8080)` | |
| UDP / QUIC | ci (ci-netns) for UDP; device for QUIC | netns `session UDP datagram did not arrive`, `ordinary UDP delivered (observed)`; conformance `coding-github-udp-denied` | QUIC to real services: device. Session hostname rules are TCP-only (UDP denied). |
| IPv6 | ci (ci-netns + conformance) | `inventory: IPv6 connection observed`, `coding-ipv6-denied` | Session IPv6 deny checks are in netns-enforcement.sh. |
| Long-lived TLS / CONNECT / WebSockets | ci (unit + ci-netns) | netns `W05: stream ended at expiry`, `a revision that no longer allows it ends the open stream`, `closing the task ends its streams`, `isolation ends open proxied streams`; `an_admitted_stream_ends_when_its_permission_expires`, `websocket_upgrade_works_through_connect_and_plain_http_and_is_ended_like_any_stream` | WebSocket: the upgrade (101) and masked frames flow both ways through CONNECT and through the transparent plain-HTTP path; a revision without the allow ends the upgraded stream; an upgrade to a refused name is a 403 and never forwarded. In-process proxy with real sockets (unit), not the netns lab; `wss://` is TLS over CONNECT, covered by the stream rows above. |
| Declared unsupported protocols | ci (unit) | `protocol_labels`, `users_ports_transport_render` | SCTP/other transports are not matched by allow rules (fallback applies). |

## Delegation

| Case | Status | Tests | Notes |
| --- | --- | --- | --- |
| SSH | device | none | Agent forwarding and ProxyJump to a real host. Broker sockets are hidden (`brokers_hidden_and_env_stripped`). |
| Browser automation | device | none | A real browser driven over CDP from inside a session. |
| Container / daemon sockets | ci (unit) for hiding; device for Docker | `brokers_hidden_and_env_stripped`, `hidden_paths_respect_flags` | External brokers are outside the protected contract (docs/threat-model.md). |
| Inherited descriptors | ci (unit + ci-netns) | `inherited_descriptors_do_not_cross`, `pre_opened_connections_are_judged_by_the_sender` | Ordinary-app inventory: inherited sockets are attributed to the lowest visible PID holding them (W09 decision). |
| Local proxies | ci (unit + ci-netns) | `session_proxy_redirects_only_its_own_session_and_fences_the_port_range`; netns `blocked $(plain fence)` | |
| Remote jobs | device | none | CI runners / remote builders launched from a session. |

## Lifecycle

| Case | Status | Tests | Notes |
| --- | --- | --- | --- |
| First install | ci (ci-installed) | installed `moatd.service started by systemd`, `installed service enforces revision 1` | Omarchy: device. |
| First canary | ci (unit) | `first_canary_needs_a_fallback_and_writes_nothing`, `first_revision_cannot_be_a_trial` | |
| Expiry | ci (unit + ci-netns) | `expiry_enforced`, `expired_grants_drop_out_of_the_effective_policy`; netns `W05: stream ended at expiry` | |
| Rollback failure | ci (unit) | `a_failed_rollback_is_retried_and_never_becomes_confirmed`, `rollback_intent_is_retained_until_the_restore_is_durable` | |
| Corrupt state | ci (unit) | `corrupt_journal_is_visible_and_never_a_fresh_bootstrap`, `corrupt_replay_mark_falls_back_to_the_journal_copy`, `roundtrip_missing_and_corrupt`, `torn_last_line_is_tolerated` | |
| Disk full | ci (unit + ci-netns) | `every_plain_apply_step_survives_disk_full_failed_rename_and_crash`; netns `W06: disk full: activation refused as not durable`, `W06: disk full: revision 8 stays reported and enforced` | |
| Stopped filter | ci (unit) | `missing_netfilter_downgrades_everything_enforcing`, `degraded_on_problems` | OpenSnitch stop behaviour measured in W09 (decision doc). |
| Daemon crash | ci (unit + ci-netns) | `a_crash_during_rollback_resumes_it_on_restart`, `trial_past_deadline_reverts_on_restart_and_never_touches_isolation`; netns `restart restores last valid policy offline` | SIGKILL mid-apply is in-process fault injection, not a kernel crash. |
| Live-task restart | ci (unit + ci-netns) | `sessions_running_across_a_restart_are_stopped_not_adopted`; netns `W06: sessions from before the restart are stopped (not adopted)` | |

## Distribution

| Case | Status | Tests | Notes |
| --- | --- | --- | --- |
| Duplicate / reordered messages | ci (unit) for replay; gap for controller | `sign_verify_apply_and_replay`, `verify_accepts_trusted_and_rejects_unknown_key_and_replay`; netns `replayed revision rejected` | Controller-side duplicate/reorder: Lane B (W13). |
| Concurrent publication | ci (ci-node) | controller `grants.test.ts` journaled publication (Lane B, #15) | |
| Lost signer response | ci (unit + ci-node) | `retried_request_keeps_the_original_expiry`; controller signer journal tests (Lane B) | |
| Partial rollout | ci (unit) | `summary_lists_unacknowledged` | Real two-endpoint rollout: device (W13). |
| Offline local change | ci (unit + ci-netns) | netns `local disable recorded`, `resume re-enforces last policy`, `restart restores last valid policy offline`; `local_owner_revisions_are_reported_as_local_changes_until_the_fleet_supersedes_them` | Endpoint reports `local_change` (W13); controller hold is Lane B; no real two-endpoint run. |

## Updates

| Case | Status | Tests | Notes |
| --- | --- | --- | --- |
| App / service / extension / schema mismatch | ci (unit) for schema | `fixtures_round_trip_and_rejects_hold` (fixture grant-unknown-version in contracts/fixtures/manifest.json), `rejects_unknown_fields`, `schemas_cover_every_rust_field` | Extension/app version skew: device (signed Mac). |
| Failed upgrade | device | none | Package upgrade on Omarchy and a Mac cask upgrade. |
| Interrupted migration | ci (unit) for version mismatch | `state_left_by_a_newer_schema_is_kept_and_refused_not_reset`, `corrupt_journal_is_visible_and_never_a_fresh_bootstrap` | No on-disk migration exists yet, so a real interrupted migration cannot be tested. Covered: an interrupted upgrade followed by a downgrade leaves state with an unknown schema; it is kept byte for byte, reported as recovery-required, the last verified snapshot stays enforced and the replay mark is honoured. **Limit:** a high-water recorded only inside the unknown journal is not read. Re-open this row when the first migration lands. |
| Trust rotation | ci (unit) | `tampering_and_unknown_keys_rejected` | Revocation of a running key on a real endpoint: device. |
| Authorized recovery downgrade | ci (unit + ci-netns) | `trial_reverts_unless_confirmed_and_replay_mark_holds`; netns `reverted revision 3 cannot be replayed` | |

## Load

| Case | Status | Tests | Notes |
| --- | --- | --- | --- |
| Process / connection churn | ci (ci-netns) | inventory `burst accounted for: … observed + … counted as loss >= … accepted`, `missed short-lived connections are counted` | |
| Sensor map / queue limits | ci (unit + ci-netns) | `missed_short_lived_connections_are_counted_never_silent`, `unreadable_tables_are_reported`; W09 overload scenario (artifact) | |
| Proxy exhaustion | ci (unit) | `exhaustion_refuses_and_reports_rather_than_bypassing` | |
| Slow disk | ci (unit) | `a_slow_disk_delays_activation_but_never_reorders_or_outlives_a_trial_deadline` | Every durable step takes 300 ms: activation still commits only after its durable steps, and a trial whose deadline passes during the slow writes is reverted on the next tick and stays reverted after restart. Spool writes under latency and the daemon's tick loop are not measured. |
| Log quota | ci (unit + ci-netns) | `quota_evicts_the_oldest_unacknowledged_segment_with_an_exact_gap`, `acknowledged_segments_go_first_and_need_no_gap`, `an_event_that_cannot_fit_is_dropped_with_a_gap`, `unexplained_gap_detection`, netns `W13: an acknowledgement beyond what was written is refused` | Bounded by --spool-mib; eviction and drops leave exact gap records. |
| Notification floods | gap | none | Lane B (UI/controller). |

## Compatibility

| Case | Status | Tests | Notes |
| --- | --- | --- | --- |
| Tailscale / Surfshark variants | device | none | docs/vpn-test-matrix.md. |
| Sleep / wake | device | none | |
| Network switch | device | none | |
| Plex / BlueBubbles / SSH | device | none | |
| Actual TV and adb paths | device | none | |

Test active traffic during transitions, not only new connections afterwards: the W05 stream checks and the W06
disk-full episode do that for sessions; ordinary-app enforcement does not exist yet, so there is nothing to test there.
