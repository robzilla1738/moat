# Operational DNS and Digital Kingdom integrations (W16)

Both integrations are optional. Desktop enforcement never depends on them, and Moat does not run its own DNS resolver.

## DNS adapters: AdGuard Home and Pi-hole

Code: `controller/src/resolvers.ts` (adapters), `controller/src/integrations.ts` (wiring), `controller/src/dns.ts`
(DNS-only clients). Tests: `controller/test/resolvers.test.ts` against loopback mock servers
(`controller/test/resolver-mocks.ts`, fixtures in `controller/test/fixtures/`).

| | AdGuard Home | Pi-hole |
| --- | --- | --- |
| Supported versions | v0.107.x (`GET /control/status` → `version`) | FTL v6.x (`GET /api/info/version`) |
| Credential | HTTP basic auth (username + password file) | app password → `POST /api/auth` session id, re-authenticated once on 401 |
| Read | `GET /control/querylog?limit&older_than` | `GET /api/queries?length&start&cursor` |
| Checkpoint | newest query time + every key seen at that instant | newest query id |
| Deduplication | checkpoint + `UNIQUE (resolver, client, name, at)` | checkpoint + unique `(resolver, source_id)` |

Every poll:

1. checks the version first. An unknown or unsupported version (including Pi-hole v5, which has no `/api`) is
   `unsupported_version` and **nothing is read or ingested**;
2. reads at most `max_pages × page_size` entries (defaults 5 × 500), each request with a timeout;
3. stores new observations, declared gaps and the new checkpoint in one transaction, so a crash re-polls from the old
   checkpoint and storage keys absorb the overlap. A restart neither duplicates nor invents events;
4. records gaps instead of skipping silently: history the resolver no longer has (retention, a cleared log), history
   beyond the poll budget, and a Pi-hole database reset (ids going backwards);
5. on failure sets health `auth_failed`, `unreachable` or `error`, backs off exponentially (interval × 2^failures, at
   most 30 min) and marks the resolver's clients not reachable. The last good poll time is kept.

### Configuration

```sh
MOAT_RESOLVERS_FILE=/etc/moat/resolvers.json moat-controller serve
```

```json
[
  { "id": "adguard", "kind": "adguard", "url": "http://192.168.1.2:3000", "username": "moat", "password_file": "/etc/moat/adguard.pw" },
  { "id": "pihole", "kind": "pihole", "url": "http://192.168.1.3", "password_file": "/etc/moat/pihole.app-password", "interval_ms": 30000 }
]
```

Passwords are read from files. They are not stored in the controller database and no API returns them.
Use a Pi-hole **app password** and an AdGuard Home account used only by Moat. These adapters only read. Changing
resolver policy is a separate, separately authorized operation and is not implemented.

### API

* `GET /v1/dns/resolvers` (owner, viewer): kind, version, supported range, health, last good poll, consecutive failures,
  next poll, history start, `evidence_age_s` (computed now from the last good poll) and the 20 newest gaps.
* `POST /v1/dns/resolvers/:id/poll` (owner): poll now.
* `GET /v1/dns/clients` (owner, viewer): each client the resolvers reported, labeled `dns-only`, with resolver health,
  evidence age and recent gaps.

### What DNS evidence is

DNS evidence shows that a client address asked a resolver for a name, and whether the resolver answered or blocked
it. It is never an app, a process, a completed connection or a byte count, and it misses direct-IP traffic and other
encrypted-DNS paths. A blocked query raises a `dns_blocked` incident on the DNS-only client `dns:<resolver>:<client>`,
never on an enrolled endpoint. Only queries stored for the first time raise one, so re-polls do not add occurrences.
The web Devices page shows these clients with resolver health, evidence age, last query and history gaps, and no
flows, processes or bytes. A client whose resolver is failing shows as `unknown`, not `dns-only`.

## Digital Kingdom producer authority

Code: `controller/src/dkfeed.ts`. Moat registers in Digital Kingdom as **one** source of kind `agent_observer`
(`GET /v1/integrations/digital-kingdom` returns the exact registration document to enter in DK):

* assets: `device:<id>` for each enrolled, non-revoked Moat endpoint, and nothing else;
* actions: `tool_invocation`, `sensor_unavailable`, `sensor_restored`;
* one independence group (`moat-endpoints`): Moat is the policy enforcer reporting its own decisions, not an
  independent observer.

Every event is checked against that authority before it leaves (`authorityProblem`) and DK checks it again on ingest:

* only an endpoint's own policy decision (`agent.phase = decision`, `origin = policy_enforcer`) may carry
  `blocked` / `allowed` / `denied` / `success`;
* self-reported agent intent is `tool_invocation` / `unknown` and never carries an outcome. The intent text is not
  sent;
* DNS-only evidence (`dns_blocked`) is not sent. A resolver block is not an endpoint flow decision;
* events for anything that is not an enrolled endpoint are dropped and counted, never sent.

Delivery is at least once. Cursors advance only after DK accepts a batch, and a retry re-sends the same
`source_event_id`s, which DK deduplicates. A 401/403/422 sets health `refused`, and the cursor does not advance.
Configure with `MOAT_DK_URL` and `MOAT_DK_SOURCE_KEY_FILE`. Moat never moves policy signing or a privileged executor
into Digital Kingdom.

## Not yet proven (device-proof list)

* A live AdGuard Home and a live Pi-hole on Robert's network. The fixtures follow the documented API shapes and were
  not captured from a running resolver.
* A real DNS query from the iPhone and the TCL TV reaching the DNS-only view, and the TV workflows.
* A real event-to-investigation round trip into a running Digital Kingdom server.
