# Adversarial-but-benign harness (real devices only)

Probes bypass paths against a **canary destination you control** and records what actually happened on *this*
machine. It refuses to run in CI (`CI` set) or without `MOAT_DEVICE_PROOF=1`, because results from a CI kernel or a
GitHub macOS runner are not evidence about Robert's devices.

Nothing here sends real data: the payload is a random canary token. Nothing promotes trust or edits policy. Results
are written to a JSON file for **human review**; a passing run does not by itself change any claim. Record the outcome
by hand in [`docs/claim-ledger.json`](../../docs/claim-ledger.json) (environment `omarchy-installed` or
`mac-signed-installed`), [docs/STATUS.md](../../docs/STATUS.md), the device rows of the
[adversarial matrix](../../docs/adversarial-matrix.md) and the [compatibility suite](../../docs/compatibility-suite.md).
No run has been recorded yet ([#11](https://github.com/robzilla1738/moat/issues/11)). The CI-side equivalents of
these cases are mapped in the adversarial matrix.

## Setup

1. A canary HTTPS endpoint you own that logs requests (any small server, e.g. a Caddy/nginx access log), reachable
   over IPv4 and IPv6. Put its hostname, IPv4 and IPv6 in the environment below.
2. A signed policy whose profile **denies** the canary (e.g. `coding-session`, which denies unknown egress).
3. Linux: `moatd` running and `moat-launch` installed. macOS: Moat installed with the filter enabled.

```sh
export MOAT_DEVICE_PROOF=1
export CANARY_HOST=canary.example.net CANARY_V4=203.0.113.10 CANARY_V6=2001:db8::10
tests/adversarial/run.sh --profile coding-session --out results-$(hostname)-$(date +%F).json
```

On macOS there are no protected sessions; the harness runs each probe as an ordinary process and you confirm the
verdicts in Moat › Activity. On Linux each probe runs inside `moat-launch --profile <profile>`.

## Cases

| id | probe | expected under a deny profile |
| --- | --- | --- |
| direct-ip-v4 | HTTPS to `CANARY_V4` with SNI | blocked |
| direct-ip-v6 | HTTPS to `[CANARY_V6]` | blocked |
| hostname | HTTPS to `CANARY_HOST` | blocked |
| udp-dns-public | DNS query over UDP to 1.1.1.1:53 | blocked |
| doh | DNS over HTTPS to cloudflare-dns.com | blocked |
| quic | HTTP/3 to `CANARY_HOST` (if curl supports `--http3`) | blocked |
| fork-chain | `sh -c 'sh -c "curl …"'` | blocked |
| detached | `setsid` + background curl after the parent exits | blocked (Linux: torn down at session end) |
| preopened-socket | socket opened **before** launch and inherited | not inherited (Linux) |
| broker-docker | `curl --unix-socket /var/run/docker.sock` | socket hidden (Linux) |
| redirect | allowed host that redirects to the canary | second hop blocked |

After the run, check the canary's access log: **any request carrying the run's token is a bypass** and must be filed.
