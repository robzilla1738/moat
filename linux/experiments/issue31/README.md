# Issue #31: "W05: stream survived isolation" (root cause)

`exp.sh` reproduces the failing order outside Moat: a nobody-owned client connects to 10.77.0.2:8444, nft
`redirect` sends it to a local proxy on 127.0.0.1:15000, the isolation table (`oif lo accept; reject`) goes in, then
the proxy shuts both sockets. Run as root on a host with nf_tables (`FIXLINE=...` adds the fix line).

Measured on ubuntu-latest (scratch runs 40552513209 and the run for 4208c96, 2026-10-27):

* `nft monitor trace`: every client→proxy packet of the redirected connection is seen in the output hook with
  `oif "va"` and `ip daddr 127.0.0.1` (conntrack `dnat`), so `oif lo accept` misses it and the reject drops it.
  Proxy→client packets are `oif "lo"` and pass.
* Without the fix the proxy sits in FIN-WAIT-1 with unacknowledged data and `notsent` bytes; its FIN is queued
  behind them and never sent. The client never sees EOF (`client done lines 12`, no EOF in 12 s).
* With `ip daddr 127.0.0.0/8 ct status dnat accept`: `client EOF` 0.0002 s after the proxy shut the sockets.

In the netns test this happened only when the daemon's 1 s tick ended the stream *after* `recover isolate` had
installed the table (it saves the state file first, then the table), hence the intermittency. The fix is in
`render_local_emergency` (moatd/src/nft.rs). The netns test reproduces the failing condition on every run: the
rules `recover isolate` installs (`moatd render-isolation`, under a probe table name moatd does not manage) are in the
kernel while the stream flows for 1.5 s, then isolation is requested; the 3 s bound is unchanged.

A first version of the test paused moatd with SIGSTOP across `recover isolate`. A negative control (draft PR #39:
that test against the unfixed renderer) still passed, because the pause also stopped the proxy's pump threads, so
no data was in flight. That version did not reproduce the failure and was replaced; the negative control was re-run
against the replacement (see PR #40's description for the run).
