#!/usr/bin/env bash
# Real enforcement test for moatd on Linux: network namespaces + veth + nftables + cgroup v2.
#
#   sudo REQUIRE_NFT=1 linux/tests/netns-enforcement.sh target/debug
#
# Needs: root, nf_tables, cgroup v2, iproute2, python3, jq. Without nf_tables it prints SKIP and exits 0 unless
# REQUIRE_NFT=1 (CI sets it). Everything it creates is torn down on exit.
set -euo pipefail
BIN_SRC=$(cd "${1:-target/debug}" && pwd)
HERE=$(cd "$(dirname "$0")" && pwd)
if ! nft list tables >/dev/null 2>&1; then
  echo "SKIP: nf_tables is not usable on this kernel"
  [[ "${REQUIRE_NFT:-0}" == "1" ]] && exit 1 || exit 0
fi
[[ -f /sys/fs/cgroup/cgroup.controllers ]] || { echo "FAIL: cgroup v2 required"; exit 1; }

WORK=$(mktemp -d /tmp/moat-lab.XXXX)
chmod 755 "$WORK"
S="$WORK/state"; SOCK="$WORK/ctl.sock"; BIN="$WORK/bin"
mkdir -p "$S" "$BIN"
install -m 755 "$BIN_SRC/moatd" "$BIN_SRC/moat-launch" "$BIN_SRC/moatctl" "$BIN/"
PASS=0; FAIL=0
DAEMON_PID=""; SERVER_PID=""

cleanup() {
  set +e
  [[ -n "$DAEMON_PID" ]] && kill "$DAEMON_PID" 2>/dev/null
  [[ -n "$SERVER_PID" ]] && kill "$SERVER_PID" 2>/dev/null
  sleep 0.3
  ip netns del moat-a 2>/dev/null; ip netns del moat-b 2>/dev/null
  for d in /sys/fs/cgroup/moat.slice/p-*/s-*; do [[ -d "$d" ]] && echo 1 > "$d/cgroup.kill" 2>/dev/null; rmdir "$d" 2>/dev/null; done
  rmdir /sys/fs/cgroup/moat.slice/p-* /sys/fs/cgroup/moat.slice 2>/dev/null
  rm -rf "$WORK"
}
trap cleanup EXIT

ok()   { echo "PASS  $1"; PASS=$((PASS+1)); }
bad()  { echo "FAIL  $1"; FAIL=$((FAIL+1)); }
# nsenter switches only the network namespace. (`ip netns exec` also remounts /sys, which hides the cgroup v2
# mount that moatd and nftables' cgroupv2 path lookup need.)
A()    { nsenter --net=/run/netns/moat-a "$@"; }
as_nobody() { A runuser -u nobody -- env -i PATH=/usr/bin:/bin bash -c "cd / && $1"; }
mk() { # name, script body → script file readable by nobody
  mkdir -p "$WORK/s"; printf '%s\n' "$2" > "$WORK/s/$1.sh"; chmod 755 "$WORK/s" "$WORK/s/$1.sh"
}
launch() { # profile, script name → exit code of moat-launch
  as_nobody "MOAT_QUIET=1 $BIN/moat-launch --socket $SOCK --profile $1 -- bash $WORK/s/$2.sh" >/dev/null 2>&1 && echo 0 || echo $?
}
plain() { # script name → exit code, run as nobody without a session
  as_nobody "bash $WORK/s/$1.sh" >/dev/null 2>&1 && echo 0 || echo 1
}
expect() { # name, want(0|blocked|126), got.  "blocked" = the session ran (not refused: 125/126) and failed.
  if [[ "$2" == "blocked" ]]; then
    if [[ "$3" != "0" && "$3" != "125" && "$3" != "126" ]]; then ok "$1"; else bad "$1 (want blocked, got $3)"; fi
  elif [[ "$2" == "$3" ]]; then ok "$1"; else bad "$1 (want $2, got $3)"; fi
}
tcp() { echo "timeout 3 bash -c 'echo hi > /dev/tcp/$1/$2'"; }

# --- lab network -----------------------------------------------------------------------------------------------
ip netns add moat-a; ip netns add moat-b
ip link add va type veth peer name vb
ip link set va netns moat-a; ip link set vb netns moat-b
ip -n moat-a addr add 10.77.0.1/24 dev va; ip -n moat-b addr add 10.77.0.2/24 dev vb
ip -n moat-a -6 addr add fd00:77::1/64 dev va nodad; ip -n moat-b -6 addr add fd00:77::2/64 dev vb nodad
for ns in moat-a moat-b; do ip -n $ns link set lo up; done
ip -n moat-a link set va up; ip -n moat-b link set vb up
UDPLOG="$WORK/udp.log"; : > "$UDPLOG"
ip netns exec moat-b python3 "$HERE/lab_server.py" "$UDPLOG" > "$WORK/server.out" 2>&1 &
SERVER_PID=$!
for _ in $(seq 50); do grep -q ready "$WORK/server.out" 2>/dev/null && break; sleep 0.1; done

# --- signer, policy, daemon ------------------------------------------------------------------------------------
"$BIN/moatctl" keygen --out "$WORK/signer.key" >/dev/null
"$BIN/moatd" --state "$S" trust "$WORK/signer.key.pub" >/dev/null
"$BIN/moatctl" compile "$HERE/lab.toml" --adapter linux --revision 1 -o "$WORK/snap1.json"
"$BIN/moatctl" sign "$WORK/snap1.json" --key "$WORK/signer.key" -o "$WORK/signed1.json"

start_daemon() {
  A "$BIN/moatd" --state "$S" --socket "$SOCK" run --device-id lab --tick-secs 1 > "$WORK/moatd.log" 2>&1 &
  DAEMON_PID=$!
  for _ in $(seq 50); do [[ -S "$SOCK" ]] && break; sleep 0.1; done
}
status() { "$BIN/moatd" --socket "$SOCK" status; }
wait_for() { # jq expression that must become true
  for _ in $(seq 60); do status 2>/dev/null | jq -e "$1" >/dev/null 2>&1 && return 0; sleep 0.25; done; return 1
}

mk tcp4_8080 "$(tcp 10.77.0.2 8080)"
mk tcp6_8080 "$(tcp fd00:77::2 8080)"
mk tcp4_9090 "$(tcp 10.77.0.2 9090)"
mk grandchild "bash -c \"sh -c \\\"bash $WORK/s/tcp4_8080.sh\\\"\""
mk escape "echo \$\$ > /sys/fs/cgroup/cgroup.procs 2>/dev/null; echo \$\$ > /sys/fs/cgroup/moat.slice/cgroup.procs 2>/dev/null; $(tcp 10.77.0.2 8080)"
mk udp_session "echo session-udp > /dev/udp/10.77.0.2/5353"
mk udp_plain "echo ordinary-udp > /dev/udp/10.77.0.2/5353"
mk noop "true"

start_daemon
expect "no policy: protected launch refused" 126 "$(launch lab-allow tcp4_8080)"
"$BIN/moatd" --state "$S" apply "$WORK/signed1.json" >/dev/null
wait_for '.revision == 1 and .enforcement_active' && ok "revision 1 applied and enforced" || { bad "revision 1 applied"; cat "$WORK/moatd.log"; status || true; }
A nft list table inet moat > "$WORK/ruleset.txt" 2>&1 || true

# --- enforcement ------------------------------------------------------------------------------------------------
expect "ordinary app (observed) reaches 10.77.0.2:8080" 0 "$(plain tcp4_8080)"
expect "lab-allow session reaches LAN 8080" 0 "$(launch lab-allow tcp4_8080)"
expect "lab-allow session reaches IPv6 ULA 8080" 0 "$(launch lab-allow tcp6_8080)"
expect "safety rule beats LAN allow (9090 blocked)" blocked "$(launch lab-allow tcp4_9090)"
expect "lab-deny session blocked" blocked "$(launch lab-deny tcp4_8080)"
expect "lab-allow grandchild still allowed (inheritance)" 0 "$(launch lab-allow grandchild)"
expect "lab-deny grandchild blocked (inheritance)" blocked "$(launch lab-deny grandchild)"
expect "escape attempt fails and stays blocked" blocked "$(launch lab-deny escape)"
expect "unknown profile refused" 126 "$(launch no-such-profile noop)"

expect "lab-allow UDP send blocked (tcp-only allow)" blocked "$(launch lab-allow udp_session)"
plain udp_plain >/dev/null || true
sleep 0.5
grep -q ordinary-udp "$UDPLOG" && ok "ordinary UDP delivered (observed)" || bad "ordinary UDP delivered"
grep -q session-udp "$UDPLOG" && bad "session UDP datagram must not arrive" || ok "session UDP datagram did not arrive"

# --- replay and malformed policy --------------------------------------------------------------------------------
"$BIN/moatd" --state "$S" apply "$WORK/signed1.json" >/dev/null
wait_for '.last_rejection != null and (.last_rejection | test("replay|revision"))' && ok "replayed revision rejected" || bad "replayed revision rejected"
wait_for '.revision == 1 and .enforcement_active' && ok "previous revision kept" || bad "previous revision kept"

# --- local recovery ---------------------------------------------------------------------------------------------
A "$BIN/moatd" --state "$S" recover disable --reason "lab" >/dev/null
wait_for '.enforcement_disabled_locally' && ok "local disable recorded" || bad "local disable recorded"
expect "protected launch refused while disabled" 126 "$(launch lab-allow tcp4_8080)"
A "$BIN/moatd" --state "$S" recover resume >/dev/null
wait_for '.enforcement_active and (.enforcement_disabled_locally|not)' && ok "resume re-enforces last policy" || bad "resume"
expect "lab-deny blocked again after resume" blocked "$(launch lab-deny tcp4_8080)"

A "$BIN/moatd" --state "$S" recover isolate >/dev/null
expect "isolation blocks ordinary traffic" blocked "$(plain tcp4_8080)"
"$BIN/moatctl" compile "$HERE/lab.toml" --adapter linux --revision 2 -o "$WORK/snap2.json"
"$BIN/moatctl" sign "$WORK/snap2.json" --key "$WORK/signer.key" -o "$WORK/signed2.json"
"$BIN/moatd" --state "$S" apply "$WORK/signed2.json" >/dev/null
wait_for '.revision == 2' && ok "new revision accepted during isolation" || bad "revision 2"
expect "isolation survives a new policy" blocked "$(plain tcp4_8080)"
A "$BIN/moatd" --state "$S" recover clear-isolation >/dev/null
wait_for '.isolation_active | not' || true
expect "clear-isolation reopens ordinary traffic" 0 "$(plain tcp4_8080)"

# --- restart: controller-free operation -------------------------------------------------------------------------
kill "$DAEMON_PID"; wait "$DAEMON_PID" 2>/dev/null || true
start_daemon
wait_for '.revision == 2 and .enforcement_active' && ok "restart restores last valid policy offline" || bad "restart restore"
expect "lab-deny still blocked after restart" blocked "$(launch lab-deny tcp4_8080)"

# --- spool ------------------------------------------------------------------------------------------------------
SP=$(cat "$S"/spool/seg-*.jsonl)
echo "$SP" | jq -s -e 'map(.event.type) | (index("session_started") != null) and (index("policy_applied") != null) and (index("restart") != null) and (index("session_launch_refused") != null)' >/dev/null \
  && ok "spool has sessions, receipts, refusals and restart markers" || bad "spool contents"
echo "$SP" | jq -s -e '[.[].seq] as $s | ($s == ($s | sort)) and ($s | length) == ($s | unique | length)' >/dev/null \
  && ok "spool sequence monotonic and unique" || bad "spool sequence"

echo "----"
echo "netns enforcement: $PASS passed, $FAIL failed"
if [[ $FAIL -gt 0 ]]; then echo "--- ruleset"; cat "$WORK/ruleset.txt"; echo "--- moatd log"; cat "$WORK/moatd.log"; exit 1; fi
