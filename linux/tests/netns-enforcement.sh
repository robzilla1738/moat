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
  [[ -f "$WORK/hosts.orig" ]] && cp "$WORK/hosts.orig" /etc/hosts
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
ip -n moat-a addr add 10.77.0.1/24 dev va; ip -n moat-b addr add 10.77.0.2/24 dev vb; ip -n moat-b addr add 10.77.0.3/24 dev vb
ip -n moat-a -6 addr add fd00:77::1/64 dev va nodad; ip -n moat-b -6 addr add fd00:77::2/64 dev vb nodad
for ns in moat-a moat-b; do ip -n $ns link set lo up; done
ip -n moat-a link set va up; ip -n moat-b link set vb up
UDPLOG="$WORK/udp.log"; : > "$UDPLOG"
# TLS lab: one certificate for allowed.lab/denied.lab; real host on .2, an "attacker" on .3 (same name, other body).
openssl req -x509 -newkey rsa:2048 -nodes -days 1 -subj /CN=allowed.lab -addext "subjectAltName=DNS:allowed.lab,DNS:denied.lab" \
  -keyout "$WORK/lab.key" -out "$WORK/lab.crt" >/dev/null 2>&1
cp /etc/hosts "$WORK/hosts.orig"
printf '10.77.0.2 allowed.lab denied.lab\n' >> /etc/hosts
ip netns exec moat-b python3 "$HERE/lab_server.py" "$UDPLOG" "$WORK/lab.crt" "$WORK/lab.key" > "$WORK/server.out" 2>&1 &
SERVER_PID=$!
for _ in $(seq 50); do grep -q ready "$WORK/server.out" 2>/dev/null && break; sleep 0.1; done

# --- signer, policy, daemon ------------------------------------------------------------------------------------
"$BIN/moatctl" keygen --out "$WORK/signer.key" >/dev/null
"$BIN/moatd" --state "$S" trust "$WORK/signer.key.pub" >/dev/null
"$BIN/moatctl" compile "$HERE/lab.toml" --adapter linux --revision 1 -o "$WORK/snap1.json"
"$BIN/moatctl" sign "$WORK/snap1.json" --key "$WORK/signer.key" -o "$WORK/signed1.json"

start_daemon() {
  # Not via the A() function: a backgrounded function is a subshell, and killing it would leave moatd running.
  nsenter --net=/run/netns/moat-a "$BIN/moatd" --state "$S" --socket "$SOCK" run --device-id lab --tick-secs 1 >> "$WORK/moatd.log" 2>&1 &
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

# --- W04: a contained caller cannot obtain a looser session through the control socket ----------------------------
mkdir -p "$WORK/o"; chmod 777 "$WORK/o"
mk nested_broader "MOAT_QUIET=1 $BIN/moat-launch --socket $SOCK --profile lab-allow -- bash $WORK/s/tcp4_8080.sh; [ \$? -eq 126 ] && exit 7; exit 0"
mk nested_same "MOAT_QUIET=1 $BIN/moat-launch --socket $SOCK --profile lab-allow -- bash $WORK/s/tcp4_8080.sh"
cat > "$WORK/s/raw_launch.py" <<PY
import json, socket, sys
fd = int(sys.argv[1]) if len(sys.argv) > 1 else -1
if fd >= 0:
    s = socket.socket(fileno=fd)
else:
    s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM); s.connect("$SOCK")
s.sendall((json.dumps({"op": "launch", "profile": "lab-allow", "argv": ["/bin/true"], "cwd": "/", "isolate_brokers": False}) + "\n").encode())
reply = s.recv(65536).decode()
print(reply)
sys.exit(7 if '"refused"' in reply else 0)
PY
chmod 644 "$WORK/s/raw_launch.py"
mk raw_from_inside "python3 $WORK/s/raw_launch.py"
mk preopened_inside "python3 $WORK/s/raw_launch.py 0"
cat > "$WORK/s/preopen.py" <<PY
import socket, subprocess, sys
s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM); s.connect("$SOCK")
# the connection is opened OUTSIDE any session, then handed to a lab-deny workload as its stdin
r = subprocess.run(["$BIN/moat-launch", "--socket", "$SOCK", "--profile", "lab-deny", "--no-pty", "--", "bash", "$WORK/s/preopened_inside.sh"], stdin=s.fileno(), env={"MOAT_QUIET": "1", "PATH": "/usr/bin:/bin"})
sys.exit(r.returncode)
PY
chmod 644 "$WORK/s/preopen.py"
expect "W04: lab-deny workload cannot launch a lab-allow session via moat-launch" blocked "$(launch lab-deny nested_broader)"
expect "W04: nested launch with the same profile is allowed (and keeps that profile)" 0 "$(launch lab-allow nested_same)"
expect "W04: raw control-socket request from inside lab-deny refused" blocked "$(launch lab-deny raw_from_inside)"
P=$(as_nobody "python3 $WORK/s/preopen.py" >/dev/null 2>&1 && echo 0 || echo $?)
expect "W04: pre-opened outside connection used from inside lab-deny refused" 7 "$P"
grep -q 'cannot start a session with another profile' "$WORK/moatd.log" "$S"/spool* 2>/dev/null || true
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

# --- PTY proxy: interactive programs get their own controlling terminal and are its foreground group --------------
if command -v script >/dev/null && command -v ps >/dev/null; then
  mk pty_fg 'test -t 0 && [ "$(ps -o tpgid= -p $$ | tr -d " ")" = "$(ps -o pgid= -p $$ | tr -d " ")" ]'
  pty_launch() { as_nobody "script -qec 'MOAT_QUIET=1 $BIN/moat-launch --socket $SOCK --profile lab-deny $1 -- bash $WORK/s/pty_fg.sh' /dev/null" >/dev/null 2>&1 && echo 0 || echo $?; }
  expect "--pty: workload owns a controlling terminal and is its foreground group" 0 "$(pty_launch --pty)"
  expect "--no-pty: workload is not the terminal's foreground group (documented limitation)" blocked "$(pty_launch --no-pty)"
else
  echo "SKIP  PTY proxy checks (script/ps not installed)"
fi

# --- timed trial (canary) rollback ------------------------------------------------------------------------------
"$BIN/moatctl" compile "$HERE/lab-broken.toml" --adapter linux --revision 3 -o "$WORK/snap3.json"
"$BIN/moatctl" sign "$WORK/snap3.json" --key "$WORK/signer.key" -o "$WORK/signed3.json"
"$BIN/moatd" --state "$S" apply "$WORK/signed3.json" --trial-secs 6 >/dev/null
wait_for '.revision == 3 and .trial.revision == 3 and .trial.fallback_revision == 2' && ok "broken revision 3 installed on a 6s trial" || bad "trial started"
expect "trial revision is really enforced (lab-allow LAN now blocked)" blocked "$(launch lab-allow tcp4_8080)"
wait_for '.revision == 2 and .trial == null' && ok "unconfirmed trial reverted to revision 2 on its own" || bad "trial reverted"
expect "after rollback lab-allow reaches LAN again" 0 "$(launch lab-allow tcp4_8080)"
"$BIN/moatd" --state "$S" apply "$WORK/signed3.json" >/dev/null
wait_for '.last_rejection != null and (.last_rejection | test("not newer|replay"))' && ok "reverted revision 3 cannot be replayed" || bad "replay after rollback"
"$BIN/moatctl" compile "$HERE/lab.toml" --adapter linux --revision 4 -o "$WORK/snap4.json"
"$BIN/moatctl" sign "$WORK/snap4.json" --key "$WORK/signer.key" -o "$WORK/signed4.json"
"$BIN/moatd" --state "$S" apply "$WORK/signed4.json" --trial-secs 30 >/dev/null
wait_for '.revision == 4 and .trial.revision == 4' && ok "revision 4 on trial" || bad "revision 4 trial"
A "$BIN/moatd" --state "$S" recover confirm >/dev/null
wait_for '.revision == 4 and .trial == null' && ok "local confirm keeps revision 4" || bad "confirm"

# --- session egress proxy: hostname rules for TCP, no TLS interception -------------------------------------------
mkdir -p "$WORK/o"; chmod 777 "$WORK/o"
C="curl -sk --max-time 5"
mk sni_allowed "$C --noproxy '*' -o $WORK/o/sni_allowed https://allowed.lab:8443/ && grep -q lab-tls-real $WORK/o/sni_allowed"
mk sni_denied "$C --noproxy '*' https://denied.lab:8443/"
mk sni_spoof "$C --noproxy '*' --resolve allowed.lab:8443:10.77.0.3 -o $WORK/o/sni_spoof https://allowed.lab:8443/; cat $WORK/o/sni_spoof"
mk connect_allowed "test -n \"\$HTTPS_PROXY\" && $C -o $WORK/o/connect https://allowed.lab:8443/ && grep -q lab-tls-real $WORK/o/connect"
mk connect_denied "$C -f https://denied.lab:8443/"
mk http_allowed "curl -s --max-time 5 --noproxy '*' -f http://allowed.lab:8081/ | grep -q lab-http"
mk http_denied "curl -s --max-time 5 --noproxy '*' -o $WORK/o/http_denied -w '%{http_code}' http://denied.lab:8081/ | grep -q 403"
mk ip_no_sni "$C --noproxy '*' https://10.77.0.2:8443/"
mk hold "sleep 6"
wait_for '.proxied_profiles == ["lab-hosts"]' && ok "lab-hosts is the only proxied profile" || bad "proxied profiles"
expect "proxy: TLS SNI allowed.lab reaches the real host (transparent redirect)" 0 "$(launch lab-hosts sni_allowed)"
expect "proxy: TLS SNI denied.lab blocked" blocked "$(launch lab-hosts sni_denied)"
as_nobody "MOAT_QUIET=1 $BIN/moat-launch --socket $SOCK --profile lab-hosts -- bash $WORK/s/sni_spoof.sh" > "$WORK/spoof.out" 2>/dev/null || true
grep -q lab-tls-real "$WORK/spoof.out" && ! grep -q lab-tls-evil "$WORK/spoof.out" \
  && ok "proxy: spoofed SNI to another IP still reaches the resolved host, never the dialed one" || bad "SNI spoof ($(cat "$WORK/spoof.out"))"
expect "proxy: CONNECT via injected HTTPS_PROXY allowed" 0 "$(launch lab-hosts connect_allowed)"
expect "proxy: CONNECT to denied.lab refused" blocked "$(launch lab-hosts connect_denied)"
expect "proxy: plain HTTP Host allowed.lab allowed" 0 "$(launch lab-hosts http_allowed)"
expect "proxy: plain HTTP Host denied.lab answered 403 by the proxy" 0 "$(launch lab-hosts http_denied)"
expect "proxy: TLS to a bare IP (no SNI) blocked" blocked "$(launch lab-hosts ip_no_sni)"
as_nobody "MOAT_QUIET=1 $BIN/moat-launch --socket $SOCK --profile lab-hosts -- bash $WORK/s/hold.sh" >/dev/null 2>&1 &
HOLD=$!
wait_for '.egress_proxy | length == 1' || true
PPORT=$(status | jq -r '.egress_proxy | to_entries[0].value')
mk fence "$(tcp 127.0.0.1 "$PPORT")"
[[ "$PPORT" =~ ^[0-9]+$ ]] && expect "another process cannot use a session's proxy listener" blocked "$(plain fence)" || bad "proxy port not reported"
wait "$HOLD" 2>/dev/null || true
A nft list table inet moat > "$WORK/ruleset-proxy.txt" 2>&1 || true

# --- restart: controller-free operation -------------------------------------------------------------------------
kill "$DAEMON_PID"; wait "$DAEMON_PID" 2>/dev/null || true
if pgrep -f "moatd --state $S" >/dev/null; then bad "daemon stopped before restart"; pkill -f "moatd --state $S"; sleep 0.5; fi
start_daemon
wait_for '.revision == 4 and .enforcement_active' && ok "restart restores last valid policy offline" || bad "restart restore"
expect "lab-deny still blocked after restart" blocked "$(launch lab-deny tcp4_8080)"

# --- spool ------------------------------------------------------------------------------------------------------
SP=$(cat "$S"/spool/seg-*.jsonl)
echo "$SP" | jq -s -e 'map(.event.type) | (index("session_started") != null) and (index("policy_applied") != null) and (index("restart") != null) and (index("session_launch_refused") != null)' >/dev/null \
  && ok "spool has sessions, receipts, refusals and restart markers" || bad "spool contents"
echo "$SP" | jq -s -e 'map(.event.type) | (index("policy_trial_started") != null) and (index("policy_rolled_back") != null) and (index("policy_trial_confirmed") != null)' >/dev/null \
  && ok "spool records trial start, rollback and confirm" || bad "trial events in spool"
echo "$SP" | jq -s -e '[.[] | select(.event.type == "flow") | .event] | (map(select(.attempt.hostname.source == "sni" and .decision.verdict == "allow")) | length > 0) and (map(select(.attempt.hostname.source == "connect_proxy")) | length > 0) and (map(select(.decision.verdict == "deny")) | length > 0) and (map(select(.attempt.client_dialed == "10.77.0.3:8443")) | length > 0)' >/dev/null \
  && ok "spool records proxy decisions with hostname source and the dialed address" || bad "proxy flow events in spool"
echo "$SP" | jq -s -e '[.[].seq] as $s | ($s == ($s | sort)) and ($s | length) == ($s | unique | length)' >/dev/null \
  && ok "spool sequence monotonic and unique" || bad "spool sequence"
echo "$SP" | jq -s -e '[.[] | select(.event.type == "restart")] | last | .event.clean_shutdown == true' >/dev/null \
  && ok "SIGTERM recorded as a clean shutdown" || bad "clean shutdown marker"

echo "----"
echo "netns enforcement: $PASS passed, $FAIL failed"
if [[ $FAIL -gt 0 ]]; then
  echo "--- ruleset"; cat "$WORK/ruleset.txt"; echo "--- ruleset with a proxied session"; cat "$WORK/ruleset-proxy.txt" 2>/dev/null
  echo "--- moatd log"; cat "$WORK/moatd.log"; echo "--- proxy flows"; cat "$S"/spool/seg-*.jsonl | jq -c 'select(.event.type == "flow") | .event | {h: .attempt.hostname, ip: .attempt.remote_ip, d: .decision.summary}' 2>/dev/null | tail -20
  exit 1
fi
