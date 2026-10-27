#!/usr/bin/env bash
# W10 increment 2: connect-time attribution (observe-only) via bpftrace, checked against an independent receiver and
# the kernel's own counter.
#
#   sudo linux/tests/ordinary-inventory-ebpf.sh target/debug
#
# Topology: client netns `moatebpf-c` (10.78.0.1, fd78::1) -- veth -- receiver netns `moatebpf-r` (10.78.0.2, fd78::2).
# `moatd inventory --ebpf` runs on the host (the tracepoint sees every namespace). Checks:
#   * processes that connect once and exit at once (invisible to socket-table sampling) are each attributed with the
#     pid they reported themselves, the kernel's uid/comm, and an identity or a stated reason;
#   * a non-root user's connect carries that uid; IPv6 is attributed;
#   * every attributed connect to the receiver is one the receiver accepted (independent evidence);
#   * with a deliberately tiny tracer buffer and a connect flood, attributed + reported loss >= the kernel's own
#     ActiveOpens count for the client namespace: loss is reported, never hidden;
#   * killing the tracer is reported as ebpf_stopped;
#   * nothing is enforced: every record says observe_only and the receiver accepted every connection.
# Needs root, iproute2 and bpftrace. Not the installed unit and not Omarchy.
set -euo pipefail
BIN=$(cd "${1:-target/debug}" && pwd)
BPFTRACE=$(command -v bpftrace) || { echo "FAIL  bpftrace not installed"; exit 1; }
W=$(mktemp -d /tmp/moat-ebpf.XXXX); chmod 755 "$W"
C=moatebpf-c; R=moatebpf-r
inc() { nsenter --net=/run/netns/$C "$@"; }
inr() { nsenter --net=/run/netns/$R "$@"; }
cleanup() {
  set +e
  kill $(jobs -p) 2>/dev/null
  ip netns del $C 2>/dev/null; ip netns del $R 2>/dev/null
  rm -rf "$W"
}
trap cleanup EXIT
"$BPFTRACE" --version

ip netns add $C; ip netns add $R
ip link add moatebpf0 type veth peer name moatebpf1
ip link set moatebpf0 netns $C; ip link set moatebpf1 netns $R
inc ip addr add 10.78.0.1/24 dev moatebpf0; inc ip addr add fd78::1/64 dev moatebpf0 nodad
inr ip addr add 10.78.0.2/24 dev moatebpf1; inr ip addr add fd78::2/64 dev moatebpf1 nodad
inc ip link set lo up; inr ip link set lo up; inc ip link set moatebpf0 up; inr ip link set moatebpf1 up

cat > "$W/recv.py" <<'PY'
import socket, sys, threading, time, json
log = open(sys.argv[1], "a", buffering=1)
def serve(fam, addr, port):
    s = socket.socket(fam, socket.SOCK_STREAM); s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    if fam == socket.AF_INET6: s.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 1)
    s.bind((addr, port)); s.listen(1024)
    while True:
        c, peer = s.accept()
        log.write(json.dumps({"peer": peer[0], "port": peer[1], "local_port": port}) + "\n"); c.close()
for fam, a in ((socket.AF_INET, "10.78.0.2"), (socket.AF_INET6, "fd78::2")):
    threading.Thread(target=serve, args=(fam, a, 7101), daemon=True).start()
print("ready", flush=True)
while True: time.sleep(1)
PY
inr python3 "$W/recv.py" "$W/accepted.jsonl" > "$W/recv.out" 2>&1 &
for _ in $(seq 40); do grep -q ready "$W/recv.out" && break; sleep 0.1; done

wait_attached() { for _ in $(seq 100); do grep -q sensor_attached "$1" 2>/dev/null && return 0; sleep 0.1; done; return 1; }

# --- run 1: attribution of short-lived processes -------------------------------------------------------------------
"$BIN/moatd" inventory --ebpf "$BPFTRACE" --seconds 14 > "$W/run1.jsonl" 2> "$W/run1.err" &
INV=$!
wait_attached "$W/run1.jsonl" || { echo "FAIL  tracer never attached"; cat "$W/run1.err"; exit 1; }
cat > "$W/once.py" <<'PY'
import os, socket, sys
print(os.getpid(), flush=True)
socket.create_connection((sys.argv[1], 7101), timeout=3).close()   # connect once, exit at once
PY
: > "$W/pids"
for i in $(seq 20); do inc python3 "$W/once.py" 10.78.0.2 >> "$W/pids"; done
inc python3 "$W/once.py" fd78::2 >> "$W/pids.v6"
id moatebpfu >/dev/null 2>&1 || useradd -M -s /usr/sbin/nologin moatebpfu
U=$(id -u moatebpfu)
inc setpriv --reuid "$U" --regid "$U" --clear-groups curl -s --max-time 3 http://10.78.0.2:7101/ >/dev/null 2>&1 || true
sleep 2
pkill -f "^$BPFTRACE -e" || pkill -x bpftrace || true   # the tracer dies: must be reported
wait $INV || true

# --- run 2: forced loss (1-page buffer, connect flood) vs the kernel's ActiveOpens --------------------------------
opens() { inc awk '/^Tcp:/ {n++; if (n==1) for (i=1;i<=NF;i++) if ($i=="ActiveOpens") c=i; if (n==2) print $c}' /proc/net/snmp; }
"$BIN/moatd" inventory --ebpf "$BPFTRACE" --perf-rb-pages 1 --seconds 12 > "$W/run2.jsonl" 2> "$W/run2.err" &
INV=$!
wait_attached "$W/run2.jsonl" || { echo "FAIL  tracer (run 2) never attached"; cat "$W/run2.err"; exit 1; }
O0=$(opens)
inc python3 - <<'PY'
import socket
for i in range(20000):
    s = socket.socket()
    try: s.connect(("10.78.0.2", 7199))   # closed port: refused at once, still an active open
    except OSError: pass
    s.close()
PY
O1=$(opens)
wait $INV || true
echo "$((O1 - O0))" > "$W/flood_opens"

python3 - "$W" "$U" <<'PY' && RESULT=0 || RESULT=$?
import json, sys
W, U = sys.argv[1], int(sys.argv[2])
load = lambda f: [json.loads(l) for l in open(f"{W}/{f}") if l.strip()]
r1, r2, acc = load("run1.jsonl"), load("run2.jsonl"), load("accepted.jsonl")
pids = {int(x) for x in open(f"{W}/pids").read().split()}
pid6 = {int(x) for x in open(f"{W}/pids.v6").read().split()}
fails = []
def check(cond, msg):
    print(("PASS  " if cond else "FAIL  ") + msg)
    if not cond: fails.append(msg)
def port(s): return int(s.rsplit(":", 1)[1])
def host(s): return s.rsplit(":", 1)[0].strip("[]")
for name, r in (("run 1", r1), ("run 2", r2)):
    check(r and r[0].get("type") == "coverage" and r[0].get("coverage") == "observe_only", f"{name}: coverage statement first: observe_only")
    check(all(x.get("coverage", "observe_only") == "observe_only" for x in r), f"{name}: every record is observe_only (nothing enforced)")
c1 = [x for x in r1 if x.get("type") == "connect_attempt" and host(x["remote"]) in ("10.78.0.2", "fd78::2") and port(x["remote"]) == 7101]
lost1 = sum(x["count"] for x in r1 if x.get("type") == "inventory_loss" and x["scope"] == "ebpf_buffer")
got = {x["kernel"]["pid"] for x in c1}
short = [x for x in c1 if x["kernel"]["pid"] in pids]
check(len(pids) == 20 and (pids <= got or len(short) + lost1 >= 20),
      f"short-lived processes attributed at connect time by their own pid: {len(pids & got)}/20 (+{lost1} reported lost)")
check(all(x["kernel"]["comm"].startswith("python") for x in short), "kernel comm recorded (python3)")
check(all(x.get("identity") or x.get("unknown_reason") for x in c1), f"every attribution has an identity or a reason ({len(c1)})")
check(any("exited" in (x.get("unknown_reason") or "") for x in short) or all(x.get("identity") for x in short),
      "processes gone before /proc lookup are kernel-attributed with a stated reason, not guessed")
check(any(x["kernel"]["pid"] in pid6 and host(x["remote"]) == "fd78::2" for x in c1), "IPv6 connect attributed")
curl = [x for x in c1 if x["kernel"]["comm"] == "curl"]
check(any(x["kernel"]["uid"] == U for x in curl), f"non-root curl carries uid {U} from the kernel")
accepted = {(a["peer"], a["port"]) for a in acc}
check(len(acc) >= 22, f"receiver accepted every connection ({len(acc)}): observe-only never blocks")
check(len(c1) <= len(acc), f"no attributed connect to the receiver beyond what it accepted ({len(c1)} <= {len(acc)})")
check(any(x.get("type") == "inventory_loss" and x["scope"] == "ebpf_stopped" for x in r1), "tracer killed: reported as ebpf_stopped")
opens = int(open(f"{W}/flood_opens").read())
c2 = sum(1 for x in r2 if x.get("type") == "connect_attempt" and port(x["remote"]) == 7199)
lost2 = sum(x["count"] for x in r2 if x.get("type") == "inventory_loss" and x["scope"] == "ebpf_buffer")
check(opens >= 20000, f"kernel counted the flood: ActiveOpens +{opens}")
check(c2 + lost2 >= opens, f"flood accounted for: {c2} attributed + {lost2} reported lost >= {opens} kernel active opens")
check(c2 == opens or lost2 > 0, "anything not attributed is reported as loss")
print(json.dumps({"short_attributed": len(pids & got), "run1_lost": lost1, "flood_opens": opens, "flood_attributed": c2, "flood_lost_reported": lost2}))
sys.exit(1 if fails else 0)
PY
echo "ebpf inventory checks exit $RESULT"
[[ $RESULT -eq 0 ]] || { echo "--- run1 err"; cat "$W/run1.err"; echo "--- run2 err"; tail -20 "$W/run2.err"; echo "--- run1 head"; head -30 "$W/run1.jsonl"; }
exit $RESULT
