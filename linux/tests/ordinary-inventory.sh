#!/usr/bin/env bash
# W10: observe-only ordinary-app inventory, checked against an independent receiver in another network namespace.
#
#   sudo linux/tests/ordinary-inventory.sh target/debug
#
# Topology: client netns `moatinv-c` (10.77.0.1, fd77::1) -- veth -- receiver netns `moatinv-r` (10.77.0.2, fd77::2).
# `moatd inventory` samples the client namespace's socket tables. Ordinary processes (not launched by Moat) connect
# to the receiver, which logs every peer it accepts. Checks:
#   * each identified flow's 4-tuple is one the receiver really accepted (independent evidence);
#   * identity: curl's executable, two python scripts told apart only by their script (low confidence), an executable
#     replaced while running is flagged, a non-root user's uid, IPv6;
#   * a burst of short connections that sampling cannot see is COUNTED as loss: observed + lost >= accepted;
#   * nothing is enforced: every record says observe_only and every connection reached the receiver.
# Needs root and iproute2. Not the installed unit (W11) and not Omarchy.
set -euo pipefail
BIN=$(cd "${1:-target/debug}" && pwd)
PASS=0; FAIL=0
ok()  { echo "PASS  $1"; PASS=$((PASS+1)); }
bad() { echo "FAIL  $1"; FAIL=$((FAIL+1)); }
W=$(mktemp -d /tmp/moat-inv.XXXX); chmod 755 "$W"
C=moatinv-c; R=moatinv-r
inc() { nsenter --net=/run/netns/$C "$@"; }
inr() { nsenter --net=/run/netns/$R "$@"; }
cleanup() {
  set +e
  kill $(jobs -p) 2>/dev/null
  ip netns del $C 2>/dev/null; ip netns del $R 2>/dev/null
  rm -rf "$W"
}
trap cleanup EXIT

ip netns add $C; ip netns add $R
ip link add moatinv0 type veth peer name moatinv1
ip link set moatinv0 netns $C; ip link set moatinv1 netns $R
inc ip addr add 10.77.0.1/24 dev moatinv0; inc ip addr add fd77::1/64 dev moatinv0 nodad
inr ip addr add 10.77.0.2/24 dev moatinv1; inr ip addr add fd77::2/64 dev moatinv1 nodad
inc ip link set lo up; inr ip link set lo up; inc ip link set moatinv0 up; inr ip link set moatinv1 up

# --- independent receiver: logs (family, peer ip, peer port, local port) for every accepted connection -------------
cat > "$W/recv.py" <<'PY'
import socket, sys, threading, time, json
log = open(sys.argv[1], "a", buffering=1)
def serve(fam, addr, port):
    s = socket.socket(fam, socket.SOCK_STREAM); s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    if fam == socket.AF_INET6: s.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 1)
    s.bind((addr, port)); s.listen(512)
    while True:
        c, peer = s.accept()
        log.write(json.dumps({"peer": peer[0], "port": peer[1], "local_port": port}) + "\n")
        hold = 0.0 if port == 7009 else 1.2   # 7009: burst port, close at once; others: hold so sampling sees them
        threading.Thread(target=lambda c=c, h=hold: (time.sleep(h), c.close()), daemon=True).start()
for fam, a in ((socket.AF_INET, "10.77.0.2"), (socket.AF_INET6, "fd77::2")):
    for p in (7001, 7009):
        threading.Thread(target=serve, args=(fam, a, p), daemon=True).start()
print("ready", flush=True)
while True: time.sleep(1)
PY
inr python3 "$W/recv.py" "$W/accepted.jsonl" > "$W/recv.out" 2>&1 &
for _ in $(seq 40); do grep -q ready "$W/recv.out" && break; sleep 0.1; done

inc "$BIN/moatd" inventory --interval-ms 100 --seconds 25 > "$W/inv.jsonl" 2> "$W/inv.err" &
INV=$!
sleep 1.5

# --- ordinary traffic -----------------------------------------------------------------------------------------------
id moatinvu >/dev/null 2>&1 || useradd -M -s /usr/sbin/nologin moatinvu
U=$(id -u moatinvu)
inc setpriv --reuid "$U" --regid "$U" --clear-groups curl -s --max-time 3 http://10.77.0.2:7001/ >/dev/null 2>&1 || true
cat > "$W/client.py" <<'PY'
import socket, sys, time
time.sleep(float(sys.argv[4]) if len(sys.argv) > 4 else 0)   # optional delay before connecting
s = socket.create_connection((sys.argv[1], int(sys.argv[2])), timeout=3); time.sleep(float(sys.argv[3]) if len(sys.argv) > 3 else 1.0); s.close()
PY
cp "$W/client.py" "$W/sync_a.py"; cp "$W/client.py" "$W/sync_b.py"
inc python3 "$W/sync_a.py" 10.77.0.2 7001
inc python3 "$W/sync_b.py" 10.77.0.2 7001
inc python3 "$W/client.py" fd77::2 7001
# an executable replaced while it runs (replaced before it connects, so the flow's identity is read afterwards)
cp "$(readlink -f "$(command -v python3)")" "$W/fetcher"
inc "$W/fetcher" "$W/client.py" 10.77.0.2 7001 1.2 1.2 &
F=$!; sleep 0.5; rm -f "$W/fetcher"; cp /bin/true "$W/fetcher"; wait $F || true
sleep 0.5
# a burst of short connections, closed at once (sampling cannot see most of them)
inc python3 - <<'PY'
import socket
for i in range(300):
    s = socket.create_connection(("10.77.0.2", 7009), timeout=3); s.close()
PY
sleep 1
kill $INV 2>/dev/null || true; wait $INV 2>/dev/null || true
cp "$W/inv.jsonl" /tmp/moat-inventory-ci.jsonl 2>/dev/null || true

# --- checks ---------------------------------------------------------------------------------------------------------
python3 - "$W" "$U" <<'PY' && RESULT=0 || RESULT=$?
import json, sys
W, U = sys.argv[1], int(sys.argv[2])
inv = [json.loads(l) for l in open(f"{W}/inv.jsonl") if l.strip()]
acc = [json.loads(l) for l in open(f"{W}/accepted.jsonl") if l.strip()]
flows = [r for r in inv if r.get("type") == "ordinary_flow"]
loss = [r for r in inv if r.get("type") == "inventory_loss"]
fails = []
def check(cond, msg):
    print(("PASS  " if cond else "FAIL  ") + msg)
    if not cond: fails.append(msg)
def host_port(s):
    h, p = s.rsplit(":", 1); return h.strip("[]"), int(p)
accepted = {(a["peer"], a["port"], a["local_port"]) for a in acc}
to_recv = [f for f in flows if host_port(f["remote"])[0] in ("10.77.0.2", "fd77::2")]
check(inv and inv[0].get("type") == "coverage" and inv[0].get("coverage") == "observe_only", "coverage statement first: observe_only")
check(all(r.get("coverage") == "observe_only" for r in inv), "every record is labelled observe_only (nothing enforced)")
real = [f for f in to_recv if (host_port(f["local"])[0], host_port(f["local"])[1], host_port(f["remote"])[1]) in accepted]
check(len(to_recv) > 0 and len(real) == len(to_recv), f"every reported flow ({len(to_recv)}) is a connection the independent receiver accepted ({len(real)} matched)")
held = [f for f in to_recv if host_port(f["remote"])[1] == 7001]
exes = [((f.get("identity") or {}).get("executable") or "") for f in held]
check(any(e.endswith("/curl") for e in exes), "curl attributed by executable path")
curl = [f for f in held if ((f.get("identity") or {}).get("executable") or "").endswith("/curl")]
check(any(f["identity"]["uid"] == U for f in curl), "curl run as a non-root user carries that uid")
scripts = {(f.get("identity") or {}).get("script") for f in held}
check(any(s and s.endswith("sync_a.py") for s in scripts) and any(s and s.endswith("sync_b.py") for s in scripts),
      "two scripts on the same interpreter are told apart by script")
check(all(f["identity"]["confidence"] == "low" for f in held if (f.get("identity") or {}).get("script")), "interpreter identities are low confidence")
check(any(host_port(f["remote"])[0] == "fd77::2" for f in held), "IPv6 connection observed")
check(any((f.get("identity") or {}).get("executable_replaced") for f in held), "an executable replaced while running is flagged")
burst_acc = sum(1 for a in acc if a["local_port"] == 7009)
burst_seen = sum(1 for f in to_recv if host_port(f["remote"])[1] == 7009)
lost = sum(r["count"] for r in loss if r["scope"] == "tcp_active_opens_not_observed")
check(burst_acc == 300, f"receiver accepted the whole burst ({burst_acc}/300): observe-only never blocks")
check(burst_seen + lost >= burst_acc, f"burst accounted for: {burst_seen} observed + {lost} counted as loss >= {burst_acc} accepted")
check(lost > 0, f"missed short-lived connections are counted ({lost}), not silent")
unknown = [f for f in flows if f.get("identity") is None]
check(all(f.get("unknown_reason") for f in unknown), f"unknown identities ({len(unknown)}) carry a reason")
print(json.dumps({"flows": len(flows), "to_receiver": len(to_recv), "held": len(held), "burst_seen": burst_seen,
                  "burst_lost_counted": lost, "unknown": len(unknown), "accepted": len(acc)}))
sys.exit(1 if fails else 0)
PY
echo "inventory checks exit $RESULT"
exit $RESULT
