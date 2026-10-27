#!/usr/bin/env bash
# W09 experiment: a pinned OpenSnitch (v1.8.0) as a read-only sensor, compared with a native kernel collector
# (bpftrace), on real traffic. Produces $OUT/results.json and $OUT/results.md. CI only (installs packages).
#
#   sudo OUT=/tmp/w09-out linux/experiments/w09/run.sh
set -euo pipefail
HERE=$(cd "$(dirname "$0")" && pwd)
OUT=${OUT:-/tmp/w09-out}; mkdir -p "$OUT"; chmod 755 "$OUT"
OS_VER=1.8.0
OS_DEB=opensnitch_${OS_VER}-1_amd64.deb
OS_SHA=9f517926877f07761ca95ec43dc9daefecac582574f9856079e1064be3fa1c8a
PROTO_SHA=62de7d3661c33558daeae1092cd7eb98cdc05179695f5d41f166b1c8f7ffbd06
mark() { python3 -c "import json,time,sys; print(json.dumps({'scenario': sys.argv[1], 'edge': sys.argv[2], 'wall': time.time(), 'mono': time.monotonic_ns()}))" "$1" "$2" >> "$OUT/scenarios.jsonl"; }

# --- pinned installs ---------------------------------------------------------------------------------------------
cd "$OUT"
curl -sSLfo "$OS_DEB" "https://github.com/evilsocket/opensnitch/releases/download/v${OS_VER}/${OS_DEB}"
echo "$OS_SHA  $OS_DEB" | sha256sum -c -
curl -sSLfo ui.proto "https://raw.githubusercontent.com/evilsocket/opensnitch/v${OS_VER}/proto/ui.proto"
echo "$PROTO_SHA  ui.proto" | sha256sum -c -
python3 -m venv "$OUT/venv"; "$OUT/venv/bin/pip" -q install grpcio==1.66.2 grpcio-tools==1.66.2 protobuf==5.28.3
"$OUT/venv/bin/python" -m grpc_tools.protoc -I. --python_out=. --grpc_python_out=. ui.proto
cp "$HERE/sensor.py" "$HERE/analyze.py" "$HERE/native.bt" .
# the daemon must not start before our config and sensor exist
echo 'exit 101' > /usr/sbin/policy-rc.d; chmod 755 /usr/sbin/policy-rc.d
apt-get install -y -qq "./$OS_DEB" >/dev/null
rm -f /usr/sbin/policy-rc.d
CFG=/etc/opensnitchd/default-config.json
jq '.Rules.EnableChecksums = true | .Server.Address = "unix:///tmp/osui.sock" | .DefaultAction = "allow" | .LogLevel = 1' "$CFG" > "$CFG.new" && mv "$CFG.new" "$CFG"
cp "$CFG" "$OUT/opensnitch-config.json"

# --- sensors ------------------------------------------------------------------------------------------------------
rm -f /tmp/osui.sock
"$OUT/venv/bin/python" sensor.py /tmp/osui.sock "$OUT/sensor.jsonl" > "$OUT/sensor.out" 2>&1 &
SENSOR=$!
for _ in $(seq 40); do grep -q ready "$OUT/sensor.out" && break; sleep 0.25; done
bpftrace native.bt > "$OUT/native.log" 2> "$OUT/native.err" &
NATIVE=$!
for _ in $(seq 60); do grep -q 'Attaching' "$OUT/native.err" "$OUT/native.log" 2>/dev/null && break; sleep 0.5; done
sleep 2
OSU=$(systemctl list-unit-files --no-legend "opensnitch*" | awk '{print $1; exit}'); echo "unit: $OSU" > "$OUT/unit.txt"
systemctl start "$OSU"
for _ in $(seq 60); do grep -q '"kind": "subscribe"' "$OUT/sensor.jsonl" 2>/dev/null && break; sleep 0.5; done
sleep 2
nft list ruleset > "$OUT/nft-ruleset.txt" 2>&1 || true
opensnitchd --version > "$OUT/opensnitchd-version.txt" 2>&1 || true

BIN=/tmp/w09bin; mkdir -p "$BIN"; chmod 755 "$BIN"
hit() { timeout "${3:-2}" bash -c "echo > /dev/tcp/$1/$2" 2>/dev/null || true; }

# --- scenarios: each uses its own destination port so both collectors can be matched exactly -----------------------
mark terminal start; curl -s --max-time 2 http://1.1.1.1:9001/ >/dev/null || true; mark terminal end

mark short_lived start
for b in $(seq 10); do for i in $(seq 20); do sh -c 'exec curl -s --max-time 1 http://1.1.1.1:9002/' >/dev/null 2>&1 & done; wait; done
mark short_lived end

cat > "$BIN/a.py" <<'PY'
import socket, sys
s = socket.socket(); s.settimeout(1)
try: s.connect(("1.1.1.1", int(sys.argv[1])))
except Exception: pass
PY
cp "$BIN/a.py" "$BIN/b.py"
mark interpreter start; python3 "$BIN/a.py" 9003; python3 "$BIN/b.py" 9004; mark interpreter end

cp /usr/bin/curl "$BIN/fetchtool"
mark exe_update start
"$BIN/fetchtool" -s --max-time 1 http://1.1.1.1:9005/ >/dev/null 2>&1 || true
sleep 1; printf 'moat-w09-update' >> "$BIN/fetchtool"
"$BIN/fetchtool" -s --max-time 1 http://1.1.1.1:9006/ >/dev/null 2>&1 || true
mark exe_update end

cp "$(readlink -f "$(command -v python3)")" "$BIN/childpy"
cat > "$BIN/parent.py" <<PY
import os, socket, subprocess
s = socket.socket(); os.set_inheritable(s.fileno(), True)
subprocess.run(["$BIN/childpy", "-c", "import socket,sys; s=socket.socket(fileno=int(sys.argv[1])); s.settimeout(1)\ntry: s.connect(('1.1.1.1', 9007))\nexcept Exception: pass", str(s.fileno())], pass_fds=[s.fileno()])
PY
mark inherited start; python3 "$BIN/parent.py"; mark inherited end

mark service start
systemd-run --quiet --wait --uid=nobody --unit=w09-bg /usr/bin/curl -s --max-time 1 http://1.1.1.1:9008/ >/dev/null 2>&1 || true
mark service end

mark browser start
CHROME=$(command -v google-chrome || command -v chromium || true)
if [[ -n "$CHROME" ]]; then timeout 20 "$CHROME" --headless=new --no-sandbox --disable-gpu --dump-dom http://1.1.1.1:9009/ >/dev/null 2>&1 || true; fi
echo "${CHROME:-none}" > "$OUT/browser.txt"
mark browser end

mark udp start
python3 -c "
import socket
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
for i in range(5): s.sendto(b'w09', ('1.1.1.1', 9010))
"
mark udp end

ip link add w09d type dummy; ip addr add fd00:99::1/64 dev w09d nodad; ip link set w09d up
mark ipv6 start; hit fd00:99::2 9011 2; mark ipv6 end
ip link del w09d

mark overload start
python3 - <<'PY'
import socket, errno
socks = []
for i in range(2000):
    s = socket.socket(); s.setblocking(False)
    try: s.connect(("1.1.1.1", 9012))
    except BlockingIOError: pass
    except OSError: pass
    socks.append(s)
    if len(socks) > 400:
        for x in socks: x.close()
        socks = []
PY
sleep 3
mark overload end

mark sensor_restart start
( for i in $(seq 60); do curl -s -o /dev/null -w '%{http_code}\n' --max-time 2 http://1.0.0.1/ >> "$OUT/restart-codes.txt" 2>/dev/null || echo fail >> "$OUT/restart-codes.txt"; sleep 0.05; done ) &
L=$!
sleep 1; systemctl restart "$OSU"; wait $L
mark sensor_restart end
sleep 3

mark sensor_stopped start
systemctl stop "$OSU"
for i in $(seq 10); do curl -s -o /dev/null -w '%{http_code}\n' --max-time 2 http://1.0.0.1/ >> "$OUT/stopped-codes.txt" 2>/dev/null || echo fail >> "$OUT/stopped-codes.txt"; done
nft list ruleset > "$OUT/nft-ruleset-stopped.txt" 2>&1 || true
mark sensor_stopped end

sleep 2
kill $NATIVE $SENSOR 2>/dev/null || true; sleep 1
journalctl -u "$OSU" --no-pager > "$OUT/opensnitchd-journal.txt" 2>&1 || true
cp /var/log/opensnitchd.log "$OUT/" 2>/dev/null || true
"$OUT/venv/bin/python" analyze.py "$OUT"
cat "$OUT/results.md"
