#!/bin/bash
# Experiment for issue #31: does traffic from a local REDIRECT proxy back to its client pass an output-hook
# "oif lo accept; reject" table?
set -u
ip netns del a 2>/dev/null; ip netns del b 2>/dev/null; pkill -f srv.py; pkill -f proxy.py; sleep 0.5
W=$(mktemp -d); chmod 755 $W
ip netns add a; ip netns add b
ip link add va type veth peer name vb; ip link set va netns a; ip link set vb netns b
ip -n a addr add 10.77.0.1/24 dev va; ip -n b addr add 10.77.0.2/24 dev vb
for n in a b; do ip -n $n link set lo up; done; ip -n a link set va up; ip -n b link set vb up
cat > $W/srv.py <<'PY'
import socket,time,threading
s=socket.socket(); s.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR,1); s.bind(("10.77.0.2",8444)); s.listen()
def h(c):
    n=0
    try:
        while True:
            c.sendall(b"x\n"); n+=1; time.sleep(0.1)
    except OSError as e: print("srv end",n,e,flush=True)
while True:
    c,_=s.accept(); threading.Thread(target=h,args=(c,),daemon=True).start()
PY
cat > $W/proxy.py <<'PY'
import socket,struct,threading,time,sys
L=socket.socket(); L.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR,1); L.bind(("127.0.0.1",15000)); L.listen()
c,peer=L.accept(); print("proxy accepted from",peer,"local",c.getsockname(),flush=True)
od=c.getsockopt(socket.SOL_IP,80,16); port,ip=struct.unpack("!2xH4s8x",od); ip=socket.inet_ntoa(ip)
u=socket.socket(); u.setsockopt(socket.SOL_SOCKET,36,0x4d4f4154); u.connect((ip,port)); print("upstream",ip,port,flush=True)
def pump(a,b):
    try:
        while True:
            d=a.recv(4096)
            if not d: break
            b.sendall(d)
    except OSError: pass
threading.Thread(target=pump,args=(u,c),daemon=True).start()
open(sys.argv[1],"w").write("ok")
import os
while not os.path.exists(sys.argv[2]): time.sleep(0.05)
print("proxy kill",time.time(),flush=True); c.shutdown(socket.SHUT_RDWR); u.shutdown(socket.SHUT_RDWR)
time.sleep(30)
PY
touch $W/x; cat > $W/cli.py <<'PY'
import socket,time
t=socket.create_connection(("10.77.0.2",8444)); print("client local",t.getsockname(),flush=True); t.settimeout(1)
n=0; end=time.time()+12
while time.time()<end:
    try: d=t.recv(4096)
    except socket.timeout: continue
    except OSError as e: print("client err",e); break
    if not d: print("client EOF",time.time(),"lines",n,flush=True); break
    n+=d.count(b"\n")
print("client done lines",n,flush=True)
PY
ip netns exec b python3 $W/srv.py > $W/srv.log 2>&1 &
sleep 0.5
ip netns exec a nft -f - <<'NFT'
table inet moat {
  chain proxy_nat { type nat hook output priority -100; policy accept;
    meta skuid 65534 ip daddr 10.77.0.2 tcp dport 8444 redirect to :15000
  }
  chain output { type filter hook output priority -20; policy accept;
    meta nftrace set 1
  }
}
NFT
ip netns exec a python3 $W/proxy.py $W/ready $W/kill > $W/proxy.log 2>&1 &
sleep 0.5
chmod 644 $W/*.py; ip netns exec a runuser -u nobody -- python3 $W/cli.py > $W/cli.log 2>&1 &
CLI=$!
for _ in $(seq 50); do [[ -f $W/ready ]] && break; sleep 0.1; done
sleep 1
echo "== before isolation"; ip netns exec a ss -tni | head -20
ip netns exec a nft monitor trace > $W/trace.log 2>&1 &
TR=$!
ip netns exec a nft -f - <<NFT
table inet moat_local_emergency {
  chain output { type filter hook output priority -10; policy accept;
    oif lo accept comment "loopback"
    ${FIXLINE:-}
    counter reject comment "local-emergency-isolation"
  }
}
NFT
echo "isolated $(date +%s.%N)"
sleep 1
touch $W/kill
sleep 3
echo "== during isolation after kill"; ip netns exec a ss -tnio | head -20
ip netns exec a nft list ruleset
kill $TR
wait $CLI
echo "== client"; cat $W/cli.log; echo "== proxy"; cat $W/proxy.log; echo "== srv"; cat $W/srv.log
echo "== trace (rejects / drops)"; grep -E 'verdict (drop|reject)|rule .*reject|oif' $W/trace.log | head -40
echo "== trace head"; head -60 $W/trace.log
