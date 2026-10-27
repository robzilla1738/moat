#!/usr/bin/env python3
"""Lab peer: accepts TCP on 8080/9090 (v4+v6) and logs UDP datagrams on 5353 to a file."""
import socket, sys, threading

log = open(sys.argv[1], "a", buffering=1)

def tcp(port, fam, addr):
    s = socket.socket(fam, socket.SOCK_STREAM)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    if fam == socket.AF_INET6:
        s.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 1)
    s.bind((addr, port)); s.listen(64)
    while True:
        c, _ = s.accept(); c.close()

def udp(fam, addr):
    s = socket.socket(fam, socket.SOCK_DGRAM)
    if fam == socket.AF_INET6:
        s.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 1)
    s.bind((addr, 5353))
    while True:
        data, peer = s.recvfrom(2048)
        log.write(data.decode(errors="replace").strip() + "\n")

for port in (8080, 9090):
    threading.Thread(target=tcp, args=(port, socket.AF_INET, "10.77.0.2"), daemon=True).start()
    threading.Thread(target=tcp, args=(port, socket.AF_INET6, "fd00:77::2"), daemon=True).start()
threading.Thread(target=udp, args=(socket.AF_INET, "10.77.0.2"), daemon=True).start()
print("ready", flush=True)
threading.Event().wait()
