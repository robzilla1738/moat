#!/usr/bin/env python3
"""Lab peer: accepts TCP on 8080/9090 (v4+v6), logs UDP datagrams on 5353 to a file, and, given a cert and key,
serves TLS on 10.77.0.2:8443 ("lab-tls-real") and 10.77.0.3:8443 ("lab-tls-evil") plus plain HTTP on 10.77.0.2:8081."""
import socket, ssl, sys, threading

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

def respond(conn, body):
    try:
        conn.settimeout(5)
        data = b""
        while b"\r\n\r\n" not in data and len(data) < 65536:
            chunk = conn.recv(4096)
            if not chunk:
                break
            data += chunk
        conn.sendall(b"HTTP/1.1 200 OK\r\nContent-Length: %d\r\nConnection: close\r\n\r\n%s" % (len(body), body))
    except Exception:
        pass
    finally:
        try:
            conn.close()
        except Exception:
            pass

def https(addr, body, ctx):
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.bind((addr, 8443)); s.listen(64)
    while True:
        c, _ = s.accept()
        def serve(c=c):
            try:
                t = ctx.wrap_socket(c, server_side=True)
            except Exception:
                c.close(); return
            respond(t, body)
        threading.Thread(target=serve, daemon=True).start()

def http(addr, port, body):
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.bind((addr, port)); s.listen(64)
    while True:
        c, _ = s.accept()
        threading.Thread(target=respond, args=(c, body), daemon=True).start()

for port in (8080, 9090):
    threading.Thread(target=tcp, args=(port, socket.AF_INET, "10.77.0.2"), daemon=True).start()
    threading.Thread(target=tcp, args=(port, socket.AF_INET6, "fd00:77::2"), daemon=True).start()
threading.Thread(target=udp, args=(socket.AF_INET, "10.77.0.2"), daemon=True).start()
if len(sys.argv) >= 4:
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.load_cert_chain(sys.argv[2], sys.argv[3])
    threading.Thread(target=https, args=("10.77.0.2", b"lab-tls-real", ctx), daemon=True).start()
    threading.Thread(target=https, args=("10.77.0.3", b"lab-tls-evil", ctx), daemon=True).start()
    threading.Thread(target=http, args=("10.77.0.2", 8081, b"lab-http"), daemon=True).start()
print("ready", flush=True)
threading.Event().wait()
