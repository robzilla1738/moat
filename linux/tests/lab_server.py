#!/usr/bin/env python3
"""Lab peer: accepts TCP on 8080/9090 (v4+v6), logs UDP datagrams on 5353 to a file, and, given a cert and key,
serves TLS on 10.77.0.2:8443 ("lab-tls-real") and 10.77.0.3:8443 ("lab-tls-evil") plus plain HTTP on 10.77.0.2:8081.

Given a fourth argument (a directory), it is also the independent receiver for the W05 checks:
* recv.log: "recv <port> <first line>" for every TCP payload that reaches 8080/9090/7070 (v4 and v6);
* dns.log: "q <name> <type>" for every DNS query to 10.77.0.2:53 (A answers 10.77.0.2 for *.dnslab, else none);
* stream.log: "start <tag> <t>" / "end <tag> <t> <ticks>" for long-lived TLS streams on 10.77.0.2:8444, which send a
  tick every 100 ms until the peer goes away."""
import socket, ssl, struct, sys, threading, time

log = open(sys.argv[1], "a", buffering=1)
LAB = sys.argv[4] if len(sys.argv) >= 5 else None
logs = {}
lock = threading.Lock()

def note(name, line):
    if LAB is None:
        return
    with lock:
        f = logs.get(name) or logs.setdefault(name, open(f"{LAB}/{name}", "a", buffering=1))
        f.write(line + "\n")

def take(c, port):
    try:
        c.settimeout(2)
        data = c.recv(256)
        if data:
            note("recv.log", f"recv {port} {data.decode(errors='replace').splitlines()[0].strip() if data.strip() else ''}")
    except Exception:
        pass
    finally:
        c.close()

def tcp(port, fam, addr):
    s = socket.socket(fam, socket.SOCK_STREAM)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    if fam == socket.AF_INET6:
        s.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 1)
    s.bind((addr, port)); s.listen(64)
    while True:
        c, _ = s.accept()
        threading.Thread(target=take, args=(c, port), daemon=True).start()

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

def dns():
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.bind(("10.77.0.2", 53))
    while True:
        q, peer = s.recvfrom(512)
        try:
            i, labels = 12, []
            while q[i]:
                labels.append(q[i + 1:i + 1 + q[i]].decode().lower()); i += 1 + q[i]
            qtype = struct.unpack(">H", q[i + 1:i + 3])[0]
            name = ".".join(labels)
            note("dns.log", f"q {name} {qtype}")
            question = q[12:i + 5]
            hit = name.endswith(".dnslab")
            ans = b""
            if hit and qtype == 1:
                ans = b"\xc0\x0c" + struct.pack(">HHIH", 1, 1, 5, 4) + socket.inet_aton("10.77.0.2")
            flags = 0x8180 if hit else 0x8183
            s.sendto(q[:2] + struct.pack(">HHHHH", flags, 1, 1 if ans else 0, 0, 0) + question + ans, peer)
        except Exception:
            pass

def streams(ctx):
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.bind(("10.77.0.2", 8444)); s.listen(64)
    while True:
        c, _ = s.accept()
        def serve(c=c):
            ticks, tag = 0, "?"
            try:
                t = ctx.wrap_socket(c, server_side=True)
                t.settimeout(5)
                buf = b""
                while b"\n" not in buf:
                    d = t.recv(256)
                    if not d:
                        raise OSError("closed before tag")
                    buf += d
                tag = buf.split(b"\n")[0].decode(errors="replace").strip()
                note("stream.log", f"start {tag} {time.time():.3f}")
                while True:
                    t.sendall(b"tick\n"); ticks += 1
                    time.sleep(0.1)
            except Exception:
                pass
            if tag != "?":
                note("stream.log", f"end {tag} {time.time():.3f} {ticks}")
            try:
                c.close()
            except Exception:
                pass
        threading.Thread(target=serve, daemon=True).start()

for port in (8080, 9090, 7070):
    threading.Thread(target=tcp, args=(port, socket.AF_INET, "10.77.0.2"), daemon=True).start()
    threading.Thread(target=tcp, args=(port, socket.AF_INET6, "fd00:77::2"), daemon=True).start()
threading.Thread(target=udp, args=(socket.AF_INET, "10.77.0.2"), daemon=True).start()
if len(sys.argv) >= 4:
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.load_cert_chain(sys.argv[2], sys.argv[3])
    threading.Thread(target=https, args=("10.77.0.2", b"lab-tls-real", ctx), daemon=True).start()
    threading.Thread(target=https, args=("10.77.0.3", b"lab-tls-evil", ctx), daemon=True).start()
    threading.Thread(target=http, args=("10.77.0.2", 8081, b"lab-http"), daemon=True).start()
    if LAB is not None:
        threading.Thread(target=streams, args=(ctx,), daemon=True).start()
if LAB is not None:
    threading.Thread(target=dns, daemon=True).start()
print("ready", flush=True)
threading.Event().wait()
