#!/usr/bin/env python3
"""W09: a read-only OpenSnitch sensor. Plays the role of the OpenSnitch UI (gRPC server on a unix socket) so the
daemon streams its events to us. It never blocks anything: AskRule answers "allow, once" immediately. Every event
and every AskRule is appended to a JSONL file with the time we received it.

  sensor.py <unix socket path> <out.jsonl>
"""
import json, sys, threading, time
from concurrent import futures
import grpc
import ui_pb2, ui_pb2_grpc
from google.protobuf.json_format import MessageToDict

sock, out_path = sys.argv[1], sys.argv[2]
out = open(out_path, "a", buffering=1)
lock = threading.Lock()
seen = set()

def redact(d):
    """OpenSnitch sends each process's full environment (tokens, keys). Keep only the variable count."""
    c = d.get("conn")
    if isinstance(c, dict) and "process_env" in c:
        c["process_env"] = {"_redacted_variable_count": len(c["process_env"] or {})}
    return d

def emit(kind, d):
    d = redact(d)
    with lock:
        out.write(json.dumps({"kind": kind, "rx": time.time(), **d}) + "\n")

class UI(ui_pb2_grpc.UIServicer):
    def Ping(self, req, ctx):
        st = req.stats
        emit("stats", {"stats": {k: v for k, v in MessageToDict(st).items() if k != "events"}})
        for ev in st.events:
            c = ev.connection
            key = (ev.unixnano, c.process_id, c.dst_ip, c.dst_port, c.src_port, c.protocol)
            if key in seen:
                continue
            seen.add(key)
            emit("event", {"unixnano": ev.unixnano, "rule": ev.rule.name, "action": ev.rule.action,
                           "conn": MessageToDict(c, preserving_proto_field_name=True)})
        return ui_pb2.PingReply(id=req.id)

    def AskRule(self, c, ctx):
        emit("ask", {"conn": MessageToDict(c, preserving_proto_field_name=True)})
        op = ui_pb2.Operator(type="simple", operand="true", data="")
        return ui_pb2.Rule(name="w09-sensor-allow-once", enabled=True, action="allow", duration="once", operator=op)

    def Subscribe(self, cfg, ctx):
        emit("subscribe", {"name": cfg.name, "version": cfg.version, "firewall_running": cfg.isFirewallRunning,
                           "config": cfg.config})
        return ui_pb2.ClientConfig(id=cfg.id, name="moat-w09-sensor", version="w09", config=cfg.config)

    def Notifications(self, it, ctx):
        # keep the stream open; we never send commands (read-only)
        def drain():
            for r in it:
                emit("notification_reply", {"code": int(r.code), "data": r.data})
        threading.Thread(target=drain, daemon=True).start()
        while ctx.is_active():
            time.sleep(0.5)
        return iter(())

    def PostAlert(self, a, ctx):
        emit("alert", {"alert": MessageToDict(a)})
        return ui_pb2.MsgResponse(id=a.id)

server = grpc.server(futures.ThreadPoolExecutor(max_workers=16))
ui_pb2_grpc.add_UIServicer_to_server(UI(), server)
server.add_insecure_port("unix://" + sock)
server.start()
print("sensor ready", flush=True)
server.wait_for_termination()
