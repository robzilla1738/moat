#!/usr/bin/env python3
"""W09: match OpenSnitch sensor records and native kernel records per scenario; write results.json/results.md."""
import json, sys, collections, os

OUT = sys.argv[1]
def jl(p):
    try:
        return [json.loads(l) for l in open(os.path.join(OUT, p)) if l.strip()]
    except FileNotFoundError:
        return []

marks = jl("scenarios.jsonl")
win = collections.defaultdict(dict)
for m in marks:
    win[m["scenario"]][m["edge"]] = m
sensor = jl("sensor.jsonl")
events = [r for r in sensor if r["kind"] == "event"]
asks = [r for r in sensor if r["kind"] == "ask"]
stats = [r["stats"] for r in sensor if r["kind"] == "stats"]
alerts = [r for r in sensor if r["kind"] == "alert"]
native = []
for l in open(os.path.join(OUT, "native.log")):
    p = l.split()
    if len(p) >= 9 and p[0] in ("tcp", "udp"):
        native.append({"proto": p[0], "mono": int(p[1]), "pid": int(p[2]), "uid": int(p[3]), "comm": p[4],
                       "family": p[5], "daddr": p[6], "dport": int(p[7]), "cgroup": p[8]})

def in_wall(sc, t):
    w = win.get(sc, {})
    return "start" in w and "end" in w and w["start"]["wall"] - 0.5 <= t <= w["end"]["wall"] + 3

def in_mono(sc, t):
    w = win.get(sc, {})
    return "start" in w and "end" in w and w["start"]["mono"] - 5e8 <= t <= w["end"]["mono"] + 3e9

def sens(sc, port=None, ip=None, proto=None):
    """OpenSnitch records (events + AskRule) for a scenario, deduplicated per (pid, src_port, dst)."""
    out, seen = [], set()
    for r in events + asks:
        c = r["conn"]
        t = r.get("unixnano", 0) / 1e9 or r["rx"]
        if not in_wall(sc, t) and not in_wall(sc, r["rx"]):
            continue
        if port is not None and int(c.get("dst_port", 0)) != port:
            continue
        if ip is not None and c.get("dst_ip") != ip:
            continue
        if proto is not None and c.get("protocol") != proto:
            continue
        k = (c.get("process_id"), c.get("src_port"), c.get("dst_ip"), c.get("dst_port"), c.get("protocol"))
        if k in seen:
            continue
        seen.add(k)
        out.append(c)
    return out

def nat(sc, port=None, proto="tcp", ip=None):
    return [n for n in native if n["proto"] == proto and in_mono(sc, n["mono"])
            and (port is None or n["dport"] == port) and (ip is None or n["daddr"] == ip)]

def summary(s, n, expected):
    paths = collections.Counter(c.get("process_path", "") or "(none)" for c in s)
    return {
        "expected": expected,
        "opensnitch_records": len(s),
        "opensnitch_with_pid": sum(1 for c in s if int(c.get("process_id", 0) or 0) > 0),
        "opensnitch_with_path": sum(1 for c in s if c.get("process_path")),
        "opensnitch_paths": dict(paths.most_common(5)),
        "opensnitch_uids": sorted({int(c.get("user_id", 0) or 0) for c in s}),
        "opensnitch_args_examples": [c.get("process_args", [])[:4] for c in s[:2]],
        "opensnitch_checksums": [c.get("process_checksums", {}) for c in s[:2]],
        "opensnitch_tree_depth": [len(c.get("process_tree", [])) for c in s[:2]],
        "native_records": len(n),
        "native_comms": dict(collections.Counter(x["comm"] for x in n).most_common(5)),
        "native_uids": sorted({x["uid"] for x in n}),
        "native_cgroup_ids": len({x["cgroup"] for x in n}),
    }

R = {}
R["terminal"] = summary(sens("terminal", 9001), nat("terminal", 9001), 1)
R["short_lived"] = summary(sens("short_lived", 9002), nat("short_lived", 9002), 200)
R["interpreter_a"] = summary(sens("interpreter", 9003), nat("interpreter", 9003), 1)
R["interpreter_b"] = summary(sens("interpreter", 9004), nat("interpreter", 9004), 1)
R["exe_update_before"] = summary(sens("exe_update", 9005), nat("exe_update", 9005), 1)
R["exe_update_after"] = summary(sens("exe_update", 9006), nat("exe_update", 9006), 1)
R["inherited_socket"] = summary(sens("inherited", 9007), nat("inherited", 9007), 1)
R["background_service"] = summary(sens("service", 9008), nat("service", 9008), 1)
R["browser"] = summary(sens("browser", 9009), nat("browser", 9009), 1)
R["udp"] = summary(sens("udp", 9010, proto="udp"), nat("udp", None, proto="udp"), "5 datagrams, 1 flow")
R["ipv6"] = summary(sens("ipv6", 9011), nat("ipv6", 9011), 1)
R["overload"] = summary(sens("overload", 9012), nat("overload", 9012), 2000)
R["sensor_restart"] = summary(sens("sensor_restart", 80, ip="1.0.0.1"), nat("sensor_restart", 80, ip="1.0.0.1"), 60)
R["sensor_stopped"] = summary(sens("sensor_stopped", 80, ip="1.0.0.1"), nat("sensor_stopped", 80, ip="1.0.0.1"), 10)

def codes(p):
    try:
        return dict(collections.Counter(l.strip() for l in open(os.path.join(OUT, p))))
    except FileNotFoundError:
        return {}
R["sensor_restart"]["http_results"] = codes("restart-codes.txt")
R["sensor_stopped"]["http_results"] = codes("stopped-codes.txt")

fields = collections.Counter()
for r in events + asks:
    for k, v in r["conn"].items():
        if v not in ("", 0, [], {}, None, "0"):
            fields[k] += 1
meta = {
    "opensnitch_version": open(os.path.join(OUT, "opensnitchd-version.txt")).read().strip() if os.path.exists(os.path.join(OUT, "opensnitchd-version.txt")) else "?",
    "sensor_event_records": len(events), "sensor_askrule_records": len(asks), "alerts": len(alerts),
    "alert_examples": [a["alert"] for a in alerts[:5]],
    "connection_fields_populated": dict(fields),
    "last_stats": stats[-1] if stats else {},
    "native_records": len(native),
    "nft_tables_with_opensnitch": [l.strip() for l in open(os.path.join(OUT, "nft-ruleset.txt")) if l.startswith("table")],
    "nft_tables_after_stop": [l.strip() for l in open(os.path.join(OUT, "nft-ruleset-stopped.txt")) if l.startswith("table")] if os.path.exists(os.path.join(OUT, "nft-ruleset-stopped.txt")) else [],
    "browser": open(os.path.join(OUT, "browser.txt")).read().strip() if os.path.exists(os.path.join(OUT, "browser.txt")) else "?",
}
json.dump({"meta": meta, "scenarios": R}, open(os.path.join(OUT, "results.json"), "w"), indent=2)
with open(os.path.join(OUT, "results.md"), "w") as f:
    f.write(f"# W09 results\n\nOpenSnitch: {meta['opensnitch_version']}; sensor events {len(events)}, AskRule {len(asks)}, alerts {len(alerts)}; native records {len(native)}\n\n")
    f.write("| scenario | expected | OpenSnitch | with pid | with path | paths | native | native comms |\n|---|---|---|---|---|---|---|---|\n")
    for k, v in R.items():
        f.write(f"| {k} | {v['expected']} | {v['opensnitch_records']} | {v['opensnitch_with_pid']} | {v['opensnitch_with_path']} | {v['opensnitch_paths']} | {v['native_records']} | {v['native_comms']} |\n")
    f.write("\nFields populated (count of records): " + json.dumps(meta["connection_fields_populated"]) + "\n")
    f.write("\nLast stats: " + json.dumps(meta["last_stats"])[:1500] + "\n")
    f.write("\nnft tables (running / stopped): " + json.dumps(meta["nft_tables_with_opensnitch"]) + " / " + json.dumps(meta["nft_tables_after_stop"]) + "\n")
    f.write("\nRestart HTTP: " + json.dumps(R["sensor_restart"]["http_results"]) + "; stopped HTTP: " + json.dumps(R["sensor_stopped"]["http_results"]) + "\n")
    f.write("\nexe_update checksums: " + json.dumps([R["exe_update_before"]["opensnitch_checksums"], R["exe_update_after"]["opensnitch_checksums"]]) + "\n")
    f.write("\ninherited socket paths: " + json.dumps(R["inherited_socket"]["opensnitch_paths"]) + " native " + json.dumps(R["inherited_socket"]["native_comms"]) + "\n")
    f.write("\nalerts: " + json.dumps(meta["alert_examples"])[:1500] + "\n")
