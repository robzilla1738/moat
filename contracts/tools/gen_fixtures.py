import json, copy, os
D1="sha256:"+"1"*64; D2="sha256:"+"2"*64; D3="sha256:"+"3"*64; D4="sha256:"+"4"*64
exe={"path":"/Applications/Claude.app/Contents/MacOS/claude","team_id":"Q6L2SF6YDW","signing_id":"com.anthropic.claude"}
def grant(**over):
    g={"schema":"moat.grant.v1","grant_id":"grant-01hx","idempotency_key":"incident-42:allow-once",
       "scope":{"kind":"app_on_device","device_id":"mbp-m1","executable":exe},
       "destination":{"kind":"hostname","hostname":"api.example.com"},"transport":"tcp","port":443,
       "issued_at":"2026-10-27T15:00:00Z","not_before":"2026-10-27T15:00:00Z","admission_until":"2026-10-27T15:10:00Z",
       "stream_policy":"admission_only","base_policy_digest":D1,
       "issuer":{"principal":"owner:robert","role":"owner","key_id":"a1b2c3d4e5f60718"},
       "approval_digest":D2,"reason":"Allow once for incident 42"}
    g.update(over); return g
valid={}; invalid={}
valid["subject-process.json"]=("moat.subject.v1",{"schema":"moat.subject.v1","device_id":"arch-desk","boot_id":"6f1c2a8e-boot","process":{"pid":4242,"start_generation":918273},"executable":{"path":"/usr/bin/curl","digest":D3},"user":"robert"})
valid["grant-app-on-device.json"]=("moat.grant.v1",grant())
g2=grant(grant_id="grant-01hy"); g2["scope"]=dict(g2["scope"],device_id="mbp-2")
valid["grant-app-on-device-second-device.json"]=("moat.grant.v1",g2)
valid["grant-process-instance.json"]=("moat.grant.v1",grant(grant_id="grant-01hz",scope={"kind":"process_instance","device_id":"arch-desk","boot_id":"6f1c2a8e-boot","process":{"pid":4242,"start_generation":918273},"executable":{"path":"/usr/bin/curl"}},destination={"kind":"address","address":"2001:db8::7"},stream_policy="terminate_at_deadline"))
valid["grant-task.json"]=("moat.grant.v1",grant(grant_id="grant-01j0",scope={"kind":"task","device_id":"arch-desk","boot_id":"6f1c2a8e-boot","task_id":"20261027150000-a1b2c3d4e5f6"},destination={"kind":"address","address":"198.51.100.7"},transport="udp",port=53,admission_until="2026-10-28T15:00:00Z"))
valid["dispositions-linux.json"]=("moat.capability_dispositions.v1",{"schema":"moat.capability_dispositions.v1","device_id":"arch-desk","backend":"moatd-nftables","backend_version":"0.1.0","capability_generation":3,
  "cells":[{"capability":"session_enforcement","mode":"direct","subject":"task","destination_evidence":"ip","transport":"any","lifecycle":"admit_new","disposition":"implemented_unproven","note":"CI runner kernel only"},
           {"capability":"session_hostname_proxy","mode":"session_proxy","subject":"task","destination_evidence":"proxy_hostname","transport":"tcp","lifecycle":"admit_new","disposition":"implemented_unproven"},
           {"capability":"app_enforcement","mode":"direct","subject":"app_on_device","destination_evidence":"ip","transport":"any","lifecycle":"admit_new","disposition":"unsupported_rejected"}],
  "policy_digest":D4,
  "items":[{"item":"profile:coding-session","restrictive":True,"disposition":"implemented_unproven"},
           {"item":"rule:allow-github-app","restrictive":False,"disposition":"omitted_accepted","omission":"stricter","missing":["app_enforcement"],"note":"omitting an allow is stricter"},
           {"item":"rule:deny-telemetry-app","restrictive":True,"disposition":"unsupported_rejected","missing":["app_enforcement","hostname_enforcement"]}]})
valid["dispositions-macos-session-rules.json"]=("moat.capability_dispositions.v1",{"schema":"moat.capability_dispositions.v1","device_id":"mbp-m1","backend":"moat-macos-ne","backend_version":"0.1.0","capability_generation":1,
  "cells":[{"capability":"session_enforcement","mode":"direct","subject":"task","destination_evidence":"none","transport":"any","lifecycle":"admit_new","disposition":"unsupported_rejected","note":"no tested macOS session boundary"}],
  "policy_digest":D4,
  "items":[{"item":"rule:safety-workloads-never-reach-controller","restrictive":True,"disposition":"omitted_accepted","omission":"subject_unavailable","missing":["session_enforcement"],"note":"sessions are refused at launch on this platform"}]})
d=copy.deepcopy(valid["dispositions-linux.json"][1]); del d["items"][1]["omission"]
invalid["dispositions-omitted-without-reason.json"]=("moat.capability_dispositions.v1",d,"semantic","omission reason required")
act={"schema":"moat.activation.v1","device_id":"arch-desk","boot_id":"6f1c2a8e-boot","phase":"trial","desired":{"revision":12,"effective_digest":D3},"received":{"revision":12,"effective_digest":D3},"verified_candidate":{"revision":12,"effective_digest":D3},"active":{"revision":12,"effective_digest":D3},"trial_deadline":"2026-10-27T15:10:00Z","rollback_target":{"revision":11,"effective_digest":D4},"replay_high_water":12,"durability":"durable"}
valid["activation-trial.json"]=("moat.activation.v1",act)
a2=copy.deepcopy(act); a2.update(phase="rollback_required",detail="trial deadline passed"); del a2["trial_deadline"]
valid["activation-rollback-required.json"]=("moat.activation.v1",a2)
a3=copy.deepcopy(act); a3.update(phase="restored",active={"revision":11,"effective_digest":D4}); del a3["trial_deadline"]; del a3["rollback_target"]
valid["activation-restored-high-water-kept.json"]=("moat.activation.v1",a3)
rec={"schema":"moat.receipt.v1","receipt_id":"rcpt-arch-desk-77","device_id":"arch-desk","boot_id":"6f1c2a8e-boot","sequence":77,"producer":"moatd","observed_at":"2026-10-27T15:00:00Z","monotonic_ms":5400000,"clock":{"source":"synchronized","uncertainty_ms":250},
     "activation":{"phase":"confirmed","active":{"revision":12,"effective_digest":D3},"replay_high_water":12,"capability_generation":3,"durability":"durable"},"health_label":"healthy"}
valid["receipt-current.json"]=("moat.receipt.v1",rec)
r2=copy.deepcopy(rec); r2.update(receipt_id="rcpt-arch-desk-12",sequence=12,observed_at="2026-10-27T13:00:00Z")
valid["receipt-old-labeled-healthy.json"]=("moat.receipt.v1",r2)
r3=copy.deepcopy(rec); r3.update(receipt_id="rcpt-arch-desk-78",sequence=78,observed_at="2026-10-27T15:30:00Z")
valid["receipt-future-clock.json"]=("moat.receipt.v1",r3)
ev={"schema":"moat.event.v1","event_id":"ev-arch-desk-901","kind":"flow_decision","producer":"moatd","authority":"endpoint_enforcer","device_id":"arch-desk","boot_id":"6f1c2a8e-boot","sequence":901,"event_time":"2026-10-27T15:00:01Z","ingest_time":"2026-10-27T15:00:03Z","clock_uncertainty_ms":250,
    "subject":{"schema":"moat.subject.v1","device_id":"arch-desk","boot_id":"6f1c2a8e-boot","task_id":"20261027150000-a1b2c3d4e5f6"},"subject_confidence":"high",
    "destination":{"address":"203.0.113.9","port":443,"transport":"tcp","hostname":{"name":"oss-cn-beijing.aliyuncs.com","source":"sni","confidence":"medium"}},
    "generations":{"policy_revision":12,"effective_digest":D3,"capability_generation":3},
    "decision":{"verdict":"deny","winner":"rule:safety-no-alibaba","overridden":["rule:coding-allow-any-443"]},
    "measurements":[{"name":"packets_dropped","value":3,"unit":"packets","scope":"rule_counter","source":"nftables_counter"}]}
valid["event-flow-decision.json"]=("moat.event.v1",ev)
valid["event-gap.json"]=("moat.event.v1",{"schema":"moat.event.v1","event_id":"ev-arch-desk-902","kind":"gap","producer":"moatd","authority":"endpoint_enforcer","device_id":"arch-desk","boot_id":"6f1c2a8e-boot","sequence":902,"event_time":"2026-10-27T15:00:05Z","clock_uncertainty_ms":250,"gap":{"scope":"quota_pruned","count":120,"from_sequence":100,"to_sequence":219}})
valid["event-independently-checked.json"]=("moat.event.v1",{"schema":"moat.event.v1","event_id":"canary-mini-31","kind":"lifecycle","stage":"independently_checked","producer":"canary-receiver","authority":"independent_observer","device_id":"arch-desk","boot_id":"6f1c2a8e-boot","sequence":31,"event_time":"2026-10-27T15:01:00Z","clock_uncertainty_ms":1000,"generations":{"policy_revision":12},"parent_event_id":"ev-arch-desk-880"})
# invalid
def drop(d,*path):
    d=copy.deepcopy(d); x=d
    for p in path[:-1]: x=x[p]
    del x[path[-1]]; return d
g=grant(); invalid["grant-missing-device.json"]=("moat.grant.v1",drop(g,"scope","device_id"),"schema","missing mandatory scope")
invalid["grant-process-without-boot.json"]=("moat.grant.v1",drop(valid["grant-process-instance.json"][1],"scope","boot_id"),"semantic","process scope needs boot_id")
gp=grant(); gp["scope"]=dict(gp["scope"],process={"pid":1,"start_generation":2})
invalid["grant-app-scope-with-process.json"]=("moat.grant.v1",gp,"semantic","app_on_device forbids process")
invalid["grant-app-scope-without-executable.json"]=("moat.grant.v1",drop(g,"scope","executable"),"semantic","app_on_device needs executable")
invalid["grant-unknown-field.json"]=("moat.grant.v1",grant(also_allow_everything=True),"schema","unknown field")
invalid["grant-unknown-version.json"]=("moat.grant.v1",grant(schema="moat.grant.v2"),"schema","unknown schema version")
invalid["grant-noncanonical-time.json"]=("moat.grant.v1",grant(admission_until="2026-10-27T15:10:00.000Z"),"semantic","non-canonical timestamp")
invalid["grant-window-too-long.json"]=("moat.grant.v1",grant(admission_until="2026-10-29T15:00:00Z"),"semantic","window over 24h")
invalid["grant-wildcard-host.json"]=("moat.grant.v1",grant(destination={"kind":"hostname","hostname":"*.example.com"}),"semantic","wildcard host")
invalid["grant-noncanonical-address.json"]=("moat.grant.v1",grant(destination={"kind":"address","address":"2001:DB8:0:0:0:0:0:7"}),"semantic","non-canonical address")
invalid["grant-float-port.json"]=("moat.grant.v1",grant(port=443.0),"schema","float")
invalid["grant-null-reason.json"]=("moat.grant.v1",grant(reason=None),"schema","null")
d=copy.deepcopy(valid["dispositions-linux.json"][1]); d["items"][2]["disposition"]="omitted_accepted"; d["items"][2]["omission"]="stricter"
invalid["dispositions-omitted-restrictive.json"]=("moat.capability_dispositions.v1",d,"semantic","restrictive item omitted")
d=copy.deepcopy(valid["dispositions-linux.json"][1]); d["cells"][0]["disposition"]="supported_installed"
invalid["dispositions-supported-without-evidence.json"]=("moat.capability_dispositions.v1",d,"semantic","supported without evidence")
d=copy.deepcopy(valid["dispositions-linux.json"][1]); d["cells"][2]["disposition"]="supported"
invalid["dispositions-unknown-disposition.json"]=("moat.capability_dispositions.v1",d,"schema","unknown disposition value")
invalid["activation-trial-without-rollback-target.json"]=("moat.activation.v1",drop(act,"rollback_target"),"semantic","first canary needs a fallback")
a=copy.deepcopy(a3); a["replay_high_water"]=11
invalid["activation-high-water-lowered.json"]=("moat.activation.v1",a,"semantic","high-water below accepted revision")
invalid["activation-rollback-without-target.json"]=("moat.activation.v1",drop(a2,"rollback_target"),"semantic","rollback intent lost")
r=copy.deepcopy(rec); r["activation"]["phase"]="applied"
invalid["receipt-applied-phase.json"]=("moat.receipt.v1",r,"schema","no 'applied' phase; activation commit states only")
invalid["receipt-missing-observed-at.json"]=("moat.receipt.v1",drop(rec,"observed_at"),"schema","observation time required")
e=copy.deepcopy(valid["event-independently-checked.json"][1]); e["authority"]="endpoint_enforcer"
invalid["event-enforcer-self-verifies.json"]=("moat.event.v1",e,"semantic","endpoint cannot independently check itself")
e=copy.deepcopy(valid["event-independently-checked.json"][1]); e.update(authority="runtime_self_report",stage="activated")
invalid["event-agent-claims-activation.json"]=("moat.event.v1",e,"semantic","agent cannot assert activation")
invalid["event-flow-without-decision.json"]=("moat.event.v1",drop(ev,"decision"),"semantic","flow decision needs decision")
manifest={"schema":"moat.contract_fixtures.v1","note":"Every implementation must accept each valid fixture, re-serialize it canonically and produce canonical_sha256 exactly; and must reject each invalid fixture. layer=schema rejects are caught by the JSON schema alone; layer=semantic rejects need the semantic checks in contracts/README.md.","fixtures":[]}
for n,(s,d) in valid.items():
    open(f"fixtures/valid/{n}","w").write(json.dumps(d,indent=2)+"\n")
    ent={"file":f"valid/{n}","schema":s,"expect":"accept"}
    fr={"receipt-current.json":"fresh","receipt-old-labeled-healthy.json":"stale","receipt-future-clock.json":"unknown"}.get(n)
    if fr: ent["freshness"]={"now":"2026-10-27T15:01:00Z","max_age_seconds":300,"expect":fr}
    manifest["fixtures"].append(ent)
for n,(s,d,layer,why) in invalid.items():
    open(f"fixtures/invalid/{n}","w").write(json.dumps(d,indent=2)+"\n")
    manifest["fixtures"].append({"file":f"invalid/{n}","schema":s,"expect":"reject","layer":layer,"reason":why})
old={}
if os.path.exists("fixtures/manifest.json"):
    old={f["file"]:f.get("canonical_sha256") for f in json.load(open("fixtures/manifest.json"))["fixtures"]}
for f in manifest["fixtures"]:
    if old.get(f["file"]): f["canonical_sha256"]=old[f["file"]]
open("fixtures/manifest.json","w").write(json.dumps(manifest,indent=2)+"\n")
print(len(valid),len(invalid))
