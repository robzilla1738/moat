import json
S=lambda **k: dict(type="string",**k)
I=lambda **k: dict(type="integer",minimum=0,maximum=9007199254740991,**k)
B={"type":"boolean"}
def O(props, req=(), **k):
    return dict(type="object", additionalProperties=False, required=sorted(req), properties=props, **k)
def E(*vals): return {"type":"string","enum":list(vals)}
def A(item): return {"type":"array","items":item}
TS=S(description="canonical UTC timestamp YYYY-MM-DDTHH:MM:SSZ")
DIG=S(description="sha256: + 64 lowercase hex")
ID=S(description="[A-Za-z0-9-_.:@/]{1,128}")
exe=O({"team_id":S(),"signing_id":S(),"bundle_id":S(),"digest":S(),"path":S()})
proc=O({"pid":I(),"start_generation":I()},["pid","start_generation"])
gen=O({"revision":I(),"effective_digest":DIG},["revision","effective_digest"])
def schema(name, body, desc):
    d={"$schema":"https://json-schema.org/draft/2020-12/schema","$id":f"https://github.com/robzilla1738/moat/contracts/schemas/{name}.schema.json","title":name,"description":desc}
    d.update(body); d["properties"]["schema"]={"const":name}
    return d
schemas={}
schemas["moat.subject.v1"]=schema("moat.subject.v1",O({"schema":None,"device_id":ID,"boot_id":ID,"process":proc,"task_id":ID,"executable":exe,"user":S()},["schema","device_id"]),
 "Who a decision, grant or event is about, at the precision the producer can prove. Absent = unknown, never 'any'. boot_id is required when process or task_id is present.")
schemas["moat.grant.v1"]=schema("moat.grant.v1",O({"schema":None,"grant_id":ID,"idempotency_key":ID,
  "scope":O({"kind":E("app_on_device","process_instance","task"),"device_id":ID,"boot_id":ID,"process":proc,"task_id":ID,"executable":exe},["kind","device_id"]),
  "destination":O({"kind":E("address","hostname"),"address":S(),"hostname":S()},["kind"]),
  "transport":E("tcp","udp"),"port":I(),"issued_at":TS,"not_before":TS,"admission_until":TS,
  "stream_policy":E("admission_only","terminate_at_deadline"),"base_policy_digest":DIG,
  "issuer":O({"principal":ID,"role":E("owner","delegated"),"key_id":ID},["principal","role"]),
  "approval_digest":DIG,"reason":S()},
  ["schema","grant_id","idempotency_key","scope","destination","transport","port","issued_at","not_before","admission_until","stream_policy","base_policy_digest","issuer","approval_digest"]),
 "A temporary permission as a precise object. Scope kind fixes which identity fields are required: app_on_device needs executable and forbids boot/process/task; process_instance needs boot_id+process; task needs boot_id+task_id. Window at most 86400 s.")
DISP=E("supported_installed","implemented_unproven","unsupported_rejected","omitted_accepted","unknown_degraded")
schemas["moat.capability_dispositions.v1"]=schema("moat.capability_dispositions.v1",O({"schema":None,"device_id":ID,"backend":ID,"backend_version":S(),"capability_generation":I(),
  "cells":A(O({"capability":S(),"mode":S(),"subject":S(),"destination_evidence":S(),"transport":E("tcp","udp","any"),"lifecycle":S(),"disposition":DISP,"evidence_ref":S(),"note":S()},["capability","mode","subject","destination_evidence","transport","lifecycle","disposition"])),
  "policy_digest":DIG,
  "items":A(O({"item":S(),"restrictive":B,"disposition":DISP,"omission":E("stricter","subject_unavailable"),"missing":A(S()),"note":S()},["item","restrictive","disposition"]))},
  ["schema","device_id","backend","backend_version","capability_generation","cells"]),
 "Per-endpoint capability cells and per-item (profile/rule) dispositions. omitted_accepted needs omission (stricter | subject_unavailable); a restrictive item is never omitted as stricter; supported_installed needs evidence_ref.")
PHASE=E("none","prepared","applying","trial","confirmed","rollback_required","restored","recovery_required","rejected")
DUR=E("durable","not_durable","uncertain")
schemas["moat.activation.v1"]=schema("moat.activation.v1",O({"schema":None,"device_id":ID,"boot_id":ID,"phase":PHASE,"desired":gen,"received":gen,"verified_candidate":gen,"active":gen,"trial_deadline":TS,"rollback_target":gen,"replay_high_water":I(),"durability":DUR,"detail":S()},
  ["schema","device_id","boot_id","phase","replay_high_water","durability"]),
 "Endpoint activation state. replay_high_water is independent of active and never trails an accepted revision; trial needs trial_deadline and rollback_target; rollback_required keeps rollback_target.")
schemas["moat.receipt.v1"]=schema("moat.receipt.v1",O({"schema":None,"receipt_id":ID,"device_id":ID,"boot_id":ID,"sequence":I(),"producer":ID,"observed_at":TS,"monotonic_ms":I(),
  "clock":O({"source":E("synchronized","unknown","unsynchronized"),"uncertainty_ms":I()},["source","uncertainty_ms"]),
  "activation":O({"phase":PHASE,"active":gen,"replay_high_water":I(),"capability_generation":I(),"durability":DUR},["phase","replay_high_water","capability_generation","durability"]),
  "health_label":S()},["schema","receipt_id","device_id","boot_id","sequence","producer","observed_at","monotonic_ms","clock","activation"]),
 "Endpoint statement of activation state at one observation time. Consumers compute freshness from observed_at and clock.uncertainty_ms; health_label is display only.")
schemas["moat.event.v1"]=schema("moat.event.v1",O({"schema":None,"event_id":ID,"kind":E("lifecycle","flow_decision","gap","restart","coverage_change","task_lifecycle"),
  "producer":ID,"authority":E("runtime_self_report","launcher","endpoint_enforcer","independent_observer","dns_resolver"),
  "device_id":ID,"boot_id":ID,"sequence":I(),"event_time":TS,"ingest_time":TS,"clock_uncertainty_ms":I(),
  "stage":E("requested","authorized","compiled","delivered","received","activated","independently_checked"),
  "subject":{"$ref":"moat.subject.v1.schema.json"},"subject_confidence":E("low","medium","high"),
  "destination":O({"address":S(),"port":I(),"transport":E("tcp","udp","other"),"hostname":O({"name":S(),"source":E("flow_api","connect_proxy","sni","http_host","dns_answer","inferred"),"confidence":E("low","medium","high")},["name","source","confidence"])},["transport"]),
  "generations":O({"policy_revision":I(),"effective_digest":DIG,"trust_generation":I(),"capability_generation":I()}),
  "decision":O({"verdict":E("allow","deny","observe"),"winner":S(),"overridden":A(S())},["verdict","winner"]),
  "measurements":A(O({"name":S(),"value":I(),"unit":S(),"scope":E("flow","rule_counter","conversation_window","task"),"source":S()},["name","value","unit","scope","source"])),
  "gap":O({"scope":S(),"count":I(),"from_sequence":I(),"to_sequence":I()},["scope"]),
  "coverage":S(),"parent_event_id":ID,"ext":{"type":"object"}},
  ["schema","event_id","kind","producer","authority","device_id","boot_id","sequence","event_time","clock_uncertainty_ms"]),
 "Event envelope and evidence vocabulary. The producer's authority must permit what the event asserts (e.g. only independent_observer may assert independently_checked).")
for n,d in schemas.items():
    open(f"schemas/{n}.schema.json","w").write(json.dumps(d,indent=2,sort_keys=False)+"\n")
print(list(schemas))
