//! `moatctl`: the Moat policy command line.
//!
//! Every command is offline and data-only. `moatctl` never talks to a privileged service and never executes
//! anything a policy names; policies are declarative and contain no scripts.
//!
//! Exit codes: 0 ok, 1 usage/IO error, 2 policy invalid or verification failed, 3 change broadens access and needs
//! an explicit owner authorization, 4 conformance failure.

use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::ExitCode;

use chrono::{DateTime, Duration, Utc};
use clap::{Parser, Subcommand, ValueEnum};
use moat_core::compile::{compile, CompileOptions, Snapshot};
use moat_core::diff::diff;
use moat_core::enrichment::Enricher;
use moat_core::eval::{evaluate, EvalContext, FlowAttempt, Verdict, Winner};
use moat_core::signing::{
    generate_key, key_id, sign_snapshot, signing_key_from_hex, verify_snapshot, verifying_key_from_hex, SignedSnapshot, TrustStore,
};
use moat_core::simulate::{simulate, SimulationInput};
use moat_core::{CapabilityAdvertisement, Platform, Policy};
use serde_json::{json, Value};

#[derive(Parser)]
#[command(name = "moatctl", version, about = "Moat policy CLI: validate, compile, diff, simulate, sign, verify, explain")]
struct Cli {
    /// Emit machine-readable JSON instead of text.
    #[arg(long, global = true)]
    json: bool,
    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Copy, Clone, ValueEnum, Debug)]
enum Adapter {
    Macos,
    Linux,
    Dns,
}

impl Adapter {
    fn adv(self) -> CapabilityAdvertisement {
        match self {
            Adapter::Macos => CapabilityAdvertisement::macos_network_extension(),
            Adapter::Linux => CapabilityAdvertisement::linux_nftables_cgroup(),
            Adapter::Dns => CapabilityAdvertisement::dns_resolver("adguard-home"),
        }
    }
    fn platform(self) -> Platform {
        self.adv().platform
    }
}

#[derive(Subcommand)]
enum Cmd {
    /// Validate a policy's schema, references and precedence constraints; optionally check it compiles per adapter.
    Validate {
        policy: PathBuf,
        /// Also compile against these adapters (repeatable). Default: all.
        #[arg(long = "adapter", value_enum)]
        adapters: Vec<Adapter>,
    },
    /// Compile a policy into an unsigned per-platform snapshot.
    Compile {
        policy: PathBuf,
        #[arg(long, value_enum)]
        adapter: Adapter,
        #[arg(long)]
        revision: u64,
        /// Mark this revision as a rollback to an older revision's content.
        #[arg(long)]
        rollback_of: Option<u64>,
        /// Snapshot validity in hours (omit for no expiry).
        #[arg(long)]
        valid_hours: Option<i64>,
        /// Override the issue time (RFC 3339), for reproducible builds.
        #[arg(long)]
        issued_at: Option<DateTime<Utc>>,
        #[arg(short, long)]
        out: Option<PathBuf>,
    },
    /// Show what changed between two policies and whether it broadens access.
    Diff { old: PathBuf, new: PathBuf },
    /// Replay a proposed policy against recorded observations (JSON array or JSON lines of flow attempts).
    Simulate {
        current: PathBuf,
        proposed: PathBuf,
        #[arg(long)]
        observations: PathBuf,
        /// Devices that have not acknowledged the current revision (repeatable).
        #[arg(long = "unacknowledged")]
        unacknowledged: Vec<String>,
    },
    /// Generate an Ed25519 signer key. Keep the secret file outside agent workspaces.
    Keygen {
        /// Path for the secret key (hex, written 0600). The public key goes to <path>.pub.
        #[arg(long)]
        out: PathBuf,
    },
    /// Sign a compiled snapshot. Broadening against --previous requires --authorize-broadening.
    Sign {
        snapshot: PathBuf,
        #[arg(long)]
        key: PathBuf,
        /// Previously signed source policy; used to detect broadening.
        #[arg(long)]
        previous: Option<PathBuf>,
        /// Explicit local owner authorization for a broadening change. Never pass this from an agent.
        #[arg(long)]
        authorize_broadening: bool,
        #[arg(short, long)]
        out: Option<PathBuf>,
    },
    /// Verify a signed snapshot as an endpoint would.
    Verify {
        signed: PathBuf,
        /// Trusted public key file(s) (hex).
        #[arg(long = "pub", required = true)]
        pubkeys: Vec<PathBuf>,
        #[arg(long, value_enum)]
        adapter: Adapter,
        /// Highest revision already applied (replay protection).
        #[arg(long)]
        last_applied: Option<u64>,
    },
    /// Explain the decision for one flow attempt: winning rule, overridden rules and uncertainty.
    Explain {
        policy: PathBuf,
        /// Flow attempt JSON file.
        #[arg(long)]
        flow: PathBuf,
    },
    /// Run the implementation-independent conformance cases in a directory.
    Conformance {
        #[arg(default_value = "conformance")]
        dir: PathBuf,
    },
}

struct Out {
    json: bool,
    code: u8,
}

fn read(p: &Path) -> Result<String, String> {
    fs::read_to_string(p).map_err(|e| format!("{}: {e}", p.display()))
}

fn load_policy(p: &Path) -> Result<Policy, String> {
    Policy::parse(&read(p)?).map_err(|e| format!("{}: {e}", p.display()))
}

fn write_out(path: &Option<PathBuf>, s: &str) -> Result<(), String> {
    match path {
        Some(p) => fs::write(p, s).map_err(|e| format!("{}: {e}", p.display())),
        None => {
            println!("{s}");
            Ok(())
        }
    }
}

fn load_flows(p: &Path) -> Result<Vec<FlowAttempt>, String> {
    let t = read(p)?;
    let trimmed = t.trim_start();
    if trimmed.starts_with('[') {
        return serde_json::from_str(trimmed).map_err(|e| format!("{}: {e}", p.display()));
    }
    trimmed
        .lines()
        .filter(|l| !l.trim().is_empty())
        .enumerate()
        .map(|(i, l)| serde_json::from_str(l).map_err(|e| format!("{} line {}: {e}", p.display(), i + 1)))
        .collect()
}

fn main() -> ExitCode {
    let cli = Cli::parse();
    let mut o = Out { json: cli.json, code: 0 };
    match run(cli.cmd, &mut o) {
        Ok(()) => ExitCode::from(o.code),
        Err(e) => {
            if o.json {
                println!("{}", json!({"ok": false, "error": e}));
            } else {
                eprintln!("moatctl: {e}");
            }
            ExitCode::from(if o.code == 0 { 1 } else { o.code })
        }
    }
}

fn run(cmd: Cmd, o: &mut Out) -> Result<(), String> {
    match cmd {
        Cmd::Validate { policy, adapters } => {
            let p = load_policy(&policy)?;
            if let Err(errs) = p.validate() {
                o.code = 2;
                let msgs: Vec<String> = errs.iter().map(|e| e.to_string()).collect();
                if o.json {
                    println!("{}", json!({"ok": false, "errors": msgs}));
                } else {
                    for m in &msgs {
                        eprintln!("error: {m}");
                    }
                }
                return Ok(());
            }
            let adapters = if adapters.is_empty() { vec![Adapter::Macos, Adapter::Linux, Adapter::Dns] } else { adapters };
            let opts = CompileOptions { revision: 1, rollback_of: None, issued_at: Utc::now(), not_after: None };
            let mut results = Vec::new();
            for a in adapters {
                let adv = a.adv();
                match compile(&p, &adv, &opts) {
                    Ok(s) => results.push(json!({
                        "adapter": adv.adapter, "compiles": true,
                        "omitted": s.report.omitted, "warnings": s.report.warnings,
                        "unavailable_session_profiles": s.report.unavailable_session_profiles,
                    })),
                    Err(e) => {
                        o.code = 2;
                        results.push(json!({"adapter": adv.adapter, "compiles": false, "errors": e.iter().map(|x| x.to_string()).collect::<Vec<_>>()}))
                    }
                }
            }
            if o.json {
                println!("{}", json!({"ok": o.code == 0, "policy": p.name, "rules": p.rules.len(), "adapters": results}));
            } else {
                println!("policy {} is valid ({} rules, {} profiles)", p.name, p.rules.len(), p.profiles.len());
                for r in &results {
                    let ad = r["adapter"].as_str().unwrap_or("?");
                    if r["compiles"] == true {
                        let om = r["omitted"].as_array().map(|a| a.len()).unwrap_or(0);
                        let wn = r["warnings"].as_array().map(|a| a.len()).unwrap_or(0);
                        println!("  {ad}: compiles ({om} rules omitted with report, {wn} warnings)");
                        for x in r["omitted"].as_array().into_iter().flatten() {
                            println!("    omitted {}: {}", x["rule_id"].as_str().unwrap_or(""), x["reason"].as_str().unwrap_or(""));
                        }
                        let up: Vec<&str> =
                            r["unavailable_session_profiles"].as_array().into_iter().flatten().filter_map(|v| v.as_str()).collect();
                        if !up.is_empty() {
                            println!("    protected sessions refused at launch: {}", up.join(", "));
                        }
                    } else {
                        println!("  {ad}: DOES NOT COMPILE");
                        for e in r["errors"].as_array().into_iter().flatten() {
                            println!("    {}", e.as_str().unwrap_or(""));
                        }
                    }
                }
            }
            Ok(())
        }
        Cmd::Compile { policy, adapter, revision, rollback_of, valid_hours, issued_at, out } => {
            let p = load_policy(&policy)?;
            let issued = issued_at.unwrap_or_else(Utc::now);
            let opts =
                CompileOptions { revision, rollback_of, issued_at: issued, not_after: valid_hours.map(|h| issued + Duration::hours(h)) };
            match compile(&p, &adapter.adv(), &opts) {
                Ok(s) => write_out(&out, &serde_json::to_string_pretty(&s).unwrap()),
                Err(e) => {
                    o.code = 2;
                    Err(e.iter().map(|x| x.to_string()).collect::<Vec<_>>().join("; "))
                }
            }
        }
        Cmd::Diff { old, new } => {
            let d = diff(&load_policy(&old)?, &load_policy(&new)?);
            if d.is_broadening() {
                o.code = 3;
            }
            if o.json {
                println!("{}", json!({"diff": d, "broadening": d.is_broadening()}));
            } else if d.is_empty() {
                println!("no changes");
            } else {
                for (label, v) in [
                    ("added", &d.added),
                    ("removed", &d.removed),
                    ("changed", &d.changed),
                    ("profiles", &d.profile_changes),
                    ("sets", &d.set_changes),
                ] {
                    if !v.is_empty() {
                        println!("{label}: {}", v.join(", "));
                    }
                }
                for n in &d.narrowing {
                    println!("narrows: {n}");
                }
                for b in &d.broadening {
                    println!("BROADENS: {b}");
                }
                if d.is_broadening() {
                    println!("This change broadens access. Signing it requires a local owner authorization.");
                }
            }
            Ok(())
        }
        Cmd::Simulate { current, proposed, observations, unacknowledged } => {
            let (c, p) = (load_policy(&current)?, load_policy(&proposed)?);
            let flows = load_flows(&observations)?;
            let e = Enricher::new();
            let plats = [
                CapabilityAdvertisement::macos_network_extension(),
                CapabilityAdvertisement::linux_nftables_cgroup(),
                CapabilityAdvertisement::dns_resolver("adguard-home"),
            ];
            let r = simulate(&SimulationInput {
                current: &c,
                proposed: &p,
                observations: &flows,
                enricher: &e,
                platforms: &plats,
                compile_options: CompileOptions { revision: 0, rollback_of: None, issued_at: Utc::now(), not_after: None },
                unacknowledged_devices: unacknowledged,
            });
            if o.json {
                println!("{}", serde_json::to_string_pretty(&r).unwrap());
            } else {
                println!("replayed {} observations: {} newly blocked, {} newly allowed", r.observations, r.newly_blocked, r.newly_allowed);
                for (app, n) in &r.affected_apps {
                    println!("  affects {app}: {n} flow(s)");
                }
                for ch in &r.changed {
                    println!("  {} {} {}: {} -> {}", ch.device_id, ch.app, ch.destination, ch.before, ch.after);
                }
                if !r.uncertain.is_empty() {
                    println!("uncertain (missing evidence): {}", r.uncertain.join(", "));
                }
                if !r.unobserved_destinations.is_empty() {
                    println!("allowed but never observed: {}", r.unobserved_destinations.join(", "));
                }
                for pl in &r.platforms {
                    if pl.compiles {
                        println!("  {}: compiles; omitted {:?}", pl.adapter, pl.omitted_rules);
                    } else {
                        println!("  {}: unsupported: {}", pl.adapter, pl.errors.join("; "));
                    }
                }
                if !r.unacknowledged_devices.is_empty() {
                    println!("devices not acknowledging the current revision: {}", r.unacknowledged_devices.join(", "));
                }
                println!("{}", r.disclaimer);
            }
            Ok(())
        }
        Cmd::Keygen { out } => {
            if out.exists() {
                return Err(format!("{} exists; refusing to overwrite a signer key", out.display()));
            }
            let k = generate_key();
            let mut f = {
                let mut opts = fs::OpenOptions::new();
                opts.write(true).create_new(true);
                #[cfg(unix)]
                {
                    use std::os::unix::fs::OpenOptionsExt;
                    opts.mode(0o600);
                }
                opts.open(&out).map_err(|e| format!("{}: {e}", out.display()))?
            };
            writeln!(f, "{}", hex::encode(k.to_bytes())).map_err(|e| e.to_string())?;
            let pubp = PathBuf::from(format!("{}.pub", out.display()));
            fs::write(&pubp, format!("{}\n", hex::encode(k.verifying_key().to_bytes()))).map_err(|e| e.to_string())?;
            let id = key_id(&k.verifying_key());
            if o.json {
                println!("{}", json!({"key_id": id, "secret": out, "public": pubp}));
            } else {
                println!("signer key {id}\n  secret: {} (0600; keep out of agent workspaces)\n  public: {}", out.display(), pubp.display());
            }
            Ok(())
        }
        Cmd::Sign { snapshot, key, previous, authorize_broadening, out } => {
            let snap: Snapshot = serde_json::from_str(&read(&snapshot)?).map_err(|e| format!("{}: {e}", snapshot.display()))?;
            if let Err(errs) = snap.policy.validate() {
                o.code = 2;
                return Err(format!("snapshot policy invalid: {}", errs.iter().map(|e| e.to_string()).collect::<Vec<_>>().join("; ")));
            }
            if let Some(prev) = previous {
                let d = diff(&load_policy(&prev)?, &snap.policy);
                if d.is_broadening() && !authorize_broadening {
                    o.code = 3;
                    return Err(format!(
                        "refusing to sign: change broadens access ({}). A local owner must re-run with --authorize-broadening.",
                        d.broadening.join("; ")
                    ));
                }
            }
            let k = signing_key_from_hex(&read(&key)?)?;
            let s = sign_snapshot(&snap, &k);
            write_out(&out, &serde_json::to_string_pretty(&s).unwrap())
        }
        Cmd::Verify { signed, pubkeys, adapter, last_applied } => {
            let s: SignedSnapshot = serde_json::from_str(&read(&signed)?).map_err(|e| format!("{}: {e}", signed.display()))?;
            let mut t = TrustStore::new();
            for p in &pubkeys {
                t.trust(verifying_key_from_hex(&read(p)?)?);
            }
            match verify_snapshot(&s, &t, adapter.platform(), last_applied, Utc::now()) {
                Ok(snap) => {
                    if o.json {
                        println!(
                            "{}",
                            json!({"ok": true, "revision": snap.revision, "rollback_of": snap.rollback_of, "policy_digest": snap.policy_digest, "key_id": s.key_id})
                        );
                    } else {
                        println!(
                            "valid: revision {} of {} for {} signed by {}",
                            snap.revision,
                            snap.policy_name,
                            snap.platform.label(),
                            s.key_id
                        );
                    }
                    Ok(())
                }
                Err(e) => {
                    o.code = 2;
                    Err(format!("rejected: {e}"))
                }
            }
        }
        Cmd::Explain { policy, flow } => {
            let p = load_policy(&policy)?;
            let f: FlowAttempt = serde_json::from_str(&read(&flow)?).map_err(|e| format!("{}: {e}", flow.display()))?;
            let e = Enricher::new();
            let ctx = EvalContext::new(&p, &e, &f.device_id);
            let d = evaluate(&ctx, &f);
            if o.json {
                println!("{}", serde_json::to_string_pretty(&d).unwrap());
            } else {
                let dest = f.hostname.as_ref().map(|h| h.name.clone()).unwrap_or_else(|| f.remote_ip.to_string());
                println!("{} -> {}:{} ({:?})", f.app.display(), dest, f.remote_port, f.transport);
                println!("{}", d.summary());
                println!("profile: {}", d.profile);
                if let Winner::Rule { provenance, .. } = &d.winner {
                    println!("source: {provenance}");
                }
                for ov in &d.overridden {
                    println!("  overrode {} ({} {:?}): {}", ov.id, ov.layer.label(), ov.action, ov.why);
                }
                for n in &d.notes {
                    println!("  note: {n}");
                }
                if d.permitted_by_observation {
                    println!("  This profile observes; the flow was permitted, not enforced.");
                }
            }
            Ok(())
        }
        Cmd::Conformance { dir } => conformance(&dir, o),
    }
}

fn conformance(dir: &Path, o: &mut Out) -> Result<(), String> {
    let mut pass = 0usize;
    let mut failures: Vec<String> = Vec::new();
    let e = Enricher::new();
    let opts = CompileOptions { revision: 1, rollback_of: None, issued_at: Utc::now(), not_after: None };
    for sub in ["policy", "compile"] {
        let d = dir.join("cases").join(sub);
        let mut entries: Vec<PathBuf> = fs::read_dir(&d)
            .map_err(|e| format!("{}: {e}", d.display()))?
            .filter_map(|x| x.ok().map(|x| x.path()))
            .filter(|p| p.extension().is_some_and(|e| e == "json"))
            .collect();
        entries.sort();
        for path in entries {
            let c: Value = serde_json::from_str(&read(&path)?).map_err(|e| format!("{}: {e}", path.display()))?;
            let name = c["name"].as_str().unwrap_or("?").to_string();
            let pol = load_policy(&path.parent().unwrap().join(c["policy"].as_str().unwrap_or("")))?;
            let exp = &c["expect"];
            let res: Result<(), String> = if sub == "policy" {
                (|| {
                    let f: FlowAttempt = serde_json::from_value(c["flow"].clone()).map_err(|e| e.to_string())?;
                    let d = evaluate(&EvalContext::new(&pol, &e, &f.device_id), &f);
                    let want = if exp["verdict"] == "allow" { Verdict::Allow } else { Verdict::Deny };
                    if d.verdict != want {
                        return Err(format!("verdict {:?}, want {:?}", d.verdict, want));
                    }
                    if let Some(w) = exp.get("winner").and_then(|w| w.as_str()) {
                        let got = match &d.winner {
                            Winner::Rule { id, .. } => format!("rule:{id}"),
                            Winner::ProfileDefault { profile, .. } => format!("profile:{profile}"),
                        };
                        if got != w {
                            return Err(format!("winner {got}, want {w}"));
                        }
                    }
                    if let Some(ob) = exp.get("permitted_by_observation").and_then(|v| v.as_bool()) {
                        if d.permitted_by_observation != ob {
                            return Err("permitted_by_observation mismatch".into());
                        }
                    }
                    Ok(())
                })()
            } else {
                let adv = match c["adapter"].as_str().unwrap_or("") {
                    "linux" => Adapter::Linux.adv(),
                    "macos" => Adapter::Macos.adv(),
                    _ => Adapter::Dns.adv(),
                };
                match (compile(&pol, &adv, &opts), exp["compiles"].as_bool().unwrap_or(true)) {
                    (Ok(s), true) => {
                        let missing: Vec<String> = exp
                            .get("omitted_contains")
                            .and_then(|v| v.as_array())
                            .into_iter()
                            .flatten()
                            .filter_map(|v| v.as_str())
                            .filter(|id| !s.report.omitted.iter().any(|o| o.rule_id == *id))
                            .map(String::from)
                            .collect();
                        if missing.is_empty() {
                            Ok(())
                        } else {
                            Err(format!("not omitted: {missing:?}"))
                        }
                    }
                    (Err(_), false) => Ok(()),
                    (Ok(_), false) => Err("compiled but expected rejection".into()),
                    (Err(e), true) => Err(format!("rejected: {e:?}")),
                }
            };
            match res {
                Ok(()) => pass += 1,
                Err(m) => failures.push(format!("{sub}/{name}: {m}")),
            }
        }
    }
    if !failures.is_empty() {
        o.code = 4;
    }
    if o.json {
        println!("{}", json!({"passed": pass, "failed": failures}));
    } else {
        println!("conformance: {pass} passed, {} failed", failures.len());
        for f in &failures {
            println!("  FAIL {f}");
        }
    }
    Ok(())
}
