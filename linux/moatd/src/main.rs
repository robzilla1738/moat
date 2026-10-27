//! `moatd` — Moat Linux endpoint daemon and local recovery CLI.

use std::fs;
use std::path::PathBuf;
use std::process::ExitCode;
use std::time::Duration;

use clap::{Parser, Subcommand};
use ipnet::IpNet;
use moatd::cgroup::{boot_id, Cgroups};
use moatd::control::{replies, send, Reply, Request};
use moatd::endpoint::Endpoint;
use moatd::nft::{self, NftBackend, NftCli};
use moatd::recovery::RecoveryState;
use moatd::spool::{Spool, SpoolConfig};

#[derive(Parser)]
#[command(name = "moatd", version, about = "Moat Linux endpoint: nftables enforcement, cgroup v2 protected sessions, event spool")]
struct Cli {
    #[arg(long, default_value = "/var/lib/moat", global = true)]
    state: PathBuf,
    #[arg(long, default_value = "/run/moat/control.sock", global = true)]
    socket: PathBuf,
    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Subcommand)]
enum Cmd {
    /// Run the daemon (systemd: moatd.service).
    Run {
        /// Device id used in events and device-group matching. Default: /etc/hostname.
        #[arg(long)]
        device_id: Option<String>,
        #[arg(long, default_value = "/sys/fs/cgroup")]
        cgroup_mount: PathBuf,
        /// Spool disk quota in MiB.
        #[arg(long, default_value_t = 256)]
        spool_mib: u64,
        #[arg(long, default_value_t = 2)]
        tick_secs: u64,
        /// Do not run the session egress proxy: hostname rules in protected sessions are then left out (allows,
        /// stricter) or refused (denies), exactly as on an IP-only host.
        #[arg(long)]
        no_egress_proxy: bool,
        /// Loopback port range for session egress-proxy listeners (keep it outside the ephemeral range).
        #[arg(long, default_value = "15000-15999")]
        egress_proxy_ports: String,
        /// Observe-only inventory of ordinary (non-launcher) app connections, sampled every N milliseconds into the
        /// spool (W10). Off unless set. Never enforces anything.
        #[arg(long)]
        ordinary_inventory_ms: Option<u64>,
        /// Also attribute ordinary-app TCP connects at connect time with this bpftrace binary (W10 increment 2,
        /// observe-only; buffer loss, stalls and tracer exit are spooled as inventory_loss). Off unless set.
        #[arg(long)]
        ordinary_inventory_bpftrace: Option<String>,
    },
    /// Observe-only ordinary-app inventory in the foreground: JSON lines on stdout (W10). Never enforces anything.
    Inventory {
        /// Sampling interval in milliseconds.
        #[arg(long, default_value_t = 200)]
        interval_ms: u64,
        /// Stop after this many seconds (default: run until killed). With --ebpf, counted from the moment the tracer
        /// attached.
        #[arg(long)]
        seconds: Option<u64>,
        /// Connect-time attribution with this bpftrace binary instead of socket-table sampling (W10 increment 2).
        #[arg(long)]
        ebpf: Option<String>,
        /// bpftrace per-CPU buffer pages (tests force loss with a tiny buffer).
        #[arg(long)]
        perf_rb_pages: Option<u32>,
    },
    /// Queue a signed snapshot for the daemon (copied into <state>/inbox).
    Apply {
        signed: PathBuf,
        /// Install on trial: the daemon reverts to the last confirmed revision after this many seconds unless
        /// `moatd recover confirm` runs first.
        #[arg(long)]
        trial_secs: Option<u64>,
    },
    /// Show daemon status (coverage, revision, sessions).
    Status,
    /// Print this host's capability advertisement (probed, never upgraded).
    Capabilities {
        #[arg(long, default_value = "/sys/fs/cgroup")]
        cgroup_mount: PathBuf,
    },
    /// Render the nftables ruleset for a signed snapshot without applying it.
    Render {
        signed: PathBuf,
        #[arg(long)]
        device_id: String,
    },
    /// Print the local isolation table `moatd recover isolate` installs (nft syntax), without installing it.
    RenderIsolation {
        #[arg(long = "keep")]
        keep: Vec<IpNet>,
    },
    /// Trust a policy signer public key (hex file).
    Trust {
        pubkey: PathBuf,
        /// This is the device owner's local key: revisions it signs are reported to the controller as a
        /// `local_change` (fleet distribution to this device is then held until the owner resolves it).
        #[arg(long)]
        local_owner: bool,
    },
    /// Fleet sync: record the controller's contiguous `acked_seq` (the daemon removes acknowledged spool segments).
    SpoolAck { seq: u64 },
    /// Fleet sync: print `spool/sync-state.json` (spool_low_seq, acked_seq, next_seq, local_change).
    SyncState,
    /// Local recovery (root, on this device). Works with the daemon stopped.
    #[command(subcommand)]
    Recover(Recover),
}

#[derive(Subcommand)]
enum Recover {
    Status,
    /// Remove Moat's enforcement table and keep it removed until `resume`. Protected sessions are refused meanwhile.
    Disable {
        #[arg(long)]
        reason: String,
    },
    Resume,
    /// Whole-device isolation except loopback and the given recovery paths. Does not reopen on its own.
    Isolate {
        #[arg(long = "keep")]
        keep: Vec<IpNet>,
    },
    ClearIsolation,
    /// Keep the revision that is on trial (ends the countdown).
    Confirm,
    /// Revert the revision on trial to the last confirmed one now.
    Rollback,
}

fn hostname() -> String {
    fs::read_to_string("/etc/hostname").map(|s| s.trim().to_string()).unwrap_or_else(|_| "linux".into())
}

fn require_root() -> Result<u32, String> {
    let uid = nix::unistd::getuid().as_raw();
    if uid != 0 {
        return Err("this command must run as root on the device".into());
    }
    Ok(uid)
}

fn main() -> ExitCode {
    let cli = Cli::parse();
    match run(cli) {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("moatd: {e}");
            ExitCode::from(1)
        }
    }
}

fn run(cli: Cli) -> Result<(), String> {
    match cli.cmd {
        Cmd::Run {
            device_id,
            cgroup_mount,
            spool_mib,
            tick_secs,
            no_egress_proxy,
            egress_proxy_ports,
            ordinary_inventory_ms,
            ordinary_inventory_bpftrace,
        } => {
            let ports = egress_proxy_ports
                .split_once('-')
                .and_then(|(a, b)| Some((a.parse::<u16>().ok()?, b.parse::<u16>().ok()?)))
                .filter(|(a, b)| a <= b && *a > 0)
                .ok_or("--egress-proxy-ports must look like 15000-15999")?;
            require_root()?;
            let device_id = device_id.unwrap_or_else(hostname);
            fs::create_dir_all(&cli.state).map_err(|e| e.to_string())?;
            let spool = Spool::open(SpoolConfig {
                dir: cli.state.join("spool"),
                device_id: device_id.clone(),
                boot_id: boot_id(),
                max_bytes: spool_mib * 1024 * 1024,
                segment_bytes: 4 * 1024 * 1024,
            })
            .map_err(|e| e.to_string())?;
            let cg = Cgroups { mount: cgroup_mount.clone(), root_name: "moat.slice".into() };
            let _ = cg.ensure_profiles(&[]);
            let mut facts = moatd::probe::gather(&cgroup_mount, "moat.slice", "nft");
            facts.egress_proxy_disabled = no_egress_proxy;
            let adv = moatd::probe::advertise(&facts);
            let mut ep = Endpoint::new(cli.state.clone(), device_id, NftCli::default(), cg, spool, adv);
            if !no_egress_proxy {
                let shared = std::sync::Arc::new(moatd::proxy::Shared::new(Box::new(moatd::proxy::system_resolver)));
                ep = ep.with_proxy(moatd::proxy::ProxyManager::new(shared, ports));
            }
            ep.startup();
            eprintln!("moatd: coverage {}", ep.coverage_label());
            moatd::server::serve_with(
                ep,
                cli.socket,
                Duration::from_secs(tick_secs),
                ordinary_inventory_ms.map(Duration::from_millis),
                ordinary_inventory_bpftrace,
            )
            .map_err(|e| e.to_string())
        }
        Cmd::Inventory { interval_ms, seconds, ebpf: Some(bpftrace), perf_rb_pages } => {
            use moatd::inventory::{ProcFs, Source};
            let src = ProcFs::default();
            let mut t = moatd::ebpf::Tracer::start(&bpftrace, perf_rb_pages).map_err(|e| format!("{bpftrace}: {e}"))?;
            println!(
                "{}",
                serde_json::json!({"type": "coverage", "coverage": moatd::inventory::COVERAGE, "note": moatd::ebpf::coverage_note()})
            );
            // --seconds counts attached tracing time: bpftrace may take many seconds to compile and attach.
            let launched = std::time::Instant::now();
            let mut start = launched;
            let mut announced = false;
            let ident = |pid: u32| src.identity(pid);
            loop {
                for ev in t.drain(&ident) {
                    println!("{}", serde_json::to_string(&ev).unwrap());
                }
                if t.decoder.attached && !announced {
                    announced = true;
                    start = std::time::Instant::now();
                    println!(
                        "{}",
                        serde_json::json!({"type": "sensor_attached", "measurement_source": moatd::ebpf::MEASUREMENT, "attach_ms": launched.elapsed().as_millis() as u64})
                    );
                }
                use std::io::Write;
                let _ = std::io::stdout().flush();
                if !announced && launched.elapsed() >= Duration::from_secs(180) {
                    for ev in t.drain(&ident) {
                        println!("{}", serde_json::to_string(&ev).unwrap());
                    }
                    t.stop();
                    return Err("bpftrace did not attach within 180 s (see ebpf_unparsed records for its output)".into());
                }
                if announced && seconds.is_some_and(|s| start.elapsed() >= Duration::from_secs(s)) {
                    // let the tracer flush what it already has (and its loss counters) before stopping
                    std::thread::sleep(Duration::from_millis(1500));
                    for ev in t.drain(&ident) {
                        println!("{}", serde_json::to_string(&ev).unwrap());
                    }
                    t.stop();
                    return Ok(());
                }
                std::thread::sleep(Duration::from_millis(interval_ms.clamp(10, 200)));
            }
        }
        Cmd::Inventory { interval_ms, seconds, ebpf: None, .. } => {
            use moatd::inventory::{Inventory, ProcFs};
            let src = ProcFs::default();
            let mut inv = Inventory::new();
            let start = std::time::Instant::now();
            println!(
                "{}",
                serde_json::json!({"type": "coverage", "coverage": moatd::inventory::COVERAGE, "note": Inventory::coverage_note()})
            );
            loop {
                for ev in inv.tick(&src) {
                    println!("{}", serde_json::to_string(&ev).unwrap());
                }
                use std::io::Write;
                let _ = std::io::stdout().flush();
                if seconds.is_some_and(|s| start.elapsed() >= Duration::from_secs(s)) {
                    return Ok(());
                }
                std::thread::sleep(Duration::from_millis(interval_ms.max(10)));
            }
        }
        Cmd::Apply { signed, trial_secs } => {
            let inbox = cli.state.join("inbox");
            fs::create_dir_all(&inbox).map_err(|e| e.to_string())?;
            let stem = chrono::Utc::now().format("%Y%m%d%H%M%S%f").to_string();
            // The sidecar is written first so the daemon never sees the snapshot without its trial marker.
            if let Some(secs) = trial_secs {
                fs::write(inbox.join(format!("{stem}.trial")), secs.to_string()).map_err(|e| e.to_string())?;
            }
            let tmp = inbox.join(format!("{stem}.part"));
            fs::copy(&signed, &tmp).map_err(|e| e.to_string())?;
            fs::rename(&tmp, inbox.join(format!("{stem}.json"))).map_err(|e| e.to_string())?;
            match trial_secs {
                Some(s) => println!(
                    "queued {} on a {s}s trial; it reverts to the last confirmed revision unless `moatd recover confirm` runs in time",
                    signed.display()
                ),
                None => println!("queued {} for moatd", signed.display()),
            }
            Ok(())
        }
        Cmd::Status => {
            let s = std::os::unix::net::UnixStream::connect(&cli.socket)
                .map_err(|e| format!("daemon not reachable at {}: {e}", cli.socket.display()))?;
            send(&s, &Request::Status, &[]).map_err(|e| e.to_string())?;
            if let Some(Reply::Status { status }) = replies(&s).next() {
                println!("{}", serde_json::to_string_pretty(&status).unwrap());
            }
            Ok(())
        }
        Cmd::Capabilities { cgroup_mount } => {
            if nix::unistd::getuid().is_root() {
                let _ = Cgroups { mount: cgroup_mount.clone(), root_name: "moat.slice".into() }.ensure_profiles(&[]);
            }
            let facts = moatd::probe::gather(&cgroup_mount, "moat.slice", "nft");
            let adv = moatd::probe::advertise(&facts);
            println!("{}", serde_json::to_string_pretty(&serde_json::json!({"host": facts, "advertisement": adv})).unwrap());
            Ok(())
        }
        Cmd::RenderIsolation { keep } => {
            print!("{}", nft::render_local_emergency(&keep));
            Ok(())
        }
        Cmd::Render { signed, device_id } => {
            let s: moat_core::signing::SignedSnapshot =
                serde_json::from_str(&fs::read_to_string(&signed).map_err(|e| e.to_string())?).map_err(|e| e.to_string())?;
            let trust = moatd::endpoint::load_trust(&cli.state.join("trusted"));
            let snap = moat_core::signing::verify_snapshot_for_device(
                &s,
                &trust,
                moat_core::Platform::Linux,
                Some(&device_id),
                None,
                chrono::Utc::now(),
            )
            .map_err(|e| e.to_string())?;
            let (rules, rep) =
                nft::render(&snap, &device_id, &nft::CgroupLayout::default(), &moatd::endpoint::lookup_uid).map_err(|e| e.0)?;
            print!("{rules}");
            eprintln!("{}", serde_json::to_string_pretty(&rep).unwrap());
            Ok(())
        }
        Cmd::Trust { pubkey, local_owner } => {
            require_root()?;
            let hexs = fs::read_to_string(&pubkey).map_err(|e| e.to_string())?;
            let vk = moat_core::signing::verifying_key_from_hex(&hexs)?;
            let id = moat_core::signing::key_id(&vk);
            let dir = cli.state.join("trusted");
            fs::create_dir_all(&dir).map_err(|e| e.to_string())?;
            let name = if local_owner { format!("{id}{}", moatd::endpoint::LOCAL_OWNER_SUFFIX) } else { format!("{id}.pub") };
            fs::write(dir.join(name), hexs.trim()).map_err(|e| e.to_string())?;
            println!("trusted {} {id}", if local_owner { "local owner key" } else { "signer" });
            Ok(())
        }
        Cmd::SpoolAck { seq } => {
            require_root()?;
            let dir = cli.state.join("spool");
            fs::create_dir_all(&dir).map_err(|e| e.to_string())?;
            let tmp = dir.join(format!("{}.tmp", moatd::spool::ACKED_FILE));
            fs::write(&tmp, seq.to_string()).map_err(|e| e.to_string())?;
            fs::rename(&tmp, dir.join(moatd::spool::ACKED_FILE)).map_err(|e| e.to_string())?;
            println!("acknowledged through {seq}; the daemon applies it on its next tick (never lowered, never beyond what it wrote)");
            Ok(())
        }
        Cmd::SyncState => {
            let p = cli.state.join("spool").join(moatd::spool::SYNC_STATE_FILE);
            let t = fs::read_to_string(&p).map_err(|e| format!("{}: {e} (is moatd running?)", p.display()))?;
            println!("{}", t.trim());
            Ok(())
        }
        Cmd::Recover(r) => recover(&cli.state, r),
    }
}

fn recover(state: &std::path::Path, r: Recover) -> Result<(), String> {
    let mut rec = RecoveryState::load(state);
    if let Recover::Status = r {
        let trial = moatd::trial::TrialState::load(state);
        println!("{}", serde_json::to_string_pretty(&serde_json::json!({"recovery": rec, "trial": trial})).unwrap());
        return Ok(());
    }
    let uid = require_root()?;
    if matches!(r, Recover::Confirm | Recover::Rollback) {
        let mut t = moatd::trial::TrialState::load(state).ok_or("no revision is on trial")?;
        t.changed_by_uid = Some(uid);
        let confirm = matches!(r, Recover::Confirm);
        if confirm {
            t.confirmed = true;
        } else {
            t.revert_now = true;
        }
        t.save(state).map_err(|e| e.to_string())?;
        if confirm {
            println!("Revision {} confirmed; the daemon ends the trial on its next tick.", t.revision);
        } else {
            println!("Revision {} will be reverted to {} on the daemon's next tick.", t.revision, t.fallback_revision);
        }
        return Ok(());
    }
    let mut nft = NftCli::default();
    rec.changed_by_uid = Some(uid);
    rec.changed_at = Some(chrono::Utc::now());
    match r {
        Recover::Status | Recover::Confirm | Recover::Rollback => unreachable!(),
        Recover::Disable { reason } => {
            rec.enforcement_disabled = true;
            rec.reason = Some(reason);
            rec.save(state).map_err(|e| e.to_string())?;
            nft.delete_table(nft::TABLE).map_err(|e| format!("state saved, but removing the table failed: {e}"))?;
            println!("Moat enforcement disabled on this device. Protected sessions are refused until `moatd recover resume`.");
        }
        Recover::Resume => {
            rec.enforcement_disabled = false;
            rec.reason = None;
            rec.save(state).map_err(|e| e.to_string())?;
            println!("Enforcement will resume on the daemon's next tick with the last valid policy.");
        }
        Recover::Isolate { keep } => {
            rec.isolation = moatd::recovery::Isolation { active: true, keep: keep.clone(), since: Some(chrono::Utc::now()) };
            rec.save(state).map_err(|e| e.to_string())?;
            nft.apply(&nft::render_local_emergency(&keep))?;
            println!(
                "Device isolated. Kept: loopback{}. Only `moatd recover clear-isolation` reopens.",
                keep.iter().map(|k| format!(", {k}")).collect::<String>()
            );
        }
        Recover::ClearIsolation => {
            rec.isolation.active = false;
            rec.save(state).map_err(|e| e.to_string())?;
            nft.delete_table(nft::LOCAL_EMERGENCY_TABLE)?;
            println!("Isolation cleared.");
        }
    }
    Ok(())
}
