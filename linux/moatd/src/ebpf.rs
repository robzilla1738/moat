//! Connect-time attribution for ordinary apps (W10 increment 2), **observe-only**.
//!
//! The socket-table inventory (`crate::inventory`) samples, so a process that connects and exits between passes is
//! only counted as loss. This collector attributes each TCP connect in the kernel, in the connecting task's
//! context, through `tracepoint:sock:inet_sock_set_state` (CLOSE -> SYN_SENT), using `bpftrace` as the loader (no
//! new kernel code ships with Moat; bpftrace is an optional runtime dependency, probed, never assumed).
//!
//! Loss is reported, never hidden:
//! * bpftrace reports perf/ring-buffer overflow as `Lost N events`; each becomes an `inventory_loss` record with
//!   scope `ebpf_buffer` and the exact count.
//! * The script prints a heartbeat every second. Missing heartbeats become `inventory_loss` scope `ebpf_stalled`
//!   (count unknown, reported as 0 with that statement); the tracer exiting becomes scope `ebpf_stopped`.
//! * Lines the decoder cannot parse are counted (`ebpf_unparsed`).
//! * A PID whose /proc start time is later than the connect was reused: its identity is discarded with a reason.
//!
//! Scope limits (stated in the coverage note): TCP connects only (UDP is not attributed by this path); every network
//! namespace is seen (the tracepoint is global) but the namespace is not reported; comm is set by the process and is
//! a hint. Nothing here enforces anything: Moat's ruleset is untouched, and no ordinary-app rule is supported on
//! Linux (no enforcement hook proven, docs/decisions/W10-enforcement.md).

use std::io::{BufRead, BufReader};
use std::process::{Child, Command, Stdio};
use std::sync::mpsc::{channel, Receiver, TryRecvError};
use std::time::{Duration, Instant};

use crate::inventory::{Identity, InventoryEvent, KernelAttribution, Transport, COVERAGE};

pub const MEASUREMENT: &str = "ebpf:tracepoint:sock:inet_sock_set_state";

/// The tracer program. Output lines: `C <ns> <pid> <uid> <cgroup> <4|6> <daddr> <dport> <comm>` and `H <ns>`.
pub const SCRIPT: &str = r#"
tracepoint:sock:inet_sock_set_state
/args->newstate == 2 && args->oldstate == 7/
{
  if (args->family == 2) {
    printf("C %llu %d %d %llu 4 %s %d %s\n", nsecs, pid, uid, cgroup, ntop(args->daddr), args->dport, comm);
  } else {
    printf("C %llu %d %d %llu 6 %s %d %s\n", nsecs, pid, uid, cgroup, ntop(args->daddr_v6), args->dport, comm);
  }
}
interval:s:1 { printf("H %llu\n", nsecs); }
"#;

/// A heartbeat older than this is a stall.
pub const STALL_AFTER: Duration = Duration::from_secs(3);

pub fn coverage_note() -> &'static str {
    "observe_only: TCP connects attributed in the kernel at connect time (pid, uid, comm, cgroup id), all network \
     namespaces, via bpftrace on tracepoint sock:inet_sock_set_state; executable identity from /proc afterwards when \
     the process still exists. Buffer overflow, stalls and tracer exit are reported as loss. UDP is not attributed \
     by this path. Not enforced."
}

/// Turns tracer output into inventory records. Pure: the tests drive it with fixture lines.
pub struct Decoder {
    pub attached: bool,
    last_heartbeat: Option<Instant>,
    stall_reported: bool,
    unparsed: u64,
    /// The first few unparsed lines since the last report, verbatim (tracer errors and warnings land here).
    unparsed_sample: Vec<String>,
    /// Nanoseconds per /proc clock tick (start_generation unit), for the PID-reuse guard.
    ns_per_tick: u64,
}

impl Decoder {
    pub fn new(clk_tck: u64) -> Self {
        Decoder {
            attached: false,
            last_heartbeat: None,
            stall_reported: false,
            unparsed: 0,
            unparsed_sample: Vec::new(),
            ns_per_tick: 1_000_000_000 / clk_tck.max(1),
        }
    }

    fn loss(scope: &str, count: u64, detail: String) -> InventoryEvent {
        InventoryEvent::InventoryLoss { coverage: COVERAGE.into(), scope: scope.into(), count, detail }
    }

    /// Feed one output line. `identity` looks a pid up in /proc (None if gone).
    pub fn feed(&mut self, line: &str, now: Instant, identity: &dyn Fn(u32) -> Option<Identity>) -> Option<InventoryEvent> {
        let line = line.trim_end();
        if let Some(rest) = line.strip_prefix("H ") {
            if rest.trim().parse::<u64>().is_ok() {
                self.attached = true;
                self.last_heartbeat = Some(now);
                self.stall_reported = false;
                return None;
            }
        }
        if let Some(n) = line.strip_prefix("Lost ").and_then(|r| r.strip_suffix(" events")).and_then(|n| n.trim().parse::<u64>().ok()) {
            return Some(Self::loss(
                "ebpf_buffer",
                n,
                format!("the kernel dropped {n} connect events before the tracer read them (buffer overflow)"),
            ));
        }
        // "Attaching N probes..." (older bpftrace) / "Attached N probe(s)" (0.25): informational, not connect data.
        if line.starts_with("Attaching ") || line.starts_with("Attached ") || line.is_empty() {
            return None;
        }
        match parse_connect(line) {
            Some((k, remote)) => Some(self.attribute(k, remote, identity)),
            None => {
                self.unparsed += 1;
                if self.unparsed_sample.len() < 5 {
                    self.unparsed_sample.push(line.chars().take(300).collect());
                }
                None
            }
        }
    }

    fn attribute(&self, k: KernelAttribution, remote: String, identity: &dyn Fn(u32) -> Option<Identity>) -> InventoryEvent {
        let (identity, unknown_reason) = match identity(k.pid) {
            None => (None, Some("process exited before its executable could be read; kernel attribution only".to_string())),
            Some(id) if id.start_generation.saturating_mul(self.ns_per_tick) > k.at_ns + 1_000_000_000 => (
                None,
                Some(format!("pid {} was reused after the connect (process started later); identity not attributed by guess", k.pid)),
            ),
            Some(id) if id.uid != k.uid => {
                (None, Some(format!("pid {} now has uid {} (kernel saw uid {}); not attributed by guess", k.pid, id.uid, k.uid)))
            }
            Some(id) => (Some(id), None),
        };
        InventoryEvent::ConnectAttempt {
            coverage: COVERAGE.into(),
            measurement_source: MEASUREMENT.into(),
            transport: Transport::Tcp,
            remote,
            kernel: k,
            identity,
            unknown_reason,
        }
    }

    /// Periodic checks: a missing heartbeat (once per stall) and unparsed lines since the last call.
    pub fn check(&mut self, now: Instant) -> Vec<InventoryEvent> {
        let mut out = Vec::new();
        if let Some(h) = self.last_heartbeat {
            if now.duration_since(h) > STALL_AFTER && !self.stall_reported {
                self.stall_reported = true;
                out.push(Self::loss(
                    "ebpf_stalled",
                    0,
                    format!(
                        "no tracer heartbeat for {} s: connects in this period may be missing (count unknown)",
                        now.duration_since(h).as_secs()
                    ),
                ));
            }
        }
        if self.unparsed > 0 {
            let sample = std::mem::take(&mut self.unparsed_sample);
            out.push(Self::loss(
                "ebpf_unparsed",
                self.unparsed,
                format!("{} tracer lines could not be parsed; first: {}", self.unparsed, sample.join(" | ")),
            ));
            self.unparsed = 0;
        }
        out
    }

    pub fn stopped(&self, why: &str) -> InventoryEvent {
        Self::loss("ebpf_stopped", 0, format!("the connect tracer stopped ({why}): no connect-time attribution until it restarts"))
    }
}

fn parse_connect(line: &str) -> Option<(KernelAttribution, String)> {
    let mut it = line.splitn(9, ' ');
    if it.next()? != "C" {
        return None;
    }
    let at_ns = it.next()?.parse().ok()?;
    let pid = it.next()?.parse().ok()?;
    let uid = it.next()?.parse().ok()?;
    let cgroup_id = it.next()?.parse().ok()?;
    let fam = it.next()?;
    let ip: std::net::IpAddr = it.next()?.parse().ok()?;
    let port: u16 = it.next()?.parse().ok()?;
    let comm = it.next().unwrap_or("").to_string();
    let remote = match (fam, ip) {
        ("4", std::net::IpAddr::V4(_)) | ("6", std::net::IpAddr::V6(_)) => std::net::SocketAddr::new(ip, port).to_string(),
        _ => return None,
    };
    Some((KernelAttribution { pid, uid, comm, cgroup_id, at_ns }, remote))
}

/// A running bpftrace process feeding a `Decoder`.
pub struct Tracer {
    child: Child,
    rx: Receiver<String>,
    pub decoder: Decoder,
    stopped_reported: bool,
}

pub fn clk_tck() -> u64 {
    // SAFETY: sysconf has no preconditions.
    let v = unsafe { libc::sysconf(libc::_SC_CLK_TCK) };
    if v > 0 {
        v as u64
    } else {
        100
    }
}

impl Tracer {
    /// Start `bpftrace` with `SCRIPT`. `perf_rb_pages` sets bpftrace's per-CPU buffer size (tests use a tiny one to
    /// force and measure loss).
    pub fn start(bpftrace: &str, perf_rb_pages: Option<u32>) -> std::io::Result<Tracer> {
        let mut cmd = Command::new(bpftrace);
        // -B line: bpftrace's stdout is a pipe here; line buffering keeps heartbeats and connects timely.
        cmd.arg("-B").arg("line").arg("-e").arg(SCRIPT).stdout(Stdio::piped()).stderr(Stdio::piped()).stdin(Stdio::null());
        if let Some(p) = perf_rb_pages {
            cmd.env("BPFTRACE_PERF_RB_PAGES", p.to_string());
        }
        let mut child = cmd.spawn()?;
        let (tx, rx) = channel();
        for r in [
            child.stdout.take().map(|s| Box::new(s) as Box<dyn std::io::Read + Send>),
            child.stderr.take().map(|s| Box::new(s) as Box<dyn std::io::Read + Send>),
        ]
        .into_iter()
        .flatten()
        {
            let tx = tx.clone();
            std::thread::spawn(move || {
                for l in BufReader::new(r).lines().map_while(Result::ok) {
                    if tx.send(l).is_err() {
                        break;
                    }
                }
            });
        }
        Ok(Tracer { child, rx, decoder: Decoder::new(clk_tck()), stopped_reported: false })
    }

    /// Everything available now, plus periodic checks and a one-time `ebpf_stopped` if the tracer exited.
    pub fn drain(&mut self, identity: &dyn Fn(u32) -> Option<Identity>) -> Vec<InventoryEvent> {
        let mut out = Vec::new();
        let now = Instant::now();
        loop {
            match self.rx.try_recv() {
                Ok(l) => out.extend(self.decoder.feed(&l, now, identity)),
                Err(TryRecvError::Empty) => break,
                Err(TryRecvError::Disconnected) => break,
            }
        }
        out.extend(self.decoder.check(now));
        if !self.stopped_reported {
            if let Ok(Some(st)) = self.child.try_wait() {
                self.stopped_reported = true;
                out.push(self.decoder.stopped(&format!("bpftrace exited: {st}")));
            }
        }
        out
    }

    pub fn stop(mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ident(pid: u32, start_generation: u64, uid: u32) -> Identity {
        Identity {
            pid,
            start_generation,
            executable: "/usr/bin/curl".into(),
            executable_replaced: false,
            uid,
            cgroup: "/user.slice".into(),
            script: None,
            confidence: "medium".into(),
        }
    }

    #[test]
    fn connect_lines_carry_kernel_attribution_and_identity() {
        let mut d = Decoder::new(100);
        let id = |pid: u32| (pid == 4242).then(|| ident(4242, 100, 1000)); // started at 1 s
        let ev = d.feed("C 5000000000 4242 1000 7781 4 10.77.0.2 7101 curl", Instant::now(), &id).unwrap();
        match ev {
            InventoryEvent::ConnectAttempt { coverage, remote, kernel, identity, unknown_reason, measurement_source, .. } => {
                assert_eq!(coverage, "observe_only");
                assert_eq!(measurement_source, MEASUREMENT);
                assert_eq!(remote, "10.77.0.2:7101");
                assert_eq!((kernel.pid, kernel.uid, kernel.cgroup_id, kernel.comm.as_str()), (4242, 1000, 7781, "curl"));
                assert_eq!(identity.unwrap().executable, "/usr/bin/curl");
                assert!(unknown_reason.is_none());
            }
            e => panic!("{e:?}"),
        }
        let v6 = d.feed("C 5000000000 4242 1000 7781 6 fd77::2 7101 python3 x", Instant::now(), &id).unwrap();
        assert!(
            matches!(v6, InventoryEvent::ConnectAttempt { ref remote, ref kernel, .. } if remote == "[fd77::2]:7101" && kernel.comm == "python3 x")
        );
    }

    #[test]
    fn exited_and_reused_pids_are_not_attributed_by_guess() {
        let mut d = Decoder::new(100);
        let gone = |_| None;
        let ev = d.feed("C 5000000000 77 1000 1 4 10.0.0.1 443 short", Instant::now(), &gone).unwrap();
        assert!(
            matches!(ev, InventoryEvent::ConnectAttempt { identity: None, unknown_reason: Some(ref r), ref kernel, .. } if r.contains("exited") && kernel.comm == "short")
        );
        // pid 77 now belongs to a process that started at 9 s, after the 5 s connect
        let reused = |_| Some(ident(77, 900, 1000));
        let ev = d.feed("C 5000000000 77 1000 1 4 10.0.0.1 443 short", Instant::now(), &reused).unwrap();
        assert!(matches!(ev, InventoryEvent::ConnectAttempt { identity: None, unknown_reason: Some(ref r), .. } if r.contains("reused")));
        let other_uid = |_| Some(ident(77, 100, 0));
        let ev = d.feed("C 5000000000 77 1000 1 4 10.0.0.1 443 short", Instant::now(), &other_uid).unwrap();
        assert!(matches!(ev, InventoryEvent::ConnectAttempt { identity: None, unknown_reason: Some(ref r), .. } if r.contains("uid")));
    }

    #[test]
    fn buffer_loss_stalls_unparsed_lines_and_exit_are_reported() {
        let mut d = Decoder::new(100);
        let none = |_| None;
        let t0 = Instant::now();
        assert!(d.feed("Attaching 2 probes...", t0, &none).is_none());
        assert!(d.feed("Attached 2 probes", t0, &none).is_none());
        assert!(d.feed("H 1000", t0, &none).is_none());
        assert!(d.attached);
        let lost = d.feed("Lost 1234 events", t0, &none).unwrap();
        assert!(matches!(lost, InventoryEvent::InventoryLoss { ref scope, count: 1234, .. } if scope == "ebpf_buffer"));
        assert!(d.feed("C garbage", t0, &none).is_none());
        assert!(d.feed("C 1 2 3 4 4 not-an-ip 80 x", t0, &none).is_none());
        assert!(d.feed("C 1 2 3 4 6 10.0.0.1 80 family-mismatch", t0, &none).is_none());
        let checks = d.check(t0 + Duration::from_secs(1));
        assert!(checks.iter().any(
            |e| matches!(e, InventoryEvent::InventoryLoss { scope, count: 3, detail, .. } if scope == "ebpf_unparsed" && detail.contains("not-an-ip"))
        ));
        assert!(d.check(t0 + Duration::from_secs(1)).is_empty(), "unparsed counts are reported once");
        let stall = d.check(t0 + Duration::from_secs(5));
        assert!(stall.iter().any(|e| matches!(e, InventoryEvent::InventoryLoss { scope, .. } if scope == "ebpf_stalled")));
        assert!(d.check(t0 + Duration::from_secs(6)).is_empty(), "one report per stall");
        d.feed("H 7000", t0 + Duration::from_secs(7), &none);
        assert!(d.check(t0 + Duration::from_secs(8)).is_empty(), "heartbeat resumed");
        assert!(matches!(d.stopped("exit 1"), InventoryEvent::InventoryLoss { scope, .. } if scope == "ebpf_stopped"));
    }

    #[test]
    fn the_script_traces_connect_starts_and_heartbeats() {
        assert!(SCRIPT.contains("tracepoint:sock:inet_sock_set_state"));
        assert!(SCRIPT.contains("args->newstate == 2 && args->oldstate == 7"));
        assert!(SCRIPT.contains("interval:s:1"));
        assert!(coverage_note().starts_with("observe_only"));
    }
}
