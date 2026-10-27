//! Ordinary-app inventory on Linux (W10), **observe-only**.
//!
//! What it does: every tick it reads the kernel's socket tables for this network namespace
//! (`/proc/net/{tcp,tcp6,udp,udp6}`), reports each newly seen connected socket once, and attributes it to a process
//! by finding the socket inode among `/proc/<pid>/fd`. Identity is the executable path, the process start generation
//! (boot-relative start time, so a reused PID is a different process), the uid, the cgroup and, for interpreters,
//! the script argument. It never changes what traffic is allowed: Moat's nftables ruleset is untouched by it.
//!
//! What it does **not** hide (W09 decision, docs/decisions/W09-linux-ordinary-apps.md):
//! * Sampling misses short-lived connections. For TCP the kernel counts every active open
//!   (`/proc/net/snmp` `Tcp: ActiveOpens`, both families); each tick the inventory compares that delta with the
//!   outbound TCP sockets it actually saw and reports the difference as an `inventory_loss` event. UDP has no
//!   per-flow kernel counter, so UDP completeness is reported as unmeasured, never as complete.
//! * A socket whose owning process cannot be found (it exited, it is in another PID namespace, /proc is restricted)
//!   is reported with `identity: null` and a reason. It is never attributed by guess.
//! * Sockets in other network namespaces (containers, other netns) are not in these tables at all; the coverage note
//!   says so.
//! * Two scripts run by the same interpreter share an executable; they are told apart only by the script argument,
//!   which a process can rewrite. Such identities carry `confidence: low`.

use std::collections::{BTreeMap, HashMap, HashSet};
use std::fs;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

pub const COVERAGE: &str = "observe_only";

#[derive(Serialize, Deserialize, Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
#[serde(rename_all = "lowercase")]
pub enum Transport {
    Tcp,
    Udp,
}

/// One row of /proc/net/{tcp,tcp6,udp,udp6}.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SockRow {
    pub transport: Transport,
    pub local: SocketAddr,
    pub remote: SocketAddr,
    pub state: u8,
    pub uid: u32,
    pub inode: u64,
}

#[cfg(test)]
const TCP_SYN_SENT: u8 = 0x02;
const TCP_LISTEN: u8 = 0x0A;

fn parse_v4(hex: &str) -> Option<Ipv4Addr> {
    let n = u32::from_str_radix(hex, 16).ok()?;
    // The kernel prints the network-order address as a host-order u32 (`%08X`): its native bytes are the address.
    Some(Ipv4Addr::from(n.to_ne_bytes()))
}

fn parse_v6(hex: &str) -> Option<Ipv6Addr> {
    if hex.len() != 32 {
        return None;
    }
    let mut b = [0u8; 16];
    for w in 0..4 {
        let n = u32::from_str_radix(&hex[w * 8..w * 8 + 8], 16).ok()?;
        b[w * 4..w * 4 + 4].copy_from_slice(&n.to_ne_bytes());
    }
    Some(Ipv6Addr::from(b))
}

fn parse_addr(s: &str, v6: bool) -> Option<SocketAddr> {
    let (a, p) = s.split_once(':')?;
    let port = u16::from_str_radix(p, 16).ok()?;
    let ip = if v6 { IpAddr::V6(parse_v6(a)?) } else { IpAddr::V4(parse_v4(a)?) };
    Some(SocketAddr::new(ip, port))
}

/// Parse one /proc/net socket table. Malformed rows are skipped and counted.
pub fn parse_table(text: &str, transport: Transport, v6: bool) -> (Vec<SockRow>, usize) {
    let mut rows = Vec::new();
    let mut bad = 0;
    for line in text.lines().skip(1) {
        let f: Vec<&str> = line.split_whitespace().collect();
        if f.len() < 10 {
            if !line.trim().is_empty() {
                bad += 1;
            }
            continue;
        }
        let parsed = (|| {
            Some(SockRow {
                transport,
                local: parse_addr(f[1], v6)?,
                remote: parse_addr(f[2], v6)?,
                state: u8::from_str_radix(f[3], 16).ok()?,
                uid: f[7].parse().ok()?,
                inode: f[9].parse().ok()?,
            })
        })();
        match parsed {
            Some(r) => rows.push(r),
            None => bad += 1,
        }
    }
    (rows, bad)
}

/// `Tcp: ActiveOpens` from /proc/net/snmp (counts IPv4 and IPv6 active opens).
pub fn parse_active_opens(snmp: &str) -> Option<u64> {
    let mut lines = snmp.lines().filter(|l| l.starts_with("Tcp:"));
    let head: Vec<&str> = lines.next()?.split_whitespace().collect();
    let vals: Vec<&str> = lines.next()?.split_whitespace().collect();
    let i = head.iter().position(|h| *h == "ActiveOpens")?;
    vals.get(i)?.parse().ok()
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
pub struct Identity {
    pub pid: u32,
    /// Process start time in clock ticks since boot (/proc/<pid>/stat field 22): with the boot id it names one
    /// process instance; a reused PID gets a different value.
    pub start_generation: u64,
    pub executable: String,
    /// The executable was replaced or deleted after the process started (`(deleted)` link).
    pub executable_replaced: bool,
    pub uid: u32,
    pub cgroup: String,
    /// For interpreters (python, node, perl, ruby, sh...): the script argument, if any.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub script: Option<String>,
    pub confidence: String,
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum InventoryEvent {
    /// A connected socket seen for the first time. Never a decision: `coverage` is always `observe_only`.
    OrdinaryFlow {
        coverage: String,
        transport: Transport,
        local: String,
        remote: String,
        /// `outbound`, `inbound` (local port was listening) or `unknown`.
        direction: String,
        socket_uid: u32,
        identity: Option<Identity>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        unknown_reason: Option<String>,
    },
    /// Connections the kernel saw that the inventory did not (or could not) report.
    InventoryLoss { coverage: String, scope: String, count: u64, detail: String },
}

/// Where the collector reads from (procfs in production, fixtures in tests).
pub trait Source {
    fn table(&self, name: &str) -> Option<String>;
    fn snmp(&self) -> Option<String>;
    /// socket inode -> pid, for all processes we can see.
    fn socket_owners(&self) -> HashMap<u64, u32>;
    fn identity(&self, pid: u32) -> Option<Identity>;
}

pub struct ProcFs {
    pub root: PathBuf,
}

impl Default for ProcFs {
    fn default() -> Self {
        ProcFs { root: PathBuf::from("/proc") }
    }
}

const INTERPRETERS: [&str; 10] = ["python", "python3", "node", "perl", "ruby", "sh", "bash", "dash", "zsh", "java"];

fn interpreter_of(exe: &str) -> bool {
    let base = Path::new(exe).file_name().and_then(|s| s.to_str()).unwrap_or("");
    let stem = base.trim_end_matches(|c: char| c.is_ascii_digit() || c == '.');
    INTERPRETERS.contains(&base) || INTERPRETERS.contains(&stem)
}

impl Source for ProcFs {
    fn table(&self, name: &str) -> Option<String> {
        fs::read_to_string(self.root.join("net").join(name)).ok()
    }
    fn snmp(&self) -> Option<String> {
        fs::read_to_string(self.root.join("net/snmp")).ok()
    }
    fn socket_owners(&self) -> HashMap<u64, u32> {
        let mut m = HashMap::new();
        let Ok(rd) = fs::read_dir(&self.root) else { return m };
        for e in rd.flatten() {
            let Some(pid) = e.file_name().to_str().and_then(|s| s.parse::<u32>().ok()) else { continue };
            let Ok(fds) = fs::read_dir(e.path().join("fd")) else { continue };
            for fd in fds.flatten() {
                if let Ok(t) = fs::read_link(fd.path()) {
                    if let Some(ino) = t.to_str().and_then(|s| s.strip_prefix("socket:[")).and_then(|s| s.strip_suffix(']')) {
                        if let Ok(ino) = ino.parse::<u64>() {
                            // Inherited sockets are shared; keep the lowest pid (usually the parent that created it)
                            // but the event is still marked by the identity we report, never merged.
                            m.entry(ino).and_modify(|p: &mut u32| *p = (*p).min(pid)).or_insert(pid);
                        }
                    }
                }
            }
        }
        m
    }
    fn identity(&self, pid: u32) -> Option<Identity> {
        let dir = self.root.join(pid.to_string());
        let stat = fs::read_to_string(dir.join("stat")).ok()?;
        // comm may contain spaces and parentheses: fields resume after the last ')'.
        let rest = &stat[stat.rfind(')')? + 2..];
        let start_generation: u64 = rest.split_whitespace().nth(19)?.parse().ok()?;
        let link = fs::read_link(dir.join("exe")).ok()?.to_string_lossy().into_owned();
        let (executable, executable_replaced) = match link.strip_suffix(" (deleted)") {
            Some(p) => (p.to_string(), true),
            None => (link, false),
        };
        let status = fs::read_to_string(dir.join("status")).ok()?;
        let uid =
            status.lines().find_map(|l| l.strip_prefix("Uid:")).and_then(|v| v.split_whitespace().next()).and_then(|v| v.parse().ok())?;
        let cgroup = fs::read_to_string(dir.join("cgroup"))
            .ok()
            .and_then(|c| c.lines().find_map(|l| l.strip_prefix("0::").map(str::to_string)))
            .unwrap_or_default();
        let argv: Vec<String> = fs::read(dir.join("cmdline"))
            .map(|b| b.split(|c| *c == 0).filter(|s| !s.is_empty()).map(|s| String::from_utf8_lossy(s).into_owned()).collect())
            .unwrap_or_default();
        let interp = interpreter_of(&executable);
        let script =
            if interp { argv.iter().skip(1).find(|a| !a.starts_with('-')).map(|a| a.chars().take(256).collect::<String>()) } else { None };
        let confidence = if executable_replaced || interp { "low" } else { "medium" };
        Some(Identity { pid, start_generation, executable, executable_replaced, uid, cgroup, script, confidence: confidence.into() })
    }
}

type Key = (Transport, SocketAddr, SocketAddr, u64);

#[derive(Default)]
pub struct Inventory {
    seen: HashSet<Key>,
    last_active_opens: Option<u64>,
    primed: bool,
}

impl Inventory {
    pub fn new() -> Self {
        Self::default()
    }

    /// One sampling pass. The first pass only records what already exists (no events) so a restart does not
    /// re-announce every open socket as new.
    pub fn tick(&mut self, src: &dyn Source) -> Vec<InventoryEvent> {
        let mut out = Vec::new();
        let mut rows = Vec::new();
        let mut unreadable = Vec::new();
        let mut malformed = 0;
        for (name, t, v6) in
            [("tcp", Transport::Tcp, false), ("tcp6", Transport::Tcp, true), ("udp", Transport::Udp, false), ("udp6", Transport::Udp, true)]
        {
            match src.table(name) {
                Some(text) => {
                    let (r, bad) = parse_table(&text, t, v6);
                    malformed += bad;
                    rows.extend(r);
                }
                None => unreadable.push(name),
            }
        }
        let listening: HashSet<(Transport, u16)> =
            rows.iter().filter(|r| r.transport == Transport::Tcp && r.state == TCP_LISTEN).map(|r| (r.transport, r.local.port())).collect();
        let connected: Vec<&SockRow> = rows
            .iter()
            .filter(|r| r.remote.port() != 0 && r.inode != 0)
            .filter(|r| r.transport == Transport::Udp || r.state != TCP_LISTEN)
            .collect();
        let current: HashSet<Key> = connected.iter().map(|r| (r.transport, r.local, r.remote, r.inode)).collect();
        let opens = src.snmp().and_then(|s| parse_active_opens(&s));
        if !self.primed {
            self.primed = true;
            self.seen = current;
            self.last_active_opens = opens;
            return out;
        }
        let fresh: Vec<&SockRow> =
            connected.into_iter().filter(|r| !self.seen.contains(&(r.transport, r.local, r.remote, r.inode))).collect();
        let owners = if fresh.is_empty() { HashMap::new() } else { src.socket_owners() };
        let mut ids: BTreeMap<u32, Option<Identity>> = BTreeMap::new();
        let mut outbound_tcp_new = 0u64;
        for r in &fresh {
            let inbound = listening.contains(&(r.transport, r.local.port()));
            // A TCP socket that is not on a listening port was opened by connect(): an active open.
            let direction = if inbound {
                "inbound"
            } else if r.transport == Transport::Tcp {
                outbound_tcp_new += 1;
                "outbound"
            } else {
                "unknown"
            };
            let (identity, unknown_reason) = match owners.get(&r.inode) {
                Some(pid) => match ids.entry(*pid).or_insert_with(|| src.identity(*pid)).clone() {
                    Some(id) => (Some(id), None),
                    None => (None, Some(format!("pid {pid} owned the socket but exited or hid its /proc entry before it was read"))),
                },
                None => (None, Some("no visible process holds this socket (exited, other PID namespace, or /proc restricted)".into())),
            };
            out.push(InventoryEvent::OrdinaryFlow {
                coverage: COVERAGE.into(),
                transport: r.transport,
                local: r.local.to_string(),
                remote: r.remote.to_string(),
                direction: direction.into(),
                socket_uid: r.uid,
                identity,
                unknown_reason,
            });
        }
        if let (Some(now), Some(prev)) = (opens, self.last_active_opens) {
            let delta = now.saturating_sub(prev);
            let missed = delta.saturating_sub(outbound_tcp_new);
            if missed > 0 {
                out.push(InventoryEvent::InventoryLoss {
                    coverage: COVERAGE.into(),
                    scope: "tcp_active_opens_not_observed".into(),
                    count: missed,
                    detail: format!(
                        "the kernel counted {delta} TCP active opens since the last pass and the inventory saw {outbound_tcp_new}: short-lived connections were missed"
                    ),
                });
            }
        } else if opens.is_none() {
            out.push(InventoryEvent::InventoryLoss {
                coverage: COVERAGE.into(),
                scope: "tcp_completeness_unmeasured".into(),
                count: 0,
                detail: "/proc/net/snmp is unreadable: missed TCP connections cannot be counted".into(),
            });
        }
        if !unreadable.is_empty() || malformed > 0 {
            out.push(InventoryEvent::InventoryLoss {
                coverage: COVERAGE.into(),
                scope: "socket_table_unreadable".into(),
                count: malformed as u64,
                detail: format!("unreadable tables: {:?}; malformed rows: {malformed}", unreadable),
            });
        }
        self.last_active_opens = opens.or(self.last_active_opens);
        // Forget sockets that are gone so a new connection reusing the same tuple and inode is seen again.
        self.seen = current;
        out
    }

    /// Fixed coverage statement shipped with every inventory session (and shown by the UI).
    pub fn coverage_note() -> &'static str {
        "observe_only: ordinary-app connections in this network namespace, sampled from the kernel socket tables. \
         Not enforced. Short-lived TCP connections that open and close between passes are counted as loss; UDP \
         completeness is not measured; other network namespaces are not observed."
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    struct Fake {
        tables: HashMap<&'static str, String>,
        snmp: Option<String>,
        owners: HashMap<u64, u32>,
        ids: HashMap<u32, Identity>,
    }

    impl Source for Fake {
        fn table(&self, name: &str) -> Option<String> {
            self.tables.get(name).cloned()
        }
        fn snmp(&self) -> Option<String> {
            self.snmp.clone()
        }
        fn socket_owners(&self) -> HashMap<u64, u32> {
            self.owners.clone()
        }
        fn identity(&self, pid: u32) -> Option<Identity> {
            self.ids.get(&pid).cloned()
        }
    }

    const HEAD: &str = "  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode\n";

    fn snmp(opens: u64) -> String {
        format!("Ip: Forwarding DefaultTTL\nIp: 1 64\nTcp: RtoAlgorithm RtoMin RtoMax MaxConn ActiveOpens PassiveOpens\nTcp: 1 200 120000 -1 {opens} 3\n")
    }

    fn id(pid: u32, exe: &str) -> Identity {
        Identity {
            pid,
            start_generation: 1000 + pid as u64,
            executable: exe.into(),
            executable_replaced: false,
            uid: 1000,
            cgroup: "/user.slice".into(),
            script: None,
            confidence: "medium".into(),
        }
    }

    fn fake(tcp: &str, opens: u64) -> Fake {
        Fake {
            tables: HashMap::from([
                ("tcp", format!("{HEAD}{tcp}")),
                ("tcp6", HEAD.to_string()),
                ("udp", HEAD.to_string()),
                ("udp6", HEAD.to_string()),
            ]),
            snmp: Some(snmp(opens)),
            owners: HashMap::new(),
            ids: HashMap::new(),
        }
    }

    // 10.0.0.2:40000 -> 1.1.1.1:443, SYN_SENT, uid 1000, inode 777 (addresses as the kernel prints them)
    const CONN: &str = "   0: 0200000A:9C40 01010101:01BB 02 00000000:00000000 00:00000000 00000000  1000        0 777 1 0 100 0 0 10 0\n";
    // a listener on 0.0.0.0:22
    const LISTEN: &str =
        "   1: 00000000:0016 00000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 555 1 0 100 0 0 10 0\n";

    #[test]
    fn parses_kernel_rows_in_host_order() {
        let (rows, bad) = parse_table(&format!("{HEAD}{CONN}{LISTEN}"), Transport::Tcp, false);
        assert_eq!(bad, 0);
        assert_eq!(rows[0].local, "10.0.0.2:40000".parse().unwrap());
        assert_eq!(rows[0].remote, "1.1.1.1:443".parse().unwrap());
        assert_eq!((rows[0].state, rows[0].uid, rows[0].inode), (TCP_SYN_SENT, 1000, 777));
        assert_eq!(rows[1].state, TCP_LISTEN);
        let v6 =
            format!("{HEAD}   0: 0000000000000000FFFF00000200000A:9C40 B80D0120000000000000000002000000:01BB 01 0:0 0:0 0 1000 0 778 1\n");
        let (r6, _) = parse_table(&v6, Transport::Tcp, true);
        assert_eq!(r6[0].local.ip(), "::ffff:10.0.0.2".parse::<IpAddr>().unwrap());
        assert_eq!(r6[0].remote.ip(), "2001:db8::2".parse::<IpAddr>().unwrap());
        assert_eq!(parse_active_opens(&snmp(42)), Some(42));
    }

    #[test]
    fn a_new_connection_is_reported_once_with_its_process_identity() {
        let mut inv = Inventory::new();
        assert!(inv.tick(&fake(LISTEN, 10)).is_empty(), "first pass primes, never announces existing sockets");
        let mut f = fake(&format!("{LISTEN}{CONN}"), 11);
        f.owners.insert(777, 4242);
        f.ids.insert(4242, id(4242, "/usr/bin/curl"));
        let ev = inv.tick(&f);
        assert_eq!(ev.len(), 1, "{ev:?}");
        match &ev[0] {
            InventoryEvent::OrdinaryFlow { coverage, direction, identity, remote, .. } => {
                assert_eq!(coverage, "observe_only");
                assert_eq!(direction, "outbound");
                assert_eq!(remote, "1.1.1.1:443");
                assert_eq!(identity.as_ref().unwrap().executable, "/usr/bin/curl");
            }
            e => panic!("{e:?}"),
        }
        assert!(inv.tick(&f).is_empty(), "the same socket is not announced twice");
    }

    #[test]
    fn missed_short_lived_connections_are_counted_never_silent() {
        let mut inv = Inventory::new();
        inv.tick(&fake("", 100));
        // 25 connections opened and closed between passes: no rows, but the kernel counter moved.
        let ev = inv.tick(&fake("", 125));
        assert!(
            matches!(&ev[..], [InventoryEvent::InventoryLoss { scope, count: 25, .. }] if scope == "tcp_active_opens_not_observed"),
            "{ev:?}"
        );
        // Without the counter the loss is unmeasurable, and the event says so.
        let mut f = fake("", 0);
        f.snmp = None;
        let ev = inv.tick(&f);
        assert!(ev.iter().any(|e| matches!(e, InventoryEvent::InventoryLoss { scope, .. } if scope == "tcp_completeness_unmeasured")));
    }

    #[test]
    fn a_socket_without_a_visible_owner_is_unknown_not_guessed() {
        let mut inv = Inventory::new();
        inv.tick(&fake("", 1));
        let mut f = fake(CONN, 2);
        // owner known but its /proc entry vanished before identity was read
        f.owners.insert(777, 99);
        let ev = inv.tick(&f);
        match &ev[0] {
            InventoryEvent::OrdinaryFlow { identity: None, unknown_reason: Some(r), .. } => assert!(r.contains("pid 99")),
            e => panic!("{e:?}"),
        }
        let mut inv = Inventory::new();
        inv.tick(&fake("", 1));
        let ev = inv.tick(&fake(CONN, 2));
        assert!(matches!(&ev[0], InventoryEvent::OrdinaryFlow { identity: None, unknown_reason: Some(_), .. }));
    }

    #[test]
    fn inbound_connections_on_a_listening_port_are_not_counted_as_outbound() {
        let mut inv = Inventory::new();
        inv.tick(&fake(LISTEN, 5));
        let accepted = "   2: 0200000A:0016 0300000A:D431 01 00000000:00000000 00:00000000 00000000     0        0 900 1 0 100 0 0 10 0\n";
        let ev = inv.tick(&fake(&format!("{LISTEN}{accepted}"), 5));
        assert!(matches!(&ev[..], [InventoryEvent::OrdinaryFlow { direction, .. }] if direction == "inbound"), "{ev:?}");
    }

    #[test]
    fn unreadable_tables_are_reported() {
        let mut inv = Inventory::new();
        inv.tick(&fake("", 1));
        let mut f = fake("", 1);
        f.tables.remove("udp6");
        let ev = inv.tick(&f);
        assert!(ev.iter().any(|e| matches!(e, InventoryEvent::InventoryLoss { scope, .. } if scope == "socket_table_unreadable")));
    }

    #[test]
    fn interpreters_are_low_confidence_and_carry_the_script() {
        assert!(interpreter_of("/usr/bin/python3.12"));
        assert!(interpreter_of("/usr/bin/node"));
        assert!(!interpreter_of("/usr/bin/curl"));
    }
}
