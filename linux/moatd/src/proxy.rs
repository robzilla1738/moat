//! Session egress proxy: hostname rules for TCP inside protected sessions, without TLS interception.
//!
//! What it does, exactly:
//! * nftables redirects every TCP connection a proxied session makes to a non-loopback address to this session's
//!   own loopback listener (`redirect to :<port>`, matched by the session's cgroup). Tools that honour
//!   `HTTPS_PROXY` reach the same listener with `CONNECT`.
//! * The proxy reads only the start of the connection: the TLS ClientHello (for the SNI), an HTTP `CONNECT`
//!   request line, or a plain-HTTP request header (for `Host`). It never decrypts, never terminates TLS and never
//!   presents a certificate.
//! * It resolves the hostname itself and connects to the address *it* resolved on the original port, never to the
//!   address the client dialed. A spoofed SNI therefore reaches the real host of that name, not an attacker's IP.
//! * Every candidate address is evaluated with moat-core together with the hostname evidence, so safety rules on
//!   addresses (e.g. the controller) still win when an allowed name resolves to them.
//! * Without a hostname (no SNI, server-speaks-first protocols after a short wait, non-HTTP) the flow is evaluated
//!   on the original address only, so hostname allows cannot match it.
//!
//! What it does not do, stated plainly: it cannot see hostnames for UDP/QUIC (those stay with nftables, and a
//! compile-time check refuses hostname denies that would need UDP); it cannot restrict paths, methods or
//! repositories; only the first request's `Host` is checked on a plain-HTTP keep-alive connection; Encrypted
//! ClientHello exposes only its public outer name; domain fronting through an allowed host's CDN remains possible.

use std::collections::BTreeMap;
use std::io::{Read, Write};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, Shutdown, SocketAddr, TcpListener, TcpStream, ToSocketAddrs};
use std::os::fd::AsRawFd;
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, RwLock};
use std::thread::JoinHandle;
use std::time::Duration;

use chrono::Utc;
use moat_core::enrichment::Enricher;
use moat_core::eval::{evaluate, hostname_admission, Decision, EvalContext, FlowAttempt, HostnameAdmission, Verdict, Winner};
use moat_core::identity::{AppIdentity, Boundary, SessionRef};
use moat_core::net::{classify as scope_of, Confidence, HostnameEvidence, HostnameSource, NetScope, Transport};
use moat_core::policy::Policy;

use crate::spool::Event;

/// Socket mark on the proxy's upstream connections. The nftables table accepts it before the ordinary-traffic
/// rules: the proxy has already decided the flow with the full policy (safety rules included). Only root can set it.
pub const UPSTREAM_MARK: u32 = 0x4d4f_4154; // "MOAT"
pub const MEASUREMENT: &str = "moatd session egress proxy (TLS SNI / HTTP CONNECT / HTTP Host; no TLS interception)";
const MAX_PEEK: usize = 64 * 1024;

/// What the first bytes of a connection say about where it is going.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Peeked {
    /// A TLS ClientHello. `sni` is None when the extension is absent or not a valid hostname.
    Tls { sni: Option<String> },
    /// An HTTP CONNECT request (explicit proxy use). `header_len` bytes are consumed, not forwarded.
    Connect { host: String, port: u16, header_len: usize },
    /// A plain-HTTP request. `host` from the absolute-form target or the Host header.
    Http { host: Option<String>, port: Option<u16> },
    /// Anything else (or nothing within the wait): evaluated on the address only.
    Opaque,
}

fn valid_hostname(h: &str) -> bool {
    !h.is_empty()
        && h.len() <= 253
        && h.parse::<IpAddr>().is_err()
        && h.split('.').all(|l| !l.is_empty() && l.len() <= 63 && l.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_'))
}

/// Split `host[:port]` / `[v6]:port`.
fn split_host_port(s: &str) -> (String, Option<u16>) {
    let s = s.trim();
    if let Some(rest) = s.strip_prefix('[') {
        if let Some((h, p)) = rest.split_once(']') {
            return (h.to_string(), p.strip_prefix(':').and_then(|p| p.parse().ok()));
        }
    }
    match s.rsplit_once(':') {
        Some((h, p)) if !h.contains(':') => (h.to_string(), p.parse().ok()),
        _ => (s.to_string(), None),
    }
}

/// Classify the buffered start of a connection. `None` means "need more bytes".
pub fn classify(buf: &[u8]) -> Option<Peeked> {
    if buf.is_empty() {
        return None;
    }
    if buf[0] == 0x16 {
        return parse_client_hello(buf).map(|sni| Peeked::Tls { sni });
    }
    let method_end = buf.iter().take(16).position(|b| *b == b' ');
    let looks_http = method_end.map(|n| n > 0 && buf[..n].iter().all(|b| b.is_ascii_uppercase())).unwrap_or(false);
    if !looks_http {
        // Not a method token yet: wait a little for more bytes unless it clearly is something else.
        return if buf.len() >= 16 || buf.iter().take(buf.len().min(16)).any(|b| !b.is_ascii_uppercase()) {
            Some(Peeked::Opaque)
        } else {
            None
        };
    }
    let Some(end) = buf.windows(4).position(|w| w == b"\r\n\r\n") else {
        return if buf.len() >= MAX_PEEK { Some(Peeked::Opaque) } else { None };
    };
    let head = String::from_utf8_lossy(&buf[..end]);
    let mut lines = head.split("\r\n");
    let req = lines.next().unwrap_or("");
    let mut parts = req.split(' ');
    let method = parts.next().unwrap_or("");
    let target = parts.next().unwrap_or("");
    if method == "CONNECT" {
        let (h, p) = split_host_port(target);
        return Some(match p {
            Some(port) if !h.is_empty() => Peeked::Connect { host: h.to_ascii_lowercase(), port, header_len: end + 4 },
            _ => Peeked::Opaque,
        });
    }
    if let Some(rest) = target.strip_prefix("http://") {
        let authority = rest.split('/').next().unwrap_or("");
        let (h, p) = split_host_port(authority.rsplit('@').next().unwrap_or(""));
        return Some(Peeked::Http { host: Some(h.to_ascii_lowercase()).filter(|h| !h.is_empty()), port: p });
    }
    let host = lines.find_map(|l| {
        let (k, v) = l.split_once(':')?;
        k.trim().eq_ignore_ascii_case("host").then(|| v.trim().to_string())
    });
    Some(match host {
        Some(h) => {
            let (h, p) = split_host_port(&h);
            Peeked::Http { host: Some(h.to_ascii_lowercase()).filter(|h| !h.is_empty()), port: p }
        }
        None => Peeked::Http { host: None, port: None },
    })
}

/// Reassemble the ClientHello from consecutive TLS handshake records and return its SNI.
/// `None` = incomplete, `Some(None)` = complete but no usable SNI (or not a ClientHello).
fn parse_client_hello(buf: &[u8]) -> Option<Option<String>> {
    let mut hs = Vec::new();
    let mut i = 0;
    loop {
        if buf.len() < i + 5 {
            return if buf.len() >= MAX_PEEK { Some(None) } else { None };
        }
        if buf[i] != 0x16 || buf[i + 1] != 0x03 {
            return Some(None);
        }
        let len = u16::from_be_bytes([buf[i + 3], buf[i + 4]]) as usize;
        if buf.len() < i + 5 + len {
            return if buf.len() >= MAX_PEEK { Some(None) } else { None };
        }
        hs.extend_from_slice(&buf[i + 5..i + 5 + len]);
        i += 5 + len;
        if hs.len() >= 4 {
            if hs[0] != 0x01 {
                return Some(None);
            }
            let need = 4 + ((hs[1] as usize) << 16 | (hs[2] as usize) << 8 | hs[3] as usize);
            if hs.len() >= need {
                return Some(sni_from_hello(&hs[4..need]));
            }
        }
    }
}

fn sni_from_hello(b: &[u8]) -> Option<String> {
    let mut p = 2 + 32; // version + random
    let sid = *b.get(p)? as usize;
    p += 1 + sid;
    let cs = u16::from_be_bytes([*b.get(p)?, *b.get(p + 1)?]) as usize;
    p += 2 + cs;
    let comp = *b.get(p)? as usize;
    p += 1 + comp;
    let ext_len = u16::from_be_bytes([*b.get(p)?, *b.get(p + 1)?]) as usize;
    p += 2;
    let end = (p + ext_len).min(b.len());
    while p + 4 <= end {
        let ty = u16::from_be_bytes([b[p], b[p + 1]]);
        let len = u16::from_be_bytes([b[p + 2], b[p + 3]]) as usize;
        p += 4;
        if ty == 0 {
            let e = b.get(p..p + len)?;
            let mut q = 2; // list length
            while q + 3 <= e.len() {
                let nt = e[q];
                let nl = u16::from_be_bytes([e[q + 1], e[q + 2]]) as usize;
                let name = e.get(q + 3..q + 3 + nl)?;
                if nt == 0 {
                    let s = std::str::from_utf8(name).ok()?.trim_end_matches('.').to_ascii_lowercase();
                    return valid_hostname(&s).then_some(s);
                }
                q += 3 + nl;
            }
            return None;
        }
        p += len;
    }
    None
}

/// The policy the proxy evaluates against (the installed snapshot's normalized policy).
pub struct ProxyPolicy {
    pub policy: Policy,
    pub device_id: String,
    pub revision: u64,
}

pub type Resolver = dyn Fn(&str, u16) -> std::io::Result<Vec<IpAddr>> + Send + Sync;

pub fn system_resolver(host: &str, port: u16) -> std::io::Result<Vec<IpAddr>> {
    Ok((host, port).to_socket_addrs()?.map(|a| a.ip()).collect())
}

/// Resource bounds. Exhaustion refuses new connections (with an event); it never lets one through unchecked.
#[derive(Debug, Clone, Copy)]
pub struct Limits {
    pub max_connections: usize,
    pub max_lookups: usize,
}

impl Default for Limits {
    fn default() -> Self {
        Limits { max_connections: 512, max_lookups: 16 }
    }
}

/// One admitted, still-open proxied stream.
pub struct StreamEntry {
    pub session: SessionRef,
    pub host: Option<HostnameEvidence>,
    pub to: SocketAddr,
    pub admitted_by: String,
    pub admitted_at: chrono::DateTime<Utc>,
    client: TcpStream,
    upstream: TcpStream,
}

impl StreamEntry {
    fn kill(&self) {
        let _ = self.client.shutdown(Shutdown::Both);
        let _ = self.upstream.shutdown(Shutdown::Both);
    }
}

pub struct Shared {
    pub policy: RwLock<Option<Arc<ProxyPolicy>>>,
    /// Emergency isolation: refuse every new connection and end every open stream.
    pub isolated: AtomicBool,
    pub limits: Limits,
    active_connections: AtomicUsize,
    active_lookups: AtomicUsize,
    /// Open streams, re-evaluated on every policy change and daemon tick (stream contract in docs/platforms/linux.md).
    pub streams: Mutex<BTreeMap<u64, StreamEntry>>,
    next_stream: AtomicU64,
    pub resolver: Box<Resolver>,
    /// Events for the spool, drained by the daemon tick (no proxy thread ever takes the endpoint lock).
    pub events: Mutex<Vec<Event>>,
    pub peek_timeout: Duration,
    pub connect_timeout: Duration,
    /// Tests only: the address a transparently redirected connection was originally sent to.
    pub test_original_dst: Option<SocketAddr>,
    /// Hostname rules may not reach local addresses by themselves (see `local_scope`). Always true in production;
    /// in-process tests whose only upstream is on loopback turn it off.
    pub guard_local: bool,
}

impl Shared {
    pub fn new(resolver: Box<Resolver>) -> Self {
        Shared {
            policy: RwLock::new(None),
            isolated: AtomicBool::new(false),
            limits: Limits::default(),
            active_connections: AtomicUsize::new(0),
            active_lookups: AtomicUsize::new(0),
            streams: Mutex::new(BTreeMap::new()),
            next_stream: AtomicU64::new(1),
            resolver,
            events: Mutex::new(Vec::new()),
            peek_timeout: Duration::from_millis(1500),
            connect_timeout: Duration::from_secs(10),
            test_original_dst: None,
            guard_local: true,
        }
    }

    pub fn drain_events(&self) -> Vec<Event> {
        std::mem::take(&mut *self.events.lock().unwrap())
    }

    pub fn active_connections(&self) -> usize {
        self.active_connections.load(Ordering::SeqCst)
    }

    fn terminated(&self, id: u64, e: &StreamEntry, reason: &str) {
        e.kill();
        self.events.lock().unwrap().push(Event::StreamTerminated {
            session_id: e.session.id.clone(),
            stream: id,
            destination: e.to.to_string(),
            hostname: e.host.as_ref().map(|h| h.name.clone()),
            admitted_by: e.admitted_by.clone(),
            reason: reason.to_string(),
        });
    }

    /// Re-evaluate every open stream against the current policy at `now`. A stream whose verdict is no longer
    /// allow (rule or grant expired, policy changed to deny, no policy) or any stream during isolation is ended:
    /// both sockets are shut down. Returns the ids ended.
    pub fn revalidate(&self, now: chrono::DateTime<Utc>) -> Vec<u64> {
        let pp = self.policy.read().unwrap().clone();
        let isolated = self.isolated.load(Ordering::SeqCst);
        let mut ended = Vec::new();
        let enricher = Enricher::new();
        let mut streams = self.streams.lock().unwrap();
        let ids: Vec<u64> = streams.keys().copied().collect();
        for id in ids {
            let e = &streams[&id];
            let why = if isolated {
                Some("emergency isolation".to_string())
            } else {
                match pp.as_deref() {
                    None => Some("no policy installed".to_string()),
                    Some(p) => {
                        let ctx = EvalContext::new(&p.policy, &enricher, &p.device_id);
                        let mut a = attempt(&e.session, Some(p), e.to.ip(), e.to.port(), e.host.as_ref());
                        a.at = now;
                        let d = evaluate(&ctx, &a);
                        (d.verdict != Verdict::Allow).then(|| format!("no longer allowed: {}", d.summary()))
                    }
                }
            };
            if let Some(why) = why {
                let e = streams.remove(&id).unwrap();
                self.terminated(id, &e, &why);
                ended.push(id);
            }
        }
        ended
    }

    /// End every open stream of one session (task closed).
    pub fn terminate_session(&self, session_id: &str, reason: &str) -> usize {
        let mut streams = self.streams.lock().unwrap();
        let ids: Vec<u64> = streams.iter().filter(|(_, e)| e.session.id == session_id).map(|(id, _)| *id).collect();
        for id in &ids {
            let e = streams.remove(id).unwrap();
            self.terminated(*id, &e, reason);
        }
        ids.len()
    }

    /// Enter or leave emergency isolation. Entering ends every open stream immediately.
    pub fn set_isolated(&self, on: bool) {
        self.isolated.store(on, Ordering::SeqCst);
        if on {
            self.revalidate(Utc::now());
        }
    }
}

/// Counts a resource while alive.
struct Slot<'a>(&'a AtomicUsize);
impl<'a> Slot<'a> {
    fn take(c: &'a AtomicUsize, max: usize) -> Option<Slot<'a>> {
        let mut cur = c.load(Ordering::SeqCst);
        loop {
            if cur >= max {
                return None;
            }
            match c.compare_exchange(cur, cur + 1, Ordering::SeqCst, Ordering::SeqCst) {
                Ok(_) => return Some(Slot(c)),
                Err(v) => cur = v,
            }
        }
    }
}
impl Drop for Slot<'_> {
    fn drop(&mut self) {
        self.0.fetch_sub(1, Ordering::SeqCst);
    }
}

/// A resolved address a hostname rule must not reach on its own: the proxy runs in the host network namespace
/// with a privileged mark, so a name that resolves to loopback, unspecified, link-local or multicast space could
/// otherwise reach local services the session may not. Such an address is used only if an address rule (without
/// the hostname) allows it.
fn local_scope(ip: IpAddr) -> bool {
    ip.is_unspecified() || matches!(scope_of(ip), NetScope::Loopback | NetScope::LinkLocal | NetScope::Multicast)
}

/// The verdict for one proxied connection.
#[derive(Debug, Clone)]
pub struct Outcome {
    pub connect_to: Option<SocketAddr>,
    pub decision: Option<Decision>,
    pub reason: String,
    pub attempt: FlowAttempt,
}

fn attempt(sess: &SessionRef, pp: Option<&ProxyPolicy>, ip: IpAddr, port: u16, host: Option<&HostnameEvidence>) -> FlowAttempt {
    FlowAttempt {
        id: format!("proxy-{}-{}", sess.id, Utc::now().timestamp_nanos_opt().unwrap_or(0)),
        device_id: pp.map(|p| p.device_id.clone()).unwrap_or_default(),
        user: None,
        process: None,
        app: AppIdentity::default(),
        ancestors: vec![],
        ancestry_complete: false,
        session: Some(sess.clone()),
        remote_ip: ip,
        remote_port: port,
        transport: Transport::Tcp,
        hostname: host.cloned(),
        at: Utc::now(),
    }
}

/// Decide a connection: evaluate every candidate address (with the hostname evidence, if any) and pick the first
/// one the policy allows. No policy installed means deny.
pub fn decide(pp: Option<&ProxyPolicy>, sess: &SessionRef, host: Option<HostnameEvidence>, candidates: &[IpAddr], port: u16) -> Outcome {
    decide_with(pp, sess, host, candidates, port, true)
}

pub fn decide_with(
    pp: Option<&ProxyPolicy>,
    sess: &SessionRef,
    host: Option<HostnameEvidence>,
    candidates: &[IpAddr],
    port: u16,
    guard_local: bool,
) -> Outcome {
    let Some(p) = pp else {
        let ip = candidates.first().copied().unwrap_or(IpAddr::V4(Ipv4Addr::UNSPECIFIED));
        return Outcome {
            connect_to: None,
            decision: None,
            reason: "no policy installed".into(),
            attempt: attempt(sess, pp, ip, port, host.as_ref()),
        };
    };
    if candidates.is_empty() {
        return Outcome {
            connect_to: None,
            decision: None,
            reason: format!("{} did not resolve", host.as_ref().map(|h| h.name.as_str()).unwrap_or("destination")),
            attempt: attempt(sess, pp, IpAddr::V4(Ipv4Addr::UNSPECIFIED), port, host.as_ref()),
        };
    }
    let enricher = Enricher::new();
    let ctx = EvalContext::new(&p.policy, &enricher, &p.device_id);
    let mut first: Option<(Decision, FlowAttempt)> = None;
    for ip in candidates {
        let a = attempt(sess, pp, *ip, port, host.as_ref());
        let mut d = evaluate(&ctx, &a);
        if let Some(h) = host.as_ref().filter(|_| guard_local && d.verdict == Verdict::Allow && local_scope(*ip)) {
            let by_address = evaluate(&ctx, &attempt(sess, pp, *ip, port, None));
            if by_address.verdict != Verdict::Allow {
                d = by_address;
                d.notes.push(format!("{} resolved to local address {ip}; a hostname rule cannot reach local addresses", h.name));
            }
        }
        if d.verdict == Verdict::Allow {
            let reason = d.summary();
            return Outcome { connect_to: Some(SocketAddr::new(*ip, port)), decision: Some(d), reason, attempt: a };
        }
        if first.is_none() {
            first = Some((d, a));
        }
    }
    let (d, a) = first.unwrap();
    Outcome { connect_to: None, reason: d.summary(), decision: Some(d), attempt: a }
}

fn decision_json(o: &Outcome, revision: Option<u64>) -> serde_json::Value {
    match &o.decision {
        Some(d) => serde_json::json!({
            "verdict": d.verdict,
            "permitted_by_observation": d.permitted_by_observation,
            "rule": match &d.winner { Winner::Rule { id, .. } => Some(id.clone()), _ => None },
            "profile": d.profile,
            "policy_revision": revision,
            "summary": o.reason,
            "notes": d.notes,
        }),
        None => serde_json::json!({ "verdict": "deny", "policy_revision": revision, "summary": o.reason }),
    }
}

/// SO_ORIGINAL_DST / IP6T_SO_ORIGINAL_DST: where a redirected connection was going.
fn original_dst(s: &TcpStream) -> Option<SocketAddr> {
    let fd = s.as_raw_fd();
    let local = s.local_addr().ok()?;
    let got = if local.is_ipv4() {
        let mut a: libc::sockaddr_in = unsafe { std::mem::zeroed() };
        let mut len = std::mem::size_of::<libc::sockaddr_in>() as libc::socklen_t;
        // SAFETY: valid fd, correctly sized out-parameter.
        let r = unsafe { libc::getsockopt(fd, libc::SOL_IP, 80, &mut a as *mut _ as *mut libc::c_void, &mut len) };
        (r == 0).then(|| SocketAddr::new(IpAddr::V4(Ipv4Addr::from(u32::from_be(a.sin_addr.s_addr))), u16::from_be(a.sin_port)))
    } else {
        let mut a: libc::sockaddr_in6 = unsafe { std::mem::zeroed() };
        let mut len = std::mem::size_of::<libc::sockaddr_in6>() as libc::socklen_t;
        // SAFETY: as above.
        let r = unsafe { libc::getsockopt(fd, libc::SOL_IPV6, 80, &mut a as *mut _ as *mut libc::c_void, &mut len) };
        (r == 0).then(|| SocketAddr::new(IpAddr::V6(Ipv6Addr::from(a.sin6_addr.s6_addr)), u16::from_be(a.sin6_port)))
    }?;
    // A direct connection to the listener (explicit proxy use) reports the listener itself.
    (got != local).then_some(got)
}

fn set_mark(s: &socket2_lite::Socket) {
    let m = UPSTREAM_MARK;
    // SAFETY: setsockopt with a u32 option value on a socket we own. Fails harmlessly without CAP_NET_ADMIN.
    unsafe {
        libc::setsockopt(s.fd, libc::SOL_SOCKET, libc::SO_MARK, &m as *const u32 as *const libc::c_void, 4);
    }
}

/// Minimal socket creation so the mark is set before connect (std has no hook for that).
mod socket2_lite {
    use std::net::{SocketAddr, TcpStream};
    use std::os::fd::FromRawFd;
    use std::time::Duration;

    pub struct Socket {
        pub fd: i32,
    }

    impl Socket {
        pub fn new(addr: &SocketAddr) -> std::io::Result<Socket> {
            let fam = if addr.is_ipv4() { libc::AF_INET } else { libc::AF_INET6 };
            // SAFETY: plain socket(2).
            let fd = unsafe { libc::socket(fam, libc::SOCK_STREAM | libc::SOCK_CLOEXEC, 0) };
            if fd < 0 {
                return Err(std::io::Error::last_os_error());
            }
            Ok(Socket { fd })
        }

        pub fn connect(self, addr: &SocketAddr, timeout: Duration) -> std::io::Result<TcpStream> {
            // Hand the fd to std, then use a non-blocking connect with a timeout via a temporary std socket.
            // SAFETY: we own fd and transfer it exactly once.
            let s = unsafe { TcpStream::from_raw_fd(self.fd) };
            std::mem::forget(self);
            let sa = socket2_sockaddr(addr);
            let (ptr, len) = (sa.0.as_ptr() as *const libc::sockaddr, sa.1);
            use std::os::fd::AsRawFd;
            let fd = s.as_raw_fd();
            // SAFETY: valid fd and sockaddr buffer.
            unsafe {
                let fl = libc::fcntl(fd, libc::F_GETFL);
                libc::fcntl(fd, libc::F_SETFL, fl | libc::O_NONBLOCK);
                let r = libc::connect(fd, ptr, len);
                if r != 0 {
                    let e = std::io::Error::last_os_error();
                    if e.raw_os_error() != Some(libc::EINPROGRESS) {
                        return Err(e);
                    }
                    let mut pfd = libc::pollfd { fd, events: libc::POLLOUT, revents: 0 };
                    let n = libc::poll(&mut pfd, 1, timeout.as_millis().min(i32::MAX as u128) as i32);
                    if n <= 0 {
                        return Err(std::io::Error::new(std::io::ErrorKind::TimedOut, "connect timed out"));
                    }
                    let mut err: libc::c_int = 0;
                    let mut l = 4 as libc::socklen_t;
                    libc::getsockopt(fd, libc::SOL_SOCKET, libc::SO_ERROR, &mut err as *mut _ as *mut libc::c_void, &mut l);
                    if err != 0 {
                        return Err(std::io::Error::from_raw_os_error(err));
                    }
                }
                libc::fcntl(fd, libc::F_SETFL, fl);
            }
            Ok(s)
        }
    }

    impl Drop for Socket {
        fn drop(&mut self) {
            // SAFETY: closing an fd we own.
            unsafe { libc::close(self.fd) };
        }
    }

    fn socket2_sockaddr(a: &SocketAddr) -> ([u8; 28], libc::socklen_t) {
        let mut buf = [0u8; 28];
        match a {
            SocketAddr::V4(v4) => {
                let sa = libc::sockaddr_in {
                    sin_family: libc::AF_INET as libc::sa_family_t,
                    sin_port: v4.port().to_be(),
                    sin_addr: libc::in_addr { s_addr: u32::from(*v4.ip()).to_be() },
                    sin_zero: [0; 8],
                };
                // SAFETY: sockaddr_in fits in 28 bytes.
                unsafe { std::ptr::copy_nonoverlapping(&sa as *const _ as *const u8, buf.as_mut_ptr(), std::mem::size_of_val(&sa)) };
                (buf, std::mem::size_of::<libc::sockaddr_in>() as libc::socklen_t)
            }
            SocketAddr::V6(v6) => {
                let sa = libc::sockaddr_in6 {
                    sin6_family: libc::AF_INET6 as libc::sa_family_t,
                    sin6_port: v6.port().to_be(),
                    sin6_flowinfo: v6.flowinfo(),
                    sin6_addr: libc::in6_addr { s6_addr: v6.ip().octets() },
                    sin6_scope_id: v6.scope_id(),
                };
                // SAFETY: sockaddr_in6 is 28 bytes.
                unsafe { std::ptr::copy_nonoverlapping(&sa as *const _ as *const u8, buf.as_mut_ptr(), std::mem::size_of_val(&sa)) };
                (buf, std::mem::size_of::<libc::sockaddr_in6>() as libc::socklen_t)
            }
        }
    }
}

fn connect_upstream(addr: SocketAddr, timeout: Duration) -> std::io::Result<TcpStream> {
    let s = socket2_lite::Socket::new(&addr)?;
    set_mark(&s);
    s.connect(&addr, timeout)
}

fn pump(mut from: TcpStream, mut to: TcpStream) {
    let mut buf = [0u8; 16 * 1024];
    loop {
        match from.read(&mut buf) {
            Ok(0) | Err(_) => break,
            Ok(n) => {
                if to.write_all(&buf[..n]).is_err() {
                    break;
                }
            }
        }
    }
    let _ = to.shutdown(Shutdown::Write);
}

fn deny_http(client: &mut TcpStream, why: &str) {
    let body = format!("Blocked by Moat: {why}\n");
    let msg = format!(
        "HTTP/1.1 403 Forbidden\r\nContent-Type: text/plain\r\nContent-Length: {}\r\nConnection: close\r\nX-Moat: blocked\r\n\r\n{body}",
        body.len()
    );
    let _ = client.write_all(msg.as_bytes());
}

/// Handle one connection from a proxied session.
pub fn handle_connection(shared: &Shared, sess: &SessionRef, mut client: TcpStream) {
    let orig = shared.test_original_dst.or_else(|| original_dst(&client));
    let Some(_conn) = Slot::take(&shared.active_connections, shared.limits.max_connections) else {
        shared.events.lock().unwrap().push(Event::ProxyLimit {
            session_id: sess.id.clone(),
            resource: "connections".into(),
            limit: shared.limits.max_connections as u64,
        });
        let _ = client.shutdown(Shutdown::Both);
        return;
    };
    let _ = client.set_read_timeout(Some(shared.peek_timeout));
    let mut buf = Vec::with_capacity(4096);
    let mut chunk = [0u8; 8192];
    let peeked = loop {
        if let Some(p) = classify(&buf) {
            break p;
        }
        match client.read(&mut chunk) {
            Ok(0) => break classify(&buf).unwrap_or(Peeked::Opaque),
            Ok(n) => buf.extend_from_slice(&chunk[..n]),
            Err(_) => break Peeked::Opaque, // nothing (more) within the wait: server-speaks-first or idle
        }
        if buf.len() >= MAX_PEEK {
            break classify(&buf).unwrap_or(Peeked::Opaque);
        }
    };
    let _ = client.set_read_timeout(None);
    let ev = |name: &str, source: HostnameSource| HostnameEvidence { name: name.to_string(), source, confidence: Confidence::Medium };
    // (hostname evidence, literal address, port, bytes to forward, is CONNECT)
    let (host, literal, port, forward, connect): (Option<HostnameEvidence>, Option<IpAddr>, Option<u16>, Vec<u8>, bool) = match &peeked {
        Peeked::Connect { host, port, header_len } => {
            let lit = host.parse::<IpAddr>().ok();
            let h = if lit.is_none() && valid_hostname(host) { Some(ev(host, HostnameSource::ConnectProxy)) } else { None };
            (h, lit, Some(*port), buf[*header_len..].to_vec(), true)
        }
        Peeked::Tls { sni } => (sni.as_deref().map(|s| ev(s, HostnameSource::Sni)), None, orig.map(|o| o.port()), buf.clone(), false),
        Peeked::Http { host, port } => {
            let lit = host.as_deref().and_then(|h| h.parse::<IpAddr>().ok());
            let h = host.as_deref().filter(|h| lit.is_none() && valid_hostname(h)).map(|h| ev(h, HostnameSource::HttpHost));
            (h, lit, orig.map(|o| o.port()).or(*port), buf.clone(), false)
        }
        Peeked::Opaque => (None, None, orig.map(|o| o.port()), buf.clone(), false),
    };
    let pp = shared.policy.read().unwrap().clone();
    let refuse = |reason: String, port: u16| Outcome {
        connect_to: None,
        decision: None,
        reason,
        attempt: attempt(sess, pp.as_deref(), IpAddr::V4(Ipv4Addr::UNSPECIFIED), port, host.as_ref()),
    };
    // How the hostname was (or was not) looked up, for the record.
    let mut lookup = "none";
    let outcome = match port {
        None => refuse("no destination: not a redirected connection and not a CONNECT request".into(), 0),
        Some(port) if shared.isolated.load(Ordering::SeqCst) => refuse("emergency isolation".into(), port),
        Some(port) => match (&host, literal, pp.as_deref()) {
            (Some(h), _, Some(p)) => {
                // W05: authorize the name before any DNS lookup.
                let enricher = Enricher::new();
                let ctx = EvalContext::new(&p.policy, &enricher, &p.device_id);
                let probe = attempt(sess, Some(p), IpAddr::V4(Ipv4Addr::UNSPECIFIED), port, Some(h));
                match hostname_admission(&ctx, &probe) {
                    HostnameAdmission::DenyWithoutLookup { reason } => {
                        lookup = "refused_before_lookup";
                        refuse(reason, port)
                    }
                    adm => match Slot::take(&shared.active_lookups, shared.limits.max_lookups) {
                        None => {
                            shared.events.lock().unwrap().push(Event::ProxyLimit {
                                session_id: sess.id.clone(),
                                resource: "dns_lookups".into(),
                                limit: shared.limits.max_lookups as u64,
                            });
                            refuse("resolver capacity reached; refusing rather than skipping the check".into(), port)
                        }
                        Some(_slot) => {
                            lookup = if adm == HostnameAdmission::ResolveAllowedName { "allowed_name" } else { "address_rules_exposure" };
                            let candidates = (shared.resolver)(&h.name, port).unwrap_or_default();
                            decide_with(Some(p), sess, host.clone(), &candidates, port, shared.guard_local)
                        }
                    },
                }
            }
            (Some(_), _, None) => refuse("no policy installed".into(), port),
            (None, Some(ip), _) => decide(pp.as_deref(), sess, None, &[ip], port),
            (None, None, _) => decide(pp.as_deref(), sess, None, &orig.map(|o| vec![o.ip()]).unwrap_or_default(), port),
        },
    };
    let mut attempt_json = serde_json::to_value(&outcome.attempt).unwrap_or_default();
    attempt_json["dns_lookup"] = serde_json::Value::String(lookup.into());
    if let (Some(o), Some(to)) = (orig, outcome.connect_to) {
        if o.ip() != to.ip() {
            attempt_json["client_dialed"] = serde_json::Value::String(o.to_string());
        }
    }
    let record = Event::Flow {
        attempt: attempt_json,
        decision: decision_json(&outcome, pp.as_ref().map(|p| p.revision)),
        measurement_source: MEASUREMENT.into(),
        transfer: None,
    };
    shared.events.lock().unwrap().push(record);
    let Some(to) = outcome.connect_to else {
        if connect || matches!(peeked, Peeked::Http { .. }) {
            deny_http(&mut client, &outcome.reason);
        }
        let _ = client.shutdown(Shutdown::Both);
        return;
    };
    let mut up = match connect_upstream(to, shared.connect_timeout) {
        Ok(u) => u,
        Err(e) => {
            if connect {
                let _ = write!(client, "HTTP/1.1 502 Bad Gateway\r\nContent-Length: 0\r\nConnection: close\r\n\r\n");
            }
            let _ = e;
            return;
        }
    };
    if connect && client.write_all(b"HTTP/1.1 200 Connection Established\r\n\r\n").is_err() {
        return;
    }
    if !forward.is_empty() && up.write_all(&forward).is_err() {
        return;
    }
    let (Ok(c2), Ok(u2)) = (client.try_clone(), up.try_clone()) else { return };
    // Register the stream before any byte flows back, so revalidation can end it.
    let id = shared.next_stream.fetch_add(1, Ordering::SeqCst);
    let (Ok(cr), Ok(ur)) = (client.try_clone(), up.try_clone()) else { return };
    let admitted_by = match outcome.decision.as_ref().map(|d| &d.winner) {
        Some(Winner::Rule { id, .. }) => format!("rule:{id}"),
        Some(Winner::ProfileDefault { profile, .. }) => format!("profile_default:{profile}"),
        None => "unknown".into(),
    };
    shared.streams.lock().unwrap().insert(
        id,
        StreamEntry { session: sess.clone(), host: host.clone(), to, admitted_by, admitted_at: Utc::now(), client: cr, upstream: ur },
    );
    // A policy change or isolation between the decision and registration must not be missed.
    let changed = match (&pp, &*shared.policy.read().unwrap()) {
        (Some(a), Some(b)) => !Arc::ptr_eq(a, b),
        (None, None) => false,
        _ => true,
    };
    if changed || shared.isolated.load(Ordering::SeqCst) {
        shared.revalidate(Utc::now());
    }
    let t = std::thread::spawn(move || pump(c2, u2));
    pump(up, client);
    let _ = t.join();
    shared.streams.lock().unwrap().remove(&id);
}

/// One session's listener (127.0.0.1 and ::1 on the same port).
pub struct SessionProxy {
    pub port: u16,
    pub session: SessionRef,
    stop: Arc<AtomicBool>,
    threads: Vec<JoinHandle<()>>,
}

impl SessionProxy {
    pub fn start(shared: Arc<Shared>, session: SessionRef, port: u16) -> std::io::Result<SessionProxy> {
        let v4 = TcpListener::bind(SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), port))?;
        let mut listeners = vec![v4];
        if let Ok(v6) = TcpListener::bind(SocketAddr::new(IpAddr::V6(Ipv6Addr::LOCALHOST), port)) {
            listeners.push(v6);
        }
        let stop = Arc::new(AtomicBool::new(false));
        let mut threads = Vec::new();
        for l in listeners {
            l.set_nonblocking(true)?;
            let (shared, stop, sess) = (shared.clone(), stop.clone(), session.clone());
            threads.push(std::thread::spawn(move || {
                while !stop.load(Ordering::Relaxed) {
                    match l.accept() {
                        Ok((c, _)) => {
                            let _ = c.set_nonblocking(false);
                            let (shared, sess) = (shared.clone(), sess.clone());
                            std::thread::spawn(move || handle_connection(&shared, &sess, c));
                        }
                        Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => std::thread::sleep(Duration::from_millis(20)),
                        Err(_) => std::thread::sleep(Duration::from_millis(50)),
                    }
                }
            }));
        }
        Ok(SessionProxy { port, session, stop, threads })
    }

    pub fn stop(self) {
        self.stop.store(true, Ordering::Relaxed);
        for t in self.threads {
            let _ = t.join();
        }
    }
}

/// Session proxies owned by the endpoint.
pub struct ProxyManager {
    pub shared: Arc<Shared>,
    pub ports: (u16, u16),
    pub sessions: BTreeMap<String, SessionProxy>,
}

impl ProxyManager {
    pub fn new(shared: Arc<Shared>, ports: (u16, u16)) -> Self {
        ProxyManager { shared, ports, sessions: BTreeMap::new() }
    }

    /// Start a listener for a session on the first free port in the range.
    pub fn open(&mut self, session_id: &str, profile: &str) -> Result<u16, String> {
        let used: Vec<u16> = self.sessions.values().map(|s| s.port).collect();
        let sess = SessionRef { id: session_id.into(), profile: profile.into(), boundary: Boundary::LinuxCgroup, verified: true };
        for port in self.ports.0..=self.ports.1 {
            if used.contains(&port) {
                continue;
            }
            if let Ok(p) = SessionProxy::start(self.shared.clone(), sess.clone(), port) {
                self.sessions.insert(session_id.into(), p);
                return Ok(port);
            }
        }
        Err(format!("no free egress-proxy port in {}-{}", self.ports.0, self.ports.1))
    }

    pub fn close(&mut self, session_id: &str) {
        if let Some(p) = self.sessions.remove(session_id) {
            p.stop();
        }
        // Task closed: its admitted streams end with it.
        self.shared.terminate_session(session_id, "session closed");
    }

    /// Install a new policy and immediately re-check every open stream against it.
    pub fn set_policy(&self, p: Option<ProxyPolicy>) {
        *self.shared.policy.write().unwrap() = p.map(Arc::new);
        self.shared.revalidate(Utc::now());
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;

    /// A minimal, well-formed TLS 1.2-style ClientHello carrying `sni` (or none), split into records of `frag` bytes.
    pub fn client_hello(sni: Option<&str>, frag: usize) -> Vec<u8> {
        let mut ext = Vec::new();
        if let Some(n) = sni {
            let mut list = vec![0u8];
            list.extend_from_slice(&(n.len() as u16).to_be_bytes());
            list.extend_from_slice(n.as_bytes());
            let mut sn = (list.len() as u16).to_be_bytes().to_vec();
            sn.extend_from_slice(&list);
            ext.extend_from_slice(&[0, 0]);
            ext.extend_from_slice(&(sn.len() as u16).to_be_bytes());
            ext.extend_from_slice(&sn);
        }
        // an unrelated extension (supported_versions) so SNI is not trivially first
        ext.splice(0..0, [0x00, 0x2b, 0x00, 0x03, 0x02, 0x03, 0x04]);
        let mut body = vec![0x03, 0x03];
        body.extend_from_slice(&[7u8; 32]);
        body.push(0); // session id
        body.extend_from_slice(&[0, 2, 0x13, 0x01]); // one cipher suite
        body.extend_from_slice(&[1, 0]); // compression
        body.extend_from_slice(&(ext.len() as u16).to_be_bytes());
        body.extend_from_slice(&ext);
        let mut hs = vec![0x01];
        hs.extend_from_slice(&(body.len() as u32).to_be_bytes()[1..]);
        hs.extend_from_slice(&body);
        let mut out = Vec::new();
        for c in hs.chunks(frag) {
            out.extend_from_slice(&[0x16, 0x03, 0x01]);
            out.extend_from_slice(&(c.len() as u16).to_be_bytes());
            out.extend_from_slice(c);
        }
        out
    }

    #[test]
    fn reads_sni_including_fragmented_hellos() {
        let h = client_hello(Some("API.GitHub.com."), 4096);
        assert_eq!(classify(&h), Some(Peeked::Tls { sni: Some("api.github.com".into()) }));
        let f = client_hello(Some("registry.npmjs.org"), 7);
        assert_eq!(classify(&f), Some(Peeked::Tls { sni: Some("registry.npmjs.org".into()) }));
        assert_eq!(classify(&f[..f.len() - 1]), None, "incomplete hello waits for more bytes");
        assert_eq!(classify(&client_hello(None, 4096)), Some(Peeked::Tls { sni: None }));
        // an IP literal is not a valid SNI hostname
        assert_eq!(classify(&client_hello(Some("140.82.112.3"), 4096)), Some(Peeked::Tls { sni: None }));
    }

    #[test]
    fn reads_connect_and_http_host() {
        let c = b"CONNECT api.anthropic.com:443 HTTP/1.1\r\nHost: api.anthropic.com:443\r\n\r\nxyz";
        assert_eq!(classify(c), Some(Peeked::Connect { host: "api.anthropic.com".into(), port: 443, header_len: c.len() - 3 }));
        assert_eq!(classify(b"CONNECT api.anthropic.com:443 HTTP/1.1\r\n"), None);
        assert_eq!(
            classify(b"GET / HTTP/1.1\r\nhost: Example.COM:8080\r\nAccept: */*\r\n\r\n"),
            Some(Peeked::Http { host: Some("example.com".into()), port: Some(8080) })
        );
        assert_eq!(
            classify(b"GET http://deb.debian.org/debian/ HTTP/1.1\r\nHost: other\r\n\r\n"),
            Some(Peeked::Http { host: Some("deb.debian.org".into()), port: None })
        );
        assert_eq!(classify(b"SSH-2.0-OpenSSH_9.6\r\n"), Some(Peeked::Opaque));
        assert_eq!(classify(b"\x00\x01binary"), Some(Peeked::Opaque));
        assert_eq!(classify(b"GE"), None);
        assert_eq!(split_host_port("[2001:db8::1]:443"), ("2001:db8::1".into(), Some(443)));
    }

    fn home() -> ProxyPolicy {
        let p = Policy::parse(include_str!("../../../conformance/policies/home.toml")).unwrap();
        ProxyPolicy { policy: p, device_id: "omarchy".into(), revision: 7 }
    }

    fn coding() -> SessionRef {
        SessionRef { id: "s1".into(), profile: "coding-session".into(), boundary: Boundary::LinuxCgroup, verified: true }
    }

    fn sni(n: &str) -> Option<HostnameEvidence> {
        Some(HostnameEvidence { name: n.into(), source: HostnameSource::Sni, confidence: Confidence::Medium })
    }

    #[test]
    fn decisions_use_hostname_and_resolved_address() {
        let pp = home();
        let gh: IpAddr = "140.82.113.6".parse().unwrap();
        let o = decide(Some(&pp), &coding(), sni("api.github.com"), &[gh], 443);
        assert_eq!(o.connect_to, Some(SocketAddr::new(gh, 443)), "{}", o.reason);
        // wrong port: the allow is tcp/443 only
        assert!(decide(Some(&pp), &coding(), sni("api.github.com"), &[gh], 22).connect_to.is_none());
        // an allowed name resolving to the controller is denied by the safety rule; a second, public answer is used
        let ctl: IpAddr = "100.100.1.2".parse().unwrap();
        let o = decide(Some(&pp), &coding(), sni("github.com"), &[ctl], 443);
        assert!(o.connect_to.is_none());
        assert!(o.reason.contains("safety"), "{}", o.reason);
        let o = decide(Some(&pp), &coding(), sni("github.com"), &[ctl, gh], 443);
        assert_eq!(o.connect_to.unwrap().ip(), gh);
        // unlisted host and missing SNI fall to the profile default
        assert!(decide(Some(&pp), &coding(), sni("paste.example"), &[gh], 443).connect_to.is_none());
        assert!(decide(Some(&pp), &coding(), None, &[gh], 443).connect_to.is_none());
        // no policy or no resolution: deny
        assert!(decide(None, &coding(), sni("api.github.com"), &[gh], 443).connect_to.is_none());
        assert!(decide(Some(&pp), &coding(), sni("api.github.com"), &[], 443).reason.contains("did not resolve"));
        // another session of the same profile gets the same answer for an unlisted host
        let other = SessionRef { id: "s2".into(), ..coding() };
        assert!(decide(Some(&pp), &other, sni("paste.example"), &[gh], 443).connect_to.is_none());
    }

    fn echo_server() -> SocketAddr {
        let l = TcpListener::bind("127.0.0.1:0").unwrap();
        let a = l.local_addr().unwrap();
        std::thread::spawn(move || {
            for c in l.incoming().flatten() {
                std::thread::spawn(move || {
                    let mut c = c;
                    let mut b = [0u8; 4096];
                    while let Ok(n) = c.read(&mut b) {
                        if n == 0 || c.write_all(&b[..n]).is_err() {
                            break;
                        }
                    }
                });
            }
        });
        a
    }

    fn lab_policy(upstream_port: u16) -> ProxyPolicy {
        lab_policy_with(upstream_port, None)
    }

    /// `expires`: an RFC 3339 deadline for the allow-lab rule (an expiring permission).
    fn lab_policy_with(upstream_port: u16, expires: Option<&str>) -> ProxyPolicy {
        let exp = expires.map(|e| format!("expires_at = \"{e}\"\n")).unwrap_or_default();
        let src = format!(
            "{}\n[[rules]]\nid = \"allow-lab\"\naction = \"allow\"\ntransport = \"tcp\"\nports = [{upstream_port}]\nselector = {{ session = {{ profiles = [\"coding-session\"] }} }}\ndestinations = {{ hosts = [\"allowed.test\"] }}\n{exp}provenance = {{ kind = \"git\", reference = \"t\" }}\n",
            // without the loopback allow, so the upstream (on loopback) is reachable only through the hostname rule
            include_str!("../../../conformance/policies/home.toml").replace(
                "id = \"coding-allow-loopback\"\naction = \"allow\"\nselector = { session = { profiles = [\"coding-session\"] } }",
                "id = \"coding-allow-loopback\"\naction = \"allow\"\nselector = { session = { profiles = [\"local-inference\"] } }"
            )
        );
        ProxyPolicy { policy: Policy::parse(&src).unwrap(), device_id: "omarchy".into(), revision: 9 }
    }

    fn resolver(h: &str, _p: u16) -> std::io::Result<Vec<IpAddr>> {
        match h {
            "allowed.test" => Ok(vec!["127.0.0.1".parse().unwrap()]),
            "denied.test" => Ok(vec!["198.51.100.9".parse().unwrap()]),
            _ => Err(std::io::Error::new(std::io::ErrorKind::NotFound, "nxdomain")),
        }
    }

    fn start(test_orig: Option<SocketAddr>, upstream_port: u16) -> (Arc<Shared>, SessionProxy) {
        start_with(test_orig, lab_policy(upstream_port), Box::new(resolver), Limits::default())
    }

    fn start_with(test_orig: Option<SocketAddr>, policy: ProxyPolicy, res: Box<Resolver>, limits: Limits) -> (Arc<Shared>, SessionProxy) {
        let mut sh = Shared::new(res);
        sh.limits = limits;
        sh.test_original_dst = test_orig;
        sh.peek_timeout = Duration::from_millis(300);
        // the only upstream available in-process is on loopback; the local-address guard has its own test
        sh.guard_local = false;
        let sh = Arc::new(sh);
        *sh.policy.write().unwrap() = Some(Arc::new(policy));
        let l = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = l.local_addr().unwrap().port();
        drop(l);
        let p = SessionProxy::start(sh.clone(), coding(), port).unwrap();
        (sh, p)
    }

    fn read_some(s: &mut TcpStream) -> String {
        s.set_read_timeout(Some(Duration::from_secs(3))).unwrap();
        let mut b = vec![0u8; 4096];
        let n = s.read(&mut b).unwrap_or(0);
        String::from_utf8_lossy(&b[..n]).into()
    }

    #[test]
    fn connect_tunnel_allows_listed_hosts_and_refuses_others() {
        let up = echo_server();
        let (sh, p) = start(None, up.port());
        let mut c = TcpStream::connect(("127.0.0.1", p.port)).unwrap();
        write!(c, "CONNECT allowed.test:{} HTTP/1.1\r\nHost: allowed.test\r\n\r\n", up.port()).unwrap();
        assert!(read_some(&mut c).starts_with("HTTP/1.1 200"));
        c.write_all(b"ping").unwrap();
        assert_eq!(read_some(&mut c), "ping");
        drop(c);
        let mut d = TcpStream::connect(("127.0.0.1", p.port)).unwrap();
        write!(d, "CONNECT denied.test:{} HTTP/1.1\r\n\r\n", up.port()).unwrap();
        let r = read_some(&mut d);
        assert!(r.starts_with("HTTP/1.1 403") && r.contains("coding-session"), "{r}");
        // a TLS hello sent straight to the listener has no original destination: refused
        let mut t = TcpStream::connect(("127.0.0.1", p.port)).unwrap();
        t.write_all(&client_hello(Some("allowed.test"), 4096)).unwrap();
        assert_eq!(read_some(&mut t), "");
        std::thread::sleep(Duration::from_millis(100));
        let evs = sh.drain_events();
        assert_eq!(evs.len(), 3, "{evs:?}");
        let Event::Flow { attempt, decision, .. } = &evs[0] else { panic!() };
        assert_eq!(attempt["hostname"]["source"], "connect_proxy");
        assert_eq!(decision["verdict"], "allow");
        assert_eq!(decision["rule"], "allow-lab");
        p.stop();
    }

    #[test]
    fn transparent_sni_connects_to_the_resolved_host_not_the_dialed_ip() {
        let up = echo_server();
        // the client "dialed" 192.0.2.66 (an attacker's address) with SNI allowed.test
        let (sh, p) = start(Some(SocketAddr::new("192.0.2.66".parse().unwrap(), up.port())), up.port());
        let mut c = TcpStream::connect(("127.0.0.1", p.port)).unwrap();
        let hello = client_hello(Some("allowed.test"), 4096);
        c.write_all(&hello).unwrap();
        // the echo server (the resolved host) returns the hello unchanged: forwarded byte for byte, not terminated
        c.set_read_timeout(Some(Duration::from_secs(3))).unwrap();
        let mut got = vec![0u8; hello.len()];
        c.read_exact(&mut got).unwrap();
        assert_eq!(got, hello);
        drop(c);
        // unlisted SNI: closed without forwarding
        let mut d = TcpStream::connect(("127.0.0.1", p.port)).unwrap();
        d.write_all(&client_hello(Some("denied.test"), 4096)).unwrap();
        assert_eq!(read_some(&mut d), "");
        // plain HTTP: Host header decides; a refusal is an explicit 403
        let mut h = TcpStream::connect(("127.0.0.1", p.port)).unwrap();
        h.write_all(b"GET / HTTP/1.1\r\nHost: denied.test\r\n\r\n").unwrap();
        assert!(read_some(&mut h).starts_with("HTTP/1.1 403"));
        std::thread::sleep(Duration::from_millis(100));
        let evs = sh.drain_events();
        let Event::Flow { attempt, decision, .. } = &evs[0] else { panic!() };
        assert_eq!(attempt["hostname"]["source"], "sni");
        assert_eq!(attempt["remote_ip"], "127.0.0.1");
        assert_eq!(attempt["client_dialed"], format!("192.0.2.66:{}", up.port()));
        assert_eq!(decision["verdict"], "allow");
        assert!(evs.iter().skip(1).all(|e| matches!(e, Event::Flow { decision, .. } if decision["verdict"] == "deny")));
        p.stop();
    }

    #[test]
    fn server_first_protocols_are_decided_on_the_address_after_a_short_wait() {
        let up = echo_server();
        // a LAN address the coding-session profile does not allow
        let (sh, p) = start(Some(SocketAddr::new("192.168.1.50".parse().unwrap(), 22)), up.port());
        let mut c = TcpStream::connect(("127.0.0.1", p.port)).unwrap();
        assert_eq!(read_some(&mut c), "");
        let evs = sh.drain_events();
        let Event::Flow { attempt, decision, .. } = &evs[0] else { panic!() };
        assert!(attempt.get("hostname").is_none());
        assert_eq!(decision["verdict"], "deny");
        p.stop();
    }

    /// Open a CONNECT tunnel to allowed.test through the proxy and prove bytes flow.
    fn open_tunnel(p: &SessionProxy, upstream_port: u16) -> TcpStream {
        let mut c = TcpStream::connect(("127.0.0.1", p.port)).unwrap();
        write!(c, "CONNECT allowed.test:{upstream_port} HTTP/1.1\r\n\r\n").unwrap();
        assert!(read_some(&mut c).starts_with("HTTP/1.1 200"));
        c.write_all(b"ping").unwrap();
        assert_eq!(read_some(&mut c), "ping");
        c
    }

    fn wait_streams(sh: &Shared, n: usize) {
        for _ in 0..100 {
            if sh.streams.lock().unwrap().len() == n {
                return;
            }
            std::thread::sleep(Duration::from_millis(10));
        }
        panic!("expected {n} open streams, have {}", sh.streams.lock().unwrap().len());
    }

    /// After Moat ends a stream the client sees EOF (or a reset), never more echoed bytes.
    fn assert_ended(c: &mut TcpStream) {
        let _ = c.write_all(b"after");
        c.set_read_timeout(Some(Duration::from_secs(3))).unwrap();
        let mut b = [0u8; 64];
        match c.read(&mut b) {
            Ok(0) | Err(_) => {}
            Ok(n) => panic!("stream still delivering after termination: {:?}", String::from_utf8_lossy(&b[..n])),
        }
    }

    fn terminated_reasons(sh: &Shared) -> Vec<String> {
        sh.drain_events()
            .into_iter()
            .filter_map(|e| match e {
                Event::StreamTerminated { reason, .. } => Some(reason),
                _ => None,
            })
            .collect()
    }

    #[test]
    fn an_admitted_stream_ends_when_its_permission_expires() {
        let up = echo_server();
        let deadline = Utc::now() + chrono::Duration::seconds(30);
        let (sh, p) = start_with(None, lab_policy_with(up.port(), Some(&deadline.to_rfc3339())), Box::new(resolver), Limits::default());
        let mut c = open_tunnel(&p, up.port());
        wait_streams(&sh, 1);
        // before the deadline the stream stays open
        assert!(sh.revalidate(deadline - chrono::Duration::seconds(1)).is_empty());
        c.write_all(b"still").unwrap();
        assert_eq!(read_some(&mut c), "still");
        // at the deadline it is ended, not renewed
        assert_eq!(sh.revalidate(deadline).len(), 1);
        assert_ended(&mut c);
        let r = terminated_reasons(&sh);
        assert!(r.len() == 1 && r[0].starts_with("no longer allowed"), "{r:?}");
        p.stop();
    }

    #[test]
    fn a_policy_change_to_deny_ends_open_streams() {
        let up = echo_server();
        let (sh, p) = start(None, up.port());
        let mut c = open_tunnel(&p, up.port());
        wait_streams(&sh, 1);
        let mgr = ProxyManager { shared: sh.clone(), ports: (0, 0), sessions: BTreeMap::new() };
        // same policy again: nothing ends
        mgr.set_policy(Some(lab_policy(up.port())));
        assert_eq!(sh.streams.lock().unwrap().len(), 1);
        // the allow removed (base home policy only): the open stream ends immediately
        mgr.set_policy(Some(lab_policy(up.port() ^ 1)));
        assert_ended(&mut c);
        assert_eq!(terminated_reasons(&sh).len(), 1);
        // and a new attempt is refused
        let mut d = TcpStream::connect(("127.0.0.1", p.port)).unwrap();
        write!(d, "CONNECT allowed.test:{} HTTP/1.1\r\n\r\n", up.port()).unwrap();
        assert!(read_some(&mut d).starts_with("HTTP/1.1 403"));
        p.stop();
    }

    #[test]
    fn isolation_ends_open_streams_and_refuses_new_ones() {
        let up = echo_server();
        let (sh, p) = start(None, up.port());
        let mut c = open_tunnel(&p, up.port());
        wait_streams(&sh, 1);
        sh.set_isolated(true);
        assert_ended(&mut c);
        assert_eq!(terminated_reasons(&sh), vec!["emergency isolation".to_string()]);
        let mut d = TcpStream::connect(("127.0.0.1", p.port)).unwrap();
        write!(d, "CONNECT allowed.test:{} HTTP/1.1\r\n\r\n", up.port()).unwrap();
        assert!(read_some(&mut d).starts_with("HTTP/1.1 403"));
        sh.set_isolated(false);
        drop(open_tunnel(&p, up.port()));
        p.stop();
    }

    #[test]
    fn closing_a_task_ends_its_streams_only() {
        let up = echo_server();
        let (sh, p) = start(None, up.port());
        let mut c = open_tunnel(&p, up.port());
        wait_streams(&sh, 1);
        assert_eq!(sh.terminate_session("some-other-session", "session closed"), 0);
        c.write_all(b"x").unwrap();
        assert_eq!(read_some(&mut c), "x");
        assert_eq!(sh.terminate_session("s1", "session closed"), 1);
        assert_ended(&mut c);
        p.stop();
    }

    #[test]
    fn a_name_the_policy_refuses_is_never_looked_up() {
        use std::sync::atomic::AtomicUsize;
        static LOOKUPS: AtomicUsize = AtomicUsize::new(0);
        static LOOKED: Mutex<Vec<String>> = Mutex::new(Vec::new());
        fn counting(h: &str, p: u16) -> std::io::Result<Vec<IpAddr>> {
            LOOKUPS.fetch_add(1, Ordering::SeqCst);
            LOOKED.lock().unwrap().push(h.to_string());
            resolver(h, p)
        }
        let up = echo_server();
        // lab policy with the loopback allow removed: coding-session has no address rule that could allow port 443/up
        let (sh, p) = start_with(None, lab_policy(up.port()), Box::new(counting), Limits::default());
        for name in ["forbidden.test", "denied.test"] {
            let mut d = TcpStream::connect(("127.0.0.1", p.port)).unwrap();
            write!(d, "CONNECT {name}:{} HTTP/1.1\r\n\r\n", up.port()).unwrap();
            assert!(read_some(&mut d).starts_with("HTTP/1.1 403"));
        }
        std::thread::sleep(Duration::from_millis(50));
        let looked = LOOKED.lock().unwrap().clone();
        assert!(!looked.iter().any(|h| h == "forbidden.test" || h == "denied.test"), "refused names were resolved: {looked:?}");
        let evs = sh.drain_events();
        assert!(
            evs.iter().all(|e| !matches!(e, Event::Flow { attempt, .. } if attempt["dns_lookup"] != "refused_before_lookup")),
            "{evs:?}"
        );
        // positive control: the allowed name is resolved (so the counter does observe lookups)
        drop(open_tunnel(&p, up.port()));
        assert!(LOOKED.lock().unwrap().iter().any(|h| h == "allowed.test"));
        p.stop();
    }

    #[test]
    fn exhaustion_refuses_and_reports_rather_than_bypassing() {
        let up = echo_server();
        let (sh, p) = start_with(None, lab_policy(up.port()), Box::new(resolver), Limits { max_connections: 1, max_lookups: 16 });
        let _held = open_tunnel(&p, up.port());
        wait_streams(&sh, 1);
        let mut d = TcpStream::connect(("127.0.0.1", p.port)).unwrap();
        write!(d, "CONNECT allowed.test:{} HTTP/1.1\r\n\r\n", up.port()).unwrap();
        assert_eq!(read_some(&mut d), "", "over the connection bound: closed, not tunnelled");
        std::thread::sleep(Duration::from_millis(50));
        assert!(sh.drain_events().iter().any(|e| matches!(e, Event::ProxyLimit { resource, limit: 1, .. } if resource == "connections")));
        p.stop();
    }
}
