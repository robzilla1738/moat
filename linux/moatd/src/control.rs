//! Local control socket: a small set of typed operations. No shell commands, no policy authoring, no signing.
//!
//! * `launch` — start a protected session for the *calling* user (identity from SO_PEERCRED, never from the
//!   request). The caller passes stdin/stdout/stderr with SCM_RIGHTS. A session only restricts its caller, so any
//!   local user may request one for themselves.
//! * `status`, `sessions` — read-only.
//! * `close` — end a session; only its owner or root.
//!
//! Recovery is deliberately *not* on this socket: it is a root-only CLI acting on local state, so it keeps
//! working when the daemon is wedged.

use std::collections::BTreeMap;
use std::io::{BufRead, BufReader, IoSlice, IoSliceMut, Write};
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd, RawFd};
use std::os::unix::net::UnixStream;
use std::path::PathBuf;

use nix::sys::socket::{getsockopt, recvmsg, sendmsg, sockopt::PeerCredentials, ControlMessage, ControlMessageOwned, MsgFlags};
use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
#[serde(tag = "op", rename_all = "snake_case")]
pub enum Request {
    Launch {
        profile: String,
        argv: Vec<String>,
        cwd: PathBuf,
        #[serde(default)]
        env: BTreeMap<String, String>,
        /// Hide user-session brokers (systemd --user/D-Bus, Docker, SSH agent). Default true.
        #[serde(default = "yes")]
        isolate_brokers: bool,
        /// stdin (fd 0 passed) is a PTY slave allocated by moat-launch: make it the workload's controlling terminal
        /// (setsid + TIOCSCTTY) so interactive programs get job control.
        #[serde(default)]
        controlling_tty: bool,
    },
    Status,
    Sessions,
    Close {
        session_id: String,
    },
}

fn yes() -> bool {
    true
}

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
#[serde(tag = "reply", rename_all = "snake_case")]
pub enum Reply {
    Started { session_id: String, pid: u32, cgroup: String, boundary: String },
    Exited { session_id: String, code: Option<i32>, signal: Option<i32> },
    Refused { reason: String },
    Status { status: serde_json::Value },
    Sessions { sessions: serde_json::Value },
    Closed { session_id: String },
    Error { message: String },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Peer {
    pub pid: i32,
    pub uid: u32,
    pub gid: u32,
}

pub fn peer(s: &UnixStream) -> std::io::Result<Peer> {
    let c = getsockopt(s, PeerCredentials).map_err(std::io::Error::from)?;
    Ok(Peer { pid: c.pid(), uid: c.uid(), gid: c.gid() })
}

pub const MAX_REQUEST: usize = 256 * 1024;

/// Send one JSON line, optionally with file descriptors attached.
pub fn send(s: &UnixStream, v: &impl Serialize, fds: &[RawFd]) -> std::io::Result<()> {
    let mut line = serde_json::to_vec(v).map_err(std::io::Error::other)?;
    line.push(b'\n');
    if fds.is_empty() {
        let mut w = s;
        return w.write_all(&line);
    }
    let iov = [IoSlice::new(&line)];
    let cmsg = [ControlMessage::ScmRights(fds)];
    let n = sendmsg::<()>(s.as_raw_fd(), &iov, &cmsg, MsgFlags::empty(), None).map_err(std::io::Error::from)?;
    if n < line.len() {
        let mut w = s;
        w.write_all(&line[n..])?;
    }
    Ok(())
}

/// Receive the first request line plus any descriptors that arrived with it.
pub fn recv_request(s: &UnixStream) -> std::io::Result<(Request, Vec<OwnedFd>)> {
    let mut buf = vec![0u8; 64 * 1024];
    let mut fds = Vec::new();
    let mut data = Vec::new();
    loop {
        let mut cmsg = nix::cmsg_space!([RawFd; 3]);
        let mut iov = [IoSliceMut::new(&mut buf)];
        let msg = recvmsg::<()>(s.as_raw_fd(), &mut iov, Some(&mut cmsg), MsgFlags::MSG_CMSG_CLOEXEC).map_err(std::io::Error::from)?;
        for c in msg.cmsgs().map_err(std::io::Error::from)? {
            if let ControlMessageOwned::ScmRights(rs) = c {
                for fd in rs {
                    // SAFETY: the kernel just installed these descriptors for us.
                    fds.push(unsafe { OwnedFd::from_raw_fd(fd) });
                }
            }
        }
        let n = msg.bytes;
        if n == 0 {
            return Err(std::io::Error::new(std::io::ErrorKind::UnexpectedEof, "peer closed"));
        }
        data.extend_from_slice(&buf[..n]);
        if let Some(pos) = data.iter().position(|b| *b == b'\n') {
            let req = serde_json::from_slice(&data[..pos]).map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?;
            return Ok((req, fds));
        }
        if data.len() > MAX_REQUEST {
            return Err(std::io::Error::new(std::io::ErrorKind::InvalidData, "request too large"));
        }
    }
}

/// Client helper: read reply lines.
pub fn replies(s: &UnixStream) -> impl Iterator<Item = Reply> + '_ {
    BufReader::new(s).lines().map_while(Result::ok).filter_map(|l| serde_json::from_str(&l).ok())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Read;

    #[test]
    fn request_roundtrip_with_fds() {
        let (a, b) = UnixStream::pair().unwrap();
        let (r, mut w) = UnixStream::pair().unwrap();
        let req = Request::Launch {
            profile: "coding-session".into(),
            argv: vec!["claude".into()],
            cwd: "/tmp".into(),
            env: BTreeMap::new(),
            isolate_brokers: true,
            controlling_tty: false,
        };
        send(&a, &req, &[w.as_raw_fd()]).unwrap();
        let (got, fds) = recv_request(&b).unwrap();
        assert_eq!(got, req);
        assert_eq!(fds.len(), 1);
        // the passed fd is the write end of `r`
        let mut f = std::fs::File::from(fds.into_iter().next().unwrap());
        f.write_all(b"hi").unwrap();
        drop(f);
        w.flush().unwrap();
        drop(w);
        let mut s = String::new();
        let mut r = r;
        r.set_read_timeout(Some(std::time::Duration::from_secs(2))).unwrap();
        let _ = r.read_to_string(&mut s);
        assert_eq!(s, "hi");
    }

    #[test]
    fn peer_credentials_are_kernel_supplied() {
        let (a, _b) = UnixStream::pair().unwrap();
        let p = peer(&a).unwrap();
        assert_eq!(p.uid, nix::unistd::getuid().as_raw());
    }

    #[test]
    fn unknown_ops_are_rejected() {
        assert!(serde_json::from_str::<Request>(r#"{"op":"exec","cmd":"rm -rf /"}"#).is_err());
        assert!(serde_json::from_str::<Request>(r#"{"op":"sign","policy":"x"}"#).is_err());
        let r: Request = serde_json::from_str(r#"{"op":"launch","profile":"p","argv":["x"],"cwd":"/"}"#).unwrap();
        assert!(matches!(r, Request::Launch { isolate_brokers: true, .. }));
    }
}
