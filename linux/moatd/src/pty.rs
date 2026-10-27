//! PTY proxy for interactive programs in protected sessions (client side, used by `moat-launch --pty`).
//!
//! Without it the workload receives the caller's terminal descriptors but runs in the daemon's session, so it is not
//! the terminal's foreground process group: full-screen TUIs lose job control and Ctrl-C reaches `moat-launch`.
//!
//! With it, `moat-launch` (running as the caller, outside the session) allocates a fresh PTY, passes the **slave** as
//! the workload's stdin/stdout/stderr, and asks the daemon to make it the workload's controlling terminal
//! (`setsid` + `TIOCSCTTY` between fork and exec, after the cgroup join and privilege drop). `moat-launch` puts the
//! real terminal in raw mode and relays bytes between it and the PTY master, propagating window-size changes. Ctrl-C,
//! Ctrl-Z and resizes then reach the workload through its own line discipline.
//!
//! Boundary note: the relay moves terminal bytes only, between two descriptors the caller already owned. It opens no
//! sockets and does not widen the session's network policy.

use std::fs::File;
use std::io::{Read, Write};
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd, RawFd};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::thread;
use std::time::Duration;

fn last_err(ctx: &str) -> std::io::Error {
    let e = std::io::Error::last_os_error();
    std::io::Error::new(e.kind(), format!("{ctx}: {e}"))
}

/// A freshly allocated PTY pair. The master stays with the caller; the slave goes to the workload.
pub struct PtyPair {
    pub master: OwnedFd,
    pub slave: OwnedFd,
}

/// Allocate a PTY with `posix_openpt` (no libutil dependency). Both ends are close-on-exec.
pub fn open_pty() -> std::io::Result<PtyPair> {
    // SAFETY: plain libc calls with checked return values; the fds are wrapped immediately.
    unsafe {
        let m = libc::posix_openpt(libc::O_RDWR | libc::O_NOCTTY | libc::O_CLOEXEC);
        if m < 0 {
            return Err(last_err("posix_openpt"));
        }
        let master = OwnedFd::from_raw_fd(m);
        if libc::grantpt(m) != 0 {
            return Err(last_err("grantpt"));
        }
        if libc::unlockpt(m) != 0 {
            return Err(last_err("unlockpt"));
        }
        let mut buf = [0 as libc::c_char; 128];
        if libc::ptsname_r(m, buf.as_mut_ptr(), buf.len()) != 0 {
            return Err(last_err("ptsname_r"));
        }
        let s = libc::open(buf.as_ptr(), libc::O_RDWR | libc::O_NOCTTY | libc::O_CLOEXEC);
        if s < 0 {
            return Err(last_err("open pty slave"));
        }
        Ok(PtyPair { master, slave: OwnedFd::from_raw_fd(s) })
    }
}

pub fn is_tty(fd: RawFd) -> bool {
    // SAFETY: isatty only inspects the descriptor.
    unsafe { libc::isatty(fd) == 1 }
}

/// Copy the window size of `from` (a terminal) to `to` (the PTY master). Returns the size copied.
pub fn copy_winsize(from: RawFd, to: RawFd) -> Option<(u16, u16)> {
    // SAFETY: TIOCGWINSZ/TIOCSWINSZ read/write a winsize struct we own.
    unsafe {
        let mut ws: libc::winsize = std::mem::zeroed();
        if libc::ioctl(from, libc::TIOCGWINSZ, &mut ws) != 0 {
            return None;
        }
        if libc::ioctl(to, libc::TIOCSWINSZ, &ws) != 0 {
            return None;
        }
        Some((ws.ws_row, ws.ws_col))
    }
}

/// Puts a terminal in raw mode and restores the original settings when dropped.
pub struct RawMode {
    fd: RawFd,
    saved: libc::termios,
}

impl RawMode {
    pub fn enter(fd: RawFd) -> std::io::Result<RawMode> {
        // SAFETY: termios structs are plain data; return values are checked.
        unsafe {
            let mut t: libc::termios = std::mem::zeroed();
            if libc::tcgetattr(fd, &mut t) != 0 {
                return Err(last_err("tcgetattr"));
            }
            let saved = t;
            libc::cfmakeraw(&mut t);
            if libc::tcsetattr(fd, libc::TCSANOW, &t) != 0 {
                return Err(last_err("tcsetattr"));
            }
            Ok(RawMode { fd, saved })
        }
    }
}

impl Drop for RawMode {
    fn drop(&mut self) {
        // SAFETY: restoring the settings captured in `enter`.
        unsafe {
            libc::tcsetattr(self.fd, libc::TCSAFLUSH, &self.saved);
        }
    }
}

/// Relay between the caller's terminal and the PTY master until the workload side closes (EIO on the master) or
/// `stop` is set. Spawns three threads: input, output, and a window-size follower.
pub fn relay(master: OwnedFd, stop: Arc<AtomicBool>) -> std::io::Result<thread::JoinHandle<()>> {
    let m_out = File::from(master.try_clone()?);
    let mut m_in = File::from(master);
    let winsize_master = m_out.as_raw_fd();

    // window-size follower: cheap polling avoids installing a SIGWINCH handler in a process that also blocks on IPC.
    {
        let stop = stop.clone();
        thread::spawn(move || {
            let mut last = None;
            while !stop.load(Ordering::Relaxed) {
                let cur = copy_winsize(0, winsize_master);
                if cur != last {
                    last = cur;
                }
                thread::sleep(Duration::from_millis(250));
            }
        });
    }
    // input: caller's stdin -> master
    {
        let stop = stop.clone();
        thread::spawn(move || {
            let mut stdin = std::io::stdin().lock();
            let mut buf = [0u8; 4096];
            while !stop.load(Ordering::Relaxed) {
                match stdin.read(&mut buf) {
                    Ok(0) | Err(_) => break,
                    Ok(n) => {
                        if m_in.write_all(&buf[..n]).is_err() {
                            break;
                        }
                    }
                }
            }
        });
    }
    // output: master -> caller's stdout. Ends with EIO once every slave descriptor is closed.
    let out = thread::spawn(move || {
        let mut m = m_out;
        let mut stdout = std::io::stdout().lock();
        let mut buf = [0u8; 8192];
        loop {
            match m.read(&mut buf) {
                Ok(0) | Err(_) => break,
                Ok(n) => {
                    if stdout.write_all(&buf[..n]).and_then(|_| stdout.flush()).is_err() {
                        break;
                    }
                }
            }
        }
        stop.store(true, Ordering::Relaxed);
    });
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pty_pair_round_trips_bytes_through_the_line_discipline() {
        let p = open_pty().expect("posix_openpt available");
        assert!(is_tty(p.slave.as_raw_fd()));
        assert!(!is_tty(-1));
        let mut slave = File::from(p.slave);
        let mut master = File::from(p.master);
        // raw-ish: write from the program side, read on the terminal side
        slave.write_all(b"hello\n").unwrap();
        let mut buf = [0u8; 64];
        let n = master.read(&mut buf).unwrap();
        let s = String::from_utf8_lossy(&buf[..n]);
        assert!(s.starts_with("hello"), "{s:?}");
    }

    #[test]
    fn winsize_copies_between_ptys() {
        let a = open_pty().unwrap();
        let b = open_pty().unwrap();
        // SAFETY: setting a winsize on our own PTY.
        unsafe {
            let ws = libc::winsize { ws_row: 40, ws_col: 120, ws_xpixel: 0, ws_ypixel: 0 };
            assert_eq!(libc::ioctl(a.master.as_raw_fd(), libc::TIOCSWINSZ, &ws), 0);
        }
        assert_eq!(copy_winsize(a.slave.as_raw_fd(), b.master.as_raw_fd()), Some((40, 120)));
    }
}
