//! Map a network 4-tuple to the process that owns it.
//!
//! This is the load-bearing piece of pfsnitch: a diverted packet carries no
//! identity, so the daemon must ask the kernel which process owns the socket.
//!
//! Uses libprocstat - the same library sockstat links against - because on
//! FreeBSD 15.1 both `net.inet.tcp.pcblist` and `kern.file` return zero bytes.
//!
//! Attribution works *before* the connection is established: a SYN still has a
//! PCB in SYN_SENT with its owning pid. net.inet.tcp.keepinit is 75000 ms, so
//! there are ~75s of SYN retries in which to decide.

#![allow(non_camel_case_types, non_upper_case_globals, dead_code)]

use std::collections::HashMap;
use std::ffi::CStr;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::time::{Duration, Instant};

use libc::{sockaddr_in, AF_INET, KERN_PROC_PROC};

include!("procstat_sys.rs");

/// Identity of the process behind a socket.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Owner {
    pub pid: i32,
    pub command: String,
    /// Full executable path. Policy keys on THIS, never on `command`:
    /// a process name is trivially spoofed, a path is not.
    pub path: String,
}

/// The 4-tuple identifying a flow. Ports alone are not enough - two processes
/// can legitimately hold the same local port to different peers.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Tuple {
    pub proto: u8,
    pub src: IpAddr,
    pub sport: u16,
    pub dst: IpAddr,
    pub dport: u16,
}

/// Cached attribution.
///
/// A full process+file walk costs milliseconds; a browser opening thirty
/// sockets would make that per-packet cost intolerable. So: look up on miss,
/// cache the result, and refresh the whole table at most every `ttl`.
pub struct Resolver {
    cache: HashMap<Tuple, Owner>,
    last_scan: Option<Instant>,
    ttl: Duration,
}

impl Resolver {
    pub fn new() -> Self {
        Resolver { cache: HashMap::new(), last_scan: None, ttl: Duration::from_millis(750) }
    }

    /// Resolve a flow to its owning process, rescanning if the cache misses.
    pub fn owner(&mut self, t: &Tuple) -> Option<Owner> {
        if let Some(o) = self.cache.get(t) {
            return Some(o.clone());
        }
        let stale = self.last_scan.map(|i| i.elapsed() > self.ttl).unwrap_or(true);
        if stale || !self.cache.contains_key(t) {
            self.rescan();
        }
        self.cache.get(t).cloned()
    }

    fn rescan(&mut self) {
        self.cache = snapshot();
        self.last_scan = Some(Instant::now());
    }
}

/// Full snapshot of sockets -> owning process, keyed by 4-tuple.
pub fn snapshot() -> HashMap<Tuple, Owner> {
    let mut out = HashMap::new();

    unsafe {
        let ps = procstat_open_sysctl();
        if ps.is_null() {
            return out;
        }
        let mut nproc: u32 = 0;
        let procs = procstat_getprocs(ps, KERN_PROC_PROC, 0, &mut nproc);
        if procs.is_null() {
            procstat_close(ps);
            return out;
        }

        for i in 0..nproc as isize {
            let p = procs.offset(i);
            let pid = (*p).ki_pid;
            let command = CStr::from_ptr((*p).ki_comm.as_ptr()).to_string_lossy().into_owned();

            // Executable path. Falls back to the command name if the binary is
            // gone (deleted or replaced while running) - which is itself worth
            // noticing, so it is recorded as such rather than silently blank.
            let mut pathbuf = [0i8; 1024];
            let path = if procstat_getpathname(ps, p, pathbuf.as_mut_ptr(), pathbuf.len()) == 0 {
                let s = CStr::from_ptr(pathbuf.as_ptr()).to_string_lossy().into_owned();
                if s.is_empty() { format!("<unknown:{command}>") } else { s }
            } else {
                format!("<unknown:{command}>")
            };

            let files = procstat_getfiles(ps, p, 0);
            if files.is_null() {
                continue; // process exited between getprocs and getfiles - normal, not an error
            }

            let mut fst = (*files).stqh_first;
            while !fst.is_null() {
                if (*fst).fs_type == PS_FST_TYPE_SOCKET as i32 {
                    let mut sock: sockstat = std::mem::zeroed();
                    let mut errbuf = [0i8; 256];
                    if procstat_get_socket_info(ps, fst, &mut sock, errbuf.as_mut_ptr()) == 0 {
                        if let (Some((sa, sp)), Some((da, dp))) =
                            (endpoint(&sock.sa_local), endpoint(&sock.sa_peer))
                        {
                            out.insert(
                                Tuple { proto: sock.proto as u8, src: sa, sport: sp, dst: da, dport: dp },
                                Owner { pid, command: command.clone(), path: path.clone() },
                            );
                        }
                    }
                }
                fst = (*fst).next.stqe_next;
            }
            procstat_freefiles(ps, files);
        }
        procstat_freeprocs(ps, procs);
        procstat_close(ps);
    }
    out
}

/// Pull the address and port out of a kernel socket, either family.
///
/// Renamed from v4() now that it handles both. The family filter lives here and
/// nowhere else, so this function alone decides what the resolver can attribute.
fn endpoint(sa: &sockaddr_storage) -> Option<(IpAddr, u16)> {
    unsafe {
        match sa.ss_family as i32 {
            f if f == AF_INET as i32 => {
                let sin = sa as *const sockaddr_storage as *const sockaddr_in;
                let port = u16::from_be((*sin).sin_port);
                if port == 0 {
                    return None; // unbound socket - nothing to key a flow on
                }
                Some((IpAddr::V4(Ipv4Addr::from(u32::from_be((*sin).sin_addr.s_addr))), port))
            }
            f if f == libc::AF_INET6 as i32 => {
                let sin6 = sa as *const sockaddr_storage as *const libc::sockaddr_in6;
                let port = u16::from_be((*sin6).sin6_port);
                if port == 0 {
                    return None;
                }
                Some((IpAddr::V6(Ipv6Addr::from((*sin6).sin6_addr.s6_addr)), port))
            }
            _ => None,
        }
    }
}

/// Is a pfsnitch daemon running?
///
/// Answerable WITHOUT privilege, which matters: the previous check bound the
/// divert port, and only root can do that. Every unprivileged frontend
/// therefore got "unknown", and at least two of them went on to render that as
/// "not running" - telling the user the firewall was off when it was not. A
/// security indicator that lies in that direction is worse than none.
///
/// Matches on argv rather than the process name, because `pfsnitch status` is
/// also called "pfsnitch" and would otherwise count as a daemon.
pub fn daemon_running() -> bool {
    const MODES: &[&str] = &["visibility", "enforcement", "listen", "enforce"];
    let me = std::process::id() as i32;

    unsafe {
        let ps = procstat_open_sysctl();
        if ps.is_null() {
            return false;
        }
        let mut cnt: libc::c_uint = 0;
        let procs = procstat_getprocs(ps, KERN_PROC_PROC as i32, 0, &mut cnt);
        if procs.is_null() {
            procstat_close(ps);
            return false;
        }

        let mut found = false;
        for i in 0..cnt as isize {
            let p = procs.offset(i);
            if (*p).ki_pid == me {
                continue;
            }
            let argv = procstat_getargv(ps, p, 0);
            if argv.is_null() {
                continue;
            }
            // argv is a NULL-terminated array of C strings.
            let mut words: Vec<String> = Vec::new();
            let mut j = 0isize;
            while !(*argv.offset(j)).is_null() && j < 8 {
                words.push(
                    CStr::from_ptr(*argv.offset(j))
                        .to_string_lossy()
                        .into_owned(),
                );
                j += 1;
            }
            procstat_freeargv(ps);

            let is_pfsnitch = words
                .first()
                .map(|a| a.rsplit('/').next().unwrap_or(a) == "pfsnitch")
                .unwrap_or(false);
            let has_mode = words.get(1).map(|m| MODES.contains(&m.as_str())).unwrap_or(false);
            if is_pfsnitch && has_mode {
                found = true;
                break;
            }
        }

        procstat_freeprocs(ps, procs);
        procstat_close(ps);
        found
    }
}
