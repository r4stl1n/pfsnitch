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

use std::collections::{HashMap, HashSet};
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

/// How confidently an owner was identified.
///
/// Why this exists: requiring a peer address made every *unconnected* UDP
/// socket invisible. `sendto()` without `connect()` leaves sa_peer zeroed, so
/// ntpd - which holds `*:123` and `10.0.0.2:123` with no peer - could never be
/// named, and its traffic became a global `allow-dest` rule applying to every
/// binary on the system. Weaker keys fix that, but they ARE weaker, and the
/// prompt says which one was used rather than pretending they are equivalent.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Confidence {
    /// Named by mac_pfsnitch.ko, which recorded the owner at socket creation
    /// in the creating process's own context. Stronger than `Exact`: not a
    /// scan that raced the process table, but the kernel's own answer.
    Kernel,
    /// Full 4-tuple. A connected socket; unambiguous.
    Exact,
    /// Peer-less socket, matched on (proto, local address, local port).
    Local,
    /// Wildcard-bound peer-less socket, matched on (proto, local port) alone.
    /// The weakest tier, so a contested key is refused rather than guessed.
    Port,
}

impl Confidence {
    pub fn as_str(self) -> &'static str {
        match self {
            Confidence::Kernel => "kernel",
            Confidence::Exact => "exact",
            Confidence::Local => "local",
            Confidence::Port => "port",
        }
    }
}

/// An owner, plus how it was found.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Attribution {
    pub owner: Owner,
    pub confidence: Confidence,
}

/// One attributable socket, as `pfsnitch probe` reports it.
#[derive(Debug, Clone)]
pub struct ProbeEntry {
    pub proto: u8,
    pub local: IpAddr,
    pub lport: u16,
    /// None for an unconnected socket: there is no peer to show.
    pub peer: Option<(IpAddr, u16)>,
    pub owner: Owner,
    pub confidence: Confidence,
}

/// Socket tables, one per confidence tier.
#[derive(Default)]
pub struct Tables {
    exact: HashMap<Tuple, Owner>,
    local: HashMap<(u8, IpAddr, u16), Owner>,
    port: HashMap<(u8, u16), Owner>,
    /// Weak keys claimed by more than one process. Naming the WRONG application
    /// is worse than naming none: the user would approve a rule for a binary
    /// that never made the connection. So a contested key is refused.
    contested_local: HashSet<(u8, IpAddr, u16)>,
    contested_port: HashSet<(u8, u16)>,
}

impl Tables {
    fn add_local(&mut self, k: (u8, IpAddr, u16), o: &Owner) {
        match self.local.get(&k) {
            Some(prev) if prev.pid != o.pid => { self.contested_local.insert(k); }
            Some(_) => {}
            None => { self.local.insert(k, o.clone()); }
        }
    }

    fn add_port(&mut self, k: (u8, u16), o: &Owner) {
        match self.port.get(&k) {
            Some(prev) if prev.pid != o.pid => { self.contested_port.insert(k); }
            Some(_) => {}
            None => { self.port.insert(k, o.clone()); }
        }
    }

    /// Look a flow up, strongest tier first.
    ///
    /// `outbound` gates the weak tiers, and must. For an INBOUND packet the
    /// local end is the destination, so matching its source port against local
    /// sockets would attribute a DNS reply from port 53 to whatever holds local
    /// port 53 - a resolver that never sent the query. The exact tier needs no
    /// such guard: it matches a whole tuple or nothing.
    pub fn get(&self, t: &Tuple, outbound: bool) -> Option<Attribution> {
        if let Some(o) = self.exact.get(t) {
            return Some(Attribution { owner: o.clone(), confidence: Confidence::Exact });
        }
        if !outbound {
            return None;
        }
        let lk = (t.proto, t.src, t.sport);
        if !self.contested_local.contains(&lk) {
            if let Some(o) = self.local.get(&lk) {
                return Some(Attribution { owner: o.clone(), confidence: Confidence::Local });
            }
        }
        let pk = (t.proto, t.sport);
        if !self.contested_port.contains(&pk) {
            if let Some(o) = self.port.get(&pk) {
                return Some(Attribution { owner: o.clone(), confidence: Confidence::Port });
            }
        }
        None
    }

    /// One row per attributable socket, for `pfsnitch probe`.
    pub fn entries(&self) -> Vec<ProbeEntry> {
        let mut v: Vec<ProbeEntry> = Vec::new();
        for (t, o) in &self.exact {
            v.push(ProbeEntry {
                proto: t.proto,
                local: t.src,
                lport: t.sport,
                peer: Some((t.dst, t.dport)),
                owner: o.clone(),
                confidence: Confidence::Exact,
            });
        }
        for ((proto, ip, port), o) in &self.local {
            if self.contested_local.contains(&(*proto, *ip, *port)) {
                continue;
            }
            v.push(ProbeEntry {
                proto: *proto,
                local: *ip,
                lport: *port,
                peer: None,
                owner: o.clone(),
                confidence: Confidence::Local,
            });
        }
        for ((proto, port), o) in &self.port {
            if self.contested_port.contains(&(*proto, *port)) {
                continue;
            }
            // Already reported with a real local address by the tier above;
            // listing it twice would overstate how much we know.
            if self.local.keys().any(|(p, _, lp)| p == proto && lp == port) {
                continue;
            }
            v.push(ProbeEntry {
                proto: *proto,
                local: IpAddr::V4(Ipv4Addr::UNSPECIFIED),
                lport: *port,
                peer: None,
                owner: o.clone(),
                confidence: Confidence::Port,
            });
        }
        v
    }

    pub fn len(&self) -> usize {
        self.entries().len()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Test seams. Nothing outside tests needs to build a table by hand.
    #[cfg(test)]
    pub fn insert_exact(&mut self, t: Tuple, o: Owner) { self.exact.insert(t, o); }
    #[cfg(test)]
    pub fn insert_unconnected(&mut self, proto: u8, local: IpAddr, port: u16, o: &Owner) {
        if local.is_unspecified() {
            self.add_port((proto, port), o);
        } else {
            self.add_local((proto, local, port), o);
            self.add_port((proto, port), o);
        }
    }
}

/// Cached attribution.
///
/// A full process+file walk costs milliseconds; a browser opening thirty
/// sockets would make that per-packet cost intolerable. So: look up on miss,
/// cache the result, and refresh the whole table at most every `ttl`.
pub struct Resolver {
    tables: Tables,
    last_scan: Option<Instant>,
    ttl: Duration,
    /// Flows that have already missed since the last scan. Without this, a
    /// genuinely unattributable flow - kernel traffic, or a socket that is
    /// already closed - forced a fresh process walk on EVERY packet, because
    /// the old miss test (`!cache.contains_key(t)`) was true by construction
    /// at the point it was evaluated.
    missed: HashSet<Tuple>,
}

impl Resolver {
    pub fn new() -> Self {
        Resolver {
            tables: Tables::default(),
            last_scan: None,
            ttl: Duration::from_millis(750),
            missed: HashSet::new(),
        }
    }

    /// Resolve a flow to its owner, rescanning once if the tables miss.
    pub fn resolve(&mut self, t: &Tuple, outbound: bool) -> Option<Attribution> {
        if let Some(a) = self.tables.get(t, outbound) {
            return Some(a);
        }
        let stale = self.last_scan.map(|i| i.elapsed() > self.ttl).unwrap_or(true);
        if stale || !self.missed.contains(t) {
            self.rescan();
            if let Some(a) = self.tables.get(t, outbound) {
                return Some(a);
            }
        }
        self.missed.insert(*t);
        None
    }

    /// Owner only, for callers that do not care how it was found.
    pub fn owner(&mut self, t: &Tuple) -> Option<Owner> {
        self.resolve(t, true).map(|a| a.owner)
    }

    fn rescan(&mut self) {
        self.tables = snapshot();
        self.last_scan = Some(Instant::now());
        self.missed.clear();
    }
}

/// Full snapshot of sockets -> owning process, across all three tiers.
pub fn snapshot() -> Tables {
    let mut out = Tables::default();

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
            // c_char, not i8: signedness of char differs by architecture
            // (i8 on x86_64, u8 on aarch64), and a literal type would only
            // compile on one of them.
            let mut pathbuf = [0 as libc::c_char; 1024];
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

            let owner = Owner { pid, command, path };

            let mut fst = (*files).stqh_first;
            while !fst.is_null() {
                if (*fst).fs_type == PS_FST_TYPE_SOCKET as i32 {
                    let mut sock: sockstat = std::mem::zeroed();
                    let mut errbuf = [0 as libc::c_char; 256];
                    if procstat_get_socket_info(ps, fst, &mut sock, errbuf.as_mut_ptr()) == 0 {
                        let proto = sock.proto as u8;
                        match (endpoint(&sock.sa_local), endpoint(&sock.sa_peer)) {
                            // Connected: the strong case, and the only one that
                            // can be keyed exactly.
                            (Some((sa, sp)), Some((da, dp))) => {
                                out.exact.insert(
                                    Tuple { proto, src: sa, sport: sp, dst: da, dport: dp },
                                    owner.clone(),
                                );
                            }
                            // Unconnected - `sendto()` with no `connect()`. This
                            // entire branch used to be discarded, which is why
                            // ntpd, mDNS, SSDP and DHCP clients came out as
                            // unattributed and earned global rules.
                            (Some((sa, sp)), None) => {
                                if sa.is_unspecified() {
                                    out.add_port((proto, sp), &owner);
                                } else {
                                    out.add_local((proto, sa, sp), &owner);
                                    // A packet can leave on an address the socket
                                    // never bound, so keep the port-only key too.
                                    out.add_port((proto, sp), &owner);
                                }
                            }
                            _ => {}
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

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    fn own(pid: i32, name: &str) -> Owner {
        Owner { pid, command: name.into(), path: format!("/usr/sbin/{name}") }
    }

    fn v4(a: u8, b: u8, c: u8, d: u8) -> IpAddr {
        IpAddr::V4(Ipv4Addr::new(a, b, c, d))
    }

    const UDP: u8 = 17;
    const TCP: u8 = 6;

    /// A connected socket is matched on the whole tuple.
    #[test]
    fn exact_tuple_wins() {
        let mut t = Tables::default();
        let f = Tuple { proto: TCP, src: v4(10, 0, 0, 2), sport: 54614, dst: v4(1, 1, 1, 1), dport: 443 };
        t.insert_exact(f, own(100, "firefox"));

        let got = t.get(&f, true).expect("exact match");
        assert_eq!(got.confidence, Confidence::Exact);
        assert_eq!(got.owner.pid, 100);
    }

    /// The regression this whole change exists for: ntpd sends from an
    /// unconnected socket, so there is no peer to key on, and it used to be
    /// invisible. Its real bound address must now name it.
    #[test]
    fn unconnected_socket_matches_on_local_address() {
        let mut t = Tables::default();
        t.insert_unconnected(UDP, v4(10, 0, 0, 2), 123, &own(200, "ntpd"));

        let f = Tuple { proto: UDP, src: v4(10, 0, 0, 2), sport: 123, dst: v4(198, 71, 50, 75), dport: 123 };
        let got = t.get(&f, true).expect("should attribute ntpd");
        assert_eq!(got.owner.command, "ntpd");
        assert_eq!(got.confidence, Confidence::Local);
    }

    /// ntpd also holds a wildcard `*:123`. A packet leaving on an address that
    /// socket never bound still has to land somewhere.
    #[test]
    fn wildcard_bind_falls_back_to_port() {
        let mut t = Tables::default();
        t.insert_unconnected(UDP, v4(0, 0, 0, 0), 123, &own(200, "ntpd"));

        let f = Tuple { proto: UDP, src: v4(10, 0, 0, 2), sport: 123, dst: v4(198, 71, 50, 75), dport: 123 };
        let got = t.get(&f, true).expect("should fall back to the port tier");
        assert_eq!(got.owner.command, "ntpd");
        assert_eq!(got.confidence, Confidence::Port);
    }

    /// Same process holding several sockets on one port is not a conflict.
    #[test]
    fn same_pid_many_sockets_is_not_contested() {
        let mut t = Tables::default();
        let o = own(200, "ntpd");
        t.insert_unconnected(UDP, v4(0, 0, 0, 0), 123, &o);
        t.insert_unconnected(UDP, v4(127, 0, 0, 1), 123, &o);
        t.insert_unconnected(UDP, v4(10, 0, 0, 2), 123, &o);

        let f = Tuple { proto: UDP, src: v4(10, 0, 0, 2), sport: 123, dst: v4(1, 2, 3, 4), dport: 123 };
        assert_eq!(t.get(&f, true).unwrap().owner.command, "ntpd");
    }

    /// Two different processes on one port: refuse rather than guess. Naming
    /// the wrong binary would have the user approve a rule for software that
    /// never made the connection.
    #[test]
    fn contested_port_is_refused() {
        let mut t = Tables::default();
        t.insert_unconnected(UDP, v4(0, 0, 0, 0), 5353, &own(300, "avahi"));
        t.insert_unconnected(UDP, v4(0, 0, 0, 0), 5353, &own(301, "mdnsd"));

        let f = Tuple { proto: UDP, src: v4(10, 0, 0, 2), sport: 5353, dst: v4(224, 0, 0, 251), dport: 5353 };
        assert!(t.get(&f, true).is_none(), "ambiguous port must not be attributed");
    }

    #[test]
    fn contested_local_address_is_refused() {
        let mut t = Tables::default();
        t.insert_unconnected(UDP, v4(10, 0, 0, 2), 9999, &own(400, "one"));
        t.insert_unconnected(UDP, v4(10, 0, 0, 2), 9999, &own(401, "two"));

        let f = Tuple { proto: UDP, src: v4(10, 0, 0, 2), sport: 9999, dst: v4(8, 8, 8, 8), dport: 53 };
        assert!(t.get(&f, true).is_none());
    }

    /// The reason `outbound` is a parameter. An inbound DNS reply comes FROM
    /// port 53; a local resolver holds local port 53. Matching the weak tiers
    /// on an inbound packet would blame the resolver for a query it never sent.
    #[test]
    fn inbound_packet_never_uses_weak_tiers() {
        let mut t = Tables::default();
        t.insert_unconnected(UDP, v4(0, 0, 0, 0), 53, &own(500, "unbound"));

        let reply = Tuple { proto: UDP, src: v4(8, 8, 8, 8), sport: 53, dst: v4(10, 0, 0, 2), dport: 54321 };
        assert!(t.get(&reply, false).is_none(), "must not attribute an inbound reply");
        // Proof the guard is what stops it, not an absent table entry.
        assert!(t.get(&reply, true).is_some());
    }

    /// A full tuple is direction-independent, so the guard must not break it.
    #[test]
    fn exact_match_still_works_inbound() {
        let mut t = Tables::default();
        let f = Tuple { proto: TCP, src: v4(1, 1, 1, 1), sport: 443, dst: v4(10, 0, 0, 2), dport: 54614 };
        t.insert_exact(f, own(100, "firefox"));
        assert_eq!(t.get(&f, false).unwrap().confidence, Confidence::Exact);
    }

    /// Exact must be preferred even when a weaker key would also match.
    #[test]
    fn stronger_tier_wins() {
        let mut t = Tables::default();
        let f = Tuple { proto: UDP, src: v4(10, 0, 0, 2), sport: 123, dst: v4(198, 71, 50, 75), dport: 123 };
        t.insert_exact(f, own(100, "the-real-sender"));
        t.insert_unconnected(UDP, v4(10, 0, 0, 2), 123, &own(200, "ntpd"));

        let got = t.get(&f, true).unwrap();
        assert_eq!(got.owner.command, "the-real-sender");
        assert_eq!(got.confidence, Confidence::Exact);
    }

    /// Protocol is part of every key: TCP and UDP port 123 are different things.
    #[test]
    fn protocol_is_part_of_the_key() {
        let mut t = Tables::default();
        t.insert_unconnected(UDP, v4(10, 0, 0, 2), 123, &own(200, "ntpd"));

        let tcp = Tuple { proto: TCP, src: v4(10, 0, 0, 2), sport: 123, dst: v4(1, 2, 3, 4), dport: 80 };
        assert!(t.get(&tcp, true).is_none());
    }

    #[test]
    fn confidence_strings_are_stable() {
        // The prompt contract passes these as argv; renaming one silently would
        // change what a frontend displays.
        assert_eq!(Confidence::Kernel.as_str(), "kernel");
        assert_eq!(Confidence::Exact.as_str(), "exact");
        assert_eq!(Confidence::Local.as_str(), "local");
        assert_eq!(Confidence::Port.as_str(), "port");
    }

    /// A contested key is dropped from `probe` output too, not just lookups.
    #[test]
    fn entries_skips_contested_keys() {
        let mut t = Tables::default();
        t.insert_unconnected(UDP, v4(0, 0, 0, 0), 5353, &own(300, "avahi"));
        t.insert_unconnected(UDP, v4(0, 0, 0, 0), 5353, &own(301, "mdnsd"));
        assert_eq!(t.entries().len(), 0);
    }

    /// One socket should be one row: the port-tier duplicate of a local-tier
    /// entry is suppressed so probe does not overstate what is known.
    #[test]
    fn entries_does_not_double_count_one_socket() {
        let mut t = Tables::default();
        t.insert_unconnected(UDP, v4(10, 0, 0, 2), 123, &own(200, "ntpd"));
        let rows = t.entries();
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].confidence, Confidence::Local);
    }
}
