//! Learn hostnames by watching DNS answers.
//!
//! The daemon only ever sees packets, so a connection looks like an IP. But
//! the useful question at prompt time is "what did the application ask for?",
//! and that is the DNS *query* name, not a reverse lookup: a PTR on
//! 104.20.23.154 returns a Cloudflare hostname, not `example.com`.
//!
//! So: divert inbound DNS responses, remember question-name -> A records, and
//! consult that map when prompting. This is how Little Snitch and OpenSnitch
//! do it too.
//!
//! HONEST LIMITATION: this sees plaintext DNS only. An application using
//! DNS-over-HTTPS or DNS-over-TLS - which Firefox may do by default - resolves
//! names inside an encrypted channel we cannot read, so its connections will
//! show an IP with no name. That is a real blind spot, not a bug, and the
//! prompt must not imply a name is absent because none was used.
//!
//! SECURITY NOTE: this parses hostile input as root. Every read is bounds
//! checked and compression pointers are followed at most a fixed number of
//! times, so a malicious response cannot loop us or read out of bounds.

use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::time::{Duration, Instant};

pub struct DnsCache {
    map: HashMap<IpAddr, (String, Instant)>,
    ttl: Duration,
}

impl DnsCache {
    pub fn new() -> Self {
        // Deliberately longer than typical record TTLs: a name is useful for
        // explaining a connection even after the record technically expired.
        DnsCache { map: HashMap::new(), ttl: Duration::from_secs(3600) }
    }

    pub fn name_for(&self, ip: &IpAddr) -> Option<&str> {
        self.map.get(ip).map(|(n, _)| n.as_str())
    }

    pub fn len(&self) -> usize {
        self.map.len()
    }

    /// Feed a UDP payload that came from port 53. Non-responses are ignored.
    pub fn observe(&mut self, payload: &[u8]) {
        if let Some((name, ips)) = parse_response(payload) {
            let now = Instant::now();
            for ip in ips {
                self.map.insert(ip, (name.clone(), now));
            }
        }
        // opportunistic expiry, cheap enough to do inline
        if self.map.len() > 4096 {
            let ttl = self.ttl;
            self.map.retain(|_, (_, t)| t.elapsed() < ttl);
        }
    }
}

/// Extract (question name, A-record addresses) from a DNS response.
fn parse_response(b: &[u8]) -> Option<(String, Vec<IpAddr>)> {
    if b.len() < 12 {
        return None;
    }
    let flags = u16::from_be_bytes([b[2], b[3]]);
    if flags & 0x8000 == 0 {
        return None; // a query, not a response
    }
    let qd = u16::from_be_bytes([b[4], b[5]]) as usize;
    let an = u16::from_be_bytes([b[6], b[7]]) as usize;
    if qd == 0 || an == 0 {
        return None;
    }

    let mut off = 12usize;
    let (qname, next) = read_name(b, off)?;
    off = next + 4; // QTYPE + QCLASS
    // skip any further questions
    for _ in 1..qd {
        let (_, n) = read_name(b, off)?;
        off = n + 4;
    }

    let mut ips = Vec::new();
    for _ in 0..an {
        let (_, n) = read_name(b, off)?;
        off = n;
        if off + 10 > b.len() {
            break;
        }
        let rtype = u16::from_be_bytes([b[off], b[off + 1]]);
        let rdlen = u16::from_be_bytes([b[off + 8], b[off + 9]]) as usize;
        off += 10;
        if off + rdlen > b.len() {
            break;
        }
        // A (type 1) and AAAA (type 28) are the only records that map a name to
        // an address; CNAME and friends carry nothing we can key a flow on.
        // Match on type *and* length together so a malformed rdlen can never
        // make us read the wrong number of bytes as an address.
        match (rtype, rdlen) {
            (1, 4) => {
                ips.push(IpAddr::V4(Ipv4Addr::new(b[off], b[off + 1], b[off + 2], b[off + 3])));
            }
            (28, 16) => {
                let mut a = [0u8; 16];
                a.copy_from_slice(&b[off..off + 16]);
                ips.push(IpAddr::V6(Ipv6Addr::from(a)));
            }
            _ => {}
        }
        off += rdlen;
    }

    if ips.is_empty() { None } else { Some((qname, ips)) }
}

/// Read a (possibly compressed) DNS name. Returns the name and the offset just
/// past the name *in the original stream* - which for a compressed name is
/// past the 2-byte pointer, not past the target.
fn read_name(b: &[u8], start: usize) -> Option<(String, usize)> {
    let mut out = String::new();
    let mut off = start;
    let mut after: Option<usize> = None;
    let mut hops = 0;

    loop {
        if off >= b.len() {
            return None;
        }
        let len = b[off] as usize;

        if len & 0xc0 == 0xc0 {
            // compression pointer
            if off + 1 >= b.len() {
                return None;
            }
            let ptr = (((len & 0x3f) << 8) | b[off + 1] as usize) as usize;
            if after.is_none() {
                after = Some(off + 2);
            }
            hops += 1;
            if hops > 16 || ptr >= b.len() {
                return None; // malformed or a pointer loop
            }
            off = ptr;
            continue;
        }
        if len == 0 {
            off += 1;
            break;
        }
        if off + 1 + len > b.len() {
            return None;
        }
        if !out.is_empty() {
            out.push('.');
        }
        out.push_str(&String::from_utf8_lossy(&b[off + 1..off + 1 + len]));
        off += 1 + len;
    }
    Some((out, after.unwrap_or(off)))
}
