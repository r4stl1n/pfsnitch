//! Divert socket: receive packets the firewall hands us, decide, reinject.
//!
//! CORRECTION TO EARLY DESIGN: this was originally planned around ipfw,
//! on the belief that pf had no userspace-verdict path. That was wrong -
//! FreeBSD's pf supports `divert-to <host> port <n>`, so pfsnitch runs
//! alongside the existing pf ruleset and ipfw is not involved at all.
//! That removes a whole firewall-migration phase and the risk that came
//! with it (loading ipfw activates a deny-all rule and drops the network).
//!
//! Semantics from divert(4):
//!   * socket(PF_DIVERT, SOCK_RAW, 0), bind sockaddr_in with sin_port = port
//!   * the port is NOT a TCP/UDP port - it is a cookie. For pf it encodes the
//!     original direction of the packet.
//!   * recvfrom returns the packet verbatim; the returned address has
//!     INADDR_ANY for outgoing packets.
//!   * sendto with INADDR_ANY reinjects as outgoing. Dropping a packet is
//!     simply never reinjecting it.
//!   * a reinjected packet that does not change direction is not re-diverted,
//!     so there is no feedback loop to defend against.

use std::io;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::mem;
use std::os::unix::io::RawFd;

/// PF_DIVERT from <sys/socket.h>. Not exposed by the libc crate on FreeBSD.
const PF_DIVERT: libc::c_int = 44;

pub struct Divert {
    fd: RawFd,
}

impl Divert {
    /// Bind a divert socket to `port`. Requires root.
    pub fn bind(port: u16) -> io::Result<Self> {
        unsafe {
            // SOCK_CLOEXEC is not optional here.
            //
            // Without it this descriptor is inherited by every process the
            // daemon execs - and the daemon execs the prompt, which execs eww,
            // which daemonises and spawns the whole user bar. The observed
            // result: `eww`, `socat`, `wpa_cli` and assorted shell scripts, all
            // running as an unprivileged user, holding fd 3 open on a root
            // divert socket. That is a privilege leak - those processes can read
            // and inject raw packets - and it also pins the port, so the daemon
            // can never rebind and `service pfsnitch restart` fails with
            // EADDRINUSE, leaving an empty anchor and a blocked network.
            //
            // std's sockets set this by default; this one is raw libc, so it
            // must be asked for explicitly.
            let fd = libc::socket(PF_DIVERT, libc::SOCK_RAW | libc::SOCK_CLOEXEC, 0);
            if fd < 0 {
                return Err(io::Error::last_os_error());
            }

            // Belt and braces: if a kernel ever ignores SOCK_CLOEXEC in the type
            // argument, set the flag directly rather than silently leaking again.
            if libc::fcntl(fd, libc::F_SETFD, libc::FD_CLOEXEC) < 0 {
                let e = io::Error::last_os_error();
                libc::close(fd);
                return Err(e);
            }

            let mut addr: libc::sockaddr_in = mem::zeroed();
            addr.sin_family = libc::AF_INET as libc::sa_family_t;
            addr.sin_port = port.to_be();
            addr.sin_addr.s_addr = libc::INADDR_ANY.to_be();

            if libc::bind(
                fd,
                &addr as *const _ as *const libc::sockaddr,
                mem::size_of::<libc::sockaddr_in>() as libc::socklen_t,
            ) < 0
            {
                let e = io::Error::last_os_error();
                libc::close(fd);
                return Err(e);
            }
            Ok(Divert { fd })
        }
    }

    /// Block until a packet is diverted to us. Returns the raw IP packet and
    /// the sockaddr it arrived with, which must be passed back to reinject.
    pub fn recv(&self, buf: &mut [u8]) -> io::Result<(usize, libc::sockaddr_in)> {
        unsafe {
            let mut from: libc::sockaddr_in = mem::zeroed();
            let mut len = mem::size_of::<libc::sockaddr_in>() as libc::socklen_t;
            let n = libc::recvfrom(
                self.fd,
                buf.as_mut_ptr() as *mut libc::c_void,
                buf.len(),
                0,
                &mut from as *mut _ as *mut libc::sockaddr,
                &mut len,
            );
            if n < 0 {
                return Err(io::Error::last_os_error());
            }
            Ok((n as usize, from))
        }
    }

    /// Reinject a packet, letting it continue through the stack.
    /// Not calling this is how a packet gets dropped.
    pub fn reinject(&self, pkt: &[u8], to: &libc::sockaddr_in) -> io::Result<()> {
        unsafe {
            let n = libc::sendto(
                self.fd,
                pkt.as_ptr() as *const libc::c_void,
                pkt.len(),
                0,
                to as *const _ as *const libc::sockaddr,
                mem::size_of::<libc::sockaddr_in>() as libc::socklen_t,
            );
            if n < 0 {
                return Err(io::Error::last_os_error());
            }
            Ok(())
        }
    }
}

impl Drop for Divert {
    fn drop(&mut self) {
        unsafe { libc::close(self.fd) };
    }
}
/// Minimal IPv4/IPv6 + TCP/UDP header parse - enough to identify a flow.
///
/// One divert socket carries both families: the kernel switches on the packet's
/// own version nibble (ip_divert.c, `case IPV6_VERSION >> 4`) rather than on
/// anything about the socket, so there is no second v6 socket to bind. Nor does
/// reinjection change - div_output() picks ip_output vs ip6_output from the same
/// version nibble, and reads only sin_addr==0 (out) vs !=0 (in) from the
/// sockaddr_in we echo back. So the entire cost of IPv6 lands right here.
#[derive(Debug, Clone, Copy)]
pub struct Flow {
    pub proto: u8,
    pub src: IpAddr,
    pub dst: IpAddr,
    pub sport: u16,
    pub dport: u16,
    pub syn_only: bool,
}

/// The upper-layer protocol and the offset its header starts at.
///
/// For IPv4 that offset is just the IHL. For IPv6 it means walking the
/// extension-header chain, which is the whole reason this is a separate step:
/// unlike IPv4's fixed byte-9 protocol field, v6's upper-layer protocol is only
/// known after following next_header to the end of the chain.
struct L3 {
    proto: u8,
    src: IpAddr,
    dst: IpAddr,
    l4: usize,
}

/// Step over one IPv6 extension header. Anything we don't recognise is treated
/// as the upper layer, which is the right default: an unknown next-header value
/// is by definition not one we know the length of, so we must stop.
fn skip_ext(pkt: &[u8], nh0: u8, off0: usize) -> Option<(u8, usize)> {
    let (mut nh, mut off) = (nh0, off0);
    // A well-formed chain is a handful of headers. A long one is a bug or an
    // attack, so bound it rather than trusting the packet to terminate.
    for _ in 0..8 {
        let len = match nh {
            // hop-by-hop, routing, destination options: length in 8-octet
            // units, not counting the first 8.
            0 | 43 | 60 => (*pkt.get(off + 1)? as usize + 1) * 8,
            44 => {
                // Fragment header is a fixed 8 bytes, but only the *first*
                // fragment carries the L4 header. A later fragment has no ports
                // to read, so refuse rather than parse whatever is at that
                // offset and mistake it for a port pair.
                let fo = u16::from_be_bytes([*pkt.get(off + 2)?, *pkt.get(off + 3)?]) >> 3;
                if fo != 0 {
                    return None;
                }
                8
            }
            // authentication header: length in 4-octet units, minus 2.
            51 => (*pkt.get(off + 1)? as usize + 2) * 4,
            _ => return Some((nh, off)),
        };
        nh = *pkt.get(off)?; // next_header is byte 0 of the header we're leaving
        off = off.checked_add(len)?;
        if off >= pkt.len() {
            return None;
        }
    }
    None
}

fn l3(pkt: &[u8]) -> Option<L3> {
    match pkt.first()? >> 4 {
        4 => {
            if pkt.len() < 20 {
                return None;
            }
            let ihl = ((pkt[0] & 0x0f) as usize) * 4;
            if ihl < 20 || pkt.len() < ihl {
                return None;
            }
            Some(L3 {
                proto: pkt[9],
                src: IpAddr::V4(Ipv4Addr::new(pkt[12], pkt[13], pkt[14], pkt[15])),
                dst: IpAddr::V4(Ipv4Addr::new(pkt[16], pkt[17], pkt[18], pkt[19])),
                l4: ihl,
            })
        }
        6 => {
            // Fixed 40-byte header: next_header at 6, addresses at 8 and 24.
            if pkt.len() < 40 {
                return None;
            }
            let mut s = [0u8; 16];
            let mut d = [0u8; 16];
            s.copy_from_slice(&pkt[8..24]);
            d.copy_from_slice(&pkt[24..40]);
            let (proto, l4) = skip_ext(pkt, pkt[6], 40)?;
            Some(L3 {
                proto,
                src: IpAddr::V6(Ipv6Addr::from(s)),
                dst: IpAddr::V6(Ipv6Addr::from(d)),
                l4,
            })
        }
        _ => None,
    }
}

pub fn parse(pkt: &[u8]) -> Option<Flow> {
    let h = l3(pkt)?;
    if pkt.len() < h.l4 + 4 {
        return None;
    }
    let sport = u16::from_be_bytes([pkt[h.l4], pkt[h.l4 + 1]]);
    let dport = u16::from_be_bytes([pkt[h.l4 + 2], pkt[h.l4 + 3]]);

    // For TCP, a connection attempt is SYN set and ACK clear.
    let syn_only = if h.proto == 6 && pkt.len() >= h.l4 + 14 {
        let flags = pkt[h.l4 + 13];
        (flags & 0x02) != 0 && (flags & 0x10) == 0
    } else {
        false
    };

    Some(Flow { proto: h.proto, src: h.src, dst: h.dst, sport, dport, syn_only })
}

pub fn payload_offset(pkt: &[u8]) -> Option<usize> {
    let h = l3(pkt)?;
    match h.proto {
        17 => Some(h.l4 + 8),                                    // udp: fixed 8-byte header
        6 => {
            let doff = ((pkt.get(h.l4 + 12)? >> 4) as usize) * 4; // tcp: variable
            Some(h.l4 + doff)
        }
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Build an IPv6 header with a given next-header and payload appended.
    fn v6(nh: u8, rest: &[u8]) -> Vec<u8> {
        let mut p = vec![0x60, 0, 0, 0];              // version 6
        p.extend_from_slice(&(rest.len() as u16).to_be_bytes()); // payload len
        p.push(nh);                                    // next header
        p.push(64);                                    // hop limit
        p.extend_from_slice(&[0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1]); // src
        p.extend_from_slice(&[0x20, 0x01, 0x48, 0x60, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x88, 0x88]); // dst
        p.extend_from_slice(rest);
        p
    }

    /// TCP header with the given flags byte.
    fn tcp(sport: u16, dport: u16, flags: u8) -> Vec<u8> {
        let mut t = Vec::new();
        t.extend_from_slice(&sport.to_be_bytes());
        t.extend_from_slice(&dport.to_be_bytes());
        t.extend_from_slice(&[0; 8]);   // seq + ack
        t.push(0x50);                   // data offset 5 words, no options
        t.push(flags);
        t.extend_from_slice(&[0; 6]);   // window, cksum, urg
        t
    }

    #[test]
    fn v6_syn_is_parsed_and_recognised_as_a_connection_attempt() {
        let f = parse(&v6(6, &tcp(41000, 443, 0x02))).expect("v6 SYN should parse");
        assert_eq!(f.proto, 6);
        assert_eq!(f.dport, 443);
        assert_eq!(f.sport, 41000);
        assert_eq!(f.dst, "2001:4860::8888".parse::<IpAddr>().unwrap());
        assert!(f.syn_only, "SYN without ACK is a connection attempt");
    }

    #[test]
    fn v6_synack_is_not_a_connection_attempt() {
        let f = parse(&v6(6, &tcp(443, 41000, 0x12))).unwrap(); // SYN|ACK
        assert!(!f.syn_only, "SYN+ACK is a reply, not an attempt");
    }

    #[test]
    fn v6_extension_headers_are_walked_to_reach_the_real_protocol() {
        // hop-by-hop (8 bytes: nh=tcp, len=0) then the TCP header.
        let mut chain = vec![6u8, 0, 0, 0, 0, 0, 0, 0];
        chain.extend_from_slice(&tcp(41000, 443, 0x02));
        let f = parse(&v6(0, &chain)).expect("must walk past hop-by-hop");
        assert_eq!(f.proto, 6, "protocol comes from the end of the chain, not byte 6");
        assert_eq!(f.dport, 443, "ports must be read after the extension header");
        assert!(f.syn_only);
    }

    #[test]
    fn v6_non_first_fragment_is_refused_rather_than_misparsed() {
        // Fragment header with a non-zero offset: no L4 header follows, so the
        // bytes at that offset are payload and must not be read as ports.
        let mut frag = vec![6u8, 0, 0x00, 0x08, 0, 0, 0, 1]; // frag offset != 0
        frag.extend_from_slice(&tcp(41000, 443, 0x02));
        assert!(parse(&v6(44, &frag)).is_none(), "later fragments carry no ports");
    }

    #[test]
    fn v6_udp_payload_offset_lands_after_the_udp_header() {
        let mut udp = vec![0x00, 0x35, 0x00, 0x35, 0, 8, 0, 0]; // sport/dport 53
        udp.extend_from_slice(b"DNSBODY");
        let pkt = v6(17, &udp);
        assert_eq!(payload_offset(&pkt), Some(48), "40-byte v6 header + 8-byte udp");
        assert_eq!(&pkt[48..], b"DNSBODY");
    }

    #[test]
    fn v4_still_parses_unchanged() {
        let mut p = vec![0x45, 0, 0, 40, 0, 0, 0, 0, 64, 6, 0, 0];
        p.extend_from_slice(&[10, 0, 0, 2]);
        p.extend_from_slice(&[8, 8, 8, 8]);
        p.extend_from_slice(&tcp(41000, 443, 0x02));
        let f = parse(&p).expect("v4 must still work");
        assert_eq!(f.dst, "8.8.8.8".parse::<IpAddr>().unwrap());
        assert_eq!(f.dport, 443);
        assert!(f.syn_only);
    }

    /// A checksum is correct exactly when summing the whole thing yields zero.
    /// Checking that is stronger than comparing against a value I computed the
    /// same way the code does.
    fn sums_to_zero(parts: &[&[u8]]) -> bool {
        csum(parts) == 0
    }

    #[test]
    fn v4_rst_has_valid_ip_and_tcp_checksums() {
        let mut p = vec![0x45, 0, 0, 40, 0, 0, 0, 0, 64, 6, 0, 0];
        p.extend_from_slice(&[10, 0, 0, 2]);
        p.extend_from_slice(&[93, 184, 216, 34]);
        p.extend_from_slice(&tcp(41000, 443, 0x02));
        let r = tcp_rst(&p).expect("a SYN should get a reset");

        assert_eq!(r.len(), 40);
        assert!(sums_to_zero(&[&r[..20]]), "IP header checksum is wrong");

        let pseudo = [93, 184, 216, 34, 10, 0, 0, 2, 0, 6, 0, 20];
        assert!(sums_to_zero(&[&pseudo, &r[20..]]), "TCP checksum is wrong");
    }

    #[test]
    fn v4_rst_is_addressed_back_to_the_sender() {
        let mut p = vec![0x45, 0, 0, 40, 0, 0, 0, 0, 64, 6, 0, 0];
        p.extend_from_slice(&[10, 0, 0, 2]);
        p.extend_from_slice(&[93, 184, 216, 34]);
        p.extend_from_slice(&tcp(41000, 443, 0x02));
        let r = tcp_rst(&p).unwrap();

        assert_eq!(&r[12..16], &[93, 184, 216, 34], "reset must come FROM the peer");
        assert_eq!(&r[16..20], &[10, 0, 0, 2], "and go TO the local end");
        assert_eq!(u16::from_be_bytes([r[20], r[21]]), 443, "source port is the peer's");
        assert_eq!(u16::from_be_bytes([r[22], r[23]]), 41000);
        assert_eq!(r[33] & 0x04, 0x04, "RST flag must be set");
        // A SYN consumes one sequence number, so the reset acknowledges seq+1.
        assert_eq!(u32::from_be_bytes([r[28], r[29], r[30], r[31]]), 1);
    }

    #[test]
    fn v6_rst_has_a_valid_tcp_checksum() {
        let p = v6(6, &tcp(41000, 443, 0x02));
        let r = tcp_rst(&p).expect("a v6 SYN should get a reset");
        assert_eq!(r.len(), 60);

        let mut pseudo = Vec::new();
        pseudo.extend_from_slice(&r[8..24]);
        pseudo.extend_from_slice(&r[24..40]);
        pseudo.extend_from_slice(&20u32.to_be_bytes());
        pseudo.extend_from_slice(&[0, 0, 0, 6]);
        assert!(sums_to_zero(&[&pseudo, &r[40..]]), "v6 TCP checksum is wrong");
        assert_eq!(r[40 + 13] & 0x04, 0x04);
    }

    #[test]
    fn an_rst_is_never_answered_with_another_rst() {
        // Otherwise two hosts can bounce resets off each other forever.
        let mut p = vec![0x45, 0, 0, 40, 0, 0, 0, 0, 64, 6, 0, 0];
        p.extend_from_slice(&[10, 0, 0, 2]);
        p.extend_from_slice(&[93, 184, 216, 34]);
        p.extend_from_slice(&tcp(41000, 443, 0x04));
        assert!(tcp_rst(&p).is_none());
    }

    #[test]
    fn udp_gets_no_reset() {
        let mut udp = vec![0x00, 0x35, 0x00, 0x35, 0, 8, 0, 0];
        udp.extend_from_slice(b"x");
        assert!(tcp_rst(&v6(17, &udp)).is_none());
    }

    #[test]
    fn truncated_and_garbage_packets_are_rejected_not_panicked_on() {
        assert!(parse(&[]).is_none());
        assert!(parse(&[0x60]).is_none());
        assert!(parse(&vec![0x60; 39]).is_none(), "short of the 40-byte v6 header");
        assert!(parse(&[0x00; 60]).is_none(), "version 0 is neither family");
        // v6 header claiming hop-by-hop but with nothing after it
        assert!(parse(&v6(0, &[])).is_none());
    }
}

// ---------------------------------------------------------------------------
// Rejection.
//
// Dropping an unapproved SYN makes the application wait out TCP's own timeout -
// 75 seconds by default. That is the right behaviour while a prompt is open,
// because the retransmissions are what carry the connection until the user
// answers. It is the wrong behaviour for a settled `deny`: the application
// should be told no, immediately, the way a closed port would tell it.
//
// So a definitive deny synthesises an RST from the remote end and hands it back
// to the local stack.
// ---------------------------------------------------------------------------

/// Ones-complement sum used by both the IP and TCP checksums.
fn csum(parts: &[&[u8]]) -> u16 {
    let mut sum: u32 = 0;
    let mut carry_byte: Option<u8> = None;

    for part in parts {
        let mut i = 0;
        // A part may have odd length, in which case its last byte pairs with the
        // first byte of the next part - the sum is over the concatenation, not
        // over each piece separately.
        if let Some(hi) = carry_byte.take() {
            if !part.is_empty() {
                sum += u16::from_be_bytes([hi, part[0]]) as u32;
                i = 1;
            } else {
                carry_byte = Some(hi);
            }
        }
        while i + 1 < part.len() {
            sum += u16::from_be_bytes([part[i], part[i + 1]]) as u32;
            i += 2;
        }
        if i < part.len() {
            carry_byte = Some(part[i]);
        }
    }
    if let Some(hi) = carry_byte {
        sum += u16::from_be_bytes([hi, 0]) as u32;
    }
    while (sum >> 16) != 0 {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    !(sum as u16)
}

/// Build a TCP RST that answers `pkt`, addressed back to whoever sent it.
///
/// Returns None for anything that is not a TCP segment we should be resetting -
/// notably an RST itself, which must never be answered with another.
pub fn tcp_rst(pkt: &[u8]) -> Option<Vec<u8>> {
    let h = l3(pkt)?;
    if h.proto != 6 || pkt.len() < h.l4 + 20 {
        return None;
    }
    let flags = pkt[h.l4 + 13];
    if (flags & 0x04) != 0 {
        return None; // never answer an RST with an RST
    }

    let sport = u16::from_be_bytes([pkt[h.l4], pkt[h.l4 + 1]]);
    let dport = u16::from_be_bytes([pkt[h.l4 + 2], pkt[h.l4 + 3]]);
    let seq = u32::from_be_bytes([
        pkt[h.l4 + 4],
        pkt[h.l4 + 5],
        pkt[h.l4 + 6],
        pkt[h.l4 + 7],
    ]);

    // A SYN consumes one sequence number, so the reset acknowledges seq+1.
    let ack = seq.wrapping_add(if (flags & 0x02) != 0 { 1 } else { 0 });

    let mut tcp = Vec::with_capacity(20);
    tcp.extend_from_slice(&dport.to_be_bytes()); // ports swap: this comes FROM the peer
    tcp.extend_from_slice(&sport.to_be_bytes());
    tcp.extend_from_slice(&0u32.to_be_bytes()); // seq
    tcp.extend_from_slice(&ack.to_be_bytes());
    tcp.push(0x50); // data offset 5 words, no options
    tcp.push(0x14); // RST | ACK
    tcp.extend_from_slice(&0u16.to_be_bytes()); // window 0
    tcp.extend_from_slice(&0u16.to_be_bytes()); // checksum, filled below
    tcp.extend_from_slice(&0u16.to_be_bytes()); // urgent pointer

    match (h.src, h.dst) {
        (IpAddr::V4(s), IpAddr::V4(d)) => {
            let (so, de) = (d.octets(), s.octets()); // swapped
            let pseudo = [
                so[0], so[1], so[2], so[3], de[0], de[1], de[2], de[3], 0, 6, 0, 20,
            ];
            let ck = csum(&[&pseudo, &tcp]);
            tcp[16..18].copy_from_slice(&ck.to_be_bytes());

            let mut ip = Vec::with_capacity(40);
            ip.push(0x45);
            ip.push(0);
            ip.extend_from_slice(&40u16.to_be_bytes());
            ip.extend_from_slice(&0u16.to_be_bytes()); // id
            ip.extend_from_slice(&0u16.to_be_bytes()); // flags/frag
            ip.push(64); // ttl
            ip.push(6);
            ip.extend_from_slice(&0u16.to_be_bytes()); // header checksum
            ip.extend_from_slice(&so);
            ip.extend_from_slice(&de);
            let hc = csum(&[&ip]);
            ip[10..12].copy_from_slice(&hc.to_be_bytes());
            ip.extend_from_slice(&tcp);
            Some(ip)
        }
        (IpAddr::V6(s), IpAddr::V6(d)) => {
            let (so, de) = (d.octets(), s.octets()); // swapped
            let mut pseudo = Vec::with_capacity(40);
            pseudo.extend_from_slice(&so);
            pseudo.extend_from_slice(&de);
            pseudo.extend_from_slice(&20u32.to_be_bytes());
            pseudo.extend_from_slice(&[0, 0, 0, 6]);
            let ck = csum(&[&pseudo, &tcp]);
            tcp[16..18].copy_from_slice(&ck.to_be_bytes());

            let mut ip = Vec::with_capacity(60);
            ip.extend_from_slice(&[0x60, 0, 0, 0]);
            ip.extend_from_slice(&20u16.to_be_bytes()); // payload length
            ip.push(6); // next header
            ip.push(64); // hop limit
            ip.extend_from_slice(&so);
            ip.extend_from_slice(&de);
            ip.extend_from_slice(&tcp);
            Some(ip)
        }
        _ => None, // a packet cannot have mismatched families
    }
}

impl Divert {
    /// Hand a packet to the LOCAL stack as though it had arrived from outside.
    ///
    /// The kernel reads a zero sin_addr as "send this outbound" and anything
    /// else as "deliver this inbound" (ip_divert.c), so the address here only
    /// has to be non-zero - it is a direction flag, not a destination.
    pub fn reinject_inbound(&self, pkt: &[u8]) -> io::Result<()> {
        let mut sa: libc::sockaddr_in = unsafe { mem::zeroed() };
        sa.sin_len = mem::size_of::<libc::sockaddr_in>() as u8;
        sa.sin_family = libc::AF_INET as u8;
        sa.sin_addr.s_addr = u32::from_ne_bytes([127, 0, 0, 1]);
        self.reinject(pkt, &sa)
    }
}
