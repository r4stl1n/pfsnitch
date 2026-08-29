//! Kernel-side attribution, via the optional mac_pfsnitch.ko module.
//!
//! Where procinfo reconstructs "who owns this 4-tuple" backwards - scanning
//! every process's file table and racing against process exit - the module
//! recorded the answer forwards, at socket creation, in the creating
//! process's own context. Asking it is one ioctl: no scan, no race, and it
//! still answers for a process that connected and exited immediately.
//!
//! This backend is OPT-IN (`attribution kernel` in policy.conf) and a miss is
//! expected, not exceptional: sockets created before the module loaded and
//! kernel-born sockets have no label. The caller falls back to procinfo, and
//! the confidence tier tells the prompt which path did the naming.
//!
//! The struct below mirrors kmod/pfsnitch_ioctl.h field for field. Any change
//! there bumps PFSNITCH_ATTR_VERSION and must be made here too; the module
//! rejects a version it does not speak rather than misreading the bytes.

use std::cell::Cell;
use std::io;
use std::net::IpAddr;
use std::os::unix::io::RawFd;

use crate::procinfo::{Attribution, Confidence, Owner, Tuple};

const PFSNITCH_DEV: &str = "/dev/pfsnitch\0";
const PFSNITCH_ATTR_VERSION: u32 = 1;

const PFSNITCH_MISS: u8 = 0;

const PFSNITCH_V_ALLOW: u8 = 1;
const PFSNITCH_V_DENY: u8 = 2;

/// kmod/pfsnitch_ioctl.h `struct pfsnitch_attr`, bit for bit.
#[repr(C)]
struct PfsnitchAttr {
    version: u32,
    af: u8,
    proto: u8,
    lport: u16, // network byte order, straight off the wire
    fport: u16,
    _pad0: [u8; 2],
    laddr: [u8; 16],
    faddr: [u8; 16],
    found: u8,
    _pad1: [u8; 3],
    pid: i32,
    uid: u32,
    _pad2: [u8; 4],
    comm: [u8; 24],
    path: [u8; 1024],
}

/// kmod/pfsnitch_ioctl.h `struct pfsnitch_verdict`, bit for bit.
#[repr(C)]
struct PfsnitchVerdict {
    version: u32,
    af: u8,
    proto: u8,
    fport: u16, // network byte order
    faddr: [u8; 16],
    verdict: u8,
    _pad: [u8; 3],
    path: [u8; 1024],
}

const IOC_VOID: libc::c_ulong = 0x2000_0000;
const IOC_IN: libc::c_ulong = 0x8000_0000;
const IOC_INOUT: libc::c_ulong = 0xC000_0000;
const IOCPARM_MASK: libc::c_ulong = 0x1fff;

const fn ioc(inout: libc::c_ulong, num: libc::c_ulong, len: libc::c_ulong) -> libc::c_ulong {
    inout | ((len & IOCPARM_MASK) << 16) | ((b'F' as libc::c_ulong) << 8) | num
}

/// _IOWR('F', 1, struct pfsnitch_attr) — computed, not pasted, so a struct
/// size change here cannot silently disagree with the constant.
const fn attr_query_cmd() -> libc::c_ulong {
    ioc(IOC_INOUT, 1, std::mem::size_of::<PfsnitchAttr>() as libc::c_ulong)
}
/// _IOW('F', 2, struct pfsnitch_verdict)
const fn verdict_push_cmd() -> libc::c_ulong {
    ioc(IOC_IN, 2, std::mem::size_of::<PfsnitchVerdict>() as libc::c_ulong)
}
/// _IO('F', 3)
const fn verdict_flush_cmd() -> libc::c_ulong {
    ioc(IOC_VOID, 3, 0)
}

pub struct KernAttr {
    fd: RawFd,
    /// Set when an ioctl reports the device is gone - kldunload revokes the
    /// open descriptor, and reloading the module creates a NEW device this fd
    /// will never reach. The daemon polls this and reopens, so an unload/load
    /// cycle heals within a second instead of silently degrading to procstat
    /// for the rest of the daemon's life.
    dead: Cell<bool>,
}

impl KernAttr {
    /// Open the query device. Fails if the module is not loaded, which the
    /// caller reports and survives - the userspace path still works.
    pub fn open() -> io::Result<Self> {
        let fd = unsafe {
            libc::open(
                PFSNITCH_DEV.as_ptr() as *const libc::c_char,
                libc::O_RDWR | libc::O_CLOEXEC,
            )
        };
        if fd < 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(KernAttr { fd, dead: Cell::new(false) })
    }

    pub fn is_dead(&self) -> bool {
        self.dead.get()
    }

    /// Ask the kernel who owns an OUTBOUND flow: the packet's source is the
    /// local end, exactly how the tuple is keyed into the pcb hash.
    pub fn query(&self, t: &Tuple) -> Option<Attribution> {
        if t.proto != 6 && t.proto != 17 {
            return None;
        }
        let mut q: PfsnitchAttr = unsafe { std::mem::zeroed() };
        q.version = PFSNITCH_ATTR_VERSION;
        q.proto = t.proto;
        q.lport = t.sport.to_be();
        q.fport = t.dport.to_be();
        match (t.src, t.dst) {
            (IpAddr::V4(s), IpAddr::V4(d)) => {
                q.af = 4;
                q.laddr[..4].copy_from_slice(&s.octets());
                q.faddr[..4].copy_from_slice(&d.octets());
            }
            (IpAddr::V6(s), IpAddr::V6(d)) => {
                q.af = 6;
                q.laddr.copy_from_slice(&s.octets());
                q.faddr.copy_from_slice(&d.octets());
            }
            _ => return None,
        }

        let rc = unsafe { libc::ioctl(self.fd, attr_query_cmd(), &mut q) };
        if rc < 0 {
            self.note_errno();
            return None;
        }
        if q.found == PFSNITCH_MISS {
            return None;
        }

        let cstr = |b: &[u8]| -> String {
            let end = b.iter().position(|&c| c == 0).unwrap_or(b.len());
            String::from_utf8_lossy(&b[..end]).into_owned()
        };
        let command = cstr(&q.comm);
        let path = cstr(&q.path);
        // Same convention as the procstat path: a nameless binary is recorded
        // as such, not as an empty string a rule could never sensibly key on.
        let path = if path.is_empty() { format!("<unknown:{command}>") } else { path };

        Some(Attribution {
            owner: Owner { pid: q.pid, command, path },
            confidence: Confidence::Kernel,
        })
    }

    /// Push a settled verdict for one (binary, destination) into the kernel's
    /// cache, so a later connect() to it is answered in the hook rather than by
    /// diverting. A DENY becomes an EPERM at connect; an ALLOW is cached for the
    /// phase that retires divert. Best-effort: a failure just means the flow
    /// keeps taking the divert path, so errors are swallowed (a dead device is
    /// still noted, so the daemon's reconnect logic fires).
    pub fn push_verdict(&self, proto: u8, dst: IpAddr, dport: u16, path: &str, allow: bool) {
        if self.dead.get() || (proto != 6 && proto != 17) {
            return;
        }
        let pb = path.as_bytes();
        // The kernel wants a NUL-terminated path inside a fixed field; a path
        // that does not fit cannot be keyed on, so skip it rather than truncate
        // to a different binary.
        if pb.is_empty() || pb.len() >= 1024 {
            return;
        }
        let mut v: PfsnitchVerdict = unsafe { std::mem::zeroed() };
        v.version = PFSNITCH_ATTR_VERSION;
        v.proto = proto;
        v.fport = dport.to_be();
        v.verdict = if allow { PFSNITCH_V_ALLOW } else { PFSNITCH_V_DENY };
        match dst {
            IpAddr::V4(a) => {
                v.af = 4;
                v.faddr[..4].copy_from_slice(&a.octets());
            }
            IpAddr::V6(a) => {
                v.af = 6;
                v.faddr.copy_from_slice(&a.octets());
            }
        }
        v.path[..pb.len()].copy_from_slice(pb);
        let rc = unsafe { libc::ioctl(self.fd, verdict_push_cmd(), &v) };
        if rc < 0 {
            self.note_errno();
        }
    }

    /// Abandon the whole kernel cache. The daemon calls this on any policy
    /// reload, the same moment it clears its own decided-verdict map — a cached
    /// allow or deny must never outlive the rule that produced it.
    pub fn flush_verdicts(&self) {
        if self.dead.get() {
            return;
        }
        let rc = unsafe { libc::ioctl(self.fd, verdict_flush_cmd(), 0) };
        if rc < 0 {
            self.note_errno();
        }
    }

    /// A destroyed device answers ENOTTY — observed, not assumed: devfs swaps a
    /// dead cdevsw under the open fd and its ioctl entry knows no commands at
    /// all. The same errno would come from a daemon/module ABI mismatch, and
    /// treating that as death too is deliberate: the reopen cycle it triggers
    /// logs once a second instead of failing every call forever. ENXIO/EBADF/
    /// ENODEV are other spellings of "this fd is not coming back".
    fn note_errno(&self) {
        if matches!(
            io::Error::last_os_error().raw_os_error(),
            Some(libc::ENOTTY) | Some(libc::ENXIO) | Some(libc::EBADF) | Some(libc::ENODEV)
        ) {
            self.dead.set(true);
        }
    }
}

impl Drop for KernAttr {
    fn drop(&mut self) {
        unsafe { libc::close(self.fd) };
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The ioctl constant encodes the struct's size; if the struct drifts
    /// from the C definition the command stops matching and every query
    /// fails loudly instead of misreading memory. Pin both.
    #[test]
    fn abi_layout_matches_the_c_header() {
        assert_eq!(std::mem::size_of::<PfsnitchAttr>(), 1108);
        assert_eq!(attr_query_cmd(), 0xC454_4601);
    }

    #[test]
    fn verdict_abi_layout_matches_the_c_header() {
        assert_eq!(std::mem::size_of::<PfsnitchVerdict>(), 1052);
        assert_eq!(verdict_push_cmd(), 0x841C_4602);
        assert_eq!(verdict_flush_cmd(), 0x2000_4603);
    }
}
