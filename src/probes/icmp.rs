use std::io;
use std::mem::size_of;
use std::net::{SocketAddr, ToSocketAddrs, UdpSocket};
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};

const ICMP_ECHO: u8 = 8;
const ICMP_ECHOREPLY: u8 = 0;
const ICMP_DEST_UNREACH: u8 = 3;
const ICMPV6_ECHO_REQUEST: u8 = 128;
const ICMPV6_ECHO_REPLY: u8 = 129;
const ICMPV6_DEST_UNREACH: u8 = 1;
const SO_EE_ORIGIN_ICMP: u8 = 2;
const SO_EE_ORIGIN_ICMP6: u8 = 3;
const SO_TIMESTAMPNS: libc::c_int = 35;
const PACKET_LEN: usize = 64;
const ROUTE_PROBE_PORT: u16 = 1025;

#[derive(Clone, Copy, Debug, PartialEq)]
pub struct EchoReply {
    pub seq: u16,
    pub sent_ns: u64,
}

#[derive(Clone, Copy, Debug, PartialEq)]
pub struct ExtendedErr {
    pub origin: u8,
    pub icmp_type: u8,
    pub icmp_code: u8,
}

#[derive(Clone, Copy, Debug, PartialEq)]
pub struct IcmpError {
    pub seq: u16,
    pub unreachable: bool,
}

pub struct Cmsg<'a> {
    pub level: libc::c_int,
    pub kind: libc::c_int,
    pub data: &'a [u8],
}

pub fn clock_ns(id: libc::clockid_t) -> i128 {
    let mut ts = libc::timespec { tv_sec: 0, tv_nsec: 0 };
    // SAFETY: ts is a valid out-pointer for clock_gettime.
    unsafe { libc::clock_gettime(id, &mut ts) };
    ts.tv_sec as i128 * 1_000_000_000 + ts.tv_nsec as i128
}

pub fn echo_request(seq: u16, sent_ns: u64, v6: bool) -> [u8; PACKET_LEN] {
    let mut pkt = [0u8; PACKET_LEN];
    pkt[0] = if v6 { ICMPV6_ECHO_REQUEST } else { ICMP_ECHO };
    pkt[6..8].copy_from_slice(&seq.to_be_bytes());
    pkt[8..16].copy_from_slice(&sent_ns.to_be_bytes());
    for (i, b) in pkt[16..].iter_mut().enumerate() {
        *b = (i + 16) as u8;
    }
    pkt
}

pub fn decode_echo_reply(buf: &[u8], v6: bool) -> Option<EchoReply> {
    let want = if v6 { ICMPV6_ECHO_REPLY } else { ICMP_ECHOREPLY };
    if buf.len() < 16 || buf[0] != want {
        return None;
    }
    let seq = u16::from_be_bytes([buf[6], buf[7]]);
    let sent_ns = u64::from_be_bytes(buf[8..16].try_into().ok()?);
    Some(EchoReply { seq, sent_ns })
}

pub fn is_unreachable(v6: bool, icmp_type: u8, code: u8) -> bool {
    if v6 {
        return icmp_type == ICMPV6_DEST_UNREACH;
    }
    // INFO: fc 17oct26 the codes whose iputils text contains "nreachable", which is all the Python regex matched
    icmp_type == ICMP_DEST_UNREACH && matches!(code, 0..=3 | 11 | 12 | 16..)
}

pub fn decode_error(err: ExtendedErr, original: &[u8], v6: bool) -> Option<IcmpError> {
    let (origin, echo) = if v6 { (SO_EE_ORIGIN_ICMP6, ICMPV6_ECHO_REQUEST) } else { (SO_EE_ORIGIN_ICMP, ICMP_ECHO) };
    if err.origin != origin || original.len() < 8 || original[0] != echo {
        return None;
    }
    Some(IcmpError {
        seq: u16::from_be_bytes([original[6], original[7]]),
        unreachable: is_unreachable(v6, err.icmp_type, err.icmp_code),
    })
}

pub fn ping_display_ms(triptime_us: u64) -> f64 {
    // INFO: fc 17oct26 iputils prints RTT to three significant digits and Python parsed that text; kept so figures match
    if triptime_us >= 100_000 - 50 {
        ((triptime_us + 500) / 1000) as f64
    } else if triptime_us >= 10_000 - 5 {
        ((triptime_us + 50) / 100) as f64 / 10.0
    } else if triptime_us >= 1000 {
        ((triptime_us + 5) / 10) as f64 / 100.0
    } else {
        triptime_us as f64 / 1000.0
    }
}

pub fn cmsgs(control: &[u8]) -> Vec<Cmsg<'_>> {
    let align = |n: usize| (n + size_of::<usize>() - 1) & !(size_of::<usize>() - 1);
    let head = align(size_of::<libc::cmsghdr>());
    let mut out = Vec::new();
    let mut off = 0;
    while off + head <= control.len() {
        // SAFETY: at least size_of::<cmsghdr>() bytes remain at off; read_unaligned tolerates any alignment.
        let hdr: libc::cmsghdr = unsafe { std::ptr::read_unaligned(control[off..].as_ptr().cast()) };
        let len = hdr.cmsg_len as usize;
        if len < head || off + len > control.len() {
            break;
        }
        out.push(Cmsg { level: hdr.cmsg_level, kind: hdr.cmsg_type, data: &control[off + head..off + len] });
        off += align(len);
    }
    out
}

pub fn rx_wall_ns(cmsgs: &[Cmsg]) -> Option<i128> {
    let c = cmsgs.iter().find(|c| c.level == libc::SOL_SOCKET && c.kind == SO_TIMESTAMPNS)?;
    if c.data.len() < 16 {
        return None;
    }
    let sec = i64::from_ne_bytes(c.data[0..8].try_into().ok()?);
    let nsec = i64::from_ne_bytes(c.data[8..16].try_into().ok()?);
    Some(sec as i128 * 1_000_000_000 + nsec as i128)
}

pub fn extended_err(cmsgs: &[Cmsg], v6: bool) -> Option<ExtendedErr> {
    let (level, kind) =
        if v6 { (libc::IPPROTO_IPV6, libc::IPV6_RECVERR) } else { (libc::IPPROTO_IP, libc::IP_RECVERR) };
    let c = cmsgs.iter().find(|c| c.level == level && c.kind == kind)?;
    if c.data.len() < 8 {
        return None;
    }
    Some(ExtendedErr { origin: c.data[4], icmp_type: c.data[5], icmp_code: c.data[6] })
}

pub fn resolve_target(target: &str) -> io::Result<SocketAddr> {
    (target, 0)
        .to_socket_addrs()?
        .next()
        .ok_or_else(|| io::Error::new(io::ErrorKind::NotFound, format!("{target} did not resolve")))
}

pub fn check_route(dest: SocketAddr) -> io::Result<()> {
    let local: SocketAddr = if dest.is_ipv6() {
        (std::net::Ipv6Addr::UNSPECIFIED, 0).into()
    } else {
        (std::net::Ipv4Addr::UNSPECIFIED, 0).into()
    };
    let mut probe = dest;
    probe.set_port(ROUTE_PROBE_PORT);
    UdpSocket::bind(local)?.connect(probe)
}

fn sockaddr_of(addr: &SocketAddr) -> (libc::sockaddr_storage, libc::socklen_t) {
    // SAFETY: sockaddr_storage is plain old data; all-zero is a valid value.
    let mut storage: libc::sockaddr_storage = unsafe { std::mem::zeroed() };
    let len = match addr {
        SocketAddr::V4(a) => {
            let sin = libc::sockaddr_in {
                sin_family: libc::AF_INET as libc::sa_family_t,
                sin_port: 0,
                sin_addr: libc::in_addr { s_addr: u32::from_ne_bytes(a.ip().octets()) },
                sin_zero: [0; 8],
            };
            // SAFETY: sockaddr_storage is larger than and suitably aligned for sockaddr_in.
            unsafe { std::ptr::write((&mut storage as *mut libc::sockaddr_storage).cast(), sin) };
            size_of::<libc::sockaddr_in>()
        }
        SocketAddr::V6(a) => {
            let sin6 = libc::sockaddr_in6 {
                sin6_family: libc::AF_INET6 as libc::sa_family_t,
                sin6_port: 0,
                sin6_flowinfo: a.flowinfo(),
                sin6_addr: libc::in6_addr { s6_addr: a.ip().octets() },
                sin6_scope_id: a.scope_id(),
            };
            // SAFETY: sockaddr_storage is larger than and suitably aligned for sockaddr_in6.
            unsafe { std::ptr::write((&mut storage as *mut libc::sockaddr_storage).cast(), sin6) };
            size_of::<libc::sockaddr_in6>()
        }
    };
    (storage, len as libc::socklen_t)
}

fn setsockopt_on(fd: &OwnedFd, level: libc::c_int, name: libc::c_int) -> io::Result<()> {
    let one: libc::c_int = 1;
    // SAFETY: passes a live c_int and its exact size.
    let rc = unsafe {
        libc::setsockopt(
            fd.as_raw_fd(),
            level,
            name,
            (&one as *const libc::c_int).cast(),
            size_of::<libc::c_int>() as libc::socklen_t,
        )
    };
    if rc < 0 { Err(io::Error::last_os_error()) } else { Ok(()) }
}

pub enum Received {
    Reply(EchoReply, Option<i128>),
    Error(IcmpError),
    Other,
}

pub struct IcmpSocket {
    fd: OwnedFd,
    dest: SocketAddr,
    pub v6: bool,
}

impl IcmpSocket {
    pub fn open(dest: SocketAddr) -> io::Result<Self> {
        let v6 = dest.is_ipv6();
        let (domain, proto) =
            if v6 { (libc::AF_INET6, libc::IPPROTO_ICMPV6) } else { (libc::AF_INET, libc::IPPROTO_ICMP) };
        // SAFETY: socket takes no pointers; a non-negative return is a fresh fd we own.
        let raw = unsafe { libc::socket(domain, libc::SOCK_DGRAM | libc::SOCK_NONBLOCK | libc::SOCK_CLOEXEC, proto) };
        if raw < 0 {
            return Err(io::Error::last_os_error());
        }
        // SAFETY: raw is a valid descriptor we just created and nobody else owns.
        let fd = unsafe { OwnedFd::from_raw_fd(raw) };
        setsockopt_on(&fd, libc::SOL_SOCKET, SO_TIMESTAMPNS)?;
        if v6 {
            setsockopt_on(&fd, libc::IPPROTO_IPV6, libc::IPV6_RECVERR)?;
        } else {
            setsockopt_on(&fd, libc::IPPROTO_IP, libc::IP_RECVERR)?;
        }
        Ok(Self { fd, dest, v6 })
    }

    pub fn raw_fd(&self) -> libc::c_int {
        self.fd.as_raw_fd()
    }

    pub fn send(&self, seq: u16, sent_ns: u64) -> io::Result<()> {
        let pkt = echo_request(seq, sent_ns, self.v6);
        let (addr, len) = sockaddr_of(&self.dest);
        // SAFETY: pkt and addr are live for the call and their lengths are exact.
        let rc = unsafe {
            libc::sendto(
                self.fd.as_raw_fd(),
                pkt.as_ptr().cast(),
                pkt.len(),
                0,
                (&addr as *const libc::sockaddr_storage).cast(),
                len,
            )
        };
        if rc < 0 { Err(io::Error::last_os_error()) } else { Ok(()) }
    }

    pub fn recv(&self, errqueue: bool) -> io::Result<Option<Received>> {
        let mut data = [0u8; 1500];
        let mut control = [0u64; 64];
        let mut iov = libc::iovec { iov_base: data.as_mut_ptr().cast(), iov_len: data.len() };
        // SAFETY: msghdr is plain old data; all-zero is a valid value.
        let mut msg: libc::msghdr = unsafe { std::mem::zeroed() };
        msg.msg_iov = &mut iov;
        msg.msg_iovlen = 1;
        msg.msg_control = control.as_mut_ptr().cast();
        msg.msg_controllen = size_of::<[u64; 64]>() as _;
        let flags = if errqueue { libc::MSG_ERRQUEUE } else { 0 } | libc::MSG_DONTWAIT;
        // SAFETY: msg points at live buffers (data, control, iov) that outlive the call.
        let n = unsafe { libc::recvmsg(self.fd.as_raw_fd(), &mut msg, flags) };
        if n < 0 {
            let err = io::Error::last_os_error();
            if err.kind() == io::ErrorKind::WouldBlock {
                return Ok(None);
            }
            return Err(err);
        }
        let control_len = (msg.msg_controllen as usize).min(size_of::<[u64; 64]>());
        // SAFETY: control is a live [u64; 64]; viewing its first control_len bytes as u8 is valid.
        let control_bytes = unsafe { std::slice::from_raw_parts(control.as_ptr().cast::<u8>(), control_len) };
        let cm = cmsgs(control_bytes);
        let payload = &data[..n as usize];
        if errqueue {
            let err = extended_err(&cm, self.v6);
            return Ok(Some(match err.and_then(|e| decode_error(e, payload, self.v6)) {
                Some(e) => Received::Error(e),
                None => Received::Other,
            }));
        }
        Ok(Some(match decode_echo_reply(payload, self.v6) {
            Some(r) => Received::Reply(r, rx_wall_ns(&cm)),
            None => Received::Other,
        }))
    }

    pub fn clear_pending_error(&self) {
        let mut err: libc::c_int = 0;
        let mut len = size_of::<libc::c_int>() as libc::socklen_t;
        // SAFETY: err and len are live out-pointers of the right sizes.
        unsafe {
            libc::getsockopt(
                self.fd.as_raw_fd(),
                libc::SOL_SOCKET,
                libc::SO_ERROR,
                (&mut err as *mut libc::c_int).cast(),
                &mut len,
            )
        };
    }
}

pub fn rtt_us(sent_ns: u64, boot_now: i128, wall_now: i128, rx_wall: Option<i128>) -> u64 {
    let since_sent = (boot_now - sent_ns as i128).max(0);
    let queued = rx_wall.map_or(0, |rx| wall_now - rx);
    let queued = if (0..=since_sent).contains(&queued) { queued } else { 0 };
    ((since_sent - queued) / 1000) as u64
}
