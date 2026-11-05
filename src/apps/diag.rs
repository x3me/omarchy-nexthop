use std::io;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};

use crate::net::netlink::{NLMSG_DONE, NLMSG_ERROR, NLMSG_HDRLEN, align4};
use crate::util::monotonic;

const NETLINK_SOCK_DIAG: libc::c_int = 4;
pub const TCPDIAG_GETSOCK: u16 = 18;
pub const INET_DIAG_INFO: u16 = 2;
pub const DIAG_MSG_LEN: usize = 72;
pub const REQ_LEGACY_LEN: usize = 60;
const TCP_INFO_LEN: usize = 216;
const RECV_BUF: usize = 64 * 1024;

const TCP_SYN_RECV: u32 = 3;
const TCP_TIME_WAIT: u32 = 6;
const TCP_CLOSE: u32 = 7;
const TCP_LISTEN: u32 = 10;
const SS_MAX: u32 = 14;
const TCP_BOUND_INACTIVE: u32 = 13;
// INFO: fc 17oct26 ss -t defaults minus bound-inactive, whose kernel walk locks every bind-hash bucket for sockets without traffic
pub const SS_CONN_STATES: u32 = ((1 << SS_MAX) - 1)
    & !((1 << TCP_LISTEN) | (1 << TCP_CLOSE) | (1 << TCP_TIME_WAIT) | (1 << TCP_SYN_RECV) | (1 << TCP_BOUND_INACTIVE));

#[derive(Clone, Copy, Debug, Default, PartialEq)]
pub struct TcpInfo {
    pub rtt_us: u32,
    pub min_rtt_us: u32,
    pub bytes_sent: u64,
    pub bytes_received: u64,
    pub bytes_retrans: u64,
}

#[derive(Clone, Debug, PartialEq)]
pub struct DiagSock {
    pub local: SocketAddr,
    pub peer: SocketAddr,
    pub ifindex: u32,
    pub inode: u32,
    pub info: Option<TcpInfo>,
}

fn u16_ne(b: &[u8], at: usize) -> u16 {
    u16::from_ne_bytes([b[at], b[at + 1]])
}

fn u32_ne(b: &[u8], at: usize) -> u32 {
    u32::from_ne_bytes(b[at..at + 4].try_into().unwrap())
}

fn u64_ne(b: &[u8], at: usize) -> u64 {
    u64::from_ne_bytes(b[at..at + 8].try_into().unwrap())
}

fn invalid(msg: &str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, msg.to_string())
}

// INFO: fc 17oct26 the legacy request dumps both address families in one walk of the established hash, v2 needs one walk each
pub fn build_request(seq: u32) -> Vec<u8> {
    let len = NLMSG_HDRLEN + REQ_LEGACY_LEN;
    let mut b = Vec::with_capacity(len);
    b.extend_from_slice(&(len as u32).to_ne_bytes());
    b.extend_from_slice(&TCPDIAG_GETSOCK.to_ne_bytes());
    b.extend_from_slice(&((libc::NLM_F_REQUEST | libc::NLM_F_DUMP) as u16).to_ne_bytes());
    b.extend_from_slice(&seq.to_ne_bytes());
    b.extend_from_slice(&0u32.to_ne_bytes());
    b.extend_from_slice(&[0, 0, 0, 1 << (INET_DIAG_INFO - 1)]);
    b.resize(NLMSG_HDRLEN + 52, 0);
    b.extend_from_slice(&SS_CONN_STATES.to_ne_bytes());
    b.resize(len, 0);
    b
}

pub fn in_ss_order(socks: &mut [DiagSock]) {
    socks.sort_by_key(|s| s.local.is_ipv6());
}

pub fn parse_tcp_info(raw: &[u8]) -> TcpInfo {
    let mut b = [0u8; TCP_INFO_LEN];
    let n = raw.len().min(TCP_INFO_LEN);
    b[..n].copy_from_slice(&raw[..n]);
    TcpInfo {
        rtt_us: u32_ne(&b, 68),
        min_rtt_us: u32_ne(&b, 148),
        bytes_received: u64_ne(&b, 128),
        bytes_sent: u64_ne(&b, 200),
        bytes_retrans: u64_ne(&b, 208),
    }
}

fn addr(family: u8, raw: &[u8], port: u16) -> io::Result<SocketAddr> {
    let ip = match family as i32 {
        libc::AF_INET => IpAddr::V4(Ipv4Addr::new(raw[0], raw[1], raw[2], raw[3])),
        libc::AF_INET6 => IpAddr::V6(Ipv6Addr::from(<[u8; 16]>::try_from(raw).unwrap())),
        other => return Err(invalid(&format!("inet_diag_msg with family {other}"))),
    };
    Ok(SocketAddr::new(ip, port))
}

pub fn parse_diag_msg(p: &[u8]) -> io::Result<DiagSock> {
    if p.len() < DIAG_MSG_LEN {
        return Err(invalid("short inet_diag_msg"));
    }
    let family = p[0];
    let sport = u16::from_be_bytes([p[4], p[5]]);
    let dport = u16::from_be_bytes([p[6], p[7]]);
    let mut info = None;
    let mut at = DIAG_MSG_LEN;
    while at + 4 <= p.len() {
        let rta_len = u16_ne(p, at) as usize;
        let rta_type = u16_ne(p, at + 2);
        if rta_len < 4 || at + rta_len > p.len() {
            return Err(invalid("malformed inet_diag attribute"));
        }
        if rta_type == INET_DIAG_INFO {
            info = Some(parse_tcp_info(&p[at + 4..at + rta_len]));
        }
        at += align4(rta_len);
    }
    Ok(DiagSock {
        local: addr(family, &p[8..24], sport)?,
        peer: addr(family, &p[24..40], dport)?,
        ifindex: u32_ne(p, 40),
        inode: u32_ne(p, 68),
        info,
    })
}

pub fn parse_batch(buf: &[u8], seq: u32, out: &mut Vec<DiagSock>) -> io::Result<bool> {
    let mut at = 0;
    while at + NLMSG_HDRLEN <= buf.len() {
        let len = u32_ne(buf, at) as usize;
        let kind = u16_ne(buf, at + 4);
        let msg_seq = u32_ne(buf, at + 8);
        if len < NLMSG_HDRLEN || at + len > buf.len() {
            return Err(invalid("malformed netlink message"));
        }
        let payload = &buf[at + NLMSG_HDRLEN..at + len];
        at += align4(len);
        if msg_seq != seq {
            continue;
        }
        match kind {
            NLMSG_DONE => return Ok(true),
            NLMSG_ERROR => {
                let errno = if payload.len() >= 4 { -(u32_ne(payload, 0) as i32) } else { 0 };
                if errno == 0 {
                    continue;
                }
                return Err(io::Error::from_raw_os_error(errno));
            }
            TCPDIAG_GETSOCK => out.push(parse_diag_msg(payload)?),
            _ => {}
        }
    }
    Ok(false)
}

fn open_socket() -> io::Result<OwnedFd> {
    // SAFETY: plain socket(2) call; the result is checked before use.
    let fd = unsafe { libc::socket(libc::AF_NETLINK, libc::SOCK_DGRAM | libc::SOCK_CLOEXEC, NETLINK_SOCK_DIAG) };
    if fd < 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: fd is a freshly created descriptor we own.
    Ok(unsafe { OwnedFd::from_raw_fd(fd) })
}

fn set_recv_timeout(sock: &OwnedFd, timeout_s: f64) -> io::Result<()> {
    let us = ((timeout_s * 1e6).ceil() as i64).max(1);
    let tv = libc::timeval { tv_sec: (us / 1_000_000) as libc::time_t, tv_usec: (us % 1_000_000) as libc::suseconds_t };
    // SAFETY: tv outlives the call and its size is passed.
    let rc = unsafe {
        libc::setsockopt(
            sock.as_raw_fd(),
            libc::SOL_SOCKET,
            libc::SO_RCVTIMEO,
            (&tv as *const libc::timeval).cast(),
            size_of::<libc::timeval>() as libc::socklen_t,
        )
    };
    if rc < 0 { Err(io::Error::last_os_error()) } else { Ok(()) }
}

fn send_request(sock: &OwnedFd, req: &[u8]) -> io::Result<()> {
    // SAFETY: sockaddr_nl is plain data; zeroed is a valid value.
    let mut kernel: libc::sockaddr_nl = unsafe { std::mem::zeroed() };
    kernel.nl_family = libc::AF_NETLINK as libc::sa_family_t;
    // SAFETY: req and kernel are valid for the lengths passed.
    let rc = unsafe {
        libc::sendto(
            sock.as_raw_fd(),
            req.as_ptr().cast(),
            req.len(),
            0,
            (&kernel as *const libc::sockaddr_nl).cast(),
            size_of::<libc::sockaddr_nl>() as libc::socklen_t,
        )
    };
    if rc < 0 { Err(io::Error::last_os_error()) } else { Ok(()) }
}

fn timed_out() -> io::Error {
    io::Error::new(io::ErrorKind::TimedOut, "sock_diag dump timed out")
}

pub fn recv_before(sock: &OwnedFd, buf: &mut [u8], deadline: f64, clock: impl Fn() -> f64) -> io::Result<usize> {
    loop {
        let remaining = deadline - clock();
        if remaining <= 0.0 {
            return Err(timed_out());
        }
        set_recv_timeout(sock, remaining)?;
        // SAFETY: buf is valid for writes of buf.len() bytes.
        let n = unsafe { libc::recv(sock.as_raw_fd(), buf.as_mut_ptr().cast(), buf.len(), libc::MSG_TRUNC) };
        if n >= 0 {
            let n = n as usize;
            if n > buf.len() {
                return Err(invalid("netlink datagram larger than the receive buffer"));
            }
            return Ok(n);
        }
        let err = io::Error::last_os_error();
        match err.kind() {
            io::ErrorKind::Interrupted => continue,
            io::ErrorKind::WouldBlock => return Err(timed_out()),
            _ => return Err(err),
        }
    }
}

pub fn dump(max_bytes: usize, deadline: f64) -> io::Result<Vec<DiagSock>> {
    let sock = open_socket()?;
    let mut buf = vec![0u8; RECV_BUF];
    let mut out = Vec::new();
    let mut total = 0usize;
    send_request(&sock, &build_request(1))?;
    loop {
        let n = recv_before(&sock, &mut buf, deadline, monotonic)?;
        total += n;
        if total > max_bytes || parse_batch(&buf[..n], 1, &mut out)? {
            break;
        }
    }
    in_ss_order(&mut out);
    Ok(out)
}
