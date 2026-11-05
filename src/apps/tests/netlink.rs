use super::super::diag::*;
use crate::net::netlink::{NLMSG_DONE, NLMSG_ERROR, NLMSG_HDRLEN};
use std::net::SocketAddr;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};

fn nlmsg(kind: u16, seq: u32, payload: &[u8]) -> Vec<u8> {
    let len = NLMSG_HDRLEN + payload.len();
    let mut b = Vec::new();
    b.extend_from_slice(&(len as u32).to_ne_bytes());
    b.extend_from_slice(&kind.to_ne_bytes());
    b.extend_from_slice(&2u16.to_ne_bytes());
    b.extend_from_slice(&seq.to_ne_bytes());
    b.extend_from_slice(&0u32.to_ne_bytes());
    b.extend_from_slice(payload);
    b.resize((b.len() + 3) & !3, 0);
    b
}

fn attr(kind: u16, data: &[u8]) -> Vec<u8> {
    let mut b = Vec::new();
    b.extend_from_slice(&((4 + data.len()) as u16).to_ne_bytes());
    b.extend_from_slice(&kind.to_ne_bytes());
    b.extend_from_slice(data);
    b.resize((b.len() + 3) & !3, 0);
    b
}

fn put_u32(b: &mut [u8], at: usize, v: u32) {
    b[at..at + 4].copy_from_slice(&v.to_ne_bytes());
}

fn put_u64(b: &mut [u8], at: usize, v: u64) {
    b[at..at + 8].copy_from_slice(&v.to_ne_bytes());
}

fn tcp_info(len: usize) -> Vec<u8> {
    let mut b = vec![0u8; 280];
    put_u32(&mut b, 68, 15_023);
    put_u32(&mut b, 72, 1_326);
    put_u64(&mut b, 120, 7_107);
    put_u64(&mut b, 128, 9_792);
    put_u32(&mut b, 148, 12_941);
    put_u64(&mut b, 200, 7_106);
    put_u64(&mut b, 208, 108);
    b.truncate(len);
    b
}

fn diag_msg(family: u8, src: &[u8], dst: &[u8], inode: u32, attrs: &[Vec<u8>]) -> Vec<u8> {
    let mut b = vec![0u8; DIAG_MSG_LEN];
    b[0] = family;
    b[1] = 1;
    b[4..6].copy_from_slice(&37952u16.to_be_bytes());
    b[6..8].copy_from_slice(&443u16.to_be_bytes());
    b[8..8 + src.len()].copy_from_slice(src);
    b[24..24 + dst.len()].copy_from_slice(dst);
    put_u32(&mut b, 40, 3);
    put_u32(&mut b, 68, inode);
    for a in attrs {
        b.extend_from_slice(a);
    }
    b
}

#[test]
fn request_is_one_legacy_tcp_dump_asking_for_tcp_info() {
    let req = build_request(7);
    assert_eq!(req.len(), 76);
    assert_eq!(u32::from_ne_bytes(req[0..4].try_into().unwrap()), 76);
    assert_eq!(u16::from_ne_bytes([req[4], req[5]]), TCPDIAG_GETSOCK);
    assert_eq!(u16::from_ne_bytes([req[6], req[7]]), 0x301);
    assert_eq!(u32::from_ne_bytes(req[8..12].try_into().unwrap()), 7);
    assert_eq!(&req[16..20], &[0, 0, 0, 0b10]);
    assert!(req[20..68].iter().all(|&b| b == 0));
    assert_eq!(u32::from_ne_bytes(req[68..72].try_into().unwrap()), SS_CONN_STATES);
    assert!(req[72..].iter().all(|&b| b == 0));
}

#[test]
fn states_are_ss_defaults_without_listen_close_timewait_synrecv_or_bound_inactive() {
    let has = |s: u32| SS_CONN_STATES & (1 << s) != 0;
    for s in [1, 2, 4, 5, 8, 9, 11, 12] {
        assert!(has(s), "state {s}");
    }
    for s in [3, 6, 7, 10, 13, 14] {
        assert!(!has(s), "state {s}");
    }
}

fn sample_v4() -> DiagSock {
    parse_diag_msg(&diag_msg(2, &[127, 0, 0, 1], &[127, 0, 0, 1], 1, &[])).unwrap()
}

fn sample_v6() -> DiagSock {
    parse_diag_msg(&diag_msg(10, &[0; 16], &[0; 16], 2, &[])).unwrap()
}

#[test]
fn ipv4_sockets_come_before_ipv6_like_ss() {
    let v6 = sample_v6();
    let v4 = sample_v4();
    let mut socks = vec![v6.clone(), v4.clone()];
    in_ss_order(&mut socks);
    assert_eq!(socks, [v4, v6]);
}

#[test]
fn decodes_ipv4_diag_message_with_tcp_info() {
    let p = diag_msg(2, &[192, 168, 0, 41], &[185, 199, 110, 133], 4242, &[attr(INET_DIAG_INFO, &tcp_info(280))]);
    let s = parse_diag_msg(&p).unwrap();
    assert_eq!(s.local, "192.168.0.41:37952".parse::<SocketAddr>().unwrap());
    assert_eq!(s.peer, "185.199.110.133:443".parse::<SocketAddr>().unwrap());
    assert_eq!(s.ifindex, 3);
    assert_eq!(s.inode, 4242);
    let info = s.info.unwrap();
    assert_eq!(info.rtt_us, 15_023);
    assert_eq!(info.min_rtt_us, 12_941);
    assert_eq!(info.bytes_sent, 7_106);
    assert_eq!(info.bytes_received, 9_792);
    assert_eq!(info.bytes_retrans, 108);
}

#[test]
fn decodes_ipv6_and_skips_other_attributes() {
    let src: Vec<u8> = "2001:db8::1".parse::<std::net::Ipv6Addr>().unwrap().octets().to_vec();
    let dst: Vec<u8> = "::ffff:1.2.3.4".parse::<std::net::Ipv6Addr>().unwrap().octets().to_vec();
    let attrs = [attr(4, b"cubic"), attr(INET_DIAG_INFO, &tcp_info(280)), attr(1, &[0; 16])];
    let s = parse_diag_msg(&diag_msg(10, &src, &dst, 9, &attrs)).unwrap();
    assert_eq!(s.local.to_string(), "[2001:db8::1]:37952");
    assert_eq!(s.peer.to_string(), "[::ffff:1.2.3.4]:443");
    assert_eq!(s.info.unwrap().bytes_received, 9_792);
}

#[test]
fn message_without_tcp_info_has_none() {
    let s = parse_diag_msg(&diag_msg(2, &[127, 0, 0, 1], &[127, 0, 0, 1], 1, &[])).unwrap();
    assert_eq!(s.info, None);
}

#[test]
fn short_tcp_info_from_an_older_kernel_reads_zero_for_missing_fields() {
    let p = diag_msg(2, &[10, 0, 0, 1], &[10, 0, 0, 2], 5, &[attr(INET_DIAG_INFO, &tcp_info(192))]);
    let info = parse_diag_msg(&p).unwrap().info.unwrap();
    assert_eq!(info.rtt_us, 15_023);
    assert_eq!(info.bytes_received, 9_792);
    assert_eq!(info.bytes_sent, 0);
    assert_eq!(info.bytes_retrans, 0);
}

#[test]
fn malformed_messages_are_errors() {
    assert!(parse_diag_msg(&[0u8; 40]).is_err());
    let mut p = diag_msg(2, &[10, 0, 0, 1], &[10, 0, 0, 2], 5, &[]);
    p.extend_from_slice(&[200, 0, 2, 0]);
    assert!(parse_diag_msg(&p).is_err());
    assert!(parse_diag_msg(&diag_msg(1, &[], &[], 5, &[])).is_err());
}

#[test]
fn batch_collects_sockets_until_done_and_ignores_other_sequences() {
    let one = diag_msg(2, &[10, 0, 0, 1], &[10, 0, 0, 2], 11, &[attr(INET_DIAG_INFO, &tcp_info(280))]);
    let two = diag_msg(2, &[10, 0, 0, 1], &[10, 0, 0, 3], 12, &[]);
    let mut buf = nlmsg(TCPDIAG_GETSOCK, 5, &one);
    buf.extend(nlmsg(TCPDIAG_GETSOCK, 4, &two));
    buf.extend(nlmsg(TCPDIAG_GETSOCK, 5, &two));
    let mut out = Vec::new();
    assert!(!parse_batch(&buf, 5, &mut out).unwrap());
    assert_eq!(out.iter().map(|s| s.inode).collect::<Vec<_>>(), [11, 12]);
    let done = nlmsg(NLMSG_DONE, 5, &0i32.to_ne_bytes());
    assert!(parse_batch(&done, 5, &mut out).unwrap());
    assert_eq!(out.len(), 2);
}

#[test]
fn batch_surfaces_kernel_errors() {
    let mut payload = (-libc::EACCES).to_ne_bytes().to_vec();
    payload.extend_from_slice(&[0u8; 16]);
    let err = parse_batch(&nlmsg(NLMSG_ERROR, 1, &payload), 1, &mut Vec::new()).unwrap_err();
    assert_eq!(err.raw_os_error(), Some(libc::EACCES));
}

#[test]
fn batch_rejects_a_truncated_message() {
    let mut buf = nlmsg(TCPDIAG_GETSOCK, 1, &diag_msg(2, &[1, 1, 1, 1], &[2, 2, 2, 2], 1, &[]));
    buf.truncate(60);
    assert!(parse_batch(&buf, 1, &mut Vec::new()).is_err());
}

fn dgram_pair() -> (OwnedFd, OwnedFd) {
    let mut fds = [0; 2];
    // SAFETY: fds is a valid two-element array for socketpair to fill.
    let rc = unsafe { libc::socketpair(libc::AF_UNIX, libc::SOCK_DGRAM | libc::SOCK_CLOEXEC, 0, fds.as_mut_ptr()) };
    assert_eq!(rc, 0, "{}", std::io::Error::last_os_error());
    // SAFETY: both descriptors were just created and are owned here.
    unsafe { (OwnedFd::from_raw_fd(fds[0]), OwnedFd::from_raw_fd(fds[1])) }
}

fn send(fd: &OwnedFd, data: &[u8]) {
    // SAFETY: data is valid for reads of data.len() bytes.
    let n = unsafe { libc::send(fd.as_raw_fd(), data.as_ptr().cast(), data.len(), 0) };
    assert_eq!(n, data.len() as isize);
}

fn recv_timeout_s(fd: &OwnedFd) -> f64 {
    let mut tv = libc::timeval { tv_sec: 0, tv_usec: 0 };
    let mut len = size_of::<libc::timeval>() as libc::socklen_t;
    // SAFETY: tv and len are valid for writes and len holds the size of tv.
    let rc = unsafe {
        libc::getsockopt(
            fd.as_raw_fd(),
            libc::SOL_SOCKET,
            libc::SO_RCVTIMEO,
            (&mut tv as *mut libc::timeval).cast(),
            &mut len,
        )
    };
    assert_eq!(rc, 0);
    tv.tv_sec as f64 + tv.tv_usec as f64 / 1e6
}

#[test]
fn each_receive_waits_only_for_the_remaining_budget() {
    let (ours, kernel) = dgram_pair();
    let mut buf = [0u8; 64];
    send(&kernel, b"first");
    send(&kernel, b"second");
    assert_eq!(recv_before(&ours, &mut buf, 100.5, || 100.0).unwrap(), 5);
    // the kernel stores SO_RCVTIMEO in jiffies, so the read-back value is rounded up to a tick
    assert!((recv_timeout_s(&ours) - 0.5).abs() < 0.011, "{}", recv_timeout_s(&ours));
    assert_eq!(recv_before(&ours, &mut buf, 100.5, || 100.3).unwrap(), 6);
    assert!((recv_timeout_s(&ours) - 0.2).abs() < 0.011, "{}", recv_timeout_s(&ours));
}

#[test]
fn receive_past_the_deadline_times_out_even_with_data_pending() {
    let (ours, kernel) = dgram_pair();
    let mut buf = [0u8; 64];
    send(&kernel, b"late");
    let err = recv_before(&ours, &mut buf, 100.5, || 100.6).unwrap_err();
    assert_eq!(err.kind(), std::io::ErrorKind::TimedOut);
}
