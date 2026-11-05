use std::io;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use super::netlink::{AttrWriter, Attrs, NLM_F_DUMP, NlError, NlSocket};

const RTM_NEWROUTE: u16 = 24;
const RTM_GETROUTE: u16 = 26;
const RTM_F_CLONED: u32 = 0x200;
const RT_TABLE_MAIN: u32 = 254;
const RTA_DST: u16 = 1;
const RTA_OIF: u16 = 4;
const RTA_GATEWAY: u16 = 5;
const RTA_PRIORITY: u16 = 6;
const RTA_PREFSRC: u16 = 7;
const RTA_TABLE: u16 = 15;
const RTMSG_LEN: usize = 12;
const SIOCGIFNAME: libc::c_ulong = 0x8910;
const SIOCGIFINDEX: libc::c_ulong = 0x8933;
const ONE_REPLY: usize = 64 * 1024;

#[derive(Clone, Debug, Default, PartialEq)]
pub struct RouteRow {
    pub dst: String,
    pub gateway: String,
    pub dev: String,
    pub prefsrc: String,
    pub metric: u64,
}

#[derive(Clone, Debug, Default, PartialEq)]
pub struct RouteGet {
    pub dev: String,
    pub oif: u32,
    pub gateway: String,
    pub prefsrc: String,
}

pub fn rtmsg(family: u8, dst_len: u8) -> [u8; RTMSG_LEN] {
    let mut h = [0u8; RTMSG_LEN];
    h[0] = family;
    h[1] = dst_len;
    h
}

pub fn parse_destination(text: &str) -> Option<IpAddr> {
    if text.contains(':') {
        return text.parse::<Ipv6Addr>().ok().map(IpAddr::V6);
    }
    iproute2_ipv4(text).map(IpAddr::V4)
}

// INFO: fc 17oct26 iproute2's get_addr_ipv4: strtoul base 0 per part, so "1.1" is 1.1.0.0
fn iproute2_ipv4(text: &str) -> Option<Ipv4Addr> {
    let mut out = [0u8; 4];
    let mut rest = text.as_bytes();
    for (i, slot) in out.iter_mut().enumerate() {
        let (n, used) = strtoul0(rest);
        if n > 255 {
            return None;
        }
        *slot = n as u8;
        rest = &rest[used..];
        if rest.is_empty() {
            break;
        }
        if i == 3 || rest[0] != b'.' {
            return None;
        }
        rest = &rest[1..];
    }
    Some(Ipv4Addr::from(out))
}

fn strtoul0(s: &[u8]) -> (u64, usize) {
    let (radix, start) = if s.len() > 2 && s[0] == b'0' && (s[1] | 0x20) == b'x' && s[2].is_ascii_hexdigit() {
        (16, 2)
    } else if s.first() == Some(&b'0') {
        (8, 0)
    } else {
        (10, 0)
    };
    let mut n: u64 = 0;
    let mut i = start;
    while let Some(d) = s.get(i).and_then(|&c| (c as char).to_digit(radix)) {
        n = n.saturating_mul(radix as u64).saturating_add(d as u64);
        i += 1;
    }
    (n, i)
}

pub fn format_addr(family: u8, data: &[u8]) -> Option<String> {
    match (family as i32, data.len()) {
        (libc::AF_INET, 4) => Some(Ipv4Addr::from(<[u8; 4]>::try_from(data).ok()?).to_string()),
        (libc::AF_INET6, 16) => Some(Ipv6Addr::from(<[u8; 16]>::try_from(data).ok()?).to_string()),
        _ => None,
    }
}

pub fn decode_route_get(body: &[u8]) -> Option<(u32, RouteGet)> {
    let family = *body.first()?;
    let attrs = Attrs::new(body.get(RTMSG_LEN..)?);
    let mut out = RouteGet::default();
    for a in &attrs {
        match a.kind {
            RTA_OIF => out.oif = a.u32().unwrap_or(0),
            RTA_GATEWAY => out.gateway = format_addr(family, a.data).unwrap_or_default(),
            RTA_PREFSRC => out.prefsrc = format_addr(family, a.data).unwrap_or_default(),
            _ => {}
        }
    }
    Some((out.oif, out))
}

pub fn decode_main_route(body: &[u8]) -> Option<(RouteRow, u32)> {
    if body.len() < RTMSG_LEN {
        return None;
    }
    let family = body[0];
    let dst_len = body[1];
    let mut table = body[4] as u32;
    let flags = u32::from_ne_bytes(body[8..12].try_into().ok()?);
    let attrs = Attrs::new(&body[RTMSG_LEN..]);
    let mut row = RouteRow::default();
    let mut dst = None;
    let mut oif = 0;
    for a in &attrs {
        match a.kind {
            RTA_DST => dst = format_addr(family, a.data),
            RTA_OIF => oif = a.u32().unwrap_or(0),
            RTA_GATEWAY => row.gateway = format_addr(family, a.data).unwrap_or_default(),
            RTA_PREFSRC => row.prefsrc = format_addr(family, a.data).unwrap_or_default(),
            RTA_PRIORITY => row.metric = a.u32().unwrap_or(0) as u64,
            RTA_TABLE => table = a.u32().unwrap_or(table),
            _ => {}
        }
    }
    if table != RT_TABLE_MAIN || flags & RTM_F_CLONED != 0 {
        return None;
    }
    row.dst = match dst {
        Some(d) if dst_len == 32 => d,
        Some(d) => format!("{d}/{dst_len}"),
        None if dst_len != 0 => format!("0/{dst_len}"),
        None => "default".into(),
    };
    Some((row, oif))
}

#[repr(C)]
struct IfReq {
    name: [u8; libc::IFNAMSIZ],
    index: libc::c_int,
    _pad: [u8; 20],
}

pub struct Rtnl {
    sock: NlSocket,
}

impl Rtnl {
    pub fn open() -> io::Result<Self> {
        Ok(Rtnl { sock: NlSocket::open(libc::NETLINK_ROUTE)? })
    }

    pub fn route_get(&mut self, addr: IpAddr) -> Result<RouteGet, NlError> {
        let (family, bytes, len): (u8, Vec<u8>, u8) = match addr {
            IpAddr::V4(a) => (libc::AF_INET as u8, a.octets().to_vec(), 32),
            IpAddr::V6(a) => (libc::AF_INET6 as u8, a.octets().to_vec(), 128),
        };
        let mut w = AttrWriter::with_header(&rtmsg(family, len));
        w.put(RTA_DST, &bytes);
        let mut found = None;
        self.sock.request(RTM_GETROUTE, 0, &w.buf, ONE_REPLY, |t, body| {
            if t == RTM_NEWROUTE {
                found = decode_route_get(body).map(|(_, r)| r);
            }
        })?;
        let mut route = found.ok_or(NlError::Malformed)?;
        if route.oif != 0 {
            route.dev = self.ifname(route.oif);
        }
        Ok(route)
    }

    pub fn main_table(&mut self, max_bytes: usize) -> Result<Vec<RouteRow>, NlError> {
        let header = rtmsg(libc::AF_INET as u8, 0);
        let mut rows = Vec::new();
        self.sock.request(RTM_GETROUTE, NLM_F_DUMP, &header, max_bytes, |t, body| {
            if t == RTM_NEWROUTE
                && let Some(r) = decode_main_route(body)
            {
                rows.push(r);
            }
        })?;
        Ok(rows
            .into_iter()
            .map(|(mut row, oif)| {
                if oif != 0 {
                    row.dev = self.ifname(oif);
                }
                row
            })
            .collect())
    }

    pub fn ifname(&self, index: u32) -> String {
        let mut req = IfReq { name: [0; libc::IFNAMSIZ], index: index as libc::c_int, _pad: [0; 20] };
        // SAFETY: req is a valid ifreq-sized buffer that SIOCGIFNAME fills in.
        let rc = unsafe { libc::ioctl(self.sock.raw_fd(), SIOCGIFNAME, &mut req as *mut IfReq) };
        if rc < 0 {
            return format!("if{index}");
        }
        let end = req.name.iter().position(|&b| b == 0).unwrap_or(req.name.len());
        String::from_utf8_lossy(&req.name[..end]).into_owned()
    }

    pub fn ifindex(&self, name: &str) -> Option<u32> {
        let bytes = name.as_bytes();
        if bytes.is_empty() || bytes.len() >= libc::IFNAMSIZ || bytes.contains(&0) {
            return None;
        }
        let mut req = IfReq { name: [0; libc::IFNAMSIZ], index: 0, _pad: [0; 20] };
        req.name[..bytes.len()].copy_from_slice(bytes);
        // SAFETY: req is a valid ifreq-sized buffer that SIOCGIFINDEX fills in.
        let rc = unsafe { libc::ioctl(self.sock.raw_fd(), SIOCGIFINDEX, &mut req as *mut IfReq) };
        if rc < 0 || req.index <= 0 { None } else { Some(req.index as u32) }
    }
}
