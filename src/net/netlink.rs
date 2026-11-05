use std::io;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd, RawFd};

pub const NLMSG_HDRLEN: usize = 16;
pub const NLMSG_ERROR: u16 = 2;
pub const NLMSG_DONE: u16 = 3;
pub const NLM_F_REQUEST: u16 = 0x1;
pub const NLM_F_DUMP: u16 = 0x300;
const NLA_TYPE_MASK: u16 = !0xC000;
#[cfg(test)]
const NLA_F_NESTED: u16 = 0x8000;
const RECV_BUF: usize = 64 * 1024;
const RECV_TIMEOUT_S: libc::time_t = 2;

pub const fn align4(n: usize) -> usize {
    (n + 3) & !3
}

#[derive(Debug)]
pub enum NlError {
    Kernel(i32),
    Io(io::Error),
    TooLarge,
    Malformed,
}

impl From<io::Error> for NlError {
    fn from(e: io::Error) -> Self {
        NlError::Io(e)
    }
}

impl std::fmt::Display for NlError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            NlError::Kernel(errno) => {
                write!(f, "netlink: {}", io::Error::from_raw_os_error(*errno))
            }
            NlError::Io(e) => write!(f, "netlink: {e}"),
            NlError::TooLarge => write!(f, "netlink: reply over its size cap"),
            NlError::Malformed => write!(f, "netlink: malformed reply"),
        }
    }
}

pub struct NlSocket {
    fd: OwnedFd,
    seq: u32,
    buf: Vec<u8>,
}

impl NlSocket {
    pub fn open(protocol: libc::c_int) -> io::Result<Self> {
        // SAFETY: plain socket(2) call; the result is checked before use.
        let raw = unsafe { libc::socket(libc::AF_NETLINK, libc::SOCK_RAW | libc::SOCK_CLOEXEC, protocol) };
        if raw < 0 {
            return Err(io::Error::last_os_error());
        }
        // SAFETY: raw is a fresh, owned, valid descriptor.
        let fd = unsafe { OwnedFd::from_raw_fd(raw) };
        // SAFETY: sockaddr_nl is plain old data; zeroed is a valid value.
        let mut addr: libc::sockaddr_nl = unsafe { std::mem::zeroed() };
        addr.nl_family = libc::AF_NETLINK as libc::sa_family_t;
        // SAFETY: addr is a valid sockaddr_nl of the size passed.
        let rc = unsafe {
            libc::bind(raw, &addr as *const _ as *const libc::sockaddr, std::mem::size_of::<libc::sockaddr_nl>() as u32)
        };
        if rc < 0 {
            return Err(io::Error::last_os_error());
        }
        let tv = libc::timeval { tv_sec: RECV_TIMEOUT_S, tv_usec: 0 };
        setsockopt(raw, libc::SOL_SOCKET, libc::SO_RCVTIMEO, &tv)?;
        Ok(NlSocket { fd, seq: 0, buf: vec![0; RECV_BUF] })
    }

    pub fn raw_fd(&self) -> RawFd {
        self.fd.as_raw_fd()
    }

    pub fn add_membership(&self, group: u32) -> io::Result<()> {
        setsockopt(self.raw_fd(), libc::SOL_NETLINK, libc::NETLINK_ADD_MEMBERSHIP, &group)
    }

    pub fn request<F>(
        &mut self,
        msg_type: u16,
        flags: u16,
        payload: &[u8],
        max_bytes: usize,
        mut on_msg: F,
    ) -> Result<(), NlError>
    where
        F: FnMut(u16, &[u8]),
    {
        self.seq = self.seq.wrapping_add(1);
        let seq = self.seq;
        let mut msg = Vec::with_capacity(NLMSG_HDRLEN + payload.len());
        msg.extend_from_slice(&((NLMSG_HDRLEN + payload.len()) as u32).to_ne_bytes());
        msg.extend_from_slice(&msg_type.to_ne_bytes());
        msg.extend_from_slice(&(flags | NLM_F_REQUEST).to_ne_bytes());
        msg.extend_from_slice(&seq.to_ne_bytes());
        msg.extend_from_slice(&0u32.to_ne_bytes());
        msg.extend_from_slice(payload);
        // SAFETY: msg is a valid buffer of msg.len() bytes.
        let sent = unsafe { libc::send(self.raw_fd(), msg.as_ptr() as *const libc::c_void, msg.len(), 0) };
        if sent < 0 {
            return Err(io::Error::last_os_error().into());
        }
        let dump = flags & NLM_F_DUMP == NLM_F_DUMP;
        let mut total = 0usize;
        loop {
            let n = self.recv()?;
            total += n;
            if total > max_bytes {
                self.drain(seq);
                return Err(NlError::TooLarge);
            }
            let mut finished = false;
            for (hdr, body) in Messages::new(&self.buf[..n]) {
                if hdr.seq != seq {
                    continue;
                }
                match hdr.msg_type {
                    NLMSG_DONE => finished = true,
                    NLMSG_ERROR => {
                        let errno = body
                            .get(..4)
                            .map(|b| i32::from_ne_bytes([b[0], b[1], b[2], b[3]]))
                            .ok_or(NlError::Malformed)?;
                        if errno != 0 {
                            return Err(NlError::Kernel(-errno));
                        }
                        finished = true;
                    }
                    t => {
                        on_msg(t, body);
                        if !dump {
                            finished = true;
                        }
                    }
                }
            }
            if finished {
                return Ok(());
            }
        }
    }

    pub fn recv(&mut self) -> io::Result<usize> {
        loop {
            // SAFETY: buf is a valid writable buffer of buf.len() bytes.
            let n = unsafe {
                libc::recv(self.raw_fd(), self.buf.as_mut_ptr() as *mut libc::c_void, self.buf.len(), libc::MSG_TRUNC)
            };
            if n < 0 {
                let e = io::Error::last_os_error();
                if e.kind() == io::ErrorKind::Interrupted {
                    continue;
                }
                return Err(e);
            }
            let n = n as usize;
            if n > self.buf.len() {
                return Err(io::Error::new(io::ErrorKind::InvalidData, "netlink message truncated"));
            }
            return Ok(n);
        }
    }

    pub fn received(&self, n: usize) -> &[u8] {
        &self.buf[..n]
    }

    fn drain(&mut self, seq: u32) {
        while let Ok(n) = self.recv() {
            if Messages::new(&self.buf[..n])
                .any(|(h, _)| h.seq == seq && matches!(h.msg_type, NLMSG_DONE | NLMSG_ERROR))
            {
                return;
            }
        }
    }
}

fn setsockopt<T>(fd: RawFd, level: libc::c_int, name: libc::c_int, value: &T) -> io::Result<()> {
    // SAFETY: value points to a live T of the size passed.
    let rc = unsafe {
        libc::setsockopt(fd, level, name, value as *const T as *const libc::c_void, std::mem::size_of::<T>() as u32)
    };
    if rc < 0 { Err(io::Error::last_os_error()) } else { Ok(()) }
}

pub struct MsgHeader {
    pub msg_type: u16,
    pub seq: u32,
}

pub struct Messages<'a> {
    data: &'a [u8],
}

impl<'a> Messages<'a> {
    pub fn new(data: &'a [u8]) -> Self {
        Messages { data }
    }
}

impl<'a> Iterator for Messages<'a> {
    type Item = (MsgHeader, &'a [u8]);

    fn next(&mut self) -> Option<Self::Item> {
        if self.data.len() < NLMSG_HDRLEN {
            return None;
        }
        let len = u32::from_ne_bytes(self.data[0..4].try_into().ok()?) as usize;
        if len < NLMSG_HDRLEN || len > self.data.len() {
            return None;
        }
        let hdr = MsgHeader {
            msg_type: u16::from_ne_bytes(self.data[4..6].try_into().ok()?),
            seq: u32::from_ne_bytes(self.data[8..12].try_into().ok()?),
        };
        let body = &self.data[NLMSG_HDRLEN..len];
        self.data = &self.data[align4(len).min(self.data.len())..];
        Some((hdr, body))
    }
}

#[derive(Clone, Copy)]
pub struct Attr<'a> {
    pub kind: u16,
    pub data: &'a [u8],
}

impl<'a> Attr<'a> {
    pub fn u8(&self) -> Option<u8> {
        self.data.first().copied()
    }

    pub fn u16(&self) -> Option<u16> {
        Some(u16::from_ne_bytes(self.data.get(..2)?.try_into().ok()?))
    }

    pub fn u32(&self) -> Option<u32> {
        Some(u32::from_ne_bytes(self.data.get(..4)?.try_into().ok()?))
    }

    pub fn u64(&self) -> Option<u64> {
        Some(u64::from_ne_bytes(self.data.get(..8)?.try_into().ok()?))
    }

    pub fn nested(&self) -> Attrs<'a> {
        Attrs::new(self.data)
    }

    pub fn cstr(&self) -> &'a [u8] {
        let end = self.data.iter().position(|&b| b == 0).unwrap_or(self.data.len());
        &self.data[..end]
    }
}

#[derive(Clone, Copy)]
pub struct Attrs<'a> {
    data: &'a [u8],
}

impl<'a> Attrs<'a> {
    pub fn new(data: &'a [u8]) -> Self {
        Attrs { data }
    }

    pub fn get(&self, kind: u16) -> Option<Attr<'a>> {
        self.into_iter().find(|a| a.kind == kind)
    }
}

impl<'a> IntoIterator for Attrs<'a> {
    type Item = Attr<'a>;
    type IntoIter = AttrIter<'a>;

    fn into_iter(self) -> AttrIter<'a> {
        AttrIter { data: self.data }
    }
}

impl<'a> IntoIterator for &Attrs<'a> {
    type Item = Attr<'a>;
    type IntoIter = AttrIter<'a>;

    fn into_iter(self) -> AttrIter<'a> {
        AttrIter { data: self.data }
    }
}

pub struct AttrIter<'a> {
    data: &'a [u8],
}

impl<'a> Iterator for AttrIter<'a> {
    type Item = Attr<'a>;

    fn next(&mut self) -> Option<Attr<'a>> {
        if self.data.len() < 4 {
            return None;
        }
        let len = u16::from_ne_bytes([self.data[0], self.data[1]]) as usize;
        let kind = u16::from_ne_bytes([self.data[2], self.data[3]]) & NLA_TYPE_MASK;
        if len < 4 || len > self.data.len() {
            return None;
        }
        let attr = Attr { kind, data: &self.data[4..len] };
        self.data = &self.data[align4(len).min(self.data.len())..];
        Some(attr)
    }
}

#[derive(Default)]
pub struct AttrWriter {
    pub buf: Vec<u8>,
    #[cfg(test)]
    nests: Vec<usize>,
}

impl AttrWriter {
    pub fn with_header(header: &[u8]) -> Self {
        let mut w = AttrWriter::default();
        w.buf.extend_from_slice(header);
        w.pad();
        w
    }

    pub fn put(&mut self, kind: u16, data: &[u8]) -> &mut Self {
        self.buf.extend_from_slice(&((4 + data.len()) as u16).to_ne_bytes());
        self.buf.extend_from_slice(&kind.to_ne_bytes());
        self.buf.extend_from_slice(data);
        self.pad();
        self
    }

    pub fn put_u32(&mut self, kind: u16, v: u32) -> &mut Self {
        self.put(kind, &v.to_ne_bytes())
    }

    fn pad(&mut self) {
        let target = align4(self.buf.len());
        self.buf.resize(target, 0);
    }
}

#[cfg(test)]
impl AttrWriter {
    pub fn put_u8(&mut self, kind: u16, v: u8) -> &mut Self {
        self.put(kind, &[v])
    }

    pub fn put_u16(&mut self, kind: u16, v: u16) -> &mut Self {
        self.put(kind, &v.to_ne_bytes())
    }

    pub fn put_u64(&mut self, kind: u16, v: u64) -> &mut Self {
        self.put(kind, &v.to_ne_bytes())
    }

    pub fn put_flag(&mut self, kind: u16) -> &mut Self {
        self.put(kind, &[])
    }

    pub fn begin(&mut self, kind: u16) -> &mut Self {
        self.nests.push(self.buf.len());
        self.buf.extend_from_slice(&0u16.to_ne_bytes());
        self.buf.extend_from_slice(&(kind | NLA_F_NESTED).to_ne_bytes());
        self
    }

    pub fn end(&mut self) -> &mut Self {
        if let Some(start) = self.nests.pop() {
            let len = (self.buf.len() - start) as u16;
            self.buf[start..start + 2].copy_from_slice(&len.to_ne_bytes());
        }
        self
    }
}

#[cfg(test)]
pub fn frame_message(msg_type: u16, seq: u32, body: &[u8]) -> Vec<u8> {
    let mut out = Vec::new();
    out.extend_from_slice(&((NLMSG_HDRLEN + body.len()) as u32).to_ne_bytes());
    out.extend_from_slice(&msg_type.to_ne_bytes());
    out.extend_from_slice(&0u16.to_ne_bytes());
    out.extend_from_slice(&seq.to_ne_bytes());
    out.extend_from_slice(&0u32.to_ne_bytes());
    out.extend_from_slice(body);
    out.resize(align4(out.len()), 0);
    out
}
