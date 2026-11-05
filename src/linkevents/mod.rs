use serde::Serialize;
use std::collections::VecDeque;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};

use crate::net::genl::{Family, genl_attrs, open_family};
use crate::net::netlink::{Attrs, Messages, NlError, NlSocket};
use crate::net::nl80211::{
    ATTR_FRAME, ATTR_IFINDEX, ATTR_MAC, ATTR_STATUS_CODE, ATTR_TIMED_OUT, CMD_ASSOCIATE, CMD_AUTHENTICATE, CMD_CONNECT,
    CMD_DEAUTHENTICATE, CMD_DISASSOCIATE, CMD_ROAM, NL80211_GENL_NAME, mac_of, mac_text,
};

#[cfg(test)]
mod tests;

pub const MAX_CAUSES: usize = 64;
pub const MLME_GROUP: &str = "mlme";
const BACKOFF_MAX_S: f64 = 30.0;

fn reason_words(code: u32) -> Option<&'static str> {
    Some(match code {
        1 => "unspecified",
        2 => "previous authentication no longer valid",
        5 => "the AP is full",
        6 => "class 2 frame from an unauthenticated station",
        7 => "class 3 frame from an unassociated station",
        9 => "not authenticated",
        14 => "MIC failure",
        15 => "4-way handshake timeout",
        16 => "group key handshake timeout",
        17 => "IE mismatch in the 4-way handshake",
        23 => "802.1X authentication failed",
        34 => "poor channel conditions",
        39 => "timeout",
        _ => return None,
    })
}

fn side_words(code: u32, by_ap: bool) -> Option<&'static str> {
    match (code, by_ap) {
        (3, true) => Some("the AP is leaving"),
        (4, true) => Some("inactivity"),
        (8, true) => Some("the AP is leaving the BSS"),
        (3, false) => Some("leaving"),
        (4, false) => Some("beacon loss"),
        (8, false) => Some("leaving the BSS"),
        _ => None,
    }
}

pub fn reason_text(code: u32, by_ap: bool) -> String {
    match side_words(code, by_ap).or_else(|| reason_words(code)) {
        Some(text) => format!("reason {code}: {text}"),
        None => format!("reason {code}"),
    }
}

#[derive(Clone, Debug, PartialEq)]
pub enum NlEvent {
    Frame { frame: &'static str, sa: String, da: String, reason: u32 },
    Next,
}

fn frame_status(frame: &[u8]) -> Option<u16> {
    let at = match frame[0] & 0xfc {
        0x10 | 0x30 => 26,
        0xb0 => 28,
        _ => return None,
    };
    Some(u16::from_le_bytes(frame.get(at..at + 2)?.try_into().ok()?))
}

pub fn decode_event(cmd: u8, attrs: Attrs<'_>) -> Option<NlEvent> {
    attrs.get(ATTR_IFINDEX)?;
    let frame = attrs.get(ATTR_FRAME).map(|a| a.data).filter(|f| f.len() >= 26);
    match cmd {
        CMD_DEAUTHENTICATE | CMD_DISASSOCIATE => {
            let f = frame?;
            if !matches!(f[0] & 0xfc, 0xa0 | 0xc0) {
                return None;
            }
            Some(NlEvent::Frame {
                frame: if cmd == CMD_DEAUTHENTICATE { "deauth" } else { "disassoc" },
                sa: mac_text(f[10..16].try_into().ok()?),
                da: mac_text(f[4..10].try_into().ok()?),
                reason: u16::from_le_bytes([f[24], f[25]]) as u32,
            })
        }
        CMD_AUTHENTICATE | CMD_ASSOCIATE => (frame_status(frame?)? == 0).then_some(NlEvent::Next),
        CMD_CONNECT => {
            let ok = attrs.get(ATTR_TIMED_OUT).is_none() && attrs.get(ATTR_STATUS_CODE)?.u16()? == 0;
            (ok && mac_of(attrs.get(ATTR_MAC)).is_some()).then_some(NlEvent::Next)
        }
        CMD_ROAM => mac_of(attrs.get(ATTR_MAC)).map(|_| NlEvent::Next),
        _ => None,
    }
}

pub fn decode_message(family_id: u16, msg_type: u16, body: &[u8]) -> Option<NlEvent> {
    if msg_type != family_id {
        return None;
    }
    let (cmd, attrs) = genl_attrs(body)?;
    decode_event(cmd, attrs)
}

#[derive(Clone, Debug, PartialEq, Serialize)]
pub struct Cause {
    pub t: f64,
    pub frame: String,
    pub by_ap: bool,
    pub reason: u32,
    pub gap_s: Option<f64>,
}

struct Record {
    t: f64,
    frame: &'static str,
    sa: String,
    da: String,
    reason: u32,
    next_at: Option<f64>,
}

struct Inner {
    causes: Mutex<VecDeque<Record>>,
    stopped: AtomicBool,
    wake: OwnedFd,
}

#[derive(Clone)]
pub struct NlEvents {
    inner: Arc<Inner>,
}

pub fn subscribe() -> Result<(NlSocket, Family), NlError> {
    let (sock, family) = open_family(NL80211_GENL_NAME)?;
    let group = family.group(MLME_GROUP).ok_or(NlError::Malformed)?;
    sock.add_membership(group)?;
    Ok((sock, family))
}

impl NlEvents {
    pub fn new() -> std::io::Result<Self> {
        // SAFETY: plain eventfd(2) call; the result is checked before use.
        let fd = unsafe { libc::eventfd(0, libc::EFD_CLOEXEC | libc::EFD_NONBLOCK) };
        if fd < 0 {
            return Err(std::io::Error::last_os_error());
        }
        // SAFETY: fd is a fresh, owned, valid descriptor.
        let wake = unsafe { OwnedFd::from_raw_fd(fd) };
        let inner =
            Inner { causes: Mutex::new(VecDeque::with_capacity(MAX_CAUSES)), stopped: AtomicBool::new(false), wake };
        Ok(NlEvents { inner: Arc::new(inner) })
    }

    pub fn start(&self) -> std::io::Result<std::thread::JoinHandle<()>> {
        let me = self.clone();
        std::thread::Builder::new().name("nl-events".into()).spawn(move || me.run())
    }

    pub fn stop(&self) {
        self.inner.stopped.store(true, Ordering::SeqCst);
        let one: u64 = 1;
        // SAFETY: writes 8 bytes from a live u64 to our own eventfd.
        unsafe { libc::write(self.inner.wake.as_raw_fd(), &one as *const u64 as *const libc::c_void, 8) };
    }

    fn is_stopped(&self) -> bool {
        self.inner.stopped.load(Ordering::SeqCst)
    }

    fn run(&self) {
        let mut backoff: f64 = 1.0;
        while !self.is_stopped() {
            let _ = self.run_once();
            if !self.is_stopped() {
                self.wait(None, Some(backoff.min(BACKOFF_MAX_S)));
                backoff = (backoff * 2.0).min(BACKOFF_MAX_S);
            }
        }
    }

    fn wait(&self, sock: Option<&NlSocket>, timeout_s: Option<f64>) -> bool {
        let mut fds = vec![libc::pollfd { fd: self.inner.wake.as_raw_fd(), events: libc::POLLIN, revents: 0 }];
        if let Some(s) = sock {
            fds.push(libc::pollfd { fd: s.raw_fd(), events: libc::POLLIN, revents: 0 });
        }
        let ms = timeout_s.map(|s| (s * 1000.0) as libc::c_int).unwrap_or(-1);
        // SAFETY: fds is a valid array of fds.len() pollfd entries.
        let rc = unsafe { libc::poll(fds.as_mut_ptr(), fds.len() as libc::nfds_t, ms) };
        rc > 0 && fds.get(1).is_some_and(|p| p.revents != 0)
    }

    fn run_once(&self) -> Result<(), NlError> {
        let (mut sock, family) = subscribe()?;
        while !self.is_stopped() {
            if !self.wait(Some(&sock), None) {
                continue;
            }
            let n = match sock.recv() {
                Ok(n) => n,
                Err(e) if e.raw_os_error() == Some(libc::ENOBUFS) => continue,
                Err(e) if matches!(e.kind(), std::io::ErrorKind::WouldBlock | std::io::ErrorKind::InvalidData) => {
                    continue;
                }
                Err(e) => return Err(e.into()),
            };
            let at = crate::util::now();
            for (hdr, body) in Messages::new(sock.received(n)) {
                if let Some(ev) = decode_message(family.id, hdr.msg_type, body) {
                    self.consume(&ev, Some(at));
                }
            }
        }
        Ok(())
    }

    pub fn consume(&self, ev: &NlEvent, now: Option<f64>) {
        let t = now.filter(|n| *n != 0.0).unwrap_or_else(crate::util::now);
        let mut causes = self.inner.causes.lock().unwrap();
        match ev {
            NlEvent::Frame { frame, sa, da, reason } => {
                if causes.len() == MAX_CAUSES {
                    causes.pop_front();
                }
                causes.push_back(Record {
                    t,
                    frame,
                    sa: sa.to_lowercase(),
                    da: da.to_lowercase(),
                    reason: (*reason).min(65535),
                    next_at: None,
                });
            }
            NlEvent::Next => {
                if let Some(last) = causes.back_mut()
                    && last.next_at.is_none()
                {
                    last.next_at = Some(t);
                }
            }
        }
    }

    pub fn cause_for(&self, bssid: &str, now: f64, window: f64) -> Option<Cause> {
        let bssid = bssid.to_lowercase();
        if bssid.is_empty() {
            return None;
        }
        let causes = self.inner.causes.lock().unwrap();
        for c in causes.iter().rev() {
            if now - c.t > window {
                break;
            }
            if bssid != c.sa && bssid != c.da {
                continue;
            }
            let gap_s = c.next_at.map(|n| (n - c.t).max(0.0));
            return Some(Cause { t: c.t, frame: c.frame.to_string(), by_ap: c.sa == bssid, reason: c.reason, gap_s });
        }
        None
    }
}
