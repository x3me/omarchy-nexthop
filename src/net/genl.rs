use super::netlink::{AttrWriter, Attrs, NlError, NlSocket};

pub const GENL_ID_CTRL: u16 = 0x10;
pub const GENL_HDRLEN: usize = 4;
const CTRL_CMD_GETFAMILY: u8 = 3;
const CTRL_ATTR_FAMILY_ID: u16 = 1;
const CTRL_ATTR_FAMILY_NAME: u16 = 2;
const CTRL_ATTR_MCAST_GROUPS: u16 = 7;
const CTRL_ATTR_MCAST_GRP_NAME: u16 = 1;
const CTRL_ATTR_MCAST_GRP_ID: u16 = 2;
const ONE_REPLY: usize = 64 * 1024;

#[derive(Clone, Debug, Default, PartialEq)]
pub struct Family {
    pub id: u16,
    pub groups: Vec<(String, u32)>,
}

impl Family {
    pub fn group(&self, name: &str) -> Option<u32> {
        self.groups.iter().find(|(n, _)| n == name).map(|(_, id)| *id)
    }
}

pub fn genl_header(cmd: u8) -> [u8; GENL_HDRLEN] {
    [cmd, 1, 0, 0]
}

pub fn genl_attrs(body: &[u8]) -> Option<(u8, Attrs<'_>)> {
    Some((*body.first()?, Attrs::new(body.get(GENL_HDRLEN..)?)))
}

pub fn decode_family(body: &[u8]) -> Option<Family> {
    let (_, attrs) = genl_attrs(body)?;
    let id = attrs.get(CTRL_ATTR_FAMILY_ID)?.u16()?;
    let mut groups = Vec::new();
    if let Some(list) = attrs.get(CTRL_ATTR_MCAST_GROUPS) {
        for g in list.nested() {
            let inner = g.nested();
            let name = inner.get(CTRL_ATTR_MCAST_GRP_NAME).map(|a| String::from_utf8_lossy(a.cstr()).into_owned());
            let gid = inner.get(CTRL_ATTR_MCAST_GRP_ID).and_then(|a| a.u32());
            if let (Some(name), Some(gid)) = (name, gid) {
                groups.push((name, gid));
            }
        }
    }
    Some(Family { id, groups })
}

pub fn resolve_family(sock: &mut NlSocket, name: &str) -> Result<Family, NlError> {
    let mut w = AttrWriter::with_header(&genl_header(CTRL_CMD_GETFAMILY));
    let mut cname = name.as_bytes().to_vec();
    cname.push(0);
    w.put(CTRL_ATTR_FAMILY_NAME, &cname);
    let mut found = None;
    sock.request(GENL_ID_CTRL, 0, &w.buf, ONE_REPLY, |t, body| {
        if t == GENL_ID_CTRL {
            found = decode_family(body);
        }
    })?;
    found.ok_or(NlError::Malformed)
}

pub fn open_family(name: &str) -> Result<(NlSocket, Family), NlError> {
    let mut sock = NlSocket::open(libc::NETLINK_GENERIC).map_err(NlError::Io)?;
    let family = resolve_family(&mut sock, name)?;
    Ok((sock, family))
}
