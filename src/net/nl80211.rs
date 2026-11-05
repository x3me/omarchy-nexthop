use super::genl::{Family, genl_attrs, genl_header, open_family};
use super::netlink::{Attr, AttrWriter, Attrs, NLM_F_DUMP, NlError, NlSocket};

pub const NL80211_GENL_NAME: &str = "nl80211";
pub const CMD_GET_STATION: u8 = 17;
pub const CMD_GET_SCAN: u8 = 32;
pub const CMD_AUTHENTICATE: u8 = 37;
pub const CMD_ASSOCIATE: u8 = 38;
pub const CMD_DEAUTHENTICATE: u8 = 39;
pub const CMD_DISASSOCIATE: u8 = 40;
pub const CMD_CONNECT: u8 = 46;
pub const CMD_ROAM: u8 = 47;
pub const ATTR_IFINDEX: u16 = 3;
pub const ATTR_MAC: u16 = 6;
pub const ATTR_STA_INFO: u16 = 21;
pub const ATTR_BSS: u16 = 47;
pub const ATTR_FRAME: u16 = 51;
pub const ATTR_TIMED_OUT: u16 = 65;
pub const ATTR_STATUS_CODE: u16 = 72;
pub const ATTR_MLO_LINKS: u16 = 312;
pub const ATTR_MLO_LINK_ID: u16 = 313;
pub const BSS_BSSID: u16 = 1;
pub const BSS_FREQUENCY: u16 = 2;
pub const BSS_INFORMATION_ELEMENTS: u16 = 6;
pub const BSS_STATUS: u16 = 9;
pub const BSS_FREQUENCY_OFFSET: u16 = 20;
pub const BSS_MLO_LINK_ID: u16 = 21;
pub const BSS_MLD_ADDR: u16 = 22;
pub const BSS_STATUS_AUTHENTICATED: u32 = 0;
pub const BSS_STATUS_ASSOCIATED: u32 = 1;
pub const BSS_STATUS_IBSS_JOINED: u32 = 2;
pub const STA_INFO_INACTIVE_TIME: u16 = 1;
pub const STA_INFO_SIGNAL: u16 = 7;
pub const STA_INFO_TX_BITRATE: u16 = 8;
pub const STA_INFO_RX_PACKETS: u16 = 9;
pub const STA_INFO_TX_PACKETS: u16 = 10;
pub const STA_INFO_TX_RETRIES: u16 = 11;
pub const STA_INFO_TX_FAILED: u16 = 12;
pub const STA_INFO_SIGNAL_AVG: u16 = 13;
pub const STA_INFO_RX_BITRATE: u16 = 14;
pub const STA_INFO_BEACON_LOSS: u16 = 18;
pub const STA_INFO_RX_DROP_MISC: u16 = 28;
const DUMP_MAX_BYTES: usize = 4 << 20;

pub type Mac = [u8; 6];

pub fn mac_text(mac: &Mac) -> String {
    let [a, b, c, d, e, f] = mac;
    format!("{a:02x}:{b:02x}:{c:02x}:{d:02x}:{e:02x}:{f:02x}")
}

pub fn mac_of(attr: Option<Attr<'_>>) -> Option<Mac> {
    attr?.data.get(..6)?.try_into().ok()
}

#[derive(Clone, Debug, Default, PartialEq)]
pub struct BssEntry {
    pub bssid: Mac,
    pub status: u32,
    pub freq: Option<u32>,
    pub freq_offset: u32,
    pub ies: Option<Vec<u8>>,
    pub mld_addr: Option<Mac>,
    pub link_id: Option<u8>,
}

#[derive(Clone, Debug, Default, PartialEq)]
pub struct StaInfo {
    pub inactive_ms: Option<u32>,
    pub rx_packets: Option<u32>,
    pub tx_packets: Option<u32>,
    pub tx_retries: Option<u32>,
    pub tx_failed: Option<u32>,
    pub beacon_loss: Option<u32>,
    pub rx_drop_misc: Option<u64>,
    pub signal: Option<i8>,
    pub signal_avg: Option<i8>,
    pub rx_bitrate: Option<String>,
    pub tx_bitrate: Option<String>,
}

#[derive(Clone, Debug, Default, PartialEq)]
pub struct StaEntry {
    pub mac: Mac,
    pub info: StaInfo,
    pub links: Vec<StaInfo>,
}

pub fn decode_bss(body: &[u8]) -> Option<BssEntry> {
    let (_, attrs) = genl_attrs(body)?;
    let bss = attrs.get(ATTR_BSS)?.nested();
    let bssid = mac_of(bss.get(BSS_BSSID))?;
    let status = bss.get(BSS_STATUS)?.u32()?;
    Some(BssEntry {
        bssid,
        status,
        freq: bss.get(BSS_FREQUENCY).and_then(|a| a.u32()),
        freq_offset: bss.get(BSS_FREQUENCY_OFFSET).and_then(|a| a.u32()).unwrap_or(0),
        ies: bss.get(BSS_INFORMATION_ELEMENTS).map(|a| a.data.to_vec()),
        mld_addr: mac_of(bss.get(BSS_MLD_ADDR)),
        link_id: bss.get(BSS_MLO_LINK_ID).and_then(|a| a.u8()),
    })
}

pub fn decode_sta_info(sinfo: Attrs<'_>) -> StaInfo {
    let u32_of = |k| sinfo.get(k).and_then(|a| a.u32());
    let i8_of = |k| sinfo.get(k).and_then(|a| a.u8()).map(|v| v as i8);
    StaInfo {
        inactive_ms: u32_of(STA_INFO_INACTIVE_TIME),
        rx_packets: u32_of(STA_INFO_RX_PACKETS),
        tx_packets: u32_of(STA_INFO_TX_PACKETS),
        tx_retries: u32_of(STA_INFO_TX_RETRIES),
        tx_failed: u32_of(STA_INFO_TX_FAILED),
        beacon_loss: u32_of(STA_INFO_BEACON_LOSS),
        rx_drop_misc: sinfo.get(STA_INFO_RX_DROP_MISC).and_then(|a| a.u64()),
        signal: i8_of(STA_INFO_SIGNAL),
        signal_avg: i8_of(STA_INFO_SIGNAL_AVG),
        rx_bitrate: sinfo.get(STA_INFO_RX_BITRATE).map(|a| format_bitrate(a.nested())),
        tx_bitrate: sinfo.get(STA_INFO_TX_BITRATE).map(|a| format_bitrate(a.nested())),
    }
}

pub fn decode_station(body: &[u8]) -> Option<StaEntry> {
    let (_, attrs) = genl_attrs(body)?;
    let info = decode_sta_info(attrs.get(ATTR_STA_INFO)?.nested());
    let mac = mac_of(attrs.get(ATTR_MAC)).unwrap_or_default();
    let mut links = Vec::new();
    if let Some(list) = attrs.get(ATTR_MLO_LINKS) {
        for link in list.nested() {
            let link = link.nested();
            if link.get(ATTR_MLO_LINK_ID).is_none() {
                continue;
            }
            let Some(sinfo) = link.get(ATTR_STA_INFO) else {
                break;
            };
            links.push(decode_sta_info(sinfo.nested()));
        }
    }
    Some(StaEntry { mac, info, links })
}

const RATE_BITRATE: u16 = 1;
const RATE_BITRATE32: u16 = 5;
const RATE_FIELDS: &[(u16, &str, bool)] = &[
    (2, " MCS", true),
    (6, " VHT-MCS", true),
    (3, " 40MHz", false),
    (8, " 80MHz", false),
    (9, " 80P80MHz", false),
    (10, " 160MHz", false),
    (18, " 320MHz", false),
    (25, " 1MHz", false),
    (26, " 2MHz", false),
    (27, " 4MHz", false),
    (28, " 8MHz", false),
    (29, " 16MHz", false),
    (4, " short GI", false),
    (7, " VHT-NSS", true),
    (13, " HE-MCS", true),
    (14, " HE-NSS", true),
    (15, " HE-GI", true),
    (16, " HE-DCM", true),
    (17, " HE-RU-ALLOC", true),
    (19, " EHT-MCS", true),
    (20, " EHT-NSS", true),
    (21, " EHT-GI", true),
    (22, " EHT-RU-ALLOC", true),
];

pub fn format_bitrate(rinfo: Attrs<'_>) -> String {
    let rate = match rinfo.get(RATE_BITRATE32).and_then(|a| a.u32()) {
        Some(r) => r as i32,
        None => rinfo.get(RATE_BITRATE).and_then(|a| a.u16()).map(|r| r as i32).unwrap_or(0),
    };
    let mut out = if rate > 0 { format!("{}.{} MBit/s", rate / 10, rate % 10) } else { "(unknown)".to_string() };
    for &(kind, label, valued) in RATE_FIELDS {
        let Some(a) = rinfo.get(kind) else { continue };
        out.push_str(label);
        if valued {
            out.push_str(&format!(" {}", a.u8().unwrap_or(0)));
        }
    }
    out.truncate(99);
    out
}

pub struct Nl80211 {
    sock: NlSocket,
    pub family: Family,
}

impl Nl80211 {
    pub fn open() -> Result<Self, NlError> {
        let (sock, family) = open_family(NL80211_GENL_NAME)?;
        Ok(Nl80211 { sock, family })
    }

    fn dump<T>(&mut self, cmd: u8, ifindex: u32, decode: fn(&[u8]) -> Option<T>) -> Result<Vec<T>, NlError> {
        let mut w = AttrWriter::with_header(&genl_header(cmd));
        w.put_u32(ATTR_IFINDEX, ifindex);
        let mut out = Vec::new();
        let id = self.family.id;
        self.sock.request(id, NLM_F_DUMP, &w.buf, DUMP_MAX_BYTES, |t, body| {
            if t == id
                && let Some(v) = decode(body)
            {
                out.push(v);
            }
        })?;
        Ok(out)
    }

    pub fn scan_dump(&mut self, ifindex: u32) -> Result<Vec<BssEntry>, NlError> {
        self.dump(CMD_GET_SCAN, ifindex, decode_bss)
    }

    pub fn station_dump(&mut self, ifindex: u32) -> Result<Vec<StaEntry>, NlError> {
        self.dump(CMD_GET_STATION, ifindex, decode_station)
    }
}
