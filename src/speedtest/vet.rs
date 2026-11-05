use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, ToSocketAddrs};

fn urlsplit(url: &str) -> Option<(String, Option<String>)> {
    let cleaned: String =
        url.trim_start_matches(|c: char| c <= ' ').chars().filter(|c| !matches!(c, '\t' | '\r' | '\n')).collect();
    let url = cleaned.as_str();
    let mut scheme = String::new();
    let mut rest = url;
    if let Some(i) = url.find(':')
        && i > 0
        && url.starts_with(|c: char| c.is_ascii_alphabetic())
        && url[..i].chars().all(|c| c.is_ascii_alphanumeric() || "+-.".contains(c))
    {
        scheme = url[..i].to_ascii_lowercase();
        rest = &url[i + 1..];
    }
    let netloc = rest.strip_prefix("//").map(|r| &r[..r.find(['/', '?', '#']).unwrap_or(r.len())]);
    if let Some(n) = netloc {
        if n.contains('[') != n.contains(']') {
            return None;
        }
        if n.contains('[') {
            check_bracketed_netloc(n)?;
        }
    }
    Some((scheme, netloc.map(str::to_string)))
}

fn after_userinfo(netloc: &str) -> &str {
    netloc.rsplit_once('@').map_or(netloc, |(_, h)| h)
}

fn check_bracketed_netloc(netloc: &str) -> Option<()> {
    let hp = after_userinfo(netloc);
    let hostname = match hp.split_once('[') {
        Some((before, bracketed)) => {
            if !before.is_empty() {
                return None;
            }
            let (h, port) = bracketed.split_once(']').unwrap_or((bracketed, ""));
            if !port.is_empty() && !port.starts_with(':') {
                return None;
            }
            h
        }
        None => hp.split_once(':').map_or(hp, |(h, _)| h),
    };
    check_bracketed_host(hostname)
}

fn check_bracketed_host(hostname: &str) -> Option<()> {
    if let Some(rest) = hostname.strip_prefix(['v', 'V']) {
        let (version, tail) = rest.split_once('.')?;
        let ok = !version.is_empty() && version.chars().all(|c| c.is_ascii_hexdigit()) && !tail.is_empty();
        return ok.then_some(());
    }
    let addr = match hostname.split_once('%') {
        Some((_, zone)) if zone.is_empty() || zone.contains('%') => return None,
        Some((a, _)) => a,
        None => hostname,
    };
    addr.parse::<Ipv6Addr>().ok().map(|_| ())
}

fn hostinfo(netloc: &str) -> (&str, Option<&str>) {
    let info = after_userinfo(netloc);
    let (hostname, port) = match info.split_once('[') {
        Some((_, bracketed)) => {
            let (h, after) = bracketed.split_once(']').unwrap_or((bracketed, ""));
            (h, after.split_once(':').map_or("", |(_, p)| p))
        }
        None => info.split_once(':').unwrap_or((info, "")),
    };
    (hostname, (!port.is_empty()).then_some(port))
}

fn hostname(netloc: &str) -> Option<String> {
    let (host, _) = hostinfo(netloc);
    if host.is_empty() {
        return None;
    }
    Some(match host.split_once('%') {
        Some((h, zone)) => format!("{}%{zone}", h.to_lowercase()),
        None => host.to_lowercase(),
    })
}

fn port(netloc: &str) -> Result<Option<u16>, ()> {
    match hostinfo(netloc).1 {
        None => Ok(None),
        Some(p) if !p.is_empty() && p.bytes().all(|b| b.is_ascii_digit()) => {
            let digits = p.trim_start_matches('0');
            if digits.len() > 5 {
                return Err(());
            }
            let n: u32 = if digits.is_empty() { 0 } else { digits.parse().map_err(|_| ())? };
            u16::try_from(n).map(Some).map_err(|_| ())
        }
        Some(_) => Err(()),
    }
}

fn in4(ip: u32, net: [u8; 4], len: u32) -> bool {
    let mask = if len == 0 { 0 } else { u32::MAX << (32 - len) };
    ip & mask == u32::from_be_bytes(net) & mask
}

fn in6(ip: u128, net: &str, len: u32) -> bool {
    let net: Ipv6Addr = net.parse().expect("constant network");
    let mask = if len == 0 { 0 } else { u128::MAX << (128 - len) };
    ip & mask == net.to_bits() & mask
}

const V4_PRIVATE: [([u8; 4], u32); 14] = [
    ([0, 0, 0, 0], 8),
    ([10, 0, 0, 0], 8),
    ([127, 0, 0, 0], 8),
    ([169, 254, 0, 0], 16),
    ([172, 16, 0, 0], 12),
    ([192, 0, 0, 0], 24),
    ([192, 0, 0, 170], 31),
    ([192, 0, 2, 0], 24),
    ([192, 168, 0, 0], 16),
    ([198, 18, 0, 0], 15),
    ([198, 51, 100, 0], 24),
    ([203, 0, 113, 0], 24),
    ([240, 0, 0, 0], 4),
    ([255, 255, 255, 255], 32),
];
const V4_PRIVATE_EXCEPTIONS: [([u8; 4], u32); 2] = [([192, 0, 0, 9], 32), ([192, 0, 0, 10], 32)];

const V6_PRIVATE: [(&str, u32); 11] = [
    ("::1", 128),
    ("::", 128),
    ("::ffff:0:0", 96),
    ("64:ff9b:1::", 48),
    ("100::", 64),
    ("2001::", 23),
    ("2001:db8::", 32),
    ("2002::", 16),
    ("3fff::", 20),
    ("fc00::", 7),
    ("fe80::", 10),
];
const V6_PRIVATE_EXCEPTIONS: [(&str, u32); 6] = [
    ("2001:1::1", 128),
    ("2001:1::2", 128),
    ("2001:3::", 32),
    ("2001:4:112::", 48),
    ("2001:20::", 28),
    ("2001:30::", 28),
];
const V6_RESERVED: [(&str, u32); 15] = [
    ("::", 8),
    ("100::", 8),
    ("200::", 7),
    ("400::", 6),
    ("800::", 5),
    ("1000::", 4),
    ("4000::", 3),
    ("6000::", 3),
    ("8000::", 3),
    ("a000::", 3),
    ("c000::", 3),
    ("e000::", 4),
    ("f000::", 5),
    ("f800::", 6),
    ("fe00::", 9),
];

fn refused_v4(ip: Ipv4Addr) -> bool {
    let n = ip.to_bits();
    let private = V4_PRIVATE.iter().any(|&(net, len)| in4(n, net, len))
        && V4_PRIVATE_EXCEPTIONS.iter().all(|&(net, len)| !in4(n, net, len));
    let loopback = in4(n, [127, 0, 0, 0], 8);
    let link_local = in4(n, [169, 254, 0, 0], 16);
    let multicast = in4(n, [224, 0, 0, 0], 4);
    let reserved = in4(n, [240, 0, 0, 0], 4);
    private || loopback || link_local || multicast || reserved || n == 0
}

fn refused_v6(ip: Ipv6Addr) -> bool {
    let n = ip.to_bits();
    let private = V6_PRIVATE.iter().any(|&(net, len)| in6(n, net, len))
        && V6_PRIVATE_EXCEPTIONS.iter().all(|&(net, len)| !in6(n, net, len));
    let link_local = in6(n, "fe80::", 10);
    let multicast = in6(n, "ff00::", 8);
    let reserved = V6_RESERVED.iter().any(|&(net, len)| in6(n, net, len));
    private || n == 1 || link_local || multicast || reserved || n == 0
}

fn vetted(ip: IpAddr) -> Option<IpAddr> {
    let ip = match ip {
        IpAddr::V6(v6) => v6.to_ipv4_mapped().map_or(ip, IpAddr::V4),
        v4 => v4,
    };
    let refused = match ip {
        IpAddr::V4(v4) => refused_v4(v4),
        IpAddr::V6(v6) => refused_v6(v6),
    };
    (!refused).then_some(ip)
}

pub fn vet_target(url: &str) -> Option<(String, String)> {
    let (scheme, netloc) = urlsplit(url)?;
    let netloc = netloc.unwrap_or_default();
    if !netloc.is_ascii() {
        return None;
    }
    let host = hostname(&netloc);
    if scheme != "https" {
        return None;
    }
    let host = host?;
    // INFO: fc 17oct26 Python's `parsed.port or 443` sends an explicit port 0 to 443 too
    let port = match port(&netloc).ok()? {
        Some(0) | None => 443,
        Some(p) => p,
    };
    let infos = (host.as_str(), port).to_socket_addrs().ok()?;
    let mut addrs = Vec::new();
    for info in infos {
        addrs.push(vetted(info.ip())?.to_string());
    }
    if addrs.is_empty() {
        return None;
    }
    Some((url.to_string(), format!("{host}:{port}:{}", addrs.join(","))))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn vet(url: &str) -> Option<(String, String)> {
        vet_target(url)
    }

    #[test]
    fn plaintext_is_refused() {
        assert_eq!(vet("http://93.184.216.34/download"), None);
    }

    #[test]
    fn non_http_schemes_are_refused() {
        for url in [
            "file:///etc/passwd",
            "ftp://93.184.216.34/x",
            "gopher://93.184.216.34/x",
            "scp://93.184.216.34/x",
            "dict://93.184.216.34/x",
        ] {
            assert_eq!(vet(url), None, "{url}");
        }
    }

    #[test]
    fn loopback_is_refused() {
        for url in ["https://127.0.0.1/x", "https://127.1.2.3/x", "https://[::1]/x"] {
            assert_eq!(vet(url), None, "{url}");
        }
    }

    #[test]
    fn private_ranges_are_refused() {
        for url in ["https://192.168.1.1/x", "https://10.0.0.1/x", "https://172.16.4.2/x", "https://[fd00::1]/x"] {
            assert_eq!(vet(url), None, "{url}");
        }
    }

    #[test]
    fn cloud_metadata_address_is_refused() {
        assert_eq!(vet("https://169.254.169.254/latest/meta-data/"), None);
    }

    #[test]
    fn ipv4_mapped_private_address_is_refused() {
        assert_eq!(vet("https://[::ffff:192.168.1.1]/x"), None);
    }

    #[test]
    fn unspecified_and_broadcast_refused() {
        assert_eq!(vet("https://0.0.0.0/x"), None);
        assert_eq!(vet("https://255.255.255.255/x"), None);
    }

    #[test]
    fn garbage_is_refused_without_raising() {
        for url in ["", "not a url", "https://", "https:///x", "https://:443/x"] {
            assert_eq!(vet(url), None, "{url:?}");
        }
    }

    #[test]
    fn public_https_is_accepted_and_pinned() {
        let (url, resolve) = vet("https://8.8.8.8/download?size=25000000").expect("vetted");
        assert_eq!(url, "https://8.8.8.8/download?size=25000000");
        assert_eq!(resolve, "8.8.8.8:443:8.8.8.8");
    }

    #[test]
    fn explicit_port_is_carried_into_the_pin() {
        let got = vet("https://8.8.8.8:8443/x").expect("vetted");
        assert_eq!(got.1, "8.8.8.8:8443:8.8.8.8");
    }

    #[test]
    fn a_bad_target_costs_one_candidate_not_the_test() {
        let urls = ["http://93.184.216.34/a", "https://169.254.169.254/b", "https://8.8.8.8/c"];
        let vetted: Vec<_> = urls.iter().filter_map(|u| vet(u)).collect();
        assert_eq!(vetted.len(), 1);
        assert_eq!(vetted[0].0, "https://8.8.8.8/c");
    }

    #[test]
    fn python_ipaddress_tables_are_mirrored() {
        let refused = |s: &str| vetted(s.parse().expect("ip")).is_none();
        for ip in ["100.64.0.1", "192.0.0.9", "8.8.8.8", "2606:4700::1", "fec0::1", "2001:4:112::1"] {
            assert!(!refused(ip), "{ip}");
        }
        for ip in ["192.0.0.8", "198.18.0.1", "224.0.0.1", "240.0.0.1", "2001:db8::1", "ff02::1", "fe00::1", "::"] {
            assert!(refused(ip), "{ip}");
        }
    }

    #[test]
    fn urlsplit_follows_python_netloc_rules() {
        assert_eq!(urlsplit("HTTPS://Host:1/x"), Some(("https".into(), Some("Host:1".into()))));
        assert_eq!(urlsplit(" \thttps://a\n.b/x"), Some(("https".into(), Some("a.b".into()))));
        assert_eq!(urlsplit("https://[::1/x"), None);
        assert_eq!(urlsplit("https://[1.2.3.4]/x"), None);
        assert_eq!(urlsplit("https://x[::1]/x"), None);
        assert_eq!(hostname("u@[FE80::1%Eth0]:8"), Some("fe80::1%Eth0".into()));
        assert_eq!(port("h:0443"), Ok(Some(443)));
        assert_eq!(port("h:65536"), Err(()));
        assert_eq!(port("h:4a"), Err(()));
        assert_eq!(port("h:0"), Ok(Some(0)));
        assert_eq!(vet_target("https://8.8.8.8:0/x").map(|v| v.1), Some("8.8.8.8:443:8.8.8.8".into()));
    }
}
