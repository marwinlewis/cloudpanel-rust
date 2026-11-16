//! The DNS records a sending domain needs, and a small stub resolver to check them (TXT and MX over
//! UDP, retried over TCP when truncated) against the system's nameserver.

use std::io::{Read, Write};
use std::net::{SocketAddr, TcpStream, UdpSocket};
use std::time::Duration;

/// One record to publish.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Record {
    pub kind: &'static str,
    pub name: String,
    pub value: String,
    pub priority: Option<u16>,
    /// Why it's there, shown next to it.
    pub purpose: &'static str,
}

/// Everything `domain` should publish to send through (and receive at) `host`.
pub fn records(domain: &str, host: &str, dkim_public_b64: &str) -> Vec<Record> {
    vec![
        Record {
            kind: "TXT",
            name: format!("{}._domainkey.{domain}", super::DKIM_SELECTOR),
            value: super::dkim::dns_value(dkim_public_b64),
            priority: None,
            purpose: "DKIM signature key (required)",
        },
        Record {
            kind: "TXT",
            name: domain.to_string(),
            value: format!("v=spf1 a:{host} ~all"),
            priority: None,
            purpose: "SPF: this server may send for the domain (merge into an existing v=spf1 record)",
        },
        Record {
            kind: "MX",
            name: domain.to_string(),
            value: host.to_string(),
            priority: Some(10),
            purpose: "Inbound mail for forwarding addresses (needed for Gmail's verification email)",
        },
        Record {
            kind: "TXT",
            name: format!("_dmarc.{domain}"),
            value: "v=DMARC1; p=none; adkim=r; aspf=r".to_string(),
            priority: None,
            purpose: "DMARC policy (start with p=none, tighten once mail checks out)",
        },
    ]
}

/// Result of checking one record.
#[derive(Debug, Clone)]
pub struct Check {
    pub record: Record,
    pub ok: bool,
    pub found: Vec<String>,
}

/// Look every record up. DKIM must match exactly; SPF must mention this host (or `a`/`mx`).
pub fn check(domain: &str, host: &str, dkim_public_b64: &str) -> Vec<Check> {
    let host_lc = host.to_ascii_lowercase();
    records(domain, host, dkim_public_b64)
        .into_iter()
        .map(|record| {
            let (ok, found) = match record.kind {
                "MX" => {
                    let found = lookup_mx(&record.name).unwrap_or_default();
                    let ok = found.iter().any(|(_, h)| h.eq_ignore_ascii_case(&host_lc));
                    (ok, found.into_iter().map(|(p, h)| format!("{p} {h}")).collect())
                }
                _ => {
                    let found = lookup_txt(&record.name).unwrap_or_default();
                    let ok = if record.name.contains("._domainkey.") {
                        found.iter().any(|t| dkim_matches(t, dkim_public_b64))
                    } else if record.name.starts_with("_dmarc.") {
                        found
                            .iter()
                            .any(|t| t.trim_start().to_ascii_lowercase().starts_with("v=dmarc1"))
                    } else {
                        found.iter().any(|t| spf_allows(t, &host_lc))
                    };
                    (ok, found)
                }
            };
            Check { record, ok, found }
        })
        .collect()
}

fn dkim_matches(txt: &str, public_b64: &str) -> bool {
    txt.split(';')
        .filter_map(|t| t.split_once('='))
        .any(|(k, v)| k.trim() == "p" && v.chars().filter(|c| !c.is_whitespace()).eq(public_b64.chars()))
}

fn spf_allows(txt: &str, host: &str) -> bool {
    let t = txt.to_ascii_lowercase();
    if !t.starts_with("v=spf1") {
        return false;
    }
    t.split_whitespace().any(|m| {
        let m = m.trim_start_matches(['+', '?']);
        m == "a"
            || m == "mx"
            || m == format!("a:{host}")
            || m == format!("mx:{host}")
            || m.starts_with("ip4:")
            || m.starts_with("ip6:")
            || m.starts_with("include:")
    })
}

// ---------- Stub resolver ----------

const TYPE_MX: u16 = 15;
const TYPE_TXT: u16 = 16;

fn nameservers() -> Vec<SocketAddr> {
    let conf = std::fs::read_to_string("/etc/resolv.conf").unwrap_or_default();
    let mut out: Vec<SocketAddr> = conf
        .lines()
        .filter_map(|l| l.trim().strip_prefix("nameserver"))
        .filter_map(|ip| ip.trim().parse::<std::net::IpAddr>().ok())
        .map(|ip| SocketAddr::new(ip, 53))
        .collect();
    if out.is_empty() {
        out.push("127.0.0.53:53".parse().unwrap());
    }
    out
}

/// A query for `name`/`qtype` with recursion desired.
pub fn build_query(id: u16, name: &str, qtype: u16) -> Result<Vec<u8>, String> {
    let mut q = Vec::with_capacity(32 + name.len());
    q.extend_from_slice(&id.to_be_bytes());
    q.extend_from_slice(&[0x01, 0x00, 0, 1, 0, 0, 0, 0, 0, 0]);
    for label in name.trim_end_matches('.').split('.') {
        if label.is_empty() || label.len() > 63 {
            return Err(format!("Invalid DNS name {name}"));
        }
        q.push(label.len() as u8);
        q.extend_from_slice(label.as_bytes());
    }
    q.push(0);
    q.extend_from_slice(&qtype.to_be_bytes());
    q.extend_from_slice(&1u16.to_be_bytes());
    Ok(q)
}

/// Read a (possibly compressed) name at `pos`; returns it and the offset after it.
fn read_name(msg: &[u8], mut pos: usize) -> Option<(String, usize)> {
    let mut labels = Vec::new();
    let mut end = None;
    for _ in 0..64 {
        let len = *msg.get(pos)? as usize;
        if len == 0 {
            return Some((labels.join("."), end.unwrap_or(pos + 1)));
        }
        if len & 0xc0 == 0xc0 {
            let ptr = ((len & 0x3f) << 8) | *msg.get(pos + 1)? as usize;
            end.get_or_insert(pos + 2);
            pos = ptr;
            continue;
        }
        labels.push(String::from_utf8_lossy(msg.get(pos + 1..pos + 1 + len)?).into_owned());
        pos += 1 + len;
    }
    None
}

/// Answer records of `qtype` as `(rdata offset, rdata)`. Errors on a server failure; NXDOMAIN is empty.
pub fn parse_answers(msg: &[u8], id: u16, qtype: u16) -> Result<Vec<(usize, Vec<u8>)>, String> {
    let bad = || "Malformed DNS response".to_string();
    if msg.len() < 12 || u16::from_be_bytes([msg[0], msg[1]]) != id {
        return Err(bad());
    }
    let rcode = msg[3] & 0x0f;
    if rcode == 3 {
        return Ok(Vec::new());
    }
    if rcode != 0 {
        return Err(format!("DNS server error (rcode {rcode})"));
    }
    let qd = u16::from_be_bytes([msg[4], msg[5]]);
    let an = u16::from_be_bytes([msg[6], msg[7]]);
    let mut pos = 12;
    for _ in 0..qd {
        pos = read_name(msg, pos).ok_or_else(bad)?.1 + 4;
    }
    let mut out = Vec::new();
    for _ in 0..an {
        pos = read_name(msg, pos).ok_or_else(bad)?.1;
        let hdr = msg.get(pos..pos + 10).ok_or_else(bad)?;
        let rtype = u16::from_be_bytes([hdr[0], hdr[1]]);
        let rdlen = u16::from_be_bytes([hdr[8], hdr[9]]) as usize;
        pos += 10;
        let rdata = msg.get(pos..pos + rdlen).ok_or_else(bad)?;
        if rtype == qtype {
            out.push((pos, rdata.to_vec()));
        }
        pos += rdlen;
    }
    Ok(out)
}

fn exchange(server: SocketAddr, query: &[u8]) -> Result<Vec<u8>, String> {
    let sock = UdpSocket::bind(if server.is_ipv4() { "0.0.0.0:0" } else { "[::]:0" }).map_err(|e| e.to_string())?;
    sock.set_read_timeout(Some(Duration::from_secs(4)))
        .map_err(|e| e.to_string())?;
    sock.send_to(query, server).map_err(|e| e.to_string())?;
    let mut buf = vec![0u8; 4096];
    let n = sock.recv(&mut buf).map_err(|e| format!("DNS query failed: {e}"))?;
    buf.truncate(n);
    if buf.len() > 2 && buf[2] & 0x02 != 0 {
        // Truncated: ask again over TCP.
        let mut tcp = TcpStream::connect_timeout(&server, Duration::from_secs(4)).map_err(|e| e.to_string())?;
        tcp.set_read_timeout(Some(Duration::from_secs(4)))
            .map_err(|e| e.to_string())?;
        let mut framed = (query.len() as u16).to_be_bytes().to_vec();
        framed.extend_from_slice(query);
        tcp.write_all(&framed).map_err(|e| e.to_string())?;
        let mut len = [0u8; 2];
        tcp.read_exact(&mut len).map_err(|e| e.to_string())?;
        buf = vec![0u8; u16::from_be_bytes(len) as usize];
        tcp.read_exact(&mut buf).map_err(|e| e.to_string())?;
    }
    Ok(buf)
}

/// A whole response and its matching answers as `(rdata offset, rdata)`.
type Answers = (Vec<u8>, Vec<(usize, Vec<u8>)>);

fn query(name: &str, qtype: u16) -> Result<Answers, String> {
    let id: u16 = rand::random();
    let q = build_query(id, name, qtype)?;
    let mut last = String::from("no nameserver");
    for ns in nameservers() {
        match exchange(ns, &q).and_then(|resp| parse_answers(&resp, id, qtype).map(|a| (resp, a))) {
            Ok(r) => return Ok(r),
            Err(e) => last = e,
        }
    }
    Err(last)
}

/// TXT records at `name`, each with its strings joined.
pub fn lookup_txt(name: &str) -> Result<Vec<String>, String> {
    let (_, answers) = query(name, TYPE_TXT)?;
    Ok(answers.iter().map(|(_, rd)| txt_rdata(rd)).collect())
}

/// Join a TXT record's character-strings.
pub fn txt_rdata(rd: &[u8]) -> String {
    let mut s = String::new();
    let mut i = 0;
    while i < rd.len() {
        let n = rd[i] as usize;
        s.push_str(&String::from_utf8_lossy(&rd[i + 1..(i + 1 + n).min(rd.len())]));
        i += 1 + n;
    }
    s
}

/// MX records at `name` as `(preference, host)`, best first.
pub fn lookup_mx(name: &str) -> Result<Vec<(u16, String)>, String> {
    let (msg, answers) = query(name, TYPE_MX)?;
    let mut out: Vec<(u16, String)> = answers
        .iter()
        .filter(|(_, rd)| rd.len() >= 3)
        .filter_map(|(off, rd)| Some((u16::from_be_bytes([rd[0], rd[1]]), read_name(&msg, off + 2)?.0)))
        .collect();
    out.sort();
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn query_wire_format() {
        let q = build_query(0x1234, "example.com", TYPE_TXT).unwrap();
        assert_eq!(&q[..4], &[0x12, 0x34, 0x01, 0x00]);
        assert_eq!(&q[12..], b"\x07example\x03com\x00\x00\x10\x00\x01");
        assert!(build_query(1, "a..b", TYPE_TXT).is_err());
    }

    #[test]
    fn parses_compressed_mx_and_split_txt() {
        // Response to an MX query for example.com: one MX 10 mail.example.com (compressed).
        let mut r = build_query(7, "example.com", TYPE_MX).unwrap();
        r[2] = 0x81;
        r[3] = 0x80;
        r[7] = 1; // ANCOUNT
        r.extend_from_slice(&[
            0xc0, 12, 0, 15, 0, 1, 0, 0, 0, 60, 0, 9, 0, 10, 4, b'm', b'a', b'i', b'l', 0xc0, 12,
        ]);
        let answers = parse_answers(&r, 7, TYPE_MX).unwrap();
        assert_eq!(answers.len(), 1);
        let (off, rd) = &answers[0];
        assert_eq!(u16::from_be_bytes([rd[0], rd[1]]), 10);
        assert_eq!(read_name(&r, off + 2).unwrap().0, "mail.example.com");
        assert!(parse_answers(&r, 8, TYPE_MX).is_err());

        assert_eq!(txt_rdata(b"\x05v=DKI\x0aM1; k=rsa;"), "v=DKIM1; k=rsa;");
    }

    #[test]
    fn record_checks() {
        assert!(dkim_matches("v=DKIM1; k=rsa; p=AB CD", "ABCD"));
        assert!(!dkim_matches("v=DKIM1; k=rsa; p=ABCE", "ABCD"));
        assert!(spf_allows("v=spf1 a:mail.example.com ~all", "mail.example.com"));
        assert!(spf_allows("v=spf1 mx -all", "mail.example.com"));
        assert!(!spf_allows("v=spf1 -all", "mail.example.com"));
        assert!(!spf_allows("google-site-verification=x", "mail.example.com"));
        let r = records("example.com", "mail.example.com", "KEY");
        assert_eq!(r[0].name, "cloudpanel._domainkey.example.com");
        assert_eq!(r[0].value, "v=DKIM1; k=rsa; p=KEY");
        assert_eq!(r[2].priority, Some(10));
    }
}
