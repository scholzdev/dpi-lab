// Phase 2: classification - signature match, TLS SNI extraction, DNS query name extraction.
use aho_corasick::AhoCorasick;

/// Multi-pattern keyword matcher over raw payload bytes (Suricata-style content match).
pub struct Signatures {
    ac: AhoCorasick,
    patterns: Vec<String>,
}

impl Signatures {
    pub fn new<S: AsRef<str>>(patterns: &[S]) -> Self {
        Self {
            ac: AhoCorasick::new(patterns.iter().map(|s| s.as_ref())).expect("valid patterns"),
            patterns: patterns.iter().map(|s| s.as_ref().to_string()).collect(),
        }
    }

    /// Returns the names of every pattern found in `payload`.
    pub fn matches(&self, payload: &[u8]) -> Vec<&str> {
        self.ac
            .find_iter(payload)
            .map(|m| self.patterns[m.pattern()].as_str())
            .collect()
    }
}

/// Fields pulled from a TLS ClientHello - enough for SNI extraction and JA3
/// fingerprinting from one parse pass instead of two.
pub struct ClientHello {
    pub version: u16,
    pub sni: Option<String>,
    pub cipher_suites: Vec<u16>,
    pub extensions: Vec<u16>,   // in wire order, GREASE included (callers filter as needed)
    pub curves: Vec<u16>,       // supported_groups extension (10)
    pub ec_point_formats: Vec<u8>, // ec_point_formats extension (11)
}

/// GREASE values (RFC 8701): reserved values of the form 0x?A?A with both bytes
/// equal, sprinkled into cipher/extension/curve lists to prevent ossification.
/// JA3 fingerprinting excludes them by convention since they're randomized noise,
/// not identifying signal.
fn is_grease(v: u16) -> bool {
    let hi = (v >> 8) as u8;
    let lo = v as u8;
    hi == lo && (hi & 0x0f) == 0x0a
}

/// Parse a TLS ClientHello. Handles a single TLS record containing the full
/// ClientHello (the common case - ClientHello rarely spans multiple TCP segments
/// unless extension-heavy, e.g. ECH; callers should retry against the reassembled
/// stream as more segments arrive rather than giving up on the first packet).
pub fn parse_client_hello(data: &[u8]) -> Option<ClientHello> {
    // TLS record header: type(1) version(2) length(2)
    let rec_type = *data.get(0)?;
    if rec_type != 0x16 {
        return None; // not a handshake record
    }
    let rec_len = u16::from_be_bytes([*data.get(3)?, *data.get(4)?]) as usize;
    let body = data.get(5..5 + rec_len)?;

    // Handshake header: type(1) length(3)
    if *body.get(0)? != 0x01 {
        return None; // not a ClientHello
    }
    let hs_len = u32::from_be_bytes([0, body[1], body[2], body[3]]) as usize;
    let hs = body.get(4..4 + hs_len)?;

    let version = u16::from_be_bytes([*hs.get(0)?, *hs.get(1)?]);

    // ClientHello: version(2) random(32) session_id_len(1)+id
    let mut p = 2 + 32;
    let sid_len = *hs.get(p)? as usize;
    p += 1 + sid_len;

    // cipher_suites_len(2)+suites
    let cs_len = u16::from_be_bytes([*hs.get(p)?, *hs.get(p + 1)?]) as usize;
    p += 2;
    let cipher_suites: Vec<u16> = hs
        .get(p..p + cs_len)?
        .chunks_exact(2)
        .map(|c| u16::from_be_bytes([c[0], c[1]]))
        .collect();
    p += cs_len;

    // compression_methods_len(1)+methods
    let cm_len = *hs.get(p)? as usize;
    p += 1 + cm_len;

    // extensions_len(2)+extensions
    let ext_total = u16::from_be_bytes([*hs.get(p)?, *hs.get(p + 1)?]) as usize;
    p += 2;
    let ext_end = p + ext_total;

    let mut sni = None;
    let mut extensions = Vec::new();
    let mut curves = Vec::new();
    let mut ec_point_formats = Vec::new();

    while p + 4 <= ext_end && p + 4 <= hs.len() {
        let ext_type = u16::from_be_bytes([hs[p], hs[p + 1]]);
        let ext_len = u16::from_be_bytes([hs[p + 2], hs[p + 3]]) as usize;
        let ext_data = hs.get(p + 4..p + 4 + ext_len)?;
        extensions.push(ext_type);
        match ext_type {
            0x0000 => {
                // server_name extension: list_len(2), then type(1) name_len(2) name
                let name_len = u16::from_be_bytes([*ext_data.get(3)?, *ext_data.get(4)?]) as usize;
                let name = ext_data.get(5..5 + name_len)?;
                sni = std::str::from_utf8(name).ok().map(String::from);
            }
            0x000a => {
                // supported_groups: list_len(2), then u16 curve IDs
                let list_len = u16::from_be_bytes([*ext_data.get(0)?, *ext_data.get(1)?]) as usize;
                curves = ext_data.get(2..2 + list_len)?.chunks_exact(2).map(|c| u16::from_be_bytes([c[0], c[1]])).collect();
            }
            0x000b => {
                // ec_point_formats: list_len(1), then u8 format IDs
                let list_len = *ext_data.get(0)? as usize;
                ec_point_formats = ext_data.get(1..1 + list_len)?.to_vec();
            }
            _ => {}
        }
        p += 4 + ext_len;
    }

    Some(ClientHello { version, sni, cipher_suites, extensions, curves, ec_point_formats })
}

/// Extract just the SNI hostname - see `parse_client_hello` for details.
pub fn parse_sni(data: &[u8]) -> Option<String> {
    parse_client_hello(data)?.sni
}

/// Compute the JA3 fingerprint (Salesforce's TLS client fingerprint format):
/// MD5 of "version,ciphers,extensions,curves,ec_point_formats" with GREASE values
/// stripped from the three list fields. Returns (ja3_string, md5_hex).
pub fn ja3(data: &[u8]) -> Option<(String, String)> {
    let ch = parse_client_hello(data)?;
    let join = |v: &[u16]| v.iter().filter(|x| !is_grease(**x)).map(|x| x.to_string()).collect::<Vec<_>>().join("-");
    let ja3_string = format!(
        "{},{},{},{},{}",
        ch.version,
        join(&ch.cipher_suites),
        join(&ch.extensions),
        join(&ch.curves),
        ch.ec_point_formats.iter().map(|x| x.to_string()).collect::<Vec<_>>().join("-"),
    );
    let digest = md5::compute(ja3_string.as_bytes());
    Some((ja3_string, format!("{digest:x}")))
}

/// A parsed DNS message's transaction ID, queried name, and the raw question-section
/// bytes (name + QTYPE + QCLASS) - the latter needed verbatim to build a spoofed
/// response the client will accept as answering its own query.
pub struct DnsQuery {
    pub id: u16,
    pub name: String,
    pub question_raw: Vec<u8>,
}

/// Parse a DNS message's first question (works on queries and responses, since a
/// response echoes its question section). Does not follow compression pointers -
/// queries don't use them in practice.
pub fn parse_dns_query_full(data: &[u8]) -> Option<DnsQuery> {
    let id = u16::from_be_bytes([*data.get(0)?, *data.get(1)?]);
    let qdcount = u16::from_be_bytes([*data.get(4)?, *data.get(5)?]);
    if qdcount == 0 {
        return None;
    }
    let start = 12; // after fixed 12-byte header
    let mut p = start;
    let mut labels = Vec::new();
    loop {
        let len = *data.get(p)? as usize;
        if len == 0 {
            p += 1;
            break;
        }
        if len & 0xC0 != 0 {
            return None; // compression pointer, not expected in a query name
        }
        p += 1;
        let label = data.get(p..p + len)?;
        labels.push(std::str::from_utf8(label).ok()?.to_string());
        p += len;
    }
    let question_end = p + 4; // + QTYPE(2) + QCLASS(2)
    let question_raw = data.get(start..question_end)?.to_vec();
    Some(DnsQuery { id, name: labels.join("."), question_raw })
}


#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn signature_match() {
        let sigs = Signatures::new(&["evil.com", "malware"]);
        let hits = sigs.matches(b"GET /path HTTP/1.1\r\nHost: evil.com\r\n");
        assert_eq!(hits, vec!["evil.com"]);
    }

    #[test]
    fn signature_no_match() {
        let sigs = Signatures::new(&["evil.com"]);
        assert!(sigs.matches(b"GET / HTTP/1.1\r\nHost: fine.com\r\n").is_empty());
    }

    #[test]
    fn dns_query_name() {
        // 12-byte header (qdcount=1) + "www.example.com" as labels + type A + class IN
        let mut pkt = vec![0u8; 12];
        pkt[5] = 1; // qdcount = 1
        for label in ["www", "example", "com"] {
            pkt.push(label.len() as u8);
            pkt.extend_from_slice(label.as_bytes());
        }
        pkt.push(0); // root label
        pkt.extend_from_slice(&[0x00, 0x01, 0x00, 0x01]); // QTYPE A, QCLASS IN
        assert_eq!(parse_dns_query_full(&pkt).unwrap().name, "www.example.com");
    }

    #[test]
    fn tls_sni_extraction() {
        // Minimal ClientHello with one server_name extension for "example.com".
        let hostname = b"example.com";
        let mut sni_ext_data = vec![0u8, 0u8]; // server_name_list_len, filled below
        let mut list = vec![0u8]; // name_type = host_name
        list.extend_from_slice(&(hostname.len() as u16).to_be_bytes());
        list.extend_from_slice(hostname);
        sni_ext_data = (list.len() as u16).to_be_bytes().to_vec();
        sni_ext_data.extend_from_slice(&list);

        let mut ext = vec![0x00, 0x00]; // extension type = server_name
        ext.extend_from_slice(&(sni_ext_data.len() as u16).to_be_bytes());
        ext.extend_from_slice(&sni_ext_data);

        let mut hs = vec![];
        hs.extend_from_slice(&[0x03, 0x03]); // client version
        hs.extend_from_slice(&[0u8; 32]); // random
        hs.push(0); // session_id_len = 0
        hs.extend_from_slice(&(2u16).to_be_bytes()); // cipher_suites_len
        hs.extend_from_slice(&[0x13, 0x01]); // one cipher suite
        hs.push(1); // compression_methods_len
        hs.push(0); // null compression
        hs.extend_from_slice(&(ext.len() as u16).to_be_bytes()); // extensions_len
        hs.extend_from_slice(&ext);

        let mut handshake = vec![0x01]; // ClientHello
        let hs_len = hs.len() as u32;
        handshake.extend_from_slice(&hs_len.to_be_bytes()[1..]); // 3-byte length
        handshake.extend_from_slice(&hs);

        let mut record = vec![0x16, 0x03, 0x01]; // handshake, TLS 1.0 record version
        record.extend_from_slice(&(handshake.len() as u16).to_be_bytes());
        record.extend_from_slice(&handshake);

        assert_eq!(parse_sni(&record).unwrap(), "example.com");
    }

    #[test]
    fn grease_values_detected() {
        assert!(is_grease(0x0a0a));
        assert!(is_grease(0xfafa));
        assert!(is_grease(0xcaca));
        assert!(!is_grease(0x1301)); // real cipher suite, not GREASE
        assert!(!is_grease(0x0000)); // SNI extension type, not GREASE
    }

    #[test]
    fn ja3_extracts_ciphers_extensions_curves_and_strips_grease() {
        // ClientHello with: two ciphers (one GREASE), supported_groups (curve +
        // GREASE curve), ec_point_formats, and a GREASE extension type. JA3 should
        // list only the real values, GREASE stripped from all three list fields.
        let curves_ext = {
            let mut d = vec![];
            let list: Vec<u8> = [0x0a0au16, 0x001d].iter().flat_map(|v| v.to_be_bytes()).collect(); // GREASE + x25519
            d.extend_from_slice(&(list.len() as u16).to_be_bytes());
            d.extend_from_slice(&list);
            d
        };
        let ec_pf_ext = vec![1u8, 0x00]; // list_len=1, format=uncompressed(0)

        let mut ext = vec![];
        // GREASE extension (type 0x1a1a, empty data) - should be dropped from JA3
        ext.extend_from_slice(&0x1a1au16.to_be_bytes());
        ext.extend_from_slice(&0u16.to_be_bytes());
        // supported_groups (10)
        ext.extend_from_slice(&10u16.to_be_bytes());
        ext.extend_from_slice(&(curves_ext.len() as u16).to_be_bytes());
        ext.extend_from_slice(&curves_ext);
        // ec_point_formats (11)
        ext.extend_from_slice(&11u16.to_be_bytes());
        ext.extend_from_slice(&(ec_pf_ext.len() as u16).to_be_bytes());
        ext.extend_from_slice(&ec_pf_ext);

        let mut hs = vec![];
        hs.extend_from_slice(&[0x03, 0x03]); // client version = 771
        hs.extend_from_slice(&[0u8; 32]);
        hs.push(0); // session_id_len
        let ciphers = [0x0a0au16, 0x1301]; // GREASE + real cipher
        let cipher_bytes: Vec<u8> = ciphers.iter().flat_map(|v| v.to_be_bytes()).collect();
        hs.extend_from_slice(&(cipher_bytes.len() as u16).to_be_bytes());
        hs.extend_from_slice(&cipher_bytes);
        hs.push(1); // compression_methods_len
        hs.push(0);
        hs.extend_from_slice(&(ext.len() as u16).to_be_bytes());
        hs.extend_from_slice(&ext);

        let mut handshake = vec![0x01];
        let hs_len = hs.len() as u32;
        handshake.extend_from_slice(&hs_len.to_be_bytes()[1..]);
        handshake.extend_from_slice(&hs);

        let mut record = vec![0x16, 0x03, 0x01];
        record.extend_from_slice(&(handshake.len() as u16).to_be_bytes());
        record.extend_from_slice(&handshake);

        let (ja3_string, hash) = ja3(&record).unwrap();
        assert_eq!(ja3_string, "771,4865,10-11,29,0"); // 0x1301=4865, 0x001d=29
        assert_eq!(hash.len(), 32); // md5 hex digest
    }
}
