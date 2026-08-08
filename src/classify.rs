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
    pub alpn: Vec<String>,      // application_layer_protocol_negotiation extension (16), in offered order
    pub signature_algorithms: Vec<u16>, // signature_algorithms extension (13), in wire order - JA4 needs this
    pub supported_versions: Vec<u16>, // supported_versions extension (0x002b) - JA4's actual version signal
    /// True if the "encrypted_client_hello" extension (0xfe0d, current IANA
    /// codepoint used by Chrome/Cloudflare/Firefox deployments) is present.
    /// When set, `sni` is the *outer* ClientHello's - decoy - SNI, not the
    /// real destination: ECH's whole point is hiding the true SNI from a
    /// path observer. A censor that can't read it can still block on its
    /// presence alone (see `engine.rs`'s `--block-ech`).
    pub has_ech: bool,
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
    let mut alpn = Vec::new();
    let mut signature_algorithms = Vec::new();
    let mut supported_versions = Vec::new();
    let mut has_ech = false;

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
            0x000d => {
                // signature_algorithms (RFC 8446 SS4.2.3): list_len(2), then u16 scheme IDs
                let list_len = u16::from_be_bytes([*ext_data.get(0)?, *ext_data.get(1)?]) as usize;
                signature_algorithms =
                    ext_data.get(2..2 + list_len)?.chunks_exact(2).map(|c| u16::from_be_bytes([c[0], c[1]])).collect();
            }
            0x0010 => {
                // ALPN (RFC 7301): protocol_name_list_len(2), then (len(1)+name) entries
                let list_len = u16::from_be_bytes([*ext_data.get(0)?, *ext_data.get(1)?]) as usize;
                let mut list = ext_data.get(2..2 + list_len)?;
                while let Some(&name_len) = list.first() {
                    let name = list.get(1..1 + name_len as usize)?;
                    alpn.push(String::from_utf8_lossy(name).into_owned());
                    list = list.get(1 + name_len as usize..)?;
                }
            }
            0x002b => {
                // supported_versions (RFC 8446 SS4.2.1): list_len(1), then u16 version entries
                let list_len = *ext_data.get(0)? as usize;
                supported_versions =
                    ext_data.get(1..1 + list_len)?.chunks_exact(2).map(|c| u16::from_be_bytes([c[0], c[1]])).collect();
            }
            0xfe0d => has_ech = true, // encrypted_client_hello - contents are opaque, presence is the signal
            _ => {}
        }
        p += 4 + ext_len;
    }

    Some(ClientHello {
        version,
        sni,
        cipher_suites,
        extensions,
        curves,
        ec_point_formats,
        alpn,
        signature_algorithms,
        supported_versions,
        has_ech,
    })
}

/// In-place TLS 1.3->1.2 forced downgrade (`--inline --downgrade-tls13`
/// only - see engine.rs's off-path/`--inline` split, this needs to mangle a
/// live packet). Flips every `0x0304` (TLS 1.3) entry inside the
/// `supported_versions` extension (0x002b, RFC 8446 SS4.2.1: list_len(1) +
/// u16 version entries) to `0x0303` (TLS 1.2), byte-for-byte in place -
/// deliberately never removes the extension or changes any length field.
/// Shrinking the record would shrink this TCP segment's payload, which
/// desyncs every later real segment from this flow (the sender computed
/// their sequence numbers against its own, unmangled, longer payload) -
/// same-length-in-place editing has no such resegmentation problem, at the
/// cost of only being able to substitute, never delete.
///
/// Returns whether anything changed - `false` (buffer untouched) covers
/// "not a ClientHello", "no supported_versions extension" (already <=1.2),
/// and "extension present but no 1.3 entry to strip", all safe no-ops.
///
/// Ceiling, not hidden: RFC 8446 SS4.1.3 has a downgrade-detection sentinel -
/// a TLS-1.3-capable server that ends up negotiating <=1.2 stamps the last 8
/// bytes of ServerHello.random with a fixed value, and TLS-1.3-capable
/// clients (every current browser, curl, OpenSSL 1.1.1+, ...) check for it
/// and abort specifically to catch this attack. This does force the
/// negotiation down (real, observable on the wire) - RFC-conformant modern
/// clients then refuse it rather than silently downgrading.
pub fn mangle_supported_versions_in_place(record: &mut [u8]) -> bool {
    let Some(rec_type) = record.first().copied() else { return false };
    if rec_type != 0x16 {
        return false;
    }
    let Some(rec_len_bytes) = record.get(3..5) else { return false };
    let rec_len = u16::from_be_bytes([rec_len_bytes[0], rec_len_bytes[1]]) as usize;
    let Some(body) = record.get_mut(5..5 + rec_len) else { return false };

    if body.first().copied() != Some(0x01) {
        return false; // not a ClientHello
    }
    let hs_len = u32::from_be_bytes([0, body[1], body[2], body[3]]) as usize;
    let Some(hs) = body.get_mut(4..4 + hs_len) else { return false };

    // Same field walk as parse_client_hello, just skipping to compute an
    // offset instead of extracting values - see that function for the
    // field-by-field byte layout this mirrors.
    let mut p = 2 + 32;
    let Some(&sid_len) = hs.get(p) else { return false };
    p += 1 + sid_len as usize;

    let Some(cs_len_bytes) = hs.get(p..p + 2) else { return false };
    let cs_len = u16::from_be_bytes([cs_len_bytes[0], cs_len_bytes[1]]) as usize;
    p += 2 + cs_len;

    let Some(&cm_len) = hs.get(p) else { return false };
    p += 1 + cm_len as usize;

    let Some(ext_total_bytes) = hs.get(p..p + 2) else { return false };
    let ext_total = u16::from_be_bytes([ext_total_bytes[0], ext_total_bytes[1]]) as usize;
    p += 2;
    let ext_end = p + ext_total;

    let mut changed = false;
    while p + 4 <= ext_end && p + 4 <= hs.len() {
        let ext_type = u16::from_be_bytes([hs[p], hs[p + 1]]);
        let ext_len = u16::from_be_bytes([hs[p + 2], hs[p + 3]]) as usize;
        if hs.get(p + 4..p + 4 + ext_len).is_none() {
            return changed; // truncated - stop, keep whatever was already flipped
        }
        if ext_type == 0x002b {
            let Some(&list_len) = hs.get(p + 4) else { return changed };
            let entries_start = p + 5;
            let entries_end = entries_start + list_len as usize;
            if entries_end > p + 4 + ext_len {
                return changed; // malformed list length - leave alone
            }
            let mut e = entries_start;
            while e + 2 <= entries_end {
                if hs[e] == 0x03 && hs[e + 1] == 0x04 {
                    hs[e + 1] = 0x03; // TLS 1.3 -> TLS 1.2
                    changed = true;
                }
                e += 2;
            }
        }
        p += 4 + ext_len;
    }
    changed
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

/// Fields pulled from a TLS ServerHello - the server-side counterpart of
/// `ClientHello`, for JA3S. Unlike ClientHello's cipher_suites (a list the
/// client offers), a ServerHello names exactly the one cipher the server
/// picked - singular by the wire format itself, not a simplification.
pub struct ServerHello {
    pub version: u16,
    pub cipher_suite: u16,
    pub extensions: Vec<u16>,
}

/// Parse a TLS ServerHello - same record/handshake framing as
/// `parse_client_hello`, simpler body (RFC 8446 SS4.1.3 / RFC 5246 SS7.4.1.3):
/// version(2) random(32) session_id_len(1)+id cipher_suite(2)
/// compression_method(1) extensions_len(2)+extensions. Always sent in the
/// clear at the record layer in both TLS 1.2 and 1.3 - encryption only
/// starts after the key material this message carries is derived - so this
/// works on either version, no version branch needed.
pub fn parse_server_hello(data: &[u8]) -> Option<ServerHello> {
    let rec_type = *data.get(0)?;
    if rec_type != 0x16 {
        return None;
    }
    let rec_len = u16::from_be_bytes([*data.get(3)?, *data.get(4)?]) as usize;
    let body = data.get(5..5 + rec_len)?;

    if *body.get(0)? != 0x02 {
        return None; // not a ServerHello
    }
    let hs_len = u32::from_be_bytes([0, body[1], body[2], body[3]]) as usize;
    let hs = body.get(4..4 + hs_len)?;

    let version = u16::from_be_bytes([*hs.get(0)?, *hs.get(1)?]);

    let mut p = 2 + 32;
    let sid_len = *hs.get(p)? as usize;
    p += 1 + sid_len;

    let cipher_suite = u16::from_be_bytes([*hs.get(p)?, *hs.get(p + 1)?]);
    p += 2;
    p += 1; // compression_method - single byte, unlike ClientHello's list

    let ext_total = u16::from_be_bytes([*hs.get(p)?, *hs.get(p + 1)?]) as usize;
    p += 2;
    let ext_end = p + ext_total;

    let mut extensions = Vec::new();
    while p + 4 <= ext_end && p + 4 <= hs.len() {
        let ext_type = u16::from_be_bytes([hs[p], hs[p + 1]]);
        let ext_len = u16::from_be_bytes([hs[p + 2], hs[p + 3]]) as usize;
        if hs.get(p + 4..p + 4 + ext_len).is_none() {
            break;
        }
        extensions.push(ext_type);
        p += 4 + ext_len;
    }

    Some(ServerHello { version, cipher_suite, extensions })
}

/// JA3S: the server-fingerprint counterpart of JA3 (same Salesforce spec,
/// same GREASE-stripping convention). MD5 of "version,cipher,extensions" -
/// useful independent of SNI/JA3, e.g. spotting a fake/self-signed cert
/// server serving a distinctive TLS stack fingerprint regardless of what
/// hostname the client asked for.
pub fn ja3s(data: &[u8]) -> Option<(String, String)> {
    let sh = parse_server_hello(data)?;
    let join = |v: &[u16]| v.iter().filter(|x| !is_grease(**x)).map(|x| x.to_string()).collect::<Vec<_>>().join("-");
    let ja3s_string = format!("{},{},{}", sh.version, sh.cipher_suite, join(&sh.extensions));
    let digest = md5::compute(ja3s_string.as_bytes());
    Some((ja3s_string, format!("{digest:x}")))
}

/// JA4 (FoxIO spec, TLS-client variant only - not the JA4S/JA4H/JA4L
/// protocol-family siblings). Format: `t{version}{sni}{ciphers:02}{exts:02}{alpn}_{cipher-hash}_{ext-hash}`.
/// GREASE excluded from every list before counting/hashing, same convention
/// as JA3.
///
/// ponytail: reasonably faithful, not a byte-for-byte guarantee against the
/// reference implementation on every edge case - e.g. this truncates a
/// non-ASCII/multi-byte-first-char ALPN value's "first/last char" by raw
/// byte rather than the spec's own edge-case handling for non-alphanumeric
/// protocol IDs. Real-world ALPN values (`h2`, `http/1.1`, `h3`) all hit the
/// common path correctly; upgrade path if it matters is closer spec-reading
/// for the uncommon ones, not a rewrite.
pub fn ja4(data: &[u8]) -> Option<String> {
    let ch = parse_client_hello(data)?;

    // Version code: JA4 wants the real negotiated-max version, which for a
    // real TLS 1.3 client lives in supported_versions (the legacy top-level
    // `version` field stays 0x0303/TLS-1.2 for backward compat on those
    // clients) - falls back to the legacy field only when the extension is
    // absent (a genuine <=1.2-only client).
    let versions: Vec<u16> = ch.supported_versions.iter().copied().filter(|v| !is_grease(*v)).collect();
    let effective_version = versions.into_iter().max().unwrap_or(ch.version);
    let version_code = match effective_version {
        0x0304 => "13",
        0x0303 => "12",
        0x0302 => "11",
        0x0301 => "10",
        0x0300 => "s3",
        _ => "00",
    };

    let sni_flag = if ch.sni.is_some() { "d" } else { "i" };

    let ciphers: Vec<u16> = ch.cipher_suites.iter().copied().filter(|c| !is_grease(*c)).collect();
    let extensions: Vec<u16> = ch.extensions.iter().copied().filter(|e| !is_grease(*e)).collect();
    let cipher_count = ciphers.len().min(99);
    let ext_count = extensions.len().min(99);

    let alpn_code = match ch.alpn.first() {
        Some(proto) if !proto.is_empty() => {
            let first = proto.as_bytes()[0] as char;
            let last = proto.as_bytes()[proto.len() - 1] as char;
            format!("{first}{last}")
        }
        _ => "00".to_string(),
    };

    let mut sorted_ciphers = ciphers.clone();
    sorted_ciphers.sort_unstable();
    let cipher_hash = truncated_sha256_hex(&sorted_ciphers.iter().map(|c| format!("{c:04x}")).collect::<Vec<_>>().join(","));

    // Extension hash payload excludes SNI(0x0000) and ALPN(0x0010) - JA4
    // already encodes their presence/value separately (sni_flag, alpn_code)
    // - plus the signature_algorithms list appended in its original
    // (unsorted) order, per spec.
    let mut sorted_exts: Vec<u16> = extensions.iter().copied().filter(|e| *e != 0x0000 && *e != 0x0010).collect();
    sorted_exts.sort_unstable();
    let ext_part = sorted_exts.iter().map(|e| format!("{e:04x}")).collect::<Vec<_>>().join(",");
    let sig_alg_part = ch.signature_algorithms.iter().map(|s| format!("{s:04x}")).collect::<Vec<_>>().join(",");
    let ext_hash = truncated_sha256_hex(&format!("{ext_part}_{sig_alg_part}"));

    Some(format!("t{version_code}{sni_flag}{cipher_count:02}{ext_count:02}{alpn_code}_{cipher_hash}_{ext_hash}"))
}

/// First 12 hex chars of SHA256(s) - JA4's own truncation convention. Uses
/// `ring::digest` (already a dependency for QUIC's AEAD/HKDF) rather than
/// adding a dedicated sha2 crate for one call site.
fn truncated_sha256_hex(s: &str) -> String {
    let digest = ring::digest::digest(&ring::digest::SHA256, s.as_bytes());
    digest.as_ref().iter().take(6).map(|b| format!("{b:02x}")).collect()
}

/// Extract CN + SAN DNS names from a TLS <=1.2 Certificate handshake message
/// (RFC 5246 §7.4.2) somewhere in a reassembled record stream. TLS 1.3 has no
/// equivalent here - its Certificate message is encrypted under handshake
/// traffic keys derived from the ECDHE exchange, which passive capture never
/// has; this naturally returns None on a 1.3 flow rather than needing a
/// version check, matching every other "try, return Option" parser here.
/// Gives up (returns None) if the Certificate message or the record carrying
/// it hasn't fully arrived yet, or spans more than one TLS record - real
/// cert chains almost always fit in one, the rare exception isn't chased
/// (see example.md's known limits).
pub fn parse_tls_certificate_names(data: &[u8]) -> Option<Vec<String>> {
    let mut offset = 0;
    while offset + 5 <= data.len() {
        let record_type = data[offset];
        let record_len = u16::from_be_bytes([data[offset + 3], data[offset + 4]]) as usize;
        let record_start = offset + 5;
        if record_start + record_len > data.len() {
            return None; // record not fully delivered yet
        }
        if record_type == 0x16 {
            if let Some(names) = parse_certificate_handshake(&data[record_start..record_start + record_len]) {
                return Some(names);
            }
        }
        offset = record_start + record_len;
    }
    None
}

/// Walk handshake messages within one TLS record looking for a Certificate
/// message (type 0x0b) - a record commonly carries several handshake
/// messages back to back (e.g. ServerHello immediately followed by
/// Certificate), not just one.
fn parse_certificate_handshake(record: &[u8]) -> Option<Vec<String>> {
    let mut offset = 0;
    while offset + 4 <= record.len() {
        let msg_type = record[offset];
        let hs_len = u32::from_be_bytes([0, record[offset + 1], record[offset + 2], record[offset + 3]]) as usize;
        let body_start = offset + 4;
        if body_start + hs_len > record.len() {
            return None; // this handshake message spans records - give up
        }
        if msg_type == 0x0b {
            return parse_certificate_body(&record[body_start..body_start + hs_len]);
        }
        offset = body_start + hs_len;
    }
    None
}

/// Certificate message body (RFC 5246 §7.4.2): a 3-byte total-length prefix
/// followed by a list of (3-byte length, DER cert) entries. Only the first
/// (leaf) certificate is parsed - that's the one naming the actual server.
fn parse_certificate_body(body: &[u8]) -> Option<Vec<String>> {
    if body.len() < 6 {
        return None; // 3-byte list length + at least one 3-byte cert length
    }
    let cert_len = u32::from_be_bytes([0, body[3], body[4], body[5]]) as usize;
    let cert_start = 6;
    if cert_start + cert_len > body.len() {
        return None;
    }
    names_from_der(&body[cert_start..cert_start + cert_len])
}

/// CN (subject) + SAN DNS names from a DER-encoded X.509 certificate.
fn names_from_der(der: &[u8]) -> Option<Vec<String>> {
    use x509_parser::prelude::*;
    let (_, cert) = X509Certificate::from_der(der).ok()?;
    let mut names: Vec<String> = Vec::new();
    for cn in cert.subject().iter_common_name() {
        if let Ok(s) = cn.as_str() {
            names.push(s.to_string());
        }
    }
    for ext in cert.extensions() {
        if let ParsedExtension::SubjectAlternativeName(san) = ext.parsed_extension() {
            for name in &san.general_names {
                if let GeneralName::DNSName(dns) = name {
                    names.push(dns.to_string());
                }
            }
        }
    }
    if names.is_empty() {
        None
    } else {
        names.dedup();
        Some(names)
    }
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

/// Extract the `Host:` header value from a plaintext HTTP request - the GFW
/// (and every other DPI box) has always inspected this alongside TLS SNI,
/// since circumvention over plain HTTP (no TLS at all) doesn't have an SNI
/// to filter on but still names its destination in the clear. Case-insensitive
/// header name per RFC 7230; stops at the first CRLF, trims a trailing \r.
pub fn parse_http_host(data: &[u8]) -> Option<String> {
    let text = std::str::from_utf8(data).ok()?;
    // Only look at the request line + headers, not any body - a "Host:" byte
    // sequence appearing in POST data isn't the request's actual destination.
    let head = text.split("\r\n\r\n").next().unwrap_or(text);
    for line in head.split("\r\n") {
        if let Some(value) = line.strip_prefix("Host:").or_else(|| line.strip_prefix("host:")) {
            return Some(value.trim().to_string());
        }
    }
    None
}

/// Extract the path and (percent-decoded) query string from a plaintext
/// HTTP request line, e.g. `GET /search?q=blocked+term HTTP/1.1` ->
/// `("/search", "q=blocked term")`. Query strings are encrypted under TLS
/// regardless of version - plaintext-HTTP-only, same limitation
/// `parse_http_host` already has. Real GFW-style deployments inspect actual
/// search queries/URL parameters, not just "does this byte sequence appear
/// anywhere in the stream" (see `Signatures`'s whole-stream scan) - this is
/// that same keyword match, just scoped to the decoded query value so a
/// match there is distinguishable from one anywhere else in the request.
pub fn parse_http_request_line(data: &[u8]) -> Option<(String, String)> {
    let text = std::str::from_utf8(data).ok()?;
    let line = text.split("\r\n").next()?;
    let mut parts = line.split(' ');
    let _method = parts.next()?;
    let target = parts.next()?;
    let version = parts.next()?;
    if !version.starts_with("HTTP/") {
        return None; // doesn't look like a real request line, not just any two space-separated tokens
    }
    let (path, query) = target.split_once('?').unwrap_or((target, ""));
    Some((path.to_string(), percent_decode(query)))
}

/// `application/x-www-form-urlencoded`-style decoding (RFC 3986 §2.1 plus
/// the `+` -> space convention query strings use): `%XX` -> that byte, `+`
/// -> space, everything else passed through. Malformed `%` sequences (not
/// two hex digits) are left as literal bytes rather than erroring - a
/// keyword scan shouldn't give up on an entire query string over one bad
/// escape.
fn percent_decode(s: &str) -> String {
    let bytes = s.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        match bytes[i] {
            b'%' if i + 3 <= bytes.len() => match std::str::from_utf8(&bytes[i + 1..i + 3]).ok().and_then(|hex| u8::from_str_radix(hex, 16).ok()) {
                Some(byte) => {
                    out.push(byte);
                    i += 3;
                }
                None => {
                    out.push(bytes[i]);
                    i += 1;
                }
            },
            b'+' => {
                out.push(b' ');
                i += 1;
            }
            b => {
                out.push(b);
                i += 1;
            }
        }
    }
    String::from_utf8_lossy(&out).into_owned()
}

/// One known protocol handshake signature: an optional exact total length,
/// plus a set of (offset, expected bytes) anchors that must all match. Fixed
/// wire-format handshakes (WireGuard, OpenVPN, ...) are recognized this way -
/// structure/shape, not a keyword search - so a rule fires on any connection
/// attempting that handshake regardless of destination IP/port, not just one
/// already on a blocklist. Loaded from config/handshakes.yml, see config.rs.
#[derive(serde::Deserialize, Debug, Clone, PartialEq)]
pub struct HandshakeRule {
    pub name: String,
    pub length: Option<usize>,
    #[serde(rename = "match", default)]
    pub anchors: Vec<HandshakeAnchor>,
    /// "tcp" | "udp" | omitted (matches either). Without this, a UDP-only
    /// rule like WireGuard's could in principle match bytes that happen to
    /// land at the same offsets in an unrelated TCP stream - astronomically
    /// unlikely by chance given the byte anchors involved, but scoping by
    /// transport is free correctness, not paranoia.
    pub protocol: Option<String>,
}

#[derive(serde::Deserialize, Debug, Clone, PartialEq)]
pub struct HandshakeAnchor {
    pub offset: usize,
    pub bytes: Vec<u8>,
}

/// True if `rule` applies to `transport` ("tcp"/"udp") - rules with no
/// `protocol` set apply to either.
pub fn rule_applies_to(rule: &HandshakeRule, transport: &str) -> bool {
    rule.protocol.as_deref().is_none_or(|p| p == transport)
}

/// True if `payload` matches every anchor (and the exact length, if set) in `rule`.
pub fn matches_handshake(payload: &[u8], rule: &HandshakeRule) -> bool {
    if let Some(len) = rule.length {
        if payload.len() != len {
            return false;
        }
    }
    rule.anchors.iter().all(|a| payload.get(a.offset..a.offset + a.bytes.len()) == Some(a.bytes.as_slice()))
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

    fn wireguard_rule() -> HandshakeRule {
        HandshakeRule {
            name: "wireguard-handshake-init".to_string(),
            length: Some(148),
            anchors: vec![HandshakeAnchor { offset: 0, bytes: vec![1, 0, 0, 0] }],
            protocol: Some("udp".to_string()),
        }
    }

    #[test]
    fn handshake_recognized_by_structure() {
        let mut pkt = vec![0u8; 148];
        pkt[0] = 1; // handshake-initiation type; reserved [1..4] already zero
        assert!(matches_handshake(&pkt, &wireguard_rule()));
    }

    #[test]
    fn wrong_length_not_recognized() {
        let mut pkt = vec![0u8; 100]; // right type, wrong length
        pkt[0] = 1;
        assert!(!matches_handshake(&pkt, &wireguard_rule()));
    }

    #[test]
    fn wrong_type_not_recognized() {
        let pkt = vec![0u8; 148]; // right length, type byte is 0 not 1
        assert!(!matches_handshake(&pkt, &wireguard_rule()));
    }

    #[test]
    fn nonzero_reserved_not_recognized() {
        let mut pkt = vec![0u8; 148];
        pkt[0] = 1;
        pkt[2] = 5; // reserved bytes must be zero
        assert!(!matches_handshake(&pkt, &wireguard_rule()));
    }

    #[test]
    fn rule_with_no_anchors_matches_on_length_alone() {
        let rule = HandshakeRule { name: "any-148-byte-udp".to_string(), length: Some(148), anchors: vec![], protocol: None };
        assert!(matches_handshake(&[0u8; 148], &rule));
        assert!(!matches_handshake(&[0u8; 100], &rule));
    }

    #[test]
    fn ssh_banner_recognized_by_prefix() {
        let rule = HandshakeRule {
            name: "ssh-version-exchange".to_string(),
            length: None,
            anchors: vec![HandshakeAnchor { offset: 0, bytes: b"SSH-".to_vec() }],
            protocol: Some("tcp".to_string()),
        };
        assert!(matches_handshake(b"SSH-2.0-OpenSSH_9.6\r\n", &rule));
        assert!(!matches_handshake(b"GET / HTTP/1.1\r\n", &rule));
    }

    #[test]
    fn rule_applies_to_scopes_by_transport() {
        let udp_only = HandshakeRule { name: "x".to_string(), length: None, anchors: vec![], protocol: Some("udp".to_string()) };
        let either = HandshakeRule { name: "y".to_string(), length: None, anchors: vec![], protocol: None };
        assert!(rule_applies_to(&udp_only, "udp"));
        assert!(!rule_applies_to(&udp_only, "tcp"));
        assert!(rule_applies_to(&either, "udp"));
        assert!(rule_applies_to(&either, "tcp"));
    }

    #[test]
    fn cert_parse_empty_data_returns_none() {
        assert!(parse_tls_certificate_names(&[]).is_none());
    }

    #[test]
    fn cert_parse_no_handshake_record_returns_none() {
        // A record of some other type (e.g. application_data, 0x17) never gets walked.
        let record = [0x17u8, 0x03, 0x03, 0x00, 0x01, 0xff];
        assert!(parse_tls_certificate_names(&record).is_none());
    }

    #[test]
    fn cert_parse_truncated_record_returns_none() {
        // Record header claims 100 bytes of body but only 1 is present.
        let record = [0x16u8, 0x03, 0x03, 0x00, 0x64, 0xff];
        assert!(parse_tls_certificate_names(&record).is_none());
    }

    #[test]
    fn cert_parse_skips_non_certificate_handshake_messages() {
        // A handshake record carrying a ServerHello (type 0x02) only - no
        // Certificate message anywhere - must walk past it and return None,
        // not mistake it for one.
        let server_hello_body = vec![0u8; 40];
        let mut hs_msg = vec![0x02u8]; // ServerHello
        hs_msg.extend_from_slice(&(server_hello_body.len() as u32).to_be_bytes()[1..]); // 3-byte length
        hs_msg.extend_from_slice(&server_hello_body);

        let mut record = vec![0x16u8, 0x03, 0x03];
        record.extend_from_slice(&(hs_msg.len() as u16).to_be_bytes());
        record.extend_from_slice(&hs_msg);

        assert!(parse_tls_certificate_names(&record).is_none());
    }

    #[test]
    fn cert_parse_invalid_der_returns_none_not_panic() {
        // Certificate message located correctly (type 0x0b, framing intact),
        // but the "DER" bytes inside are garbage - must fail closed, not panic.
        let garbage_der = vec![0xffu8; 20];
        let mut cert_entry = vec![0u8, 0u8]; // 3-byte cert length, filled below
        cert_entry = (garbage_der.len() as u32).to_be_bytes()[1..].to_vec();
        cert_entry.extend_from_slice(&garbage_der);

        let mut cert_body = (cert_entry.len() as u32).to_be_bytes()[1..].to_vec(); // cert_list total length
        cert_body.extend_from_slice(&cert_entry);

        let mut hs_msg = vec![0x0bu8]; // Certificate
        hs_msg.extend_from_slice(&(cert_body.len() as u32).to_be_bytes()[1..]);
        hs_msg.extend_from_slice(&cert_body);

        let mut record = vec![0x16u8, 0x03, 0x03];
        record.extend_from_slice(&(hs_msg.len() as u16).to_be_bytes());
        record.extend_from_slice(&hs_msg);

        assert!(parse_tls_certificate_names(&record).is_none());
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

    /// Build a minimal ClientHello record whose only extension is
    /// `supported_versions` (0x002b) listing the given u16 version entries
    /// in order (e.g. GREASE, 0x0304, 0x0303) - same builder shape as
    /// `tls_sni_extraction` above, just parameterized on this one extension.
    fn client_hello_with_supported_versions(versions: &[u16]) -> Vec<u8> {
        let mut entries = Vec::new();
        for v in versions {
            entries.extend_from_slice(&v.to_be_bytes());
        }
        let mut ext_data = vec![entries.len() as u8];
        ext_data.extend_from_slice(&entries);

        let mut ext = vec![0x00, 0x2b]; // extension type = supported_versions
        ext.extend_from_slice(&(ext_data.len() as u16).to_be_bytes());
        ext.extend_from_slice(&ext_data);

        let mut hs = vec![];
        hs.extend_from_slice(&[0x03, 0x03]);
        hs.extend_from_slice(&[0u8; 32]);
        hs.push(0);
        hs.extend_from_slice(&(2u16).to_be_bytes());
        hs.extend_from_slice(&[0x13, 0x01]);
        hs.push(1);
        hs.push(0);
        hs.extend_from_slice(&(ext.len() as u16).to_be_bytes());
        hs.extend_from_slice(&ext);

        let mut handshake = vec![0x01];
        handshake.extend_from_slice(&(hs.len() as u32).to_be_bytes()[1..]);
        handshake.extend_from_slice(&hs);

        let mut record = vec![0x16, 0x03, 0x01];
        record.extend_from_slice(&(handshake.len() as u16).to_be_bytes());
        record.extend_from_slice(&handshake);
        record
    }

    #[test]
    fn downgrade_strips_tls13_leaves_grease_and_length_fields_untouched() {
        let mut record = client_hello_with_supported_versions(&[0x0a0a, 0x0304, 0x0303]);
        let before = record.clone();
        assert!(mangle_supported_versions_in_place(&mut record));
        assert_eq!(record.len(), before.len()); // no length field anywhere changed

        // Only the 0x0304 entry's low byte flips; everything else - including
        // the GREASE entry right next to it - is byte-for-byte identical.
        let mut expected = before.clone();
        let flip_at = expected.windows(2).position(|w| w == [0x03, 0x04]).unwrap();
        expected[flip_at + 1] = 0x03;
        assert_eq!(record, expected);

        assert_eq!(parse_client_hello(&record).unwrap().sni, None); // still a valid, parseable ClientHello
    }

    #[test]
    fn downgrade_noop_when_no_tls13_offered() {
        let mut record = client_hello_with_supported_versions(&[0x0303, 0x0302]);
        let before = record.clone();
        assert!(!mangle_supported_versions_in_place(&mut record));
        assert_eq!(record, before);
    }

    #[test]
    fn downgrade_noop_on_non_client_hello() {
        let mut data = b"GET / HTTP/1.1\r\n".to_vec();
        let before = data.clone();
        assert!(!mangle_supported_versions_in_place(&mut data));
        assert_eq!(data, before);
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

    fn build_server_hello(version: u16, cipher_suite: u16, ext_types: &[u16]) -> Vec<u8> {
        let mut ext = vec![];
        for &t in ext_types {
            ext.extend_from_slice(&t.to_be_bytes());
            ext.extend_from_slice(&0u16.to_be_bytes()); // empty extension data, fine for JA3S (only types matter)
        }

        let mut hs = vec![];
        hs.extend_from_slice(&version.to_be_bytes());
        hs.extend_from_slice(&[0u8; 32]);
        hs.push(0); // session_id_len
        hs.extend_from_slice(&cipher_suite.to_be_bytes());
        hs.push(0); // compression_method
        hs.extend_from_slice(&(ext.len() as u16).to_be_bytes());
        hs.extend_from_slice(&ext);

        let mut handshake = vec![0x02]; // ServerHello
        handshake.extend_from_slice(&(hs.len() as u32).to_be_bytes()[1..]);
        handshake.extend_from_slice(&hs);

        let mut record = vec![0x16, 0x03, 0x03];
        record.extend_from_slice(&(handshake.len() as u16).to_be_bytes());
        record.extend_from_slice(&handshake);
        record
    }

    #[test]
    fn ja3s_extracts_version_cipher_and_extensions_strips_grease() {
        let record = build_server_hello(0x0303, 0x1301, &[0x0a0a, 0x0000, 0x002b]); // GREASE + server_name + supported_versions
        let (ja3s_string, hash) = ja3s(&record).unwrap();
        assert_eq!(ja3s_string, "771,4865,0-43"); // GREASE stripped, 0x002b=43
        assert_eq!(hash.len(), 32);
    }

    #[test]
    fn ja3s_rejects_client_hello() {
        // A ServerHello parser must not accept a ClientHello (handshake type
        // 0x01, not 0x02) even though the record framing looks the same.
        let record = client_hello_with_supported_versions(&[0x0304]);
        assert!(parse_server_hello(&record).is_none());
        assert!(ja3s(&record).is_none());
    }

    /// Build a ClientHello with all the extensions JA4 reads: SNI (so
    /// sni_flag="d"), two real ciphers + one GREASE, ALPN "h2", one
    /// signature_algorithms entry, and supported_versions offering TLS 1.3.
    fn build_ja4_client_hello() -> Vec<u8> {
        let sni_ext = {
            let mut list = vec![0u8]; // name_type = host_name
            let host = b"example.com";
            list.extend_from_slice(&(host.len() as u16).to_be_bytes());
            list.extend_from_slice(host);
            let mut d = (list.len() as u16).to_be_bytes().to_vec();
            d.extend_from_slice(&list);
            d
        };
        let alpn_ext = {
            let mut list = vec![2u8]; // len("h2")
            list.extend_from_slice(b"h2");
            let mut d = (list.len() as u16).to_be_bytes().to_vec();
            d.extend_from_slice(&list);
            d
        };
        let sig_algs_ext = {
            let entries: Vec<u8> = [0x0403u16].iter().flat_map(|v| v.to_be_bytes()).collect(); // ecdsa_secp256r1_sha256
            let mut d = (entries.len() as u16).to_be_bytes().to_vec();
            d.extend_from_slice(&entries);
            d
        };
        let sv_ext = {
            let entries: Vec<u8> = [0x0a0au16, 0x0304].iter().flat_map(|v| v.to_be_bytes()).collect(); // GREASE + TLS 1.3
            let mut d = vec![entries.len() as u8];
            d.extend_from_slice(&entries);
            d
        };

        let mut ext = vec![];
        for (t, data) in [(0x0000u16, &sni_ext), (0x0010, &alpn_ext), (0x000d, &sig_algs_ext), (0x002b, &sv_ext)] {
            ext.extend_from_slice(&t.to_be_bytes());
            ext.extend_from_slice(&(data.len() as u16).to_be_bytes());
            ext.extend_from_slice(data);
        }

        let mut hs = vec![0x03, 0x03]; // legacy version - real 1.3 signal is in supported_versions
        hs.extend_from_slice(&[0u8; 32]);
        hs.push(0);
        let ciphers = [0x0a0au16, 0x1301, 0x1302]; // GREASE + two real ciphers
        let cipher_bytes: Vec<u8> = ciphers.iter().flat_map(|v| v.to_be_bytes()).collect();
        hs.extend_from_slice(&(cipher_bytes.len() as u16).to_be_bytes());
        hs.extend_from_slice(&cipher_bytes);
        hs.push(1);
        hs.push(0);
        hs.extend_from_slice(&(ext.len() as u16).to_be_bytes());
        hs.extend_from_slice(&ext);

        let mut handshake = vec![0x01];
        handshake.extend_from_slice(&(hs.len() as u32).to_be_bytes()[1..]);
        handshake.extend_from_slice(&hs);

        let mut record = vec![0x16, 0x03, 0x01];
        record.extend_from_slice(&(handshake.len() as u16).to_be_bytes());
        record.extend_from_slice(&handshake);
        record
    }

    #[test]
    fn ja4_uses_supported_versions_not_legacy_field_for_tls13() {
        let record = build_ja4_client_hello();
        let fp = ja4(&record).unwrap();
        // t=TCP, 13=TLS1.3 (from supported_versions, not the 0x0303 legacy
        // field), d=SNI present, 02 ciphers, 04 extensions, h2 ALPN.
        assert!(fp.starts_with("t13d0204h2_"), "got {fp}");
        let parts: Vec<&str> = fp.split('_').collect();
        assert_eq!(parts.len(), 3);
        assert_eq!(parts[1].len(), 12); // truncated sha256 hex
        assert_eq!(parts[2].len(), 12);
    }

    #[test]
    fn ja4_no_sni_flags_i_and_no_alpn_is_00() {
        // Minimal ClientHello with none of JA4's optional extensions.
        let mut hs = vec![0x03, 0x03];
        hs.extend_from_slice(&[0u8; 32]);
        hs.push(0);
        hs.extend_from_slice(&2u16.to_be_bytes());
        hs.extend_from_slice(&[0x13, 0x01]);
        hs.push(1);
        hs.push(0);
        hs.extend_from_slice(&0u16.to_be_bytes()); // no extensions at all

        let mut handshake = vec![0x01];
        handshake.extend_from_slice(&(hs.len() as u32).to_be_bytes()[1..]);
        handshake.extend_from_slice(&hs);
        let mut record = vec![0x16, 0x03, 0x01];
        record.extend_from_slice(&(handshake.len() as u16).to_be_bytes());
        record.extend_from_slice(&handshake);

        let fp = ja4(&record).unwrap();
        assert!(fp.starts_with("t12i010000_"), "got {fp}"); // no supported_versions -> legacy 0x0303 -> "12"; no ALPN -> "00"
    }

    #[test]
    fn ech_extension_detected_even_without_readable_sni() {
        // ECH extension (0xfe0d, empty payload for this test - contents are
        // opaque anyway) with no server_name extension present at all: this
        // is exactly what a real ECH ClientHello's outer half looks like to
        // an observer that can't decrypt it.
        let mut ext = vec![];
        ext.extend_from_slice(&0xfe0du16.to_be_bytes());
        ext.extend_from_slice(&0u16.to_be_bytes());

        let mut hs = vec![0x03, 0x03];
        hs.extend_from_slice(&[0u8; 32]);
        hs.push(0); // session_id_len
        hs.extend_from_slice(&2u16.to_be_bytes());
        hs.extend_from_slice(&[0x13, 0x01]);
        hs.push(1);
        hs.push(0);
        hs.extend_from_slice(&(ext.len() as u16).to_be_bytes());
        hs.extend_from_slice(&ext);

        let mut handshake = vec![0x01];
        handshake.extend_from_slice(&(hs.len() as u32).to_be_bytes()[1..]);
        handshake.extend_from_slice(&hs);

        let mut record = vec![0x16, 0x03, 0x01];
        record.extend_from_slice(&(handshake.len() as u16).to_be_bytes());
        record.extend_from_slice(&handshake);

        let ch = parse_client_hello(&record).unwrap();
        assert!(ch.has_ech);
        assert!(ch.sni.is_none());
    }

    #[test]
    fn no_ech_extension_not_flagged() {
        assert!(!parse_client_hello(b"").is_some_and(|ch| ch.has_ech)); // trivially false, real coverage is in earlier SNI tests
    }

    #[test]
    fn http_host_header_extracted() {
        let req = b"GET /path HTTP/1.1\r\nHost: evil.com\r\nUser-Agent: curl\r\n\r\n";
        assert_eq!(parse_http_host(req).unwrap(), "evil.com");
    }

    #[test]
    fn http_host_header_case_insensitive() {
        let req = b"GET / HTTP/1.1\r\nhost: evil.com\r\n\r\n";
        assert_eq!(parse_http_host(req).unwrap(), "evil.com");
    }

    #[test]
    fn http_host_ignores_header_lookalike_in_body() {
        let req = b"POST / HTTP/1.1\r\nHost: real.com\r\n\r\nHost: fake.com\r\n";
        assert_eq!(parse_http_host(req).unwrap(), "real.com");
    }

    #[test]
    fn http_host_missing_returns_none() {
        assert!(parse_http_host(b"GET / HTTP/1.1\r\n\r\n").is_none());
    }

    #[test]
    fn request_line_extracts_path_and_decoded_query() {
        let (path, query) = parse_http_request_line(b"GET /search?q=blocked+term HTTP/1.1\r\nHost: example.com\r\n\r\n").unwrap();
        assert_eq!(path, "/search");
        assert_eq!(query, "q=blocked term");
    }

    #[test]
    fn request_line_percent_decodes_special_characters() {
        let (_, query) = parse_http_request_line(b"GET /search?q=100%25%20blocked HTTP/1.1\r\n\r\n").unwrap();
        assert_eq!(query, "q=100% blocked");
    }

    #[test]
    fn request_line_no_query_is_empty_string_not_none() {
        let (path, query) = parse_http_request_line(b"GET /index.html HTTP/1.1\r\n\r\n").unwrap();
        assert_eq!(path, "/index.html");
        assert_eq!(query, "");
    }

    #[test]
    fn request_line_malformed_percent_escape_kept_literal() {
        // "%zz" isn't valid hex - passed through byte-for-byte rather than
        // dropped or erroring the whole query out.
        let (_, query) = parse_http_request_line(b"GET /x?a=%zz HTTP/1.1\r\n\r\n").unwrap();
        assert_eq!(query, "a=%zz");
    }

    #[test]
    fn request_line_missing_or_malformed_is_none() {
        assert!(parse_http_request_line(b"not an http request at all").is_none());
        assert!(parse_http_request_line(b"").is_none());
    }
}
