// Transparent TLS-intercepting MITM proxy - the only way to apply keyword
// censorship to HTTPS (engine.rs's [url-keyword] only ever sees plaintext
// HTTP; a TLS ClientHello exposes SNI, nothing past it). This actually
// terminates TLS in the middle: present a locally-signed leaf cert to the
// client, decrypt, scan the request with the same `classify::Signatures`
// config/signatures.yml already feeds the plaintext-HTTP path, re-encrypt
// to the real origin.
//
// Two enforcement points once decrypted: a match in the *request* (path,
// query, or h2 :path) kills the connection outright ([mitm-keyword], see
// `handle_conn`). A match in the *response body* gets redacted in place
// instead - same-length byte overwrite, so Content-Length/chunk-size
// headers never need touching - and the (otherwise unmodified) response is
// still forwarded ([mitm-redact], see `redact_first_response`). HTTP/1.1
// only for the response side (h2 response rewriting would need re-encoding
// through HPACK/frame boundaries, not built); h2 requests still get the
// request-side block/allow decision.
//
// Two backends behind the same public API (`setup`/`teardown`/`original_dst`),
// same split as throttle.rs/lockdown.rs: Linux uses TPROXY (nftables
// `tproxy to` + policy routing + IP_TRANSPARENT), macOS uses PF `rdr-to` +
// a DIOCNATLOOK ioctl against /dev/pf to recover the pre-NAT destination
// (TPROXY has no macOS equivalent; rdr-to rewrites the destination before
// delivery, unlike TPROXY which preserves it). Both require this machine to
// actually be the network's gateway (IP forwarding enabled, other devices
// routed through it) - same precondition inline.rs already documents for
// the Linux NFQUEUE path.
//
// SECURITY: the CA private key loaded here can mint a trusted certificate
// for *any* hostname, not just the ones in config/mitm_domains.yml - treat
// it like any other real secret (root-only file perms, never committed).
// Only ever intercepts hosts in that explicit allow-list, same "own lab
// only" framing as cannon.rs/probe.rs/config/probe_targets.yml.
use crate::classify::{self, Signatures};
use rcgen::{CertificateParams, Issuer, KeyPair};
use rustls::pki_types::{PrivateKeyDer, PrivatePkcs8KeyDer, ServerName};
use std::collections::HashMap;
use std::io::{Read, Write};
use std::net::{SocketAddr, TcpStream};
use std::path::PathBuf;
use std::sync::{Arc, Mutex};

/// Cap on how many bytes we'll read while peeking a ClientHello or the
/// decrypted first HTTP request - same reasoning/value as engine.rs's
/// CLIENTHELLO_CAP: give up rather than buffer an unbounded stream.
const PEEK_CAP: usize = 4096;

pub struct MitmConfig {
    pub intercept_domains: Vec<String>,
    pub sigs: Signatures,
    pub ca_cert_path: PathBuf,
    pub ca_key_path: PathBuf,
    pub listen_port: u16,
    pub iface: String,
}

/// Loaded CA + a cache of leaf certs already issued this run, keyed by SNI -
/// signing a cert is real asymmetric crypto work, not worth repeating for
/// every connection to the same intercepted host.
struct CertIssuer {
    issuer: Issuer<'static, KeyPair>,
    cache: Mutex<HashMap<String, Arc<rustls::ServerConfig>>>,
}

impl CertIssuer {
    fn load(cert_path: &std::path::Path, key_path: &std::path::Path) -> std::io::Result<Self> {
        let ca_cert_pem = std::fs::read_to_string(cert_path)?;
        let ca_key_pem = std::fs::read_to_string(key_path)?;
        let ca_key = KeyPair::from_pem(&ca_key_pem).map_err(std::io::Error::other)?;
        let issuer = Issuer::from_ca_cert_pem(&ca_cert_pem, ca_key).map_err(std::io::Error::other)?;
        Ok(Self { issuer, cache: Mutex::new(HashMap::new()) })
    }

    /// Get (or generate + sign + cache) a single-cert `ServerConfig` for `sni`.
    fn server_config_for(&self, sni: &str) -> std::io::Result<Arc<rustls::ServerConfig>> {
        if let Some(cfg) = self.cache.lock().unwrap().get(sni) {
            return Ok(cfg.clone());
        }
        let leaf_key = KeyPair::generate().map_err(std::io::Error::other)?;
        let params = CertificateParams::new(vec![sni.to_string()]).map_err(std::io::Error::other)?;
        let cert = params.signed_by(&leaf_key, &self.issuer).map_err(std::io::Error::other)?;
        let cert_der = cert.der().clone();
        let key_der = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(leaf_key.serialize_der()));

        let mut server_config = rustls::ServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(vec![cert_der], key_der)
            .map_err(std::io::Error::other)?;
        // Offer both - most real browsers (Chrome to Google included)
        // negotiate h2 given the chance, and forcing http/1.1-only just
        // means a modern client behaves differently than it would in the
        // real world instead of actually getting inspected. See
        // h2::extract_path (reused from the passive-capture [host] path)
        // for how the request line gets read back out of h2 framing.
        server_config.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];

        let cfg = Arc::new(server_config);
        self.cache.lock().unwrap().insert(sni.to_string(), cfg.clone());
        Ok(cfg)
    }
}

fn upstream_client_config() -> Arc<rustls::ClientConfig> {
    let root_store = rustls::RootCertStore { roots: webpki_roots::TLS_SERVER_ROOTS.to_vec() };
    let mut cfg = rustls::ClientConfig::builder().with_root_certificates(root_store).with_no_client_auth();
    cfg.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];
    Arc::new(cfg)
}

/// Run the MITM listener. Blocks forever - own top-level `--mitm` mode,
/// independent of --inline/NFQUEUE (this is TPROXY/pf-rdr's own
/// interception mechanism, doesn't need the packet-classify queue running
/// too).
pub fn run(config: MitmConfig) -> std::io::Result<()> {
    // Process-wide crypto provider - rustls 0.23 requires one be installed
    // before building any ServerConfig/ClientConfig. `ring` (not aws-lc-rs)
    // to match the `ring` crate this project already depends on elsewhere.
    let _ = rustls::crypto::ring::default_provider().install_default();

    backend::setup(config.listen_port, &config.iface)?;
    log::info!("[mitm] listening on :{} (iface {})", config.listen_port, config.iface);

    let issuer = Arc::new(CertIssuer::load(&config.ca_cert_path, &config.ca_key_path)?);
    let client_config = upstream_client_config();
    let intercept_domains = Arc::new(config.intercept_domains);
    let sigs = Arc::new(config.sigs);

    let listener = backend::bind(config.listen_port)?;
    for conn in listener.incoming() {
        let conn = match conn {
            Ok(c) => c,
            Err(e) => {
                log::warn!("[mitm] accept error: {e}");
                continue;
            }
        };
        let issuer = issuer.clone();
        let client_config = client_config.clone();
        let intercept_domains = intercept_domains.clone();
        let sigs = sigs.clone();
        std::thread::spawn(move || {
            if let Err(e) = handle_conn(conn, &issuer, &client_config, &intercept_domains, &sigs) {
                log::debug!("[mitm] connection error: {e}");
            }
        });
    }
    Ok(())
}

pub fn teardown() {
    backend::teardown();
}

/// Pure decision, split out for unit testing: only ever intercept an SNI
/// that's a literal entry in `config/mitm_domains.yml` - anything else
/// (including a ClientHello we failed to peek/parse) blind-relays.
fn should_intercept(sni: Option<&str>, intercept_domains: &[String]) -> bool {
    sni.is_some_and(|s| intercept_domains.iter().any(|d| d == s))
}

fn handle_conn(
    conn: TcpStream,
    issuer: &CertIssuer,
    client_config: &Arc<rustls::ClientConfig>,
    intercept_domains: &[String],
    sigs: &Signatures,
) -> std::io::Result<()> {
    let original_dst = backend::original_dst(&conn)?;

    // Peek (non-consuming) until we can parse a whole ClientHello or give
    // up - a short first read is possible if the client's ClientHello
    // segments across multiple TCP packets.
    let mut peek_buf = vec![0u8; PEEK_CAP];
    let mut sni = None;
    for _ in 0..20 {
        let n = conn.peek(&mut peek_buf)?;
        if let Some(ch) = classify::parse_client_hello(&peek_buf[..n]) {
            sni = ch.sni;
            break;
        }
        if n >= PEEK_CAP {
            break; // gave up - not a (whole) TLS ClientHello in the cap
        }
        std::thread::sleep(std::time::Duration::from_millis(5));
    }

    if !should_intercept(sni.as_deref(), intercept_domains) {
        return blind_relay(conn, original_dst);
    }
    let sni = sni.unwrap();
    log::info!("[mitm] intercepting {sni} ({original_dst})");

    let server_config = issuer.server_config_for(&sni)?;
    let mut server_conn = rustls::ServerConnection::new(server_config).map_err(std::io::Error::other)?;
    let mut client_sock = conn;

    // Dial the real origin (the domain the client actually asked for, not
    // `original_dst` - that's this box's own address post-rdr/tproxy).
    let server_name = ServerName::try_from(sni.clone()).map_err(std::io::Error::other)?;
    let mut upstream_sock = TcpStream::connect((sni.as_str(), 443))?;
    let mut upstream_conn = rustls::ClientConnection::new(client_config.clone(), server_name).map_err(std::io::Error::other)?;

    // First request only: read until we can parse a request line (or give
    // up at PEEK_CAP), scan it, then decide once - mirrors engine.rs's
    // [url-keyword]/[host] pattern of checking once per flow, not forever.
    // Blocking reads here are fine (no concurrency needed yet): the client
    // sends its request before either side has anything else to say.
    let mut buf = Vec::new();
    let mut chunk = [0u8; 512];
    let (path, blocked_on, is_h2) = loop {
        let n = rustls::Stream::new(&mut server_conn, &mut client_sock).read(&mut chunk)?;
        if n == 0 {
            return Ok(()); // client closed before a full request line arrived
        }
        buf.extend_from_slice(&chunk[..n]);
        if let Some((path, query)) = classify::parse_http_request_line(&buf) {
            let hit = sigs.matches(&buf).into_iter().next().or_else(|| sigs.matches(query.as_bytes()).into_iter().next());
            break (path, hit.map(str::to_string), false);
        }
        // h2::extract_path (reused from the passive-capture [host] path)
        // handles the HTTP/2 case - :path already carries the full
        // target including any query string, no separate split needed.
        if let Some(path) = crate::h2::extract_path(&buf) {
            let hit = sigs.matches(&buf).into_iter().next().or_else(|| sigs.matches(path.as_bytes()).into_iter().next());
            break (path, hit.map(str::to_string), true);
        }
        if buf.len() >= PEEK_CAP {
            break (String::new(), None, false); // neither parsed (or too large) - relay as-is
        }
    };

    if let Some(hit) = blocked_on {
        log::info!("[mitm-keyword] {hit} in https://{sni}{path}");
        // h2 framing can't take a raw HTTP/1.1 text response - just close;
        // http/1.1 gets a real 403 the client can render.
        if !is_h2 {
            let _ = rustls::Stream::new(&mut server_conn, &mut client_sock).write_all(
                b"HTTP/1.1 403 Forbidden\r\nContent-Type: text/plain\r\nConnection: close\r\n\r\nBlocked.\n",
            );
        }
        return Ok(());
    }

    // Response filtering (redact matched keywords in the body instead of
    // killing the whole request) is HTTP/1.1-only for now - h2 response
    // bodies would need re-encoding through HPACK/frame boundaries the
    // same way a rewritten h2 request would, not built. h2 still gets the
    // old block-the-whole-request treatment above; only relay_tls handles
    // it from here on.
    if !is_h2 {
        force_identity_encoding(&mut buf);
        rustls::Stream::new(&mut upstream_conn, &mut upstream_sock).write_all(&buf)?;
        redact_first_response(&sni, sigs, &mut upstream_conn, &mut upstream_sock, &mut server_conn, &mut client_sock)?;
    } else {
        rustls::Stream::new(&mut upstream_conn, &mut upstream_sock).write_all(&buf)?;
    }
    relay_tls(&mut server_conn, &mut client_sock, &mut upstream_conn, &mut upstream_sock)
}

/// Force the upstream request to ask for an uncompressed response. Simpler
/// and far more robust than decompressing gzip/br ourselves just to redact
/// a keyword and re-compress it: replaces (or adds) `Accept-Encoding:
/// identity` in the request's header block. A server that ignores this and
/// compresses anyway just means redaction silently finds nothing to do -
/// no crash, no corrupted response, see `redact_first_response`'s doc
/// comment on how the caller stays safe either way.
fn force_identity_encoding(buf: &mut Vec<u8>) {
    let Ok(text) = std::str::from_utf8(buf) else { return };
    let Some(head_end) = text.find("\r\n\r\n") else { return };
    let (head, rest) = text.split_at(head_end);
    let mut lines: Vec<&str> = head.split("\r\n").collect();
    let existing = lines.iter().position(|l| l.to_ascii_lowercase().starts_with("accept-encoding:"));
    match existing {
        Some(i) => lines[i] = "Accept-Encoding: identity",
        None => lines.push("Accept-Encoding: identity"),
    }
    *buf = format!("{}{}", lines.join("\r\n"), rest).into_bytes();
}

/// Ceiling on how much of a response body gets buffered for redaction -
/// past this, relay the rest through unredacted rather than hold an
/// unbounded amount of memory per connection. 4 MiB comfortably covers a
/// search-results page; a multi-megabyte download just keeps its tail
/// uninspected instead of stalling the proxy.
const RESPONSE_BODY_CAP: usize = 4 * 1024 * 1024;

/// Read the first HTTP/1.1 response, redact any `Signatures` hit in the
/// body (same-length in-place byte overwrite - keeps Content-Length and
/// every chunk-size header valid with zero rewriting), forward it to the
/// client, log a `[mitm-redact]` line per hit. Falls back to relaying
/// whatever it read completely unmodified on anything it doesn't
/// understand (no Content-Length/chunked framing, a body past
/// RESPONSE_BODY_CAP, non-UTF8 headers, ...) - never blocks or corrupts a
/// response it can't safely redact.
fn redact_first_response(
    sni: &str,
    sigs: &Signatures,
    upstream_conn: &mut rustls::ClientConnection,
    upstream_sock: &mut TcpStream,
    client_conn: &mut rustls::ServerConnection,
    client_sock: &mut TcpStream,
) -> std::io::Result<()> {
    let mut head_buf = Vec::new();
    let mut chunk = [0u8; 512];
    let (status, headers, head_len) = loop {
        let n = rustls::Stream::new(upstream_conn, upstream_sock).read(&mut chunk)?;
        if n == 0 {
            // Upstream closed before headers finished - nothing to redact,
            // forward whatever fragment we got and stop.
            rustls::Stream::new(client_conn, client_sock).write_all(&head_buf)?;
            return Ok(());
        }
        head_buf.extend_from_slice(&chunk[..n]);
        if let Some(parsed) = classify::parse_http_response_head(&head_buf) {
            break parsed;
        }
        if head_buf.len() >= PEEK_CAP {
            rustls::Stream::new(client_conn, client_sock).write_all(&head_buf)?;
            return Ok(()); // headers too large or not HTTP/1.1 - relay raw, don't hold it up
        }
    };

    let content_length = headers.iter().find(|(k, _)| k.eq_ignore_ascii_case("content-length")).and_then(|(_, v)| v.parse::<usize>().ok());
    let chunked = headers.iter().any(|(k, v)| k.eq_ignore_ascii_case("transfer-encoding") && v.eq_ignore_ascii_case("chunked"));
    let mut client_tls = rustls::Stream::new(client_conn, client_sock);
    client_tls.write_all(&head_buf[..head_len])?; // status line + headers, unchanged either way

    let already_read_body = &head_buf[head_len..];
    match (status, content_length, chunked) {
        (204 | 304, _, _) => {} // no body by definition (RFC 9110 §6.4.1) - nothing left to read/write
        (_, Some(len), _) if len <= RESPONSE_BODY_CAP => {
            let mut body = already_read_body.to_vec();
            read_exact_from_tls(upstream_conn, upstream_sock, &mut body, len)?;
            let hits = redact_in_place(&mut body, sigs);
            for hit in hits {
                log::info!("[mitm-redact] {hit} in https://{sni} response body");
            }
            client_tls.write_all(&body)?;
        }
        (_, _, true) => redact_chunked_body(sni, sigs, upstream_conn, upstream_sock, &mut client_tls, already_read_body)?,
        _ => {
            // No Content-Length, not chunked: connection-close-delimited
            // (or a length too large to buffer) - relay the rest raw.
            client_tls.write_all(already_read_body)?;
            std::io::copy(&mut rustls::Stream::new(upstream_conn, upstream_sock), &mut client_tls)?;
        }
    }
    Ok(())
}

/// Read exactly `len` more body bytes (on top of whatever's already in
/// `body` from the initial header read) via a fresh short-lived `Stream`
/// each call - matches this file's existing pattern of constructing one
/// per read/write rather than holding it across the whole function.
fn read_exact_from_tls(conn: &mut rustls::ClientConnection, sock: &mut TcpStream, body: &mut Vec<u8>, len: usize) -> std::io::Result<()> {
    let mut chunk = [0u8; 4096];
    while body.len() < len {
        let n = rustls::Stream::new(conn, sock).read(&mut chunk)?;
        if n == 0 {
            break; // upstream closed early - redact/forward whatever arrived
        }
        body.extend_from_slice(&chunk[..n]);
    }
    body.truncate(len.min(body.len()));
    Ok(())
}

/// Redact every `Signatures` hit in `buf` by overwriting the matched bytes
/// with `*`, in place - same length in, same length out, so nothing else
/// about the surrounding response (Content-Length, chunk-size headers)
/// needs adjusting. Returns the hit pattern names for logging.
fn redact_in_place(buf: &mut [u8], sigs: &Signatures) -> Vec<String> {
    let hits = sigs.find_matches(buf);
    let names = hits.iter().map(|(_, _, name)| name.to_string()).collect();
    for (start, end, _) in hits {
        buf[start..end].fill(b'*');
    }
    names
}

/// Stream a `Transfer-Encoding: chunked` body chunk by chunk, redacting
/// each chunk's payload independently and forwarding its size header
/// unchanged (redaction never changes length). A keyword split across a
/// chunk boundary is missed - documented limitation, not a crash risk;
/// matches this codebase's existing "give up gracefully, don't block
/// traffic you can't fully inspect" ethos (e.g. inline.rs's own
/// per-packet-only scope note).
fn redact_chunked_body(
    sni: &str,
    sigs: &Signatures,
    upstream_conn: &mut rustls::ClientConnection,
    upstream_sock: &mut TcpStream,
    client_tls: &mut rustls::Stream<'_, rustls::ServerConnection, TcpStream>,
    already_read: &[u8],
) -> std::io::Result<()> {
    let mut buf = already_read.to_vec();
    loop {
        // Chunk size line: hex digits up to \r\n (ignore any chunk
        // extensions after ';' - RFC 9112 §7.1.1, no proxy needs to act on them).
        let size_end = loop {
            if let Some(pos) = find_crlf(&buf) {
                break pos;
            }
            if !fill(upstream_conn, upstream_sock, &mut buf)? {
                return Ok(()); // upstream closed mid chunk-size line
            }
        };
        let size_line = std::str::from_utf8(&buf[..size_end]).unwrap_or("");
        let size_hex = size_line.split(';').next().unwrap_or("").trim();
        let Ok(size) = usize::from_str_radix(size_hex, 16) else {
            client_tls.write_all(&buf)?; // malformed - forward raw and stop trying to parse further
            return Ok(());
        };
        while buf.len() < size_end + 2 + size + 2 {
            if !fill(upstream_conn, upstream_sock, &mut buf)? {
                client_tls.write_all(&buf)?;
                return Ok(());
            }
        }
        let chunk_start = size_end + 2;
        let mut chunk_data = buf[chunk_start..chunk_start + size].to_vec();
        let hits = redact_in_place(&mut chunk_data, sigs);
        for hit in hits {
            log::info!("[mitm-redact] {hit} in https://{sni} response body");
        }
        client_tls.write_all(&buf[..chunk_start])?; // size line + CRLF, unchanged
        client_tls.write_all(&chunk_data)?;
        client_tls.write_all(b"\r\n")?;
        let consumed = chunk_start + size + 2;
        if size == 0 {
            // Last chunk - trailer headers + final CRLF may follow; not
            // scanned (empty/near-empty by convention), just relayed.
            client_tls.write_all(&buf[consumed..])?;
            return Ok(());
        }
        buf.drain(..consumed);
    }
}

fn find_crlf(buf: &[u8]) -> Option<usize> {
    buf.windows(2).position(|w| w == b"\r\n")
}

fn fill(conn: &mut rustls::ClientConnection, sock: &mut TcpStream, buf: &mut Vec<u8>) -> std::io::Result<bool> {
    let mut chunk = [0u8; 4096];
    let n = rustls::Stream::new(conn, sock).read(&mut chunk)?;
    if n == 0 {
        return Ok(false);
    }
    buf.extend_from_slice(&chunk[..n]);
    Ok(true)
}

/// Splice the rest of an intercepted TLS session bidirectionally.
///
/// ponytail: rustls's sync `Stream`/`StreamOwned` need `&mut` on the shared
/// `Connection` for both directions - can't split into independent
/// concurrently-readable halves the way a raw socket clones. Rather than
/// pull in an async runtime + non-blocking rustls plumbing for a lab
/// keyword-censorship proxy, this alternates directions on one thread with
/// a short read timeout on the underlying sockets (WouldBlock/TimedOut = no
/// data yet on that side right now, try the other one). Adds up to ~50ms of
/// direction-switch latency; upgrade to non-blocking + mio if that ever
/// matters for a real deployment.
fn relay_tls(
    client_conn: &mut rustls::ServerConnection,
    client_sock: &mut TcpStream,
    upstream_conn: &mut rustls::ClientConnection,
    upstream_sock: &mut TcpStream,
) -> std::io::Result<()> {
    let timeout = Some(std::time::Duration::from_millis(50));
    client_sock.set_read_timeout(timeout)?;
    upstream_sock.set_read_timeout(timeout)?;
    let mut buf = [0u8; 8192];
    loop {
        let mut progressed = false;
        match rustls::Stream::new(client_conn, client_sock).read(&mut buf) {
            Ok(0) => return Ok(()),
            Ok(n) => {
                rustls::Stream::new(upstream_conn, upstream_sock).write_all(&buf[..n])?;
                progressed = true;
            }
            Err(e) if would_block(&e) => {}
            Err(e) => return Err(e),
        }
        match rustls::Stream::new(upstream_conn, upstream_sock).read(&mut buf) {
            Ok(0) => return Ok(()),
            Ok(n) => {
                rustls::Stream::new(client_conn, client_sock).write_all(&buf[..n])?;
                progressed = true;
            }
            Err(e) if would_block(&e) => {}
            Err(e) => return Err(e),
        }
        if !progressed {
            std::thread::sleep(std::time::Duration::from_millis(5));
        }
    }
}

fn would_block(e: &std::io::Error) -> bool {
    matches!(e.kind(), std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut)
}

/// Not in `config/mitm_domains.yml` - dial the real destination and splice
/// raw bytes both ways, untouched. No TLS termination, no cert involved.
/// Plain sockets (unlike the TLS case above) clone cheaply into two
/// independent handles, so this stays genuinely concurrent on two threads.
fn blind_relay(client: TcpStream, original_dst: SocketAddr) -> std::io::Result<()> {
    let upstream = TcpStream::connect(original_dst)?;
    let mut c_out = client.try_clone()?;
    let mut u_out = upstream.try_clone()?;
    let mut c_in = client;
    let mut u_in = upstream;
    std::thread::scope(|scope| {
        scope.spawn(|| {
            let _ = std::io::copy(&mut c_in, &mut u_out);
        });
        let _ = std::io::copy(&mut u_in, &mut c_out);
    });
    Ok(())
}

#[cfg(target_os = "linux")]
mod backend {
    use std::io::Write as _;
    use std::mem::size_of;
    use std::net::{SocketAddr, TcpListener, TcpStream};
    use std::os::unix::io::FromRawFd;
    use std::process::Command;

    const NFT_TABLE: &str = "dpi-lab-mitm";
    const FWMARK: u32 = 0x1;
    const RT_TABLE: u32 = 100;
    // Not exposed by every libc version for every target - defined locally
    // per <linux/in.h> rather than depending on it being present.
    const IP_TRANSPARENT: libc::c_int = 19;

    pub fn setup(port: u16, iface: &str) -> std::io::Result<()> {
        let _ = Command::new("nft").args(["delete", "table", "inet", NFT_TABLE]).status();
        let rule = format!(
            "table inet {NFT_TABLE} {{ chain prerouting {{ type filter hook prerouting priority -150; \
             meta l4proto tcp th dport 443 iifname \"{iface}\" meta mark set {FWMARK} tproxy to :{port} \
             }} }}"
        );
        let status = Command::new("nft").args(["-f", "-"]).stdin(std::process::Stdio::piped()).spawn().and_then(|mut child| {
            child.stdin.take().unwrap().write_all(rule.as_bytes())?;
            child.wait()
        })?;
        if !status.success() {
            return Err(std::io::Error::other("nft failed to load MITM tproxy table"));
        }
        // Idempotent-ish: ignore "already exists" from a second setup() call
        // in the same run, same style as throttle.rs's Linux backend.
        let _ = Command::new("ip").args(["rule", "add", "fwmark", &FWMARK.to_string(), "lookup", &RT_TABLE.to_string()]).status();
        let _ = Command::new("ip").args(["route", "add", "local", "0.0.0.0/0", "dev", "lo", "table", &RT_TABLE.to_string()]).status();
        Ok(())
    }

    pub fn teardown() {
        let result = Command::new("nft").args(["delete", "table", "inet", NFT_TABLE]).status();
        match result {
            Ok(status) if status.success() => log::info!("[mitm] cleared nft table"),
            _ => log::error!("[mitm] failed to clear nft table - check manually: sudo nft delete table inet {NFT_TABLE}"),
        }
        let _ = Command::new("ip").args(["rule", "del", "fwmark", &FWMARK.to_string(), "lookup", &RT_TABLE.to_string()]).status();
    }

    /// TPROXY sockets need `IP_TRANSPARENT` set *before* bind - std's
    /// `TcpListener` has no hook for that, so build the socket by hand with
    /// raw libc calls (same low-level style inject.rs/redirect.rs already
    /// use for IPV6_HDRINCL) and hand the fd to `TcpListener::from_raw_fd`.
    pub fn bind(port: u16) -> std::io::Result<TcpListener> {
        unsafe {
            let fd = libc::socket(libc::AF_INET, libc::SOCK_STREAM, 0);
            if fd < 0 {
                return Err(std::io::Error::last_os_error());
            }
            let on: libc::c_int = 1;
            let opts = [(libc::SOL_SOCKET, libc::SO_REUSEADDR), (libc::IPPROTO_IP, IP_TRANSPARENT)];
            for (level, name) in opts {
                if libc::setsockopt(fd, level, name, &on as *const _ as *const libc::c_void, size_of::<libc::c_int>() as libc::socklen_t) < 0 {
                    let e = std::io::Error::last_os_error();
                    libc::close(fd);
                    return Err(e);
                }
            }
            let addr = libc::sockaddr_in {
                sin_family: libc::AF_INET as libc::sa_family_t,
                sin_port: port.to_be(),
                sin_addr: libc::in_addr { s_addr: 0 }, // 0.0.0.0
                sin_zero: [0; 8],
            };
            if libc::bind(fd, &addr as *const _ as *const libc::sockaddr, size_of::<libc::sockaddr_in>() as libc::socklen_t) < 0 {
                let e = std::io::Error::last_os_error();
                libc::close(fd);
                return Err(e);
            }
            if libc::listen(fd, 1024) < 0 {
                let e = std::io::Error::last_os_error();
                libc::close(fd);
                return Err(e);
            }
            Ok(TcpListener::from_raw_fd(fd))
        }
    }

    /// TPROXY's whole point: the accepted socket's local address already
    /// *is* the original destination - the kernel never rewrites it (unlike
    /// REDIRECT/DNAT), so no extra syscall is needed here.
    pub fn original_dst(conn: &TcpStream) -> std::io::Result<SocketAddr> {
        conn.local_addr()
    }
}

#[cfg(not(target_os = "linux"))]
mod backend {
    use std::io::Write as _;
    use std::mem::size_of;
    use std::net::{SocketAddr, TcpListener, TcpStream};
    use std::os::unix::io::AsRawFd;
    use std::process::Command;

    const ANCHOR: &str = "dpi-lab-mitm";

    pub fn setup(port: u16, iface: &str) -> std::io::Result<()> {
        let rule = format!("rdr pass on {iface} inet proto tcp from any to any port 443 -> 127.0.0.1 port {port}\n");
        let mut child = Command::new("pfctl").args(["-a", ANCHOR, "-f", "-"]).stdin(std::process::Stdio::piped()).spawn()?;
        child.stdin.take().unwrap().write_all(rule.as_bytes())?;
        let status = child.wait()?;
        if !status.success() {
            return Err(std::io::Error::other("pfctl failed to load MITM rdr anchor"));
        }
        let _ = Command::new("pfctl").args(["-e"]).status(); // enable pf; errors if already on, ignored
        Ok(())
    }

    pub fn teardown() {
        let result = Command::new("pfctl").args(["-a", ANCHOR, "-F", "all"]).status();
        match result {
            Ok(status) if status.success() => log::info!("[mitm] cleared pf anchor"),
            _ => log::error!("[mitm] failed to clear pf anchor - check manually: sudo pfctl -a {ANCHOR} -F all"),
        }
    }

    pub fn bind(port: u16) -> std::io::Result<TcpListener> {
        TcpListener::bind(("127.0.0.1", port))
    }

    #[repr(C)]
    #[derive(Clone, Copy)]
    struct PfAddr {
        bytes: [u8; 16], // union of v4/v6/addr8/16/32 - only need raw bytes
    }

    #[repr(C)]
    #[derive(Clone, Copy)]
    union PfStateXport {
        port: u16,
        call_id: u16,
        spi: u32,
    }

    #[repr(C)]
    struct PfiocNatlook {
        saddr: PfAddr,
        daddr: PfAddr,
        rsaddr: PfAddr,
        rdaddr: PfAddr,
        sxport: PfStateXport,
        dxport: PfStateXport,
        rsxport: PfStateXport,
        rdxport: PfStateXport,
        af: u8, // sa_family_t
        proto: u8,
        proto_variant: u8,
        direction: u8,
    }

    const AF_INET: u8 = libc::AF_INET as u8;
    const IPPROTO_TCP: u8 = libc::IPPROTO_TCP as u8;
    const PF_OUT: u8 = 2; // enum { PF_INOUT, PF_IN, PF_OUT } - confirmed via sshuttle's working Darwin backend

    /// `_IOWR('D', 23, struct pfioc_natlook)` computed the same way
    /// <sys/ioccom.h>'s _IOWR macro does, rather than hardcoding the
    /// resulting magic number - self-documenting and correct if the struct
    /// size ever needs adjusting. Struct layout confirmed against Apple's
    /// xnu bsd/net/pfvar.h and sshuttle's working Darwin pf backend
    /// (sshuttle/methods/pf.py), which uses this exact ioctl the same way.
    const fn iowr(group: u8, num: u8, len: usize) -> libc::c_ulong {
        const IOC_INOUT: u32 = 0x8000_0000 | 0x4000_0000;
        const IOCPARM_MASK: u32 = 0x1fff;
        (IOC_INOUT | (((len as u32) & IOCPARM_MASK) << 16) | ((group as u32) << 8) | (num as u32)) as libc::c_ulong
    }

    /// `rdr-to` rewrites the destination before the kernel delivers to our
    /// listener, unlike Linux TPROXY - `local_addr()` on the accepted
    /// socket is *our* address, not the client's real target. Recover it
    /// via DIOCNATLOOK against /dev/pf: direction=PF_OUT, af/proto set,
    /// saddr/sport = the real client (peer_addr), daddr/dport = us as the
    /// client sees us (local_addr) - the kernel returns rdaddr/rdport = the
    /// pre-NAT original destination.
    pub fn original_dst(conn: &TcpStream) -> std::io::Result<SocketAddr> {
        let peer = conn.peer_addr()?;
        let local = conn.local_addr()?;
        // IPv6 unreachable in practice today, not just unhandled here: the
        // pf rule above is `inet proto tcp` (v4 only) and bind() is
        // 127.0.0.1 (v4 only) - a v6 connection can't reach this listener
        // at all yet. Wiring up the natlook struct for AF_INET6 without
        // also adding a v6 rdr rule + dual-stack/::1 listener would be
        // dead code nothing could ever exercise or verify; real v6 support
        // is that whole bundle, not this one function.
        let (SocketAddr::V4(peer4), SocketAddr::V4(local4)) = (peer, local) else {
            return Err(std::io::Error::other("mitm: IPv6 not supported (rdr rule + listener are v4-only, see comment above)"));
        };

        let mut nl: PfiocNatlook = unsafe { std::mem::zeroed() };
        nl.af = AF_INET;
        nl.proto = IPPROTO_TCP;
        nl.direction = PF_OUT;
        nl.saddr.bytes[..4].copy_from_slice(&peer4.ip().octets());
        nl.daddr.bytes[..4].copy_from_slice(&local4.ip().octets());
        nl.sxport.port = peer4.port().to_be();
        nl.dxport.port = local4.port().to_be();

        let dev = std::fs::OpenOptions::new().read(true).write(true).open("/dev/pf")?;
        let req = iowr(b'D', 23, size_of::<PfiocNatlook>());
        let ret = unsafe { libc::ioctl(dev.as_raw_fd(), req, &mut nl as *mut _ as *mut libc::c_void) };
        if ret != 0 {
            return Err(std::io::Error::last_os_error());
        }

        let real_ip = std::net::Ipv4Addr::new(nl.rdaddr.bytes[0], nl.rdaddr.bytes[1], nl.rdaddr.bytes[2], nl.rdaddr.bytes[3]);
        let real_port = unsafe { u16::from_be(nl.rdxport.port) };
        Ok(SocketAddr::new(std::net::IpAddr::V4(real_ip), real_port))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn should_intercept_matches_exact_sni_only() {
        let list = vec!["google.com".to_string()];
        assert!(should_intercept(Some("google.com"), &list));
        assert!(!should_intercept(Some("evil.example"), &list));
        assert!(!should_intercept(None, &list));
    }

    #[test]
    fn should_intercept_empty_list_never_intercepts() {
        assert!(!should_intercept(Some("google.com"), &[]));
    }

    /// Throwaway self-signed CA (deliberately not the real mkcert one) -
    /// proves CertIssuer::load + server_config_for actually produce a
    /// usable rustls ServerConfig end to end, without this test depending
    /// on any file outside itself.
    fn test_ca_pem() -> (String, String) {
        let ca_key = KeyPair::generate().unwrap();
        let mut params = CertificateParams::new(Vec::<String>::new()).unwrap();
        params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
        params.key_usages = vec![rcgen::KeyUsagePurpose::KeyCertSign, rcgen::KeyUsagePurpose::CrlSign];
        let ca = rcgen::CertifiedIssuer::self_signed(params, ca_key).unwrap();
        (ca.pem(), ca.key().serialize_pem())
    }

    #[test]
    fn cert_issuer_signs_and_caches_a_leaf_for_sni() {
        let _ = rustls::crypto::ring::default_provider().install_default();
        let (ca_cert_pem, ca_key_pem) = test_ca_pem();
        let dir = std::env::temp_dir().join(format!("dpi-lab-mitm-test-{}-{:?}", std::process::id(), std::thread::current().id()));
        std::fs::create_dir_all(&dir).unwrap();
        let cert_path = dir.join("ca.crt");
        let key_path = dir.join("ca.key");
        std::fs::write(&cert_path, &ca_cert_pem).unwrap();
        std::fs::write(&key_path, &ca_key_pem).unwrap();

        let issuer = CertIssuer::load(&cert_path, &key_path).expect("load CA");
        let cfg1 = issuer.server_config_for("example.test").expect("issue leaf cert");
        let cfg2 = issuer.server_config_for("example.test").expect("cache hit");
        assert!(Arc::ptr_eq(&cfg1, &cfg2), "second call should hit the cache, not re-sign");

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn cert_issuer_load_rejects_missing_files() {
        assert!(CertIssuer::load(std::path::Path::new("/nonexistent/ca.crt"), std::path::Path::new("/nonexistent/ca.key")).is_err());
    }

    #[test]
    fn force_identity_encoding_replaces_existing_header() {
        let mut buf = b"GET / HTTP/1.1\r\nHost: example.com\r\nAccept-Encoding: gzip, br\r\n\r\n".to_vec();
        force_identity_encoding(&mut buf);
        let text = String::from_utf8(buf).unwrap();
        assert!(text.contains("Accept-Encoding: identity"));
        assert!(!text.contains("gzip"));
    }

    #[test]
    fn force_identity_encoding_adds_header_if_absent() {
        let mut buf = b"GET / HTTP/1.1\r\nHost: example.com\r\n\r\n".to_vec();
        force_identity_encoding(&mut buf);
        assert!(String::from_utf8(buf).unwrap().contains("Accept-Encoding: identity"));
    }

    #[test]
    fn redact_in_place_blanks_matches_and_keeps_length() {
        let sigs = Signatures::new(&["tiananmen"]);
        let mut buf = b"results for tiananmen square query".to_vec();
        let before_len = buf.len();
        let hits = redact_in_place(&mut buf, &sigs);
        assert_eq!(hits, vec!["tiananmen".to_string()]);
        assert_eq!(buf.len(), before_len); // same-length redaction - no Content-Length fixup needed
        assert_eq!(&buf, b"results for ********* square query");
    }

    #[test]
    fn redact_in_place_no_match_is_a_no_op() {
        let sigs = Signatures::new(&["blocked"]);
        let mut buf = b"perfectly fine content".to_vec();
        assert!(redact_in_place(&mut buf, &sigs).is_empty());
        assert_eq!(&buf, b"perfectly fine content");
    }

    #[test]
    fn find_crlf_locates_first_occurrence() {
        assert_eq!(find_crlf(b"5\r\nhello\r\n"), Some(1));
        assert_eq!(find_crlf(b"no crlf here"), None);
    }
}
