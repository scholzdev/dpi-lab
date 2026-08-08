// Active probing: on a suspected-obfuscated-protocol hit, connect out to the
// destination *ourselves* and try known proxy-protocol handshakes to confirm
// before trusting the entropy heuristic alone - the real GFW technique. Kept
// strictly to hosts on an explicit allow-list (config/probe_targets.yml, your
// own lab boxes) since probing anything else means touching infra you don't
// own, no matter how "read-only" the probe itself is.
use std::io::{Read, Write};
use std::net::{IpAddr, Ipv4Addr, SocketAddr, TcpStream};
use std::sync::Mutex;
use std::time::Duration;

const PROBE_TIMEOUT: Duration = Duration::from_secs(2);

/// Try a couple of well-known protocol handshakes against `ip:port`. Returns
/// a label for whichever one gets a matching response, None if nothing did -
/// which isn't proof of innocence, a real obfs4/Shadowsocks stream is
/// designed to not respond in a fingerprintable way to an unrelated probe.
pub fn probe(ip: IpAddr, port: u16) -> Option<&'static str> {
    if try_socks5(ip, port) {
        return Some("socks5");
    }
    if try_http_connect(ip, port) {
        return Some("http-proxy");
    }
    None
}

// The real GFW scans the whole IPv4 space unprompted looking for open
// circumvention-protocol servers; that's not something this lab ships
// (indiscriminate scanning of hosts you don't control). This is the scoped
// version: an explicit CIDR the caller already owns/controls, checked
// against config/probe_targets.yml by main.rs before this is ever called -
// same allow-list discipline as reactive probing above, just applied
// proactively instead of on a [detect] hit.
const MAX_SCAN_HOSTS: u32 = 1024; // refuses anything wider than a /22
const SCAN_MAX_THREADS: usize = 64;

/// Enumerate every host in an IPv4 CIDR range. `None` on a malformed CIDR or
/// one wider than `MAX_SCAN_HOSTS` (a deliberate backstop - even an
/// allow-listed range shouldn't silently balloon into scanning thousands of
/// hosts because of a typo'd prefix length).
fn enumerate_cidr_hosts(cidr: &str) -> Option<Vec<Ipv4Addr>> {
    let (base, bits) = cidr.split_once('/')?;
    let base4: Ipv4Addr = base.parse().ok()?;
    let bits: u32 = bits.parse().ok()?;
    if bits > 32 {
        return None;
    }
    let host_bits = 32 - bits;
    if host_bits > 30 && 1u64 << host_bits > MAX_SCAN_HOSTS as u64 {
        return None; // overflow-safe check before the shift below
    }
    let count = 1u32 << host_bits;
    if count > MAX_SCAN_HOSTS {
        return None;
    }
    let mask = if bits == 0 { 0 } else { !0u32 << host_bits };
    let network = u32::from(base4) & mask;
    Some((0..count).map(|i| Ipv4Addr::from(network + i)).collect())
}

/// Scan every host x port in `cidr` x `ports` for a known proxy-protocol
/// handshake, same `probe()` above just applied proactively across a whole
/// range instead of reactively to one already-flagged flow. Runs
/// concurrently (bounded thread count) since a serial scan of even a /24
/// against several ports, each with its own `PROBE_TIMEOUT`, would take
/// minutes. Returns every (ip, port, protocol) hit.
pub fn scan_range(cidr: &str, ports: &[u16]) -> Vec<(IpAddr, u16, &'static str)> {
    let Some(hosts) = enumerate_cidr_hosts(cidr) else {
        eprintln!("[scan] refusing {cidr}: malformed, or wider than a /22 ({MAX_SCAN_HOSTS} hosts)");
        return Vec::new();
    };
    let targets: Vec<(Ipv4Addr, u16)> = hosts.iter().flat_map(|&ip| ports.iter().map(move |&p| (ip, p))).collect();
    if targets.is_empty() {
        return Vec::new();
    }
    let results: Mutex<Vec<(IpAddr, u16, &'static str)>> = Mutex::new(Vec::new());
    let n_threads = targets.len().min(SCAN_MAX_THREADS);
    let chunk_size = targets.len().div_ceil(n_threads).max(1);
    let results_ref = &results;
    std::thread::scope(|scope| {
        for chunk in targets.chunks(chunk_size) {
            scope.spawn(move || {
                for &(ip, port) in chunk {
                    if let Some(proto) = probe(IpAddr::V4(ip), port) {
                        results_ref.lock().unwrap().push((IpAddr::V4(ip), port, proto));
                    }
                }
            });
        }
    });
    results.into_inner().unwrap()
}

fn try_socks5(ip: IpAddr, port: u16) -> bool {
    let Ok(mut stream) = TcpStream::connect_timeout(&SocketAddr::new(ip, port), PROBE_TIMEOUT) else { return false };
    let _ = stream.set_read_timeout(Some(PROBE_TIMEOUT));
    if stream.write_all(&[0x05, 0x01, 0x00]).is_err() {
        return false; // ver=5, 1 auth method offered, no-auth
    }
    let mut resp = [0u8; 2];
    stream.read_exact(&mut resp).is_ok() && resp == [0x05, 0x00]
}

fn try_http_connect(ip: IpAddr, port: u16) -> bool {
    let Ok(mut stream) = TcpStream::connect_timeout(&SocketAddr::new(ip, port), PROBE_TIMEOUT) else { return false };
    let _ = stream.set_read_timeout(Some(PROBE_TIMEOUT));
    let req = b"CONNECT example.com:443 HTTP/1.1\r\nHost: example.com\r\n\r\n";
    if stream.write_all(req).is_err() {
        return false;
    }
    let mut buf = [0u8; 8];
    stream.read_exact(&mut buf).is_ok() && buf.starts_with(b"HTTP/1.")
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::TcpListener;

    #[test]
    fn socks5_probe_confirms_real_socks5_server() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let handle = std::thread::spawn(move || {
            let (mut s, _) = listener.accept().unwrap();
            let mut buf = [0u8; 3];
            s.read_exact(&mut buf).unwrap();
            s.write_all(&[0x05, 0x00]).unwrap();
        });
        assert_eq!(probe(addr.ip(), addr.port()), Some("socks5"));
        handle.join().unwrap();
    }

    #[test]
    fn probe_returns_none_against_non_matching_server() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let handle = std::thread::spawn(move || {
            let (mut s, _) = listener.accept().unwrap();
            let _ = s.write_all(b"not a known protocol");
        });
        assert_eq!(probe(addr.ip(), addr.port()), None);
        handle.join().unwrap();
    }

    #[test]
    fn probe_returns_none_against_closed_port() {
        // nothing listening on this port -> connect itself fails
        assert_eq!(probe("127.0.0.1".parse().unwrap(), 1), None);
    }

    #[test]
    fn enumerate_cidr_hosts_covers_full_range() {
        let hosts = enumerate_cidr_hosts("10.27.0.0/30").unwrap();
        let want: Vec<Ipv4Addr> = ["10.27.0.0", "10.27.0.1", "10.27.0.2", "10.27.0.3"].iter().map(|s| s.parse().unwrap()).collect();
        assert_eq!(hosts, want);
    }

    #[test]
    fn enumerate_cidr_hosts_masks_off_host_bits_in_base() {
        // Base address has host bits set (10.27.0.5/30) - real network is
        // still 10.27.0.4/30, same masking rule ip_rule_matches/cidr_contains use.
        let hosts = enumerate_cidr_hosts("10.27.0.5/30").unwrap();
        let want: Vec<Ipv4Addr> = ["10.27.0.4", "10.27.0.5", "10.27.0.6", "10.27.0.7"].iter().map(|s| s.parse().unwrap()).collect();
        assert_eq!(hosts, want);
    }

    #[test]
    fn enumerate_cidr_hosts_refuses_ranges_wider_than_cap() {
        assert!(enumerate_cidr_hosts("10.0.0.0/21").is_none()); // 2048 hosts > MAX_SCAN_HOSTS
        assert!(enumerate_cidr_hosts("0.0.0.0/0").is_none()); // the pathological case - must not panic
        assert!(enumerate_cidr_hosts("10.27.0.0/22").is_some()); // exactly at the cap, allowed
    }

    #[test]
    fn enumerate_cidr_hosts_rejects_malformed_input() {
        assert!(enumerate_cidr_hosts("not-a-cidr").is_none());
        assert!(enumerate_cidr_hosts("10.27.0.0").is_none()); // no /bits at all
        assert!(enumerate_cidr_hosts("10.27.0.0/33").is_none()); // bits out of range
    }

    #[test]
    fn scan_range_finds_a_real_listener_in_the_range() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        let handle = std::thread::spawn(move || {
            let (mut s, _) = listener.accept().unwrap();
            let mut buf = [0u8; 3];
            s.read_exact(&mut buf).unwrap();
            s.write_all(&[0x05, 0x00]).unwrap();
        });
        let hits = scan_range("127.0.0.1/32", &[port]);
        assert_eq!(hits, vec![(IpAddr::from([127, 0, 0, 1]), port, "socks5")]);
        handle.join().unwrap();
    }

    #[test]
    fn scan_range_refuses_oversized_cidr_without_scanning_anything() {
        assert!(scan_range("10.0.0.0/8", &[80]).is_empty());
    }
}
