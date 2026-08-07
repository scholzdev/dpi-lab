// Active probing: on a suspected-obfuscated-protocol hit, connect out to the
// destination *ourselves* and try known proxy-protocol handshakes to confirm
// before trusting the entropy heuristic alone - the real GFW technique. Kept
// strictly to hosts on an explicit allow-list (config/probe_targets.yml, your
// own lab boxes) since probing anything else means touching infra you don't
// own, no matter how "read-only" the probe itself is.
use std::io::{Read, Write};
use std::net::{IpAddr, SocketAddr, TcpStream};
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
}
