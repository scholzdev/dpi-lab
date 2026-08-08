// Genuine inline enforcement via Linux NFQUEUE - the "in-path" mode the rest
// of this project structurally can't do (see writeup.md's off-path/inline
// discussion). Passive capture (main.rs's default mode) only ever sees a
// *copy* of a packet - RST injection, DNS spoofing, and response injection
// all work by racing a forged extra packet against the real one, because
// there's no way to stop the real one. NFQUEUE is different: an nftables
// rule diverts matching packets into this process *before* the kernel
// forwards them, so classify() gets to decide accept/drop directly. No race.
//
// Architecture modeled on OpenGFW (github.com/apernet/OpenGFW, MPL-2.0) -
// same core technique (nftables `queue` rule -> NFQUEUE -> userspace
// verdict), independently reimplemented here in Rust with the `nfq` crate
// instead of OpenGFW's Go/go-nfqueue+go-iptables. Referenced for
// architecture, not copied - see writeup.md's related-work section.
//
// Scope reduction vs the passive path (engine.rs): single-packet
// classification only, no cross-packet TCP reassembly - a ClientHello split
// across multiple segments won't be seen whole here, unlike engine.rs's
// TcpStream-backed reassembly. OpenGFW's own nft rules bypass an
// already-decided flow via a conntrack mark rather than re-inspecting every
// packet forever; this first version re-inspects every packet of every flow
// instead - correct, just wasteful at anything beyond lab scale. Both are
// documented follow-ups, not oversights.
#![cfg(target_os = "linux")]

use crate::classify::{self, HandshakeRule};
use crate::engine::ip_rule_matches;
use nfq::{Queue, Verdict};
use pnet::packet::ip::IpNextHeaderProtocols;
use pnet::packet::ipv4::Ipv4Packet;
use pnet::packet::ipv6::Ipv6Packet;
use pnet::packet::tcp::{ipv4_checksum as tcp_checksum_v4, ipv6_checksum as tcp_checksum_v6, MutableTcpPacket, TcpPacket};
use pnet::packet::udp::UdpPacket;
use pnet::packet::Packet;
use std::net::IpAddr;

const QUEUE_NUM: u16 = 100;
const NFT_TABLE: &str = "dpi-lab-inline";

/// Everything an inline verdict needs - the same block lists/rules as the
/// passive path, just not wrapped in Engine's off-path injection machinery
/// (no raw sockets, no RST/DNS-spoof/cannon state - dropping the real packet
/// *is* the enforcement here, there's nothing else to set up).
pub struct InlineClassifier {
    pub blocked_sni: Vec<String>,
    pub blocked_ja3: Vec<String>,
    pub blocked_ip: Vec<String>,
    pub sigs: classify::Signatures,
    pub handshake_rules: Vec<HandshakeRule>,
    /// The one non-block-decision field here: forces TLS 1.3 ClientHellos
    /// down to 1.2 in place (see `mangle_tls13_downgrade`) instead of
    /// deciding accept/drop. Reused this struct rather than threading a
    /// second config path through `run()` for one flag.
    pub downgrade_tls13: bool,
}

impl InlineClassifier {
    /// Decide a verdict for one packet. Returns Some(reason) to block,
    /// None to accept. Pure function over bytes - no network/kernel access,
    /// so this is the part that's actually unit-testable without root/Linux.
    pub fn classify(&self, src: IpAddr, dst: IpAddr, sport: u16, dport: u16, transport: &str, payload: &[u8]) -> Option<String> {
        if self.blocked_ip.iter().any(|r| ip_rule_matches(r, &src) || ip_rule_matches(r, &dst)) {
            return Some("ip".to_string());
        }
        for hit in self.sigs.matches(payload) {
            return Some(format!("signature: {hit}"));
        }
        if let Some(ch) = classify::parse_client_hello(payload) {
            if let Some((_, hash)) = classify::ja3(payload) {
                if self.blocked_ja3.iter().any(|h| h == &hash) {
                    return Some(format!("ja3: {hash}"));
                }
            }
            if let Some(name) = ch.sni {
                if self.blocked_sni.iter().any(|s| s == &name) {
                    return Some(format!("sni: {name}"));
                }
            }
        }
        if let Some(rule) = self
            .handshake_rules
            .iter()
            .filter(|r| classify::rule_applies_to(r, transport))
            .find(|r| classify::matches_handshake(payload, r))
        {
            return Some(format!("handshake: {}", rule.name));
        }
        let _ = (sport, dport); // reserved for future port-scoped rules
        None
    }
}

/// Install the nftables rule that queues all forwarded traffic to us.
/// Requires root and `nft` on PATH (same shell-out pattern as
/// throttle.rs/lockdown.rs's pfctl calls, just nft instead).
fn setup_nft() -> std::io::Result<()> {
    let _ = std::process::Command::new("nft").args(["delete", "table", "inet", NFT_TABLE]).status(); // clear any stale table first
    let rule = format!(
        "table inet {NFT_TABLE} {{ chain forward {{ type filter hook forward priority 0; policy accept; queue num {QUEUE_NUM} bypass; }} }}"
    );
    let status = std::process::Command::new("nft").args(["-f", "-"]).stdin(std::process::Stdio::piped()).spawn().and_then(|mut child| {
        use std::io::Write;
        child.stdin.take().unwrap().write_all(rule.as_bytes())?;
        child.wait()
    })?;
    if !status.success() {
        return Err(std::io::Error::other("nft failed to load inline table"));
    }
    Ok(())
}

/// Remove the nft table. Call on exit - otherwise a crashed/Ctrl-C'd session
/// leaves the FORWARD chain pointed at a queue nothing is reading from,
/// which (without `bypass` on the queue rule) would stall all forwarded
/// traffic. `bypass` above already protects against that, but tearing down
/// cleanly is still the right default.
pub fn clear_nft() {
    let result = std::process::Command::new("nft").args(["delete", "table", "inet", NFT_TABLE]).status();
    match result {
        Ok(status) if status.success() => println!("[inline] cleared nft table"),
        _ => eprintln!("[inline] failed to clear nft table - check manually: sudo nft delete table inet {NFT_TABLE}"),
    }
}

/// Run the inline NFQUEUE loop. Blocks forever (or until an unrecoverable
/// queue error) - this replaces the passive datalink capture loop entirely
/// when --inline is passed, it doesn't run alongside it.
pub fn run(classifier: &InlineClassifier) -> std::io::Result<()> {
    setup_nft()?;
    println!("[inline] nft table loaded, queueing FORWARD traffic to queue {QUEUE_NUM}");

    let mut queue = Queue::open()?;
    queue.bind(QUEUE_NUM)?;

    loop {
        let mut msg = queue.recv()?;
        if classifier.downgrade_tls13 {
            if let Some(reason) = mangle_tls13_downgrade(msg.get_payload_mut()) {
                println!("  [inline] {reason}");
            }
        }
        let payload = msg.get_payload();
        let verdict = decide(classifier, payload);
        if let Some(reason) = &verdict {
            println!("  [inline] dropped ({reason})");
        }
        // get_payload_mut's edits above (if any) are only committed to the
        // kernel on a non-Drop verdict (nfq crate's own doc comment on that
        // method) - a packet that also matches a block rule still drops,
        // same as if it had never been mangled.
        msg.set_verdict(if verdict.is_some() { Verdict::Drop } else { Verdict::Accept });
        queue.verdict(msg)?;
    }
}

/// Force TLS 1.3 down to 1.2 in place, if `ip_payload` carries a ClientHello
/// offering it - see `classify::mangle_supported_versions_in_place` for the
/// byte-level mechanics and why this never changes any length (shrinking the
/// payload would desync every later real segment of this flow). IPv6 and
/// IPv4 both handled, same recompute-only-the-TCP-checksum reasoning either
/// way (the IP header itself is never touched, so its checksum - v4 only,
/// v6 has none - doesn't need touching). Returns a log line on a hit, so
/// `run()`'s loop only prints when something actually changed.
fn mangle_tls13_downgrade(ip_payload: &mut [u8]) -> Option<String> {
    match ip_payload.first().map(|b| b >> 4) {
        Some(4) => {
            let ip = Ipv4Packet::new(ip_payload)?;
            if ip.get_next_level_protocol() != IpNextHeaderProtocols::Tcp {
                return None;
            }
            let (src4, dst4) = (ip.get_source(), ip.get_destination());
            let ip_hdr_len = (ip.get_header_length() as usize) * 4;
            let (sport, dport) = tcp_endpoints(ip_payload.get(ip_hdr_len..)?)?;
            let data_offset = (TcpPacket::new(ip_payload.get(ip_hdr_len..)?)?.get_data_offset() as usize) * 4;
            let payload_start = ip_hdr_len + data_offset;
            if !classify::mangle_supported_versions_in_place(ip_payload.get_mut(payload_start..)?) {
                return None;
            }
            let mut tcp = MutableTcpPacket::new(&mut ip_payload[ip_hdr_len..])?;
            let cksum = tcp_checksum_v4(&tcp.to_immutable(), &src4, &dst4);
            tcp.set_checksum(cksum);
            Some(format!(
                "downgraded {}:{sport} -> {}:{dport} (stripped TLS 1.3 from supported_versions)",
                IpAddr::V4(src4),
                IpAddr::V4(dst4)
            ))
        }
        Some(6) => {
            const IPV6_HDR_LEN: usize = 40;
            let ip = Ipv6Packet::new(ip_payload)?;
            let (src6, dst6) = (ip.get_source(), ip.get_destination());
            let (proto, ext_len, _frag) =
                crate::ipv6ext::walk_ipv6_extensions_len(ip.get_next_header(), ip_payload.get(IPV6_HDR_LEN..)?);
            if proto != IpNextHeaderProtocols::Tcp {
                return None;
            }
            let tcp_start = IPV6_HDR_LEN + ext_len;
            let (sport, dport) = tcp_endpoints(ip_payload.get(tcp_start..)?)?;
            let data_offset = (TcpPacket::new(ip_payload.get(tcp_start..)?)?.get_data_offset() as usize) * 4;
            let payload_start = tcp_start + data_offset;
            if !classify::mangle_supported_versions_in_place(ip_payload.get_mut(payload_start..)?) {
                return None;
            }
            let mut tcp = MutableTcpPacket::new(&mut ip_payload[tcp_start..])?;
            let cksum = tcp_checksum_v6(&tcp.to_immutable(), &src6, &dst6);
            tcp.set_checksum(cksum);
            Some(format!(
                "downgraded {}:{sport} -> {}:{dport} (stripped TLS 1.3 from supported_versions)",
                IpAddr::V6(src6),
                IpAddr::V6(dst6)
            ))
        }
        _ => None,
    }
}

fn tcp_endpoints(tcp_bytes: &[u8]) -> Option<(u16, u16)> {
    let tcp = TcpPacket::new(tcp_bytes)?;
    Some((tcp.get_source(), tcp.get_destination()))
}

/// Parse the raw IP packet nfq hands us and run it through the classifier.
/// Split out from `run` so it's testable without an actual queue.
fn decide(classifier: &InlineClassifier, ip_payload: &[u8]) -> Option<String> {
    // First nibble of the IP header says v4 vs v6, same trick pnet itself uses.
    match ip_payload.first().map(|b| b >> 4) {
        Some(4) => {
            let ip = Ipv4Packet::new(ip_payload)?;
            let (src, dst) = (IpAddr::V4(ip.get_source()), IpAddr::V4(ip.get_destination()));
            decide_transport(classifier, src, dst, ip.get_next_level_protocol(), ip.payload())
        }
        Some(6) => {
            let ip = Ipv6Packet::new(ip_payload)?;
            let (src, dst) = (IpAddr::V6(ip.get_source()), IpAddr::V6(ip.get_destination()));
            let (proto, payload, _frag) = crate::ipv6ext::walk_ipv6_extensions(ip.get_next_header(), ip.payload());
            decide_transport(classifier, src, dst, proto, payload)
        }
        _ => None,
    }
}

fn decide_transport(
    classifier: &InlineClassifier,
    src: IpAddr,
    dst: IpAddr,
    proto: pnet::packet::ip::IpNextHeaderProtocol,
    payload: &[u8],
) -> Option<String> {
    match proto {
        IpNextHeaderProtocols::Tcp => {
            let tcp = TcpPacket::new(payload)?;
            classifier.classify(src, dst, tcp.get_source(), tcp.get_destination(), "tcp", tcp.payload())
        }
        IpNextHeaderProtocols::Udp => {
            let udp = UdpPacket::new(payload)?;
            classifier.classify(src, dst, udp.get_source(), udp.get_destination(), "udp", udp.payload())
        }
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn classifier() -> InlineClassifier {
        InlineClassifier {
            blocked_sni: vec!["evil.example".to_string()],
            blocked_ja3: vec![],
            blocked_ip: vec!["10.27.0.99".to_string(), "10.27.1.0/24".to_string()],
            sigs: classify::Signatures::new(&["malware".to_string()]),
            handshake_rules: vec![HandshakeRule {
                name: "wireguard-handshake-init".to_string(),
                length: Some(148),
                anchors: vec![classify::HandshakeAnchor { offset: 0, bytes: vec![1, 0, 0, 0] }],
                protocol: Some("udp".to_string()),
            }],
            downgrade_tls13: false,
        }
    }

    #[test]
    fn blocks_exact_ip() {
        let c = classifier();
        let src: IpAddr = "10.27.0.99".parse().unwrap();
        let dst: IpAddr = "1.1.1.1".parse().unwrap();
        assert_eq!(c.classify(src, dst, 1234, 443, "tcp", b""), Some("ip".to_string()));
    }

    #[test]
    fn blocks_cidr_ip() {
        let c = classifier();
        let src: IpAddr = "10.27.1.50".parse().unwrap();
        let dst: IpAddr = "1.1.1.1".parse().unwrap();
        assert_eq!(c.classify(src, dst, 1234, 443, "tcp", b""), Some("ip".to_string()));
    }

    #[test]
    fn blocks_signature() {
        let c = classifier();
        let src: IpAddr = "10.27.0.5".parse().unwrap();
        let dst: IpAddr = "1.1.1.1".parse().unwrap();
        assert_eq!(
            c.classify(src, dst, 1234, 80, "tcp", b"GET /malware.exe HTTP/1.1"),
            Some("signature: malware".to_string())
        );
    }

    #[test]
    fn blocks_wireguard_handshake() {
        let c = classifier();
        let src: IpAddr = "10.27.0.5".parse().unwrap();
        let dst: IpAddr = "10.27.0.10".parse().unwrap();
        let mut pkt = vec![0u8; 148];
        pkt[0] = 1;
        assert_eq!(c.classify(src, dst, 51820, 51820, "udp", &pkt), Some("handshake: wireguard-handshake-init".to_string()));
    }

    #[test]
    fn wireguard_rule_does_not_match_over_tcp() {
        let c = classifier();
        let src: IpAddr = "10.27.0.5".parse().unwrap();
        let dst: IpAddr = "10.27.0.10".parse().unwrap();
        let mut pkt = vec![0u8; 148];
        pkt[0] = 1;
        assert_eq!(c.classify(src, dst, 51820, 51820, "tcp", &pkt), None); // protocol-scoped, wrong transport
    }

    #[test]
    fn allows_unmatched_traffic() {
        let c = classifier();
        let src: IpAddr = "10.27.0.5".parse().unwrap();
        let dst: IpAddr = "1.1.1.1".parse().unwrap();
        assert_eq!(c.classify(src, dst, 1234, 443, "tcp", b"perfectly normal traffic"), None);
    }

    /// Minimal ClientHello whose only extension is `supported_versions`
    /// listing the given entries - same shape as
    /// classify.rs's own test builder of the same purpose, duplicated here
    /// rather than exposed cross-module for one test fixture.
    fn client_hello_with_supported_versions(versions: &[u16]) -> Vec<u8> {
        let mut entries = Vec::new();
        for v in versions {
            entries.extend_from_slice(&v.to_be_bytes());
        }
        let mut ext_data = vec![entries.len() as u8];
        ext_data.extend_from_slice(&entries);

        let mut ext = vec![0x00, 0x2b];
        ext.extend_from_slice(&(ext_data.len() as u16).to_be_bytes());
        ext.extend_from_slice(&ext_data);

        let mut hs = vec![0x03, 0x03];
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

    /// Wrap a TCP payload in a minimal (no options, 20-byte header) IPv4/TCP
    /// packet with a correct TCP checksum, mirroring inject.rs's `build_rst`
    /// test-fixture pattern.
    fn wrap_ipv4_tcp(payload: &[u8]) -> Vec<u8> {
        use pnet::packet::ipv4::{checksum as ipv4_checksum, Ipv4Flags, MutableIpv4Packet};
        use pnet::packet::tcp::TcpFlags;
        const IP_HDR: usize = 20;
        const TCP_HDR: usize = 20;
        let src = std::net::Ipv4Addr::new(10, 0, 0, 1);
        let dst = std::net::Ipv4Addr::new(10, 0, 0, 2);

        let mut buf = vec![0u8; IP_HDR + TCP_HDR + payload.len()];
        buf[IP_HDR + TCP_HDR..].copy_from_slice(payload);
        {
            let mut tcp = MutableTcpPacket::new(&mut buf[IP_HDR..]).unwrap();
            tcp.set_source(51234);
            tcp.set_destination(443);
            tcp.set_sequence(1);
            tcp.set_data_offset(5);
            tcp.set_flags(TcpFlags::ACK);
            let cksum = tcp_checksum_v4(&tcp.to_immutable(), &src, &dst);
            tcp.set_checksum(cksum);
        }
        {
            let mut ip = MutableIpv4Packet::new(&mut buf).unwrap();
            ip.set_version(4);
            ip.set_header_length(5);
            ip.set_total_length((IP_HDR + TCP_HDR + payload.len()) as u16);
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

    #[test]
    fn downgrade_flips_tls13_and_fixes_tcp_checksum() {
        let hello = client_hello_with_supported_versions(&[0x0a0a, 0x0304, 0x0303]);
        let mut packet = wrap_ipv4_tcp(&hello);
        let before_len = packet.len();

        let reason = mangle_tls13_downgrade(&mut packet);
        assert!(reason.unwrap().contains("downgraded"));
        assert_eq!(packet.len(), before_len); // never resegments

        // TCP payload no longer offers 0x0304.
        let tcp = TcpPacket::new(&packet[20..]).unwrap();
        assert!(!tcp.payload().windows(2).any(|w| w == [0x03, 0x04]));

        // Checksum in the buffer matches a fresh recomputation - i.e. it was
        // actually updated to match the mangled bytes, not left stale.
        let src = std::net::Ipv4Addr::new(10, 0, 0, 1);
        let dst = std::net::Ipv4Addr::new(10, 0, 0, 2);
        let fresh = tcp_checksum_v4(&tcp, &src, &dst);
        assert_eq!(tcp.get_checksum(), fresh);
    }

    #[test]
    fn downgrade_noop_on_non_tls_payload_leaves_packet_byte_identical() {
        let mut packet = wrap_ipv4_tcp(b"perfectly normal traffic");
        let before = packet.clone();
        assert!(mangle_tls13_downgrade(&mut packet).is_none());
        assert_eq!(packet, before);
    }
}
