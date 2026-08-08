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
use pnet::packet::tcp::TcpPacket;
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
}

impl InlineClassifier {
    /// Decide a verdict for one packet. Returns Some(reason) to block,
    /// None to accept. Pure function over bytes - no network/kernel access,
    /// so this is the part that's actually unit-testable without root/Linux.
    pub fn classify(&self, src: IpAddr, dst: IpAddr, sport: u16, dport: u16, payload: &[u8]) -> Option<String> {
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
        if let Some(rule) = self.handshake_rules.iter().find(|r| classify::matches_handshake(payload, r)) {
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
        let payload = msg.get_payload();
        let verdict = decide(classifier, payload);
        if let Some(reason) = &verdict {
            println!("  [inline] dropped ({reason})");
        }
        msg.set_verdict(if verdict.is_some() { Verdict::Drop } else { Verdict::Accept });
        queue.verdict(msg)?;
    }
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
            decide_transport(classifier, src, dst, ip.get_next_header(), ip.payload())
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
            classifier.classify(src, dst, tcp.get_source(), tcp.get_destination(), tcp.payload())
        }
        IpNextHeaderProtocols::Udp => {
            let udp = UdpPacket::new(payload)?;
            classifier.classify(src, dst, udp.get_source(), udp.get_destination(), udp.payload())
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
            }],
        }
    }

    #[test]
    fn blocks_exact_ip() {
        let c = classifier();
        let src: IpAddr = "10.27.0.99".parse().unwrap();
        let dst: IpAddr = "1.1.1.1".parse().unwrap();
        assert_eq!(c.classify(src, dst, 1234, 443, b""), Some("ip".to_string()));
    }

    #[test]
    fn blocks_cidr_ip() {
        let c = classifier();
        let src: IpAddr = "10.27.1.50".parse().unwrap();
        let dst: IpAddr = "1.1.1.1".parse().unwrap();
        assert_eq!(c.classify(src, dst, 1234, 443, b""), Some("ip".to_string()));
    }

    #[test]
    fn blocks_signature() {
        let c = classifier();
        let src: IpAddr = "10.27.0.5".parse().unwrap();
        let dst: IpAddr = "1.1.1.1".parse().unwrap();
        assert_eq!(c.classify(src, dst, 1234, 80, b"GET /malware.exe HTTP/1.1"), Some("signature: malware".to_string()));
    }

    #[test]
    fn blocks_wireguard_handshake() {
        let c = classifier();
        let src: IpAddr = "10.27.0.5".parse().unwrap();
        let dst: IpAddr = "10.27.0.10".parse().unwrap();
        let mut pkt = vec![0u8; 148];
        pkt[0] = 1;
        assert_eq!(c.classify(src, dst, 51820, 51820, &pkt), Some("handshake: wireguard-handshake-init".to_string()));
    }

    #[test]
    fn allows_unmatched_traffic() {
        let c = classifier();
        let src: IpAddr = "10.27.0.5".parse().unwrap();
        let dst: IpAddr = "1.1.1.1".parse().unwrap();
        assert_eq!(c.classify(src, dst, 1234, 443, b"perfectly normal traffic"), None);
    }
}
