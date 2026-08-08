// Per-packet pipeline: decode -> reassemble -> classify -> (optionally) inject/redirect.
// Owns all mutable state so main.rs stays just capture loop + CLI.
use crate::cannon;
use crate::classify::{self, ja3, parse_dns_query_full, parse_client_hello, Signatures};
use crate::config::CannonConfig;
use crate::detect::{classify_first_segment, TLS_LIKE_PORTS};
use crate::h2;
use crate::inject::{self, TransportSender};
use crate::lockdown;
use crate::reassembly::TcpStream;
use crate::probe;
use crate::redirect;
use crate::timing::TimingStats;
use pnet::packet::ip::IpNextHeaderProtocols;
use pnet::packet::ipv4::{Ipv4Flags, Ipv4Packet};
use pnet::packet::ipv6::Ipv6Packet;
use pnet::packet::tcp::{TcpFlags, TcpPacket};
use pnet::packet::udp::UdpPacket;
use pnet::packet::Packet;
use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr, SocketAddr, ToSocketAddrs};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

// After this many block events from one source IP in ESCALATE_WINDOW,
// auto-add that IP to the block list.
const ESCALATE_THRESHOLD: u32 = 3;
const ESCALATE_WINDOW: Duration = Duration::from_secs(60);
const ESCALATION_TTL: Duration = Duration::from_secs(3600); // auto-escalated blocks expire
const ESCALATED_IP_FILE: &str = "config/escalated_ip.yml"; // ip -> expiry, merged into blocked_ip on startup

// --lockdown: any IP/SNI/JA3/signature match locks that source IP down at
// the pf level immediately (not after N offenses, unlike escalation) - a
// deterministic kernel drop, not a raced RST. Also TTL-bounded + persisted.
const LOCKDOWN_TTL: Duration = Duration::from_secs(3600);
const LOCKDOWN_FILE: &str = "config/lockdown.yml";

// Flow-table bounds: a lab tool has no business tracking flows forever. Idle
// eviction handles the normal case (flow ended, no FIN/RST seen for whatever
// reason); MAX_FLOWS is the backstop against deliberate flow-churn (many
// short-lived connections opened just to grow these HashMaps unbounded).
const IDLE_TIMEOUT: Duration = Duration::from_secs(300);
const MAX_FLOWS: usize = 50_000;

/// Crude but sufficient check for "this looks like the start of an HTTP request".
fn looks_like_http_request(payload: &[u8]) -> bool {
    const METHODS: [&[u8]; 4] = [b"GET ", b"POST ", b"HEAD ", b"PUT "];
    METHODS.iter().any(|m| payload.starts_with(m))
}

/// True if `rule` matches `ip` - exact address, or (IPv4) a CIDR range.
pub(crate) fn ip_rule_matches(rule: &str, ip: &IpAddr) -> bool {
    match rule.split_once('/') {
        Some(_) => cidr_contains(rule, ip),
        None => rule == ip.to_string(),
    }
}

/// IPv4 CIDR containment check (`"10.0.0.0/24"` matching), extracted out of
/// `ip_rule_matches` so ASN range lookups (see asn.rs) reuse the exact same
/// bit-mask math instead of a second, driftable copy. `cidr` without a `/`
/// (or IPv6 `ip`) never matches - CIDR-only, unlike `ip_rule_matches` which
/// also accepts a bare exact-IP rule.
pub(crate) fn cidr_contains(cidr: &str, ip: &IpAddr) -> bool {
    let Some((base, bits)) = cidr.split_once('/') else { return false };
    let (IpAddr::V4(ip4), Ok(base4), Ok(bits)) = (ip, base.parse::<Ipv4Addr>(), bits.parse::<u32>()) else {
        return false;
    };
    if bits > 32 {
        return false;
    }
    let mask = if bits == 0 { 0 } else { !0u32 << (32 - bits) };
    u32::from(*ip4) & mask == u32::from(base4) & mask
}

/// Block-event counter keyed by kind ("sni", "ja3", "ip", "signature",
/// "detect") - shared between Engine and main.rs's Ctrl-C summary printer.
pub type BlockStats = Arc<Mutex<HashMap<String, u32>>>;

fn resolve_ipv4(host: &str) -> Option<Ipv4Addr> {
    (host, 0).to_socket_addrs().ok()?.find_map(|a: SocketAddr| match a {
        SocketAddr::V4(v4) => Some(*v4.ip()),
        _ => None,
    })
}

fn resolve_ipv6(host: &str) -> Option<std::net::Ipv6Addr> {
    (host, 0).to_socket_addrs().ok()?.find_map(|a: SocketAddr| match a {
        SocketAddr::V6(v6) => Some(*v6.ip()),
        _ => None,
    })
}

type FlowKey = (IpAddr, u16, IpAddr, u16);

// JA3 hash -> client label. Add entries by capturing your own known clients
// (see README); hashes drift across client versions so this needs upkeep.
const KNOWN_JA3: &[(&str, &str)] = &[
    ("375c6162a492dfbf2795909110ce8424", "curl/8.7.1 (macOS/LibreSSL)"),
    // ("<hash from a [ja3] log line>", "Chrome 128 (macOS)"),
];

// Re-scan overlap so a signature match spanning a segment boundary isn't missed.
const SIG_SCAN_OVERLAP: usize = 64;
// Give up waiting for the rest of a ClientHello after this many bytes.
const CLIENTHELLO_CAP: usize = 4096;
// A real ClientHello arrives in a small handful of segments even over a
// constrained MTU path. Deliberately splitting it into many tiny segments is
// a known middlebox-evasion trick (outlast a DPI box's reassembly limit) -
// this many non-empty segments on a TLS-like port before the ClientHello
// resolves is itself a signal, independent of what's eventually in it.
const FRAGMENTATION_SEGMENT_THRESHOLD: u32 = 8;

struct FlowState {
    stream: TcpStream,
    sni: Option<String>,
    checked_entropy: bool,
    saw_syn: bool, // did we see this flow's actual SYN, or start capture mid-stream?
    sig_scanned_len: usize, // how far into stream.delivered signatures have scanned
    timing: TimingStats,
    ip_checked: bool,
    cannon_fired: bool,
    handshake_checked: bool, // TCP-side structural handshake match (e.g. SSH banner), once per flow
    host_checked: bool, // plaintext HTTP Host: header, once per flow - see classify::parse_http_host
    cert_checked: bool, // TLS <=1.2 Certificate message CN/SAN, once per flow - see classify::parse_tls_certificate_names
    h2_authority_checked: bool, // HTTP/2 :authority pseudo-header, once per flow - see h2::extract_authority
    ja3s_checked: bool, // server-side JA3 (ServerHello), once per flow - see classify::ja3s
    last_seen: Instant, // for idle eviction, see prune_idle_flows
    tls_segment_count: u32, // non-empty segments seen on a TLS-like port before ClientHello resolved
    fragmentation_flagged: bool, // single-shot, like checked_entropy - don't spam the log
}

pub struct Engine {
    streams: HashMap<FlowKey, FlowState>,
    udp_timing: HashMap<FlowKey, (TimingStats, Instant)>, // stats + last-seen, for idle eviction
    udp_allowlist_logged: std::collections::HashSet<FlowKey>, // one-shot gate, see allowlist_only check in handle_udp
    ip4_fragments: crate::fragment::FragmentTable<(Ipv4Addr, Ipv4Addr, u8, u16)>, // (src, dst, proto, IP id) - see fragment.rs
    ip6_fragments: crate::fragment::FragmentTable<(std::net::Ipv6Addr, std::net::Ipv6Addr, u32)>, // (src, dst, frag-header id)
    sigs: Signatures,
    handshake_rules: Vec<classify::HandshakeRule>, // known protocol handshake signatures, see config/handshakes.yml
    injector: Option<TransportSender>,
    injector_v6: Option<inject::Ipv6RstSender>, // None if inject_enabled is off or the platform lacks IPV6_HDRINCL
    inject_on_detect: bool, // separate opt-in: entropy detect is a heuristic, not a deterministic match
    dns_redirect: Option<(HashMap<String, Ipv4Addr>, TransportSender)>,
    dns_redirect_v6: Option<(HashMap<String, std::net::Ipv6Addr>, redirect::Ipv6DnsSender)>, // None if platform lacks IPV6_HDRINCL
    blocked_sni: Vec<String>,
    blocked_ja3: Vec<String>,
    blocked_ja3s: Vec<String>, // server-side JA3 counterpart, see classify::ja3s
    blocked_ja4: Vec<String>,
    blocked_ip: Vec<(String, Option<Instant>)>, // (ip, expiry) - None = permanent, Some = auto-escalated
    allowlist: Vec<String>, // IP/CIDR allow-list, only meaningful when allowlist_only is set
    allowlist_only: bool, // default-deny: block everything NOT on `allowlist`, ignoring blocked_ip entirely
    asn_ranges: Vec<crate::asn::AsnRange>, // ip -> ASN lookup table, see config/asn.yml
    blocked_asn: Vec<u32>,
    probe_targets: Vec<String>, // allow-list for active probing, see probe.rs
    cannon: CannonConfig, // response-injection allow-list + payload, see cannon.rs
    cannon_enabled: bool,
    lockdown_ips: Vec<(String, Instant)>, // deterministic pf-level blocks, see lockdown.rs
    lockdown_enabled: bool,
    block_ech: bool,  // block on encrypted_client_hello presence alone - can't read SNI to filter by name
    block_quic: bool, // force QUIC->TCP downgrade: blanket-drop UDP:443, see lockdown::build_ruleset
    doh_providers: Vec<(String, String)>, // ip_or_cidr -> name, see config/doh_providers.yml
    block_doh: bool, // off by default: [doh] just logs unless this is set
    trace: bool, // print every raw packet, not just classification/block events
    block_stats: BlockStats,
    escalation: HashMap<IpAddr, (u32, Instant)>, // offense count + window start, per source IP
}

impl Engine {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        inject_enabled: bool,
        inject_on_detect: bool,
        redirect_enabled: bool,
        blocked_sni: Vec<String>,
        blocked_ja3: Vec<String>,
        blocked_ja3s: Vec<String>,
        blocked_ja4: Vec<String>,
        blocked_ip: Vec<(String, Option<Duration>)>, // (ip, remaining TTL); None = permanent
        allowlist: Vec<String>,
        allowlist_only: bool,
        asn_ranges: Vec<crate::asn::AsnRange>,
        blocked_asn: Vec<u32>,
        signatures: Vec<String>,
        handshake_rules: Vec<classify::HandshakeRule>,
        redirect_map: Vec<(String, String)>,
        probe_targets: Vec<String>,
        cannon: CannonConfig,
        cannon_enabled: bool,
        lockdown_ips: Vec<(String, Duration)>, // (ip, remaining TTL)
        lockdown_enabled: bool,
        block_ech: bool,
        block_quic: bool,
        doh_providers: Vec<(String, String)>,
        block_doh: bool,
        trace: bool,
        block_stats: BlockStats,
    ) -> std::io::Result<Self> {
        let injector = if inject_enabled { Some(inject::open_raw_sender()?) } else { None };
        let injector_v6 = if inject_enabled {
            match inject::Ipv6RstSender::open() {
                Ok(sender) => Some(sender),
                Err(e) => {
                    log::info!("[inject-v6] disabled: {e}");
                    None
                }
            }
        } else {
            None
        };
        let dns_redirect = if redirect_enabled {
            let mut map = HashMap::new();
            for (orig, target_host) in &redirect_map {
                let ip = resolve_ipv4(target_host)
                    .unwrap_or_else(|| panic!("could not resolve redirect target {target_host}"));
                log::info!("[redirect] {orig} -> {target_host} ({ip})");
                map.insert(orig.to_string(), ip);
            }
            Some((map, redirect::open_raw_udp_sender()?))
        } else {
            None
        };
        let dns_redirect_v6 = if redirect_enabled {
            match redirect::Ipv6DnsSender::open() {
                Ok(sender) => {
                    let mut map = HashMap::new();
                    for (orig, target_host) in &redirect_map {
                        if let Some(ip) = resolve_ipv6(target_host) {
                            log::info!("[redirect-v6] {orig} -> {target_host} ({ip})");
                            map.insert(orig.to_string(), ip);
                        }
                    }
                    Some((map, sender))
                }
                Err(e) => {
                    log::info!("[redirect-v6] disabled: {e}");
                    None
                }
            }
        } else {
            None
        };
        for s in &blocked_sni {
            log::info!("[block-sni] {s}");
        }
        for h in &blocked_ja3 {
            log::info!("[block-ja3] {h}");
        }
        for h in &blocked_ja3s {
            log::info!("[block-ja3s] {h}");
        }
        for h in &blocked_ja4 {
            log::info!("[block-ja4] {h}");
        }
        for (ip, ttl) in &blocked_ip {
            match ttl {
                Some(d) => log::info!("[block-ip] {ip} (expires in {}s)", d.as_secs()),
                None => log::info!("[block-ip] {ip}"),
            }
        }
        for s in &signatures {
            log::info!("[block-sig] {s}");
        }
        for r in &handshake_rules {
            log::info!("[handshake] {} (length={:?}, {} anchors)", r.name, r.length, r.anchors.len());
        }
        if cannon_enabled {
            log::info!("[cannon] hosts={:?} marker={:?} redirect={:?}", cannon.hosts, cannon.marker, cannon.redirect);
        }
        for (ip, d) in &lockdown_ips {
            log::info!("[lockdown] {ip} (expires in {}s)", d.as_secs());
        }
        if block_ech {
            log::info!("[block-ech] blocking on encrypted_client_hello presence alone (no SNI to name)");
        }
        if block_quic {
            log::info!("[block-quic] blanket-dropping UDP:443 - QUIC forced to fall back to TCP+TLS");
        }
        if allowlist_only {
            log::info!("[allowlist-only] default-deny mode: {} entries, everything else blocked", allowlist.len());
        }
        for asn in &blocked_asn {
            log::info!("[block-asn] AS{asn} ({} ranges loaded)", asn_ranges.len());
        }
        if block_doh {
            log::info!("[block-doh] blocking on known DoH/DoT resolver IP match ({} providers loaded)", doh_providers.len());
        }
        let now = Instant::now();
        let blocked_ip = blocked_ip.into_iter().map(|(ip, ttl)| (ip, ttl.map(|d| now + d))).collect();
        let lockdown_ips = lockdown_ips.into_iter().map(|(ip, d)| (ip, now + d)).collect();
        Ok(Self {
            streams: HashMap::new(),
            udp_timing: HashMap::new(),
            udp_allowlist_logged: std::collections::HashSet::new(),
            ip4_fragments: crate::fragment::FragmentTable::new(),
            ip6_fragments: crate::fragment::FragmentTable::new(),
            sigs: Signatures::new(&signatures),
            handshake_rules,
            injector,
            injector_v6,
            inject_on_detect,
            dns_redirect,
            dns_redirect_v6,
            blocked_sni,
            blocked_ja3,
            blocked_ja3s,
            blocked_ja4,
            blocked_ip,
            allowlist,
            allowlist_only,
            asn_ranges,
            blocked_asn,
            probe_targets,
            cannon,
            cannon_enabled,
            lockdown_ips,
            lockdown_enabled,
            block_ech,
            block_quic,
            doh_providers,
            block_doh,
            trace,
            block_stats,
            escalation: HashMap::new(),
        })
    }

    /// IPv4 gets the full pipeline (RST injection, DNS redirect); IPv6 gets
    /// capture/reassembly/classification but no RST injection (needs a
    /// separate raw socket + IPv6 pseudo-header checksum, not done).
    pub fn handle_frame_v4(&mut self, ip: &Ipv4Packet) {
        let (src, dst) = (ip.get_source(), ip.get_destination());
        let proto = ip.get_next_level_protocol();
        // Fast path: the overwhelming common case (an unfragmented datagram)
        // costs nothing extra - only a fragment_offset != 0 or MF-set packet
        // ever touches the reassembly table.
        if ip.get_fragment_offset() == 0 && ip.get_flags() & Ipv4Flags::MoreFragments == 0 {
            self.dispatch(IpAddr::V4(src), IpAddr::V4(dst), proto, ip.payload());
            return;
        }
        let key = (src, dst, proto.0, ip.get_identification());
        let offset = ip.get_fragment_offset() as usize * 8; // wire units are 8-byte blocks
        let more = ip.get_flags() & Ipv4Flags::MoreFragments != 0;
        if let Some(reassembled) = self.ip4_fragments.insert(key, offset, more, ip.payload()) {
            log::info!("  [detect] ip-fragment-reassembled {src} -> {dst} (proto={}, {} bytes)", proto.0, reassembled.len());
            self.dispatch(IpAddr::V4(src), IpAddr::V4(dst), proto, &reassembled);
        }
    }

    pub fn handle_frame_v6(&mut self, ip: &Ipv6Packet) {
        let (src, dst) = (ip.get_source(), ip.get_destination());
        // A packet carrying Hop-by-Hop/Routing/Destination-Options/Fragment
        // extension headers has the real upper-layer protocol and payload
        // further in than `get_next_header()`/`payload()` alone would say -
        // see ipv6ext.rs.
        let (proto, payload, frag) = crate::ipv6ext::walk_ipv6_extensions(ip.get_next_header(), ip.payload());
        let Some(frag) = frag else {
            self.dispatch(IpAddr::V6(src), IpAddr::V6(dst), proto, payload);
            return;
        };
        let key = (src, dst, frag.id);
        let offset = frag.offset as usize * 8;
        if let Some(reassembled) = self.ip6_fragments.insert(key, offset, frag.more_fragments, payload) {
            log::info!("  [detect] ip-fragment-reassembled {src} -> {dst} (proto={}, {} bytes)", proto.0, reassembled.len());
            self.dispatch(IpAddr::V6(src), IpAddr::V6(dst), proto, &reassembled);
        }
    }

    fn dispatch(&mut self, src: IpAddr, dst: IpAddr, proto: pnet::packet::ip::IpNextHeaderProtocol, payload: &[u8]) {
        match proto {
            IpNextHeaderProtocols::Tcp => {
                if let Some(tcp) = TcpPacket::new(payload) {
                    self.handle_tcp(src, dst, &tcp);
                }
            }
            IpNextHeaderProtocols::Udp => {
                if let Some(udp) = UdpPacket::new(payload) {
                    self.handle_udp(src, dst, &udp);
                }
            }
            other => {
                if self.trace {
                    log::debug!("IP   {src} -> {dst}  proto={other:?}");
                }
            }
        }
    }

    /// Drop expired auto-escalated blocked_ip entries. List stays small, so
    /// just check once per packet rather than on a separate timer.
    fn prune_expired_ips(&mut self) {
        let now = Instant::now();
        let (kept, expired): (Vec<_>, Vec<_>) =
            std::mem::take(&mut self.blocked_ip).into_iter().partition(|(_, exp)| exp.is_none_or(|e| now < e));
        for (ip, _) in &expired {
            log::info!("  [escalate] {ip} block expired");
        }
        self.blocked_ip = kept;
    }

    /// Drop expired lockdown entries and, unlike prune_expired_ips, actually
    /// re-push the reduced set to pf - a stale rule left in the anchor keeps
    /// blocking traffic at the kernel level regardless of what dpi-lab's own
    /// in-memory state thinks.
    fn prune_expired_lockdowns(&mut self) {
        let now = Instant::now();
        let before = self.lockdown_ips.len();
        self.lockdown_ips.retain(|(_, exp)| now < *exp);
        if self.lockdown_ips.len() != before {
            let ips: Vec<String> = self.lockdown_ips.iter().map(|(ip, _)| ip.clone()).collect();
            if let Err(e) = lockdown::apply_all(&ips, self.block_quic) {
                log::error!("[lockdown] failed to update firewall rules after expiry: {e}");
            }
            log::info!("  [lockdown] expired entries removed, firewall rules updated");
        }
    }

    /// Drop flows with no activity in IDLE_TIMEOUT. A lab tool has no
    /// business tracking a flow forever just because neither side sent a
    /// clean FIN/RST we happened to observe.
    fn prune_idle_flows(&mut self) {
        let now = Instant::now();
        self.streams.retain(|_, s| now.duration_since(s.last_seen) < IDLE_TIMEOUT);
        self.udp_timing.retain(|_, (_, last_seen)| now.duration_since(*last_seen) < IDLE_TIMEOUT);
        let live: &HashMap<_, _> = &self.udp_timing;
        self.udp_allowlist_logged.retain(|k| live.contains_key(k));
        self.ip4_fragments.prune(IDLE_TIMEOUT);
        self.ip6_fragments.prune(IDLE_TIMEOUT);
    }

    fn handle_tcp(&mut self, src: IpAddr, dst: IpAddr, tcp: &TcpPacket) {
        self.prune_expired_ips(); // must run before `state` borrow below
        self.prune_expired_lockdowns();
        self.prune_idle_flows();
        let (sport, dport) = (tcp.get_source(), tcp.get_destination());
        let key = (src, sport, dst, dport);
        let syn = tcp.get_flags() & TcpFlags::SYN != 0;
        let payload = tcp.payload();

        // Backstop against flow-churn (many short-lived connections opened
        // just to grow this HashMap unbounded) - idle eviction above handles
        // the normal case, this is the hard cap for a genuinely new key.
        if !self.streams.contains_key(&key) && self.streams.len() >= MAX_FLOWS {
            if let Some(oldest) = self.streams.iter().min_by_key(|(_, s)| s.last_seen).map(|(k, _)| *k) {
                self.streams.remove(&oldest);
            }
        }

        // Cannon-eligibility check needs a second self.streams lookup (the
        // reverse flow's ISN), which can't happen once `state` below borrows
        // self.streams - so resolve it first, while nothing else is borrowed.
        let cannon_server_seq = if self.cannon_enabled
            && dport == self.cannon.port
            && looks_like_http_request(payload)
            && self.cannon.hosts.iter().any(|h| ip_rule_matches(h, &src))
            && self.cannon.hosts.iter().any(|h| ip_rule_matches(h, &dst))
        {
            self.streams.get(&(dst, dport, src, sport)).map(|s| s.stream.next_seq())
        } else {
            None
        };

        let state = self.streams.entry(key).or_insert_with(|| {
            // SYN's seq is the ISN; first data byte is ISN+1.
            let isn = if syn { tcp.get_sequence().wrapping_add(1) } else { tcp.get_sequence() };
            FlowState {
                stream: TcpStream::new(isn),
                sni: None,
                checked_entropy: false,
                saw_syn: syn,
                sig_scanned_len: 0,
                timing: TimingStats::new(),
                ip_checked: false,
                cannon_fired: false,
                handshake_checked: false,
                host_checked: false,
                cert_checked: false,
                h2_authority_checked: false,
                ja3s_checked: false,
                last_seen: Instant::now(),
                tls_segment_count: 0,
                fragmentation_flagged: false,
            }
        });
        state.last_seen = Instant::now();

        if let Some(server_seq) = cannon_server_seq {
            if !state.cannon_fired {
                state.cannon_fired = true;
                if let (IpAddr::V4(client4), IpAddr::V4(server4)) = (src, dst) {
                    let client_seq_after = tcp.get_sequence().wrapping_add(payload.len() as u32);
                    let body = cannon::build_http_response(&self.cannon.marker, self.cannon.redirect.as_deref());
                    if let Some(tx) = self.injector.as_mut() {
                        match cannon::inject_response(tx, server4, dport, client4, sport, server_seq, client_seq_after, &body) {
                            Ok(()) => log::info!("  [cannon] injected response to {src}:{sport} -> {dst}:{dport}"),
                            Err(e) => log::error!("  [cannon] failed: {e}"),
                        }
                    }
                }
            }
        }

        if !syn {
            state.stream.feed(tcp.get_sequence(), payload);
        }
        if !payload.is_empty() {
            state.timing.record(payload.len());
        }

        // Deliberate over-fragmentation of the ClientHello (many tiny
        // segments) is itself a middlebox-evasion signal - check before the
        // ClientHello retry logic below so it can fire even if the hello
        // never resolves within CLIENTHELLO_CAP.
        if !payload.is_empty() && !state.checked_entropy && !state.fragmentation_flagged
            && (TLS_LIKE_PORTS.contains(&dport) || TLS_LIKE_PORTS.contains(&sport))
        {
            state.tls_segment_count += 1;
            if state.tls_segment_count > FRAGMENTATION_SEGMENT_THRESHOLD {
                state.fragmentation_flagged = true;
                log::info!("  [detect] possible-fragmentation-evasion on {src}:{sport} -> {dst}:{dport}");
                if self.lockdown_enabled {
                    lockdown_on_match(&mut self.lockdown_ips, self.block_quic, src, "possible-fragmentation-evasion");
                }
                if self.inject_on_detect {
                    block(self.injector.as_mut(), self.injector_v6.as_ref(), &self.block_stats, &mut self.blocked_ip, &mut self.escalation, tcp, src, sport, dst, dport, payload, "detect", "possible-fragmentation-evasion");
                }
            }
        }

        // IP block needs no payload inspection, so check once per flow, first.
        if !state.ip_checked {
            state.ip_checked = true;
            if self.blocked_ip.iter().any(|(rule, _)| ip_rule_matches(rule, &src) || ip_rule_matches(rule, &dst)) {
                log::info!("  [ip] blocked flow {src}:{sport} -> {dst}:{dport}");
                block(self.injector.as_mut(), self.injector_v6.as_ref(), &self.block_stats, &mut self.blocked_ip, &mut self.escalation, tcp, src, sport, dst, dport, payload, "ip", "");
                if self.lockdown_enabled {
                    lockdown_on_match(&mut self.lockdown_ips, self.block_quic, src, "ip");
                }
            } else if self.allowlist_only && !self.allowlist.iter().any(|rule| ip_rule_matches(rule, &src) || ip_rule_matches(rule, &dst)) {
                // Default-deny mode: neither side of this flow is on the
                // allowlist, so it's blocked regardless of the (irrelevant
                // in this mode) blocked_ip list. IP/CIDR only for now - SNI
                // isn't known yet at this point in the flow.
                log::info!("  [ip] blocked flow {src}:{sport} -> {dst}:{dport} (not on allowlist)");
                block(self.injector.as_mut(), self.injector_v6.as_ref(), &self.block_stats, &mut self.blocked_ip, &mut self.escalation, tcp, src, sport, dst, dport, payload, "allowlist", "");
                if self.lockdown_enabled {
                    lockdown_on_match(&mut self.lockdown_ips, self.block_quic, src, "allowlist");
                }
            } else if !self.blocked_asn.is_empty() {
                let hit = [src, dst].into_iter().find_map(|ip| {
                    crate::asn::asn_for_ip(&self.asn_ranges, &ip).filter(|asn| self.blocked_asn.contains(asn)).map(|asn| (ip, asn))
                });
                if let Some((_, asn)) = hit {
                    log::info!("  [asn] blocked flow {src}:{sport} -> {dst}:{dport} (AS{asn})");
                    block(self.injector.as_mut(), self.injector_v6.as_ref(), &self.block_stats, &mut self.blocked_ip, &mut self.escalation, tcp, src, sport, dst, dport, payload, "asn", &asn.to_string());
                    if self.lockdown_enabled {
                        lockdown_on_match(&mut self.lockdown_ips, self.block_quic, src, "asn");
                    }
                }
            }
        }

        // Scan the reassembled stream, not each raw packet, so a keyword split
        // across a segment boundary isn't missed. Re-scan only the unseen suffix.
        let scan_from = state.sig_scanned_len.saturating_sub(SIG_SCAN_OVERLAP);
        let scan_buf = &state.stream.delivered[scan_from.min(state.stream.delivered.len())..];
        for hit in self.sigs.matches(scan_buf) {
            log::info!("  [signature] {hit} in {src}:{sport} -> {dst}:{dport}");
            block(self.injector.as_mut(), self.injector_v6.as_ref(), &self.block_stats, &mut self.blocked_ip, &mut self.escalation, tcp, src, sport, dst, dport, payload, "signature", hit);
            if self.lockdown_enabled {
                lockdown_on_match(&mut self.lockdown_ips, self.block_quic, src, "signature");
            }
        }
        state.sig_scanned_len = state.stream.delivered.len();

        // TCP-side structural handshakes (e.g. SSH's plaintext "SSH-..." version
        // banner, RFC 4253 §4.2) - same rule database as the UDP side, just
        // scoped to protocol: tcp/omitted rules via rule_applies_to. Checked
        // once per flow against the reassembled buffer, not the raw packet,
        // since a banner line could in principle be split across segments.
        if !state.handshake_checked && !state.stream.delivered.is_empty() {
            if let Some(rule) = self
                .handshake_rules
                .iter()
                .filter(|r| classify::rule_applies_to(r, "tcp"))
                .find(|r| classify::matches_handshake(&state.stream.delivered, r))
            {
                log::info!("  [detect] {} on {src}:{sport} -> {dst}:{dport}", rule.name);
                state.handshake_checked = true;
                if self.lockdown_enabled {
                    lockdown_on_match(&mut self.lockdown_ips, self.block_quic, src, &rule.name);
                }
                if self.inject_on_detect {
                    block(self.injector.as_mut(), self.injector_v6.as_ref(), &self.block_stats, &mut self.blocked_ip, &mut self.escalation, tcp, src, sport, dst, dport, payload, "handshake", &rule.name);
                }
            } else if state.stream.delivered.len() >= 32 {
                state.handshake_checked = true; // give up - not this protocol
            }
        }

        // ClientHellos can span multiple segments; retry against the growing
        // reassembled buffer until parsed or CLIENTHELLO_CAP is hit.
        if !state.checked_entropy && (TLS_LIKE_PORTS.contains(&dport) || TLS_LIKE_PORTS.contains(&sport)) {
            let buf = &state.stream.delivered;
            if let Some(ch) = parse_client_hello(buf) {
                // JA3 fingerprints the TLS stack, not the SNI, so check it regardless.
                if let Some((ja3_string, hash)) = ja3(buf) {
                    let label = KNOWN_JA3.iter().find(|(h, _)| *h == hash).map(|(_, l)| *l);
                    match label {
                        Some(l) => log::info!("  [ja3] {src}:{sport} -> {dst}:{dport}  ja3={hash} client={l} ({ja3_string})"),
                        None => log::info!("  [ja3] {src}:{sport} -> {dst}:{dport}  ja3={hash} client=unknown ({ja3_string})"),
                    }
                    if self.blocked_ja3.iter().any(|h| h == &hash) {
                        block(self.injector.as_mut(), self.injector_v6.as_ref(), &self.block_stats, &mut self.blocked_ip, &mut self.escalation, tcp, src, sport, dst, dport, payload, "ja3", &hash);
                        if self.lockdown_enabled {
                            lockdown_on_match(&mut self.lockdown_ips, self.block_quic, dst, "ja3");
                        }
                    }
                }
                if let Some(ja4_fp) = classify::ja4(buf) {
                    log::info!("  [ja4] {src}:{sport} -> {dst}:{dport}  ja4={ja4_fp}");
                    if self.blocked_ja4.iter().any(|h| h == &ja4_fp) {
                        block(self.injector.as_mut(), self.injector_v6.as_ref(), &self.block_stats, &mut self.blocked_ip, &mut self.escalation, tcp, src, sport, dst, dport, payload, "ja4", &ja4_fp);
                        if self.lockdown_enabled {
                            lockdown_on_match(&mut self.lockdown_ips, self.block_quic, dst, "ja4");
                        }
                    }
                }
                if let Some((_, name)) = self.doh_providers.iter().find(|(rule, _)| ip_rule_matches(rule, &dst)) {
                    log::info!("  [doh] {src}:{sport} -> {dst}:{dport}  known DoH/DoT resolver ({name})");
                    if self.block_doh {
                        block(self.injector.as_mut(), self.injector_v6.as_ref(), &self.block_stats, &mut self.blocked_ip, &mut self.escalation, tcp, src, sport, dst, dport, payload, "doh", name);
                        if self.lockdown_enabled {
                            lockdown_on_match(&mut self.lockdown_ips, self.block_quic, dst, "doh");
                        }
                    }
                }
                if ch.has_ech {
                    // ECH's outer ClientHello almost always still carries a
                    // plaintext SNI extension - the public "cover" name (e.g.
                    // Cloudflare's cover.defo.ie), not the real destination
                    // hidden inside the encrypted inner hello. Trusting that
                    // outer name would silently defeat the whole point of
                    // blocking ECH, so this branch fires on has_ech alone,
                    // unconditionally - it does NOT fall through to the SNI
                    // branch below even when ch.sni is Some.
                    let outer = ch.sni.as_deref().unwrap_or("none");
                    log::info!("  [ech] {src}:{sport} -> {dst}:{dport}  encrypted_client_hello present, outer/cover sni={outer} (real destination hidden)");
                    if self.block_ech {
                        block(self.injector.as_mut(), self.injector_v6.as_ref(), &self.block_stats, &mut self.blocked_ip, &mut self.escalation, tcp, src, sport, dst, dport, payload, "ech", outer);
                        if self.lockdown_enabled {
                            lockdown_on_match(&mut self.lockdown_ips, self.block_quic, dst, "ech");
                        }
                    }
                } else if let Some(name) = ch.sni {
                    log::info!("  [sni] {src}:{sport} -> {dst}:{dport}  server_name={name}");
                    if self.blocked_sni.iter().any(|s| s == &name) {
                        block(self.injector.as_mut(), self.injector_v6.as_ref(), &self.block_stats, &mut self.blocked_ip, &mut self.escalation, tcp, src, sport, dst, dport, payload, "sni", &name);
                        if self.lockdown_enabled {
                            lockdown_on_match(&mut self.lockdown_ips, self.block_quic, dst, "sni");
                        }
                    }
                    state.sni = Some(name);
                }
                state.checked_entropy = true; // real ClientHello, no need to score entropy
            } else if state.saw_syn && buf.len() >= CLIENTHELLO_CAP {
                let candidate_port = if TLS_LIKE_PORTS.contains(&dport) { dport } else { sport };
                if let Some(label) = classify_first_segment(buf, candidate_port) {
                    log::info!("  [detect] {label} on {src}:{sport} -> {dst}:{dport}");
                    // Probe only against allow-listed hosts; no target -> trust the heuristic.
                    let confirmed = match [src, dst].into_iter().find(|ip| self.probe_targets.iter().any(|r| ip_rule_matches(r, ip))) {
                        None => true,
                        Some(target) => match probe::probe(target, candidate_port) {
                            Some(proto) => {
                                log::info!("  [probe] confirmed {proto} on {target}:{candidate_port}");
                                true
                            }
                            None => {
                                log::info!("  [probe] no known protocol matched on {target}:{candidate_port} - not blocking");
                                false
                            }
                        },
                    };
                    if self.inject_on_detect && confirmed {
                        block(self.injector.as_mut(), self.injector_v6.as_ref(), &self.block_stats, &mut self.blocked_ip, &mut self.escalation, tcp, src, sport, dst, dport, payload, "detect", label);
                        if self.lockdown_enabled {
                            lockdown_on_match(&mut self.lockdown_ips, self.block_quic, src, "detect");
                        }
                    }
                }
                state.checked_entropy = true;
            }
        }

        // Plaintext HTTP has no SNI to filter on, but names its destination in
        // the clear via the Host: header - the GFW has always inspected this
        // too, not just TLS. Scanned once per flow against the reassembled
        // buffer, same reasoning as the ClientHello retry above (Host header
        // could in principle split across segments).
        if !state.host_checked && !state.stream.delivered.is_empty() {
            if let Some(name) = classify::parse_http_host(&state.stream.delivered) {
                log::info!("  [host] {src}:{sport} -> {dst}:{dport}  host={name}");
                if self.blocked_sni.iter().any(|s| s == &name) {
                    block(self.injector.as_mut(), self.injector_v6.as_ref(), &self.block_stats, &mut self.blocked_ip, &mut self.escalation, tcp, src, sport, dst, dport, payload, "host", &name);
                    if self.lockdown_enabled {
                        lockdown_on_match(&mut self.lockdown_ips, self.block_quic, dst, "host");
                    }
                }
                state.host_checked = true;
            } else if state.stream.delivered.len() >= CLIENTHELLO_CAP {
                state.host_checked = true; // give up - not a plaintext HTTP request
            }
        }

        // TLS <=1.2 Certificate message: sent by the server, so on whichever
        // flow direction happens to carry it (the server->client one) - no
        // cross-flow correlation needed, this check runs per-flow same as
        // everything else and simply finds nothing on the other direction.
        // TLS 1.3 naturally never matches here (message is encrypted).
        if !state.cert_checked && !state.stream.delivered.is_empty() {
            if let Some(names) = classify::parse_tls_certificate_names(&state.stream.delivered) {
                log::info!("  [cert] {src}:{sport} -> {dst}:{dport}  names={names:?}");
                if names.iter().any(|n| self.blocked_sni.iter().any(|s| s == n)) {
                    block(self.injector.as_mut(), self.injector_v6.as_ref(), &self.block_stats, &mut self.blocked_ip, &mut self.escalation, tcp, src, sport, dst, dport, payload, "cert", &names.join(","));
                    if self.lockdown_enabled {
                        lockdown_on_match(&mut self.lockdown_ips, self.block_quic, src, "cert");
                    }
                }
                state.cert_checked = true;
            } else if state.stream.delivered.len() >= CLIENTHELLO_CAP * 4 {
                // Cert chains run bigger than a ClientHello - a wider cap
                // before giving up, still bounded so a non-TLS flow doesn't
                // get rescanned on every packet forever.
                state.cert_checked = true;
            }
        }

        // JA3S: the server-side counterpart of JA3, from the ServerHello
        // (server->client direction, same "try, no-op on the wrong
        // direction's bytes" reasoning as the cert check above). Useful
        // independent of SNI - e.g. flagging a distinctive/fake TLS stack
        // regardless of what hostname the client asked for.
        if !state.ja3s_checked && !state.stream.delivered.is_empty() {
            if let Some((ja3s_string, hash)) = classify::ja3s(&state.stream.delivered) {
                log::info!("  [ja3s] {src}:{sport} -> {dst}:{dport}  ja3s={hash} ({ja3s_string})");
                if self.blocked_ja3s.iter().any(|h| h == &hash) {
                    block(self.injector.as_mut(), self.injector_v6.as_ref(), &self.block_stats, &mut self.blocked_ip, &mut self.escalation, tcp, src, sport, dst, dport, payload, "ja3s", &hash);
                    if self.lockdown_enabled {
                        lockdown_on_match(&mut self.lockdown_ips, self.block_quic, src, "ja3s");
                    }
                }
                state.ja3s_checked = true;
            } else if state.stream.delivered.len() >= CLIENTHELLO_CAP {
                state.ja3s_checked = true; // give up - not a ServerHello
            }
        }

        // HTTP/2's :authority pseudo-header names the destination the way
        // HTTP/1.1's Host: header does, just HPACK-compressed - only fires on
        // the client->server direction (the one carrying the preface).
        if !state.h2_authority_checked && !state.stream.delivered.is_empty() {
            if let Some(name) = h2::extract_authority(&state.stream.delivered) {
                log::info!("  [h2-authority] {src}:{sport} -> {dst}:{dport}  authority={name}");
                if self.blocked_sni.iter().any(|s| s == &name) {
                    block(self.injector.as_mut(), self.injector_v6.as_ref(), &self.block_stats, &mut self.blocked_ip, &mut self.escalation, tcp, src, sport, dst, dport, payload, "h2-authority", &name);
                    if self.lockdown_enabled {
                        lockdown_on_match(&mut self.lockdown_ips, self.block_quic, dst, "h2-authority");
                    }
                }
                state.h2_authority_checked = true;
            } else if state.stream.delivered.len() >= CLIENTHELLO_CAP {
                state.h2_authority_checked = true; // give up - not h2, or headers didn't arrive in one frame
            }
        }

        if let Some(label) = state.timing.check() {
            log::info!("  [timing] {label} on {src}:{sport} -> {dst}:{dport}");
        }

        if self.trace {
            log::debug!(
                "TCP  {src}:{sport} -> {dst}:{dport}  len={len}  reassembled={total}",
                len = payload.len(),
                total = state.stream.delivered.len(),
            );
        }
    }

    fn handle_udp(&mut self, src: IpAddr, dst: IpAddr, udp: &UdpPacket) {
        self.prune_idle_flows();
        let (sport, dport) = (udp.get_source(), udp.get_destination());
        let payload = udp.payload();

        let key = (src, sport, dst, dport);
        let (timing, last_seen) = self.udp_timing.entry(key).or_insert_with(|| (TimingStats::new(), Instant::now()));
        *last_seen = Instant::now();
        if !payload.is_empty() {
            timing.record(payload.len());
        }
        if let Some(label) = timing.check() {
            log::info!("  [timing] {label} on {src}:{sport} -> {dst}:{dport}");
        }

        // Default-deny mode, UDP side: no RST-equivalent for UDP (see the
        // handshake-rule branch below), so this is lockdown-only, and only
        // fires once per flow (a log line per packet would flood the log).
        if self.allowlist_only && !self.allowlist.iter().any(|rule| ip_rule_matches(rule, &src) || ip_rule_matches(rule, &dst)) {
            if self.udp_allowlist_logged.insert(key) {
                log::info!("  [ip] blocked flow {src}:{sport} -> {dst}:{dport} (not on allowlist)");
            }
            if self.lockdown_enabled {
                lockdown_on_match(&mut self.lockdown_ips, self.block_quic, src, "allowlist");
            }
        }

        // dport==53: this is a client's outbound query to a resolver at `dst`.
        if dport == 53 {
            if let Some(query) = parse_dns_query_full(payload) {
                log::info!("  [dns] {src}:{sport} -> {dst}:{dport}  query={}", query.name);
                if let (Some((map, tx)), IpAddr::V4(dst4), IpAddr::V4(src4)) = (self.dns_redirect.as_mut(), dst, src) {
                    if let Some(&answer_ip) = map.get(&query.name) {
                        match redirect::send_dns_redirect_flood(tx, dst4, src4, sport, &query, answer_ip) {
                            Ok(()) => log::info!("  [redirect] spoofed A record {} -> {answer_ip}", query.name),
                            Err(e) => log::error!("  [redirect] failed: {e}"),
                        }
                    }
                }
                if let (Some((map, tx)), IpAddr::V6(dst6), IpAddr::V6(src6)) = (self.dns_redirect_v6.as_ref(), dst, src) {
                    if let Some(&answer_ip) = map.get(&query.name) {
                        match redirect::send_dns_redirect_v6_flood(tx, dst6, src6, sport, &query, answer_ip) {
                            Ok(()) => log::info!("  [redirect] spoofed AAAA record {} -> {answer_ip}", query.name),
                            Err(e) => log::error!("  [redirect] failed: {e}"),
                        }
                    }
                }
            }
        } else if sport == 53 {
            if let Some(name) = parse_dns_query_full(payload).map(|q| q.name) {
                log::info!("  [dns] {src}:{sport} -> {dst}:{dport}  query={name}");
            }
        } else if dport == 5353 || sport == 5353 {
            // mDNS (RFC 6762) - same wire format as unicast DNS, reuse the
            // parser as-is. Multicast, so there's no single resolver to spoof
            // an answer to the way --redirect-dns does for unicast :53 -
            // detection/log only.
            if let Some(query) = parse_dns_query_full(payload) {
                log::info!("  [mdns] {src}:{sport} -> {dst}:{dport}  query={}", query.name);
            }
        } else if dport == 443 || sport == 443 {
            // QUIC Initial packets are decryptable without keys - RFC 9001 §5.2
            // derives them from a public salt, not the real handshake secret.
            // See quic.rs. Everything past the Initial (Handshake, 1-RTT/app
            // data) stays opaque, same blind spot as post-handshake TCP TLS.
            if let Some(record) = crate::quic::decrypt_initial_client_hello_record(payload) {
                if let Some((ja3_string, hash)) = ja3(&record) {
                    log::info!("  [quic-ja3] {src}:{sport} -> {dst}:{dport}  ja3={hash} ({ja3_string})");
                    if self.blocked_ja3.iter().any(|h| h == &hash) {
                        if self.lockdown_enabled {
                            lockdown_on_match(&mut self.lockdown_ips, self.block_quic, dst, "ja3");
                        }
                    }
                }
                if let Some(ja4_fp) = classify::ja4(&record) {
                    log::info!("  [quic-ja4] {src}:{sport} -> {dst}:{dport}  ja4={ja4_fp}");
                    if self.blocked_ja4.iter().any(|h| h == &ja4_fp) && self.lockdown_enabled {
                        lockdown_on_match(&mut self.lockdown_ips, self.block_quic, dst, "ja4");
                    }
                }
                if let Some(name) = classify::parse_sni(&record) {
                    log::info!("  [quic-sni] {src}:{sport} -> {dst}:{dport}  server_name={name}");
                    if self.blocked_sni.iter().any(|s| s == &name) && self.lockdown_enabled {
                        lockdown_on_match(&mut self.lockdown_ips, self.block_quic, dst, "sni");
                    }
                }
            }
        } else if let Some(rule) = self
            .handshake_rules
            .iter()
            .filter(|r| classify::rule_applies_to(r, "udp"))
            .find(|r| classify::matches_handshake(payload, r))
        {
            // Structural recognition (byte anchors + exact length from
            // config/handshakes.yml), not a keyword search - fires on any
            // connection attempting that handshake regardless of destination
            // IP/port, not just one already on a blocklist. This only ever
            // catches the handshake message itself, not an already-established
            // session (those look like opaque encrypted data, same blind spot
            // as obfs4 - see detect.rs). UDP has no RST equivalent, so
            // --inject doesn't apply here; --lockdown (IP-level,
            // protocol-agnostic) does.
            log::info!("  [detect] {} on {src}:{sport} -> {dst}:{dport}", rule.name);
            if self.lockdown_enabled {
                lockdown_on_match(&mut self.lockdown_ips, self.block_quic, src, &rule.name);
            }
        }
        if self.trace {
            log::debug!("UDP  {src}:{sport} -> {dst}:{dport}  len={len}", len = payload.len());
        }
    }
}

/// Reset both ends of a matched flow, if injection is enabled - IPv4 via
/// `injector`, IPv6 via `injector_v6` (see inject::Ipv6RstSender; None on a
/// platform that can't open it, same fallback shape as dns_redirect_v6).
/// Returns true if the RST fired, so the caller can count it toward escalation.
#[allow(clippy::too_many_arguments)]
fn try_reset(
    injector: Option<&mut TransportSender>,
    injector_v6: Option<&inject::Ipv6RstSender>,
    stats: &BlockStats,
    tcp: &TcpPacket,
    src: IpAddr,
    sport: u16,
    dst: IpAddr,
    dport: u16,
    payload: &[u8],
    kind: &str,
    detail: &str,
) -> bool {
    let seq_to_dst = tcp.get_sequence().wrapping_add(payload.len() as u32);
    let seq_to_src = tcp.get_acknowledgement();
    let reason = if detail.is_empty() { kind.to_string() } else { format!("{kind} block: {detail}") };
    let result = match (src, dst) {
        (IpAddr::V4(src4), IpAddr::V4(dst4)) => {
            let Some(tx) = injector else { return false };
            inject::reset_flow(tx, src4, sport, dst4, dport, seq_to_dst, seq_to_src)
        }
        (IpAddr::V6(src6), IpAddr::V6(dst6)) => {
            let Some(tx) = injector_v6 else { return false };
            inject::reset_flow_v6(tx, src6, sport, dst6, dport, seq_to_dst, seq_to_src)
        }
        _ => return false, // mixed v4/v6 src/dst never happens on a real flow
    };
    match result {
        Ok(()) => {
            log::info!("  [inject] RST sent both directions ({reason})");
            *stats.lock().unwrap().entry(kind.to_string()).or_insert(0) += 1;
            true
        }
        Err(e) => {
            log::error!("  [inject] failed: {e}");
            false
        }
    }
}

/// Wraps `try_reset` with escalation tracking. Free function (not &mut self)
/// so callers can hold a live borrow into self.streams at the same time.
#[allow(clippy::too_many_arguments)]
fn block(
    injector: Option<&mut TransportSender>,
    injector_v6: Option<&inject::Ipv6RstSender>,
    stats: &BlockStats,
    blocked_ip: &mut Vec<(String, Option<Instant>)>,
    escalation: &mut HashMap<IpAddr, (u32, Instant)>,
    tcp: &TcpPacket,
    src: IpAddr,
    sport: u16,
    dst: IpAddr,
    dport: u16,
    payload: &[u8],
    kind: &str,
    detail: &str,
) {
    let fired = try_reset(injector, injector_v6, stats, tcp, src, sport, dst, dport, payload, kind, detail);
    if !fired {
        return;
    }
    let now = Instant::now();
    let entry = escalation.entry(src).or_insert((0, now));
    if now.duration_since(entry.1) > ESCALATE_WINDOW {
        *entry = (0, now); // window expired, offense count resets
    }
    entry.0 += 1;
    let (count, _) = *entry;
    let src_s = src.to_string();
    if count >= ESCALATE_THRESHOLD && !blocked_ip.iter().any(|(ip, _)| ip == &src_s) {
        log::info!("  [escalate] auto-blocking {src_s} after {count} offenses in {ESCALATE_WINDOW:?} (expires in {ESCALATION_TTL:?}, persisted)");
        let expires_at = std::time::SystemTime::now() + ESCALATION_TTL;
        let epoch = expires_at.duration_since(std::time::UNIX_EPOCH).unwrap().as_secs();
        crate::config::set_expiry_entry(std::path::Path::new(ESCALATED_IP_FILE), &src_s, epoch);
        blocked_ip.push((src_s, Some(Instant::now() + ESCALATION_TTL)));
    }
}

/// --lockdown: any match (IP/SNI/JA3/signature/detect) locks the source IP
/// down at the pf level immediately, independent of whether the RST race
/// above fired or even ran (lockdown doesn't need --inject's raw socket at
/// all) - a deterministic kernel drop rather than a raced packet.
fn lockdown_on_match(lockdown_ips: &mut Vec<(String, Instant)>, block_quic: bool, src: IpAddr, kind: &str) {
    let src_s = src.to_string();
    if lockdown_ips.iter().any(|(ip, _)| ip == &src_s) {
        return; // already locked down
    }
    lockdown_ips.push((src_s.clone(), Instant::now() + LOCKDOWN_TTL));
    let ips: Vec<String> = lockdown_ips.iter().map(|(ip, _)| ip.clone()).collect();
    if let Err(e) = lockdown::apply_all(&ips, block_quic) {
        log::error!("  [lockdown] failed to apply firewall rule for {src_s}: {e}");
        lockdown_ips.pop(); // roll back - firewall state and our list must agree
        return;
    }
    let epoch = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_secs() + LOCKDOWN_TTL.as_secs();
    crate::config::set_expiry_entry(std::path::Path::new(LOCKDOWN_FILE), &src_s, epoch);
    log::info!("  [lockdown] {src_s} blocked at firewall level ({kind} match, expires in {LOCKDOWN_TTL:?})");
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn prune_expired_ips_drops_only_expired_entries() {
        // inject/redirect both off, so no raw socket (root) needed.
        let mut engine = Engine::new(false, false, false, vec![], vec![], vec![], vec![], vec![
            ("expired".to_string(), Some(Duration::from_secs(0))),
            ("still-blocked".to_string(), Some(Duration::from_secs(3600))),
            ("permanent".to_string(), None),
        ], vec![], false, vec![], vec![], vec![], vec![], vec![], vec![], CannonConfig::default(), false, vec![], false, false, false, vec![], false, false, Arc::new(Mutex::new(HashMap::new())))
        .unwrap();
        std::thread::sleep(Duration::from_millis(5)); // let the zero-TTL entry actually pass
        engine.prune_expired_ips();
        let remaining: Vec<&str> = engine.blocked_ip.iter().map(|(ip, _)| ip.as_str()).collect();
        assert_eq!(remaining, vec!["still-blocked", "permanent"]);
    }

    #[test]
    fn prune_idle_flows_drops_stale_entries() {
        let mut engine = Engine::new(false, false, false, vec![], vec![], vec![], vec![], vec![], vec![], false, vec![], vec![], vec![], vec![], vec![], vec![], CannonConfig::default(), false, vec![], false, false, false, vec![], false, false, Arc::new(Mutex::new(HashMap::new())))
        .unwrap();
        let stale_key = ("10.0.0.1".parse().unwrap(), 1, "10.0.0.2".parse().unwrap(), 2);
        let fresh_key = ("10.0.0.3".parse().unwrap(), 3, "10.0.0.4".parse().unwrap(), 4);
        let mut stale = FlowState {
            stream: TcpStream::new(0),
            sni: None,
            checked_entropy: false,
            saw_syn: false,
            sig_scanned_len: 0,
            timing: TimingStats::new(),
            ip_checked: false,
            cannon_fired: false,
            handshake_checked: false,
            host_checked: false,
                cert_checked: false,
                h2_authority_checked: false,
                ja3s_checked: false,
            last_seen: Instant::now(),
            tls_segment_count: 0,
            fragmentation_flagged: false,
        };
        stale.last_seen -= IDLE_TIMEOUT + Duration::from_secs(1);
        let mut fresh = FlowState {
            stream: TcpStream::new(0),
            sni: None,
            checked_entropy: false,
            saw_syn: false,
            sig_scanned_len: 0,
            timing: TimingStats::new(),
            ip_checked: false,
            cannon_fired: false,
            handshake_checked: false,
            host_checked: false,
                cert_checked: false,
                h2_authority_checked: false,
                ja3s_checked: false,
            last_seen: Instant::now(),
            tls_segment_count: 0,
            fragmentation_flagged: false,
        };
        fresh.last_seen = Instant::now();
        engine.streams.insert(stale_key, stale);
        engine.streams.insert(fresh_key, fresh);
        engine.prune_idle_flows();
        assert!(!engine.streams.contains_key(&stale_key));
        assert!(engine.streams.contains_key(&fresh_key));
    }

    #[test]
    fn exact_ip_match() {
        let ip: IpAddr = "10.27.0.39".parse().unwrap();
        assert!(ip_rule_matches("10.27.0.39", &ip));
        assert!(!ip_rule_matches("10.27.0.40", &ip));
    }

    #[test]
    fn cidr_match_within_range() {
        let inside: IpAddr = "10.27.0.39".parse().unwrap();
        let outside: IpAddr = "10.27.1.5".parse().unwrap();
        assert!(ip_rule_matches("10.27.0.0/24", &inside));
        assert!(!ip_rule_matches("10.27.0.0/24", &outside));
    }

    #[test]
    fn cidr_edge_cases() {
        let ip: IpAddr = "10.27.0.39".parse().unwrap();
        assert!(ip_rule_matches("0.0.0.0/0", &ip)); // matches everything
        assert!(ip_rule_matches("10.27.0.39/32", &ip)); // exact via CIDR
        assert!(!ip_rule_matches("10.27.0.39/33", &ip)); // invalid prefix, no match
        assert!(!ip_rule_matches("not-an-ip/24", &ip)); // malformed, no match
    }

    #[test]
    fn cidr_ignores_ipv6() {
        let ip: IpAddr = "::1".parse().unwrap();
        assert!(!ip_rule_matches("10.27.0.0/24", &ip));
    }
}
