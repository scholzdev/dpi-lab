// Per-packet pipeline: decode -> reassemble -> classify -> (optionally) inject/redirect.
// Owns all mutable state so main.rs stays just capture loop + CLI.
use crate::cannon;
use crate::classify::{ja3, parse_dns_query_full, parse_client_hello, Signatures};
use crate::config::CannonConfig;
use crate::detect::{classify_first_segment, TLS_LIKE_PORTS};
use crate::inject::{self, TransportSender};
use crate::lockdown;
use crate::reassembly::TcpStream;
use crate::probe;
use crate::redirect;
use crate::timing::TimingStats;
use pnet::packet::ip::IpNextHeaderProtocols;
use pnet::packet::ipv4::Ipv4Packet;
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

/// Crude but sufficient check for "this looks like the start of an HTTP request".
fn looks_like_http_request(payload: &[u8]) -> bool {
    const METHODS: [&[u8]; 4] = [b"GET ", b"POST ", b"HEAD ", b"PUT "];
    METHODS.iter().any(|m| payload.starts_with(m))
}

/// True if `rule` matches `ip` - exact address, or (IPv4) a CIDR range.
fn ip_rule_matches(rule: &str, ip: &IpAddr) -> bool {
    match rule.split_once('/') {
        Some((base, bits)) => {
            let (IpAddr::V4(ip4), Ok(base4), Ok(bits)) = (ip, base.parse::<Ipv4Addr>(), bits.parse::<u32>()) else {
                return false;
            };
            if bits > 32 {
                return false;
            }
            let mask = if bits == 0 { 0 } else { !0u32 << (32 - bits) };
            u32::from(*ip4) & mask == u32::from(base4) & mask
        }
        None => rule == ip.to_string(),
    }
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

struct FlowState {
    stream: TcpStream,
    sni: Option<String>,
    checked_entropy: bool,
    saw_syn: bool, // did we see this flow's actual SYN, or start capture mid-stream?
    sig_scanned_len: usize, // how far into stream.delivered signatures have scanned
    timing: TimingStats,
    ip_checked: bool,
    cannon_fired: bool,
}

pub struct Engine {
    streams: HashMap<FlowKey, FlowState>,
    udp_timing: HashMap<FlowKey, TimingStats>,
    sigs: Signatures,
    injector: Option<TransportSender>,
    inject_on_detect: bool, // separate opt-in: entropy detect is a heuristic, not a deterministic match
    dns_redirect: Option<(HashMap<String, Ipv4Addr>, TransportSender)>,
    dns_redirect_v6: Option<(HashMap<String, std::net::Ipv6Addr>, redirect::Ipv6DnsSender)>, // None if platform lacks IPV6_HDRINCL
    blocked_sni: Vec<String>,
    blocked_ja3: Vec<String>,
    blocked_ip: Vec<(String, Option<Instant>)>, // (ip, expiry) - None = permanent, Some = auto-escalated
    probe_targets: Vec<String>, // allow-list for active probing, see probe.rs
    cannon: CannonConfig, // response-injection allow-list + payload, see cannon.rs
    cannon_enabled: bool,
    lockdown_ips: Vec<(String, Instant)>, // deterministic pf-level blocks, see lockdown.rs
    lockdown_enabled: bool,
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
        blocked_ip: Vec<(String, Option<Duration>)>, // (ip, remaining TTL); None = permanent
        signatures: Vec<String>,
        redirect_map: Vec<(String, String)>,
        probe_targets: Vec<String>,
        cannon: CannonConfig,
        cannon_enabled: bool,
        lockdown_ips: Vec<(String, Duration)>, // (ip, remaining TTL)
        lockdown_enabled: bool,
        trace: bool,
        block_stats: BlockStats,
    ) -> std::io::Result<Self> {
        let injector = if inject_enabled { Some(inject::open_raw_sender()?) } else { None };
        let dns_redirect = if redirect_enabled {
            let mut map = HashMap::new();
            for (orig, target_host) in &redirect_map {
                let ip = resolve_ipv4(target_host)
                    .unwrap_or_else(|| panic!("could not resolve redirect target {target_host}"));
                println!("[redirect] {orig} -> {target_host} ({ip})");
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
                            println!("[redirect-v6] {orig} -> {target_host} ({ip})");
                            map.insert(orig.to_string(), ip);
                        }
                    }
                    Some((map, sender))
                }
                Err(e) => {
                    println!("[redirect-v6] disabled: {e}");
                    None
                }
            }
        } else {
            None
        };
        for s in &blocked_sni {
            println!("[block-sni] {s}");
        }
        for h in &blocked_ja3 {
            println!("[block-ja3] {h}");
        }
        for (ip, ttl) in &blocked_ip {
            match ttl {
                Some(d) => println!("[block-ip] {ip} (expires in {}s)", d.as_secs()),
                None => println!("[block-ip] {ip}"),
            }
        }
        for s in &signatures {
            println!("[block-sig] {s}");
        }
        if cannon_enabled {
            println!("[cannon] hosts={:?} marker={:?} redirect={:?}", cannon.hosts, cannon.marker, cannon.redirect);
        }
        for (ip, d) in &lockdown_ips {
            println!("[lockdown] {ip} (expires in {}s)", d.as_secs());
        }
        let now = Instant::now();
        let blocked_ip = blocked_ip.into_iter().map(|(ip, ttl)| (ip, ttl.map(|d| now + d))).collect();
        let lockdown_ips = lockdown_ips.into_iter().map(|(ip, d)| (ip, now + d)).collect();
        Ok(Self {
            streams: HashMap::new(),
            udp_timing: HashMap::new(),
            sigs: Signatures::new(&signatures),
            injector,
            inject_on_detect,
            dns_redirect,
            dns_redirect_v6,
            blocked_sni,
            blocked_ja3,
            blocked_ip,
            probe_targets,
            cannon,
            cannon_enabled,
            lockdown_ips,
            lockdown_enabled,
            trace,
            block_stats,
            escalation: HashMap::new(),
        })
    }

    /// IPv4 gets the full pipeline (RST injection, DNS redirect); IPv6 gets
    /// capture/reassembly/classification but no RST injection (needs a
    /// separate raw socket + IPv6 pseudo-header checksum, not done).
    pub fn handle_frame_v4(&mut self, ip: &Ipv4Packet) {
        let (src, dst) = (IpAddr::V4(ip.get_source()), IpAddr::V4(ip.get_destination()));
        self.dispatch(src, dst, ip.get_next_level_protocol(), ip.payload());
    }

    pub fn handle_frame_v6(&mut self, ip: &Ipv6Packet) {
        let (src, dst) = (IpAddr::V6(ip.get_source()), IpAddr::V6(ip.get_destination()));
        self.dispatch(src, dst, ip.get_next_header(), ip.payload());
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
                    println!("IP   {src} -> {dst}  proto={other:?}");
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
            println!("  [escalate] {ip} block expired");
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
            if let Err(e) = lockdown::apply_all(&ips) {
                eprintln!("[lockdown] failed to update firewall rules after expiry: {e}");
            }
            println!("  [lockdown] expired entries removed, firewall rules updated");
        }
    }

    fn handle_tcp(&mut self, src: IpAddr, dst: IpAddr, tcp: &TcpPacket) {
        self.prune_expired_ips(); // must run before `state` borrow below
        self.prune_expired_lockdowns();
        let (sport, dport) = (tcp.get_source(), tcp.get_destination());
        let key = (src, sport, dst, dport);
        let syn = tcp.get_flags() & TcpFlags::SYN != 0;
        let payload = tcp.payload();

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
            }
        });

        if let Some(server_seq) = cannon_server_seq {
            if !state.cannon_fired {
                state.cannon_fired = true;
                if let (IpAddr::V4(client4), IpAddr::V4(server4)) = (src, dst) {
                    let client_seq_after = tcp.get_sequence().wrapping_add(payload.len() as u32);
                    let body = cannon::build_http_response(&self.cannon.marker, self.cannon.redirect.as_deref());
                    if let Some(tx) = self.injector.as_mut() {
                        match cannon::inject_response(tx, server4, dport, client4, sport, server_seq, client_seq_after, &body) {
                            Ok(()) => println!("  [cannon] injected response to {src}:{sport} -> {dst}:{dport}"),
                            Err(e) => eprintln!("  [cannon] failed: {e}"),
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

        // IP block needs no payload inspection, so check once per flow, first.
        if !state.ip_checked {
            state.ip_checked = true;
            if self.blocked_ip.iter().any(|(rule, _)| ip_rule_matches(rule, &src) || ip_rule_matches(rule, &dst)) {
                println!("  [ip] blocked flow {src}:{sport} -> {dst}:{dport}");
                block(self.injector.as_mut(), &self.block_stats, &mut self.blocked_ip, &mut self.escalation, tcp, src, sport, dst, dport, payload, "ip", "");
                if self.lockdown_enabled {
                    lockdown_on_match(&mut self.lockdown_ips, src, "ip");
                }
            }
        }

        // Scan the reassembled stream, not each raw packet, so a keyword split
        // across a segment boundary isn't missed. Re-scan only the unseen suffix.
        let scan_from = state.sig_scanned_len.saturating_sub(SIG_SCAN_OVERLAP);
        let scan_buf = &state.stream.delivered[scan_from.min(state.stream.delivered.len())..];
        for hit in self.sigs.matches(scan_buf) {
            println!("  [signature] {hit} in {src}:{sport} -> {dst}:{dport}");
            block(self.injector.as_mut(), &self.block_stats, &mut self.blocked_ip, &mut self.escalation, tcp, src, sport, dst, dport, payload, "signature", hit);
            if self.lockdown_enabled {
                lockdown_on_match(&mut self.lockdown_ips, src, "signature");
            }
        }
        state.sig_scanned_len = state.stream.delivered.len();

        // ClientHellos can span multiple segments; retry against the growing
        // reassembled buffer until parsed or CLIENTHELLO_CAP is hit.
        if !state.checked_entropy && (TLS_LIKE_PORTS.contains(&dport) || TLS_LIKE_PORTS.contains(&sport)) {
            let buf = &state.stream.delivered;
            if let Some(ch) = parse_client_hello(buf) {
                // JA3 fingerprints the TLS stack, not the SNI, so check it regardless.
                if let Some((ja3_string, hash)) = ja3(buf) {
                    let label = KNOWN_JA3.iter().find(|(h, _)| *h == hash).map(|(_, l)| *l);
                    match label {
                        Some(l) => println!("  [ja3] {src}:{sport} -> {dst}:{dport}  ja3={hash} client={l} ({ja3_string})"),
                        None => println!("  [ja3] {src}:{sport} -> {dst}:{dport}  ja3={hash} client=unknown ({ja3_string})"),
                    }
                    if self.blocked_ja3.iter().any(|h| h == &hash) {
                        block(self.injector.as_mut(), &self.block_stats, &mut self.blocked_ip, &mut self.escalation, tcp, src, sport, dst, dport, payload, "ja3", &hash);
                        if self.lockdown_enabled {
                            lockdown_on_match(&mut self.lockdown_ips, src, "ja3");
                        }
                    }
                }
                if let Some(name) = ch.sni {
                    println!("  [sni] {src}:{sport} -> {dst}:{dport}  server_name={name}");
                    if self.blocked_sni.iter().any(|s| s == &name) {
                        block(self.injector.as_mut(), &self.block_stats, &mut self.blocked_ip, &mut self.escalation, tcp, src, sport, dst, dport, payload, "sni", &name);
                        if self.lockdown_enabled {
                            lockdown_on_match(&mut self.lockdown_ips, src, "sni");
                        }
                    }
                    state.sni = Some(name);
                }
                state.checked_entropy = true; // real ClientHello, no need to score entropy
            } else if state.saw_syn && buf.len() >= CLIENTHELLO_CAP {
                let candidate_port = if TLS_LIKE_PORTS.contains(&dport) { dport } else { sport };
                if let Some(label) = classify_first_segment(buf, candidate_port) {
                    println!("  [detect] {label} on {src}:{sport} -> {dst}:{dport}");
                    // Probe only against allow-listed hosts; no target -> trust the heuristic.
                    let confirmed = match [src, dst].into_iter().find(|ip| self.probe_targets.iter().any(|r| ip_rule_matches(r, ip))) {
                        None => true,
                        Some(target) => match probe::probe(target, candidate_port) {
                            Some(proto) => {
                                println!("  [probe] confirmed {proto} on {target}:{candidate_port}");
                                true
                            }
                            None => {
                                println!("  [probe] no known protocol matched on {target}:{candidate_port} - not blocking");
                                false
                            }
                        },
                    };
                    if self.inject_on_detect && confirmed {
                        block(self.injector.as_mut(), &self.block_stats, &mut self.blocked_ip, &mut self.escalation, tcp, src, sport, dst, dport, payload, "detect", label);
                        if self.lockdown_enabled {
                            lockdown_on_match(&mut self.lockdown_ips, src, "detect");
                        }
                    }
                }
                state.checked_entropy = true;
            }
        }

        if let Some(label) = state.timing.check() {
            println!("  [timing] {label} on {src}:{sport} -> {dst}:{dport}");
        }

        if self.trace {
            println!(
                "TCP  {src}:{sport} -> {dst}:{dport}  len={len}  reassembled={total}",
                len = payload.len(),
                total = state.stream.delivered.len(),
            );
        }
    }

    fn handle_udp(&mut self, src: IpAddr, dst: IpAddr, udp: &UdpPacket) {
        let (sport, dport) = (udp.get_source(), udp.get_destination());
        let payload = udp.payload();

        let key = (src, sport, dst, dport);
        let timing = self.udp_timing.entry(key).or_insert_with(TimingStats::new);
        if !payload.is_empty() {
            timing.record(payload.len());
        }
        if let Some(label) = timing.check() {
            println!("  [timing] {label} on {src}:{sport} -> {dst}:{dport}");
        }

        // dport==53: this is a client's outbound query to a resolver at `dst`.
        if dport == 53 {
            if let Some(query) = parse_dns_query_full(payload) {
                println!("  [dns] {src}:{sport} -> {dst}:{dport}  query={}", query.name);
                if let (Some((map, tx)), IpAddr::V4(dst4), IpAddr::V4(src4)) = (self.dns_redirect.as_mut(), dst, src) {
                    if let Some(&answer_ip) = map.get(&query.name) {
                        match redirect::send_dns_redirect(tx, dst4, src4, sport, &query, answer_ip) {
                            Ok(()) => println!("  [redirect] spoofed A record {} -> {answer_ip}", query.name),
                            Err(e) => eprintln!("  [redirect] failed: {e}"),
                        }
                    }
                }
                if let (Some((map, tx)), IpAddr::V6(dst6), IpAddr::V6(src6)) = (self.dns_redirect_v6.as_ref(), dst, src) {
                    if let Some(&answer_ip) = map.get(&query.name) {
                        match redirect::send_dns_redirect_v6(tx, dst6, src6, sport, &query, answer_ip) {
                            Ok(()) => println!("  [redirect] spoofed AAAA record {} -> {answer_ip}", query.name),
                            Err(e) => eprintln!("  [redirect] failed: {e}"),
                        }
                    }
                }
            }
        } else if sport == 53 {
            if let Some(name) = parse_dns_query_full(payload).map(|q| q.name) {
                println!("  [dns] {src}:{sport} -> {dst}:{dport}  query={name}");
            }
        }
        if self.trace {
            println!("UDP  {src}:{sport} -> {dst}:{dport}  len={len}", len = payload.len());
        }
    }
}

/// Reset both ends of a matched flow, if injection is enabled. IPv4 only -
/// v6 flows are silently skipped. Returns true if the RST fired, so the
/// caller can count it toward escalation.
fn try_reset(
    injector: Option<&mut TransportSender>,
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
    let (Some(tx), IpAddr::V4(src4), IpAddr::V4(dst4)) = (injector, src, dst) else { return false };
    let seq_to_dst = tcp.get_sequence().wrapping_add(payload.len() as u32);
    let seq_to_src = tcp.get_acknowledgement();
    let reason = if detail.is_empty() { kind.to_string() } else { format!("{kind} block: {detail}") };
    match inject::reset_flow(tx, src4, sport, dst4, dport, seq_to_dst, seq_to_src) {
        Ok(()) => {
            println!("  [inject] RST sent both directions ({reason})");
            *stats.lock().unwrap().entry(kind.to_string()).or_insert(0) += 1;
            true
        }
        Err(e) => {
            eprintln!("  [inject] failed: {e}");
            false
        }
    }
}

/// Wraps `try_reset` with escalation tracking. Free function (not &mut self)
/// so callers can hold a live borrow into self.streams at the same time.
#[allow(clippy::too_many_arguments)]
fn block(
    injector: Option<&mut TransportSender>,
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
    let fired = try_reset(injector, stats, tcp, src, sport, dst, dport, payload, kind, detail);
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
        println!("  [escalate] auto-blocking {src_s} after {count} offenses in {ESCALATE_WINDOW:?} (expires in {ESCALATION_TTL:?}, persisted)");
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
fn lockdown_on_match(lockdown_ips: &mut Vec<(String, Instant)>, src: IpAddr, kind: &str) {
    let src_s = src.to_string();
    if lockdown_ips.iter().any(|(ip, _)| ip == &src_s) {
        return; // already locked down
    }
    lockdown_ips.push((src_s.clone(), Instant::now() + LOCKDOWN_TTL));
    let ips: Vec<String> = lockdown_ips.iter().map(|(ip, _)| ip.clone()).collect();
    if let Err(e) = lockdown::apply_all(&ips) {
        eprintln!("  [lockdown] failed to apply firewall rule for {src_s}: {e}");
        lockdown_ips.pop(); // roll back - firewall state and our list must agree
        return;
    }
    let epoch = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_secs() + LOCKDOWN_TTL.as_secs();
    crate::config::set_expiry_entry(std::path::Path::new(LOCKDOWN_FILE), &src_s, epoch);
    println!("  [lockdown] {src_s} blocked at firewall level ({kind} match, expires in {LOCKDOWN_TTL:?})");
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn prune_expired_ips_drops_only_expired_entries() {
        // inject/redirect both off, so no raw socket (root) needed.
        let mut engine = Engine::new(false, false, false, vec![], vec![], vec![
            ("expired".to_string(), Some(Duration::from_secs(0))),
            ("still-blocked".to_string(), Some(Duration::from_secs(3600))),
            ("permanent".to_string(), None),
        ], vec![], vec![], vec![], CannonConfig::default(), false, vec![], false, false, Arc::new(Mutex::new(HashMap::new())))
        .unwrap();
        std::thread::sleep(Duration::from_millis(5)); // let the zero-TTL entry actually pass
        engine.prune_expired_ips();
        let remaining: Vec<&str> = engine.blocked_ip.iter().map(|(ip, _)| ip.as_str()).collect();
        assert_eq!(remaining, vec!["still-blocked", "permanent"]);
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
