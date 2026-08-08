// Live capture -> engine pipeline (decode/reassemble/classify/inject/redirect).
// Run: sudo ./target/debug/dpi-lab <interface> [--inject] [--inject-on-detect] [--redirect-dns] [--trace]
//      [--block-sni <domain>]... [--block-ja3 <hash>]... [--block-ja3s <hash>]... [--block-ja4 <fp>]...
//      [--block-ip <ip>]... [--block-sig <keyword>]...
//      [--lockdown] [--block-ech] [--block-quic] [--allowlist-only] [--block-asn <num>]... [--block-doh]
// --allowlist-only: default-deny mode - block every flow whose src/dst isn't
// in config/allowlist.yml (IP/CIDR), ignoring block_ip/sni/ja3/etc entirely.
// Empty allowlist.yml + this flag blocks everything (fail-closed).
// --block-asn: block every flow whose src/dst IP resolves (via config/asn.yml's
// {cidr, asn, name} ranges - see asn.rs) to one of the given ASNs. No bundled
// ASN database; config/asn.yml ships documented example ranges only.
// --block-doh: escalate [doh] (known public DoH/DoT resolver IP match, see
// config/doh_providers.yml) from log-only to an actual block.
// --inject now also covers IPv6 flows (see inject::Ipv6RstSender) - Linux
// only (needs IPV6_HDRINCL, absent from macOS's raw IPv6 socket API); on
// other platforms IPv6 RST silently no-ops, same fallback shape as
// --redirect-dns's existing IPv6 handling.
// --trace prints every raw TCP/UDP packet (flood); without it, only
// classification/block events ([sni] [ja3] [host] [ech] [quic-sni] [quic-ja3]
// [detect] [dns] [inject] [timing] [ip]) print. --block-ech requires --lockdown
// to enforce (there's no SNI/hostname to RST-inject on, only presence to drop) -
// blocks any ClientHello carrying the encrypted_client_hello extension outright,
// since the real SNI inside it can't be read. --block-quic also requires
// --lockdown: blanket-drops UDP:443 so QUIC clients fall back to inspectable
// TCP+TLS instead of trying to selectively filter traffic dpi-lab can't decrypt
// past the Initial packet (see quic.rs).
// Block lists load from config/{sni,ja3,ip,signatures}.yml (plain YAML lists) and
// config/redirect.yml (orig -> target mapping for --redirect-dns); CLI flags add to
// whatever's in those files. Auto-escalated IPs persist to config/escalated_ip.yml
// (ip -> unix-epoch expiry) and get merged back into the IP block list, with their
// remaining TTL, on every startup - already-expired entries are dropped. Bandwidth
// throttling (macOS pfctl/dnctl) loads from config/throttle.yml (ip -> kbit/s) and
// applies at startup; cleared automatically on Ctrl-C. Active probing (on a
// [detect] hit, connect out to confirm before trusting the entropy heuristic) is
// scoped to config/probe_targets.yml - own lab hosts only. --cannon injects a
// plaintext HTTP response (marker string and/or redirect) between two hosts on
// config/cannon.yml's allow-list - own lab hosts only. --lockdown makes any
// IP/SNI/JA3/signature match a hard, TTL-bounded macOS pfctl block (kernel
// drops every subsequent packet, not just a raced RST) - persists to
// config/lockdown.yml the same way escalated_ip.yml does. Known protocol
// handshakes (structural signatures, not keyword matches) load from
// config/handshakes.yml and feed the same [detect]/lockdown pipeline as
// everything else - UDP only for now, no RST equivalent for that transport.
// --inline (Linux only) is a different mode entirely: genuine in-path NFQUEUE
// enforcement instead of passive capture + off-path racing, see src/inline.rs.
// Run as: sudo ./target/debug/dpi-lab --inline (no interface arg - nftables
// picks up FORWARD traffic directly, this machine must be the actual gateway).
// --inline --downgrade-tls13: forces TLS 1.3 ClientHellos to 1.2 in place
// (flips the supported_versions extension's 0x0304 entries to 0x0303, never
// changes packet length - see classify::mangle_supported_versions_in_place).
// The downgrade itself is real and observable on the wire, but RFC 8446
// SS4.1.3 gives every TLS-1.3-capable client a sentinel to detect exactly
// this and abort - real-world effect is confined to non-conformant/legacy
// TLS stacks, see example.md.
// (no arg = list interfaces)
mod asn;
mod cannon;
mod classify;
mod config;
mod detect;
mod fragment;
mod engine;
mod h2;
mod inject;
mod inline;
mod ipv6ext;
mod lockdown;
mod probe;
mod quic;
mod reassembly;
mod redirect;
mod throttle;
mod timing;

use engine::{BlockStats, Engine};
use pnet::datalink::{self, Channel::Ethernet};
use pnet::packet::ethernet::{EtherTypes, EthernetPacket};
use pnet::packet::ipv4::Ipv4Packet;
use pnet::packet::ipv6::Ipv6Packet;
use pnet::packet::Packet;
use std::collections::HashMap;
use std::path::Path;
use std::sync::{Arc, Mutex};

/// Print the block-event summary and exit - called from the Ctrl-C handler.
fn print_summary_and_exit(stats: &BlockStats) {
    let counts = stats.lock().unwrap();
    println!("\n--- block summary ---");
    if counts.is_empty() {
        println!("(no connections blocked)");
    } else {
        let mut kinds: Vec<_> = counts.iter().collect();
        kinds.sort_by(|a, b| b.1.cmp(a.1)); // busiest kind first
        let total: u32 = counts.values().sum();
        for (kind, count) in kinds {
            println!("  {kind:<10} {count}");
        }
        println!("  {:<10} {total}", "total");
    }
    throttle::clear_all();
    lockdown::clear_all();
    std::process::exit(0);
}

/// --inline entry point: loads the same block-list config as everything
/// else, then hands off to the Linux-only NFQUEUE loop instead of passive
/// datalink capture. No interface arg - it acts on whatever nftables' FORWARD
/// hook sees, which means this machine needs to actually be the gateway (see
/// writeup.md's inline-vs-off-path discussion).
#[cfg(target_os = "linux")]
fn run_inline(args: &[String]) {
    let config_dir = Path::new("config");
    let mut blocked_sni = config::load_list(&config_dir.join("sni.yml"));
    blocked_sni.extend(flag_values(args, "--block-sni"));
    let mut blocked_ja3 = config::load_list(&config_dir.join("ja3.yml"));
    blocked_ja3.extend(flag_values(args, "--block-ja3"));
    let mut blocked_ip = config::load_list(&config_dir.join("ip.yml"));
    blocked_ip.extend(flag_values(args, "--block-ip"));
    let mut signatures = config::load_list(&config_dir.join("signatures.yml"));
    signatures.extend(flag_values(args, "--block-sig"));
    let handshake_rules = config::load_handshake_rules(&config_dir.join("handshakes.yml"));
    let downgrade_tls13 = args.iter().any(|a| a == "--downgrade-tls13");
    if downgrade_tls13 {
        println!("[inline] --downgrade-tls13: forcing TLS 1.3 ClientHellos to 1.2 - RFC 8446 SS4.1.3's downgrade sentinel means any conformant modern client detects and aborts this rather than silently downgrading (see example.md)");
    }

    let classifier = inline::InlineClassifier {
        sigs: classify::Signatures::new(&signatures),
        blocked_sni,
        blocked_ja3,
        blocked_ip,
        handshake_rules,
        downgrade_tls13,
    };

    ctrlc::set_handler(|| {
        inline::clear_nft();
        std::process::exit(0);
    })
    .expect("failed to set Ctrl-C handler");

    if let Err(e) = inline::run(&classifier) {
        eprintln!("[inline] fatal: {e} (needs root + nft on PATH)");
        inline::clear_nft();
        std::process::exit(1);
    }
}

#[cfg(not(target_os = "linux"))]
fn run_inline(_args: &[String]) {
    eprintln!("--inline needs Linux (NFQUEUE) - not available on this platform. Use passive capture mode instead.");
    std::process::exit(1);
}

/// Collect every value following a repeatable `--flag value` pair, e.g.
/// `--block-sni a.com --block-sni b.com` -> `["a.com", "b.com"]`.
fn flag_values(args: &[String], flag: &str) -> Vec<String> {
    args.iter()
        .zip(args.iter().skip(1))
        .filter(|(f, _)| f.as_str() == flag)
        .map(|(_, v)| v.clone())
        .collect()
}

fn main() {
    let args: Vec<String> = std::env::args().collect();

    if args.iter().any(|a| a == "--inline") {
        return run_inline(&args);
    }

    let iface_name = match args.get(1) {
        Some(n) => n.clone(),
        None => {
            println!("usage: dpi-lab <interface> [--inject] [--inject-on-detect] [--redirect-dns]\n   or: dpi-lab --inline (Linux only, genuine in-path NFQUEUE mode - see writeup.md)\navailable interfaces:");
            for i in datalink::interfaces() {
                println!("  {}", i.name);
            }
            return;
        }
    };
    // Own lab only: RST injection / DNS redirect stay off unless explicitly requested.
    let inject_enabled = args.iter().any(|a| a == "--inject");
    // Separate opt-in: entropy detection is a heuristic with a real false-positive
    // rate, acting on it automatically is a stronger claim than on a signature/SNI hit.
    let inject_on_detect = args.iter().any(|a| a == "--inject-on-detect");
    // Redirect targets are defined in engine::REDIRECT_MAP and resolved there.
    let redirect_enabled = args.iter().any(|a| a == "--redirect-dns");
    // Own-lab-to-own-lab HTTP response injection (Great-Cannon-style); allow-list
    // enforced in config/cannon.yml, this flag only turns the mechanism on at all.
    let cannon_enabled = args.iter().any(|a| a == "--cannon");
    // Deterministic kernel-level block on any IP/SNI/JA3/signature match -
    // unlike --inject's raced RST, this can't lose the race.
    let lockdown_enabled = args.iter().any(|a| a == "--lockdown");
    let trace = args.iter().any(|a| a == "--trace");
    // ECH hides the real SNI from us entirely (RFC-in-progress "encrypted_client_hello",
    // codepoint 0xfe0d) - can't selectively block by hostname, so block on the
    // extension's mere presence instead. Requires --lockdown to actually enforce.
    let block_ech = args.iter().any(|a| a == "--block-ech");
    // QUIC is UDP - opaque to everything past the Initial packet (see quic.rs).
    // Rather than let that opacity through, force a downgrade: drop all UDP:443
    // so browsers fall back to TCP+TLS, where SNI/JA3 blocking already works.
    let block_quic = args.iter().any(|a| a == "--block-quic");
    // Default-deny: block every flow whose src/dst isn't on config/allowlist.yml,
    // ignoring the blocklists entirely. IP/CIDR only (see engine.rs's allowlist
    // check) - the severe GFW mode used during high-alert periods, as opposed
    // to the normal "block a known list" mode everything else here implements.
    let allowlist_only = args.iter().any(|a| a == "--allowlist-only");
    // DoH heuristic: [doh] logs whenever a ClientHello's dst IP matches a
    // known public resolver (config/doh_providers.yml); --block-doh escalates
    // that to an actual block instead of log-only.
    let block_doh = args.iter().any(|a| a == "--block-doh");

    let config_dir = Path::new("config");
    let mut block_sni = config::load_list(&config_dir.join("sni.yml"));
    block_sni.extend(flag_values(&args, "--block-sni"));
    let mut block_ja3 = config::load_list(&config_dir.join("ja3.yml"));
    block_ja3.extend(flag_values(&args, "--block-ja3"));
    let mut block_ja3s = config::load_list(&config_dir.join("ja3s.yml"));
    block_ja3s.extend(flag_values(&args, "--block-ja3s"));
    let mut block_ja4 = config::load_list(&config_dir.join("ja4.yml"));
    block_ja4.extend(flag_values(&args, "--block-ja4"));
    // escalated_ip.yml holds IPs auto-blocked by a previous run (ip -> unix-epoch
    // expiry, see engine.rs's escalation logic) - merged in here so they stay
    // blocked across restarts, with the remaining TTL carried over. Already-expired
    // entries are dropped rather than re-added.
    let now_epoch = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_secs();
    let mut block_ip: Vec<(String, Option<std::time::Duration>)> =
        config::load_list(&config_dir.join("ip.yml")).into_iter().map(|ip| (ip, None)).collect();
    block_ip.extend(config::load_expiry_map(&config_dir.join("escalated_ip.yml")).into_iter().filter_map(|(ip, exp)| {
        (exp > now_epoch).then(|| (ip, Some(std::time::Duration::from_secs(exp - now_epoch))))
    }));
    block_ip.extend(flag_values(&args, "--block-ip").into_iter().map(|ip| (ip, None)));
    let mut signatures = config::load_list(&config_dir.join("signatures.yml"));
    signatures.extend(flag_values(&args, "--block-sig"));
    // Known protocol handshake signatures (byte anchors + exact length) -
    // structural recognition, not a keyword search. See classify::HandshakeRule.
    let handshake_rules = config::load_handshake_rules(&config_dir.join("handshakes.yml"));
    let redirect_map = config::load_map(&config_dir.join("redirect.yml"));
    // Active-probing allow-list: only these hosts (your own lab boxes) ever
    // get an outbound probe connection on a [detect] hit. Empty by default.
    let probe_targets = config::load_list(&config_dir.join("probe_targets.yml"));
    let cannon = config::load_cannon_config(&config_dir.join("cannon.yml"));
    // Only meaningful with --allowlist-only; empty otherwise (nothing to check against).
    let allowlist = config::load_list(&config_dir.join("allowlist.yml"));
    // ASN blocking: --block-asn AS_NUMBER (repeatable), resolved against
    // config/asn.yml's {cidr, asn, name} ranges - see asn.rs.
    let asn_ranges = config::load_asn_ranges(&config_dir.join("asn.yml"));
    let blocked_asn: Vec<u32> = flag_values(&args, "--block-asn").into_iter().filter_map(|s| s.parse().ok()).collect();
    let doh_providers = config::load_map(&config_dir.join("doh_providers.yml"));
    // Same ip -> number shape as the escalated-block expiry map, just reused
    // here for kbit/s instead of a unix timestamp.
    let throttle_entries: Vec<(String, u32)> =
        config::load_expiry_map(&config_dir.join("throttle.yml")).into_iter().map(|(ip, kbit)| (ip, kbit as u32)).collect();
    throttle::apply_all(&throttle_entries);

    // lockdown.yml persists ip -> unix-epoch expiry, same shape/reasoning as
    // escalated_ip.yml. Re-arm the pf anchor at startup so a restart (crash
    // or clean) restores exactly the still-valid set, not a stale one.
    let lockdown_ips: Vec<(String, std::time::Duration)> =
        config::load_expiry_map(&config_dir.join("lockdown.yml")).into_iter().filter_map(|(ip, exp)| {
            (exp > now_epoch).then(|| (ip, std::time::Duration::from_secs(exp - now_epoch)))
        }).collect();
    if lockdown_enabled {
        if let Err(e) = lockdown::ensure_hooked() {
            eprintln!("[lockdown] failed to hook anchor into main ruleset - blocks will not take effect: {e}");
        }
        let ips: Vec<String> = lockdown_ips.iter().map(|(ip, _)| ip.clone()).collect();
        if let Err(e) = lockdown::apply_all(&ips, block_quic) {
            eprintln!("[lockdown] failed to restore firewall rules at startup: {e}");
        }
    }

    let block_stats: BlockStats = Arc::new(Mutex::new(HashMap::new()));
    let stats_for_handler = block_stats.clone();
    ctrlc::set_handler(move || print_summary_and_exit(&stats_for_handler)).expect("failed to set Ctrl-C handler");

    let mut engine = Engine::new(
        inject_enabled,
        inject_on_detect,
        redirect_enabled,
        block_sni,
        block_ja3,
        block_ja3s,
        block_ja4,
        block_ip,
        allowlist,
        allowlist_only,
        asn_ranges,
        blocked_asn,
        signatures,
        handshake_rules,
        redirect_map,
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
    )
    .expect("open raw socket for --inject/--redirect-dns (need root)");

    let interface = datalink::interfaces()
        .into_iter()
        .find(|i| i.name == iface_name)
        .unwrap_or_else(|| panic!("no such interface: {iface_name}"));

    let mut rx = match datalink::channel(&interface, Default::default()) {
        Ok(Ethernet(_tx, rx)) => rx,
        Ok(_) => panic!("unsupported channel type"),
        Err(e) => panic!("failed to open {iface_name}: {e} (need root/cap_net_raw?)"),
    };

    loop {
        let raw = match rx.next() {
            Ok(p) => p,
            Err(e) => {
                eprintln!("capture error: {e}");
                continue;
            }
        };
        let Some(eth) = EthernetPacket::new(raw) else { continue };
        match eth.get_ethertype() {
            EtherTypes::Ipv4 => {
                if let Some(ip) = Ipv4Packet::new(eth.payload()) {
                    engine.handle_frame_v4(&ip);
                }
            }
            EtherTypes::Ipv6 => {
                if let Some(ip) = Ipv6Packet::new(eth.payload()) {
                    engine.handle_frame_v6(&ip);
                }
            }
            _ => {}
        }
    }
}
