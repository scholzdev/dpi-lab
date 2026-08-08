// Deterministic inline traffic blocking - unlike RST/DNS-spoof injection
// (off-path, forges an extra packet that races the real traffic and can
// lose), this modifies the local kernel's own firewall state directly:
// every subsequent *new* connection for that IP is dropped by the OS
// itself, not raced. A connection that was already ESTABLISHED before the
// rule landed is not new, though - both backends check existing connection
// state before rule evaluation, so an open flow just keeps flowing past a
// fresh block rule unless that state is explicitly killed too (both
// apply_all()s do this, best-effort).
//
// Two backends behind the same public API (pub fn apply_all/ensure_hooked/
// clear_all, unchanged signatures either platform) - macOS via pfctl (a
// named anchor, same as before), Linux via nftables (mirrors inline.rs's
// own nft usage - a dedicated table this module owns exclusively).
#[cfg(not(target_os = "linux"))]
mod backend {
    use std::io::Write;
    use std::process::Command;

    const ANCHOR: &str = "dpi-lab-lockdown";
    const ANCHOR_DECL: &str = "anchor \"dpi-lab-lockdown\"\n";

    /// Pure and testable without touching pfctl.
    pub(super) fn build_ruleset(ips: &[String], block_quic: bool) -> String {
        let mut rule = String::new();
        for ip in ips {
            rule.push_str(&format!("block drop quick from {ip} to any\nblock drop quick from any to {ip}\n"));
        }
        if block_quic {
            rule.push_str("block drop quick proto udp from any port = 443\nblock drop quick proto udp to any port = 443\n");
        }
        rule
    }

    /// `pfctl -f` replaces an anchor's content wholesale, so every call must
    /// pass the full current set, not just the newly-added IP. Also kills any
    /// state pf already has for these IPs - otherwise an already-open
    /// connection keeps flowing through the new block rule.
    pub fn apply_all(ips: &[String], block_quic: bool) -> std::io::Result<()> {
        load_anchor_rule(&build_ruleset(ips, block_quic))?;
        for ip in ips {
            // `pfctl -k host` only matches states where `host` is the
            // *source* - our IP is almost always the destination (the remote
            // server), so a single -k never matched the open client->server
            // state at all (always "killed 0 states"). Two -k args kill by
            // (from, to) pair; 0.0.0.0/0 as a wildcard on the other side
            // covers both directions. Best-effort: no matching state exits
            // non-zero, not worth aborting over.
            let _ = Command::new("pfctl").args(["-k", "0.0.0.0/0", "-k", ip]).status();
            let _ = Command::new("pfctl").args(["-k", ip, "-k", "0.0.0.0/0"]).status();
        }
        Ok(())
    }

    /// Wire the `dpi-lab-lockdown` anchor into the live pf ruleset so
    /// `apply_all` actually takes effect - a no-op if already hooked. Reads
    /// the currently active ruleset via `pfctl -sr` (best-effort - empty on
    /// failure, e.g. pf not yet enabled) and reloads it with the anchor
    /// declaration appended, rather than replacing it outright, so other
    /// tools' pf rules survive.
    pub fn ensure_hooked() -> std::io::Result<()> {
        let current = Command::new("pfctl").arg("-sr").output().map(|o| String::from_utf8_lossy(&o.stdout).into_owned()).unwrap_or_default();
        if current.contains(&format!("anchor \"{ANCHOR}\"")) {
            return Ok(()); // already wired in
        }
        let mut child = Command::new("pfctl").args(["-f", "-"]).stdin(std::process::Stdio::piped()).spawn()?;
        let mut ruleset = current;
        ruleset.push_str(ANCHOR_DECL);
        child.stdin.take().unwrap().write_all(ruleset.as_bytes())?;
        let status = child.wait()?;
        if !status.success() {
            return Err(std::io::Error::other("pfctl failed to hook lockdown anchor into main ruleset"));
        }
        let _ = Command::new("pfctl").args(["-e"]).status(); // enable pf; errors if already on, ignored
        Ok(())
    }

    fn load_anchor_rule(rule: &str) -> std::io::Result<()> {
        let mut child = Command::new("pfctl").args(["-a", ANCHOR, "-f", "-"]).stdin(std::process::Stdio::piped()).spawn()?;
        child.stdin.take().unwrap().write_all(rule.as_bytes())?;
        let status = child.wait()?;
        if !status.success() {
            return Err(std::io::Error::other("pfctl failed to load lockdown anchor rule"));
        }
        let _ = Command::new("pfctl").args(["-e"]).status(); // enable pf; errors if already on, ignored
        Ok(())
    }

    pub fn clear_all() {
        let result = Command::new("pfctl").args(["-a", ANCHOR, "-F", "all"]).status();
        match result {
            Ok(status) if status.success() => log::info!("[lockdown] cleared anchor rules"),
            _ => log::error!("[lockdown] failed to clear anchor rules - check manually: sudo pfctl -a {ANCHOR} -F all"),
        }
    }
}

#[cfg(target_os = "linux")]
mod backend {
    use std::io::Write;
    use std::net::IpAddr;
    use std::process::{Command, Stdio};

    const TABLE: &str = "dpi-lab-lockdown";

    fn parse_ips(ips: &[String]) -> Vec<IpAddr> {
        ips.iter().filter_map(|s| s.parse().ok()).collect()
    }

    /// Full nft script for a dedicated table this module owns exclusively -
    /// input+output (this host's own traffic, the common case for a lab box)
    /// and forward (traffic passing through, if this box is ever a router -
    /// same as inline.rs's own forward-hook table) all get a drop rule per
    /// IP, both directions. Recreated wholesale each call - nftables'
    /// equivalent of pf's anchor-flush-and-reload - simpler here since
    /// there's no anchor-must-be-referenced quirk to work around (unlike pf,
    /// a created table with a hooked chain is live immediately, no separate
    /// "wire it into the main ruleset" step needed).
    pub(super) fn build_script(ips: &[String], block_quic: bool) -> String {
        let addrs = parse_ips(ips);
        let mut drops = String::new();
        for ip in &addrs {
            let family = if ip.is_ipv6() { "ip6" } else { "ip" };
            drops.push_str(&format!("    {family} saddr {ip} drop\n    {family} daddr {ip} drop\n"));
        }
        let quic_drop = if block_quic { "    udp sport 443 drop\n    udp dport 443 drop\n" } else { "" };
        format!(
            "table inet {TABLE} {{\n\
             \x20 chain input {{ type filter hook input priority 0; policy accept;\n{drops}{quic_drop} }}\n\
             \x20 chain output {{ type filter hook output priority 0; policy accept;\n{drops}{quic_drop} }}\n\
             \x20 chain forward {{ type filter hook forward priority 0; policy accept;\n{drops}{quic_drop} }}\n\
             }}\n"
        )
    }

    pub fn apply_all(ips: &[String], block_quic: bool) -> std::io::Result<()> {
        // Clear first (separate best-effort pass, not part of the script
        // below) - a fresh system with no prior table makes `delete table`
        // fail, and a failed statement partway through an `nft -f` script
        // aborts the rest of it too.
        let _ = Command::new("nft").args(["delete", "table", "inet", TABLE]).status();
        let script = build_script(ips, block_quic);
        let mut child = Command::new("nft").args(["-f", "-"]).stdin(Stdio::piped()).spawn()?;
        child.stdin.take().unwrap().write_all(script.as_bytes())?;
        let status = child.wait()?;
        if !status.success() {
            return Err(std::io::Error::other("nft failed to load lockdown table"));
        }
        for ip in ips {
            // Best-effort: only takes effect if `conntrack` (conntrack-tools)
            // is installed - without it, an already-ESTABLISHED connection
            // for a newly-locked IP keeps flowing (same documented limit pf's
            // backend has without an explicit state-kill, see module docs).
            let _ = Command::new("conntrack").args(["-D", "-s", ip]).status();
            let _ = Command::new("conntrack").args(["-D", "-d", ip]).status();
        }
        Ok(())
    }

    /// nftables tables are live the moment they're created - no separate
    /// "hook it into the main ruleset" step the way pf's anchors need.
    pub fn ensure_hooked() -> std::io::Result<()> {
        Ok(())
    }

    pub fn clear_all() {
        let result = Command::new("nft").args(["delete", "table", "inet", TABLE]).status();
        match result {
            Ok(status) if status.success() => log::info!("[lockdown] cleared nft table"),
            _ => log::error!("[lockdown] failed to clear nft table - check manually: sudo nft delete table inet {TABLE}"),
        }
    }
}

pub use backend::{apply_all, clear_all, ensure_hooked};

#[cfg(test)]
mod tests {
    use super::*;

    #[cfg(not(target_os = "linux"))]
    use backend::build_ruleset;
    #[cfg(target_os = "linux")]
    use backend::build_script as build_ruleset;

    #[test]
    fn ruleset_blocks_both_directions_per_ip() {
        let rule = build_ruleset(&["10.27.0.39".to_string()], false);
        assert!(rule.contains("10.27.0.39"));
    }

    #[test]
    fn ruleset_includes_every_locked_ip_not_just_the_last() {
        let rule = build_ruleset(&["10.27.0.5".to_string(), "10.27.0.39".to_string()], false);
        assert!(rule.contains("10.27.0.5"));
        assert!(rule.contains("10.27.0.39"));
    }

    #[test]
    fn block_quic_adds_udp_443_blanket_drop() {
        let rule = build_ruleset(&[], true);
        assert!(rule.contains("443"));
        assert!(rule.to_lowercase().contains("udp"));
    }

    #[test]
    fn block_quic_false_has_no_udp_443_rule() {
        assert!(!build_ruleset(&["10.27.0.39".to_string()], false).to_lowercase().contains("udp"));
    }

    #[cfg(not(target_os = "linux"))]
    #[test]
    fn empty_set_is_empty_ruleset() {
        assert_eq!(build_ruleset(&[], false), "");
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn ipv6_ips_use_ip6_family_match() {
        let script = build_ruleset(&["fe80::1".to_string()], false);
        assert!(script.contains("ip6 saddr fe80::1"));
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn ipv4_ips_use_ip_family_match() {
        let script = build_ruleset(&["10.27.0.39".to_string()], false);
        assert!(script.contains("ip saddr 10.27.0.39"));
        assert!(!script.contains("ip6 saddr 10.27.0.39"));
    }
}
