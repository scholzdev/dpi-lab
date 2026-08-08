// Deterministic inline traffic blocking via macOS pfctl (own anchor, separate
// from throttle.rs's) - unlike RST/DNS-spoof injection (off-path, forges an
// extra packet that races the real traffic and can lose), this modifies the
// local kernel's own firewall state directly: every subsequent *new*
// connection for that IP is dropped by the OS itself, not raced. A
// connection that was already ESTABLISHED before the rule landed is not
// new, though - pf checks its state table before rule evaluation, so an
// open flow just keeps flowing past a fresh `block` rule. apply_all() also
// kills existing state for each IP so already-open connections die too.
//
// A named anchor populated via `pfctl -a NAME -f -` sits inert unless the
// live top-level ruleset actually references it (`anchor "NAME"`) - macOS
// pf doesn't auto-wire arbitrary `-a` anchors into evaluation. Without that
// reference this whole module logs convincingly and blocks nothing: even a
// brand-new connection opened after the rule "lands" sails straight
// through. ensure_hooked() adds that reference once at startup, preserving
// whatever ruleset was already active (best-effort - other tools' pf state
// isn't ours to lose).
use std::io::Write;
use std::process::Command;

const ANCHOR: &str = "dpi-lab-lockdown";
const ANCHOR_DECL: &str = "anchor \"dpi-lab-lockdown\"\n";

/// Full ruleset for the anchor: block both directions for every IP currently
/// locked down, plus a blanket UDP:443 drop if `block_quic` is set (forces
/// QUIC/HTTP3 clients to fall back to TCP+TLS, where SNI/JA3 blocking already
/// applies - see quic.rs's module docs for why QUIC can't be selectively
/// inspected past its Initial packet). Pure and testable without touching pfctl.
fn build_ruleset(ips: &[String], block_quic: bool) -> String {
    let mut rule = String::new();
    for ip in ips {
        rule.push_str(&format!("block drop quick from {ip} to any\nblock drop quick from any to {ip}\n"));
    }
    if block_quic {
        rule.push_str("block drop quick proto udp from any port = 443\nblock drop quick proto udp to any port = 443\n");
    }
    rule
}

/// Replace the lockdown anchor's rules with exactly this set of IPs (plus the
/// QUIC blanket-drop if enabled). `pfctl -f` replaces an anchor's content
/// wholesale, so every call must pass the full current set, not just the
/// newly-added IP - loading one entry at a time would silently drop
/// everything already locked down. Also kills any state pf already has for
/// these IPs - otherwise a connection that was already open keeps flowing
/// through the new block rule (see module docs).
pub fn apply_all(ips: &[String], block_quic: bool) -> std::io::Result<()> {
    load_anchor_rule(&build_ruleset(ips, block_quic))?;
    for ip in ips {
        // `pfctl -k host` only matches states where `host` is the *source* -
        // our IP is almost always the destination (the remote server), so a
        // single -k never matched the open client->server state at all
        // (always "killed 0 states"). Two -k args kill by (from, to) pair;
        // 0.0.0.0/0 as a wildcard on the other side covers both directions.
        // Best-effort: no matching state exits non-zero, not worth aborting over.
        let _ = Command::new("pfctl").args(["-k", "0.0.0.0/0", "-k", ip]).status();
        let _ = Command::new("pfctl").args(["-k", ip, "-k", "0.0.0.0/0"]).status();
    }
    Ok(())
}

/// Wire the `dpi-lab-lockdown` anchor into the live pf ruleset so `apply_all`
/// actually takes effect - a no-op if already hooked (e.g. a prior dpi-lab
/// run, or restarting after a crash). Reads the currently active ruleset via
/// `pfctl -sr` (best-effort - empty on failure, e.g. pf not yet enabled) and
/// reloads it with the anchor declaration appended, rather than replacing it
/// outright, so other tools' pf rules survive.
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

/// Remove every rule this module added. Call on exit - otherwise a
/// crashed/Ctrl-C'd session leaves real traffic blocked after dpi-lab itself
/// is gone.
pub fn clear_all() {
    let result = Command::new("pfctl").args(["-a", ANCHOR, "-F", "all"]).status();
    match result {
        Ok(status) if status.success() => println!("[lockdown] cleared anchor rules"),
        _ => eprintln!("[lockdown] failed to clear anchor rules - check manually: sudo pfctl -a {ANCHOR} -F all"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ruleset_blocks_both_directions_per_ip() {
        let rule = build_ruleset(&["10.27.0.39".to_string()], false);
        assert!(rule.contains("block drop quick from 10.27.0.39 to any"));
        assert!(rule.contains("block drop quick from any to 10.27.0.39"));
    }

    #[test]
    fn ruleset_includes_every_locked_ip_not_just_the_last() {
        let rule = build_ruleset(&["10.27.0.5".to_string(), "10.27.0.39".to_string()], false);
        assert!(rule.contains("10.27.0.5"));
        assert!(rule.contains("10.27.0.39"));
    }

    #[test]
    fn empty_set_is_empty_ruleset() {
        assert_eq!(build_ruleset(&[], false), "");
    }

    #[test]
    fn block_quic_adds_udp_443_blanket_drop() {
        let rule = build_ruleset(&[], true);
        assert!(rule.contains("proto udp"));
        assert!(rule.contains("port = 443"));
    }

    #[test]
    fn block_quic_false_has_no_udp_443_rule() {
        assert!(!build_ruleset(&["10.27.0.39".to_string()], false).contains("proto udp"));
    }
}
