// Deterministic inline traffic blocking via macOS pfctl (own anchor, separate
// from throttle.rs's) - unlike RST/DNS-spoof injection (off-path, forges an
// extra packet that races the real traffic and can lose), this modifies the
// local kernel's own firewall state directly: once a rule lands, every
// subsequent packet for that IP is dropped by the OS itself, not raced.
use std::io::Write;
use std::process::Command;

const ANCHOR: &str = "dpi-lab-lockdown";

/// Full ruleset for the anchor: block both directions for every IP currently
/// locked down. Pure and testable without touching pfctl.
fn build_ruleset(ips: &[String]) -> String {
    let mut rule = String::new();
    for ip in ips {
        rule.push_str(&format!("block drop quick from {ip} to any\nblock drop quick from any to {ip}\n"));
    }
    rule
}

/// Replace the lockdown anchor's rules with exactly this set of IPs. `pfctl
/// -f` replaces an anchor's content wholesale, so every call must pass the
/// full current set, not just the newly-added IP - loading one entry at a
/// time would silently drop everything already locked down.
pub fn apply_all(ips: &[String]) -> std::io::Result<()> {
    load_anchor_rule(&build_ruleset(ips))
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
        let rule = build_ruleset(&["10.27.0.39".to_string()]);
        assert!(rule.contains("block drop quick from 10.27.0.39 to any"));
        assert!(rule.contains("block drop quick from any to 10.27.0.39"));
    }

    #[test]
    fn ruleset_includes_every_locked_ip_not_just_the_last() {
        let rule = build_ruleset(&["10.27.0.5".to_string(), "10.27.0.39".to_string()]);
        assert!(rule.contains("10.27.0.5"));
        assert!(rule.contains("10.27.0.39"));
    }

    #[test]
    fn empty_set_is_empty_ruleset() {
        assert_eq!(build_ruleset(&[]), "");
    }
}
