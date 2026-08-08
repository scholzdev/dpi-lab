// Bandwidth throttling via macOS pfctl + dnctl (dummynet) - the one mechanism
// here that's genuinely inline rather than off-path spoofing: it modifies
// this machine's own firewall/traffic-shaping rules, which only works because
// the local kernel is authoritative over its own traffic. Linux would use
// `tc` instead; this is macOS-specific (dnctl/pfctl are BSD/Darwin tools).
//
// One flat pipe per IP, no per-connection/per-protocol shaping, no
// persistence beyond the current pf anchor - cleared via `clear_all()` on
// exit so a crashed/Ctrl-C'd session doesn't leave your Mac's traffic shaped.
use std::io::Write;
use std::process::Command;

const ANCHOR: &str = "dpi-lab-throttle";
const PIPE_BASE: u16 = 100; // arbitrary base unlikely to collide with other dummynet users

/// Configure one dnctl pipe for `ip` at `kbit_s` kilobits/sec. Requires root
/// (same as everything else here needing raw sockets/system config).
fn configure_pipe(ip: &str, kbit_s: u32, pipe_num: u16) -> std::io::Result<()> {
    run(&["dnctl", "pipe", &pipe_num.to_string(), "config", "bw", &format!("{kbit_s}Kbit/s")])?;
    log::info!("[throttle] {ip} limited to {kbit_s}Kbit/s (pipe {pipe_num})");
    Ok(())
}

/// Apply every "ip: kbit_s" entry from config/throttle.yml, one pipe per entry.
/// `pfctl -f` replaces an anchor's rules wholesale, so all entries' dummynet
/// rules must be loaded together in one pass - loading them one anchor-write
/// per entry would silently drop every entry but the last.
pub fn apply_all(entries: &[(String, u32)]) {
    let mut rule = String::new();
    for (i, (ip, kbit_s)) in entries.iter().enumerate() {
        let pipe_num = PIPE_BASE + i as u16;
        if let Err(e) = configure_pipe(ip, *kbit_s, pipe_num) {
            log::error!("[throttle] failed to configure pipe for {ip}: {e}");
            continue;
        }
        rule.push_str(&format!("dummynet quick from {ip} to any pipe {pipe_num}\ndummynet quick from any to {ip} pipe {pipe_num}\n"));
    }
    if !rule.is_empty() {
        if let Err(e) = load_anchor_rule(&rule) {
            log::error!("[throttle] failed to load anchor rules: {e}");
        }
    }
}

fn load_anchor_rule(rule: &str) -> std::io::Result<()> {
    let mut child = Command::new("pfctl").args(["-a", ANCHOR, "-f", "-"]).stdin(std::process::Stdio::piped()).spawn()?;
    child.stdin.take().unwrap().write_all(rule.as_bytes())?;
    let status = child.wait()?;
    if !status.success() {
        return Err(std::io::Error::other("pfctl failed to load anchor rule"));
    }
    let _ = Command::new("pfctl").args(["-e"]).status(); // enable pf; errors if already on, ignored
    Ok(())
}

/// Remove every rule this module added. Call on exit (see main.rs's Ctrl-C
/// handler) - otherwise a crashed session leaves real traffic shaped after
/// dpi-lab itself is gone.
pub fn clear_all() {
    let result = Command::new("pfctl").args(["-a", ANCHOR, "-F", "all"]).status();
    match result {
        Ok(status) if status.success() => log::info!("[throttle] cleared anchor rules"),
        _ => log::error!("[throttle] failed to clear anchor rules - check manually: sudo pfctl -a {ANCHOR} -F all"),
    }
}

fn run(args: &[&str]) -> std::io::Result<()> {
    let status = Command::new(args[0]).args(&args[1..]).status()?;
    if !status.success() {
        return Err(std::io::Error::other(format!("{} failed", args.join(" "))));
    }
    Ok(())
}
