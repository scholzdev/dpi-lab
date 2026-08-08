// Bandwidth throttling - the one mechanism here that's genuinely inline
// rather than off-path spoofing: it modifies this machine's own firewall/
// traffic-shaping rules, which only works because the local kernel is
// authoritative over its own traffic.
//
// Two backends behind the same public API: macOS via pfctl+dnctl (one flat
// dummynet pipe per IP, interface-agnostic - dummynet operates on IP
// addresses regardless of which interface they arrive/leave on). Linux via
// `tc` (traffic control) - genuinely different shape, not just different
// syntax: tc shapes *egress* on a specific interface via a class tree, so
// unlike dnctl it needs to know which interface to attach to, and only
// shapes outbound traffic on it.
//
// No persistence beyond the current session - cleared via `clear_all()` on
// exit so a crashed/Ctrl-C'd session doesn't leave real traffic shaped.

#[cfg(not(target_os = "linux"))]
mod backend {
    use std::io::Write;
    use std::process::Command;

    const ANCHOR: &str = "dpi-lab-throttle";
    const PIPE_BASE: u16 = 100; // arbitrary base unlikely to collide with other dummynet users

    fn configure_pipe(ip: &str, kbit_s: u32, pipe_num: u16) -> std::io::Result<()> {
        run(&["dnctl", "pipe", &pipe_num.to_string(), "config", "bw", &format!("{kbit_s}Kbit/s")])?;
        log::info!("[throttle] {ip} limited to {kbit_s}Kbit/s (pipe {pipe_num})");
        Ok(())
    }

    /// `pfctl -f` replaces an anchor's rules wholesale, so all entries'
    /// dummynet rules must be loaded together in one pass - loading them one
    /// anchor-write per entry would silently drop every entry but the last.
    /// `_iface` unused here - dummynet shapes by IP, not by interface.
    pub fn apply_all(entries: &[(String, u32)], _iface: &str) {
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
}

#[cfg(target_os = "linux")]
mod backend {
    use std::process::Command;

    const CLASS_BASE: u16 = 100; // arbitrary base, mirrors macOS backend's PIPE_BASE

    /// ponytail: egress-only (outbound traffic leaving `iface`), not
    /// bidirectional - `tc`'s natural shaping point is an interface's egress
    /// qdisc. Real bidirectional shaping needs an IFB (Intermediate
    /// Functional Block) device to redirect ingress traffic through an
    /// egress qdisc too - a real chunk of additional setup (a virtual
    /// interface, a redirect filter) not built here. Named ceiling, not a
    /// silent gap: this throttles what a host *sends* to a given IP, not
    /// what it *receives* from one.
    fn setup_root_qdisc(iface: &str) -> std::io::Result<()> {
        // Ignore failure - "already exists" is the common case on a second
        // apply_all() call in the same run, and tc has no clean idempotent
        // "add if missing" verb the way `nft add table` does.
        let _ = Command::new("tc").args(["qdisc", "del", "dev", iface, "root"]).status();
        run(&["tc", "qdisc", "add", "dev", iface, "root", "handle", "1:", "htb", "default", "999"])
    }

    fn add_class_and_filter(iface: &str, ip: &str, kbit_s: u32, class_num: u16) -> std::io::Result<()> {
        let classid = format!("1:{class_num}");
        run(&["tc", "class", "add", "dev", iface, "parent", "1:", "classid", &classid, "htb", "rate", &format!("{kbit_s}kbit")])?;
        // u32 filter matching this IP as the destination - i.e. traffic this
        // host is sending *to* `ip` lands in the rate-limited class.
        run(&["tc", "filter", "add", "dev", iface, "parent", "1:", "protocol", "ip", "u32", "match", "ip", "dst", ip, "flowid", &classid])?;
        log::info!("[throttle] {ip} limited to {kbit_s}Kbit/s (class {classid} on {iface}, egress only)");
        Ok(())
    }

    pub fn apply_all(entries: &[(String, u32)], iface: &str) {
        if entries.is_empty() {
            return; // no root qdisc needed at all if there's nothing to shape
        }
        if let Err(e) = setup_root_qdisc(iface) {
            log::error!("[throttle] failed to set up root qdisc on {iface}: {e}");
            return;
        }
        for (i, (ip, kbit_s)) in entries.iter().enumerate() {
            if let Err(e) = add_class_and_filter(iface, ip, *kbit_s, CLASS_BASE + i as u16) {
                log::error!("[throttle] failed to configure class for {ip}: {e}");
            }
        }
    }

    /// Removing the root qdisc drops the whole class tree (and its filters)
    /// in one call - simpler than pf's per-anchor-flush, tc has no separate
    /// per-IP teardown needed.
    pub fn clear_all(iface: &str) {
        let result = Command::new("tc").args(["qdisc", "del", "dev", iface, "root"]).status();
        match result {
            Ok(status) if status.success() => log::info!("[throttle] cleared qdisc on {iface}"),
            _ => log::debug!("[throttle] no qdisc to clear on {iface} (nothing was throttled, or already clear)"),
        }
    }

    fn run(args: &[&str]) -> std::io::Result<()> {
        let status = Command::new(args[0]).args(&args[1..]).status()?;
        if !status.success() {
            return Err(std::io::Error::other(format!("{} failed", args.join(" "))));
        }
        Ok(())
    }
}

pub use backend::apply_all;

/// `clear_all`'s signature differs by platform (Linux needs the interface
/// name to know which qdisc to remove, macOS's pf anchor doesn't need one) -
/// callers already pass the interface as `_iface`/`iface` into `apply_all`
/// symmetrically; mirror that here so `main.rs`'s call site is uniform
/// across platforms instead of needing its own `#[cfg]`.
#[cfg(not(target_os = "linux"))]
pub fn clear_all(_iface: &str) {
    backend::clear_all();
}
#[cfg(target_os = "linux")]
pub fn clear_all(iface: &str) {
    backend::clear_all(iface);
}
