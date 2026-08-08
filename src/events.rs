// Structured JSON-Lines event log, separate from the human-readable log::
// lines everywhere else in this codebase - the web UI (src/bin/dpi-lab-ui.rs)
// tails this file for its live dashboard rather than parsing log output or
// talking to dpi-lab over a socket. Deliberately file-based, not an
// in-process channel/socket: dpi-lab runs as root (raw sockets/NFQUEUE), the
// UI deliberately doesn't - decoupling via a plain file means the UI process
// never needs any privilege or IPC access into the root process, just read
// access to a file. Off by default (`--events-log <path>`, None otherwise) -
// same "opt-in, no surprise side effects" shape as every other optional
// feature here (dns_redirect, cannon, lockdown, ...).
use serde::Serialize;
use std::io::Write;
use std::net::IpAddr;
use std::path::PathBuf;

#[derive(Serialize)]
struct Event<'a> {
    time: String,
    kind: &'a str,
    src: String,
    dst: String,
    sport: u16,
    dport: u16,
    detail: &'a str,
}

pub struct EventLog {
    path: Option<PathBuf>,
}

impl EventLog {
    pub fn new(path: Option<PathBuf>) -> Self {
        Self { path }
    }

    /// Append one JSON line for a real enforcement action (a block or
    /// lockdown, not every classification sighting - see engine.rs's
    /// `block()`/`lockdown_on_match()`, the two call sites). Best-effort:
    /// a write failure is logged, never panics or interrupts capture -
    /// the event log is a convenience for the dashboard, not something
    /// packet processing should ever depend on succeeding.
    pub fn emit(&self, kind: &str, src: IpAddr, dst: IpAddr, sport: u16, dport: u16, detail: &str) {
        let Some(path) = &self.path else { return };
        let event = Event {
            time: humantime_now(),
            kind,
            src: src.to_string(),
            dst: dst.to_string(),
            sport,
            dport,
            detail,
        };
        let Ok(mut line) = serde_json::to_string(&event) else { return }; // Event's fields are all directly serializable - infallible in practice
        line.push('\n');
        let result = std::fs::OpenOptions::new().create(true).append(true).open(path).and_then(|mut f| f.write_all(line.as_bytes()));
        if let Err(e) = result {
            log::error!("[events] failed to write {}: {e}", path.display());
        }
    }
}

/// RFC 3339 timestamp without pulling in a date/time crate beyond what's
/// already a transitive dependency (x509-parser's `time`) - kept local and
/// tiny rather than adding a new direct dependency for one timestamp.
fn humantime_now() -> String {
    let now = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap();
    format_unix_secs(now.as_secs())
}

/// Pure formatting half of `humantime_now`, split out so it's testable
/// against known timestamps instead of only "didn't panic just now".
fn format_unix_secs(secs: u64) -> String {
    let (days, time_of_day) = (secs / 86400, secs % 86400);
    let (h, m, s) = (time_of_day / 3600, (time_of_day % 3600) / 60, time_of_day % 60);
    // Civil-from-days (Howard Hinnant's algorithm) - proleptic Gregorian, no
    // leap-second handling (matches every other unix-epoch use in this
    // codebase, e.g. config.rs's expiry timestamps).
    let z = days as i64 + 719468;
    let era = if z >= 0 { z } else { z - 146096 } / 146097;
    let doe = (z - era * 146097) as u64;
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146096) / 365;
    let y = yoe as i64 + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m_num = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = if m_num <= 2 { y + 1 } else { y };
    format!("{y:04}-{m_num:02}-{d:02}T{h:02}:{m:02}:{s:02}Z")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn none_path_is_a_true_noop() {
        let log = EventLog::new(None);
        log.emit("sni", "1.2.3.4".parse().unwrap(), "5.6.7.8".parse().unwrap(), 1, 2, "evil.com");
        // nothing to assert beyond "didn't panic" - there's no path to have written to.
    }

    #[test]
    fn emit_writes_one_valid_json_line() {
        let path = std::env::temp_dir().join("dpi-lab-test-events-emit.jsonl");
        let _ = std::fs::remove_file(&path);
        let log = EventLog::new(Some(path.clone()));
        log.emit("sni", "1.2.3.4".parse().unwrap(), "5.6.7.8".parse().unwrap(), 1234, 443, "evil.com");

        let contents = std::fs::read_to_string(&path).unwrap();
        let lines: Vec<&str> = contents.lines().collect();
        assert_eq!(lines.len(), 1);
        let v: serde_json::Value = serde_json::from_str(lines[0]).unwrap();
        assert_eq!(v["kind"], "sni");
        assert_eq!(v["src"], "1.2.3.4");
        assert_eq!(v["dst"], "5.6.7.8");
        assert_eq!(v["sport"], 1234);
        assert_eq!(v["dport"], 443);
        assert_eq!(v["detail"], "evil.com");
        assert!(v["time"].as_str().unwrap().ends_with('Z'));
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn emit_appends_not_overwrites() {
        let path = std::env::temp_dir().join("dpi-lab-test-events-append.jsonl");
        let _ = std::fs::remove_file(&path);
        let log = EventLog::new(Some(path.clone()));
        log.emit("sni", "1.1.1.1".parse().unwrap(), "2.2.2.2".parse().unwrap(), 1, 2, "a");
        log.emit("ja3", "3.3.3.3".parse().unwrap(), "4.4.4.4".parse().unwrap(), 3, 4, "b");

        let contents = std::fs::read_to_string(&path).unwrap();
        assert_eq!(contents.lines().count(), 2);
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn format_unix_secs_matches_known_timestamps() {
        assert_eq!(format_unix_secs(0), "1970-01-01T00:00:00Z");
        assert_eq!(format_unix_secs(1_609_459_200), "2021-01-01T00:00:00Z");
        assert_eq!(format_unix_secs(1_609_459_200 + 3661), "2021-01-01T01:01:01Z");
        assert_eq!(format_unix_secs(1_735_689_599), "2024-12-31T23:59:59Z"); // just before a year boundary
    }
}
