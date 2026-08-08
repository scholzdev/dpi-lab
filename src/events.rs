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
use std::path::{Path, PathBuf};

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

/// Rotate to `<path>.1` once the active file passes this size - one
/// rotation slot, not a numbered chain, kept deliberately simple for a lab
/// tool's event volume (each line is a real block/lockdown, not every
/// packet - this is a lot of events even at 10MB).
const MAX_EVENTS_LOG_BYTES: u64 = 10 * 1024 * 1024;

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
        rotate_if_needed(path);
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

/// If `path` exists and is past `MAX_EVENTS_LOG_BYTES`, rename it to
/// `<path>.1` (clobbering any prior `.1`) so the next write starts a fresh
/// file. Checked before every write rather than on a timer - this is a lab
/// tool, one extra `metadata()` call per emitted event (not per packet) is
/// noise. Best-effort: a failed rotation just means the file keeps growing
/// past the threshold this once, logged, never blocks the actual event
/// write that follows.
fn rotate_if_needed(path: &PathBuf) {
    let Ok(meta) = std::fs::metadata(path) else { return }; // doesn't exist yet - nothing to rotate
    if meta.len() < MAX_EVENTS_LOG_BYTES {
        return;
    }
    let rotated = rotated_path(path);
    if let Err(e) = std::fs::rename(path, &rotated) {
        log::error!("[events] failed to rotate {} to {}: {e}", path.display(), rotated.display());
    }
}

fn rotated_path(path: &Path) -> PathBuf {
    let mut rotated = path.as_os_str().to_os_string();
    rotated.push(".1");
    PathBuf::from(rotated)
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

/// (weekday, hour, minute) for a unix timestamp - weekday 0=Sunday..6=Saturday.
/// 1970-01-01 (day 0) was a Thursday, so `(days_since_epoch + 4) % 7` is the
/// standard closed-form for this - reused by engine.rs's scheduled-policy
/// feature so there's one day/time extraction in this codebase, not two
/// slightly-different copies (the date math above already computes
/// days-since-epoch and time-of-day, this just adds the weekday remainder).
pub(crate) fn weekday_hour_minute(secs: u64) -> (u8, u8, u8) {
    let (days, time_of_day) = (secs / 86400, secs % 86400);
    let weekday = ((days + 4) % 7) as u8;
    let hour = (time_of_day / 3600) as u8;
    let minute = ((time_of_day % 3600) / 60) as u8;
    (weekday, hour, minute)
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
    fn rotate_if_needed_leaves_small_files_alone() {
        let path = std::env::temp_dir().join("dpi-lab-test-events-rotate-small.jsonl");
        let rotated = rotated_path(&path);
        let _ = std::fs::remove_file(&path);
        let _ = std::fs::remove_file(&rotated);
        std::fs::write(&path, "{\"kind\":\"sni\"}\n").unwrap();

        rotate_if_needed(&path);
        assert!(path.exists());
        assert!(!rotated.exists());
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn rotate_if_needed_moves_oversized_file_to_dot_1() {
        let path = std::env::temp_dir().join("dpi-lab-test-events-rotate-big.jsonl");
        let rotated = rotated_path(&path);
        let _ = std::fs::remove_file(&path);
        let _ = std::fs::remove_file(&rotated);
        // One big write past the threshold - cheaper than emitting millions
        // of real small events to reach the same size.
        std::fs::write(&path, vec![b'a'; (MAX_EVENTS_LOG_BYTES + 1) as usize]).unwrap();

        rotate_if_needed(&path);
        assert!(!path.exists()); // renamed away
        assert!(rotated.exists());
        assert_eq!(std::fs::metadata(&rotated).unwrap().len(), MAX_EVENTS_LOG_BYTES + 1);

        let _ = std::fs::remove_file(&rotated);
    }

    #[test]
    fn emit_after_rotation_starts_a_fresh_file() {
        let path = std::env::temp_dir().join("dpi-lab-test-events-rotate-then-emit.jsonl");
        let rotated = rotated_path(&path);
        let _ = std::fs::remove_file(&path);
        let _ = std::fs::remove_file(&rotated);
        std::fs::write(&path, vec![b'a'; (MAX_EVENTS_LOG_BYTES + 1) as usize]).unwrap();

        let log = EventLog::new(Some(path.clone()));
        log.emit("sni", "1.1.1.1".parse().unwrap(), "2.2.2.2".parse().unwrap(), 1, 2, "rotated-in");

        assert!(rotated.exists()); // the old oversized content moved here
        let fresh = std::fs::read_to_string(&path).unwrap();
        assert_eq!(fresh.lines().count(), 1); // not appended onto the old giant file

        let _ = std::fs::remove_file(&path);
        let _ = std::fs::remove_file(&rotated);
    }

    #[test]
    fn format_unix_secs_matches_known_timestamps() {
        assert_eq!(format_unix_secs(0), "1970-01-01T00:00:00Z");
        assert_eq!(format_unix_secs(1_609_459_200), "2021-01-01T00:00:00Z");
        assert_eq!(format_unix_secs(1_609_459_200 + 3661), "2021-01-01T01:01:01Z");
        assert_eq!(format_unix_secs(1_735_689_599), "2024-12-31T23:59:59Z"); // just before a year boundary
    }

    #[test]
    fn weekday_hour_minute_matches_known_timestamps() {
        // 1970-01-01T00:00:00Z was a Thursday.
        assert_eq!(weekday_hour_minute(0), (4, 0, 0));
        // 2021-01-01T00:00:00Z was a Friday.
        assert_eq!(weekday_hour_minute(1_609_459_200), (5, 0, 0));
        // Same day, 14:35.
        assert_eq!(weekday_hour_minute(1_609_459_200 + 14 * 3600 + 35 * 60), (5, 14, 35));
        // 2026-08-08T00:00:00Z was a Saturday - today, as of this session.
        assert_eq!(weekday_hour_minute(1_786_147_200).0, 6);
    }
}
