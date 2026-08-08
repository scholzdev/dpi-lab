// Unprivileged web UI: config editor + live block/lockdown dashboard for
// dpi-lab. Deliberately its own binary, not a module of the root `dpi-lab`
// process (see events.rs's doc comment for why) - this one runs as your own
// user, needs no raw sockets/NFQUEUE, and talks to dpi-lab only through the
// filesystem: reads/writes config/*.yml, tails the JSONL file dpi-lab
// appends to when `--events-log` is set.
//
// ponytail: deliberately does NOT depend on any of dpi-lab's own modules
// (config.rs, asn.rs, ...) even though a couple of their functions do
// almost the same YAML I/O - config.rs's load_handshake_rules/load_asn_ranges
// reference crate::classify/crate::asn, which would drag this binary's crate
// root through classify.rs -> asn.rs -> engine.rs's entire capture-pipeline
// dependency graph just to reuse an 8-line function. Not worth the coupling
// for a genuinely tiny amount of logic - this file is fully self-contained
// against config/*.yml's on-disk shape (generic YAML<->JSON passthrough
// below), not against dpi-lab's Rust types.
use serde_json::Value;
use std::path::{Path, PathBuf};
use tiny_http::{Header, Method, Response, Server};

const DEFAULT_BIND: &str = "127.0.0.1:8080";
const DEFAULT_CONFIG_DIR: &str = "config";
const DEFAULT_EVENTS_LOG: &str = "events.jsonl";
const DASHBOARD_HTML: &str = include_str!("../../ui/dashboard.html");

fn main() {
    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("info")).init();

    let args: Vec<String> = std::env::args().collect();
    let bind = flag_value(&args, "--bind").unwrap_or_else(|| DEFAULT_BIND.to_string());
    let config_dir = PathBuf::from(flag_value(&args, "--config-dir").unwrap_or_else(|| DEFAULT_CONFIG_DIR.to_string()));
    let events_log = PathBuf::from(flag_value(&args, "--events-log").unwrap_or_else(|| DEFAULT_EVENTS_LOG.to_string()));

    let server = Server::http(&bind).unwrap_or_else(|e| panic!("failed to bind {bind}: {e}"));
    log::info!("[ui] listening on http://{bind}  config-dir={} events-log={}", config_dir.display(), events_log.display());

    for request in server.incoming_requests() {
        let method = request.method().clone();
        let path = request.url().split('?').next().unwrap_or("").to_string();
        if let Err(e) = route(request, &method, &path, &config_dir, &events_log) {
            log::error!("[ui] request handling failed: {e}");
        }
    }
}

fn flag_value(args: &[String], flag: &str) -> Option<String> {
    args.iter().zip(args.iter().skip(1)).find(|(f, _)| f.as_str() == flag).map(|(_, v)| v.clone())
}

fn route(mut request: tiny_http::Request, method: &Method, path: &str, config_dir: &Path, events_log: &Path) -> std::io::Result<()> {
    let response = match (method, path) {
        (Method::Get, "/") => html_response(DASHBOARD_HTML),
        (Method::Get, "/api/config") => json_response(list_config_files(config_dir)),
        (Method::Get, "/api/events") => json_response(tail_events(events_log, 200)),
        (Method::Get, p) if p.starts_with("/api/config/") => match sanitize_name(&p["/api/config/".len()..]) {
            Some(name) => read_config(config_dir, &name),
            None => bad_request("invalid config name"),
        },
        (Method::Put, p) if p.starts_with("/api/config/") => match sanitize_name(&p["/api/config/".len()..]) {
            Some(name) => {
                let mut body = String::new();
                request.as_reader().read_to_string(&mut body)?;
                write_config(config_dir, &name, &body)
            }
            None => bad_request("invalid config name"),
        },
        _ => not_found(),
    };
    request.respond(response)
}

/// `<name>` comes straight from the URL - reject anything that isn't a
/// plain filename component before it ever touches a path join. No `/`,
/// no `..`, no empty string. This is the only thing standing between "edit
/// your blocklists" and writing to an arbitrary path on disk.
fn sanitize_name(name: &str) -> Option<String> {
    if name.is_empty() || name.contains('/') || name.contains('\\') || name == ".." || name.contains('\0') {
        return None;
    }
    Some(name.to_string())
}

fn list_config_files(config_dir: &Path) -> Value {
    let names: Vec<String> = std::fs::read_dir(config_dir)
        .map(|entries| {
            entries
                .filter_map(|e| e.ok())
                .filter_map(|e| e.path().file_stem().map(|s| s.to_string_lossy().into_owned()))
                .filter(|_| true)
                .collect()
        })
        .unwrap_or_default();
    Value::Array(names.into_iter().map(Value::String).collect())
}

fn read_config(config_dir: &Path, name: &str) -> Response<std::io::Cursor<Vec<u8>>> {
    let path = config_dir.join(format!("{name}.yml"));
    let Ok(contents) = std::fs::read_to_string(&path) else { return not_found() };
    match yaml_str_to_json(&contents) {
        Ok(v) => json_response(v),
        Err(e) => bad_request(&format!("{name}.yml doesn't parse as YAML: {e}")),
    }
}

fn write_config(config_dir: &Path, name: &str, json_body: &str) -> Response<std::io::Cursor<Vec<u8>>> {
    let value: Value = match serde_json::from_str(json_body) {
        Ok(v) => v,
        Err(e) => return bad_request(&format!("invalid JSON body: {e}")),
    };
    let yaml = match serde_yaml::to_string(&value) {
        Ok(y) => y,
        Err(e) => return bad_request(&format!("failed to convert to YAML: {e}")),
    };
    let _ = std::fs::create_dir_all(config_dir);
    match std::fs::write(config_dir.join(format!("{name}.yml")), yaml) {
        Ok(()) => json_response(serde_json::json!({"ok": true})),
        Err(e) => {
            log::error!("[ui] failed to write {name}.yml: {e}");
            Response::from_string(format!("{{\"error\":\"{e}\"}}")).with_status_code(500).with_header(json_header())
        }
    }
}

/// Generic YAML -> JSON passthrough (serde is format-agnostic - any
/// `Serialize` type round-trips through any `Serializer`, so parsing into
/// `serde_yaml::Value` then handing that straight to `serde_json`'s
/// serializer works uniformly for every config shape: flat lists, the
/// `{cidr,asn,name}` struct-list, key->value maps, even handshakes.yml's
/// nested anchors - no per-file Rust struct needed on this side).
fn yaml_str_to_json(yaml: &str) -> Result<Value, String> {
    let yaml_value: serde_yaml::Value = serde_yaml::from_str(yaml).map_err(|e| e.to_string())?;
    serde_json::to_value(yaml_value).map_err(|e| e.to_string())
}

/// Last `n` events from the JSONL file, newest last (same order they were
/// appended). Each line is already valid JSON (events.rs writes it that
/// way) - no need to round-trip through a Rust struct, just wrap the raw
/// lines in a JSON array. Missing file (dpi-lab not running with
/// `--events-log`, or hasn't blocked anything yet) is an empty array, not
/// an error - matches this codebase's usual "no data yet" handling.
fn tail_events(path: &Path, n: usize) -> Value {
    let Ok(contents) = std::fs::read_to_string(path) else { return Value::Array(vec![]) };
    let lines: Vec<&str> = contents.lines().filter(|l| !l.trim().is_empty()).collect();
    let start = lines.len().saturating_sub(n);
    let events: Vec<Value> = lines[start..].iter().filter_map(|l| serde_json::from_str(l).ok()).collect();
    Value::Array(events)
}

fn json_header() -> Header {
    Header::from_bytes(&b"Content-Type"[..], &b"application/json"[..]).unwrap()
}

fn html_header() -> Header {
    Header::from_bytes(&b"Content-Type"[..], &b"text/html; charset=utf-8"[..]).unwrap()
}

fn json_response(v: Value) -> Response<std::io::Cursor<Vec<u8>>> {
    Response::from_string(v.to_string()).with_header(json_header())
}

fn html_response(body: &str) -> Response<std::io::Cursor<Vec<u8>>> {
    Response::from_string(body.to_string()).with_header(html_header())
}

fn bad_request(msg: &str) -> Response<std::io::Cursor<Vec<u8>>> {
    Response::from_string(serde_json::json!({"error": msg}).to_string()).with_status_code(400).with_header(json_header())
}

fn not_found() -> Response<std::io::Cursor<Vec<u8>>> {
    Response::from_string(r#"{"error":"not found"}"#).with_status_code(404).with_header(json_header())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sanitize_name_accepts_plain_filenames() {
        assert_eq!(sanitize_name("sni"), Some("sni".to_string()));
        assert_eq!(sanitize_name("probe_targets"), Some("probe_targets".to_string()));
    }

    #[test]
    fn sanitize_name_rejects_path_traversal() {
        assert_eq!(sanitize_name(".."), None);
        assert_eq!(sanitize_name("../etc/passwd"), None);
        assert_eq!(sanitize_name("a/b"), None);
        assert_eq!(sanitize_name("a\\b"), None);
        assert_eq!(sanitize_name(""), None);
    }

    #[test]
    fn yaml_flat_list_becomes_json_array() {
        let v = yaml_str_to_json("- evil.com\n- malware.example\n").unwrap();
        assert_eq!(v, serde_json::json!(["evil.com", "malware.example"]));
    }

    #[test]
    fn yaml_struct_list_becomes_json_array_of_objects() {
        let v = yaml_str_to_json("- cidr: 10.0.0.0/24\n  asn: 64500\n  name: test\n").unwrap();
        assert_eq!(v, serde_json::json!([{"cidr": "10.0.0.0/24", "asn": 64500, "name": "test"}]));
    }

    #[test]
    fn yaml_map_becomes_json_object() {
        let v = yaml_str_to_json("evil.com: 10.0.0.5\n").unwrap();
        assert_eq!(v, serde_json::json!({"evil.com": "10.0.0.5"}));
    }

    #[test]
    fn yaml_comment_only_file_is_null_not_error() {
        // Several shipped config/*.yml files are comment-only (empty by
        // default) - must not error, matches config.rs's own load_list
        // treating a missing/malformed file as empty rather than crashing.
        assert!(yaml_str_to_json("# just a comment\n").is_ok());
    }

    #[test]
    fn write_then_read_config_round_trips() {
        let dir = std::env::temp_dir().join("dpi-lab-ui-test-roundtrip");
        let _ = std::fs::remove_dir_all(&dir);
        let resp = write_config(&dir, "sni", r#"["evil.com","malware.example"]"#);
        assert_eq!(resp.status_code().0, 200);

        let written = std::fs::read_to_string(dir.join("sni.yml")).unwrap();
        let reparsed = yaml_str_to_json(&written).unwrap();
        assert_eq!(reparsed, serde_json::json!(["evil.com", "malware.example"]));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn write_config_rejects_invalid_json_body() {
        let dir = std::env::temp_dir().join("dpi-lab-ui-test-bad-json");
        let resp = write_config(&dir, "sni", "not json");
        assert_eq!(resp.status_code().0, 400);
    }

    #[test]
    fn tail_events_missing_file_is_empty_array() {
        assert_eq!(tail_events(Path::new("/nonexistent/events.jsonl"), 200), Value::Array(vec![]));
    }

    #[test]
    fn tail_events_returns_last_n_in_order() {
        let path = std::env::temp_dir().join("dpi-lab-ui-test-tail.jsonl");
        let lines: String = (0..5).map(|i| format!("{{\"kind\":\"sni\",\"n\":{i}}}\n")).collect();
        std::fs::write(&path, lines).unwrap();

        let v = tail_events(&path, 3);
        let arr = v.as_array().unwrap();
        assert_eq!(arr.len(), 3);
        assert_eq!(arr[0]["n"], 2);
        assert_eq!(arr[2]["n"], 4);
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn tail_events_skips_malformed_lines() {
        let path = std::env::temp_dir().join("dpi-lab-ui-test-tail-malformed.jsonl");
        std::fs::write(&path, "{\"kind\":\"sni\"}\nnot json\n{\"kind\":\"ja3\"}\n").unwrap();

        let v = tail_events(&path, 200);
        assert_eq!(v.as_array().unwrap().len(), 2);
        let _ = std::fs::remove_file(&path);
    }
}
