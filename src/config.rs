// Block lists as plain YAML files under config/ - a list of strings per file,
// so adding/removing a rule is a text edit, not a rebuild. Missing file or empty
// list is fine (no extra rules from that source); a malformed file is reported
// but doesn't crash the whole capture session.
use std::path::Path;

pub fn load_list(path: &Path) -> Vec<String> {
    let Ok(contents) = std::fs::read_to_string(path) else { return Vec::new() };
    match serde_yaml::from_str::<Vec<String>>(&contents) {
        Ok(list) => list,
        Err(e) => {
            eprintln!("[config] failed to parse {}: {e}", path.display());
            Vec::new()
        }
    }
}

/// Load a YAML mapping (orig -> target) like config/redirect.yml. Same
/// missing-file/malformed-file handling as `load_list`.
pub fn load_map(path: &Path) -> Vec<(String, String)> {
    let Ok(contents) = std::fs::read_to_string(path) else { return Vec::new() };
    match serde_yaml::from_str::<std::collections::HashMap<String, String>>(&contents) {
        Ok(map) => map.into_iter().collect(),
        Err(e) => {
            eprintln!("[config] failed to parse {}: {e}", path.display());
            Vec::new()
        }
    }
}

/// Load a YAML mapping of ip -> unix-epoch-seconds expiry, used for TTL'd
/// escalated blocks. Same missing-file/malformed-file handling as `load_map`.
pub fn load_expiry_map(path: &Path) -> Vec<(String, u64)> {
    let Ok(contents) = std::fs::read_to_string(path) else { return Vec::new() };
    match serde_yaml::from_str::<std::collections::HashMap<String, u64>>(&contents) {
        Ok(map) => map.into_iter().collect(),
        Err(e) => {
            eprintln!("[config] failed to parse {}: {e}", path.display());
            Vec::new()
        }
    }
}

/// Upsert `ip -> expires_at` (unix-epoch seconds) into the expiry map at
/// `path`. Also drops any entries that have already expired, so the file
/// self-prunes on every escalation event rather than growing forever.
pub fn set_expiry_entry(path: &Path, ip: &str, expires_at: u64) {
    let now = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_secs();
    let mut map: std::collections::HashMap<String, u64> =
        load_expiry_map(path).into_iter().filter(|(_, exp)| *exp > now).collect();
    map.insert(ip.to_string(), expires_at);
    match serde_yaml::to_string(&map) {
        Ok(yaml) => {
            if let Err(e) = std::fs::write(path, yaml) {
                eprintln!("[config] failed to persist {} to {}: {e}", ip, path.display());
            }
        }
        Err(e) => eprintln!("[config] failed to serialize {}: {e}", path.display()),
    }
}

#[derive(serde::Deserialize, PartialEq, Debug)]
pub struct CannonConfig {
    #[serde(default)]
    pub hosts: Vec<String>,
    #[serde(default)]
    pub marker: String,
    pub redirect: Option<String>,
    #[serde(default = "default_cannon_port")]
    pub port: u16, // plaintext HTTP port to watch - not always 80 (e.g. a reverse proxy squats it)
}

fn default_cannon_port() -> u16 {
    80
}

impl Default for CannonConfig {
    fn default() -> Self {
        Self { hosts: Vec::new(), marker: String::new(), redirect: None, port: default_cannon_port() }
    }
}

/// Load config/cannon.yml. Missing file -> default (empty hosts, so nothing
/// ever fires); malformed file is reported, same default.
pub fn load_cannon_config(path: &Path) -> CannonConfig {
    let Ok(contents) = std::fs::read_to_string(path) else { return CannonConfig::default() };
    match serde_yaml::from_str(&contents) {
        Ok(cfg) => cfg,
        Err(e) => {
            eprintln!("[config] failed to parse {}: {e}", path.display());
            CannonConfig::default()
        }
    }
}

/// Load config/handshakes.yml - a list of known protocol handshake
/// signatures (see classify::HandshakeRule). Same missing/malformed handling
/// as everything else here: empty list, not a crash.
pub fn load_handshake_rules(path: &Path) -> Vec<crate::classify::HandshakeRule> {
    let Ok(contents) = std::fs::read_to_string(path) else { return Vec::new() };
    match serde_yaml::from_str(&contents) {
        Ok(rules) => rules,
        Err(e) => {
            eprintln!("[config] failed to parse {}: {e}", path.display());
            Vec::new()
        }
    }
}

/// Load config/asn.yml - a list of {cidr, asn, name} ranges (see asn.rs).
/// Same missing/malformed handling as everything else here.
pub fn load_asn_ranges(path: &Path) -> Vec<crate::asn::AsnRange> {
    let Ok(contents) = std::fs::read_to_string(path) else { return Vec::new() };
    match serde_yaml::from_str(&contents) {
        Ok(ranges) => ranges,
        Err(e) => {
            eprintln!("[config] failed to parse {}: {e}", path.display());
            Vec::new()
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn loads_yaml_list() {
        let path = tempfile("loads_yaml_list");
        std::fs::write(&path, "- florianscholz.dev\n- example.com").unwrap();
        assert_eq!(load_list(&path), vec!["florianscholz.dev", "example.com"]);
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn missing_file_is_empty_list_not_error() {
        assert_eq!(load_list(Path::new("/nonexistent/does-not-exist.yml")), Vec::<String>::new());
    }

    #[test]
    fn malformed_yaml_is_empty_list_not_crash() {
        let path = tempfile("malformed_yaml_is_empty_list_not_crash");
        std::fs::write(&path, "{not valid yaml list").unwrap();
        assert_eq!(load_list(&path), Vec::<String>::new());
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn loads_yaml_map() {
        let path = tempfile("loads_yaml_map");
        std::fs::write(&path, "florianscholz.dev: example.com").unwrap();
        assert_eq!(load_map(&path), vec![("florianscholz.dev".to_string(), "example.com".to_string())]);
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn set_expiry_entry_creates_and_reads_back() {
        let path = tempfile("set_expiry_entry_creates_and_reads_back");
        let _ = std::fs::remove_file(&path);
        set_expiry_entry(&path, "10.27.0.39", 9_999_999_999);
        assert_eq!(load_expiry_map(&path), vec![("10.27.0.39".to_string(), 9_999_999_999)]);
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn set_expiry_entry_drops_expired_entries() {
        let path = tempfile("set_expiry_entry_drops_expired_entries");
        std::fs::write(&path, "old-ip: 1\n").unwrap(); // epoch 1 = long expired
        set_expiry_entry(&path, "new-ip", 9_999_999_999);
        assert_eq!(load_expiry_map(&path), vec![("new-ip".to_string(), 9_999_999_999)]);
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn loads_cannon_config() {
        let path = tempfile("loads_cannon_config");
        std::fs::write(&path, "hosts: [10.27.0.5, 10.27.0.10]\nmarker: \"test\"\nredirect: http://10.27.0.10/x\n").unwrap();
        let cfg = load_cannon_config(&path);
        assert_eq!(cfg.hosts, vec!["10.27.0.5", "10.27.0.10"]);
        assert_eq!(cfg.marker, "test");
        assert_eq!(cfg.redirect, Some("http://10.27.0.10/x".to_string()));
        assert_eq!(cfg.port, 80); // not specified -> defaults to 80
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn cannon_config_port_is_overridable() {
        let path = tempfile("cannon_config_port_is_overridable");
        std::fs::write(&path, "hosts: [10.27.0.10]\nmarker: \"test\"\nport: 81\n").unwrap();
        assert_eq!(load_cannon_config(&path).port, 81);
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn missing_cannon_config_is_default() {
        let cfg = load_cannon_config(Path::new("/nonexistent/cannon.yml"));
        assert_eq!(cfg, CannonConfig::default());
    }

    #[test]
    fn loads_handshake_rules() {
        let path = tempfile("loads_handshake_rules");
        std::fs::write(
            &path,
            "- name: wireguard-handshake-init\n  length: 148\n  match:\n    - offset: 0\n      bytes: [1, 0, 0, 0]\n",
        )
        .unwrap();
        let rules = load_handshake_rules(&path);
        assert_eq!(rules.len(), 1);
        assert_eq!(rules[0].name, "wireguard-handshake-init");
        assert_eq!(rules[0].length, Some(148));
        assert_eq!(rules[0].anchors[0].bytes, vec![1, 0, 0, 0]);
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn missing_handshake_rules_is_empty_list() {
        assert!(load_handshake_rules(Path::new("/nonexistent/handshakes.yml")).is_empty());
    }

    #[test]
    fn loads_asn_ranges() {
        let path = tempfile("loads_asn_ranges");
        std::fs::write(&path, "- cidr: 10.27.0.0/24\n  asn: 64500\n  name: lab-net\n").unwrap();
        let ranges = load_asn_ranges(&path);
        assert_eq!(ranges.len(), 1);
        assert_eq!(ranges[0].cidr, "10.27.0.0/24");
        assert_eq!(ranges[0].asn, 64500);
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn missing_asn_ranges_is_empty_list() {
        assert!(load_asn_ranges(Path::new("/nonexistent/asn.yml")).is_empty());
    }

    /// Regression guard on the shipped file, same reasoning as
    /// real_handshakes_yml_parses_with_expected_rules.
    #[test]
    fn real_asn_yml_parses() {
        let ranges = load_asn_ranges(Path::new("config/asn.yml"));
        assert_eq!(ranges.len(), 2);
        assert_eq!(ranges[0].asn, 64500);
    }

    /// Regression guard on the shipped file - same reasoning as
    /// real_asn_yml_parses.
    #[test]
    fn real_doh_providers_yml_parses() {
        let providers = load_map(Path::new("config/doh_providers.yml"));
        assert_eq!(providers.len(), 6);
        assert!(providers.iter().any(|(ip, name)| ip == "1.1.1.1" && name == "Cloudflare DNS"));
    }

    /// Regression guard on the actual shipped file, not a synthetic fixture -
    /// catches a broken config/handshakes.yml (bad YAML, wrong rule count)
    /// before it ships silently as "zero rules loaded, no error printed."
    #[test]
    fn real_handshakes_yml_parses_with_expected_rules() {
        let rules = load_handshake_rules(Path::new("config/handshakes.yml"));
        let names: Vec<&str> = rules.iter().map(|r| r.name.as_str()).collect();
        assert_eq!(
            names,
            vec!["wireguard-handshake-init", "ikev2-sa-init", "openvpn-hard-reset-client-v2", "ssh-version-exchange"]
        );
        // Byte-content regression guard: names alone wouldn't have caught the
        // "SSH-" anchor being transposed to "SHS-" (wrong bytes, same rule name).
        let ssh = rules.iter().find(|r| r.name == "ssh-version-exchange").unwrap();
        assert_eq!(ssh.anchors[0].bytes, b"SSH-");
    }

    // unique-per-test filename in the OS temp dir - tests run in parallel
    // threads so names must not collide.
    fn tempfile(test_name: &str) -> std::path::PathBuf {
        std::env::temp_dir().join(format!("dpi-lab-test-{test_name}.yml"))
    }
}
