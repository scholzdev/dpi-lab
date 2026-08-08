// IP-to-ASN blocking: the GFW blackholes whole ASNs (a hosting provider, a
// VPN operator's network) during high-alert periods, not just individual
// IPs - this is that mechanism at lab scale. No bundled MaxMind GeoLite2-ASN
// or RIR delegation file (licensing/size) - config/asn.yml ships a handful
// of documented example ranges; a real deployment supplies its own ASN data
// source converted to this flat {cidr, asn, name} shape.
use crate::engine::cidr_contains;
use serde::Deserialize;
use std::net::IpAddr;

#[derive(Deserialize, Debug, Clone, PartialEq)]
pub struct AsnRange {
    pub cidr: String,
    pub asn: u32,
    pub name: String,
}

/// Resolve `ip` to an ASN via linear scan of `ranges` - fine at lab-database
/// sizes (hundreds/low-thousands of entries); a full global ASN table would
/// want a longest-prefix-match trie instead, out of scope here.
pub fn asn_for_ip(ranges: &[AsnRange], ip: &IpAddr) -> Option<u32> {
    ranges.iter().find(|r| cidr_contains(&r.cidr, ip)).map(|r| r.asn)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ranges() -> Vec<AsnRange> {
        vec![
            AsnRange { cidr: "10.27.0.0/24".to_string(), asn: 64500, name: "lab-net".to_string() },
            AsnRange { cidr: "192.0.2.0/24".to_string(), asn: 64501, name: "example-provider".to_string() },
        ]
    }

    #[test]
    fn resolves_ip_within_range() {
        let ip: IpAddr = "10.27.0.39".parse().unwrap();
        assert_eq!(asn_for_ip(&ranges(), &ip), Some(64500));
    }

    #[test]
    fn no_match_outside_any_range() {
        let ip: IpAddr = "8.8.8.8".parse().unwrap();
        assert_eq!(asn_for_ip(&ranges(), &ip), None);
    }

    #[test]
    fn first_matching_range_wins_on_overlap() {
        let overlapping = vec![
            AsnRange { cidr: "10.0.0.0/8".to_string(), asn: 1, name: "outer".to_string() },
            AsnRange { cidr: "10.27.0.0/24".to_string(), asn: 2, name: "inner".to_string() },
        ];
        let ip: IpAddr = "10.27.0.39".parse().unwrap();
        assert_eq!(asn_for_ip(&overlapping, &ip), Some(1)); // linear scan, first hit
    }
}
