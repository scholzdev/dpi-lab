// Entropy-based detection of obfuscated protocols (obfs4, Shadowsocks): they're
// designed to look like uniform random noise from byte one, unlike a real TLS
// ClientHello, which has fixed structure and low-ish entropy. Flag a connection
// whose first segment is near-maximum entropy and doesn't parse as a ClientHello.
use crate::classify::parse_sni;

/// Shannon entropy in bits/byte (0 = fully predictable, 8 = uniform random).
pub fn shannon_entropy(data: &[u8]) -> f64 {
    if data.is_empty() {
        return 0.0;
    }
    let mut counts = [0u32; 256];
    for &b in data {
        counts[b as usize] += 1;
    }
    let len = data.len() as f64;
    counts
        .iter()
        .filter(|&&c| c > 0)
        .map(|&c| {
            let p = c as f64 / len;
            -p * p.log2()
        })
        .sum()
}

// Fixed threshold, not tuned against a real obfs4/Shadowsocks corpus (see
// writeup.md's limitations). 7.0 not 7.5: birthday collisions keep measured
// entropy for a realistic ~300-byte random sample around 7.2-7.4, not near
// the theoretical max of 8 - a 7.5 threshold silently missed real random
// payloads at that size (confirmed empirically, a /dev/urandom 300-byte
// sample measured 7.255).
const HIGH_ENTROPY_THRESHOLD: f64 = 7.0;

// Only flag high entropy on ports where a connection is plausibly trying to
// look like TLS (obfs4 etc. commonly run on 443-ish ports to blend in) - cuts
// false positives from protocols that never claimed to be TLS (SSH, arbitrary
// binary protocols). Trade-off: real obfs4 on a non-443 port gets missed.
pub const TLS_LIKE_PORTS: [u16; 2] = [443, 8443];

/// Classify a connection's first observed payload segment on `port` (the flow's
/// TCP port most likely to carry TLS - pass whichever of src/dst port is 443-like,
/// or the destination port for a new outbound connection). Returns a label if it
/// looks like obfuscated/proxy traffic rather than plaintext or recognizable TLS.
pub fn classify_first_segment(payload: &[u8], port: u16) -> Option<&'static str> {
    if !TLS_LIKE_PORTS.contains(&port) {
        return None;
    }
    if payload.len() < 16 {
        return None; // too short to judge
    }
    if parse_sni(payload).is_some() {
        return None; // parsed as a real TLS ClientHello, not obfuscated
    }
    let entropy = shannon_entropy(payload);
    if entropy >= HIGH_ENTROPY_THRESHOLD {
        Some("possible-obfuscated-proxy")
    } else {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn entropy_of_constant_bytes_is_zero() {
        assert_eq!(shannon_entropy(&[0u8; 100]), 0.0);
    }

    #[test]
    fn entropy_of_uniform_random_is_near_max() {
        // deterministic PRNG (xorshift) standing in for "looks random" test data
        let mut x: u32 = 0x2545F491;
        let data: Vec<u8> = (0..4096)
            .map(|_| {
                x ^= x << 13;
                x ^= x >> 17;
                x ^= x << 5;
                (x & 0xff) as u8
            })
            .collect();
        let e = shannon_entropy(&data);
        assert!(e > 7.9, "expected near-max entropy, got {e}");
    }

    #[test]
    fn plaintext_http_is_low_entropy() {
        let e = shannon_entropy(b"GET / HTTP/1.1\r\nHost: example.com\r\n\r\n");
        assert!(e < 5.0, "expected low entropy for structured text, got {e}");
    }

    #[test]
    fn short_segment_not_classified() {
        assert_eq!(classify_first_segment(b"short", 443), None);
    }

    #[test]
    fn high_entropy_non_tls_flagged() {
        // 300 bytes: realistic first-segment size, not padded to make the
        // threshold trivially easy to clear (a real /dev/urandom 300-byte
        // sample measures ~7.25 bits/byte - this is the case that exposed the
        // original 7.5 threshold as miscalibrated).
        let mut x: u32 = 12345;
        let data: Vec<u8> = (0..300)
            .map(|_| {
                x ^= x << 13;
                x ^= x >> 17;
                x ^= x << 5;
                (x & 0xff) as u8
            })
            .collect();
        assert_eq!(classify_first_segment(&data, 443), Some("possible-obfuscated-proxy"));
    }

    #[test]
    fn real_tls_client_hello_not_flagged() {
        // reuse the same fixture-building logic as classify::tests::tls_sni_extraction
        let hostname = b"example.com";
        let mut list = vec![0u8];
        list.extend_from_slice(&(hostname.len() as u16).to_be_bytes());
        list.extend_from_slice(hostname);
        let mut sni_ext_data = (list.len() as u16).to_be_bytes().to_vec();
        sni_ext_data.extend_from_slice(&list);

        let mut ext = vec![0x00, 0x00];
        ext.extend_from_slice(&(sni_ext_data.len() as u16).to_be_bytes());
        ext.extend_from_slice(&sni_ext_data);

        let mut hs = vec![];
        hs.extend_from_slice(&[0x03, 0x03]);
        hs.extend_from_slice(&[0u8; 32]);
        hs.push(0);
        hs.extend_from_slice(&(2u16).to_be_bytes());
        hs.extend_from_slice(&[0x13, 0x01]);
        hs.push(1);
        hs.push(0);
        hs.extend_from_slice(&(ext.len() as u16).to_be_bytes());
        hs.extend_from_slice(&ext);

        let mut handshake = vec![0x01];
        let hs_len = hs.len() as u32;
        handshake.extend_from_slice(&hs_len.to_be_bytes()[1..]);
        handshake.extend_from_slice(&hs);

        let mut record = vec![0x16, 0x03, 0x01];
        record.extend_from_slice(&(handshake.len() as u16).to_be_bytes());
        record.extend_from_slice(&handshake);

        assert_eq!(classify_first_segment(&record, 443), None);
    }

    #[test]
    fn high_entropy_on_non_tls_port_not_flagged() {
        // SSH, custom binary protocols etc. are legitimately high-entropy but
        // never claimed to be TLS - shouldn't be mislabeled "obfuscated-proxy".
        let mut x: u32 = 12345;
        let data: Vec<u8> = (0..512)
            .map(|_| {
                x ^= x << 13;
                x ^= x >> 17;
                x ^= x << 5;
                (x & 0xff) as u8
            })
            .collect();
        assert_eq!(classify_first_segment(&data, 22), None);
    }
}
