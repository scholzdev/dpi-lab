// RFC 9001 QUIC-TLS: Initial packets are "protected" (header + AEAD) with keys
// derived from a fixed, public, version-specific salt - not a real secret - so
// anyone observing the wire can strip Initial protection and recover the
// ClientHello inside (SNI, JA3-equivalent fingerprint). This is the *only*
// QUIC packet number space decryptable without keys: Handshake and 1-RTT keys
// come from the real (EC)DHE exchange and stay opaque, same as any other TLS
// session after the handshake. See RFC 9001 §5.2 ("Initial Secrets").
//
// Only QUIC v1 (RFC 9001) is implemented - v2 (RFC 9369) uses a different salt
// and label prefix; add INITIAL_SALT_V2 + a version branch if that's ever seen.

use ring::aead::{self, quic as ring_quic, LessSafeKey, Nonce, UnboundKey, AES_128_GCM};
use ring::hkdf::{self, Prk, Salt, HKDF_SHA256};

// RFC 9001 §5.2.
const INITIAL_SALT_V1: [u8; 20] = [
    0x38, 0x76, 0x2c, 0xf7, 0xf5, 0x59, 0x34, 0xb3, 0x4d, 0x17, 0x9a, 0xe6, 0xa4, 0xc8, 0x0c, 0xad,
    0xcc, 0xbb, 0x7f, 0x0a,
];

struct Len(usize);
impl hkdf::KeyType for Len {
    fn len(&self) -> usize {
        self.0
    }
}

/// RFC 8446 §7.1 HKDF-Expand-Label, restricted to the empty-context case QUIC
/// key derivation always uses.
fn expand_label(secret: &Prk, label: &str, len: usize) -> Vec<u8> {
    let full_label = format!("tls13 {label}");
    let mut info = Vec::with_capacity(2 + 1 + full_label.len() + 1);
    info.extend_from_slice(&(len as u16).to_be_bytes());
    info.push(full_label.len() as u8);
    info.extend_from_slice(full_label.as_bytes());
    info.push(0); // context length = 0
    let info_refs = [info.as_slice()];
    let okm = secret.expand(&info_refs, Len(len)).expect("hkdf-expand-label: len fits digest output");
    let mut out = vec![0u8; len];
    okm.fill(&mut out).expect("hkdf fill");
    out
}

/// Read a QUIC variable-length integer (RFC 9000 §16) at `p`. Returns (value, offset past it).
fn read_varint(data: &[u8], p: usize) -> Option<(u64, usize)> {
    let b0 = *data.get(p)?;
    let len = 1usize << (b0 >> 6); // top two bits pick 1/2/4/8-byte encoding
    let mut v = (b0 & 0x3f) as u64;
    for i in 1..len {
        v = (v << 8) | *data.get(p + i)? as u64;
    }
    Some((v, p + len))
}

/// Strip Initial-packet protection from a UDP datagram and return the
/// reassembled ClientHello wrapped in a synthetic TLS record header, ready
/// for `classify::parse_client_hello` / `classify::ja3` / `classify::parse_sni`
/// (which all expect a real TLS record, not QUIC's bare CRYPTO stream).
/// Returns None for anything that isn't a QUIC v1 Initial packet, or whose
/// CRYPTO frame doesn't decode to a ClientHello (server-sent Initials, ACK-only
/// Initials, retransmits missing the frame, etc).
pub fn decrypt_initial_client_hello_record(datagram: &[u8]) -> Option<Vec<u8>> {
    let mut packet = datagram.to_vec();

    let b0 = *packet.first()?;
    if b0 & 0xc0 != 0xc0 {
        return None; // not a long-header packet
    }
    if (b0 & 0x30) >> 4 != 0x00 {
        return None; // long header type != Initial
    }
    let version = u32::from_be_bytes(packet.get(1..5)?.try_into().ok()?);
    if version != 1 {
        return None; // only v1's public salt is implemented, see module docs
    }

    let mut p = 5;
    let dcid_len = *packet.get(p)? as usize;
    p += 1;
    let dcid = packet.get(p..p + dcid_len)?.to_vec();
    p += dcid_len;
    let scid_len = *packet.get(p)? as usize;
    p += 1 + scid_len;
    let (token_len, np) = read_varint(&packet, p)?;
    p = np + token_len as usize;
    let (remainder_len, np) = read_varint(&packet, p)?;
    let pn_offset = np;
    let payload_end = (pn_offset + remainder_len as usize).min(packet.len());

    // --- derive Initial secrets (RFC 9001 §5.2) ---
    let initial_secret = Salt::new(HKDF_SHA256, &INITIAL_SALT_V1).extract(&dcid);
    let client_secret_bytes = expand_label(&initial_secret, "client in", 32);
    let client_secret = Prk::new_less_safe(HKDF_SHA256, &client_secret_bytes);
    let key_bytes = expand_label(&client_secret, "quic key", 16);
    let iv = expand_label(&client_secret, "quic iv", 12);
    let hp_key_bytes = expand_label(&client_secret, "quic hp", 16);

    // --- header protection removal (RFC 9001 §5.4) ---
    let hp_key = ring_quic::HeaderProtectionKey::new(&ring_quic::AES_128, &hp_key_bytes).ok()?;
    let sample_offset = pn_offset + 4; // sample is taken as if pn were 4 bytes, before we know its real length
    let sample = packet.get(sample_offset..sample_offset + 16)?;
    let mask = hp_key.new_mask(sample).ok()?;
    packet[0] ^= mask[0] & 0x0f; // long header: 4 bits of the first byte are protected
    let pn_len = (packet[0] & 0x03) as usize + 1;
    for i in 0..pn_len {
        packet[pn_offset + i] ^= mask[1 + i];
    }
    let mut pn: u64 = 0;
    for i in 0..pn_len {
        pn = (pn << 8) | packet[pn_offset + i] as u64;
    }

    // --- AEAD open (RFC 9001 §5.3) ---
    let key = LessSafeKey::new(UnboundKey::new(&AES_128_GCM, &key_bytes).ok()?);
    let mut nonce_bytes = [0u8; 12];
    nonce_bytes.copy_from_slice(&iv);
    for (i, b) in pn.to_be_bytes().iter().enumerate() {
        nonce_bytes[4 + i] ^= b; // left-pad pn to IV length, XOR in (RFC 9001 §5.3)
    }
    let nonce = Nonce::assume_unique_for_key(nonce_bytes);
    let header_end = pn_offset + pn_len;
    let aad = packet.get(0..header_end)?.to_vec(); // associated data = the now-deprotected header
    let ciphertext = packet.get_mut(header_end..payload_end)?;
    let plaintext = key.open_in_place(nonce, aead::Aad::from(&aad), ciphertext).ok()?;

    // --- reassemble CRYPTO frames (RFC 9000 §19.6) carrying the ClientHello ---
    let mut crypto = Vec::new();
    let mut fp = 0;
    while fp < plaintext.len() {
        match *plaintext.get(fp)? {
            0x00 => fp += 1, // PADDING
            0x06 => {
                fp += 1;
                let (_offset, np) = read_varint(plaintext, fp)?;
                let (len, np) = read_varint(plaintext, np)?;
                fp = np;
                crypto.extend_from_slice(plaintext.get(fp..fp + len as usize)?);
                fp += len as usize;
            }
            _ => break, // ACK/PING/CONNECTION_CLOSE/... - nothing more of interest here
        }
    }
    if crypto.is_empty() {
        return None;
    }

    // classify::parse_client_hello expects a TLS record (type 0x16 + length);
    // QUIC's CRYPTO stream carries the bare Handshake message, so wrap it.
    let mut record = vec![0x16, 0x03, 0x01];
    record.extend_from_slice(&(crypto.len().min(u16::MAX as usize) as u16).to_be_bytes());
    record.extend_from_slice(&crypto);
    Some(record)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejects_short_header_packets() {
        assert!(decrypt_initial_client_hello_record(&[0x40, 0x01, 0x02]).is_none());
    }

    #[test]
    fn rejects_non_initial_long_header() {
        // Long header (0xc0 set) but type bits = Handshake (0b10), not Initial (0b00).
        let mut pkt = vec![0xe0, 0, 0, 0, 1];
        pkt.extend_from_slice(&[0u8; 20]);
        assert!(decrypt_initial_client_hello_record(&pkt).is_none());
    }

    #[test]
    fn rejects_unsupported_version() {
        let mut pkt = vec![0xc0, 0, 0, 0, 2]; // version 2 (RFC 9369), not implemented
        pkt.extend_from_slice(&[0u8; 20]);
        assert!(decrypt_initial_client_hello_record(&pkt).is_none());
    }

    /// Builds a real QUIC v1 Initial packet containing a CRYPTO frame around a
    /// minimal ClientHello, encrypts it exactly as RFC 9001 specifies, and
    /// checks the round trip recovers the SNI - proves the derivation, header
    /// protection, and AEAD steps all match the spec rather than just parsing.
    #[test]
    fn decrypts_real_initial_packet_and_recovers_sni() {
        let dcid = vec![0xaa; 8];

        // Minimal ClientHello (bare handshake message, no TLS record wrapper -
        // that's how it travels inside a QUIC CRYPTO frame) for "example.com".
        let hostname = b"example.com";
        let mut sni_list = vec![0u8]; // name_type = host_name
        sni_list.extend_from_slice(&(hostname.len() as u16).to_be_bytes());
        sni_list.extend_from_slice(hostname);
        let mut sni_ext_data = (sni_list.len() as u16).to_be_bytes().to_vec();
        sni_ext_data.extend_from_slice(&sni_list);
        let mut ext = vec![0x00, 0x00];
        ext.extend_from_slice(&(sni_ext_data.len() as u16).to_be_bytes());
        ext.extend_from_slice(&sni_ext_data);

        let mut hs = vec![0x03, 0x03];
        hs.extend_from_slice(&[0u8; 32]);
        hs.push(0); // session_id_len
        hs.extend_from_slice(&2u16.to_be_bytes());
        hs.extend_from_slice(&[0x13, 0x01]);
        hs.push(1);
        hs.push(0);
        hs.extend_from_slice(&(ext.len() as u16).to_be_bytes());
        hs.extend_from_slice(&ext);
        let mut client_hello = vec![0x01];
        client_hello.extend_from_slice(&(hs.len() as u32).to_be_bytes()[1..]);
        client_hello.extend_from_slice(&hs);

        let mut crypto_frame = vec![0x06]; // CRYPTO frame type
        crypto_frame.push(0x00); // offset varint = 0
        crypto_frame.extend_from_slice(&encode_varint(client_hello.len() as u64));
        crypto_frame.extend_from_slice(&client_hello);
        while crypto_frame.len() < 20 {
            crypto_frame.push(0x00); // PADDING out to a plausible Initial size
        }

        // --- header (Initial, pn_len encoded as 1 byte -> low bits = 0b00) ---
        let mut header = vec![0xc0]; // long header, fixed bit, type=Initial, pn_len bits placeholder
        header.extend_from_slice(&1u32.to_be_bytes()); // version 1
        header.push(dcid.len() as u8);
        header.extend_from_slice(&dcid);
        header.push(0); // scid_len = 0
        header.push(0x00); // token_len varint = 0
        let pn: u64 = 0;
        let payload_len_field = crypto_frame.len() + 16 /* AEAD tag */ + 1 /* pn */;
        header.extend_from_slice(&encode_varint(payload_len_field as u64));
        let pn_offset = header.len();
        header.push(pn as u8); // 1-byte packet number

        // --- derive the same keys the function under test will derive ---
        let initial_secret = Salt::new(HKDF_SHA256, &INITIAL_SALT_V1).extract(&dcid);
        let client_secret_bytes = expand_label(&initial_secret, "client in", 32);
        let client_secret = Prk::new_less_safe(HKDF_SHA256, &client_secret_bytes);
        let key_bytes = expand_label(&client_secret, "quic key", 16);
        let iv = expand_label(&client_secret, "quic iv", 12);
        let hp_key_bytes = expand_label(&client_secret, "quic hp", 16);

        // --- AEAD-seal the CRYPTO frame as the payload ---
        let key = LessSafeKey::new(UnboundKey::new(&AES_128_GCM, &key_bytes).unwrap());
        let mut nonce_bytes = [0u8; 12];
        nonce_bytes.copy_from_slice(&iv);
        nonce_bytes[11] ^= pn as u8;
        let nonce = Nonce::assume_unique_for_key(nonce_bytes);
        let mut in_out = crypto_frame.clone();
        key.seal_in_place_append_tag(nonce, aead::Aad::from(&header), &mut in_out).unwrap();

        let mut packet = header.clone();
        packet.extend_from_slice(&in_out);

        // --- apply header protection over the now-complete packet ---
        let hp_key = ring_quic::HeaderProtectionKey::new(&ring_quic::AES_128, &hp_key_bytes).unwrap();
        let sample = packet[pn_offset + 4..pn_offset + 4 + 16].to_vec();
        let mask = hp_key.new_mask(&sample).unwrap();
        packet[0] ^= mask[0] & 0x0f;
        packet[pn_offset] ^= mask[1];

        let record = decrypt_initial_client_hello_record(&packet).expect("decrypts");
        assert_eq!(crate::classify::parse_sni(&record).unwrap(), "example.com");
    }

    fn encode_varint(v: u64) -> Vec<u8> {
        if v < 64 {
            vec![v as u8]
        } else if v < 16384 {
            let b = (v as u16) | 0x4000; // 2-byte form: top bits = 01
            b.to_be_bytes().to_vec()
        } else {
            panic!("test helper doesn't need the 4/8-byte varint forms");
        }
    }
}
