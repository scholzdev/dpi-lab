// HTTP/2 :authority extraction. HTTP/2 puts the request host in a pseudo-header
// (":authority") inside a HEADERS frame, HPACK-compressed - unlike HTTP/1.1's
// plaintext "Host:" line (see classify::parse_http_host), there's no cleartext
// substring to grep for.
//
// Scope (v1): only the client connection preface + the first HEADERS frame,
// requiring END_HEADERS set (no CONTINUATION-frame reassembly - a request's
// header block spanning multiple frames isn't chased, matching every other
// "try, return None" parser in this codebase). Full HPACK decode (static +
// dynamic table, Huffman) is delegated to the `hpack` crate rather than
// hand-rolled - re-deriving RFC 7541's Huffman code table from memory is far
// more error-prone than reusing a maintained decoder that already implements
// the whole spec, dynamic table included.
use hpack::Decoder;

const PREFACE: &[u8] = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n";
const FRAME_HEADER_LEN: usize = 9;
const HEADERS_FRAME_TYPE: u8 = 0x1;
const FLAG_END_HEADERS: u8 = 0x4;
const FLAG_PADDED: u8 = 0x8;
const FLAG_PRIORITY: u8 = 0x20;

/// Extract the `:authority` pseudo-header value from the first HEADERS frame
/// of an HTTP/2 client connection. `data` is the reassembled stream from the
/// connection's start - only fires if it begins with the HTTP/2 preface.
pub fn extract_authority(data: &[u8]) -> Option<String> {
    header_value(&first_headers_block(data)?, b":authority")
}

/// Extract the `:path` pseudo-header value (the full request-target,
/// including any query string - HTTP/2 has no separate "Host:"/request-line
/// split the way HTTP/1.1 does) from the first HEADERS frame. Used by
/// mitm.rs to scan HTTP/2 requests for blocked keywords the same way
/// classify::parse_http_request_line's query does for HTTP/1.1.
pub fn extract_path(data: &[u8]) -> Option<String> {
    header_value(&first_headers_block(data)?, b":path")
}

/// Walk frames from the connection preface to the first HEADERS frame and
/// return its (pad/priority-stripped) header block, ready for HPACK decode.
/// Shared by every pseudo-header extractor above.
fn first_headers_block(data: &[u8]) -> Option<Vec<u8>> {
    if !data.starts_with(PREFACE) {
        return None;
    }
    let mut offset = PREFACE.len();
    while offset + FRAME_HEADER_LEN <= data.len() {
        let len = u32::from_be_bytes([0, data[offset], data[offset + 1], data[offset + 2]]) as usize;
        let frame_type = data[offset + 3];
        let flags = data[offset + 4];
        let payload_start = offset + FRAME_HEADER_LEN;
        if payload_start + len > data.len() {
            return None; // frame not fully delivered yet
        }
        let payload = &data[payload_start..payload_start + len];
        if frame_type == HEADERS_FRAME_TYPE {
            if flags & FLAG_END_HEADERS == 0 {
                return None; // header block continues in a CONTINUATION frame - not chased
            }
            return Some(strip_headers_framing(payload, flags)?.to_vec());
        }
        offset = payload_start + len;
    }
    None
}

/// Strip the optional pad-length byte and priority fields (RFC 9113 §6.2) off
/// a HEADERS frame payload, returning just the header block fragment.
fn strip_headers_framing(payload: &[u8], flags: u8) -> Option<&[u8]> {
    let mut p = 0;
    let pad_len = if flags & FLAG_PADDED != 0 {
        let pl = *payload.get(0)? as usize;
        p += 1;
        pl
    } else {
        0
    };
    if flags & FLAG_PRIORITY != 0 {
        p += 5; // 4-byte stream dependency + 1-byte weight
    }
    payload.get(p..payload.len().checked_sub(pad_len)?)
}

fn header_value(block: &[u8], name: &[u8]) -> Option<String> {
    let headers = Decoder::new().decode(block).ok()?;
    headers
        .into_iter()
        .find(|(n, _)| n == name)
        .map(|(_, value)| String::from_utf8_lossy(&value).into_owned())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn frame(frame_type: u8, flags: u8, payload: &[u8]) -> Vec<u8> {
        let mut f = vec![
            (payload.len() >> 16) as u8,
            (payload.len() >> 8) as u8,
            payload.len() as u8,
            frame_type,
            flags,
            0, 0, 0, 1, // stream id 1
        ];
        f.extend_from_slice(payload);
        f
    }

    fn headers_block(authority: &str) -> Vec<u8> {
        hpack::Encoder::new().encode(vec![
            (&b":method"[..], b"GET".as_slice()),
            (&b":authority"[..], authority.as_bytes()),
        ])
    }

    fn headers_block_with_path(path: &str) -> Vec<u8> {
        hpack::Encoder::new().encode(vec![
            (&b":method"[..], b"GET".as_slice()),
            (&b":path"[..], path.as_bytes()),
        ])
    }

    #[test]
    fn extracts_path_from_first_headers_frame() {
        let mut data = PREFACE.to_vec();
        data.extend(frame(HEADERS_FRAME_TYPE, FLAG_END_HEADERS, &headers_block_with_path("/search?q=blocked")));
        assert_eq!(extract_path(&data), Some("/search?q=blocked".to_string()));
    }

    #[test]
    fn extract_path_missing_pseudo_header_returns_none() {
        let mut data = PREFACE.to_vec();
        data.extend(frame(HEADERS_FRAME_TYPE, FLAG_END_HEADERS, &headers_block("example.com"))); // no :path
        assert_eq!(extract_path(&data), None);
    }

    #[test]
    fn extracts_authority_from_first_headers_frame() {
        let mut data = PREFACE.to_vec();
        data.extend(frame(0x4, 0x0, &[0, 0, 0, 0, 0, 0])); // SETTINGS frame first, like a real client
        data.extend(frame(HEADERS_FRAME_TYPE, FLAG_END_HEADERS, &headers_block("example.com")));
        assert_eq!(extract_authority(&data), Some("example.com".to_string()));
    }

    #[test]
    fn no_preface_returns_none() {
        assert!(extract_authority(b"GET / HTTP/1.1\r\n").is_none());
    }

    #[test]
    fn truncated_frame_returns_none() {
        let mut data = PREFACE.to_vec();
        data.extend(frame(HEADERS_FRAME_TYPE, FLAG_END_HEADERS, &headers_block("example.com")));
        data.truncate(data.len() - 5); // chop off the tail of the HEADERS payload
        assert!(extract_authority(&data).is_none());
    }

    #[test]
    fn missing_end_headers_returns_none() {
        let mut data = PREFACE.to_vec();
        data.extend(frame(HEADERS_FRAME_TYPE, 0x0, &headers_block("example.com"))); // no END_HEADERS
        assert!(extract_authority(&data).is_none());
    }

    #[test]
    fn padded_and_prioritized_headers_frame_still_parses() {
        let mut payload = vec![2u8]; // pad length = 2
        payload.extend_from_slice(&[0, 0, 0, 0, 16]); // stream dependency + weight
        payload.extend_from_slice(&headers_block("example.com"));
        payload.extend_from_slice(&[0, 0]); // padding

        let mut data = PREFACE.to_vec();
        data.extend(frame(HEADERS_FRAME_TYPE, FLAG_END_HEADERS | FLAG_PADDED | FLAG_PRIORITY, &payload));
        assert_eq!(extract_authority(&data), Some("example.com".to_string()));
    }
}
