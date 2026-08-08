// IPv6 extension-header walking (RFC 8200 SS4). `Ipv6Packet::get_next_header`
// only tells you what comes *immediately* after the fixed 40-byte main
// header - if that's an extension header (Hop-by-Hop, Routing, Destination
// Options, Fragment), the real upper-layer protocol and payload are further
// in. Every v6 code path here that assumed "next_header is the transport
// protocol, payload starts right after the 40-byte header" was wrong on any
// packet carrying one of these - a known, previously-commented limitation
// (see inline.rs's old hard-coded `IPV6_HDR_LEN`). This is the one walker
// both the passive path (engine.rs) and the inline mangle path (inline.rs)
// now share instead of each getting it wrong slightly differently.
use pnet::packet::ip::{IpNextHeaderProtocol, IpNextHeaderProtocols};

/// RFC 8200 SS4.5's Fragment header fields, extracted when one is seen along
/// the way - `fragment.rs` uses this to feed the v6 reassembler.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct Ipv6FragHeader {
    pub offset: u16, // in 8-byte units, per the wire format - fragment.rs converts to bytes
    pub more_fragments: bool,
    pub id: u32,
}

/// Walk past every extension header, returning the final upper-layer
/// protocol, the payload slice after all of them, and the Fragment header's
/// fields if one was present along the chain. `payload` is everything after
/// the fixed 40-byte IPv6 header (i.e. `Ipv6Packet::payload()`).
///
/// Malformed/truncated chains return the protocol/payload/frag-info gathered
/// so far rather than panicking or looping - same "fail soft" idiom as every
/// other parser here, since a middlebox seeing garbage should never crash.
pub fn walk_ipv6_extensions<'a>(
    next_header: IpNextHeaderProtocol,
    payload: &'a [u8],
) -> (IpNextHeaderProtocol, &'a [u8], Option<Ipv6FragHeader>) {
    let (proto, consumed, frag) = walk_ipv6_extensions_len(next_header, payload);
    (proto, &payload[consumed..], frag)
}

/// Same walk, but returns bytes-consumed instead of a re-sliced borrow - for
/// callers (inline.rs's mangle path) that need to index into their own
/// *mutable* buffer at the same offset rather than take an immutable slice.
pub fn walk_ipv6_extensions_len(
    mut next_header: IpNextHeaderProtocol,
    payload: &[u8],
) -> (IpNextHeaderProtocol, usize, Option<Ipv6FragHeader>) {
    let mut frag = None;
    let mut offset = 0;
    loop {
        let rest = &payload[offset..];
        match next_header {
            IpNextHeaderProtocols::Hopopt | IpNextHeaderProtocols::Ipv6Route | IpNextHeaderProtocols::Ipv6Opts => {
                // Generic extension header (RFC 8200 SS4.3/4.4/4.6): next_header(1),
                // hdr_ext_len(1, in 8-byte units NOT counting the first 8 bytes).
                let Some(&next) = rest.first() else { return (next_header, offset, frag) };
                let Some(&hdr_ext_len) = rest.get(1) else { return (next_header, offset, frag) };
                let hdr_len = (hdr_ext_len as usize + 1) * 8;
                if hdr_len > rest.len() {
                    return (next_header, offset, frag);
                }
                next_header = IpNextHeaderProtocol(next);
                offset += hdr_len;
            }
            IpNextHeaderProtocols::Ipv6Frag => {
                // Fixed 8 bytes (RFC 8200 SS4.5): next_header(1) reserved(1)
                // frag_offset(13 bits)+reserved(2 bits)+M(1 bit) identification(4).
                let Some(header) = rest.get(0..8) else { return (next_header, offset, frag) };
                let next = header[0];
                let offset_and_flags = u16::from_be_bytes([header[2], header[3]]);
                frag = Some(Ipv6FragHeader {
                    offset: offset_and_flags >> 3,
                    more_fragments: offset_and_flags & 0x1 != 0,
                    id: u32::from_be_bytes([header[4], header[5], header[6], header[7]]),
                });
                next_header = IpNextHeaderProtocol(next);
                offset += 8;
            }
            _ => return (next_header, offset, frag), // real upper-layer protocol - done
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn no_extension_headers_returns_immediately() {
        let payload = b"tcp segment bytes here";
        let (proto, rest, frag) = walk_ipv6_extensions(IpNextHeaderProtocols::Tcp, payload);
        assert_eq!(proto, IpNextHeaderProtocols::Tcp);
        assert_eq!(rest, payload);
        assert!(frag.is_none());
    }

    #[test]
    fn walks_hop_by_hop_then_destination_options_to_tcp() {
        // Hop-by-Hop: next=DstOpts(60), hdr_ext_len=0 (8 bytes total) + 6 filler bytes.
        let mut data = vec![60, 0];
        data.extend_from_slice(&[0u8; 6]);
        // Destination Options: next=TCP(6), hdr_ext_len=0 (8 bytes total) + 6 filler.
        data.push(6);
        data.push(0);
        data.extend_from_slice(&[0u8; 6]);
        data.extend_from_slice(b"payload");

        let (proto, rest, frag) = walk_ipv6_extensions(IpNextHeaderProtocols::Hopopt, &data);
        assert_eq!(proto, IpNextHeaderProtocols::Tcp);
        assert_eq!(rest, b"payload");
        assert!(frag.is_none());
    }

    #[test]
    fn extracts_fragment_header_fields() {
        let mut data = vec![6u8, 0]; // next=TCP, reserved
        let offset_and_flags: u16 = (5 << 3) | 1; // offset=5 (*8=40 bytes), more_fragments=true
        data.extend_from_slice(&offset_and_flags.to_be_bytes());
        data.extend_from_slice(&0xdead_beefu32.to_be_bytes()); // identification
        data.extend_from_slice(b"fragment data");

        let (proto, rest, frag) = walk_ipv6_extensions(IpNextHeaderProtocols::Ipv6Frag, &data);
        assert_eq!(proto, IpNextHeaderProtocols::Tcp);
        assert_eq!(rest, b"fragment data");
        let frag = frag.unwrap();
        assert_eq!(frag.offset, 5);
        assert!(frag.more_fragments);
        assert_eq!(frag.id, 0xdead_beef);
    }

    #[test]
    fn truncated_chain_returns_gracefully_not_panicking() {
        let (proto, rest, frag) = walk_ipv6_extensions(IpNextHeaderProtocols::Hopopt, &[]);
        assert_eq!(proto, IpNextHeaderProtocols::Hopopt); // couldn't walk further, said so
        assert!(rest.is_empty());
        assert!(frag.is_none());
    }
}
