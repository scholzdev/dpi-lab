// Per-flow TCP reassembly: buffer out-of-order segments by seq, flush contiguous bytes.
// Anchored on the connection's ISN (from the SYN packet) - that's the only way to
// know the true stream start; inferring it from arrival order is unsound.
use std::collections::BTreeMap;

pub struct TcpStream {
    pending: BTreeMap<u32, Vec<u8>>,
    next_seq: u32,
    pub delivered: Vec<u8>,
}

impl TcpStream {
    /// `isn`: sequence number of the first data byte (SYN's seq + 1, or the seq of
    /// the first segment observed if capture started mid-stream).
    pub fn new(isn: u32) -> Self {
        Self { pending: BTreeMap::new(), next_seq: isn, delivered: Vec::new() }
    }

    /// Next contiguous byte this direction is expected to send - used to
    /// spoof a response as if it were the real next segment on this flow.
    pub fn next_seq(&self) -> u32 {
        self.next_seq
    }

    pub fn feed(&mut self, seq: u32, payload: &[u8]) {
        if payload.is_empty() {
            return;
        }
        self.pending.insert(seq, payload.to_vec());
        self.drain_contiguous();
    }

    fn drain_contiguous(&mut self) {
        while let Some(seg) = self.pending.remove(&self.next_seq) {
            let len = seg.len() as u32;
            self.delivered.extend_from_slice(&seg);
            self.next_seq = self.next_seq.wrapping_add(len);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn in_order_delivery() {
        let mut s = TcpStream::new(0);
        s.feed(0, b"hello ");
        s.feed(6, b"world");
        assert_eq!(s.delivered, b"hello world");
    }

    #[test]
    fn out_of_order_and_duplicate() {
        let mut s = TcpStream::new(0);
        s.feed(6, b"world");
        s.feed(0, b"hello "); // fills gap, should drain both
        s.feed(0, b"hello "); // duplicate, must not re-append
        assert_eq!(s.delivered, b"hello world");
    }

    #[test]
    fn gap_blocks_delivery() {
        let mut s = TcpStream::new(0);
        s.feed(0, b"hello ");
        s.feed(20, b"later"); // gap: seq 6..20 missing
        assert_eq!(s.delivered, b"hello "); // only contiguous part delivered
    }
}
