// IP-fragment reassembly (IPv4 header fields directly; IPv6 via the
// Fragment extension header, see ipv6ext.rs). Without this, a ClientHello
// (or anything else) split across IP fragments just silently fails to parse
// on the first fragment - a real evasion channel, one layer below the
// TCP-segment fragmentation evasion `engine.rs` already detects.
//
// ponytail: does NOT coalesce overlapping fragment ranges - a real sender
// essentially never produces them (and modern stacks drop overlaps outright
// for exactly the ambiguity reason RFC-level insertion/evasion attacks
// exploit), so `insert` just fails to complete (returns None forever) on an
// adversarial overlapping set rather than resolving it one way or another.
// Fail-closed, not exploitable - upgrade path if it ever matters: merge
// overlapping/adjacent BTreeMap ranges before the contiguity walk below.
use std::collections::{BTreeMap, HashMap};
use std::hash::Hash;
use std::time::{Duration, Instant};

const MAX_ENTRIES: usize = 4096; // backstop against many bogus partial fragment sets

struct FragBuf {
    parts: BTreeMap<usize, Vec<u8>>,
    total_len: Option<usize>, // known once the last fragment (more_fragments=false) arrives
    last_seen: Instant,
}

impl FragBuf {
    fn new() -> Self {
        Self { parts: BTreeMap::new(), total_len: None, last_seen: Instant::now() }
    }

    /// `Some(total)` once every byte of `0..total` is covered by a
    /// contiguous, non-overlapping run of fragments in offset order.
    fn reassembled(&self) -> Option<Vec<u8>> {
        let total = self.total_len?;
        let mut want = 0usize;
        for (&offset, chunk) in &self.parts {
            if offset != want {
                return None; // gap, or an overlap our contiguity check doesn't resolve
            }
            want += chunk.len();
            if want >= total {
                break;
            }
        }
        if want < total {
            return None;
        }
        let mut out = Vec::with_capacity(total);
        for chunk in self.parts.values() {
            if out.len() >= total {
                break;
            }
            out.extend_from_slice(chunk);
        }
        out.truncate(total);
        Some(out)
    }
}

pub struct FragmentTable<K> {
    table: HashMap<K, FragBuf>,
}

impl<K: Eq + Hash + Clone> FragmentTable<K> {
    pub fn new() -> Self {
        Self { table: HashMap::new() }
    }

    /// Feed one fragment. `offset`/`data` are byte offset and bytes of this
    /// fragment within the reassembled datagram; `more_fragments` is that
    /// fragment's MF flag (false = this is the last one, so
    /// `offset + data.len()` is the datagram's total length). Returns the
    /// fully reassembled datagram once complete, consuming the table entry.
    pub fn insert(&mut self, key: K, offset: usize, more_fragments: bool, data: &[u8]) -> Option<Vec<u8>> {
        if !self.table.contains_key(&key) && self.table.len() >= MAX_ENTRIES {
            if let Some(oldest) = self.table.iter().min_by_key(|(_, b)| b.last_seen).map(|(k, _)| k.clone()) {
                self.table.remove(&oldest);
            }
        }
        let buf = self.table.entry(key.clone()).or_insert_with(FragBuf::new);
        buf.last_seen = Instant::now();
        buf.parts.insert(offset, data.to_vec());
        if !more_fragments {
            buf.total_len = Some(offset + data.len());
        }
        let complete = buf.reassembled();
        if complete.is_some() {
            self.table.remove(&key);
        }
        complete
    }

    /// Drop in-progress reassemblies idle past `timeout` - same reasoning as
    /// `engine.rs`'s `prune_idle_flows`, a partial fragment set whose
    /// remaining fragments never arrived shouldn't sit in memory forever.
    pub fn prune(&mut self, timeout: Duration) {
        let now = Instant::now();
        self.table.retain(|_, b| now.duration_since(b.last_seen) < timeout);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reassembles_two_in_order_fragments() {
        let mut t: FragmentTable<u32> = FragmentTable::new();
        assert_eq!(t.insert(1, 0, true, b"hello "), None); // more_fragments=true, not last
        assert_eq!(t.insert(1, 6, false, b"world"), Some(b"hello world".to_vec()));
    }

    #[test]
    fn reassembles_out_of_order_fragments() {
        let mut t: FragmentTable<u32> = FragmentTable::new();
        assert_eq!(t.insert(1, 6, false, b"world"), None); // last fragment arrives first
        assert_eq!(t.insert(1, 0, true, b"hello "), Some(b"hello world".to_vec()));
    }

    #[test]
    fn gap_blocks_reassembly() {
        let mut t: FragmentTable<u32> = FragmentTable::new();
        assert_eq!(t.insert(1, 0, true, b"hello "), None);
        assert_eq!(t.insert(1, 20, false, b"world"), None); // gap between offset 6 and 20
    }

    #[test]
    fn different_keys_dont_cross_contaminate() {
        let mut t: FragmentTable<u32> = FragmentTable::new();
        assert_eq!(t.insert(1, 0, true, b"aaa"), None);
        assert_eq!(t.insert(2, 0, true, b"bbb"), None);
        assert_eq!(t.insert(2, 3, false, b"BBB"), Some(b"bbbBBB".to_vec()));
        // key 1's partial state is untouched by key 2 completing.
        assert_eq!(t.insert(1, 3, false, b"AAA"), Some(b"aaaAAA".to_vec()));
    }

    #[test]
    fn completed_entry_is_removed_not_reusable_stale() {
        let mut t: FragmentTable<u32> = FragmentTable::new();
        t.insert(1, 0, true, b"aaa");
        assert_eq!(t.insert(1, 3, false, b"AAA"), Some(b"aaaAAA".to_vec()));
        assert_eq!(t.table.len(), 0); // entry consumed, not left around
    }

    #[test]
    fn prune_drops_only_idle_entries() {
        let mut t: FragmentTable<u32> = FragmentTable::new();
        t.insert(1, 0, true, b"stale");
        t.table.get_mut(&1).unwrap().last_seen = Instant::now() - Duration::from_secs(600);
        t.insert(2, 0, true, b"fresh");
        t.prune(Duration::from_secs(300));
        assert!(!t.table.contains_key(&1));
        assert!(t.table.contains_key(&2));
    }
}
