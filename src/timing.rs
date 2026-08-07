// Packet-timing/size statistics: VPN tunnels (especially WireGuard) produce
// far more regular packet sizes and inter-arrival timing than ordinary
// browsing traffic - a fingerprint visible even when the payload is fully
// opaque. Coarse heuristic, thresholds are a first guess, not measured
// against a real traffic corpus (see writeup.md's limitations).
use std::time::Instant;

const SAMPLE_CAP: usize = 30; // enough for a stable variance estimate, bounds memory per flow
const MIN_SAMPLES: usize = 12; // don't judge regularity from a handful of packets

const SIZE_CV_THRESHOLD: f64 = 0.15;
const TIMING_CV_THRESHOLD: f64 = 0.6;

pub struct TimingStats {
    sizes: Vec<usize>,
    timestamps: Vec<Instant>,
    flagged: bool, // single-shot, like the entropy check - don't spam the log every packet
}

impl TimingStats {
    pub fn new() -> Self {
        Self { sizes: Vec::new(), timestamps: Vec::new(), flagged: false }
    }

    /// Record one packet's size and arrival time. Caps memory by dropping the
    /// oldest sample once full - only the most recent window matters for judging
    /// "is this flow's traffic shape regular right now."
    pub fn record(&mut self, size: usize) {
        if self.sizes.len() >= SAMPLE_CAP {
            self.sizes.remove(0);
            self.timestamps.remove(0);
        }
        self.sizes.push(size);
        self.timestamps.push(Instant::now());
    }

    /// Once enough samples are in, judge whether packet sizes and inter-arrival
    /// gaps are both suspiciously uniform. Fires at most once per flow.
    pub fn check(&mut self) -> Option<&'static str> {
        if self.flagged || self.sizes.len() < MIN_SAMPLES {
            return None;
        }
        self.flagged = true;

        let size_cv = coefficient_of_variation(&self.sizes.iter().map(|&s| s as f64).collect::<Vec<_>>());
        let gaps: Vec<f64> = self.timestamps.windows(2).map(|w| w[1].duration_since(w[0]).as_secs_f64()).collect();
        let timing_cv = coefficient_of_variation(&gaps);

        if size_cv < SIZE_CV_THRESHOLD && timing_cv < TIMING_CV_THRESHOLD {
            Some("regular-packet-shape (possible-vpn-tunnel)")
        } else {
            None
        }
    }
}

/// Coefficient of variation: stdev/mean. Scale-independent, so it works the same
/// whether comparing packet sizes (bytes) or inter-arrival gaps (seconds).
fn coefficient_of_variation(values: &[f64]) -> f64 {
    if values.is_empty() {
        return f64::INFINITY;
    }
    let mean = values.iter().sum::<f64>() / values.len() as f64;
    if mean == 0.0 {
        return f64::INFINITY;
    }
    let variance = values.iter().map(|v| (v - mean).powi(2)).sum::<f64>() / values.len() as f64;
    variance.sqrt() / mean
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::thread::sleep;
    use std::time::Duration;

    #[test]
    fn uniform_packets_flagged() {
        let mut t = TimingStats::new();
        for _ in 0..MIN_SAMPLES {
            t.record(1200); // identical size every time
            sleep(Duration::from_millis(2)); // roughly identical gaps
        }
        assert_eq!(t.check(), Some("regular-packet-shape (possible-vpn-tunnel)"));
    }

    #[test]
    fn varied_packets_not_flagged() {
        let mut t = TimingStats::new();
        let sizes = [40, 1400, 60, 800, 1200, 30, 1350, 500, 700, 1440, 90, 600, 1100, 200];
        for &s in &sizes {
            t.record(s);
            sleep(Duration::from_millis(fastrand_ms(s)));
        }
        assert_eq!(t.check(), None);
    }

    #[test]
    fn too_few_samples_not_judged() {
        let mut t = TimingStats::new();
        t.record(1200);
        t.record(1200);
        assert_eq!(t.check(), None);
    }

    #[test]
    fn single_shot_only_fires_once() {
        let mut t = TimingStats::new();
        for _ in 0..MIN_SAMPLES {
            t.record(1200);
            sleep(Duration::from_millis(2)); // real gaps, not all-zero (see mean==0 guard)
        }
        assert!(t.check().is_some());
        t.record(1200); // more of the same
        assert_eq!(t.check(), None); // already flagged, stays quiet
    }

    // cheap deterministic spread, no need for a real RNG dependency here
    fn fastrand_ms(seed: usize) -> u64 {
        ((seed * 37) % 5) as u64
    }
}
