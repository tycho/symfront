//! Proxy statistics — client-truth, not upstream-truth.
//!
//! Everything here is counted per *incoming client request*; upstream probe
//! traffic and health checks never show up as misses. Derived metrics
//! (bandwidth saved, estimated time saved) come from bytes served from
//! cache vs. fetched, and a per-upstream throughput EMA observed during
//! fills.

use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Mutex;

/// How a client request was ultimately answered.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum RequestOutcome {
    /// Served from the managed store (tier 0).
    Tier0Hit,
    /// Served from the proxy cache.
    CacheHit,
    /// Filled live from an upstream (and cached).
    Fill,
    /// 404 answered from the negative cache.
    NegativeHit,
    /// Streamed through from a nocache upstream.
    Passthrough,
    /// Nothing had it: 404 after exhausting upstreams.
    Miss,
    /// Blacklisted or unclassifiable: 404 without upstream traffic.
    Rejected,
    /// Upstream error surfaced to the client (5xx).
    Error,
}

#[derive(Default)]
pub struct UpstreamStats {
    pub fills: AtomicU64,
    pub fill_bytes: AtomicU64,
    pub negatives: AtomicU64,
    pub errors: AtomicU64,
    /// Transport failures (breaker trips are a subset).
    pub transport_failures: AtomicU64,
    /// Bytes/sec EMA over observed fills, stored as bits of an f64.
    throughput_ema: AtomicU64,
}

impl UpstreamStats {
    pub fn throughput(&self) -> f64 {
        f64::from_bits(self.throughput_ema.load(Ordering::Relaxed))
    }

    pub fn observe_fill(&self, bytes: u64, seconds: f64) {
        self.fills.fetch_add(1, Ordering::Relaxed);
        self.fill_bytes.fetch_add(bytes, Ordering::Relaxed);
        if seconds <= 0.0 || bytes == 0 {
            return;
        }
        let rate = bytes as f64 / seconds;
        // EMA with alpha 0.2; racy read-modify-write is fine for a metric.
        let old = self.throughput();
        let new = if old == 0.0 {
            rate
        } else {
            old * 0.8 + rate * 0.2
        };
        self.throughput_ema.store(new.to_bits(), Ordering::Relaxed);
    }
}

#[derive(Default)]
pub struct Stats {
    pub tier0_hits: AtomicU64,
    pub cache_hits: AtomicU64,
    pub fills: AtomicU64,
    pub negative_hits: AtomicU64,
    pub passthroughs: AtomicU64,
    pub misses: AtomicU64,
    pub rejected: AtomicU64,
    pub errors: AtomicU64,
    /// Body bytes served from the local cache (standalone mode; in X-Accel
    /// mode nginx serves them and we count the entry's size instead).
    pub bytes_from_cache: AtomicU64,
    /// Body bytes served from tier 0.
    pub bytes_from_store: AtomicU64,
    /// Body bytes fetched from upstreams (fills + passthrough).
    pub bytes_fetched: AtomicU64,
    pub upstreams: Mutex<HashMap<String, std::sync::Arc<UpstreamStats>>>,
}

impl Stats {
    pub fn count(&self, outcome: RequestOutcome) {
        let counter = match outcome {
            RequestOutcome::Tier0Hit => &self.tier0_hits,
            RequestOutcome::CacheHit => &self.cache_hits,
            RequestOutcome::Fill => &self.fills,
            RequestOutcome::NegativeHit => &self.negative_hits,
            RequestOutcome::Passthrough => &self.passthroughs,
            RequestOutcome::Miss => &self.misses,
            RequestOutcome::Rejected => &self.rejected,
            RequestOutcome::Error => &self.errors,
        };
        counter.fetch_add(1, Ordering::Relaxed);
    }

    pub fn upstream(&self, name: &str) -> std::sync::Arc<UpstreamStats> {
        let mut map = self.upstreams.lock().unwrap();
        std::sync::Arc::clone(map.entry(name.to_string()).or_default())
    }

    /// Estimated seconds saved by cache hits: cached bytes replayed at each
    /// upstream's observed fill throughput.
    pub fn estimated_seconds_saved(&self) -> f64 {
        // A global approximation: bytes_from_cache over the mean observed
        // throughput (per-upstream attribution of a *hit* is in the entry's
        // upstream_name, but the running totals here are global).
        let map = self.upstreams.lock().unwrap();
        let rates: Vec<f64> = map
            .values()
            .map(|u| u.throughput())
            .filter(|r| *r > 0.0)
            .collect();
        if rates.is_empty() {
            return 0.0;
        }
        let mean = rates.iter().sum::<f64>() / rates.len() as f64;
        self.bytes_from_cache.load(Ordering::Relaxed) as f64 / mean
    }
}
