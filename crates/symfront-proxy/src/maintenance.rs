//! Background maintenance: size-budget eviction and the patrol scrub.
//!
//! Both run as jobs (scheduled or manually triggered by the binary) and
//! report what they did. All SQLite writes go through the writer thread;
//! file removal happens off the async threads.

use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;

use serde::Serialize;

use crate::engine::ProxyEngine;
use crate::key::hex;

/// Shared progress counters, streamed to the UI by the binary's job system.
#[derive(Default)]
pub struct MaintProgress {
    pub scanned: AtomicU64,
    pub removed: AtomicU64,
    pub bytes_freed: AtomicU64,
}

#[derive(Debug, Serialize)]
pub struct EvictionReport {
    pub enabled: bool,
    pub before_bytes: u64,
    pub after_bytes: u64,
    pub evicted_entries: u64,
    pub evicted_bytes: u64,
}

impl ProxyEngine {
    /// Evict positive entries, soonest expiry first, until below the low
    /// watermark. With sliding positive TTLs this approximates LRU while
    /// staying trivially explainable.
    pub async fn evict_pass(&self, progress: &MaintProgress) -> EvictionReport {
        let Some(size) = self.config.cache_size else {
            return EvictionReport {
                enabled: false,
                before_bytes: 0,
                after_bytes: 0,
                evicted_entries: 0,
                evicted_bytes: 0,
            };
        };
        let high = (size as f64 * self.config.high_watermark) as u64;
        let low = (size as f64 * self.config.low_watermark) as u64;
        let before = self.cache.db.positive_bytes().unwrap_or(0);
        let mut total = before;
        let mut evicted_entries = 0u64;
        let mut evicted_bytes = 0u64;
        if total > high {
            tracing::info!("cache at {total} bytes (> high watermark {high}); evicting to {low}");
            while total > low {
                let batch = match self.cache.db.eviction_candidates(512) {
                    Ok(b) if !b.is_empty() => b,
                    _ => break,
                };
                // Take only enough of the batch to reach the low watermark.
                let mut keys: Vec<[u8; 32]> = Vec::new();
                let mut sizes: Vec<u64> = Vec::new();
                let mut projected = total;
                for e in &batch {
                    if projected <= low {
                        break;
                    }
                    keys.push(e.key);
                    sizes.push(e.size);
                    projected = projected.saturating_sub(e.size);
                }
                if keys.is_empty() {
                    break;
                }
                match self.cache.evict_keys(&keys, &sizes).await {
                    Ok(freed) => {
                        total = total.saturating_sub(freed);
                        evicted_entries += keys.len() as u64;
                        evicted_bytes += freed;
                        progress
                            .removed
                            .fetch_add(keys.len() as u64, Ordering::Relaxed);
                        progress.bytes_freed.fetch_add(freed, Ordering::Relaxed);
                    }
                    Err(e) => {
                        tracing::error!("eviction batch failed: {e}");
                        break;
                    }
                }
            }
        }
        EvictionReport {
            enabled: true,
            before_bytes: before,
            after_bytes: total,
            evicted_entries,
            evicted_bytes,
        }
    }
}

#[derive(Debug, Default, Serialize)]
pub struct ScrubReport {
    pub data_files: u64,
    pub db_rows: u64,
    /// Files with no metadata row (or unparseable names) — removed.
    pub orphan_files: u64,
    pub orphan_bytes: u64,
    /// Positive rows whose payload file is missing — rows removed.
    pub rows_missing_data: u64,
    /// Rows whose file size doesn't match content_length — both removed.
    pub size_mismatches: u64,
    pub repaired: bool,
}

impl ProxyEngine {
    /// Patrol scrub: cross-check the metadata db against the data tree in
    /// both directions. With `repair`, orphans are deleted; otherwise the
    /// report only counts them.
    pub async fn scrub(
        self: &Arc<Self>,
        repair: bool,
        progress: &MaintProgress,
    ) -> Result<ScrubReport, crate::db::DbError> {
        let mut report = ScrubReport {
            repaired: repair,
            ..Default::default()
        };

        // Snapshot the rows (32-byte keys; even a million rows is ~50 MB).
        let mut rows: HashMap<[u8; 32], (u16, u64)> = HashMap::new();
        self.cache.db.for_each_entry(|key, status, size| {
            rows.insert(*key, (status, size));
        })?;
        report.db_rows = rows.len() as u64;

        // Pass 1: walk the data tree; flag files without rows and size
        // mismatches. The walk is blocking fs work.
        let engine = Arc::clone(self);
        let rows_arc = Arc::new(rows);
        let rows_walk = Arc::clone(&rows_arc);
        let (orphans, mismatches, seen, files, orphan_bytes) =
            tokio::task::spawn_blocking(move || {
                let mut orphans: Vec<std::path::PathBuf> = Vec::new();
                let mut mismatch_keys: Vec<[u8; 32]> = Vec::new();
                let mut seen: std::collections::HashSet<[u8; 32]> =
                    std::collections::HashSet::new();
                let mut files = 0u64;
                let mut orphan_bytes = 0u64;
                let _ = engine.cache.walk_data(|key, path, size| {
                    files += 1;
                    match key {
                        Some(k) => match rows_walk.get(&k) {
                            Some((status, expect)) => {
                                seen.insert(k);
                                if *status == 200 && *expect != size {
                                    mismatch_keys.push(k);
                                }
                            }
                            None => {
                                if !engine.fills.in_flight(&k) {
                                    orphans.push(path.to_path_buf());
                                    orphan_bytes += size;
                                }
                            }
                        },
                        None => {
                            orphans.push(path.to_path_buf());
                            orphan_bytes += size;
                        }
                    }
                });
                (orphans, mismatch_keys, seen, files, orphan_bytes)
            })
            .await
            .map_err(|e| crate::db::DbError::Other(e.to_string()))?;

        report.data_files = files;
        report.orphan_files = orphans.len() as u64;
        report.orphan_bytes = orphan_bytes;
        report.size_mismatches = mismatches.len() as u64;
        progress.scanned.store(files, Ordering::Relaxed);

        // Pass 2: positive rows whose file vanished.
        let missing: Vec<[u8; 32]> = rows_arc
            .iter()
            .filter(|(k, (status, _))| *status == 200 && !seen.contains(*k))
            .map(|(k, _)| *k)
            .collect();
        report.rows_missing_data = missing.len() as u64;

        if repair {
            for path in &orphans {
                match std::fs::remove_file(path) {
                    Ok(()) => {
                        progress.removed.fetch_add(1, Ordering::Relaxed);
                    }
                    Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
                    Err(e) => tracing::warn!("scrub: removing {}: {e}", path.display()),
                }
            }
            // Size mismatches: drop both sides; a refill restores coherence.
            for key in &mismatches {
                let path = self.cache.data_path(key);
                let _ = std::fs::remove_file(&path);
                tracing::debug!("scrub: size mismatch for {}", hex(key));
            }
            let mut dead_rows = missing.clone();
            dead_rows.extend(mismatches.iter().copied());
            self.cache.db.delete_wait(dead_rows).await?;
        }
        Ok(report)
    }

    /// One pass of the suspended-upstream prober. Any complete HTTP
    /// response (any status) restores an upstream.
    pub async fn probe_suspended_once(&self) {
        for name in self.health.suspended_names() {
            let Some(upstream) = self.upstreams.iter().find(|u| u.name == name) else {
                continue;
            };
            if !upstream.enabled {
                continue;
            }
            let ok = self.probe_base(&upstream.base_url).await;
            if ok {
                self.health.restore(&name);
            }
        }
    }

    async fn probe_base(&self, base_url: &str) -> bool {
        match self
            .probe_client()
            .head(base_url)
            .timeout(self.health.probe_timeout)
            .send()
            .await
        {
            Ok(_) => true,
            Err(e) => {
                tracing::debug!("probe of {base_url} failed: {e}");
                false
            }
        }
    }
}
