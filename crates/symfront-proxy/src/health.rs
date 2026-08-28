//! Upstream health: a simple circuit breaker.
//!
//! An upstream trips ONLY on transport-level failure (connection refused,
//! connect/read timeout, reset — anything where no complete HTTP response
//! arrived). A complete response of any status, 5xx included, never trips
//! it. Suspended upstreams still serve cache hits but are dropped from the
//! live fan-out; a background task HEAD-probes them and any complete
//! response restores them. State is in-process (single process now — the
//! Python version's cross-worker mmap file is gone).

use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Mutex;
use std::time::{Duration, SystemTime};

#[derive(Clone, Debug, serde::Serialize)]
pub struct TripInfo {
    /// Unix seconds of the most recent trip.
    pub tripped_at: u64,
    pub cause: String,
    pub trip_count: u64,
    /// Unix seconds of the most recent restore, if any.
    pub restored_at: Option<u64>,
}

struct Slot {
    suspended: AtomicBool,
}

pub struct Health {
    slots: HashMap<String, Slot>,
    info: Mutex<HashMap<String, TripInfo>>,
    pub probe_interval: Duration,
    pub probe_timeout: Duration,
}

fn now_unix() -> u64 {
    SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

impl Health {
    pub fn new(
        upstream_names: impl IntoIterator<Item = String>,
        probe_interval: Duration,
        probe_timeout: Duration,
    ) -> Health {
        Health {
            slots: upstream_names
                .into_iter()
                .map(|n| {
                    (
                        n,
                        Slot {
                            suspended: AtomicBool::new(false),
                        },
                    )
                })
                .collect(),
            info: Mutex::new(HashMap::new()),
            probe_interval,
            probe_timeout,
        }
    }

    /// Hot-path availability check (one atomic load).
    pub fn is_available(&self, name: &str) -> bool {
        self.slots
            .get(name)
            .map(|s| !s.suspended.load(Ordering::Relaxed))
            .unwrap_or(true)
    }

    pub fn trip(&self, name: &str, cause: &str) {
        let Some(slot) = self.slots.get(name) else {
            return;
        };
        if !slot.suspended.swap(true, Ordering::Relaxed) {
            tracing::warn!(
                "upstream {name:?} suspended after a transport failure ({cause}); \
                 a background probe will restore it once it responds again"
            );
        }
        let mut info = self.info.lock().unwrap();
        let entry = info.entry(name.to_string()).or_insert(TripInfo {
            tripped_at: 0,
            cause: String::new(),
            trip_count: 0,
            restored_at: None,
        });
        entry.tripped_at = now_unix();
        entry.cause = cause.to_string();
        entry.trip_count += 1;
        entry.restored_at = None;
    }

    pub fn restore(&self, name: &str) {
        let Some(slot) = self.slots.get(name) else {
            return;
        };
        if slot.suspended.swap(false, Ordering::Relaxed) {
            tracing::info!("upstream {name:?} restored (liveness probe succeeded)");
            if let Some(entry) = self.info.lock().unwrap().get_mut(name) {
                entry.restored_at = Some(now_unix());
            }
        }
    }

    /// Manual suspend/resume from the admin surface.
    pub fn set_suspended(&self, name: &str, suspended: bool) -> bool {
        let Some(slot) = self.slots.get(name) else {
            return false;
        };
        slot.suspended.store(suspended, Ordering::Relaxed);
        if suspended {
            let mut info = self.info.lock().unwrap();
            let entry = info.entry(name.to_string()).or_insert(TripInfo {
                tripped_at: 0,
                cause: String::new(),
                trip_count: 0,
                restored_at: None,
            });
            entry.tripped_at = now_unix();
            entry.cause = "manually suspended".into();
        }
        true
    }

    pub fn suspended_names(&self) -> Vec<String> {
        self.slots
            .iter()
            .filter(|(_, s)| s.suspended.load(Ordering::Relaxed))
            .map(|(n, _)| n.clone())
            .collect()
    }

    pub fn snapshot(&self) -> HashMap<String, (bool, Option<TripInfo>)> {
        let info = self.info.lock().unwrap();
        self.slots
            .iter()
            .map(|(n, s)| {
                (
                    n.clone(),
                    (s.suspended.load(Ordering::Relaxed), info.get(n).cloned()),
                )
            })
            .collect()
    }
}
