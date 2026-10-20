//! Upstream health: a simple circuit breaker.
//!
//! An upstream trips ONLY on transport-level failure (connection refused,
//! connect/read timeout, reset — anything where no complete HTTP response
//! arrived). A complete response of any status, 5xx included, never trips
//! it. Suspended upstreams still serve cache hits but are dropped from the
//! live fan-out; a background task HEAD-probes them and any complete
//! response restores them. State is in-process (single process now — the
//! Python version's cross-worker mmap file is gone).
//!
//! Failures that can't reach the host at all (refused, connect timeout,
//! DNS) trip immediately. Failures on an established connection (read
//! timeout, reset mid-request) usually mean one slow or unlucky object, so
//! they only trip after `failure_threshold` in a row; any complete response
//! resets the run. An upstream that re-trips shortly after being restored
//! is held out of probing for an exponentially growing interval, so a
//! marginal upstream settles instead of flapping every probe tick.

use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, AtomicU32, Ordering};
use std::sync::Mutex;
use std::time::{Duration, Instant, SystemTime};

/// A re-trip within this long of a restore counts as flapping.
const FLAP_WINDOW: Duration = Duration::from_secs(10 * 60);
/// First flap holds the upstream out of probing this long; doubles per
/// further flap.
const FLAP_HOLD_BASE: Duration = Duration::from_secs(60);
const FLAP_HOLD_MAX: Duration = Duration::from_secs(15 * 60);

/// How a request failed before a complete response arrived.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FailureKind {
    /// Never got a connection: refused, unreachable, DNS, connect timeout.
    Connect,
    /// Connected, but the response didn't arrive within `read_timeout`.
    Timeout,
    /// Connected, then the connection broke (reset, closed early, ...).
    Broken,
}

impl FailureKind {
    fn label(self) -> &'static str {
        match self {
            FailureKind::Connect => "connect failed",
            FailureKind::Timeout => "timed out",
            FailureKind::Broken => "connection broke",
        }
    }
}

/// A classified transport failure with a log-ready description.
#[derive(Clone, Debug)]
pub struct TransportFailure {
    pub kind: FailureKind,
    /// e.g. `timed out after 20.0s: operation timed out` — the whole
    /// `source()` chain, which reqwest's own `Display` omits.
    pub detail: String,
}

impl TransportFailure {
    pub fn from_reqwest(e: &reqwest::Error, elapsed: Duration) -> TransportFailure {
        let kind = if e.is_connect() {
            FailureKind::Connect
        } else if e.is_timeout() {
            FailureKind::Timeout
        } else {
            FailureKind::Broken
        };
        TransportFailure {
            kind,
            detail: format!(
                "{} after {:.1}s: {}",
                kind.label(),
                elapsed.as_secs_f64(),
                error_chain(e)
            ),
        }
    }
}

/// The error's `source()` chain joined with ": ", skipping the top-level
/// reqwest message (it only says "error sending request for url (...)")
/// and consecutive duplicates (hyper often wraps an io error verbatim).
pub fn error_chain(e: &reqwest::Error) -> String {
    let mut parts: Vec<String> = Vec::new();
    let mut src = std::error::Error::source(e);
    while let Some(s) = src {
        let msg = s.to_string();
        if parts.last() != Some(&msg) {
            parts.push(msg);
        }
        src = s.source();
    }
    if parts.is_empty() {
        return "no further detail".into();
    }
    parts.join(": ")
}

/// What a recorded failure did to the breaker.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FailureVerdict {
    /// Counted; `n` of `threshold` consecutive failures so far.
    Counted { n: u32, threshold: u32 },
    /// This failure suspended the upstream.
    Tripped,
    /// The upstream was already suspended.
    AlreadySuspended,
}

#[derive(Clone, Debug, serde::Serialize)]
pub struct TripInfo {
    /// Unix seconds of the most recent trip.
    pub tripped_at: u64,
    pub cause: String,
    pub trip_count: u64,
    /// Unix seconds of the most recent restore, if any.
    pub restored_at: Option<u64>,
    /// Unix seconds before which probes won't restore it (flap backoff).
    pub hold_until: Option<u64>,
}

struct Slot {
    suspended: AtomicBool,
    /// Consecutive non-connect transport failures since the last complete
    /// response.
    consecutive: AtomicU32,
}

#[derive(Default)]
struct Flap {
    restored: Option<Instant>,
    /// Re-trips in a row that each landed within FLAP_WINDOW of a restore.
    streak: u32,
    hold_until: Option<Instant>,
}

pub struct Health {
    slots: HashMap<String, Slot>,
    info: Mutex<HashMap<String, TripInfo>>,
    flaps: Mutex<HashMap<String, Flap>>,
    pub probe_interval: Duration,
    pub probe_timeout: Duration,
    pub failure_threshold: u32,
}

fn now_unix() -> u64 {
    SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

fn flap_hold(streak: u32) -> Duration {
    if streak == 0 {
        return Duration::ZERO;
    }
    FLAP_HOLD_BASE
        .saturating_mul(1u32 << (streak - 1).min(16))
        .min(FLAP_HOLD_MAX)
}

impl Health {
    pub fn new(
        upstream_names: impl IntoIterator<Item = String>,
        probe_interval: Duration,
        probe_timeout: Duration,
        failure_threshold: u32,
    ) -> Health {
        Health {
            slots: upstream_names
                .into_iter()
                .map(|n| {
                    (
                        n,
                        Slot {
                            suspended: AtomicBool::new(false),
                            consecutive: AtomicU32::new(0),
                        },
                    )
                })
                .collect(),
            info: Mutex::new(HashMap::new()),
            flaps: Mutex::new(HashMap::new()),
            probe_interval,
            probe_timeout,
            failure_threshold: failure_threshold.max(1),
        }
    }

    /// Hot-path availability check (one atomic load).
    pub fn is_available(&self, name: &str) -> bool {
        self.slots
            .get(name)
            .map(|s| !s.suspended.load(Ordering::Relaxed))
            .unwrap_or(true)
    }

    /// A complete HTTP response (any status) arrived: the failure run ends.
    pub fn record_success(&self, name: &str) {
        if let Some(slot) = self.slots.get(name) {
            if slot.consecutive.load(Ordering::Relaxed) != 0 {
                slot.consecutive.store(0, Ordering::Relaxed);
            }
        }
    }

    /// A request failed at the transport level. Connect failures trip at
    /// once; others trip after `failure_threshold` in a row.
    pub fn record_failure(&self, name: &str, failure: &TransportFailure) -> FailureVerdict {
        let Some(slot) = self.slots.get(name) else {
            return FailureVerdict::AlreadySuspended;
        };
        if slot.suspended.load(Ordering::Relaxed) {
            return FailureVerdict::AlreadySuspended;
        }
        let threshold = self.failure_threshold;
        let n = slot.consecutive.fetch_add(1, Ordering::Relaxed) + 1;
        if failure.kind != FailureKind::Connect && n < threshold {
            return FailureVerdict::Counted { n, threshold };
        }
        let cause = if failure.kind == FailureKind::Connect || threshold == 1 {
            failure.detail.clone()
        } else {
            format!(
                "{n} consecutive transport failures, last: {}",
                failure.detail
            )
        };
        if self.trip(name, &cause) {
            FailureVerdict::Tripped
        } else {
            FailureVerdict::AlreadySuspended
        }
    }

    /// Suspend unconditionally. Returns whether this call did the suspending.
    pub fn trip(&self, name: &str, cause: &str) -> bool {
        let Some(slot) = self.slots.get(name) else {
            return false;
        };
        if slot.suspended.swap(true, Ordering::Relaxed) {
            return false;
        }
        slot.consecutive.store(0, Ordering::Relaxed);
        let hold = {
            let mut flaps = self.flaps.lock().unwrap();
            let flap = flaps.entry(name.to_string()).or_default();
            let flapping = flap.restored.is_some_and(|r| r.elapsed() < FLAP_WINDOW);
            flap.streak = if flapping { flap.streak + 1 } else { 0 };
            let hold = flap_hold(flap.streak);
            flap.hold_until = (!hold.is_zero()).then(|| Instant::now() + hold);
            hold
        };
        if hold.is_zero() {
            tracing::warn!(
                "upstream {name:?} suspended ({cause}); a background probe will \
                 restore it once it responds again"
            );
        } else {
            tracing::warn!(
                "upstream {name:?} suspended ({cause}); it was restored less than \
                 {}m ago, so probing is held off for {}s",
                FLAP_WINDOW.as_secs() / 60,
                hold.as_secs()
            );
        }
        let mut info = self.info.lock().unwrap();
        let entry = info.entry(name.to_string()).or_insert(TripInfo {
            tripped_at: 0,
            cause: String::new(),
            trip_count: 0,
            restored_at: None,
            hold_until: None,
        });
        entry.tripped_at = now_unix();
        entry.cause = cause.to_string();
        entry.trip_count += 1;
        entry.restored_at = None;
        entry.hold_until = (!hold.is_zero()).then(|| now_unix() + hold.as_secs());
        true
    }

    /// Whether a suspended upstream's flap hold has expired, i.e. a probe
    /// may restore it.
    pub fn probe_due(&self, name: &str) -> bool {
        self.flaps
            .lock()
            .unwrap()
            .get(name)
            .and_then(|f| f.hold_until)
            .is_none_or(|t| Instant::now() >= t)
    }

    pub fn restore(&self, name: &str) {
        let Some(slot) = self.slots.get(name) else {
            return;
        };
        slot.consecutive.store(0, Ordering::Relaxed);
        if slot.suspended.swap(false, Ordering::Relaxed) {
            tracing::info!("upstream {name:?} restored (liveness probe succeeded)");
            let mut flaps = self.flaps.lock().unwrap();
            let flap = flaps.entry(name.to_string()).or_default();
            flap.restored = Some(Instant::now());
            flap.hold_until = None;
            if let Some(entry) = self.info.lock().unwrap().get_mut(name) {
                entry.restored_at = Some(now_unix());
                entry.hold_until = None;
            }
        }
    }

    /// Manual suspend/resume from the admin surface. Either way the flap
    /// history is forgotten: the operator has taken over.
    pub fn set_suspended(&self, name: &str, suspended: bool) -> bool {
        let Some(slot) = self.slots.get(name) else {
            return false;
        };
        slot.suspended.store(suspended, Ordering::Relaxed);
        slot.consecutive.store(0, Ordering::Relaxed);
        self.flaps.lock().unwrap().remove(name);
        let mut info = self.info.lock().unwrap();
        if suspended {
            let entry = info.entry(name.to_string()).or_insert(TripInfo {
                tripped_at: 0,
                cause: String::new(),
                trip_count: 0,
                restored_at: None,
                hold_until: None,
            });
            entry.tripped_at = now_unix();
            entry.cause = "manually suspended".into();
            entry.hold_until = None;
        } else if let Some(entry) = info.get_mut(name) {
            entry.hold_until = None;
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

#[cfg(test)]
mod tests {
    use super::*;

    fn health(threshold: u32) -> Health {
        Health::new(
            ["u".to_string()],
            Duration::from_secs(30),
            Duration::from_secs(15),
            threshold,
        )
    }

    fn failure(kind: FailureKind) -> TransportFailure {
        TransportFailure {
            kind,
            detail: "test".into(),
        }
    }

    #[test]
    fn connect_failure_trips_at_once() {
        let h = health(3);
        assert_eq!(
            h.record_failure("u", &failure(FailureKind::Connect)),
            FailureVerdict::Tripped
        );
        assert!(!h.is_available("u"));
    }

    #[test]
    fn timeouts_trip_only_after_a_run() {
        let h = health(3);
        let t = failure(FailureKind::Timeout);
        assert_eq!(
            h.record_failure("u", &t),
            FailureVerdict::Counted { n: 1, threshold: 3 }
        );
        assert_eq!(
            h.record_failure("u", &t),
            FailureVerdict::Counted { n: 2, threshold: 3 }
        );
        // A complete response in between ends the run.
        h.record_success("u");
        assert_eq!(
            h.record_failure("u", &failure(FailureKind::Broken)),
            FailureVerdict::Counted { n: 1, threshold: 3 }
        );
        h.record_failure("u", &t);
        assert_eq!(h.record_failure("u", &t), FailureVerdict::Tripped);
        assert!(!h.is_available("u"));
        assert_eq!(h.record_failure("u", &t), FailureVerdict::AlreadySuspended);
    }

    #[test]
    fn retrip_after_restore_holds_probing_off() {
        let h = health(1);
        let t = failure(FailureKind::Timeout);
        h.record_failure("u", &t);
        assert!(h.probe_due("u"), "first trip probes normally");
        h.restore("u");
        h.record_failure("u", &t);
        assert!(!h.probe_due("u"), "quick re-trip is held off");
        let info = h.snapshot()["u"].1.clone().unwrap();
        assert!(info.hold_until.is_some());
        // Manual resume clears the history.
        h.set_suspended("u", false);
        h.record_failure("u", &t);
        assert!(h.probe_due("u"));
    }

    #[test]
    fn flap_hold_doubles_and_caps() {
        assert_eq!(flap_hold(0), Duration::ZERO);
        assert_eq!(flap_hold(1), Duration::from_secs(60));
        assert_eq!(flap_hold(2), Duration::from_secs(120));
        assert_eq!(flap_hold(20), FLAP_HOLD_MAX);
    }
}
