//! The proxy engine: one `handle()` per client request.
//!
//! Pipeline (tier 0, the managed store, runs *before* this in the binary):
//! blacklist → classify → candidates → cache decision → staggered live
//! fan-out → fill/negative-cache/passthrough.
//!
//! Concurrency guardrails (from the integration plan): all decision logic in
//! this module is synchronous; async appears only around the upstream fetch
//! and body streaming. SQLite reads are inline; writes go through the
//! metadata writer thread.

use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Instant;

use futures_util::stream::{FuturesUnordered, StreamExt};

use crate::blacklist::Blacklist;
use crate::cache::{now_unix, parse_http_date, CacheStore};
use crate::config::{CacheMode, ProxyConfig, TtlPolicy};
use crate::db::{Entry, WriteOp};
use crate::fill::{
    await_outcome, start_fill, FillHandle, FillMeta, FillRegistry, FlightEntry, FlightOutcome,
    FlightSlot,
};
use crate::health::Health;
use crate::key::CacheKey;
use crate::query::classify_request;
use crate::stats::{RequestOutcome, Stats};
use crate::upstream::Upstream;

#[derive(Copy, Clone, PartialEq, Eq, Debug)]
pub enum Method {
    Get,
    Head,
}

pub struct ClientRequest<'a> {
    pub method: Method,
    /// Normalized to exactly one leading '/'.
    pub path: &'a str,
    /// Verbatim SymbolChecksum header from the client, if any.
    pub symbol_checksum: Option<String>,
}

/// How the engine answered; the binary turns this into an HTTP response.
pub enum Outcome {
    /// 404 — blacklisted, unclassifiable, negative-cached, or exhausted.
    NotFound,
    /// Status + upstream headers, no local body (5xx passthrough etc).
    HeaderOnly { status: u16, meta: FillMeta },
    /// Positive cache hit: stream `path` (standalone mode).
    CacheHit { entry: Box<Entry>, path: PathBuf },
    /// Positive cache hit, offload mode: `header` (X-Accel-Redirect for
    /// nginx, X-Sendfile for lighttpd) pointing at `redirect`.
    AccelHit {
        entry: Box<Entry>,
        redirect: String,
        header: &'static str,
    },
    /// Live fill in progress: tail-follow it (or, for HEAD, send the
    /// headers and detach — the fill finishes regardless).
    Fill {
        handle: Arc<FillHandle>,
        upstream: String,
    },
    /// nocache upstream: stream the upstream body straight through.
    Passthrough { response: Box<reqwest::Response> },
}

pub struct ProxyEngine {
    pub config: ProxyConfig,
    pub upstreams: Vec<Arc<Upstream>>,
    pub blacklist: Blacklist,
    pub cache: CacheStore,
    pub health: Health,
    pub stats: Stats,
    pub fills: Arc<FillRegistry>,
    http: reqwest::Client,
    probe_http: reqwest::Client,
}

struct Candidate {
    upstream: Arc<Upstream>,
    key: CacheKey,
    /// Pre-existing (possibly expired) entry from the batch lookup.
    prior: Option<Entry>,
}

enum AttemptResult {
    Success(Outcome),
    Negative,
    ServerError(u16, FillMeta),
    Failed,
}

impl ProxyEngine {
    pub fn new(
        config: ProxyConfig,
        upstreams: Vec<Upstream>,
        blacklist: Blacklist,
    ) -> Result<Arc<ProxyEngine>, crate::db::DbError> {
        let cache = CacheStore::open(&config.cache_path)?;
        cache.clean_stale_temps();
        let health = Health::new(
            upstreams.iter().map(|u| u.name.clone()),
            config.health_probe_interval,
            config.health_probe_timeout,
        );
        let mk_client = |redirects: reqwest::redirect::Policy| {
            reqwest::Client::builder()
                .connect_timeout(config.connect_timeout)
                .read_timeout(config.read_timeout)
                .redirect(redirects)
                .build()
                .expect("building http client")
        };
        Ok(Arc::new(ProxyEngine {
            http: mk_client(reqwest::redirect::Policy::limited(10)),
            probe_http: mk_client(reqwest::redirect::Policy::none()),
            upstreams: upstreams.into_iter().map(Arc::new).collect(),
            blacklist,
            cache,
            health,
            stats: Stats::default(),
            fills: Arc::new(FillRegistry::default()),
            config,
        }))
    }

    pub(crate) fn probe_client(&self) -> &reqwest::Client {
        &self.probe_http
    }

    /// The negative-TTL policy for one upstream (global + override).
    fn ttl_for(&self, upstream: &Upstream) -> TtlPolicy {
        match &upstream.negative_ttl {
            Some(ladder) => TtlPolicy {
                positive: self.config.ttl.positive,
                negative: ladder.clone(),
            },
            None => self.config.ttl.clone(),
        }
    }

    fn serve_entry(&self, entry: Entry) -> Option<Outcome> {
        let path = self.cache.data_path(&entry.key);
        // Inline stat, same policy as the store handler: fast-path disk
        // metadata is not worth a spawn_blocking round-trip.
        if !path.is_file() {
            return None;
        }
        self.cache.touch_positive(&entry, &self.config.ttl);
        Some(match self.config.mode {
            CacheMode::Standalone => Outcome::CacheHit {
                entry: Box::new(entry),
                path,
            },
            CacheMode::Nginx | CacheMode::Lighttpd => {
                let redirect = format!(
                    "{}/{}",
                    self.config.accel_prefix.trim_end_matches('/'),
                    self.cache.accel_rel_path(&entry.key)
                );
                Outcome::AccelHit {
                    entry: Box::new(entry),
                    redirect,
                    header: self.config.mode.accel_header(),
                }
            }
        })
    }

    pub async fn handle(self: &Arc<Self>, req: ClientRequest<'_>) -> Outcome {
        let path = req.path;
        if self.blacklist.matches(path) {
            self.stats.count(RequestOutcome::Rejected);
            return Outcome::NotFound;
        }
        let Some(query) = classify_request(path) else {
            tracing::debug!("unrecognized request {path:?}; 404");
            self.stats.count(RequestOutcome::Rejected);
            return Outcome::NotFound;
        };

        // Which upstreams admit this query, and at what URL?
        // Too-short "build-ids" (Sentry probing PE modules through SSQP ELF
        // keys) never render for debuginfod upstreams: every real debuginfod
        // server rejects them with a 503, which we'd re-ask forever since
        // 5xx is never cached.
        let short_buildid = query
            .ident
            .as_deref()
            .map(|i| i.len() < self.config.min_buildid_hex)
            .unwrap_or(false);
        let mut candidates: Vec<Candidate> = Vec::new();
        for upstream in &self.upstreams {
            if short_buildid && upstream.layout == crate::query::LayoutKind::Debuginfod {
                continue;
            }
            if let Some(url) = upstream.candidate_url(&query) {
                candidates.push(Candidate {
                    key: CacheKey::new(&upstream.name, &url),
                    upstream: Arc::clone(upstream),
                    prior: None,
                });
            }
        }
        if candidates.is_empty() {
            tracing::debug!("no upstream can serve {path:?}; 404");
            self.stats.count(RequestOutcome::Rejected);
            return Outcome::NotFound;
        }

        // Frontload one batch metadata lookup for the cachable candidates.
        let cachable_keys: Vec<[u8; 32]> = candidates
            .iter()
            .filter(|c| c.upstream.cachable())
            .map(|c| c.key.hash)
            .collect();
        let metas: HashMap<[u8; 32], Entry> = match self.cache.db.get_many(&cachable_keys) {
            Ok(rows) => rows.into_iter().map(|e| (e.key, e)).collect(),
            Err(e) => {
                tracing::error!("cache metadata lookup failed: {e}");
                HashMap::new()
            }
        };
        for c in &mut candidates {
            c.prior = metas.get(&c.key.hash).cloned();
        }

        // Cache decision, in candidate (= config) order.
        let now = now_unix();
        let mut negative_hit = false;
        let mut reval: Option<usize> = None;
        let mut excluded: Vec<bool> = vec![false; candidates.len()];
        for (i, c) in candidates.iter().enumerate() {
            let Some(entry) = &c.prior else { continue };
            if entry.is_positive() {
                if !entry.is_expired(now) {
                    if let Some(outcome) = self.serve_entry(entry.clone()) {
                        self.stats.count(RequestOutcome::CacheHit);
                        return outcome;
                    }
                    // Fresh row but the payload file is gone: refill below.
                } else if reval.is_none() && self.cache.data_path(&entry.key).is_file() {
                    reval = Some(i);
                }
            } else if !entry.is_expired(now) {
                // Fresh negative: this upstream is excluded from fan-out.
                negative_hit = true;
                excluded[i] = true;
            }
            // Expired negative: stays live; its step feeds the ladder.
        }

        // Expiry triggers revalidation, not discard: conditional GET; 304
        // refreshes, transport failure serves stale (stale-while-error).
        if let Some(i) = reval {
            match self.revalidate(&candidates[i], req.method).await {
                Some(outcome) => return outcome,
                None => {
                    // Revalidation answered 4xx: that upstream is now
                    // negative-cached; drop it from the fan-out.
                    excluded[i] = true;
                }
            }
        }

        // Live fan-out over what's left.
        let live: Vec<&Candidate> = candidates
            .iter()
            .enumerate()
            .filter(|(i, c)| !excluded[*i] && self.health.is_available(&c.upstream.name))
            .map(|(_, c)| c)
            .collect();

        if !live.is_empty() {
            tracing::debug!(
                "querying upstreams {:?} for {path:?}",
                live.iter()
                    .map(|c| c.upstream.name.as_str())
                    .collect::<Vec<_>>()
            );
        }
        let mut server_error: Option<(u16, FillMeta)> = None;
        match self
            .fan_out(&live, req.method, &req.symbol_checksum, &mut server_error)
            .await
        {
            Some(outcome) => {
                let kind = match &outcome {
                    Outcome::Passthrough { .. } => RequestOutcome::Passthrough,
                    Outcome::CacheHit { .. } | Outcome::AccelHit { .. } => RequestOutcome::CacheHit,
                    _ => RequestOutcome::Fill,
                };
                self.stats.count(kind);
                outcome
            }
            None => {
                if let Some((status, meta)) = server_error {
                    // 5xx passed through, never cached.
                    self.stats.count(RequestOutcome::Error);
                    Outcome::HeaderOnly { status, meta }
                } else if negative_hit {
                    self.stats.count(RequestOutcome::NegativeHit);
                    Outcome::NotFound
                } else {
                    tracing::debug!("all upstreams exhausted for {path:?}");
                    self.stats.count(RequestOutcome::Miss);
                    Outcome::NotFound
                }
            }
        }
    }

    /// Conditional GET against the entry's own upstream. `Some(outcome)`
    /// resolves the request; `None` means the artifact is gone upstream
    /// (negative-cached; caller continues the fan-out without it).
    async fn revalidate(self: &Arc<Self>, cand: &Candidate, method: Method) -> Option<Outcome> {
        let entry = cand.prior.as_ref().expect("reval candidate has an entry");
        if !self.health.is_available(&cand.upstream.name) {
            // Can't ask: serve stale rather than stall.
            return self.serve_entry(entry.clone()).inspect(|_| {
                self.stats.count(RequestOutcome::CacheHit);
            });
        }
        // Singleflight: concurrent expiries revalidate once; the rest ride
        // along on the winner's answer.
        let slot = match self.fills.enter(cand.key.hash) {
            FlightEntry::Winner(slot) => slot,
            FlightEntry::Follower(rx) => {
                return match await_outcome(rx).await {
                    FlightOutcome::Positive(handle) => {
                        self.stats.count(RequestOutcome::Fill);
                        Some(Outcome::Fill {
                            handle,
                            upstream: cand.upstream.name.clone(),
                        })
                    }
                    FlightOutcome::Refreshed => self.serve_entry(entry.clone()).inspect(|_| {
                        self.stats.count(RequestOutcome::CacheHit);
                    }),
                    FlightOutcome::Status(s) if (400..500).contains(&s) => None,
                    _ => self.serve_stale(entry),
                };
            }
        };
        let mut request = self.http.get(&cand.key.full_url);
        if let Some(etag) = &entry.etag {
            request = request.header("If-None-Match", etag);
        }
        if let Some(lm) = entry.last_modified {
            request = request.header("If-Modified-Since", crate::cache::format_http_date(lm));
        }
        let sent_at = Instant::now();
        let response = match request.send().await {
            Ok(r) => r,
            Err(e) => {
                self.health.trip(&cand.upstream.name, &e.to_string());
                self.stats
                    .upstream(&cand.upstream.name)
                    .transport_failures
                    .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                // Stale-while-error: serve the stale entry, expiry unchanged.
                tracing::debug!(
                    "revalidation of {} failed ({e}); serving stale",
                    cand.key.full_url
                );
                drop(slot); // publishes Failed; followers serve stale too
                return self.serve_stale(entry);
            }
        };
        let status = response.status().as_u16();
        self.stats
            .upstream(&cand.upstream.name)
            .observe_ttfb(status, sent_at.elapsed());
        if status == 304 {
            // Still good: refresh the TTL (slides like any positive hit) and
            // serve from cache without a re-download.
            self.cache.touch_positive(entry, &self.config.ttl);
            tracing::debug!("revalidated {} via 304", cand.key.full_url);
            slot.publish(FlightOutcome::Refreshed);
            return self.serve_entry(entry.clone()).inspect(|_| {
                self.stats.count(RequestOutcome::CacheHit);
            });
        }
        if status == 200 {
            // Changed upstream: refill.
            match self.begin_fill(cand, response, Some(slot)).await {
                Some(handle) => {
                    self.stats.count(RequestOutcome::Fill);
                    return Some(Outcome::Fill {
                        handle,
                        upstream: cand.upstream.name.clone(),
                    });
                }
                None => return self.serve_stale(entry),
            }
        }
        if (400..500).contains(&status) {
            // Gone upstream: flip to negative and drop the stale payload.
            let neg =
                self.cache
                    .negative_entry(&cand.key, status, None, &self.ttl_for(&cand.upstream));
            self.cache
                .db
                .write_nowait(WriteOp::Upsert(Box::new(neg), None));
            let path = self.cache.data_path(&cand.key.hash);
            slot.publish(FlightOutcome::Status(status));
            let _ = tokio::task::spawn_blocking(move || std::fs::remove_file(path)).await;
            let _ = method;
            return None;
        }
        // 5xx during revalidation: stale-while-error.
        drop(slot);
        self.serve_stale(entry)
    }

    fn serve_stale(&self, entry: &Entry) -> Option<Outcome> {
        // Serve without touching expiry (the entry stays due for
        // revalidation on the next request).
        let path = self.cache.data_path(&entry.key);
        if !path.is_file() {
            return None;
        }
        self.stats.count(RequestOutcome::CacheHit);
        Some(match self.config.mode {
            CacheMode::Standalone => Outcome::CacheHit {
                entry: Box::new(entry.clone()),
                path,
            },
            CacheMode::Nginx | CacheMode::Lighttpd => Outcome::AccelHit {
                entry: Box::new(entry.clone()),
                redirect: format!(
                    "{}/{}",
                    self.config.accel_prefix.trim_end_matches('/'),
                    self.cache.accel_rel_path(&entry.key)
                ),
                header: self.config.mode.accel_header(),
            },
        })
    }

    /// Staggered fan-out: candidates sort into priority tiers; tier N+1
    /// launches `stagger` after tier N *starts* (or immediately once tier N
    /// has fully failed), unless a decisive answer already arrived. First
    /// 200 wins globally; already-launched losers are cancelled by drop.
    async fn fan_out(
        self: &Arc<Self>,
        live: &[&Candidate],
        method: Method,
        checksum: &Option<String>,
        server_error: &mut Option<(u16, FillMeta)>,
    ) -> Option<Outcome> {
        if live.is_empty() {
            return None;
        }
        let mut tiers: std::collections::BTreeMap<i32, Vec<&Candidate>> = Default::default();
        for c in live {
            tiers.entry(c.upstream.priority).or_default().push(c);
        }
        let mut tiers = tiers.into_values();
        let mut next_tier = tiers.next();
        let mut pending = FuturesUnordered::new();
        let mut deadline = Instant::now();

        loop {
            // Launch a due tier — immediately when nothing is in flight
            // (waiting out the stagger with an empty pipeline is pure loss).
            if next_tier.is_some() && (Instant::now() >= deadline || pending.is_empty()) {
                for c in next_tier.take().unwrap() {
                    pending.push(self.attempt(c, method, checksum));
                }
                next_tier = tiers.next();
                deadline = Instant::now() + self.config.stagger;
            }
            if pending.is_empty() && next_tier.is_none() {
                return None;
            }
            let result = if next_tier.is_some() {
                tokio::select! {
                    r = pending.next() => r,
                    _ = tokio::time::sleep_until(deadline.into()) => continue,
                }
            } else {
                pending.next().await
            };
            match result {
                Some(AttemptResult::Success(outcome)) => return Some(outcome),
                Some(AttemptResult::ServerError(status, meta)) => {
                    if server_error.is_none() {
                        *server_error = Some((status, meta));
                    }
                }
                Some(AttemptResult::Negative | AttemptResult::Failed) | None => {}
            }
        }
    }

    async fn attempt(
        self: &Arc<Self>,
        cand: &Candidate,
        method: Method,
        checksum: &Option<String>,
    ) -> AttemptResult {
        if !cand.upstream.cachable() {
            return self.attempt_nocache(cand, method, checksum).await;
        }
        // Singleflight per cache key: one live fetch, everyone else tails.
        match self.fills.enter(cand.key.hash) {
            FlightEntry::Follower(rx) => match await_outcome(rx).await {
                FlightOutcome::Positive(handle) => AttemptResult::Success(Outcome::Fill {
                    handle,
                    upstream: cand.upstream.name.clone(),
                }),
                FlightOutcome::Status(s) if (400..500).contains(&s) => AttemptResult::Negative,
                FlightOutcome::Status(s) => AttemptResult::ServerError(s, FillMeta::default()),
                FlightOutcome::Refreshed => {
                    // The winner served a cache entry that committed after
                    // our batch lookup; take the same path.
                    match self.cache.db.get(&cand.key.hash) {
                        Ok(Some(entry)) if entry.is_positive() && !entry.is_expired(now_unix()) => {
                            match self.serve_entry(entry) {
                                Some(outcome) => AttemptResult::Success(outcome),
                                None => AttemptResult::Failed,
                            }
                        }
                        _ => AttemptResult::Failed,
                    }
                }
                FlightOutcome::Failed => AttemptResult::Failed,
            },
            FlightEntry::Winner(slot) => self.attempt_winner(cand, checksum, slot).await,
        }
    }

    async fn attempt_winner(
        self: &Arc<Self>,
        cand: &Candidate,
        checksum: &Option<String>,
        slot: FlightSlot,
    ) -> AttemptResult {
        // Re-check the cache inside the flight: an earlier fill may have
        // committed between our batch lookup and now.
        if let Ok(Some(entry)) = self.cache.db.get(&cand.key.hash) {
            if entry.is_positive() && !entry.is_expired(now_unix()) {
                if let Some(outcome) = self.serve_entry(entry) {
                    slot.publish(FlightOutcome::Refreshed);
                    return AttemptResult::Success(outcome);
                }
            }
        }
        // The upstream may have been suspended while we raced (a sibling
        // request just tripped it). Cheap flag check, not a probe.
        if !self.health.is_available(&cand.upstream.name) {
            return AttemptResult::Failed; // slot drop publishes Failed
        }

        tracing::debug!("cache miss for {}", cand.key.full_url);
        // HEAD is upgraded to a GET fill for cachable upstreams (§3.4): the
        // client gets headers as soon as they arrive; the body fill finishes
        // in the background with zero tailing clients.
        let request = self
            .http
            .get(&cand.key.full_url)
            .header("Accept-Encoding", "identity");
        let request = apply_checksum(request, &cand.upstream, checksum);
        let sent_at = Instant::now();
        let response = match request.send().await {
            Ok(r) => r,
            Err(e) => {
                // Transport-level failure: no complete request/response
                // cycle. Suspend the upstream; probes restore it.
                self.health.trip(&cand.upstream.name, &e.to_string());
                self.stats
                    .upstream(&cand.upstream.name)
                    .transport_failures
                    .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                tracing::warn!(
                    "upstream request to {} failed at the transport level: {e}",
                    cand.key.full_url
                );
                return AttemptResult::Failed; // slot drop publishes Failed
            }
        };
        let status = response.status().as_u16();
        self.stats
            .upstream(&cand.upstream.name)
            .observe_ttfb(status, sent_at.elapsed());
        if status == 200 {
            match self.begin_fill(cand, response, Some(slot)).await {
                Some(handle) => AttemptResult::Success(Outcome::Fill {
                    handle,
                    upstream: cand.upstream.name.clone(),
                }),
                None => AttemptResult::Failed,
            }
        } else if (400..500).contains(&status) {
            // Negative cache write — never gates the response.
            let neg = self.cache.negative_entry(
                &cand.key,
                status,
                cand.prior.as_ref(),
                &self.ttl_for(&cand.upstream),
            );
            let was_positive = cand
                .prior
                .as_ref()
                .map(|p| p.is_positive())
                .unwrap_or(false);
            self.cache
                .db
                .write_nowait(WriteOp::Upsert(Box::new(neg), None));
            if was_positive {
                // Positive → negative transition: the stale payload file is
                // dead weight now.
                let path = self.cache.data_path(&cand.key.hash);
                tokio::task::spawn_blocking(move || {
                    let _ = std::fs::remove_file(path);
                });
            }
            self.stats
                .upstream(&cand.upstream.name)
                .negatives
                .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            slot.publish(FlightOutcome::Status(status));
            AttemptResult::Negative
        } else {
            // 5xx (or an unexpected 3xx with redirects exhausted): complete
            // response, so no breaker trip; passed through, never cached.
            self.stats
                .upstream(&cand.upstream.name)
                .errors
                .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            let meta = meta_from_response(&response);
            slot.publish(FlightOutcome::Status(status));
            AttemptResult::ServerError(status, meta)
        }
    }

    /// Start a fill from a 200 response: temp file, pump task, metadata
    /// commit on completion. Returns the handle clients tail.
    async fn begin_fill(
        self: &Arc<Self>,
        cand: &Candidate,
        response: reqwest::Response,
        slot: Option<FlightSlot>,
    ) -> Option<Arc<FillHandle>> {
        let meta = meta_from_response(&response);
        let temp = self.cache.temp_path(&cand.key.hash);
        let fin = self.cache.data_path(&cand.key.hash);
        let job = match start_fill(cand.key.hash, meta.clone(), temp, fin) {
            Ok(j) => j,
            Err(e) => {
                tracing::error!("starting fill for {}: {e}", cand.key.full_url);
                return None;
            }
        };
        let handle = Arc::clone(&job.handle);
        // Keep the flight registered while the fill runs so mid-fill
        // arrivals tail it instead of re-fetching.
        let flight_guard = slot.map(|s| s.publish_fill(&handle));

        // The pump: upstream socket → temp file, as fast as network + disk
        // allow. Clients are nowhere in this loop; they tail the file.
        let up_stats = self.stats.upstream(&cand.upstream.name);
        let entry = fill_entry_template(cand, &meta, &self.config.ttl);
        let started = Instant::now();
        let engine = Arc::clone(self);
        let url = cand.key.full_url.clone();
        tokio::spawn(async move {
            let _flight_guard = flight_guard;
            let mut response = response;
            let expected = meta.content_length;
            loop {
                match response.chunk().await {
                    Ok(Some(chunk)) => {
                        engine
                            .stats
                            .bytes_fetched
                            .fetch_add(chunk.len() as u64, std::sync::atomic::Ordering::Relaxed);
                        if job.write(chunk.to_vec()).await.is_err() {
                            job.abort().await;
                            return;
                        }
                    }
                    Ok(None) => break,
                    Err(e) => {
                        tracing::warn!("fill of {url} failed mid-stream: {e}");
                        job.abort().await;
                        return;
                    }
                }
            }
            let (finished, total, sha) = match job.finish_disk().await {
                Ok(x) => x,
                Err(e) => {
                    tracing::warn!("fill of {url}: disk finish failed: {e}");
                    return;
                }
            };
            if let Some(cl) = expected {
                if cl != total {
                    tracing::warn!("fill of {url} truncated: got {total} of {cl} bytes");
                    finished.fail();
                    return;
                }
            }
            up_stats.observe_fill(total, started.elapsed().as_secs_f64());
            let mut entry = entry;
            entry.size = total;
            entry.content_sha256 = Some(sha);
            if entry.etag.is_none() {
                entry.etag = Some(format!("\"{}\"", crate::key::hex(&sha)));
            }
            // Durability gates completion: tailing clients see EOF only
            // after the metadata commit lands.
            match engine.cache.db.write_wait(entry).await {
                Ok(()) => finished.complete(),
                Err(e) => {
                    tracing::error!("fill metadata commit failed: {e}");
                    finished.fail();
                }
            }
        });
        Some(handle)
    }

    async fn attempt_nocache(
        &self,
        cand: &Candidate,
        method: Method,
        checksum: &Option<String>,
    ) -> AttemptResult {
        let request = match method {
            Method::Get => self.http.get(&cand.key.full_url),
            Method::Head => self.http.head(&cand.key.full_url),
        }
        .header("Accept-Encoding", "identity");
        let request = apply_checksum(request, &cand.upstream, checksum);
        let sent_at = Instant::now();
        match request.send().await {
            Ok(response) => {
                let status = response.status().as_u16();
                self.stats
                    .upstream(&cand.upstream.name)
                    .observe_ttfb(status, sent_at.elapsed());
                if status == 200 {
                    AttemptResult::Success(Outcome::Passthrough {
                        response: Box::new(response),
                    })
                } else if (400..500).contains(&status) {
                    AttemptResult::Negative
                } else {
                    AttemptResult::ServerError(status, meta_from_response(&response))
                }
            }
            Err(e) => {
                self.health.trip(&cand.upstream.name, &e.to_string());
                AttemptResult::Failed
            }
        }
    }
}

fn apply_checksum(
    request: reqwest::RequestBuilder,
    upstream: &Upstream,
    checksum: &Option<String>,
) -> reqwest::RequestBuilder {
    // Minimal header passthrough; these servers are picky.
    if let Some(sum) = checksum {
        request.header("SymbolChecksum", sum)
    } else if upstream.requires_symbolchecksum {
        request.header("SymbolChecksum", "invalid")
    } else {
        request
    }
}

fn meta_from_response(response: &reqwest::Response) -> FillMeta {
    let header = |name: &str| {
        response
            .headers()
            .get(name)
            .and_then(|v| v.to_str().ok())
            .map(|s| s.to_string())
    };
    let content_length = match header("content-encoding") {
        Some(_) => None,
        None => header("content-length").and_then(|v| v.parse().ok()),
    };
    FillMeta {
        etag: header("etag"),
        last_modified: Some(
            header("last-modified").unwrap_or_else(|| crate::cache::format_http_date(now_unix())),
        ),
        content_length,
    }
}

fn fill_entry_template(cand: &Candidate, meta: &FillMeta, ttl: &TtlPolicy) -> Entry {
    let now = now_unix();
    Entry {
        key: cand.key.hash,
        url: cand.key.full_url.clone(),
        upstream: cand.key.upstream_name.clone(),
        status: 200,
        created_at: now,
        accessed_at: now,
        expires_at: now + ttl.positive.as_secs_f64(),
        ttl: ttl.positive.as_secs_f64(),
        size: 0,
        etag: meta.etag.clone(),
        last_modified: meta.last_modified.as_deref().and_then(parse_http_date),
        content_sha256: None,
        hit_count: 0,
        negative_step: 0,
    }
}
