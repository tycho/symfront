//! The root-mounted symbol serving pipeline.
//!
//! Tier 0: the managed store — cheap stat + case-insensitive resolve; if we
//! own a copy, we serve it (before blacklist/classification). Tier 1: the
//! caching proxy (symfront-proxy engine). Everything not under `/admin/` or
//! `/metrics` lands here.

use std::path::{Path, PathBuf};
use std::sync::atomic::Ordering;
use std::sync::{Arc, RwLock};

use axum::body::Body;
use axum::http::{header, HeaderMap, Method, StatusCode, Uri};
use axum::response::{IntoResponse, Response};
use symfront_proxy::config::{
    blacklist_from_file, upstreams_from_file, CompressionConfig, ProxyConfig,
};
use symfront_proxy::engine::{ClientRequest, Outcome, ProxyEngine};
use symfront_proxy::stats::RequestOutcome;
use symfront_store::Store;

use crate::config as cfgtree;
use crate::symbols::{self, plain, ServeOverrides};

/// Shared serving state for both the combined server and `--proxy-only`.
pub(crate) struct ProxyState {
    /// Tier 0; absent on a pure cache node.
    pub store: Option<Store>,
    /// Tier 1; absent when no proxy is configured. Swapped on reload.
    pub engine: RwLock<Option<Arc<ProxyEngine>>>,
    pub config_dir: Option<PathBuf>,
}

impl ProxyState {
    pub fn engine(&self) -> Option<Arc<ProxyEngine>> {
        self.engine.read().unwrap().clone()
    }

    pub fn compression(&self) -> CompressionConfig {
        self.engine()
            .map(|e| e.config.compression.clone())
            .unwrap_or_default()
    }
}

/// Build the proxy engine from the config tree. `Ok(None)` when no config
/// dir exists (flag-only runs have no proxy tier).
pub(crate) fn build_engine(config_dir: &Path) -> anyhow::Result<Option<Arc<ProxyEngine>>> {
    if !config_dir.is_dir() {
        return Ok(None);
    }
    let proxy_cfg = ProxyConfig::from_file(&config_dir.join(cfgtree::PROXY_TOML))?;
    let upstreams = upstreams_from_file(&config_dir.join(cfgtree::UPSTREAMS_TOML))?;
    let blacklist = blacklist_from_file(&config_dir.join(cfgtree::BLACKLIST_TOML))?;
    if upstreams.is_empty() {
        tracing::info!("no upstreams configured; proxy tier disabled");
        return Ok(None);
    }
    let engine = ProxyEngine::new(proxy_cfg, upstreams, blacklist)?;
    tracing::info!(
        "proxy tier: {} upstream(s), cache at {}",
        engine.upstreams.len(),
        engine.config.cache_path.display()
    );
    Ok(Some(engine))
}

/// Reload the config tree: commit manual drift, rebuild the engine, swap it
/// in. Server-level settings (listen address etc.) need a restart.
pub(crate) fn reload(state: &ProxyState) -> anyhow::Result<String> {
    let Some(dir) = &state.config_dir else {
        anyhow::bail!("no config tree; nothing to reload");
    };
    match crate::config_store::ConfigStore::open(dir) {
        Ok(store) => {
            if let Err(e) = store.commit_drift() {
                tracing::warn!("config drift commit failed: {e:#}");
            }
        }
        Err(e) => tracing::warn!("config history unavailable: {e:#}"),
    }
    let engine = build_engine(dir)?;
    let summary = match &engine {
        Some(e) => format!("proxy reloaded: {} upstream(s)", e.upstreams.len()),
        None => "proxy disabled (no upstreams configured)".to_string(),
    };
    *state.engine.write().unwrap() = engine;
    tracing::info!("{summary}");
    Ok(summary)
}

/// Background loops: health probes, periodic eviction, weekly scrub.
pub(crate) fn spawn_background(
    state: Arc<ProxyState>,
    shutdown: Arc<std::sync::atomic::AtomicBool>,
) {
    let probes = Arc::clone(&state);
    let stop = Arc::clone(&shutdown);
    tokio::spawn(async move {
        loop {
            let interval = probes
                .engine()
                .map(|e| e.health.probe_interval)
                .unwrap_or(std::time::Duration::from_secs(30));
            tokio::time::sleep(interval).await;
            if stop.load(Ordering::Relaxed) {
                break;
            }
            if let Some(engine) = probes.engine() {
                engine.probe_suspended_once().await;
            }
        }
    });
    let evict = Arc::clone(&state);
    let stop = Arc::clone(&shutdown);
    tokio::spawn(async move {
        loop {
            tokio::time::sleep(std::time::Duration::from_secs(600)).await;
            if stop.load(Ordering::Relaxed) {
                break;
            }
            if let Some(engine) = evict.engine() {
                let progress = symfront_proxy::maintenance::MaintProgress::default();
                let report = engine.evict_pass(&progress).await;
                if report.evicted_entries > 0 {
                    tracing::info!(
                        "eviction: {} entries / {} bytes freed",
                        report.evicted_entries,
                        report.evicted_bytes
                    );
                }
            }
        }
    });
    let scrub = state;
    let stop = shutdown;
    tokio::spawn(async move {
        loop {
            tokio::time::sleep(std::time::Duration::from_secs(7 * 86400)).await;
            if stop.load(Ordering::Relaxed) {
                break;
            }
            if let Some(engine) = scrub.engine() {
                let progress = symfront_proxy::maintenance::MaintProgress::default();
                match engine.scrub(true, &progress).await {
                    Ok(report) => tracing::info!("weekly scrub: {report:?}"),
                    Err(e) => tracing::error!("weekly scrub failed: {e}"),
                }
            }
        }
    });
}

/// Normalize a request path to exactly one leading '/'.
fn normalize(path: &str) -> String {
    format!("/{}", path.trim_start_matches('/'))
}

pub(crate) async fn serve_root(
    axum::extract::State(state): axum::extract::State<Arc<ProxyState>>,
    method: Method,
    uri: Uri,
    headers: HeaderMap,
) -> Response {
    serve_path(&state, method, uri.path(), &headers).await
}

/// Temporary migration alias: `/symbols/<path>` serves the same pipeline.
pub(crate) async fn serve_symbols_alias(
    axum::extract::State(state): axum::extract::State<Arc<ProxyState>>,
    axum::extract::Path(rest): axum::extract::Path<String>,
    method: Method,
    headers: HeaderMap,
) -> Response {
    serve_path(&state, method, &rest, &headers).await
}

async fn serve_path(
    state: &Arc<ProxyState>,
    method: Method,
    raw_path: &str,
    headers: &HeaderMap,
) -> Response {
    if method != Method::GET && method != Method::HEAD {
        return plain(StatusCode::METHOD_NOT_ALLOWED, "GET/HEAD only");
    }
    let path = normalize(raw_path);
    // Commonly used as a server health check (e.g. by Ghidra).
    if path == "/pingme.txt" {
        return StatusCode::OK.into_response();
    }
    let comp = state.compression();

    // Tier 0 — the managed store. Runs before blacklist/classification:
    // if we own a copy, we serve it.
    if let Some(store) = &state.store {
        if let Some(local) = symbols::resolve(store.root(), path.trim_start_matches('/')) {
            if let Some(engine) = state.engine() {
                engine.stats.count(RequestOutcome::Tier0Hit);
                if let Ok(md) = std::fs::metadata(&local) {
                    engine
                        .stats
                        .bytes_from_store
                        .fetch_add(md.len(), Ordering::Relaxed);
                }
            }
            return match symbols::serve_file(&local, &method, headers, &comp, Default::default())
                .await
            {
                Ok(resp) => resp,
                Err(e) => {
                    tracing::warn!("serving {}: {e:#}", local.display());
                    plain(StatusCode::INTERNAL_SERVER_ERROR, "read error")
                }
            };
        }
    }

    // Tier 1 — the caching proxy.
    let Some(engine) = state.engine() else {
        return plain(StatusCode::NOT_FOUND, "file not found");
    };
    let request = ClientRequest {
        method: match method {
            Method::HEAD => symfront_proxy::Method::Head,
            _ => symfront_proxy::Method::Get,
        },
        path: &path,
        symbol_checksum: headers
            .get("symbolchecksum")
            .and_then(|v| v.to_str().ok())
            .map(|s| s.to_string()),
    };
    let outcome = engine.handle(request).await;
    render_outcome(&engine, outcome, &method, headers, &comp).await
}

async fn render_outcome(
    engine: &Arc<ProxyEngine>,
    outcome: Outcome,
    method: &Method,
    headers: &HeaderMap,
    comp: &CompressionConfig,
) -> Response {
    match outcome {
        Outcome::NotFound => plain(StatusCode::NOT_FOUND, "file not found"),
        Outcome::HeaderOnly { status, meta } => {
            let mut b = Response::builder()
                .status(StatusCode::from_u16(status).unwrap_or(StatusCode::BAD_GATEWAY));
            if let Some(etag) = &meta.etag {
                b = b.header(header::ETAG, etag);
            }
            if let Some(lm) = &meta.last_modified {
                b = b.header(header::LAST_MODIFIED, lm);
            }
            b.body(Body::empty()).unwrap().into_response()
        }
        Outcome::CacheHit { entry, path } => {
            engine
                .stats
                .bytes_from_cache
                .fetch_add(entry.size, Ordering::Relaxed);
            let overrides = ServeOverrides {
                etag: entry.etag.clone(),
                last_modified: entry
                    .last_modified
                    .map(symfront_proxy::cache::format_http_date),
            };
            match symbols::serve_file(&path, method, headers, comp, overrides).await {
                Ok(resp) => resp,
                Err(e) => {
                    tracing::warn!("serving cache hit {}: {e:#}", path.display());
                    plain(StatusCode::INTERNAL_SERVER_ERROR, "read error")
                }
            }
        }
        Outcome::AccelHit { entry, redirect } => {
            engine
                .stats
                .bytes_from_cache
                .fetch_add(entry.size, Ordering::Relaxed);
            let mut b = Response::builder()
                .status(StatusCode::OK)
                .header("X-Accel-Redirect", redirect)
                .header(header::CONTENT_TYPE, "application/octet-stream");
            if let Some(etag) = &entry.etag {
                b = b.header(header::ETAG, etag);
            }
            if let Some(lm) = entry.last_modified {
                b = b.header(
                    header::LAST_MODIFIED,
                    symfront_proxy::cache::format_http_date(lm),
                );
            }
            b.body(Body::empty()).unwrap().into_response()
        }
        Outcome::Fill { handle, upstream } => {
            let mut b = Response::builder()
                .status(StatusCode::OK)
                .header(header::CONTENT_TYPE, "application/octet-stream")
                .header("x-symfront-upstream", upstream);
            if let Some(etag) = &handle.meta.etag {
                b = b.header(header::ETAG, etag);
            }
            if let Some(lm) = &handle.meta.last_modified {
                b = b.header(header::LAST_MODIFIED, lm);
            }
            if let Some(cl) = handle.meta.content_length {
                b = b.header(header::CONTENT_LENGTH, cl);
            }
            if *method == Method::HEAD {
                // §3.4: headers now; the fill finishes with no tailing
                // clients and warms the cache for the GET that follows.
                return b.body(Body::empty()).unwrap().into_response();
            }
            let reader = handle.tail();
            let stream = futures_util::stream::unfold(reader, |mut reader| async move {
                match reader.next_chunk().await {
                    Ok(Some(chunk)) => Some((Ok::<_, std::io::Error>(chunk), reader)),
                    Ok(None) => None,
                    Err(e) => Some((Err(e), reader)),
                }
            });
            b.body(Body::from_stream(stream)).unwrap().into_response()
        }
        Outcome::Passthrough { response } => {
            let status = StatusCode::from_u16(response.status().as_u16()).unwrap_or(StatusCode::OK);
            let mut b = Response::builder().status(status);
            for name in [
                header::CONTENT_LENGTH,
                header::CONTENT_TYPE,
                header::ETAG,
                header::LAST_MODIFIED,
            ] {
                if let Some(v) = response.headers().get(&name) {
                    b = b.header(name, v.clone());
                }
            }
            if *method == Method::HEAD {
                return b.body(Body::empty()).unwrap().into_response();
            }
            use futures_util::TryStreamExt;
            let stream = response.bytes_stream().map_err(std::io::Error::other);
            b.body(Body::from_stream(stream)).unwrap().into_response()
        }
    }
}

// ---------------------------------------------------------------------------
// Metrics
// ---------------------------------------------------------------------------

/// Prometheus text exposition of the proxy stats.
pub(crate) async fn metrics(
    axum::extract::State(state): axum::extract::State<Arc<ProxyState>>,
) -> Response {
    let mut out = String::new();
    if let Some(engine) = state.engine() {
        render_metrics(&engine, &mut out);
    }
    Response::builder()
        .header(header::CONTENT_TYPE, "text/plain; version=0.0.4")
        .body(Body::from(out))
        .unwrap()
        .into_response()
}

fn render_metrics(engine: &ProxyEngine, out: &mut String) {
    use std::fmt::Write;
    let s = &engine.stats;
    let counter = |out: &mut String, name: &str, help: &str, pairs: &[(&str, u64)]| {
        let _ = writeln!(out, "# HELP {name} {help}");
        let _ = writeln!(out, "# TYPE {name} counter");
        for (labels, v) in pairs {
            let _ = writeln!(out, "{name}{labels} {v}");
        }
    };
    counter(
        out,
        "symfront_requests_total",
        "Client requests by outcome",
        &[
            (
                "{outcome=\"tier0_hit\"}",
                s.tier0_hits.load(Ordering::Relaxed),
            ),
            (
                "{outcome=\"cache_hit\"}",
                s.cache_hits.load(Ordering::Relaxed),
            ),
            ("{outcome=\"fill\"}", s.fills.load(Ordering::Relaxed)),
            (
                "{outcome=\"negative_hit\"}",
                s.negative_hits.load(Ordering::Relaxed),
            ),
            (
                "{outcome=\"passthrough\"}",
                s.passthroughs.load(Ordering::Relaxed),
            ),
            ("{outcome=\"miss\"}", s.misses.load(Ordering::Relaxed)),
            ("{outcome=\"rejected\"}", s.rejected.load(Ordering::Relaxed)),
            ("{outcome=\"error\"}", s.errors.load(Ordering::Relaxed)),
        ],
    );
    counter(
        out,
        "symfront_bytes_total",
        "Body bytes by source",
        &[
            (
                "{source=\"cache\"}",
                s.bytes_from_cache.load(Ordering::Relaxed),
            ),
            (
                "{source=\"store\"}",
                s.bytes_from_store.load(Ordering::Relaxed),
            ),
            (
                "{source=\"upstream\"}",
                s.bytes_fetched.load(Ordering::Relaxed),
            ),
        ],
    );
    {
        use std::fmt::Write;
        let ups = s.upstreams.lock().unwrap();
        let health = engine.health.snapshot();
        let _ = writeln!(out, "# TYPE symfront_upstream_fills_total counter");
        let _ = writeln!(out, "# TYPE symfront_upstream_errors_total counter");
        let _ = writeln!(
            out,
            "# TYPE symfront_upstream_transport_failures_total counter"
        );
        let _ = writeln!(
            out,
            "# TYPE symfront_upstream_throughput_bytes_per_second gauge"
        );
        for (name, u) in ups.iter() {
            let _ = writeln!(
                out,
                "symfront_upstream_fills_total{{upstream=\"{name}\"}} {}",
                u.fills.load(Ordering::Relaxed)
            );
            let _ = writeln!(
                out,
                "symfront_upstream_errors_total{{upstream=\"{name}\"}} {}",
                u.errors.load(Ordering::Relaxed)
            );
            let _ = writeln!(
                out,
                "symfront_upstream_transport_failures_total{{upstream=\"{name}\"}} {}",
                u.transport_failures.load(Ordering::Relaxed)
            );
            let _ = writeln!(
                out,
                "symfront_upstream_throughput_bytes_per_second{{upstream=\"{name}\"}} {:.0}",
                u.throughput()
            );
            for (class, window) in [("2xx", &u.latency_2xx), ("4xx", &u.latency_4xx)] {
                if let Some(p50) = window.median() {
                    let _ = writeln!(
                        out,
                        "symfront_upstream_ttfb_ms{{upstream=\"{name}\",class=\"{class}\"}} {p50:.1}"
                    );
                }
            }
        }
        let _ = writeln!(out, "# TYPE symfront_upstream_suspended gauge");
        for (name, (suspended, _)) in &health {
            let _ = writeln!(
                out,
                "symfront_upstream_suspended{{upstream=\"{name}\"}} {}",
                *suspended as u8
            );
        }
    }
    if let Ok(summary) = engine.cache.db.summary() {
        use std::fmt::Write;
        let _ = writeln!(out, "# TYPE symfront_cache_entries gauge");
        let _ = writeln!(out, "# TYPE symfront_cache_bytes gauge");
        for (upstream, positive, count, bytes) in &summary {
            let kind = if *positive { "positive" } else { "negative" };
            let _ = writeln!(
                out,
                "symfront_cache_entries{{upstream=\"{upstream}\",kind=\"{kind}\"}} {count}"
            );
            let _ = writeln!(
                out,
                "symfront_cache_bytes{{upstream=\"{upstream}\",kind=\"{kind}\"}} {bytes}"
            );
        }
    }
    if let Some(size) = engine.config.cache_size {
        use std::fmt::Write;
        let _ = writeln!(out, "# TYPE symfront_cache_size_limit_bytes gauge");
        let _ = writeln!(out, "symfront_cache_size_limit_bytes {size}");
    }
}

/// JSON stats snapshot for `/admin/api/proxy/stats` and the CLI.
pub(crate) fn stats_json(state: &ProxyState) -> serde_json::Value {
    use serde_json::json;
    let Some(engine) = state.engine() else {
        return json!({ "enabled": false });
    };
    let s = &engine.stats;
    let load = |a: &std::sync::atomic::AtomicU64| a.load(Ordering::Relaxed);
    let upstream_stats: serde_json::Value = {
        let ups = s.upstreams.lock().unwrap();
        ups.iter()
            .map(|(name, u)| {
                (
                    name.clone(),
                    json!({
                        "fills": load(&u.fills),
                        "fill_bytes": load(&u.fill_bytes),
                        "negatives": load(&u.negatives),
                        "errors": load(&u.errors),
                        "transport_failures": load(&u.transport_failures),
                        "throughput_bps": u.throughput(),
                        "ttfb_ms": {
                            "p50_2xx": u.latency_2xx.median(),
                            "p50_4xx": u.latency_4xx.median(),
                            "samples_2xx": u.latency_2xx.len(),
                            "samples_4xx": u.latency_4xx.len(),
                        },
                    }),
                )
            })
            .collect::<serde_json::Map<String, serde_json::Value>>()
            .into()
    };
    let health: serde_json::Value = engine
        .health
        .snapshot()
        .into_iter()
        .map(|(name, (suspended, info))| (name, json!({ "suspended": suspended, "info": info })))
        .collect::<serde_json::Map<String, serde_json::Value>>()
        .into();
    let cache = match engine.cache.db.summary() {
        Ok(rows) => {
            let mut positive_bytes = 0u64;
            let mut positive_entries = 0u64;
            let mut negative_entries = 0u64;
            let per: Vec<serde_json::Value> = rows
                .iter()
                .map(|(upstream, positive, count, bytes)| {
                    if *positive {
                        positive_bytes += bytes;
                        positive_entries += count;
                    } else {
                        negative_entries += count;
                    }
                    json!({
                        "upstream": upstream,
                        "kind": if *positive { "positive" } else { "negative" },
                        "entries": count,
                        "bytes": bytes,
                    })
                })
                .collect();
            json!({
                "positive_bytes": positive_bytes,
                "positive_entries": positive_entries,
                "negative_entries": negative_entries,
                "size_limit": engine.config.cache_size,
                "per_upstream": per,
            })
        }
        Err(e) => json!({ "error": e.to_string() }),
    };
    let upstream_config: Vec<serde_json::Value> = engine
        .upstreams
        .iter()
        .map(|u| {
            json!({
                "name": u.name,
                "base_url": u.base_url,
                "layout": u.layout.name(),
                "priority": u.priority,
                "nocache": u.nocache,
                "enabled": u.enabled,
            })
        })
        .collect();
    json!({
        "enabled": true,
        "upstream_config": upstream_config,
        "requests": {
            "tier0_hits": load(&s.tier0_hits),
            "cache_hits": load(&s.cache_hits),
            "fills": load(&s.fills),
            "negative_hits": load(&s.negative_hits),
            "passthroughs": load(&s.passthroughs),
            "misses": load(&s.misses),
            "rejected": load(&s.rejected),
            "errors": load(&s.errors),
        },
        "bytes": {
            "from_cache": load(&s.bytes_from_cache),
            "from_store": load(&s.bytes_from_store),
            "fetched": load(&s.bytes_fetched),
        },
        "estimated_seconds_saved": s.estimated_seconds_saved(),
        "upstreams": upstream_stats,
        "health": health,
        "cache": cache,
        "mode": format!("{:?}", engine.config.mode).to_lowercase(),
    })
}
