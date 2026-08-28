//! Admin API endpoints for the proxy tier: stats, upstream suspend/resume,
//! cache entry admin, maintenance jobs, and config history/reload.
//!
//! Role gating happens in the auth middleware: reads for any authenticated
//! user, mutations (POST/DELETE) for rw, `/api/admin/config/*` admin-only.

use std::sync::Arc;

use axum::extract::{Path as AxPath, Query, State};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::Json;
use serde::Deserialize;
use serde_json::json;
use symfront_proxy::engine::ProxyEngine;
use symfront_proxy::key::unhex32;
use symfront_proxy::maintenance::MaintProgress;

use crate::web::{spawn_async_job, ApiError, App, AuthCtx, ClientIp};

type ApiResult<T> = std::result::Result<T, ApiError>;

fn engine_of(state: &App) -> ApiResult<Arc<ProxyEngine>> {
    state.proxy.engine().ok_or_else(|| {
        ApiError(
            StatusCode::SERVICE_UNAVAILABLE,
            "proxy tier is not configured (no upstreams)".into(),
        )
    })
}

pub(crate) async fn proxy_stats(State(state): State<App>) -> Json<serde_json::Value> {
    Json(crate::pipeline::stats_json(&state.proxy))
}

pub(crate) async fn suspend_upstream(
    State(state): State<App>,
    AxPath(name): AxPath<String>,
) -> ApiResult<Json<serde_json::Value>> {
    let engine = engine_of(&state)?;
    if !engine.health.set_suspended(&name, true) {
        return Err(ApiError(
            StatusCode::NOT_FOUND,
            format!("no upstream named {name:?}"),
        ));
    }
    tracing::info!("upstream {name:?} manually suspended");
    Ok(Json(json!({ "ok": true })))
}

pub(crate) async fn resume_upstream(
    State(state): State<App>,
    AxPath(name): AxPath<String>,
) -> ApiResult<Json<serde_json::Value>> {
    let engine = engine_of(&state)?;
    if !engine.health.set_suspended(&name, false) {
        return Err(ApiError(
            StatusCode::NOT_FOUND,
            format!("no upstream named {name:?}"),
        ));
    }
    tracing::info!("upstream {name:?} manually resumed");
    Ok(Json(json!({ "ok": true })))
}

#[derive(Deserialize)]
pub(crate) struct SearchParams {
    q: String,
    #[serde(default = "default_limit")]
    limit: usize,
}

fn default_limit() -> usize {
    100
}

fn entry_json(e: &symfront_proxy::db::Entry) -> serde_json::Value {
    json!({
        "key": symfront_proxy::key::hex(&e.key),
        "url": e.url,
        "upstream": e.upstream,
        "status": e.status,
        "size": e.size,
        "created_at": e.created_at,
        "accessed_at": e.accessed_at,
        "expires_at": e.expires_at,
        "hit_count": e.hit_count,
        "negative_step": e.negative_step,
        "etag": e.etag,
    })
}

pub(crate) async fn cache_search(
    State(state): State<App>,
    Query(params): Query<SearchParams>,
) -> ApiResult<Json<serde_json::Value>> {
    let engine = engine_of(&state)?;
    let rows = engine
        .cache
        .db
        .search(&params.q, params.limit.min(1000))
        .map_err(|e| ApiError(StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
    Ok(Json(json!({
        "entries": rows.iter().map(entry_json).collect::<Vec<_>>(),
    })))
}

pub(crate) async fn cache_delete_entry(
    State(state): State<App>,
    AxPath(key): AxPath<String>,
) -> ApiResult<Json<serde_json::Value>> {
    let engine = engine_of(&state)?;
    let Some(key) = unhex32(&key) else {
        return Err(ApiError(StatusCode::BAD_REQUEST, "bad cache key".into()));
    };
    let entry = engine
        .cache
        .db
        .get(&key)
        .map_err(|e| ApiError(StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
    let Some(entry) = entry else {
        return Err(ApiError(
            StatusCode::NOT_FOUND,
            "no such cache entry".into(),
        ));
    };
    engine
        .cache
        .evict_keys(&[key], &[entry.size])
        .await
        .map_err(|e| ApiError(StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
    Ok(Json(json!({ "evicted": 1, "bytes": entry.size })))
}

/// Bulk-evict entries matching filters — e.g. "forget the 404s for foo.pdb
/// now that it's published" (`negative_only` + `url_substring`).
#[derive(Deserialize)]
pub(crate) struct EvictMatchRequest {
    #[serde(default)]
    upstream: Option<String>,
    #[serde(default)]
    negative_only: bool,
    #[serde(default)]
    url_substring: Option<String>,
}

pub(crate) async fn cache_evict_matching(
    State(state): State<App>,
    axum::Extension(ClientIp(ip)): axum::Extension<ClientIp>,
    ctx: Option<axum::Extension<AuthCtx>>,
    Json(req): Json<EvictMatchRequest>,
) -> ApiResult<Json<serde_json::Value>> {
    let engine = engine_of(&state)?;
    if req.upstream.is_none() && !req.negative_only && req.url_substring.is_none() {
        return Err(ApiError(
            StatusCode::BAD_REQUEST,
            "refusing to evict the whole cache; give at least one filter".into(),
        ));
    }
    let who = ctx
        .as_ref()
        .map(|c| c.user.name.as_str())
        .unwrap_or("<open server>");
    let keys = engine
        .cache
        .db
        .keys_matching(
            req.upstream.as_deref(),
            req.negative_only,
            req.url_substring.as_deref(),
        )
        .map_err(|e| ApiError(StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
    tracing::info!(
        "cache evict of {} entries (upstream={:?} negative_only={} url~{:?}) by {who} from {ip}",
        keys.len(),
        req.upstream,
        req.negative_only,
        req.url_substring
    );
    // Sizes are only needed for the byte count; fetch them per batch.
    let mut evicted = 0u64;
    for chunk in keys.chunks(512) {
        let entries = engine
            .cache
            .db
            .get_many(chunk)
            .map_err(|e| ApiError(StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
        let keys: Vec<[u8; 32]> = entries.iter().map(|e| e.key).collect();
        let sizes: Vec<u64> = entries.iter().map(|e| e.size).collect();
        engine
            .cache
            .evict_keys(&keys, &sizes)
            .await
            .map_err(|e| ApiError(StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
        evicted += keys.len() as u64;
    }
    Ok(Json(json!({ "evicted": evicted })))
}

pub(crate) async fn run_eviction(State(state): State<App>) -> ApiResult<Response> {
    let engine = engine_of(&state)?;
    let job = spawn_async_job(
        Arc::clone(&state),
        "proxy-evict",
        "cache eviction".into(),
        {
            async move {
                let progress = MaintProgress::default();
                let report = engine.evict_pass(&progress).await;
                Ok(serde_json::to_value(&report)?)
            }
        },
    );
    Ok((StatusCode::ACCEPTED, Json(json!({ "job": job }))).into_response())
}

#[derive(Deserialize, Default)]
pub(crate) struct ScrubRequest {
    /// Report only when false.
    #[serde(default = "default_true")]
    repair: bool,
}

fn default_true() -> bool {
    true
}

pub(crate) async fn run_scrub(
    State(state): State<App>,
    body: Option<Json<ScrubRequest>>,
) -> ApiResult<Response> {
    let engine = engine_of(&state)?;
    let repair = body.map(|Json(r)| r.repair).unwrap_or(true);
    let job = spawn_async_job(Arc::clone(&state), "proxy-scrub", "patrol scrub".into(), {
        async move {
            let progress = MaintProgress::default();
            let report = engine.scrub(repair, &progress).await?;
            Ok(serde_json::to_value(&report)?)
        }
    });
    Ok((StatusCode::ACCEPTED, Json(json!({ "job": job }))).into_response())
}

// ---------------------------------------------------------------------------
// Config (admin-only via middleware: /api/admin/config/*)
// ---------------------------------------------------------------------------

pub(crate) async fn config_reload(State(state): State<App>) -> ApiResult<Json<serde_json::Value>> {
    let proxy = Arc::clone(&state.proxy);
    let summary = tokio::task::spawn_blocking(move || crate::pipeline::reload(&proxy))
        .await
        .map_err(|e| ApiError(StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?
        .map_err(|e| ApiError(StatusCode::UNPROCESSABLE_ENTITY, format!("{e:#}")))?;
    Ok(Json(json!({ "ok": true, "summary": summary })))
}

fn config_store_of(state: &App) -> ApiResult<crate::config_store::ConfigStore> {
    let Some(dir) = &state.proxy.config_dir else {
        return Err(ApiError(
            StatusCode::SERVICE_UNAVAILABLE,
            "no config tree on this server".into(),
        ));
    };
    crate::config_store::ConfigStore::open(dir)
        .map_err(|e| ApiError(StatusCode::INTERNAL_SERVER_ERROR, format!("{e:#}")))
}

#[derive(Deserialize)]
pub(crate) struct LogParams {
    #[serde(default = "default_log_limit")]
    limit: usize,
}

fn default_log_limit() -> usize {
    50
}

pub(crate) async fn config_log(
    State(state): State<App>,
    Query(params): Query<LogParams>,
) -> ApiResult<Json<serde_json::Value>> {
    let store = config_store_of(&state)?;
    let entries = store
        .log(params.limit.min(500))
        .map_err(|e| ApiError(StatusCode::INTERNAL_SERVER_ERROR, format!("{e:#}")))?;
    let dirty = store.is_dirty().unwrap_or(false);
    Ok(Json(json!({ "entries": entries, "dirty": dirty })))
}

#[derive(Deserialize)]
pub(crate) struct DiffParams {
    from: Option<String>,
    to: Option<String>,
}

pub(crate) async fn config_diff(
    State(state): State<App>,
    Query(params): Query<DiffParams>,
) -> ApiResult<Json<serde_json::Value>> {
    let store = config_store_of(&state)?;
    let text = store
        .diff(params.from.as_deref(), params.to.as_deref())
        .map_err(|e| ApiError(StatusCode::UNPROCESSABLE_ENTITY, format!("{e:#}")))?;
    Ok(Json(json!({ "diff": text })))
}

#[derive(Deserialize)]
pub(crate) struct RollbackRequest {
    rev: String,
}

pub(crate) async fn config_rollback(
    State(state): State<App>,
    ctx: Option<axum::Extension<AuthCtx>>,
    Json(req): Json<RollbackRequest>,
) -> ApiResult<Json<serde_json::Value>> {
    let store = config_store_of(&state)?;
    let author = ctx
        .as_ref()
        .map(|c| c.user.name.clone())
        .unwrap_or_else(|| "symfront".into());
    let id = store
        .rollback(&author, &req.rev)
        .map_err(|e| ApiError(StatusCode::UNPROCESSABLE_ENTITY, format!("{e:#}")))?;
    // A rollback that isn't applied is a trap; reload immediately.
    let proxy = Arc::clone(&state.proxy);
    let summary = tokio::task::spawn_blocking(move || crate::pipeline::reload(&proxy))
        .await
        .map_err(|e| ApiError(StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?
        .map_err(|e| ApiError(StatusCode::UNPROCESSABLE_ENTITY, format!("{e:#}")))?;
    Ok(Json(
        json!({ "ok": true, "commit": id, "summary": summary }),
    ))
}

/// The editable config files, by exact name.
const EDITABLE: &[&str] = &[
    crate::config::SERVER_TOML,
    crate::config::STORE_TOML,
    crate::config::PROXY_TOML,
    crate::config::UPSTREAMS_TOML,
    crate::config::BLACKLIST_TOML,
];

fn config_dir_of(state: &App) -> ApiResult<std::path::PathBuf> {
    state.proxy.config_dir.clone().ok_or_else(|| {
        ApiError(
            StatusCode::SERVICE_UNAVAILABLE,
            "no config tree on this server".into(),
        )
    })
}

pub(crate) async fn config_files(State(state): State<App>) -> ApiResult<Json<serde_json::Value>> {
    let dir = config_dir_of(&state)?;
    let files: Vec<serde_json::Value> = EDITABLE
        .iter()
        .map(|name| {
            let exists = dir.join(name).is_file();
            json!({ "name": name, "exists": exists })
        })
        .collect();
    Ok(Json(json!({ "files": files })))
}

pub(crate) async fn config_get_file(
    State(state): State<App>,
    AxPath(name): AxPath<String>,
) -> ApiResult<Json<serde_json::Value>> {
    let dir = config_dir_of(&state)?;
    if !EDITABLE.contains(&name.as_str()) {
        return Err(ApiError(
            StatusCode::NOT_FOUND,
            "unknown config file".into(),
        ));
    }
    let text = std::fs::read_to_string(dir.join(&name)).unwrap_or_default();
    Ok(Json(json!({ "name": name, "content": text })))
}

/// Validate `content` as the named config file (without touching disk).
fn validate_config(name: &str, content: &str) -> Result<(), String> {
    let err = |e: String| Err(e);
    match name {
        n if n == crate::config::SERVER_TOML => {
            toml::from_str::<crate::config::ServerConfig>(content)
                .map(|_| ())
                .map_err(|e| e.to_string())
        }
        n if n == crate::config::STORE_TOML => {
            toml::from_str::<crate::config::StoreConfig>(content)
                .map(|_| ())
                .map_err(|e| e.to_string())
        }
        n => {
            // Proxy-side files: the parsers take paths; validate via a
            // temp file so a bad save can never half-apply.
            let tmp =
                std::env::temp_dir().join(format!(".symfront-validate-{}-{n}", std::process::id()));
            if let Err(e) = std::fs::write(&tmp, content) {
                return err(e.to_string());
            }
            let result = if n == crate::config::PROXY_TOML {
                symfront_proxy::config::ProxyConfig::from_file(&tmp).map(|_| ())
            } else if n == crate::config::UPSTREAMS_TOML {
                symfront_proxy::config::upstreams_from_file(&tmp).map(|_| ())
            } else {
                symfront_proxy::config::blacklist_from_file(&tmp).map(|_| ())
            };
            let _ = std::fs::remove_file(&tmp);
            result.map_err(|e| e.to_string())
        }
    }
}

#[derive(Deserialize)]
pub(crate) struct PutFileRequest {
    content: String,
}

pub(crate) async fn config_put_file(
    State(state): State<App>,
    AxPath(name): AxPath<String>,
    ctx: Option<axum::Extension<AuthCtx>>,
    Json(req): Json<PutFileRequest>,
) -> ApiResult<Json<serde_json::Value>> {
    let dir = config_dir_of(&state)?;
    if !EDITABLE.contains(&name.as_str()) {
        return Err(ApiError(
            StatusCode::NOT_FOUND,
            "unknown config file".into(),
        ));
    }
    validate_config(&name, &req.content)
        .map_err(|e| ApiError(StatusCode::UNPROCESSABLE_ENTITY, format!("{name}: {e}")))?;
    let store = config_store_of(&state)?;
    // Manual edits made since the last commit become their own commit first,
    // so this save can never silently absorb them.
    store
        .commit_drift()
        .map_err(|e| ApiError(StatusCode::INTERNAL_SERVER_ERROR, format!("{e:#}")))?;
    std::fs::write(dir.join(&name), &req.content)
        .map_err(|e| ApiError(StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
    let author = ctx
        .as_ref()
        .map(|c| c.user.name.clone())
        .unwrap_or_else(|| "symfront".into());
    let commit = store
        .commit_all(&author, &format!("edit {name} via web UI"))
        .map_err(|e| ApiError(StatusCode::INTERNAL_SERVER_ERROR, format!("{e:#}")))?;
    let proxy = Arc::clone(&state.proxy);
    let summary = tokio::task::spawn_blocking(move || crate::pipeline::reload(&proxy))
        .await
        .map_err(|e| ApiError(StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?
        .map_err(|e| ApiError(StatusCode::UNPROCESSABLE_ENTITY, format!("{e:#}")))?;
    Ok(Json(
        json!({ "ok": true, "commit": commit, "summary": summary }),
    ))
}
