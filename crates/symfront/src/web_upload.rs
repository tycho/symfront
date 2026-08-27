//! Transactional upload API for remote clients (rw role required):
//!
//! 1. `POST /api/upload/begin` {product, version, comment} → {upload_id}
//! 2. `POST /api/upload/{id}/check` {files: [{name, hash}]} → {present: [bool]}
//!    — lets clients skip payloads the store already has.
//! 3. `POST /api/upload/{id}/file?name=&source=&hash=` (raw body, streamed)
//!    — staged server-side, re-identified, and verified against the claimed
//!    hash. Repeat per file.
//! 4. `POST /api/upload/{id}/commit` {files: [{name, hash, source}]} →
//!    {job} — runs the add as a background job (survives disconnects).
//!    Files not staged must already exist in the store (dedup path).
//! 5. `DELETE /api/upload/{id}` — abort and clean staging.
//!
//! Staging lives in `000Admin/_symfront_staging/<id>/` — same filesystem as
//! the store so commit renames instead of copying, and the `_symfront`
//! prefix keeps it out of scans, watchers, and /symbols.

use std::collections::HashMap;
use std::path::PathBuf;
use std::time::{Duration, Instant};

use axum::extract::{Path as AxPath, Query, State};
use axum::http::StatusCode;
use axum::response::IntoResponse;
use axum::Json;
use serde::Deserialize;
use serde_json::json;
use tokio_stream::StreamExt;

use symfront_core::ident::{self, FileKind};
use symfront_core::ops::{AddFile, AddRequest};

use crate::web::{spawn_add_job, App, ApiError};

type ApiResult<T> = std::result::Result<T, ApiError>;

const SESSION_TTL: Duration = Duration::from_secs(2 * 3600);
pub(crate) const STAGING_DIR: &str = "_symfront_staging";

pub(crate) struct UploadSession {
    pub dir: PathBuf,
    pub product: String,
    pub version: String,
    pub comment: String,
    /// Staged files keyed by lower-cased (name, hash).
    pub staged: HashMap<(String, String), (PathBuf, FileKind)>,
    pub counter: u64,
    pub created: Instant,
}

fn err(code: StatusCode, msg: impl Into<String>) -> ApiError {
    ApiError(code, msg.into())
}

fn random_id() -> String {
    use rand_core::{OsRng, RngCore};
    let mut buf = [0u8; 12];
    OsRng.fill_bytes(&mut buf);
    buf.iter().map(|b| format!("{b:02x}")).collect()
}

fn prune_stale(state: &App) {
    let mut uploads = state.uploads.lock().unwrap();
    let stale: Vec<String> = uploads
        .iter()
        .filter(|(_, s)| s.created.elapsed() > SESSION_TTL)
        .map(|(k, _)| k.clone())
        .collect();
    for k in stale {
        if let Some(s) = uploads.remove(&k) {
            let _ = std::fs::remove_dir_all(&s.dir);
            tracing::info!("expired stale upload session {k}");
        }
    }
}

#[derive(Deserialize)]
pub(crate) struct BeginRequest {
    product: String,
    #[serde(default)]
    version: String,
    #[serde(default)]
    comment: String,
}

pub(crate) async fn begin(
    State(state): State<App>,
    Json(req): Json<BeginRequest>,
) -> ApiResult<Json<serde_json::Value>> {
    if req.product.trim().is_empty() {
        return Err(err(StatusCode::BAD_REQUEST, "product must not be empty"));
    }
    prune_stale(&state);
    let id = random_id();
    let dir = state
        .store
        .admin_dir()
        .join(STAGING_DIR)
        .join(&id);
    tokio::fs::create_dir_all(&dir)
        .await
        .map_err(|e| err(StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
    state.uploads.lock().unwrap().insert(
        id.clone(),
        UploadSession {
            dir,
            product: req.product,
            version: req.version,
            comment: req.comment,
            staged: HashMap::new(),
            counter: 0,
            created: Instant::now(),
        },
    );
    Ok(Json(json!({ "upload_id": id })))
}

#[derive(Deserialize)]
pub(crate) struct CheckFile {
    name: String,
    hash: String,
}

#[derive(Deserialize)]
pub(crate) struct CheckRequest {
    files: Vec<CheckFile>,
}

/// Which of the given (name, hash) payloads already exist in the store.
pub(crate) async fn check(
    State(state): State<App>,
    AxPath(id): AxPath<String>,
    Json(req): Json<CheckRequest>,
) -> ApiResult<Json<serde_json::Value>> {
    if !state.uploads.lock().unwrap().contains_key(&id) {
        return Err(err(StatusCode::NOT_FOUND, "unknown upload session"));
    }
    let store = state.store.clone();
    let present = tokio::task::spawn_blocking(move || {
        req.files
            .iter()
            .map(|f| find_store_payload(&store, &f.name, &f.hash).is_some())
            .collect::<Vec<bool>>()
    })
    .await
    .map_err(|e| err(StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
    Ok(Json(json!({ "present": present })))
}

/// Case-insensitive lookup of an existing payload file.
fn find_store_payload(store: &symfront_core::Store, name: &str, hash: &str) -> Option<PathBuf> {
    let find_ci = |dir: &std::path::Path, target: &str| -> Option<PathBuf> {
        let exact = dir.join(target);
        if exact.exists() {
            return Some(exact);
        }
        for ent in std::fs::read_dir(dir).ok()?.flatten() {
            if ent.file_name().to_string_lossy().eq_ignore_ascii_case(target) {
                return Some(ent.path());
            }
        }
        None
    };
    let name_dir = find_ci(store.root(), name)?;
    let hash_dir = find_ci(&name_dir, hash)?;
    let payload = find_ci(&hash_dir, name)?;
    payload.is_file().then_some(payload)
}

#[derive(Deserialize)]
pub(crate) struct FileParams {
    name: String,
    #[serde(default)]
    source: String,
    /// Client-computed hash; the server re-identifies and must agree.
    #[serde(default)]
    hash: Option<String>,
}

pub(crate) async fn upload_file(
    State(state): State<App>,
    AxPath(id): AxPath<String>,
    Query(params): Query<FileParams>,
    body: axum::body::Body,
) -> ApiResult<Json<serde_json::Value>> {
    let staged_path = {
        let mut uploads = state.uploads.lock().unwrap();
        let session = uploads
            .get_mut(&id)
            .ok_or_else(|| err(StatusCode::NOT_FOUND, "unknown upload session"))?;
        session.counter += 1;
        session.dir.join(format!("f{:04}", session.counter))
    };

    // Stream the body to staging.
    let mut file = tokio::fs::File::create(&staged_path)
        .await
        .map_err(|e| err(StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
    let mut stream = body.into_data_stream();
    use tokio::io::AsyncWriteExt;
    let mut bytes = 0u64;
    while let Some(chunk) = stream.next().await {
        let chunk = chunk.map_err(|e| err(StatusCode::BAD_REQUEST, e.to_string()))?;
        bytes += chunk.len() as u64;
        file.write_all(&chunk)
            .await
            .map_err(|e| err(StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
    }
    file.flush()
        .await
        .map_err(|e| err(StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
    drop(file);

    // Identify server-side; the client's hash claim must match.
    let ident_path = staged_path.clone();
    let identified = tokio::task::spawn_blocking(move || ident::identify(&ident_path))
        .await
        .map_err(|e| err(StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
    let cleanup = || {
        let _ = std::fs::remove_file(&staged_path);
    };
    let (kind, hash) = match identified {
        Ok(Some(x)) => x,
        Ok(None) => {
            cleanup();
            return Err(err(
                StatusCode::UNPROCESSABLE_ENTITY,
                format!("{}: not a PE image or supported PDB", params.name),
            ));
        }
        Err(e) => {
            cleanup();
            return Err(err(StatusCode::INTERNAL_SERVER_ERROR, e.to_string()));
        }
    };
    if let Some(claimed) = &params.hash {
        if !claimed.eq_ignore_ascii_case(&hash) {
            cleanup();
            return Err(err(
                StatusCode::UNPROCESSABLE_ENTITY,
                format!(
                    "{}: server identified hash {hash} but client claimed {claimed} (truncated upload?)",
                    params.name
                ),
            ));
        }
    }

    let mut uploads = state.uploads.lock().unwrap();
    let session = uploads
        .get_mut(&id)
        .ok_or_else(|| err(StatusCode::NOT_FOUND, "upload session vanished"))?;
    session.staged.insert(
        (params.name.to_lowercase(), hash.to_lowercase()),
        (staged_path, kind),
    );
    let _ = params.source; // recorded at commit time
    Ok(Json(json!({
        "name": params.name,
        "hash": hash,
        "kind": kind,
        "bytes": bytes,
    })))
}

#[derive(Deserialize)]
pub(crate) struct CommitFile {
    name: String,
    hash: String,
    #[serde(default)]
    source: String,
}

#[derive(Deserialize)]
pub(crate) struct CommitRequest {
    files: Vec<CommitFile>,
}

pub(crate) async fn commit(
    State(state): State<App>,
    AxPath(id): AxPath<String>,
    Json(req): Json<CommitRequest>,
) -> ApiResult<axum::response::Response> {
    if req.files.is_empty() {
        return Err(err(StatusCode::BAD_REQUEST, "no files in commit"));
    }
    let session = state
        .uploads
        .lock()
        .unwrap()
        .remove(&id)
        .ok_or_else(|| err(StatusCode::NOT_FOUND, "unknown upload session"))?;

    // Resolve every file to a payload: staged, or already in the store.
    let store = state.store.clone();
    let mut files: Vec<AddFile> = Vec::new();
    for f in &req.files {
        let key = (f.name.to_lowercase(), f.hash.to_lowercase());
        if let Some((path, kind)) = session.staged.get(&key) {
            files.push(AddFile {
                path: path.clone(),
                name: f.name.clone(),
                hash: f.hash.clone(),
                kind: *kind,
                source: f.source.clone(),
            });
        } else if let Some(existing) = find_store_payload(&store, &f.name, &f.hash) {
            let kind = match ident::identify(&existing) {
                Ok(Some((kind, _))) => kind,
                _ => FileKind::Pe, // unreadable existing payload; tag as binary
            };
            files.push(AddFile {
                path: existing,
                name: f.name.clone(),
                hash: f.hash.clone(),
                kind,
                source: f.source.clone(),
            });
        } else {
            // Put the session back so the client can upload the missing file.
            let name = f.name.clone();
            let hash = f.hash.clone();
            state.uploads.lock().unwrap().insert(id, session);
            return Err(err(
                StatusCode::CONFLICT,
                format!("{name}\\{hash}: neither uploaded nor already in the store"),
            ));
        }
    }

    let request = AddRequest {
        product: session.product.clone(),
        version: session.version.clone(),
        comment: session.comment.clone(),
        files,
        consume: true, // staging is on the store filesystem: rename into place
    };
    let staging_dir = session.dir.clone();
    let job = spawn_add_job(&state, request, staging_dir);
    Ok((StatusCode::ACCEPTED, Json(json!({ "job": job }))).into_response())
}

pub(crate) async fn abort(
    State(state): State<App>,
    AxPath(id): AxPath<String>,
) -> ApiResult<Json<serde_json::Value>> {
    let session = state
        .uploads
        .lock()
        .unwrap()
        .remove(&id)
        .ok_or_else(|| err(StatusCode::NOT_FOUND, "unknown upload session"))?;
    let _ = tokio::fs::remove_dir_all(&session.dir).await;
    Ok(Json(json!({ "ok": true })))
}

/// Poll one job by id (the SSE stream is the push variant of this).
pub(crate) async fn job_status(
    State(state): State<App>,
    AxPath(id): AxPath<u64>,
) -> ApiResult<Json<serde_json::Value>> {
    let jobs = state.jobs.lock().unwrap();
    match jobs.iter().find(|j| j.id == id) {
        Some(j) => Ok(Json(j.to_json())),
        None => Err(err(StatusCode::NOT_FOUND, "no such job")),
    }
}

/// Recovery helper: staging left behind by a crashed server.
pub(crate) fn cleanup_stale_staging(store: &symfront_core::Store) {
    let staging = store.admin_dir().join(STAGING_DIR);
    if let Ok(rd) = std::fs::read_dir(&staging) {
        for ent in rd.flatten() {
            tracing::warn!(
                "removing leftover upload staging {}",
                ent.path().display()
            );
            let _ = std::fs::remove_dir_all(ent.path());
        }
    }
}
