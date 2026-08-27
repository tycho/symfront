//! HTTP API + embedded single-page UI (axum).
//!
//! The logical index (admin records) loads at startup and reloads after every
//! mutation. A full tree scan (sizes, strays, deep consistency) runs in a
//! background thread at startup and after each mutation.
//!
//! Mutations (delete, prune) run as server-side background *jobs* in dedicated
//! threads: they survive the browser navigating away or disconnecting.
//! `/api/events` is an SSE stream broadcasting scan status, job progress, and
//! an index generation counter, so every connected page sees live updates
//! regardless of who started an operation.

use std::collections::HashMap;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex, RwLock};
use std::time::{Duration, Instant, SystemTime};

use axum::extract::{Path as AxPath, Query, Request, State};
use axum::http::{header, HeaderMap, Method, StatusCode};
use axum::middleware::Next;
use axum::response::sse::{Event, KeepAlive, Sse};
use axum::response::{Html, IntoResponse, Response};
use axum::routing::{delete, get, post};
use axum::{Json, Router};
use serde::Deserialize;
use serde_json::json;
use tokio_stream::StreamExt;

use crate::auth::{AuthDb, Role, User};
use crate::web_account;

use symfront_core::check::{self, Finding};
use symfront_core::index::StoreIndex;
use symfront_core::ops::{self, OpProgress};
use symfront_core::scan::{self, ScanProgress, SizeTotals};
use symfront_core::strays::{self, StrayReport, TxIssues, TxSizes};
use symfront_core::{Store, TransactionId};

/// Result of a completed scan, condensed (the raw per-dir listing is dropped).
struct ScanBundle {
    totals: SizeTotals,
    admin: SizeTotals,
    payload: SizeTotals,
    scanned_at: u64,
    duration_ms: u64,
    strays: StrayReport,
    tx_sizes: HashMap<TransactionId, TxSizes>,
    tx_issues: HashMap<TransactionId, TxIssues>,
    deep_findings: Vec<Finding>,
}

#[derive(Default)]
struct ScanSlot {
    running: Option<Arc<ScanProgress>>,
    result: Option<Arc<ScanBundle>>,
    error: Option<String>,
}

enum JobState {
    Running,
    Done(serde_json::Value),
    Failed(String),
}

/// A background mutation. Lives in its own thread; the HTTP response returns
/// immediately with the job id and progress streams over `/api/events`.
struct Job {
    id: u64,
    kind: &'static str, // "delete" | "prune"
    target: String,
    progress: OpProgress,
    state: Mutex<JobState>,
    finished_at: Mutex<Option<SystemTime>>,
}

impl Job {
    fn to_json(&self) -> serde_json::Value {
        let state = self.state.lock().unwrap();
        let (state_str, outcome, error) = match &*state {
            JobState::Running => ("running", None, None),
            JobState::Done(v) => ("done", Some(v.clone()), None),
            JobState::Failed(e) => ("failed", None, Some(e.clone())),
        };
        json!({
            "id": self.id,
            "kind": self.kind,
            "target": self.target,
            "state": state_str,
            "progress": self.progress.snapshot(),
            "outcome": outcome,
            "error": error,
        })
    }
}

/// A login awaiting its second step (TOTP code or WebAuthn assertion).
pub(crate) enum PendingLogin {
    Totp {
        user_id: i64,
        created: Instant,
    },
    WebAuthn {
        state: webauthn_rs::prelude::PasskeyAuthentication,
        created: Instant,
    },
}

/// An in-flight passkey registration ceremony for a logged-in user.
pub(crate) struct PendingReg {
    pub user_id: i64,
    pub state: webauthn_rs::prelude::PasskeyRegistration,
    pub created: Instant,
}

pub(crate) struct AuthState {
    pub db: Arc<AuthDb>,
    /// None when no usable origin could be configured.
    pub webauthn: Option<webauthn_rs::Webauthn>,
    pub pending_logins: Mutex<HashMap<String, PendingLogin>>,
    pub pending_regs: Mutex<HashMap<String, PendingReg>>,
}

/// Who is making this request, resolved by the auth middleware.
#[derive(Clone)]
pub(crate) struct AuthCtx {
    pub user: User,
    /// True for cookie sessions (web UI); false for Bearer API tokens.
    /// Account and admin endpoints require a session — API tokens are for
    /// the symbol-store API only.
    pub via_session: bool,
}

pub(crate) struct AppState {
    pub(crate) store: Store,
    index: RwLock<Arc<StoreIndex>>,
    scan: Mutex<ScanSlot>,
    jobs: Mutex<Vec<Arc<Job>>>,
    next_job_id: AtomicU64,
    /// Bumped whenever the index reloads; clients refetch when it changes.
    generation: AtomicU64,
    /// Set on Ctrl-C so long-lived SSE streams end and graceful shutdown
    /// can actually complete.
    shutdown: AtomicBool,
    /// When we last mutated 000Admin ourselves — lets the external-change
    /// watcher skip changes we already reacted to.
    last_self_mutation: Mutex<Option<Instant>>,
    /// Present when `--auth-db` was given; None means the server is open.
    pub(crate) auth: Option<Arc<AuthState>>,
    /// Trusted reverse-proxy hop count for X-Forwarded-For / -Proto.
    pub(crate) trusted_proxies: usize,
    /// Upstream symbol servers tried (in order) on /symbols misses.
    pub(crate) upstreams: Vec<String>,
    pub(crate) http_client: reqwest::Client,
}

pub(crate) type App = Arc<AppState>;

pub(crate) struct ApiError(pub StatusCode, pub String);

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        (self.0, Json(json!({ "error": self.1 }))).into_response()
    }
}

impl From<anyhow::Error> for ApiError {
    fn from(e: anyhow::Error) -> Self {
        ApiError(StatusCode::INTERNAL_SERVER_ERROR, format!("{e:#}"))
    }
}

impl From<symfront_core::Error> for ApiError {
    fn from(e: symfront_core::Error) -> Self {
        let code = match &e {
            symfront_core::Error::TxNotFound(_) => StatusCode::NOT_FOUND,
            symfront_core::Error::TxNotActive(..) | symfront_core::Error::Refused(_) => {
                StatusCode::CONFLICT
            }
            symfront_core::Error::Locked => StatusCode::LOCKED,
            _ => StatusCode::INTERNAL_SERVER_ERROR,
        };
        ApiError(code, e.to_string())
    }
}

type ApiResult<T> = std::result::Result<T, ApiError>;

fn reload_index(state: &App) -> symfront_core::Result<Arc<StoreIndex>> {
    let index = Arc::new(StoreIndex::load(&state.store)?);
    *state.index.write().unwrap() = Arc::clone(&index);
    state.generation.fetch_add(1, Ordering::Relaxed);
    Ok(index)
}

fn spawn_scan(state: App) {
    let progress = {
        let mut slot = state.scan.lock().unwrap();
        if slot.running.is_some() {
            return;
        }
        let progress = Arc::new(ScanProgress::default());
        slot.running = Some(Arc::clone(&progress));
        slot.error = None;
        progress
    };
    std::thread::spawn(move || {
        let index = Arc::clone(&state.index.read().unwrap());
        let outcome = scan::scan(&state.store, true, &progress);
        let mut slot = state.scan.lock().unwrap();
        slot.running = None;
        match outcome {
            Ok(scan) => {
                let analysis = strays::analyze(&index, &scan);
                let deep_findings = check::check_deep(&index, &scan);
                slot.result = Some(Arc::new(ScanBundle {
                    totals: scan.total,
                    admin: scan.admin,
                    payload: scan.payload,
                    scanned_at: scan.scanned_at,
                    duration_ms: scan.duration_ms,
                    strays: analysis.strays,
                    tx_sizes: analysis.tx_sizes,
                    tx_issues: analysis.tx_issues,
                    deep_findings,
                }));
                drop(slot);
                // New analysis affects tx list badges etc.
                state.generation.fetch_add(1, Ordering::Relaxed);
            }
            Err(e) => {
                slot.error = Some(e.to_string());
            }
        }
    });
}

/// Run a mutation as a background job. Returns the job id immediately.
fn spawn_job(
    state: App,
    kind: &'static str,
    target: String,
    work: impl FnOnce(&OpProgress) -> symfront_core::Result<serde_json::Value> + Send + 'static,
) -> u64 {
    let id = state.next_job_id.fetch_add(1, Ordering::Relaxed);
    let job = Arc::new(Job {
        id,
        kind,
        target,
        progress: OpProgress::default(),
        state: Mutex::new(JobState::Running),
        finished_at: Mutex::new(None),
    });
    state.jobs.lock().unwrap().push(Arc::clone(&job));
    std::thread::spawn(move || {
        *state.last_self_mutation.lock().unwrap() = Some(Instant::now());
        let result = work(&job.progress);
        *state.last_self_mutation.lock().unwrap() = Some(Instant::now());
        *job.state.lock().unwrap() = match result {
            Ok(v) => JobState::Done(v),
            Err(e) => JobState::Failed(e.to_string()),
        };
        *job.finished_at.lock().unwrap() = Some(SystemTime::now());
        // The store changed (or might have, even on failure): refresh
        // everything so every connected client converges on reality.
        if let Err(e) = reload_index(&state) {
            tracing::error!("index reload after job {id} failed: {e}");
        }
        state.scan.lock().unwrap().result = None;
        spawn_scan(state);
    });
    id
}

/// Watch `000Admin/` (one inotify watch — the payload tree would need one per
/// hash dir) for changes made by other tools, e.g. `symstore.exe` over SMB.
/// Every transaction commit writes there, so this is the reliable signal; a
/// still-running external add just shows as strays until its commit lands.
fn spawn_admin_watcher(state: App) -> anyhow::Result<notify::RecommendedWatcher> {
    use notify::Watcher;
    let (tx, rx) = std::sync::mpsc::channel::<()>();
    let mut watcher =
        notify::recommended_watcher(move |res: notify::Result<notify::Event>| {
            let Ok(ev) = res else { return };
            // Reads don't change anything — and our own index reloads/scans
            // read these files, so reacting to Access events would loop.
            if matches!(ev.kind, notify::EventKind::Access(_)) {
                return;
            }
            // Ignore our own scratch files (lock, temp rewrites, journals).
            let only_ours = !ev.paths.is_empty()
                && ev.paths.iter().all(|p| {
                    p.file_name()
                        .map(|n| {
                            let n = n.to_string_lossy();
                            n.starts_with(".symfront") || n.starts_with(ops::JOURNAL_PREFIX)
                        })
                        .unwrap_or(false)
                });
            if !only_ours {
                let _ = tx.send(());
            }
        })?;
    let admin = state.store.admin_dir();
    watcher.watch(&admin, notify::RecursiveMode::NonRecursive)?;
    tracing::info!("watching {} for external changes", admin.display());
    std::thread::spawn(move || {
        while rx.recv().is_ok() {
            // Debounce: wait for 1.5 s of quiet so we react once per burst.
            while rx.recv_timeout(Duration::from_millis(1500)).is_ok() {}
            if state.shutdown.load(Ordering::Relaxed) {
                break;
            }
            // Our own mutations already reload + rescan; skip the echo.
            let own = state
                .last_self_mutation
                .lock()
                .unwrap()
                .map(|t| t.elapsed() < Duration::from_secs(5))
                .unwrap_or(false);
            if own {
                continue;
            }
            tracing::info!("000Admin changed externally; reloading index and rescanning");
            match reload_index(&state) {
                Ok(_) => spawn_scan(Arc::clone(&state)),
                Err(e) => tracing::error!("index reload after external change failed: {e}"),
            }
        }
    });
    Ok(watcher)
}

/// The requester's IP for audit logs, resolved by the middleware.
#[derive(Clone)]
pub(crate) struct ClientIp(pub String);

/// Whether the (trusted) reverse proxy says the outer connection is TLS —
/// controls the session cookie's `Secure` flag.
pub(crate) fn forwarded_https(state: &AppState, headers: &HeaderMap) -> bool {
    state.trusted_proxies > 0
        && headers
            .get("x-forwarded-proto")
            .and_then(|v| v.to_str().ok())
            .map(|v| v.trim().eq_ignore_ascii_case("https"))
            .unwrap_or(false)
}

/// Real client IP. With N trusted proxy hops, the rightmost N entries of
/// X-Forwarded-For were appended by proxies we control; the client is the
/// entry just inside that suffix. Anything further left is client-supplied
/// and untrusted, so we never look past the cap. With no trusted proxies the
/// header is ignored entirely and the TCP peer address is used.
fn resolve_client_ip(state: &AppState, peer: Option<SocketAddr>, headers: &HeaderMap) -> String {
    if state.trusted_proxies > 0 {
        if let Some(xff) = headers
            .get("x-forwarded-for")
            .and_then(|v| v.to_str().ok())
        {
            let entries: Vec<&str> = xff.split(',').map(|s| s.trim()).collect();
            if !entries.is_empty() {
                let idx = entries.len().saturating_sub(state.trusted_proxies);
                return entries[idx].to_string();
            }
        }
    }
    peer.map(|p| p.ip().to_string())
        .unwrap_or_else(|| "unknown".into())
}

/// Resolve the requesting user from `Authorization: Bearer` (API tokens) or
/// the session cookie (web UI). None when unauthenticated.
fn request_user(state: &AppState, headers: &HeaderMap) -> Option<AuthCtx> {
    let auth = state.auth.as_ref()?;
    if let Some(v) = headers
        .get(header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
    {
        if let Some(token) = v.strip_prefix("Bearer ") {
            if let Some(user) = auth.db.auth_token(token.trim()) {
                return Some(AuthCtx {
                    user,
                    via_session: false,
                });
            }
        }
    }
    if let Some(cookies) = headers.get(header::COOKIE).and_then(|v| v.to_str().ok()) {
        for c in cookies.split(';') {
            if let Some(v) = c.trim().strip_prefix("symfront_session=") {
                if let Some(user) = auth.db.auth_session(v) {
                    return Some(AuthCtx {
                        user,
                        via_session: true,
                    });
                }
            }
        }
    }
    None
}

async fn auth_middleware(State(state): State<App>, mut req: Request, next: Next) -> Response {
    let peer = req
        .extensions()
        .get::<axum::extract::ConnectInfo<SocketAddr>>()
        .map(|c| c.0);
    let ip = resolve_client_ip(&state, peer, req.headers());
    req.extensions_mut().insert(ClientIp(ip.clone()));
    if state.auth.is_none() {
        return next.run(req).await;
    }
    let path = req.uri().path().to_string();
    // The SPA shell, the login flows, "who am I", and public symbol serving
    // are reachable unauthenticated.
    if path == "/"
        || path == "/api/me"
        || path == "/api/login"
        || path.starts_with("/api/login/")
        || path.starts_with("/symbols/")
    {
        return next.run(req).await;
    }
    let Some(ctx) = request_user(&state, req.headers()) else {
        return (
            StatusCode::UNAUTHORIZED,
            Json(json!({ "error": "authentication required" })),
        )
            .into_response();
    };
    // Account and admin management require a web session: API tokens are
    // scoped to the symbol-store API and grant no account access.
    if path.starts_with("/api/account") || path.starts_with("/api/admin") {
        if !ctx.via_session {
            return (
                StatusCode::FORBIDDEN,
                Json(json!({ "error": "API tokens cannot manage accounts; sign in to the web UI" })),
            )
                .into_response();
        }
        if path.starts_with("/api/admin") && ctx.user.role != Role::Admin {
            return (
                StatusCode::FORBIDDEN,
                Json(json!({ "error": "admin role required" })),
            )
                .into_response();
        }
    } else {
        let mutating = req.method() == Method::DELETE
            || (req.method() == Method::POST && path != "/api/logout");
        if mutating && !ctx.user.role.can_mutate() {
            return (
                StatusCode::FORBIDDEN,
                Json(json!({ "error": format!("role '{}' is read-only", ctx.user.role) })),
            )
                .into_response();
        }
    }
    req.extensions_mut().insert(ctx);
    next.run(req).await
}

#[derive(Deserialize)]
struct LoginRequest {
    username: String,
    password: String,
}

async fn login(
    State(state): State<App>,
    axum::Extension(ClientIp(ip)): axum::Extension<ClientIp>,
    headers: HeaderMap,
    Json(req): Json<LoginRequest>,
) -> ApiResult<Response> {
    let Some(auth) = &state.auth else {
        return Err(ApiError(
            StatusCode::BAD_REQUEST,
            "authentication is not enabled".into(),
        ));
    };
    let db = Arc::clone(&auth.db);
    let username = req.username.clone();
    // argon2 verification is deliberately slow; keep it off the async threads.
    let user = tokio::task::spawn_blocking(move || {
        db.verify_password(&username, &req.password)
    })
    .await
    .map_err(|e| ApiError(StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))??;
    let Some(user) = user else {
        tracing::warn!("failed login for {:?} from {ip}", req.username);
        return Err(ApiError(
            StatusCode::UNAUTHORIZED,
            "invalid username or password".into(),
        ));
    };
    // Password OK. If the user enrolled TOTP, demand the code before a
    // session exists.
    if auth.db.totp_secret(user.id)?.is_some() {
        let login_token = {
            use rand_core::{OsRng, RngCore};
            let mut buf = [0u8; 24];
            OsRng.fill_bytes(&mut buf);
            buf.iter().map(|b| format!("{b:02x}")).collect::<String>()
        };
        auth.pending_logins.lock().unwrap().insert(
            login_token.clone(),
            PendingLogin::Totp {
                user_id: user.id,
                created: Instant::now(),
            },
        );
        return Ok(Json(json!({ "totp_required": true, "login_token": login_token }))
            .into_response());
    }
    web_account::issue_session(auth, &user, forwarded_https(&state, &headers), &ip)
}

async fn logout(State(state): State<App>, headers: HeaderMap) -> Response {
    if let (Some(auth), Some(cookies)) = (
        &state.auth,
        headers.get(header::COOKIE).and_then(|v| v.to_str().ok()),
    ) {
        for c in cookies.split(';') {
            if let Some(v) = c.trim().strip_prefix("symfront_session=") {
                auth.db.delete_session(v);
            }
        }
    }
    (
        [(
            header::SET_COOKIE,
            web_account::session_cookie("", 0, false),
        )],
        Json(json!({ "ok": true })),
    )
        .into_response()
}

async fn me(State(state): State<App>, headers: HeaderMap) -> Json<serde_json::Value> {
    match &state.auth {
        None => Json(json!({ "auth_enabled": false, "user": null })),
        Some(auth) => {
            let user = request_user(&state, &headers)
                .map(|c| json!({ "name": c.user.name, "role": c.user.role }));
            Json(json!({
                "auth_enabled": true,
                "user": user,
                "webauthn_available": auth.webauthn.is_some(),
            }))
        }
    }
}

#[tokio::main]
pub async fn serve(
    store_path: PathBuf,
    listen: String,
    auth_db: Option<PathBuf>,
    webauthn_origin: Option<String>,
    trusted_proxies: usize,
    serve_symbols: bool,
    upstreams: Vec<String>,
) -> anyhow::Result<()> {
    let auth = match &auth_db {
        Some(path) => {
            let db = AuthDb::open(path)?;
            if db.list_users()?.is_empty() {
                tracing::warn!(
                    "auth enabled but {} has no users — nobody can log in; create one with `symfront user add`",
                    path.display()
                );
            }
            // Passkeys only work in secure contexts: localhost over http, or
            // anything behind an https-terminating proxy with a matching
            // --webauthn-origin.
            let origin_str = webauthn_origin.clone().unwrap_or_else(|| {
                let port = listen.rsplit(':').next().unwrap_or("8710");
                format!("http://localhost:{port}")
            });
            let webauthn = (|| -> anyhow::Result<webauthn_rs::Webauthn> {
                let origin = webauthn_rs::prelude::Url::parse(&origin_str)?;
                let rp_id = origin
                    .host_str()
                    .ok_or_else(|| anyhow::anyhow!("origin has no host"))?
                    .to_string();
                Ok(webauthn_rs::WebauthnBuilder::new(&rp_id, &origin)?
                    .rp_name("symfront")
                    .build()?)
            })();
            let webauthn = match webauthn {
                Ok(w) => {
                    tracing::info!("webauthn enabled for origin {origin_str}");
                    Some(w)
                }
                Err(e) => {
                    tracing::warn!("webauthn disabled: {e} (origin {origin_str})");
                    None
                }
            };
            tracing::info!("authentication enabled ({})", path.display());
            Some(Arc::new(AuthState {
                db: Arc::new(db),
                webauthn,
                pending_logins: Mutex::new(HashMap::new()),
                pending_regs: Mutex::new(HashMap::new()),
            }))
        }
        None => None,
    };
    if trusted_proxies > 0 {
        tracing::info!(
            "trusting {trusted_proxies} reverse-proxy hop(s) for X-Forwarded-For / X-Forwarded-Proto"
        );
    }
    let store = Store::open(&store_path)?;
    tracing::info!("loading index for {}", store.root().display());
    let index = Arc::new(StoreIndex::load(&store)?);
    tracing::info!(
        "index loaded: {} transactions, {} entries",
        index.transactions.len(),
        index.entries.len()
    );
    let state: App = Arc::new(AppState {
        store,
        index: RwLock::new(index),
        scan: Mutex::new(ScanSlot::default()),
        jobs: Mutex::new(Vec::new()),
        next_job_id: AtomicU64::new(1),
        generation: AtomicU64::new(1),
        shutdown: AtomicBool::new(false),
        last_self_mutation: Mutex::new(None),
        auth,
        trusted_proxies,
        upstreams: if serve_symbols { upstreams } else { Vec::new() },
        http_client: reqwest::Client::builder()
            .redirect(reqwest::redirect::Policy::limited(4))
            .build()?,
    });
    spawn_scan(Arc::clone(&state));
    // Keep the watcher alive for the whole server lifetime.
    let _watcher = match spawn_admin_watcher(Arc::clone(&state)) {
        Ok(w) => Some(w),
        Err(e) => {
            tracing::warn!("external-change watching unavailable: {e}");
            None
        }
    };

    let mut app = Router::new()
        .route("/", get(|| async { Html(include_str!("ui/index.html")) }));
    if serve_symbols {
        tracing::info!(
            "serving symbols at /symbols/ (public read-only){}",
            if state.upstreams.is_empty() {
                String::new()
            } else {
                format!(", forwarding misses to {}", state.upstreams.join(", "))
            }
        );
        app = app.route("/symbols/{*path}", get(crate::symbols::serve_symbol));
    }
    let app = app
        .route("/api/summary", get(summary))
        .route("/api/events", get(events))
        .route("/api/transactions", get(tx_list))
        .route("/api/transactions/{id}", get(tx_detail))
        .route("/api/transactions/{id}", delete(tx_delete))
        .route("/api/search", get(search))
        .route("/api/strays", get(strays_report))
        .route("/api/strays/prune", post(prune))
        .route("/api/check", get(check_endpoint))
        .route("/api/scan", post(rescan))
        .route("/api/login", post(login))
        .route("/api/login/totp", post(web_account::login_totp))
        .route("/api/login/webauthn/start", post(web_account::login_webauthn_start))
        .route("/api/login/webauthn/finish", post(web_account::login_webauthn_finish))
        .route("/api/logout", post(logout))
        .route("/api/me", get(me))
        .route("/api/account", get(web_account::account_overview))
        .route("/api/account/password", post(web_account::change_password))
        .route("/api/account/tokens", get(web_account::my_tokens))
        .route("/api/account/tokens", post(web_account::create_my_token))
        .route("/api/account/tokens/{id}", delete(web_account::revoke_my_token))
        .route("/api/account/totp/setup", post(web_account::totp_setup))
        .route("/api/account/totp/enable", post(web_account::totp_enable))
        .route("/api/account/totp/disable", post(web_account::totp_disable))
        .route("/api/account/passkeys", get(web_account::my_passkeys))
        .route("/api/account/passkeys/register/start", post(web_account::passkey_register_start))
        .route("/api/account/passkeys/register/finish", post(web_account::passkey_register_finish))
        .route("/api/account/passkeys/{id}", delete(web_account::passkey_delete))
        .route("/api/admin/users", get(web_account::admin_users))
        .route("/api/admin/users", post(web_account::admin_add_user))
        .route("/api/admin/users/{name}", delete(web_account::admin_delete_user))
        .route("/api/admin/users/{name}/role", post(web_account::admin_set_role))
        .route("/api/admin/users/{name}/password", post(web_account::admin_set_password))
        .route("/api/admin/users/{name}/reset-2fa", post(web_account::admin_reset_2fa))
        .layer(axum::middleware::from_fn_with_state(
            Arc::clone(&state),
            auth_middleware,
        ))
        .with_state(Arc::clone(&state));

    let addr: SocketAddr = listen.parse()?;
    tracing::info!("listening on http://{addr}");
    let listener = tokio::net::TcpListener::bind(addr).await?;
    let shutdown_state = Arc::clone(&state);
    axum::serve(
        listener,
        app.into_make_service_with_connect_info::<SocketAddr>(),
    )
        .with_graceful_shutdown(async move {
            let _ = tokio::signal::ctrl_c().await;
            tracing::info!("shutting down (Ctrl-C again to force)");
            // Flip the flag so SSE streams end at their next tick; otherwise
            // graceful shutdown would wait on them forever.
            shutdown_state.shutdown.store(true, Ordering::Relaxed);
            tokio::spawn(async {
                let _ = tokio::signal::ctrl_c().await;
                tracing::warn!("forcing exit");
                std::process::exit(130);
            });
        })
        .await?;
    // Let any in-flight mutation finish rather than dying mid-delete
    // (the journal would make it recoverable, but clean is better).
    loop {
        let running = state
            .jobs
            .lock()
            .unwrap()
            .iter()
            .filter(|j| matches!(*j.state.lock().unwrap(), JobState::Running))
            .count();
        if running == 0 {
            break;
        }
        tracing::info!("waiting for {running} running job(s) to finish (Ctrl-C to force)");
        tokio::time::sleep(Duration::from_millis(500)).await;
    }
    Ok(())
}

fn scan_status_json(state: &App) -> serde_json::Value {
    let slot = state.scan.lock().unwrap();
    if let Some(p) = &slot.running {
        return json!({
            "status": "running",
            "files": p.files.load(Ordering::Relaxed),
            "dirs": p.dirs.load(Ordering::Relaxed),
        });
    }
    if let Some(e) = &slot.error {
        return json!({ "status": "failed", "error": e });
    }
    match &slot.result {
        Some(b) => json!({
            "status": "done",
            "scanned_at": b.scanned_at,
            "duration_ms": b.duration_ms,
            "totals": b.totals,
            "admin": b.admin,
            "payload": b.payload,
        }),
        None => json!({ "status": "idle" }),
    }
}

fn state_snapshot(state: &App) -> serde_json::Value {
    // Drop jobs that finished a while ago so the list can't grow forever.
    let jobs_json: Vec<serde_json::Value> = {
        let mut jobs = state.jobs.lock().unwrap();
        jobs.retain(|j| match *j.finished_at.lock().unwrap() {
            Some(t) => t.elapsed().map(|e| e < Duration::from_secs(300)).unwrap_or(true),
            None => true,
        });
        jobs.iter().map(|j| j.to_json()).collect()
    };
    json!({
        "gen": state.generation.load(Ordering::Relaxed),
        "scan": scan_status_json(state),
        "jobs": jobs_json,
    })
}

/// SSE stream: a state snapshot every 750 ms. The stream ends when shutdown
/// is requested — otherwise open EventSource connections would block graceful
/// shutdown forever.
async fn events(
    State(state): State<App>,
) -> Sse<impl tokio_stream::Stream<Item = std::result::Result<Event, std::convert::Infallible>>> {
    let interval = tokio::time::interval(Duration::from_millis(750));
    let gate = Arc::clone(&state);
    let stream = tokio_stream::wrappers::IntervalStream::new(interval)
        .take_while(move |_| !gate.shutdown.load(Ordering::Relaxed))
        .map(move |_| Ok(Event::default().data(state_snapshot(&state).to_string())));
    Sse::new(stream).keep_alive(KeepAlive::default())
}

async fn summary(State(state): State<App>) -> ApiResult<Json<serde_json::Value>> {
    let index = Arc::clone(&state.index.read().unwrap());
    let journals = ops::pending_journals(&state.store)?;
    let active = index.active_transactions().count();
    let deleted = index
        .transactions
        .values()
        .filter(|t| !t.deleted_by.is_empty())
        .count();
    Ok(Json(json!({
        "store": state.store.root().to_string_lossy(),
        "lastid": index.lastid,
        "transactions_active": active,
        "transactions_deleted": deleted,
        "del_records": index.dels.len(),
        "entries": index.entries.len(),
        "referenced_dirs": index.referenced_dirs().len(),
        "pending_journals": journals,
        "scan": scan_status_json(&state),
        "gen": state.generation.load(Ordering::Relaxed),
    })))
}

async fn tx_list(State(state): State<App>) -> Json<serde_json::Value> {
    let index = Arc::clone(&state.index.read().unwrap());
    let (sizes, issues) = {
        let slot = state.scan.lock().unwrap();
        match &slot.result {
            Some(b) => (Some(b.tx_sizes.clone()), Some(b.tx_issues.clone())),
            None => (None, None),
        }
    };
    let rows: Vec<serde_json::Value> = index
        .transactions
        .values()
        .map(|t| {
            let s = sizes.as_ref().and_then(|m| m.get(&t.id)).copied();
            let i = issues.as_ref().and_then(|m| m.get(&t.id)).copied();
            json!({
                "id": t.id,
                "id_str": t.id.to_string(),
                "record": t.record,
                "deleted_by": t.deleted_by,
                "in_server_txt": t.in_server_txt,
                "file_state": t.file_state,
                "entry_count": t.entry_count,
                "active": t.is_active(),
                "sizes": s,
                "issues": i,
            })
        })
        .collect();
    Json(json!({ "transactions": rows, "have_scan": sizes.is_some() }))
}

async fn tx_detail(
    State(state): State<App>,
    AxPath(id): AxPath<u32>,
) -> ApiResult<Json<serde_json::Value>> {
    let id = TransactionId(id);
    let index = Arc::clone(&state.index.read().unwrap());
    let Some(t) = index.transactions.get(&id) else {
        return Err(symfront_core::Error::TxNotFound(id).into());
    };
    let t = t.clone();
    let store = state.store.clone();
    // Stat this transaction's dirs on demand (cheap: a few reads per entry).
    let (entries, sharing) = tokio::task::spawn_blocking(
        move || -> ApiResult<(Vec<serde_json::Value>, Vec<serde_json::Value>)> {
            let entries = symfront_core::index::load_entries(&store, id)?;
            // Set comparison: for each other transaction, how many of our
            // entries' hash dirs it also references.
            let mut share_counts: HashMap<TransactionId, u64> = HashMap::new();
            let rows = entries
                .iter()
                .map(|e| {
                    let dir = store.hash_dir(&e.name, &e.hash);
                    let (mut size, mut disk, mut files, mut found) = (0u64, 0u64, 0u64, false);
                    if let Ok(rd) = std::fs::read_dir(&dir) {
                        for ent in rd.flatten() {
                            if let Ok(md) = ent.metadata() {
                                if md.is_file() {
                                    use std::os::unix::fs::MetadataExt;
                                    size += md.len();
                                    disk += md.blocks() * 512;
                                    files += 1;
                                    found = true;
                                }
                            }
                        }
                    }
                    let mut shared_with: Vec<TransactionId> = index
                        .dir_refs(&e.name.to_lowercase(), &e.hash.to_lowercase())
                        .iter()
                        .map(|i| index.entries[*i as usize].tx)
                        .filter(|tx| *tx != id)
                        .collect();
                    shared_with.sort();
                    shared_with.dedup();
                    for tx in &shared_with {
                        *share_counts.entry(*tx).or_default() += 1;
                    }
                    json!({
                        "name": e.name,
                        "hash": e.hash,
                        "source": e.source,
                        "present": found,
                        "files": files,
                        "apparent": size,
                        "disk": disk,
                        "shared_with": shared_with,
                    })
                })
                .collect();
            let mut sharing: Vec<(TransactionId, u64)> = share_counts.into_iter().collect();
            sharing.sort_by(|a, b| b.1.cmp(&a.1).then(a.0.cmp(&b.0)));
            let sharing = sharing
                .into_iter()
                .map(|(tx, count)| {
                    let rec = index.transactions.get(&tx).and_then(|t| t.record.as_ref());
                    json!({
                        "tx": tx,
                        "id_str": tx.to_string(),
                        "product": rec.map(|r| r.product.clone()),
                        "version": rec.map(|r| r.version.clone()),
                        "date": rec.map(|r| r.date.clone()),
                        "shared_entries": count,
                    })
                })
                .collect();
            Ok((rows, sharing))
        },
    )
    .await
    .map_err(|e| ApiError(StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))??;

    let issues = state
        .scan
        .lock()
        .unwrap()
        .result
        .as_ref()
        .and_then(|b| b.tx_issues.get(&id).copied());
    Ok(Json(json!({
        "id": t.id,
        "id_str": t.id.to_string(),
        "record": t.record,
        "deleted_by": t.deleted_by,
        "in_server_txt": t.in_server_txt,
        "file_state": t.file_state,
        "active": t.is_active(),
        "entries": entries,
        "sharing": sharing,
        "issues": issues,
    })))
}

#[derive(Deserialize)]
struct DeleteParams {
    #[serde(default)]
    dry_run: bool,
}

async fn tx_delete(
    State(state): State<App>,
    AxPath(id): AxPath<u32>,
    Query(params): Query<DeleteParams>,
    axum::Extension(ClientIp(ip)): axum::Extension<ClientIp>,
    ctx: Option<axum::Extension<AuthCtx>>,
) -> ApiResult<Response> {
    let id = TransactionId(id);
    if !params.dry_run {
        let who = ctx
            .as_ref()
            .map(|c| c.user.name.as_str())
            .unwrap_or("<open server>");
        tracing::info!("delete of transaction {id} requested by {who} from {ip}");
    }
    if params.dry_run {
        // Dry runs are read-only and fast: run them synchronously.
        let store = state.store.clone();
        let outcome = tokio::task::spawn_blocking(move || {
            ops::delete_transaction(&store, id, true, &OpProgress::default())
        })
        .await
        .map_err(|e| ApiError(StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))??;
        return Ok(Json(serde_json::to_value(&outcome).unwrap()).into_response());
    }
    // Cheap validation up front so obvious errors are synchronous.
    {
        let index = state.index.read().unwrap();
        match index.transactions.get(&id) {
            None => return Err(symfront_core::Error::TxNotFound(id).into()),
            Some(t) if !t.is_active() => {
                return Err(
                    symfront_core::Error::TxNotActive(id, "not an active transaction".into())
                        .into(),
                )
            }
            _ => {}
        }
    }
    let store = state.store.clone();
    let job = spawn_job(
        Arc::clone(&state),
        "delete",
        id.to_string(),
        move |progress| {
            let outcome = ops::delete_transaction(&store, id, false, progress)?;
            Ok(serde_json::to_value(&outcome).unwrap())
        },
    );
    Ok((StatusCode::ACCEPTED, Json(json!({ "job": job }))).into_response())
}

#[derive(Deserialize)]
struct SearchParams {
    q: String,
    #[serde(default = "default_limit")]
    limit: usize,
}

fn default_limit() -> usize {
    200
}

async fn search(
    State(state): State<App>,
    Query(params): Query<SearchParams>,
) -> Json<serde_json::Value> {
    let index = Arc::clone(&state.index.read().unwrap());
    let hits = index.search(&params.q, params.limit.min(2000));
    Json(json!({ "hits": hits, "limited": hits.len() >= params.limit.min(2000) }))
}

async fn strays_report(State(state): State<App>) -> ApiResult<Json<serde_json::Value>> {
    let slot = state.scan.lock().unwrap();
    match &slot.result {
        Some(b) => Ok(Json(json!({
            "strays": b.strays,
            "scanned_at": b.scanned_at,
        }))),
        None => Err(ApiError(
            StatusCode::SERVICE_UNAVAILABLE,
            "scan not finished yet".into(),
        )),
    }
}

#[derive(Deserialize)]
struct PruneRequest {
    #[serde(default)]
    paths: Vec<String>,
    /// Prune everything in the current stray report.
    #[serde(default)]
    all: bool,
    #[serde(default)]
    dry_run: bool,
}

async fn prune(
    State(state): State<App>,
    axum::Extension(ClientIp(ip)): axum::Extension<ClientIp>,
    ctx: Option<axum::Extension<AuthCtx>>,
    Json(req): Json<PruneRequest>,
) -> ApiResult<Response> {
    if !req.dry_run {
        let who = ctx
            .as_ref()
            .map(|c| c.user.name.as_str())
            .unwrap_or("<open server>");
        tracing::info!("stray prune requested by {who} from {ip}");
    }
    let paths = if req.all {
        let slot = state.scan.lock().unwrap();
        match &slot.result {
            Some(b) => b.strays.strays.iter().map(|s| s.rel_path.clone()).collect(),
            None => {
                return Err(ApiError(
                    StatusCode::SERVICE_UNAVAILABLE,
                    "scan not finished yet".into(),
                ))
            }
        }
    } else {
        req.paths
    };
    if paths.is_empty() {
        return Err(ApiError(StatusCode::BAD_REQUEST, "no paths given".into()));
    }
    if req.dry_run {
        let store = state.store.clone();
        let outcome = tokio::task::spawn_blocking(move || {
            ops::prune_strays(&store, &paths, true, &OpProgress::default())
        })
        .await
        .map_err(|e| ApiError(StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))??;
        return Ok(Json(serde_json::to_value(&outcome).unwrap()).into_response());
    }
    let store = state.store.clone();
    let count = paths.len();
    let job = spawn_job(
        Arc::clone(&state),
        "prune",
        format!("{count} stray paths"),
        move |progress| {
            let outcome = ops::prune_strays(&store, &paths, false, progress)?;
            Ok(serde_json::to_value(&outcome).unwrap())
        },
    );
    Ok((StatusCode::ACCEPTED, Json(json!({ "job": job }))).into_response())
}

async fn check_endpoint(State(state): State<App>) -> ApiResult<Json<serde_json::Value>> {
    let index = Arc::clone(&state.index.read().unwrap());
    let store = state.store.clone();
    let admin = tokio::task::spawn_blocking(move || check::check_admin(&store, &index))
        .await
        .map_err(|e| ApiError(StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))??;
    let (deep, missing) = {
        let slot = state.scan.lock().unwrap();
        match &slot.result {
            Some(b) => (
                Some(b.deep_findings.clone()),
                Some(b.strays.missing.clone()),
            ),
            None => (None, None),
        }
    };
    Ok(Json(json!({
        "admin": admin,
        "deep": deep,
        "missing_payloads": missing,
    })))
}

async fn rescan(State(state): State<App>) -> ApiResult<Json<serde_json::Value>> {
    reload_index(&state)?;
    spawn_scan(Arc::clone(&state));
    Ok(Json(json!({ "started": true })))
}
