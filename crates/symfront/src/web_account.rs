//! Login flows (password + TOTP, WebAuthn), self-service account management,
//! and the admin user-management API.
//!
//! All endpoints here require a *session* (web UI) — Bearer API tokens are
//! deliberately limited to the symbol-store API and cannot manage accounts.

use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use axum::extract::{Path as AxPath, State};
use axum::http::{header, HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::{Extension, Json};
use serde::Deserialize;
use serde_json::json;
use webauthn_rs::prelude::{
    Passkey, PublicKeyCredential, RegisterPublicKeyCredential, Uuid,
};

use crate::auth::{Role, SESSION_TTL};
use crate::totp;
use crate::web::{App, ApiError, AuthCtx, AuthState, PendingLogin, PendingReg};

type ApiResult<T> = std::result::Result<T, ApiError>;

const PENDING_TTL: Duration = Duration::from_secs(300);

fn err(code: StatusCode, msg: impl Into<String>) -> ApiError {
    ApiError(code, msg.into())
}

fn auth_state(state: &App) -> ApiResult<&Arc<AuthState>> {
    state
        .auth
        .as_ref()
        .ok_or_else(|| err(StatusCode::BAD_REQUEST, "authentication is not enabled"))
}

/// Account/admin endpoints require a cookie session, enforced by the
/// middleware; the extension is absent only when auth is disabled.
fn session_user(ctx: &Option<Extension<AuthCtx>>) -> ApiResult<&AuthCtx> {
    match ctx {
        Some(Extension(c)) => Ok(c),
        None => Err(err(StatusCode::BAD_REQUEST, "authentication is not enabled")),
    }
}

fn unix_now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

fn random_token() -> String {
        let mut buf = [0u8; 24];
    getrandom::fill(&mut buf).expect("OS RNG");
    buf.iter().map(|b| format!("{b:02x}")).collect()
}

fn prune_pending(auth: &AuthState) {
    auth.pending_logins.lock().unwrap().retain(|_, p| {
        let created = match p {
            PendingLogin::Totp { created, .. } => created,
            PendingLogin::WebAuthn { created, .. } => created,
        };
        created.elapsed() < PENDING_TTL
    });
    auth.pending_regs
        .lock()
        .unwrap()
        .retain(|_, p| p.created.elapsed() < PENDING_TTL);
}

/// Session cookie; `Secure` when the trusted proxy says the outer hop is TLS.
pub(crate) fn session_cookie(value: &str, max_age: u64, secure: bool) -> String {
    format!(
        "symfront_session={value}; Path=/; HttpOnly; SameSite=Lax; Max-Age={max_age}{}",
        if secure { "; Secure" } else { "" }
    )
}

pub(crate) fn issue_session(
    auth: &AuthState,
    user: &crate::auth::User,
    secure: bool,
    ip: &str,
) -> ApiResult<Response> {
    let session = auth.db.create_session(user.id)?;
    tracing::info!("user {} logged in from {ip}", user.name);
    Ok((
        [(
            header::SET_COOKIE,
            session_cookie(&session, SESSION_TTL.as_secs(), secure),
        )],
        Json(json!({ "user": user.name, "role": user.role })),
    )
        .into_response())
}

// ---------- login: TOTP second step ----------

#[derive(Deserialize)]
pub(crate) struct TotpLoginRequest {
    login_token: String,
    code: String,
}

pub(crate) async fn login_totp(
    State(state): State<App>,
    Extension(crate::web::ClientIp(ip)): Extension<crate::web::ClientIp>,
    headers: HeaderMap,
    Json(req): Json<TotpLoginRequest>,
) -> ApiResult<Response> {
    let auth = auth_state(&state)?;
    prune_pending(auth);
    let user_id = {
        let mut pending = auth.pending_logins.lock().unwrap();
        match pending.get(&req.login_token) {
            Some(PendingLogin::Totp { user_id, .. }) => {
                let id = *user_id;
                // Consume the token regardless of code validity: each
                // password check buys at most one TOTP attempt.
                pending.remove(&req.login_token);
                id
            }
            _ => {
                return Err(err(
                    StatusCode::UNAUTHORIZED,
                    "login expired; start again",
                ))
            }
        }
    };
    let secret = auth
        .db
        .totp_secret(user_id)?
        .ok_or_else(|| err(StatusCode::UNAUTHORIZED, "login expired; start again"))?;
    if !totp::verify(&secret, &req.code, unix_now()) {
        tracing::warn!("failed TOTP for user id {user_id} from {ip}");
        return Err(err(StatusCode::UNAUTHORIZED, "incorrect code"));
    }
    let user = auth
        .db
        .user_by_id(user_id)?
        .ok_or_else(|| err(StatusCode::UNAUTHORIZED, "user no longer exists"))?;
    issue_session(auth, &user, crate::web::forwarded_https(&state, &headers), &ip)
}

// ---------- login: WebAuthn ----------

#[derive(Deserialize)]
pub(crate) struct WebAuthnStartRequest {
    username: String,
}

pub(crate) async fn login_webauthn_start(
    State(state): State<App>,
    Json(req): Json<WebAuthnStartRequest>,
) -> ApiResult<Json<serde_json::Value>> {
    let auth = auth_state(&state)?;
    prune_pending(auth);
    let webauthn = auth.webauthn.as_ref().ok_or_else(|| {
        err(StatusCode::BAD_REQUEST, "webauthn is not configured on this server")
    })?;
    let Some(user) = auth.db.user_by_name(&req.username)? else {
        return Err(err(StatusCode::UNAUTHORIZED, "no passkeys registered"));
    };
    let passkeys: Vec<Passkey> = auth
        .db
        .passkey_creds(user.id)?
        .iter()
        .filter_map(|(_, json)| serde_json::from_str(json).ok())
        .collect();
    if passkeys.is_empty() {
        return Err(err(StatusCode::UNAUTHORIZED, "no passkeys registered"));
    }
    let (rcr, auth_state_) = webauthn
        .start_passkey_authentication(&passkeys)
        .map_err(|e| err(StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
    let login_token = random_token();
    auth.pending_logins.lock().unwrap().insert(
        login_token.clone(),
        PendingLogin::WebAuthn {
            state: auth_state_,
            created: Instant::now(),
        },
    );
    Ok(Json(json!({ "login_token": login_token, "challenge": rcr })))
}

#[derive(Deserialize)]
pub(crate) struct WebAuthnFinishRequest {
    login_token: String,
    credential: PublicKeyCredential,
}

pub(crate) async fn login_webauthn_finish(
    State(state): State<App>,
    Extension(crate::web::ClientIp(ip)): Extension<crate::web::ClientIp>,
    headers: HeaderMap,
    Json(req): Json<WebAuthnFinishRequest>,
) -> ApiResult<Response> {
    let auth = auth_state(&state)?;
    let webauthn = auth.webauthn.as_ref().ok_or_else(|| {
        err(StatusCode::BAD_REQUEST, "webauthn is not configured on this server")
    })?;
    let ceremony = {
        let mut pending = auth.pending_logins.lock().unwrap();
        match pending.remove(&req.login_token) {
            Some(PendingLogin::WebAuthn { state, .. }) => state,
            _ => return Err(err(StatusCode::UNAUTHORIZED, "login expired; start again")),
        }
    };
    let result = webauthn
        .finish_passkey_authentication(&req.credential, &ceremony)
        .map_err(|e| err(StatusCode::UNAUTHORIZED, format!("passkey rejected: {e}")))?;
    // Find the matching stored credential, bump its counter, identify the user.
    for (pk_id, user_id, json) in auth.db.all_passkey_creds()? {
        let Ok(mut pk) = serde_json::from_str::<Passkey>(&json) else {
            continue;
        };
        if pk.cred_id() == result.cred_id() {
            pk.update_credential(&result);
            let _ = auth
                .db
                .passkey_update_cred(pk_id, &serde_json::to_string(&pk).unwrap());
            let user = auth
                .db
                .user_by_id(user_id)?
                .ok_or_else(|| err(StatusCode::UNAUTHORIZED, "user no longer exists"))?;
            return issue_session(
                auth,
                &user,
                crate::web::forwarded_https(&state, &headers),
                &ip,
            );
        }
    }
    Err(err(StatusCode::UNAUTHORIZED, "unknown credential"))
}

// ---------- account: password ----------

#[derive(Deserialize)]
pub(crate) struct ChangePasswordRequest {
    #[serde(default)]
    current_password: String,
    new_password: String,
}

pub(crate) async fn change_password(
    State(state): State<App>,
    ctx: Option<Extension<AuthCtx>>,
    Json(req): Json<ChangePasswordRequest>,
) -> ApiResult<Json<serde_json::Value>> {
    let auth = auth_state(&state)?;
    let ctx = session_user(&ctx)?.clone();
    if req.new_password.len() < 8 {
        return Err(err(StatusCode::BAD_REQUEST, "new password must be at least 8 characters"));
    }
    let db = Arc::clone(&auth.db);
    let (name, user_id) = (ctx.user.name.clone(), ctx.user.id);
    let current = req.current_password.clone();
    let ok = tokio::task::spawn_blocking(move || -> anyhow::Result<bool> {
        if db.has_password(user_id)? {
            Ok(db.verify_password(&name, &current)?.is_some())
        } else {
            Ok(true) // first password on a token-only account
        }
    })
    .await
    .map_err(|e| err(StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))??;
    if !ok {
        return Err(err(StatusCode::FORBIDDEN, "current password is incorrect"));
    }
    auth.db.set_password(&ctx.user.name, &req.new_password)?;
    tracing::info!("user {} changed their password", ctx.user.name);
    Ok(Json(json!({ "ok": true })))
}

// ---------- account: API tokens ----------

pub(crate) async fn my_tokens(
    State(state): State<App>,
    ctx: Option<Extension<AuthCtx>>,
) -> ApiResult<Json<serde_json::Value>> {
    let auth = auth_state(&state)?;
    let ctx = session_user(&ctx)?;
    let tokens = auth.db.list_tokens(Some(ctx.user.id))?;
    Ok(Json(json!({ "tokens": tokens })))
}

#[derive(Deserialize)]
pub(crate) struct CreateTokenRequest {
    #[serde(default)]
    label: String,
    cap: Role,
}

pub(crate) async fn create_my_token(
    State(state): State<App>,
    ctx: Option<Extension<AuthCtx>>,
    Extension(crate::web::ClientIp(ip)): Extension<crate::web::ClientIp>,
    Json(req): Json<CreateTokenRequest>,
) -> ApiResult<Json<serde_json::Value>> {
    let auth = auth_state(&state)?;
    let ctx = session_user(&ctx)?;
    // Tokens are ro or rw only, and never exceed the owner's role.
    let cap = req.cap.min(Role::Rw).min(ctx.user.role);
    let token = auth.db.create_token(&ctx.user.name, &req.label, cap)?;
    tracing::info!(
        "user {} created a {cap} API token ({:?}) from {ip}",
        ctx.user.name,
        req.label,
    );
    Ok(Json(json!({ "token": token, "cap": cap })))
}

pub(crate) async fn revoke_my_token(
    State(state): State<App>,
    ctx: Option<Extension<AuthCtx>>,
    AxPath(id): AxPath<i64>,
) -> ApiResult<Json<serde_json::Value>> {
    let auth = auth_state(&state)?;
    let ctx = session_user(&ctx)?;
    auth.db.revoke_token(id, Some(ctx.user.id))?;
    Ok(Json(json!({ "ok": true })))
}

// ---------- account: TOTP ----------

pub(crate) async fn totp_setup(
    State(state): State<App>,
    ctx: Option<Extension<AuthCtx>>,
) -> ApiResult<Json<serde_json::Value>> {
    let _auth = auth_state(&state)?;
    let ctx = session_user(&ctx)?;
    let secret = totp::generate_secret();
    let url = totp::otpauth_url(&ctx.user.name, &secret);
    let qr_svg = qrcode::QrCode::new(url.as_bytes())
        .map(|code| {
            code.render::<qrcode::render::svg::Color>()
                .min_dimensions(180, 180)
                .quiet_zone(true)
                .build()
        })
        .map_err(|e| err(StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
    Ok(Json(json!({ "secret": secret, "otpauth_url": url, "qr_svg": qr_svg })))
}

#[derive(Deserialize)]
pub(crate) struct TotpEnableRequest {
    secret: String,
    code: String,
}

pub(crate) async fn totp_enable(
    State(state): State<App>,
    ctx: Option<Extension<AuthCtx>>,
    Json(req): Json<TotpEnableRequest>,
) -> ApiResult<Json<serde_json::Value>> {
    let auth = auth_state(&state)?;
    let ctx = session_user(&ctx)?;
    let decoded = totp::base32_decode(&req.secret);
    if decoded.as_ref().map(|d| d.len() < 10).unwrap_or(true) {
        return Err(err(StatusCode::BAD_REQUEST, "invalid secret"));
    }
    if !totp::verify(&req.secret, &req.code, unix_now()) {
        return Err(err(
            StatusCode::BAD_REQUEST,
            "code does not match — check the authenticator and its clock",
        ));
    }
    auth.db.set_totp_secret(ctx.user.id, Some(&req.secret))?;
    tracing::info!("user {} enabled TOTP", ctx.user.name);
    Ok(Json(json!({ "ok": true })))
}

#[derive(Deserialize)]
pub(crate) struct TotpDisableRequest {
    code: String,
}

pub(crate) async fn totp_disable(
    State(state): State<App>,
    ctx: Option<Extension<AuthCtx>>,
    Json(req): Json<TotpDisableRequest>,
) -> ApiResult<Json<serde_json::Value>> {
    let auth = auth_state(&state)?;
    let ctx = session_user(&ctx)?;
    let Some(secret) = auth.db.totp_secret(ctx.user.id)? else {
        return Err(err(StatusCode::BAD_REQUEST, "TOTP is not enabled"));
    };
    if !totp::verify(&secret, &req.code, unix_now()) {
        return Err(err(StatusCode::FORBIDDEN, "incorrect code"));
    }
    auth.db.set_totp_secret(ctx.user.id, None)?;
    tracing::info!("user {} disabled TOTP", ctx.user.name);
    Ok(Json(json!({ "ok": true })))
}

// ---------- account: passkeys ----------

pub(crate) async fn my_passkeys(
    State(state): State<App>,
    ctx: Option<Extension<AuthCtx>>,
) -> ApiResult<Json<serde_json::Value>> {
    let auth = auth_state(&state)?;
    let ctx = session_user(&ctx)?;
    Ok(Json(json!({
        "passkeys": auth.db.passkeys_meta(ctx.user.id)?,
        "webauthn_available": auth.webauthn.is_some(),
    })))
}

pub(crate) async fn passkey_register_start(
    State(state): State<App>,
    ctx: Option<Extension<AuthCtx>>,
) -> ApiResult<Json<serde_json::Value>> {
    let auth = auth_state(&state)?;
    let ctx = session_user(&ctx)?;
    let webauthn = auth.webauthn.as_ref().ok_or_else(|| {
        err(StatusCode::BAD_REQUEST, "webauthn is not configured on this server")
    })?;
    prune_pending(auth);
    let exclude: Vec<_> = auth
        .db
        .passkey_creds(ctx.user.id)?
        .iter()
        .filter_map(|(_, json)| serde_json::from_str::<Passkey>(json).ok())
        .map(|pk| pk.cred_id().clone())
        .collect();
    let (ccr, reg_state) = webauthn
        .start_passkey_registration(
            Uuid::from_u128(ctx.user.id as u128),
            &ctx.user.name,
            &ctx.user.name,
            if exclude.is_empty() { None } else { Some(exclude) },
        )
        .map_err(|e| err(StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
    let reg_token = random_token();
    auth.pending_regs.lock().unwrap().insert(
        reg_token.clone(),
        PendingReg {
            user_id: ctx.user.id,
            state: reg_state,
            created: Instant::now(),
        },
    );
    Ok(Json(json!({ "reg_token": reg_token, "challenge": ccr })))
}

#[derive(Deserialize)]
pub(crate) struct PasskeyFinishRequest {
    reg_token: String,
    #[serde(default)]
    name: String,
    credential: RegisterPublicKeyCredential,
}

pub(crate) async fn passkey_register_finish(
    State(state): State<App>,
    ctx: Option<Extension<AuthCtx>>,
    Json(req): Json<PasskeyFinishRequest>,
) -> ApiResult<Json<serde_json::Value>> {
    let auth = auth_state(&state)?;
    let ctx = session_user(&ctx)?;
    let webauthn = auth.webauthn.as_ref().ok_or_else(|| {
        err(StatusCode::BAD_REQUEST, "webauthn is not configured on this server")
    })?;
    let reg = {
        let mut regs = auth.pending_regs.lock().unwrap();
        match regs.remove(&req.reg_token) {
            Some(r) if r.user_id == ctx.user.id => r,
            _ => return Err(err(StatusCode::BAD_REQUEST, "registration expired; start again")),
        }
    };
    let passkey = webauthn
        .finish_passkey_registration(&req.credential, &reg.state)
        .map_err(|e| err(StatusCode::BAD_REQUEST, format!("registration rejected: {e}")))?;
    auth.db.passkey_add(
        ctx.user.id,
        &req.name,
        &serde_json::to_string(&passkey).unwrap(),
    )?;
    tracing::info!("user {} registered passkey {:?}", ctx.user.name, req.name);
    Ok(Json(json!({ "ok": true })))
}

pub(crate) async fn passkey_delete(
    State(state): State<App>,
    ctx: Option<Extension<AuthCtx>>,
    AxPath(id): AxPath<i64>,
) -> ApiResult<Json<serde_json::Value>> {
    let auth = auth_state(&state)?;
    let ctx = session_user(&ctx)?;
    auth.db.passkey_delete(ctx.user.id, id)?;
    Ok(Json(json!({ "ok": true })))
}

// ---------- account: overview ----------

pub(crate) async fn account_overview(
    State(state): State<App>,
    ctx: Option<Extension<AuthCtx>>,
) -> ApiResult<Json<serde_json::Value>> {
    let auth = auth_state(&state)?;
    let ctx = session_user(&ctx)?;
    Ok(Json(json!({
        "user": ctx.user.name,
        "role": ctx.user.role,
        "has_password": auth.db.has_password(ctx.user.id)?,
        "totp_enabled": auth.db.totp_secret(ctx.user.id)?.is_some(),
        "passkeys": auth.db.passkeys_meta(ctx.user.id)?,
        "tokens": auth.db.list_tokens(Some(ctx.user.id))?,
        "webauthn_available": auth.webauthn.is_some(),
    })))
}

// ---------- admin: user management ----------

pub(crate) async fn admin_users(
    State(state): State<App>,
    ctx: Option<Extension<AuthCtx>>,
) -> ApiResult<Json<serde_json::Value>> {
    let auth = auth_state(&state)?;
    session_user(&ctx)?;
    Ok(Json(json!({ "users": auth.db.list_users()? })))
}

#[derive(Deserialize)]
pub(crate) struct AdminAddUserRequest {
    name: String,
    role: Role,
    #[serde(default)]
    password: Option<String>,
}

pub(crate) async fn admin_add_user(
    State(state): State<App>,
    ctx: Option<Extension<AuthCtx>>,
    Json(req): Json<AdminAddUserRequest>,
) -> ApiResult<Json<serde_json::Value>> {
    let auth = auth_state(&state)?;
    let ctx = session_user(&ctx)?;
    if let Some(p) = &req.password {
        if p.len() < 8 {
            return Err(err(StatusCode::BAD_REQUEST, "password must be at least 8 characters"));
        }
    }
    auth.db.add_user(&req.name, req.password.as_deref(), req.role)?;
    tracing::info!("admin {} created user {} ({})", ctx.user.name, req.name, req.role);
    Ok(Json(json!({ "ok": true })))
}

fn guard_not_self(ctx: &AuthCtx, name: &str) -> ApiResult<()> {
    if ctx.user.name == name {
        return Err(err(
            StatusCode::CONFLICT,
            "refusing to modify your own account here — use the Account page",
        ));
    }
    Ok(())
}

pub(crate) async fn admin_delete_user(
    State(state): State<App>,
    ctx: Option<Extension<AuthCtx>>,
    AxPath(name): AxPath<String>,
) -> ApiResult<Json<serde_json::Value>> {
    let auth = auth_state(&state)?;
    let ctx = session_user(&ctx)?;
    guard_not_self(ctx, &name)?;
    auth.db.remove_user(&name)?;
    tracing::info!("admin {} deleted user {name}", ctx.user.name);
    Ok(Json(json!({ "ok": true })))
}

#[derive(Deserialize)]
pub(crate) struct AdminRoleRequest {
    role: Role,
}

pub(crate) async fn admin_set_role(
    State(state): State<App>,
    ctx: Option<Extension<AuthCtx>>,
    AxPath(name): AxPath<String>,
    Json(req): Json<AdminRoleRequest>,
) -> ApiResult<Json<serde_json::Value>> {
    let auth = auth_state(&state)?;
    let ctx = session_user(&ctx)?;
    guard_not_self(ctx, &name)?;
    auth.db.set_role(&name, req.role)?;
    tracing::info!("admin {} set role of {name} to {}", ctx.user.name, req.role);
    Ok(Json(json!({ "ok": true })))
}

#[derive(Deserialize)]
pub(crate) struct AdminPasswordRequest {
    password: String,
}

pub(crate) async fn admin_set_password(
    State(state): State<App>,
    ctx: Option<Extension<AuthCtx>>,
    AxPath(name): AxPath<String>,
    Json(req): Json<AdminPasswordRequest>,
) -> ApiResult<Json<serde_json::Value>> {
    let auth = auth_state(&state)?;
    let ctx = session_user(&ctx)?;
    if req.password.len() < 8 {
        return Err(err(StatusCode::BAD_REQUEST, "password must be at least 8 characters"));
    }
    auth.db.set_password(&name, &req.password)?;
    tracing::info!("admin {} reset password of {name}", ctx.user.name);
    Ok(Json(json!({ "ok": true })))
}

pub(crate) async fn admin_reset_2fa(
    State(state): State<App>,
    ctx: Option<Extension<AuthCtx>>,
    AxPath(name): AxPath<String>,
) -> ApiResult<Json<serde_json::Value>> {
    let auth = auth_state(&state)?;
    let ctx = session_user(&ctx)?;
    auth.db.clear_second_factors(&name)?;
    tracing::info!("admin {} cleared TOTP and passkeys of {name}", ctx.user.name);
    Ok(Json(json!({ "ok": true })))
}
