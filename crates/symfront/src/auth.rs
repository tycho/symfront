//! Optional authentication: users, API tokens, and web sessions in a small
//! SQLite database. When no auth db is configured, the server runs open
//! (unchanged behavior).
//!
//! - Passwords: argon2id hashes; used by the web UI login (session cookie).
//! - API tokens: `sf_<64 hex>`, shown once at creation, stored as SHA-256;
//!   sent as `Authorization: Bearer …` — the non-interactive path for
//!   headless clients (e.g. automated symbol uploads).
//! - Sessions: server-side, persisted so restarts don't log everyone out.

use std::fmt;
use std::path::Path;
use std::sync::Mutex;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use anyhow::{anyhow, bail, Context, Result};
use argon2::password_hash::{PasswordHasher, PasswordVerifier};
use argon2::Argon2;
use rusqlite::{params, Connection, OptionalExtension};
use sha2::{Digest, Sha256};

pub const SESSION_TTL: Duration = Duration::from_secs(30 * 24 * 3600);

#[derive(
    Copy, Clone, PartialEq, Eq, Debug, clap::ValueEnum, serde::Serialize, serde::Deserialize,
)]
#[serde(rename_all = "lowercase")]
pub enum Role {
    /// Read-only: browse, search, reports.
    Ro,
    /// Read-write: everything except user management.
    Rw,
    /// Full control (reserved for future API-side user management).
    Admin,
}

impl Role {
    pub fn can_mutate(self) -> bool {
        !matches!(self, Role::Ro)
    }
    fn rank(self) -> u8 {
        match self {
            Role::Ro => 1,
            Role::Rw => 2,
            Role::Admin => 3,
        }
    }
    /// The lesser of two roles — used to cap a token's capability by its
    /// owner's role.
    pub fn min(self, other: Role) -> Role {
        if self.rank() <= other.rank() {
            self
        } else {
            other
        }
    }
    fn as_str(self) -> &'static str {
        match self {
            Role::Ro => "ro",
            Role::Rw => "rw",
            Role::Admin => "admin",
        }
    }
    fn parse(s: &str) -> Result<Role> {
        match s {
            "ro" => Ok(Role::Ro),
            "rw" => Ok(Role::Rw),
            "admin" => Ok(Role::Admin),
            _ => bail!("unknown role {s:?}"),
        }
    }
}

impl fmt::Display for Role {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

#[derive(Clone, Debug)]
pub struct User {
    pub id: i64,
    pub name: String,
    pub role: Role,
}

#[derive(serde::Serialize)]
pub struct UserInfo {
    pub name: String,
    pub role: Role,
    pub has_password: bool,
    pub totp_enabled: bool,
    pub passkeys: i64,
    pub tokens: i64,
}

#[derive(serde::Serialize)]
pub struct TokenInfo {
    pub id: i64,
    pub user: String,
    pub label: String,
    pub cap: Role,
    pub created_at: i64,
    pub last_used_at: Option<i64>,
}

#[derive(serde::Serialize)]
pub struct PasskeyInfo {
    pub id: i64,
    pub name: String,
    pub created_at: i64,
    pub last_used_at: Option<i64>,
}

pub struct AuthDb {
    conn: Mutex<Connection>,
}

fn now() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

fn sha256_hex(s: &str) -> String {
    let mut h = Sha256::new();
    h.update(s.as_bytes());
    let out = h.finalize();
    out.iter().map(|b| format!("{b:02x}")).collect()
}

fn random_hex(bytes: usize) -> String {
    let mut buf = vec![0u8; bytes];
    getrandom::fill(&mut buf).expect("OS RNG");
    buf.iter().map(|b| format!("{b:02x}")).collect()
}

impl AuthDb {
    pub fn open(path: &Path) -> Result<AuthDb> {
        let conn = Connection::open(path)
            .with_context(|| format!("opening auth db {}", path.display()))?;
        conn.execute_batch(
            "PRAGMA foreign_keys = ON;
             CREATE TABLE IF NOT EXISTS users(
               id INTEGER PRIMARY KEY,
               name TEXT NOT NULL UNIQUE,
               pass_hash TEXT,
               role TEXT NOT NULL DEFAULT 'rw',
               created_at INTEGER NOT NULL
             );
             CREATE TABLE IF NOT EXISTS tokens(
               id INTEGER PRIMARY KEY,
               user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
               label TEXT NOT NULL DEFAULT '',
               token_hash TEXT NOT NULL UNIQUE,
               created_at INTEGER NOT NULL,
               last_used_at INTEGER
             );
             CREATE TABLE IF NOT EXISTS sessions(
               id INTEGER PRIMARY KEY,
               user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
               token_hash TEXT NOT NULL UNIQUE,
               created_at INTEGER NOT NULL,
               expires_at INTEGER NOT NULL
             );
             CREATE TABLE IF NOT EXISTS passkeys(
               id INTEGER PRIMARY KEY,
               user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
               name TEXT NOT NULL DEFAULT '',
               cred TEXT NOT NULL,
               created_at INTEGER NOT NULL,
               last_used_at INTEGER
             );",
        )?;
        // Additive migrations for databases created by earlier versions.
        ensure_column(&conn, "users", "totp_secret", "TEXT")?;
        ensure_column(&conn, "tokens", "cap", "TEXT NOT NULL DEFAULT 'rw'")?;
        Ok(AuthDb {
            conn: Mutex::new(conn),
        })
    }

    fn user_id(conn: &Connection, name: &str) -> Result<i64> {
        conn.query_row("SELECT id FROM users WHERE name = ?1", params![name], |r| {
            r.get(0)
        })
        .optional()?
        .ok_or_else(|| anyhow!("no such user {name:?}"))
    }

    pub fn add_user(&self, name: &str, password: Option<&str>, role: Role) -> Result<()> {
        if name.is_empty()
            || !name
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || "-_.@".contains(c))
        {
            bail!("user names are limited to ASCII alphanumerics and -_.@");
        }
        let hash = password.map(hash_password).transpose()?;
        self.conn
            .lock()
            .unwrap()
            .execute(
                "INSERT INTO users(name, pass_hash, role, created_at) VALUES(?1, ?2, ?3, ?4)",
                params![name, hash, role.as_str(), now()],
            )
            .map_err(|e| match e {
                rusqlite::Error::SqliteFailure(f, _)
                    if f.code == rusqlite::ErrorCode::ConstraintViolation =>
                {
                    anyhow!("user {name:?} already exists")
                }
                e => e.into(),
            })?;
        Ok(())
    }

    pub fn set_password(&self, name: &str, password: &str) -> Result<()> {
        let hash = hash_password(password)?;
        let n = self.conn.lock().unwrap().execute(
            "UPDATE users SET pass_hash = ?1 WHERE name = ?2",
            params![hash, name],
        )?;
        if n == 0 {
            bail!("no such user {name:?}");
        }
        Ok(())
    }

    pub fn remove_user(&self, name: &str) -> Result<()> {
        let n = self
            .conn
            .lock()
            .unwrap()
            .execute("DELETE FROM users WHERE name = ?1", params![name])?;
        if n == 0 {
            bail!("no such user {name:?}");
        }
        Ok(())
    }

    pub fn list_users(&self) -> Result<Vec<UserInfo>> {
        let conn = self.conn.lock().unwrap();
        let mut stmt = conn.prepare(
            "SELECT u.name, u.role, u.pass_hash IS NOT NULL, u.totp_secret IS NOT NULL,
                    (SELECT COUNT(*) FROM passkeys p WHERE p.user_id = u.id),
                    (SELECT COUNT(*) FROM tokens t WHERE t.user_id = u.id)
             FROM users u ORDER BY u.name",
        )?;
        let rows = stmt.query_map([], |r| {
            Ok((
                r.get::<_, String>(0)?,
                r.get::<_, String>(1)?,
                r.get::<_, bool>(2)?,
                r.get::<_, bool>(3)?,
                r.get::<_, i64>(4)?,
                r.get::<_, i64>(5)?,
            ))
        })?;
        let mut out = Vec::new();
        for row in rows {
            let (name, role, has_password, totp_enabled, passkeys, tokens) = row?;
            out.push(UserInfo {
                name,
                role: Role::parse(&role)?,
                has_password,
                totp_enabled,
                passkeys,
                tokens,
            });
        }
        Ok(out)
    }

    pub fn set_role(&self, name: &str, role: Role) -> Result<()> {
        let n = self.conn.lock().unwrap().execute(
            "UPDATE users SET role = ?1 WHERE name = ?2",
            params![role.as_str(), name],
        )?;
        if n == 0 {
            bail!("no such user {name:?}");
        }
        Ok(())
    }

    /// Only passkey login looks users up by name today; keep it around.
    #[cfg_attr(not(passkeys), allow(dead_code))]
    pub fn user_by_name(&self, name: &str) -> Result<Option<User>> {
        let conn = self.conn.lock().unwrap();
        Ok(conn
            .query_row(
                "SELECT id, role FROM users WHERE name = ?1",
                params![name],
                |r| Ok((r.get::<_, i64>(0)?, r.get::<_, String>(1)?)),
            )
            .optional()?
            .and_then(|(id, role)| {
                Some(User {
                    id,
                    name: name.to_string(),
                    role: Role::parse(&role).ok()?,
                })
            }))
    }

    pub fn user_by_id(&self, id: i64) -> Result<Option<User>> {
        let conn = self.conn.lock().unwrap();
        Ok(conn
            .query_row(
                "SELECT name, role FROM users WHERE id = ?1",
                params![id],
                |r| Ok((r.get::<_, String>(0)?, r.get::<_, String>(1)?)),
            )
            .optional()?
            .and_then(|(name, role)| {
                Some(User {
                    id,
                    name,
                    role: Role::parse(&role).ok()?,
                })
            }))
    }

    /// Every stored passkey: (passkey row id, owning user id, credential JSON).
    #[cfg(passkeys)]
    pub fn all_passkey_creds(&self) -> Result<Vec<(i64, i64, String)>> {
        let conn = self.conn.lock().unwrap();
        let mut stmt = conn.prepare("SELECT id, user_id, cred FROM passkeys ORDER BY id")?;
        let rows = stmt.query_map([], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)))?;
        Ok(rows.collect::<rusqlite::Result<_>>()?)
    }

    pub fn has_password(&self, user_id: i64) -> Result<bool> {
        Ok(self.conn.lock().unwrap().query_row(
            "SELECT pass_hash IS NOT NULL FROM users WHERE id = ?1",
            params![user_id],
            |r| r.get(0),
        )?)
    }

    // ----- TOTP -----

    pub fn totp_secret(&self, user_id: i64) -> Result<Option<String>> {
        Ok(self.conn.lock().unwrap().query_row(
            "SELECT totp_secret FROM users WHERE id = ?1",
            params![user_id],
            |r| r.get(0),
        )?)
    }

    pub fn set_totp_secret(&self, user_id: i64, secret: Option<&str>) -> Result<()> {
        self.conn.lock().unwrap().execute(
            "UPDATE users SET totp_secret = ?1 WHERE id = ?2",
            params![secret, user_id],
        )?;
        Ok(())
    }

    /// Admin lockout recovery: clear TOTP and all passkeys for a user.
    pub fn clear_second_factors(&self, name: &str) -> Result<()> {
        let conn = self.conn.lock().unwrap();
        let id = Self::user_id(&conn, name)?;
        conn.execute(
            "UPDATE users SET totp_secret = NULL WHERE id = ?1",
            params![id],
        )?;
        conn.execute("DELETE FROM passkeys WHERE user_id = ?1", params![id])?;
        Ok(())
    }

    // ----- Passkeys (WebAuthn credentials, serialized JSON) -----
    //
    // Listing and deleting work in every build; the credential accessors
    // only serve the WebAuthn ceremonies, which are `cfg(passkeys)`.

    #[cfg(passkeys)]
    pub fn passkey_add(&self, user_id: i64, name: &str, cred_json: &str) -> Result<()> {
        self.conn.lock().unwrap().execute(
            "INSERT INTO passkeys(user_id, name, cred, created_at) VALUES(?1, ?2, ?3, ?4)",
            params![user_id, name, cred_json, now()],
        )?;
        Ok(())
    }

    pub fn passkeys_meta(&self, user_id: i64) -> Result<Vec<PasskeyInfo>> {
        let conn = self.conn.lock().unwrap();
        let mut stmt = conn.prepare(
            "SELECT id, name, created_at, last_used_at FROM passkeys
             WHERE user_id = ?1 ORDER BY id",
        )?;
        let rows = stmt.query_map(params![user_id], |r| {
            Ok(PasskeyInfo {
                id: r.get(0)?,
                name: r.get(1)?,
                created_at: r.get(2)?,
                last_used_at: r.get(3)?,
            })
        })?;
        Ok(rows.collect::<rusqlite::Result<_>>()?)
    }

    #[cfg(passkeys)]
    pub fn passkey_creds(&self, user_id: i64) -> Result<Vec<(i64, String)>> {
        let conn = self.conn.lock().unwrap();
        let mut stmt =
            conn.prepare("SELECT id, cred FROM passkeys WHERE user_id = ?1 ORDER BY id")?;
        let rows = stmt.query_map(params![user_id], |r| Ok((r.get(0)?, r.get(1)?)))?;
        Ok(rows.collect::<rusqlite::Result<_>>()?)
    }

    #[cfg(passkeys)]
    pub fn passkey_update_cred(&self, id: i64, cred_json: &str) -> Result<()> {
        self.conn.lock().unwrap().execute(
            "UPDATE passkeys SET cred = ?1, last_used_at = ?2 WHERE id = ?3",
            params![cred_json, now(), id],
        )?;
        Ok(())
    }

    pub fn passkey_delete(&self, user_id: i64, id: i64) -> Result<()> {
        let n = self.conn.lock().unwrap().execute(
            "DELETE FROM passkeys WHERE id = ?1 AND user_id = ?2",
            params![id, user_id],
        )?;
        if n == 0 {
            bail!("no such passkey");
        }
        Ok(())
    }

    pub fn verify_password(&self, name: &str, password: &str) -> Result<Option<User>> {
        let row: Option<(i64, Option<String>, String)> = self
            .conn
            .lock()
            .unwrap()
            .query_row(
                "SELECT id, pass_hash, role FROM users WHERE name = ?1",
                params![name],
                |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
            )
            .optional()?;
        let Some((id, Some(hash), role)) = row else {
            // Unknown user or token-only user: burn comparable time anyway so
            // login timing doesn't reveal which names exist.
            let _ = verify_password_hash("x", dummy_hash());
            return Ok(None);
        };
        if verify_password_hash(password, &hash) {
            Ok(Some(User {
                id,
                name: name.to_string(),
                role: Role::parse(&role)?,
            }))
        } else {
            Ok(None)
        }
    }

    /// Create an API token for a user; returns the plaintext (shown once).
    /// `cap` limits what the token may do, further capped by the user's role.
    pub fn create_token(&self, user: &str, label: &str, cap: Role) -> Result<String> {
        let token = format!("sf_{}", random_hex(32));
        let conn = self.conn.lock().unwrap();
        let user_id = Self::user_id(&conn, user)?;
        conn.execute(
            "INSERT INTO tokens(user_id, label, token_hash, cap, created_at) VALUES(?1, ?2, ?3, ?4, ?5)",
            params![user_id, label, sha256_hex(&token), cap.as_str(), now()],
        )?;
        Ok(token)
    }

    pub fn list_tokens(&self, user_id: Option<i64>) -> Result<Vec<TokenInfo>> {
        let conn = self.conn.lock().unwrap();
        let mut stmt = conn.prepare(
            "SELECT t.id, u.name, t.label, t.cap, t.created_at, t.last_used_at
             FROM tokens t JOIN users u ON u.id = t.user_id
             WHERE ?1 IS NULL OR t.user_id = ?1
             ORDER BY t.id",
        )?;
        let rows = stmt.query_map(params![user_id], |r| {
            Ok((
                r.get::<_, i64>(0)?,
                r.get::<_, String>(1)?,
                r.get::<_, String>(2)?,
                r.get::<_, String>(3)?,
                r.get::<_, i64>(4)?,
                r.get::<_, Option<i64>>(5)?,
            ))
        })?;
        let mut out = Vec::new();
        for row in rows {
            let (id, user, label, cap, created_at, last_used_at) = row?;
            out.push(TokenInfo {
                id,
                user,
                label,
                cap: Role::parse(&cap)?,
                created_at,
                last_used_at,
            });
        }
        Ok(out)
    }

    /// Revoke a token; when `owner` is given the token must belong to them.
    pub fn revoke_token(&self, id: i64, owner: Option<i64>) -> Result<()> {
        let n = self.conn.lock().unwrap().execute(
            "DELETE FROM tokens WHERE id = ?1 AND (?2 IS NULL OR user_id = ?2)",
            params![id, owner],
        )?;
        if n == 0 {
            bail!("no such token id {id}");
        }
        Ok(())
    }

    /// Authenticate an `Authorization: Bearer` API token.
    pub fn auth_token(&self, token: &str) -> Option<User> {
        let hash = sha256_hex(token);
        let conn = self.conn.lock().unwrap();
        let (token_id, id, name, role, cap): (i64, i64, String, String, String) = conn
            .query_row(
                "SELECT t.id, u.id, u.name, u.role, t.cap
                 FROM tokens t JOIN users u ON u.id = t.user_id
                 WHERE t.token_hash = ?1",
                params![hash],
                |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?, r.get(4)?)),
            )
            .optional()
            .ok()??;
        let _ = conn.execute(
            "UPDATE tokens SET last_used_at = ?1 WHERE id = ?2",
            params![now(), token_id],
        );
        // Effective role: token capability capped by the owner's role.
        Some(User {
            id,
            name,
            role: Role::parse(&role).ok()?.min(Role::parse(&cap).ok()?),
        })
    }

    /// Create a web session; returns the cookie value.
    pub fn create_session(&self, user_id: i64) -> Result<String> {
        let token = format!("ss_{}", random_hex(32));
        self.conn.lock().unwrap().execute(
            "INSERT INTO sessions(user_id, token_hash, created_at, expires_at)
             VALUES(?1, ?2, ?3, ?4)",
            params![
                user_id,
                sha256_hex(&token),
                now(),
                now() + SESSION_TTL.as_secs() as i64
            ],
        )?;
        Ok(token)
    }

    pub fn auth_session(&self, token: &str) -> Option<User> {
        let hash = sha256_hex(token);
        let conn = self.conn.lock().unwrap();
        // Opportunistic cleanup of expired sessions.
        let _ = conn.execute("DELETE FROM sessions WHERE expires_at < ?1", params![now()]);
        let (id, name, role): (i64, String, String) = conn
            .query_row(
                "SELECT u.id, u.name, u.role
                 FROM sessions s JOIN users u ON u.id = s.user_id
                 WHERE s.token_hash = ?1 AND s.expires_at >= ?2",
                params![hash, now()],
                |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
            )
            .optional()
            .ok()??;
        Some(User {
            id,
            name,
            role: Role::parse(&role).ok()?,
        })
    }

    pub fn delete_session(&self, token: &str) {
        let _ = self.conn.lock().unwrap().execute(
            "DELETE FROM sessions WHERE token_hash = ?1",
            params![sha256_hex(token)],
        );
    }
}

fn ensure_column(conn: &Connection, table: &str, column: &str, ddl: &str) -> Result<()> {
    let mut stmt = conn.prepare(&format!("PRAGMA table_info({table})"))?;
    let exists = stmt
        .query_map([], |r| r.get::<_, String>(1))?
        .filter_map(|r| r.ok())
        .any(|c| c == column);
    if !exists {
        conn.execute(
            &format!("ALTER TABLE {table} ADD COLUMN {column} {ddl}"),
            [],
        )?;
    }
    Ok(())
}

fn hash_password(password: &str) -> Result<String> {
    // password-hash 0.6: the salt is generated internally (getrandom).
    Ok(Argon2::default()
        .hash_password(password.as_bytes())
        .map_err(|e| anyhow!("hashing password: {e}"))?
        .to_string())
}

/// A valid argon2id hash of an unguessable value, used to equalize timing for
/// unknown users.
fn dummy_hash() -> &'static str {
    static DUMMY: std::sync::OnceLock<String> = std::sync::OnceLock::new();
    DUMMY.get_or_init(|| hash_password(&random_hex(16)).expect("argon2 hash"))
}

fn verify_password_hash(password: &str, hash: &str) -> bool {
    // argon2 0.6 parses the PHC string itself (malformed -> Err -> false).
    Argon2::default()
        .verify_password(password.as_bytes(), hash)
        .is_ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn db() -> (tempfile::TempDir, AuthDb) {
        let tmp = tempfile::tempdir().unwrap();
        let db = AuthDb::open(&tmp.path().join("auth.db")).unwrap();
        (tmp, db)
    }

    #[test]
    fn password_roundtrip() {
        let (_t, db) = db();
        db.add_user("steven", Some("hunter2"), Role::Admin).unwrap();
        assert!(db.verify_password("steven", "hunter2").unwrap().is_some());
        assert!(db.verify_password("steven", "wrong").unwrap().is_none());
        assert!(db.verify_password("nobody", "hunter2").unwrap().is_none());
        assert!(db.add_user("steven", None, Role::Ro).is_err()); // duplicate
    }

    #[test]
    fn token_roundtrip() {
        let (_t, db) = db();
        db.add_user("bot", None, Role::Rw).unwrap();
        let token = db.create_token("bot", "ci uploads", Role::Rw).unwrap();
        assert!(token.starts_with("sf_"));
        let u = db.auth_token(&token).unwrap();
        assert_eq!(u.name, "bot");
        assert_eq!(u.role, Role::Rw);
        assert!(db.auth_token("sf_bogus").is_none());
        let id = db.list_tokens(None).unwrap()[0].id;
        db.revoke_token(id, None).unwrap();
        assert!(db.auth_token(&token).is_none());
    }

    #[test]
    fn session_roundtrip() {
        let (_t, db) = db();
        db.add_user("steven", Some("pw"), Role::Rw).unwrap();
        let u = db.verify_password("steven", "pw").unwrap().unwrap();
        let sess = db.create_session(u.id).unwrap();
        assert_eq!(db.auth_session(&sess).unwrap().name, "steven");
        db.delete_session(&sess);
        assert!(db.auth_session(&sess).is_none());
    }

    #[test]
    fn token_capability_is_capped() {
        let (_t, db) = db();
        db.add_user("bot", None, Role::Rw).unwrap();
        db.add_user("viewer", None, Role::Ro).unwrap();
        let ro_tok = db.create_token("bot", "", Role::Ro).unwrap();
        assert_eq!(db.auth_token(&ro_tok).unwrap().role, Role::Ro);
        // A viewer's rw token is still capped at ro by their role.
        let esc_tok = db.create_token("viewer", "", Role::Rw).unwrap();
        assert_eq!(db.auth_token(&esc_tok).unwrap().role, Role::Ro);
    }

    #[test]
    fn user_removal_cascades() {
        let (_t, db) = db();
        db.add_user("bot", None, Role::Rw).unwrap();
        let token = db.create_token("bot", "", Role::Rw).unwrap();
        db.remove_user("bot").unwrap();
        assert!(db.auth_token(&token).is_none());
    }
}
