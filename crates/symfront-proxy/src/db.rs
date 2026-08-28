//! Cache metadata: SQLite via rusqlite.
//!
//! Concurrency model (deliberate, see the integration plan):
//!
//! - **Reads happen inline** on the calling task via a small checkout pool
//!   of read-only connections. Indexed lookups are sub-millisecond; no
//!   spawn_blocking round-trips.
//! - **All writes go through one dedicated writer thread** fed by a bounded
//!   channel. This matches SQLite's single-writer reality instead of
//!   fighting it. Fire-and-forget for access-time touches (batched, like
//!   the Python implementation's 30 s flusher); awaited via oneshot only
//!   where durability gates the response (fill commits).
//!
//! The file stays inspectable with plain `sqlite3` — explicitly valued.

use std::path::{Path, PathBuf};
use std::sync::Mutex;
use std::time::{Duration, Instant};

use rusqlite::{params, Connection, OpenFlags};
use tokio::sync::{mpsc, oneshot};

use crate::key::hex;

#[derive(thiserror::Error, Debug)]
pub enum DbError {
    #[error("sqlite: {0}")]
    Sqlite(#[from] rusqlite::Error),
    #[error("cache writer is gone")]
    WriterGone,
    #[error("{0}")]
    Other(String),
}

pub type Result<T> = std::result::Result<T, DbError>;

/// One metadata row. Times are Unix seconds (REAL in the db, matching the
/// Python schema so a full cache import is possible).
#[derive(Clone, Debug)]
pub struct Entry {
    pub key: [u8; 32],
    pub url: String,
    pub upstream: String,
    pub status: u16,
    pub created_at: f64,
    pub accessed_at: f64,
    pub expires_at: f64,
    pub ttl: f64,
    pub size: u64,
    pub etag: Option<String>,
    /// Unix seconds, parsed from the upstream Last-Modified.
    pub last_modified: Option<f64>,
    pub content_sha256: Option<[u8; 32]>,
    pub hit_count: u64,
    pub negative_step: u32,
}

impl Entry {
    pub fn is_positive(&self) -> bool {
        self.status == 200
    }

    pub fn is_expired(&self, now: f64) -> bool {
        now > self.expires_at
    }
}

pub enum WriteOp {
    /// Insert or replace a full entry. `done` is signalled after commit.
    Upsert(Box<Entry>, Option<oneshot::Sender<Result<()>>>),
    /// Batched: slide expiry / bump atime / count a hit.
    Touch {
        key: [u8; 32],
        accessed_at: f64,
        expires_at: f64,
    },
    Delete(Vec<[u8; 32]>, Option<oneshot::Sender<Result<()>>>),
    /// Flush pending touches now (tests, shutdown).
    Flush(oneshot::Sender<()>),
}

const SCHEMA: &str = "
CREATE TABLE IF NOT EXISTS cache_entries (
    cache_key       BLOB PRIMARY KEY CHECK (length(cache_key) = 32),
    url             TEXT NOT NULL,
    upstream_name   TEXT NOT NULL,
    status_code     INTEGER NOT NULL CHECK (status_code BETWEEN 100 AND 599),
    created_at      REAL NOT NULL,
    accessed_at     REAL NOT NULL,
    expires_at      REAL NOT NULL,
    ttl             REAL NOT NULL,
    content_length  INTEGER NOT NULL DEFAULT 0,
    etag            TEXT,
    last_modified   REAL,
    content_sha256  BLOB CHECK (content_sha256 IS NULL OR length(content_sha256) = 32),
    hit_count       INTEGER NOT NULL DEFAULT 0,
    negative_step   INTEGER NOT NULL DEFAULT 0,
    content_encoding TEXT
);
CREATE INDEX IF NOT EXISTS idx_expires ON cache_entries(expires_at);
CREATE INDEX IF NOT EXISTS idx_upstream_status ON cache_entries(upstream_name, status_code);
CREATE INDEX IF NOT EXISTS idx_status_expires ON cache_entries(status_code, expires_at);
";

const SELECT_COLS: &str = "cache_key, url, upstream_name, status_code, created_at, \
     accessed_at, expires_at, ttl, content_length, etag, last_modified, \
     content_sha256, hit_count, negative_step";

fn row_to_entry(row: &rusqlite::Row<'_>) -> rusqlite::Result<Entry> {
    let key: Vec<u8> = row.get(0)?;
    let sha: Option<Vec<u8>> = row.get(11)?;
    Ok(Entry {
        key: key.try_into().unwrap_or([0; 32]),
        url: row.get(1)?,
        upstream: row.get(2)?,
        status: row.get::<_, i64>(3)? as u16,
        created_at: row.get(4)?,
        accessed_at: row.get(5)?,
        expires_at: row.get(6)?,
        ttl: row.get(7)?,
        size: row.get::<_, i64>(8)? as u64,
        etag: row.get(9)?,
        last_modified: row.get(10)?,
        content_sha256: sha.and_then(|v| v.try_into().ok()),
        hit_count: row.get::<_, i64>(12)? as u64,
        negative_step: row.get::<_, i64>(13)? as u32,
    })
}

pub struct MetaDb {
    path: PathBuf,
    readers: Mutex<Vec<Connection>>,
    writer: mpsc::Sender<WriteOp>,
    writer_thread: Mutex<Option<std::thread::JoinHandle<()>>>,
}

/// How long touches may sit unflushed. Short enough that a crash loses
/// little; long enough to batch bursts.
const TOUCH_FLUSH_INTERVAL: Duration = Duration::from_secs(30);
const TOUCH_FLUSH_MAX: usize = 1024;

impl MetaDb {
    pub fn open(path: &Path) -> Result<MetaDb> {
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)
                .map_err(|e| DbError::Other(format!("{}: {e}", parent.display())))?;
        }
        // Writer connection creates and owns the schema.
        let conn = Connection::open(path)?;
        conn.pragma_update(None, "page_size", 65536)?;
        conn.pragma_update(None, "journal_mode", "WAL")?;
        conn.pragma_update(None, "synchronous", "NORMAL")?;
        conn.busy_timeout(Duration::from_secs(5))?;
        conn.execute_batch(SCHEMA)?;

        let (tx, rx) = mpsc::channel::<WriteOp>(4096);
        let thread = std::thread::Builder::new()
            .name("cache-db-writer".into())
            .spawn(move || writer_loop(conn, rx))
            .map_err(|e| DbError::Other(format!("spawning writer thread: {e}")))?;

        Ok(MetaDb {
            path: path.to_path_buf(),
            readers: Mutex::new(Vec::new()),
            writer: tx,
            writer_thread: Mutex::new(Some(thread)),
        })
    }

    fn reader(&self) -> Result<Connection> {
        if let Some(c) = self.readers.lock().unwrap().pop() {
            return Ok(c);
        }
        let c = Connection::open_with_flags(
            &self.path,
            OpenFlags::SQLITE_OPEN_READ_ONLY | OpenFlags::SQLITE_OPEN_NO_MUTEX,
        )?;
        c.busy_timeout(Duration::from_secs(5))?;
        Ok(c)
    }

    fn recycle(&self, conn: Connection) {
        let mut pool = self.readers.lock().unwrap();
        if pool.len() < 8 {
            pool.push(conn);
        }
    }

    fn with_reader<T>(&self, f: impl FnOnce(&Connection) -> rusqlite::Result<T>) -> Result<T> {
        let conn = self.reader()?;
        let out = f(&conn);
        self.recycle(conn);
        Ok(out?)
    }

    /// Batch metadata lookup. Missing keys are simply absent from the result.
    pub fn get_many(&self, keys: &[[u8; 32]]) -> Result<Vec<Entry>> {
        if keys.is_empty() {
            return Ok(Vec::new());
        }
        self.with_reader(|conn| {
            let placeholders = vec!["?"; keys.len()].join(",");
            let sql = format!(
                "SELECT {SELECT_COLS} FROM cache_entries WHERE cache_key IN ({placeholders})"
            );
            let mut stmt = conn.prepare_cached(&sql)?;
            let mut rows = Vec::new();
            let params = rusqlite::params_from_iter(keys.iter().map(|k| k.to_vec()));
            let mut q = stmt.query(params)?;
            while let Some(row) = q.next()? {
                rows.push(row_to_entry(row)?);
            }
            Ok(rows)
        })
    }

    pub fn get(&self, key: &[u8; 32]) -> Result<Option<Entry>> {
        Ok(self.get_many(std::slice::from_ref(key))?.pop())
    }

    /// Total bytes of positive entries (eviction accounting).
    pub fn positive_bytes(&self) -> Result<u64> {
        self.with_reader(|conn| {
            conn.query_row(
                "SELECT COALESCE(SUM(content_length), 0) FROM cache_entries WHERE status_code = 200",
                [],
                |r| r.get::<_, i64>(0),
            )
            .map(|v| v as u64)
        })
    }

    /// Positive entries in eviction order (soonest expiry first).
    pub fn eviction_candidates(&self, limit: usize) -> Result<Vec<Entry>> {
        self.with_reader(|conn| {
            let mut stmt = conn.prepare_cached(&format!(
                "SELECT {SELECT_COLS} FROM cache_entries WHERE status_code = 200 \
                 ORDER BY expires_at ASC LIMIT ?"
            ))?;
            let mut out = Vec::new();
            let mut q = stmt.query(params![limit as i64])?;
            while let Some(row) = q.next()? {
                out.push(row_to_entry(row)?);
            }
            Ok(out)
        })
    }

    /// All keys with (status, size), streamed in batches for scrub.
    pub fn for_each_entry(&self, mut f: impl FnMut(&[u8; 32], u16, u64)) -> Result<()> {
        self.with_reader(|conn| {
            let mut stmt = conn.prepare_cached(
                "SELECT cache_key, status_code, content_length FROM cache_entries",
            )?;
            let mut q = stmt.query([])?;
            while let Some(row) = q.next()? {
                let key: Vec<u8> = row.get(0)?;
                let Ok(key) = <[u8; 32]>::try_from(key) else {
                    continue;
                };
                let status = row.get::<_, i64>(1)? as u16;
                let size = row.get::<_, i64>(2)? as u64;
                f(&key, status, size);
            }
            Ok(())
        })
    }

    /// Search entries by URL substring (admin UI). Case-sensitive LIKE.
    pub fn search(&self, needle: &str, limit: usize) -> Result<Vec<Entry>> {
        self.with_reader(|conn| {
            let mut stmt = conn.prepare_cached(&format!(
                "SELECT {SELECT_COLS} FROM cache_entries WHERE url LIKE ? \
                 ORDER BY accessed_at DESC LIMIT ?"
            ))?;
            let pattern = format!("%{}%", needle.replace('%', "\\%").replace('_', "\\_"));
            let mut out = Vec::new();
            let mut q = stmt.query(params![pattern, limit as i64])?;
            while let Some(row) = q.next()? {
                out.push(row_to_entry(row)?);
            }
            Ok(out)
        })
    }

    /// Keys of entries matching an upstream and/or status class (admin evict).
    pub fn keys_matching(
        &self,
        upstream: Option<&str>,
        negative_only: bool,
        url_prefix: Option<&str>,
    ) -> Result<Vec<[u8; 32]>> {
        self.with_reader(|conn| {
            let mut sql = "SELECT cache_key FROM cache_entries WHERE 1=1".to_string();
            let mut binds: Vec<Box<dyn rusqlite::ToSql>> = Vec::new();
            if let Some(u) = upstream {
                sql.push_str(" AND upstream_name = ?");
                binds.push(Box::new(u.to_string()));
            }
            if negative_only {
                sql.push_str(" AND status_code != 200");
            }
            if let Some(p) = url_prefix {
                sql.push_str(" AND url LIKE ?");
                binds.push(Box::new(format!(
                    "%{}%",
                    p.replace('%', "\\%").replace('_', "\\_")
                )));
            }
            let mut stmt = conn.prepare(&sql)?;
            let mut out = Vec::new();
            let mut q = stmt.query(rusqlite::params_from_iter(binds.iter().map(|b| b.as_ref())))?;
            while let Some(row) = q.next()? {
                let key: Vec<u8> = row.get(0)?;
                if let Ok(k) = <[u8; 32]>::try_from(key) {
                    out.push(k);
                }
            }
            Ok(out)
        })
    }

    /// Entry counts and byte totals grouped by (upstream, positive/negative).
    pub fn summary(&self) -> Result<Vec<(String, bool, u64, u64)>> {
        self.with_reader(|conn| {
            let mut stmt = conn.prepare_cached(
                "SELECT upstream_name, status_code = 200, COUNT(*), COALESCE(SUM(content_length),0) \
                 FROM cache_entries GROUP BY upstream_name, status_code = 200",
            )?;
            let mut out = Vec::new();
            let mut q = stmt.query([])?;
            while let Some(row) = q.next()? {
                out.push((
                    row.get(0)?,
                    row.get::<_, i64>(1)? != 0,
                    row.get::<_, i64>(2)? as u64,
                    row.get::<_, i64>(3)? as u64,
                ));
            }
            Ok(out)
        })
    }

    // --- write path ---

    /// Queue a write without waiting for it (touches, negative entries).
    /// Drops the op (with a warning) if the writer is saturated: losing an
    /// atime slide or a negative-cache write is always safe.
    pub fn write_nowait(&self, op: WriteOp) {
        if let Err(e) = self.writer.try_send(op) {
            match e {
                mpsc::error::TrySendError::Full(_) => {
                    tracing::warn!("cache-db writer saturated; dropping non-gating write")
                }
                mpsc::error::TrySendError::Closed(_) => {
                    tracing::error!("cache-db writer is gone")
                }
            }
        }
    }

    /// Queue a write and wait for its commit (fill commits).
    pub async fn write_wait(&self, mut entry: Entry) -> Result<()> {
        let (tx, rx) = oneshot::channel();
        entry.url.shrink_to_fit();
        self.writer
            .send(WriteOp::Upsert(Box::new(entry), Some(tx)))
            .await
            .map_err(|_| DbError::WriterGone)?;
        rx.await.map_err(|_| DbError::WriterGone)?
    }

    /// Delete entries and wait for the commit.
    pub async fn delete_wait(&self, keys: Vec<[u8; 32]>) -> Result<()> {
        if keys.is_empty() {
            return Ok(());
        }
        let (tx, rx) = oneshot::channel();
        self.writer
            .send(WriteOp::Delete(keys, Some(tx)))
            .await
            .map_err(|_| DbError::WriterGone)?;
        rx.await.map_err(|_| DbError::WriterGone)?
    }

    /// Flush batched touches (tests/shutdown).
    pub async fn flush(&self) -> Result<()> {
        let (tx, rx) = oneshot::channel();
        self.writer
            .send(WriteOp::Flush(tx))
            .await
            .map_err(|_| DbError::WriterGone)?;
        rx.await.map_err(|_| DbError::WriterGone)
    }
}

impl Drop for MetaDb {
    fn drop(&mut self) {
        // Swap our sender for a dead one so the writer loop sees the channel
        // close, drains what's queued (flushing touches), and exits; then
        // join so pending commits land before the process moves on.
        let (dummy, dummy_rx) = mpsc::channel(1);
        drop(dummy_rx);
        drop(std::mem::replace(&mut self.writer, dummy));
        if let Some(h) = self.writer_thread.lock().unwrap().take() {
            let _ = h.join();
        }
    }
}

fn writer_loop(conn: Connection, mut rx: mpsc::Receiver<WriteOp>) {
    let mut touches: std::collections::HashMap<[u8; 32], (f64, f64, u64)> =
        std::collections::HashMap::new();
    let mut last_flush = Instant::now();

    let flush_touches =
        |conn: &Connection, touches: &mut std::collections::HashMap<[u8; 32], (f64, f64, u64)>| {
            if touches.is_empty() {
                return;
            }
            let result = (|| -> rusqlite::Result<()> {
                let tx = conn.unchecked_transaction()?;
                {
                    let mut stmt = tx.prepare_cached(
                        "UPDATE cache_entries SET accessed_at = ?, expires_at = ?, \
                     hit_count = hit_count + ? WHERE cache_key = ?",
                    )?;
                    for (key, (at, exp, hits)) in touches.iter() {
                        stmt.execute(params![at, exp, *hits as i64, key.to_vec()])?;
                    }
                }
                tx.commit()
            })();
            if let Err(e) = result {
                tracing::error!("flushing {} cache touches: {e}", touches.len());
            } else {
                tracing::debug!("flushed {} cache touches", touches.len());
            }
            touches.clear();
        };

    loop {
        let op = rx.blocking_recv();
        let Some(op) = op else {
            flush_touches(&conn, &mut touches);
            break;
        };
        match op {
            WriteOp::Touch {
                key,
                accessed_at,
                expires_at,
            } => {
                let slot = touches.entry(key).or_insert((0.0, 0.0, 0));
                slot.0 = accessed_at;
                slot.1 = expires_at;
                slot.2 += 1;
            }
            WriteOp::Upsert(entry, done) => {
                let r = upsert(&conn, &entry);
                if let Err(e) = &r {
                    tracing::error!("cache upsert for {}: {e}", hex(&entry.key));
                }
                if let Some(done) = done {
                    let _ = done.send(r.map_err(DbError::from));
                }
            }
            WriteOp::Delete(keys, done) => {
                let r = delete(&conn, &keys);
                if let Err(e) = &r {
                    tracing::error!("cache delete of {} keys: {e}", keys.len());
                }
                if let Some(done) = done {
                    let _ = done.send(r.map_err(DbError::from));
                }
            }
            WriteOp::Flush(done) => {
                flush_touches(&conn, &mut touches);
                let _ = done.send(());
            }
        }
        if touches.len() >= TOUCH_FLUSH_MAX || last_flush.elapsed() >= TOUCH_FLUSH_INTERVAL {
            flush_touches(&conn, &mut touches);
            last_flush = Instant::now();
        }
    }
    tracing::debug!("cache-db writer exiting");
}

fn upsert(conn: &Connection, e: &Entry) -> rusqlite::Result<()> {
    conn.prepare_cached(
        "INSERT OR REPLACE INTO cache_entries (\
             cache_key, url, upstream_name, status_code, created_at, accessed_at, \
             expires_at, ttl, content_length, etag, last_modified, content_sha256, \
             hit_count, negative_step) \
         VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
    )?
    .execute(params![
        e.key.to_vec(),
        e.url,
        e.upstream,
        e.status as i64,
        e.created_at,
        e.accessed_at,
        e.expires_at,
        e.ttl,
        e.size as i64,
        e.etag,
        e.last_modified,
        e.content_sha256.map(|s| s.to_vec()),
        e.hit_count as i64,
        e.negative_step as i64,
    ])?;
    Ok(())
}

fn delete(conn: &Connection, keys: &[[u8; 32]]) -> rusqlite::Result<()> {
    let tx = conn.unchecked_transaction()?;
    {
        let mut stmt = tx.prepare_cached("DELETE FROM cache_entries WHERE cache_key = ?")?;
        for key in keys {
            stmt.execute(params![key.to_vec()])?;
        }
    }
    tx.commit()
}
