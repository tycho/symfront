//! The on-disk cache: sharded data tree + temp dir + metadata db glue,
//! plus the maintenance passes (eviction, patrol scrub).
//!
//! Layout under the cache root:
//!
//! ```text
//! <cache root>/
//!   metadata.db            # SQLite (WAL)
//!   data/aa/bb/<hex64>     # payloads, sharded by key prefix
//!   tmp/<hex64>.<nonce>    # in-progress fills (crash leftovers reaped)
//! ```

use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::SystemTime;

use crate::config::TtlPolicy;
use crate::db::{DbError, Entry, MetaDb, WriteOp};
use crate::key::{hex, unhex32, CacheKey};

pub fn now_unix() -> f64 {
    SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .map(|d| d.as_secs_f64())
        .unwrap_or(0.0)
}

pub fn parse_http_date(s: &str) -> Option<f64> {
    let t = httpdate::parse_http_date(s).ok()?;
    t.duration_since(SystemTime::UNIX_EPOCH)
        .ok()
        .map(|d| d.as_secs_f64())
}

pub fn format_http_date(unix: f64) -> String {
    let t = SystemTime::UNIX_EPOCH + std::time::Duration::from_secs_f64(unix.max(0.0));
    httpdate::fmt_http_date(t)
}

pub struct CacheStore {
    pub db: MetaDb,
    root: PathBuf,
    data_dir: PathBuf,
    tmp_dir: PathBuf,
    temp_nonce: AtomicU64,
}

impl CacheStore {
    pub fn open(root: &Path) -> Result<CacheStore, DbError> {
        let data_dir = root.join("data");
        let tmp_dir = root.join("tmp");
        for d in [&data_dir, &tmp_dir] {
            std::fs::create_dir_all(d)
                .map_err(|e| DbError::Other(format!("{}: {e}", d.display())))?;
        }
        let db = MetaDb::open(&root.join("metadata.db"))?;
        Ok(CacheStore {
            db,
            root: root.to_path_buf(),
            data_dir,
            tmp_dir,
            temp_nonce: AtomicU64::new(1),
        })
    }

    pub fn root(&self) -> &Path {
        &self.root
    }

    /// Final payload path for a key: `data/aa/bb/<hex64>`.
    pub fn data_path(&self, key: &[u8; 32]) -> PathBuf {
        let h = hex(key);
        self.data_dir.join(&h[0..2]).join(&h[2..4]).join(&h)
    }

    /// The path nginx serves for a key in X-Accel mode, relative to the
    /// data dir (the internal location aliases `data/`).
    pub fn accel_rel_path(&self, key: &[u8; 32]) -> String {
        let h = hex(key);
        format!("{}/{}/{}", &h[0..2], &h[2..4], h)
    }

    /// A fresh temp path for a fill of `key`.
    pub fn temp_path(&self, key: &[u8; 32]) -> PathBuf {
        let nonce = self.temp_nonce.fetch_add(1, Ordering::Relaxed);
        self.tmp_dir
            .join(format!("{}.{}.{}", hex(key), std::process::id(), nonce))
    }

    /// Remove stale in-progress files from a previous run.
    pub fn clean_stale_temps(&self) {
        let Ok(rd) = std::fs::read_dir(&self.tmp_dir) else {
            return;
        };
        let mut removed = 0u32;
        for ent in rd.flatten() {
            if ent.path().is_file() && std::fs::remove_file(ent.path()).is_ok() {
                removed += 1;
            }
        }
        if removed > 0 {
            tracing::info!("removed {removed} stale cache temp file(s)");
        }
    }

    /// Slide a positive entry's expiry on a hit (batched, fire-and-forget).
    pub fn touch_positive(&self, entry: &Entry, ttl: &TtlPolicy) {
        let now = now_unix();
        self.db.write_nowait(WriteOp::Touch {
            key: entry.key,
            accessed_at: now,
            expires_at: now + ttl.positive.as_secs_f64(),
        });
    }

    /// Build a negative entry for `key`, advancing the ladder if an expired
    /// negative entry existed before.
    pub fn negative_entry(
        &self,
        key: &CacheKey,
        status: u16,
        previous: Option<&Entry>,
        ttl: &TtlPolicy,
    ) -> Entry {
        let step = match previous {
            // Re-confirmed miss after the previous negative TTL ran out:
            // advance one step (saturating at the ladder end).
            Some(prev) if !prev.is_positive() => {
                (prev.negative_step + 1).min(ttl.max_step())
            }
            _ => 0,
        };
        let now = now_unix();
        let ttl_secs = ttl.negative_ttl(step).as_secs_f64();
        Entry {
            key: key.hash,
            url: key.full_url.clone(),
            upstream: key.upstream_name.clone(),
            status,
            created_at: now,
            accessed_at: now,
            expires_at: now + ttl_secs,
            ttl: ttl_secs,
            size: 0,
            etag: None,
            last_modified: None,
            content_sha256: None,
            hit_count: 0,
            negative_step: step,
        }
    }

    /// Delete entries (rows + data files). Returns bytes freed.
    pub async fn evict_keys(&self, keys: &[[u8; 32]], sizes: &[u64]) -> Result<u64, DbError> {
        self.db.delete_wait(keys.to_vec()).await?;
        let paths: Vec<PathBuf> = keys.iter().map(|k| self.data_path(k)).collect();
        let freed: u64 = sizes.iter().sum();
        tokio::task::spawn_blocking(move || {
            for p in paths {
                match std::fs::remove_file(&p) {
                    Ok(()) => {}
                    Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
                    Err(e) => tracing::warn!("removing {}: {e}", p.display()),
                }
            }
        })
        .await
        .map_err(|e| DbError::Other(e.to_string()))?;
        Ok(freed)
    }

    /// Walk the data tree, yielding (key, path, size) for every payload file
    /// and flagging unparseable names.
    pub fn walk_data(
        &self,
        mut f: impl FnMut(Option<[u8; 32]>, &Path, u64),
    ) -> std::io::Result<()> {
        fn walk(
            dir: &Path,
            depth: u32,
            f: &mut impl FnMut(Option<[u8; 32]>, &Path, u64),
        ) -> std::io::Result<()> {
            for ent in std::fs::read_dir(dir)?.flatten() {
                let path = ent.path();
                let Ok(md) = ent.metadata() else { continue };
                if md.is_dir() {
                    if depth < 2 {
                        walk(&path, depth + 1, f)?;
                    }
                    continue;
                }
                let key = path
                    .file_name()
                    .and_then(|n| n.to_str())
                    .and_then(unhex32);
                f(key, &path, md.len());
            }
            Ok(())
        }
        walk(&self.data_dir, 0, &mut f)
    }
}
