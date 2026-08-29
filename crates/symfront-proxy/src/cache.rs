//! The on-disk cache: sharded storage tree + temp dir + metadata db glue,
//! plus the maintenance passes (eviction, patrol scrub).
//!
//! Layout: three directories, each independently configurable so they can
//! be separate filesystems (ZFS datasets with their own recordsize and
//! compression). Defaults sit under the cache root:
//!
//! ```text
//! <cache root>/
//!   db/metadata.db          # SQLite (WAL)          -- cache.path_db
//!   storage/aa/bb/<hex64>   # payloads, sharded     -- cache.path_storage
//!   temp/<hex64>.<nonce>    # in-progress fills     -- cache.path_temp
//! ```
//!
//! Two things follow from wherever they're pointed:
//!
//! - Completing a fill renames temp → storage, which is cheap only within
//!   one filesystem. Split them and every fill pays a full copy instead
//!   (warned at open, handled in [`crate::fill`]).
//! - Nesting db or temp *inside* storage is fine: [`CacheLayout`] reports
//!   them as excludes and the scrub walk skips them, so in-flight fills
//!   are never mistaken for orphans.

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

/// Where each part of the cache lives. Defaults are `db/`, `storage/` and
/// `temp/` under the root, but each is configurable (`cache.path_db`,
/// `cache.path_storage`, `cache.path_temp`) so they can be put on separate
/// filesystems — or nested inside one another.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CacheLayout {
    pub root: PathBuf,
    pub db_dir: PathBuf,
    pub storage_dir: PathBuf,
    pub temp_dir: PathBuf,
}

impl CacheLayout {
    /// The default layout under a cache root.
    pub fn under(root: impl Into<PathBuf>) -> CacheLayout {
        let root = root.into();
        CacheLayout {
            db_dir: root.join("db"),
            storage_dir: root.join("storage"),
            temp_dir: root.join("temp"),
            root,
        }
    }

    /// Reject layouts that would eat their own data. Nesting db or temp
    /// inside storage is allowed — [`CacheLayout::storage_excludes`] keeps
    /// the scrub out of them — but the reverse isn't: storage under a dir
    /// the scrub skips would hide every payload, and a db under temp would
    /// be reaped as a crash leftover.
    pub fn validate(&self) -> Result<(), String> {
        let (db, storage, temp) = (
            normalize(&self.db_dir),
            normalize(&self.storage_dir),
            normalize(&self.temp_dir),
        );
        for (a, an, b, bn) in [
            (&db, "path_db", &storage, "path_storage"),
            (&db, "path_db", &temp, "path_temp"),
            (&storage, "path_storage", &temp, "path_temp"),
        ] {
            if a == b {
                return Err(format!(
                    "cache.{an} and cache.{bn} must be different directories (both {})",
                    a.display()
                ));
            }
        }
        for (inner, iname, outer, oname) in [
            (&storage, "path_storage", &temp, "path_temp"),
            (&storage, "path_storage", &db, "path_db"),
            (&db, "path_db", &temp, "path_temp"),
        ] {
            if inner.starts_with(outer) {
                return Err(format!(
                    "cache.{iname} ({}) must not be inside cache.{oname} ({})",
                    inner.display(),
                    outer.display()
                ));
            }
        }
        Ok(())
    }

    /// Directories to skip when walking the storage tree: whichever of the
    /// db and temp dirs were configured inside it.
    pub fn storage_excludes(&self) -> Vec<PathBuf> {
        let storage = normalize(&self.storage_dir);
        [&self.db_dir, &self.temp_dir]
            .into_iter()
            .map(|d| normalize(d))
            .filter(|d| *d != storage && d.starts_with(&storage))
            .collect()
    }

    /// The same layout with every directory resolved through symlinks.
    /// Only meaningful once they exist, so [`CacheStore::open`] calls it
    /// after creating them: a temp dir reached by symlink (or spelled with
    /// `..`) has to compare equal to its real location, or the scrub would
    /// walk into it.
    pub fn resolved(&self) -> CacheLayout {
        let resolve = |p: &Path| std::fs::canonicalize(p).unwrap_or_else(|_| normalize(p));
        CacheLayout {
            root: resolve(&self.root),
            db_dir: resolve(&self.db_dir),
            storage_dir: resolve(&self.storage_dir),
            temp_dir: resolve(&self.temp_dir),
        }
    }
}

/// Absolute and lexically normalized (`.` and `..` folded away), so
/// configured paths can be compared before they exist. `std::path::absolute`
/// deliberately leaves `..` in place — correct in general, since a symlinked
/// parent makes the fold wrong, which is why [`CacheLayout::resolved`]
/// canonicalizes for real once the directories are there.
fn normalize(p: &Path) -> PathBuf {
    use std::path::Component;
    let abs = std::path::absolute(p).unwrap_or_else(|_| p.to_path_buf());
    let mut out = PathBuf::new();
    for c in abs.components() {
        match c {
            Component::CurDir => {}
            Component::ParentDir => {
                out.pop();
            }
            c => out.push(c),
        }
    }
    out
}

pub struct CacheStore {
    pub db: MetaDb,
    root: PathBuf,
    db_path: PathBuf,
    storage_dir: PathBuf,
    temp_dir: PathBuf,
    /// Directories inside the storage tree that aren't payloads (a nested
    /// db or temp dir); the scrub walk skips them.
    storage_excludes: Vec<PathBuf>,
    temp_nonce: AtomicU64,
    /// Per-open discriminator so temp names can't collide across engine
    /// generations (config reloads rebuild the engine over the same cache
    /// dir while the old engine's fills may still be running).
    temp_boot: u64,
}

/// Temp files older than this are crash leftovers; anything younger may be
/// an in-flight fill of this — or a previous — engine generation.
const STALE_TEMP_AGE: std::time::Duration = std::time::Duration::from_secs(24 * 3600);

impl CacheStore {
    pub fn open(layout: &CacheLayout) -> Result<CacheStore, DbError> {
        layout.validate().map_err(DbError::Other)?;
        check_legacy_layout(layout)?;
        for d in [&layout.db_dir, &layout.storage_dir, &layout.temp_dir] {
            std::fs::create_dir_all(d)
                .map_err(|e| DbError::Other(format!("{}: {e}", d.display())))?;
        }
        // From here on work with the resolved paths: the scrub compares
        // directories against the exclude list, so neither a symlink nor a
        // `..` may hide a nested temp dir from it. Re-validate afterwards —
        // symlinks can nest what the configured spelling kept apart.
        let layout = layout.resolved();
        layout.validate().map_err(DbError::Other)?;
        let storage_excludes = layout.storage_excludes();
        let CacheLayout {
            root,
            db_dir,
            storage_dir,
            temp_dir,
        } = layout;
        warn_if_split_filesystems(&temp_dir, &storage_dir);
        let db_path = db_dir.join("metadata.db");
        let db = MetaDb::open(&db_path)?;
        let temp_boot = SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .map(|d| d.as_nanos() as u64)
            .unwrap_or(0)
            ^ ((std::process::id() as u64) << 48);
        Ok(CacheStore {
            db,
            temp_boot,
            root,
            db_path,
            storage_dir,
            temp_dir,
            storage_excludes,
            temp_nonce: AtomicU64::new(1),
        })
    }

    pub fn root(&self) -> &Path {
        &self.root
    }

    /// The SQLite metadata db (`db/metadata.db`).
    pub fn db_path(&self) -> &Path {
        &self.db_path
    }

    /// The payload tree (`storage/`).
    pub fn storage_dir(&self) -> &Path {
        &self.storage_dir
    }

    /// Final payload path for a key: `storage/aa/bb/<hex64>`.
    pub fn data_path(&self, key: &[u8; 32]) -> PathBuf {
        shard_path(&self.storage_dir, key)
    }

    /// The path nginx serves for a key in X-Accel mode, relative to the
    /// storage dir (the internal location aliases `storage/`).
    pub fn accel_rel_path(&self, key: &[u8; 32]) -> String {
        let h = hex(key);
        format!("{}/{}/{}", &h[0..2], &h[2..4], h)
    }

    /// A fresh temp path for a fill of `key`.
    pub fn temp_path(&self, key: &[u8; 32]) -> PathBuf {
        let nonce = self.temp_nonce.fetch_add(1, Ordering::Relaxed);
        self.temp_dir
            .join(format!("{}.{:016x}.{}", hex(key), self.temp_boot, nonce))
    }

    /// Remove crash leftovers from the temp dir. Runs on every engine
    /// construction — including config reloads, where the previous engine's
    /// fills may still be streaming — so only clearly-abandoned files
    /// (older than [`STALE_TEMP_AGE`]) are touched. Fills clean up their
    /// own temp files on abort/failure; only a crash leaks one.
    pub fn clean_stale_temps(&self) {
        let Ok(rd) = std::fs::read_dir(&self.temp_dir) else {
            return;
        };
        let mut removed = 0u32;
        for ent in rd.flatten() {
            let Ok(md) = ent.metadata() else { continue };
            let abandoned = md
                .modified()
                .ok()
                .and_then(|t| t.elapsed().ok())
                .map(|age| age > STALE_TEMP_AGE)
                .unwrap_or(false);
            if md.is_file() && abandoned && std::fs::remove_file(ent.path()).is_ok() {
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
            Some(prev) if !prev.is_positive() => (prev.negative_step + 1).min(ttl.max_step()),
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

    /// Walk the storage tree, yielding (key, path, size) for every payload file
    /// and flagging unparseable names. A db or temp dir configured *inside*
    /// the storage tree is skipped: those files aren't payloads and their
    /// names don't parse as keys, so a scrub that walked into them would
    /// delete live downloads (and the metadata db) as orphans.
    pub fn walk_data(
        &self,
        mut f: impl FnMut(Option<[u8; 32]>, &Path, u64),
    ) -> std::io::Result<()> {
        fn walk(
            dir: &Path,
            depth: u32,
            skip: &[PathBuf],
            f: &mut impl FnMut(Option<[u8; 32]>, &Path, u64),
        ) -> std::io::Result<()> {
            for ent in std::fs::read_dir(dir)?.flatten() {
                let path = ent.path();
                let Ok(md) = ent.metadata() else { continue };
                if md.is_dir() {
                    if depth < 2 && !skip.contains(&path) {
                        walk(&path, depth + 1, skip, f)?;
                    }
                    continue;
                }
                let key = path.file_name().and_then(|n| n.to_str()).and_then(unhex32);
                f(key, &path, md.len());
            }
            Ok(())
        }
        walk(&self.storage_dir, 0, &self.storage_excludes, &mut f)
    }
}

/// `<dir>/aa/bb/<hex64>` for a key — the sharding the storage tree uses.
pub fn shard_path(dir: &Path, key: &[u8; 32]) -> PathBuf {
    let h = hex(key);
    dir.join(&h[0..2]).join(&h[2..4]).join(&h)
}

/// Refuse to run against a cache root still in the flat layout
/// (`metadata.db` + `data/` + `tmp/` at the root). Starting anyway would
/// silently ignore the payloads already there and refill from upstream, so
/// say what to move instead.
fn check_legacy_layout(layout: &CacheLayout) -> Result<(), DbError> {
    let root = &layout.root;
    let legacy_db = root.join("metadata.db");
    let legacy_data = root.join("data");
    // Already migrated, or deliberately pointed back at the old dirs.
    let configured_away = layout.db_dir.join("metadata.db").is_file()
        || normalize(&layout.storage_dir) == normalize(&legacy_data);
    if !(legacy_db.is_file() || legacy_data.is_dir()) || configured_away {
        return Ok(());
    }
    let r = root.display();
    Err(DbError::Other(format!(
        "{r} is in the old flat cache layout; move it into db/ + storage/:\n  \
         mkdir -p {r}/db && mv {r}/metadata.db* {r}/db/\n  \
         mv {r}/data {r}/storage\n  \
         mv {r}/tmp {r}/temp\n\
         …or point cache.path_db / cache.path_storage at the old directories."
    )))
}

/// Completing a fill renames the temp file to `storage/aa/bb/<key>`; that
/// only works within one filesystem. Pointing them at separate ones is
/// legal (the fill path falls back to a copy) but costs a full extra
/// read+write per fill, so it should never happen unnoticed.
fn warn_if_split_filesystems(temp_dir: &Path, storage_dir: &Path) {
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        let dev = |p: &Path| std::fs::metadata(p).map(|m| m.dev()).ok();
        if let (Some(a), Some(b)) = (dev(temp_dir), dev(storage_dir)) {
            if a != b {
                tracing::warn!(
                    "{} and {} are on different filesystems: every completed fill \
                     pays a copy instead of a rename",
                    temp_dir.display(),
                    storage_dir.display()
                );
            }
        }
    }
    #[cfg(not(unix))]
    let _ = (temp_dir, storage_dir);
}
