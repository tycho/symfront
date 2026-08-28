//! Local `symfront proxy ...` commands: cache summary, maintenance passes,
//! and the one-shot import from the Python symsrv cache.
//!
//! These operate directly on the cache directory named in proxy.toml. WAL
//! journaling makes that safe alongside a running server; maintenance
//! passes are the same code the server's jobs run.

use std::path::Path;

use anyhow::{bail, Context, Result};
use symfront_proxy::maintenance::MaintProgress;

use crate::cli::human;

fn engine_for(config_dir: &Path) -> Result<std::sync::Arc<symfront_proxy::ProxyEngine>> {
    match crate::pipeline::build_engine(config_dir)? {
        Some(e) => Ok(e),
        None => bail!(
            "no proxy configured in {} (need upstreams.toml with at least one upstream)",
            config_dir.display()
        ),
    }
}

fn runtime() -> Result<tokio::runtime::Runtime> {
    Ok(tokio::runtime::Builder::new_multi_thread()
        .worker_threads(2)
        .enable_all()
        .build()?)
}

pub fn stats(config_dir: &Path) -> Result<()> {
    let engine = engine_for(config_dir)?;
    println!("cache: {}", engine.config.cache_path.display());
    let rows = engine.cache.db.summary()?;
    if rows.is_empty() {
        println!("cache is empty");
        return Ok(());
    }
    let mut positive = (0u64, 0u64);
    let mut negative = 0u64;
    println!("{:<20} {:>10} {:>12} {:>10}", "upstream", "entries", "bytes", "kind");
    for (upstream, is_positive, count, bytes) in &rows {
        let kind = if *is_positive { "positive" } else { "negative" };
        println!("{upstream:<20} {count:>10} {:>12} {kind:>10}", human(*bytes));
        if *is_positive {
            positive.0 += count;
            positive.1 += bytes;
        } else {
            negative += count;
        }
    }
    println!(
        "\n{} positive entries ({}), {} negative entries",
        positive.0,
        human(positive.1),
        negative
    );
    if let Some(size) = engine.config.cache_size {
        println!(
            "budget: {} ({:.1}% used)",
            human(size),
            positive.1 as f64 / size as f64 * 100.0
        );
    }
    println!("\nnote: live request counters exist on the running server; use --server for them");
    Ok(())
}

pub fn evict(config_dir: &Path) -> Result<()> {
    let engine = engine_for(config_dir)?;
    let rt = runtime()?;
    let report = rt.block_on(async {
        let progress = MaintProgress::default();
        engine.evict_pass(&progress).await
    });
    if !report.enabled {
        println!("eviction disabled (no cache.size configured)");
        return Ok(());
    }
    println!(
        "evicted {} entries ({}); cache {} -> {}",
        report.evicted_entries,
        human(report.evicted_bytes),
        human(report.before_bytes),
        human(report.after_bytes)
    );
    Ok(())
}

pub fn scrub(config_dir: &Path, repair: bool) -> Result<()> {
    let engine = engine_for(config_dir)?;
    let rt = runtime()?;
    let report = rt.block_on(async {
        let progress = MaintProgress::default();
        engine.scrub(repair, &progress).await
    })?;
    println!(
        "scanned {} data files against {} rows",
        report.data_files, report.db_rows
    );
    println!(
        "orphan files: {} ({}); rows missing data: {}; size mismatches: {}",
        report.orphan_files,
        human(report.orphan_bytes),
        report.rows_missing_data,
        report.size_mismatches
    );
    println!(
        "{}",
        if repair {
            "repaired (orphans removed both directions)"
        } else {
            "report only; rerun without --report-only to repair"
        }
    );
    Ok(())
}

/// Import the Python symsrv cache: walk its metadata.db, map rows into the
/// new schema, and hardlink (or copy) the payload files into the new
/// layout. Keying is unchanged (sha256 of the upstream URL), so entries
/// carry over verbatim; ladder state starts at step 0.
pub fn import(config_dir: &Path, from: &Path, copy: bool, dry_run: bool) -> Result<()> {
    let engine = engine_for(config_dir)?;
    let old_db_path = from.join("db/metadata.db");
    let old_data = from.join("storage/data");
    if !old_db_path.is_file() {
        bail!("{} not found (expected a symsrv cache root)", old_db_path.display());
    }
    if !old_data.is_dir() {
        bail!("{} not found", old_data.display());
    }
    let new_root = engine.config.cache_path.clone();
    let new_db_path = new_root.join("metadata.db");
    // The engine created the schema; from here plain connections suffice.
    drop(engine);

    let old = rusqlite::Connection::open_with_flags(
        &old_db_path,
        rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY,
    )
    .with_context(|| old_db_path.display().to_string())?;
    let new = rusqlite::Connection::open(&new_db_path)?;
    new.busy_timeout(std::time::Duration::from_secs(30))?;

    let total: i64 = old.query_row("SELECT COUNT(*) FROM cache_entries", [], |r| r.get(0))?;
    println!(
        "importing {total} entries from {} -> {}{}",
        from.display(),
        new_root.display(),
        if dry_run { " (dry run)" } else { "" }
    );

    let mut stmt = old.prepare(
        "SELECT cache_key, url, upstream_name, status_code, created_at, accessed_at, \
         ttl, content_length, etag, last_modified, content_sha256 FROM cache_entries",
    )?;
    let mut rows = stmt.query([])?;

    let mut imported_pos = 0u64;
    let mut imported_neg = 0u64;
    let mut linked = 0u64;
    let mut copied = 0u64;
    let mut missing = 0u64;
    let mut bytes = 0u64;
    let mut batch = 0usize;
    if !dry_run {
        new.execute_batch("BEGIN")?;
    }
    while let Some(row) = rows.next()? {
        let key: Vec<u8> = row.get(0)?;
        if key.len() != 32 {
            continue;
        }
        let url: String = row.get(1)?;
        let upstream: String = row.get(2)?;
        let status: i64 = row.get(3)?;
        let created_at: f64 = row.get(4)?;
        let accessed_at: f64 = row.get(5)?;
        let ttl: f64 = row.get(6)?;
        let size: i64 = row.get(7)?;
        let etag: Option<String> = row.get(8)?;
        let last_modified: Option<f64> = row.get(9)?;
        let sha: Option<Vec<u8>> = row.get(10)?;
        let expires_at = if status == 200 {
            accessed_at + ttl
        } else {
            created_at + ttl
        };
        let hex = symfront_proxy::key::hex(&key);

        if status == 200 {
            // Bring the payload over; a row without its file is dead weight.
            let old_file = old_data.join(&hex[0..2]).join(&hex[2..4]).join(&hex);
            if !old_file.is_file() {
                missing += 1;
                continue;
            }
            let new_file = new_root.join("data").join(&hex[0..2]).join(&hex[2..4]).join(&hex);
            if !dry_run && !new_file.exists() {
                std::fs::create_dir_all(new_file.parent().unwrap())?;
                if copy {
                    std::fs::copy(&old_file, &new_file)?;
                    copied += 1;
                } else {
                    match std::fs::hard_link(&old_file, &new_file) {
                        Ok(()) => linked += 1,
                        Err(_) => {
                            // Cross-dataset (EXDEV) or fs without links.
                            std::fs::copy(&old_file, &new_file)?;
                            copied += 1;
                        }
                    }
                }
            }
            bytes += size as u64;
            imported_pos += 1;
        } else {
            imported_neg += 1;
        }
        if !dry_run {
            new.execute(
                "INSERT OR REPLACE INTO cache_entries (\
                     cache_key, url, upstream_name, status_code, created_at, accessed_at, \
                     expires_at, ttl, content_length, etag, last_modified, content_sha256, \
                     hit_count, negative_step) \
                 VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 0, 0)",
                rusqlite::params![
                    key,
                    url,
                    upstream,
                    status,
                    created_at,
                    accessed_at,
                    expires_at,
                    ttl,
                    size,
                    etag,
                    last_modified,
                    sha,
                ],
            )?;
            batch += 1;
            if batch >= 2000 {
                new.execute_batch("COMMIT; BEGIN")?;
                batch = 0;
                eprint!("\r{} / {total} entries", imported_pos + imported_neg);
            }
        }
    }
    if !dry_run {
        new.execute_batch("COMMIT")?;
        eprintln!();
    }
    println!(
        "imported {imported_pos} positive ({}) + {imported_neg} negative entries; \
         {linked} hardlinked, {copied} copied, {missing} rows skipped (payload missing)",
        human(bytes)
    );
    if dry_run {
        println!("dry run: nothing was written");
    }
    Ok(())
}
