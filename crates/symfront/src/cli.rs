//! CLI subcommands operating directly on a local store.

use std::io::Write as _;
use std::path::Path;
use std::sync::atomic::Ordering;
use std::sync::Arc;

use anyhow::{bail, Context};
use symfront_store::index::StoreIndex;
use symfront_store::scan::{self, ScanProgress, ScanResult};
use symfront_store::{check, ops, strays, Store, TransactionId};

pub fn human(bytes: u64) -> String {
    const UNITS: [&str; 6] = ["B", "KiB", "MiB", "GiB", "TiB", "PiB"];
    let mut v = bytes as f64;
    let mut u = 0;
    while v >= 1024.0 && u < UNITS.len() - 1 {
        v /= 1024.0;
        u += 1;
    }
    if u == 0 {
        format!("{bytes} B")
    } else {
        format!("{v:.1} {}", UNITS[u])
    }
}

fn open(store_path: &Path) -> anyhow::Result<(Store, StoreIndex)> {
    let store = Store::open(store_path)
        .with_context(|| format!("opening store at {}", store_path.display()))?;
    let index = StoreIndex::load(&store).context("loading store index")?;
    Ok((store, index))
}

/// Run a scan with a live progress line on stderr.
fn scan_with_progress(store: &Store, deep: bool) -> anyhow::Result<ScanResult> {
    let progress = Arc::new(ScanProgress::default());
    let ticker = {
        let progress = Arc::clone(&progress);
        std::thread::spawn(move || {
            while !progress.done.load(Ordering::Relaxed) {
                eprint!(
                    "\rscanning... {} files in {} dirs",
                    progress.files.load(Ordering::Relaxed),
                    progress.dirs.load(Ordering::Relaxed)
                );
                let _ = std::io::stderr().flush();
                std::thread::sleep(std::time::Duration::from_millis(200));
            }
            eprint!("\r\x1b[K");
            let _ = std::io::stderr().flush();
        })
    };
    let result = scan::scan(store, deep, &progress);
    progress.done.store(true, Ordering::Relaxed);
    let _ = ticker.join();
    Ok(result?)
}

/// Run a mutating op with a live progress line on stderr.
fn with_op_progress<T>(
    verb: &str,
    f: impl FnOnce(&ops::OpProgress) -> symfront_store::Result<T>,
) -> symfront_store::Result<T> {
    let progress = Arc::new(ops::OpProgress::default());
    let finished = Arc::new(std::sync::atomic::AtomicBool::new(false));
    let ticker = {
        let progress = Arc::clone(&progress);
        let finished = Arc::clone(&finished);
        let verb = verb.to_string();
        std::thread::spawn(move || {
            while !finished.load(Ordering::Relaxed) {
                let s = progress.snapshot();
                if s.total > 0 {
                    eprint!(
                        "\r{verb}... {}/{} dirs, {} files, {} freed",
                        s.done,
                        s.total,
                        s.files_removed,
                        human(s.freed_apparent)
                    );
                    let _ = std::io::stderr().flush();
                }
                std::thread::sleep(std::time::Duration::from_millis(200));
            }
            eprint!("\r\x1b[K");
            let _ = std::io::stderr().flush();
        })
    };
    let result = f(&progress);
    finished.store(true, Ordering::Relaxed);
    let _ = ticker.join();
    result
}

pub fn init(store_path: &Path) -> anyhow::Result<()> {
    let admin = store_path.join("000Admin");
    if admin.is_dir() {
        bail!("{} already looks like a symbol store", store_path.display());
    }
    std::fs::create_dir_all(&admin)?;
    // Some HTTP clients (e.g. Ghidra) require pingme.txt to consider the
    // server alive; symstore.exe-compatible admin files appear on first add.
    std::fs::write(store_path.join("pingme.txt"), b"")?;
    println!("initialized empty symbol store at {}", store_path.display());
    Ok(())
}

pub fn upload(
    store_path: &Path,
    paths: &[std::path::PathBuf],
    product: &str,
    version: &str,
    comment: &str,
    dry_run: bool,
) -> anyhow::Result<()> {
    if paths.is_empty() {
        bail!("no paths given");
    }
    let (candidates, skipped) = symfront_ident::collect(paths)?;
    for s in &skipped {
        println!("skipped (not a PE or PDB): {}", s.display());
    }
    if candidates.is_empty() {
        bail!("no identifiable PE/PDB files found");
    }
    println!("{} file(s) identified:", candidates.len());
    for c in &candidates {
        println!("  {:?}  {}/{}  <- {}", c.kind, c.name, c.hash, c.path.display());
    }
    let store = Store::open(store_path)?;
    let req = ops::AddRequest {
        product: product.into(),
        version: version.into(),
        comment: comment.into(),
        consume: false,
        files: candidates
            .iter()
            .map(|c| ops::AddFile {
                path: c.path.clone(),
                name: c.name.clone(),
                hash: c.hash.clone(),
                kind: c.kind,
                source: c.path.to_string_lossy().into_owned(),
            })
            .collect(),
    };
    let out = with_op_progress("adding", |p| ops::add_transaction(&store, &req, dry_run, p))?;
    let verb = if dry_run { "would add" } else { "added" };
    println!(
        "{verb} transaction {}: {} new payload(s) ({}), {} deduplicated",
        out.id
            .map(|i| i.to_string())
            .unwrap_or_else(|| "(dry run)".into()),
        out.files_new,
        human(out.bytes_copied),
        out.files_deduped
    );
    for w in &out.warnings {
        println!("  warning: {w}");
    }
    Ok(())
}

pub fn status(store_path: &Path) -> anyhow::Result<()> {
    let (store, index) = open(store_path)?;
    let active = index.active_transactions().count();
    let deleted = index
        .transactions
        .values()
        .filter(|t| !t.deleted_by.is_empty())
        .count();
    println!("store:        {}", store.root().display());
    println!("last id:      {}", index.lastid.map(|i| i.to_string()).unwrap_or_else(|| "?".into()));
    println!("transactions: {active} active, {deleted} deleted, {} del records", index.dels.len());
    println!("entries:      {} indexed files", index.entries.len());
    println!("hash dirs:    {} referenced", index.referenced_dirs().len());
    let journals = ops::pending_journals(&store)?;
    if !journals.is_empty() {
        println!(
            "WARNING: interrupted operations pending: {}",
            journals
                .iter()
                .map(|(j, k)| format!("{j} ({k:?})"))
                .collect::<Vec<_>>()
                .join(", ")
        );
    }
    Ok(())
}

pub fn tx_list(store_path: &Path, all: bool, sizes: bool) -> anyhow::Result<()> {
    let (store, index) = open(store_path)?;
    let analysis = if sizes {
        let scan = scan_with_progress(&store, false)?;
        Some(strays::analyze(&index, &scan))
    } else {
        None
    };

    if sizes {
        println!("{:>10}  {:<10} {:>7}  {:>10} {:>10} {:>10}  {:<28} {}", "id", "date", "entries", "apparent", "on-disk", "exclusive", "product", "version");
    } else {
        println!("{:>10}  {:<10} {:>7}  {:<28} {}", "id", "date", "entries", "product", "version");
    }
    for t in index.transactions.values() {
        let active = t.is_active();
        if !all && !active {
            continue;
        }
        let (date, product, version) = t
            .record
            .as_ref()
            .map(|r| (r.date.clone(), r.product.clone(), r.version.clone()))
            .unwrap_or_default();
        let incomplete = analysis
            .as_ref()
            .map(|a| a.tx_issues.contains_key(&t.id))
            .unwrap_or(false);
        let flag = if !t.deleted_by.is_empty() {
            " [deleted]"
        } else if !active {
            " [anomalous]"
        } else if incomplete {
            " [incomplete]"
        } else {
            ""
        };
        if let Some(a) = &analysis {
            let s = a.tx_sizes.get(&t.id).copied().unwrap_or_default();
            println!(
                "{:>10}  {:<10} {:>7}  {:>10} {:>10} {:>10}  {:<28} {}{flag}",
                t.id.to_string(),
                date,
                t.entry_count,
                human(s.apparent),
                human(s.disk),
                human(s.exclusive_apparent),
                truncate(&product, 28),
                version,
            );
        } else {
            println!(
                "{:>10}  {:<10} {:>7}  {:<28} {}{flag}",
                t.id.to_string(),
                date,
                t.entry_count,
                truncate(&product, 28),
                version,
            );
        }
    }
    Ok(())
}

fn truncate(s: &str, n: usize) -> String {
    if s.chars().count() <= n {
        s.to_string()
    } else {
        let cut: String = s.chars().take(n - 1).collect();
        format!("{cut}…")
    }
}

pub fn tx_show(store_path: &Path, id: TransactionId) -> anyhow::Result<()> {
    let (store, index) = open(store_path)?;
    let Some(t) = index.transactions.get(&id) else {
        bail!("transaction {id} not found");
    };
    println!("transaction {id}");
    if let Some(r) = &t.record {
        println!("  kind:    {:?} add", r.kind);
        println!("  date:    {} {}", r.date, r.time);
        println!("  product: {}", r.product);
        if !r.version.is_empty() {
            println!("  version: {}", r.version);
        }
        if !r.comment.is_empty() {
            println!("  comment: {}", r.comment);
        }
    }
    if !t.deleted_by.is_empty() {
        println!(
            "  DELETED by {}",
            t.deleted_by.iter().map(|d| d.to_string()).collect::<Vec<_>>().join(", ")
        );
    }
    println!("  manifest: {:?}, {} entries", t.file_state, t.entry_count);

    let entries = symfront_store::index::load_entries(&store, id)?;
    // Stat just this transaction's dirs rather than walking the whole store.
    let mut total_size = 0u64;
    let mut total_disk = 0u64;
    let mut missing = 0usize;
    println!();
    println!("{:>12} {:>12}  {}", "apparent", "on-disk", "path");
    for e in &entries {
        let dir = store.hash_dir(&e.name, &e.hash);
        let (mut size, mut disk, mut found) = (0u64, 0u64, false);
        if let Ok(rd) = std::fs::read_dir(&dir) {
            for ent in rd.flatten() {
                if let Ok(md) = ent.metadata() {
                    if md.is_file() {
                        use std::os::unix::fs::MetadataExt;
                        size += md.len();
                        disk += md.blocks() * 512;
                        found = true;
                    }
                }
            }
        }
        total_size += size;
        total_disk += disk;
        let marker = if found {
            String::new()
        } else {
            missing += 1;
            "  [MISSING]".to_string()
        };
        println!(
            "{:>12} {:>12}  {}/{}{marker}   <- {}",
            human(size),
            human(disk),
            e.name,
            e.hash,
            e.source
        );
    }
    println!();
    println!(
        "  {} entries, {} apparent, {} on disk{}",
        entries.len(),
        human(total_size),
        human(total_disk),
        if missing > 0 {
            format!(", {missing} MISSING")
        } else {
            String::new()
        }
    );
    println!("  (sizes include refs.ptr and are shared with other transactions referencing the same dirs)");
    Ok(())
}

pub fn tx_del(store_path: &Path, id: TransactionId, dry_run: bool, yes: bool) -> anyhow::Result<()> {
    let (store, index) = open(store_path)?;
    let Some(t) = index.transactions.get(&id) else {
        bail!("transaction {id} not found");
    };
    if !t.is_active() {
        bail!("transaction {id} is not active");
    }
    if !dry_run && !yes {
        let product = t.record.as_ref().map(|r| r.product.as_str()).unwrap_or("?");
        eprint!(
            "delete transaction {id} ({product}, {} entries)? [y/N] ",
            t.entry_count
        );
        std::io::stderr().flush()?;
        let mut line = String::new();
        std::io::stdin().read_line(&mut line)?;
        if !matches!(line.trim(), "y" | "Y" | "yes") {
            bail!("aborted");
        }
    }
    let out = with_op_progress("deleting", |p| ops::delete_transaction(&store, id, dry_run, p))?;
    let verb = if dry_run { "would delete" } else { "deleted" };
    println!("{verb} transaction {id}:");
    println!("  {} entries", out.entries);
    println!("  {} dirs removed, {} still referenced by other transactions, {} already missing", out.dirs_removed, out.dirs_still_referenced, out.dirs_missing);
    println!("  {} files removed, freeing {} apparent / {} on disk", out.files_removed, human(out.freed_apparent), human(out.freed_disk));
    if let Some(del_id) = out.del_id {
        println!("  recorded as del transaction {del_id}");
    }
    for w in &out.warnings {
        println!("  warning: {w}");
    }
    Ok(())
}

pub fn search(store_path: &Path, query: &str, limit: usize) -> anyhow::Result<()> {
    let (_store, index) = open(store_path)?;
    let hits = index.search(query, limit);
    if hits.is_empty() {
        println!("no matches");
        return Ok(());
    }
    for h in &hits {
        println!(
            "{}/{}  tx {} ({} {})  <- {}",
            h.name,
            h.hash,
            h.tx,
            h.product.as_deref().unwrap_or("?"),
            h.version.as_deref().unwrap_or(""),
            h.source
        );
    }
    if hits.len() >= limit {
        println!("... (limited to {limit}; use --limit to see more)");
    }
    Ok(())
}

pub fn strays(store_path: &Path, prune: bool, dry_run: bool) -> anyhow::Result<()> {
    let (store, index) = open(store_path)?;
    let scan = scan_with_progress(&store, true)?;
    let analysis = strays::analyze(&index, &scan);
    let report = &analysis.strays;

    if report.strays.is_empty() && report.missing.is_empty() {
        println!("store is clean: every file is accounted for by an active transaction");
        return Ok(());
    }

    for s in &report.strays {
        println!(
            "{:>12} {:>12}  {:<24} {}  ({})",
            human(s.size),
            human(s.disk),
            format!("{:?}", s.kind),
            s.rel_path,
            s.detail
        );
    }
    println!(
        "\n{} stray files, {} apparent / {} on disk, {} unreferenced hash dirs",
        report.totals.files,
        human(report.totals.apparent),
        human(report.totals.disk),
        report.totals.unreferenced_dirs
    );
    for m in &report.missing {
        println!(
            "MISSING payload: {}/{} (tx {}, {})",
            m.name,
            m.hash,
            m.tx,
            if m.dir_missing { "dir absent" } else { "dir present but no payload" }
        );
    }

    if prune {
        let paths: Vec<String> = report.strays.iter().map(|s| s.rel_path.clone()).collect();
        let out = with_op_progress("pruning", |p| ops::prune_strays(&store, &paths, dry_run, p))?;
        let verb = if dry_run { "would remove" } else { "removed" };
        println!(
            "\n{verb} {} files and {} dirs, freeing {} apparent / {} on disk",
            out.files_removed,
            out.dirs_removed,
            human(out.freed_apparent),
            human(out.freed_disk)
        );
        for s in &out.skipped {
            println!("  skipped: {s}");
        }
    } else if !report.strays.is_empty() {
        println!("\nrun with --prune to remove these (add --dry-run to preview)");
    }
    Ok(())
}

pub fn check(store_path: &Path, deep: bool) -> anyhow::Result<()> {
    let (store, index) = open(store_path)?;
    let mut findings = check::check_admin(&store, &index)?;
    if deep {
        let scan = scan_with_progress(&store, true)?;
        findings.extend(check::check_deep(&index, &scan));
        let analysis = strays::analyze(&index, &scan);
        for m in &analysis.strays.missing {
            findings.push(check::Finding {
                severity: check::Severity::Error,
                code: "missing-payload",
                subject: format!("{}/{}", m.name, m.hash),
                message: format!("recorded by tx {} but not on disk", m.tx),
            });
        }
    }
    if findings.is_empty() {
        println!("no problems found{}", if deep { "" } else { " (admin records; use --deep for a full tree check)" });
        return Ok(());
    }
    for f in &findings {
        println!("{:<7} {:<20} {}: {}", format!("{:?}", f.severity).to_lowercase(), f.code, f.subject, f.message);
    }
    let errors = findings.iter().filter(|f| f.severity == check::Severity::Error).count();
    println!("\n{} finding(s), {errors} error(s)", findings.len());
    if errors > 0 {
        std::process::exit(1);
    }
    Ok(())
}
