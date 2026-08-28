//! Mutating operations: delete a transaction (symstore-del compatible) and
//! prune stray files.
//!
//! All mutations take the store-wide advisory lock, and admin files are
//! rewritten atomically (temp file + rename in the same directory). A journal
//! file is written into `000Admin/` before a delete touches the tree, so an
//! interrupted delete is detectable (`check` reports it) and re-runnable.

use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

use serde::Serialize;

use crate::format::{self, compressed_name, HistoryRecord};
use crate::store::TxFileState;
use crate::{Error, Result, Store, TransactionId};

pub const JOURNAL_PREFIX: &str = "_symfront_del_";

/// Live progress counters for a running delete/prune, shared with UIs.
/// `total`/`done` count hash dirs (delete) or paths (prune).
#[derive(Default)]
pub struct OpProgress {
    pub total: AtomicU64,
    pub done: AtomicU64,
    pub files_removed: AtomicU64,
    pub freed_apparent: AtomicU64,
    pub freed_disk: AtomicU64,
}

#[derive(Clone, Copy, Debug, Serialize)]
pub struct OpProgressSnapshot {
    pub total: u64,
    pub done: u64,
    pub files_removed: u64,
    pub freed_apparent: u64,
    pub freed_disk: u64,
}

impl OpProgress {
    pub fn snapshot(&self) -> OpProgressSnapshot {
        OpProgressSnapshot {
            total: self.total.load(Ordering::Relaxed),
            done: self.done.load(Ordering::Relaxed),
            files_removed: self.files_removed.load(Ordering::Relaxed),
            freed_apparent: self.freed_apparent.load(Ordering::Relaxed),
            freed_disk: self.freed_disk.load(Ordering::Relaxed),
        }
    }

    fn count_file(&self, apparent: u64, disk: u64) {
        self.files_removed.fetch_add(1, Ordering::Relaxed);
        self.freed_apparent.fetch_add(apparent, Ordering::Relaxed);
        self.freed_disk.fetch_add(disk, Ordering::Relaxed);
    }
}

#[derive(Clone, Debug, Default, Serialize)]
pub struct DeleteOutcome {
    /// Id of the recorded del transaction (None on dry runs).
    pub del_id: Option<TransactionId>,
    pub entries: u64,
    /// Hash dirs whose refcount reached zero and were removed.
    pub dirs_removed: u64,
    /// Hash dirs still referenced by other transactions (refs.ptr rewritten).
    pub dirs_still_referenced: u64,
    /// Referenced dirs that were already gone.
    pub dirs_missing: u64,
    pub files_removed: u64,
    pub freed_apparent: u64,
    pub freed_disk: u64,
    pub warnings: Vec<String>,
    pub dry_run: bool,
}

/// Delete transaction `id` the way `symstore del` would:
/// for each manifest entry, drop this tx's line from the dir's `refs.ptr`;
/// when the last reference goes, remove the payload and the directory.
/// Then rename the manifest to `.deleted`, drop the record from `server.txt`,
/// and append a del record to `history.txt` under a freshly allocated id.
pub fn delete_transaction(
    store: &Store,
    id: TransactionId,
    dry_run: bool,
    progress: &OpProgress,
) -> Result<DeleteOutcome> {
    let _lock = store.lock_exclusive()?;

    if store.tx_file_state(id) != TxFileState::Present {
        return Err(Error::TxNotActive(id, "no live manifest file".into()));
    }
    // Guard against deleting a transaction some other record already deleted.
    for rec in store.read_history()? {
        if let HistoryRecord::Del(d) = rec {
            if d.target == Some(id) {
                return Err(Error::TxNotActive(
                    id,
                    format!("already deleted by {}", d.id),
                ));
            }
        }
    }

    let (entries, bad) = store.read_tx_entries(id)?;
    let mut out = DeleteOutcome {
        entries: entries.len() as u64,
        dry_run,
        ..Default::default()
    };
    for b in bad {
        out.warnings
            .push(format!("unparsed manifest line kept out of scope: {b}"));
    }

    // Dedupe dirs: a manifest normally lists each dir once, but be safe.
    let mut dirs: Vec<(String, String)> = entries
        .iter()
        .map(|e| (e.name.clone(), e.hash.clone()))
        .collect();
    dirs.sort_by_key(|a| (a.0.to_lowercase(), a.1.to_lowercase()));
    dirs.dedup_by(|a, b| a.0.eq_ignore_ascii_case(&b.0) && a.1.eq_ignore_ascii_case(&b.1));

    let journal = store.admin_dir().join(format!("{JOURNAL_PREFIX}{id}"));
    if !dry_run {
        write_file(&journal, format!("deleting {id}\n").as_bytes())?;
    }

    progress.total.store(dirs.len() as u64, Ordering::Relaxed);
    for (name, hash) in &dirs {
        delete_one_ref(store, id, name, hash, dry_run, progress, &mut out)?;
        progress.done.fetch_add(1, Ordering::Relaxed);
    }

    if !dry_run {
        // Manifest -> .deleted
        let live = store.tx_file_path(id);
        let dead = store.deleted_tx_file_path(id);
        fs::rename(&live, &dead).map_err(|e| Error::io(&live, e))?;

        // server.txt: drop the record for `id`.
        rewrite_server_without(store, id)?;

        // Allocate del id and append the history record.
        let last = store.read_lastid()?.unwrap_or(TransactionId(0));
        let del_id = TransactionId(last.0 + 1);
        write_file(&store.lastid_path(), del_id.to_string().as_bytes())?;
        append_history_line(store, &format!("{del_id},del,{id}"))?;
        out.del_id = Some(del_id);

        fs::remove_file(&journal).map_err(|e| Error::io(&journal, e))?;
    }

    Ok(out)
}

fn delete_one_ref(
    store: &Store,
    id: TransactionId,
    name: &str,
    hash: &str,
    dry_run: bool,
    progress: &OpProgress,
    out: &mut DeleteOutcome,
) -> Result<()> {
    let dir = match resolve_dir_case(store.root(), name, hash) {
        Some(d) => d,
        None => {
            out.dirs_missing += 1;
            out.warnings
                .push(format!("{name}/{hash}: directory missing"));
            return Ok(());
        }
    };

    let refs_path = dir.join("refs.ptr");
    if !refs_path.is_file() {
        // Without refs.ptr we can't tell whether another transaction still
        // references this dir; leave it alone and let `check`/strays surface it.
        out.warnings.push(format!(
            "{name}/{hash}: refs.ptr missing; dir left in place (will show as stray if unreferenced)"
        ));
        return Ok(());
    }
    let bytes = fs::read(&refs_path).map_err(|e| Error::io(&refs_path, e))?;
    let text = String::from_utf8_lossy(&bytes);
    let remaining: Vec<String> = format::lines(&text)
        .filter(|l| format::parse_ref_line(l).tx != Some(id))
        .map(|l| l.to_string())
        .collect();

    if remaining.is_empty() {
        // Last reference: remove payload files we recognize, refs.ptr, and the
        // directory (only if that empties it — strays are left in place).
        let candidates = [
            name.to_string(),
            compressed_name(name),
            "file.ptr".to_string(),
            "refs.ptr".to_string(),
        ];
        let rd = fs::read_dir(&dir).map_err(|e| Error::io(&dir, e))?;
        let mut leftover = false;
        for ent in rd {
            let ent = ent.map_err(|e| Error::io(&dir, e))?;
            let fname = ent.file_name().to_string_lossy().into_owned();
            let known = candidates.iter().any(|c| fname.eq_ignore_ascii_case(c));
            let md = ent.metadata().map_err(|e| Error::io(ent.path(), e))?;
            if known && md.is_file() {
                use std::os::unix::fs::MetadataExt;
                out.files_removed += 1;
                out.freed_apparent += md.len();
                out.freed_disk += md.blocks() * 512;
                progress.count_file(md.len(), md.blocks() * 512);
                if !dry_run {
                    fs::remove_file(ent.path()).map_err(|e| Error::io(ent.path(), e))?;
                }
            } else {
                leftover = true;
                out.warnings
                    .push(format!("{name}/{hash}: leaving unrecognized entry {fname}"));
            }
        }
        if !dry_run && !leftover {
            fs::remove_dir(&dir).map_err(|e| Error::io(&dir, e))?;
            // Remove the <name>/ dir too if this was its last hash dir.
            if let Some(parent) = dir.parent() {
                let _ = fs::remove_dir(parent);
            }
        }
        out.dirs_removed += 1;
    } else {
        out.dirs_still_referenced += 1;
        if !dry_run {
            // Preserve the store's on-disk style: CRLF separators, no
            // trailing newline.
            write_file_atomic(&refs_path, remaining.join("\r\n").as_bytes())?;
        }
    }
    Ok(())
}

/// The manifest records the dir with the case symstore used at add time; the
/// on-disk dir should match, but resolve case-insensitively as a fallback.
fn resolve_dir_case(root: &Path, name: &str, hash: &str) -> Option<PathBuf> {
    let exact = root.join(name).join(hash);
    if exact.is_dir() {
        return Some(exact);
    }
    let name_dir = find_ci(root, name)?;
    let hash_dir = find_ci(&name_dir, hash)?;
    hash_dir.is_dir().then_some(hash_dir)
}

fn find_ci(dir: &Path, target: &str) -> Option<PathBuf> {
    let exact = dir.join(target);
    if exact.exists() {
        return Some(exact);
    }
    for ent in fs::read_dir(dir).ok()?.flatten() {
        if ent
            .file_name()
            .to_string_lossy()
            .eq_ignore_ascii_case(target)
        {
            return Some(ent.path());
        }
    }
    None
}

fn rewrite_server_without(store: &Store, id: TransactionId) -> Result<()> {
    let path = store.server_path();
    let text = store.read_text(&path)?;
    let mut kept: Vec<String> = Vec::new();
    for line in format::lines(&text) {
        let keep = match format::parse_history_line(line) {
            HistoryRecord::Add(a) => a.id != id,
            _ => true,
        };
        if keep {
            kept.push(line.to_string());
        }
    }
    // server.txt on disk ends with a CRLF; preserve that.
    let mut body = kept.join("\r\n");
    if !body.is_empty() {
        body.push_str("\r\n");
    }
    write_file_atomic(&path, body.as_bytes())
}

fn append_history_line(store: &Store, line: &str) -> Result<()> {
    let path = store.history_path();
    let existing = match fs::read(&path) {
        Ok(b) => b,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Vec::new(),
        Err(e) => return Err(Error::io(&path, e)),
    };
    let mut f = fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(&path)
        .map_err(|e| Error::io(&path, e))?;
    // history.txt's final line is unterminated in symstore-written stores;
    // terminate it before appending, then keep the new final line unterminated.
    if !existing.is_empty() && !existing.ends_with(b"\n") {
        f.write_all(b"\r\n").map_err(|e| Error::io(&path, e))?;
    }
    f.write_all(line.as_bytes())
        .map_err(|e| Error::io(&path, e))?;
    Ok(())
}

fn write_file(path: &Path, bytes: &[u8]) -> Result<()> {
    fs::write(path, bytes).map_err(|e| Error::io(path, e))
}

fn write_file_atomic(path: &Path, bytes: &[u8]) -> Result<()> {
    let dir = path
        .parent()
        .ok_or_else(|| Error::Refused(format!("no parent dir for {}", path.display())))?;
    let tmp = dir.join(format!(
        ".symfront.tmp.{}",
        path.file_name().unwrap_or_default().to_string_lossy()
    ));
    fs::write(&tmp, bytes).map_err(|e| Error::io(&tmp, e))?;
    fs::rename(&tmp, path).map_err(|e| Error::io(path, e))
}

// ---------- add ----------

pub const ADD_JOURNAL_PREFIX: &str = "_symfront_add_";

/// One file of an add request.
#[derive(Clone, Debug)]
pub struct AddFile {
    /// Local path of the payload to ingest.
    pub path: PathBuf,
    /// Store file name (first path component).
    pub name: String,
    pub hash: String,
    pub kind: symfront_ident::FileKind,
    /// Source path recorded in the manifest and refs.ptr — the client's
    /// original path for uploads, the local path for local adds.
    pub source: String,
}

#[derive(Clone, Debug)]
pub struct AddRequest {
    pub product: String,
    pub version: String,
    pub comment: String,
    pub files: Vec<AddFile>,
    /// Try to rename payloads into place (staging on the same filesystem)
    /// before falling back to a copy.
    pub consume: bool,
}

#[derive(Clone, Debug, Default, Serialize)]
pub struct AddOutcome {
    pub id: Option<TransactionId>,
    /// Payloads newly stored.
    pub files_new: u64,
    /// Payloads that already existed (only a refs.ptr line was added).
    pub files_deduped: u64,
    pub bytes_copied: u64,
    pub warnings: Vec<String>,
    pub dry_run: bool,
}

/// Strip characters that would corrupt the quoted-CSV admin records
/// (symstore has no escaping convention for embedded quotes).
fn sanitize_field(s: &str) -> String {
    s.replace(['"', '\r', '\n'], "'")
}

fn valid_component(s: &str) -> bool {
    !s.is_empty()
        && !s.contains(['/', '\\', '\0'])
        && s != "."
        && s != ".."
        && !s.eq_ignore_ascii_case("000admin")
        && !s.starts_with(".symfront")
        && !s.starts_with("_symfront")
}

/// Add a transaction the way `symstore add` would, but atomically: payloads
/// and refs.ptr lines land first, then the manifest, then the admin records
/// commit the transaction. The store lock is held throughout, and a journal
/// marks the operation so an interrupted add is detectable (its files show
/// as strays claiming a never-committed id, prunable).
pub fn add_transaction(
    store: &Store,
    req: &AddRequest,
    dry_run: bool,
    progress: &OpProgress,
) -> Result<AddOutcome> {
    if req.files.is_empty() {
        return Err(Error::Refused("no files to add".into()));
    }
    if req.product.trim().is_empty() {
        return Err(Error::Refused("product must not be empty".into()));
    }
    for f in &req.files {
        if !valid_component(&f.name) || !valid_component(&f.hash) {
            return Err(Error::Refused(format!(
                "invalid store path component in {}\\{}",
                f.name, f.hash
            )));
        }
    }
    let _lock = store.lock_exclusive()?;

    let mut out = AddOutcome {
        dry_run,
        ..Default::default()
    };
    let id = TransactionId(store.read_lastid()?.map(|t| t.0).unwrap_or(0) + 1);

    // Dedupe within the request: one manifest entry / refs line per dir.
    let mut seen: std::collections::HashSet<(String, String)> = Default::default();
    let mut files: Vec<&AddFile> = Vec::new();
    for f in &req.files {
        if seen.insert((f.name.to_lowercase(), f.hash.to_lowercase())) {
            files.push(f);
        } else {
            out.warnings.push(format!(
                "{}\\{}: listed twice in request; using first",
                f.name, f.hash
            ));
        }
    }

    let journal = store.admin_dir().join(format!("{ADD_JOURNAL_PREFIX}{id}"));
    if !dry_run {
        write_file(&journal, format!("adding {id}\n").as_bytes())?;
    }

    progress.total.store(files.len() as u64, Ordering::Relaxed);
    for f in &files {
        add_one_payload(store, id, f, dry_run, req.consume, progress, &mut out)?;
        progress.done.fetch_add(1, Ordering::Relaxed);
    }

    if !dry_run {
        // Manifest. Unlike history.txt, symstore terminates every manifest
        // line including the last (verified against symstore.exe output).
        let mut manifest: String = files
            .iter()
            .map(|f| {
                format!(
                    "\"{}\\{}\",\"{}\"",
                    f.name,
                    f.hash,
                    sanitize_field(&f.source)
                )
            })
            .collect::<Vec<_>>()
            .join("\r\n");
        manifest.push_str("\r\n");
        write_file_atomic(&store.tx_file_path(id), manifest.as_bytes())?;

        // Commit: history + server + lastid, symstore-style local timestamps.
        let now = chrono::Local::now();
        let record = format!(
            "{id},add,file,{},{},\"{}\",\"{}\",\"{}\",",
            now.format("%m/%d/%Y"),
            now.format("%H:%M:%S"),
            sanitize_field(&req.product),
            sanitize_field(&req.version),
            sanitize_field(&req.comment),
        );
        append_history_line(store, &record)?;
        append_server_line(store, &record)?;
        write_file(&store.lastid_path(), id.to_string().as_bytes())?;
        fs::remove_file(&journal).map_err(|e| Error::io(&journal, e))?;
        out.id = Some(id);
    }
    Ok(out)
}

fn add_one_payload(
    store: &Store,
    id: TransactionId,
    f: &AddFile,
    dry_run: bool,
    consume: bool,
    progress: &OpProgress,
    out: &mut AddOutcome,
) -> Result<()> {
    let src_md = fs::metadata(&f.path).map_err(|e| Error::io(&f.path, e))?;
    // Reuse an existing dir case-insensitively rather than creating a
    // case-twin next to it.
    let dir = resolve_dir_case(store.root(), &f.name, &f.hash)
        .unwrap_or_else(|| store.hash_dir(&f.name, &f.hash));
    let payload = dir.join(&f.name);

    if payload.is_file() {
        let existing = fs::metadata(&payload).map_err(|e| Error::io(&payload, e))?;
        if existing.len() != src_md.len() {
            out.warnings.push(format!(
                "{}\\{}: existing payload is {} bytes but incoming is {} — keeping existing (hash collision or corruption?)",
                f.name,
                f.hash,
                existing.len(),
                src_md.len()
            ));
        }
        out.files_deduped += 1;
    } else {
        out.files_new += 1;
        out.bytes_copied += src_md.len();
        progress.count_file(src_md.len(), src_md.len());
        if !dry_run {
            fs::create_dir_all(&dir).map_err(|e| Error::io(&dir, e))?;
            let mut done = false;
            if consume {
                done = fs::rename(&f.path, &payload).is_ok();
            }
            if !done {
                fs::copy(&f.path, &payload).map_err(|e| Error::io(&payload, e))?;
            }
        }
    }

    if !dry_run {
        // refs.ptr line, matching symstore's format and unterminated-final-
        // line style.
        let line = format!(
            "{id},file,\"{}\",{},,N,,",
            sanitize_field(&f.source),
            f.kind.refs_tag()
        );
        let refs_path = dir.join("refs.ptr");
        let existing = match fs::read(&refs_path) {
            Ok(b) => Some(b),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => None,
            Err(e) => return Err(Error::io(&refs_path, e)),
        };
        match existing {
            None => {
                fs::create_dir_all(&dir).map_err(|e| Error::io(&dir, e))?;
                write_file(&refs_path, line.as_bytes())?;
            }
            Some(bytes) => {
                let mut fh = fs::OpenOptions::new()
                    .append(true)
                    .open(&refs_path)
                    .map_err(|e| Error::io(&refs_path, e))?;
                if !bytes.is_empty() && !bytes.ends_with(b"\n") {
                    fh.write_all(b"\r\n")
                        .map_err(|e| Error::io(&refs_path, e))?;
                }
                fh.write_all(line.as_bytes())
                    .map_err(|e| Error::io(&refs_path, e))?;
            }
        }
    }
    Ok(())
}

fn append_server_line(store: &Store, line: &str) -> Result<()> {
    let path = store.server_path();
    let existing = match fs::read(&path) {
        Ok(b) => b,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Vec::new(),
        Err(e) => return Err(Error::io(&path, e)),
    };
    let mut fh = fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(&path)
        .map_err(|e| Error::io(&path, e))?;
    // server.txt keeps every line terminated (unlike history.txt's final line).
    if !existing.is_empty() && !existing.ends_with(b"\n") {
        fh.write_all(b"\r\n").map_err(|e| Error::io(&path, e))?;
    }
    fh.write_all(line.as_bytes())
        .map_err(|e| Error::io(&path, e))?;
    fh.write_all(b"\r\n").map_err(|e| Error::io(&path, e))?;
    Ok(())
}

#[derive(Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Debug, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum JournalKind {
    Add,
    Del,
}

/// Leftover add/delete journals from interrupted operations.
pub fn pending_journals(store: &Store) -> Result<Vec<(TransactionId, JournalKind)>> {
    let dir = store.admin_dir();
    let mut out = Vec::new();
    let rd = fs::read_dir(&dir).map_err(|e| Error::io(&dir, e))?;
    for ent in rd.flatten() {
        let name = ent.file_name().to_string_lossy().into_owned();
        let (rest, kind) = if let Some(r) = name.strip_prefix(JOURNAL_PREFIX) {
            (r, JournalKind::Del)
        } else if let Some(r) = name.strip_prefix(ADD_JOURNAL_PREFIX) {
            (r, JournalKind::Add)
        } else {
            continue;
        };
        if let Ok(id) = rest.parse::<TransactionId>() {
            out.push((id, kind));
        }
    }
    out.sort();
    Ok(out)
}

#[derive(Clone, Debug, Default, Serialize)]
pub struct PruneOutcome {
    pub files_removed: u64,
    pub dirs_removed: u64,
    pub freed_apparent: u64,
    pub freed_disk: u64,
    pub skipped: Vec<String>,
    pub dry_run: bool,
}

/// Remove stray files by store-relative path, then clean up any directories
/// the removals emptied. Paths are validated to stay inside the store and
/// outside `000Admin/`.
pub fn prune_strays(
    store: &Store,
    rel_paths: &[String],
    dry_run: bool,
    progress: &OpProgress,
) -> Result<PruneOutcome> {
    let _lock = store.lock_exclusive()?;
    let root = store.root();
    let mut out = PruneOutcome {
        dry_run,
        ..Default::default()
    };
    let mut parents: Vec<PathBuf> = Vec::new();

    progress
        .total
        .store(rel_paths.len() as u64, Ordering::Relaxed);
    for rel in rel_paths {
        progress.done.fetch_add(1, Ordering::Relaxed);
        let rel_path = Path::new(rel);
        if rel_path.is_absolute()
            || rel_path
                .components()
                .any(|c| matches!(c, std::path::Component::ParentDir))
        {
            return Err(Error::Refused(format!("path escapes store: {rel}")));
        }
        if rel_path.starts_with(crate::store::ADMIN_DIR) {
            return Err(Error::Refused(format!(
                "refusing to prune inside 000Admin: {rel}"
            )));
        }
        let abs = root.join(rel_path);
        let md = match fs::symlink_metadata(&abs) {
            Ok(md) => md,
            Err(_) => {
                out.skipped.push(format!("{rel}: already gone"));
                continue;
            }
        };
        if md.is_dir() {
            // Only empty directories are pruned directly.
            match fs::read_dir(&abs).map_err(|e| Error::io(&abs, e))?.next() {
                None => {
                    if !dry_run {
                        fs::remove_dir(&abs).map_err(|e| Error::io(&abs, e))?;
                    }
                    out.dirs_removed += 1;
                    if let Some(p) = abs.parent() {
                        parents.push(p.to_path_buf());
                    }
                }
                Some(_) => out.skipped.push(format!("{rel}: directory not empty")),
            }
        } else {
            use std::os::unix::fs::MetadataExt;
            out.files_removed += 1;
            out.freed_apparent += md.len();
            out.freed_disk += md.blocks() * 512;
            progress.count_file(md.len(), md.blocks() * 512);
            if !dry_run {
                fs::remove_file(&abs).map_err(|e| Error::io(&abs, e))?;
            }
            if let Some(p) = abs.parent() {
                parents.push(p.to_path_buf());
            }
        }
    }

    // Remove now-empty parent dirs, walking up to (but never including) root.
    if !dry_run {
        parents.sort();
        parents.dedup();
        for mut dir in parents {
            while dir != *root && dir.starts_with(root) {
                match fs::remove_dir(&dir) {
                    Ok(()) => out.dirs_removed += 1,
                    Err(_) => break, // not empty or gone — stop climbing
                }
                match dir.parent() {
                    Some(p) => dir = p.to_path_buf(),
                    None => break,
                }
            }
        }
    }

    Ok(out)
}
