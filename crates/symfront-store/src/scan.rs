//! Physical scan of the store tree: every file, its apparent size (`st_size`)
//! and size on disk (`st_blocks * 512`), organized by hash directory.

use std::fs;
use std::path::Path;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::time::SystemTime;

use rayon::prelude::*;
use serde::Serialize;

use crate::format::{self, RefLine};
use crate::store::ADMIN_DIR;
use crate::{Error, Result, Store};

/// Progress counters for a running scan, shared with UIs.
#[derive(Default)]
pub struct ScanProgress {
    pub files: AtomicU64,
    pub dirs: AtomicU64,
    pub done: AtomicBool,
}

#[derive(Clone, Debug, Serialize)]
pub struct FileMeta {
    /// File name within its directory.
    pub name: String,
    pub size: u64,
    pub disk: u64,
}

/// A `<name>/<HASH>/` directory as found on disk.
#[derive(Clone, Debug, Serialize)]
pub struct HashDirInfo {
    /// Top-level file name directory (as on disk).
    pub name: String,
    /// Hash directory name (as on disk).
    pub hash: String,
    pub files: Vec<FileMeta>,
    /// Parsed refs.ptr lines, if `read_refs` was requested and the file exists.
    pub refs: Option<Vec<RefLine>>,
    /// Subdirectories found inside the hash dir (unexpected; reported as strays).
    pub subdirs: Vec<String>,
}

impl HashDirInfo {
    pub fn key(&self) -> (String, String) {
        (self.name.to_lowercase(), self.hash.to_lowercase())
    }

    pub fn apparent(&self) -> u64 {
        self.files.iter().map(|f| f.size).sum()
    }

    pub fn disk(&self) -> u64 {
        self.files.iter().map(|f| f.disk).sum()
    }
}

/// A file somewhere it shouldn't be: directly in the store root, directly in a
/// `<name>/` dir, or nested below a hash dir. Path is store-relative.
#[derive(Clone, Debug, Serialize)]
pub struct OddFile {
    pub rel_path: String,
    pub size: u64,
    pub disk: u64,
}

#[derive(Clone, Copy, Debug, Default, Serialize)]
pub struct SizeTotals {
    pub files: u64,
    pub apparent: u64,
    pub disk: u64,
}

impl SizeTotals {
    fn add(&mut self, size: u64, disk: u64) {
        self.files += 1;
        self.apparent += size;
        self.disk += disk;
    }
}

#[derive(Serialize)]
pub struct ScanResult {
    pub hash_dirs: Vec<HashDirInfo>,
    pub odd_files: Vec<OddFile>,
    pub admin: SizeTotals,
    pub payload: SizeTotals,
    pub total: SizeTotals,
    /// Unix seconds when the scan finished.
    pub scanned_at: u64,
    pub duration_ms: u64,
    /// Whether refs.ptr files were read during this scan.
    pub with_refs: bool,
}

/// `(apparent, on_disk)` bytes for a file: `st_size` and `st_blocks * 512`.
///
/// Only Unix exposes the allocated size through `std`; elsewhere the on-disk
/// figure falls back to the apparent size, so sparse and compressed files
/// are over-counted there rather than guessed at.
pub fn meta_sizes(md: &fs::Metadata) -> (u64, u64) {
    #[cfg(unix)]
    let disk = {
        use std::os::unix::fs::MetadataExt;
        md.blocks() * 512
    };
    #[cfg(not(unix))]
    let disk = md.len();
    (md.len(), disk)
}

/// Walk the whole store. `read_refs` additionally parses every `refs.ptr`
/// (needed for deep consistency checks; adds one read per hash dir).
pub fn scan(store: &Store, read_refs: bool, progress: &ScanProgress) -> Result<ScanResult> {
    let started = std::time::Instant::now();
    let root = store.root();

    // Pass 1: enumerate top-level entries.
    let mut name_dirs: Vec<String> = Vec::new();
    let mut odd_files: Vec<OddFile> = Vec::new();
    let mut admin = SizeTotals::default();
    let rd = fs::read_dir(root).map_err(|e| Error::io(root, e))?;
    for ent in rd {
        let ent = ent.map_err(|e| Error::io(root, e))?;
        let fname = ent.file_name().to_string_lossy().into_owned();
        let md = ent.metadata().map_err(|e| Error::io(ent.path(), e))?;
        if md.is_dir() {
            if fname == ADMIN_DIR {
                admin = scan_admin_sizes(&ent.path())?;
            } else {
                name_dirs.push(fname);
            }
        } else {
            // Files in the root: pingme.txt is legitimate (symsrv touches it).
            if !fname.eq_ignore_ascii_case("pingme.txt") {
                let (size, disk) = meta_sizes(&md);
                odd_files.push(OddFile {
                    rel_path: fname,
                    size,
                    disk,
                });
            }
        }
    }

    // Pass 2: walk each <name>/ dir in parallel.
    let results: Vec<Result<(Vec<HashDirInfo>, Vec<OddFile>)>> = name_dirs
        .par_iter()
        .map(|name| scan_name_dir(root, name, read_refs, progress))
        .collect();

    let mut hash_dirs = Vec::new();
    for r in results {
        let (dirs, odd) = r?;
        hash_dirs.extend(dirs);
        odd_files.extend(odd);
    }

    let mut payload = SizeTotals::default();
    for d in &hash_dirs {
        for f in &d.files {
            payload.add(f.size, f.disk);
        }
    }
    for f in &odd_files {
        payload.add(f.size, f.disk);
    }
    let total = SizeTotals {
        files: admin.files + payload.files,
        apparent: admin.apparent + payload.apparent,
        disk: admin.disk + payload.disk,
    };

    hash_dirs.sort_by(|a, b| (&a.name, &a.hash).cmp(&(&b.name, &b.hash)));
    odd_files.sort_by(|a, b| a.rel_path.cmp(&b.rel_path));

    progress.done.store(true, Ordering::Relaxed);
    Ok(ScanResult {
        hash_dirs,
        odd_files,
        admin,
        payload,
        total,
        scanned_at: SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0),
        duration_ms: started.elapsed().as_millis() as u64,
        with_refs: read_refs,
    })
}

fn scan_admin_sizes(admin_dir: &Path) -> Result<SizeTotals> {
    let mut totals = SizeTotals::default();
    let rd = fs::read_dir(admin_dir).map_err(|e| Error::io(admin_dir, e))?;
    for ent in rd {
        let ent = ent.map_err(|e| Error::io(admin_dir, e))?;
        let md = ent.metadata().map_err(|e| Error::io(ent.path(), e))?;
        if md.is_file() {
            let (size, disk) = meta_sizes(&md);
            totals.add(size, disk);
        }
    }
    Ok(totals)
}

fn scan_name_dir(
    root: &Path,
    name: &str,
    read_refs: bool,
    progress: &ScanProgress,
) -> Result<(Vec<HashDirInfo>, Vec<OddFile>)> {
    let dir = root.join(name);
    let mut hash_dirs = Vec::new();
    let mut odd = Vec::new();
    let rd = fs::read_dir(&dir).map_err(|e| Error::io(&dir, e))?;
    for ent in rd {
        let ent = ent.map_err(|e| Error::io(&dir, e))?;
        let fname = ent.file_name().to_string_lossy().into_owned();
        let md = ent.metadata().map_err(|e| Error::io(ent.path(), e))?;
        if md.is_dir() {
            progress.dirs.fetch_add(1, Ordering::Relaxed);
            hash_dirs.push(scan_hash_dir(root, name, &fname, read_refs, progress)?);
        } else {
            // A file directly under <name>/ — not part of the format.
            let (size, disk) = meta_sizes(&md);
            progress.files.fetch_add(1, Ordering::Relaxed);
            odd.push(OddFile {
                rel_path: format!("{name}/{fname}"),
                size,
                disk,
            });
        }
    }
    Ok((hash_dirs, odd))
}

fn scan_hash_dir(
    root: &Path,
    name: &str,
    hash: &str,
    read_refs: bool,
    progress: &ScanProgress,
) -> Result<HashDirInfo> {
    let dir = root.join(name).join(hash);
    let mut files = Vec::new();
    let mut subdirs = Vec::new();
    let mut refs = None;
    let rd = fs::read_dir(&dir).map_err(|e| Error::io(&dir, e))?;
    for ent in rd {
        let ent = ent.map_err(|e| Error::io(&dir, e))?;
        let fname = ent.file_name().to_string_lossy().into_owned();
        let md = ent.metadata().map_err(|e| Error::io(ent.path(), e))?;
        if md.is_dir() {
            subdirs.push(fname);
            continue;
        }
        progress.files.fetch_add(1, Ordering::Relaxed);
        let (size, disk) = meta_sizes(&md);
        if read_refs && fname.eq_ignore_ascii_case("refs.ptr") {
            let bytes = fs::read(ent.path()).map_err(|e| Error::io(ent.path(), e))?;
            let text = String::from_utf8_lossy(&bytes);
            refs = Some(format::lines(&text).map(format::parse_ref_line).collect());
        }
        files.push(FileMeta {
            name: fname,
            size,
            disk,
        });
    }
    files.sort_by(|a, b| a.name.cmp(&b.name));
    Ok(HashDirInfo {
        name: name.to_string(),
        hash: hash.to_string(),
        files,
        refs,
        subdirs,
    })
}
