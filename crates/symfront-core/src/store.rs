//! Filesystem access to a symbol store's admin area.

use std::fs;
use std::path::{Path, PathBuf};

use crate::format::{self, AddRecord, HistoryRecord, TxEntry};
use crate::{Error, Result, TransactionId};

pub const ADMIN_DIR: &str = "000Admin";
pub const HISTORY: &str = "history.txt";
pub const SERVER: &str = "server.txt";
pub const LASTID: &str = "lastid.txt";
pub const LOCKFILE: &str = ".symfront.lock";

/// State of a transaction's manifest file in `000Admin/`.
#[derive(Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Debug, serde::Serialize)]
#[serde(rename_all = "snake_case")]
pub enum TxFileState {
    Present,
    Deleted,
    Missing,
}

#[derive(Clone)]
pub struct Store {
    root: PathBuf,
}

impl Store {
    pub fn open(root: impl Into<PathBuf>) -> Result<Self> {
        let root: PathBuf = root.into();
        let root = root
            .canonicalize()
            .map_err(|e| Error::io(root.clone(), e))?;
        if !root.join(ADMIN_DIR).is_dir() {
            return Err(Error::NotAStore(root));
        }
        Ok(Store { root })
    }

    pub fn root(&self) -> &Path {
        &self.root
    }

    pub fn admin_dir(&self) -> PathBuf {
        self.root.join(ADMIN_DIR)
    }

    /// Read a file as text. Admin files are ASCII/ANSI in practice; we decode
    /// lossily so a stray non-UTF-8 byte can't take the whole store offline.
    pub(crate) fn read_text(&self, path: &Path) -> Result<String> {
        let bytes = fs::read(path).map_err(|e| Error::io(path, e))?;
        Ok(String::from_utf8_lossy(&bytes).into_owned())
    }

    pub fn history_path(&self) -> PathBuf {
        self.admin_dir().join(HISTORY)
    }

    pub fn server_path(&self) -> PathBuf {
        self.admin_dir().join(SERVER)
    }

    pub fn lastid_path(&self) -> PathBuf {
        self.admin_dir().join(LASTID)
    }

    pub fn tx_file_path(&self, id: TransactionId) -> PathBuf {
        self.admin_dir().join(id.to_string())
    }

    pub fn deleted_tx_file_path(&self, id: TransactionId) -> PathBuf {
        self.admin_dir().join(format!("{id}.deleted"))
    }

    /// Missing history.txt means a store with no transactions yet (symstore
    /// only creates the admin files on first add) — treated as empty.
    pub fn read_history(&self) -> Result<Vec<HistoryRecord>> {
        let path = self.history_path();
        if !path.exists() {
            return Ok(Vec::new());
        }
        let text = self.read_text(&path)?;
        Ok(format::lines(&text).map(format::parse_history_line).collect())
    }

    /// `server.txt` holds one add record per currently-active transaction.
    /// Returns parsed adds plus any lines that didn't parse as adds.
    /// Missing file (fresh store) is treated as empty.
    pub fn read_server(&self) -> Result<(Vec<AddRecord>, Vec<String>)> {
        let path = self.server_path();
        if !path.exists() {
            return Ok((Vec::new(), Vec::new()));
        }
        let text = self.read_text(&path)?;
        let mut adds = Vec::new();
        let mut bad = Vec::new();
        for line in format::lines(&text) {
            match format::parse_history_line(line) {
                HistoryRecord::Add(a) => adds.push(a),
                _ => bad.push(line.to_string()),
            }
        }
        Ok((adds, bad))
    }

    pub fn read_lastid(&self) -> Result<Option<TransactionId>> {
        let path = self.lastid_path();
        if !path.exists() {
            return Ok(None);
        }
        let text = self.read_text(&path)?;
        Ok(text.trim().parse::<TransactionId>().ok())
    }

    pub fn tx_file_state(&self, id: TransactionId) -> TxFileState {
        if self.tx_file_path(id).is_file() {
            TxFileState::Present
        } else if self.deleted_tx_file_path(id).is_file() {
            TxFileState::Deleted
        } else {
            TxFileState::Missing
        }
    }

    /// Read a transaction manifest (live or `.deleted`). Returns the entries
    /// and any lines that failed to parse.
    pub fn read_tx_entries(&self, id: TransactionId) -> Result<(Vec<TxEntry>, Vec<String>)> {
        let path = match self.tx_file_state(id) {
            TxFileState::Present => self.tx_file_path(id),
            TxFileState::Deleted => self.deleted_tx_file_path(id),
            TxFileState::Missing => return Err(Error::TxNotFound(id)),
        };
        let text = self.read_text(&path)?;
        let mut entries = Vec::new();
        let mut bad = Vec::new();
        for line in format::lines(&text) {
            match format::parse_tx_entry(line) {
                Some(e) => entries.push(e),
                None => bad.push(line.to_string()),
            }
        }
        Ok((entries, bad))
    }

    /// All transaction manifest files present in `000Admin/`, with their state.
    pub fn list_tx_files(&self) -> Result<Vec<(TransactionId, TxFileState)>> {
        let dir = self.admin_dir();
        let mut out = Vec::new();
        let rd = fs::read_dir(&dir).map_err(|e| Error::io(&dir, e))?;
        for ent in rd {
            let ent = ent.map_err(|e| Error::io(&dir, e))?;
            let name = ent.file_name();
            let name = name.to_string_lossy();
            if let Some(stripped) = name.strip_suffix(".deleted") {
                if let Ok(id) = stripped.parse::<TransactionId>() {
                    if stripped.len() == 10 {
                        out.push((id, TxFileState::Deleted));
                    }
                }
            } else if name.len() == 10 {
                if let Ok(id) = name.parse::<TransactionId>() {
                    out.push((id, TxFileState::Present));
                }
            }
        }
        out.sort();
        Ok(out)
    }

    /// Absolute path of a hash directory, using recorded case.
    pub fn hash_dir(&self, name: &str, hash: &str) -> PathBuf {
        self.root.join(name).join(hash)
    }

    /// Take the store-wide advisory write lock (flock on 000Admin/.symfront.lock).
    /// Held for the lifetime of the returned guard.
    ///
    /// Retries briefly rather than failing on the first EWOULDBLOCK: besides
    /// short critical sections in concurrent operations, a fork() elsewhere in
    /// the process (e.g. spawning a subprocess) can keep a just-released flock
    /// alive for a moment via the child's inherited fd until its exec closes it.
    pub fn lock_exclusive(&self) -> Result<StoreLock> {
        use fs2::FileExt;
        let path = self.admin_dir().join(LOCKFILE);
        let file = fs::OpenOptions::new()
            .create(true)
            .write(true)
            .truncate(false)
            .open(&path)
            .map_err(|e| Error::io(&path, e))?;
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(30);
        loop {
            match file.try_lock_exclusive() {
                Ok(()) => return Ok(StoreLock { _file: file }),
                Err(_) if std::time::Instant::now() < deadline => {
                    std::thread::sleep(std::time::Duration::from_millis(50));
                }
                Err(_) => return Err(Error::Locked),
            }
        }
    }
}

/// Guard for the store write lock; released on drop.
pub struct StoreLock {
    _file: fs::File,
}
