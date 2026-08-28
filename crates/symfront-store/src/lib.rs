//! Core library for managing a Windows NT symbol store (`symstore.exe`-compatible)
//! on a POSIX filesystem.
//!
//! Layout of a symbol store:
//!
//! ```text
//! <root>/
//!   000Admin/
//!     history.txt        # append-only log of add/del transactions (CRLF)
//!     server.txt         # add records for currently-active transactions (CRLF)
//!     lastid.txt         # last allocated transaction id, zero-padded, no newline
//!     0000000001         # per-transaction manifest: "name\HASH","source path" (CRLF)
//!     0000000184.deleted # manifest of a deleted transaction (renamed on del)
//!   <filename>/<HASH>/
//!     <filename>         # the stored payload (or <filenam_> if CAB-compressed,
//!                        #  or file.ptr for pointer adds)
//!     refs.ptr           # one line per referencing transaction (refcount)
//!   pingme.txt           # touched by symsrv clients; not managed here
//! ```

pub mod check;
pub mod format;
pub mod index;
pub mod ops;
pub mod scan;
pub mod store;
pub mod strays;

use std::fmt;
use std::path::PathBuf;

use serde::{Deserialize, Serialize};

pub use index::StoreIndex;
pub use scan::{ScanProgress, ScanResult};
pub use store::Store;
pub use strays::StrayReport;

/// Transaction id. Rendered zero-padded to 10 digits, as `symstore.exe` does.
#[derive(Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Debug, Serialize, Deserialize)]
#[serde(transparent)]
pub struct TransactionId(pub u32);

impl fmt::Display for TransactionId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{:010}", self.0)
    }
}

impl std::str::FromStr for TransactionId {
    type Err = std::num::ParseIntError;
    fn from_str(s: &str) -> std::result::Result<Self, Self::Err> {
        s.trim().parse::<u32>().map(TransactionId)
    }
}

#[derive(thiserror::Error, Debug)]
pub enum Error {
    #[error("{path}: {source}")]
    Io {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },
    #[error("not a symbol store (missing 000Admin): {0}")]
    NotAStore(PathBuf),
    #[error("transaction {0} not found")]
    TxNotFound(TransactionId),
    #[error("transaction {0} is not an active add transaction: {1}")]
    TxNotActive(TransactionId, String),
    #[error("refusing operation: {0}")]
    Refused(String),
    #[error("store is locked by another symfront operation")]
    Locked,
}

pub type Result<T> = std::result::Result<T, Error>;

impl Error {
    pub fn io(path: impl Into<PathBuf>, source: std::io::Error) -> Self {
        Error::Io {
            path: path.into(),
            source,
        }
    }
}
