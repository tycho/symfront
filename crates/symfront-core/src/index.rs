//! Logical index of the store, built purely from `000Admin/` records
//! (no walk of the payload tree — that's `scan`).

use std::collections::{BTreeMap, HashMap};

use serde::Serialize;

use crate::format::{AddRecord, HistoryRecord, TxEntry};
use crate::store::TxFileState;
use crate::{Result, Store, TransactionId};

/// A transaction as reconstructed from history + server.txt + manifest files.
#[derive(Clone, Debug, Serialize)]
pub struct Transaction {
    pub id: TransactionId,
    /// The add record from history.txt (if any).
    pub record: Option<AddRecord>,
    /// Del transactions that targeted this one.
    pub deleted_by: Vec<TransactionId>,
    /// Whether server.txt currently lists this transaction.
    pub in_server_txt: bool,
    pub file_state: TxFileState,
    /// Number of manifest entries (0 if no manifest file).
    pub entry_count: usize,
    /// Manifest lines that failed to parse.
    pub bad_lines: Vec<String>,
}

impl Transaction {
    /// Active means: deletable, searchable, owns references in the tree.
    pub fn is_active(&self) -> bool {
        self.deleted_by.is_empty() && self.file_state == TxFileState::Present
    }
}

/// One manifest entry of an *active* transaction, flattened for search.
#[derive(Clone, Debug, Serialize)]
pub struct IndexEntry {
    pub tx: TransactionId,
    pub name: String,
    pub hash: String,
    pub source: String,
}

#[derive(Default, Serialize)]
pub struct StoreIndex {
    /// Full history, in file order.
    pub history: Vec<HistoryRecord>,
    pub lastid: Option<TransactionId>,
    /// All transactions we know about (from history and/or manifest files).
    pub transactions: BTreeMap<TransactionId, Transaction>,
    /// Del records from history, in order.
    pub dels: Vec<crate::format::DelRecord>,
    /// Flattened entries of all active transactions.
    pub entries: Vec<IndexEntry>,
    /// server.txt lines that didn't parse as add records.
    pub server_bad_lines: Vec<String>,
    /// Add records in server.txt with no matching id in history.
    pub server_orphans: Vec<TransactionId>,
    #[serde(skip)]
    by_dir: HashMap<(String, String), Vec<u32>>,
    #[serde(skip)]
    by_tx: HashMap<TransactionId, Vec<u32>>,
}

#[derive(Clone, Debug, Serialize)]
pub struct SearchHit {
    pub tx: TransactionId,
    pub name: String,
    pub hash: String,
    pub source: String,
    pub product: Option<String>,
    pub version: Option<String>,
}

impl StoreIndex {
    pub fn load(store: &Store) -> Result<StoreIndex> {
        let history = store.read_history()?;
        let (server_adds, server_bad_lines) = store.read_server()?;
        let lastid = store.read_lastid()?;
        let tx_files = store.list_tx_files()?;

        let mut transactions: BTreeMap<TransactionId, Transaction> = BTreeMap::new();
        let tx = |id: TransactionId| -> Transaction {
            Transaction {
                id,
                record: None,
                deleted_by: Vec::new(),
                in_server_txt: false,
                file_state: TxFileState::Missing,
                entry_count: 0,
                bad_lines: Vec::new(),
            }
        };

        let mut dels = Vec::new();
        for rec in &history {
            match rec {
                HistoryRecord::Add(a) => {
                    let t = transactions.entry(a.id).or_insert_with(|| tx(a.id));
                    t.record = Some(a.clone());
                }
                HistoryRecord::Del(d) => {
                    dels.push(d.clone());
                    if let Some(target) = d.target {
                        let t = transactions.entry(target).or_insert_with(|| tx(target));
                        t.deleted_by.push(d.id);
                    }
                }
                HistoryRecord::Unknown { .. } => {}
            }
        }

        let mut server_orphans = Vec::new();
        for a in &server_adds {
            match transactions.get_mut(&a.id) {
                Some(t) => t.in_server_txt = true,
                None => server_orphans.push(a.id),
            }
        }

        for (id, state) in &tx_files {
            let t = transactions.entry(*id).or_insert_with(|| tx(*id));
            t.file_state = *state;
        }

        // Load manifest entries. Active transactions feed the search index;
        // for deleted/orphaned manifests we still record the entry count.
        let mut entries: Vec<IndexEntry> = Vec::new();
        let mut by_dir: HashMap<(String, String), Vec<u32>> = HashMap::new();
        let mut by_tx: HashMap<TransactionId, Vec<u32>> = HashMap::new();
        for t in transactions.values_mut() {
            if t.file_state == TxFileState::Missing {
                continue;
            }
            let (tx_entries, bad) = store.read_tx_entries(t.id)?;
            t.entry_count = tx_entries.len();
            t.bad_lines = bad;
            if !t.is_active() {
                continue;
            }
            for e in tx_entries {
                let idx = entries.len() as u32;
                by_dir.entry(e.key()).or_default().push(idx);
                by_tx.entry(t.id).or_default().push(idx);
                entries.push(IndexEntry {
                    tx: t.id,
                    name: e.name,
                    hash: e.hash,
                    source: e.source,
                });
            }
        }

        Ok(StoreIndex {
            history,
            lastid,
            transactions,
            dels,
            entries,
            server_bad_lines,
            server_orphans,
            by_dir,
            by_tx,
        })
    }

    pub fn active_transactions(&self) -> impl Iterator<Item = &Transaction> {
        self.transactions.values().filter(|t| t.is_active())
    }

    /// Entry indices for a hash directory, keyed case-insensitively.
    pub fn dir_refs(&self, name_lower: &str, hash_lower: &str) -> &[u32] {
        self.by_dir
            .get(&(name_lower.to_string(), hash_lower.to_string()))
            .map(|v| v.as_slice())
            .unwrap_or(&[])
    }

    pub fn tx_entries(&self, id: TransactionId) -> impl Iterator<Item = &IndexEntry> {
        self.by_tx
            .get(&id)
            .into_iter()
            .flatten()
            .map(move |i| &self.entries[*i as usize])
    }

    /// Search active entries by file-name substring or hash prefix
    /// (case-insensitive). A query containing `\` or `/` also matches against
    /// the recorded source path.
    pub fn search(&self, query: &str, limit: usize) -> Vec<SearchHit> {
        let q = query.to_lowercase();
        if q.is_empty() {
            return Vec::new();
        }
        let path_query = q.contains('\\') || q.contains('/');
        let mut hits = Vec::new();
        for e in &self.entries {
            let matched = e.name.to_lowercase().contains(&q)
                || e.hash.to_lowercase().starts_with(&q)
                || (path_query && e.source.to_lowercase().contains(&q));
            if !matched {
                continue;
            }
            let rec = self.transactions.get(&e.tx).and_then(|t| t.record.as_ref());
            hits.push(SearchHit {
                tx: e.tx,
                name: e.name.clone(),
                hash: e.hash.clone(),
                source: e.source.clone(),
                product: rec.map(|r| r.product.clone()),
                version: rec.map(|r| r.version.clone()),
            });
            if hits.len() >= limit {
                break;
            }
        }
        hits
    }

    /// The set of hash dirs referenced by at least one active transaction,
    /// with reference counts. Keys are lower-cased `(name, hash)`.
    pub fn referenced_dirs(&self) -> &HashMap<(String, String), Vec<u32>> {
        &self.by_dir
    }
}

/// Load manifest entries for one transaction (helper for detail views).
pub fn load_entries(store: &Store, id: TransactionId) -> Result<Vec<TxEntry>> {
    Ok(store.read_tx_entries(id)?.0)
}
