//! Join of the logical index and the physical scan: stray detection,
//! missing-payload detection, and per-transaction size accounting.

use std::collections::HashMap;

use serde::Serialize;

use crate::format::compressed_name;
use crate::index::StoreIndex;
use crate::scan::ScanResult;
use crate::TransactionId;

#[derive(Copy, Clone, PartialEq, Eq, Debug, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum StrayKind {
    /// A whole hash dir no active transaction references.
    UnreferencedHashDir,
    /// A file inside a referenced hash dir that is neither the payload,
    /// its compressed form, `file.ptr`, nor `refs.ptr`.
    UnexpectedFile,
    /// A file outside the `<name>/<HASH>/` structure (store root, inside a
    /// `<name>/` dir, or a nested subdirectory of a hash dir).
    OutOfPlace,
}

/// One stray file, store-relative path.
#[derive(Clone, Debug, Serialize)]
pub struct Stray {
    pub rel_path: String,
    pub kind: StrayKind,
    pub size: u64,
    pub disk: u64,
    /// For hash-dir strays: the dir this belongs to, used for grouping and
    /// for cleaning up emptied directories after a prune.
    pub group: Option<String>,
    pub detail: String,
}

/// An entry recorded in an active transaction whose payload is not on disk.
#[derive(Clone, Debug, Serialize)]
pub struct MissingPayload {
    pub tx: TransactionId,
    pub name: String,
    pub hash: String,
    /// True if the whole hash dir is absent; false if the dir exists but
    /// contains no recognizable payload file.
    pub dir_missing: bool,
}

#[derive(Clone, Copy, Debug, Default, Serialize)]
pub struct StrayTotals {
    pub files: u64,
    pub apparent: u64,
    pub disk: u64,
    pub unreferenced_dirs: u64,
}

#[derive(Serialize)]
pub struct StrayReport {
    pub strays: Vec<Stray>,
    pub missing: Vec<MissingPayload>,
    pub totals: StrayTotals,
}

/// Per-transaction physical size accounting.
#[derive(Clone, Copy, Debug, Default, Serialize)]
pub struct TxSizes {
    /// Total apparent size of all files in all hash dirs this tx references.
    pub apparent: u64,
    /// Total on-disk size of the same.
    pub disk: u64,
    /// Portion in hash dirs referenced by no *other* active transaction —
    /// i.e. what deleting this transaction would free.
    pub exclusive_apparent: u64,
    pub exclusive_disk: u64,
    /// Hash dirs shared with other active transactions.
    pub shared_dirs: u64,
    /// Referenced hash dirs missing from disk.
    pub missing_dirs: u64,
    pub files: u64,
}

/// Problems tying an otherwise-active transaction to strays or lost payloads —
/// the fingerprint of a partial/interrupted add.
#[derive(Clone, Copy, Debug, Default, Serialize)]
pub struct TxIssues {
    /// Unreferenced hash dirs whose refs.ptr claims this transaction even
    /// though its manifest does not list them.
    pub claimed_stray_dirs: u64,
    /// Manifest entries whose payload is missing on disk.
    pub missing_payloads: u64,
}

pub struct Analysis {
    pub strays: StrayReport,
    pub tx_sizes: HashMap<TransactionId, TxSizes>,
    /// Only transactions with at least one issue appear here.
    pub tx_issues: HashMap<TransactionId, TxIssues>,
}

/// Is `file_name` an expected payload for any of the recorded entry names?
fn is_expected_payload(file_name: &str, entry_names: &[&str]) -> bool {
    if file_name.eq_ignore_ascii_case("file.ptr") {
        return true;
    }
    entry_names.iter().any(|n| {
        file_name.eq_ignore_ascii_case(n)
            || file_name.eq_ignore_ascii_case(&compressed_name(n))
    })
}

pub fn analyze(index: &StoreIndex, scan: &ScanResult) -> Analysis {
    let mut strays = Vec::new();
    let mut totals = StrayTotals::default();
    let mut tx_sizes: HashMap<TransactionId, TxSizes> = HashMap::new();
    let mut tx_issues: HashMap<TransactionId, TxIssues> = HashMap::new();

    // Physical dirs by lower-cased key.
    let mut seen_dirs: HashMap<(String, String), usize> = HashMap::new();
    for (i, d) in scan.hash_dirs.iter().enumerate() {
        seen_dirs.insert(d.key(), i);
    }

    for d in &scan.hash_dirs {
        let refs = index.dir_refs(&d.name.to_lowercase(), &d.hash.to_lowercase());
        let rel_dir = format!("{}/{}", d.name, d.hash);

        if refs.is_empty() {
            // Entire dir is unaccounted for.
            totals.unreferenced_dirs += 1;
            // If its refs.ptr claims an active transaction, that transaction's
            // manifest is missing entries — mark it incomplete.
            if let Some(lines) = &d.refs {
                let mut claimers: Vec<TransactionId> =
                    lines.iter().filter_map(|l| l.tx).collect();
                claimers.sort();
                claimers.dedup();
                for t in claimers {
                    let active = index
                        .transactions
                        .get(&t)
                        .map(|x| x.is_active())
                        .unwrap_or(false);
                    if active {
                        tx_issues.entry(t).or_default().claimed_stray_dirs += 1;
                    }
                }
            }
            let detail = match &d.refs {
                Some(lines) if !lines.is_empty() => {
                    let txs: Vec<String> = lines
                        .iter()
                        .map(|l| match l.tx {
                            Some(t) => {
                                let active = index
                                    .transactions
                                    .get(&t)
                                    .map(|x| x.is_active())
                                    .unwrap_or(false);
                                if active {
                                    format!("{t} (active, but its manifest does not list this dir — partial add?)")
                                } else {
                                    format!("{t} (deleted/unknown)")
                                }
                            }
                            None => "?".into(),
                        })
                        .collect();
                    format!("refs.ptr claims tx {}", txs.join(", "))
                }
                _ => "no active transaction references this dir".to_string(),
            };
            for f in &d.files {
                totals.files += 1;
                totals.apparent += f.size;
                totals.disk += f.disk;
                strays.push(Stray {
                    rel_path: format!("{rel_dir}/{}", f.name),
                    kind: StrayKind::UnreferencedHashDir,
                    size: f.size,
                    disk: f.disk,
                    group: Some(rel_dir.clone()),
                    detail: detail.clone(),
                });
            }
            if d.files.is_empty() {
                // Empty unreferenced dir: still worth listing (prunable).
                strays.push(Stray {
                    rel_path: rel_dir.clone(),
                    kind: StrayKind::UnreferencedHashDir,
                    size: 0,
                    disk: 0,
                    group: Some(rel_dir.clone()),
                    detail: "empty unreferenced directory".to_string(),
                });
            }
        } else {
            // Referenced dir: account sizes to owning transactions and check
            // each file is expected.
            let entry_names: Vec<&str> = refs
                .iter()
                .map(|i| index.entries[*i as usize].name.as_str())
                .collect();
            let owners: Vec<TransactionId> = {
                let mut v: Vec<TransactionId> =
                    refs.iter().map(|i| index.entries[*i as usize].tx).collect();
                v.sort();
                v.dedup();
                v
            };
            let (apparent, disk) = (d.apparent(), d.disk());
            for owner in &owners {
                let s = tx_sizes.entry(*owner).or_default();
                s.apparent += apparent;
                s.disk += disk;
                s.files += d.files.len() as u64;
                if owners.len() == 1 {
                    s.exclusive_apparent += apparent;
                    s.exclusive_disk += disk;
                } else {
                    s.shared_dirs += 1;
                }
            }
            for f in &d.files {
                if f.name.eq_ignore_ascii_case("refs.ptr")
                    || is_expected_payload(&f.name, &entry_names)
                {
                    continue;
                }
                totals.files += 1;
                totals.apparent += f.size;
                totals.disk += f.disk;
                strays.push(Stray {
                    rel_path: format!("{rel_dir}/{}", f.name),
                    kind: StrayKind::UnexpectedFile,
                    size: f.size,
                    disk: f.disk,
                    group: Some(rel_dir.clone()),
                    detail: format!("expected payload named {}", entry_names.join(" or ")),
                });
            }
        }

        for sub in &d.subdirs {
            strays.push(Stray {
                rel_path: format!("{rel_dir}/{sub}"),
                kind: StrayKind::OutOfPlace,
                size: 0,
                disk: 0,
                group: Some(rel_dir.clone()),
                detail: "unexpected subdirectory inside hash dir".to_string(),
            });
        }
    }

    for f in &scan.odd_files {
        totals.files += 1;
        totals.apparent += f.size;
        totals.disk += f.disk;
        strays.push(Stray {
            rel_path: f.rel_path.clone(),
            kind: StrayKind::OutOfPlace,
            size: f.size,
            disk: f.disk,
            group: None,
            detail: "file outside <name>/<HASH>/ structure".to_string(),
        });
    }

    // Missing payloads: every referenced dir must exist and contain a payload.
    let mut missing = Vec::new();
    let mut checked: std::collections::HashSet<(String, String)> = Default::default();
    for e in &index.entries {
        let key = (e.name.to_lowercase(), e.hash.to_lowercase());
        match seen_dirs.get(&key) {
            None => {
                let s = tx_sizes.entry(e.tx).or_default();
                s.missing_dirs += 1;
                tx_issues.entry(e.tx).or_default().missing_payloads += 1;
                missing.push(MissingPayload {
                    tx: e.tx,
                    name: e.name.clone(),
                    hash: e.hash.clone(),
                    dir_missing: true,
                });
            }
            Some(i) => {
                if checked.insert(key) {
                    let d = &scan.hash_dirs[*i];
                    let has_payload = d
                        .files
                        .iter()
                        .any(|f| is_expected_payload(&f.name, &[e.name.as_str()]));
                    if !has_payload {
                        tx_issues.entry(e.tx).or_default().missing_payloads += 1;
                        missing.push(MissingPayload {
                            tx: e.tx,
                            name: e.name.clone(),
                            hash: e.hash.clone(),
                            dir_missing: false,
                        });
                    }
                }
            }
        }
    }

    strays.sort_by(|a, b| a.rel_path.cmp(&b.rel_path));

    Analysis {
        strays: StrayReport {
            strays,
            missing,
            totals,
        },
        tx_sizes,
        tx_issues,
    }
}
