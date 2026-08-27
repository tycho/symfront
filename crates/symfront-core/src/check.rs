//! Consistency checks over the admin records (fast) and, when a deep scan is
//! available, over the payload tree as well.

use serde::Serialize;

use crate::index::StoreIndex;
use crate::scan::ScanResult;
use crate::store::TxFileState;
use crate::{ops, Result, Store, TransactionId};

#[derive(Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Debug, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Severity {
    Info,
    Warning,
    Error,
}

#[derive(Clone, Debug, Serialize)]
pub struct Finding {
    pub severity: Severity,
    pub code: &'static str,
    pub subject: String,
    pub message: String,
}

fn finding(severity: Severity, code: &'static str, subject: impl Into<String>, message: impl Into<String>) -> Finding {
    Finding {
        severity,
        code,
        subject: subject.into(),
        message: message.into(),
    }
}

/// Checks that only need the logical index (no tree walk).
pub fn check_admin(store: &Store, index: &StoreIndex) -> Result<Vec<Finding>> {
    let mut out = Vec::new();

    // Some HTTP symbol clients (e.g. Ghidra) probe for pingme.txt and treat
    // the whole server as down when it's absent.
    if !store.root().join("pingme.txt").is_file() {
        out.push(finding(
            Severity::Warning,
            "pingme-missing",
            "pingme.txt",
            "store root has no pingme.txt; some clients (e.g. Ghidra) declare an HTTP symbol server down without it — create an empty pingme.txt",
        ));
    }

    for (j, kind) in ops::pending_journals(store)? {
        match kind {
            ops::JournalKind::Del => out.push(finding(
                Severity::Error,
                "interrupted-delete",
                j.to_string(),
                format!("delete of {j} was interrupted mid-flight (journal present); re-run the delete to finish it"),
            )),
            ops::JournalKind::Add => out.push(finding(
                Severity::Error,
                "interrupted-add",
                j.to_string(),
                format!("add of {j} was interrupted before committing; its payloads show as strays claiming id {j} — prune them and remove the journal"),
            )),
        }
    }

    for rec in &index.history {
        if let crate::format::HistoryRecord::Unknown { raw } = rec {
            out.push(finding(
                Severity::Warning,
                "history-unparsed",
                raw.chars().take(60).collect::<String>(),
                "history.txt line could not be parsed",
            ));
        }
    }
    for raw in &index.server_bad_lines {
        out.push(finding(
            Severity::Warning,
            "server-unparsed",
            raw.chars().take(60).collect::<String>(),
            "server.txt line could not be parsed",
        ));
    }

    // del record hygiene.
    for d in &index.dels {
        if d.target.is_none() {
            out.push(finding(
                Severity::Error,
                "del-bad-target",
                d.id.to_string(),
                format!("del record targets unparseable id {:?}", d.target_raw),
            ));
            continue;
        }
        if d.target_raw.len() != 10 {
            out.push(finding(
                Severity::Warning,
                "del-unpadded-target",
                d.id.to_string(),
                format!(
                    "del record targets '{}' (not zero-padded); symstore.exe would not match it against files on disk",
                    d.target_raw
                ),
            ));
        }
        let target = d.target.unwrap();
        match index.transactions.get(&target) {
            None => out.push(finding(
                Severity::Warning,
                "del-dangling-target",
                d.id.to_string(),
                format!("del record targets unknown transaction {target}"),
            )),
            Some(t) => {
                if t.record.is_none() {
                    out.push(finding(
                        Severity::Warning,
                        "del-target-not-add",
                        d.id.to_string(),
                        format!("del record targets {target}, which has no add record in history"),
                    ));
                }
                if t.deleted_by.len() > 1 && t.deleted_by.first() != Some(&d.id) {
                    out.push(finding(
                        Severity::Info,
                        "del-duplicate",
                        d.id.to_string(),
                        format!(
                            "transaction {target} deleted more than once (by {})",
                            t.deleted_by
                                .iter()
                                .map(|x| x.to_string())
                                .collect::<Vec<_>>()
                                .join(", ")
                        ),
                    ));
                }
            }
        }
    }

    // Per-transaction cross-checks.
    for t in index.transactions.values() {
        let id = t.id;
        let is_deleted = !t.deleted_by.is_empty();
        match (t.record.as_ref(), t.file_state, is_deleted) {
            (Some(_), TxFileState::Missing, false) => out.push(finding(
                Severity::Error,
                "manifest-missing",
                id.to_string(),
                format!("history records add {id} but 000Admin/{id} is missing (and not .deleted)"),
            )),
            (Some(_), TxFileState::Deleted, false) => out.push(finding(
                Severity::Warning,
                "deleted-without-record",
                id.to_string(),
                format!("000Admin/{id}.deleted exists but history has no del record for {id} (interrupted delete?)"),
            )),
            (Some(_), TxFileState::Present, true) => out.push(finding(
                Severity::Error,
                "deleted-but-live",
                id.to_string(),
                format!("history says {id} was deleted but 000Admin/{id} still exists undeleted"),
            )),
            (None, TxFileState::Present, _) => out.push(finding(
                Severity::Warning,
                "manifest-orphan",
                id.to_string(),
                format!("000Admin/{id} exists but history has no add record (partial add?)"),
            )),
            _ => {}
        }

        // server.txt must list exactly the active adds.
        if t.is_active() && t.record.is_some() && !t.in_server_txt {
            out.push(finding(
                Severity::Warning,
                "server-missing-entry",
                id.to_string(),
                format!("active transaction {id} is not listed in server.txt"),
            ));
        }
        if t.in_server_txt && is_deleted {
            out.push(finding(
                Severity::Warning,
                "server-stale-entry",
                id.to_string(),
                format!("server.txt still lists {id}, which history says was deleted"),
            ));
        }

        if !t.bad_lines.is_empty() {
            out.push(finding(
                Severity::Warning,
                "manifest-unparsed",
                id.to_string(),
                format!("{} unparseable line(s) in manifest {id}", t.bad_lines.len()),
            ));
        }
    }

    for id in &index.server_orphans {
        out.push(finding(
            Severity::Warning,
            "server-orphan",
            id.to_string(),
            format!("server.txt lists {id} but history has no such transaction"),
        ));
    }

    // lastid must be >= every id seen anywhere.
    let max_seen = index
        .transactions
        .keys()
        .last()
        .copied()
        .max(index.dels.iter().map(|d| d.id).max());
    match (index.lastid, max_seen) {
        (Some(last), Some(max)) if last < max => out.push(finding(
            Severity::Error,
            "lastid-behind",
            last.to_string(),
            format!("lastid.txt is {last} but ids up to {max} exist; new transactions could collide"),
        )),
        (None, Some(max)) => out.push(finding(
            Severity::Error,
            "lastid-missing",
            "lastid.txt".to_string(),
            format!("lastid.txt missing/unreadable; ids up to {max} exist"),
        )),
        _ => {}
    }

    out.sort_by(|a, b| b.severity.cmp(&a.severity).then(a.subject.cmp(&b.subject)));
    Ok(out)
}

/// Checks that need a deep scan (refs.ptr contents).
pub fn check_deep(index: &StoreIndex, scan: &ScanResult) -> Vec<Finding> {
    let mut out = Vec::new();
    if !scan.with_refs {
        return out;
    }
    for d in &scan.hash_dirs {
        let rel = format!("{}/{}", d.name, d.hash);
        let active: Vec<TransactionId> = {
            let mut v: Vec<TransactionId> = index
                .dir_refs(&d.name.to_lowercase(), &d.hash.to_lowercase())
                .iter()
                .map(|i| index.entries[*i as usize].tx)
                .collect();
            v.sort();
            v.dedup();
            v
        };
        let Some(refs) = &d.refs else {
            if !active.is_empty() {
                out.push(finding(
                    Severity::Warning,
                    "refs-missing",
                    rel,
                    format!(
                        "referenced by {} but has no refs.ptr",
                        active.iter().map(|x| x.to_string()).collect::<Vec<_>>().join(", ")
                    ),
                ));
            }
            continue;
        };
        if active.is_empty() {
            // Wholly-unreferenced dirs are the stray report's job.
            continue;
        }
        let mut ref_txs: Vec<TransactionId> = refs.iter().filter_map(|r| r.tx).collect();
        ref_txs.sort();
        ref_txs.dedup();
        for tx in &ref_txs {
            let live = index
                .transactions
                .get(tx)
                .map(|t| t.is_active())
                .unwrap_or(false);
            if !live {
                out.push(finding(
                    Severity::Warning,
                    "refs-dead-tx",
                    rel.clone(),
                    format!("refs.ptr line references non-active transaction {tx} (leftover from a partial delete?)"),
                ));
            }
        }
        for tx in &active {
            if !ref_txs.contains(tx) {
                out.push(finding(
                    Severity::Warning,
                    "refs-line-missing",
                    rel.clone(),
                    format!("active transaction {tx} references this dir but refs.ptr has no line for it"),
                ));
            }
        }
    }
    out.sort_by(|a, b| b.severity.cmp(&a.severity).then(a.subject.cmp(&b.subject)));
    out
}
