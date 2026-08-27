//! End-to-end tests against a synthetic store built the way symstore.exe
//! builds one (CRLF, unterminated final lines, refs.ptr refcounts).

use std::fs;
use std::path::Path;

use symfront_core::check;
use symfront_core::index::StoreIndex;
use symfront_core::ops;
use symfront_core::scan::{self, ScanProgress};
use symfront_core::strays;
use symfront_core::{Store, TransactionId};

struct Fixture {
    _tmp: tempfile::TempDir,
    root: std::path::PathBuf,
}

fn add_payload(root: &Path, name: &str, hash: &str, tx: u32, content: &[u8]) {
    let dir = root.join(name).join(hash);
    fs::create_dir_all(&dir).unwrap();
    fs::write(dir.join(name), content).unwrap();
    let refs = dir.join("refs.ptr");
    let line = format!("{:010},file,\"C:\\src\\{name}\",bin,,N,,", tx);
    if refs.exists() {
        let mut cur = fs::read_to_string(&refs).unwrap();
        cur.push_str("\r\n");
        cur.push_str(&line);
        fs::write(&refs, cur).unwrap();
    } else {
        fs::write(&refs, line).unwrap();
    }
}

/// Build a store with:
///   tx 1: a.exe/AAAA1000, shared.pdb/S1 (2 entries)
///   tx 2: b.exe/BBBB2000, shared.pdb/S1 (2 entries; shares shared.pdb/S1)
/// plus strays: an unreferenced hash dir, an unexpected file in a referenced
/// dir, and an out-of-place file.
fn fixture() -> Fixture {
    let tmp = tempfile::tempdir().unwrap();
    let root = tmp.path().to_path_buf();
    let admin = root.join("000Admin");
    fs::create_dir_all(&admin).unwrap();

    add_payload(&root, "a.exe", "AAAA1000", 1, b"payload-a");
    add_payload(&root, "shared.pdb", "S1", 1, b"payload-shared");
    add_payload(&root, "b.exe", "BBBB2000", 2, b"payload-b");
    add_payload(&root, "shared.pdb", "S1", 2, b"payload-shared");
    // add_payload writes the payload twice for shared.pdb; that's fine.

    fs::write(
        admin.join("0000000001"),
        "\"a.exe\\AAAA1000\",\"C:\\src\\a.exe\"\r\n\"shared.pdb\\S1\",\"C:\\src\\shared.pdb\"",
    )
    .unwrap();
    fs::write(
        admin.join("0000000002"),
        "\"b.exe\\BBBB2000\",\"C:\\src\\b.exe\"\r\n\"shared.pdb\\S1\",\"C:\\src\\shared.pdb\"",
    )
    .unwrap();
    fs::write(
        admin.join("history.txt"),
        "0000000001,add,file,01/01/2026,10:00:00,\"Prod A\",\"1.0\",\"\",\r\n\
         0000000002,add,file,01/02/2026,11:00:00,\"Prod B\",\"2.0\",\"\",",
    )
    .unwrap();
    fs::write(
        admin.join("server.txt"),
        "0000000001,add,file,01/01/2026,10:00:00,\"Prod A\",\"1.0\",\"\",\r\n\
         0000000002,add,file,01/02/2026,11:00:00,\"Prod B\",\"2.0\",\"\",\r\n",
    )
    .unwrap();
    fs::write(admin.join("lastid.txt"), "0000000002").unwrap();
    fs::write(root.join("pingme.txt"), b"").unwrap();

    // Strays.
    let orphan = root.join("orphan.exe").join("DEAD0001");
    fs::create_dir_all(&orphan).unwrap();
    fs::write(orphan.join("orphan.exe"), b"orphan-payload").unwrap();
    fs::write(orphan.join("refs.ptr"), "0000000099,file,\"C:\\gone\",bin,,N,,").unwrap();
    fs::write(root.join("a.exe").join("AAAA1000").join("junk.tmp"), b"junk").unwrap();
    fs::write(root.join("b.exe").join("stray-note.txt"), b"note").unwrap();

    Fixture { _tmp: tmp, root }
}

fn load(root: &Path) -> (Store, StoreIndex) {
    let store = Store::open(root).unwrap();
    let index = StoreIndex::load(&store).unwrap();
    (store, index)
}

#[test]
fn index_and_search() {
    let f = fixture();
    let (_store, index) = load(&f.root);
    assert_eq!(index.active_transactions().count(), 2);
    assert_eq!(index.entries.len(), 4);
    assert_eq!(index.lastid, Some(TransactionId(2)));

    let hits = index.search("a.exe", 10);
    assert_eq!(hits.len(), 1);
    assert_eq!(hits[0].product.as_deref(), Some("Prod A"));

    // Hash prefix search, case-insensitive.
    let hits = index.search("bbbb", 10);
    assert_eq!(hits.len(), 1);
    assert_eq!(hits[0].name, "b.exe");

    // Shared dir referenced by both transactions.
    assert_eq!(index.dir_refs("shared.pdb", "s1").len(), 2);
}

#[test]
fn scan_and_strays() {
    let f = fixture();
    let (store, index) = load(&f.root);
    let scan = scan::scan(&store, true, &ScanProgress::default()).unwrap();
    assert_eq!(scan.hash_dirs.len(), 4); // a, b, shared, orphan

    let analysis = strays::analyze(&index, &scan);
    let report = &analysis.strays;

    let paths: Vec<&str> = report.strays.iter().map(|s| s.rel_path.as_str()).collect();
    assert!(paths.contains(&"orphan.exe/DEAD0001/orphan.exe"));
    assert!(paths.contains(&"orphan.exe/DEAD0001/refs.ptr"));
    assert!(paths.contains(&"a.exe/AAAA1000/junk.tmp"));
    assert!(paths.contains(&"b.exe/stray-note.txt"));
    // Legitimate payloads are not strays.
    assert!(!paths.iter().any(|p| p.ends_with("shared.pdb/S1/shared.pdb")));
    assert_eq!(report.totals.unreferenced_dirs, 1);
    assert!(report.missing.is_empty());

    // Size accounting: tx1's exclusive size excludes the shared dir.
    let s1 = &analysis.tx_sizes[&TransactionId(1)];
    assert_eq!(s1.shared_dirs, 1);
    assert!(s1.exclusive_apparent < s1.apparent);
    assert!(s1.apparent > 0);
}

#[test]
fn missing_payload_detection() {
    let f = fixture();
    fs::remove_file(f.root.join("a.exe/AAAA1000/a.exe")).unwrap();
    let (store, index) = load(&f.root);
    let scan = scan::scan(&store, true, &ScanProgress::default()).unwrap();
    let analysis = strays::analyze(&index, &scan);
    assert_eq!(analysis.strays.missing.len(), 1);
    assert_eq!(analysis.strays.missing[0].name, "a.exe");
    assert!(!analysis.strays.missing[0].dir_missing);
}

#[test]
fn delete_respects_refcounts() {
    let f = fixture();
    let (store, _index) = load(&f.root);

    // Dry run mutates nothing.
    let dry = ops::delete_transaction(&store, TransactionId(1), true, &ops::OpProgress::default()).unwrap();
    assert!(dry.dry_run);
    assert!(f.root.join("a.exe/AAAA1000/a.exe").exists());
    assert!(store.admin_dir().join("0000000001").exists());

    let out = ops::delete_transaction(&store, TransactionId(1), false, &ops::OpProgress::default()).unwrap();
    assert_eq!(out.del_id, Some(TransactionId(3)));
    // a.exe refcount hit zero: payload and dirs gone (junk.tmp keeps the dir).
    assert!(!f.root.join("a.exe/AAAA1000/a.exe").exists());
    assert!(!f.root.join("a.exe/AAAA1000/refs.ptr").exists());
    assert!(f.root.join("a.exe/AAAA1000/junk.tmp").exists());
    // shared.pdb still referenced by tx2: payload stays, refs.ptr rewritten.
    assert!(f.root.join("shared.pdb/S1/shared.pdb").exists());
    let refs = fs::read_to_string(f.root.join("shared.pdb/S1/refs.ptr")).unwrap();
    assert!(refs.contains("0000000002"));
    assert!(!refs.contains("0000000001"));

    // Admin records updated.
    assert!(!store.admin_dir().join("0000000001").exists());
    assert!(store.admin_dir().join("0000000001.deleted").exists());
    let history = fs::read_to_string(store.history_path()).unwrap();
    assert!(history.ends_with("0000000003,del,0000000001"));
    let server = fs::read_to_string(store.server_path()).unwrap();
    assert!(!server.contains("0000000001,add"));
    assert!(server.contains("0000000002,add"));
    assert_eq!(
        fs::read_to_string(store.lastid_path()).unwrap(),
        "0000000003"
    );
    // No leftover journal.
    assert!(ops::pending_journals(&store).unwrap().is_empty());

    // Re-index: tx1 inactive, tx2 alone owns the shared dir now.
    let index = StoreIndex::load(&store).unwrap();
    assert_eq!(index.active_transactions().count(), 1);
    assert_eq!(index.dir_refs("shared.pdb", "s1").len(), 1);

    // Deleting again fails cleanly.
    let err = ops::delete_transaction(&store, TransactionId(1), false, &ops::OpProgress::default()).unwrap_err();
    assert!(matches!(err, symfront_core::Error::TxNotActive(..)));

    // Deleting tx2 empties the store payload side entirely.
    ops::delete_transaction(&store, TransactionId(2), false, &ops::OpProgress::default()).unwrap();
    assert!(!f.root.join("shared.pdb").exists());
    assert!(!f.root.join("b.exe/BBBB2000").exists());
}

#[test]
fn prune_removes_strays_and_empty_dirs() {
    let f = fixture();
    let (store, index) = load(&f.root);
    let scan = scan::scan(&store, true, &ScanProgress::default()).unwrap();
    let report = strays::analyze(&index, &scan).strays;
    let paths: Vec<String> = report.strays.iter().map(|s| s.rel_path.clone()).collect();

    let dry = ops::prune_strays(&store, &paths, true, &ops::OpProgress::default()).unwrap();
    assert!(dry.files_removed >= 4);
    assert!(f.root.join("orphan.exe").exists());

    let out = ops::prune_strays(&store, &paths, false, &ops::OpProgress::default()).unwrap();
    assert_eq!(out.files_removed, dry.files_removed);
    assert!(!f.root.join("orphan.exe").exists()); // dir chain cleaned up
    assert!(!f.root.join("a.exe/AAAA1000/junk.tmp").exists());
    assert!(f.root.join("a.exe/AAAA1000/a.exe").exists()); // payload untouched
    assert!(!f.root.join("b.exe/stray-note.txt").exists());
    assert!(f.root.join("b.exe/BBBB2000/b.exe").exists());

    // Now a clean bill of health.
    let index = StoreIndex::load(&store).unwrap();
    let scan = scan::scan(&store, true, &ScanProgress::default()).unwrap();
    let report = strays::analyze(&index, &scan).strays;
    assert!(report.strays.is_empty(), "{:?}", report.strays);
}

#[test]
fn prune_refuses_escapes_and_admin() {
    let f = fixture();
    let (store, _) = load(&f.root);
    assert!(ops::prune_strays(&store, &["../etc/passwd".into()], false, &ops::OpProgress::default()).is_err());
    assert!(ops::prune_strays(&store, &["000Admin/history.txt".into()], false, &ops::OpProgress::default()).is_err());
    assert!(ops::prune_strays(&store, &["/etc/passwd".into()], false, &ops::OpProgress::default()).is_err());
}

#[test]
fn checks_clean_store_then_break_it() {
    let f = fixture();
    let (store, index) = load(&f.root);
    let findings = check::check_admin(&store, &index).unwrap();
    assert!(findings.is_empty(), "{findings:?}");

    // Deep check: the orphan dir's refs.ptr points at a dead tx, but that's
    // only reported via strays; refs checks cover referenced dirs.
    let scan = scan::scan(&store, true, &ScanProgress::default()).unwrap();
    let deep = check::check_deep(&index, &scan);
    assert!(deep.is_empty(), "{deep:?}");

    // Break things: unpadded del target, stale server.txt line, missing manifest.
    let admin = store.admin_dir();
    let mut history = fs::read_to_string(store.history_path()).unwrap();
    history.push_str("\r\n0000000003,del,1");
    fs::write(store.history_path(), history).unwrap();
    fs::remove_file(admin.join("0000000002")).unwrap();

    let index = StoreIndex::load(&store).unwrap();
    let findings = check::check_admin(&store, &index).unwrap();
    let codes: Vec<&str> = findings.iter().map(|f| f.code).collect();
    assert!(codes.contains(&"del-unpadded-target"), "{codes:?}");
    // tx1 "deleted" by the del record but its manifest still present.
    assert!(codes.contains(&"deleted-but-live"), "{codes:?}");
    assert!(codes.contains(&"server-stale-entry"), "{codes:?}");
    // tx2's manifest is gone without a del record.
    assert!(codes.contains(&"manifest-missing"), "{codes:?}");
    // lastid (2) is now behind the del record id (3).
    assert!(codes.contains(&"lastid-behind"), "{codes:?}");
}

#[test]
fn missing_pingme_is_flagged() {
    let f = fixture();
    fs::remove_file(f.root.join("pingme.txt")).unwrap();
    let (store, index) = load(&f.root);
    let findings = check::check_admin(&store, &index).unwrap();
    assert!(findings.iter().any(|x| x.code == "pingme-missing"));
}

#[test]
fn interrupted_delete_is_reported_and_resumable() {
    let f = fixture();
    let (store, _) = load(&f.root);
    // Simulate a crash: journal exists, nothing else happened.
    fs::write(store.admin_dir().join("_symfront_del_0000000001"), "x").unwrap();
    let index = StoreIndex::load(&store).unwrap();
    let findings = check::check_admin(&store, &index).unwrap();
    assert!(findings.iter().any(|f| f.code == "interrupted-delete"));

    // Re-running the delete completes and clears the journal.
    ops::delete_transaction(&store, TransactionId(1), false, &ops::OpProgress::default()).unwrap();
    assert!(ops::pending_journals(&store).unwrap().is_empty());
}
