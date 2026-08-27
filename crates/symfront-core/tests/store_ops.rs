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

/// Ground truth: hash real payloads from the live store and compare against
/// the directory names symstore.exe chose. Skips when the store is absent.
#[test]
fn ident_matches_live_store() {
    let root = Path::new("/srv/symstore");
    if !root.is_dir() {
        return;
    }
    let mut checked = 0;
    for name_dir in fs::read_dir(root).unwrap().flatten() {
        if checked >= 200 {
            break;
        }
        if !name_dir.file_type().unwrap().is_dir()
            || name_dir.file_name() == "000Admin"
        {
            continue;
        }
        let fname = name_dir.file_name().to_string_lossy().into_owned();
        for hash_dir in fs::read_dir(name_dir.path()).unwrap().flatten() {
            let expect = hash_dir.file_name().to_string_lossy().into_owned();
            let payload = hash_dir.path().join(&fname);
            if !payload.is_file() {
                continue;
            }
            match symfront_core::ident::identify(&payload) {
                Ok(Some((_kind, hash))) => {
                    assert_eq!(hash, expect, "hash mismatch for {}", payload.display());
                    checked += 1;
                }
                Ok(None) => panic!("failed to identify {}", payload.display()),
                Err(e) => panic!("{e}"),
            }
        }
    }
    assert!(checked > 50, "only {checked} payloads checked");
}

/// Full add lifecycle, fully self-contained via synthetic fixtures.
#[test]
fn add_transaction_roundtrip() {
    let tmp = tempfile::tempdir().unwrap();
    let root = tmp.path().join("store");
    fs::create_dir_all(root.join("000Admin")).unwrap();
    let src = tmp.path().join("src");
    fs::create_dir_all(&src).unwrap();
    fs::write(src.join("7zr.exe"), fixtures::minimal_pe(0x5685393C, 0xbf000, true)).unwrap();
    let guid = *b"\x69\x47\xd8\xfb\x3a\x2a\xde\x46\x84\x01\x7f\x48\x0a\xcf\x33\x89";
    fs::write(
        src.join("3dquicklogicplugin.pdb"),
        fixtures::minimal_msf_pdb(guid, 1, Some(1)),
    )
    .unwrap();
    fs::write(src.join("notes.txt"), b"not a symbol file").unwrap();

    let (candidates, skipped) = symfront_core::ident::collect(&[src.clone()]).unwrap();
    assert_eq!(candidates.len(), 2);
    assert_eq!(skipped.len(), 1);

    let store = Store::open(&root).unwrap();
    let req = ops::AddRequest {
        product: "Test Product".into(),
        version: "1.0".into(),
        comment: "".into(),
        consume: false,
        files: candidates
            .iter()
            .map(|c| ops::AddFile {
                path: c.path.clone(),
                name: c.name.clone(),
                hash: c.hash.clone(),
                kind: c.kind,
                source: format!("C:\\build\\{}", c.name),
            })
            .collect(),
    };

    // Dry run: nothing lands.
    let dry = ops::add_transaction(&store, &req, true, &ops::OpProgress::default()).unwrap();
    assert!(dry.dry_run && dry.id.is_none());
    assert_eq!(dry.files_new, 2);
    assert!(!root.join("7zr.exe").exists());

    let out = ops::add_transaction(&store, &req, false, &ops::OpProgress::default()).unwrap();
    assert_eq!(out.id, Some(TransactionId(1)));
    assert_eq!(out.files_new, 2);
    assert!(root.join("7zr.exe/5685393Cbf000/7zr.exe").is_file());
    let refs = fs::read_to_string(root.join("7zr.exe/5685393Cbf000/refs.ptr")).unwrap();
    assert_eq!(refs, "0000000001,file,\"C:\\build\\7zr.exe\",bin,,N,,");
    let refs_pdb = fs::read_to_string(
        root.join("3dquicklogicplugin.pdb/FBD847692A3A46DE84017F480ACF33891/refs.ptr"),
    )
    .unwrap();
    assert!(refs_pdb.ends_with(",pri,,N,,"));
    let manifest = fs::read_to_string(root.join("000Admin/0000000001")).unwrap();
    assert!(manifest.contains("\"7zr.exe\\5685393Cbf000\",\"C:\\build\\7zr.exe\""));
    assert!(manifest.ends_with("\r\n")); // manifests are fully terminated
    let history = fs::read_to_string(root.join("000Admin/history.txt")).unwrap();
    assert!(history.starts_with("0000000001,add,file,"));
    assert!(history.contains("\"Test Product\",\"1.0\",\"\","));
    assert!(ops::pending_journals(&store).unwrap().is_empty());

    // Index sees it; checks are clean.
    let index = StoreIndex::load(&store).unwrap();
    assert_eq!(index.active_transactions().count(), 1);
    assert_eq!(index.entries.len(), 2);
    fs::write(root.join("pingme.txt"), b"").unwrap();
    assert!(check::check_admin(&store, &index).unwrap().is_empty());

    // Second add of the same files: dedup, refs gets a second line.
    let out2 = ops::add_transaction(&store, &req, false, &ops::OpProgress::default()).unwrap();
    assert_eq!(out2.id, Some(TransactionId(2)));
    assert_eq!(out2.files_deduped, 2);
    assert_eq!(out2.files_new, 0);
    let refs = fs::read_to_string(root.join("7zr.exe/5685393Cbf000/refs.ptr")).unwrap();
    assert_eq!(
        refs,
        "0000000001,file,\"C:\\build\\7zr.exe\",bin,,N,,\r\n0000000002,file,\"C:\\build\\7zr.exe\",bin,,N,,"
    );

    // Delete tx1: payload survives (tx2 refs it); delete tx2: gone.
    ops::delete_transaction(&store, TransactionId(1), false, &ops::OpProgress::default()).unwrap();
    assert!(root.join("7zr.exe/5685393Cbf000/7zr.exe").is_file());
    ops::delete_transaction(&store, TransactionId(2), false, &ops::OpProgress::default()).unwrap();
    assert!(!root.join("7zr.exe").exists());

    // Deep-clean bill of health.
    let index = StoreIndex::load(&store).unwrap();
    let scan = scan::scan(&store, true, &ScanProgress::default()).unwrap();
    let report = strays::analyze(&index, &scan).strays;
    assert!(report.strays.is_empty() && report.missing.is_empty());
}

/// PDB age must come from the DBI stream when it disagrees with the info
/// stream — debuggers request the RSDS age from the PE, which matches DBI.
/// Ground truth: RSDS records inside the paired DLLs in ~/testcases.
#[test]
fn pdb_age_uses_dbi_stream() {
    let dir = Path::new("/home/steven/testcases");
    if !dir.is_dir() {
        return;
    }
    let cases = [
        // (file, expected hash from the paired DLL's RSDS record)
        ("Microsoft.ConfigCI.Commands.pdb", "57D8363310B240CCBC9CE9D78163C38D1"),
        ("Microsoft.Data.Entity.Build.Tasks.pdb", "F002579388CE46038E78A8AAB55AEAEE1"),
        // Portable PDB (BSJB): GUID from #Pdb stream + literal FFFFFFFF;
        // verified live: msdl serves this exact file under this key.
        (
            "Microsoft.NET.StringTools.pdb",
            "E820FC90985942DBA3CD83B6AAB8EC3DFFFFFFFF",
        ),
    ];
    for (name, expect) in cases {
        let path = dir.join(name);
        if !path.is_file() {
            continue;
        }
        let (kind, hash) = symfront_core::ident::identify(&path).unwrap().unwrap();
        assert_eq!(kind, symfront_core::ident::FileKind::Pdb);
        assert_eq!(hash, expect, "{name}");
    }
}

mod fixtures;

fn data_dir() -> std::path::PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/data")
}

/// The synthetic input files used by the checked-in reference stores.
/// Regenerate with SYMFRONT_REGEN=1; otherwise the checked-in bytes must
/// exactly match the generators (pins generator behavior).
fn replay_inputs() -> Vec<(&'static str, Vec<u8>, &'static str)> {
    vec![
        ("a.exe", fixtures::minimal_pe(0x5FA00000, 0x3000, true), "5FA000003000"),
        ("b.exe", fixtures::minimal_pe(0x5FB00000, 0x4000, false), "5FB000004000"),
        ("shared.exe", fixtures::minimal_pe(0x5FC00000, 0x5000, true), "5FC000005000"),
    ]
}

#[test]
fn fixture_inputs_are_pinned() {
    let dir = data_dir().join("inputs");
    if std::env::var("SYMFRONT_REGEN").is_ok() {
        fs::create_dir_all(&dir).unwrap();
        for (name, bytes, _) in replay_inputs() {
            fs::write(dir.join(name), &bytes).unwrap();
        }
        return;
    }
    for (name, bytes, hash) in replay_inputs() {
        let on_disk = fs::read(dir.join(name)).unwrap();
        assert_eq!(on_disk, bytes, "{name} drifted from its generator");
        let tmp = tempfile::NamedTempFile::new().unwrap();
        fs::write(tmp.path(), &bytes).unwrap();
        let (kind, h) = symfront_core::ident::identify(tmp.path()).unwrap().unwrap();
        assert_eq!(kind, symfront_core::ident::FileKind::Pe);
        assert_eq!(h, hash, "{name}");
    }
}

#[test]
fn ident_synthetic() {
    let tmp = tempfile::tempdir().unwrap();
    let write = |name: &str, bytes: &[u8]| {
        let p = tmp.path().join(name);
        fs::write(&p, bytes).unwrap();
        p
    };
    let guid = *b"\x10\x11\x12\x13\x14\x15\x16\x17\x18\x19\x1a\x1b\x1c\x1d\x1e\x1f";
    let ghex = fixtures::guid_hex(&guid);

    let pe64 = write("x64.exe", &fixtures::minimal_pe(0x11223344, 0xABC00, true));
    assert_eq!(symfront_core::ident::identify(&pe64).unwrap().unwrap().1, "11223344abc00");
    let pe32 = write("x86.exe", &fixtures::minimal_pe(0x01020304, 0x1000, false));
    assert_eq!(symfront_core::ident::identify(&pe32).unwrap().unwrap().1, "010203041000");

    // Age mismatch: DBI age (1) must win over info age (3).
    let pdb = write("m.pdb", &fixtures::minimal_msf_pdb(guid, 3, Some(1)));
    assert_eq!(symfront_core::ident::identify(&pdb).unwrap().unwrap().1, format!("{ghex}1"));
    // No DBI stream: info age is the fallback.
    let pdb2 = write("n.pdb", &fixtures::minimal_msf_pdb(guid, 3, None));
    assert_eq!(symfront_core::ident::identify(&pdb2).unwrap().unwrap().1, format!("{ghex}3"));
    // Portable PDB: literal FFFFFFFF.
    let ppdb = write("p.pdb", &fixtures::minimal_portable_pdb(guid));
    assert_eq!(
        symfront_core::ident::identify(&ppdb).unwrap().unwrap().1,
        format!("{ghex}FFFFFFFF")
    );
    // Garbage is skipped, not an error.
    let junk = write("junk.bin", b"not a pe or pdb at all");
    assert!(symfront_core::ident::identify(&junk).unwrap().is_none());
}

/// The checked-in single-add store produced by real symstore.exe: we must
/// parse it cleanly and our identification must agree with its layout.
#[test]
fn reference_store_parses_and_hashes_match() {
    let root = data_dir().join("refstore");
    let store = Store::open(&root).unwrap();
    let index = StoreIndex::load(&store).unwrap();
    assert_eq!(index.active_transactions().count(), 1);
    assert_eq!(index.entries.len(), 1);
    let e = &index.entries[0];
    assert_eq!(e.name, "symfronttest.exe");
    assert_eq!(e.hash, "5F0000003000");
    let payload = root.join("symfronttest.exe/5F0000003000/symfronttest.exe");
    let (_, h) = symfront_core::ident::identify(&payload).unwrap().unwrap();
    assert_eq!(h, e.hash);
    assert!(check::check_admin(&store, &index).unwrap().is_empty());
    let scan = scan::scan(&store, true, &ScanProgress::default()).unwrap();
    let report = strays::analyze(&index, &scan).strays;
    assert!(report.strays.is_empty() && report.missing.is_empty(), "{:?}", report.strays);
}

// ---- replay: add, add (shared), del, re-add ----

fn replay_with_ours(root: &Path) {
    let inputs = data_dir().join("inputs");
    fs::create_dir_all(root.join("000Admin")).unwrap();
    let store = Store::open(root).unwrap();
    let add = |files: &[&str]| {
        let req = ops::AddRequest {
            product: "Replay".into(),
            version: "1.0".into(),
            comment: "".into(),
            consume: false,
            files: files
                .iter()
                .map(|n| {
                    let path = inputs.join(n);
                    let (kind, hash) = symfront_core::ident::identify(&path).unwrap().unwrap();
                    ops::AddFile {
                        path: path.clone(),
                        name: n.to_string(),
                        hash,
                        kind,
                        source: path.to_string_lossy().into_owned(),
                    }
                })
                .collect(),
        };
        ops::add_transaction(&store, &req, false, &ops::OpProgress::default()).unwrap();
    };
    add(&["a.exe", "shared.exe"]); // tx 1
    add(&["b.exe", "shared.exe"]); // tx 2
    ops::delete_transaction(&store, TransactionId(1), false, &ops::OpProgress::default())
        .unwrap(); // tx 3 = del 1
    add(&["a.exe"]); // tx 4
}

/// Normalized view of a store tree for comparison: payload file list +
/// per-dir refs.ptr (txid, tag) sequences + admin record shapes.
fn tree_summary(root: &Path) -> Vec<String> {
    let store = Store::open(root).unwrap();
    let index = StoreIndex::load(&store).unwrap();
    let mut out = Vec::new();
    let scan = scan::scan(&store, true, &ScanProgress::default()).unwrap();
    for d in &scan.hash_dirs {
        for f in &d.files {
            if f.name.eq_ignore_ascii_case("refs.ptr") {
                let text = fs::read_to_string(root.join(&d.name).join(&d.hash).join(&f.name)).unwrap();
                let refs: Vec<String> = symfront_core::format::lines(&text)
                    .map(|l| {
                        let fields: Vec<&str> = l.split(',').collect();
                        format!("{},{},{}", fields[0], fields[1], fields[3])
                    })
                    .collect();
                out.push(format!("{}/{} refs: {}", d.name, d.hash, refs.join(" | ")));
            } else {
                out.push(format!("{}/{} payload: {} ({} bytes)", d.name, d.hash, f.name, f.size));
            }
        }
    }
    for t in index.transactions.values() {
        out.push(format!(
            "tx {} state={:?} deleted_by={:?} entries={} product={:?}",
            t.id,
            t.file_state,
            t.deleted_by.iter().map(|d| d.0).collect::<Vec<_>>(),
            t.entry_count,
            t.record.as_ref().map(|r| r.product.clone()).unwrap_or_default(),
        ));
    }
    out.push(format!("lastid={:?}", store.read_lastid().unwrap()));
    out.sort();
    out
}

/// Replay the scripted sequence with our code and compare against the
/// checked-in tree that real symstore.exe produced for the same script.
#[test]
fn replay_matches_symstore_reference() {
    let reference = data_dir().join("refstore-replay");
    let tmp = tempfile::tempdir().unwrap();
    let ours = tmp.path().join("store");
    replay_with_ours(&ours);
    let (a, b) = (tree_summary(&ours), tree_summary(&reference));
    assert_eq!(a, b, "replayed tree differs from symstore.exe reference");
    // Payload bytes must be identical too.
    for (name, bytes, hash) in replay_inputs() {
        let rel = format!("{name}/{hash}/{name}");
        let ref_payload = reference.join(&rel);
        if ref_payload.exists() {
            assert_eq!(fs::read(ref_payload).unwrap(), bytes, "{rel}");
            assert_eq!(fs::read(ours.join(&rel)).unwrap(), bytes, "{rel}");
        }
    }
}

/// Live differential test against the bundled symstore.exe (tests/tools/):
/// run the same add/add/del/add script through both implementations and
/// compare the resulting trees. Runs under wine on Unix (or natively on
/// Windows); skips silently when neither can execute it.
#[test]
fn differential_replay_vs_bundled_symstore() {
    let tools = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/tools/symstore.exe");
    let runner: &[&str] = if cfg!(windows) { &[] } else { &["wine"] };
    let available = std::process::Command::new(runner.first().copied().unwrap_or("cmd"))
        .arg(if runner.is_empty() { "/c" } else { "--version" })
        .arg(if runner.is_empty() { "ver" } else { "" })
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false);
    if !available || !tools.is_file() {
        eprintln!("skipping: no way to execute symstore.exe here");
        return;
    }
    let winepath = |p: &Path| -> String {
        if cfg!(windows) {
            p.to_string_lossy().into_owned()
        } else {
            format!("Z:{}", p.to_string_lossy().replace('/', "\\"))
        }
    };
    let tmp = tempfile::tempdir().unwrap();
    let inputs = data_dir().join("inputs");
    let dirs = ["dir1", "dir2", "dir3"];
    for d in dirs {
        fs::create_dir_all(tmp.path().join(d)).unwrap();
    }
    for (d, files) in dirs.iter().zip([
        &["a.exe", "shared.exe"][..],
        &["b.exe", "shared.exe"][..],
        &["a.exe"][..],
    ]) {
        for f in files {
            fs::copy(inputs.join(f), tmp.path().join(d).join(f)).unwrap();
        }
    }
    let theirs = tmp.path().join("theirs");
    let sym = |args: &[String]| {
        let mut cmd = if runner.is_empty() {
            std::process::Command::new(&tools)
        } else {
            let mut c = std::process::Command::new(runner[0]);
            c.arg(&tools);
            c
        };
        cmd.env("WINEDEBUG", "-all");
        let out = cmd.args(args).output().expect("running symstore.exe");
        assert!(out.status.success(), "symstore.exe failed: {args:?}");
        let text = String::from_utf8_lossy(&out.stdout).into_owned();
        assert!(
            !text.contains("Number of errors = 1"),
            "symstore.exe reported errors: {text}"
        );
    };
    let add = |dir: &str| {
        sym(&[
            "add".into(),
            "/r".into(),
            "/f".into(),
            format!("{}\\*", winepath(&tmp.path().join(dir))),
            "/s".into(),
            winepath(&theirs),
            "/t".into(),
            "Replay".into(),
            "/v".into(),
            "1.0".into(),
        ]);
    };
    add("dir1");
    add("dir2");
    sym(&[
        "del".into(),
        "/i".into(),
        "0000000001".into(),
        "/s".into(),
        winepath(&theirs),
    ]);
    add("dir3");

    let ours = tmp.path().join("ours");
    replay_with_ours(&ours);
    assert_eq!(
        tree_summary(&ours),
        tree_summary(&theirs),
        "our replay diverged from live symstore.exe"
    );
}
