# symfront

Management service for a Windows NT symbol store (`symstore.exe`-compatible
layout) living on a Linux host. One binary provides both a CLI and a web
UI/HTTP API.

## Layout

- `crates/symfront-core` — store model and operations: admin-record parsing
  (`history.txt`, `server.txt`, `lastid.txt`, transaction manifests,
  `refs.ptr`), physical tree scanning with apparent-vs-on-disk sizes, stray
  detection, consistency checks, and symstore-compatible transactional delete.
- `crates/symfront` — the `symfront` binary: CLI subcommands plus `serve`
  (axum server with an embedded single-page UI).

## Usage

The store path defaults to `/srv/symstore`; override with `--store` or
`SYMFRONT_STORE`.

```console
$ symfront serve --listen 127.0.0.1:8710   # web UI + JSON API
$ symfront status                          # quick summary from admin records
$ symfront tx list [--all] [--sizes]       # transactions (--sizes walks the tree)
$ symfront tx show 719                     # per-entry sizes, sources, sharing
$ symfront tx del 719 [--dry-run] [-y]     # delete like `symstore del`
$ symfront search clang-cl                 # name substring / hash prefix / source path
$ symfront strays [--prune] [--dry-run]    # files no active transaction accounts for
$ symfront check [--deep]                  # consistency checks (exit 1 on errors)
```

The web API mirrors the CLI: `GET /api/summary`, `/api/transactions[/{id}]`,
`DELETE /api/transactions/{id}?dry_run=`, `/api/search?q=`, `/api/strays`,
`POST /api/strays/prune`, `/api/check`, `POST /api/scan`.

## Semantics worth knowing

- **Sizes**: "apparent" is the sum of `st_size` (what `du
  --apparent-size` reports); "on disk" is `st_blocks * 512` (what plain `du`
  reports — with ZFS compression these differ a lot). Per-transaction views
  also report the *exclusive* size: what deleting that transaction would
  actually free, given hash dirs shared with other transactions via
  `refs.ptr` refcounts.
- **Delete** mirrors `symstore del`: drop the transaction's line from each
  referenced dir's `refs.ptr`; remove payload + dir when the last reference
  goes; rename the manifest to `.deleted`; rewrite `server.txt`; bump
  `lastid.txt`; append a `del` record to `history.txt`. All admin rewrites are
  atomic (temp file + rename), mutations hold an flock
  (`000Admin/.symfront.lock`), and a journal file marks in-flight deletes so
  `check` can flag an interrupted one (re-running the delete finishes it).
- **Strays** are files no *active* transaction manifest accounts for:
  wholly-unreferenced hash dirs, unexpected files inside referenced dirs, and
  files outside the `<name>/<HASH>/` structure. Missing payloads (recorded
  but absent) are reported separately as integrity errors, never pruned.
- The file formats are written back the way `symstore.exe` writes them
  (CRLF, unterminated final lines, zero-padded ids) so the store stays
  usable by Windows tooling.

## Not yet implemented

- `symfront add`: transactional add (recursive discovery of exe/dll/sys/pdb,
  PE timestamp+size / PDB GUID+age hashing) — locally and via the HTTP API,
  so remote clients get truly atomic adds instead of `symstore.exe` over UNC.
- Authentication for the web server (bind it to localhost or a trusted
  network for now).
