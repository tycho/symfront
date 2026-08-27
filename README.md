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
- **Coexistence with symstore.exe**: the server watches `000Admin/` with
  inotify, so transactions added/deleted by other tools are picked up
  automatically (index reload + rescan, debounced). An external add in
  progress shows as strays/incomplete until its commit lands in
  `000Admin/` — it converges once the other tool finishes. Only the admin
  dir is watched; the payload tree would need a watch per hash dir.
- Web mutations (delete, prune) run as background jobs server-side: they
  keep running if the browser disconnects, progress streams to all
  connected pages over SSE (`/api/events`), and Ctrl-C waits for running
  jobs to finish (press it twice to force).

## Serving symbols to debuggers (optional)

`serve --serve-symbols` exposes the store read-only at `/symbols/` in the
plain HTTP layout dbghelp/symsrv/Ghidra expect: HEAD, byte ranges,
ETag/Last-Modified conditionals, on-the-fly gzip (skipped for ranges and
already-CAB-compressed `*_` payloads), and case-insensitive path
resolution (clients request whatever case the debuggee's headers
produced). No directory listings; `000Admin/`, `refs.ptr`, and scratch
files are never served. `/symbols/` is always unauthenticated — that is
the "unauthenticated" tier of the role model.

`--upstream <url>` (repeatable) forwards local misses to upstream symbol
servers and proxies the response through — no HTTP redirects, since old
symsrv builds don't follow them reliably:

```console
$ symfront init --store /tmp/scratch-store    # ad-hoc store, ready to serve
$ symfront serve --store /tmp/scratch-store --serve-symbols \
    --upstream https://msdl.microsoft.com/download/symbols
```

### Behind nginx

The UI uses relative URLs, so it works under any path prefix without
configuration — e.g. management at `/admin/` with nginx serving symbols
itself:

```nginx
location /admin/ { proxy_pass http://127.0.0.1:8710/; }   # trailing / strips the prefix
location /symbols/ { root /srv/symstore; ... }            # or let symfront serve them
```

Combine with `--trusted-proxies 1` so audit logs see real client IPs.

## Authentication (optional)

Without `--auth-db` the server is open (bind it to localhost or a trusted
network). With `--auth-db <path>` (or `SYMFRONT_AUTH_DB`), a small SQLite
database provides users, web sessions, and API tokens:

```console
$ export SYMFRONT_AUTH_DB=~/.local/share/symfront/auth.db
$ symfront user add steven --role admin        # prompts for password
$ symfront user add ci-bot --role rw --no-password   # token-only headless user
$ symfront user add viewer --role ro
$ symfront token create ci-bot --label "ci uploads"  # prints sf_… once
$ symfront serve
```

- Roles are strict supersets: unauthenticated (nothing) < `ro`
  (browse/search) < `rw` (store mutations) < `admin` (user management via
  the web Admin page or the CLI).
- Web UI sign-in paths: password (+ TOTP code if enrolled), or a WebAuthn
  passkey (which skips TOTP). Sessions are HttpOnly cookies (30 days,
  persisted across restarts; `Secure` when behind a TLS proxy).
- The Account page self-serves password changes, TOTP enrollment (QR code
  plus the `otpauth://` URL text for password managers; verification
  accepts the previous/current/next 30 s step for clock drift), passkey
  management, and API tokens with a read-only or read-write capability
  (further capped by the user's role).
- Headless clients: `Authorization: Bearer sf_…` — tokens are for the
  symbol-store API only; they can never reach account/admin endpoints or
  the web UI. Stored hashed, shown exactly once; passwords are argon2id.
- WebAuthn needs a secure context: it works on `http://localhost` out of
  the box; anywhere else set `--webauthn-origin https://…` and terminate
  TLS at a reverse proxy.
- Reverse proxy: run with `--trusted-proxies 1` behind nginx. Client IPs
  for audit logs then come from `X-Forwarded-For` (never looking past the
  trusted depth, so clients can't spoof), and `X-Forwarded-Proto: https`
  marks cookies `Secure`. With the default of 0 those headers are ignored.
- No TLS built in: front with a reverse proxy if it leaves localhost.

## Uploading (local or remote)

```console
$ symfront upload ./build/Release --product "My App" --version 1.2.3
$ symfront --server https://syms.example.com --token sf_… \
    upload ./build/Release --product "My App" --version 1.2.3
```

Files are identified by *content*, not extension — every PE flavor
(exe/dll/sys/ocx/com/…, hashed as TimeDateStamp+SizeOfImage) and MSF 7
PDBs (GUID+Age) — and land as one atomic transaction. Hashing and the
on-disk layout (manifests, refs.ptr, history/server records) are
byte-compatible with `symstore.exe` output, verified against a real
symstore.exe run and 200+ payloads of an existing store. Remote uploads
first ask the server which payloads it already has and skip those
entirely (incremental builds transfer only what changed), then commit
server-side as a background job that survives client disconnects.

The web UI has an Upload page with the same behavior: files are
identified client-side (headers only, nothing is read fully), payloads
the store already has are skipped, and the commit runs as a server-side
job. Drag-and-drop of files and folders is supported.

Uploads run a few streams in parallel (`--jobs N` on the CLI, 3-wide in
the browser) and are resumable: staged files persist server-side across
interruptions and even server restarts, expiring after 24 h of
inactivity. The CLI resumes implicitly (re-run the same command; staged
files are skipped); the web UI offers Resume/Discard when it finds a
previous session.

## Remote CLI

`--server URL` (env `SYMFRONT_SERVER`) switches supported commands to
the HTTP API: `status`, `search`, `tx list/show/del`, `upload`,
`strays [--prune]`, and `check`.
Authentication, in precedence order:

1. `--token` / `SYMFRONT_TOKEN` — an API token; wins over a stored
   session because tokens have indefinite lifetime (automation keeps
   working regardless of who is logged in).
2. A session from `symfront login --server URL` (username + password +
   TOTP code if enrolled), stored per-server in
   `~/.config/symfront/sessions.json` (mode 0600). `symfront logout`
   forgets it.
