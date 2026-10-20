# symfront

A complete symbol-server front end for a POSIX host, in one binary:

- **Managed store** — a Windows NT symbol store (`symstore.exe`-compatible
  layout) with transactional add/delete, scanning, stray detection, and
  consistency checks. Served read-only to debuggers as **tier 0** of the
  pipeline.
- **Caching proxy** — the Rust successor to
  [symsrv](https://github.com/tycho/symsrv): local misses fan out to
  configurable upstream symbol servers (Microsoft, vendor stores,
  debuginfod instances, …) with write-through caching, negative caching,
  health breaking, and singleflight.
- **Admin UI + API** — a single-page web UI at `/admin/` with live jobs,
  upload, proxy dashboard, and a git-backed configuration editor; the same
  surface is scriptable over HTTP and mirrored by the CLI.

Symbol serving owns the URL root, so every client type — `symsrv.dll` /
WinDbg, Ghidra, Sentry-style SSQP, native `debuginfod` — points at the
bare server URL.

## Crates

- `crates/symfront-ident` — file identification and store hashing: PE
  (TimeDateStamp+SizeOfImage), MSF 7 PDB (GUID+Age from the DBI stream),
  portable PDB (GUID+`FFFFFFFF`). By content, not extension. Tiny, pure,
  usable by third parties.
- `crates/symfront-store` — the symstore format: admin-record parsing
  (`history.txt`, `server.txt`, manifests, `refs.ptr`), tree scanning with
  apparent-vs-on-disk sizes, strays, checks, and symstore-compatible
  transactional operations.
- `crates/symfront-proxy` — the caching-proxy engine: request
  classification, upstream admission, cache backend, fan-out, TTL policy,
  eviction and scrub. No HTTP-server or UI dependencies.
- `crates/symfront` — the binary: axum server (pipeline at `/`, admin at
  `/admin/`), auth, jobs/SSE, CLI, remote client.

## Configuration

Everything lives in one transplantable directory of TOML files (default
`/etc/symfront`, override with `--config-dir` / `SYMFRONT_CONFIG_DIR`);
CLI flags override the tree, and a missing tree means flag-only operation:

```
/etc/symfront/
  server.toml      # listen (tcp/uds), trusted proxies, auth db, webauthn, log filter
  store.toml       # managed store path
  proxy.toml       # cache path/size/mode, TTLs, health, stagger, compression
  upstreams.toml   # [[upstream]] entries
  blacklist.toml   # requests rejected before any classification
```

`symfront config init` emits a commented starter tree. The directory is a
local git repository (bundled libgit2; no system git needed): every web-UI
edit is a commit authored as the logged-in user, and out-of-band manual
edits are auto-committed as drift before any reload or save — a hand edit
can never be silently lost. `symfront config log|diff|rollback` (and the
same in the admin UI) browse and restore history.

Hot reload: `SIGHUP`, `POST /admin/api/admin/config/reload`, or
`symfront config reload --server …`. Upstreams, blacklists, and proxy
settings apply immediately; listen-address changes need a restart.

## The serving pipeline

`GET`/`HEAD` on any path outside `/admin/` and `/metrics`:

1. `/pingme.txt` → 200 (client health checks).
2. **Tier 0 — the managed store**: cheap stat + case-insensitive resolve
   (clients request whatever case the debuggee's headers produced). If we
   own a copy, we serve it — before any blacklist or classification.
   `000Admin/`, `refs.ptr`, and scratch files are never served.
3. **Tier 1 — the proxy**: blacklist → classify → candidate upstreams →
   cache → live fan-out.

`GET /` redirects to `/admin/`; `/symbols/…` remains as a temporary alias
for migrating clients. `serve --proxy-only` runs the bare pipeline with no
admin/auth surface (store read-only as tier 0, or absent for a pure cache
node) — same binary, separate systemd instance.

### Classification and layouts

Inbound requests are parsed into a layout-independent query by two
layouts: **debuginfod** (`/buildid/<hex>/{debuginfo,executable,source/…}`,
strict) and **symstore** (`/<name>/<id>/<name>`, the general fallback,
including SSQP `elf-buildid[-sym]-<hex>` / `mach-uuid[-sym]-<hex>` id
markers). Each configured upstream admits a query through three axes —
`binformat` (pe/elf/macho), `provides` (image/debug), `extensions` — and
renders it in its own layout. Symstore URLs pass through verbatim (stable
cache keys); debuginfod renders canonically from the decoded build-id, so
a Sentry-style SSQP request and a native debuginfod request **converge on
one cache entry**. Behavior is pinned by 435 golden vectors generated from
the Python implementation.

### Cache semantics

- Keys are `sha256(full upstream URL)` — per-upstream, and identical to
  symsrv's keying, which is what makes `symfront proxy import` a lossless
  migration.
- Metadata in SQLite (WAL; the file stays inspectable with plain
  `sqlite3`), payloads in a sharded storage tree. Reads are inline on the
  handler; all writes flow through one dedicated writer thread — batched
  access-time/expiry touches, commit-gated fill upserts.
- The cache root holds three directories, each individually configurable
  (`cache.path_db` / `path_storage` / `path_temp`, where `{path}` stands
  for `cache.path`), so any of them can be its own filesystem — ZFS
  datasets with their own recordsize and compression:

  ```text
  {cache.path}/
    db/metadata.db          # SQLite (WAL)
    storage/aa/bb/<hex64>   # payloads, sharded by key prefix
    temp/<hex64>.<nonce>    # in-progress fills (crash leftovers reaped)
  ```

  Completing a fill renames temp → storage, which is cheap only within one
  filesystem; split across datasets it still works, at one full copy per
  fill and a warning at startup. (ZFS compresses per record, not per file,
  so a raw temp dataset buys no compression the direct write doesn't
  already get.) Pointing `path_temp` or `path_db` *inside* the storage
  tree is supported: the patrol scrub excludes them, so in-flight fills
  are never mistaken for orphans.
- **Positive TTLs slide** on every hit. An expired positive entry is
  **revalidated, not discarded**: conditional GET; 304 refreshes the TTL
  with no re-download; transport failure serves the stale copy
  (stale-while-error).
- **Negative caching follows an escalating ladder** (default
  `1h,1h,1h,8h,8h,24h,7d`; per-upstream override): each re-confirmed miss
  advances a step, so late-appearing symbols (fresh Windows patches on
  msdl) are re-probed quickly without hammering anything.
- **Fills are write-through + tail-follow**: one fill task per key pumps
  upstream → cache temp file as fast as network and disk allow; every
  client — the requester and any singleflight followers arriving mid-fill —
  tails the growing file at its own pace. A slow client backpressures
  nobody; a disconnecting client changes nothing (the fill commits
  anyway). Completion is atomic rename + metadata commit.
- **HEAD upgrades to a GET fill** on a miss: the client gets headers as
  soon as upstream headers arrive, the body fill finishes in the
  background, and probe-heavy clients warm the cache instead of bypassing
  it.
- **Fan-out is staggered by priority tier**: tier N+1 launches
  `stagger` (default 100 ms) after tier N *starts* — or immediately once
  the pipeline drains — and the first 200 wins globally. A slow upstream
  can no longer add its full timeout to worst-case latency.
- **Health breaker**: trips only on transport-level failure (never on any
  complete HTTP response, 5xx included): connect failures trip at once, read
  timeouts and resets after `health.failure_threshold` (default 3) in a row.
  Suspended upstreams still serve cache hits but leave the fan-out; background
  HEAD probes restore them on any complete response. An upstream that re-trips
  within 10 minutes of a restore is held out of probing for 1 min, doubling per
  repeat up to 15 min. 4xx are negative-cached; 5xx pass through and are never
  cached.
- **Eviction** enforces `cache.size` between watermarks, dropping
  soonest-expiring positive entries first (with sliding TTLs this
  approximates LRU while staying trivially explainable). A **patrol
  scrub** cross-checks metadata against the storage tree in both
  directions.
  Both run scheduled and on demand (UI job or CLI).
- Upstream entries can be parked with `enabled = false`: kept in config
  and visible in the UI, never queried.

### Serving details

HEAD, single byte ranges, `ETag`/`Last-Modified` conditionals, and
negotiated compression: zstd first for clients that offer it, gzip
fallback (zlib-rs backend), never for CAB-packed `*_` payloads, range
responses, or bodies under the floor (default 4 KiB). Live fills
compress per-client too — the pump writes raw bytes to disk while each
tailing client wraps its own reader, so encoding never throttles the
fill. Cache hits can alternatively be offloaded to nginx via
`X-Accel-Redirect` (`mode = "nginx"`) or to lighttpd via `X-Sendfile`
(`mode = "lighttpd"`, with `accel_prefix` set to the absolute cache
storage directory), trading per-response stats for sendfile;
`accel_store_prefix` extends the offload to tier-0 store hits.

The opt-in `[quirks] ghidra_cab` flag handles Ghidra's compression-blind
HTTP client (no `Accept-Encoding`, but a known `.pd_` fallback on miss):
payloads we already hold are 404'd at the `.pdb` name and served as an
on-the-fly MSZIP CAB at the compressed name instead.

## Observability

- `/metrics` — Prometheus text format.
- `GET /admin/api/proxy/stats` — JSON: request outcomes, bytes by source,
  estimated time saved, per-upstream fills/errors/throughput EMA, health,
  cache totals.
- Statistics are **client-truth**: counted per incoming request (tier-0
  hit / cache hit / fill / negative hit / passthrough / miss / rejected /
  error); probe traffic never pollutes them.
- The admin **Proxy** tab shows all of the above live, plus upstream
  suspend/resume, cache entry search/evict, a "forget matching 404s"
  purge (for just-published symbols), and one-click eviction/scrub jobs.

## CLI

Store management (local against `--store`, or remote against `--server`):

```console
$ symfront serve [--listen 127.0.0.1:8710 | --uds /run/symfront/http.sock] [--proxy-only]
$ symfront status | tx list|show|del | search | strays | check | upload | init
```

Proxy and config:

```console
$ symfront proxy stats            # cache summary (local) or live counters (--server)
$ symfront proxy health --server …
$ symfront proxy evict|scrub [--report-only]
$ symfront proxy import /srv/cache/ntsymbols/data [--copy] [--dry-run]
$ symfront config init|log|diff|rollback
$ symfront config reload --server …
```

`symfront proxy import` migrates a Python symsrv cache wholesale:
identical keying, rows mapped into the new schema, payloads hardlinked
(or copied across datasets).

## Store semantics worth knowing

- **Sizes**: "apparent" is `st_size` (`du --apparent-size`); "on disk" is
  `st_blocks * 512` — with ZFS compression these differ a lot.
  Per-transaction views also report the *exclusive* size: what deleting
  that transaction would actually free given `refs.ptr` sharing.
- **Delete** mirrors `symstore del` exactly (refcount decrement, `.deleted`
  manifest rename, `server.txt` rewrite, `del` history record). Admin
  rewrites are atomic, mutations hold an flock, and a journal makes an
  interrupted delete detectable and resumable.
- File formats are written back the way `symstore.exe` writes them (CRLF,
  unterminated final lines, zero-padded ids); hashing and layout are
  byte-compatible, verified against real `symstore.exe` output.
- **Coexistence**: `000Admin/` is inotify-watched, so transactions
  added/deleted by other tools (e.g. symstore.exe over SMB) are picked up
  automatically.
- Web mutations run as background jobs that survive browser disconnects;
  progress streams to every connected page over SSE.

## Uploading

```console
$ symfront upload ./build/Release --product "My App" --version 1.2.3
$ symfront --server https://syms.example.com --token sf_… upload …
```

Content-identified (every PE flavor + MSF 7 / portable PDBs), one atomic
transaction, incremental (already-present payloads are skipped before any
bytes move), parallel, and resumable across interruptions and server
restarts. The web Upload page does the same with drag-and-drop; its
client-side identifier is a JS port of `symfront-ident` kept honest by a
node-based drift test against the same fixtures.

## Authentication

Without an auth db the server is open (bind it to localhost). With
`auth_db` set (server.toml or `--auth-db`):

```console
$ symfront user --auth-db … add steven --role admin
$ symfront token --auth-db … create ci-bot --label "ci uploads"
```

- Roles: unauthenticated (symbol serving only) < `ro` (browse, stats) <
  `rw` (store mutations, cache evict/scrub, upstream suspend) < `admin`
  (users, config editing).
- Web sign-in: password (+ TOTP if enrolled) or WebAuthn passkey; HttpOnly
  session cookies. API tokens (`Authorization: Bearer sf_…`) are scoped to
  the store/proxy API and can never reach account/admin endpoints.
- Behind nginx set `trusted_proxies = 1` so audit logs see real client
  IPs and cookies are marked `Secure`. No TLS built in — front with a
  reverse proxy.

## Deployment

`deploy/` holds a translated production config tree, an nginx vhost
example (including the X-Accel internal location), a hardened systemd
unit (`ExecReload` sends SIGHUP), and `docs/deployment.md` — the runbook
for migrating off Python symsrv: import the cache, parallel-run on a beta
vhost, benchmark against the Python instance (regressions block cutover),
then move the main vhost over and retire the raw-autoindex private vhost.

## Testing

`cargo test --workspace`: store-format round-trips against symstore.exe
fixtures; 435 layout golden vectors from the Python proxy; a fake-upstream
integration suite (fills, singleflight collapse, ladder progression,
revalidation/stale-while-error, health trip/probe/restore, stagger racing,
disconnect-commit, HEAD upgrade, eviction order, scrub repair); config
git-history semantics; and the JS ident drift guard (skips without node).
