# Plan: folding the symsrv caching proxy into symfront

Status: **planning complete, pre-implementation review pending** (start of next
session). Produced 2026-08-27 from a full read of the symsrv source at
`/srv/cache/ntsymbols` (github.com/tycho/symsrv, last commit 2026-08-23).

## Decisions already made

- **Name**: the project stays **symfront** — one front door for all symbol
  traffic. Component clarity comes from role-named library crates, not the
  umbrella name.
- **Merge, don't keep separate**: symsrv is rewritten in Rust as a symfront
  component. Rationale: symfront's `/symbols` + `--upstream` forwarding is
  already a proto-symsrv; the store becomes the proxy's tier 0 with no
  internal HTTP hop; hash/key/layout knowledge stays in one place; the web
  UI/SSE/jobs machinery gives the proxy the observability the Python version
  never had.
- **The store and the cache are different things.** The self-managed store
  (`/srv/symstore`) is authoritative and precious; the proxy cache is
  disposable, lives at a **separate path**, and is administered separately
  (TTLs, eviction, scrubbing). They must never share a directory tree.
- **Layering**: the self-managed store is the top layer; the pull-through
  multi-upstream cache is the next layer down. One unified client endpoint.
- **X-Accel-Redirect stays** as an optional mode (offload cache-hit transfer
  to nginx), but the ad-hoc no-nginx setup must remain a one-liner.
- Library crates should be genuinely usable by third parties (publishable
  shape, minimal cross-deps).

## 1. symsrv as it exists today (reference semantics)

~2,900 lines of Python/FastAPI/uvicorn (4 workers, UNIX socket), recently
refactored around a typed layout/upstream seam. 17 GB live cache. These are
the semantics the Rust port must preserve unless explicitly changed:

### Request flow (GET/HEAD only; 405 otherwise)

1. Normalize path; `/pingme.txt` → 200 immediately.
2. **Blacklists** (3 kinds, from `blacklist.toml`): substring anywhere in
   path, suffix match, and first-path-component exact match (used to block
   e.g. a long list of AMD driver PDBs that never exist upstream). Match →
   404, nothing cached.
3. **Classify** the path into a layout-independent `SymbolQuery`
   {family: pe|elf|macho, role: image|debug|source|None, ext, ident,
   source_path, inbound_layout}. Inbound layouts tried in order: debuginfod
   (strict `/buildid/<hex>/{debuginfo,executable,source/<path>}`), then
   symstore (`/<name>/<id>/<name>`). Unclassifiable → 404, no cache write.
   - SSQP middle-field markers decode ELF/Mach-O identities carried in
     symstore-shaped URLs: `elf-buildid[-sym]-<hex>`, `mach-uuid[-sym]-<hex>`
     (`-sym` = debug role). Malformed marked ids are rejected (no PE
     fallback). This is what makes Sentry (and WinDbg SSQP) ELF lookups work.
   - symstore ext handling: compressed extensions map to canonical
     (`.pd_`→`.pdb`, `.dl_`, `.ex_`, `.sy_`, `.db_`) for classification only
     (the upstream URL keeps the compressed form). `.ptr` → role None
     ("any"); recognized roles: .pdb/.snupkg/.dbg = debug,
     .dll/.exe/.sys = image. Unrecognized extension → warn + 404.
4. **Candidates**: every configured upstream whose admission axes accept the
   query renders a canonical URL via *its* layout.
   - Axes: `binformat` (default [pe]), `provides` (image/debug; roles SOURCE
     and None bypass this narrowing), `extensions` (optional, symstore-only
     narrowing; only applies when the query has an ext).
   - symstore layout renders only queries that *arrived* in symstore form
     (verbatim path passthrough, preserving exact URLs and cache keys).
     debuginfod renders canonically from the decoded build-id — so a
     symstore-ELF (Sentry) request and a native debuginfod request converge
     on the **same URL and cache entry**.
   - Mach-O currently classifies but no layout renders it → 404 (lldb layout
     is future work).
   - No candidates → 404, no negative-cache write.
5. **Cache lookup** (batch, one query for all cachable candidates).
   Cache key = **sha256(full upstream URL)** — per-upstream because base_url
   is in the URL. `nocache=1` upstreams (the internal one, today) are always
   queried live.
   - Positive hit (status 200): stream from cache, or `X-Accel-Redirect` in
     nginx mode. ETag/Last-Modified/Content-Length replayed from metadata.
   - Negative hit (4xx within TTL): that upstream is excluded from live
     fan-out; if all candidates end negative → 404.
6. **Live fan-out**: remaining candidates (minus suspended upstreams) are
   queried **concurrently**; first 200 wins, losers cancelled. Per-candidate:
   - **Singleflight** per cache key (abstract-namespace UDS lock — a
     cross-*process* mutex because uvicorn runs 4 workers). Inside the lock,
     re-check the cache (lost race = serve the winner's fill).
   - Header passthrough is minimal by design: only `SymbolChecksum` is
     forwarded (nuget requires it; sent as "invalid" if required but absent).
   - **Health circuit breaker**: a *transport-level* failure (connect/read
     timeout, refused, reset) trips the upstream; any complete HTTP response
     (even 5xx) never trips it. State in an mmap'd file shared across
     workers, fcntl-locked, keyed by a hash of the upstream name list.
     Suspended upstreams still serve *cache hits* but are dropped from live
     fan-out; a background task HEAD-probes them every 30 s (15 s timeout);
     any complete response restores.
   - 200 → **CachePump**: stream upstream → cache write + client
     simultaneously, 8 MiB chunks, never blocking on the client; if the
     client disconnects, caching continues to completion and commits
     (shielded). Commit = temp file rename + metadata row.
   - 4xx → negative-cache write with per-status TTL; response passed through
     with empty body. 5xx → passed through, never cached.
   - HEAD and 304 are passed through header-only and never fill the cache.
7. All upstreams exhausted → 404.

### Cache backend (`AsyncSqliteCache`)

- Metadata: SQLite (WAL, 64 KiB pages, NORMAL sync, busy_timeout 5 s, small
  per-worker connection pool) at `{cache.path}/db/metadata.db`. One table
  `cache_entries` (key hash, upstream name, url, status, size, etag,
  last_modified, created/accessed/expires timestamps) with indexes on
  expiration, (upstream, status), accessed_at.
- Data: sharded subdirectory tree under `{cache.path}/storage/data/`, file
  path derived from the hex key.
- TTLs from config by status code: 200 = 365 d, 403 = 14 d, 404 = 7 d
  (defaults 8 h success / 1 h failure if unconfigured).
- Access times batched (30 s flush) to avoid per-hit writes.
- Cleanup passes exist for both orphan directions (metadata without file,
  file without metadata) — the seed of "patrol scrubbing".
- **Gap:** `cache.size = "512GB"` is parsed but there is **no size-based
  eviction implemented**. TTL expiry only. (Confirmed by reading; the disk
  currently holds 17 GB so it has never mattered.)
- nginx mode: cache hits return `X-Accel-Redirect: /_symsrv_cache/<rel>`,
  with nginx `internal alias` doing sendfile; ranges therefore work on cache
  hits for free. Standalone mode streams from disk in-process (no range
  support in the Python proxy path — note: symfront's local-store serving
  already does ranges properly).

### Operational bits

- Config: `main.toml` (uvicorn args, cache backend/mode/path/size, sqlite
  tuning, log filters, TTL table, health probe settings), `upstreams.toml`
  (12 upstreams today incl. msdl, nuget w/ checksum, vendor image servers,
  mozilla/chrome/unity/renderdoc, several debuginfod servers, and the
  `internal` nocache upstream pointing at the private store — the hop this
  merge eliminates), `blacklist.toml`.
- Logging: queued logging, access-log filter to drop configured
  (status,path) pairs (e.g. 404 /index2.txt noise).
- systemd units + nginx sample config in-repo.
- No admin UI, no metrics endpoint, no eviction, no cache introspection.

## 2. Target architecture in symfront

### Crate restructure (role-named, third-party-usable)

```
crates/
  symfront-ident/    # split OUT of symfront-core: PE/PDB/portable-PDB
                     # identification + store hashing. Pure, tiny deps.
  symfront-store/    # rename of symfront-core minus ident: symstore format,
                     # transactions (add/del), scan, strays, check, locking.
  symfront-proxy/    # NEW: SymbolQuery + layouts (symstore/SSQP, debuginfod),
                     # upstream model + admission, cache backend (rusqlite
                     # metadata + sharded data dir), negative cache, TTLs,
                     # singleflight, health breaker, eviction, scrub.
                     # Async (tokio + reqwest), but no axum/UI dependency —
                     # usable as a library for embedding a caching proxy.
  symfront/          # the binary: axum server (store admin API/UI, /symbols
                     # pipeline, auth, jobs, SSE), CLI, remote client.
```

Dependency direction: `symfront` → {store, proxy, ident}; `symfront-store` →
`symfront-ident`; `symfront-proxy` → `symfront-ident` (for nothing yet —
keep it independent if possible). No crate depends on the binary.

### The unified serving pipeline

`GET /symbols/<path>` becomes a tiered pipeline:

1. **Tier 0 — local store** (exists today): resolve case-insensitively in
   the managed store; serve with ranges/ETag/gzip. Deny 000Admin/refs.ptr.
2. **Tier 1 — proxy** (new, replaces the naive `--upstream` forwarder):
   blacklist → classify → candidates → cache lookup → live fan-out →
   cache-fill streaming, exactly per the semantics above.

Enabled/configured via a `[proxy]` section in a config file (see below);
without it, `--serve-symbols --upstream URL` keeps working as sugar for a
one-upstream, no-cache proxy tier (ad-hoc case stays a one-liner).

Notes:
- Tier 0 is consulted for *symstore-family* requests only; debuginfod-layout
  requests skip straight to tier 1 (the store never holds ELF).
- The store is NOT an "upstream" — no HTTP hop, no cache entry for tier-0
  hits, adds are visible immediately.
- pingme.txt, blacklist, and classification run *before* tier 0? No:
  tier 0 first (cheap stat), then blacklist+classify for the miss path.
  (Blacklisted names can't exist in the store anyway; if one does, serving
  our own copy is correct.)
- Range requests on proxy cache hits: standalone mode should support ranges
  from the cache file (improvement over Python); X-Accel mode gets them from
  nginx as today. Ranges are NOT forwarded upstream on fill (fills are whole
  files; symsrv already behaves this way implicitly).

### Process topology

Single binary, both shapes supported:

- **Combined (default / ad-hoc)**: `symfront serve` with proxy config —
  admin UI + store + proxy in one process.
- **Split (isolation)**: two systemd instances of the same binary:
  - `symfront serve …` — store admin (private vhost)
  - `symfront serve --proxy-only …` — serving+proxy only: /symbols + proxy
    endpoints, no admin UI/API, store opened **read-only** as tier 0 (or no
    store at all for a pure cache node).
  Both may point at the same store path; only the admin instance mutates it.

### Cache storage

- Separate root, e.g. `/srv/cache/symfront` (config `proxy.cache.path`;
  never defaulted to inside the store).
- Metadata: rusqlite (already a dependency), WAL, same logical schema as
  Python (plus columns for hit counters if cheap). Single process → simple
  connection handling, no cross-worker games.
- Data: sharded tree as today. **Keep sha256(full-URL) keying** so the
  existing cache/negative-cache can optionally be imported (see migration).
- In-process replacements for the multi-worker machinery (a real
  simplification the Rust rewrite gets for free):
  - UDS singleflight → `HashMap<Key, watch::Receiver>` in a mutex.
  - mmap health file → plain shared struct + background probe task.
  (If a multi-node story ever appears, these seams stay behind traits.)

### Configuration

CLI flags stop scaling here; introduce an optional TOML config file
(`symfront serve --config /etc/symfront/symfront.toml`), flags overriding.
Mapping from the existing symsrv files:

| symsrv | symfront.toml |
|---|---|
| `main.toml [uvicorn]` | `[server]` listen/uds (uds support: new) |
| `main.toml [cache]` type/mode/path/size | `[proxy.cache]` (mode: standalone\|nginx; size gains real meaning via eviction) |
| `main.toml [sqlite]` | `[proxy.cache.sqlite]` (mostly obsolete single-process) |
| `main.toml [cache_ttl]` | `[proxy.ttl]` status→seconds |
| `main.toml [health]` | `[proxy.health]` probe_interval/timeout |
| `main.toml [log_filters]` | `[server.log]` ignore_access |
| `upstreams.toml [[upstream]]` | `[[proxy.upstream]]` — same fields: name, base_url, layout, binformat, provides, extensions, priority, nocache, requires_symbolchecksum |
| `blacklist.toml` | `[proxy.blacklist]` substring/suffix/first_component |

Provide a `symfront proxy import-config /srv/cache/ntsymbols/config` helper
(or just do the translation by hand once — the files are small; decide at
review).

`priority` note: config has it but the Python fan-out is flat within one
group (all-at-once, first 200 wins). Decide at review: implement priority
tiers (fan out per tier) or drop the field. Recommendation: implement tiers
— msdl should not race the internal-store-adjacent upstreams — with the
current flat behavior as the single-tier degenerate case.

## 3. Feature mapping (symsrv → Rust)

| Feature | Disposition |
|---|---|
| Layout seam (SymbolQuery, classify/render) | Port as-is; it's well designed. Golden-test against the Python impl (see §5). |
| SSQP ELF/Mach-O decode | Port as-is (Sentry + WinDbg compat). |
| debuginfod layout | Port as-is incl. source role. |
| Mach-O render (lldb layout) | Port the classify side; render stays unimplemented (as today). Parked feature. |
| Admission axes | Port as-is. |
| sha256-of-URL cache keys | Keep (enables cache import). |
| SQLite metadata + sharded data | Port to rusqlite; same logical schema. |
| Negative caching (4xx, per-status TTL) | Port as-is. |
| Batched atime updates | Port (background flusher task). |
| Singleflight | Reimplement in-process (tokio). |
| Health breaker + probes | Port semantics exactly (transport-failure-only trip; any complete response restores; suspended ⇒ cache-hits-only). In-process state. |
| CachePump (client-detach-safe fill) | Reimplement with tokio tasks/channels; commit-on-disconnect preserved. |
| X-Accel-Redirect mode | Keep, optional. Header name/internal path configurable. |
| Blacklists (3 kinds) | Port as-is. |
| pingme.txt 200 | Already handled by tier 0 (store has a real pingme.txt); proxy-only mode answers it synthetically. |
| SymbolChecksum passthrough | Port as-is. |
| uvicorn/uds/workers | Replaced by tokio; add `--listen-uds` support for the nginx deployment. |
| Access-log ignore filters | Port into tracing layer. |
| `internal` nocache upstream | **Deleted** — becomes tier 0. |
| cache.size config | **Implement for real**: LRU eviction (below). |

## 4. New capabilities (beyond parity)

Cache administration (the Python version is a black box):

- **Stats**: entry counts and bytes by status/upstream, hit/miss/fill/negative
  counters, eviction counts — in `/api/proxy/stats`, the summary, and SSE.
- **Upstream health page**: per-upstream state (available/suspended, last
  trip reason/time, probe results), manual suspend/resume, live config view.
- **Cache entry admin**: search by URL/path substring, inspect metadata,
  evict single entries / by upstream / by path prefix; purge negative
  entries selectively (e.g. "forget all 404s for foo.pdb" after publishing
  the symbol upstream).
- **TTL & eviction config surfaced in UI** (read-only view of config +
  effective values; editing stays in the config file, at least initially).
- **Size-based eviction**: background job, LRU by accessed_at until under
  `cache.size` watermark (high/low water marks, e.g. evict at 100% down to
  95%). Runs on the existing jobs/SSE machinery.
- **Patrol scrub**: the two orphan-cleanup passes become a schedulable +
  manually-triggerable job with progress and a report (DB-only entries
  dropped, file-only entries deleted, mismatched sizes flagged).
- **Auth interplay**: proxy client endpoints (`/symbols`, `/buildid`) stay
  unauthenticated (same tier as today's /symbols). Proxy *admin* endpoints:
  ro can view stats/health; rw can evict/purge/trigger scrub; config changes
  admin-only (if ever exposed).
- CLI: `symfront proxy stats|evict|scrub|health` (local or --server).

## 5. Testing plan

- **Golden vectors from the Python implementation** (do this while the
  Python venv still exists!): run symsrv's `classify_request` and each
  layout's `render` over a corpus (real access-log paths + crafted SSQP/
  debuginfod/compressed-ext/malformed cases), dump JSON goldens into
  `crates/symfront-proxy/tests/data/`, and test the Rust port against them.
  Same for blacklist decisions.
- **Fake-upstream integration tests**: an in-test axum server scripted per
  test: cache fill + second-request hit; negative cache honored + expiry;
  health trip on connect-refused + probe restore; singleflight (N concurrent
  requests → 1 upstream fetch); 5xx-not-cached; HEAD/304 no-fill;
  SymbolChecksum forwarding; client-disconnect-still-commits.
- **Pipeline tests**: tier-0 hit short-circuits proxy; store miss cascades;
  debuginfod path skips tier 0; SSQP-ELF and native debuginfod converge on
  one cache entry.
- **Eviction/scrub tests**: fill past watermark → LRU evicts; orphan both
  directions → scrub repairs and reports.
- Existing store/differential suites unchanged.

## 6. Migration & rollout

1. Land the crate restructure (pure refactor, no behavior change) first.
2. Build symfront-proxy with tests; wire pipeline behind `[proxy]` config.
3. Translate the three TOML files (minus the `internal` upstream).
4. Run the Rust proxy on a second UDS/port beside Python symsrv; diff
   behavior on live traffic (same requests via nginx mirror or manual).
5. Optional cache import: walk Python metadata.db → insert rows (keying
   is compatible) → verify sampled entries; negative cache import is the
   valuable part (re-warming 200s is just bandwidth; re-warming a 404
   negative cache is upstream-hammering). Decide at review; importer is
   ~100 lines either way.
6. Cut nginx over; keep Python dir frozen as rollback for a while.
7. Public-repo question (separate from code): symsrv has a public identity;
   long-term either open-source symfront or note the successor in symsrv's
   README. User's call, no code impact.

## 7. Open questions for the pre-implementation review

1. Mount points: proxy answers under `/symbols/...` only, or also bare
   `/<name>/<id>/<name>` + `/buildid/...` at the root for drop-in symsrv URL
   compat? (Recommendation: root-level too in `--proxy-only` mode; admin UI
   claims `/` only in combined mode, where nginx can rewrite.)
2. Implement `priority` as fan-out tiers (recommended) or drop the field?
3. Cache import: full, negative-only, or cold start?
4. Config file: adopt for serve-side flags too (listen/auth/etc.) or proxy
   section only?
5. Hot-reload of upstreams/blacklists (SIGHUP or admin endpoint) — v1 or
   later?
6. Metrics: JSON-only or also Prometheus text format at `/metrics`?
7. UDS listening support in axum (for the nginx socket deployment) — v1?
8. Eviction watermarks and scrub schedule defaults.
9. Crate rename mechanics: `symfront-core` → `symfront-store` + extract
   `symfront-ident`; do we keep a deprecated `symfront-core` re-export shim
   or just break (nothing external depends on it yet — recommend clean
   break).
10. Keep the JS ident port in sync with `symfront-ident` — fold the node
    validation script into CI/tests?
