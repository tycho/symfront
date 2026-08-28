# Plan: folding the symsrv caching proxy into symfront

Status: **planning complete (rev 3, final)** —
pre-implementation architecture review opens the next session. Produced
2026-08-27 from a full read of the symsrv source at `/srv/cache/ntsymbols`
(github.com/tycho/symsrv, last commit 2026-08-23) and the live nginx
deployment (`/etc/nginx/extra/vhosts/ntsymbols.conf`).

## Decisions (settled)

- **Name**: stays **symfront**. Component clarity via role-named crates.
- **Merge**: symsrv is rewritten in Rust as a symfront component; the managed
  store becomes tier 0 of the serving pipeline (the Python proxy's `internal`
  HTTP upstream disappears).
- **Store ≠ cache**: proxy cache lives at a separate path with its own
  metadata; disposable by definition. Full import of the existing 15.8 GB
  cache (new directory layout on our side; keying stays compatible).
- **Mount points**: symbol serving moves to the **root** (`/…` for symstore
  paths, `/buildid/…` for debuginfod) so every client type (symsrv.dll,
  Sentry, Ghidra, debuginfod) points at the bare URL. The admin UI moves to a
  subtree (`/admin/`), and `GET /` (index) **redirects to the admin UI** — no
  real symbol server has an index, so the root page is ours to take.
  (Today's `symbols-private` vhost is raw nginx `autoindex on` over the
  store; symfront serving replaces it — and stops leaking directory listings
  / transaction history in the process.)
- **No `--upstream` sugar**: the current `--serve-symbols --upstream` flags
  are retired when the proxy lands. Ad-hoc ease comes from a commented
  example config (msdl as the sample upstream), not compat flags.
- **All configuration moves to a tree of TOML files**, hand-editable offline
  and editable through the web UI (admin role); versioned in a local git
  repository for history/rollback (§ Configuration). No more
  everything-as-flags; the tree is transplantable between hosts.
- **Hot reload**: SIGHUP re-reads the config tree (plus a portable
  `symfront config reload` admin endpoint/CLI for Windows). Web-UI edits are
  the recommended path; the reload path auto-commits on-disk drift before
  applying, so a manual edit can never be silently lost by a later UI edit.
- **Windows stays supported** (unlike the Python symsrv): UDS listening on
  Unix (lower overhead behind nginx), TCP everywhere; no SIGHUP-only
  functionality; no Unix-only path assumptions in the new crates.
- **Metrics**: both JSON (`/api/proxy/stats`) and Prometheus text format
  (`/metrics`).
- **Compat**: pre-1.0, breaking changes are fine and expected (no
  `symfront-core` shim; clean crate renames).
- **Priority tiers**: implemented as *staggered* fan-out, not
  wait-for-tier-failure (§ Fan-out), so a slow tier never adds its full
  timeout to the worst-case RTT.
- **Eviction**: positive entries only (negative entries are just DB rows),
  ordered by **soonest expiry first** — which, with sliding positive TTLs,
  approximates LRU while staying trivially explainable.
- **TTLs**: global defaults + per-upstream overrides; positive TTLs slide on
  every hit; negative TTLs follow an escalating ladder (§ TTL semantics).
- **Compression**: fast-zlib backend (zlib-rs) for gzip, zstd for clients
  that negotiate it, never recompress CAB-packed (`*_`) payloads
  (§ Compression policy).
- **Concurrency**: async confined to the socket edge; all decision logic and
  fast-disk work stays synchronous (§ Concurrency model — the guardrails are
  part of the plan, reviewable like any other interface).
- **Performance mandate**: the Rust proxy must be **strictly faster than the
  Python implementation in every measured aspect** — cache-hit TTFB and
  throughput, fill throughput, negative-hit latency, concurrent request
  handling. The parallel-run phase (§8) includes a benchmark comparison
  against the live Python instance, and regressions block cutover.

## 1. symsrv as it exists today (reference semantics)

~2,900 lines of Python/FastAPI/uvicorn (4 workers, UNIX socket behind
nginx). These are the semantics the Rust port preserves unless a change is
explicitly called out in §3:

### Request flow (GET/HEAD only; 405 otherwise)

1. Normalize path; `/pingme.txt` → 200 immediately.
2. **Blacklists** (3 kinds from `blacklist.toml`): substring, suffix,
   first-path-component. Match → 404, nothing cached, no upstream traffic.
   The point of the blacklist is to eliminate whole classes of requests that
   have never and will never exist upstream (e.g. AMD driver PDBs).
3. **Classify** into a layout-independent `SymbolQuery`
   {family: pe|elf|macho, role: image|debug|source|None, ext, ident,
   source_path, inbound_layout}. Inbound layouts in order: debuginfod
   (strict `/buildid/<hex>/{debuginfo,executable,source/<path>}`), then
   symstore (`/<name>/<id>/<name>`). Unclassifiable → 404, no cache write.
   - SSQP markers decode ELF/Mach-O identity from symstore-shaped URLs:
     `elf-buildid[-sym]-<hex>`, `mach-uuid[-sym]-<hex>` (`-sym` = debug).
     Malformed marked ids are rejected (no PE fallback). This is the
     Sentry-compat path (WinDbg SSQP uses the same shapes).
   - symstore ext handling: compressed extensions map to canonical for
     classification only (`.pd_`→`.pdb`, `.dl_`, `.ex_`, `.sy_`, `.db_`);
     upstream URLs keep the compressed form. `.ptr` → role None ("any").
     Roles: .pdb/.snupkg/.dbg = debug; .dll/.exe/.sys = image. Unrecognized
     ext → 404.
4. **Candidates**: each configured upstream whose admission axes accept the
   query renders its canonical URL. Axes: `binformat` (default [pe]),
   `provides` (image/debug; SOURCE and None bypass), `extensions`
   (symstore-only narrowing). symstore layout renders only queries that
   arrived symstore-shaped (verbatim passthrough → stable URLs and cache
   keys); debuginfod renders canonically from the decoded build-id, so
   Sentry-style and native debuginfod requests **converge on one cache
   entry**. Mach-O classifies but nothing renders it yet (lldb layout is
   future work). No candidates → 404 without negative-cache write.
5. **Cache**: key = **sha256(full upstream URL)** (per-upstream since
   base_url is embedded). Batch metadata lookup for all cachable candidates.
   Positive hit → stream from cache or X-Accel; negative hit (4xx in TTL) →
   that upstream is excluded from fan-out. `nocache` upstreams always live.
6. **Live fan-out**: remaining candidates concurrently; first 200 wins,
   losers cancelled. Per candidate: singleflight per cache key (re-check
   cache inside the lock); minimal header passthrough (`SymbolChecksum`
   only; sent as "invalid" when an upstream requires it and the client
   didn't provide one); **health breaker** trips only on transport-level
   failure (never on any complete HTTP response, even 5xx), suspended
   upstreams still serve cache hits but are dropped from fan-out, background
   HEAD probes (30 s interval / 15 s timeout) restore on any complete
   response; 200 → **CachePump** (stream to cache + client simultaneously,
   8 MiB chunks, never blocks on the client, client disconnect ⇒ caching
   continues to completion and commits); 4xx → negative-cache write with
   per-status TTL; 5xx passed through, never cached; HEAD/304 pass through
   header-only without cache fill (semantics *tightened* in §3).
7. Exhausted → 404.

### Cache backend

SQLite metadata (WAL, 64 KiB pages, NORMAL sync, busy_timeout, per-worker
async connection pools — the part the owner found gross and single-threaded
in practice) + sharded data tree under `{cache.path}/storage/data/`. One
`cache_entries` table (key hash, upstream, url, status, size, etag,
last_modified, created/accessed/expires) with indexes on expiration,
(upstream,status), accessed_at. TTL by status (200: 365 d, 403: 14 d,
404: 7 d). Access times batched (30 s). Orphan-cleanup passes in both
directions exist (seed of patrol scrub). **`cache.size` is parsed but
eviction is not implemented.** nginx mode returns
`X-Accel-Redirect: /_symsrv_cache/<rel>` (internal alias, `sendfile off`
so nginx gzip applies, ETag/Last-Modified replayed from metadata headers).

### Live deployment (nginx)

- `symbols.*` → symsrv over UDS; `gzip_types *` + `gzip_min_length 4096`
  (currently recompresses even CAB-packed payloads); X-Accel alias.
- `symbols-private.*` → raw nginx `root /srv/symstore; autoindex on` — the
  store symfront manages; to be replaced by symfront serving.
- `symbols-beta.*` → second symsrv instance (ntsymbols2), currently unused —
  **the parallel-run/cutover slot for the Rust proxy.**

## 2. Target architecture

### Crates

```
crates/
  symfront-ident/   # PE/PDB/portable-PDB identification + store hashing
                    # (split out of symfront-core). Later: ELF build-id,
                    # Mach-O UUID (§6). Pure, tiny deps, third-party-usable.
  symfront-store/   # symstore format, transactions, scan, strays, check
                    # (symfront-core minus ident). Sync.
  symfront-proxy/   # SymbolQuery + layouts, upstream model + admission,
                    # cache backend, TTL/negative ladder, singleflight,
                    # health, eviction, scrub, stats. Sync core + thin async
                    # fetch/stream module. No axum/UI dependency.
  symfront/         # binary: axum server (admin UI/API at /admin, symbol
                    # pipeline at /), auth, jobs, SSE, CLI, remote client.
```

### Serving pipeline (mounted at `/`)

1. `GET /` → redirect to `/admin/` (combined mode) or 404 (`--proxy-only`).
   `/admin/…` → UI + APIs (absent in `--proxy-only`). `/pingme.txt` → 200.
2. **Tier 0 — managed store** (symstore-family paths, and §6 later for
   debuginfod paths): cheap stat + case-insensitive resolve; serve with
   ranges/ETag/compression. Deny 000Admin/refs.ptr. Tier 0 runs *before*
   blacklist/classification — if we own a copy, we serve it.
3. **Tier 1 — proxy**: blacklist → classify → candidates → cache → fan-out →
   cache-fill streaming, per §1 semantics as amended in §3.

`/symbols/…` may remain as a temporary alias during migration (decide at
review; costs one route).

Process topology: combined (default) or `--proxy-only` (no admin UI/API,
store opened read-only as tier 0, or absent for a pure cache node). Same
binary, two systemd instances for isolation.

### Concurrency model (owner concern: async overreach)

Position: **async only where a socket can actually park; sync everywhere
else.** Concretely:

- The axum/tokio edge stays — it already runs this codebase's admin server,
  SSE (many idle connections is the one canonical async fit), and it is the
  path of least regression. This is not up for re-litigation lightly: a
  thread-per-connection rewrite of the working server would be large,
  risk-heavy, and win little at LAN concurrency levels.
- Guardrails for the proxy path (enforced in review, written here so they
  are reviewable):
  - No async in `symfront-proxy`'s decision logic. Classification,
    admission, blacklist, TTL policy, key derivation: plain sync functions.
  - SQLite **reads happen inline** on the handler task (indexed, sub-ms;
    the same policy as today's inline `stat()` in the symbols handler — no
    spawn_blocking round-trips for fast operations).
  - SQLite **writes go through one dedicated writer thread** fed by a
    bounded channel (fire-and-forget for atime/stats; awaited via oneshot
    only where durability gates the response, i.e. negative-cache writes
    don't gate, fill commits do). This matches SQLite's single-writer
    reality instead of fighting it — and is the direct fix for the Python
    version's async-pool-funneling-into-one-thread grossness.
  - Async appears in exactly two places: upstream fetch + body streaming
    (reqwest/hyper), and response streaming to clients. Both are genuinely
    parked-socket workloads.
  - No `async_trait` in public APIs of symfront-proxy's core; the async
    surface is a small `fetch` module.
  - File reads for cache hits: streamed with large buffers (8 MiB) —
    sequential disk reads on ZFS are effectively never parked, so if
    profiling shows tokio-fs overhead, switch to plain std reads on the
    handler with chunked writes; keep this swappable.
- If the review still prefers zero tokio: the fallback design is
  thread-per-request on a bounded pool with `ureq` + `tiny_http`. It is
  workable at this scale but forfeits SSE elegance and reuses none of the
  existing server. Recommendation stands: tokio at the edge, sync core.

### 2a. Fill streaming: write-through + tail-follow

The Python CachePump streams upstream → cache and client simultaneously so
the client never blocks on cache warming — behavior we must preserve. But it
couples the upstream read loop to the *cache write* (each chunk awaits the
disk write before the next read) and decouples the client via an
**unbounded** queue (memory growth under a slow client). Neither sink should
throttle the other, and neither should throttle the upstream read.

Target design — **the cache file is the buffer**:

- One fill task per key (the singleflight winner): upstream socket → cache
  temp file, as fast as network + disk allow, through a bounded channel to
  the disk writer. Nothing else is in this loop.
- Clients — the requester, *and* any singleflight followers that arrive
  during the fill — **tail-read the growing temp file**, woken by an
  append/completion watch. Each client streams at its own pace; a slow
  client backpressures nobody (its buffer is the file itself, and
  recently-written data is RAM-speed via the page cache/ARC); a fast client
  waits only for bytes that haven't arrived yet.
- Fill completion → atomic rename + metadata commit; failure → temp file
  removed, tailing clients get a truncated-stream error.
- Client disconnect: nothing to do — the fill task never knew about
  clients. HEAD-upgrade fills are just fills with zero tailing clients.
- Bonus over Python: singleflight followers currently block until the
  winner's fill *commits*; here they stream immediately alongside it.
- `nocache` upstreams (no file to write): direct passthrough streaming with
  a bounded in-memory buffer (the only case where client pace matters, and
  it is that client's own transfer).

### Metadata storage (owner asked for options)

Stay on **SQLite via rusqlite** — with the writer-thread + inline-reads
architecture above rather than any async pool:

- WAL mode gives N concurrent readers + 1 writer without locking drama;
  reads are lock-free against the WAL; the single writer thread serializes
  writes at the app layer where it's visible and debuggable.
- rusqlite is sync (a *feature* here), already a dependency (auth db), and
  the file stays inspectable with plain `sqlite3` — explicitly valued.
- Alternatives considered and rejected: redb / LMDB-heed (better raw
  concurrency, but opaque to standard tooling), rocksdb (operationally
  heavy), flat files + index rebuild (loses queryability for admin
  features). None justify losing `sqlite3`-openability.
- Schema: as today plus `hit_count`, `negative_step` (ladder index, §3),
  `content_encoding` (future precompressed storage, if ever), and
  `filled_by` (upstream name — already present as upstream_name).

### Configuration (tree + git history)

- Layout (one directory, transplantable):
  ```
  /etc/symfront/            # or any --config-dir
    server.toml             # listen (tcp/uds), trusted proxies, auth db path,
                            # webauthn origin, log filters
    store.toml              # store path, scan options
    proxy.toml              # cache path/size/mode, TTL defaults & ladder,
                            # health, stagger, compression
    upstreams.toml          # [[upstream]] entries (same axes as today)
    blacklist.toml          # three lists, as today
  ```
- CLI flags become overrides for one-off/ad-hoc runs; `symfront init`
  can emit a commented starter tree (msdl example upstream commented out).
- **Git-backed history** (owner asked for evaluation — verdict: cheap and
  worth it): the config dir is a local git repo managed via the `git2`
  crate (bundled libgit2; no system git needed, Windows-safe; ~a day of
  work). Every web-UI edit = commit authored as the logged-in user with a
  descriptive message. `symfront config log/diff/rollback` + the same in
  the admin UI. On SIGHUP/reload (and at startup), if the working tree
  differs from HEAD, commit the drift first as "manual edit (out-of-band)"
  — this makes the lost-update scenario (edit file, forget reload, edit in
  UI) structurally impossible. Nicer-path alternatives considered:
  timestamped snapshot copies (no diffs, no author attribution) and
  etckeeper (host-global, not transplantable). git2 wins.

## 3. Semantics changed from the Python implementation

These are deliberate improvements; everything not listed ports as-is.

1. **Positive TTLs slide.** Any positive cache hit extends the entry's
   expiry (`expires = now + ttl`). Batched with the existing atime flusher.
2. **Expiry triggers revalidation, not discard.** On a hit whose entry has
   expired: send conditional GET upstream (If-None-Match/If-Modified-Since
   from stored metadata). 304 → refresh TTL, serve from cache (no
   re-download). 200 → refill. Transport failure → serve the stale entry
   (stale-while-error) and leave expiry unchanged.
3. **Negative-TTL ladder.** Negative entries carry a step counter and a
   configurable ladder, e.g. `negative_ttl = ["1h","1h","1h","8h","8h",
   "24h","7d"]` (last entry repeats). Expired negative → re-probe on next
   request → still missing → advance one step. Global default +
   per-upstream override. Guidance: the ladder chiefly benefits msdl
   (symbols for fresh Windows patches appear late); most upstreams are fine
   with a long flat negative TTL — which is just a single-entry ladder, so
   one mechanism covers both.
4. **HEAD coherence.** If the cache has an entry, HEAD is answered from it
   (as today). On a miss, HEAD is upgraded to a **GET fill** for cachable
   upstreams: the client gets headers as soon as upstream headers arrive,
   while the body fill completes in the background (CachePump already
   supports body-less clients — a HEAD client is just a client that
   detached immediately). Result: a HEAD answer is always consistent with
   the GET that follows it, and probe-heavy clients warm the cache instead
   of bypassing it.
5. **Tier stagger instead of tier barriers.** Candidates sort into priority
   tiers; tier N+1 launches `stagger_ms` (default 100 ms, configurable)
   after tier N *starts*, unless a decisive answer already arrived. First
   200 wins globally; already-launched losers cancelled. `stagger_ms = 0`
   reproduces today's flat behavior. Slow upstreams can no longer add their
   full timeout to worst-case RTT.
6. **Statistics are client-truth, not upstream-truth.** Counted per
   incoming client request: tier-0 hit / cache hit / upstream fill /
   negative-hit 404 / passthrough / error. Upstream probe traffic and
   health checks are never counted as misses. Derived metrics: bytes served
   from cache vs. fetched from upstreams ("bandwidth saved"), estimated
   time saved (bytes × observed per-upstream throughput EMA), fill/error
   rates per upstream. Exposed via `/api/proxy/stats`, the admin UI, SSE,
   and Prometheus.
7. **Compression policy** (serving to clients, both tier 0 and cache hits):
   - Backend: `flate2` pinned to the **zlib-rs** backend (order-of-magnitude
     faster than stock zlib, on par with zlib-ng, pure Rust — no C build).
   - **zstd offered first** when the client's Accept-Encoding includes it
     (level 2–3: saturates 10 GbE with headroom; symsrv.dll won't negotiate
     it, but other tooling can). gzip fallback at a fast level (zlib-rs
     level ~4–6 band; benchmark once during implementation and pin).
   - Never compress `*_` CAB-packed payloads or anything below a size
     floor (~4 KiB, matching today's nginx `gzip_min_length`).
   - In X-Accel mode, nginx does the compressing; we record *that* a
     response was compressible/offloaded but can't observe ratios —
     **standalone mode yields richer stats** (actual wire bytes, per-response
     ratio); noted as a stats-vs-offload tradeoff knob, per owner.
   - Follow-up for the nginx side (deployment doc, not code): replace
     `gzip_types *` with a types/paths split that skips CAB payloads, and
     optionally enable nginx zstd for the X-Accel path.

## 4. Feature mapping (symsrv → Rust)

| Feature | Disposition |
|---|---|
| Layout seam + SSQP + debuginfod | Port as-is; verified against `crates/symfront-proxy/tests/data/layout-goldens.json` (435 vectors incl. 400 real request paths, generated from the Python impl). |
| Admission axes | Port as-is. |
| sha256-of-URL keys | Keep (enables full cache import). |
| SQLite metadata + sharded data | Port per §2 storage design (writer thread + inline reads). |
| Negative caching | Port + ladder (§3.3). |
| Singleflight | In-process (HashMap + watch); UDS cross-worker machinery deleted. |
| Health breaker | Port semantics exactly; in-process state; probes as today. |
| CachePump | **Redesigned** as write-through + tail-follow (§2a): preserves client-never-waits-for-cache-warming, fixes the Python weak point where sinks throttled the pump. |
| X-Accel mode | Keep, optional; header/internal-path configurable. |
| Blacklists | Port as-is; tier 0 is consulted first regardless. |
| SymbolChecksum passthrough | Port as-is. |
| uvicorn/UDS/workers | tokio; UDS listener on Unix + TCP everywhere (Windows support is a requirement). |
| Access-log ignore filters | Port into tracing layer. |
| `internal` nocache upstream | Deleted — becomes tier 0. |
| `--serve-symbols --upstream` | **Retired** (example config instead). |
| cache.size | Implemented: eviction of positive entries, soonest-expiry-first, high/low watermarks, background job. |
| Orphan cleanup passes | Become **patrol scrub**: scheduled + manually triggerable job with progress + report (rows without files, files without rows, size mismatches). |

## 5. Admin & observability features (new)

- Proxy dashboard: request-based hit/miss breakdown, bytes/time saved,
  per-upstream health (state, last trip cause/time, probe history), fills
  and error rates, cache size vs. watermark, negative-entry counts.
- Upstream admin: manual suspend/resume; config view; edit via config-UI
  (below).
- Cache entry admin: search by URL/path substring; inspect metadata; evict
  by entry / upstream / path prefix; purge negative entries selectively
  ("forget 404s for foo.pdb" after publishing it).
- Config editing UI (admin role): edits the TOML tree through the
  git-backed store; history + diff + rollback views. ro sees stats; rw may
  evict/scrub; config edits admin-only.
- Jobs: eviction and scrub run on the existing jobs/SSE machinery.
- CLI: `symfront proxy stats|evict|scrub|health`, `symfront config
  log|diff|rollback|reload` — local or `--server`.
- `/metrics` Prometheus text format + JSON stats endpoint.

## 6. Roadmap: ELF/Mach-O in the managed store (tier 0)

Owner-requested value-add over symstore.exe, phased **after** proxy parity:

- `symfront-ident` learns ELF (GNU build-id from `PT_NOTE`/section notes)
  and Mach-O (`LC_UUID`), by content as usual.
- Store layout: SSQP conventions inside the existing symstore tree —
  `<name>/elf-buildid-<hex>/<name>`, `<name>/elf-buildid-sym-<hex>/<name>`,
  and `mach-uuid[-sym]-…` equivalents. symstore.exe-compatible in shape
  (SSQP is Microsoft's own convention); upload/delete/scan/strays all work
  unchanged since they're layout-agnostic above the hash-dir level.
- Tier 0 answers: symstore-shaped SSQP requests directly, **and**
  debuginfod-shaped requests (`/buildid/<id>/{debuginfo,executable}`) by
  translating to the SSQP dirs — the same cross-layout convergence the
  proxy does, applied to our own store. Sentry and native debuginfod
  clients then see self-hosted ELF symbols.
- Mach-O render/lldb layout for the proxy lights up alongside.
- Open for that phase: name normalization for ELF (no canonical filename in
  a build-id world — likely use the uploaded basename), `_.debug`-style
  Sentry naming quirks, and whether `symfront upload` auto-splits
  debuginfo (objcopy-style) or stores what it's given (recommend: store
  what it's given, v1).

## 7. Testing

- Golden vectors (already generated ✔) for classify/render; same-format
  goldens for blacklist decisions and negative-ladder progression.
- Fake-upstream integration suite: fill + hit; negative ladder advance;
  revalidation 304-refresh and stale-while-error; health trip/probe/restore;
  singleflight collapse; 5xx-never-cached; HEAD-upgrade fill coherence;
  SymbolChecksum; client-disconnect-commit; stagger ordering (tier 1 wins
  race started later, etc.).
- Pipeline: tier-0 short-circuit; store-miss cascade; SSQP↔debuginfod
  convergence on one cache entry; blacklist-after-tier-0 ordering.
- Eviction/scrub: watermark behavior (soonest-expiry order), orphan repair
  both directions, report accuracy.
- Compression: negotiation matrix (zstd/gzip/identity × CAB/non-CAB ×
  size floor); golden ratios not asserted (level-dependent), only behavior.
- JS ident drift guard: the browser upload page embeds a JS port of
  symfront-ident (between `IDENT-BEGIN/END` markers in index.html). Add a
  test that extracts that block and runs it under node against the same
  pinned fixtures as the Rust tests (skips gracefully when node is absent).
  *(This was open question #10 — the concern is the two implementations
  silently drifting; the fix is making the existing node comparison script
  part of the suite.)*
- Config store: git history semantics (UI edit commits, drift auto-commit
  on reload, rollback restores + reloads).

## 8. Migration & rollout

1. Crate restructure (`symfront-core` → `symfront-store` + extract
   `symfront-ident`; clean break, no shim) — pure refactor commit.
2. Config-tree + git-backed config store; port existing flags into
   `server.toml`/`store.toml` (flags remain as overrides).
3. `symfront-proxy` with the fake-upstream suite + goldens.
4. Wire the pipeline; move admin UI to `/admin/` with root redirect;
   root-mounted symbol serving.
5. Translate the three symsrv TOML files (drop `internal`); commit as the
   initial config-repo state.
6. **Full cache import**: walk Python `metadata.db` → new schema (add
   `negative_step=0`, map timestamps), copy/hardlink data files into the
   new layout under the new cache root (same keying; 15.8 GB, plenty of
   pool space). Importer is a one-shot `symfront proxy import` command.
7. Parallel-run on the `symbols-beta` vhost/socket (it exists for exactly
   this); diff behavior/logs against Python symsrv on mirrored requests.
8. Cut `symbols.*` over to the Rust proxy; retire the `symbols-private`
   raw-nginx vhost in favor of symfront serving (auth decision for that
   vhost at review: it currently has zero auth and autoindex).
9. Freeze the Python tree as rollback for a while; update symsrv's public
   README pointing at its successor when/if symfront goes public.

## 9. Remaining open questions (for the review session)

1. Eviction watermark defaults (e.g. start at 100% of `cache.size`, stop at
   95%?) and scrub schedule default (weekly?).
2. `stagger_ms`: default 100 ms (owner); decide per-upstream vs. per-tier
   override granularity.
3. Keep `/symbols/…` alias during migration, and for how long?
4. gzip level after zlib-rs benchmarking (pin a number).
5. Config-repo location: inside the config dir (`.git` beside the TOMLs,
   recommended for transplantability) vs. elsewhere.
6. Exact Prometheus metric names/labels (follow prometheus naming
   conventions; draft at review).
7. `symbols-private` replacement vhost: keep unauthenticated read-only
   store serving (status quo semantics, minus autoindex), or fold into the
   main vhost entirely?
8. Import: hardlink vs. copy for cache data files (same pool/dataset?
   hardlink is instant; copy is safer across datasets — check dataset
   boundaries at implementation time).
