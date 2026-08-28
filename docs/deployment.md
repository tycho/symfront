# Deployment runbook: symsrv → symfront cutover

Migration steps 5–9 from `proxy-integration-plan.md`. Steps 1–4 (crate
restructure, config tree, proxy engine, pipeline wiring) are done in the
tree; everything below happens on the server host and is deliberately
manual.

## 5. Install the config tree

`deploy/etc-symfront/` is the translated symsrv config (validated against
the parsers; `internal` dropped — the store is tier 0 now; previously
commented upstreams preserved with `enabled = false`; blacklist verbatim).

```sh
sudo cp -r deploy/etc-symfront /etc/symfront
sudo symfront config init          # no-op for existing files; creates the
                                   # history repo + initial commit
```

Create the auth db and first admin user (the admin UI is authenticated in
production):

```sh
sudo mkdir -p /var/lib/symfront
sudo symfront user --auth-db /var/lib/symfront/auth.db add steven --role admin
```

## 6. Import the Python cache

Same keying (sha256 of upstream URL), so the entire cache carries over.
Hardlinks are instant when `/srv/cache/ntsymbols/data` and
`/srv/cache/symfront` are on the same dataset; otherwise use `--copy`
(check `zfs list` first). Verified against the live db: all 26,220 entries
map cleanly.

```sh
sudo symfront proxy import /srv/cache/ntsymbols/data --dry-run   # sanity
sudo symfront proxy import /srv/cache/ntsymbols/data
```

The Python cache is left untouched (it keeps serving symbols.* until
cutover).

## 7. Parallel-run on symbols-beta

- Install `deploy/symfront.service`, start it; the socket appears at
  `/run/symfront/http.sock`.
- Point the `symbols-beta.*` vhost at it (see
  `deploy/nginx-symfront.conf.example`, which includes the
  `/_symfront_cache/` internal location for X-Accel mode).
- Mirror real traffic or replay access-log paths against both hosts and
  diff status codes; the layout goldens already pin classification, so
  differences should be limited to timing and the intentional semantic
  changes (sliding TTLs, ladder, HEAD-upgrade).

### Benchmarks (performance mandate — regressions block cutover)

Compare symfront (beta vhost) against Python symsrv (live vhost) on:

- cache-hit TTFB and throughput (large PDB, `curl -w`; both nginx and
  standalone modes)
- fill throughput (cold key from msdl, measured end-to-end)
- negative-hit latency (`/index2.txt`-class and negative-cached paths)
- concurrent request handling (e.g. `oha`/`wrk` over a mixed hit/negative
  path list)

`/metrics` + `symfront proxy stats --server …` provide the symfront side;
the Python side only has nginx logs.

## 8. Cutover

- Move `symbols.*` to the symfront socket in nginx.
- Retire the `symbols-private.*` raw-autoindex vhost: tier 0 serves the
  store at the root of the main vhost without directory listings or
  transaction history. (If the private hostname must keep working, point
  it at the same upstream.)
- Watch `/metrics` and the admin dashboard; upstream health and fill rates
  should look like the Python instance's steady state.

## 9. Afterwards

- Freeze the Python tree as rollback for a while
  (`systemctl stop symsrv`, keep `/srv/cache/ntsymbols` until confident;
  the import never mutates it).
- Update symsrv's public README to point here when/if symfront goes
  public.
- Revisit `mode = "nginx"` vs `"standalone"` with the benchmark numbers
  (standalone gives richer stats; nginx offloads sendfile+gzip).
