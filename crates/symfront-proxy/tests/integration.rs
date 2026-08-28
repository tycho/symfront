//! Fake-upstream integration suite: fills, negative ladder, revalidation,
//! stale-while-error, health breaker, singleflight, stagger, HEAD upgrade,
//! eviction, scrub.

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use axum::body::Body;
use axum::extract::State;
use axum::http::{HeaderMap, Method as AxMethod, StatusCode, Uri};
use axum::response::{IntoResponse, Response};
use symfront_proxy::config::{ProxyConfig, TtlPolicy};
use symfront_proxy::engine::{ClientRequest, Method, Outcome, ProxyEngine};
use symfront_proxy::maintenance::MaintProgress;
use symfront_proxy::query::{Family, LayoutKind, Role};
use symfront_proxy::{Blacklist, Upstream};

#[derive(Clone)]
enum Reply {
    Body(Vec<u8>),
    Status(u16),
    /// Stream the body slowly in two halves.
    SlowBody(Vec<u8>, Duration),
    /// 304 if If-None-Match matches, else the body with that ETag.
    Conditional(String, Vec<u8>),
    /// Sleep, then 404.
    SlowStatus(u16, Duration),
}

#[derive(Clone, Default)]
struct Seen {
    method: String,
    headers: Vec<(String, String)>,
}

#[derive(Clone)]
struct FakeState {
    replies: Arc<Mutex<HashMap<String, Reply>>>,
    hits: Arc<Mutex<HashMap<String, u32>>>,
    seen: Arc<Mutex<Vec<(String, Seen)>>>,
}

async fn fake_handler(
    State(st): State<FakeState>,
    method: AxMethod,
    uri: Uri,
    headers: HeaderMap,
) -> Response {
    let path = uri.path().to_string();
    *st.hits.lock().unwrap().entry(path.clone()).or_default() += 1;
    st.seen.lock().unwrap().push((
        path.clone(),
        Seen {
            method: method.to_string(),
            headers: headers
                .iter()
                .map(|(k, v)| (k.to_string(), v.to_str().unwrap_or("").to_string()))
                .collect(),
        },
    ));
    let reply = st.replies.lock().unwrap().get(&path).cloned();
    match reply {
        None => StatusCode::NOT_FOUND.into_response(),
        Some(Reply::Body(b)) => b.into_response(),
        Some(Reply::Status(s)) => StatusCode::from_u16(s).unwrap().into_response(),
        Some(Reply::SlowStatus(s, delay)) => {
            tokio::time::sleep(delay).await;
            StatusCode::from_u16(s).unwrap().into_response()
        }
        Some(Reply::SlowBody(b, delay)) => {
            let mid = b.len() / 2;
            let (a, z) = (b[..mid].to_vec(), b[mid..].to_vec());
            let stream =
                futures_util::stream::unfold((0u8, a, z, delay), |(i, a, z, delay)| async move {
                    match i {
                        0 => Some((Ok::<_, std::io::Error>(a.clone()), (1, a, z, delay))),
                        1 => {
                            tokio::time::sleep(delay).await;
                            Some((Ok(z.clone()), (2, a, z, delay)))
                        }
                        _ => None,
                    }
                });
            Response::builder()
                .header("content-length", b.len())
                .body(Body::from_stream(stream))
                .unwrap()
        }
        Some(Reply::Conditional(etag, b)) => {
            let inm = headers
                .get("if-none-match")
                .and_then(|v| v.to_str().ok())
                .unwrap_or("");
            if inm == etag {
                StatusCode::NOT_MODIFIED.into_response()
            } else {
                Response::builder()
                    .header("etag", etag)
                    .body(Body::from(b))
                    .unwrap()
            }
        }
    }
}

struct Fake {
    addr: SocketAddr,
    state: FakeState,
}

impl Fake {
    async fn start() -> Fake {
        let state = FakeState {
            replies: Default::default(),
            hits: Default::default(),
            seen: Default::default(),
        };
        let app = axum::Router::new()
            .fallback(fake_handler)
            .with_state(state.clone());
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            axum::serve(listener, app).await.unwrap();
        });
        Fake { addr, state }
    }

    fn base_url(&self) -> String {
        format!("http://{}", self.addr)
    }

    fn set(&self, path: &str, reply: Reply) {
        self.state
            .replies
            .lock()
            .unwrap()
            .insert(path.to_string(), reply);
    }

    fn hits(&self, path: &str) -> u32 {
        *self.state.hits.lock().unwrap().get(path).unwrap_or(&0)
    }

    fn last_seen(&self, path: &str) -> Option<Seen> {
        self.state
            .seen
            .lock()
            .unwrap()
            .iter()
            .rev()
            .find(|(p, _)| p == path)
            .map(|(_, s)| s.clone())
    }
}

fn upstream(name: &str, base: &str) -> Upstream {
    Upstream {
        name: name.into(),
        enabled: true,
        base_url: base.into(),
        layout: LayoutKind::Symstore,
        binformat: [Family::Pe].into_iter().collect(),
        provides: [Role::Image, Role::Debug].into_iter().collect(),
        extensions: None,
        priority: 10,
        nocache: false,
        requires_symbolchecksum: false,
        negative_ttl: None,
    }
}

fn test_config(dir: &std::path::Path) -> ProxyConfig {
    ProxyConfig {
        cache_path: dir.to_path_buf(),
        stagger: Duration::from_millis(30),
        connect_timeout: Duration::from_millis(500),
        read_timeout: Duration::from_secs(5),
        ..ProxyConfig::default()
    }
}

fn engine_with(dir: &std::path::Path, cfg: ProxyConfig, ups: Vec<Upstream>) -> Arc<ProxyEngine> {
    let _ = dir;
    ProxyEngine::new(cfg, ups, Blacklist::default()).unwrap()
}

async fn fetch(engine: &Arc<ProxyEngine>, path: &str) -> (u16, Vec<u8>) {
    fetch_full(engine, Method::Get, path, None).await
}

async fn fetch_full(
    engine: &Arc<ProxyEngine>,
    method: Method,
    path: &str,
    checksum: Option<&str>,
) -> (u16, Vec<u8>) {
    let outcome = engine
        .handle(ClientRequest {
            method,
            path,
            symbol_checksum: checksum.map(|s| s.to_string()),
        })
        .await;
    consume(outcome).await
}

async fn consume(outcome: Outcome) -> (u16, Vec<u8>) {
    match outcome {
        Outcome::NotFound => (404, Vec::new()),
        Outcome::HeaderOnly { status, .. } => (status, Vec::new()),
        Outcome::CacheHit { path, .. } => (200, tokio::fs::read(&path).await.unwrap()),
        Outcome::AccelHit { .. } => (200, Vec::new()),
        Outcome::Fill { handle, .. } => {
            let mut reader = handle.tail();
            let mut body = Vec::new();
            while let Some(chunk) = reader.next_chunk().await.unwrap() {
                body.extend_from_slice(&chunk);
            }
            (200, body)
        }
        Outcome::Passthrough { response } => {
            let status = response.status().as_u16();
            let body = response.bytes().await.unwrap_or_default().to_vec();
            (status, body)
        }
    }
}

const PDB: &str = "/foo.pdb/ABCDEF01234567890123456789ABCDEF1/foo.pdb";

/// Wait for a key's fill flight to deregister. A completed fill stays
/// registered for a few ms after clients see EOF (the pump drops its guard
/// after the metadata commit); a request landing in that window correctly
/// becomes a follower of the finished fill instead of hitting the upstream,
/// which is fine for clients but nondeterministic for hit-count asserts.
async fn wait_flight_done(engine: &Arc<ProxyEngine>, upstream_name: &str, url: &str) {
    let key = symfront_proxy::CacheKey::new(upstream_name, url).hash;
    let deadline = std::time::Instant::now() + Duration::from_secs(5);
    while engine.fills.in_flight(&key) {
        assert!(
            std::time::Instant::now() < deadline,
            "fill flight never deregistered"
        );
        tokio::time::sleep(Duration::from_millis(5)).await;
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn fill_then_hit() {
    let fake = Fake::start().await;
    let dir = tempfile::tempdir().unwrap();
    let engine = engine_with(
        dir.path(),
        test_config(dir.path()),
        vec![upstream("u", &fake.base_url())],
    );
    fake.set(PDB, Reply::Body(b"pdb-bytes".to_vec()));

    let (status, body) = fetch(&engine, PDB).await;
    assert_eq!((status, body.as_slice()), (200, b"pdb-bytes".as_slice()));
    assert_eq!(fake.hits(PDB), 1);
    wait_flight_done(&engine, "u", &format!("{}{}", fake.base_url(), PDB)).await;

    let (status, body) = fetch(&engine, PDB).await;
    assert_eq!((status, body.as_slice()), (200, b"pdb-bytes".as_slice()));
    assert_eq!(fake.hits(PDB), 1, "second request must be a cache hit");
    assert_eq!(
        engine
            .stats
            .cache_hits
            .load(std::sync::atomic::Ordering::Relaxed),
        1
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn negative_ladder_advances() {
    let fake = Fake::start().await;
    let dir = tempfile::tempdir().unwrap();
    let mut cfg = test_config(dir.path());
    // Step 0 expires instantly; step 1 lasts.
    cfg.ttl = TtlPolicy {
        positive: Duration::from_secs(3600),
        negative: vec![Duration::from_secs(0), Duration::from_secs(3600)],
    };
    let engine = engine_with(dir.path(), cfg, vec![upstream("u", &fake.base_url())]);
    // No reply configured -> upstream 404s.

    assert_eq!(fetch(&engine, PDB).await.0, 404);
    assert_eq!(fake.hits(PDB), 1);
    // Negative writes are fire-and-forget; drain the writer before relying
    // on the entry being visible.
    engine.cache.db.flush().await.unwrap();
    // Step 0 (0s TTL) has expired: re-probe advances to step 1.
    assert_eq!(fetch(&engine, PDB).await.0, 404);
    assert_eq!(fake.hits(PDB), 2);
    engine.cache.db.flush().await.unwrap();
    let entry = engine
        .cache
        .db
        .get(&symfront_proxy::CacheKey::new("u", &format!("{}{}", fake.base_url(), PDB)).hash)
        .unwrap()
        .expect("negative entry exists");
    assert_eq!(entry.negative_step, 1);
    assert_eq!(entry.status, 404);
    // Step 1 is fresh for an hour: no upstream traffic now.
    assert_eq!(fetch(&engine, PDB).await.0, 404);
    assert_eq!(
        fake.hits(PDB),
        2,
        "fresh negative entry must be served from cache"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn revalidation_304_refreshes() {
    let fake = Fake::start().await;
    let dir = tempfile::tempdir().unwrap();
    let mut cfg = test_config(dir.path());
    cfg.ttl.positive = Duration::from_secs(0); // born expired
    let engine = engine_with(dir.path(), cfg, vec![upstream("u", &fake.base_url())]);
    fake.set(
        PDB,
        Reply::Conditional("\"v1\"".into(), b"payload".to_vec()),
    );

    let (status, body) = fetch(&engine, PDB).await;
    assert_eq!((status, body.as_slice()), (200, b"payload".as_slice()));
    assert_eq!(fake.hits(PDB), 1);
    wait_flight_done(&engine, "u", &format!("{}{}", fake.base_url(), PDB)).await;

    // Entry is expired immediately; next request revalidates and gets 304.
    let (status, body) = fetch(&engine, PDB).await;
    assert_eq!((status, body.as_slice()), (200, b"payload".as_slice()));
    assert_eq!(fake.hits(PDB), 2);
    let seen = fake.last_seen(PDB).unwrap();
    assert!(
        seen.headers
            .iter()
            .any(|(k, v)| k == "if-none-match" && v == "\"v1\""),
        "revalidation must send If-None-Match: {:?}",
        seen.headers
    );
    // No refill happened: body came from cache after the 304.
    assert_eq!(
        engine
            .stats
            .fills
            .load(std::sync::atomic::Ordering::Relaxed),
        1
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn stale_while_error() {
    let fake = Fake::start().await;
    let dir = tempfile::tempdir().unwrap();
    let mut cfg = test_config(dir.path());
    cfg.ttl.positive = Duration::from_secs(0);
    let engine = engine_with(dir.path(), cfg, vec![upstream("u", &fake.base_url())]);
    fake.set(PDB, Reply::Body(b"old-but-gold".to_vec()));
    assert_eq!(fetch(&engine, PDB).await.0, 200);
    wait_flight_done(&engine, "u", &format!("{}{}", fake.base_url(), PDB)).await;

    // A 500 during revalidation takes the serve-stale path (the transport-
    // failure variant of stale-while-error shares the same code path but
    // additionally trips the breaker; that side is covered by
    // health_trip_and_probe_restore).
    fake.set(PDB, Reply::Status(500));
    let (status, body) = fetch(&engine, PDB).await;
    assert_eq!((status, body.as_slice()), (200, b"old-but-gold".as_slice()));
}

#[tokio::test(flavor = "multi_thread")]
async fn health_trip_and_probe_restore() {
    // An upstream at a dead port trips on first use.
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    drop(listener); // free the port; nothing listens now

    let dir = tempfile::tempdir().unwrap();
    let engine = engine_with(
        dir.path(),
        test_config(dir.path()),
        vec![upstream("flaky", &format!("http://{addr}"))],
    );
    assert_eq!(fetch(&engine, PDB).await.0, 404);
    assert!(!engine.health.is_available("flaky"), "breaker must trip");

    // While suspended, no upstream traffic happens (and it 404s fast).
    assert_eq!(fetch(&engine, PDB).await.0, 404);

    // Bring the port back and probe: any complete response restores.
    let listener = tokio::net::TcpListener::bind(addr).await.unwrap();
    let app = axum::Router::new().fallback(|| async { StatusCode::IM_A_TEAPOT });
    tokio::spawn(async move {
        axum::serve(listener, app).await.unwrap();
    });
    engine.probe_suspended_once().await;
    assert!(engine.health.is_available("flaky"), "probe must restore");
}

#[tokio::test(flavor = "multi_thread")]
async fn singleflight_collapses_concurrent_misses() {
    let fake = Fake::start().await;
    let dir = tempfile::tempdir().unwrap();
    let engine = engine_with(
        dir.path(),
        test_config(dir.path()),
        vec![upstream("u", &fake.base_url())],
    );
    let body: Vec<u8> = (0..200_000u32).map(|i| i as u8).collect();
    fake.set(
        PDB,
        Reply::SlowBody(body.clone(), Duration::from_millis(150)),
    );

    let mut tasks = Vec::new();
    for _ in 0..4 {
        let engine = Arc::clone(&engine);
        tasks.push(tokio::spawn(async move { fetch(&engine, PDB).await }));
    }
    for t in tasks {
        let (status, got) = t.await.unwrap();
        assert_eq!(status, 200);
        assert_eq!(got, body);
    }
    assert_eq!(
        fake.hits(PDB),
        1,
        "one upstream fetch for N concurrent clients"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn server_errors_pass_through_uncached() {
    let fake = Fake::start().await;
    let dir = tempfile::tempdir().unwrap();
    let engine = engine_with(
        dir.path(),
        test_config(dir.path()),
        vec![upstream("u", &fake.base_url())],
    );
    fake.set(PDB, Reply::Status(503));

    assert_eq!(fetch(&engine, PDB).await.0, 503);
    assert_eq!(fetch(&engine, PDB).await.0, 503);
    assert_eq!(fake.hits(PDB), 2, "5xx must never be cached");
    let key = symfront_proxy::CacheKey::new("u", &format!("{}{}", fake.base_url(), PDB));
    assert!(engine.cache.db.get(&key.hash).unwrap().is_none());
}

#[tokio::test(flavor = "multi_thread")]
async fn head_upgrades_to_get_fill() {
    let fake = Fake::start().await;
    let dir = tempfile::tempdir().unwrap();
    let engine = engine_with(
        dir.path(),
        test_config(dir.path()),
        vec![upstream("u", &fake.base_url())],
    );
    fake.set(PDB, Reply::Body(b"warmed".to_vec()));

    let outcome = engine
        .handle(ClientRequest {
            method: Method::Head,
            path: PDB,
            symbol_checksum: None,
        })
        .await;
    // A HEAD miss becomes a GET fill; the client just doesn't read the body.
    let Outcome::Fill { handle, .. } = outcome else {
        panic!("HEAD miss should produce a fill");
    };
    assert_eq!(fake.last_seen(PDB).unwrap().method, "GET");

    // The fill completes with zero tailing clients and warms the cache.
    let mut reader = handle.tail();
    let mut got = Vec::new();
    while let Some(chunk) = reader.next_chunk().await.unwrap() {
        got.extend_from_slice(&chunk);
    }
    drop(reader);
    let (status, body) = fetch(&engine, PDB).await;
    assert_eq!((status, body.as_slice()), (200, b"warmed".as_slice()));
    assert_eq!(fake.hits(PDB), 1);
}

#[tokio::test(flavor = "multi_thread")]
async fn client_disconnect_still_commits() {
    let fake = Fake::start().await;
    let dir = tempfile::tempdir().unwrap();
    let engine = engine_with(
        dir.path(),
        test_config(dir.path()),
        vec![upstream("u", &fake.base_url())],
    );
    let body: Vec<u8> = vec![7u8; 100_000];
    fake.set(
        PDB,
        Reply::SlowBody(body.clone(), Duration::from_millis(100)),
    );

    let outcome = engine
        .handle(ClientRequest {
            method: Method::Get,
            path: PDB,
            symbol_checksum: None,
        })
        .await;
    // Client vanishes without reading a byte.
    drop(outcome);

    // The fill must still run to completion and commit.
    let key = symfront_proxy::CacheKey::new("u", &format!("{}{}", fake.base_url(), PDB));
    let deadline = std::time::Instant::now() + Duration::from_secs(5);
    loop {
        if let Some(entry) = engine.cache.db.get(&key.hash).unwrap() {
            assert_eq!(entry.status, 200);
            assert_eq!(entry.size, body.len() as u64);
            break;
        }
        assert!(std::time::Instant::now() < deadline, "fill never committed");
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    assert_eq!(fake.hits(PDB), 1);
    let (status, got) = fetch(&engine, PDB).await;
    assert_eq!(status, 200);
    assert_eq!(got, body);
}

#[tokio::test(flavor = "multi_thread")]
async fn stagger_lets_later_tier_win() {
    let slow = Fake::start().await;
    let fast = Fake::start().await;
    let dir = tempfile::tempdir().unwrap();
    let mut tier0 = upstream("slow", &slow.base_url());
    tier0.priority = 1;
    let mut tier1 = upstream("fast", &fast.base_url());
    tier1.priority = 2;
    let engine = engine_with(dir.path(), test_config(dir.path()), vec![tier0, tier1]);

    // Tier 0 takes 400 ms to say 404; tier 1 has the file. With a 30 ms
    // stagger the answer arrives long before tier 0 finishes.
    slow.set(PDB, Reply::SlowStatus(404, Duration::from_millis(400)));
    fast.set(PDB, Reply::Body(b"from-tier-1".to_vec()));

    let started = std::time::Instant::now();
    let (status, body) = fetch(&engine, PDB).await;
    assert_eq!((status, body.as_slice()), (200, b"from-tier-1".as_slice()));
    assert!(
        started.elapsed() < Duration::from_millis(300),
        "tier 1 should win the race without waiting for tier 0's timeout \
         (took {:?})",
        started.elapsed()
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn symbolchecksum_passthrough_and_invalid() {
    let fake = Fake::start().await;
    let dir = tempfile::tempdir().unwrap();
    let mut u = upstream("nuget", &fake.base_url());
    u.requires_symbolchecksum = true;
    let engine = engine_with(dir.path(), test_config(dir.path()), vec![u]);
    fake.set(PDB, Reply::Status(404));

    // Client didn't send one; the upstream requires it: send "invalid".
    fetch(&engine, PDB).await;
    let seen = fake.last_seen(PDB).unwrap();
    assert!(seen
        .headers
        .iter()
        .any(|(k, v)| k == "symbolchecksum" && v == "invalid"));

    // Client sent one: pass it through. (Different path: the previous 404
    // is negative-cached.)
    let other = "/bar.pdb/ABCDEF01234567890123456789ABCDEF2/bar.pdb";
    fake.set(other, Reply::Status(404));
    fetch_full(&engine, Method::Get, other, Some("SHA256:abc123")).await;
    let seen = fake.last_seen(other).unwrap();
    assert!(seen
        .headers
        .iter()
        .any(|(k, v)| k == "symbolchecksum" && v == "SHA256:abc123"));
}

#[tokio::test(flavor = "multi_thread")]
async fn ssqp_and_debuginfod_share_one_cache_entry() {
    let fake = Fake::start().await;
    let dir = tempfile::tempdir().unwrap();
    let buildid = "aabbccddeeff00112233445566778899aabbccdd";
    let mut u = upstream("dbg", &fake.base_url());
    u.layout = LayoutKind::Debuginfod;
    u.binformat = [Family::Elf].into_iter().collect();
    let engine = engine_with(dir.path(), test_config(dir.path()), vec![u]);
    let canonical = format!("/buildid/{buildid}/debuginfo");
    fake.set(&canonical, Reply::Body(b"dwarf-data".to_vec()));

    // Sentry-style SSQP request…
    let ssqp = format!("/_.debug/elf-buildid-sym-{buildid}/_.debug");
    let (status, body) = fetch(&engine, &ssqp).await;
    assert_eq!((status, body.as_slice()), (200, b"dwarf-data".as_slice()));
    // …and a native debuginfod request converge on one cache entry.
    let native = format!("/buildid/{buildid}/debuginfo");
    let (status, body) = fetch(&engine, &native).await;
    assert_eq!((status, body.as_slice()), (200, b"dwarf-data".as_slice()));
    assert_eq!(fake.hits(&canonical), 1, "one fill for both request shapes");
}

#[tokio::test(flavor = "multi_thread")]
async fn eviction_soonest_expiry_first() {
    let fake = Fake::start().await;
    let dir = tempfile::tempdir().unwrap();
    let mut cfg = test_config(dir.path());
    // Budget of 250 KB with 3×100 KB entries -> must evict down to 200 KB.
    cfg.cache_size = Some(250_000);
    cfg.high_watermark = 1.0;
    cfg.low_watermark = 0.8;
    let engine = engine_with(dir.path(), cfg, vec![upstream("u", &fake.base_url())]);

    let paths = [
        "/a.pdb/AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA1/a.pdb",
        "/b.pdb/BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB1/b.pdb",
        "/c.pdb/CCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCC1/c.pdb",
    ];
    for (i, p) in paths.iter().enumerate() {
        fake.set(p, Reply::Body(vec![i as u8; 100_000]));
        assert_eq!(fetch(&engine, p).await.0, 200);
        // Distinct commit times -> distinct expiry order.
        tokio::time::sleep(Duration::from_millis(15)).await;
    }
    assert_eq!(engine.cache.db.positive_bytes().unwrap(), 300_000);

    let report = engine.evict_pass(&MaintProgress::default()).await;
    assert!(report.enabled);
    assert_eq!(
        report.evicted_entries, 1,
        "one eviction reaches the low watermark"
    );
    // Soonest expiry = the first fill (a.pdb): it must be the one gone.
    let key_a = symfront_proxy::CacheKey::new("u", &format!("{}{}", fake.base_url(), paths[0]));
    let key_c = symfront_proxy::CacheKey::new("u", &format!("{}{}", fake.base_url(), paths[2]));
    assert!(engine.cache.db.get(&key_a.hash).unwrap().is_none());
    assert!(engine.cache.db.get(&key_c.hash).unwrap().is_some());
    assert!(!engine.cache.data_path(&key_a.hash).exists());
}

#[tokio::test(flavor = "multi_thread")]
async fn scrub_repairs_both_directions() {
    let fake = Fake::start().await;
    let dir = tempfile::tempdir().unwrap();
    let engine = engine_with(
        dir.path(),
        test_config(dir.path()),
        vec![upstream("u", &fake.base_url())],
    );
    let paths = [
        "/a.pdb/AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA1/a.pdb",
        "/b.pdb/BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB1/b.pdb",
        "/c.pdb/CCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCC1/c.pdb",
    ];
    for p in &paths {
        fake.set(p, Reply::Body(b"data-here".to_vec()));
        assert_eq!(fetch(&engine, p).await.0, 200);
    }
    let key = |p: &str| symfront_proxy::CacheKey::new("u", &format!("{}{}", fake.base_url(), p));

    // Direction 1: a file with no row (orphan).
    let orphan_key = [0xabu8; 32];
    let orphan_path = engine.cache.data_path(&orphan_key);
    std::fs::create_dir_all(orphan_path.parent().unwrap()).unwrap();
    std::fs::write(&orphan_path, b"who am i").unwrap();
    // Direction 2: a row whose file is gone.
    std::fs::remove_file(engine.cache.data_path(&key(paths[0]).hash)).unwrap();
    // Direction 3: a size mismatch.
    std::fs::write(engine.cache.data_path(&key(paths[1]).hash), b"short").unwrap();

    let report = engine.scrub(true, &MaintProgress::default()).await.unwrap();
    assert_eq!(report.orphan_files, 1);
    assert_eq!(report.rows_missing_data, 1);
    assert_eq!(report.size_mismatches, 1);
    assert!(!orphan_path.exists());
    assert!(engine.cache.db.get(&key(paths[0]).hash).unwrap().is_none());
    assert!(engine.cache.db.get(&key(paths[1]).hash).unwrap().is_none());
    // The healthy entry survives untouched.
    assert!(engine.cache.db.get(&key(paths[2]).hash).unwrap().is_some());
    assert!(engine.cache.data_path(&key(paths[2]).hash).exists());
}

#[tokio::test(flavor = "multi_thread")]
async fn blacklist_and_unclassifiable_reject_without_traffic() {
    let fake = Fake::start().await;
    let dir = tempfile::tempdir().unwrap();
    let engine = ProxyEngine::new(
        test_config(dir.path()),
        vec![upstream("u", &fake.base_url())],
        Blacklist {
            substrings: vec!["AMDRyzen".into()],
            suffixes: vec![],
            first_components: ["index2.txt".to_string()].into_iter().collect(),
        },
    )
    .unwrap();

    assert_eq!(
        fetch(
            &engine,
            "/AMDRyzenMasterDriver.pdb/ABC1/AMDRyzenMasterDriver.pdb"
        )
        .await
        .0,
        404
    );
    assert_eq!(fetch(&engine, "/index2.txt").await.0, 404);
    assert_eq!(fetch(&engine, "/nonsense-no-extension").await.0, 404);
    assert!(
        fake.state.hits.lock().unwrap().is_empty(),
        "no upstream traffic"
    );
    assert_eq!(
        engine
            .stats
            .rejected
            .load(std::sync::atomic::Ordering::Relaxed),
        3
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn disabled_upstream_is_never_used() {
    let fake = Fake::start().await;
    let dir = tempfile::tempdir().unwrap();
    let mut u = upstream("parked", &fake.base_url());
    u.enabled = false;
    let engine = engine_with(dir.path(), test_config(dir.path()), vec![u]);
    fake.set(PDB, Reply::Body(b"should never be seen".to_vec()));

    assert_eq!(fetch(&engine, PDB).await.0, 404);
    assert_eq!(
        fake.hits(PDB),
        0,
        "disabled upstream must receive no traffic"
    );
    // Still present in the engine's config (for the admin UI).
    assert_eq!(engine.upstreams.len(), 1);
    assert!(!engine.upstreams[0].enabled);
}

#[tokio::test(flavor = "multi_thread")]
async fn short_buildids_never_reach_debuginfod() {
    let fake = Fake::start().await;
    let dir = tempfile::tempdir().unwrap();
    let mut u = upstream("dbg", &fake.base_url());
    u.layout = LayoutKind::Debuginfod;
    u.binformat = [Family::Elf].into_iter().collect();
    let engine = engine_with(dir.path(), test_config(dir.path()), vec![u]);

    // A PE timestamp+size masquerading as a build-id (Sentry probe shape):
    // rejected without any upstream traffic, via either inbound layout.
    assert_eq!(
        fetch(&engine, "/_.debug/elf-buildid-sym-0871fae9be000/_.debug")
            .await
            .0,
        404
    );
    assert_eq!(
        fetch(&engine, "/buildid/0871fae9be000/debuginfo").await.0,
        404
    );
    assert!(
        fake.state.hits.lock().unwrap().is_empty(),
        "no upstream traffic"
    );

    // A real-length build-id still fans out.
    let id = "aabbccddeeff00112233445566778899aabbccdd";
    fake.set(
        &format!("/buildid/{id}/debuginfo"),
        Reply::Body(b"dwarf".to_vec()),
    );
    assert_eq!(
        fetch(&engine, &format!("/buildid/{id}/debuginfo")).await.0,
        200
    );

    // min_buildid_hex = 0 disables the guard.
    let dir2 = tempfile::tempdir().unwrap();
    let mut cfg = test_config(dir2.path());
    cfg.min_buildid_hex = 0;
    let mut u = upstream("dbg", &fake.base_url());
    u.layout = LayoutKind::Debuginfod;
    u.binformat = [Family::Elf].into_iter().collect();
    let engine = engine_with(dir2.path(), cfg, vec![u]);
    assert_eq!(
        fetch(&engine, "/buildid/0871fae9be000/debuginfo").await.0,
        404
    );
    assert_eq!(
        fake.hits("/buildid/0871fae9be000/debuginfo"),
        1,
        "guard disabled: probed"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn ttfb_medians_split_by_response_class() {
    let fake = Fake::start().await;
    let dir = tempfile::tempdir().unwrap();
    let engine = engine_with(
        dir.path(),
        test_config(dir.path()),
        vec![upstream("u", &fake.base_url())],
    );

    // One 200 fill and one 404: each lands in its own latency window.
    fake.set(PDB, Reply::Body(b"bytes".to_vec()));
    assert_eq!(fetch(&engine, PDB).await.0, 200);
    let missing = "/gone.pdb/ABCDEF01234567890123456789ABCDEF9/gone.pdb";
    assert_eq!(fetch(&engine, missing).await.0, 404);

    let stats = engine.stats.upstream("u");
    assert_eq!(stats.latency_2xx.len(), 1, "one 2xx sample");
    assert_eq!(stats.latency_4xx.len(), 1, "one 4xx sample");
    assert!(stats.latency_2xx.median().unwrap() >= 0.0);
    assert!(stats.latency_4xx.median().unwrap() >= 0.0);

    // A slow 404 shows up in the 4xx median, leaving 2xx untouched.
    let slow = "/slow.pdb/ABCDEF01234567890123456789ABCDEF8/slow.pdb";
    fake.set(slow, Reply::SlowStatus(404, Duration::from_millis(120)));
    assert_eq!(fetch(&engine, slow).await.0, 404);
    assert_eq!(stats.latency_4xx.len(), 2);
    let sorted_in = stats.latency_4xx.median().unwrap();
    assert!(
        sorted_in >= 50.0,
        "slow 404 must raise the 4xx median (got {sorted_in}ms)"
    );
    assert_eq!(stats.latency_2xx.len(), 1, "2xx window unaffected");
}

#[tokio::test(flavor = "multi_thread")]
async fn temp_cleanup_only_reaps_abandoned_files() {
    let dir = tempfile::tempdir().unwrap();
    let engine = {
        let fake = Fake::start().await;
        engine_with(
            dir.path(),
            test_config(dir.path()),
            vec![upstream("u", &fake.base_url())],
        )
    };
    let tmp_dir = dir.path().join("tmp");
    let fresh = tmp_dir.join("deadbeef.0123456789abcdef.1");
    let stale = tmp_dir.join("cafebabe.0123456789abcdef.2");
    std::fs::write(&fresh, b"in flight").unwrap();
    std::fs::write(&stale, b"crash leftover").unwrap();
    let two_days_ago = std::time::SystemTime::now() - Duration::from_secs(48 * 3600);
    let f = std::fs::File::options().write(true).open(&stale).unwrap();
    f.set_times(std::fs::FileTimes::new().set_modified(two_days_ago))
        .unwrap();
    drop(f);

    engine.cache.clean_stale_temps();
    assert!(
        fresh.exists(),
        "recent temp (possibly an in-flight fill) must survive"
    );
    assert!(!stale.exists(), "day-old crash leftover must be reaped");
}

#[tokio::test(flavor = "multi_thread")]
async fn config_reload_mid_fill_does_not_break_the_fill() {
    let fake = Fake::start().await;
    let dir = tempfile::tempdir().unwrap();
    let engine = engine_with(
        dir.path(),
        test_config(dir.path()),
        vec![upstream("u", &fake.base_url())],
    );
    let body: Vec<u8> = vec![9u8; 80_000];
    fake.set(
        PDB,
        Reply::SlowBody(body.clone(), Duration::from_millis(300)),
    );

    // Start a fill and, while its body is still streaming, rebuild the
    // engine over the same cache dir — exactly what a config reload does.
    // The old behavior wiped the in-flight temp file here, so the fill
    // died at the final rename with ENOENT.
    let e1 = Arc::clone(&engine);
    let fill = tokio::spawn(async move { fetch(&e1, PDB).await });
    tokio::time::sleep(Duration::from_millis(80)).await;
    let engine2 = engine_with(
        dir.path(),
        test_config(dir.path()),
        vec![upstream("u", &fake.base_url())],
    );

    let (status, got) = fill.await.unwrap();
    assert_eq!(status, 200);
    assert_eq!(got, body);
    // And the fill committed: the *new* engine serves it from cache.
    let (status, got) = fetch(&engine2, PDB).await;
    assert_eq!(status, 200);
    assert_eq!(got, body);
    assert_eq!(
        fake.hits(PDB),
        1,
        "second engine must hit the committed cache entry"
    );
}
