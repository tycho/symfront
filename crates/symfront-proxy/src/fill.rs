//! Cache fills: write-through + tail-follow.
//!
//! One fill task per key (the singleflight winner) pumps the upstream body
//! into a cache temp file as fast as network + disk allow — nothing else is
//! in that loop. Every client (the requester and any singleflight followers
//! that arrive during the fill) *tail-reads the growing temp file*, woken by
//! a watch channel. A slow client backpressures nobody: its buffer is the
//! file itself, and recently written data is RAM-speed via the page cache.
//! Client disconnects change nothing — the fill never knew about clients,
//! and a HEAD-upgraded fill is just a fill with zero tailing clients.
//!
//! Completion: fsync → atomic rename into the data tree → metadata commit
//! (awaited; durability gates completion) → watch flips to Done. Failure:
//! temp file removed, tailing clients get a truncated-stream error.

use std::collections::HashMap;
use std::io::Write;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};

use tokio::sync::watch;

use crate::key::hex;

#[derive(Copy, Clone, PartialEq, Eq, Debug)]
pub enum FillState {
    Running,
    Done,
    Failed,
}

#[derive(Copy, Clone, Debug)]
pub struct FillProgress {
    pub written: u64,
    pub state: FillState,
}

/// Response metadata known as soon as upstream headers arrive — what a
/// client needs to start its response before the body exists locally.
#[derive(Clone, Debug, Default)]
pub struct FillMeta {
    pub etag: Option<String>,
    pub last_modified: Option<String>,
    /// Upstream Content-Length, when it sent one (identity encoding only).
    pub content_length: Option<u64>,
}

/// A running (or just-finished) fill that clients can tail.
pub struct FillHandle {
    pub key: [u8; 32],
    pub meta: FillMeta,
    temp_path: PathBuf,
    final_path: PathBuf,
    progress: watch::Receiver<FillProgress>,
}

impl FillHandle {
    pub fn progress(&self) -> FillProgress {
        *self.progress.borrow()
    }

    /// Stream the fill's body from the start, at this client's own pace.
    pub fn tail(self: &Arc<Self>) -> TailReader {
        TailReader {
            handle: Arc::clone(self),
            progress: self.progress.clone(),
            file: None,
            pos: 0,
        }
    }
}

/// Reads a fill's file from position 0, waiting on the watch channel for
/// bytes that haven't arrived yet.
pub struct TailReader {
    handle: Arc<FillHandle>,
    progress: watch::Receiver<FillProgress>,
    file: Option<std::fs::File>,
    pos: u64,
}

/// Per-read cap. Tail reads are usually page-cache hits; 1 MiB keeps
/// per-chunk latency low without small-read overhead.
const TAIL_CHUNK: usize = 1 << 20;

impl TailReader {
    /// Next chunk of the body; `Ok(None)` = clean EOF.
    pub async fn next_chunk(&mut self) -> std::io::Result<Option<Vec<u8>>> {
        loop {
            let FillProgress { written, state } = *self.progress.borrow_and_update();
            if self.pos < written {
                let want = ((written - self.pos) as usize).min(TAIL_CHUNK);
                return Ok(Some(self.read_at(want, state).await?));
            }
            match state {
                FillState::Done => return Ok(None),
                FillState::Failed => {
                    return Err(std::io::Error::other("upstream fill failed mid-stream"))
                }
                FillState::Running => {
                    if self.progress.changed().await.is_err() {
                        // Sender dropped without reaching Done: treat as failed.
                        return Err(std::io::Error::other("fill task vanished"));
                    }
                }
            }
        }
    }

    async fn read_at(&mut self, want: usize, state: FillState) -> std::io::Result<Vec<u8>> {
        if self.file.is_none() {
            // Lazy open. The temp file may already have been renamed to its
            // final home (rename keeps the inode, so an open fd survives it;
            // only the *open* has to race-fallback).
            let (temp, fin) = (
                self.handle.temp_path.clone(),
                self.handle.final_path.clone(),
            );
            let file = tokio::task::spawn_blocking(move || {
                if state == FillState::Done {
                    std::fs::File::open(&fin)
                } else {
                    match std::fs::File::open(&temp) {
                        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                            std::fs::File::open(&fin)
                        }
                        r => r,
                    }
                }
            })
            .await
            .map_err(std::io::Error::other)??;
            self.file = Some(file);
        }
        let mut file = self.file.take().expect("just set");
        let pos = self.pos;
        let (file, buf) = tokio::task::spawn_blocking(move || {
            use std::io::{Read, Seek, SeekFrom};
            let mut buf = vec![0u8; want];
            let r = (|| {
                file.seek(SeekFrom::Start(pos))?;
                let mut total = 0;
                while total < buf.len() {
                    let n = file.read(&mut buf[total..])?;
                    if n == 0 {
                        break;
                    }
                    total += n;
                }
                buf.truncate(total);
                Ok::<_, std::io::Error>(())
            })();
            (file, r.map(|()| buf))
        })
        .await
        .map_err(std::io::Error::other)?;
        self.file = Some(file);
        let buf = buf?;
        self.pos += buf.len() as u64;
        Ok(buf)
    }
}

/// What a singleflight follower learns about the winner's attempt.
#[derive(Clone)]
pub enum FlightOutcome {
    /// Upstream said 200; tail this fill.
    Positive(Arc<FillHandle>),
    /// Upstream answered with a non-200 status (negative-cached if 4xx).
    Status(u16),
    /// The winner found a freshly committed cache entry: re-check the cache.
    Refreshed,
    /// Transport-level failure; the upstream never completed a response.
    Failed,
}

struct InFlight {
    outcome: watch::Receiver<Option<FlightOutcome>>,
}

/// In-process singleflight: at most one live upstream fetch per cache key.
/// (The Python version needed cross-worker UDS locks; one process, one map.)
#[derive(Default)]
pub struct FillRegistry {
    active: Mutex<HashMap<[u8; 32], InFlight>>,
}

/// Winner's token: publish the outcome exactly once. Dropping without
/// publishing counts as Failed (so followers never hang).
pub struct FlightSlot {
    registry: Arc<FillRegistry>,
    key: [u8; 32],
    tx: Option<watch::Sender<Option<FlightOutcome>>>,
}

impl FlightSlot {
    /// Publish a terminal outcome; the flight ends now.
    pub fn publish(mut self, outcome: FlightOutcome) {
        if let Some(tx) = self.tx.take() {
            let _ = tx.send(Some(outcome));
        }
        self.registry.active.lock().unwrap().remove(&self.key);
    }

    /// Publish a running fill. The flight stays registered — requests
    /// arriving mid-fill become followers and tail it — until the returned
    /// guard drops (the pump holds it through commit/failure).
    pub fn publish_fill(mut self, handle: &Arc<FillHandle>) -> FlightGuard {
        if let Some(tx) = self.tx.take() {
            let _ = tx.send(Some(FlightOutcome::Positive(Arc::clone(handle))));
        }
        FlightGuard {
            registry: Arc::clone(&self.registry),
            key: self.key,
        }
    }
}

/// Keeps a fill's flight registered until the fill finishes.
pub struct FlightGuard {
    registry: Arc<FillRegistry>,
    key: [u8; 32],
}

impl Drop for FlightGuard {
    fn drop(&mut self) {
        self.registry.active.lock().unwrap().remove(&self.key);
    }
}

impl Drop for FlightSlot {
    fn drop(&mut self) {
        if let Some(tx) = self.tx.take() {
            let _ = tx.send(Some(FlightOutcome::Failed));
            self.registry.active.lock().unwrap().remove(&self.key);
        }
    }
}

pub enum FlightEntry {
    /// This task fetches; publish the outcome via the slot.
    Winner(FlightSlot),
    /// Another task is already fetching this key.
    Follower(watch::Receiver<Option<FlightOutcome>>),
}

impl FillRegistry {
    pub fn enter(self: &Arc<Self>, key: [u8; 32]) -> FlightEntry {
        let mut active = self.active.lock().unwrap();
        if let Some(inflight) = active.get(&key) {
            return FlightEntry::Follower(inflight.outcome.clone());
        }
        let (tx, rx) = watch::channel(None);
        active.insert(key, InFlight { outcome: rx });
        FlightEntry::Winner(FlightSlot {
            registry: Arc::clone(self),
            key,
            tx: Some(tx),
        })
    }

    /// Is a fill for `key` currently in flight? (scrub uses this to leave
    /// active temp files alone)
    pub fn in_flight(&self, key: &[u8; 32]) -> bool {
        self.active.lock().unwrap().contains_key(key)
    }
}

/// Wait for a follower's outcome.
pub async fn await_outcome(
    mut rx: watch::Receiver<Option<FlightOutcome>>,
) -> FlightOutcome {
    loop {
        if let Some(outcome) = rx.borrow_and_update().clone() {
            return outcome;
        }
        if rx.changed().await.is_err() {
            return FlightOutcome::Failed;
        }
    }
}

/// The sink side of a fill: the upstream pump feeds chunks in; a blocking
/// writer thread appends them to the temp file and advances the watch.
pub struct FillSink {
    tx: tokio::sync::mpsc::Sender<FillMsg>,
    join: tokio::task::JoinHandle<std::io::Result<(u64, [u8; 32])>>,
}

enum FillMsg {
    Data(Vec<u8>),
    Eof,
}

pub struct FillJob {
    pub handle: Arc<FillHandle>,
    pub sink: FillSink,
    progress_tx: watch::Sender<FillProgress>,
}

/// Create the temp file and the writer thread for a new fill.
pub fn start_fill(
    key: [u8; 32],
    meta: FillMeta,
    temp_path: PathBuf,
    final_path: PathBuf,
) -> std::io::Result<FillJob> {
    let file = std::fs::File::create(&temp_path)?;
    let (progress_tx, progress_rx) = watch::channel(FillProgress {
        written: 0,
        state: FillState::Running,
    });
    let handle = Arc::new(FillHandle {
        key,
        meta,
        temp_path,
        final_path,
        progress: progress_rx,
    });
    let (tx, mut rx) = tokio::sync::mpsc::channel::<FillMsg>(32);
    let watch_tx = progress_tx.clone();
    let join = tokio::task::spawn_blocking(move || {
        use sha2::Digest;
        let mut out = file;
        let mut hasher = sha2::Sha256::new();
        let mut written: u64 = 0;
        loop {
            match rx.blocking_recv() {
                Some(FillMsg::Data(chunk)) => {
                    // Unbuffered on purpose: tail readers read through the
                    // filesystem, so every byte we announce must be write()n.
                    // Page-cache writes at network-chunk granularity are cheap.
                    out.write_all(&chunk)?;
                    hasher.update(&chunk);
                    written += chunk.len() as u64;
                    watch_tx.send_modify(|p| p.written = written);
                }
                Some(FillMsg::Eof) => {
                    out.sync_all()?;
                    return Ok((written, hasher.finalize().into()));
                }
                None => {
                    // Pump dropped without EOF: aborted fill.
                    return Err(std::io::Error::other("fill aborted"));
                }
            }
        }
    });
    Ok(FillJob {
        handle,
        sink: FillSink { tx, join },
        progress_tx,
    })
}

impl FillJob {
    pub async fn write(&self, chunk: Vec<u8>) -> std::io::Result<()> {
        self.sink
            .tx
            .send(FillMsg::Data(chunk))
            .await
            .map_err(|_| std::io::Error::other("fill writer died"))
    }

    /// Finish the disk side: flush, fsync, rename into place. Returns
    /// (total bytes, sha256). The caller commits metadata, then calls
    /// [`FillJob::complete`] / [`FillJob::fail`] to release tailing clients.
    pub async fn finish_disk(self) -> std::io::Result<(FinishedFill, u64, [u8; 32])> {
        let FillJob {
            handle,
            sink,
            progress_tx,
        } = self;
        let _ = sink.tx.send(FillMsg::Eof).await;
        let result = sink.join.await.map_err(std::io::Error::other)?;
        match result {
            Ok((written, sha)) => {
                let temp = handle.temp_path.clone();
                let fin = handle.final_path.clone();
                tokio::task::spawn_blocking(move || {
                    if let Some(parent) = fin.parent() {
                        std::fs::create_dir_all(parent)?;
                    }
                    std::fs::rename(&temp, &fin)
                })
                .await
                .map_err(std::io::Error::other)??;
                Ok((
                    FinishedFill {
                        handle,
                        progress_tx,
                    },
                    written,
                    sha,
                ))
            }
            Err(e) => {
                fail_fill(handle, progress_tx).await;
                Err(e)
            }
        }
    }

    /// Abort: stop the writer, remove the temp file, fail tailing clients.
    pub async fn abort(self) {
        let FillJob {
            handle,
            sink,
            progress_tx,
        } = self;
        drop(sink.tx); // writer sees closed channel -> error return
        let _ = sink.join.await;
        fail_fill(handle, progress_tx).await;
    }
}

async fn fail_fill(handle: Arc<FillHandle>, progress_tx: watch::Sender<FillProgress>) {
    let temp = handle.temp_path.clone();
    let _ = tokio::task::spawn_blocking(move || std::fs::remove_file(temp)).await;
    progress_tx.send_modify(|p| p.state = FillState::Failed);
    tracing::debug!("fill {} aborted", hex(&handle.key));
}

/// A fill whose bytes are safely on disk; flip the watch once metadata is
/// committed (or failed).
pub struct FinishedFill {
    pub handle: Arc<FillHandle>,
    progress_tx: watch::Sender<FillProgress>,
}

impl FinishedFill {
    pub fn complete(self) {
        self.progress_tx.send_modify(|p| p.state = FillState::Done);
    }

    pub fn fail(self) {
        // Metadata commit failed; the data file exists but is orphaned (the
        // patrol scrub will reap it). Clients get a truncation error.
        let fin = self.handle.final_path.clone();
        let _ = std::fs::remove_file(fin);
        self.progress_tx
            .send_modify(|p| p.state = FillState::Failed);
    }
}
