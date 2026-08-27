//! Unauthenticated read-only symbol serving at `/symbols/<path>` — the plain
//! HTTP layout dbghelp/symsrv clients expect, mapped onto the store root.
//!
//! Supports HEAD, single byte ranges, ETag/Last-Modified conditionals, and
//! on-the-fly gzip (skipped for range requests and already-CAB-compressed
//! `*_` payloads). No directory listings. `000Admin/`, `refs.ptr`, and our
//! scratch files are never served: they aren't part of the client protocol
//! and leak transaction history / original build paths.
//!
//! Local misses can be forwarded to upstream symbol servers and proxied
//! through transparently (old symsrv builds don't follow HTTP redirects
//! reliably, so we never redirect).

use std::path::{Path, PathBuf};
use std::time::SystemTime;

use axum::body::Body;
use axum::extract::{Path as AxPath, State};
use axum::http::{header, HeaderMap, Method, StatusCode};
use axum::response::{IntoResponse, Response};
use tokio_util::io::ReaderStream;

use crate::web::App;

const GZIP_MIN_SIZE: u64 = 1024;

fn plain(status: StatusCode, msg: &'static str) -> Response {
    (status, msg).into_response()
}

/// Validate and resolve a request path inside the store, case-insensitively
/// (dbghelp requests whatever case the debuggee's headers produced; the disk
/// has whatever case symstore wrote).
fn resolve(root: &Path, rel: &str) -> Option<PathBuf> {
    let mut clean: Vec<&str> = Vec::new();
    for comp in rel.split('/') {
        if comp.is_empty() || comp == "." || comp == ".." || comp.contains('\\') {
            return None;
        }
        clean.push(comp);
    }
    if clean.is_empty() {
        return None;
    }
    // Deny list: admin records, refcounts, and our scratch files.
    if clean[0].eq_ignore_ascii_case("000admin") {
        return None;
    }
    for comp in &clean {
        if comp.starts_with(".symfront") || comp.starts_with("_symfront") {
            return None;
        }
    }
    if clean
        .last()
        .map(|c| c.eq_ignore_ascii_case("refs.ptr"))
        .unwrap_or(false)
    {
        return None;
    }

    let mut path = root.to_path_buf();
    for comp in clean {
        let exact = path.join(comp);
        if exact.exists() {
            path = exact;
            continue;
        }
        // Case-insensitive fallback.
        let mut found = None;
        if let Ok(rd) = std::fs::read_dir(&path) {
            for ent in rd.flatten() {
                if ent.file_name().to_string_lossy().eq_ignore_ascii_case(comp) {
                    found = Some(ent.path());
                    break;
                }
            }
        }
        path = found?;
    }
    path.is_file().then_some(path)
}

fn etag_of(md: &std::fs::Metadata) -> String {
    use std::os::unix::fs::MetadataExt;
    format!("\"{:x}-{:x}-{:x}\"", md.ino(), md.mtime(), md.len())
}

fn content_type(path: &Path) -> &'static str {
    match path.extension().and_then(|e| e.to_str()) {
        Some("txt") => "text/plain",
        _ => "application/octet-stream",
    }
}

/// Parse a single `bytes=a-b` range against `len`. Returns (start, end
/// inclusive), or Err(()) for an unsatisfiable range. Multi-range requests
/// fall back to a full response (allowed by RFC 9110).
fn parse_range(spec: &str, len: u64) -> Result<Option<(u64, u64)>, ()> {
    let Some(ranges) = spec.strip_prefix("bytes=") else {
        return Ok(None);
    };
    if ranges.contains(',') || len == 0 {
        return if len == 0 { Err(()) } else { Ok(None) };
    }
    let (a, b) = ranges.split_once('-').ok_or(())?;
    let (a, b) = (a.trim(), b.trim());
    match (a.is_empty(), b.is_empty()) {
        (true, false) => {
            // suffix: last N bytes
            let n: u64 = b.parse().map_err(|_| ())?;
            if n == 0 {
                return Err(());
            }
            Ok(Some((len.saturating_sub(n), len - 1)))
        }
        (false, true) => {
            let start: u64 = a.parse().map_err(|_| ())?;
            if start >= len {
                return Err(());
            }
            Ok(Some((start, len - 1)))
        }
        (false, false) => {
            let start: u64 = a.parse().map_err(|_| ())?;
            let end: u64 = b.parse().map_err(|_| ())?;
            if start > end || start >= len {
                return Err(());
            }
            Ok(Some((start, end.min(len - 1))))
        }
        (true, true) => Err(()),
    }
}

fn header_str<'h>(headers: &'h HeaderMap, name: header::HeaderName) -> Option<&'h str> {
    headers.get(name).and_then(|v| v.to_str().ok())
}

pub(crate) async fn serve_symbol(
    State(state): State<App>,
    AxPath(rel): AxPath<String>,
    method: Method,
    headers: HeaderMap,
) -> Response {
    if method != Method::GET && method != Method::HEAD {
        return plain(StatusCode::METHOD_NOT_ALLOWED, "GET/HEAD only");
    }
    let Some(path) = resolve(state.store.root(), &rel) else {
        return miss(&state, &rel, &headers, &method).await;
    };
    match serve_local(&state, &path, &method, &headers).await {
        Ok(resp) => resp,
        Err(e) => {
            tracing::warn!("serving {}: {e}", path.display());
            plain(StatusCode::INTERNAL_SERVER_ERROR, "read error")
        }
    }
}

async fn serve_local(
    _state: &App,
    path: &Path,
    method: &Method,
    headers: &HeaderMap,
) -> anyhow::Result<Response> {
    let md = tokio::fs::metadata(path).await?;
    let len = md.len();
    let etag = etag_of(&md);
    let modified: SystemTime = md.modified()?;
    let last_modified = httpdate::fmt_http_date(modified);

    let mut base = Response::builder()
        .header(header::ETAG, &etag)
        .header(header::LAST_MODIFIED, &last_modified)
        .header(header::ACCEPT_RANGES, "bytes")
        .header(header::VARY, "Accept-Encoding")
        .header(header::CONTENT_TYPE, content_type(path));

    // Conditional GET: If-None-Match wins over If-Modified-Since.
    if let Some(inm) = header_str(headers, header::IF_NONE_MATCH) {
        if inm == "*" || inm.split(',').any(|t| t.trim() == etag) {
            return Ok(base
                .status(StatusCode::NOT_MODIFIED)
                .body(Body::empty())?
                .into_response());
        }
    } else if let Some(ims) = header_str(headers, header::IF_MODIFIED_SINCE) {
        if let Ok(since) = httpdate::parse_http_date(ims) {
            // mtime truncated to seconds for a fair comparison.
            let mtime_secs = modified
                .duration_since(SystemTime::UNIX_EPOCH)
                .map(|d| d.as_secs())
                .unwrap_or(0);
            let since_secs = since
                .duration_since(SystemTime::UNIX_EPOCH)
                .map(|d| d.as_secs())
                .unwrap_or(0);
            if mtime_secs <= since_secs {
                return Ok(base
                    .status(StatusCode::NOT_MODIFIED)
                    .body(Body::empty())?
                    .into_response());
            }
        }
    }

    // Range, honoring If-Range (mismatched validator => send the full body).
    let mut range = None;
    if let Some(spec) = header_str(headers, header::RANGE) {
        let validator_ok = match header_str(headers, header::IF_RANGE) {
            None => true,
            Some(v) => v == etag || v == last_modified,
        };
        if validator_ok {
            match parse_range(spec, len) {
                Ok(r) => range = r,
                Err(()) => {
                    return Ok(Response::builder()
                        .status(StatusCode::RANGE_NOT_SATISFIABLE)
                        .header(header::CONTENT_RANGE, format!("bytes */{len}"))
                        .body(Body::empty())?
                        .into_response());
                }
            }
        }
    }

    // gzip only for full-body responses of compressible payloads.
    let already_cab = path
        .file_name()
        .and_then(|n| n.to_str())
        .map(|n| n.ends_with('_'))
        .unwrap_or(false);
    let want_gzip = range.is_none()
        && len >= GZIP_MIN_SIZE
        && !already_cab
        && header_str(headers, header::ACCEPT_ENCODING)
            .map(|v| v.split(',').any(|e| e.trim().split(';').next() == Some("gzip")))
            .unwrap_or(false);

    let (status, start, count) = match range {
        Some((s, e)) => {
            base = base.header(header::CONTENT_RANGE, format!("bytes {s}-{e}/{len}"));
            (StatusCode::PARTIAL_CONTENT, s, e - s + 1)
        }
        None => (StatusCode::OK, 0, len),
    };

    if *method == Method::HEAD {
        let base = if want_gzip {
            base.header(header::CONTENT_ENCODING, "gzip")
        } else {
            base.header(header::CONTENT_LENGTH, count)
        };
        return Ok(base.status(status).body(Body::empty())?.into_response());
    }

    let mut file = tokio::fs::File::open(path).await?;
    if start > 0 {
        use tokio::io::AsyncSeekExt;
        file.seek(std::io::SeekFrom::Start(start)).await?;
    }
    use tokio::io::AsyncReadExt;
    let limited = file.take(count);
    if want_gzip {
        let encoder = async_compression::tokio::bufread::GzipEncoder::with_quality(
            tokio::io::BufReader::new(limited),
            async_compression::Level::Fastest,
        );
        Ok(base
            .status(status)
            .header(header::CONTENT_ENCODING, "gzip")
            .body(Body::from_stream(ReaderStream::new(encoder)))?
            .into_response())
    } else {
        Ok(base
            .status(status)
            .header(header::CONTENT_LENGTH, count)
            .body(Body::from_stream(ReaderStream::new(limited)))?
            .into_response())
    }
}

/// Local miss: try upstream symbol servers in order, proxying the response
/// through (no redirects — symsrv clients don't follow them reliably).
async fn miss(state: &App, rel: &str, headers: &HeaderMap, method: &Method) -> Response {
    if state.upstreams.is_empty() {
        return plain(StatusCode::NOT_FOUND, "file not found");
    }
    for upstream in &state.upstreams {
        let mut url = match reqwest::Url::parse(upstream) {
            Ok(u) => u,
            Err(_) => continue,
        };
        {
            let Ok(mut segs) = url.path_segments_mut() else {
                continue;
            };
            segs.pop_if_empty().extend(rel.split('/'));
        }
        let client = &state.http_client;
        let mut req = match *method {
            Method::HEAD => client.head(url.clone()),
            _ => client.get(url.clone()),
        };
        // Pass ranges through; keep the transfer identity-encoded so lengths
        // and ranges stay meaningful end to end.
        if let Some(range) = header_str(headers, header::RANGE) {
            req = req.header(header::RANGE, range);
        }
        req = req.header(header::ACCEPT_ENCODING, "identity");
        match req.send().await {
            Ok(resp) if resp.status().is_success() => {
                tracing::debug!("upstream hit: {url}");
                let status = StatusCode::from_u16(resp.status().as_u16())
                    .unwrap_or(StatusCode::OK);
                let mut builder = Response::builder().status(status);
                for name in [
                    header::CONTENT_LENGTH,
                    header::CONTENT_TYPE,
                    header::CONTENT_RANGE,
                    header::LAST_MODIFIED,
                    header::ETAG,
                    header::ACCEPT_RANGES,
                ] {
                    if let Some(v) = resp.headers().get(&name) {
                        builder = builder.header(name, v.clone());
                    }
                }
                builder = builder.header("x-symfront-upstream", upstream.as_str());
                let body = Body::from_stream(resp.bytes_stream());
                match builder.body(body) {
                    Ok(r) => return r.into_response(),
                    Err(_) => continue,
                }
            }
            Ok(resp) => {
                tracing::debug!("upstream {url}: {}", resp.status());
            }
            Err(e) => {
                tracing::warn!("upstream {upstream} unreachable: {e}");
            }
        }
    }
    plain(StatusCode::NOT_FOUND, "file not found (upstreams missed too)")
}
