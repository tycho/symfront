//! Read-only file serving for symbol payloads — used by tier 0 (the managed
//! store) and by proxy cache hits in standalone mode.
//!
//! Supports HEAD, single byte ranges, ETag/Last-Modified conditionals, and
//! negotiated compression (zstd preferred, gzip fallback; never for
//! already-CAB-compressed `*_` payloads, range responses, or bodies under
//! the configured floor). No directory listings. `000Admin/`, `refs.ptr`,
//! and our scratch files are never served: they aren't part of the client
//! protocol and leak transaction history / original build paths.

use std::path::{Path, PathBuf};
use std::time::SystemTime;

use axum::body::Body;
use axum::http::{header, HeaderMap, Method, StatusCode};
use axum::response::{IntoResponse, Response};
use symfront_proxy::config::CompressionConfig;
use tokio_util::io::ReaderStream;

pub(crate) fn plain(status: StatusCode, msg: &'static str) -> Response {
    (status, msg).into_response()
}

/// Validate and resolve a request path inside the store, case-insensitively
/// (dbghelp requests whatever case the debuggee's headers produced; the disk
/// has whatever case symstore wrote).
pub(crate) fn resolve(root: &Path, rel: &str) -> Option<PathBuf> {
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
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        format!("\"{:x}-{:x}-{:x}\"", md.ino(), md.mtime(), md.len())
    }
    #[cfg(not(unix))]
    {
        let mtime = md
            .modified()
            .ok()
            .and_then(|t| t.duration_since(SystemTime::UNIX_EPOCH).ok())
            .map(|d| d.as_secs())
            .unwrap_or(0);
        format!("\"{:x}-{:x}\"", mtime, md.len())
    }
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

pub(crate) fn header_str(headers: &HeaderMap, name: header::HeaderName) -> Option<&str> {
    headers.get(name).and_then(|v| v.to_str().ok())
}

/// Compression negotiated for a response body.
enum Encoding {
    Identity,
    Gzip,
    Zstd,
}

fn negotiate_encoding(
    headers: &HeaderMap,
    path: &Path,
    len: u64,
    ranged: bool,
    comp: &CompressionConfig,
) -> Encoding {
    if ranged || len < comp.min_size {
        return Encoding::Identity;
    }
    // Never recompress CAB-packed payloads (symstore `*_` names).
    let cab = path
        .file_name()
        .and_then(|n| n.to_str())
        .map(|n| n.ends_with('_'))
        .unwrap_or(false);
    if cab {
        return Encoding::Identity;
    }
    let accepts = |wanted: &str| {
        header_str(headers, header::ACCEPT_ENCODING)
            .map(|v| {
                v.split(',')
                    .any(|e| e.trim().split(';').next() == Some(wanted))
            })
            .unwrap_or(false)
    };
    // zstd first for clients that negotiate it; gzip as the broad fallback.
    if accepts("zstd") {
        Encoding::Zstd
    } else if accepts("gzip") {
        Encoding::Gzip
    } else {
        Encoding::Identity
    }
}

/// Optional header overrides for cache-hit serving (validators recorded at
/// fill time beat filesystem-derived ones).
#[derive(Default)]
pub(crate) struct ServeOverrides {
    pub etag: Option<String>,
    pub last_modified: Option<String>,
    /// Offload the body to the front proxy: `(header name, target)`,
    /// e.g. `("X-Sendfile", "/srv/symstore/foo.pdb/…/foo.pdb")`. The
    /// proxy applies Range and content negotiation against the file
    /// itself; we still answer conditionals (304s carry no body anyway).
    pub accel: Option<(&'static str, String)>,
}

/// Serve a file with conditionals, ranges, and negotiated compression.
pub(crate) async fn serve_file(
    path: &Path,
    method: &Method,
    headers: &HeaderMap,
    comp: &CompressionConfig,
    overrides: ServeOverrides,
) -> anyhow::Result<Response> {
    let md = tokio::fs::metadata(path).await?;
    let len = md.len();
    let etag = overrides.etag.unwrap_or_else(|| etag_of(&md));
    let last_modified = match overrides.last_modified {
        Some(lm) => lm,
        None => httpdate::fmt_http_date(md.modified()?),
    };
    let modified: SystemTime =
        httpdate::parse_http_date(&last_modified).unwrap_or(SystemTime::UNIX_EPOCH);

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

    if let Some((accel_header, target)) = overrides.accel {
        let base = base.status(StatusCode::OK);
        return Ok(if *method == Method::HEAD {
            base.header(header::CONTENT_LENGTH, len)
        } else {
            base.header(accel_header, target)
        }
        .body(Body::empty())?
        .into_response());
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

    let encoding = negotiate_encoding(headers, path, len, range.is_some(), comp);

    let (status, start, count) = match range {
        Some((s, e)) => {
            base = base.header(header::CONTENT_RANGE, format!("bytes {s}-{e}/{len}"));
            (StatusCode::PARTIAL_CONTENT, s, e - s + 1)
        }
        None => (StatusCode::OK, 0, len),
    };

    if *method == Method::HEAD {
        let base = match encoding {
            Encoding::Gzip => base.header(header::CONTENT_ENCODING, "gzip"),
            Encoding::Zstd => base.header(header::CONTENT_ENCODING, "zstd"),
            Encoding::Identity => base.header(header::CONTENT_LENGTH, count),
        };
        return Ok(base.status(status).body(Body::empty())?.into_response());
    }

    let mut file = tokio::fs::File::open(path).await?;
    if start > 0 {
        use tokio::io::AsyncSeekExt;
        file.seek(std::io::SeekFrom::Start(start)).await?;
    }
    use tokio::io::AsyncReadExt;
    let limited = tokio::io::BufReader::with_capacity(1 << 20, file.take(count));
    match encoding {
        Encoding::Gzip => {
            let encoder = async_compression::tokio::bufread::GzipEncoder::with_quality(
                limited,
                async_compression::Level::Precise(comp.gzip_level as i32),
            );
            Ok(base
                .status(status)
                .header(header::CONTENT_ENCODING, "gzip")
                .body(Body::from_stream(ReaderStream::new(encoder)))?
                .into_response())
        }
        Encoding::Zstd => {
            let encoder = async_compression::tokio::bufread::ZstdEncoder::with_quality(
                limited,
                async_compression::Level::Precise(comp.zstd_level),
            );
            Ok(base
                .status(status)
                .header(header::CONTENT_ENCODING, "zstd")
                .body(Body::from_stream(ReaderStream::new(encoder)))?
                .into_response())
        }
        Encoding::Identity => Ok(base
            .status(status)
            .header(header::CONTENT_LENGTH, count)
            .body(Body::from_stream(ReaderStream::with_capacity(
                limited,
                1 << 20,
            )))?
            .into_response()),
    }
}
