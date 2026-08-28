//! Client-specific serving quirks.
//!
//! Ghidra's `HttpSymbolServer` (UA `Ghidra_HttpSymbolServer_client`,
//! java.net.http) sends no Accept-Encoding, so every transfer to it goes
//! uncompressed — but source inspection of `AbstractSymbolServer.find()`
//! shows it probes the CAB name (`foo.pd_`) whenever the `foo.pdb` HEAD
//! misses, and expands whatever CAB it gets (MSZIP included). The
//! `ghidra_cab` quirk exploits that known fallback: 404 requests for
//! payloads we already hold, then serve an on-the-fly MSZIP CAB (flate2 on
//! the zlib-rs backend, ~gzip ratio) for the `.pd_` follow-up.
//!
//! The quirk only ever engages for bodies already on disk (store or
//! positive cache); a first-time fetch takes the normal fill path and
//! streams the `.pdb` uncompressed. Caveat for operators: Ghidra builds
//! after the SevenZipJBinding removal need an external 7-Zip on the
//! analyst machine to expand CABs — without one, quirked lookups fail on
//! the client, so keep the knob off if such clients matter.

use std::path::Path;

use axum::body::Body;
use axum::http::{header, HeaderMap, Method, StatusCode};
use axum::response::{IntoResponse, Response};
use tokio_util::io::ReaderStream;

use crate::symbols::plain;

const GHIDRA_UA: &str = "Ghidra_HttpSymbolServer_client";

/// The exact client whose fallback behavior we know from source.
pub(crate) fn is_ghidra_no_accept_encoding(headers: &HeaderMap) -> bool {
    !headers.contains_key(header::ACCEPT_ENCODING)
        && headers
            .get(header::USER_AGENT)
            .and_then(|v| v.to_str().ok())
            .map(|ua| ua == GHIDRA_UA)
            .unwrap_or(false)
}

/// The symsrv compressed-name transform: `foo.pdb` -> `foo.pd_`
/// (matches Ghidra's `getCompressedFilename`).
fn compressed_name(name: &str) -> Option<String> {
    let (stem, ext) = name.rsplit_once('.')?;
    if ext.is_empty() || !ext.is_ascii() {
        return None;
    }
    Some(format!("{stem}.{}_", &ext[..ext.len() - 1]))
}

/// For a `/<name>/<id>/<name.xx_>` request, the real payload path
/// (`/<name>/<id>/<name>`) and the filename to embed in the CAB — but
/// only if the last component really is the symsrv compressed variant of
/// the first.
pub(crate) fn cab_target(path: &str) -> Option<(String, String)> {
    let mut parts = path.trim_matches('/').split('/');
    let (name, id, file) = (parts.next()?, parts.next()?, parts.next()?);
    if parts.next().is_some() || compressed_name(name)? != file {
        return None;
    }
    Some((format!("/{name}/{id}/{name}"), name.to_string()))
}

/// Serve `src` as a single-file MSZIP cabinet named `inner_name`. The CAB
/// is built into an anonymous temp file (the format needs Seek for its
/// header offsets/checksums) off the async runtime, then streamed.
pub(crate) async fn serve_cab(src: &Path, inner_name: &str, method: &Method) -> Response {
    let b = Response::builder()
        .status(StatusCode::OK)
        .header(header::CONTENT_TYPE, "application/octet-stream");
    if *method == Method::HEAD {
        // Ghidra's exists() probe; it tolerates an absent Content-Length.
        return b.body(Body::empty()).unwrap().into_response();
    }
    let src_for_task = src.to_path_buf();
    let name = inner_name.to_string();
    let built = tokio::task::spawn_blocking(move || -> std::io::Result<(std::fs::File, u64)> {
        use std::io::{Seek, SeekFrom};
        let mut builder = cab::CabinetBuilder::new();
        builder
            .add_folder(cab::CompressionType::MsZip)
            .add_file(name);
        let mut writer = builder.build(tempfile::tempfile()?)?;
        while let Some(mut fw) = writer.next_file()? {
            std::io::copy(&mut std::fs::File::open(&src_for_task)?, &mut fw)?;
        }
        let mut f = writer.finish()?;
        let len = f.seek(SeekFrom::End(0))?;
        f.seek(SeekFrom::Start(0))?;
        Ok((f, len))
    })
    .await;
    match built {
        Ok(Ok((file, len))) => b
            .header(header::CONTENT_LENGTH, len)
            .body(Body::from_stream(ReaderStream::with_capacity(
                tokio::fs::File::from_std(file),
                1 << 20,
            )))
            .unwrap()
            .into_response(),
        Ok(Err(e)) => {
            tracing::warn!("building CAB for {}: {e:#}", src.display());
            plain(StatusCode::INTERNAL_SERVER_ERROR, "cab build error")
        }
        Err(e) => {
            tracing::warn!("CAB build task for {}: {e:#}", src.display());
            plain(StatusCode::INTERNAL_SERVER_ERROR, "cab build error")
        }
    }
}
