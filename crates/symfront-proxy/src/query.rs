//! Symbol-server URI layouts.
//!
//! A *layout* is a bidirectional codec between raw request URL paths and a
//! layout-independent description of the symbol being requested
//! ([`SymbolQuery`]):
//!
//! - [`classify_request`] parses an inbound request path into a `SymbolQuery`
//!   (or `None` if no layout recognizes it → 404, no cache write).
//! - [`render`] produces the URL an upstream speaking a given layout would
//!   serve that query at (or `None` if it can't).
//!
//! This is the single seam through which upstream request URLs are produced.
//!
//! Two layouts exist:
//!
//! - **symstore** — Microsoft SymbolStore / SSQP, `/<name>/<id>/<name>`.
//!   PE/COFF requests pass through verbatim (stable URLs and cache keys).
//!   ELF/Mach-O requests carry their identity in the middle `<id>` field
//!   (`elf-buildid[-sym]-<hex>` / `mach-uuid[-sym]-<hex>`), decoded so other
//!   layouts can render them. Malformed marked ids are rejected outright (no
//!   PE fallback).
//! - **debuginfod** — `/buildid/<hex>/{debuginfo,executable,source/<path>}`.
//!   Renders canonically from the decoded build-id, so a Sentry-style
//!   SymbolStore ELF request and a native debuginfod request converge on one
//!   URL → one cache entry per upstream.
//!
//! Ported 1:1 from the Python implementation; behavior is pinned by
//! `tests/data/layout-goldens.json` (435 vectors generated from it).

use serde::{Deserialize, Serialize};

/// The binary/symbol family a request refers to.
#[derive(Copy, Clone, PartialEq, Eq, Hash, Debug, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Family {
    /// PE/COFF/PDB — the Windows world.
    Pe,
    Elf,
    Macho,
}

/// What kind of artifact a request is for.
#[derive(Copy, Clone, PartialEq, Eq, Hash, Debug, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Role {
    /// The binary itself (.dll/.exe/.sys, ELF executable, …).
    Image,
    /// Debug info / symbols (.pdb/.snupkg, ELF debuginfo, …).
    Debug,
    /// Source file (debuginfod only).
    Source,
}

/// The URI layout a request arrived in / an upstream speaks.
#[derive(Copy, Clone, PartialEq, Eq, Hash, Debug, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum LayoutKind {
    Symstore,
    Debuginfod,
}

impl LayoutKind {
    pub fn name(self) -> &'static str {
        match self {
            LayoutKind::Symstore => "symstore",
            LayoutKind::Debuginfod => "debuginfod",
        }
    }
}

/// A layout-independent description of the symbol a client asked for.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct SymbolQuery {
    pub family: Family,
    /// `None` means "unknown / any role" — e.g. SymbolStore index (.ptr)
    /// files, which are offered to every otherwise-eligible upstream.
    pub role: Option<Role>,
    /// Normalized (canonical, lowercase, with dot) file extension used for
    /// symstore fine-grained narrowing. `None` = don't narrow on extension.
    pub ext: Option<String>,
    /// The normalized inbound request path, e.g. `/foo.pdb/HASH/foo.pdb`.
    pub raw_path: String,
    /// The layout the request arrived in.
    pub inbound_layout: LayoutKind,
    /// Decoded identity for translatable families: the full lowercase-hex
    /// GNU build-id (ELF) or UUID (Mach-O). `None` for PE.
    pub ident: Option<String>,
    /// For debuginfod source requests, the path after `.../source/`.
    pub source_path: Option<String>,
}

fn is_hex(s: &str) -> bool {
    !s.is_empty() && s.bytes().all(|b| b.is_ascii_hexdigit())
}

/// SSQP middle-field markers → (family, role). Ordered longest-first so the
/// `-sym-` variants match before their bare prefixes.
const SSQP_MARKERS: &[(&str, Family, Role)] = &[
    ("elf-buildid-sym-", Family::Elf, Role::Debug),
    ("elf-buildid-", Family::Elf, Role::Image),
    ("mach-uuid-sym-", Family::Macho, Role::Debug),
    ("mach-uuid-", Family::Macho, Role::Image),
];

/// Compressed ("last character replaced with `_`") → canonical extension.
/// The upstream URL is still fetched verbatim (with the compressed
/// extension); this mapping only drives narrowing and role classification.
const SYMSTORE_COMPRESSED: &[(&str, &str)] = &[
    (".pd_", ".pdb"),
    (".dl_", ".dll"),
    (".ex_", ".exe"),
    (".sy_", ".sys"),
    (".db_", ".dbg"),
];

/// Recognized (canonical) symstore extensions and the role each implies.
const SYMSTORE_ROLES: &[(&str, Role)] = &[
    (".pdb", Role::Debug),
    (".snupkg", Role::Debug),
    (".dbg", Role::Debug),
    (".dll", Role::Image),
    (".exe", Role::Image),
    (".sys", Role::Image),
];

/// Extension of the final path component, Python `os.path.splitext` style:
/// the last dot in the basename, ignoring any leading dots (so ".bashrc" has
/// no extension and "foo." has extension ".").
fn split_ext(path: &str) -> &str {
    let base = path.rsplit('/').next().unwrap_or(path);
    let non_dot = base.find(|c| c != '.').unwrap_or(base.len());
    match base[non_dot..].rfind('.') {
        Some(i) => &base[non_dot + i..],
        None => "",
    }
}

fn classify_symstore(path: &str) -> Option<SymbolQuery> {
    // ELF / Mach-O requests carry their identity in the middle <id> field.
    // Decode those first (family/role/build-id); PE keys off the extension.
    let parts: Vec<&str> = path.split('/').collect();
    if parts.len() >= 3 {
        for (prefix, family, role) in SSQP_MARKERS {
            if let Some(ident) = parts[2].strip_prefix(prefix) {
                if !is_hex(ident) {
                    // Marked as ELF/Mach-O but malformed: reject outright.
                    tracing::warn!("malformed SSQP id field {:?} in {:?}", parts[2], path);
                    return None;
                }
                return Some(SymbolQuery {
                    family: *family,
                    role: Some(*role),
                    ext: None,
                    raw_path: path.to_string(),
                    inbound_layout: LayoutKind::Symstore,
                    ident: Some(ident.to_ascii_lowercase()),
                    source_path: None,
                });
            }
        }
    }

    let ext = split_ext(path).to_ascii_lowercase();
    let ext = SYMSTORE_COMPRESSED
        .iter()
        .find(|(c, _)| *c == ext)
        .map(|(_, canon)| canon.to_string())
        .unwrap_or(ext);

    if ext == ".ptr" {
        // Index pointer files carry no specific file type; let every
        // eligible upstream try them.
        return Some(SymbolQuery {
            family: Family::Pe,
            role: None,
            ext: None,
            raw_path: path.to_string(),
            inbound_layout: LayoutKind::Symstore,
            ident: None,
            source_path: None,
        });
    }

    let role = SYMSTORE_ROLES.iter().find(|(e, _)| *e == ext).map(|(_, r)| *r)?;
    Some(SymbolQuery {
        family: Family::Pe,
        role: Some(role),
        ext: Some(ext),
        raw_path: path.to_string(),
        inbound_layout: LayoutKind::Symstore,
        ident: None,
        source_path: None,
    })
}

fn classify_debuginfod(path: &str) -> Option<SymbolQuery> {
    // Keep the source remainder (which may itself contain slashes) intact.
    let parts: Vec<&str> = path.splitn(5, '/').collect();
    if parts.len() < 4 || !parts[0].is_empty() || parts[1] != "buildid" {
        return None;
    }
    let ident = parts[2];
    if !is_hex(ident) {
        return None;
    }
    let artifact = parts[3];
    if artifact == "source" {
        let source_path = if parts.len() == 5 { parts[4] } else { "" };
        if source_path.is_empty() {
            return None;
        }
        return Some(SymbolQuery {
            family: Family::Elf,
            role: Some(Role::Source),
            ext: None,
            raw_path: path.to_string(),
            inbound_layout: LayoutKind::Debuginfod,
            ident: Some(ident.to_ascii_lowercase()),
            source_path: Some(source_path.to_string()),
        });
    }
    let role = match artifact {
        "debuginfo" => Role::Debug,
        "executable" => Role::Image,
        _ => return None,
    };
    // Reject trailing junk after the artifact (e.g. /buildid/id/debuginfo/x).
    if parts.len() == 5 && !parts[4].is_empty() {
        return None;
    }
    Some(SymbolQuery {
        family: Family::Elf,
        role: Some(role),
        ext: None,
        raw_path: path.to_string(),
        inbound_layout: LayoutKind::Debuginfod,
        ident: Some(ident.to_ascii_lowercase()),
        source_path: None,
    })
}

/// Classify an inbound request path into a layout-independent `SymbolQuery`.
///
/// debuginfod is strict (`/buildid/...`) so it never swallows a symstore
/// path; symstore is the general fallback. `None` → 404, no cache write.
pub fn classify_request(path: &str) -> Option<SymbolQuery> {
    classify_debuginfod(path).or_else(|| classify_symstore(path))
}

/// Render the canonical URL an upstream speaking `layout` at `base_url`
/// would serve `query` at, or `None` if that layout can't express it.
pub fn render(layout: LayoutKind, base_url: &str, query: &SymbolQuery) -> Option<String> {
    match layout {
        LayoutKind::Symstore => {
            // A symstore upstream can only re-emit a request it received in
            // symstore form (it has no way to reconstruct the SSQP <name>
            // otherwise). Verbatim passthrough preserves exact URLs — and
            // therefore cache keys.
            if query.inbound_layout != LayoutKind::Symstore {
                return None;
            }
            Some(format!("{}{}", base_url.trim_end_matches('/'), query.raw_path))
        }
        LayoutKind::Debuginfod => {
            // Render canonically from the decoded identity (never from
            // raw_path), so SymbolStore-ELF and native debuginfod requests
            // converge on the same URL → the same cache entry.
            if query.family != Family::Elf {
                return None;
            }
            let ident = query.ident.as_deref().filter(|i| !i.is_empty())?;
            let base = format!("{}/buildid/{ident}", base_url.trim_end_matches('/'));
            match query.role {
                Some(Role::Debug) => Some(format!("{base}/debuginfo")),
                Some(Role::Image) => Some(format!("{base}/executable")),
                Some(Role::Source) => {
                    let sp = query.source_path.as_deref().filter(|s| !s.is_empty())?;
                    Some(format!("{base}/source/{sp}"))
                }
                None => None,
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn split_ext_python_compat() {
        assert_eq!(split_ext("/foo.pdb/HASH/foo.pdb"), ".pdb");
        assert_eq!(split_ext("/a/b/noext"), "");
        assert_eq!(split_ext("/a/b/.bashrc"), "");
        assert_eq!(split_ext("/a/b/..foo"), "");
        assert_eq!(split_ext("/a/b/foo."), ".");
        assert_eq!(split_ext("/a/b/foo.tar.gz"), ".gz");
    }
}
