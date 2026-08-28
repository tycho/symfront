//! Typed upstream symbol servers.
//!
//! An [`Upstream`] bundles a base URL with three orthogonal admission axes —
//!
//! - `binformat`: which binary/symbol families it hosts (pe / elf / macho)
//! - `provides`:  which roles it hosts (image / debug)
//! - `extensions`: optional finer, symstore-only file-extension narrowing
//!
//! — plus the URI `layout` it speaks. Given a [`SymbolQuery`] it decides
//! whether it can serve the request and, if so, renders the canonical URL to
//! fetch (via its layout). A request is sent to an upstream only if ALL
//! declared axes admit it.

use std::collections::HashSet;
use std::time::Duration;

use crate::query::{render, Family, LayoutKind, Role, SymbolQuery};

#[derive(Clone, Debug)]
pub struct Upstream {
    pub name: String,
    /// Disabled upstreams stay configured (and visible in the admin UI)
    /// but are never admitted, fanned out to, or probed.
    pub enabled: bool,
    pub base_url: String,
    pub layout: LayoutKind,
    pub binformat: HashSet<Family>,
    pub provides: HashSet<Role>,
    /// Lowercased canonical extensions (with dot); `None` = no narrowing.
    pub extensions: Option<HashSet<String>>,
    /// Fan-out tier: lower launches earlier (see stagger).
    pub priority: i32,
    /// Never cache responses from this upstream; always query it live.
    pub nocache: bool,
    /// Send `SymbolChecksum: invalid` when the client didn't provide one.
    pub requires_symbolchecksum: bool,
    /// Per-upstream negative-TTL ladder override (None = global default).
    pub negative_ttl: Option<Vec<Duration>>,
}

impl Upstream {
    pub fn cachable(&self) -> bool {
        !self.nocache
    }

    /// Whether this upstream could plausibly hold the requested artifact.
    pub fn accepts(&self, query: &SymbolQuery) -> bool {
        if !self.enabled {
            return false;
        }
        if !self.binformat.contains(&query.family) {
            return false;
        }
        // `provides` is the image/debug split; it doesn't narrow other roles
        // (SOURCE, or the None "any" role of symstore index files).
        if let Some(role @ (Role::Image | Role::Debug)) = query.role {
            if !self.provides.contains(&role) {
                return false;
            }
        }
        if let (Some(exts), Some(ext)) = (&self.extensions, &query.ext) {
            if !exts.contains(ext) {
                return false;
            }
        }
        true
    }

    /// The canonical URL to fetch for this query, or `None` if this upstream
    /// can't/shouldn't serve it.
    pub fn candidate_url(&self, query: &SymbolQuery) -> Option<String> {
        if !self.accepts(query) {
            return None;
        }
        render(self.layout, &self.base_url, query)
    }
}
