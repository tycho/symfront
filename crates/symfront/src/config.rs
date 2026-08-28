//! The symfront configuration tree: one directory of hand-editable TOML
//! files, versioned in a local git repository (see `config_store`).
//!
//! ```text
//! /etc/symfront/            # or any --config-dir
//!   server.toml             # listen (tcp/uds), trusted proxies, auth db,
//!                           # webauthn origin, log filter
//!   store.toml              # managed symbol store path
//!   proxy.toml              # cache path/size/mode, TTLs, health, stagger
//!   upstreams.toml          # [[upstream]] entries
//!   blacklist.toml          # request blacklists
//! ```
//!
//! Every file is optional; a missing file means "all defaults". CLI flags
//! override whatever the tree says, so ad-hoc runs never need a config dir.

use std::path::{Path, PathBuf};

use serde::Deserialize;

pub const SERVER_TOML: &str = "server.toml";
pub const STORE_TOML: &str = "store.toml";
pub const PROXY_TOML: &str = "proxy.toml";
pub const UPSTREAMS_TOML: &str = "upstreams.toml";
pub const BLACKLIST_TOML: &str = "blacklist.toml";

#[derive(Debug, Default, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ServerConfig {
    /// TCP listen address, e.g. "127.0.0.1:8710".
    pub listen: Option<String>,
    /// Unix domain socket path; takes precedence over `listen` (Unix only).
    pub uds: Option<PathBuf>,
    /// Socket file mode, octal (e.g. "0666"); default = whatever the
    /// process umask yields. Needed when the fronting proxy runs as a
    /// different user.
    pub uds_mode: Option<String>,
    /// Trusted reverse-proxy hop count for X-Forwarded-For / -Proto.
    pub trusted_proxies: Option<usize>,
    /// SQLite auth database; enables authentication.
    pub auth_db: Option<PathBuf>,
    /// Public origin for WebAuthn/passkeys.
    pub webauthn_origin: Option<String>,
    /// Default tracing filter (RUST_LOG still wins when set).
    pub log_filter: Option<String>,
}

#[derive(Debug, Default, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct StoreConfig {
    /// Path of the managed symbol store.
    pub path: Option<PathBuf>,
}

/// The parsed configuration tree. Proxy-related files are parsed by
/// symfront-proxy's own config types and only pass through here as raw text
/// presence; see `web` for where they are consumed.
#[derive(Debug, Default)]
pub struct ConfigTree {
    pub dir: Option<PathBuf>,
    pub server: ServerConfig,
    pub store: StoreConfig,
}

fn parse_file<T: serde::de::DeserializeOwned + Default>(path: &Path) -> anyhow::Result<T> {
    if !path.is_file() {
        return Ok(T::default());
    }
    let text =
        std::fs::read_to_string(path).map_err(|e| anyhow::anyhow!("{}: {e}", path.display()))?;
    toml::from_str(&text).map_err(|e| anyhow::anyhow!("{}: {e}", path.display()))
}

impl ConfigTree {
    /// Load the tree from `dir`. A missing directory yields all-defaults with
    /// `dir: None` (flag-only operation); parse errors are hard errors — a
    /// server must not come up half-configured.
    pub fn load(dir: &Path) -> anyhow::Result<ConfigTree> {
        if !dir.is_dir() {
            return Ok(ConfigTree::default());
        }
        Ok(ConfigTree {
            dir: Some(dir.to_path_buf()),
            server: parse_file(&dir.join(SERVER_TOML))?,
            store: parse_file(&dir.join(STORE_TOML))?,
        })
    }
}

/// Commented starter files for `symfront config init`.
pub const STARTER_FILES: &[(&str, &str)] = &[
    (
        SERVER_TOML,
        r#"# symfront server configuration.
# Every key is optional; CLI flags override anything set here.

# TCP listen address.
listen = "127.0.0.1:8710"

# Unix domain socket (takes precedence over `listen`; Unix only). Lower
# overhead when nginx proxies to us on the same host.
#uds = "/run/symfront/symfront.sock"

# Socket file mode (octal). The default is umask-derived; set 0666 (or 0660
# with a shared group) when the reverse proxy runs as a different user.
#uds_mode = "0666"

# Trusted reverse-proxy hop count. When > 0, the client IP comes from
# X-Forwarded-For (capped at this depth) and X-Forwarded-Proto: https marks
# session cookies Secure.
#trusted_proxies = 1

# SQLite auth database; enables authentication. Manage users with
# `symfront user` / `symfront token`. Without this the server is open.
#auth_db = "/var/lib/symfront/auth.db"

# Public origin for WebAuthn/passkeys, e.g. "https://syms.example.com".
#webauthn_origin = "https://syms.example.com"

# Default tracing filter (RUST_LOG overrides).
#log_filter = "symfront=info,tower_http=info"
"#,
    ),
    (
        STORE_TOML,
        r#"# The managed symbol store (tier 0 of the serving pipeline).

path = "/srv/symstore"
"#,
    ),
    (
        PROXY_TOML,
        r#"# Caching-proxy settings. See upstreams.toml for where misses go.

[cache]
# Proxy cache root (metadata db + data tree). Separate from the store:
# disposable by definition.
path = "/var/cache/symfront"

# Total size budget for positive cache entries. Eviction starts at the high
# watermark and stops at the low one, dropping soonest-expiring entries first.
size = "512GB"
#high_watermark = 1.0
#low_watermark = 0.95

# "standalone": stream cache hits ourselves (richer stats).
# "nginx": offload cache-hit bodies via X-Accel-Redirect.
mode = "standalone"
#accel_prefix = "/_symfront_cache"

[ttl]
# Positive TTL; slides on every hit.
positive = "365d"
# Negative-cache ladder: each re-confirmed miss advances one step; the last
# entry repeats. A single entry means a flat negative TTL.
negative = ["1h", "1h", "1h", "8h", "8h", "24h", "7d"]

[health]
# Suspended upstreams are probed with a HEAD every probe_interval; any
# complete HTTP response restores them.
probe_interval = "30s"
probe_timeout = "15s"

[fanout]
# Delay between launching successive priority tiers. 0 = flat fan-out.
stagger = "100ms"

[debuginfod]
# Queries with a build-id shorter than this (hex chars) are never offered
# to debuginfod upstreams — real GNU build-ids are 32-40 chars, and the
# servers 503 on shorter probes (Sentry emits some). 0 disables.
#min_buildid_hex = 32

[dns]
# Re-resolve every enabled upstream's hostname this often (A + AAAA via the
# system resolver), keeping OS and LAN DNS caches warm so requests never
# pay for a cold recursive lookup. No traffic reaches the upstreams.
# "0" disables.
#prewarm_interval = "60s"

[compression]
# Serve-side compression (tier 0 and cache hits). CAB-packed (*_) payloads
# are never recompressed.
#min_size = 4096
#gzip_level = 6
#zstd_level = 3
"#,
    ),
    (
        UPSTREAMS_TOML,
        r#"# Upstream symbol servers, fanned out to on cache misses.
#
# Each upstream declares a URI layout plus three admission axes:
#   layout     = "symstore" | "debuginfod"
#   binformat  = ["pe"]              # families: pe / elf / macho
#   provides   = ["image", "debug"]  # roles it hosts
#   extensions = [".pdb", ".dll"]    # optional symstore-only narrowing
# A request goes to an upstream only if ALL declared axes admit it.
#
# Other keys: priority (lower = earlier tier), nocache (never cache),
# requires_symbolchecksum, negative_ttl (per-upstream ladder override), and
# enabled = false to keep an entry configured (and visible in the UI)
# without using it.

#[[upstream]]
#name = "microsoft"
#layout = "symstore"
#binformat = ["pe"]
#base_url = "https://msdl.microsoft.com/download/symbols"

#[[upstream]]
#name = "archlinux"
#layout = "debuginfod"
#binformat = ["elf"]
#base_url = "https://debuginfod.archlinux.org"
"#,
    ),
    (
        BLACKLIST_TOML,
        r#"# Requests rejected before classification: 404, nothing cached, no
# upstream traffic. For whole classes of requests that have never and will
# never exist upstream.

# Reject any path containing one of these substrings.
[substring_blacklist]
names = []

# Reject any path ending with one of these suffixes.
[suffix_blacklist]
names = []

# Reject when the first path component matches exactly.
[first_path_component_blacklist]
names = [
    "index2.txt",
]
"#,
    ),
];
