//! Proxy configuration: `proxy.toml`, `upstreams.toml`, `blacklist.toml`.
//!
//! All durations are strings like "100ms", "30s", "5m", "8h", "7d" (or plain
//! integer seconds); sizes are strings like "512GB" / "64GiB" (or plain
//! integer bytes). Decimal suffixes are powers of 1000, `i` suffixes powers
//! of 1024.

use std::collections::HashSet;
use std::path::{Path, PathBuf};
use std::time::Duration;

use serde::Deserialize;

use crate::blacklist::Blacklist;
use crate::query::{Family, LayoutKind, Role};
use crate::upstream::Upstream;

#[derive(thiserror::Error, Debug)]
pub enum ConfigError {
    #[error("{0}")]
    Invalid(String),
    #[error("{path}: {source}")]
    Io {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },
    #[error("{path}: {source}")]
    Toml {
        path: PathBuf,
        #[source]
        source: Box<toml::de::Error>,
    },
}

fn invalid(msg: impl Into<String>) -> ConfigError {
    ConfigError::Invalid(msg.into())
}

pub fn parse_duration(s: &str) -> Result<Duration, ConfigError> {
    let s = s.trim();
    let split = s
        .find(|c: char| !c.is_ascii_digit() && c != '.')
        .unwrap_or(s.len());
    let (num, unit) = s.split_at(split);
    let value: f64 = num
        .parse()
        .map_err(|_| invalid(format!("bad duration {s:?}")))?;
    let secs = match unit.trim() {
        "" | "s" => value,
        "ms" => value / 1000.0,
        "m" => value * 60.0,
        "h" => value * 3600.0,
        "d" => value * 86400.0,
        u => return Err(invalid(format!("bad duration unit {u:?} in {s:?}"))),
    };
    if !secs.is_finite() || secs < 0.0 {
        return Err(invalid(format!("bad duration {s:?}")));
    }
    Ok(Duration::from_secs_f64(secs))
}

pub fn parse_size(s: &str) -> Result<u64, ConfigError> {
    let s = s.trim();
    let split = s
        .find(|c: char| !c.is_ascii_digit() && c != '.')
        .unwrap_or(s.len());
    let (num, unit) = s.split_at(split);
    let value: f64 = num
        .parse()
        .map_err(|_| invalid(format!("bad size {s:?}")))?;
    let unit = unit.trim().to_ascii_lowercase();
    let mult: u64 = match unit.as_str() {
        "" | "b" => 1,
        "k" | "kb" => 1000,
        "m" | "mb" => 1000 * 1000,
        "g" | "gb" => 1000 * 1000 * 1000,
        "t" | "tb" => 1000u64.pow(4),
        "ki" | "kib" => 1 << 10,
        "mi" | "mib" => 1 << 20,
        "gi" | "gib" => 1 << 30,
        "ti" | "tib" => 1 << 40,
        u => return Err(invalid(format!("bad size unit {u:?} in {s:?}"))),
    };
    Ok((value * mult as f64) as u64)
}

/// TTL policy: sliding positive TTL + escalating negative ladder.
#[derive(Clone, Debug)]
pub struct TtlPolicy {
    pub positive: Duration,
    /// Escalating negative-cache ladder; the last entry repeats. A single
    /// entry is a flat negative TTL.
    pub negative: Vec<Duration>,
}

impl Default for TtlPolicy {
    fn default() -> Self {
        TtlPolicy {
            positive: Duration::from_secs(365 * 86400),
            negative: ["1h", "1h", "1h", "8h", "8h", "24h", "7d"]
                .iter()
                .map(|s| parse_duration(s).unwrap())
                .collect(),
        }
    }
}

impl TtlPolicy {
    /// TTL for a negative entry at ladder step `step` (clamped to the end).
    pub fn negative_ttl(&self, step: u32) -> Duration {
        *self
            .negative
            .get(step as usize)
            .or_else(|| self.negative.last())
            .expect("ladder is never empty")
    }

    pub fn max_step(&self) -> u32 {
        (self.negative.len() - 1) as u32
    }
}

/// How cache-hit bodies reach the client.
#[derive(Copy, Clone, PartialEq, Eq, Debug, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum CacheMode {
    /// Stream cache hits ourselves (richer stats).
    Standalone,
    /// Offload cache-hit bodies to nginx via X-Accel-Redirect.
    Nginx,
    /// Offload cache-hit bodies to lighttpd via X-Sendfile. Unlike nginx's
    /// internal-location URIs, lighttpd expects an absolute filesystem
    /// path, so `accel_prefix` must be the cache data directory itself.
    Lighttpd,
}

impl CacheMode {
    /// Response header carrying the offload path in the accel modes.
    pub fn accel_header(self) -> &'static str {
        match self {
            CacheMode::Lighttpd => "X-Sendfile",
            _ => "X-Accel-Redirect",
        }
    }
}

#[derive(Clone, Debug)]
pub struct ProxyConfig {
    pub cache_path: PathBuf,
    /// Total positive-entry size budget; `None` disables eviction.
    pub cache_size: Option<u64>,
    /// Eviction starts above `high_watermark * cache_size` …
    pub high_watermark: f64,
    /// … and stops below `low_watermark * cache_size`.
    pub low_watermark: f64,
    pub mode: CacheMode,
    /// Internal-location prefix for X-Accel-Redirect responses.
    pub accel_prefix: String,
    /// Also offload tier-0 (managed store) hits in the accel modes:
    /// header value is this prefix + the path relative to the store root.
    /// For lighttpd this is the absolute store root itself; for nginx an
    /// internal location aliasing it. `None` streams store hits ourselves.
    pub accel_store_prefix: Option<String>,
    pub ttl: TtlPolicy,
    pub health_probe_interval: Duration,
    pub health_probe_timeout: Duration,
    /// Delay between launching successive priority tiers (0 = flat).
    pub stagger: Duration,
    pub connect_timeout: Duration,
    pub read_timeout: Duration,
    /// Minimum build-id length (hex chars) for a query to be offered to
    /// debuginfod upstreams. Real GNU build-ids are 32-40 hex chars;
    /// Sentry probes PE modules through SSQP ELF keys with 13-char
    /// timestamp+size pseudo-ids, which every debuginfod server rejects
    /// with a 503. 0 disables the guard.
    pub min_buildid_hex: usize,
    /// Re-resolve every enabled upstream's hostname this often, keeping
    /// OS/LAN DNS caches warm so client requests never pay for a cold
    /// recursive lookup (no traffic to the upstream itself). 0 disables.
    pub dns_prewarm_interval: Duration,
    /// Ghidra's HTTP client sends no Accept-Encoding, so its transfers
    /// are never compressed — but source inspection shows it falls back
    /// to the CAB name (`foo.pd_`) on a `.pdb` miss and expands it. This
    /// quirk 404s `.pdb` requests from that exact client when we already
    /// hold the payload, then serves an on-the-fly MSZIP CAB for the
    /// `.pd_` follow-up. Never applies to fills (a first-time fetch
    /// streams the `.pdb` normally).
    pub ghidra_cab_quirk: bool,
    pub compression: CompressionConfig,
}

#[derive(Clone, Debug)]
pub struct CompressionConfig {
    /// Responses smaller than this are never compressed.
    pub min_size: u64,
    pub gzip_level: u32,
    pub zstd_level: i32,
}

impl Default for CompressionConfig {
    fn default() -> Self {
        CompressionConfig {
            min_size: 4096,
            gzip_level: 6,
            zstd_level: 3,
        }
    }
}

impl Default for ProxyConfig {
    fn default() -> Self {
        ProxyConfig {
            cache_path: PathBuf::from("/var/cache/symfront"),
            cache_size: None,
            high_watermark: 1.0,
            low_watermark: 0.95,
            mode: CacheMode::Standalone,
            accel_prefix: "/_symfront_cache".into(),
            accel_store_prefix: None,
            ttl: TtlPolicy::default(),
            health_probe_interval: Duration::from_secs(30),
            health_probe_timeout: Duration::from_secs(15),
            stagger: Duration::from_millis(100),
            connect_timeout: Duration::from_secs(5),
            read_timeout: Duration::from_secs(20),
            min_buildid_hex: 32,
            dns_prewarm_interval: Duration::from_secs(60),
            ghidra_cab_quirk: false,
            compression: CompressionConfig::default(),
        }
    }
}

// ---------------------------------------------------------------------------
// Raw TOML shapes
// ---------------------------------------------------------------------------

#[derive(Deserialize, Default)]
#[serde(deny_unknown_fields)]
struct RawProxy {
    #[serde(default)]
    cache: RawCache,
    #[serde(default)]
    ttl: RawTtl,
    #[serde(default)]
    health: RawHealth,
    #[serde(default)]
    fanout: RawFanout,
    #[serde(default)]
    debuginfod: RawDebuginfod,
    #[serde(default)]
    dns: RawDns,
    #[serde(default)]
    compression: RawCompression,
    #[serde(default)]
    quirks: RawQuirks,
}

#[derive(Deserialize, Default)]
#[serde(deny_unknown_fields)]
struct RawQuirks {
    ghidra_cab: Option<bool>,
}

#[derive(Deserialize, Default)]
#[serde(deny_unknown_fields)]
struct RawCache {
    path: Option<PathBuf>,
    size: Option<String>,
    high_watermark: Option<f64>,
    low_watermark: Option<f64>,
    mode: Option<CacheMode>,
    accel_prefix: Option<String>,
    accel_store_prefix: Option<String>,
}

#[derive(Deserialize, Default)]
#[serde(deny_unknown_fields)]
struct RawTtl {
    positive: Option<String>,
    negative: Option<Vec<String>>,
}

#[derive(Deserialize, Default)]
#[serde(deny_unknown_fields)]
struct RawHealth {
    probe_interval: Option<String>,
    probe_timeout: Option<String>,
}

#[derive(Deserialize, Default)]
#[serde(deny_unknown_fields)]
struct RawFanout {
    stagger: Option<String>,
    connect_timeout: Option<String>,
    read_timeout: Option<String>,
}

#[derive(Deserialize, Default)]
#[serde(deny_unknown_fields)]
struct RawDebuginfod {
    min_buildid_hex: Option<usize>,
}

#[derive(Deserialize, Default)]
#[serde(deny_unknown_fields)]
struct RawDns {
    prewarm_interval: Option<String>,
}

#[derive(Deserialize, Default)]
#[serde(deny_unknown_fields)]
struct RawCompression {
    min_size: Option<u64>,
    gzip_level: Option<u32>,
    zstd_level: Option<i32>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawUpstream {
    name: String,
    base_url: String,
    layout: Option<LayoutKind>,
    binformat: Option<Vec<Family>>,
    provides: Option<Vec<Role>>,
    extensions: Option<Vec<String>>,
    priority: Option<i32>,
    /// Keep the entry (and show it in the UI) but don't use it.
    enabled: Option<bool>,
    #[serde(default)]
    nocache: bool,
    #[serde(default)]
    requires_symbolchecksum: bool,
    negative_ttl: Option<Vec<String>>,
}

#[derive(Deserialize, Default)]
struct RawUpstreams {
    #[serde(default)]
    upstream: Vec<RawUpstream>,
}

#[derive(Deserialize, Default)]
struct RawNames {
    #[serde(default)]
    names: Vec<String>,
}

#[derive(Deserialize, Default)]
#[serde(deny_unknown_fields)]
struct RawBlacklist {
    #[serde(default)]
    substring_blacklist: RawNames,
    #[serde(default)]
    suffix_blacklist: RawNames,
    #[serde(default)]
    first_path_component_blacklist: RawNames,
}

fn read_toml<T: serde::de::DeserializeOwned + Default>(path: &Path) -> Result<T, ConfigError> {
    if !path.is_file() {
        return Ok(T::default());
    }
    let text = std::fs::read_to_string(path).map_err(|e| ConfigError::Io {
        path: path.to_path_buf(),
        source: e,
    })?;
    toml::from_str(&text).map_err(|e| ConfigError::Toml {
        path: path.to_path_buf(),
        source: Box::new(e),
    })
}

fn durations(specs: &[String], what: &str) -> Result<Vec<Duration>, ConfigError> {
    if specs.is_empty() {
        return Err(invalid(format!("{what} must not be empty")));
    }
    specs.iter().map(|s| parse_duration(s)).collect()
}

impl ProxyConfig {
    pub fn from_file(path: &Path) -> Result<ProxyConfig, ConfigError> {
        let raw: RawProxy = read_toml(path)?;
        let mut cfg = ProxyConfig::default();
        if let Some(p) = raw.cache.path {
            cfg.cache_path = p;
        }
        if let Some(s) = raw.cache.size {
            cfg.cache_size = Some(parse_size(&s)?);
        }
        if let Some(v) = raw.cache.high_watermark {
            cfg.high_watermark = v;
        }
        if let Some(v) = raw.cache.low_watermark {
            cfg.low_watermark = v;
        }
        if !(0.0..=1.0).contains(&cfg.low_watermark)
            || !(0.0..=1.0).contains(&cfg.high_watermark)
            || cfg.low_watermark > cfg.high_watermark
        {
            return Err(invalid(
                "cache watermarks must satisfy 0 <= low <= high <= 1",
            ));
        }
        if let Some(m) = raw.cache.mode {
            cfg.mode = m;
        }
        if let Some(p) = raw.cache.accel_prefix {
            cfg.accel_prefix = p;
        }
        cfg.accel_store_prefix = raw.cache.accel_store_prefix;
        if let Some(s) = raw.ttl.positive {
            cfg.ttl.positive = parse_duration(&s)?;
        }
        if let Some(l) = raw.ttl.negative {
            cfg.ttl.negative = durations(&l, "ttl.negative")?;
        }
        if let Some(s) = raw.health.probe_interval {
            cfg.health_probe_interval = parse_duration(&s)?;
        }
        if let Some(s) = raw.health.probe_timeout {
            cfg.health_probe_timeout = parse_duration(&s)?;
        }
        if let Some(s) = raw.fanout.stagger {
            cfg.stagger = parse_duration(&s)?;
        }
        if let Some(s) = raw.fanout.connect_timeout {
            cfg.connect_timeout = parse_duration(&s)?;
        }
        if let Some(s) = raw.fanout.read_timeout {
            cfg.read_timeout = parse_duration(&s)?;
        }
        if let Some(v) = raw.debuginfod.min_buildid_hex {
            cfg.min_buildid_hex = v;
        }
        if let Some(s) = raw.dns.prewarm_interval {
            cfg.dns_prewarm_interval = parse_duration(&s)?;
        }
        if let Some(v) = raw.compression.min_size {
            cfg.compression.min_size = v;
        }
        if let Some(v) = raw.compression.gzip_level {
            cfg.compression.gzip_level = v.min(9);
        }
        if let Some(v) = raw.compression.zstd_level {
            cfg.compression.zstd_level = v.clamp(1, 19);
        }
        if let Some(v) = raw.quirks.ghidra_cab {
            cfg.ghidra_cab_quirk = v;
        }
        Ok(cfg)
    }
}

pub fn upstreams_from_file(path: &Path) -> Result<Vec<Upstream>, ConfigError> {
    let raw: RawUpstreams = read_toml(path)?;
    let mut seen = HashSet::new();
    let mut out = Vec::with_capacity(raw.upstream.len());
    for u in raw.upstream {
        if !seen.insert(u.name.clone()) {
            return Err(invalid(format!("duplicate upstream name {:?}", u.name)));
        }
        out.push(Upstream {
            layout: u.layout.unwrap_or(LayoutKind::Symstore),
            binformat: u
                .binformat
                .map(|v| v.into_iter().collect())
                .unwrap_or_else(|| [Family::Pe].into_iter().collect()),
            provides: u
                .provides
                .map(|v| v.into_iter().collect())
                .unwrap_or_else(|| [Role::Image, Role::Debug].into_iter().collect()),
            extensions: u
                .extensions
                .map(|v| v.into_iter().map(|e| e.to_ascii_lowercase()).collect()),
            priority: u.priority.unwrap_or(10),
            enabled: u.enabled.unwrap_or(true),
            nocache: u.nocache,
            requires_symbolchecksum: u.requires_symbolchecksum,
            negative_ttl: match u.negative_ttl {
                Some(l) => Some(durations(&l, "negative_ttl")?),
                None => None,
            },
            name: u.name,
            base_url: u.base_url,
        });
    }
    Ok(out)
}

pub fn blacklist_from_file(path: &Path) -> Result<Blacklist, ConfigError> {
    let raw: RawBlacklist = read_toml(path)?;
    Ok(Blacklist {
        substrings: raw.substring_blacklist.names,
        suffixes: raw.suffix_blacklist.names,
        first_components: raw
            .first_path_component_blacklist
            .names
            .into_iter()
            .collect(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn durations_and_sizes() {
        assert_eq!(parse_duration("100ms").unwrap(), Duration::from_millis(100));
        assert_eq!(parse_duration("30").unwrap(), Duration::from_secs(30));
        assert_eq!(
            parse_duration("7d").unwrap(),
            Duration::from_secs(7 * 86400)
        );
        assert_eq!(parse_size("512GB").unwrap(), 512_000_000_000);
        assert_eq!(parse_size("4KiB").unwrap(), 4096);
        assert_eq!(parse_size("1024").unwrap(), 1024);
        assert!(parse_duration("5 fortnights").is_err());
        assert!(parse_size("many").is_err());
    }
}
