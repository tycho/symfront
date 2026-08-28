//! symfront-proxy: a caching symbol-server proxy engine.
//!
//! The Rust port of symsrv (github.com/tycho/symsrv), redesigned per
//! `docs/proxy-integration-plan.md`:
//!
//! - Layout seam (symstore/SSQP + debuginfod) with cross-layout convergence,
//!   pinned by golden vectors generated from the Python implementation.
//! - sha256-of-URL cache keys (import-compatible with the Python cache).
//! - SQLite metadata (inline reads, one writer thread) + sharded data tree.
//! - Sliding positive TTLs, revalidation on expiry, escalating negative-TTL
//!   ladder, singleflight with tail-follow fills, health breaker with
//!   background probes, staggered priority fan-out, eviction and scrub.
//!
//! No HTTP-server or UI dependencies: the `symfront` binary mounts this
//! behind axum; anything else could mount it elsewhere.

pub mod blacklist;
pub mod cache;
pub mod config;
pub mod db;
pub mod engine;
pub mod fill;
pub mod health;
pub mod key;
pub mod maintenance;
pub mod query;
pub mod stats;
pub mod upstream;

pub use blacklist::Blacklist;
pub use config::{CacheMode, ProxyConfig, TtlPolicy};
pub use engine::{ClientRequest, Method, Outcome, ProxyEngine};
pub use key::CacheKey;
pub use query::{classify_request, Family, LayoutKind, Role, SymbolQuery};
pub use upstream::Upstream;
