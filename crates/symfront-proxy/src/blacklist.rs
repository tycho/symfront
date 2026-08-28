//! Request blacklists: whole classes of requests that have never and will
//! never exist upstream (e.g. AMD driver PDBs). A match → 404 before
//! classification, nothing cached, no upstream traffic.

use std::collections::HashSet;

#[derive(Clone, Debug, Default)]
pub struct Blacklist {
    pub substrings: Vec<String>,
    pub suffixes: Vec<String>,
    pub first_components: HashSet<String>,
}

impl Blacklist {
    /// `path` must be normalized to exactly one leading '/'.
    pub fn matches(&self, path: &str) -> bool {
        for part in &self.substrings {
            if path.contains(part.as_str()) {
                tracing::debug!("{path:?} rejected: substring blacklist {part:?}");
                return true;
            }
        }
        for suffix in &self.suffixes {
            if path.ends_with(suffix.as_str()) {
                tracing::debug!("{path:?} rejected: suffix blacklist {suffix:?}");
                return true;
            }
        }
        let first = path.strip_prefix('/').unwrap_or(path);
        let first = first.split('/').next().unwrap_or(first);
        if self.first_components.contains(first) {
            tracing::debug!("{path:?} rejected: first component {first:?} blacklisted");
            return true;
        }
        false
    }
}
