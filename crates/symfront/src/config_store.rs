//! Git-backed history for the configuration tree.
//!
//! The config dir is a plain local git repository (bundled libgit2 via the
//! `git2` crate; no system git needed). Every web-UI edit becomes a commit
//! authored as the logged-in user. On startup and on every reload, working-
//! tree drift (manual edits) is committed first as "manual edit
//! (out-of-band)", so a later UI edit can never silently clobber a hand
//! edit — the lost-update scenario is structurally impossible.

use std::path::Path;

use anyhow::{Context, Result};
use git2::{Repository, Signature, StatusOptions};

pub struct ConfigStore {
    repo: Repository,
}

#[derive(Debug, serde::Serialize)]
pub struct LogEntry {
    pub id: String,
    pub short_id: String,
    pub author: String,
    /// Unix seconds.
    pub time: i64,
    pub message: String,
}

fn signature(author: &str) -> Result<Signature<'static>> {
    // The author name is the interesting part (web username / OS user); the
    // email only exists because git requires one.
    Ok(Signature::now(author, &format!("{author}@symfront"))?)
}

impl ConfigStore {
    /// Open the config dir as a git repo, creating the repo (and an initial
    /// commit of whatever is there) on first use.
    pub fn open(dir: &Path) -> Result<ConfigStore> {
        let repo = match Repository::open(dir) {
            Ok(r) => r,
            Err(_) => {
                let repo = Repository::init(dir)
                    .with_context(|| format!("git init in {}", dir.display()))?;
                tracing::info!("initialized config history repo in {}", dir.display());
                repo
            }
        };
        let store = ConfigStore { repo };
        if store.repo.head().is_err() && store.is_dirty()? {
            // Fresh repo over an existing tree: capture the initial state.
            store.commit_all("symfront", "initial config state")?;
        }
        Ok(store)
    }

    /// Any difference between the working tree and HEAD (or a non-empty tree
    /// with no commits yet)?
    pub fn is_dirty(&self) -> Result<bool> {
        let mut opts = StatusOptions::new();
        opts.include_untracked(true).recurse_untracked_dirs(true);
        let statuses = self.repo.statuses(Some(&mut opts))?;
        Ok(!statuses.is_empty())
    }

    /// Commit working-tree drift, if any, as an out-of-band manual edit.
    /// Returns the commit id when something was committed.
    pub fn commit_drift(&self) -> Result<Option<String>> {
        if !self.is_dirty()? {
            return Ok(None);
        }
        let id = self.commit_all("symfront", "manual edit (out-of-band)")?;
        tracing::info!("committed out-of-band config edits as {}", &id[..10]);
        Ok(Some(id))
    }

    /// Stage everything (adds, edits, deletions) and commit as `author`.
    pub fn commit_all(&self, author: &str, message: &str) -> Result<String> {
        let mut index = self.repo.index()?;
        index.add_all(["*"].iter(), git2::IndexAddOption::DEFAULT, None)?;
        index.update_all(["*"].iter(), None)?;
        index.write()?;
        let tree_id = index.write_tree()?;
        let tree = self.repo.find_tree(tree_id)?;
        let sig = signature(author)?;
        let parent = self
            .repo
            .head()
            .ok()
            .and_then(|h| h.peel_to_commit().ok());
        let parents: Vec<&git2::Commit> = parent.iter().collect();
        let id = self
            .repo
            .commit(Some("HEAD"), &sig, &sig, message, &tree, &parents)?;
        Ok(id.to_string())
    }

    pub fn log(&self, limit: usize) -> Result<Vec<LogEntry>> {
        let mut out = Vec::new();
        if self.repo.head().is_err() {
            return Ok(out); // no commits yet
        }
        let mut walk = self.repo.revwalk()?;
        walk.push_head()?;
        for oid in walk.take(limit) {
            let commit = self.repo.find_commit(oid?)?;
            out.push(LogEntry {
                id: commit.id().to_string(),
                short_id: commit.id().to_string()[..10].to_string(),
                author: commit.author().name().unwrap_or("?").to_string(),
                time: commit.time().seconds(),
                message: commit.summary().ok().flatten().unwrap_or("").to_string(),
            });
        }
        Ok(out)
    }

    /// Unified diff. With no revs: working tree vs HEAD. One rev: that commit
    /// vs the working tree. Two revs: between the two commits.
    pub fn diff(&self, from: Option<&str>, to: Option<&str>) -> Result<String> {
        let tree_of = |rev: &str| -> Result<git2::Tree> {
            let obj = self.repo.revparse_single(rev)?;
            Ok(obj.peel_to_commit()?.tree()?)
        };
        let diff = match (from, to) {
            (None, None) => {
                let head = match self.repo.head() {
                    Ok(h) => Some(h.peel_to_tree()?),
                    Err(_) => None,
                };
                self.repo
                    .diff_tree_to_workdir_with_index(head.as_ref(), None)?
            }
            (Some(a), None) => {
                let ta = tree_of(a)?;
                self.repo.diff_tree_to_workdir_with_index(Some(&ta), None)?
            }
            (Some(a), Some(b)) => {
                let (ta, tb) = (tree_of(a)?, tree_of(b)?);
                self.repo
                    .diff_tree_to_tree(Some(&ta), Some(&tb), None)?
            }
            (None, Some(_)) => unreachable!("to without from"),
        };
        let mut text = String::new();
        diff.print(git2::DiffFormat::Patch, |_, _, line| {
            match line.origin() {
                '+' | '-' | ' ' => text.push(line.origin()),
                _ => {}
            }
            text.push_str(std::str::from_utf8(line.content()).unwrap_or("<binary>\n"));
            true
        })?;
        Ok(text)
    }

    /// Restore the working tree to `rev`'s content and record that as a new
    /// commit (history moves forward; nothing is rewritten).
    pub fn rollback(&self, author: &str, rev: &str) -> Result<String> {
        // Resolve first: `rev` must mean what the user saw in the log, not
        // shift under the drift commit below (HEAD would otherwise move).
        let obj = self.repo.revparse_single(rev)?;
        let commit = obj.peel_to_commit()?;
        // Refuse to silently blend uncommitted edits into a rollback.
        self.commit_drift()?;
        let mut co = git2::build::CheckoutBuilder::new();
        co.force().remove_untracked(true);
        self.repo
            .checkout_tree(commit.tree()?.as_object(), Some(&mut co))?;
        let short = &commit.id().to_string()[..10];
        self.commit_all(author, &format!("rollback to {short}"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn history_semantics() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("a.toml"), "x = 1\n").unwrap();
        let store = ConfigStore::open(dir.path()).unwrap();
        // Pre-existing content is captured as the initial commit.
        assert_eq!(store.log(10).unwrap().len(), 1);
        assert!(!store.is_dirty().unwrap());

        // An attributed edit commits as that author.
        std::fs::write(dir.path().join("a.toml"), "x = 2\n").unwrap();
        store.commit_all("alice", "edit a.toml via web UI").unwrap();
        let log = store.log(10).unwrap();
        assert_eq!(log[0].author, "alice");

        // Out-of-band drift is auto-committed, once.
        std::fs::write(dir.path().join("a.toml"), "x = 3\n").unwrap();
        assert!(store.commit_drift().unwrap().is_some());
        assert!(store.commit_drift().unwrap().is_none());
        assert_eq!(store.log(10).unwrap()[0].message, "manual edit (out-of-band)");

        // Deletions are drift too.
        std::fs::write(dir.path().join("b.toml"), "y = 1\n").unwrap();
        store.commit_all("alice", "add b").unwrap();
        std::fs::remove_file(dir.path().join("b.toml")).unwrap();
        assert!(store.commit_drift().unwrap().is_some());

        // Rollback restores an earlier tree as a NEW commit; the rev means
        // what the log showed even with uncommitted edits present.
        let target = store.log(10).unwrap()[1].id.clone(); // "add b" state
        std::fs::write(dir.path().join("a.toml"), "x = 999\n").unwrap(); // drift
        store.rollback("bob", &target).unwrap();
        assert_eq!(
            std::fs::read_to_string(dir.path().join("a.toml")).unwrap(),
            "x = 3\n"
        );
        assert!(dir.path().join("b.toml").exists());
        let log = store.log(10).unwrap();
        assert!(log[0].message.starts_with("rollback to"));
        assert_eq!(log[0].author, "bob");
        // The pre-rollback drift survives in history.
        assert_eq!(log[1].message, "manual edit (out-of-band)");
        assert!(!store.is_dirty().unwrap());
    }

    #[test]
    fn diff_modes() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("a.toml"), "x = 1\n").unwrap();
        let store = ConfigStore::open(dir.path()).unwrap();
        assert_eq!(store.diff(None, None).unwrap(), "");
        std::fs::write(dir.path().join("a.toml"), "x = 2\n").unwrap();
        let d = store.diff(None, None).unwrap();
        assert!(d.contains("-x = 1") && d.contains("+x = 2"), "{d}");
        store.commit_all("alice", "bump").unwrap();
        let log = store.log(10).unwrap();
        let d = store.diff(Some(&log[1].id), Some(&log[0].id)).unwrap();
        assert!(d.contains("+x = 2"), "{d}");
    }
}
