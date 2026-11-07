//! Module 2 — Zero-Driver Snapshot & Delta Reconciliation.
//!
//! Recursive traversal + SHA-256 hashing. No filesystem driver, no
//! minifilter: take a baseline, re-scan, and diff the two manifests.

use crate::json::Value;
use crate::sha256::hash_file;
use crate::util::{extension_lower, path_to_slash_string};
use crate::{Error, Result};
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

#[derive(Debug, Clone, PartialEq)]
pub struct FileEntry {
    /// Path relative to the snapshot root, `/`-separated on every OS.
    pub path: String,
    pub size: u64,
    /// SHA-256 hex; empty for directories / symlinks / unreadable files.
    pub sha256: String,
    pub kind: EntryKind,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EntryKind { File, Directory, Symlink, Other }

impl EntryKind {
    pub fn as_str(&self) -> &'static str {
        match self { EntryKind::File => "file", EntryKind::Directory => "directory",
                     EntryKind::Symlink => "symlink", EntryKind::Other => "other" }
    }
    fn from_str(s: &str) -> EntryKind {
        match s { "directory" => EntryKind::Directory, "symlink" => EntryKind::Symlink,
                  "file" => EntryKind::File, _ => EntryKind::Other }
    }
}

#[derive(Debug, Clone)]
pub struct Snapshot {
    pub root: PathBuf,
    pub created_unix: u64,
    pub entries: BTreeMap<String, FileEntry>,
}

#[derive(Debug, Clone, Default)]
pub struct Delta {
    pub added: Vec<FileEntry>,
    pub modified: Vec<FileEntry>,
    pub deleted: Vec<FileEntry>,
    pub unchanged: Vec<FileEntry>,
}

impl Snapshot {
    /// Capture every file/dir under `root`. Symlinked directories are
    /// recorded but never followed (loop / escape protection).
    pub fn capture(root: &Path) -> Result<Snapshot> {
        if !root.exists() { return Err(Error::NotFound(root.to_path_buf())); }
        let mut entries = BTreeMap::new();
        let mut stack: Vec<PathBuf> = vec![root.to_path_buf()];
        while let Some(dir) = stack.pop() {
            let read = match std::fs::read_dir(&dir) {
                Ok(r) => r,
                Err(_) => continue, // unreadable dir: skip, never abort a scan
            };
            let mut children: Vec<PathBuf> = read.filter_map(|e| e.ok().map(|e| e.path())).collect();
            children.sort();
            for path in children {
                let rel = match path.strip_prefix(root) {
                    Ok(r) => path_to_slash_string(r),
                    Err(_) => continue,
                };
                if rel.is_empty() { continue; }
                let meta = match std::fs::symlink_metadata(&path) {
                    Ok(m) => m,
                    Err(_) => continue,
                };
                let ft = meta.file_type();
                let (kind, size, sha) = if ft.is_symlink() {
                    (EntryKind::Symlink, 0, String::new())
                } else if ft.is_dir() {
                    stack.push(path.clone());
                    (EntryKind::Directory, 0, String::new())
                } else if ft.is_file() {
                    // Unreadable / locked files are recorded with an empty
                    // hash instead of aborting the whole snapshot.
                    let sha = hash_file(&path).unwrap_or_default();
                    (EntryKind::File, meta.len(), sha)
                } else {
                    (EntryKind::Other, 0, String::new())
                };
                entries.insert(rel.clone(), FileEntry { path: rel, size, sha256: sha, kind });
            }
        }
        Ok(Snapshot { root: root.to_path_buf(), created_unix: crate::util::unix_secs(), entries })
    }

    pub fn diff(&self, after: &Snapshot) -> Delta {
        let mut delta = Delta::default();
        for (path, new) in &after.entries {
            match self.entries.get(path) {
                None => delta.added.push(new.clone()),
                Some(old) if old.sha256 != new.sha256 || old.size != new.size || old.kind != new.kind => {
                    delta.modified.push(new.clone())
                }
                Some(_) => delta.unchanged.push(new.clone()),
            }
        }
        for (path, old) in &self.entries {
            if !after.entries.contains_key(path) { delta.deleted.push(old.clone()); }
        }
        delta
    }

    fn entry_json(e: &FileEntry) -> Value {
        Value::obj(vec![
            ("path", Value::str(e.path.clone())),
            ("size", Value::num(e.size)),
            ("sha256", Value::str(e.sha256.clone())),
            ("kind", Value::str(e.kind.as_str())),
        ])
    }

    pub fn to_json(&self) -> Value {
        Value::obj(vec![
            ("root", Value::str(path_to_slash_string(&self.root))),
            ("created_unix", Value::num(self.created_unix)),
            ("entries", Value::Array(self.entries.values().map(Self::entry_json).collect())),
        ])
    }

    pub fn save(&self, path: &Path) -> Result<()> {
        std::fs::write(path, self.to_json().to_string_pretty())?;
        Ok(())
    }

    pub fn load(path: &Path) -> Result<Snapshot> {
        let text = std::fs::read_to_string(path)?;
        let value = crate::json::parse(&text)?;
        let mut entries = BTreeMap::new();
        if let Some(Value::Array(items)) = value.get("entries") {
            for item in items {
                let rel = item.get("path").and_then(Value::as_str).unwrap_or_default().to_string();
                if rel.is_empty() { continue; }
                let size = match item.get("size") { Some(Value::Number(n)) => *n as u64, _ => 0 };
                entries.insert(rel.clone(), FileEntry {
                    path: rel,
                    size,
                    sha256: item.get("sha256").and_then(Value::as_str).unwrap_or_default().to_string(),
                    kind: EntryKind::from_str(item.get("kind").and_then(Value::as_str).unwrap_or("file")),
                });
            }
        }
        Ok(Snapshot {
            root: PathBuf::from(value.get("root").and_then(Value::as_str).unwrap_or_default()),
            created_unix: match value.get("created_unix") { Some(Value::Number(n)) => *n as u64, _ => 0 },
            entries,
        })
    }
}

impl Delta {
    pub fn is_empty(&self) -> bool {
        self.added.is_empty() && self.modified.is_empty() && self.deleted.is_empty()
    }
    /// Only files an installer actually dropped/changed — the REA input set.
    pub fn changed_files(&self) -> Vec<&FileEntry> {
        self.added.iter().chain(self.modified.iter())
            .filter(|e| e.kind == EntryKind::File).collect()
    }
    pub fn to_json(&self) -> Value {
        let list = |v: &[FileEntry]| Value::Array(v.iter().map(Snapshot::entry_json_pub).collect());
        Value::obj(vec![
            ("added", list(&self.added)),
            ("modified", list(&self.modified)),
            ("deleted", list(&self.deleted)),
            ("unchanged_count", Value::num(self.unchanged.len() as u64)),
        ])
    }
}

// Small indirection so Delta (same module) reuses entry serialization.
impl Snapshot {
    fn entry_json_pub(e: &FileEntry) -> Value { Self::entry_json(e) }
}

/// True for extensions REA should look at first.
pub fn is_interesting(path: &Path) -> bool {
    matches!(extension_lower(path).as_str(),
        "exe"|"dll"|"sys"|"msi"|"bat"|"cmd"|"ps1"|"vbs"|"js"|"jar"|"com"|"scr"|"ocx"|"cpl")
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn delta_detects_add_modify_delete() {
        let dir = std::env::temp_dir().join(format!("rea_offline_test_{}", crate::util::new_id()));
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(dir.join("keep.txt"), b"same").unwrap();
        std::fs::write(dir.join("change.txt"), b"before").unwrap();
        std::fs::write(dir.join("gone.txt"), b"x").unwrap();
        let before = Snapshot::capture(&dir).unwrap();
        std::fs::write(dir.join("change.txt"), b"after!").unwrap();
        std::fs::write(dir.join("new.exe"), b"MZ fake").unwrap();
        std::fs::remove_file(dir.join("gone.txt")).unwrap();
        let after = Snapshot::capture(&dir).unwrap();
        let delta = before.diff(&after);
        assert_eq!(delta.added.iter().map(|e| e.path.as_str()).collect::<Vec<_>>(), vec!["new.exe"]);
        assert_eq!(delta.modified.len(), 1);
        assert_eq!(delta.deleted.len(), 1);
        assert_eq!(delta.unchanged.len(), 1);
        std::fs::remove_dir_all(&dir).unwrap();
    }
}
