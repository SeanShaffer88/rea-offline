//! Module 2 — Zero-Driver Snapshot & Delta Reconciliation.
//!
//! Recursive traversal + SHA-256 hashing. No filesystem driver, no
//! minifilter: take a baseline, re-scan, and diff the two manifests.
//!
//! A manifest is only evidence if it says what it could not see. Every
//! traversal failure is recorded in `issues`, and a file whose contents
//! could not be read is never silently reported as unchanged: an empty
//! hash means "not verified", not "identical".

use crate::json::Value;
use crate::rea_bridge::ScanIssue;
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
    /// For a [`EntryKind::File`] an empty hash means the contents were
    /// **not** verified — see [`FileEntry::content_verified`].
    pub sha256: String,
    pub kind: EntryKind,
}

impl FileEntry {
    /// True when this entry's contents were actually hashed. Directories,
    /// symlinks and special files have nothing to hash and are not
    /// "unverified"; a regular file with an empty hash could not be read.
    pub fn content_verified(&self) -> bool {
        self.kind != EntryKind::File || !self.sha256.is_empty()
    }
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
    /// What the traversal could not see. Empty means the manifest covers
    /// the whole tree; non-empty means absence from `entries` proves nothing.
    pub issues: Vec<ScanIssue>,
}

impl Snapshot {
    /// True when nothing was skipped, so "not in the manifest" really does
    /// mean "not on disk".
    pub fn is_complete(&self) -> bool {
        self.issues.is_empty()
    }
}

/// Whether a file moved between two stats of it. A different length or a
/// different modification time means the bytes read in between may not be
/// any single version of the file.
fn changed_during(before: &std::fs::Metadata, after: &std::fs::Metadata) -> bool {
    before.len() != after.len() || before.modified().ok() != after.modified().ok()
}

#[derive(Debug, Clone, Default)]
pub struct Delta {
    pub added: Vec<FileEntry>,
    pub modified: Vec<FileEntry>,
    pub deleted: Vec<FileEntry>,
    pub unchanged: Vec<FileEntry>,
    /// Present in both manifests, but at least one side could not be
    /// hashed, so the contents cannot be compared. Reported separately
    /// rather than counted as unchanged: "we could not tell" is not "no
    /// change", and an installer that rewrites a locked file must not
    /// disappear from the record.
    pub unverified: Vec<FileEntry>,
}

impl Snapshot {
    /// Capture every file/dir under `root`. Symlinked directories are
    /// recorded but never followed (loop / escape protection).
    ///
    /// Failures never abort the walk — a partial manifest is far more use
    /// than none — but each one is recorded in `issues` so the caller can
    /// tell a clean tree from a tree it was not allowed to read.
    pub fn capture(root: &Path) -> Result<Snapshot> {
        if !root.exists() { return Err(Error::NotFound(root.to_path_buf())); }
        let mut entries = BTreeMap::new();
        let mut issues: Vec<ScanIssue> = Vec::new();
        // Label failures with a root-relative path so a manifest stays
        // readable (and comparable) after it is moved between machines.
        let label = |path: &Path| -> String {
            match path.strip_prefix(root) {
                Ok(rel) if rel.as_os_str().is_empty() => ".".to_string(),
                Ok(rel) => path_to_slash_string(rel),
                Err(_) => path_to_slash_string(path),
            }
        };
        let mut stack: Vec<PathBuf> = vec![root.to_path_buf()];
        while let Some(dir) = stack.pop() {
            let read = match std::fs::read_dir(&dir) {
                Ok(r) => r,
                Err(e) => {
                    // Previously `continue`: the entire subtree vanished
                    // and the manifest still looked complete.
                    issues.push(ScanIssue::new(label(&dir), "traverse", e.to_string()));
                    continue;
                }
            };
            let mut children: Vec<PathBuf> = Vec::new();
            for entry in read {
                match entry {
                    Ok(entry) => children.push(entry.path()),
                    Err(e) => issues.push(ScanIssue::new(label(&dir), "entry", e.to_string())),
                }
            }
            children.sort();
            for path in children {
                let rel = match path.strip_prefix(root) {
                    Ok(r) => path_to_slash_string(r),
                    Err(_) => {
                        issues.push(ScanIssue::new(
                            path_to_slash_string(&path), "path", "escapes the snapshot root",
                        ));
                        continue;
                    }
                };
                if rel.is_empty() { continue; }
                let meta = match std::fs::symlink_metadata(&path) {
                    Ok(m) => m,
                    Err(e) => {
                        issues.push(ScanIssue::new(rel, "metadata", e.to_string()));
                        continue;
                    }
                };
                let ft = meta.file_type();
                let (kind, size, sha) = if ft.is_symlink() {
                    (EntryKind::Symlink, 0, String::new())
                } else if ft.is_dir() {
                    stack.push(path.clone());
                    (EntryKind::Directory, 0, String::new())
                } else if ft.is_file() {
                    // Still recorded, so the file is known to exist; the
                    // empty hash plus this issue says its contents are
                    // unverified rather than pretending they matched.
                    let mut size = meta.len();
                    let mut sha = match hash_file(&path) {
                        Ok(sha) => sha,
                        Err(e) => {
                            issues.push(ScanIssue::new(rel.clone(), "hash", e.to_string()));
                            String::new()
                        }
                    };
                    if !sha.is_empty() {
                        // The size was taken before the contents were
                        // streamed. A file rewritten mid-read would pair
                        // the hash of one version with the size of another,
                        // and a later diff would trust the pair. Re-stat:
                        // on any movement the entry stays, but unverified.
                        match std::fs::metadata(&path) {
                            Ok(after) if changed_during(&meta, &after) => {
                                size = after.len();
                                sha = String::new();
                                issues.push(ScanIssue::new(
                                    rel.clone(),
                                    "changed",
                                    "file changed while it was being read; its contents are unverified",
                                ));
                            }
                            Ok(_) => {}
                            Err(e) => {
                                sha = String::new();
                                issues.push(ScanIssue::new(
                                    rel.clone(),
                                    "changed",
                                    format!("file could not be re-checked after reading: {e}"),
                                ));
                            }
                        }
                    }
                    (EntryKind::File, size, sha)
                } else {
                    (EntryKind::Other, 0, String::new())
                };
                entries.insert(rel.clone(), FileEntry { path: rel, size, sha256: sha, kind });
            }
        }
        issues.sort_by(|a, b| a.path.cmp(&b.path).then(a.stage.cmp(&b.stage)));
        Ok(Snapshot { root: root.to_path_buf(), created_unix: crate::util::unix_secs(), entries, issues })
    }

    pub fn diff(&self, after: &Snapshot) -> Delta {
        let mut delta = Delta::default();
        for (path, new) in &after.entries {
            match self.entries.get(path) {
                None => delta.added.push(new.clone()),
                // A kind or size change is proof of modification even when
                // the contents were never readable.
                Some(old) if old.kind != new.kind || old.size != new.size => {
                    delta.modified.push(new.clone())
                }
                // Same size, but one side never got hashed: two empty
                // hashes are not evidence of equality.
                Some(old) if !old.content_verified() || !new.content_verified() => {
                    delta.unverified.push(new.clone())
                }
                Some(old) if old.sha256 != new.sha256 => delta.modified.push(new.clone()),
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
            ("issues", Value::Array(self.issues.iter().map(ScanIssue::to_json).collect())),
            ("issue_count", Value::num(self.issues.len() as u64)),
            ("complete", Value::Bool(self.is_complete())),
        ])
    }

    pub fn save(&self, path: &Path) -> Result<()> {
        std::fs::write(path, self.to_json().to_string_pretty())?;
        Ok(())
    }

    pub fn load(path: &Path) -> Result<Snapshot> {
        let text = std::fs::read_to_string(path)?;
        let value = crate::json::parse(&text)?;
        // A manifest is only comparable because it says *what* it is a
        // manifest of. Anything else — a report archive, a truncated file,
        // an empty object — used to load as "a snapshot of nothing", and a
        // diff against it reported every real file as added or deleted while
        // claiming full coverage of a comparison that never happened.
        let root = value.get("root").and_then(Value::as_str).unwrap_or_default();
        if root.is_empty() {
            return Err(Error::InvalidInput(format!(
                "{} is not a snapshot manifest (no root); expected a file \
                 written by `rea-offline snapshot`",
                path.display(),
            )));
        }
        let items = match value.get("entries") {
            Some(Value::Array(items)) => items,
            _ => return Err(Error::InvalidInput(format!(
                "{} is not a snapshot manifest (no entries list); expected a \
                 file written by `rea-offline snapshot`",
                path.display(),
            ))),
        };
        // The entries are the evidence, so they are held to the same
        // standard as the document itself. An entry that is not an object,
        // has no path, repeats an earlier path, or carries a size or hash
        // of the wrong shape used to be silently dropped, overwritten or
        // defaulted — the manifest loaded with fewer files than it listed,
        // and a diff against it still claimed complete coverage of a
        // comparison that had quietly lost evidence. Refuse instead, the
        // way a document that is not a manifest at all is refused. Two
        // fields stay lenient by design: a missing `sha256` is an empty
        // digest, which diffs as `unverified` rather than `unchanged`,
        // and a missing `kind` is a regular file.
        let malformed = |reason: String| {
            Error::InvalidInput(format!(
                "{} is not a snapshot manifest ({reason}); expected a file \
                 written by `rea-offline snapshot`",
                path.display(),
            ))
        };
        let mut entries = BTreeMap::new();
        for (index, item) in items.iter().enumerate() {
            if !matches!(item, Value::Object(_)) {
                return Err(malformed(format!("entry {index} is not an object")));
            }
            let rel = match item.get("path").and_then(Value::as_str) {
                Some(rel) if !rel.is_empty() => rel.to_string(),
                _ => return Err(malformed(format!("entry {index} has no path"))),
            };
            if entries.contains_key(&rel) {
                return Err(malformed(format!("entry {index} duplicates '{rel}'")));
            }
            let size = match item.get("size") {
                Some(Value::Number(n))
                    if n.is_finite() && *n >= 0.0 && n.fract() == 0.0 && *n <= u64::MAX as f64 =>
                {
                    *n as u64
                }
                _ => return Err(malformed(format!("entry {index} ('{rel}') has no usable size"))),
            };
            let sha256 = match item.get("sha256") {
                None => String::new(),
                Some(Value::String(hash)) => hash.clone(),
                _ => return Err(malformed(format!("entry {index} ('{rel}') has a non-string sha256"))),
            };
            let kind = match item.get("kind") {
                None => EntryKind::File,
                Some(Value::String(kind)) => EntryKind::from_str(kind),
                _ => return Err(malformed(format!("entry {index} ('{rel}') has a non-string kind"))),
            };
            entries.insert(rel.clone(), FileEntry { path: rel, size, sha256, kind });
        }
        // Manifests written before coverage was recorded carry no issues
        // block. They are still readable; files they could not hash have an
        // empty digest and therefore diff as `unverified`, not `unchanged`.
        let mut issues = Vec::new();
        if let Some(Value::Array(items)) = value.get("issues") {
            for item in items {
                let field = |k: &str| item.get(k).and_then(Value::as_str).unwrap_or_default().to_string();
                issues.push(ScanIssue::new(field("path"), field("stage"), field("message")));
            }
        }
        Ok(Snapshot {
            root: PathBuf::from(root),
            created_unix: match value.get("created_unix") { Some(Value::Number(n)) => *n as u64, _ => 0 },
            entries,
            issues,
        })
    }

    /// The root as it travels in a manifest: slash-separated, so a tree
    /// snapshotted on Windows and diffed on a POSIX box still names the same
    /// directory.
    pub fn root_label(&self) -> String {
        path_to_slash_string(&self.root)
    }

    /// Why two manifests cannot be compared — the reasons a delta between
    /// them is not evidence. Both are *stated* rather than refused: a
    /// manifest keeps root-relative paths precisely so it stays comparable
    /// after the tree is moved, so a different root is a fact to report, not
    /// an error — but a delta built across two different trees has to say so
    /// instead of looking like a normal install.
    pub fn compare_issues(&self, after: &Snapshot) -> Vec<ScanIssue> {
        let mut issues = Vec::new();
        let (before_root, after_root) = (self.root_label(), after.root_label());
        if before_root != after_root {
            issues.push(ScanIssue::new(
                after_root.clone(),
                "root",
                &format!(
                    "compared against a snapshot of a different directory: \
                     before is {before_root}, after is {after_root}",
                ),
            ));
        }
        // The first argument is "before". An after that predates it means
        // either swapped arguments or a moved clock, and either way the
        // added and deleted columns are inverted. A capture time of zero is
        // a manifest that never recorded one, which says nothing either way.
        if self.created_unix > 0 && after.created_unix > 0 && after.created_unix < self.created_unix {
            issues.push(ScanIssue::new(
                after_root,
                "order",
                &format!(
                    "the 'after' snapshot was taken {}s before the 'before' \
                     snapshot — the arguments may be swapped, which inverts \
                     added and deleted",
                    self.created_unix - after.created_unix,
                ),
            ));
        }
        issues
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
            ("unverified", list(&self.unverified)),
            ("unverified_count", Value::num(self.unverified.len() as u64)),
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
    /// Build a manifest by hand so diff semantics can be tested without
    /// depending on filesystem permissions (which behave differently on
    /// Windows, and are bypassed entirely when running as root).
    fn manifest(entries: &[(&str, u64, &str, EntryKind)]) -> Snapshot {
        Snapshot {
            root: PathBuf::from("/virtual"),
            created_unix: 0,
            entries: entries.iter().map(|(path, size, sha, kind)| {
                (path.to_string(), FileEntry {
                    path: path.to_string(), size: *size, sha256: sha.to_string(), kind: *kind,
                })
            }).collect(),
            issues: Vec::new(),
        }
    }

    #[test]
    fn two_unreadable_captures_are_unverified_not_unchanged() {
        // The bug: both hashes empty and equal size compared equal, so an
        // installer rewriting a locked file vanished from the delta.
        let before = manifest(&[("locked.bin", 4, "", EntryKind::File)]);
        let after = manifest(&[("locked.bin", 4, "", EntryKind::File)]);
        let delta = before.diff(&after);
        assert!(delta.unchanged.is_empty(), "must not claim a file it never read is unchanged");
        assert!(delta.modified.is_empty());
        assert_eq!(delta.unverified.iter().map(|e| e.path.as_str()).collect::<Vec<_>>(), vec!["locked.bin"]);
        let json = delta.to_json();
        assert_eq!(json.get("unverified_count"), Some(&Value::num(1)));
    }

    #[test]
    fn one_readable_side_is_enough_to_report_a_change() {
        let locked = manifest(&[("f.bin", 4, "", EntryKind::File)]);
        let read = manifest(&[("f.bin", 4, "aa", EntryKind::File)]);
        // Unreadable -> readable: contents cannot be compared either way.
        assert_eq!(locked.diff(&read).unverified.len(), 1);
        assert_eq!(read.diff(&locked).unverified.len(), 1);
    }

    #[test]
    fn a_size_or_kind_change_is_a_modification_even_when_unreadable() {
        let before = manifest(&[("f.bin", 4, "", EntryKind::File)]);
        let bigger = manifest(&[("f.bin", 9, "", EntryKind::File)]);
        let delta = before.diff(&bigger);
        assert_eq!(delta.modified.len(), 1, "size proves a change without a hash");
        assert!(delta.unverified.is_empty());

        let replaced = manifest(&[("f.bin", 4, "", EntryKind::Symlink)]);
        assert_eq!(before.diff(&replaced).modified.len(), 1, "kind proves a change too");
    }

    #[test]
    fn directories_and_symlinks_are_not_unverified() {
        // Empty hashes are normal for non-files; only regular files can be
        // "unverified", otherwise every directory would raise a warning.
        let entries = [("d", 0, "", EntryKind::Directory), ("l", 0, "", EntryKind::Symlink)];
        let delta = manifest(&entries).diff(&manifest(&entries));
        assert!(delta.unverified.is_empty());
        assert_eq!(delta.unchanged.len(), 2);
        assert!(manifest(&entries).entries.values().all(FileEntry::content_verified));
        assert!(!manifest(&[("f", 1, "", EntryKind::File)]).entries["f"].content_verified());
    }

    #[test]
    fn coverage_survives_a_save_load_round_trip() {
        let mut snap = manifest(&[("a.txt", 1, "aa", EntryKind::File)]);
        snap.issues.push(ScanIssue::new("secret", "traverse", "Permission denied"));
        let path = std::env::temp_dir().join(format!("rea_snap_{}.json", crate::util::new_id()));
        snap.save(&path).unwrap();
        let loaded = Snapshot::load(&path).unwrap();
        std::fs::remove_file(&path).unwrap();
        assert!(!loaded.is_complete());
        assert_eq!(loaded.issues.len(), 1);
        assert_eq!(loaded.issues[0].path, "secret");
        assert_eq!(loaded.issues[0].stage, "traverse");
        assert_eq!(loaded.to_json().get("complete"), Some(&Value::Bool(false)));
    }

    #[test]
    fn a_manifest_with_no_issues_claims_completeness() {
        let snap = manifest(&[("a.txt", 1, "aa", EntryKind::File)]);
        assert!(snap.is_complete());
        let json = snap.to_json();
        assert_eq!(json.get("complete"), Some(&Value::Bool(true)));
        assert_eq!(json.get("issue_count"), Some(&Value::num(0)));
    }

    fn manifest_at(root: &str, created_unix: u64,
                   entries: &[(&str, u64, &str, EntryKind)]) -> Snapshot {
        let mut snap = manifest(entries);
        snap.root = PathBuf::from(root);
        snap.created_unix = created_unix;
        snap
    }

    #[test]
    fn a_document_that_is_not_a_manifest_is_refused_not_diffed() {
        // A report archive, an empty object, a truncated file: all of them
        // used to load as "a snapshot of nothing", so a diff against one
        // reported every file as added or deleted.
        let dir = std::env::temp_dir().join(format!("rea_load_{}", crate::util::new_id()));
        std::fs::create_dir_all(&dir).unwrap();
        for (name, body) in [
            ("empty.json", "{}"),
            ("report.json", r#"{"schema_version":3,"mode":"sandbox-installer","report":{"files":[]}}"#),
            ("noentries.json", r#"{"root":"/virtual"}"#),
        ] {
            let path = dir.join(name);
            std::fs::write(&path, body).unwrap();
            let error = Snapshot::load(&path).unwrap_err().to_string();
            assert!(error.contains("is not a snapshot manifest"), "{name}: {error}");
            assert!(error.contains(&path.display().to_string()), "{name}: {error}");
        }
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn malformed_entries_are_refused_not_silently_dropped() {
        // The entries are the evidence. Each of these used to load anyway:
        // the pathless entry vanished, the duplicate overwrote the first
        // copy, and the rest were defaulted — so the manifest that reached
        // the diff held less than the manifest on disk, and said nothing.
        let dir = std::env::temp_dir().join(format!("rea_load_{}", crate::util::new_id()));
        std::fs::create_dir_all(&dir).unwrap();
        let good = r#"{"path":"a.txt","size":1,"sha256":"aa","kind":"file"}"#;
        for (name, entries, reason) in [
            ("bare.json", r#"["oops"]"#, "is not an object"),
            ("nopath.json", r#"[{"size":1,"sha256":"aa","kind":"file"}]"#, "has no path"),
            ("emptypath.json", r#"[{"path":"","size":1,"sha256":"aa","kind":"file"}]"#, "has no path"),
            ("dupe.json", &format!("[{good},{good}]"), "duplicates 'a.txt'"),
            ("nosize.json", r#"[{"path":"a.txt","sha256":"aa","kind":"file"}]"#, "has no usable size"),
            ("strsize.json", r#"[{"path":"a.txt","size":"1","sha256":"aa","kind":"file"}]"#, "has no usable size"),
            ("negsize.json", r#"[{"path":"a.txt","size":-1,"sha256":"aa","kind":"file"}]"#, "has no usable size"),
            ("fracsize.json", r#"[{"path":"a.txt","size":1.5,"sha256":"aa","kind":"file"}]"#, "has no usable size"),
            ("numhash.json", r#"[{"path":"a.txt","size":1,"sha256":7,"kind":"file"}]"#, "non-string sha256"),
            ("numkind.json", r#"[{"path":"a.txt","size":1,"sha256":"aa","kind":7}]"#, "non-string kind"),
        ] {
            let path = dir.join(name);
            std::fs::write(&path, format!(r#"{{"root":"/virtual","entries":{entries}}}"#)).unwrap();
            let error = Snapshot::load(&path).unwrap_err().to_string();
            assert!(error.contains("is not a snapshot manifest"), "{name}: {error}");
            assert!(error.contains(reason), "{name}: {error}");
        }
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn a_manifest_entry_without_a_hash_loads_as_unverified_not_unchanged() {
        // The one lenient field, by design: a file the capture could not
        // read has an empty digest, and an absent field is the same fact.
        let dir = std::env::temp_dir().join(format!("rea_load_{}", crate::util::new_id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("nohash.json");
        std::fs::write(&path, r#"{"root":"/virtual","entries":[{"path":"a.txt","size":1,"kind":"file"}]}"#).unwrap();
        let loaded = Snapshot::load(&path).unwrap();
        std::fs::remove_dir_all(&dir).unwrap();
        let entry = &loaded.entries["a.txt"];
        assert!(entry.sha256.is_empty());
        assert!(!entry.content_verified());
    }

    #[test]
    fn a_manifest_of_an_empty_directory_is_still_a_manifest() {
        let dir = std::env::temp_dir().join(format!("rea_load_{}", crate::util::new_id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("empty-tree.json");
        manifest_at("/virtual", 0, &[]).save(&path).unwrap();
        let loaded = Snapshot::load(&path).unwrap();
        assert!(loaded.is_complete(), "an empty tree hid nothing");
        assert!(loaded.entries.is_empty());
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn two_manifests_of_the_same_tree_are_comparable() {
        let before = manifest_at("/virtual", 100, &[("a.txt", 1, "aa", EntryKind::File)]);
        let after = manifest_at("/virtual", 200, &[("a.txt", 1, "aa", EntryKind::File)]);
        assert!(before.compare_issues(&after).is_empty());
        // The same second is not "swapped".
        let same_instant = manifest_at("/virtual", 100, &[("a.txt", 1, "aa", EntryKind::File)]);
        assert!(before.compare_issues(&same_instant).is_empty());
    }

    #[test]
    fn a_different_root_is_stated_by_the_delta_not_assumed_away() {
        // Roots are recorded relative and stay comparable after a tree is
        // moved, so this is a fact to report — not a reason to refuse.
        let before = manifest_at("/virtual/install", 100, &[("a.txt", 1, "aa", EntryKind::File)]);
        let after = manifest_at("/virtual", 200, &[("a.txt", 1, "aa", EntryKind::File)]);
        let issues = before.compare_issues(&after);
        assert_eq!(issues.len(), 1, "{issues:?}");
        assert_eq!(issues[0].stage, "root");
        assert!(issues[0].message.contains("/virtual/install")
            && issues[0].message.contains("/virtual"), "both sides are named: {}", issues[0].message);
    }

    #[test]
    fn an_after_that_predates_the_before_is_reported_as_possibly_swapped() {
        let before = manifest_at("/virtual", 500, &[("a.txt", 1, "aa", EntryKind::File)]);
        let after = manifest_at("/virtual", 100, &[("a.txt", 1, "aa", EntryKind::File)]);
        let issues = before.compare_issues(&after);
        assert_eq!(issues.len(), 1, "{issues:?}");
        assert_eq!(issues[0].stage, "order");
        assert!(issues[0].message.contains("400s"), "{}", issues[0].message);

        // A manifest that never recorded a capture time says nothing about
        // ordering, so it is not accused of being swapped.
        let undated = manifest_at("/virtual", 0, &[("a.txt", 1, "aa", EntryKind::File)]);
        assert!(before.compare_issues(&undated).is_empty());
    }

    #[test]
    fn capturing_a_file_instead_of_a_directory_is_not_an_empty_success() {
        // Cross-platform: read_dir on a regular file always fails. It used
        // to produce an empty manifest that claimed the tree was empty.
        let path = std::env::temp_dir().join(format!("rea_notadir_{}.bin", crate::util::new_id()));
        std::fs::write(&path, b"not a directory").unwrap();
        let snap = Snapshot::capture(&path).unwrap();
        std::fs::remove_file(&path).unwrap();
        assert!(snap.entries.is_empty());
        assert!(!snap.is_complete(), "an unreadable root must not look like an empty tree");
        assert_eq!(snap.issues[0].stage, "traverse");
        assert_eq!(snap.issues[0].path, ".");
    }

    /// POSIX mode bits are the portable way to make a real unreadable tree.
    /// Returns false (and restores nothing) when the process can read it
    /// anyway, e.g. running as root, so the caller can skip the assertion.
    #[cfg(unix)]
    fn make_unreadable(path: &Path) -> bool {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o000)).unwrap();
        // A directory is blocked when it cannot be listed; a file when it
        // cannot be opened. `read_dir` on a file errors for every caller,
        // so asking it about a file would claim "blocked" even for a
        // privileged process that can in fact read the file.
        let blocked = if path.is_dir() {
            std::fs::read_dir(path).is_err()
        } else {
            std::fs::File::open(path).is_err()
        };
        if !blocked {
            std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o700)).unwrap();
        }
        blocked
    }

    #[cfg(unix)]
    #[test]
    fn an_unreadable_directory_is_recorded_instead_of_silently_skipped() {
        use std::os::unix::fs::PermissionsExt;
        let root = std::env::temp_dir().join(format!("rea_locked_{}", crate::util::new_id()));
        let locked = root.join("locked");
        std::fs::create_dir_all(&locked).unwrap();
        std::fs::write(locked.join("payload.exe"), b"MZ hidden").unwrap();
        std::fs::write(root.join("visible.txt"), b"hi").unwrap();
        if !make_unreadable(&locked) {
            std::fs::remove_dir_all(&root).unwrap();
            return; // privileged process: mode bits do not block it
        }
        let snap = Snapshot::capture(&root).unwrap();
        std::fs::set_permissions(&locked, std::fs::Permissions::from_mode(0o700)).unwrap();
        std::fs::remove_dir_all(&root).unwrap();

        assert!(!snap.entries.contains_key("locked/payload.exe"));
        assert!(snap.entries.contains_key("visible.txt"), "the walk still covers what it can");
        assert!(!snap.is_complete(), "absence from the manifest must not look like absence from disk");
        let issue = snap.issues.iter().find(|i| i.path == "locked").expect("traversal issue");
        assert_eq!(issue.stage, "traverse");
        assert!(!issue.message.is_empty());
    }

    #[cfg(unix)]
    #[test]
    fn an_unreadable_file_is_listed_but_marked_unverified() {
        use std::os::unix::fs::PermissionsExt;
        let root = std::env::temp_dir().join(format!("rea_lockedfile_{}", crate::util::new_id()));
        std::fs::create_dir_all(&root).unwrap();
        let file = root.join("locked.bin");
        std::fs::write(&file, b"AAAA").unwrap();
        if !make_unreadable(&file) {
            std::fs::remove_dir_all(&root).unwrap();
            return;
        }
        let snap = Snapshot::capture(&root).unwrap();
        std::fs::set_permissions(&file, std::fs::Permissions::from_mode(0o600)).unwrap();
        std::fs::remove_dir_all(&root).unwrap();

        let entry = &snap.entries["locked.bin"];
        assert_eq!(entry.kind, EntryKind::File);
        assert_eq!(entry.size, 4, "its existence and size are still evidence");
        assert!(entry.sha256.is_empty());
        assert!(!entry.content_verified());
        assert_eq!(snap.issues[0].stage, "hash");
        assert!(!snap.is_complete());
    }

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

    #[test]
    fn changed_during_compares_length_and_mtime() {
        let dir = std::env::temp_dir().join(format!("rea_offline_test_{}", crate::util::new_id()));
        std::fs::create_dir_all(&dir).unwrap();
        let file = dir.join("f.bin");
        std::fs::write(&file, b"1234").unwrap();
        let before = std::fs::metadata(&file).unwrap();
        assert!(!changed_during(&before, &std::fs::metadata(&file).unwrap()));
        std::fs::write(&file, b"123456").unwrap();
        assert!(changed_during(&before, &std::fs::metadata(&file).unwrap()));
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn a_file_growing_during_capture_is_unverified_not_stable() {
        use std::sync::atomic::{AtomicBool, Ordering};
        let dir = std::env::temp_dir().join(format!("rea_offline_test_{}", crate::util::new_id()));
        std::fs::create_dir_all(&dir).unwrap();
        let file = dir.join("growing.bin");
        std::fs::write(&file, vec![7u8; 4 * 1024 * 1024]).unwrap();
        // Keep appending for the whole capture, so the file provably moves
        // between the pre-read stat and the post-read re-check.
        let stop = std::sync::Arc::new(AtomicBool::new(false));
        let writer = {
            let stop = stop.clone();
            let file = file.clone();
            std::thread::spawn(move || {
                let mut f = std::fs::OpenOptions::new().append(true).open(&file).unwrap();
                use std::io::Write;
                while !stop.load(Ordering::Relaxed) {
                    let _ = f.write_all(&[1u8; 1024]);
                    std::thread::sleep(std::time::Duration::from_micros(100));
                }
            })
        };
        let snap = Snapshot::capture(&dir).unwrap();
        stop.store(true, Ordering::Relaxed);
        writer.join().unwrap();
        let entry = snap.entries.get("growing.bin").expect("the file is still recorded");
        assert!(entry.sha256.is_empty(), "a torn read must not carry a trusted hash");
        assert!(
            snap.issues.iter().any(|i| i.path == "growing.bin" && i.stage == "changed"),
            "the movement must be named: {:?}", snap.issues
        );
        std::fs::remove_dir_all(&dir).unwrap();
    }
}
