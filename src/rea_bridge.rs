//! Module 4 — REA Engine Bridge.
//!
//! Primary path: invoke a locally installed REA (`morluto/rea`) CLI/Node
//! entry point, fully offline, and collect its JSON report.
//! Fallback path: the built-in native analyzer below (PE parsing, section
//! entropy, import table, indicator string scan). A machine with no REA
//! and no network still gets a useful structured report — REA enriches
//! it when present, it is never required.

use crate::json::Value;
use std::io::Read;
use crate::{Error, Result};
use std::path::{Path, PathBuf};
use std::time::Duration;

#[derive(Debug, Clone, Default)]
pub struct ReaConfig {
    /// Path to the REA executable or its Node entry (`.js`). `None` →
    /// probe `REA_PATH`, then `rea` on PATH, then fall back to native.
    pub rea_path: Option<PathBuf>,
    pub timeout: Option<Duration>,
}

#[derive(Debug, Clone)]
pub struct FileAnalysis {
    pub path: String,
    pub size: u64,
    pub sha256: String,
    /// MD5 for cross-checking against feeds that still publish MD5 only.
    /// Never used for integrity decisions inside this tool.
    pub md5: String,
    /// MD5 over the normalized import list (see [`imphash`]); `None` when
    /// the file has no import table. Comparable across builds of a family,
    /// which SHA-256 is not.
    pub imphash: Option<String>,
    pub format: String,
    /// Whole-file entropy, accumulated while hashing (not prefix entropy).
    pub entropy: f64,
    /// Bytes retained for structural and string inspection, starting at offset zero.
    pub content_bytes: u64,
    pub pe: Option<PeInfo>,
    pub indicators: Vec<Indicator>,
}

#[derive(Debug, Clone)]
pub struct PeSection {
    pub name: String,
    pub virtual_size: u32,
    pub raw_size: u32,
    pub raw_offset: u32,
    pub virtual_address: u32,
    /// Unknown when the entire raw section is not retained for inspection.
    pub entropy: Option<f64>,
    pub executable: bool,
    pub writable: bool,
}

/// A half-open file interval [offset, offset + size), never an RVA.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FileRange { pub offset: u64, pub size: u64 }
impl FileRange {
    fn to_json(&self) -> Value {
        Value::obj(vec![("offset", Value::num(self.offset)), ("size", Value::num(self.size))])
    }
}

#[derive(Debug, Clone)]
pub struct PeInfo {
    pub machine: String,
    pub is_64bit: bool,
    pub subsystem: String,
    pub sections: Vec<String>,
    pub section_details: Vec<PeSection>,
    pub imports: Vec<String>,
    /// `DLL.dll!FunctionName` (or `DLL.dll!#ordinal`) per imported function.
    pub imported_functions: Vec<String>,
    pub executable_sections: Vec<String>,
    /// COFF TimeDateStamp (seconds since epoch, as stamped by the linker).
    pub timestamp: u32,
    pub entry_point_rva: u32,
    /// Names of set DllCharacteristics flags, e.g. `dynamic_base`.
    pub dll_characteristics: Vec<String>,
    pub mitigations: Mitigations,
    /// True when an Authenticode certificate table is present (presence
    /// only — signature *validity* needs WinVerifyTrust, done by REA/OS).
    pub signed: bool,
    /// Bytes appended after the last section (classic dropper/packer sign).
    pub overlay_size: u64,
    pub overlay_ranges: Vec<FileRange>,
    pub certificate_range: Option<FileRange>,
}

#[derive(Debug, Clone, Copy, Default)]
pub struct Mitigations {
    pub aslr_dynamic_base: bool,
    pub nx_compat: bool,
    pub guard_cf: bool,
    pub no_seh: bool,
    pub high_entropy_va: bool,
}

#[derive(Debug, Clone)]
pub struct Indicator {
    pub category: String,
    pub matched: String,
    pub severity: String,
}

/// A coverage limitation, not a risk finding. Kept separate so an I/O
/// failure can never be mistaken for evidence that a file is malicious —
/// or silently disappear and make an incomplete scan look clean.
#[derive(Debug, Clone, PartialEq)]
pub struct ScanIssue {
    pub path: String,
    pub stage: String,
    pub message: String,
}

impl ScanIssue {
    pub fn new(path: impl Into<String>, stage: impl Into<String>, message: impl Into<String>) -> Self {
        Self { path: path.into(), stage: stage.into(), message: message.into() }
    }
    pub fn to_json(&self) -> Value {
        Value::obj(vec![
            ("path", Value::str(self.path.clone())),
            ("stage", Value::str(self.stage.clone())),
            ("message", Value::str(self.message.clone())),
        ])
    }
}

pub struct ReaReport {
    pub engine: String,
    pub target: String,
    pub files: Vec<FileAnalysis>,
    /// Raw REA JSON when the external engine ran.
    pub external_json: Option<Value>,
    /// Files/directories that could not be fully inspected. Additive schema-3
    /// field; older consumers can ignore it, new renderers surface it.
    pub scan_issues: Vec<ScanIssue>,
}

impl ReaReport {
    /// All rule findings across the report (rules module owns the logic;
    /// the bridge just knows how to ask).
    pub fn findings(&self) -> Vec<crate::rules::Finding> {
        crate::rules::evaluate(self)
    }

    /// 0–100 risk score. Every point is attributable to a named finding in
    /// `rules`/`findings`, so a number in a report can always be explained.
    pub fn risk_score(&self) -> u64 {
        crate::rules::risk(&self.findings()).0
    }

    /// `low` / `medium` / `high` / `critical`.
    pub fn verdict(&self) -> &'static str {
        crate::rules::risk(&self.findings()).1
    }
    pub fn to_json(&self) -> Value {
        let files = self.files.iter().map(|f| {
            let mut pairs = vec![
                ("path", Value::str(f.path.clone())),
                ("size", Value::num(f.size)),
                ("sha256", Value::str(f.sha256.clone())),
                ("md5", Value::str(f.md5.clone())),
                ("imphash", f.imphash.clone().map(Value::str).unwrap_or(Value::Null)),
                ("format", Value::str(f.format.clone())),
                ("entropy", Value::Number((f.entropy * 1000.0).round() / 1000.0)),
                ("analysis_scope", Value::obj(vec![
                    ("content_bytes", Value::num(f.content_bytes)),
                    ("content_complete", Value::Bool(f.content_bytes == f.size)),
                    ("hash_bytes", Value::num(f.size)),
                    ("entropy_bytes", Value::num(f.size)),
                ])),
                ("indicators", Value::Array(f.indicators.iter().map(|i| Value::obj(vec![
                    ("category", Value::str(i.category.clone())),
                    ("matched", Value::str(i.matched.clone())),
                    ("severity", Value::str(i.severity.clone())),
                ])).collect())),
            ];
            if let Some(pe) = &f.pe {
                pairs.push(("pe", Value::obj(vec![
                    ("machine", Value::str(pe.machine.clone())),
                    ("is_64bit", Value::Bool(pe.is_64bit)),
                    ("subsystem", Value::str(pe.subsystem.clone())),
                    ("timestamp", Value::num(pe.timestamp as u64)),
                    ("entry_point_rva", Value::num(pe.entry_point_rva as u64)),
                    ("sections", Value::Array(pe.sections.iter().map(|s| Value::str(s.clone())).collect())),
                    ("section_details", Value::Array(pe.section_details.iter().map(|s| Value::obj(vec![
                        ("name", Value::str(s.name.clone())),
                        ("virtual_size", Value::num(s.virtual_size as u64)),
                        ("raw_size", Value::num(s.raw_size as u64)),
                        ("raw_offset", Value::num(s.raw_offset as u64)),
                        ("virtual_address", Value::num(s.virtual_address as u64)),
                        ("entropy", s.entropy.map(|e| Value::Number((e * 1000.0).round() / 1000.0)).unwrap_or(Value::Null)),
                        ("executable", Value::Bool(s.executable)),
                        ("writable", Value::Bool(s.writable)),
                    ])).collect())),
                    ("imports", Value::Array(pe.imports.iter().map(|s| Value::str(s.clone())).collect())),
                    ("imported_functions", Value::Array(pe.imported_functions.iter().map(|s| Value::str(s.clone())).collect())),
                    ("executable_sections", Value::Array(pe.executable_sections.iter().map(|s| Value::str(s.clone())).collect())),
                    ("dll_characteristics", Value::Array(pe.dll_characteristics.iter().map(|s| Value::str(s.clone())).collect())),
                    ("mitigations", Value::obj(vec![
                        ("aslr_dynamic_base", Value::Bool(pe.mitigations.aslr_dynamic_base)),
                        ("nx_compat", Value::Bool(pe.mitigations.nx_compat)),
                        ("guard_cf", Value::Bool(pe.mitigations.guard_cf)),
                        ("no_seh", Value::Bool(pe.mitigations.no_seh)),
                        ("high_entropy_va", Value::Bool(pe.mitigations.high_entropy_va)),
                    ])),
                    ("signed", Value::Bool(pe.signed)),
                    ("overlay_size", Value::num(pe.overlay_size)),
                    ("overlay_ranges", Value::Array(pe.overlay_ranges.iter().map(FileRange::to_json).collect())),
                    ("certificate_range", pe.certificate_range.as_ref().map(FileRange::to_json).unwrap_or(Value::Null)),
                ])));
            }
            Value::obj(pairs)
        }).collect();
        let findings = self.findings();
        let (score, verdict) = crate::rules::risk(&findings);
        let mut root = vec![
            ("engine", Value::str(self.engine.clone())),
            ("target", Value::str(self.target.clone())),
            ("file_count", Value::num(self.files.len() as u64)),
            ("risk_score", Value::num(score)),
            ("verdict", Value::str(verdict)),
            ("summary", self.summary_json()),
            ("scan_issues", Value::Array(self.scan_issues.iter().map(ScanIssue::to_json).collect())),
            ("rules", crate::rules::to_json(&findings)),
            ("files", Value::Array(files)),
        ];
        if let Some(ext) = &self.external_json {
            root.push(("rea_external", ext.clone()));
        }
        Value::obj(root)
    }
}

impl ReaReport {
    /// Aggregate counts for dashboards / quick human triage.
    pub fn summary_json(&self) -> Value {
        use std::collections::BTreeMap;
        let mut by_format: BTreeMap<&str, u64> = BTreeMap::new();
        let (mut high, mut medium, mut low) = (0u64, 0u64, 0u64);
        let mut packed = 0u64;
        let mut unsigned_pe = 0u64;
        let mut wx_sections = 0u64;
        for f in &self.files {
            *by_format.entry(f.format.as_str()).or_default() += 1;
            if f.entropy > 7.2 { packed += 1; }
            for i in &f.indicators {
                match i.severity.as_str() { "high" => high += 1, "medium" => medium += 1, _ => low += 1 }
            }
            if let Some(pe) = &f.pe {
                if !pe.signed { unsigned_pe += 1; }
                wx_sections += pe.section_details.iter().filter(|s| s.executable && s.writable).count() as u64;
            }
        }
        let with_imphash = self.files.iter().filter(|f| f.imphash.is_some()).count() as u64;
        Value::obj(vec![
            ("by_format", Value::Object(by_format.into_iter().map(|(k, v)| (k.to_string(), Value::num(v))).collect())),
            ("indicators", Value::obj(vec![
                ("high", Value::num(high)), ("medium", Value::num(medium)), ("low", Value::num(low)),
            ])),
            ("total_bytes", Value::num(self.files.iter().map(|f| f.size).sum())),
            ("pe_files", Value::num(self.files.iter().filter(|f| f.pe.is_some()).count() as u64)),
            ("files_with_imphash", Value::num(with_imphash)),
            ("high_entropy_files", Value::num(packed)),
            ("unsigned_pe_files", Value::num(unsigned_pe)),
            ("writable_executable_sections", Value::num(wx_sections)),
            ("verdict", Value::str(self.verdict())),
            ("risk_score", Value::num(self.risk_score())),
            ("scan_issue_count", Value::num(self.scan_issues.len() as u64)),
            ("complete", Value::Bool(self.scan_issues.is_empty())),
        ])
    }
}

pub struct ReaBridge {
    config: ReaConfig,
}

impl ReaBridge {
    pub fn new(config: ReaConfig) -> ReaBridge { ReaBridge { config } }

    /// The REA executable that would be used, if any (for `doctor`).
    pub fn resolved_rea_path(&self) -> Option<PathBuf> { self.resolve_rea() }

    fn resolve_rea(&self) -> Option<PathBuf> {
        // An explicit selection must not silently switch to another tool
        // when misspelled or missing: report its failure alongside native results.
        if let Some(p) = &self.config.rea_path { return Some(p.clone()); }
        if let Some(p) = std::env::var_os("REA_PATH").filter(|p| !p.is_empty()) {
            return Some(PathBuf::from(p));
        }
        std::env::var_os("PATH").and_then(|path| {
            discover_rea(std::env::split_paths(&path), cfg!(windows))
        })
    }

    /// Analyze a file or a directory (recursively) — Mode A entry point.
    pub fn analyze(&self, target: &Path) -> Result<ReaReport> {
        if !target.exists() { return Err(Error::NotFound(target.to_path_buf())); }
        if let Some(rea) = self.resolve_rea() {
            match self.run_external(&rea, target) {
                Ok(json) => {
                    // External findings complement, never replace, native ones.
                    let mut report = self.analyze_native(target)?;
                    report.engine = format!("rea-external ({}) + native", rea.display());
                    report.external_json = Some(json);
                    return Ok(report);
                }
                Err(e) => {
                    let mut report = self.analyze_native(target)?;
                    report.scan_issues.push(ScanIssue::new(
                        crate::util::path_to_slash_string(target), "rea-external",
                        format!("External REA analyzer '{}' failed: {e}. Native static analysis completed; external enrichment is unavailable.", rea.display()),
                    ));
                    return Ok(report);
                }
            }
        }
        self.analyze_native(target)
    }

    fn run_external(&self, rea: &Path, target: &Path) -> Result<Value> {
        #[cfg(windows)]
        if !matches!(crate::util::extension_lower(rea).as_str(), "exe" | "cmd" | "bat" | "js") {
            return Err(Error::InvalidInput(format!(
                "unsupported Windows REA launcher '{}'; select a Windows .exe, .cmd/.bat launcher, or Node .js entry point with REA_PATH or --rea", rea.display()
            )));
        }
        let is_js = crate::util::extension_lower(rea) == "js";
        let mut cmd = if is_js {
            let mut c = std::process::Command::new("node");
            c.arg(rea);
            c
        } else {
            // Rust's Windows Command handles .cmd/.bat using its batch-file
            // quoting rules. Do not concatenate target paths into cmd /C.
            std::process::Command::new(rea)
        };
        cmd.arg(target).arg("--format").arg("json")
            .stdin(std::process::Stdio::null());
        let timeout = self.config.timeout.unwrap_or(Duration::from_secs(600));
        let output = run_with_timeout(cmd, timeout).map_err(|e| Error::Process(format!(
            "could not run REA launcher '{}': {e}. On Windows, error 193 means the launcher is not a compatible Windows application; use its .cmd launcher or .js entry point instead of an extensionless script, or a matching-architecture .exe", rea.display()
        )))?;
        if output.stdout_truncated {
            return Err(Error::Process(format!(
                "REA stdout exceeded the {} MiB capture limit ({} bytes seen)",
                MAX_REA_STDOUT_BYTES / (1024 * 1024),
                output.stdout_bytes
            )));
        }
        if !output.status_ok {
            let stderr = tail_str(output.stderr.trim(), 512);
            return Err(Error::Process(if stderr.is_empty() {
                format!("REA exited with code {:?}", output.exit_code)
            } else {
                format!("REA exited with code {:?}: {stderr}", output.exit_code)
            }));
        }
        crate::json::parse(&output.stdout).map_err(|e| {
            let stderr = tail_str(output.stderr.trim(), 256);
            if stderr.is_empty() {
                Error::Process(format!(
                    "REA did not emit valid JSON: {e} (stdout {} bytes, stderr {} bytes)",
                    output.stdout_bytes, output.stderr_bytes
                ))
            } else {
                Error::Process(format!(
                    "REA did not emit valid JSON: {e}; stderr: {stderr}"
                ))
            }
        })
    }

    pub fn analyze_native(&self, target: &Path) -> Result<ReaReport> {
        let mut files = Vec::new();
        let mut scan_issues = Vec::new();
        let meta = std::fs::symlink_metadata(target)?;
        if meta.is_file() {
            let display = target.file_name().map(Path::new).unwrap_or(target);
            let file = analyze_file(target, display)?;
            if file.size > MAX_ANALYZE_BYTES {
                scan_issues.push(content_limit_issue(&file.path, file.size));
            }
            files.push(file);
        } else if meta.is_dir() {
            // Walk without following links, including file links. Snapshot
            // manifests intentionally record links as entries; static analysis
            // must not read a link target outside the selected tree.
            let mut stack = vec![(target.to_path_buf(), String::new())];
            while let Some((dir, prefix)) = stack.pop() {
                let read = match std::fs::read_dir(&dir) {
                    Ok(read) => read,
                    Err(e) => {
                        scan_issues.push(ScanIssue::new(display_path(&prefix, &dir, target), "directory", e.to_string()));
                        continue;
                    }
                };
                let mut children = Vec::new();
                for entry in read {
                    match entry {
                        Ok(entry) => children.push(entry.path()),
                        Err(e) => scan_issues.push(ScanIssue::new(
                            display_path(&prefix, &dir, target), "directory-entry", e.to_string(),
                        )),
                    }
                }
                children.sort();
                for path in children {
                    let name = path.file_name().map(|n| n.to_string_lossy().into_owned()).unwrap_or_default();
                    let rel = if prefix.is_empty() { name } else { format!("{prefix}/{name}") };
                    let meta = match std::fs::symlink_metadata(&path) {
                        Ok(meta) => meta,
                        Err(e) => { scan_issues.push(ScanIssue::new(rel, "metadata", e.to_string())); continue; }
                    };
                    if meta.is_dir() {
                        stack.push((path, rel));
                    } else if meta.is_file() {
                        match analyze_file(&path, Path::new(&rel)) {
                            Ok(file) => {
                                if file.size > MAX_ANALYZE_BYTES {
                                    scan_issues.push(content_limit_issue(&rel, file.size));
                                }
                                files.push(file);
                            }
                            Err(e) => scan_issues.push(ScanIssue::new(rel, "analysis", e.to_string())),
                        }
                    } else if meta.file_type().is_symlink() {
                        // Never follow a link to a target outside the tree —
                        // but say so. A link that is silently skipped is a
                        // file the report never mentions, under a summary
                        // that still claims the scan was complete.
                        scan_issues.push(ScanIssue::new(rel, "symlink",
                            "symlink not followed; its target was not analyzed"));
                    } else {
                        scan_issues.push(ScanIssue::new(rel, "special",
                            "not a regular file or directory; not analyzed"));
                    }
                }
            }
        } else {
            return Err(Error::InvalidInput(format!("not a regular file or directory: {}", target.display())));
        }
        files.sort_by(|a, b| a.path.cmp(&b.path));
        scan_issues.sort_by(|a, b| a.path.cmp(&b.path).then(a.stage.cmp(&b.stage)));
        Ok(ReaReport {
            engine: "rea-offline-native".to_string(),
            target: crate::util::path_to_slash_string(target),
            files,
            external_json: None,
            scan_issues,
        })
    }
}

/// Platform-specific candidates keep npm's Unix shell shim `rea` from
/// shadowing rea.cmd on Windows. PATH directory precedence is preserved.
fn discover_rea(directories: impl IntoIterator<Item = PathBuf>, windows: bool) -> Option<PathBuf> {
    let names: &[&str] = if windows {
        &["rea.exe", "rea.cmd", "rea.js", "rea.bat"]
    } else {
        &["rea", "rea.exe", "rea.cmd", "rea.js"]
    };
    for dir in directories {
        for name in names {
            let candidate = dir.join(name);
            if candidate.is_file() { return Some(candidate); }
        }
    }
    None
}

/// External REA output is captured through temporary files rather than
/// pipes. A pipe that is not drained while the child runs can fill its OS
/// buffer and deadlock the child until the timeout; stderr was previously
/// never drained at all. Files also let us bound disk/memory use and keep
/// stderr for diagnostics.
const MAX_REA_STDOUT_BYTES: u64 = 32 * 1024 * 1024;
const MAX_REA_STDERR_BYTES: u64 = 1024 * 1024;

#[derive(Debug)]
struct CmdOutput {
    status_ok: bool,
    exit_code: Option<i32>,
    stdout: String,
    stderr: String,
    stdout_bytes: u64,
    stderr_bytes: u64,
    stdout_truncated: bool,
}

struct CaptureFile {
    path: PathBuf,
}

impl Drop for CaptureFile {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.path);
    }
}

fn read_capped(path: &Path, cap: u64) -> Result<(String, u64, bool)> {
    use std::io::Read;
    let file = std::fs::File::open(path)?;
    let total = file.metadata()?.len();
    let mut buf = Vec::new();
    file.take(cap.saturating_add(1)).read_to_end(&mut buf)?;
    let truncated = total > cap;
    if buf.len() as u64 > cap {
        buf.truncate(cap as usize);
    }
    Ok((String::from_utf8_lossy(&buf).to_string(), total, truncated))
}

fn tail_str(s: &str, max: usize) -> &str {
    if s.len() <= max {
        return s;
    }
    let mut start = s.len() - max;
    while start < s.len() && !s.is_char_boundary(start) {
        start += 1;
    }
    &s[start..]
}

fn run_with_timeout(mut cmd: std::process::Command, timeout: Duration) -> Result<CmdOutput> {
    let id = crate::util::new_id();
    let stdout_path = crate::util::temp_root().join(format!("rea_offline_rea_{id}.stdout.log"));
    let stderr_path = crate::util::temp_root().join(format!("rea_offline_rea_{id}.stderr.log"));
    // create_new refuses to follow a pre-planted symlink in the temp dir.
    let stdout_file = std::fs::OpenOptions::new().write(true).create_new(true).open(&stdout_path)?;
    let _stdout_guard = CaptureFile { path: stdout_path.clone() };
    let stderr_file = std::fs::OpenOptions::new().write(true).create_new(true).open(&stderr_path)?;
    let _stderr_guard = CaptureFile { path: stderr_path.clone() };

    let mut child = cmd
        .stdout(std::process::Stdio::from(stdout_file))
        .stderr(std::process::Stdio::from(stderr_file))
        .spawn()?;
    let deadline = std::time::Instant::now() + timeout;
    let status = loop {
        if let Some(status) = child.try_wait()? {
            break status;
        }
        // Bound capture size while the child is still running, not only
        // when reading the result back.
        if std::fs::metadata(&stdout_path).map(|m| m.len()).unwrap_or(0) > MAX_REA_STDOUT_BYTES {
            let _ = child.kill();
            let _ = child.wait();
            return Err(Error::Process(format!(
                "REA stdout exceeded the {} MiB capture limit",
                MAX_REA_STDOUT_BYTES / (1024 * 1024)
            )));
        }
        if std::fs::metadata(&stderr_path).map(|m| m.len()).unwrap_or(0) > MAX_REA_STDERR_BYTES {
            let _ = child.kill();
            let _ = child.wait();
            return Err(Error::Process(format!(
                "REA stderr exceeded the {} KiB capture limit",
                MAX_REA_STDERR_BYTES / 1024
            )));
        }
        if std::time::Instant::now() >= deadline {
            let _ = child.kill();
            let _ = child.wait();
            return Err(Error::Timeout("REA process exceeded its timeout".into()));
        }
        std::thread::sleep(Duration::from_millis(50));
    };

    let (stdout, stdout_bytes, stdout_truncated) = read_capped(&stdout_path, MAX_REA_STDOUT_BYTES)?;
    let (stderr, stderr_bytes, _) = read_capped(&stderr_path, MAX_REA_STDERR_BYTES)?;
    Ok(CmdOutput {
        status_ok: status.success(),
        exit_code: status.code(),
        stdout,
        stderr,
        stdout_bytes,
        stderr_bytes,
        stdout_truncated,
    })
}

// ---------------------------------------------------------------------------
// Native static analysis
// ---------------------------------------------------------------------------

pub(crate) const MAX_ANALYZE_BYTES: u64 = 32 * 1024 * 1024;

pub(crate) fn content_limit_issue(path: &str, size: u64) -> ScanIssue {
    ScanIssue::new(
        path, "content",
        format!("file is {size} bytes, above the {} MiB content-analysis limit; only the first {} bytes are inspected for structure and strings; hashes and entropy cover the full file; imports may be partial and imphash is withheld", MAX_ANALYZE_BYTES / (1024 * 1024), MAX_ANALYZE_BYTES),
    )
}

fn display_path(prefix: &str, path: &Path, root: &Path) -> String {
    if prefix.is_empty() {
        let rel = crate::util::path_to_slash_string(path.strip_prefix(root).unwrap_or(path));
        if rel.is_empty() { ".".to_string() } else { rel }
    } else {
        prefix.to_string()
    }
}

pub fn analyze_file(path: &Path, display: &Path) -> Result<FileAnalysis> {
    let mut file = std::fs::File::open(path)?;
    let meta = file.metadata()?;
    if !meta.is_file() {
        return Err(Error::InvalidInput(format!("not a regular file: {}", path.display())));
    }
    let size = meta.len();
    let sample = inspect_stream(&mut file, MAX_ANALYZE_BYTES as usize)?;
    // Hashes, entropy and prefix now describe the same byte stream. Still
    // refuse detectable mutation/replacement rather than claim a stable file.
    let after = file.metadata()?;
    let path_after = std::fs::metadata(path)?;
    if sample.size != size || meta.len() != after.len()
        || meta.modified().ok() != after.modified().ok()
        || meta.len() != path_after.len() || meta.modified().ok() != path_after.modified().ok()
    {
        return Err(Error::InvalidInput(format!(
            "{} changed while it was being analyzed; no stable file record can be produced", path.display()
        )));
    }
    let data = sample.prefix;
    let format = detect_format(&data, path);
    let pe = if format == "PE" { parse_pe_with_size(&data, size) } else { None };
    // A partial import table must not become a comparable family fingerprint.
    let imphash = if data.len() as u64 == size {
        pe.as_ref().and_then(|p| imphash(&p.imported_functions))
    } else { None };
    Ok(FileAnalysis {
        path: crate::util::path_to_slash_string(display),
        size,
        sha256: sample.sha256,
        md5: sample.md5,
        imphash,
        format,
        entropy: sample.entropy,
        content_bytes: data.len() as u64,
        indicators: scan_indicators(&data),
        pe,
    })
}

/// Bounded memory independent of input length. Full-stream fingerprints and
/// entropy share exactly the bytes read; only the prefix is retained.
struct StreamInspection {
    size: u64,
    prefix: Vec<u8>,
    sha256: String,
    md5: String,
    entropy: f64,
}

fn inspect_stream(reader: &mut impl Read, limit: usize) -> std::io::Result<StreamInspection> {
    let mut sha = crate::sha256::Sha256::new();
    let mut md5 = crate::md5::Md5::new();
    let mut counts = [0u64; 256];
    let mut size = 0u64;
    let mut prefix = Vec::new();
    let mut buf = [0u8; 64 * 1024];
    loop {
        let n = match reader.read(&mut buf) {
            Err(e) if e.kind() == std::io::ErrorKind::Interrupted => continue,
            result => result?,
        };
        if n == 0 { break; }
        size = size.checked_add(n as u64).ok_or_else(||
            std::io::Error::new(std::io::ErrorKind::InvalidData, "file length overflow"))?;
        let chunk = &buf[..n];
        sha.update(chunk);
        md5.update(chunk);
        for byte in chunk { counts[*byte as usize] += 1; }
        let keep = n.min(limit.saturating_sub(prefix.len()));
        prefix.extend_from_slice(&chunk[..keep]);
    }
    Ok(StreamInspection { size, prefix,
        sha256: crate::sha256::to_hex(&sha.finalize()),
        md5: crate::sha256::to_hex(&md5.finalize()),
        entropy: entropy_counts(&counts, size),
    })
}

/// `kernel32.dll!CreateRemoteThread` → `CreateRemoteThread`. Import names
/// are stored qualified so reports keep the owning DLL; rules usually care
/// about the function alone.
pub fn bare_function(import: &str) -> &str {
    import.rsplit('!').next().unwrap_or(import)
}

/// Import hash ("imphash"): MD5 over the normalized import list, byte-for-byte
/// the convention `pefile` uses, so values line up with VirusTotal, YARA and
/// YARA-X rather than merely looking like them.
///
/// Normalization, per pefile's `get_imphash()`:
///   * libraries and functions are visited in **file order** — descriptor
///     order, then thunk order. Order is significant: reordering imports
///     changes the digest, which is what makes it a build fingerprint.
///   * the library is lowercased and loses its extension **only** when that
///     extension is `.ocx`, `.sys` or `.dll` (so `.drv`/`.cpl` keep theirs).
///   * `DLL.dll!Func`  → `dll.func`
///   * `DLL.dll!#42`   → `dll.<name>` when the frozen ordinal table knows it
///     (`ws2_32.dll!#23` → `ws2_32.socket`), otherwise `dll.ord42`. The lookup
///     keys on the full lowercased DLL name, before the extension is dropped.
///   * entries are joined with `,` and hashed with MD5.
///
/// Earlier versions of this function sorted ordinals to the end, emitted them
/// unqualified, and stripped `.drv`/`.cpl` too. All three diverged from pefile,
/// so digests for ordinal-importing samples did not match public corpora.
pub fn imphash(imported_functions: &[String]) -> Option<String> {
    let normalized = imphash_source(imported_functions);
    if normalized.is_empty() {
        return None;
    }
    Some(crate::md5::hash_bytes(normalized.as_bytes()))
}

/// The exact string [`imphash`] hashes. Exposed because "why is this digest
/// what it is" is otherwise unanswerable without re-deriving the algorithm,
/// and because it lets tests assert the normalization directly instead of
/// only comparing opaque hashes.
pub fn imphash_source(imported_functions: &[String]) -> String {
    let mut entries: Vec<String> = Vec::new();
    for entry in imported_functions {
        let Some((dll, func)) = entry.split_once('!') else { continue };
        if func.is_empty() {
            continue;
        }
        let dll_lower = dll.to_lowercase();
        // rsplit(".", 1): only a recognised executable extension is dropped.
        let stem = match dll_lower.rsplit_once('.') {
            Some((prefix, "ocx" | "sys" | "dll")) => prefix,
            _ => dll_lower.as_str(),
        };
        let name = match func.strip_prefix('#') {
            Some(ordinal) => match ordinal.trim().parse::<u16>() {
                Ok(ordinal) => crate::imphash_ordinals::lookup(&dll_lower, ordinal),
                // Only our own parser writes these, and it always emits a
                // u16; anything else is not an import we can name.
                Err(_) => continue,
            },
            None => func.to_lowercase(),
        };
        entries.push(format!("{stem}.{name}"));
    }
    entries.join(",")
}

fn detect_format(data: &[u8], path: &Path) -> String {
    if data.starts_with(b"MZ") { return "PE".to_string(); }
    if data.starts_with(b"\x7fELF") { return "ELF".to_string(); }
    if data.starts_with(b"PK\x03\x04") { return "ZIP".to_string(); }
    if data.starts_with(b"\xd0\xcf\x11\xe0") { return "OLE/MSI".to_string(); }
    match crate::util::extension_lower(path).as_str() {
        "ps1" | "bat" | "cmd" | "vbs" | "js" | "sh" | "py" => "script".to_string(),
        "exe" | "dll" | "sys" => "binary".to_string(),
        _ if data.iter().take(4096).all(|b| b.is_ascii() || *b == b'\n' || *b == b'\r') && !data.is_empty() => "text".to_string(),
        _ => "unknown".to_string(),
    }
}

pub fn shannon_entropy(data: &[u8]) -> f64 {
    if data.is_empty() { return 0.0; }
    let mut counts = [0u64; 256];
    for b in data { counts[*b as usize] += 1; }
    entropy_counts(&counts, data.len() as u64)
}

fn entropy_counts(counts: &[u64; 256], size: u64) -> f64 {
    if size == 0 { return 0.0; }
    let len = size as f64;
    counts.iter().filter(|&&c| c > 0).map(|&c| {
        let p = c as f64 / len;
        -p * p.log2()
    }).sum()
}

/// (needle, category, severity) — capability indicators, not verdicts.
const INDICATORS: &[(&str, &str, &str)] = &[
    ("http://", "network", "medium"), ("https://", "network", "low"),
    ("powershell", "execution", "high"), ("cmd.exe", "execution", "medium"),
    ("CreateProcess", "execution", "medium"), ("ShellExecute", "execution", "medium"),
    ("VirtualAlloc", "memory", "medium"), ("WriteProcessMemory", "memory", "high"),
    ("CreateRemoteThread", "injection", "high"), ("RegSetValue", "persistence", "medium"),
    ("CurrentVersion\\Run", "persistence", "high"), ("schtasks", "persistence", "medium"),
    ("CreateService", "persistence", "high"), ("IsDebuggerPresent", "anti-analysis", "medium"),
    ("VirtualProtect", "memory", "medium"), ("CryptEncrypt", "crypto", "low"),
    ("WinHttp", "network", "medium"), ("InternetOpen", "network", "medium"),
    ("socket", "network", "low"), ("DownloadString", "network", "high"),
    ("FromBase64String", "obfuscation", "medium"), ("-enc", "obfuscation", "medium"),
];

fn extract_ascii_strings(data: &[u8], min_len: usize) -> Vec<String> {
    let mut out = Vec::new();
    let mut cur = Vec::new();
    for &b in data {
        if (0x20..=0x7e).contains(&b) { cur.push(b); }
        else {
            if cur.len() >= min_len {
                if let Ok(s) = String::from_utf8(cur.clone()) { out.push(s); }
            }
            cur.clear();
        }
    }
    if cur.len() >= min_len {
        if let Ok(s) = String::from_utf8(cur) { out.push(s); }
    }
    out
}

fn scan_indicators(data: &[u8]) -> Vec<Indicator> {
    if data.is_empty() { return Vec::new(); }
    let haystack = extract_ascii_strings(data, 4).join("\n");
    let mut found = Vec::new();
    for (needle, category, severity) in INDICATORS {
        if haystack.contains(needle) {
            found.push(Indicator {
                category: category.to_string(),
                matched: needle.to_string(),
                severity: severity.to_string(),
            });
        }
    }
    found.sort_by(|a, b| a.category.cmp(&b.category).then(a.matched.cmp(&b.matched)));
    found.dedup_by(|a, b| a.category == b.category && a.matched == b.matched);
    found
}

// --- Minimal PE parser (headers, sections, import DLL/function names) ------

fn u16le(d: &[u8], off: usize) -> Option<u16> {
    d.get(off..off.checked_add(2)?).map(|s| u16::from_le_bytes([s[0], s[1]]))
}
fn u32le(d: &[u8], off: usize) -> Option<u32> {
    d.get(off..off.checked_add(4)?).map(|s| u32::from_le_bytes([s[0], s[1], s[2], s[3]]))
}
fn u64le(d: &[u8], off: usize) -> Option<u64> {
    d.get(off..off.checked_add(8)?).map(|s| u64::from_le_bytes([s[0], s[1], s[2], s[3], s[4], s[5], s[6], s[7]]))
}

struct Section {
    virtual_address: u32,
    virtual_size: u32,
    raw_ptr: u32,
    raw_size: u32,
}

/// Parse a PE image already in memory (used by tests, fixtures and callers
/// that hold bytes rather than a path).
pub fn parse_pe_bytes(data: &[u8]) -> Option<PeInfo> { parse_pe(data) }

fn parse_pe(data: &[u8]) -> Option<PeInfo> {
    parse_pe_with_size(data, data.len() as u64)
}

fn parse_pe_with_size(data: &[u8], file_len: u64) -> Option<PeInfo> {
    if !data.starts_with(b"MZ") { return None; }
    let pe_off = u32le(data, 0x3c)? as usize;
    if data.get(pe_off..pe_off.checked_add(4)?)? != b"PE\0\0".as_slice() { return None; }
    let coff = pe_off + 4;
    let machine_raw = u16le(data, coff)?;
    let num_sections = u16le(data, coff + 2)? as usize;
    let opt_size = u16le(data, coff + 16)? as usize;
    let opt = coff + 20;
    // The optional header is a declared structure, not permission to read
    // arbitrary bytes from the section table or payload as header fields.
    let optional = data.get(opt..opt.checked_add(opt_size)?)?;
    let magic = u16le(optional, 0)?;
    let is_64bit = match magic { 0x10b => false, 0x20b => true, _ => return None };
    let directory_base = if is_64bit { 112 } else { 96 };
    if optional.len() < directory_base { return None; }
    let directory_count = u32le(optional, directory_base - 4)? as usize;
    let headers_size = u32le(optional, 60)? as usize;
    let timestamp = u32le(data, coff + 4).unwrap_or(0);
    let entry_point_rva = u32le(data, opt + 16).unwrap_or(0);
    let subsystem_raw = u16le(data, opt + 68)?; // same offset in PE32 and PE32+
    // DllCharacteristics sits at optional-header offset 70 in both formats.
    let dll_char_raw = u16le(data, opt + 70).unwrap_or(0);
    const DLL_CHARS: &[(u16, &str)] = &[
        (0x0020, "high_entropy_va"), (0x0040, "dynamic_base"), (0x0080, "force_integrity"),
        (0x0100, "nx_compat"), (0x0200, "no_isolation"), (0x0400, "no_seh"),
        (0x0800, "no_bind"), (0x1000, "app_container"), (0x2000, "wdm_driver"),
        (0x4000, "guard_cf"), (0x8000, "terminal_server_aware"),
    ];
    let dll_characteristics: Vec<String> = DLL_CHARS.iter()
        .filter(|(bit, _)| dll_char_raw & bit != 0)
        .map(|(_, name)| name.to_string()).collect();
    let mitigations = Mitigations {
        aslr_dynamic_base: dll_char_raw & 0x0040 != 0,
        nx_compat: dll_char_raw & 0x0100 != 0,
        guard_cf: dll_char_raw & 0x4000 != 0,
        no_seh: dll_char_raw & 0x0400 != 0,
        high_entropy_va: dll_char_raw & 0x0020 != 0,
    };
    // Data directories start at opt+96 (PE32) / opt+112 (PE32+); import = #1,
    // certificate (Authenticode) = #4 and is a *file offset*, not an RVA.
    let directory = |idx: usize| -> (u32, u32) {
        if idx >= directory_count { return (0, 0); }
        let off = directory_base + idx * 8;
        match (u32le(optional, off), u32le(optional, off + 4)) {
            (Some(address), Some(size)) => (address, size),
            _ => (0, 0),
        }
    };
    let dir_rva = |idx: usize| directory(idx).0;
    let dir_size = |idx: usize| directory(idx).1;
    let import_rva = dir_rva(1);
    let cert_off = dir_rva(4) as u64;
    let cert_size = dir_size(4) as u64;
    let certificate_in_file = cert_off != 0 && cert_size >= 8
        && cert_off + cert_size <= file_len;

    let mut sections = Vec::new();
    let mut section_details = Vec::new();
    let mut parsed_sections = Vec::new();
    let mut executable_sections = Vec::new();
    let mut last_section_end = 0u64;
    let sec_base = opt + opt_size;
    for i in 0..num_sections.min(96) {
        let off = sec_base + i * 40;
        let name_bytes = data.get(off..off + 8)?;
        let name = String::from_utf8_lossy(name_bytes).trim_end_matches('\0').to_string();
        let characteristics = u32le(data, off + 36).unwrap_or(0);
        let raw_size = u32le(data, off + 16).unwrap_or(0);
        let raw_ptr = u32le(data, off + 20).unwrap_or(0);
        let executable = characteristics & 0x2000_0000 != 0;
        let writable = characteristics & 0x8000_0000 != 0;
        if executable { executable_sections.push(name.clone()); }
        last_section_end = last_section_end.max(raw_ptr as u64 + raw_size as u64);
        let raw = data.get(raw_ptr as usize..(raw_ptr as usize).saturating_add(raw_size as usize));
        section_details.push(PeSection {
            name: name.clone(),
            virtual_size: u32le(data, off + 8).unwrap_or(0),
            raw_size,
            raw_offset: raw_ptr,
            virtual_address: u32le(data, off + 12).unwrap_or(0),
            entropy: raw.map(shannon_entropy),
            executable,
            writable,
        });
        sections.push(name.clone());
        parsed_sections.push(Section {
            virtual_size: u32le(data, off + 8).unwrap_or(0),
            virtual_address: u32le(data, off + 12).unwrap_or(0),
            raw_size,
            raw_ptr,
        });
    }
    // Presence only, not cryptographic trust. A table pointing outside the
    // actual file or into a section is not an on-disk certificate table.
    let signed = certificate_in_file && cert_off >= last_section_end.max(headers_size as u64);
    // Record exact disjoint file intervals, excluding certificate bytes but
    // retaining payloads on either side. Headers are not overlay data.
    let start = last_section_end.max(headers_size as u64).min(file_len);
    let certificate_range = if signed { Some(FileRange { offset: cert_off, size: cert_size }) } else { None };
    let mut overlay_ranges = Vec::new();
    if signed {
        if start < cert_off { overlay_ranges.push(FileRange { offset: start, size: cert_off - start }); }
        let end = cert_off + cert_size;
        if end < file_len { overlay_ranges.push(FileRange { offset: end, size: file_len - end }); }
    } else if start < file_len {
        overlay_ranges.push(FileRange { offset: start, size: file_len - start });
    }
    let overlay_size = overlay_ranges.iter().map(|range| range.size).sum();

    let rva_to_offset = |rva: u32| -> Option<usize> {
        for s in &parsed_sections {
            // Widen before addition: hostile u32 addresses can wrap in
            // optimized builds or panic in debug builds.
            let delta = (rva as u64).checked_sub(s.virtual_address as u64);
            if let Some(delta) = delta.filter(|d| *d < s.virtual_size.max(s.raw_size) as u64) {
                // Virtual zero-fill is not backed by file bytes and must
                // not be read as an import table from a following section.
                if delta >= s.raw_size as u64 { return None; }
                let off = s.raw_ptr as u64 + delta;
                return usize::try_from(off).ok().filter(|off| *off < data.len());
            }
        }
        // RVAs outside sections may point into headers, not arbitrary raw
        // section contents. SizeOfHeaders bounds this fallback.
        if (rva as usize) < headers_size && (rva as usize) < data.len() { Some(rva as usize) } else { None }
    };

    let read_c_string = |off: usize| -> Option<String> {
        // Do not invent an import name from an unterminated prefix or
        // replace invalid bytes with Unicode replacement characters.
        let slice = data.get(off..off.saturating_add(512).min(data.len()))?;
        let end = slice.iter().position(|&b| b == 0)?;
        let name = std::str::from_utf8(&slice[..end]).ok()?;
        if name.is_empty() || !name.bytes().all(|b| b.is_ascii_graphic() || b == b' ') { return None; }
        Some(name.to_string())
    };

    let mut imports = Vec::new();
    let mut imported_functions = Vec::new();
    if import_rva != 0 {
        if let Some(mut desc) = rva_to_offset(import_rva) {
            for _ in 0..64 { // descriptor cap
                let oft_rva = u32le(data, desc).unwrap_or(0);       // OriginalFirstThunk
                let name_rva = u32le(data, desc + 12).unwrap_or(0);
                let ft_rva = u32le(data, desc + 16).unwrap_or(0);   // FirstThunk
                if oft_rva == 0 && name_rva == 0 && ft_rva == 0 { break; }
                let dll = rva_to_offset(name_rva).and_then(&read_c_string).unwrap_or_default();
                if !dll.is_empty() { imports.push(dll.clone()); }
                // Walk the lookup table for per-function names/ordinals.
                let thunk_rva = if oft_rva != 0 { oft_rva } else { ft_rva };
                if thunk_rva != 0 && !dll.is_empty() {
                    if let Some(mut thunk) = rva_to_offset(thunk_rva) {
                        for _ in 0..512 { // per-DLL function cap
                            let (entry, step) = if is_64bit {
                                (u64le(data, thunk).unwrap_or(0), 8usize)
                            } else {
                                (u32le(data, thunk).unwrap_or(0) as u64, 4usize)
                            };
                            if entry == 0 { break; }
                            let ordinal_flag: u64 = if is_64bit { 0x8000_0000_0000_0000 } else { 0x8000_0000 };
                            if entry & ordinal_flag != 0 {
                                imported_functions.push(format!("{dll}!#{}", entry & 0xffff));
                            } else if let Ok(rva) = u32::try_from(entry) {
                                // PE32+ name thunks still contain a 32-bit
                                // RVA. Never wrap reserved high bits into
                                // an unrelated valid name in the prefix.
                                if let Some(hn) = rva_to_offset(rva) {
                                    if u16le(data, hn).is_some() {
                                        if let Some(name) = read_c_string(hn.saturating_add(2)) {
                                            imported_functions.push(format!("{dll}!{name}"));
                                        }
                                    }
                                }
                            }
                            thunk += step;
                            if imported_functions.len() >= 4096 { break; }
                        }
                    }
                }
                desc += 20;
            }
        }
    }

    Some(PeInfo {
        machine: match machine_raw { 0x8664 => "x86-64", 0x14c => "x86", 0xaa64 => "ARM64", 0x1c0 => "ARM", _ => "unknown" }.to_string(),
        is_64bit,
        subsystem: match subsystem_raw { 2 => "windows-gui", 3 => "windows-console", 1 => "native", _ => "other" }.to_string(),
        sections, section_details, imports, imported_functions, executable_sections,
        timestamp, entry_point_rva, dll_characteristics, mitigations, signed, overlay_size, overlay_ranges, certificate_range,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn discovery_skips_unix_shims_on_windows_and_preserves_path_order() {
        let root = std::env::temp_dir().join(format!("rea_discovery_{}", crate::util::new_id()));
        let first = root.join("first");
        let second = root.join("second");
        std::fs::create_dir_all(&first).unwrap();
        std::fs::create_dir_all(&second).unwrap();
        std::fs::write(first.join("rea"), b"#!/bin/sh").unwrap();
        std::fs::write(first.join("rea.cmd"), b"@echo off").unwrap();
        std::fs::write(second.join("rea.exe"), b"fake").unwrap();
        assert_eq!(discover_rea(vec![first.clone(), second.clone()], true), Some(first.join("rea.cmd")));
        assert_eq!(discover_rea(vec![first.clone()], false), Some(first.join("rea")));
        std::fs::remove_file(first.join("rea.cmd")).unwrap();
        assert_eq!(discover_rea(vec![first.clone(), second.clone()], true), Some(second.join("rea.exe")));
        std::fs::create_dir(first.join("rea.exe")).unwrap();
        assert_eq!(discover_rea(vec![first.clone()], true), None);
        std::fs::write(first.join("rea.js"), b"// node entry").unwrap();
        assert_eq!(discover_rea(vec![first.clone()], true), Some(first.join("rea.js")));
        std::fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn explicit_missing_analyzer_is_named_without_losing_native_results() {
        let root = std::env::temp_dir().join(format!("rea_missing_{}", crate::util::new_id()));
        std::fs::create_dir_all(&root).unwrap();
        let target = root.join("target.txt");
        let launcher = root.join("missing-rea.exe");
        std::fs::write(&target, b"plain text").unwrap();
        let bridge = ReaBridge::new(ReaConfig { rea_path: Some(launcher.clone()), timeout: None });
        assert_eq!(bridge.resolved_rea_path(), Some(launcher));
        let report = bridge.analyze(&target).unwrap();
        assert_eq!(report.files.len(), 1);
        let issue = report.scan_issues.iter().find(|i| i.stage == "rea-external").unwrap();
        assert!(issue.message.contains("missing-rea.exe"));
        assert!(issue.message.contains("Native static analysis completed"));
        std::fs::remove_dir_all(root).unwrap();
    }

    #[cfg(windows)]
    #[test]
    fn windows_batch_launcher_runs_with_a_target_containing_spaces() {
        let root = std::env::temp_dir().join(format!("rea batch {}", crate::util::new_id()));
        std::fs::create_dir_all(&root).unwrap();
        let launcher = root.join("rea.cmd");
        std::fs::write(&launcher, b"@echo off\r\necho {\"ok\":true}\r\n").unwrap();
        let bridge = ReaBridge::new(ReaConfig::default());
        let json = bridge.run_external(&launcher, &root.join("target file & name.exe")).unwrap();
        assert_eq!(json.get("ok"), Some(&Value::Bool(true)));
        assert!(bridge.run_external(&root.join("rea"), Path::new("unused.exe")).is_err());
        std::fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn stream_fingerprints_and_entropy_cover_bytes_beyond_the_prefix() {
        let data: Vec<u8> = (0..150_003).map(|i| (i % 251) as u8).collect();
        for limit in [0, 1, 63, 64, 65535, 65536, data.len(), data.len() + 1] {
            let sample = inspect_stream(&mut std::io::Cursor::new(&data), limit).unwrap();
            assert_eq!(sample.prefix, data[..limit.min(data.len())]);
            assert_eq!(sample.size, data.len() as u64);
            assert_eq!(sample.sha256, crate::sha256::hash_bytes(&data));
            assert_eq!(sample.md5, crate::md5::hash_bytes(&data));
            assert!((sample.entropy - shannon_entropy(&data)).abs() < 1e-10);
        }
    }

    #[test]
    fn stream_handles_short_reads_interruptions_and_errors() {
        struct Short { data: std::io::Cursor<Vec<u8>>, interrupted: bool }
        impl Read for Short {
            fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
                if !self.interrupted {
                    self.interrupted = true;
                    return Err(std::io::ErrorKind::Interrupted.into());
                }
                let len = buf.len().min(3);
                self.data.read(&mut buf[..len])
            }
        }
        let data = b"abcdefghijklmnopqrstuvwxyz".to_vec();
        let sample = inspect_stream(&mut Short { data: std::io::Cursor::new(data.clone()), interrupted: false }, 7).unwrap();
        assert_eq!(sample.prefix, &data[..7]);
        assert_eq!(sample.sha256, crate::sha256::hash_bytes(&data));
        assert_eq!(sample.md5, crate::md5::hash_bytes(&data));
        struct Broken;
        impl Read for Broken {
            fn read(&mut self, _: &mut [u8]) -> std::io::Result<usize> {
                Err(std::io::ErrorKind::PermissionDenied.into())
            }
        }
        assert!(inspect_stream(&mut Broken, 16).is_err());
        let empty = inspect_stream(&mut std::io::empty(), 16).unwrap();
        assert_eq!(empty.entropy, 0.0);
        assert_eq!(empty.md5, crate::md5::hash_bytes(b""));
    }

    #[test]
    fn oversized_pe_keeps_headers_findings_and_full_file_fingerprints() {
        use std::io::{Seek, SeekFrom, Write};
        let dir = std::env::temp_dir().join(format!("rea_prefix_{}", crate::util::new_id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("large.exe");
        let mut file = std::fs::File::create(&path).unwrap();
        file.write_all(&synthetic_pe()).unwrap();
        file.set_len(MAX_ANALYZE_BYTES + 4096).unwrap();
        file.seek(SeekFrom::End(-32)).unwrap();
        file.write_all(b"https://outside-prefix.invalid").unwrap();
        drop(file);
        let bridge = ReaBridge::new(ReaConfig::default());
        let report = bridge.analyze_native(&path).unwrap();
        let analysis = &report.files[0];
        assert_eq!(analysis.path, "large.exe");
        assert_eq!(analysis.format, "PE");
        assert_eq!(analysis.content_bytes, MAX_ANALYZE_BYTES);
        assert_eq!(analysis.sha256, crate::sha256::hash_file(&path).unwrap());
        assert_eq!(analysis.md5, crate::md5::hash_file(&path).unwrap());
        assert!(analysis.pe.as_ref().unwrap().imported_functions.iter().any(|s| s.contains("CreateRemoteThread")));
        assert_eq!(analysis.pe.as_ref().unwrap().overlay_size, analysis.size - 0x400);
        assert!(analysis.imphash.is_none());
        assert!(!analysis.indicators.iter().any(|s| s.category == "network"));
        assert_eq!(report.scan_issues.len(), 1);
        assert!(report.scan_issues[0].message.contains("only the first"));
        let json = report.to_json();
        let scope = match json.get("files").unwrap() {
            Value::Array(files) => files[0].get("analysis_scope").unwrap(),
            _ => panic!("files array"),
        };
        assert_eq!(scope.get("content_complete"), Some(&Value::Bool(false)));
        std::fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn full_small_pe_retains_imphash_and_complete_scope() {
        let dir = std::env::temp_dir().join(format!("rea_full_{}", crate::util::new_id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("small.exe");
        let data = synthetic_pe();
        std::fs::write(&path, &data).unwrap();
        let analysis = analyze_file(&path, Path::new("small.exe")).unwrap();
        assert_eq!(analysis.content_bytes, data.len() as u64);
        assert_eq!(analysis.sha256, crate::sha256::hash_bytes(&data));
        assert_eq!(analysis.md5, crate::md5::hash_bytes(&data));
        assert!(analysis.imphash.is_some());
        assert!((analysis.entropy - shannon_entropy(&data)).abs() < 1e-10);
        std::fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn identical_prefixes_do_not_make_full_file_fingerprints_identical() {
        let a = vec![0u8; 256];
        let mut b = a.clone();
        for (i, byte) in b[64..].iter_mut().enumerate() { *byte = i as u8; }
        let first = inspect_stream(&mut std::io::Cursor::new(a), 64).unwrap();
        let second = inspect_stream(&mut std::io::Cursor::new(b), 64).unwrap();
        assert_eq!(first.prefix, second.prefix);
        assert_ne!(first.sha256, second.sha256);
        assert_ne!(first.md5, second.md5);
        assert!(second.entropy > first.entropy);
    }

    #[test]
    fn pe_overlay_uses_full_length_not_retained_prefix_length() {
        let bytes = synthetic_pe();
        let pe = parse_pe_with_size(&bytes, 100_000_000).unwrap();
        assert_eq!(pe.overlay_size, 100_000_000 - 0x400);
        assert_eq!(pe.section_details[0].raw_size, 0x200);
    }

    #[test]
    fn a_file_growing_during_analysis_is_refused_not_mixed() {
        use std::io::Write;
        use std::sync::atomic::{AtomicBool, Ordering};
        let dir = std::env::temp_dir().join(format!("rea_bridge_test_{}", crate::util::new_id()));
        std::fs::create_dir_all(&dir).unwrap();
        let file = dir.join("growing.bin");
        std::fs::write(&file, vec![3u8; 48 * 1024 * 1024]).unwrap();
        // Keep appending for the whole analysis, so the file moves between
        // the metadata checks that bracket the streaming read.
        let stop = std::sync::Arc::new(AtomicBool::new(false));
        let writer = {
            let stop = stop.clone();
            let file = file.clone();
            std::thread::spawn(move || {
                let mut f = std::fs::OpenOptions::new().append(true).open(&file).unwrap();
                while !stop.load(Ordering::Relaxed) {
                    let _ = f.write_all(&[1u8; 4096]);
                    std::thread::sleep(std::time::Duration::from_micros(200));
                }
            })
        };
        let result = analyze_file(&file, Path::new("growing.bin"));
        stop.store(true, Ordering::Relaxed);
        writer.join().unwrap();
        let error = result.unwrap_err().to_string();
        assert!(error.contains("changed while it was being analyzed"), "{error}");
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn entropy_and_format() {
        assert_eq!(shannon_entropy(&[]), 0.0);
        assert!(shannon_entropy(b"aaaaaaaaaaaaaaaa") < 0.01);
        assert_eq!(detect_format(b"MZ....", Path::new("a.exe")), "PE");
        let inds = scan_indicators(b"xx CreateRemoteThread yy https://example.invalid");
        assert!(inds.iter().any(|i| i.category == "injection"));
    }

    /// Build a minimal but structurally valid PE32+ in memory:
    /// one `.text` section (RVA 0x1000, raw at 0x200, size 0x200) importing
    /// `KERNEL32.dll!CreateRemoteThread` + ordinal #42, with 0x40 overlay bytes.
    fn synthetic_pe() -> Vec<u8> {
        let mut d = vec![0u8; 0x440];
        d[0] = b'M'; d[1] = b'Z';
        d[0x3c..0x40].copy_from_slice(&0x80u32.to_le_bytes()); // e_lfanew
        d[0x80..0x84].copy_from_slice(b"PE\0\0");
        let coff = 0x84;
        d[coff..coff + 2].copy_from_slice(&0x8664u16.to_le_bytes()); // x86-64
        d[coff + 2..coff + 4].copy_from_slice(&1u16.to_le_bytes()); // 1 section
        d[coff + 4..coff + 8].copy_from_slice(&0x6500_0000u32.to_le_bytes()); // timestamp
        d[coff + 16..coff + 18].copy_from_slice(&240u16.to_le_bytes()); // opt header size
        let opt = coff + 20;
        d[opt..opt + 2].copy_from_slice(&0x20bu16.to_le_bytes()); // PE32+
        d[opt + 16..opt + 20].copy_from_slice(&0x1000u32.to_le_bytes()); // entry point
        d[opt + 60..opt + 64].copy_from_slice(&0x200u32.to_le_bytes()); // SizeOfHeaders
        d[opt + 68..opt + 70].copy_from_slice(&3u16.to_le_bytes()); // subsystem: console
        // DllCharacteristics: high_entropy_va | dynamic_base | nx_compat | guard_cf
        d[opt + 70..opt + 72].copy_from_slice(&0x4160u16.to_le_bytes());
        d[opt + 108..opt + 112].copy_from_slice(&16u32.to_le_bytes()); // NumRvaAndSizes
        let dd = opt + 112;
        d[dd + 8..dd + 12].copy_from_slice(&0x1100u32.to_le_bytes()); // import dir RVA
        d[dd + 12..dd + 16].copy_from_slice(&40u32.to_le_bytes());
        let sec = opt + 240;
        d[sec..sec + 5].copy_from_slice(b".text");
        d[sec + 8..sec + 12].copy_from_slice(&0x200u32.to_le_bytes()); // virtual size
        d[sec + 12..sec + 16].copy_from_slice(&0x1000u32.to_le_bytes()); // VA
        d[sec + 16..sec + 20].copy_from_slice(&0x200u32.to_le_bytes()); // raw size
        d[sec + 20..sec + 24].copy_from_slice(&0x200u32.to_le_bytes()); // raw ptr
        d[sec + 36..sec + 40].copy_from_slice(&0x6000_0020u32.to_le_bytes()); // code|exec|read
        // Import descriptor at RVA 0x1100 -> raw 0x300.
        let raw = |rva: u32| (0x200 + (rva - 0x1000)) as usize;
        d[raw(0x1100)..raw(0x1100) + 4].copy_from_slice(&0x1140u32.to_le_bytes()); // OFT
        d[raw(0x1100) + 12..raw(0x1100) + 16].copy_from_slice(&0x1180u32.to_le_bytes()); // name
        d[raw(0x1100) + 16..raw(0x1100) + 20].copy_from_slice(&0x1160u32.to_le_bytes()); // FT
        // Lookup table (u64 entries) at RVA 0x1140 -> raw 0x340.
        d[raw(0x1140)..raw(0x1140) + 8].copy_from_slice(&0x1190u64.to_le_bytes()); // by-name
        d[raw(0x1140) + 8..raw(0x1140) + 16].copy_from_slice(&(0x8000_0000_0000_0000u64 | 42).to_le_bytes()); // ordinal
        // Hint/name at RVA 0x1190 -> raw 0x390 (hint u16 skipped by parser).
        d[raw(0x1190) + 2..raw(0x1190) + 2 + 18].copy_from_slice(b"CreateRemoteThread");
        d[raw(0x1180)..raw(0x1180) + 12].copy_from_slice(b"KERNEL32.dll");
        d
    }

    fn set_certificate(data: &mut [u8], offset: u32, size: u32) {
        let directory = 0x98 + 112 + 4 * 8;
        data[directory..directory + 4].copy_from_slice(&offset.to_le_bytes());
        data[directory + 4..directory + 8].copy_from_slice(&size.to_le_bytes());
    }

    #[test]
    fn optional_header_magic_size_and_presence_are_validated() {
        let original = synthetic_pe();
        for magic in [0u16, 0x107, 0xffff] {
            let mut bytes = original.clone();
            bytes[0x98..0x9a].copy_from_slice(&magic.to_le_bytes());
            assert!(parse_pe(&bytes).is_none());
        }
        for size in [0u16, 2, 70, 111, 0xffff] {
            let mut bytes = original.clone();
            bytes[0x94..0x96].copy_from_slice(&size.to_le_bytes());
            assert!(parse_pe(&bytes).is_none(), "optional size {size}");
        }
        assert!(parse_pe(&original[..0x180]).is_none());
    }

    #[test]
    fn undeclared_directories_are_not_interpreted_as_imports_or_certificates() {
        for count in [0u32, 1] {
            let mut bytes = synthetic_pe();
            set_certificate(&mut bytes, 0x400, 0x40);
            bytes[0x98 + 108..0x98 + 112].copy_from_slice(&count.to_le_bytes());
            let pe = parse_pe(&bytes).unwrap();
            assert!(pe.imports.is_empty());
            assert!(!pe.signed);
            assert_eq!(pe.overlay_size, 0x40);
        }
    }

    #[test]
    fn directories_cannot_escape_the_declared_optional_header() {
        let mut bytes = synthetic_pe();
        // No sections, optional header ends exactly where directories begin.
        // Stale import/certificate bytes remain in the backing buffer.
        bytes[0x86..0x88].copy_from_slice(&0u16.to_le_bytes());
        bytes[0x94..0x96].copy_from_slice(&112u16.to_le_bytes());
        set_certificate(&mut bytes, 0x400, 0x40);
        let pe = parse_pe(&bytes).unwrap();
        assert!(pe.imports.is_empty());
        assert!(!pe.signed);
    }

    #[test]
    fn pe32_directory_layout_is_supported() {
        let mut bytes = synthetic_pe();
        bytes[0x98..0x9a].copy_from_slice(&0x10bu16.to_le_bytes());
        bytes[0x98 + 92..0x98 + 96].copy_from_slice(&0u32.to_le_bytes());
        let pe = parse_pe(&bytes).unwrap();
        assert!(!pe.is_64bit);
        assert!(pe.imports.is_empty());
        assert!(!pe.signed);
    }

    #[test]
    fn header_imports_use_size_of_headers_not_section_table_start() {
        let mut bytes = synthetic_pe();
        let dd = 0x98 + 112;
        bytes[dd + 8..dd + 12].copy_from_slice(&0x1b0u32.to_le_bytes());
        bytes[0x1b0..0x200].fill(0);
        bytes[0x1b0..0x1b4].copy_from_slice(&0x1e0u32.to_le_bytes());
        bytes[0x1bc..0x1c0].copy_from_slice(&0x1f0u32.to_le_bytes());
        bytes[0x1e0..0x1e8].copy_from_slice(&(0x8000_0000_0000_0000u64 | 42).to_le_bytes());
        bytes[0x1f0..0x1fd].copy_from_slice(b"KERNEL32.dll\0");
        assert_eq!(parse_pe(&bytes).unwrap().imports, vec!["KERNEL32.dll"]);
        bytes[0x98 + 60..0x98 + 64].copy_from_slice(&0x1b0u32.to_le_bytes());
        assert!(parse_pe(&bytes).unwrap().imports.is_empty());
    }

    #[test]
    fn certificate_ranges_must_be_inside_file_and_outside_sections() {
        for offset in [0xffff_fff0, 0x500, 0x200] {
            let mut data = synthetic_pe();
            set_certificate(&mut data, offset, 0x20);
            let pe = parse_pe(&data).unwrap();
            assert!(!pe.signed, "offset {offset:x}");
            assert_eq!(pe.overlay_size, 0x40);
        }
        let mut data = synthetic_pe();
        set_certificate(&mut data, 0x400, 0x40);
        let pe = parse_pe(&data).unwrap();
        assert!(pe.signed);
        assert_eq!(pe.overlay_size, 0);
    }

    #[test]
    fn file_layout_records_sections_and_disjoint_overlay_intervals() {
        let mut data = synthetic_pe();
        data.resize(0x500, 0);
        set_certificate(&mut data, 0x420, 0x20);
        let pe = parse_pe(&data).unwrap();
        assert_eq!(pe.section_details[0].raw_offset, 0x200);
        assert_eq!(pe.section_details[0].virtual_address, 0x1000);
        assert_eq!(pe.certificate_range, Some(FileRange { offset: 0x420, size: 0x20 }));
        assert_eq!(pe.overlay_ranges, vec![FileRange { offset: 0x400, size: 0x20 }, FileRange { offset: 0x440, size: 0xc0 }]);
        assert_eq!(pe.overlay_ranges.iter().map(|r| r.size).sum::<u64>(), pe.overlay_size);
        let prefix = parse_pe_with_size(&data[..0x400], data.len() as u64).unwrap();
        assert_eq!(prefix.overlay_ranges, pe.overlay_ranges);
        assert_eq!(prefix.certificate_range, pe.certificate_range);
    }

    #[test]
    fn invalid_certificate_is_not_excluded_from_overlay_ranges() {
        let mut data = synthetic_pe();
        set_certificate(&mut data, 0xffff_fff0, 0x40);
        let pe = parse_pe(&data).unwrap();
        assert!(pe.certificate_range.is_none());
        assert_eq!(pe.overlay_ranges, vec![FileRange { offset: 0x400, size: 0x40 }]);
    }

    #[test]
    fn declared_headers_are_not_misclassified_as_overlay() {
        let mut data = synthetic_pe();
        data[0x86..0x88].copy_from_slice(&0u16.to_le_bytes());
        let pe = parse_pe(&data).unwrap();
        assert_eq!(pe.overlay_ranges, vec![FileRange { offset: 0x200, size: 0x240 }]);
    }

    #[test]
    fn bytes_after_a_certificate_are_still_overlay() {
        let mut data = synthetic_pe();
        data.resize(0x500, 0);
        set_certificate(&mut data, 0x420, 0x20);
        let pe = parse_pe(&data).unwrap();
        assert!(pe.signed);
        assert_eq!(pe.overlay_size, 0xe0, "exclude only the certificate, retaining both adjacent ranges");
        // A certificate outside the retained prefix can still be present
        // in the actual full file; its bytes need not be in memory.
        let pe = parse_pe_with_size(&data[..0x400], 0x500).unwrap();
        assert!(pe.signed);
        assert_eq!(pe.overlay_size, 0xe0);
    }

    #[test]
    fn section_address_overflows_do_not_panic_or_wrap_into_headers() {
        let section = 0x98 + 240;
        for (address, raw_pointer) in [(0xffff_fff0u32, 0x200u32), (0x1000, 0xffff_fff0)] {
            let mut data = synthetic_pe();
            data[section + 12..section + 16].copy_from_slice(&address.to_le_bytes());
            data[section + 20..section + 24].copy_from_slice(&raw_pointer.to_le_bytes());
            let import_rva = if address == 0x1000 { 0x1100u32 } else { 0xffff_fff8u32 };
            data[0x98 + 112 + 8..0x98 + 112 + 12].copy_from_slice(&import_rva.to_le_bytes());
            let pe = parse_pe(&data).unwrap();
            assert!(pe.imports.is_empty());
        }
    }

    #[test]
    fn virtual_zero_fill_is_not_a_file_backed_import_table() {
        let mut data = synthetic_pe();
        let descriptor = data[0x300..0x328].to_vec();
        data.resize(0x700, 0);
        data[0x500..0x528].copy_from_slice(&descriptor);
        let section = 0x98 + 240;
        data[section + 8..section + 12].copy_from_slice(&0x1000u32.to_le_bytes());
        data[0x98 + 112 + 8..0x98 + 112 + 12].copy_from_slice(&0x1300u32.to_le_bytes());
        assert!(parse_pe(&data).unwrap().imports.is_empty());
    }

    #[test]
    fn missing_section_bytes_have_unknown_not_zero_entropy() {
        let data = synthetic_pe();
        let full = parse_pe(&data).unwrap();
        assert!(full.section_details[0].entropy.is_some());
        let prefix = parse_pe_with_size(&data[..0x300], data.len() as u64).unwrap();
        assert_eq!(prefix.section_details[0].entropy, None);
        assert_eq!(u16le(&[], usize::MAX), None);
        assert_eq!(u32le(&[], usize::MAX), None);
        assert_eq!(u64le(&[], usize::MAX), None);
    }

    #[test]
    fn pe64_name_thunks_cannot_wrap_reserved_high_bits_into_an_rva() {
        let mut bytes = synthetic_pe();
        bytes[0x340..0x348].copy_from_slice(&0x0000_0001_0000_1190u64.to_le_bytes());
        let pe = parse_pe(&bytes).unwrap();
        assert!(!pe.imported_functions.iter().any(|s| s.contains("CreateRemoteThread")));
        assert!(pe.imported_functions.iter().any(|s| s.ends_with("!#42")));
    }

    #[test]
    fn unterminated_import_names_are_not_fabricated_at_eof() {
        let mut bytes = synthetic_pe();
        // Point the DLL name to the final 16 file bytes, without a NUL.
        bytes[0x30c..0x310].copy_from_slice(&0x1230u32.to_le_bytes());
        bytes[0x430..].fill(b'A');
        // Extend the file-backed section so the EOF name is addressable.
        let sec = 0x98 + 240;
        bytes[sec + 16..sec + 20].copy_from_slice(&0x240u32.to_le_bytes());
        assert!(parse_pe(&bytes).unwrap().imports.is_empty());
    }

    #[test]
    fn invalid_import_name_bytes_are_not_lossily_normalized() {
        for value in [0xffu8, b'\n', 0x7f] {
            let mut bytes = synthetic_pe();
            bytes[0x392] = value;
            let pe = parse_pe(&bytes).unwrap();
            assert!(!pe.imported_functions.iter().any(|s| s.contains("RemoteThread")));
            assert!(pe.imported_functions.iter().any(|s| s.ends_with("!#42")));
        }
    }

    #[test]
    fn printable_import_names_preserve_spaces_and_decorations() {
        let mut bytes = synthetic_pe();
        bytes[0x380..0x390].fill(0);
        bytes[0x380..0x38b].copy_from_slice(b"my lib.dll\0");
        bytes[0x392..0x3b0].fill(0);
        let name = b"?entry@@YAXXZ";
        bytes[0x392..0x392 + name.len()].copy_from_slice(name);
        let pe = parse_pe(&bytes).unwrap();
        assert_eq!(pe.imports, vec!["my lib.dll"]);
        assert!(pe.imported_functions.iter().any(|s| s == "my lib.dll!?entry@@YAXXZ"));
    }

    #[test]
    fn truncated_function_names_are_not_accepted_as_complete_imports() {
        let mut bytes = synthetic_pe();
        bytes[0x340..0x348].copy_from_slice(&0x11f0u64.to_le_bytes());
        bytes[0x3f2..].fill(b'X');
        let pe = parse_pe(&bytes).unwrap();
        assert!(!pe.imported_functions.iter().any(|s| s.contains("!XXX")));
    }

    #[test]
    fn deep_pe_parse() {
        let pe = parse_pe(&synthetic_pe()).expect("synthetic PE must parse");
        assert_eq!(pe.machine, "x86-64");
        assert!(pe.is_64bit);
        assert_eq!(pe.subsystem, "windows-console");
        assert_eq!(pe.timestamp, 0x6500_0000);
        assert_eq!(pe.entry_point_rva, 0x1000);
        assert!(pe.mitigations.aslr_dynamic_base && pe.mitigations.nx_compat && pe.mitigations.guard_cf);
        assert!(!pe.signed);
        assert_eq!(pe.imports, vec!["KERNEL32.dll".to_string()], "full parse: {pe:?}");
        assert!(pe.imported_functions.contains(&"KERNEL32.dll!CreateRemoteThread".to_string()),
            "got {:?}", pe.imported_functions);
        assert!(pe.imported_functions.contains(&"KERNEL32.dll!#42".to_string()));
        assert_eq!(pe.section_details.len(), 1);
        assert!(pe.section_details[0].executable && !pe.section_details[0].writable);
        assert_eq!(pe.overlay_size, 0x40);
    }

    /// Import lists whose digests were produced by **upstream pefile itself**
    /// (`PE(...).get_imphash()`, erocarrera/pefile master f35dfc5, which uses the
    /// frozen imphash ordinal tables). Each entry is
    /// `(imports, normalized string, md5)`.
    ///
    /// These are the contract: if a change makes this tool stop agreeing with
    /// VirusTotal/YARA, it fails here rather than in someone's investigation
    /// months later. `wsock32` and `oleaut32` deliberately differ from the
    /// *released* pefile 2024.8.26, whose general ordinal tables were corrected
    /// after the imphash convention froze — the frozen values are the ones
    /// other tools still publish.
    const PEFILE_VECTORS: &[(&[&str], &str, &str)] = &[
        (
            &["KERNEL32.dll!Sleep", "KERNEL32.dll!CreateFileW", "USER32.dll!MessageBoxW"],
            "kernel32.sleep,kernel32.createfilew,user32.messageboxw",
            "84e38f1bb1f12dd4775179ef0334737c",
        ),
        (
            &["KERNEL32.dll!#42", "KERNEL32.dll!Sleep", "KERNEL32.dll!#7"],
            "kernel32.ord42,kernel32.sleep,kernel32.ord7",
            "7e3efb465fa7c0e9ea58e9983eb65e07",
        ),
        (
            &["WS2_32.dll!#23", "WS2_32.dll!#1", "WS2_32.dll!#111", "WS2_32.dll!#500", "WS2_32.dll!WSAStartup"],
            "ws2_32.socket,ws2_32.accept,ws2_32.wsagetlasterror,ws2_32.wep,ws2_32.wsastartup",
            "60783a553ab6e93c4f7b912f48e0c62d",
        ),
        (
            &["wsock32.dll!#10", "wsock32.dll!#11", "wsock32.dll!#1", "wsock32.dll!#24"],
            "wsock32.ioctlsocket,wsock32.inet_addr,wsock32.accept,wsock32.getaddrinfow",
            "5a9c08dc18a3c8d966264b0e82ff61ed",
        ),
        (
            &["OLEAUT32.dll!#2", "OLEAUT32.dll!#144", "OLEAUT32.dll!#6", "OLEAUT32.dll!#999"],
            "oleaut32.sysallocstring,oleaut32.dllcanunloadnow,oleaut32.sysfreestring,oleaut32.ord999",
            "8f5066f2b9ba7f9212493982daffdcf7",
        ),
        (
            &["driver.drv!DrvEntry", "panel.cpl!CPlApplet", "control.OCX!DllMain", "kernel.SYS!IoCreateDevice"],
            "driver.drv.drventry,panel.cpl.cplapplet,control.dllmain,kernel.iocreatedevice",
            "2a7355b060c343efa0b26ef027e2b61a",
        ),
        (
            &["noext!Alpha", "api-ms-win-core-x-l1-1-0.dll!Beta"],
            "noext.alpha,api-ms-win-core-x-l1-1-0.beta",
            "0a613db77c9d52cef7d86dc114998204",
        ),
        (
            &["KERNEL32.dll!Sleep", "KERNEL32.dll!ExitProcess"],
            "kernel32.sleep,kernel32.exitprocess",
            "9951ea482cdf88d83ed64c8866836e90",
        ),
        (
            &["KERNEL32.dll!ExitProcess", "KERNEL32.dll!Sleep"],
            "kernel32.exitprocess,kernel32.sleep",
            "a3b183a3587e60809b7099ba787a3790",
        ),
        (
            &["KERNEL32.dll!VirtualAllocEx", "KERNEL32.dll!#9", "ws2_32.dll!#23", "ws2_32.dll!connect", "ADVAPI32.dll!RegSetValueExW"],
            "kernel32.virtualallocex,kernel32.ord9,ws2_32.socket,ws2_32.connect,advapi32.regsetvalueexw",
            "ff6c1d896e7b926b4daed13b01d67379",
        ),
    ];

    #[test]
    fn imphash_matches_pefile_reference_vectors() {
        for (imports, expected_source, expected_hash) in PEFILE_VECTORS {
            let owned: Vec<String> = imports.iter().map(|s| s.to_string()).collect();
            assert_eq!(imphash_source(&owned), *expected_source, "normalization of {imports:?}");
            assert_eq!(imphash(&owned).as_deref(), Some(*expected_hash), "digest of {imports:?}");
        }
    }

    #[test]
    fn import_order_changes_the_digest() {
        // Vectors 7 and 8 are the same imports in opposite order: a build
        // fingerprint must notice, which the old sort-ordinals-to-the-end
        // implementation could not.
        let a: Vec<String> = PEFILE_VECTORS[7].0.iter().map(|s| s.to_string()).collect();
        let b: Vec<String> = PEFILE_VECTORS[8].0.iter().map(|s| s.to_string()).collect();
        assert_ne!(imphash(&a), imphash(&b));
    }

    #[test]
    fn imphash_survives_a_real_parse_of_the_same_imports() {
        // The vectors above feed strings directly; this proves the PE parser
        // hands imphash the same list in the same order.
        let bytes = crate::testutil::PeBuilder::new()
            .imports("WS2_32.dll", vec![
                crate::testutil::Import::Ordinal(23),
                crate::testutil::Import::Ordinal(1),
                crate::testutil::Import::Ordinal(111),
                crate::testutil::Import::Ordinal(500),
                crate::testutil::Import::Named("WSAStartup"),
            ])
            .build();
        let pe = parse_pe(&bytes).expect("parse");
        assert_eq!(imphash_source(&pe.imported_functions), PEFILE_VECTORS[2].1);
        assert_eq!(imphash(&pe.imported_functions).as_deref(), Some(PEFILE_VECTORS[2].2));
    }

    #[test]
    fn frozen_ordinal_tables_are_sorted_and_searchable() {
        use crate::imphash_ordinals::{OLEAUT32, WS2_32};
        for table in [WS2_32, OLEAUT32] {
            assert!(!table.is_empty());
            assert!(table.windows(2).all(|w| w[0].0 < w[1].0), "must be sorted and unique");
        }
    }

    #[test]
    fn known_ordinals_resolve_and_unknown_ones_fall_back() {
        use crate::imphash_ordinals::lookup;
        assert_eq!(lookup("ws2_32.dll", 23), "socket");
        assert_eq!(lookup("ws2_32.dll", 1), "accept");
        assert_eq!(lookup("oleaut32.dll", 2), "sysallocstring");
        // Upstream maps wsock32 onto the ws2_32 table, quirk included.
        assert_eq!(lookup("wsock32.dll", 10), "ioctlsocket");
        // No table for this DLL, and an ordinal past the end of one that has one.
        assert_eq!(lookup("kernel32.dll", 42), "ord42");
        assert_eq!(lookup("ws2_32.dll", 60000), "ord60000");
        // Keys are the full lowercased name: an extension-less or prefixed
        // name has no table, exactly as in pefile.
        assert_eq!(lookup("ws2_32", 23), "ord23");
        assert_eq!(lookup("c:/windows/ws2_32.dll", 23), "ord23");
    }

    #[test]
    fn imphash_ignores_entries_it_cannot_name() {
        assert!(imphash(&[]).is_none());
        assert!(imphash(&["no-separator".to_string()]).is_none());
        assert!(imphash(&["a.dll!".to_string(), "b.dll!#notanumber".to_string()]).is_none());
        let mixed = vec!["junk".to_string(), "A.dll!Real".to_string()];
        assert_eq!(imphash_source(&mixed), "a.real");
    }

    #[test]
    fn read_capped_reports_total_size_and_truncation() {
        let dir = std::env::temp_dir().join(format!("rea_offline_cap_{}", crate::util::new_id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("out.bin");
        std::fs::write(&path, b"abcdef").unwrap();
        let (text, total, truncated) = read_capped(&path, 4).unwrap();
        assert_eq!(text, "abcd");
        assert_eq!(total, 6);
        assert!(truncated);
        let (text, total, truncated) = read_capped(&path, 6).unwrap();
        assert_eq!(text, "abcdef");
        assert_eq!(total, 6);
        assert!(!truncated);
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn tail_str_keeps_char_boundaries() {
        assert_eq!(tail_str("abcdef", 3), "def");
        assert_eq!(tail_str("abcdef", 10), "abcdef");
        assert_eq!(tail_str("aé😀z", 1), "z");
        assert!(tail_str("aé😀z", 4).is_char_boundary(0));
    }

    #[cfg(unix)]
    #[test]
    fn external_capture_drains_large_stdout_and_stderr_without_deadlock() {
        // More than a typical 64 KiB pipe buffer on both streams. The old
        // wait-then-read loop deadlocked here until the timeout fired.
        let mut cmd = std::process::Command::new("sh");
        cmd.arg("-c").arg(
            "i=0; while [ $i -lt 4096 ]; do \
             printf 'xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx\\n'; \
             i=$((i+1)); done; \
             i=0; while [ $i -lt 2048 ]; do \
             printf 'yyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyy\\n' >&2; \
             i=$((i+1)); done",
        );
        let out = run_with_timeout(cmd, Duration::from_secs(30)).unwrap();
        assert!(out.status_ok);
        assert_eq!(out.stdout_bytes, 4096 * 65);
        assert_eq!(out.stderr_bytes, 2048 * 65);
        assert!(!out.stdout_truncated);
        assert!(out.stdout.starts_with("xxxx"));
        assert!(out.stderr.starts_with("yyyy"));
    }

    #[cfg(windows)]
    #[test]
    fn external_capture_drains_large_stdout_and_stderr_without_deadlock() {
        // Parenthesize each loop so the second loop is not parsed as part of
        // the first loop's body (which made stderr grow without bound).
        let mut cmd = std::process::Command::new("cmd");
        cmd.arg("/C").arg(
            "(for /L %i in (1,1,4096) do @echo xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx) & \
             (for /L %i in (1,1,2048) do @echo yyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyy 1>&2)",
        );
        let out = run_with_timeout(cmd, Duration::from_secs(30)).unwrap();
        assert!(out.status_ok);
        assert!(out.stdout_bytes > 64 * 1024);
        assert!(out.stderr_bytes > 64 * 1024);
        assert!(!out.stdout_truncated);
    }

    #[cfg(unix)]
    #[test]
    fn external_capture_times_out_and_cleans_up() {
        let mut cmd = std::process::Command::new("sh");
        cmd.arg("-c").arg("sleep 30");
        let err = run_with_timeout(cmd, Duration::from_millis(100)).unwrap_err();
        assert!(matches!(err, Error::Timeout(_)), "{err:?}");
    }
}
