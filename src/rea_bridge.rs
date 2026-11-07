//! Module 4 — REA Engine Bridge.
//!
//! Primary path: invoke a locally installed REA (`morluto/rea`) CLI/Node
//! entry point, fully offline, and collect its JSON report.
//! Fallback path: the built-in native analyzer below (PE parsing, section
//! entropy, import table, indicator string scan). A machine with no REA
//! and no network still gets a useful structured report — REA enriches
//! it when present, it is never required.

use crate::json::Value;
use crate::sha256::hash_file;
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
    pub format: String,
    pub entropy: f64,
    pub pe: Option<PeInfo>,
    pub indicators: Vec<Indicator>,
}

#[derive(Debug, Clone)]
pub struct PeInfo {
    pub machine: String,
    pub is_64bit: bool,
    pub subsystem: String,
    pub sections: Vec<String>,
    pub imports: Vec<String>,
    pub executable_sections: Vec<String>,
}

#[derive(Debug, Clone)]
pub struct Indicator {
    pub category: String,
    pub matched: String,
    pub severity: String,
}

pub struct ReaReport {
    pub engine: String,
    pub target: String,
    pub files: Vec<FileAnalysis>,
    /// Raw REA JSON when the external engine ran.
    pub external_json: Option<Value>,
}

impl ReaReport {
    pub fn risk_score(&self) -> u64 {
        let mut score = 0u64;
        for f in &self.files {
            for i in &f.indicators {
                score += match i.severity.as_str() { "high" => 25, "medium" => 10, _ => 3 };
            }
            if f.entropy > 7.2 { score += 10; } // likely packed / encrypted
        }
        score.min(100)
    }
    pub fn to_json(&self) -> Value {
        let files = self.files.iter().map(|f| {
            let mut pairs = vec![
                ("path", Value::str(f.path.clone())),
                ("size", Value::num(f.size)),
                ("sha256", Value::str(f.sha256.clone())),
                ("format", Value::str(f.format.clone())),
                ("entropy", Value::Number((f.entropy * 1000.0).round() / 1000.0)),
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
                    ("sections", Value::Array(pe.sections.iter().map(|s| Value::str(s.clone())).collect())),
                    ("imports", Value::Array(pe.imports.iter().map(|s| Value::str(s.clone())).collect())),
                    ("executable_sections", Value::Array(pe.executable_sections.iter().map(|s| Value::str(s.clone())).collect())),
                ])));
            }
            Value::obj(pairs)
        }).collect();
        let mut root = vec![
            ("engine", Value::str(self.engine.clone())),
            ("target", Value::str(self.target.clone())),
            ("file_count", Value::num(self.files.len() as u64)),
            ("risk_score", Value::num(self.risk_score())),
            ("files", Value::Array(files)),
        ];
        if let Some(ext) = &self.external_json {
            root.push(("rea_external", ext.clone()));
        }
        Value::obj(root)
    }
}

pub struct ReaBridge {
    config: ReaConfig,
}

impl ReaBridge {
    pub fn new(config: ReaConfig) -> ReaBridge { ReaBridge { config } }

    fn resolve_rea(&self) -> Option<PathBuf> {
        if let Some(p) = &self.config.rea_path {
            if p.exists() { return Some(p.clone()); }
        }
        if let Ok(p) = std::env::var("REA_PATH") {
            let p = PathBuf::from(p);
            if p.exists() { return Some(p); }
        }
        // Probe PATH for `rea` / `rea.cmd` without spawning a shell.
        if let Ok(path_var) = std::env::var("PATH") {
            for dir in std::env::split_paths(&path_var) {
                for name in ["rea", "rea.exe", "rea.cmd", "rea.js"] {
                    let candidate = dir.join(name);
                    if candidate.exists() { return Some(candidate); }
                }
            }
        }
        None
    }

    /// Analyze a file or a directory (recursively) — Mode A entry point.
    pub fn analyze(&self, target: &Path) -> Result<ReaReport> {
        if !target.exists() { return Err(Error::NotFound(target.to_path_buf())); }
        if let Some(rea) = self.resolve_rea() {
            if let Ok(json) = self.run_external(&rea, target) {
                // External findings complement, never replace, native ones.
                let mut report = self.analyze_native(target)?;
                report.engine = format!("rea-external ({}) + native", rea.display());
                report.external_json = Some(json);
                return Ok(report);
            }
        }
        self.analyze_native(target)
    }

    fn run_external(&self, rea: &Path, target: &Path) -> Result<Value> {
        let is_js = crate::util::extension_lower(rea) == "js";
        let mut cmd = if is_js {
            let mut c = std::process::Command::new("node");
            c.arg(rea);
            c
        } else {
            std::process::Command::new(rea)
        };
        cmd.arg(target).arg("--format").arg("json")
            .stdin(std::process::Stdio::null());
        let timeout = self.config.timeout.unwrap_or(Duration::from_secs(600));
        let output = run_with_timeout(cmd, timeout)?;
        if !output.status_ok {
            return Err(Error::Process(format!("REA exited with code {:?}", output.exit_code)));
        }
        crate::json::parse(&output.stdout)
            .map_err(|e| Error::Process(format!("REA did not emit valid JSON: {e}")))
    }

    pub fn analyze_native(&self, target: &Path) -> Result<ReaReport> {
        let mut files = Vec::new();
        if target.is_file() {
            files.push(analyze_file(target, target)?);
        } else {
            let snapshot = crate::snapshot::Snapshot::capture(target)?;
            for entry in snapshot.entries.values() {
                if entry.kind == crate::snapshot::EntryKind::File {
                    let full = target.join(&entry.path);
                    if let Ok(a) = analyze_file(&full, &PathBuf::from(&entry.path)) {
                        files.push(a);
                    }
                }
            }
        }
        files.sort_by(|a, b| a.path.cmp(&b.path));
        Ok(ReaReport {
            engine: "rea-offline-native".to_string(),
            target: crate::util::path_to_slash_string(target),
            files,
            external_json: None,
        })
    }
}

struct CmdOutput { status_ok: bool, exit_code: Option<i32>, stdout: String }

fn run_with_timeout(mut cmd: std::process::Command, timeout: Duration) -> Result<CmdOutput> {
    use std::io::Read;
    let mut child = cmd.stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped()).spawn()?;
    let deadline = std::time::Instant::now() + timeout;
    loop {
        if let Some(status) = child.try_wait()? {
            let mut stdout = String::new();
            if let Some(mut pipe) = child.stdout.take() { let _ = pipe.read_to_string(&mut stdout); }
            return Ok(CmdOutput { status_ok: status.success(), exit_code: status.code(), stdout });
        }
        if std::time::Instant::now() >= deadline {
            let _ = child.kill();
            let _ = child.wait();
            return Err(Error::Timeout("REA process exceeded its timeout".into()));
        }
        std::thread::sleep(Duration::from_millis(50));
    }
}

// ---------------------------------------------------------------------------
// Native static analysis
// ---------------------------------------------------------------------------

const MAX_ANALYZE_BYTES: u64 = 32 * 1024 * 1024;

pub fn analyze_file(path: &Path, display: &Path) -> Result<FileAnalysis> {
    let meta = std::fs::metadata(path)?;
    let size = meta.len();
    let sha256 = hash_file(path).unwrap_or_default();
    let data = if size <= MAX_ANALYZE_BYTES { std::fs::read(path).unwrap_or_default() } else { Vec::new() };
    let format = detect_format(&data, path);
    let pe = if format == "PE" { parse_pe(&data) } else { None };
    Ok(FileAnalysis {
        path: crate::util::path_to_slash_string(display),
        size,
        sha256,
        format,
        entropy: shannon_entropy(&data),
        indicators: scan_indicators(&data),
        pe,
    })
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
    let len = data.len() as f64;
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
    d.get(off..off + 2).map(|s| u16::from_le_bytes([s[0], s[1]]))
}
fn u32le(d: &[u8], off: usize) -> Option<u32> {
    d.get(off..off + 4).map(|s| u32::from_le_bytes([s[0], s[1], s[2], s[3]]))
}

struct Section { name: String, virtual_address: u32, virtual_size: u32, raw_ptr: u32, raw_size: u32, characteristics: u32 }

fn parse_pe(data: &[u8]) -> Option<PeInfo> {
    if !data.starts_with(b"MZ") { return None; }
    let pe_off = u32le(data, 0x3c)? as usize;
    if data.get(pe_off..pe_off + 4)? != b"PE\0\0".as_slice() { return None; }
    let coff = pe_off + 4;
    let machine_raw = u16le(data, coff)?;
    let num_sections = u16le(data, coff + 2)? as usize;
    let opt_size = u16le(data, coff + 16)? as usize;
    let opt = coff + 20;
    let magic = u16le(data, opt)?;
    let is_64bit = magic == 0x20b;
    let subsystem_raw = u16le(data, opt + if is_64bit { 68 } else { 68 })?;
    // Data directories start at opt+96 (PE32) / opt+112 (PE32+); import = #1.
    let dd_base = opt + if is_64bit { 112 } else { 96 };
    let import_rva = u32le(data, dd_base + 8).unwrap_or(0);

    let mut sections = Vec::new();
    let mut parsed_sections = Vec::new();
    let mut executable_sections = Vec::new();
    let sec_base = opt + opt_size;
    for i in 0..num_sections.min(96) {
        let off = sec_base + i * 40;
        let name_bytes = data.get(off..off + 8)?;
        let name = String::from_utf8_lossy(name_bytes).trim_end_matches('\0').to_string();
        let characteristics = u32le(data, off + 36).unwrap_or(0);
        if characteristics & 0x2000_0000 != 0 { executable_sections.push(name.clone()); }
        sections.push(name.clone());
        parsed_sections.push(Section {
            name,
            virtual_size: u32le(data, off + 8).unwrap_or(0),
            virtual_address: u32le(data, off + 12).unwrap_or(0),
            raw_size: u32le(data, off + 16).unwrap_or(0),
            raw_ptr: u32le(data, off + 20).unwrap_or(0),
            characteristics,
        });
    }

    let rva_to_offset = |rva: u32| -> Option<usize> {
        for s in &parsed_sections {
            let span = s.virtual_size.max(s.raw_size);
            if rva >= s.virtual_address && rva < s.virtual_address + span {
                return Some((s.raw_ptr + (rva - s.virtual_address)) as usize);
            }
        }
        if (rva as usize) < data.len() { Some(rva as usize) } else { None }
    };
    let read_c_string = |off: usize| -> String {
        let slice = data.get(off..off + 512).unwrap_or(&[]);
        let end = slice.iter().position(|&b| b == 0).unwrap_or(slice.len());
        String::from_utf8_lossy(&slice[..end]).to_string()
    };

    let mut imports = Vec::new();
    if import_rva != 0 {
        if let Some(mut desc) = rva_to_offset(import_rva) {
            for _ in 0..64 { // descriptor cap
                let name_rva = u32le(data, desc + 12).unwrap_or(0);
                let thunk_rva = u32le(data, desc).unwrap_or(0);
                if name_rva == 0 && thunk_rva == 0 { break; }
                if let Some(name_off) = rva_to_offset(name_rva) {
                    let dll = read_c_string(name_off);
                    if !dll.is_empty() { imports.push(dll); }
                }
                desc += 20;
            }
        }
    }

    Some(PeInfo {
        machine: match machine_raw { 0x8664 => "x86-64", 0x14c => "x86", 0xaa64 => "ARM64", 0x1c0 => "ARM", _ => "unknown" }.to_string(),
        is_64bit,
        subsystem: match subsystem_raw { 2 => "windows-gui", 3 => "windows-console", 1 => "native", _ => "other" }.to_string(),
        sections, imports, executable_sections,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn entropy_and_format() {
        assert_eq!(shannon_entropy(&[]), 0.0);
        assert!(shannon_entropy(b"aaaaaaaaaaaaaaaa") < 0.01);
        assert_eq!(detect_format(b"MZ....", Path::new("a.exe")), "PE");
        let inds = scan_indicators(b"xx CreateRemoteThread yy https://example.invalid");
        assert!(inds.iter().any(|i| i.category == "injection"));
    }
}
