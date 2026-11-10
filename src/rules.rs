//! Rule engine & risk scoring.
//!
//! The native analyzer (module 4) produces *facts* — hashes, PE metadata,
//! capability strings. This module turns facts into **findings**: named,
//! stable-ID rules with a severity and a score contribution, so two reports
//! can be compared, triaged, or fed to a ticket system without a human
//! re-reading every field.
//!
//! Rules are deliberately boring and explainable: each one is a small
//! `if` over data that is already in the report, and every finding carries
//! the evidence that triggered it. There is no ML, no signature feed and no
//! network — an air-gapped operator can read the whole rulebook in one file
//! and know exactly why a number is what it is.

use crate::json::Value;
use crate::rea_bridge::{bare_function, FileAnalysis, PeInfo};
use std::collections::BTreeMap;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Severity {
    Info,
    Low,
    Medium,
    High,
    Critical,
}

impl Severity {
    pub fn parse(text: &str) -> Option<Severity> {
        match text {
            "info" => Some(Severity::Info),
            "low" => Some(Severity::Low),
            "medium" => Some(Severity::Medium),
            "high" => Some(Severity::High),
            "critical" => Some(Severity::Critical),
            _ => None,
        }
    }

    pub fn as_str(&self) -> &'static str {
        match self {
            Severity::Info => "info",
            Severity::Low => "low",
            Severity::Medium => "medium",
            Severity::High => "high",
            Severity::Critical => "critical",
        }
    }

    fn rank(&self) -> u64 {
        match self {
            Severity::Info => 0,
            Severity::Low => 1,
            Severity::Medium => 2,
            Severity::High => 3,
            Severity::Critical => 4,
        }
    }
}

#[derive(Debug, Clone)]
pub struct Finding {
    /// Stable rule id (`PE100`) — safe to key off in downstream tooling.
    pub rule: &'static str,
    pub title: String,
    pub severity: Severity,
    pub category: &'static str,
    /// Points this finding contributes to the file / overall score.
    pub score: u64,
    pub file: String,
    pub evidence: String,
}

impl Finding {
    pub fn to_json(&self) -> Value {
        Value::obj(vec![
            ("rule", Value::str(self.rule)),
            ("title", Value::str(self.title.clone())),
            ("severity", Value::str(self.severity.as_str())),
            ("category", Value::str(self.category)),
            ("score", Value::num(self.score)),
            ("file", Value::str(self.file.clone())),
            ("evidence", Value::str(self.evidence.clone())),
        ])
    }
}

/// Tunables, all in one place so an operator can dial noise down.
#[derive(Debug, Clone)]
pub struct Thresholds {
    /// Whole-file / section entropy above this means "likely packed".
    pub packed_entropy: f64,
    /// Overlay bytes considered meaningful (tiny overlays are signatures,
    /// debug data or padding and are not worth a finding).
    pub overlay_bytes: u64,
    /// Sections smaller than this are not entropy-judged (too few bytes to
    /// be statistically meaningful).
    pub min_section_bytes: u32,
    /// Files smaller than this are not packed-judged.
    pub min_packed_bytes: u64,
}

impl Default for Thresholds {
    fn default() -> Self {
        Thresholds {
            packed_entropy: 7.2,
            overlay_bytes: 4096,
            min_section_bytes: 1024,
            min_packed_bytes: 10_240,
        }
    }
}

/// Section names used by common packers/protectors. Matching one is
/// evidence of *packing*, not of malice — commercial software does it too.
const PACKER_SECTIONS: &[(&str, &str)] = &[
    ("UPX0", "UPX"),
    ("UPX1", "UPX"),
    ("UPX2", "UPX"),
    (".aspack", "ASPack"),
    (".adata", "ASPack"),
    (".MPRESS1", "MPRESS"),
    (".MPRESS2", "MPRESS"),
    (".petite", "Petite"),
    (".themida", "Themida"),
    (".vmp0", "VMProtect"),
    (".vmp1", "VMProtect"),
    (".enigma1", "Enigma"),
    (".enigma2", "Enigma"),
    ("PELOCKnt", "PELock"),
    (".boom", "The Boomerang"),
];

/// Import combinations that describe an *injection* primitive. Each tuple is
/// (required APIs, label). All entries of the inner slice must be present.
const INJECTION_SETS: &[(&[&str], &str)] = &[
    (
        &["VirtualAllocEx", "WriteProcessMemory", "CreateRemoteThread"],
        "classic remote-thread injection",
    ),
    (
        &["NtUnmapViewOfSection", "SetThreadContext", "ResumeThread"],
        "process hollowing",
    ),
    (
        &["VirtualAllocEx", "QueueUserAPC"],
        "APC injection",
    ),
    (
        &["CreateProcess", "WriteProcessMemory", "SetThreadContext"],
        "process replacement",
    ),
];

const ANTI_DEBUG_APIS: &[&str] = &[
    "IsDebuggerPresent",
    "CheckRemoteDebuggerPresent",
    "NtQueryInformationProcess",
    "OutputDebugStringA",
];

fn has_import(pe: &PeInfo, needle: &str) -> bool {
    pe.imported_functions
        .iter()
        .any(|f| bare_function(f).eq_ignore_ascii_case(needle))
}

/// Indicator categories come from the string scanner as borrowed strings;
/// findings store `&'static str` so reports stay cheap to copy. Map the
/// known set and fall back to `capability` for anything new.
fn static_category(category: &str) -> &'static str {
    match category {
        "network" => "network",
        "execution" => "execution",
        "memory" => "memory",
        "injection" => "injection",
        "persistence" => "persistence",
        "anti-analysis" => "anti-analysis",
        "obfuscation" => "obfuscation",
        "crypto" => "crypto",
        "signature" => "signature",
        "hardening" => "hardening",
        "packing" => "packing",
        "metadata" => "metadata",
        "loader" => "loader",
        "masquerade" => "masquerade",
        _ => "capability",
    }
}

/// Record one finding. Takes `&mut Vec` explicitly rather than capturing a
/// closure: closures with several arguments cannot always infer the
/// late-bound lifetime of a `&'static str` rule id.
#[allow(clippy::too_many_arguments)]
fn add(
    out: &mut Vec<Finding>,
    file: &FileAnalysis,
    rule: &'static str,
    title: String,
    severity: Severity,
    category: &'static str,
    score: u64,
    evidence: String,
) {
    out.push(Finding {
        rule,
        title,
        severity,
        category,
        score,
        file: file.path.clone(),
        evidence,
    });
}

/// Extensions that promise a Windows executable.
const EXECUTABLE_EXTENSIONS: &[&str] = &["exe", "dll", "sys", "ocx", "scr", "cpl", "com"];
/// Extensions that promise a document, image or other passive data.
const DATA_EXTENSIONS: &[&str] = &[
    "txt", "log", "csv", "json", "xml", "pdf", "rtf", "png", "jpg", "jpeg", "gif", "bmp",
    "mp3", "mp4", "avi", "doc", "docx", "xls", "xlsx", "ppt", "pptx",
];

/// FMT002 — the name promises one kind of content and the bytes are another.
///
/// Only *known* formats count. `unknown`/`binary` mean "we could not classify
/// it" (including files above the content-analysis limit), and turning our
/// own blind spot into a masquerade finding would be dishonest.
fn format_mismatch(file: &FileAnalysis) -> Option<String> {
    let extension = std::path::Path::new(&file.path).extension()?.to_string_lossy().to_ascii_lowercase();
    if EXECUTABLE_EXTENSIONS.contains(&extension.as_str())
        && matches!(file.format.as_str(), "script" | "text" | "ZIP" | "OLE/MSI" | "ELF")
    {
        return Some(format!(
            "'.{extension}' promises a Windows executable, but the content is {}",
            file.format
        ));
    }
    if file.format == "PE" && DATA_EXTENSIONS.contains(&extension.as_str()) {
        return Some(format!(
            "'.{extension}' promises passive data, but the content is a PE executable"
        ));
    }
    None
}

/// Evaluate every rule against one file. Deterministic order: the rules run
/// in a fixed sequence and findings are returned in rule order.
pub fn evaluate_file(file: &FileAnalysis, t: &Thresholds) -> Vec<Finding> {
    let mut out: Vec<Finding> = Vec::new();
    if let Some(pe) = &file.pe {
        // --- Hardening -----------------------------------------------------
        // A free function records findings, never a closure: closures with
        // several arguments cannot reliably infer the late-bound lifetime of
        // a `&'static str` rule id.
        if !pe.signed {
            add(&mut out, file,
                "PE001",
                "Executable is not Authenticode-signed".into(),
                Severity::Low,
                "signature",
                6,
                "no certificate table (signature validity still needs WinVerifyTrust/REA)".into(),
            );
        } else {
            add(&mut out, file,
                "PE000",
                "Authenticode certificate table present".into(),
                Severity::Info,
                "signature",
                0,
                "presence only — verify the chain with REA/Windows for trust".into(),
            );
        }
        if !pe.mitigations.aslr_dynamic_base {
            add(&mut out, file,
                "PE002",
                "No ASLR (DYNAMIC_BASE unset)".into(),
                Severity::Medium,
                "hardening",
                8,
                "DllCharacteristics lacks 0x0040".into(),
            );
        }
        if !pe.mitigations.nx_compat {
            add(&mut out, file,
                "PE003",
                "No NX/DEP compatibility (NX_COMPAT unset)".into(),
                Severity::Medium,
                "hardening",
                8,
                "DllCharacteristics lacks 0x0100".into(),
            );
        }
        if pe.mitigations.no_seh {
            add(&mut out, file,
                "PE004",
                "SEH disabled (NO_SEH)".into(),
                Severity::Low,
                "hardening",
                3,
                "structured exception handling stripped — anti-analysis or old packer".into(),
            );
        }

        // --- Sections ------------------------------------------------------
        for s in &pe.section_details {
            if s.executable && s.writable {
                add(&mut out, file,
                    "PE100",
                    format!("Writable + executable section '{}'", s.name),
                    Severity::High,
                    "memory",
                    20,
                    format!("section characteristics include code|write ({} bytes)", s.raw_size),
                );
            }
            if let Some(entropy) = s.entropy.filter(|e| s.raw_size >= t.min_section_bytes && *e > t.packed_entropy) {
                add(&mut out, file,
                    "PE110",
                    format!("High-entropy section '{}'", s.name),
                    Severity::Medium,
                    "packing",
                    12,
                    format!("entropy {:.2} over {} raw bytes (packed or encrypted)", entropy, s.raw_size),
                );
            }
        }
        for (name, packer) in PACKER_SECTIONS {
            if pe.sections.iter().any(|s| s.eq_ignore_ascii_case(name)) {
                add(&mut out, file,
                    "PE130",
                    format!("Packer section layout ({packer})"),
                    Severity::High,
                    "packing",
                    18,
                    format!("section '{name}' is characteristic of {packer}"),
                );
            }
        }
        // An executable section with no code is a classic unpacking stub.
        if pe.executable_sections.is_empty() && !pe.sections.is_empty() {
            add(&mut out, file,
                "PE131",
                "No executable sections".into(),
                Severity::Medium,
                "packing",
                10,
                "every section lacks the executable flag — likely an unpacking stub".into(),
            );
        }

        // --- Overlay / appended data ---------------------------------------
        if pe.overlay_size >= t.overlay_bytes {
            add(&mut out, file,
                "PE120",
                "Data appended after the last section".into(),
                Severity::Medium,
                "packing",
                10,
                format!("{} overlay bytes (dropper / second stage / installer payload)", pe.overlay_size),
            );
        }

        // --- Imports -------------------------------------------------------
        if pe.imported_functions.is_empty() {
            add(&mut out, file,
                "PE170",
                "No imported functions".into(),
                Severity::Medium,
                "loader",
                10,
                "import table empty — dynamically resolved or shellcode-style loader".into(),
            );
        } else {
            for (apis, label) in INJECTION_SETS {
                if apis.iter().all(|a| has_import(pe, a)) {
                    add(&mut out, file,
                        "PE140",
                        format!("Injection API set present ({label})"),
                        Severity::High,
                        "injection",
                        22,
                        apis.join(" + "),
                    );
                }
            }
            let anti: Vec<&str> = ANTI_DEBUG_APIS.iter().copied().filter(|a| has_import(pe, a)).collect();
            if !anti.is_empty() {
                add(&mut out, file,
                    "PE141",
                    "Anti-debugging API present".into(),
                    Severity::Medium,
                    "anti-analysis",
                    10,
                    anti.join(", "),
                );
            }
            let ordinals = pe.imported_functions.iter().filter(|f| bare_function(f).starts_with('#')).count();
            if ordinals > 0 && ordinals == pe.imported_functions.len() {
                add(&mut out, file,
                    "PE150",
                    "All imports resolved by ordinal".into(),
                    Severity::Medium,
                    "anti-analysis",
                    12,
                    format!("{ordinals} ordinal-only imports, no function names"),
                );
            }
        }

        // --- Metadata sanity ----------------------------------------------
        const EPOCH_1990: u32 = 631_152_000;
        if pe.timestamp != 0 && !(EPOCH_1990..=crate::util::unix_secs() as u32 + 86_400).contains(&pe.timestamp) {
            add(&mut out, file,
                "PE160",
                "Implausible compile timestamp".into(),
                Severity::Low,
                "metadata",
                5,
                format!("TimeDateStamp {} is before 1990 or in the future", pe.timestamp),
            );
        }
        if pe.timestamp == 0 {
            add(&mut out, file,
                "PE161",
                "Zeroed compile timestamp".into(),
                Severity::Low,
                "metadata",
                3,
                "TimeDateStamp 0 is rewritten by some builders/packers".into(),
            );
        }
    }

    // --- Whole-file heuristics ---------------------------------------------
    if file.size >= t.min_packed_bytes && file.entropy > 7.5 {
        add(&mut out, file,
            "ENT001",
            "Whole file is high entropy".into(),
            Severity::Medium,
            "packing",
            10,
            format!("entropy {:.2} over {} bytes", file.entropy, file.size),
        );
    }
    // --- Format sanity -----------------------------------------------------
    // FMT001 is about a *broken* PE, not about other executable formats:
    // an ELF file legitimately has no PE header, and claiming its "magic
    // bytes disagree" was both wrong and noisy on Linux trees.
    if file.pe.is_none() && file.format == "PE" && file.content_bytes == file.size {
        add(&mut out, file,
            "FMT001",
            "PE header could not be parsed".into(),
            Severity::Medium,
            "masquerade",
            8,
            "MZ signature present but the PE headers are missing or malformed (DOS-only, truncated or deliberately broken image)".into(),
        );
    }
    if let Some(evidence) = format_mismatch(file) {
        add(&mut out, file,
            "FMT002",
            "Extension/format mismatch".into(),
            Severity::Medium,
            "masquerade",
            8,
            evidence,
        );
    }

    // --- Capability strings (from the native string scan) ------------------
    let mut by_category: BTreeMap<&str, Vec<&str>> = BTreeMap::new();
    for ind in &file.indicators {
        by_category.entry(ind.category.as_str()).or_default().push(ind.matched.as_str());
    }
    for (category, matches) in by_category {
        let category: &'static str = static_category(category);
        if category == "obfuscation" || category == "crypto" {
            continue; // noisy and low-signal on their own
        }
        let sev = if matches.len() >= 3 { Severity::Medium } else { Severity::Low };
        let score = if matches.len() >= 3 { 8 } else { 4 };
        add(&mut out, file,
            "STR001",
            format!("Capability strings: {category}"),
            sev,
            category,
            score,
            matches.join(", "),
        );
    }

    out.sort_by(|a, b| b.severity.rank().cmp(&a.severity.rank()).then(a.rule.cmp(b.rule)));
    out
}

/// Evaluate the whole report.
pub fn evaluate(report: &crate::rea_bridge::ReaReport) -> Vec<Finding> {
    let t = Thresholds::default();
    let mut all = Vec::new();
    for file in &report.files {
        all.extend(evaluate_file(file, &t));
    }
    all.sort_by(|a, b| {
        b.severity
            .rank()
            .cmp(&a.severity.rank())
            .then(a.file.cmp(&b.file))
            .then(a.rule.cmp(b.rule))
    });
    all
}

/// Score + verdict for a set of findings.
///
/// Scores are capped at 100. A single critical finding always lands the
/// target in at least the `high` band so one decisive rule cannot be diluted
/// by a hundred boring files.
/// The shared arithmetic: cap the summed score, then floor it by the
/// worst severity present, then band it into a verdict.
fn score_with_floor(raw: u64, highest: Severity) -> (u64, &'static str) {
    let mut score = raw.min(100);
    if highest == Severity::Critical {
        score = score.max(70);
    } else if highest == Severity::High {
        score = score.max(30);
    }
    (score, verdict_for_score(score))
}

pub fn risk(findings: &[Finding]) -> (u64, &'static str) {
    let raw: u64 = findings.iter().map(|f| f.score).sum();
    let highest = findings.iter().map(|f| f.severity).max().unwrap_or(Severity::Info);
    score_with_floor(raw, highest)
}

/// The score, verdict and per-severity counts a list of *serialized*
/// findings implies — the same arithmetic as [`risk`], over the JSON an
/// archive carries. Archive validation recomputes from this because a
/// stored report's labels are claims and its findings are the evidence.
/// Counts are in writer order: critical, high, medium, low, info.
/// `None` when a finding lacks a usable severity or score: the caller
/// refuses rather than guessing at a verdict it cannot check.
pub fn risk_from_serialized(findings: &[Value]) -> Option<(u64, &'static str, [u64; 5])> {
    let mut raw: u64 = 0;
    let mut highest = Severity::Info;
    let mut counts = [0u64; 5];
    for finding in findings {
        let severity = Severity::parse(finding.get("severity").and_then(Value::as_str)?)?;
        let score = match finding.get("score") {
            Some(Value::Number(n)) if n.is_finite() && *n >= 0.0 && n.fract() == 0.0 => *n as u64,
            _ => return None,
        };
        raw = raw.saturating_add(score);
        highest = highest.max(severity);
        counts[match severity {
            Severity::Critical => 0,
            Severity::High => 1,
            Severity::Medium => 2,
            Severity::Low => 3,
            Severity::Info => 4,
        }] += 1;
    }
    let (score, verdict) = score_with_floor(raw, highest);
    Some((score, verdict, counts))
}

/// The band a score falls in. Every verdict in every report comes from here,
/// so a verdict can never disagree with the number next to it.
pub fn verdict_for_score(score: u64) -> &'static str {
    match score {
        0..=9 => "low",
        10..=29 => "medium",
        30..=59 => "high",
        _ => "critical",
    }
}

/// Findings aggregated into the shape reports carry under `"rules"`.
pub fn to_json(findings: &[Finding]) -> Value {
    let (score, verdict) = risk(findings);
    let mut counts = BTreeMap::new();
    for sev in ["critical", "high", "medium", "low", "info"] {
        let n = findings.iter().filter(|f| f.severity.as_str() == sev).count() as u64;
        counts.insert(sev.to_string(), Value::num(n));
    }
    // One entry per rule that fired, with how many files it hit.
    let mut rules: BTreeMap<String, (u64, &'static str, String)> = BTreeMap::new();
    for f in findings {
        let entry = rules.entry(f.rule.to_string())
            .or_insert((0, f.severity.as_str(), f.title.clone()));
        entry.0 += 1;
    }
    let fired: Vec<Value> = rules.into_iter().map(|(rule, (count, severity, title))| {
        Value::obj(vec![
            ("rule", Value::str(rule)),
            ("title", Value::str(title)),
            ("severity", Value::str(severity)),
            ("files", Value::num(count)),
        ])
    }).collect();
    Value::obj(vec![
        ("score", Value::num(score)),
        ("verdict", Value::str(verdict)),
        ("finding_count", Value::num(findings.len() as u64)),
        ("by_severity", Value::Object(counts)),
        ("rules_fired", Value::Array(fired)),
        ("findings", Value::Array(findings.iter().map(Finding::to_json).collect())),
    ])
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::rea_bridge::{Indicator, Mitigations, PeSection};

    fn clean_pe() -> PeInfo {
        PeInfo {
            machine: "x86-64".into(),
            is_64bit: true,
            subsystem: "windows-console".into(),
            sections: vec![".text".into(), ".rdata".into()],
            section_details: vec![
                PeSection { name: ".text".into(), virtual_size: 0x1000, raw_size: 0x1000, raw_offset: 0x200, virtual_address: 0x1000,
                            entropy: Some(6.1), executable: true, writable: false },
                PeSection { name: ".rdata".into(), virtual_size: 0x1000, raw_size: 0x1000, raw_offset: 0x200, virtual_address: 0x1000,
                            entropy: Some(4.0), executable: false, writable: false },
            ],
            imports: vec!["KERNEL32.dll".into()],
            imported_functions: vec!["KERNEL32.dll!Sleep".into()],
            imports_complete: true,
            executable_sections: vec![".text".into()],
            timestamp: 1_700_000_000,
            entry_point_rva: 0x1000,
            dll_characteristics: vec!["dynamic_base".into(), "nx_compat".into(), "guard_cf".into()],
            mitigations: Mitigations { aslr_dynamic_base: true, nx_compat: true, guard_cf: true,
                                       no_seh: false, high_entropy_va: true },
            signed: true,
            overlay_size: 0,
            overlay_ranges: vec![],
            certificate_range: None,
        }
    }

    fn file_with(pe: Option<PeInfo>) -> FileAnalysis {
        FileAnalysis {
            path: "sample.exe".into(),
            size: 40_960,
            sha256: "0".repeat(64),
            md5: "0".repeat(32),
            imphash: Some("0".repeat(32)),
            format: "PE".into(),
            entropy: 6.0,
            content_bytes: 40_960,
            pe,
            indicators: vec![],
        }
    }

    #[test]
    fn clean_signed_pe_scores_zero() {
        let findings = evaluate_file(&file_with(Some(clean_pe())), &Thresholds::default());
        assert_eq!(findings.len(), 1, "only the info-level signature finding: {findings:?}");
        assert_eq!(findings[0].severity, Severity::Info);
        let (score, verdict) = risk(&findings);
        assert_eq!(score, 0);
        assert_eq!(verdict, "low");
    }

    #[test]
    fn packed_injector_trips_expected_rules() {
        let mut pe = clean_pe();
        pe.signed = false;
        pe.sections = vec!["UPX0".into(), "UPX1".into()];
        pe.section_details = vec![PeSection {
            name: "UPX1".into(), virtual_size: 0x4000, raw_size: 0x4000, raw_offset: 0x200, virtual_address: 0x1000,
            entropy: Some(7.8), executable: true, writable: true,
        }];
        pe.executable_sections = vec!["UPX1".into()];
        pe.overlay_size = 20_000;
        pe.imported_functions = vec![
            "KERNEL32.dll!VirtualAllocEx".into(),
            "KERNEL32.dll!WriteProcessMemory".into(),
            "KERNEL32.dll!CreateRemoteThread".into(),
        ];
        let findings = evaluate_file(&file_with(Some(pe)), &Thresholds::default());
        let ids: Vec<&str> = findings.iter().map(|f| f.rule).collect();
        for expected in ["PE001", "PE100", "PE110", "PE120", "PE130", "PE140"] {
            assert!(ids.contains(&expected), "missing {expected} in {ids:?}");
        }
        let (score, verdict) = risk(&findings);
        assert!(score >= 70, "packed injector must score high, got {score}");
        assert_eq!(verdict, "critical");
    }

    #[test]
    fn ordinal_only_imports_and_missing_mitigations() {
        let mut pe = clean_pe();
        pe.imported_functions = vec!["KERNEL32.dll!#42".into(), "KERNEL32.dll!#7".into()];
        pe.mitigations = Mitigations::default();
        pe.dll_characteristics.clear();
        let findings = evaluate_file(&file_with(Some(pe)), &Thresholds::default());
        let ids: Vec<&str> = findings.iter().map(|f| f.rule).collect();
        assert!(ids.contains(&"PE002") && ids.contains(&"PE003") && ids.contains(&"PE150"), "{ids:?}");
    }

    #[test]
    fn capability_strings_roll_up_into_one_finding_per_category() {
        let mut f = file_with(None);
        f.format = "script".into();
        f.indicators = vec![
            Indicator { category: "network".into(), matched: "http://".into(), severity: "medium".into() },
            Indicator { category: "network".into(), matched: "WinHttp".into(), severity: "medium".into() },
            Indicator { category: "network".into(), matched: "InternetOpen".into(), severity: "medium".into() },
            Indicator { category: "persistence".into(), matched: "schtasks".into(), severity: "medium".into() },
            Indicator { category: "crypto".into(), matched: "CryptEncrypt".into(), severity: "low".into() },
        ];
        let findings = evaluate_file(&f, &Thresholds::default());
        let network: Vec<&Finding> = findings.iter().filter(|x| x.rule == "STR001" && x.category == "network").collect();
        assert_eq!(network.len(), 1);
        assert_eq!(network[0].severity, Severity::Medium);
        assert!(network[0].evidence.contains("WinHttp"));
        assert!(!findings.iter().any(|x| x.category == "crypto"), "crypto is intentionally skipped");
    }

    #[test]
    fn elf_without_a_pe_header_is_not_a_format_finding() {
        // FMT001 used to fire on every ELF file: no PE header is exactly
        // what an ELF is supposed to have.
        let mut f = file_with(None);
        f.path = "usr/bin/tool".into();
        f.format = "ELF".into();
        let findings = evaluate_file(&f, &Thresholds::default());
        assert!(!findings.iter().any(|x| x.rule == "FMT001" || x.rule == "FMT002"), "{findings:?}");
    }

    #[test]
    fn unknown_section_entropy_does_not_trigger_a_packing_finding() {
        let mut pe = clean_pe();
        pe.section_details[0].entropy = None;
        let file = file_with(Some(pe));
        assert!(!evaluate_file(&file, &Thresholds::default()).iter().any(|f| f.rule == "PE110"));
    }

    #[test]
    fn a_prefix_limit_is_not_evidence_of_a_broken_pe_header() {
        let mut file = file_with(None);
        file.content_bytes = 64;
        assert!(!evaluate_file(&file, &Thresholds::default()).iter().any(|f| f.rule == "FMT001"));
    }

    #[test]
    fn broken_pe_header_is_reported_once() {
        let mut f = file_with(None);
        f.format = "PE".into();
        let findings = evaluate_file(&f, &Thresholds::default());
        let fmt: Vec<&Finding> = findings.iter().filter(|x| x.rule == "FMT001").collect();
        assert_eq!(fmt.len(), 1, "{findings:?}");
        assert_eq!(fmt[0].severity, Severity::Medium);
    }

    #[test]
    fn extension_mismatch_fires_only_on_known_formats() {
        let mut f = file_with(None);
        f.path = "photos/picture.jpg".into();
        f.format = "PE".into();
        // A PE named .jpg is a masquerade; the broken header is a separate fact.
        assert!(evaluate_file(&f, &Thresholds::default()).iter().any(|x| x.rule == "FMT002"));

        f.path = "setup.exe".into();
        f.format = "script".into();
        let findings = evaluate_file(&f, &Thresholds::default());
        let mismatch: Vec<&Finding> = findings.iter().filter(|x| x.rule == "FMT002").collect();
        assert_eq!(mismatch.len(), 1, "{findings:?}");
        assert!(mismatch[0].evidence.contains("script"), "{:?}", mismatch[0]);

        // Our own blind spots must never become findings: an unclassified
        // file (e.g. one above the content limit) is not evidence of disguise.
        for format in ["unknown", "binary"] {
            f.format = format.into();
            assert!(!evaluate_file(&f, &Thresholds::default()).iter().any(|x| x.rule == "FMT002"), "{format}");
        }

        // Matching name and content stay quiet.
        f.path = "app.exe".into();
        f.format = "PE".into();
        assert!(format_mismatch(&f).is_none());
        f.path = "notes.txt".into();
        f.format = "text".into();
        assert!(format_mismatch(&f).is_none());
        f.path = "README".into();
        f.format = "text".into();
        assert!(format_mismatch(&f).is_none(), "no extension, no promise");
    }

    #[test]
    fn verdict_always_matches_the_score_band() {
        for score in [0, 9, 10, 29, 30, 59, 60, 100] {
            let expected = match score {
                0..=9 => "low",
                10..=29 => "medium",
                30..=59 => "high",
                _ => "critical",
            };
            assert_eq!(verdict_for_score(score), expected);
        }
    }

    #[test]
    fn json_shape_is_stable() {
        let json = to_json(&evaluate_file(&file_with(Some(clean_pe())), &Thresholds::default()));
        assert!(json.get("score").is_some());
        assert_eq!(json.get("verdict").and_then(Value::as_str), Some("low"));
        assert_eq!(json.get("findings").map(|f| matches!(f, Value::Array(_))), Some(true));
        let text = json.to_string_pretty();
        assert!(crate::json::parse(&text).is_ok());
    }

    #[test]
    fn imphash_is_stable_across_unrelated_changes() {
        // Rule-facing guarantee: imphash depends only on the import order
        // and names — not on size, path, or section layout.
        let mut pe = clean_pe();
        pe.imported_functions = vec!["KERNEL32.dll!CreateFileW".into(), "USER32.dll!#12".into()];
        let a = crate::rea_bridge::imphash(&pe.imported_functions).unwrap();
        pe.overlay_size = 9_999;
        pe.signed = false;
        let b = crate::rea_bridge::imphash(&pe.imported_functions).unwrap();
        assert_eq!(a, b);
        assert_eq!(a.len(), 32);
    }
}
