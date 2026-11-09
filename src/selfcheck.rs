//! Cross-module self-checks.
//!
//! The per-module unit tests prove each piece works on its own. These prove
//! the *pipeline* does: bytes on disk → native analyzer → rules → report
//! JSON → human rendering. That is the path an operator actually walks, and
//! it previously had no end-to-end coverage on the Windows side of the code.

use crate::json::Value;
use crate::testutil::{Import, PeBuilder};

/// A PE designed to look hostile: unsigned, W+X packed section, a large
/// overlay, and the classic injection triad.
fn hostile_pe() -> Vec<u8> {
    let mut bytes = PeBuilder::new()
        .signed(false)
        .dll_characteristics(0x0100) // NX only: no ASLR, no CFG
        .sections(vec![
            (".text".to_string(), 0x200, 0x200, 0x6000_0020),
            ("UPX1".to_string(), 0x1000, 0x200, 0xE000_0020), // exec + write
        ])
        .imports(
            "KERNEL32.dll",
            vec![
                Import::Named("VirtualAllocEx"),
                Import::Named("WriteProcessMemory"),
                Import::Named("CreateRemoteThread"),
                Import::Named("IsDebuggerPresent"),
            ],
        )
        .overlay(8192)
        .build();
    bytes.extend_from_slice(b"http://example.invalid/gate.php\x00powershell -enc AAAA\x00");
    bytes
}

fn write_temp(name: &str, bytes: &[u8]) -> std::path::PathBuf {
    let dir = std::env::temp_dir().join(format!("rea_offline_selfcheck_{}", crate::util::new_id()));
    std::fs::create_dir_all(&dir).unwrap();
    let path = dir.join(name);
    std::fs::write(&path, bytes).unwrap();
    path
}

#[test]
fn hostile_binary_end_to_end() {
    let path = write_temp("implant.exe", &hostile_pe());
    let report = crate::rea_bridge::ReaBridge::new(crate::rea_bridge::ReaConfig::default())
        .analyze(&path)
        .expect("analysis");

    assert_eq!(report.files.len(), 1);
    let file = &report.files[0];
    assert_eq!(file.format, "PE");
    assert_eq!(file.sha256.len(), 64);
    assert_eq!(file.md5.len(), 32);
    assert!(file.imphash.is_some(), "imports present → imphash expected");
    assert!(file.pe.is_some());
    // Overlay = 8 KiB of filler *plus* the appended indicator strings.
    assert!(
        file.pe.as_ref().unwrap().overlay_size >= 8192,
        "overlay: {}",
        file.pe.as_ref().unwrap().overlay_size
    );

    let json = report.to_json();
    let score = match json.get("risk_score") {
        Some(Value::Number(x)) => *x,
        other => panic!("risk_score must be a number, got {other:?}"),
    };
    assert!(
        score >= 60.0,
        "hostile binary should score high, got {score}"
    );
    assert_eq!(
        json.get("verdict").and_then(Value::as_str),
        Some("critical")
    );

    // Findings name rules and evidence, and the summary agrees with them.
    let rules = json.get("rules").expect("rules block");
    let findings = match rules.get("findings") {
        Some(Value::Array(items)) => items.clone(),
        other => panic!("findings array expected, got {other:?}"),
    };
    let rule_ids: Vec<String> = findings
        .iter()
        .filter_map(|f| f.get("rule").and_then(Value::as_str).map(|s| s.to_string()))
        .collect();
    for expected in ["PE100", "PE130", "PE140", "PE120"] {
        assert!(
            rule_ids.iter().any(|r| r == expected),
            "missing {expected} in {rule_ids:?}"
        );
    }
    assert_eq!(
        json.get("summary")
            .and_then(|s| s.get("verdict"))
            .and_then(Value::as_str),
        Some("critical")
    );

    // Rendering must not lose the decision.
    let text = crate::render::summary_text(&json);
    assert!(text.contains("CRITICAL"), "{text}");
    let md = crate::render::to_markdown(&json);
    assert!(md.contains("PE140"), "{md}");

    // And the whole document must be valid JSON after a round trip.
    let reparsed = crate::json::parse(&json.to_string_pretty()).expect("valid JSON");
    assert_eq!(
        reparsed.get("file_count").and_then(|v| match v {
            Value::Number(n) => Some(*n as u64),
            _ => None,
        }),
        Some(1)
    );

    std::fs::remove_dir_all(path.parent().unwrap()).unwrap();
}

#[test]
fn clean_binary_scores_low() {
    let bytes = PeBuilder::new()
        .signed(true)
        .imports(
            "KERNEL32.dll",
            vec![Import::Named("Sleep"), Import::Named("CreateFileW")],
        )
        .build();
    let path = write_temp("clean.exe", &bytes);
    let report = crate::rea_bridge::ReaBridge::new(crate::rea_bridge::ReaConfig::default())
        .analyze(&path)
        .unwrap();
    assert_eq!(report.risk_score(), 0, "signed, hardened, no indicators");
    assert_eq!(report.verdict(), "low");
    std::fs::remove_dir_all(path.parent().unwrap()).unwrap();
}

#[test]
fn directory_scan_covers_every_file() {
    let dir = std::env::temp_dir().join(format!("rea_offline_selfcheck_{}", crate::util::new_id()));
    std::fs::create_dir_all(dir.join("nested")).unwrap();
    std::fs::write(dir.join("a.bin"), b"plain text").unwrap();
    std::fs::write(dir.join("nested/b.exe"), hostile_pe()).unwrap();
    std::fs::write(dir.join("nested/empty.txt"), b"").unwrap();
    let report = crate::rea_bridge::ReaBridge::new(crate::rea_bridge::ReaConfig::default())
        .analyze(&dir)
        .unwrap();
    assert_eq!(
        report.files.len(),
        3,
        "files: {:?}",
        report.files.iter().map(|f| &f.path).collect::<Vec<_>>()
    );
    assert!(report
        .files
        .iter()
        .any(|f| f.path.ends_with("nested/b.exe")));
    // The empty file must still be hashed rather than skipped.
    let empty = report
        .files
        .iter()
        .find(|f| f.path.ends_with("empty.txt"))
        .unwrap();
    assert_eq!(
        empty.sha256,
        "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
    );
    assert_eq!(empty.md5, "d41d8cd98f00b204e9800998ecf8427e");
    std::fs::remove_dir_all(&dir).unwrap();
}

#[test]
fn imphash_is_shared_by_rebuilds_with_different_overlays() {
    // Same imports, different size/overlay/signature state → same imphash
    // but different SHA-256. That is the whole point of the value.
    let a = PeBuilder::new()
        .imports("KERNEL32.dll", vec![Import::Named("Sleep")])
        .imports("USER32.dll", vec![Import::Ordinal(12)])
        .build();
    let b = PeBuilder::new()
        .imports("KERNEL32.dll", vec![Import::Named("Sleep")])
        .imports("USER32.dll", vec![Import::Ordinal(12)])
        .signed(true)
        .overlay(4096)
        .build();
    let pa = write_temp("a.exe", &a);
    let pb = write_temp("b.exe", &b);
    let bridge = crate::rea_bridge::ReaBridge::new(crate::rea_bridge::ReaConfig::default());
    let fa = &bridge.analyze(&pa).unwrap().files[0];
    let fb = &bridge.analyze(&pb).unwrap().files[0];
    assert_eq!(fa.imphash, fb.imphash);
    assert_ne!(fa.sha256, fb.sha256);
    // Ordinal-only funcs must not leak as named imports.
    assert!(fa.imphash.as_ref().unwrap().len() == 32);
    std::fs::remove_dir_all(pa.parent().unwrap()).unwrap();
    std::fs::remove_dir_all(pb.parent().unwrap()).unwrap();
}
