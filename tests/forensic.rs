use rea_offline::json::{parse, Value};
use std::path::{Path, PathBuf};
use std::process::Command;

fn root() -> PathBuf {
    let root = std::env::temp_dir().join(format!("rea-forensic-{}", rea_offline::util::new_id()));
    std::fs::create_dir(&root).unwrap();
    root
}
fn cli(root: &Path, args: &[&str]) -> std::process::Output {
    Command::new(env!("CARGO_BIN_EXE_rea-offline")).current_dir(root)
        .env_remove("REA_PATH").args(args).output().unwrap()
}
#[test]
fn installed_program_folder_exports_verified_ai_evidence() {
    let root = root();
    std::fs::create_dir(root.join("installed")).unwrap();
    std::fs::write(root.join("installed/app.config"), br#"{"feature":"offline-editor"}"#).unwrap();
    std::fs::write(root.join("installed/app.exe"), rea_offline::testutil::demo_installer_bytes()).unwrap();
    let output = cli(&root, &["forensic", "installed", "--output", "evidence", "--include-files"]);
    assert!(output.status.success(), "{}", String::from_utf8_lossy(&output.stderr));
    let folder = root.join("evidence");
    let reconstruction = parse(&std::fs::read_to_string(folder.join("reconstruction.json")).unwrap()).unwrap();
    assert_eq!(reconstruction.get("source_kind").and_then(Value::as_str), Some("installed-program-folder"));
    assert_eq!(reconstruction.get("replication_complete"), Some(&Value::Bool(false)));
    assert_eq!(reconstruction.get("file_count"), Some(&Value::num(2)));
    assert!(!folder.join("installer-execution.json").exists());
    assert_eq!(std::fs::read(root.join("installed/app.config")).unwrap(),
        std::fs::read(folder.join("originals/app.config")).unwrap());
    let manifest = parse(&std::fs::read_to_string(folder.join("manifest.json")).unwrap()).unwrap();
    let entries = match manifest.get("files").unwrap() { Value::Array(a) => a, _ => panic!() };
    assert!(entries.len() >= 9);
    for entry in entries {
        let path = folder.join(entry.get("path").and_then(Value::as_str).unwrap());
        assert_eq!(rea_offline::sha256::hash_file(&path).unwrap(), entry.get("sha256").and_then(Value::as_str).unwrap());
    }
    for line in std::fs::read_to_string(folder.join("strings.jsonl")).unwrap().lines() {
        parse(line).unwrap();
    }
    assert!(std::fs::read_to_string(folder.join("resources.json")).unwrap().contains("app.config"));
    std::fs::remove_dir_all(root).unwrap();
}
#[test]
fn installer_static_export_never_runs_the_input_or_includes_originals_implicitly() {
    let root = root();
    std::fs::write(root.join("setup.exe"), rea_offline::testutil::demo_installer_bytes()).unwrap();
    let output = cli(&root, &["forensic", "setup.exe", "--output", "evidence"]);
    assert!(output.status.success());
    let value = parse(&std::fs::read_to_string(root.join("evidence/reconstruction.json")).unwrap()).unwrap();
    assert_eq!(value.get("source_kind").and_then(Value::as_str), Some("file-or-installer"));
    assert_eq!(value.get("installer_execution_requested"), Some(&Value::Bool(false)));
    assert!(!root.join("evidence/originals").exists());
    std::fs::remove_dir_all(root).unwrap();
}
#[test]
fn export_refuses_overwrites_recursive_output_and_installer_mode_for_folders() {
    let root = root();
    std::fs::create_dir(root.join("installed")).unwrap();
    std::fs::write(root.join("installed/data.txt"), "unchanged").unwrap();
    std::fs::create_dir(root.join("exists")).unwrap();
    for args in [
        vec!["forensic", "installed", "--output", "installed/nested"],
        vec!["forensic", "installed", "--output", "exists"],
        vec!["forensic", "installed", "--output", "evidence", "--run-installer"],
        vec!["forensic", "installed", "--output", "evidence", "--", "/quiet"],
    ] {
        let output = cli(&root, &args);
        assert!(!output.status.success(), "{args:?}");
    }
    assert_eq!(std::fs::read_to_string(root.join("installed/data.txt")).unwrap(), "unchanged");
    assert!(!root.join("installed/nested").exists());
    assert!(!root.join("evidence").exists());
    std::fs::remove_dir_all(root).unwrap();
}

#[cfg(unix)]
#[test]
fn installed_payload_is_preserved_before_temporary_install_tree_is_purged() {
    use std::os::unix::fs::PermissionsExt;
    let root = root();
    let installer = root.join("installer.sh");
    std::fs::write(&installer, "#!/bin/sh\nmkdir -p \"$REASANDBOX_INSTALL/Demo\"\nprintf 'offline editor config' > \"$REASANDBOX_INSTALL/Demo/app.ini\"\n").unwrap();
    std::fs::set_permissions(&installer, std::fs::Permissions::from_mode(0o700)).unwrap();
    let output = cli(&root, &["forensic", "installer.sh", "--output", "evidence", "--run-installer", "--include-files"]);
    assert!(output.status.success(), "{}", String::from_utf8_lossy(&output.stderr));
    assert_eq!(std::fs::read_to_string(root.join("evidence/installed-files/install/Demo/app.ini")).unwrap(), "offline editor config");
    assert!(root.join("evidence/installed-report.json").exists());
    let run = parse(&std::fs::read_to_string(root.join("evidence/installer-execution.json")).unwrap()).unwrap();
    assert_eq!(run.get("sandbox_kept"), Some(&Value::Bool(false)));
    assert!(!Path::new(run.get("sandbox_path").and_then(Value::as_str).unwrap()).exists());
    std::fs::remove_dir_all(root).unwrap();
}
