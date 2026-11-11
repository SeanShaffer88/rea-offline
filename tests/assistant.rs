//! Mock runner tests exercise the full CLI without a model download or network.
use rea_offline::json::{parse, Value};
use std::path::{Path, PathBuf};
use std::process::Command;

fn root() -> PathBuf {
    let path = std::env::temp_dir().join(format!("rea-assistant-{}", rea_offline::util::new_id()));
    std::fs::create_dir(&path).unwrap();
    path
}
fn cli(root: &Path, args: &[&str]) -> std::process::Output {
    Command::new(env!("CARGO_BIN_EXE_rea-offline")).current_dir(root)
        .args(args).env_remove("REA_PATH").output().unwrap()
}
#[test]
fn cached_details_are_available_offline_and_bad_caches_fail_clearly() {
    let root = root();
    std::fs::write(root.join("details.json"),
        r#"{"cache_version":1,"repository":"morluto/rea","latest_commit":{"sha":"cached"}}"#).unwrap();
    let output = cli(&root, &["upstream", "details.json"]);
    assert!(output.status.success());
    let json = parse(std::str::from_utf8(&output.stdout).unwrap()).unwrap();
    assert_eq!(json.get("repository").and_then(Value::as_str), Some("morluto/rea"));
    std::fs::write(root.join("details.json"), "{}").unwrap();
    let invalid = cli(&root, &["upstream", "details.json"]);
    assert!(!invalid.status.success());
    assert!(String::from_utf8_lossy(&invalid.stderr).contains("not a morluto/rea"));
    std::fs::remove_dir_all(root).unwrap();
}
#[test]
fn ask_requires_local_model_and_runner_not_cloud_credentials() {
    let root = root();
    let output = cli(&root, &["ask", "explain imports"]);
    assert!(!output.status.success());
    assert!(String::from_utf8_lossy(&output.stderr).contains("--model"));
    let invalid = cli(&root, &["ask", "explain", "--model", "missing.gguf", "--llm", "missing.exe"]);
    assert!(!invalid.status.success());
    assert!(String::from_utf8_lossy(&invalid.stderr).contains("runner not found"));
    std::fs::remove_dir_all(root).unwrap();
}
#[cfg(unix)]
fn runner(root: &Path, script: &str) -> PathBuf {
    use std::os::unix::fs::PermissionsExt;
    let path = root.join("local runner.sh");
    std::fs::write(&path, format!("#!/bin/sh\n{script}\n")).unwrap();
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o700)).unwrap();
    std::fs::write(root.join("model.gguf"), b"GGUFmock-only").unwrap();
    path
}
#[cfg(unix)]
#[test]
fn local_model_receives_bounded_evidence_and_cannot_execute_generated_commands() {
    let root = root();
    let executable = runner(&root, r#"
set -eu
prompt=''
offline=0
while [ "$#" -gt 0 ]; do
  case "$1" in
    -f) shift; prompt="$1";;
    --offline) offline=1;;
  esac
  shift
done
test "$offline" = 1
grep -q 'CreateRemoteThread' "$prompt"
grep -q 'request-marker' "$prompt"
cp "$prompt" captured-prompt.txt
printf '%s\n' "$prompt" > prompt-path.txt
printf 'Advisory: inspect the injection imports. Do not execute: echo unsafe > executed.txt'
"#);
    std::fs::write(root.join("sample.txt"), b"CreateRemoteThread").unwrap();
    let output = cli(&root, &["ask", "request-marker", "--model", "model.gguf",
        "--llm", executable.to_str().unwrap(), "--target", "sample.txt", "--output", "answer.json"]);
    assert!(output.status.success(), "{}", String::from_utf8_lossy(&output.stderr));
    assert!(output.stdout.is_empty());
    let result = parse(&std::fs::read_to_string(root.join("answer.json")).unwrap()).unwrap();
    assert_eq!(result.get("mode").and_then(Value::as_str), Some("local-micro-llm"));
    assert_eq!(result.get("advisory"), Some(&Value::Bool(true)));
    assert!(!root.join("executed.txt").exists());
    let prompt = std::fs::read_to_string(root.join("prompt-path.txt")).unwrap();
    assert!(!Path::new(prompt.trim()).exists(), "prompt deleted after success");
    std::fs::remove_dir_all(root).unwrap();
}
#[cfg(unix)]
#[test]
fn runner_failure_deletes_prompt_and_does_not_call_a_cloud_service() {
    let root = root();
    let executable = runner(&root, r#"
while [ "$#" -gt 0 ]; do
  if [ "$1" = "-f" ]; then shift; printf '%s' "$1" > prompt-path.txt; fi
  shift
done
echo 'incompatible local runner' >&2
exit 7
"#);
    let output = cli(&root, &["ask", "explain", "--model", "model.gguf",
        "--llm", executable.to_str().unwrap()]);
    assert!(!output.status.success());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("incompatible local runner"), "{stderr}");
    assert!(stderr.contains("no cloud fallback"), "{stderr}");
    let prompt = std::fs::read_to_string(root.join("prompt-path.txt")).unwrap();
    assert!(!Path::new(&prompt).exists());
    std::fs::remove_dir_all(root).unwrap();
}
#[cfg(unix)]
#[test]
fn invalid_model_and_timeout_fail_before_starting_the_runner() {
    let root = root();
    let executable = runner(&root, "touch started.txt");
    std::fs::write(root.join("model.gguf"), b"not-gguf").unwrap();
    let output = cli(&root, &["ask", "explain", "--model", "model.gguf",
        "--llm", executable.to_str().unwrap()]);
    assert!(!output.status.success());
    assert!(String::from_utf8_lossy(&output.stderr).contains("GGUF"));
    assert!(!root.join("started.txt").exists());
    for timeout in ["0", "1801"] {
        let output = cli(&root, &["ask", "explain", "--model", "model.gguf",
            "--llm", executable.to_str().unwrap(), "--timeout", timeout]);
        assert!(!output.status.success());
        assert!(String::from_utf8_lossy(&output.stderr).contains("between 1 and 1800"));
    }
    std::fs::remove_dir_all(root).unwrap();
}
#[cfg(not(windows))]
#[test]
fn failed_refresh_does_not_overwrite_cache() {
    let root = root();
    std::fs::write(root.join("details.json"), b"previous cache").unwrap();
    let output = cli(&root, &["upstream", "details.json", "--refresh"]);
    assert!(!output.status.success());
    assert_eq!(std::fs::read(root.join("details.json")).unwrap(), b"previous cache");
    std::fs::remove_dir_all(root).unwrap();
}

#[cfg(unix)]
#[test]
fn timeout_kills_local_inference_and_removes_prompt() {
    let root = root();
    let executable = runner(&root, r#"
while [ "$#" -gt 0 ]; do
  if [ "$1" = "-f" ]; then shift; printf '%s' "$1" > prompt-path.txt; fi
  shift
done
while :; do :; done
"#);
    let started = std::time::Instant::now();
    let output = cli(&root, &["ask", "explain", "--model", "model.gguf",
        "--llm", executable.to_str().unwrap(), "--timeout", "1"]);
    assert!(!output.status.success());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("timeout"), "{stderr}");
    assert!(stderr.contains("no cloud fallback"), "{stderr}");
    assert!(started.elapsed().as_secs() < 10);
    let prompt = std::fs::read_to_string(root.join("prompt-path.txt")).unwrap();
    assert!(!Path::new(&prompt).exists());
    std::fs::remove_dir_all(root).unwrap();
}

#[cfg(unix)]
#[test]
fn oversized_output_is_rejected_instead_of_becoming_an_answer() {
    let root = root();
    let executable = runner(&root, "head -c 1100000 /dev/zero | tr '\\000' x");
    let output = cli(&root, &["ask", "explain", "--model", "model.gguf",
        "--llm", executable.to_str().unwrap()]);
    assert!(!output.status.success());
    assert!(String::from_utf8_lossy(&output.stderr).contains("exceeded 1 MiB"));
    assert!(output.stdout.is_empty());
    std::fs::remove_dir_all(root).unwrap();
}

#[cfg(unix)]
#[test]
fn assistant_evidence_never_starts_external_rea() {
    let root = root();
    let executable = runner(&root, "printf 'Local explanation'");
    let rea = root.join("rea.sh");
    std::fs::write(&rea, "#!/bin/sh\ntouch external-rea-started.txt\n").unwrap();
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&rea, std::fs::Permissions::from_mode(0o700)).unwrap();
    }
    std::fs::write(root.join("sample.txt"), b"static local evidence").unwrap();
    let output = Command::new(env!("CARGO_BIN_EXE_rea-offline")).current_dir(&root)
        .env("REA_PATH", &rea).args(["ask", "explain", "--model", "model.gguf",
            "--llm", executable.to_str().unwrap(), "--target", "sample.txt"]).output().unwrap();
    assert!(output.status.success(), "{}", String::from_utf8_lossy(&output.stderr));
    assert!(!root.join("external-rea-started.txt").exists());
    let large = "x".repeat(4097);
    let output = cli(&root, &["ask", &large, "--model", "model.gguf",
        "--llm", executable.to_str().unwrap()]);
    assert!(!output.status.success());
    assert!(String::from_utf8_lossy(&output.stderr).contains("1–4096"));
    std::fs::remove_dir_all(root).unwrap();
}
