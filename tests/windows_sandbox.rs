#![cfg(windows)]

use rea_offline::universal_sandbox::{Sandbox, SandboxConfig};
use std::path::PathBuf;
use std::process::{Command, Stdio};
use std::time::Duration;

#[test]
fn windows_job_child_process_helper() {
    if std::env::var_os("REA_OFFLINE_JOB_TEST_CHILD").is_some() {
        loop {
            std::thread::sleep(Duration::from_secs(60));
        }
    }

    let Ok(root) = std::env::var("REASANDBOX") else {
        return;
    };
    let child_pid_path = PathBuf::from(root).join("work").join("child.pid");
    let mut child = Command::new(std::env::current_exe().unwrap())
        .args(["--exact", "windows_job_child_process_helper", "--nocapture"])
        .env("REA_OFFLINE_JOB_TEST_CHILD", "1")
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .unwrap();
    std::fs::write(child_pid_path, child.id().to_string()).unwrap();
    let _ = child.wait();

    loop {
        std::thread::sleep(Duration::from_secs(60));
    }
}

#[test]
fn a_timed_out_windows_job_terminates_its_child_processes() {
    let root = std::env::temp_dir().join(format!(
        "rea_sandbox_windows_job_{}",
        rea_offline::util::new_id()
    ));
    let sandbox = Sandbox::prepare(SandboxConfig {
        root: Some(root.clone()),
        timeout: Duration::from_secs(2),
        ..SandboxConfig::default()
    })
    .unwrap();

    let outcome = sandbox
        .run_installer(
            &std::env::current_exe().unwrap(),
            &[
                "--exact".into(),
                "windows_job_child_process_helper".into(),
                "--nocapture".into(),
            ],
        )
        .unwrap();

    assert!(
        outcome.timed_out,
        "the sleeping helper must hit the timeout"
    );
    let child_pid: u32 = std::fs::read_to_string(sandbox.work_dir.join("child.pid"))
        .expect("parent helper wrote the child process id")
        .parse()
        .unwrap();
    assert_process_has_exited(child_pid);
    std::fs::remove_dir_all(&root).unwrap();
    assert!(
        !root.exists(),
        "sandbox cleanup left its root directory behind"
    );
}

fn assert_process_has_exited(pid: u32) {
    use std::os::windows::io::FromRawHandle;

    const SYNCHRONIZE: u32 = 0x0010_0000;
    const WAIT_OBJECT_0: u32 = 0;
    const ERROR_INVALID_PARAMETER: u32 = 87;

    #[link(name = "kernel32")]
    unsafe extern "system" {
        fn OpenProcess(access: u32, inherit_handle: i32, process_id: u32) -> *mut std::ffi::c_void;
        fn WaitForSingleObject(handle: *mut std::ffi::c_void, millis: u32) -> u32;
        fn GetLastError() -> u32;
    }

    let raw = unsafe { OpenProcess(SYNCHRONIZE, 0, pid) };
    if raw.is_null() {
        let error = unsafe { GetLastError() };
        assert_eq!(
            error, ERROR_INVALID_PARAMETER,
            "could not query child process {pid}: Windows error {error}"
        );
        return;
    }
    let handle = unsafe { std::fs::File::from_raw_handle(raw) };
    let wait = unsafe { WaitForSingleObject(raw, 5000) };
    drop(handle);
    assert_eq!(
        wait, WAIT_OBJECT_0,
        "child process {pid} remained alive after its Job Object was terminated"
    );
}
