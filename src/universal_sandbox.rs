//! Module 1 — Universal Sandbox Engine.
//!
//! Windows (7 SP1 → 11, Home included — no Hyper-V / Windows Sandbox):
//! the installer is created *suspended*, assigned to a Job Object with
//! `JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE` + a process-memory ceiling, then
//! resumed. Closing the job handle kills the whole process tree.
//!
//! Non-Windows: same lifecycle via `std::process` with a timeout watchdog
//! (used for development/tests; Job Objects are a Windows facility).
//!
//! Isolation is defence-in-depth, not a hypervisor: Job Object limits,
//! a throwaway directory, and a redirected per-user environment
//! (`TEMP`/`APPDATA`/`USERPROFILE`-style vars point inside the sandbox).

use crate::util::{new_id, temp_root};
use crate::{Error, Result};
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

#[derive(Debug, Clone)]
pub struct SandboxConfig {
    /// Explicit sandbox root; `None` → `%TEMP%\rea_sandbox_<id>`.
    pub root: Option<PathBuf>,
    pub memory_limit_mb: u64,
    /// Job Object active-process ceiling (0 = no explicit limit).
    pub max_processes: u32,
    pub timeout: Duration,
    /// Keep the sandbox directory after the run (still unmounts the hive).
    pub keep: bool,
}

impl Default for SandboxConfig {
    fn default() -> Self {
        SandboxConfig { root: None, memory_limit_mb: 1024, max_processes: 32, timeout: Duration::from_secs(300), keep: false }
    }
}

#[derive(Debug, Clone)]
pub struct RunOutcome {
    pub exit_code: Option<u32>,
    pub timed_out: bool,
    pub duration_ms: u64,
    pub command: String,
    /// Last bytes of the installer's captured stdout/stderr (lossy UTF-8).
    pub stdout_tail: String,
    pub stderr_tail: String,
    pub stdout_bytes: u64,
    pub stderr_bytes: u64,
}

/// Read up to the last 8 KiB of a captured log; returns (tail, total_bytes).
pub fn read_log_tail(path: &Path) -> (String, u64) {
    use std::io::{Read, Seek, SeekFrom};
    let mut file = match std::fs::File::open(path) { Ok(f) => f, Err(_) => return (String::new(), 0) };
    let total = file.metadata().map(|m| m.len()).unwrap_or(0);
    let window = total.min(8192);
    if total > window { let _ = file.seek(SeekFrom::End(-(window as i64))); }
    let mut buf = Vec::with_capacity(window as usize);
    let _ = file.read_to_end(&mut buf);
    (String::from_utf8_lossy(&buf).to_string(), total)
}

pub struct Sandbox {
    pub id: String,
    pub root: PathBuf,
    pub install_dir: PathBuf,
    pub work_dir: PathBuf,
    pub tmp_dir: PathBuf,
    pub config: SandboxConfig,
}

impl Sandbox {
    pub fn prepare(config: SandboxConfig) -> Result<Sandbox> {
        let id = new_id();
        let root = config.root.clone().unwrap_or_else(|| temp_root().join(format!("rea_sandbox_{id}")));
        let install_dir = root.join("install");
        let work_dir = root.join("work");
        let tmp_dir = root.join("tmp");
        for dir in [&root, &install_dir, &work_dir, &tmp_dir] {
            std::fs::create_dir_all(dir)?;
        }
        Ok(Sandbox { id, root, install_dir, work_dir, tmp_dir, config })
    }

    /// Environment that keeps the child's scratch/profile writes inside
    /// the sandbox tree on both Windows and POSIX.
    fn isolated_env(&self) -> Vec<(String, String)> {
        let s = |p: &Path| p.to_string_lossy().to_string();
        vec![
            ("TEMP".into(), s(&self.tmp_dir)),
            ("TMP".into(), s(&self.tmp_dir)),
            ("TMPDIR".into(), s(&self.tmp_dir)),
            ("REASANDBOX".into(), s(&self.root)),
            ("REASANDBOX_INSTALL".into(), s(&self.install_dir)),
            // Per-user profile redirection (best effort; apps that honor it
            // never touch the real profile).
            ("APPDATA".into(), s(&self.root.join("AppData").join("Roaming"))),
            ("LOCALAPPDATA".into(), s(&self.root.join("AppData").join("Local"))),
            ("USERPROFILE".into(), s(&self.root)),
            ("HOME".into(), s(&self.root)),
        ]
    }

    /// Validate + build the (program, args) pair for the platform.
    fn launch_spec(&self, installer: &Path, args: &[String]) -> Result<(PathBuf, Vec<String>)> {
        if !installer.exists() { return Err(Error::NotFound(installer.to_path_buf())); }
        #[cfg(windows)]
        {
            match crate::util::extension_lower(installer).as_str() {
                "exe" => return Ok((installer.to_path_buf(), args.to_vec())),
                "msi" => {
                    let mut a = vec![
                        "/i".to_string(), installer.to_string_lossy().to_string(),
                        "/qn".to_string(), "/norestart".to_string(),
                        format!("TARGETDIR={}", self.install_dir.to_string_lossy()),
                    ];
                    a.extend(args.iter().cloned());
                    return Ok((PathBuf::from("msiexec.exe"), a));
                }
                other => return Err(Error::InvalidInput(format!(
                    "unsupported installer type '.{other}' (expected .exe or .msi)"))),
            }
        }
        #[cfg(not(windows))]
        {
            let _ = self;
            // `Command::new("dropper.sh")` is looked up on PATH, not in the
            // working directory, so a relative installer that plainly exists
            // would fail to spawn. Resolve it first (Windows already searches
            // the current directory), and record the absolute path as evidence.
            let program = std::fs::canonicalize(installer).unwrap_or_else(|_| installer.to_path_buf());
            Ok((program, args.to_vec()))
        }
    }

    pub fn run_installer(&self, installer: &Path, args: &[String]) -> Result<RunOutcome> {
        let (program, argv) = self.launch_spec(installer, args)?;
        let started = Instant::now();
        let stdout_log = self.work_dir.join("installer.stdout.log");
        let stderr_log = self.work_dir.join("installer.stderr.log");
        #[cfg(windows)]
        let mut outcome = win::run(&program, &argv, &self.work_dir, &self.isolated_env(),
                               self.config.memory_limit_mb, self.config.max_processes,
                               self.config.timeout, &stdout_log, &stderr_log)?;
        #[cfg(not(windows))]
        let mut outcome = portable::run(&program, &argv, &self.work_dir, &self.isolated_env(),
                                        self.config.timeout, &stdout_log, &stderr_log)?;
        let (stdout_tail, stdout_bytes) = read_log_tail(&stdout_log);
        let (stderr_tail, stderr_bytes) = read_log_tail(&stderr_log);
        outcome.stdout_tail = stdout_tail;
        outcome.stderr_tail = stderr_tail;
        outcome.stdout_bytes = stdout_bytes;
        outcome.stderr_bytes = stderr_bytes;
        Ok(RunOutcome {
            duration_ms: started.elapsed().as_millis() as u64,
            command: format!("{} {}", program.display(),
                             argv.iter().map(|a| format!("\"{a}\"")).collect::<Vec<_>>().join(" ")),
            ..outcome
        })
    }
}

#[cfg(not(windows))]
mod portable {
    use super::*;
    pub fn run(program: &Path, argv: &[String], cwd: &Path,
               env: &[(String, String)], timeout: Duration,
               stdout_log: &Path, stderr_log: &Path) -> Result<RunOutcome> {
        let stdout_file = std::fs::File::create(stdout_log)?;
        let stderr_file = std::fs::File::create(stderr_log)?;
        let mut cmd = std::process::Command::new(program);
        cmd.args(argv).current_dir(cwd)
            .stdin(std::process::Stdio::null())
            .stdout(std::process::Stdio::from(stdout_file))
            .stderr(std::process::Stdio::from(stderr_file));
        for (k, v) in env { cmd.env(k, v); }
        let mut child = cmd.spawn().map_err(|e| Error::Process(format!("spawn {}: {e}", program.display())))?;
        let deadline = Instant::now() + timeout;
        loop {
            match child.try_wait()? {
                Some(status) => return Ok(RunOutcome {
                    exit_code: status.code().map(|c| c as u32),
                    timed_out: false, duration_ms: 0, command: String::new(),
                    stdout_tail: String::new(), stderr_tail: String::new(),
                    stdout_bytes: 0, stderr_bytes: 0,
                }),
                None => {
                    if Instant::now() >= deadline {
                        let _ = child.kill();
                        let _ = child.wait();
                        return Ok(RunOutcome { exit_code: None, timed_out: true, duration_ms: 0, command: String::new(),
                            stdout_tail: String::new(), stderr_tail: String::new(), stdout_bytes: 0, stderr_bytes: 0 });
                    }
                    std::thread::sleep(Duration::from_millis(50));
                }
            }
        }
    }
}

#[cfg(windows)]
mod win {
    use super::*;
    use std::os::windows::ffi::OsStrExt;

    type Handle = isize;
    const NULL_HANDLE: Handle = 0;
    const CREATE_SUSPENDED: u32 = 0x0000_0004;
    const JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE: u32 = 0x0000_2000;
    const JOB_OBJECT_LIMIT_PROCESS_MEMORY: u32 = 0x0000_0100;
    const JOB_OBJECT_LIMIT_ACTIVE_PROCESS: u32 = 0x0000_0008;
    const STARTF_USE_STDHANDLES: u32 = 0x0000_0100;
    const CREATE_ALWAYS: u32 = 2;
    const FILE_SHARE_READ: u32 = 0x0000_0001;
    const FILE_SHARE_WRITE: u32 = 0x0000_0002;
    const JOB_OBJECT_EXTENDED_LIMIT_INFORMATION: i32 = 9;
    const WAIT_OBJECT_0: u32 = 0;
    const WAIT_TIMEOUT: u32 = 0x0000_0102;

    #[repr(C)]
    #[derive(Default)]
    struct JobObjectBasicLimitInformation {
        per_process_user_time_limit: i64,
        per_job_user_time_limit: i64,
        limit_flags: u32,
        minimum_working_set_size: usize,
        maximum_working_set_size: usize,
        active_process_limit: u32,
        affinity: usize,
        priority_class: u32,
        scheduling_class: u32,
    }
    #[repr(C)]
    #[derive(Default)]
    struct IoCounters {
        read_operation_count: u64, write_operation_count: u64, other_operation_count: u64,
        read_transfer_count: u64, write_transfer_count: u64, other_transfer_count: u64,
    }
    #[repr(C)]
    #[derive(Default)]
    struct JobObjectExtendedLimitInformation {
        basic_limit_information: JobObjectBasicLimitInformation,
        io_info: IoCounters,
        process_memory_limit: usize,
        job_memory_limit: usize,
        peak_process_memory_used: usize,
        peak_job_memory_used: usize,
    }
    #[repr(C)]
    struct SecurityAttributes {
        length: u32,
        security_descriptor: *mut core::ffi::c_void,
        inherit_handle: i32,
    }

    #[repr(C)]
    #[derive(Default)]
    struct StartupInfoW {
        cb: u32, reserved: *mut u16, desktop: *mut u16, title: *mut u16,
        x: u32, y: u32, x_size: u32, y_size: u32, x_count_chars: u32, y_count_chars: u32,
        fill_attribute: u32, flags: u32, show_window: u16, cb_reserved2: u16,
        lp_reserved2: *mut u8, std_input: Handle, std_output: Handle, std_error: Handle,
    }
    #[repr(C)]
    #[derive(Default)]
    struct ProcessInformation {
        process: Handle, thread: Handle, process_id: u32, thread_id: u32,
    }

    #[link(name = "kernel32")]
    extern "system" {
        fn CreateJobObjectW(attrs: *mut core::ffi::c_void, name: *const u16) -> Handle;
        fn SetInformationJobObject(job: Handle, class: i32, info: *const core::ffi::c_void, len: u32) -> i32;
        fn AssignProcessToJobObject(job: Handle, process: Handle) -> i32;
        fn TerminateJobObject(job: Handle, exit_code: u32) -> i32;
        fn CreateFileW(name: *const u16, access: u32, share: u32,
                       attrs: *const SecurityAttributes, disposition: u32,
                       flags: u32, template: Handle) -> Handle;
        fn CreateProcessW(app: *const u16, cmdline: *mut u16, proc_attrs: *mut core::ffi::c_void,
                          thread_attrs: *mut core::ffi::c_void, inherit: i32, flags: u32,
                          env: *const core::ffi::c_void, cwd: *const u16,
                          startup: *const StartupInfoW, info: *mut ProcessInformation) -> i32;
        fn ResumeThread(thread: Handle) -> u32;
        fn WaitForSingleObject(handle: Handle, millis: u32) -> u32;
        fn GetExitCodeProcess(process: Handle, code: *mut u32) -> i32;
        fn CloseHandle(handle: Handle) -> i32;
        fn GetLastError() -> u32;
    }

    fn wide(s: &std::ffi::OsStr) -> Vec<u16> { s.encode_wide().chain(std::iter::once(0)).collect() }
    fn quote(arg: &str) -> String {
        if arg.chars().any(|c| c.is_whitespace() || c == '"') { format!("\"{}\"", arg.replace('"', "\\\"")) }
        else { arg.to_string() }
    }
    fn last_err(api: &'static str) -> Error {
        Error::WindowsApi { api, code: unsafe { GetLastError() } }
    }

    /// RAII handle so the job (and KILL_ON_JOB_CLOSE) fires on every path.
    struct HandleGuard(Handle);
    impl Drop for HandleGuard {
        fn drop(&mut self) { if self.0 != NULL_HANDLE { unsafe { CloseHandle(self.0); } } }
    }

    pub fn run(program: &Path, argv: &[String], cwd: &Path, env: &[(String, String)],
               memory_limit_mb: u64, max_processes: u32, timeout: Duration,
               stdout_log: &Path, stderr_log: &Path) -> Result<RunOutcome> {
        unsafe {
            // 1) Job Object with kill-on-close + memory ceiling.
            let job = HandleGuard(CreateJobObjectW(std::ptr::null_mut(), std::ptr::null()));
            if job.0 == NULL_HANDLE { return Err(last_err("CreateJobObjectW")); }
            let mut limits = JobObjectExtendedLimitInformation::default();
            limits.basic_limit_information.limit_flags =
                JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE | JOB_OBJECT_LIMIT_PROCESS_MEMORY;
            if max_processes > 0 {
                limits.basic_limit_information.limit_flags |= JOB_OBJECT_LIMIT_ACTIVE_PROCESS;
                limits.basic_limit_information.active_process_limit = max_processes;
            }
            limits.process_memory_limit = (memory_limit_mb as usize).saturating_mul(1024 * 1024);
            if SetInformationJobObject(job.0, JOB_OBJECT_EXTENDED_LIMIT_INFORMATION,
                    &limits as *const _ as *const core::ffi::c_void,
                    std::mem::size_of::<JobObjectExtendedLimitInformation>() as u32) == 0 {
                return Err(last_err("SetInformationJobObject"));
            }

            // 2) Isolated environment block (double-NUL terminated UTF-16).
            let mut env_block: Vec<u16> = Vec::new();
            let mut merged: Vec<(String, String)> = std::env::vars().collect();
            for (k, v) in env {
                merged.retain(|(ek, _)| !ek.eq_ignore_ascii_case(k));
                merged.push((k.clone(), v.clone()));
            }
            for (k, v) in &merged {
                env_block.extend(std::ffi::OsStr::new(&format!("{k}={v}")).encode_wide());
                env_block.push(0);
            }
            env_block.push(0);

            // 3) Create suspended → assign to job → resume.
            let mut cmdline_str = quote(&program.to_string_lossy());
            for a in argv { cmdline_str.push(' '); cmdline_str.push_str(&quote(a)); }
            let mut cmdline = wide(std::ffi::OsStr::new(&cmdline_str));
            let app = wide(program.as_os_str());
            let cwd_w = wide(cwd.as_os_str());
            let mut startup = StartupInfoW::default();
            startup.cb = std::mem::size_of::<StartupInfoW>() as u32;
            // Capture installer stdout/stderr to log files via inheritable
            // handles (STARTF_USESTDHANDLES); stdin stays null.
            const GENERIC_WRITE: u32 = 0x4000_0000;
            let sa = SecurityAttributes {
                length: std::mem::size_of::<SecurityAttributes>() as u32,
                security_descriptor: std::ptr::null_mut(),
                inherit_handle: 1,
            };
            let stdout_h = HandleGuard(CreateFileW(wide(stdout_log.as_os_str()).as_ptr(),
                GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE, &sa, CREATE_ALWAYS, 0, NULL_HANDLE));
            let stderr_h = HandleGuard(CreateFileW(wide(stderr_log.as_os_str()).as_ptr(),
                GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE, &sa, CREATE_ALWAYS, 0, NULL_HANDLE));
            if stdout_h.0 == -1 || stderr_h.0 == -1 { return Err(last_err("CreateFileW")); }
            startup.flags = STARTF_USE_STDHANDLES;
            startup.std_output = stdout_h.0;
            startup.std_error = stderr_h.0;
            let mut proc_info = ProcessInformation::default();
            const CREATE_UNICODE_ENVIRONMENT: u32 = 0x0000_0400;
            if CreateProcessW(app.as_ptr(), cmdline.as_mut_ptr(), std::ptr::null_mut(),
                    std::ptr::null_mut(), 1, CREATE_SUSPENDED | CREATE_UNICODE_ENVIRONMENT,
                    env_block.as_ptr() as *const core::ffi::c_void, cwd_w.as_ptr(),
                    &startup, &mut proc_info) == 0 {
                return Err(last_err("CreateProcessW"));
            }
            let process = HandleGuard(proc_info.process);
            let thread = HandleGuard(proc_info.thread);
            if AssignProcessToJobObject(job.0, process.0) == 0 {
                return Err(last_err("AssignProcessToJobObject"));
            }
            if ResumeThread(thread.0) == u32::MAX { return Err(last_err("ResumeThread")); }

            // 4) Wait with timeout; on timeout kill the whole job tree.
            let millis = timeout.as_millis().min(u32::MAX as u128) as u32;
            let wait = WaitForSingleObject(process.0, millis);
            let mut outcome = RunOutcome { exit_code: None, timed_out: false, duration_ms: 0, command: String::new(),
                stdout_tail: String::new(), stderr_tail: String::new(), stdout_bytes: 0, stderr_bytes: 0 };
            if wait == WAIT_TIMEOUT {
                outcome.timed_out = true;
                TerminateJobObject(job.0, 1);
                WaitForSingleObject(process.0, 10_000);
            } else if wait != WAIT_OBJECT_0 {
                return Err(last_err("WaitForSingleObject"));
            }
            let mut code: u32 = 0;
            if GetExitCodeProcess(process.0, &mut code) != 0 { outcome.exit_code = Some(code); }
            Ok(outcome)
            // Guards close here: closing the job handle kills any stragglers.
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn log_tail_reads_last_bytes_and_total() {
        let dir = std::env::temp_dir().join(format!("rea_offline_tail_{}", new_id()));
        std::fs::create_dir_all(&dir).unwrap();
        let log = dir.join("big.log");
        std::fs::write(&log, vec![b'x'; 10_000]).unwrap();
        let (tail, total) = read_log_tail(&log);
        assert_eq!(total, 10_000);
        assert_eq!(tail.len(), 8192);
        let (empty, zero) = read_log_tail(&dir.join("missing.log"));
        assert!(empty.is_empty() && zero == 0);
        std::fs::remove_dir_all(&dir).unwrap();
    }
}
