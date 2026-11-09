//! What a sandbox run could **not contain** — and therefore could not see.
//!
//! A Job Object bounds a process tree; it is not a hypervisor. Two facts
//! decide how much of an install a run can observe, and neither one appears
//! in a file delta:
//!
//! * **privileges** — an elevated (Windows) or root (POSIX) installer can
//!   write wherever it likes. Those writes land *outside* the sandbox tree,
//!   so they are missing from the delta and from every hash in the report;
//! * **the registry** — with no driver, no API redirects arbitrary registry
//!   writes, so an installer's persistence keys are invisible unless the run
//!   managed to mount a hive it could write into.
//!
//! Both are recorded once per run in the envelope's `containment` block, and
//! both are folded into `coverage` when they mean evidence is missing.
//! Neither is a risk finding: a privileged run is not evidence of malice, it
//! is evidence that this report may be partial.

use crate::json::Value;
use crate::registry_sandbox::RegistryStatus;

/// Whether this process holds privileges that let an installer step outside
/// the sandbox: elevated on Windows, root on POSIX. `None` when the platform
/// will not say — which is recorded rather than assumed to be "no".
pub fn elevation() -> Option<bool> {
    #[cfg(windows)]
    {
        win::elevated()
    }
    #[cfg(unix)]
    {
        Some(posix::euid() == 0)
    }
    #[cfg(not(any(windows, unix)))]
    {
        None
    }
}

/// The envelope block: what this run could contain, in one place.
pub fn to_json(elevated: Option<bool>, registry: &RegistryStatus) -> Value {
    let mut map = std::collections::BTreeMap::new();
    map.insert(
        "elevated".to_string(),
        match elevated {
            Some(flag) => Value::Bool(flag),
            None => Value::Null,
        },
    );
    let mut registry_json = std::collections::BTreeMap::new();
    registry_json.insert(
        "mounted".to_string(),
        Value::Bool(matches!(registry, RegistryStatus::Mounted)),
    );
    registry_json.insert("status".to_string(), Value::str(registry.label()));
    if let RegistryStatus::Unavailable(reason) = registry {
        registry_json.insert("message".to_string(), Value::str(reason.clone()));
    }
    map.insert("registry".to_string(), Value::Object(registry_json));
    map.insert(
        "limits".to_string(),
        Value::Array(limits().into_iter().map(Value::str).collect()),
    );
    Value::Object(map)
}

/// What this method can never see, stated once per report so an archived
/// verdict can be read without the manual.
///
/// These are properties of the *method*, not of the run, so they are never
/// coverage issues: a warning that is always true is a warning nobody reads.
/// They are listed here precisely so the per-run gaps above can stay rare
/// enough to mean something.
pub fn limits() -> Vec<String> {
    let mut limits = Vec::new();
    if cfg!(windows) {
        limits.push(
            "registry writes are not captured: redirecting them needs a driver, \
             so installer persistence keys are outside this report"
                .to_string(),
        );
    }
    limits.push(
        "writes outside the sandbox tree are not visible: a Job Object bounds \
         the process tree, not the filesystem"
            .to_string(),
    );
    limits.push(
        "no runtime telemetry: no process, network or syscall monitoring — \
         static analysis plus a filesystem delta only"
            .to_string(),
    );
    limits
}

/// The coverage issues a containment block implies, as `(stage, message)`.
///
/// Shared by the writer (`app`) and the archive validator (`report`) so a
/// saved report cannot claim complete coverage for a run it admits it could
/// not contain.
pub fn issues(block: &Value) -> Vec<(String, String)> {
    let mut out = Vec::new();
    // An archive written before this block existed says nothing about
    // containment, and silence is not a claim that the run was contained.
    if !matches!(block, Value::Object(_)) {
        return out;
    }
    match block.get("elevated") {
        Some(Value::Bool(true)) => out.push((
            "elevated".to_string(),
            "the sandbox ran elevated (administrator/root): the installer could write \
             outside the sandbox tree, and anything written there is missing from this report"
                .to_string(),
        )),
        Some(Value::Bool(false)) => {}
        _ => out.push((
            "elevation-unknown".to_string(),
            "whether this run was elevated could not be determined: if it was, writes \
             outside the sandbox tree are missing from this report"
                .to_string(),
        )),
    }
    let registry_unavailable = block
        .get("registry")
        .and_then(|r| r.get("status"))
        .and_then(Value::as_str)
        == Some("unavailable");
    if registry_unavailable {
        let reason = block
            .get("registry")
            .and_then(|r| r.get("message"))
            .and_then(Value::as_str)
            .unwrap_or("no reason recorded");
        out.push((
            "registry".to_string(),
            format!(
                "the registry hive could not be mounted ({reason}): installer writes to the \
                 registry were neither redirected into the sandbox nor visible in this report"
            ),
        ));
    }
    out
}

#[cfg(unix)]
mod posix {
    // `geteuid` is the one privileged fact we need, and the crate has no
    // dependencies by design: it is a single extern away.
    #[cfg(not(target_os = "macos"))]
    #[link(name = "c")]
    extern "C" {
        fn geteuid() -> u32;
    }

    #[cfg(target_os = "macos")]
    #[link(name = "System")]
    extern "C" {
        fn geteuid() -> u32;
    }

    pub fn euid() -> u32 {
        unsafe { geteuid() }
    }
}

#[cfg(windows)]
mod win {
    type Handle = isize;

    const TOKEN_QUERY: u32 = 0x0008;
    /// `TOKEN_INFORMATION_CLASS::TokenElevation` — "is this token split and
    /// running with the full administrator token?" (Vista and later).
    const TOKEN_ELEVATION: i32 = 20;

    #[repr(C)]
    #[derive(Default)]
    struct TokenElevation {
        token_is_elevated: u32,
    }

    #[link(name = "kernel32")]
    extern "system" {
        fn GetCurrentProcess() -> Handle;
        fn CloseHandle(handle: Handle) -> i32;
    }

    #[link(name = "advapi32")]
    extern "system" {
        fn OpenProcessToken(process: Handle, access: u32, token: *mut Handle) -> i32;
        fn GetTokenInformation(
            token: Handle,
            class: i32,
            information: *mut core::ffi::c_void,
            length: u32,
            return_length: *mut u32,
        ) -> i32;
    }

    /// `None` when the platform will not answer (pre-Vista, or a failed
    /// call): claiming "not elevated" without knowing would be the one
    /// answer that makes a partial report look complete.
    pub fn elevated() -> Option<bool> {
        unsafe {
            let mut token: Handle = 0;
            if OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token) == 0 {
                return None;
            }
            let mut elevation = TokenElevation::default();
            let mut written: u32 = 0;
            let ok = GetTokenInformation(
                token,
                TOKEN_ELEVATION,
                &mut elevation as *mut TokenElevation as *mut core::ffi::c_void,
                std::mem::size_of::<TokenElevation>() as u32,
                &mut written,
            );
            CloseHandle(token);
            if ok == 0 {
                return None;
            }
            Some(elevation.token_is_elevated != 0)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn block(elevated: &str, registry_status: Option<&str>) -> Value {
        let registry = match registry_status {
            None => String::new(),
            Some(status) => format!(
                r#","registry":{{"mounted":{},"status":"{status}"}}"#,
                status == "mounted"
            ),
        };
        crate::json::parse(&format!(r#"{{"elevated":{elevated}{registry}}}"#)).unwrap()
    }

    #[test]
    fn an_unprivileged_run_with_no_registry_to_see_is_not_an_issue() {
        // The common case, and the one that must stay quiet: a standard user
        // on POSIX, where there is no registry to redirect at all.
        assert!(issues(&block("false", Some("not-applicable"))).is_empty());
        // Windows, hive mounted: redirected writes landed in the sandbox.
        assert!(issues(&block("false", Some("mounted"))).is_empty());
    }

    #[test]
    fn an_elevated_run_says_what_it_could_not_hold() {
        let (stage, message) = issues(&block("true", Some("mounted")))
            .pop()
            .expect("an elevated run is a coverage issue");
        assert_eq!(stage, "elevated");
        assert!(message.contains("outside the sandbox tree"), "{message}");
    }

    #[test]
    fn an_unmountable_hive_says_registry_writes_were_never_seen() {
        let issues = issues(&block("false", Some("unavailable")));
        assert_eq!(issues.len(), 1, "{issues:?}");
        assert_eq!(issues[0].0, "registry");
        assert!(
            issues[0].1.contains("neither redirected"),
            "{}",
            issues[0].1
        );
    }

    #[test]
    fn an_unknown_elevation_is_recorded_rather_than_assumed() {
        let (stage, message) = issues(&block("null", Some("not-applicable")))
            .pop()
            .expect("an unknown is not a clean bill of health");
        assert_eq!(stage, "elevation-unknown");
        assert!(message.contains("could not be determined"), "{message}");
        // So is an archive that predates the block: silence is not an answer.
        assert!(issues(&Value::Null).is_empty());
        assert!(issues(&Value::obj(vec![]))
            .iter()
            .any(|(stage, _)| stage == "elevation-unknown"));
    }

    #[test]
    fn the_block_records_the_facts_every_surface_reads() {
        let json = to_json(
            Some(true),
            &RegistryStatus::Unavailable("access denied".into()),
        );
        assert_eq!(json.get("elevated"), Some(&Value::Bool(true)));
        assert_eq!(
            json.get("registry")
                .and_then(|r| r.get("status"))
                .and_then(Value::as_str),
            Some("unavailable")
        );
        assert_eq!(
            json.get("registry")
                .and_then(|r| r.get("message"))
                .and_then(Value::as_str),
            Some("access denied")
        );
        assert!(
            !array(&json, "limits").is_empty(),
            "the method's standing limits travel with the report"
        );
        // An unprivileged run on a machine with no registry is the quiet case.
        let plain = to_json(Some(false), &RegistryStatus::NotApplicable);
        assert_eq!(plain.get("elevated"), Some(&Value::Bool(false)));
        assert_eq!(
            plain
                .get("registry")
                .and_then(|r| r.get("status"))
                .and_then(Value::as_str),
            Some("not-applicable")
        );
        // Re-reading either block reproduces the same verdict.
        assert_eq!(issues(&json).len(), 2, "elevated and unmountable: {json:?}");
        assert!(issues(&plain).is_empty(), "{plain:?}");
    }

    fn array(block: &Value, key: &str) -> Vec<Value> {
        match block.get(key) {
            Some(Value::Array(items)) => items.clone(),
            _ => Vec::new(),
        }
    }

    #[test]
    fn elevation_answers_on_this_platform() {
        // Whatever this machine is, the answer must be a fact we can print,
        // not a silent assumption of "no".
        let elevated = elevation();
        let json = to_json(elevated, &RegistryStatus::Mounted);
        match elevated {
            Some(flag) => assert_eq!(json.get("elevated"), Some(&Value::Bool(flag))),
            None => assert_eq!(json.get("elevated"), Some(&Value::Null)),
        }
    }
}
