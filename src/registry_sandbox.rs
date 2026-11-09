//! Module 3 — Registry Virtualization & Isolation.
//!
//! Windows: mounts an offline hive file (`sandbox_reg.dat`) under
//! `HKEY_USERS\REA_SANDBOX_<id>` via `RegLoadKeyW`, so installer writes
//! aimed at that key land in the sandbox file, not the host registry.
//! `RegUnLoadKeyW` on unmount/drop leaves the host registry pristine.
//!
//! Honest limitation (documented, not hidden): `RegLoadKeyW` requires
//! `SeRestorePrivilege` (normally administrators) and a *valid* hive file,
//! and no API can transparently redirect *arbitrary* registry writes from
//! an unmodified installer without a driver. The sandbox therefore also
//! redirects the installer's per-user environment (`APPDATA`, `TEMP`, …)
//! into the sandbox tree, and this hive carries redirected-user state.
//! Non-Windows builds keep the same lifecycle as a file-backed no-op so
//! the workflow and tests run anywhere.

use crate::Result;
#[cfg(windows)]
use crate::Error;
use std::path::{Path, PathBuf};

/// How much of the registry a run could see.
///
/// The distinction matters for the report: "we mounted the hive" and "there
/// is no registry on this OS" are both fine, while "a registry exists and we
/// could not see into it" means installer registry writes were neither
/// redirected into the sandbox nor visible afterwards.
#[derive(Debug, Clone, PartialEq)]
pub enum RegistryStatus {
    /// The hive was mounted: redirected-user writes land in the sandbox file.
    Mounted,
    /// A registry exists on this OS but the hive would not mount.
    Unavailable(String),
    /// No Windows registry to redirect (POSIX): the per-user environment
    /// redirection still applies, and nothing a registry could have told us
    /// is missing from the report.
    NotApplicable,
}

impl RegistryStatus {
    /// Stable label for the report: the vocabulary the validator also speaks.
    pub fn label(&self) -> &'static str {
        match self {
            RegistryStatus::Mounted => "mounted",
            RegistryStatus::Unavailable(_) => "unavailable",
            RegistryStatus::NotApplicable => "not-applicable",
        }
    }
}

pub struct RegistrySandbox {
    hive_file: PathBuf,
    mount_name: String,
    mounted: bool,
    /// Why the last `mount()` failed, if it did: the report has to be able
    /// to say what it could not see, not just that something went wrong.
    failure: Option<String>,
}

impl RegistrySandbox {
    pub fn new(sandbox_root: &Path, id: &str) -> RegistrySandbox {
        RegistrySandbox {
            hive_file: sandbox_root.join("sandbox_reg.dat"),
            mount_name: format!("REA_SANDBOX_{id}"),
            mounted: false,
            failure: None,
        }
    }

    pub fn hive_file(&self) -> &Path { &self.hive_file }
    pub fn mount_name(&self) -> &str { &self.mount_name }
    pub fn is_mounted(&self) -> bool { self.mounted }

    /// Create the hive backing file if absent, then mount it.
    pub fn mount(&mut self) -> Result<()> {
        if self.mounted { return Ok(()); }
        if !self.hive_file.exists() {
            // Placeholder: replaced by a real hive by tools that seed one
            // (e.g. `reg save`); RegLoadKeyW rejects non-hive files and
            // that error is surfaced to the caller as a warning.
            std::fs::write(&self.hive_file, b"")?;
        }
        #[cfg(windows)]
        {
            if let Err(e) = win::load(&self.mount_name, &self.hive_file) {
                self.failure = Some(e.to_string());
                return Err(e);
            }
            self.mounted = true;
        }
        #[cfg(not(windows))]
        {
            // Nothing to mount: POSIX runs exercise the same lifecycle so the
            // workflow and the tests are portable, but no hive is claimed.
        }
        Ok(())
    }

    /// What this run could see of the registry. Only meaningful after
    /// `mount()` has been attempted — the caller records it either way.
    pub fn status(&self) -> RegistryStatus {
        if !cfg!(windows) {
            return RegistryStatus::NotApplicable;
        }
        match (self.mounted, &self.failure) {
            (true, _) => RegistryStatus::Mounted,
            (false, Some(reason)) => RegistryStatus::Unavailable(reason.clone()),
            (false, None) => RegistryStatus::Unavailable("hive was never mounted".to_string()),
        }
    }

    pub fn unmount(&mut self) -> Result<()> {
        if !self.mounted { return Ok(()); }
        #[cfg(windows)]
        {
            win::unload(&self.mount_name)?;
        }
        self.mounted = false;
        Ok(())
    }
}

impl Drop for RegistrySandbox {
    fn drop(&mut self) {
        // Best-effort: a leaked mounted hive would violate zero-residue.
        let _ = self.unmount();
    }
}

#[cfg(windows)]
mod win {
    use super::*;
    use std::os::windows::ffi::OsStrExt;

    const HKEY_USERS: isize = 0x8000_0003u32 as i32 as isize;

    #[link(name = "advapi32")]
    extern "system" {
        fn RegLoadKeyW(h_key: isize, sub_key: *const u16, file: *const u16) -> i32;
        fn RegUnLoadKeyW(h_key: isize, sub_key: *const u16) -> i32;
    }

    fn wide(s: &std::ffi::OsStr) -> Vec<u16> {
        s.encode_wide().chain(std::iter::once(0)).collect()
    }

    pub fn load(mount_name: &str, hive_file: &Path) -> Result<()> {
        let sub = wide(std::ffi::OsStr::new(mount_name));
        let file = wide(hive_file.as_os_str());
        let rc = unsafe { RegLoadKeyW(HKEY_USERS, sub.as_ptr(), file.as_ptr()) };
        if rc != 0 { return Err(Error::Registry { api: "RegLoadKeyW", code: rc }); }
        Ok(())
    }

    pub fn unload(mount_name: &str) -> Result<()> {
        let sub = wide(std::ffi::OsStr::new(mount_name));
        let rc = unsafe { RegUnLoadKeyW(HKEY_USERS, sub.as_ptr()) };
        if rc != 0 { return Err(Error::Registry { api: "RegUnLoadKeyW", code: rc }); }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_run_without_a_registry_says_so_rather_than_claiming_coverage() {
        let dir = std::env::temp_dir().join(format!("rea_offline_reg_{}", crate::util::new_id()));
        std::fs::create_dir_all(&dir).unwrap();
        let mut registry = RegistrySandbox::new(&dir, "test");
        let mounted = registry.mount();
        if cfg!(windows) {
            // Either the hive took, or the report must be able to say why not.
            match mounted {
                Ok(()) => assert_eq!(registry.status(), RegistryStatus::Mounted),
                Err(_) => assert_eq!(registry.status().label(), "unavailable"),
            }
        } else {
            // POSIX: the lifecycle runs so the workflow is portable, but no
            // hive is claimed and no registry evidence is missing.
            assert!(mounted.is_ok(), "{mounted:?}");
            assert_eq!(registry.status(), RegistryStatus::NotApplicable);
            assert!(!registry.is_mounted());
        }
        // A loaded hive holds its file open: unmount before cleanup, or
        // Windows refuses the delete (ERROR_SHARING_VIOLATION).
        let _ = registry.unmount();
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn a_mounted_hive_releases_its_file_on_unmount() {
        // Windows keeps the hive file open while it is loaded, so an orderly
        // unmount is what makes the zero-residue purge possible at all.
        let dir = std::env::temp_dir().join(format!("rea_offline_reg_{}", crate::util::new_id()));
        std::fs::create_dir_all(&dir).unwrap();
        let mut registry = RegistrySandbox::new(&dir, "test");
        if registry.mount().is_ok() && registry.is_mounted() {
            registry.unmount().unwrap();
            assert!(!registry.is_mounted());
        }
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn an_unmountable_hive_carries_the_reason() {
        // "Something went wrong" is not a report; the reason is what lets an
        // operator decide whether to re-run elevated.
        match RegistryStatus::Unavailable("access denied".into()) {
            RegistryStatus::Unavailable(reason) => assert_eq!(reason, "access denied"),
            other => panic!("expected unavailable, got {other:?}"),
        }
        assert_eq!(RegistryStatus::Mounted.label(), "mounted");
        assert_eq!(RegistryStatus::NotApplicable.label(), "not-applicable");
    }
}
