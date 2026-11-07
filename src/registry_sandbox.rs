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

use crate::{Error, Result};
use std::path::{Path, PathBuf};

pub struct RegistrySandbox {
    hive_file: PathBuf,
    mount_name: String,
    mounted: bool,
}

impl RegistrySandbox {
    pub fn new(sandbox_root: &Path, id: &str) -> RegistrySandbox {
        RegistrySandbox {
            hive_file: sandbox_root.join("sandbox_reg.dat"),
            mount_name: format!("REA_SANDBOX_{id}"),
            mounted: false,
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
            win::load(&self.mount_name, &self.hive_file)?;
        }
        self.mounted = true;
        Ok(())
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
