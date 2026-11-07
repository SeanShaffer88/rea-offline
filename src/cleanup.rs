//! Module 5 — Cleanup & Purge Controller.
//!
//! Unmounts the temporary hive, releases handles, wipes the sandbox tree
//! and *verifies* zero residue. Guards against deleting arbitrary paths:
//! only directories named `rea_sandbox_*` (or an explicit `force`) go away.

use crate::registry_sandbox::RegistrySandbox;
use crate::{Error, Result};
use std::path::Path;

pub struct CleanupController;

pub struct PurgeReport {
    pub path: String,
    pub removed: bool,
    pub verified_zero_residue: bool,
}

impl CleanupController {
    pub fn purge_sandbox(sandbox_root: &Path, registry: Option<&mut RegistrySandbox>, force: bool) -> Result<PurgeReport> {
        if let Some(reg) = registry {
            reg.unmount()?; // hive must go before its file can be deleted
        }
        Self::purge_dir(sandbox_root, force)
    }

    pub fn purge_dir(path: &Path, force: bool) -> Result<PurgeReport> {
        if !path.exists() {
            return Ok(PurgeReport { path: path.display().to_string(), removed: false, verified_zero_residue: true });
        }
        if !force {
            let name = path.file_name().map(|n| n.to_string_lossy().to_string()).unwrap_or_default();
            let parent_is_temp = path.parent().map(|p| p == std::env::temp_dir()).unwrap_or(false);
            if !(name.starts_with("rea_sandbox_") && parent_is_temp) && !name.starts_with("rea_sandbox_") {
                return Err(Error::Refused(format!(
                    "'{}' is not a rea_sandbox_* directory; pass --force to purge it anyway",
                    path.display())));
            }
            if path.parent().is_none() || path == Path::new("/") {
                return Err(Error::Refused("refusing to purge a filesystem root".into()));
            }
        }
        // Retry a few times: antivirus / the just-exited installer may
        // briefly hold handles on Windows.
        let mut last_err: Option<std::io::Error> = None;
        for attempt in 0..5 {
            match std::fs::remove_dir_all(path) {
                Ok(()) => {
                    return Ok(PurgeReport {
                        path: path.display().to_string(),
                        removed: true,
                        verified_zero_residue: !path.exists(),
                    });
                }
                Err(e) => {
                    last_err = Some(e);
                    if attempt < 4 { std::thread::sleep(std::time::Duration::from_millis(200 * (attempt + 1))); }
                }
            }
        }
        Err(Error::Io(last_err.unwrap()))
    }

    pub fn verify_zero_residue(path: &Path) -> bool { !path.exists() }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn refuses_arbitrary_dirs_without_force() {
        let dir = std::env::temp_dir().join(format!("some_user_dir_{}", crate::util::new_id()));
        std::fs::create_dir_all(&dir).unwrap();
        assert!(CleanupController::purge_dir(&dir, false).is_err());
        assert!(dir.exists(), "guard must not delete the directory");
        assert!(CleanupController::purge_dir(&dir, true).unwrap().verified_zero_residue);
    }
}
