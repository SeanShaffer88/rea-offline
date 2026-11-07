use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

pub fn unix_millis() -> u64 {
    SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_millis() as u64).unwrap_or(0)
}
pub fn unix_secs() -> u64 {
    SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0)
}

/// Short unique id without external crates (time + pid, hashed).
pub fn new_id() -> String {
    let seed = format!("{}-{}-{}", unix_millis(), std::process::id(), unix_millis() ^ 0x9e37_79b9);
    crate::sha256::hash_bytes(seed.as_bytes())[..16].to_string()
}

/// Sandbox root: `%TEMP%` on Windows / `$TMPDIR` (else `/tmp`) elsewhere.
pub fn temp_root() -> PathBuf {
    std::env::temp_dir()
}

pub fn path_to_slash_string(path: &Path) -> String {
    path.to_string_lossy().replace('\\', "/")
}

pub fn extension_lower(path: &Path) -> String {
    path.extension().map(|e| e.to_string_lossy().to_lowercase()).unwrap_or_default()
}
