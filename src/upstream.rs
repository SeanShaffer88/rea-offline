//! Explicit repository-details refresh. No remote code is installed or run.
//! Normal scans, model inference and cached reads never call this transport.
use crate::json::Value;
use crate::{Error, Result};
use std::path::Path;

pub const REPOSITORY: &str = "morluto/rea";
pub const HOST: &str = "api.github.com";
const ROOT: &str = "/repos/morluto/rea";
const MAX_RESPONSE: usize = 2 * 1024 * 1024;
const MAX_CACHE: u64 = 8 * 1024 * 1024;

fn invalid(message: &str) -> Error { Error::InvalidInput(message.into()) }
fn valid_sha(sha: &str) -> bool {
    sha.len() == 40 && sha.bytes().all(|b| b.is_ascii_hexdigit())
}
fn allowed_path(path: &str) -> bool {
    matches!(path, ROOT | "/repos/morluto/rea/commits?per_page=1" |
        "/repos/morluto/rea/releases/latest")
        || path.strip_prefix("/repos/morluto/rea/readme?ref=").is_some_and(valid_sha)
}
fn parse_reply(status: u32, body: &[u8], optional: bool) -> Result<Value> {
    if body.len() > MAX_RESPONSE { return Err(invalid("GitHub response exceeded 2 MiB")); }
    if status == 404 && optional { return Ok(Value::Null); }
    if status != 200 {
        return Err(Error::Process(format!(
            "GitHub returned HTTP {status}; no redirects, retries or alternate sources were followed"
        )));
    }
    let text = std::str::from_utf8(body).map_err(|_| invalid("GitHub returned non-UTF-8 JSON"))?;
    crate::json::parse(text)
}

fn collect(mut get: impl FnMut(&str) -> Result<(u32, Vec<u8>)>) -> Result<Value> {
    let mut request = |path: &str, optional| {
        if !allowed_path(path) { return Err(invalid("upstream endpoint is not allowlisted")); }
        let (status, body) = get(path)?;
        parse_reply(status, &body, optional)
    };
    let metadata = request(ROOT, false)?;
    if metadata.get("full_name").and_then(Value::as_str) != Some(REPOSITORY) {
        return Err(invalid("GitHub repository identity did not match morluto/rea"));
    }
    let commits = request("/repos/morluto/rea/commits?per_page=1", false)?;
    let latest = match commits {
        Value::Array(mut entries) if !entries.is_empty() => entries.remove(0),
        _ => return Err(invalid("GitHub returned no latest commit")),
    };
    let sha = latest.get("sha").and_then(Value::as_str)
        .filter(|s| valid_sha(s)).ok_or_else(|| invalid("invalid upstream commit SHA"))?;
    // Do not follow download_url, README links, images or release assets.
    let readme = request(&format!("{ROOT}/readme?ref={sha}"), false)?;
    let release = request("/repos/morluto/rea/releases/latest", true)?;
    Ok(Value::obj(vec![
        ("cache_version", Value::num(1)),
        ("repository", Value::str(REPOSITORY)),
        ("fetched_unix", Value::num(crate::util::unix_secs())),
        ("metadata", metadata), ("latest_commit", latest),
        ("readme", readme), ("latest_release", release),
    ]))
}

/// Cached JSON is data only: reading it never opens a network connection.
pub fn load(path: &Path) -> Result<Value> {
    use std::io::Read;
    let mut bytes = Vec::new();
    std::fs::File::open(path)?.take(MAX_CACHE + 1).read_to_end(&mut bytes)?;
    if bytes.len() as u64 > MAX_CACHE { return Err(invalid("upstream cache exceeded 8 MiB")); }
    let text = std::str::from_utf8(&bytes).map_err(|_| invalid("upstream cache is not UTF-8"))?;
    let value = crate::json::parse(text)?;
    if value.get("cache_version") != Some(&Value::num(1))
        || value.get("repository").and_then(Value::as_str) != Some(REPOSITORY) {
        return Err(invalid("not a morluto/rea details cache"));
    }
    Ok(value)
}

fn save(path: &Path, value: &Value) -> Result<()> {
    use std::io::Write;
    let name = path.file_name().ok_or_else(|| invalid("cache needs a filename"))?;
    let staging = path.with_file_name(format!("{}.{}.tmp", name.to_string_lossy(), crate::util::new_id()));
    let result = (|| -> Result<()> {
        let mut file = std::fs::OpenOptions::new().write(true).create_new(true).open(&staging)?;
        let text = value.to_string_pretty();
        if text.len() as u64 > MAX_CACHE { return Err(invalid("upstream cache exceeded 8 MiB")); }
        file.write_all(text.as_bytes())?;
        file.sync_all()?;
        drop(file);
        replace(&staging, path)?;
        Ok(())
    })();
    let _ = std::fs::remove_file(staging);
    result
}

#[cfg(not(windows))]
fn replace(from: &Path, to: &Path) -> Result<()> { Ok(std::fs::rename(from, to)?) }

#[cfg(windows)]
fn replace(from: &Path, to: &Path) -> Result<()> {
    use std::os::windows::ffi::OsStrExt;
    #[link(name = "kernel32")]
    extern "system" { fn MoveFileExW(from: *const u16, to: *const u16, flags: u32) -> i32; }
    let from: Vec<u16> = from.as_os_str().encode_wide().chain(Some(0)).collect();
    let to: Vec<u16> = to.as_os_str().encode_wide().chain(Some(0)).collect();
    if unsafe { MoveFileExW(from.as_ptr(), to.as_ptr(), 1 | 8) } == 0 {
        return Err(std::io::Error::last_os_error().into());
    }
    Ok(())
}

/// Only the explicit `upstream <cache> --refresh` command calls this.
pub fn refresh(path: &Path) -> Result<Value> {
    let value = collect(http_get)?;
    save(path, &value)?;
    Ok(value)
}

#[cfg(not(all(windows, target_arch = "x86_64")))]
fn http_get(_: &str) -> Result<(u32, Vec<u8>)> {
    Err(invalid("online refresh is supported on Windows 11 x64; cached details remain available offline"))
}
#[cfg(all(windows, target_arch = "x86_64"))]
fn http_get(path: &str) -> Result<(u32, Vec<u8>)> { winhttp::get(path) }

#[cfg(all(windows, target_arch = "x86_64"))]
mod winhttp {
    use super::*;
    use std::ffi::c_void;
    type Handle = *mut c_void;
    #[link(name = "winhttp")]
    extern "system" {
        fn WinHttpOpen(agent: *const u16, access: u32, proxy: *const u16, bypass: *const u16, flags: u32) -> Handle;
        fn WinHttpSetTimeouts(h: Handle, resolve: i32, connect: i32, send: i32, receive: i32) -> i32;
        fn WinHttpConnect(h: Handle, host: *const u16, port: u16, reserved: u32) -> Handle;
        fn WinHttpOpenRequest(h: Handle, verb: *const u16, path: *const u16, version: *const u16,
            referer: *const u16, accept: *const *const u16, flags: u32) -> Handle;
        fn WinHttpSetOption(h: Handle, option: u32, buffer: *const c_void, length: u32) -> i32;
        fn WinHttpSendRequest(h: Handle, headers: *const u16, length: u32, data: *const c_void,
            data_length: u32, total: u32, context: usize) -> i32;
        fn WinHttpReceiveResponse(h: Handle, reserved: *mut c_void) -> i32;
        fn WinHttpQueryHeaders(h: Handle, info: u32, name: *const u16, buffer: *mut c_void,
            length: *mut u32, index: *mut u32) -> i32;
        fn WinHttpReadData(h: Handle, buffer: *mut c_void, count: u32, read: *mut u32) -> i32;
        fn WinHttpCloseHandle(h: Handle) -> i32;
    }
    struct Owned(Handle);
    impl Drop for Owned { fn drop(&mut self) { unsafe { WinHttpCloseHandle(self.0); } } }
    fn wide(s: &str) -> Vec<u16> { s.encode_utf16().chain(Some(0)).collect() }
    fn check(ok: i32) -> Result<()> {
        if ok == 0 { Err(std::io::Error::last_os_error().into()) } else { Ok(()) }
    }
    fn own(h: Handle) -> Result<Owned> {
        if h.is_null() { Err(std::io::Error::last_os_error().into()) } else { Ok(Owned(h)) }
    }
    pub fn get(path: &str) -> Result<(u32, Vec<u8>)> {
        if !allowed_path(path) { return Err(invalid("upstream endpoint is not allowlisted")); }
        let null = std::ptr::null();
        let agent = wide("rea-offline/repository-details");
        let host = wide(HOST);
        let verb = wide("GET");
        let path = wide(path);
        let headers = wide("Accept: application/vnd.github+json\r\nX-GitHub-Api-Version: 2022-11-28\r\n");
        unsafe {
            // Direct TLS, no proxy discovery, no credentials or uploaded data.
            let session = own(WinHttpOpen(agent.as_ptr(), 1, null, null, 0))?;
            check(WinHttpSetTimeouts(session.0, 5000, 5000, 5000, 15000))?;
            let tls: u32 = 0x800 | 0x2000; // TLS 1.2 / 1.3.
            check(WinHttpSetOption(session.0, 84, &tls as *const _ as _, 4))?;
            let connection = own(WinHttpConnect(session.0, host.as_ptr(), 443, 0))?;
            let request = own(WinHttpOpenRequest(connection.0, verb.as_ptr(), path.as_ptr(),
                null, null, std::ptr::null(), 0x00800000))?;
            let disabled: u32 = 1 | 2 | 4; // cookies, redirects, authentication.
            check(WinHttpSetOption(request.0, 63, &disabled as *const _ as _, 4))?;
            check(WinHttpSendRequest(request.0, headers.as_ptr(), u32::MAX, std::ptr::null(), 0, 0, 0))?;
            check(WinHttpReceiveResponse(request.0, std::ptr::null_mut()))?;
            let mut status = 0u32;
            let mut size = 4u32;
            check(WinHttpQueryHeaders(request.0, 19 | 0x20000000, null,
                &mut status as *mut _ as _, &mut size, std::ptr::null_mut()))?;
            if status != 200 { return Ok((status, Vec::new())); }
            let started = std::time::Instant::now();
            let mut body = Vec::new();
            loop {
                if started.elapsed().as_secs() >= 30 { return Err(invalid("GitHub response deadline exceeded")); }
                let mut chunk = [0u8; 8192];
                let mut count = 0;
                check(WinHttpReadData(request.0, chunk.as_mut_ptr() as _, chunk.len() as u32, &mut count))?;
                if count == 0 { break; }
                if body.len() + count as usize > MAX_RESPONSE {
                    return Err(invalid("GitHub response exceeded 2 MiB"));
                }
                body.extend_from_slice(&chunk[..count as usize]);
            }
            Ok((status, body))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn fixture(path: &str) -> Result<(u32, Vec<u8>)> {
        let body = match path {
            ROOT => r#"{"full_name":"morluto/rea","html_url":"https://untrusted.invalid"}"#.into(),
            "/repos/morluto/rea/commits?per_page=1" =>
                format!(r#"[{{"sha":"{}"}}]"#, "a".repeat(40)),
            "/repos/morluto/rea/releases/latest" => return Ok((404, vec![])),
            _ if allowed_path(path) => r#"{"content":"cached text","download_url":"https://untrusted.invalid"}"#.into(),
            _ => panic!("unexpected endpoint"),
        };
        Ok((200, body.into_bytes()))
    }
    #[test]
    fn requests_only_fixed_details_and_never_follows_embedded_links() {
        let mut paths = Vec::new();
        let details = collect(|path| { paths.push(path.to_string()); fixture(path) }).unwrap();
        assert_eq!(paths.len(), 4);
        assert!(paths.iter().all(|p| allowed_path(p)));
        assert_eq!(paths[2], format!("{ROOT}/readme?ref={}", "a".repeat(40)));
        assert_eq!(details.get("latest_release"), Some(&Value::Null));
    }
    #[test]
    fn rejects_redirects_errors_oversized_and_invalid_responses() {
        for status in [301, 302, 307, 308, 401, 403, 429, 500] {
            let mut calls = 0;
            assert!(collect(|_| { calls += 1; Ok((status, vec![])) }).is_err());
            assert_eq!(calls, 1, "no retries or fallback hosts");
        }
        assert!(parse_reply(200, &vec![b' '; MAX_RESPONSE + 1], false).is_err());
        assert!(parse_reply(200, b"not-json", false).is_err());
        assert!(collect(|_| Ok((200, br#"{"full_name":"other/repo"}"#.to_vec()))).is_err());
        assert!(collect(|path| if path.contains("commits") {
            Ok((200, br#"[{"sha":"../../other/repo"}]"#.to_vec()))
        } else { fixture(path) }).is_err());
    }
    #[test]
    fn arbitrary_hosts_repositories_and_paths_are_not_allowed() {
        for path in ["https://api.github.com/repos/morluto/rea", "/repos/other/rea",
            "/repos/morluto/rea/contents/private", "/repos/morluto/rea/../other",
            "/repos/morluto/rea/readme?ref=main", "/repos/morluto/rea?redirect=evil"] {
            assert!(!allowed_path(path), "{path}");
        }
    }
    #[test]
    fn cached_read_and_atomic_replacement_work_without_transport() {
        let root = std::env::temp_dir().join(format!("rea-cache-{}", crate::util::new_id()));
        std::fs::create_dir(&root).unwrap();
        let path = root.join("upstream.json");
        let value = collect(fixture).unwrap();
        save(&path, &value).unwrap();
        assert_eq!(load(&path).unwrap(), value);
        save(&path, &value).unwrap();
        assert_eq!(load(&path).unwrap(), value);
        assert_eq!(std::fs::read_dir(&root).unwrap().count(), 1);
        std::fs::remove_dir_all(root).unwrap();
    }
    #[test]
    fn failed_refresh_preserves_previous_cache() {
        let root = std::env::temp_dir().join(format!("rea-cache-{}", crate::util::new_id()));
        std::fs::create_dir(&root).unwrap();
        let path = root.join("upstream.json");
        std::fs::write(&path, b"previous cache").unwrap();
        let fetched = collect(|_| Err(Error::Process("network unavailable".into())));
        assert!(fetched.is_err());
        assert_eq!(std::fs::read(&path).unwrap(), b"previous cache");
        std::fs::remove_dir_all(root).unwrap();
    }
}
