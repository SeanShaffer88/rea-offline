//! Native dialogs return local paths, never browser uploads. No shell commands.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum Kind { File, Folder, Report }

pub(super) fn choose(kind: Kind) -> Result<Option<String>, String> {
    static ACTIVE: std::sync::Mutex<()> = std::sync::Mutex::new(());
    let _guard = ACTIVE.try_lock().map_err(|_| "A Browse dialog is already open. Switch to it or cancel it first.".to_string())?;
    #[cfg(windows)]
    { windows::choose(kind) }
    #[cfg(not(windows))]
    { let _ = kind; Err("Native browsing is available on Windows. Paste the full local path instead; no file is uploaded.".into()) }
}

#[cfg(windows)]
mod windows {
    use super::Kind;
    use std::ffi::c_void;
    fn wide(s: &str) -> Vec<u16> { s.encode_utf16().chain(Some(0)).collect() }

    #[repr(C)]
    struct OpenFileName {
        size: u32, owner: isize, instance: isize, filter: *const u16,
        custom_filter: *mut u16, max_custom_filter: u32, filter_index: u32,
        file: *mut u16, max_file: u32, file_title: *mut u16, max_file_title: u32,
        initial_dir: *const u16, title: *const u16, flags: u32,
        file_offset: u16, file_extension: u16, default_extension: *const u16,
        custom_data: isize, hook: *const c_void, template_name: *const u16,
        reserved: *mut c_void, reserved_size: u32, flags_ex: u32,
    }
    #[repr(C)]
    struct BrowseInfo {
        owner: isize, root: *const c_void, display: *mut u16, title: *const u16,
        flags: u32, callback: *const c_void, param: isize, image: i32,
    }
    #[link(name = "comdlg32")]
    extern "system" {
        fn GetOpenFileNameW(info: *mut OpenFileName) -> i32;
        fn CommDlgExtendedError() -> u32;
    }
    #[link(name = "shell32")]
    extern "system" {
        fn SHBrowseForFolderW(info: *const BrowseInfo) -> *mut c_void;
        fn SHGetPathFromIDListW(id: *const c_void, path: *mut u16) -> i32;
    }
    #[link(name = "ole32")]
    extern "system" {
        fn CoInitializeEx(reserved: *mut c_void, flags: u32) -> i32;
        fn CoUninitialize();
        fn CoTaskMemFree(memory: *mut c_void);
    }
    fn path(buffer: &[u16]) -> String {
        String::from_utf16_lossy(&buffer[..buffer.iter().position(|c| *c == 0).unwrap_or(buffer.len())])
    }
    pub(super) fn choose(kind: Kind) -> Result<Option<String>, String> {
        unsafe {
            if kind == Kind::Folder {
                let hr = CoInitializeEx(std::ptr::null_mut(), 2); // apartment-threaded shell dialog
                if hr < 0 { return Err(format!("Could not initialize the folder picker (HRESULT {hr:#x}). Paste the path instead.")); }
                let title = wide("rea-offline: select a folder to inspect");
                let mut display = [0u16; 260];
                let info = BrowseInfo { owner: 0, root: std::ptr::null(), display: display.as_mut_ptr(),
                    title: title.as_ptr(), flags: 0x41, callback: std::ptr::null(), param: 0, image: 0 };
                let id = SHBrowseForFolderW(&info);
                let result = if id.is_null() { Ok(None) } else {
                    let mut buffer = [0u16; 260];
                    let ok = SHGetPathFromIDListW(id, buffer.as_mut_ptr());
                    CoTaskMemFree(id);
                    if ok == 0 { Err("This selection has no filesystem path. Paste a folder path instead.".into()) }
                    else { Ok(Some(path(&buffer))) }
                };
                CoUninitialize();
                return result;
            }
            let title = wide(if kind == Kind::Report { "rea-offline: open a saved report" } else { "rea-offline: select a file or installer to inspect" });
            let filter = wide(if kind == Kind::Report { "JSON reports\0*.json\0All files\0*.*\0" } else { "All files\0*.*\0" });
            let mut buffer = vec![0u16; 32768];
            let mut info: OpenFileName = std::mem::zeroed();
            info.size = std::mem::size_of::<OpenFileName>() as u32;
            info.filter = filter.as_ptr(); info.filter_index = 1;
            info.file = buffer.as_mut_ptr(); info.max_file = buffer.len() as u32;
            info.title = title.as_ptr();
            info.flags = 0x80000 | 0x1000 | 0x800 | 8 | 0x02000000;
            if GetOpenFileNameW(&mut info) != 0 { return Ok(Some(path(&buffer))); }
            let error = CommDlgExtendedError();
            if error == 0 { Ok(None) } else { Err(format!("Could not open the file picker (dialog error {error:#x}). Paste the path instead.")) }
        }
    }
}
