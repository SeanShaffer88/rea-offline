use std::fmt;
use std::path::PathBuf;

pub type Result<T> = std::result::Result<T, Error>;

#[derive(Debug)]
pub enum Error {
    Io(std::io::Error),
    InvalidInput(String),
    NotFound(PathBuf),
    Timeout(String),
    Process(String),
    WindowsApi { api: &'static str, code: u32 },
    Registry { api: &'static str, code: i32 },
    Refused(String),
    Json(String),
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Error::Io(e) => write!(f, "I/O error: {e}"),
            Error::InvalidInput(m) => write!(f, "invalid input: {m}"),
            Error::NotFound(p) => write!(f, "not found: {}", p.display()),
            Error::Timeout(m) => write!(f, "timeout: {m}"),
            Error::Process(m) => write!(f, "process error: {m}"),
            Error::WindowsApi { api, code } => write!(f, "{api} failed (Win32 error {code})"),
            Error::Registry { api, code } => write!(f, "{api} failed (error {code})"),
            Error::Refused(m) => write!(f, "refused: {m}"),
            Error::Json(m) => write!(f, "JSON error: {m}"),
        }
    }
}
impl std::error::Error for Error {}
impl From<std::io::Error> for Error {
    fn from(e: std::io::Error) -> Self {
        Error::Io(e)
    }
}
