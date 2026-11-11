@echo off
rem Air-gapped Windows build: needs only a Rust toolchain, no network.
rem (Cargo.toml declares zero dependencies.)
cargo build --release --offline --locked --target x86_64-pc-windows-msvc
if errorlevel 1 exit /b %errorlevel%
echo Built: target\x86_64-pc-windows-msvc\release\rea-offline.exe
echo.
echo Double-click that .exe to open the picker window. A console window stays
echo open behind the browser; leave it open and close it when you are done.
echo From a terminal: target\x86_64-pc-windows-msvc\release\rea-offline.exe gui "C:\path\to\inspect"
