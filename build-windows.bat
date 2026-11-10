@echo off
rem Air-gapped Windows build: needs only a Rust toolchain, no network.
rem (Cargo.toml declares zero dependencies.)
cargo build --release
echo Built: target\release\rea-offline.exe
echo.
echo Double-click that .exe to open the picker window. A console window stays
echo open behind the browser; leave it open and close it when you are done.
echo From a terminal: target\release\rea-offline.exe gui "C:\path\to\inspect"
