@echo off
rem Air-gapped Windows build: needs only a Rust toolchain, no network.
rem (Cargo.toml declares zero dependencies.)
cargo build --release
echo Built: target\release\rea-offline.exe
