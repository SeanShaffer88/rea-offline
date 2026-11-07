//! rea-offline — Universal Offline Windows Client & REA Analysis Engine.
//!
//! Two operating modes (see `docs/ARCHITECTURE.md`):
//!   * Mode A — local program inspection (static / binary analysis).
//!   * Mode B — ephemeral Job-Object sandbox + differential installer
//!     inspection, followed by a zero-residue purge.
//!
//! The crate intentionally has **no external dependencies** so a release
//! build works on a fully air-gapped machine.

pub mod app;
pub mod cleanup;
pub mod error;
pub mod json;
pub mod rea_bridge;
pub mod registry_sandbox;
pub mod sha256;
pub mod snapshot;
pub mod universal_sandbox;
pub mod util;

pub use error::{Error, Result};
