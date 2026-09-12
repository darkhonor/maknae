//! Reading the egress bounds file (#240a D8) — the I/O half.
//!
//! Split from `bounds.rs` for the reason the crate splits `secret_io` from
//! `secret_source` and `syslog_io` from `syslog_fmt`: the PARSER and the
//! CONTAINMENT CHECK are pure, T1, and mutation-visible; this wrapper opens a
//! root-owned file, which no unit test can create, and is tiered accordingly.
//! Keeping it in the T1 file would have bought an untestable region against a
//! 95% floor and taught nothing.

use crate::{bounds_from_document, ConfigError, EgressBounds};

/// Read and parse the bounds file through `maknae-io`: anchored fd,
/// fail-closed on ownership and permissions, exactly as every other
/// configuration input. A command-line argument would take config in through a
/// side door that skips all of it — which is why D8 rejects one by name.
///
/// `root`-owned and not group- or other-writable: both `maknaed` and
/// `_maknae-egress` read it, so it is owned by neither and editable by
/// neither.
pub fn load_egress_bounds(path: &std::path::Path) -> Result<EgressBounds, ConfigError> {
    bounds_from_document(&crate::load_root_file(path)?)
}
