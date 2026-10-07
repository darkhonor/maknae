//! Where the kernel graph store lives (#488). The CLI and `maknaed` both name these
//! paths, so they live here rather than in `maknae-state`, which the CLI never links.

#[cfg(target_os = "macos")]
pub const STATE_DIR: &str = "/usr/local/var/db/maknae/state";
#[cfg(not(target_os = "macos"))]
pub const STATE_DIR: &str = "/var/lib/maknae";

pub const STORE_FILE: &str = "kernel.graph";
pub const MARKER_FILE: &str = "reseed.authorized";
