//! Lexical path normalization, ABOVE the strategy seam.
//!
//! This must not live inside the portable chain. `RESOLVE_NO_SYMLINKS` does **not**
//! constrain `..` — measured on Linux and darwin: `openat2(anchor, "../../etc/hostname",
//! RESOLVE_NO_SYMLINKS)` OPENS. If normalization were part of the portable variant,
//! flipping the default to `openat2` would silently remove `..`-escape refusal on the
//! only CI lane we run.
//!
//! `.` and in-bounds `..` are **collapsed**, not rejected: the kernel does the same
//! (`RESOLVE_BENEATH` allows `config.d/../maknae.yaml` and returns EXDEV only on
//! escape), so rejecting all `..` would refuse paths the kernel resolves correctly.

use crate::error::IoError;
use std::path::{Component, Path, PathBuf};

/// Collapse `.` and in-bounds `..`; refuse only a `..` that would escape the anchor.
///
/// Returns the relative remainder to walk. An empty result is legal here — the verb
/// decides what it means (`enumerate` takes the anchor itself; the file verbs refuse).
pub fn normalize(rel: &Path) -> Result<PathBuf, IoError> {
    let mut out: Vec<std::ffi::OsString> = Vec::new();
    for c in rel.components() {
        match c {
            Component::CurDir => {}
            Component::Normal(p) => out.push(p.to_os_string()),
            Component::ParentDir => {
                if out.pop().is_none() {
                    return Err(IoError::EscapesAnchor {
                        path: rel.to_path_buf(),
                    });
                }
            }
            // An absolute remainder would re-root the walk outside the anchor.
            Component::RootDir | Component::Prefix(_) => {
                return Err(IoError::EscapesAnchor {
                    path: rel.to_path_buf(),
                })
            }
        }
    }
    Ok(out.iter().collect())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dot_is_collapsed() {
        assert_eq!(normalize(Path::new("a/./b")).unwrap(), PathBuf::from("a/b"));
        assert_eq!(normalize(Path::new(".")).unwrap(), PathBuf::from(""));
    }

    /// In-bounds `..` collapses rather than refusing — the kernel allows it under
    /// RESOLVE_BENEATH, so refusing would be stricter than the resolver we rely on.
    #[test]
    fn in_bounds_dotdot_is_collapsed() {
        assert_eq!(
            normalize(Path::new("config.d/../maknae.yaml")).unwrap(),
            PathBuf::from("maknae.yaml")
        );
    }

    #[test]
    fn escaping_dotdot_refused() {
        for p in ["..", "a/../..", "../../etc/shadow"] {
            let e = normalize(Path::new(p)).unwrap_err();
            assert!(matches!(e, IoError::EscapesAnchor { .. }), "{p}: got {e:?}");
        }
    }

    #[test]
    fn absolute_remainder_refused() {
        let e = normalize(Path::new("/etc/shadow")).unwrap_err();
        assert!(matches!(e, IoError::EscapesAnchor { .. }), "got {e:?}");
    }

    #[test]
    fn multi_component_survives() {
        assert_eq!(
            normalize(Path::new("config.d/10-x.yaml")).unwrap(),
            PathBuf::from("config.d/10-x.yaml")
        );
    }

    /// The collapsed-to-empty case is legal and the verbs disambiguate it.
    #[test]
    fn collapses_to_empty() {
        assert_eq!(
            normalize(Path::new("config.d/..")).unwrap(),
            PathBuf::from("")
        );
    }
}
