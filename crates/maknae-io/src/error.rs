//! Error surface. PR B maps these to `ConfigError`, so the variant set and the
//! payloads are contract, not an implementation detail.

use std::path::PathBuf;

/// Errno collapsed to the discriminants consumers actually need. Owned rather than
/// `nix::errno::Errno`: re-exporting nix's type would make nix semver-public API of
/// this crate, and `maknae-config` has no nix dependency. PR B needs exactly two
/// (`NotADirectory`, `NotFound`) — a symlink is mapped to `Symlink` before it ever
/// becomes an `IoKind`.
#[non_exhaustive]
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum IoKind {
    NotFound,
    NotADirectory,
    PermissionDenied,
    /// The platform errno as i32. **Diagnostics only — never match on it**: ELOOP is
    /// 40 on Linux and 62 on macOS, so a numeric match would be wrong on the dev host.
    Other {
        raw: i32,
    },
}

#[non_exhaustive]
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum IoError {
    Symlink {
        path: PathBuf,
    },
    NotRegularFile {
        path: PathBuf,
    },
    InsecurePermissions {
        path: PathBuf,
        mode: u32,
    },
    NotOwned {
        path: PathBuf,
        uid: u32,
        want: u32,
    },
    MultiplyLinked {
        path: PathBuf,
        nlink: u64,
    },
    /// The file's length changed between the `fstat` that sized the buffer and the
    /// read that filled it. Returned rather than silently delivering the bytes we
    /// happened to get: on a policy file, a rule appended in that window would
    /// otherwise vanish with an `Ok`, which is a deny becoming a permit.
    SizeChanged {
        path: PathBuf,
        expected: usize,
        got: usize,
    },
    RelativeAnchor {
        path: PathBuf,
    },
    RootAnchor,
    /// `/etc/maknae/..` and `/..`: `parent()` is `Some` while `file_name()` is `None`,
    /// so the `RootAnchor` guard does not fire. Absoluteness is tested first, so a
    /// bare `..` is `RelativeAnchor`, never this. A trailing `.` needs no arm —
    /// `Path::components` absorbs it.
    AnchorEndsInDotDot {
        path: PathBuf,
    },
    EscapesAnchor {
        path: PathBuf,
    },
    EmptyRemainder,
    /// Payload is the caller's PRE-collapse `rel`, so the collapsed case stays diagnosable.
    NoDescendantForRequirement {
        rel: PathBuf,
    },
    Io {
        path: PathBuf,
        kind: IoKind,
    },
}

impl std::fmt::Display for IoError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Symlink { path } => write!(f, "symlink refused: {}", path.display()),
            Self::NotRegularFile { path } => write!(f, "not a regular file: {}", path.display()),
            Self::InsecurePermissions { path, mode } => {
                write!(f, "insecure permissions {mode:o}: {}", path.display())
            }
            Self::NotOwned { path, uid, want } => {
                write!(f, "owned by {uid}, require {want}: {}", path.display())
            }
            Self::MultiplyLinked { path, nlink } => {
                write!(f, "hard-linked (nlink={nlink}): {}", path.display())
            }
            Self::SizeChanged {
                path,
                expected,
                got,
            } => write!(
                f,
                "size changed under the read (expected {expected} bytes, got {got}): {}",
                path.display()
            ),
            Self::RelativeAnchor { path } => write!(f, "anchor is relative: {}", path.display()),
            Self::RootAnchor => write!(f, "anchor is the filesystem root"),
            Self::AnchorEndsInDotDot { path } => {
                write!(f, "anchor's final component is `..`: {}", path.display())
            }
            Self::EscapesAnchor { path } => write!(f, "escapes the anchor: {}", path.display()),
            Self::EmptyRemainder => write!(f, "empty relative remainder"),
            Self::NoDescendantForRequirement { rel } => {
                write!(
                    f,
                    "descendant requirement names no directory: {}",
                    rel.display()
                )
            }
            Self::Io { path, kind } => write!(f, "io error {kind:?}: {}", path.display()),
        }
    }
}

impl std::error::Error for IoError {}
