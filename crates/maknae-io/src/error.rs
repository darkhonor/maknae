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

/// # Path payload convention
///
/// Every variant carrying a `path` reports it **anchor-absolute** — except the three
/// below, which structurally cannot:
///
/// - `EscapesAnchor` is constructed in `normalize`, a free function with no anchor in
///   scope, so it carries the caller's relative input verbatim;
/// - `RelativeAnchor` carries the caller's anchor argument, which is non-absolute *by
///   construction* — that is the error being reported;
/// - `Io` raised by the anchor's own parent open carries **the parent**, one level
///   ABOVE the anchor. Deliberate: when `/etc/maknae/sub/cfg` fails because
///   `/etc/maknae/sub` is missing, naming the component that is actually absent is the
///   useful diagnostic. It is the only site in the crate whose path lies **above** the
///   anchor.
///
/// Anchor-absolute does NOT mean `anchor.join(rel)`. The portable walk names the
/// offending *component* — `Symlink { path: anchor/link }` for a `read("link/x.yaml")`
/// — which is a prefix of `anchor.join(rel)` and still anchor-absolute. `lib.rs`
/// documents that the payload differs by lane, and
/// `both_lanes_refuse_a_symlinked_component` pins both.
///
/// `NoDescendantForRequirement` names its field `rel` rather than `path` for the same
/// reason: it is the caller's input, not a resolved location.
///
/// Stated once here rather than per-variant because the convention drifted repeatedly
/// while this crate was written, and a per-variant claim is what let it: one variant
/// said "like every other path payload this crate returns", which was false for
/// `EscapesAnchor` and `RelativeAnchor`.
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
    /// The target's size exceeds the caller's named `max_bytes` requirement —
    /// refused before any allocation (#77: the read PEP's frame budget).
    TargetTooLarge {
        path: PathBuf,
        limit: u64,
        actual: u64,
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
    /// A path component is not valid UTF-8. `path` is anchor-absolute.
    ///
    /// Its own variant because the previous behaviour was to fold these into
    /// `AnchorEndsInDotDot` / `EmptyRemainder` / `EscapesAnchor` -- all fail closed,
    /// but all three say something FALSE about the path, and PR B renders these
    /// strings for operators. A `MAKNAE_CONFIG_DIR` whose final component is not UTF-8
    /// would have been reported as ending in `..`.
    NonUtf8Component {
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
            Self::TargetTooLarge {
                path,
                limit,
                actual,
            } => {
                write!(
                    f,
                    "too large ({actual} bytes, limit {limit}): {}",
                    path.display()
                )
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
            Self::NonUtf8Component { path } => {
                write!(f, "path component is not valid UTF-8: {}", path.display())
            }
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

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    /// The crate argues a correctness property IN TERMS OF the rendered text — the row-0
    /// mapper exists because `Symlink`'s Display reads "symlink refused", which would
    /// state the opposite of the documented policy for a symlink LOOP in the anchor's
    /// parent. That argument had nothing holding it: no test asserted any Display
    /// string, and `<impl Display>::fmt -> Ok(Default::default())` is the one uncaught
    /// mutant in this file.
    ///
    /// These are also the strings PR B renders for operators, which is why the payloads
    /// are contract.
    #[test]
    fn display_strings_the_crate_reasons_about() {
        let p = PathBuf::from("/etc/maknae/cfg");
        assert_eq!(
            IoError::Symlink { path: p.clone() }.to_string(),
            "symlink refused: /etc/maknae/cfg"
        );
        assert_eq!(
            IoError::SizeChanged {
                path: p.clone(),
                expected: 4096,
                got: 4,
            }
            .to_string(),
            "size changed under the read (expected 4096 bytes, got 4): /etc/maknae/cfg"
        );
        assert_eq!(
            IoError::NonUtf8Component { path: p.clone() }.to_string(),
            "path component is not valid UTF-8: /etc/maknae/cfg"
        );
        // The three the payload-convention paragraph calls out as saying something
        // FALSE about a non-UTF-8 path — the reason NonUtf8Component exists at all.
        assert_eq!(
            IoError::AnchorEndsInDotDot {
                path: PathBuf::from("/etc/maknae/..")
            }
            .to_string(),
            "anchor's final component is `..`: /etc/maknae/.."
        );
        assert_eq!(
            IoError::EmptyRemainder.to_string(),
            "empty relative remainder"
        );
        assert_eq!(
            IoError::EscapesAnchor {
                path: PathBuf::from("../x")
            }
            .to_string(),
            "escapes the anchor: ../x"
        );
        // Mode renders OCTAL — a decimal here would misreport permissions to an operator.
        assert_eq!(
            IoError::InsecurePermissions {
                path: p,
                mode: 0o666,
            }
            .to_string(),
            "insecure permissions 666: /etc/maknae/cfg"
        );
    }
}
