//! Secure filesystem I/O for the Maknae trust plane.
//!
//! The failure that motivated this crate: four different permission masks and three
//! different owner rules had accumulated across `maknae-config::loader`,
//! `maknae-config::authz`, `maknae-audit-append::sink` and `maknae-vault::secret_io`,
//! because each site re-implemented the checks by hand. A new backend's only options
//! were to duplicate security-critical code or to fail open.
//!
//! The model is an **anchor prefix**: the caller opens an anchor directory once, holds
//! it as an fd, and every subsequent operation resolves relative to that pinned fd with
//! `O_NOFOLLOW` at each component. The checked inode and the used inode are the same
//! open fd, so the check-then-reopen TOCTOU is closed.
//!
//! Callers **name** what they require — `AnchorRequired`, `DescendantRequired`,
//! `TargetRequired`. `None` means "this caller requires no such check": a named,
//! greppable, tracked value, never a silent absence. There is no unchecked public
//! entry point.
//!
//! Classification and precedence stay with the parser (see the spec's §8 Q2): this
//! crate reports `Entry.kind` resolved fd-relatively and without following the link,
//! and the caller decides what to do with each kind.

// `pub mod` lines accrete per commit — declaring a module before its file exists is E0583.

pub mod anchor;
pub mod checks;
pub mod error;
mod syscall;

pub use anchor::{open_anchor, Anchor, Entry, Kind, Mode, Outcome, Strategy, StrategyPref};
pub use checks::{AnchorRequired, DescendantRequired, TargetRequired};
pub use error::{IoError, IoKind};
/// Re-exported as a convenience so consumers need no `zeroize` pin of their own.
pub use zeroize::Zeroizing;
