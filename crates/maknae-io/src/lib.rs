//! Secure filesystem I/O for the Maknae trust plane.
//!
//! The failure that motivated this crate: four different permission masks and three
//! different owner rules had accumulated across `maknae-config::loader`,
//! `maknae-config::authz`, `maknae-audit-append::sink` and `maknae-vault::secret_io`,
//! because each site re-implemented the checks by hand. A new backend's only options
//! were to duplicate security-critical code or to fail open.
//!
//! The model is an **anchor prefix**: the caller opens an anchor directory once, holds
//! it as an fd, and every subsequent operation resolves relative to that pinned fd. The
//! checked inode and the used inode are the same open fd, so the check-then-reopen
//! TOCTOU is closed.
//!
//! The `rel` argument to every verb is normalized LEXICALLY first: `.` and in-bounds
//! `..` collapse before any filesystem resolution, so a component cancelled by `..` is
//! never examined at all (see `normalize`). Symlink refusal applies to the components
//! that survive normalization.
//!
//! Symlink refusal is carried by whichever lane runs, and the two do it differently --
//! stating "`O_NOFOLLOW` at each component" would be false on Linux:
//!
//! - **portable** — `openat` per component with `O_NOFOLLOW`, so a symlinked component
//!   fails at the component itself and the error names it;
//! - **openat2** (Linux, multi-component remainder, no descendant check) — one
//!   `RESOLVE_NO_SYMLINKS|RESOLVE_BENEATH` resolve inside the kernel, carrying no
//!   `O_NOFOLLOW` because the resolve flags subsume it.
//!
//! Both refuse the same inputs with the same `IoError` variant. The `path` PAYLOAD
//! differs by lane -- the portable walk names the offending component, openat2 reports
//! the path it was asked to resolve -- and `both_lanes_refuse_a_symlinked_component`
//! pins both.
//!
//! One deliberate exception to fd-relative resolution: the anchor's own parent is
//! opened BY PATH and follows symlinks, so a symlinked ancestor of the anchor is
//! permitted and resolved once, at open time.
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

mod account;
mod account_facts;
pub mod anchor;
mod audit_append;
pub mod checks;
pub mod delegated;
mod dir;
pub mod error;
mod home;
mod host_facts;
pub mod mutation;
pub mod normalize;
mod page;
pub mod program;
mod strategy;
mod syscall;
mod walk;
mod write;

pub use account::{
    daemon_facts, group_by_gid, group_by_name, group_gid, host_account, maknae_agents_gid,
    not_found_is_none, user_by_name, user_by_uid,
};
pub use account_facts::{
    AccountLookupError, DaemonFacts, HostAccount, MAKNAE_AGENTS_GROUP, MAKNAE_DAEMON_ACCOUNTS,
    MAKNAE_GROUP,
};
pub use anchor::{
    open_anchor, open_anchor_resolved, read_absolute, resolve_dir, Anchor, AnchorLock, Entry,
    EntryId, FileOwner, Kind, Mode, Outcome, Strategy, StrategyPref,
};
pub use audit_append::{open_audit_append, open_existing_audit_append};
pub use checks::{AnchorRequired, DescendantRequired, TargetRequired};
pub use delegated::{
    list_delegated_directory, open_directory_for_delegation, open_path_for_delegation,
    open_path_for_stat, recv_delegated, refuse_access_bearing, refuse_enumerable, send_delegated,
    sender_admitted, verify_delegated, verify_stat_delegated, Delegated, DelegatedFds,
    DelegatedMeta, DelegatedRequired, ExpectedSender, FileKind, ListedEntry, Listing, Received,
    SenderCreds, DELEGATED_FDS_PER_CONNECTION,
};
pub use error::{IoError, IoKind};
pub use home::{canonical_home, session_home, unit_safe_home, UnsafeHome};
pub use host_facts::presence;
pub use mutation::{
    held_file_is_readable, read_held_file, read_held_page, replace_held_file,
    verify_mutation_directory, verify_unconfined_directory, DirectoryCursor, EffectState,
    FileVersion, MutationDirectory, MutationEffect, MutationEffectKind, MutationFailure, WriteBase,
};
pub use normalize::normalize;
pub use page::{read_page, Page, PageNext, PageWindow};
/// Re-exported as a convenience so consumers need no `zeroize` pin of their own.
pub use zeroize::Zeroizing;

// LAST IN THE FILE, not merely last in the mod block. coverage_check.py requires that
// after a `#[cfg(test)]` marker ONLY the mod line, `}` or comments sit at column 0 —
// for the remainder of the FILE, not the remainder of the block. With this declaration
// above the `pub use` lines the checker hardfails ("column-0 code after the test
// module leaves the production denominator"), verified by running it directly; today
// that is masked only because lib.rs is `[[t3]]`, and it would bite the moment lib.rs
// is promoted.
#[cfg(test)]
mod testutil;
