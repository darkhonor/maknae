//! The local client-plane transport.
//!
//! Named for the project's existing vocabulary -- `plane/kernel` URI-SANs, `PlaneListener`,
//! `RawPlaneConn`, "local plane" -- and deliberately NOT "channel", which this codebase
//! already uses for the interaction-plane chat adapters (Discord/Slack/Telegram/email;
//! see `design/reference-implementation-autopsy.md` and the plane-architecture diagram).
//!
//! Today this crate holds one thing: the adapter that lets a subject's delegated file
//! descriptors survive the read path (ADR-0009). It is the home the client-plane
//! transport is growing into -- [#66](https://github.com/darkhonor/maknae/issues/66)
//! records the trigger for moving `PlaneListener` / `PlaneConnector` /
//! `AuthenticatedStream` here too, so that `maknae-vault` can be about talking to the
//! Vault server and nothing else (operator ruling, 2026-08-30).
//!
//! **What this crate is not.** It holds no policy, no secret, and no decision. The
//! security-relevant half of descriptor delegation -- the `recvmsg` itself,
//! `CMSG_CLOEXEC`, the per-message bound, and everything a received descriptor must
//! satisfy -- lives in [`maknae_io`], per AGENTS.md's rule that file and descriptor I/O
//! goes through that crate. What is here is the async plumbing that calls it.

#![cfg(unix)]

pub mod fd;

pub use fd::{DelegatedFds, FdCollector};
