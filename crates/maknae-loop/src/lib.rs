//! The runtime loop's I/O half (#470). Untrusted by design (ADR-0023): it asks
//! the kernel for everything and decides nothing; the decisions are in
//! `maknae-agent`. `maknaed` never links this crate.
pub mod id;
pub mod keys;
pub mod mutation;
pub mod outcome;
pub mod plane;
pub mod send;
