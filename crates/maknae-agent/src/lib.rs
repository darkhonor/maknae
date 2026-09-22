//! maknae-agent — the runtime loop's BRAIN (#241), and NOT a policy decision
//! point. It decides only what to ASK the kernel for — answer the user, send
//! this verb, or stop — and never yes or no. It performs no I/O: every effect
//! goes through [`plane::Plane`], which the untrusted CLI implements over the
//! plane client and the kernel's tests implement over the in-process fixture.
//! Nothing in this crate names a filesystem, socket or process API — and that,
//! not the feature set of its tokio, is the property. In this crate's own
//! non-dev graph tokio arrives only through `maknae-proto`, with `io-util`
//! alone; linked into `bins/maknae`, feature unification gives it that
//! binary's tokio, `process` included, so "its dependency surface
//! cannot open a file or a socket" would be false of the shipped graph.
pub mod drive;
pub mod plane;
pub mod render;
pub mod route;
pub mod transcript;
