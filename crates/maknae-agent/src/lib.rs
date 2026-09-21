//! maknae-agent — the runtime loop's BRAIN (#241), and NOT a policy decision
//! point. It decides only what to ASK the kernel for — answer the user, send
//! this verb, or stop — and never yes or no. It performs no I/O: every effect
//! goes through [`plane::Plane`], which the untrusted CLI implements over the
//! plane client and the kernel's tests implement over the in-process fixture.
//! Its dependency surface cannot open a file or a socket.
pub mod plane;
pub mod route;
pub mod transcript;
