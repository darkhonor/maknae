//! maknae-vault — shared Vault client (Microkosmos src/vault/ pattern): AppRole auth,
//! local keypair+CSR (rcgen/aws-lc-rs FIPS), pki/sign, memory-only cert, hot-reload,
//! revoke-on-shutdown, CA-bundle pin, URI-SAN verifier. Linked by BOTH binaries; each
//! plane is a Vault client with its own AppRole+policy (spec §2.11, §4). NOT privileged.
//! SCAFFOLD STUB. Body gated on ADR-0005/0007.
pub const CRATE_MARKER: &str = "maknae-vault";
