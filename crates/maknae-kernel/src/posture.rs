//! Boot credential-posture determination (spec §5.2) — PURE decision logic, no
//! I/O. `maknaed` emits an AU-3 record at every boot stating whether the SecretID
//! credential it just used was HRoT-sealed, degraded plaintext, or unverifiable.
//! This module owns ONLY the closed `(source, marker) -> posture` map; reading the
//! marker file (`<config_dir>/private/posture.yaml`) and building/emitting the
//! AU-3 record are `run.rs`'s job (T3, I/O).
//!
//! T1 (`coverage-tiers.toml`): a wrong cell in this map would silently claim a
//! STRONGER posture than what actually protected the SecretID (e.g. reporting a
//! plaintext secret as `hrot_sealed`) — exactly the "emit false assurance" T1
//! line-drawing rule.

use maknae_vault::CredentialSourceKind;

/// Mirrors [`maknae_vault::CredentialSourceKind`] (named `CredentialSource`, NOT
/// `Source` — `run.rs` already imports `maknae_audit_append::Source`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CredentialSource {
    CredentialsDirectory,
    SepSealed,
    PlaintextPath,
}

impl From<CredentialSourceKind> for CredentialSource {
    fn from(kind: CredentialSourceKind) -> Self {
        match kind {
            CredentialSourceKind::CredentialsDirectory => CredentialSource::CredentialsDirectory,
            CredentialSourceKind::SepSealed => CredentialSource::SepSealed,
            CredentialSourceKind::PlaintextPath => CredentialSource::PlaintextPath,
        }
    }
}

/// The root-owned provisioning-time attestation (`<config_dir>/private/posture.yaml`,
/// spec §4.6/§5.2): the sealing mechanism, the sealed target path, and when it was
/// written. The daemon can read this file but not modify it. A missing or
/// malformed marker file parses to `None` at the read site (`run.rs`) — never to a
/// fabricated "matches" marker.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PostureMarker {
    pub mechanism: String,
    pub target: String,
    pub timestamp: String,
}

/// The mechanism token a [`CredentialSource::CredentialsDirectory`] boot expects
/// its marker to attest (Linux `systemd-creds`, TPM2-key-pinned per spec §6.1).
pub const MECHANISM_TPM2: &str = "tpm2";
/// The mechanism token a [`CredentialSource::SepSealed`] boot expects its marker
/// to attest (macOS Secure Enclave).
pub const MECHANISM_SEP: &str = "sep";

/// The daemon's honestly-stated boot credential posture (spec §5.2).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Posture {
    HrotSealed,
    PlaintextDegraded,
    Unverified,
}

impl Posture {
    /// The exact snake_case token spec §5.2 names for `AuditRecord.outcome.posture`.
    pub fn as_str(&self) -> &'static str {
        match self {
            Posture::HrotSealed => "hrot_sealed",
            Posture::PlaintextDegraded => "plaintext_degraded",
            Posture::Unverified => "unverified",
        }
    }
}

/// The pure `(source, marker) -> posture` decision (spec §5.2) — a CLOSED map over
/// every combination:
///
/// - [`CredentialSource::PlaintextPath`] → [`Posture::PlaintextDegraded`] ALWAYS,
///   regardless of any marker (the plaintext branch is loud by construction — a
///   marker that happens to look valid must never launder a plaintext secret into
///   a sealed posture).
/// - A sealed source ([`CredentialSource::CredentialsDirectory`] /
///   [`CredentialSource::SepSealed`]) with a marker whose `mechanism` matches the
///   sealed kind → [`Posture::HrotSealed`].
/// - A sealed source with a MISSING marker, or one whose `mechanism` does not
///   match → [`Posture::Unverified`] (covers both a missing attestation and a
///   contradicting one, per spec §5.2).
pub fn determine(source: CredentialSource, marker: Option<&PostureMarker>) -> Posture {
    match source {
        CredentialSource::PlaintextPath => Posture::PlaintextDegraded,
        CredentialSource::CredentialsDirectory => sealed_posture(marker, MECHANISM_TPM2),
        CredentialSource::SepSealed => sealed_posture(marker, MECHANISM_SEP),
    }
}

fn sealed_posture(marker: Option<&PostureMarker>, expected_mechanism: &str) -> Posture {
    match marker {
        Some(m) if m.mechanism == expected_mechanism => Posture::HrotSealed,
        _ => Posture::Unverified,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn marker(mechanism: &str) -> PostureMarker {
        PostureMarker {
            mechanism: mechanism.to_string(),
            target: "/etc/maknae/private/maknaed-secret-id.cred".to_string(),
            timestamp: "2026-08-12T00:00:00.000Z".to_string(),
        }
    }

    // ---- the full 3 x 3 matrix (spec §10.5): every (source, marker) combination
    // maps to exactly one Posture ----

    #[test]
    fn credentials_directory_with_matching_marker_is_hrot_sealed() {
        assert_eq!(
            determine(
                CredentialSource::CredentialsDirectory,
                Some(&marker(MECHANISM_TPM2))
            ),
            Posture::HrotSealed
        );
    }

    #[test]
    fn credentials_directory_with_missing_marker_is_unverified() {
        assert_eq!(
            determine(CredentialSource::CredentialsDirectory, None),
            Posture::Unverified
        );
    }

    #[test]
    fn credentials_directory_with_mismatched_marker_is_unverified() {
        assert_eq!(
            determine(
                CredentialSource::CredentialsDirectory,
                Some(&marker(MECHANISM_SEP))
            ),
            Posture::Unverified
        );
    }

    #[test]
    fn sep_sealed_with_matching_marker_is_hrot_sealed() {
        assert_eq!(
            determine(CredentialSource::SepSealed, Some(&marker(MECHANISM_SEP))),
            Posture::HrotSealed
        );
    }

    #[test]
    fn sep_sealed_with_missing_marker_is_unverified() {
        assert_eq!(
            determine(CredentialSource::SepSealed, None),
            Posture::Unverified
        );
    }

    #[test]
    fn sep_sealed_with_mismatched_marker_is_unverified() {
        assert_eq!(
            determine(CredentialSource::SepSealed, Some(&marker(MECHANISM_TPM2))),
            Posture::Unverified
        );
    }

    #[test]
    fn plaintext_path_with_matching_marker_is_still_degraded() {
        // A marker that WOULD satisfy a sealed source must not launder a plaintext
        // secret into a sealed posture — the plaintext branch is loud regardless.
        assert_eq!(
            determine(
                CredentialSource::PlaintextPath,
                Some(&marker(MECHANISM_TPM2))
            ),
            Posture::PlaintextDegraded
        );
    }

    #[test]
    fn plaintext_path_with_missing_marker_is_degraded() {
        assert_eq!(
            determine(CredentialSource::PlaintextPath, None),
            Posture::PlaintextDegraded
        );
    }

    #[test]
    fn plaintext_path_with_mismatched_marker_is_still_degraded() {
        assert_eq!(
            determine(CredentialSource::PlaintextPath, Some(&marker("bogus"))),
            Posture::PlaintextDegraded
        );
    }

    // ---- CredentialSourceKind mirror ----

    #[test]
    fn credential_source_mirrors_vault_kind() {
        assert_eq!(
            CredentialSource::from(CredentialSourceKind::CredentialsDirectory),
            CredentialSource::CredentialsDirectory
        );
        assert_eq!(
            CredentialSource::from(CredentialSourceKind::SepSealed),
            CredentialSource::SepSealed
        );
        assert_eq!(
            CredentialSource::from(CredentialSourceKind::PlaintextPath),
            CredentialSource::PlaintextPath
        );
    }

    // ---- Posture::as_str ----

    #[test]
    fn posture_as_str_matches_spec_tokens() {
        assert_eq!(Posture::HrotSealed.as_str(), "hrot_sealed");
        assert_eq!(Posture::PlaintextDegraded.as_str(), "plaintext_degraded");
        assert_eq!(Posture::Unverified.as_str(), "unverified");
    }

    #[test]
    fn as_str_values_are_distinct() {
        // A mutant collapsing two match arms to the same literal must fail this.
        let all = [
            Posture::HrotSealed,
            Posture::PlaintextDegraded,
            Posture::Unverified,
        ];
        let strs: Vec<&str> = all.iter().map(Posture::as_str).collect();
        let mut sorted = strs.clone();
        sorted.sort_unstable();
        sorted.dedup();
        assert_eq!(sorted.len(), strs.len(), "as_str values must be distinct");
    }
}
