//! Per-plane SecretID credential-SOURCE resolution (spec §5.1) — PURE decision logic,
//! no I/O. The daemon (`Plane::Kernel`) and the egress deputy each have their own
//! ordered list of places a SecretID may come from; this module decides WHICH source
//! wins, `secret_io.rs` then reads it. Keeping resolution pure (no filesystem/env
//! reads inside these functions — the caller supplies already-observed inputs) is what
//! makes the fail-closed precedence provably testable and mutation-hardened (T1).
use crate::VaultError;
use std::env::VarError;
use std::fmt;
use std::path::{Path, PathBuf};
use zeroize::Zeroizing;

/// The credential name `$CREDENTIALS_DIRECTORY` always carries for the daemon
/// (systemd `LoadCredential=maknaed-secret-id:...` / `SetCredentialEncrypted`).
pub const DAEMON_CREDENTIALS_DIRECTORY_CRED_NAME: &str = "maknaed-secret-id";

/// The credential name the DEPUTY's unit loads (`LoadCredentialEncrypted=
/// maknae-egress-secret-id:…` in `maknae-egress.service`; `maknae enroll`
/// seals with the same `--name`). #240b.
pub const EGRESS_CREDENTIALS_DIRECTORY_CRED_NAME: &str = "maknae-egress-secret-id";

pub const EGRESS_SEAL_KEY_CRED_NAME: &str = "maknae-egress-seal-key";
pub const MAX_SEAL_KEY_BYTES: usize = 512;
const SEAL_KEY_LENGTH: &str = "empty or over 512 bytes";
const SEAL_KEY_NOT_HEX: &str = "not lower-case hexadecimal of even length";

/// Where the daemon's (`maknaed`) standing SecretID comes from — resolved by
/// [`resolve_daemon_secret_source`], read by `secret_io::read_daemon_secret`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DaemonSecretSource {
    /// systemd `$CREDENTIALS_DIRECTORY/maknaed-secret-id` — the HRoT-sealed boot path
    /// (`LoadCredential`/`SetCredentialEncrypted`), preferred whenever present.
    CredentialsDirectory(PathBuf),
    /// A macOS System-keychain pointer (opt-in, no systemd on darwin).
    Keychain(PathBuf),
    /// An operator-opted-in plaintext file (`vault.insecure_plaintext_secret_path`) —
    /// the weakest posture, last resort, never a silent default.
    PlaintextPath(PathBuf),
}

/// A small `Copy` classifier mirroring the three DAEMON source kinds — the posture
/// record `PlaneClient::secret_source()` exposes for Task 7's audit.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CredentialSourceKind {
    CredentialsDirectory,
    Keychain,
    PlaintextPath,
}

impl From<&DaemonSecretSource> for CredentialSourceKind {
    fn from(src: &DaemonSecretSource) -> Self {
        match src {
            DaemonSecretSource::CredentialsDirectory(_) => {
                CredentialSourceKind::CredentialsDirectory
            }
            DaemonSecretSource::Keychain(_) => CredentialSourceKind::Keychain,
            DaemonSecretSource::PlaintextPath(_) => CredentialSourceKind::PlaintextPath,
        }
    }
}

/// Resolve the DAEMON's SecretID source (spec §5.1). Resolution order — first match
/// wins, no fallthrough once a source is chosen:
///
/// 1. `$CREDENTIALS_DIRECTORY/maknaed-secret-id` (if `credentials_dir_env` is `Some`
///    and non-empty — the systemd HRoT-sealed boot path; ALWAYS preferred when
///    present, regardless of what else is configured. `Some("")`, an exported
///    but empty variable, is a REFUSAL, never a fallthrough to 2 or 3).
/// 2. The System-keychain pointer (macOS, if keychain_pointer is Some).
/// 3. The configured plaintext path (if `insecure_plaintext_secret_path` is `Some`).
/// 4. Else `Err` — fail closed. There is no silent plaintext default.
pub fn resolve_daemon_secret_source(
    credentials_dir_env: Option<&str>,
    keychain_pointer: Option<&Path>,
    insecure_plaintext_secret_path: Option<&Path>,
) -> Result<DaemonSecretSource, VaultError> {
    // An exported-but-empty $CREDENTIALS_DIRECTORY is a REFUSAL, not a
    // fallthrough: it must resolve neither to `/maknaed-secret-id` nor —
    // silently to a weaker arm (self-review round 4 caught this as a
    // demotion). The egress resolver refuses the same input.
    match credentials_dir_env {
        Some("") => {
            return Err(VaultError::CredentialSource(
                "$CREDENTIALS_DIRECTORY is exported but empty — refusing rather than \
                 falling through to a weaker source"
                    .to_string(),
            ))
        }
        Some(dir) => {
            return Ok(DaemonSecretSource::CredentialsDirectory(
                Path::new(dir).join(DAEMON_CREDENTIALS_DIRECTORY_CRED_NAME),
            ))
        }
        None => {}
    }
    if let Some(p) = keychain_pointer {
        return Ok(DaemonSecretSource::Keychain(p.to_path_buf()));
    }
    if let Some(path) = insecure_plaintext_secret_path {
        return Ok(DaemonSecretSource::PlaintextPath(path.to_path_buf()));
    }
    Err(VaultError::CredentialSource(
        "no daemon SecretID source configured: set $CREDENTIALS_DIRECTORY, enroll the \
         keychain item (macOS), or configure vault.insecure_plaintext_secret_path"
            .to_string(),
    ))
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EgressSealKeySource {
    CredentialsDirectory(PathBuf),
    Keychain(PathBuf),
}

pub fn resolve_egress_seal_key_source(
    credentials_dir_env: Option<&str>,
    keychain_pointer: Option<&Path>,
) -> Result<EgressSealKeySource, VaultError> {
    match (credentials_dir_env, keychain_pointer) {
        (Some(""), _) => Err(VaultError::CredentialSource(
            "$CREDENTIALS_DIRECTORY is exported but empty — refusing rather than falling through"
                .to_string(),
        )),
        (Some(dir), _) => Ok(EgressSealKeySource::CredentialsDirectory(
            Path::new(dir).join(EGRESS_SEAL_KEY_CRED_NAME),
        )),
        (None, Some(p)) => Ok(EgressSealKeySource::Keychain(p.to_path_buf())),
        (None, None) => Err(VaultError::CredentialSource(
            "no egress seal key source: $CREDENTIALS_DIRECTORY is unset and no keychain pointer is enrolled"
                .to_string(),
        )),
    }
}

pub(crate) fn check_seal_key_len(n: usize) -> Result<(), VaultError> {
    if !(1..=MAX_SEAL_KEY_BYTES).contains(&n) {
        return Err(VaultError::SealKey(SEAL_KEY_LENGTH));
    }
    Ok(())
}

pub struct SealKeyDer(Zeroizing<Vec<u8>>);

impl SealKeyDer {
    pub(crate) fn new(der: Zeroizing<Vec<u8>>) -> Self {
        Self(der)
    }

    pub fn expose(&self) -> &[u8] {
        &self.0
    }
}

impl fmt::Debug for SealKeyDer {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("SealKeyDer(<redacted>)")
    }
}

pub struct SealKeyHex(Zeroizing<String>);

impl SealKeyHex {
    pub fn expose(&self) -> &str {
        &self.0
    }
}

impl fmt::Debug for SealKeyHex {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("SealKeyHex(<redacted>)")
    }
}

pub fn seal_key_to_hex(der: &[u8]) -> SealKeyHex {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    let mut hex = Zeroizing::new(String::with_capacity(2 * der.len()));
    for b in der {
        hex.push(char::from(DIGITS[usize::from(b >> 4)]));
        hex.push(char::from(DIGITS[usize::from(b & 0x0f)]));
    }
    SealKeyHex(hex)
}

pub fn seal_key_from_hex(text: &str) -> Result<SealKeyDer, VaultError> {
    let hex = text.as_bytes();
    if !hex.len().is_multiple_of(2) {
        return Err(VaultError::SealKey(SEAL_KEY_NOT_HEX));
    }
    check_seal_key_len(hex.len() / 2)?;
    let mut der = Zeroizing::new(Vec::with_capacity(hex.len() / 2));
    for [hi, lo] in hex.as_chunks::<2>().0 {
        der.push(nibble(*hi)? * 16 + nibble(*lo)?);
    }
    Ok(SealKeyDer(der))
}

fn nibble(c: u8) -> Result<u8, VaultError> {
    match c {
        b'0'..=b'9' => Ok(c - b'0'),
        b'a'..=b'f' => Ok(c - b'a' + 10),
        _ => Err(VaultError::SealKey(SEAL_KEY_NOT_HEX)),
    }
}

/// `$CREDENTIALS_DIRECTORY`: unset is `None`; set but not UTF-8 refuses rather
/// than reading as unset (#76 codex r3).
pub fn credentials_directory_env() -> Result<Option<String>, VaultError> {
    classify(std::env::var("CREDENTIALS_DIRECTORY"))
}

fn classify(r: Result<String, VarError>) -> Result<Option<String>, VaultError> {
    match r {
        Ok(s) => Ok(Some(s)),
        Err(VarError::NotPresent) => Ok(None),
        Err(VarError::NotUnicode(_)) => Err(VaultError::CredentialSource(
            "$CREDENTIALS_DIRECTORY is set but not UTF-8 — refusing".to_string(),
        )),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::ffi::OsString;
    use std::os::unix::ffi::OsStringExt;

    #[test]
    fn classify_ok_is_some() {
        assert_eq!(
            classify(Ok("/run/creds".to_string())).unwrap(),
            Some("/run/creds".to_string())
        );
    }

    #[test]
    fn classify_not_present_is_none() {
        assert_eq!(classify(Err(VarError::NotPresent)).unwrap(), None);
    }

    #[test]
    fn classify_not_unicode_refuses() {
        let bytes = OsString::from_vec(vec![0xff]);
        assert!(matches!(
            classify(Err(VarError::NotUnicode(bytes))),
            Err(VaultError::CredentialSource(_))
        ));
    }

    // ---- daemon resolution ---------------------------------------------------

    #[test]
    fn daemon_prefers_credentials_directory() {
        let s = resolve_daemon_secret_source(
            Some("/run/credentials/maknaed.service"),
            None,
            Some(Path::new("/x")),
        )
        .unwrap();
        assert!(matches!(
            s,
            DaemonSecretSource::CredentialsDirectory(p) if p.ends_with("maknaed-secret-id")
        ));
    }

    #[test]
    fn daemon_no_source_fails_closed() {
        assert!(resolve_daemon_secret_source(None, None, None).is_err());
        // An exported-but-empty $CREDENTIALS_DIRECTORY is a refusal — and NOT
        // a demotion to the keychain or plaintext arm when those are available
        // (#240b, self-review round 4).
        assert!(resolve_daemon_secret_source(Some(""), None, None).is_err());
        assert!(matches!(
            resolve_daemon_secret_source(Some(""), Some(Path::new("/k")), Some(Path::new("/x"))),
            Err(VaultError::CredentialSource(_))
        ));
    }

    #[test]
    fn daemon_precedence_credentials_over_keychain() {
        let s = resolve_daemon_secret_source(
            Some("/run/credentials/maknaed.service"),
            Some(Path::new("/k/ptr")),
            None,
        )
        .unwrap();
        assert!(matches!(s, DaemonSecretSource::CredentialsDirectory(_)));
    }

    #[test]
    fn daemon_keychain_used_when_no_credentials_directory() {
        let s = resolve_daemon_secret_source(None, Some(Path::new("/k/ptr")), None).unwrap();
        assert_eq!(s, DaemonSecretSource::Keychain(PathBuf::from("/k/ptr")));
    }

    #[test]
    fn daemon_plaintext_only_when_configured() {
        let s =
            resolve_daemon_secret_source(None, None, Some(Path::new("/etc/maknaed/x"))).unwrap();
        assert_eq!(
            s,
            DaemonSecretSource::PlaintextPath(PathBuf::from("/etc/maknaed/x"))
        );
    }

    /// Mutation probe: swapping the keychain/plaintext order arms would make this
    /// pass with the WRONG variant. Explicitly assert the variant, not just "is Ok".
    #[test]
    fn daemon_order_is_credentials_then_keychain_then_plaintext() {
        assert!(matches!(
            resolve_daemon_secret_source(
                Some("/run/creds"),
                Some(Path::new("/k")),
                Some(Path::new("/plain"))
            )
            .unwrap(),
            DaemonSecretSource::CredentialsDirectory(_)
        ));
        assert!(matches!(
            resolve_daemon_secret_source(None, Some(Path::new("/k")), Some(Path::new("/plain")))
                .unwrap(),
            DaemonSecretSource::Keychain(_)
        ));
        assert!(matches!(
            resolve_daemon_secret_source(None, None, Some(Path::new("/plain"))).unwrap(),
            DaemonSecretSource::PlaintextPath(_)
        ));
    }

    // ---- CredentialSourceKind mapping -----------------------------------------

    #[test]
    fn daemon_source_kind_mapping() {
        assert_eq!(
            CredentialSourceKind::from(&DaemonSecretSource::CredentialsDirectory(PathBuf::from(
                "/x"
            ))),
            CredentialSourceKind::CredentialsDirectory
        );
        assert_eq!(
            CredentialSourceKind::from(&DaemonSecretSource::Keychain(PathBuf::from("/x"))),
            CredentialSourceKind::Keychain
        );
        assert_eq!(
            CredentialSourceKind::from(&DaemonSecretSource::PlaintextPath(PathBuf::from("/x"))),
            CredentialSourceKind::PlaintextPath
        );
    }

    #[test]
    fn the_seal_key_comes_from_its_own_credential_then_the_keychain() {
        let ptr = Path::new("/etc/maknae/egress/maknae-egress-secret-id.keychain");
        assert_eq!(
            resolve_egress_seal_key_source(
                Some("/run/credentials/maknae-egress.service"),
                Some(ptr)
            )
            .unwrap(),
            EgressSealKeySource::CredentialsDirectory(PathBuf::from(
                "/run/credentials/maknae-egress.service/maknae-egress-seal-key"
            ))
        );
        assert_eq!(
            resolve_egress_seal_key_source(None, Some(ptr)).unwrap(),
            EgressSealKeySource::Keychain(ptr.to_path_buf())
        );
        assert!(matches!(
            resolve_egress_seal_key_source(None, None),
            Err(VaultError::CredentialSource(m)) if m.starts_with("no egress seal key source")
        ));
        assert!(matches!(
            resolve_egress_seal_key_source(Some(""), Some(ptr)),
            Err(VaultError::CredentialSource(m)) if m.contains("exported but empty")
        ));
        assert_eq!(EGRESS_SEAL_KEY_CRED_NAME, "maknae-egress-seal-key");
    }

    #[test]
    fn a_seal_key_is_one_to_512_bytes() {
        assert_eq!(MAX_SEAL_KEY_BYTES, 512);
        assert!(check_seal_key_len(1).is_ok() && check_seal_key_len(MAX_SEAL_KEY_BYTES).is_ok());
        for n in [0, MAX_SEAL_KEY_BYTES + 1] {
            assert!(
                matches!(check_seal_key_len(n), Err(VaultError::SealKey(_))),
                "{n}"
            );
        }
    }

    #[test]
    fn the_hex_the_enroller_writes_is_the_hex_the_reader_accepts() {
        let key = maknae_seal::SealPrivateKey::generate().unwrap();
        let der = key.to_pkcs8_der().unwrap();
        assert!(der.len() <= MAX_SEAL_KEY_BYTES);
        let hex = seal_key_to_hex(&der);
        assert_eq!(hex.expose().len(), 2 * der.len());
        assert_eq!(hex.0.capacity(), 2 * der.len());
        let back = seal_key_from_hex(hex.expose()).unwrap();
        assert!(back.expose() == der.as_slice());
        assert_eq!(back.0.capacity(), der.len());
        assert_eq!(
            seal_key_to_hex(&[0x00, 0x0f, 0xa5, 0xff]).expose(),
            "000fa5ff"
        );
        assert_eq!(
            seal_key_from_hex("000fa5ff").unwrap().expose(),
            [0x00, 0x0f, 0xa5, 0xff]
        );
        assert_eq!(seal_key_from_hex("09af").unwrap().expose(), [0x09, 0xaf]);
        assert_eq!(
            seal_key_from_hex(&"ab".repeat(MAX_SEAL_KEY_BYTES))
                .unwrap()
                .expose()
                .len(),
            512
        );
    }

    #[test]
    fn malformed_seal_key_hex_is_refused() {
        let oversize = "00".repeat(MAX_SEAL_KEY_BYTES + 1);
        for bad in [
            "",
            "0",
            "abc",
            "0g",
            "AB",
            "0A",
            "0 00",
            "zz",
            oversize.as_str(),
        ] {
            assert!(
                matches!(seal_key_from_hex(bad), Err(VaultError::SealKey(_))),
                "{bad:?}"
            );
        }
    }

    #[test]
    fn the_seal_key_holders_print_nothing_of_the_key() {
        let der = SealKeyDer::new(Zeroizing::new(vec![0xde, 0xad, 0xbe, 0xef]));
        let hex = seal_key_to_hex(der.expose());
        assert_eq!(format!("{der:?}"), "SealKeyDer(<redacted>)");
        assert_eq!(format!("{hex:?}"), "SealKeyHex(<redacted>)");
        assert_eq!(
            format!("{:#?}", (&der, &hex)).matches("<redacted>").count(),
            2
        );
        for shown in [format!("{der:?}"), format!("{hex:?}")] {
            for leak in ["deadbeef", "222, 173", "de, ad", "DEADBEEF"] {
                assert!(!shown.contains(leak), "{shown}");
            }
        }
        assert_eq!(hex.expose(), "deadbeef");
    }
}
