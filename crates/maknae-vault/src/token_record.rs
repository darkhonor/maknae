use crate::keychain_policy::{KeychainDelete, ITEM_NOT_FOUND, TOKEN_DELETE_REMEDY};
use crate::{UserLogin, UserToken, VaultError, MAX_TOKEN_BYTES};
use maknae_io::{AnchorRequired, IoError, IoKind, TargetRequired};
use std::io::Read;
use std::path::{Path, PathBuf};
use std::time::Duration;
use zeroize::Zeroizing;

pub const TOKEN_EXPIRY_MARGIN: Duration = Duration::from_secs(60);
pub const USER_CREDS_MIN_SYSTEMD: u32 = 256;
pub const TOKEN_CREDS_FILE: &str = "maknae-vault-token.cred";
pub const TOKEN_RESIDUAL_FILE: &str = "maknae-vault-token";
pub(crate) const TOKEN_CREDS_NAME: &str = "maknae-vault-token";
pub(crate) const SYSTEMD_CREDS: &str = "/usr/bin/systemd-creds";
pub(crate) const MAX_CREDS_FILE_BYTES: usize = 16 * 1024;
pub(crate) const TOKEN_FILE_MODE: u32 = 0o600;
const OWNER_ONLY: u32 = 0o077;
const RECORD_PREFIX: &[u8] = b"maknae-vault-token v1 ";
const MAX_EXPIRY_DIGITS: usize = 20;
pub const MAX_TOKEN_RECORD_BYTES: usize =
    RECORD_PREFIX.len() + MAX_EXPIRY_DIGITS + 1 + MAX_TOKEN_BYTES;

#[derive(Debug)]
pub struct StoredToken {
    token: UserToken,
    expires_at: u64,
}

fn parse_expiry(digits: &[u8]) -> Option<u64> {
    if digits.is_empty()
        || digits.len() > MAX_EXPIRY_DIGITS
        || (digits.len() > 1 && digits[0] == b'0')
    {
        return None;
    }
    digits.iter().try_fold(0u64, |acc, &b| {
        if !b.is_ascii_digit() {
            return None;
        }
        acc.checked_mul(10)?.checked_add(u64::from(b - b'0'))
    })
}

impl StoredToken {
    pub fn from_login(login: UserLogin, issued_before: u64) -> Self {
        Self {
            expires_at: issued_before.saturating_add(login.lease.as_secs()),
            token: login.token,
        }
    }

    pub fn token(&self) -> &UserToken {
        &self.token
    }

    pub fn expires_at(&self) -> u64 {
        self.expires_at
    }

    pub fn encode(&self) -> Zeroizing<Vec<u8>> {
        let expiry = self.expires_at.to_string();
        let token = self.token.expose().as_bytes();
        let len = RECORD_PREFIX.len() + expiry.len() + 1 + token.len();
        let mut out = Zeroizing::new(Vec::with_capacity(len));
        out.extend_from_slice(RECORD_PREFIX);
        out.extend_from_slice(expiry.as_bytes());
        out.push(b' ');
        out.extend_from_slice(token);
        out
    }

    pub fn decode(bytes: &[u8]) -> Result<Self, VaultError> {
        if bytes.len() > MAX_TOKEN_RECORD_BYTES {
            return Err(VaultError::TokenRecord("over its size bound"));
        }
        let rest = bytes
            .strip_prefix(RECORD_PREFIX)
            .ok_or(VaultError::TokenRecord("not a maknae token record"))?;
        let at = rest
            .iter()
            .position(|&b| b == b' ')
            .ok_or(VaultError::TokenRecord("no expiry"))?;
        let expires_at =
            parse_expiry(&rest[..at]).ok_or(VaultError::TokenRecord("malformed expiry"))?;
        let token = std::str::from_utf8(&rest[at + 1..])
            .map_err(|_| VaultError::TokenRecord("the token is not UTF-8"))?;
        Ok(Self {
            token: UserToken::new(Zeroizing::new(token.to_owned()))
                .map_err(|_| VaultError::TokenRecord("malformed token"))?,
            expires_at,
        })
    }

    pub fn is_fresh_at(&self, now: u64) -> bool {
        now.saturating_add(TOKEN_EXPIRY_MARGIN.as_secs()) < self.expires_at
    }

    pub fn revocable_at(&self, now: u64) -> bool {
        now < self.expires_at
    }

    pub fn fresh_at(self, now: u64) -> Result<UserToken, VaultError> {
        if !self.is_fresh_at(now) {
            return Err(VaultError::TokenExpired);
        }
        Ok(self.token)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TokenCustody {
    Keychain,
    UserCreds(PathBuf),
    Residual(PathBuf),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SystemdCreds {
    Absent,
    Version(u32),
}

pub fn custody_for_store(cli_dir: &Path, macos: bool, creds: SystemdCreds) -> TokenCustody {
    if macos {
        return TokenCustody::Keychain;
    }
    match creds {
        SystemdCreds::Version(v) if v >= USER_CREDS_MIN_SYSTEMD => {
            TokenCustody::UserCreds(cli_dir.join(TOKEN_CREDS_FILE))
        }
        _ => TokenCustody::Residual(cli_dir.join(TOKEN_RESIDUAL_FILE)),
    }
}

pub(crate) fn every_custody(cli_dir: &Path, macos: bool) -> Vec<TokenCustody> {
    if macos {
        return vec![TokenCustody::Keychain];
    }
    vec![
        TokenCustody::UserCreds(cli_dir.join(TOKEN_CREDS_FILE)),
        TokenCustody::Residual(cli_dir.join(TOKEN_RESIDUAL_FILE)),
    ]
}

pub(crate) fn first_present<T>(
    reads: impl IntoIterator<Item = Result<T, VaultError>>,
) -> Result<T, VaultError> {
    for read in reads {
        match read {
            Err(VaultError::TokenAbsent) => continue,
            other => return other,
        }
    }
    Err(VaultError::TokenAbsent)
}

pub fn custody_label(custody: &TokenCustody) -> &'static str {
    match custody {
        TokenCustody::Keychain => "the macOS login keychain",
        TokenCustody::UserCreds(_) => "a systemd-creds user credential",
        TokenCustody::Residual(_) => "a 0600 file (systemd-creds --user is unavailable here)",
    }
}

pub(crate) fn systemd_major(version_output: &str) -> Option<u32> {
    let rest = version_output.lines().next()?.strip_prefix("systemd ")?;
    let end = rest
        .find(|c: char| !c.is_ascii_digit())
        .unwrap_or(rest.len());
    rest[..end].parse().ok()
}

pub(crate) fn token_dir_required(euid: u32) -> AnchorRequired {
    AnchorRequired {
        owner: Some(euid),
        mode_mask: Some(OWNER_ONLY),
    }
}

pub(crate) fn token_file_required(euid: u32, max: usize) -> TargetRequired {
    TargetRequired {
        owner: Some(euid),
        mode_mask: Some(OWNER_ONLY),
        nlink_exactly_one: true,
        regular_file: true,
        max_bytes: Some(max as u64),
    }
}

pub(crate) fn token_dir_refusal(e: IoError) -> Option<VaultError> {
    match e {
        IoError::Io {
            kind: IoKind::NotFound,
            ..
        } => None,
        other => Some(VaultError::TokenStore(format!("token directory: {other}"))),
    }
}

pub(crate) fn token_file_refusal(e: IoError) -> VaultError {
    match e {
        IoError::Io {
            kind: IoKind::NotFound,
            ..
        } => VaultError::TokenAbsent,
        other => VaultError::TokenUnreadable(other.to_string()),
    }
}

#[cfg(any(target_os = "macos", test))]
pub(crate) fn keychain_read_refusal(e: VaultError) -> VaultError {
    match e {
        VaultError::Keychain { status } if status == ITEM_NOT_FOUND => VaultError::TokenAbsent,
        VaultError::Keychain { status } => {
            VaultError::TokenUnreadable(format!("keychain status {status}"))
        }
        VaultError::CredentialSource(m) => VaultError::TokenUnreadable(m),
        other => other,
    }
}

pub(crate) fn decrypt_refusal(stderr: &str) -> VaultError {
    VaultError::TokenUnreadable(format!("systemd-creds decrypt --user: {stderr}"))
}

pub(crate) fn keychain_erase_outcome(
    deleted: Result<KeychainDelete, VaultError>,
) -> Result<bool, VaultError> {
    let detail = match deleted {
        Ok(KeychainDelete::Absent) => return Ok(false),
        Ok(KeychainDelete::Removed) => return Ok(true),
        Ok(KeychainDelete::StillPresent) => "the item is still present after delete".to_string(),
        Err(VaultError::Keychain { status }) if status == ITEM_NOT_FOUND => return Ok(false),
        Err(VaultError::Keychain { status }) => format!("keychain status {status}"),
        Err(_) => "the keychain refused the delete".to_string(),
    };
    Err(VaultError::TokenStore(format!(
        "keychain delete: {detail}; remove it with `{TOKEN_DELETE_REMEDY}`"
    )))
}

pub(crate) fn read_record(mut r: impl Read, cap: usize) -> Result<Zeroizing<Vec<u8>>, VaultError> {
    let mut buf = Zeroizing::new(vec![0u8; cap + 1]);
    let mut len = 0;
    while len < buf.len() {
        match r.read(&mut buf[len..]) {
            Ok(0) => {
                buf.truncate(len);
                return Ok(buf);
            }
            Ok(n) => len += n,
            Err(e) if e.kind() == std::io::ErrorKind::Interrupted => {}
            Err(e) => {
                return Err(VaultError::TokenUnreadable(format!(
                    "reading the token: {}",
                    e.kind()
                )))
            }
        }
    }
    Err(VaultError::TokenRecord("over its size bound"))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn token(s: &str) -> UserToken {
        UserToken::new(Zeroizing::new(s.to_string())).unwrap()
    }

    fn stored(s: &str, expires_at: u64) -> StoredToken {
        StoredToken {
            token: token(s),
            expires_at,
        }
    }

    #[test]
    fn a_login_expires_one_lease_after_the_clock_taken_before_the_request() {
        let login = UserLogin {
            token: token("hvs.a"),
            lease: Duration::from_secs(28_800),
            renewable: true,
        };
        let s = StoredToken::from_login(login, 1_000);
        assert_eq!(s.expires_at(), 29_800);
        assert!(s.token().expose() == "hvs.a");
        let login = UserLogin {
            token: token("hvs.a"),
            lease: Duration::from_secs(10),
            renewable: false,
        };
        assert_eq!(
            StoredToken::from_login(login, u64::MAX).expires_at(),
            u64::MAX
        );
    }

    #[test]
    fn a_record_round_trips_at_its_exact_size() {
        let bytes = stored("hvs.CAESIabc_-9", 1_790_000_000).encode();
        assert!(bytes.as_slice() == b"maknae-vault-token v1 1790000000 hvs.CAESIabc_-9");
        assert_eq!(bytes.capacity(), bytes.len());
        let back = StoredToken::decode(&bytes).unwrap();
        assert!(back.token().expose() == "hvs.CAESIabc_-9");
        assert_eq!(back.expires_at(), 1_790_000_000);
    }

    #[test]
    fn the_largest_record_is_exactly_the_bound() {
        let bytes = stored(&"a".repeat(MAX_TOKEN_BYTES), u64::MAX).encode();
        assert_eq!(bytes.len(), MAX_TOKEN_RECORD_BYTES);
        assert_eq!(MAX_TOKEN_RECORD_BYTES, 1067);
        assert_eq!(StoredToken::decode(&bytes).unwrap().expires_at(), u64::MAX);
        let mut over = bytes.to_vec();
        over.push(b'a');
        assert!(matches!(
            StoredToken::decode(&over),
            Err(VaultError::TokenRecord("over its size bound"))
        ));
    }

    fn refusal(bytes: &[u8]) -> &'static str {
        match StoredToken::decode(bytes) {
            Err(VaultError::TokenRecord(why)) => why,
            Err(e) => panic!("unexpected refusal {e}"),
            Ok(_) => panic!("a malformed record was accepted"),
        }
    }

    #[test]
    fn a_malformed_record_is_refused_by_name() {
        let rows: [(&[u8], &str); 12] = [
            (b"", "not a maknae token record"),
            (
                b"maknae-vault-token v2 1 hvs.a",
                "not a maknae token record",
            ),
            (b"maknae-vault-token v1 1", "no expiry"),
            (b"maknae-vault-token v1  hvs.a", "malformed expiry"),
            (b"maknae-vault-token v1 1x hvs.a", "malformed expiry"),
            (
                b"maknae-vault-token v1 18446744073709551616 hvs.a",
                "malformed expiry",
            ),
            (
                b"maknae-vault-token v1 123456789012345678901 hvs.a",
                "malformed expiry",
            ),
            (b"maknae-vault-token v1 1 \xff", "the token is not UTF-8"),
            (b"maknae-vault-token v1 1 hvs.a b", "malformed token"),
            (b"maknae-vault-token v1 0001 hvs.a", "malformed expiry"),
            (b"maknae-vault-token v1 1 ", "malformed token"),
            (b"maknae-vault-token v1 1 hvs.a\n", "malformed token"),
        ];
        for (bytes, want) in rows {
            assert_eq!(refusal(bytes), want, "{:?}", String::from_utf8_lossy(bytes));
        }
    }

    #[test]
    fn a_token_is_fresh_until_the_margin_and_revocable_until_its_expiry() {
        let m = TOKEN_EXPIRY_MARGIN.as_secs();
        assert_eq!(m, 60);
        assert!(stored("hvs.a", 1_000 + m + 1).is_fresh_at(1_000));
        assert!(!stored("hvs.a", 1_000 + m).is_fresh_at(1_000));
        assert!(!stored("hvs.a", u64::MAX).is_fresh_at(u64::MAX));
        assert!(
            stored("hvs.a", 1_000 + m + 1)
                .fresh_at(1_000)
                .unwrap()
                .expose()
                == "hvs.a"
        );
        assert!(matches!(
            stored("hvs.a", 1_000).fresh_at(1_000),
            Err(VaultError::TokenExpired)
        ));
        assert!(stored("hvs.a", 1_001).revocable_at(1_000));
        assert!(!stored("hvs.a", 1_000).revocable_at(1_000));
    }

    #[test]
    fn custody_follows_the_platform_and_the_systemd_version() {
        let d = Path::new("/home/alice/.maknae");
        let creds = TokenCustody::UserCreds(d.join("maknae-vault-token.cred"));
        let residual = TokenCustody::Residual(d.join("maknae-vault-token"));
        for c in [SystemdCreds::Absent, SystemdCreds::Version(257)] {
            assert_eq!(custody_for_store(d, true, c), TokenCustody::Keychain);
        }
        let rows = [
            (SystemdCreds::Version(256), &creds),
            (SystemdCreds::Version(257), &creds),
            (SystemdCreds::Version(255), &residual),
            (SystemdCreds::Version(252), &residual),
            (SystemdCreds::Absent, &residual),
        ];
        for (c, want) in rows {
            assert_eq!(&custody_for_store(d, false, c), want, "{c:?}");
        }
        assert_eq!(USER_CREDS_MIN_SYSTEMD, 256);
        assert_eq!(every_custody(d, true), vec![TokenCustody::Keychain]);
        assert_eq!(every_custody(d, false), vec![creds, residual]);
        assert_eq!(SYSTEMD_CREDS, "/usr/bin/systemd-creds");
    }

    #[test]
    fn only_an_absent_custody_moves_on_and_nothing_after_a_present_one_is_read() {
        let absent = || Err::<u8, _>(VaultError::TokenAbsent);
        assert_eq!(first_present([absent(), Ok(1)]).unwrap(), 1);
        assert!(matches!(
            first_present([
                absent(),
                Err(VaultError::TokenUnreadable("x".into())),
                Ok(2)
            ]),
            Err(VaultError::TokenUnreadable(_))
        ));
        assert!(matches!(
            first_present([absent(), absent()]),
            Err(VaultError::TokenAbsent)
        ));
        assert!(matches!(
            first_present(std::iter::empty::<Result<u8, VaultError>>()),
            Err(VaultError::TokenAbsent)
        ));
        let lazy = std::iter::once(Ok(3u8))
            .chain(std::iter::from_fn(|| panic!("read past a present custody")));
        assert_eq!(first_present(lazy).unwrap(), 3);
    }

    #[test]
    fn each_custody_is_named_for_the_user() {
        let d = Path::new("/h");
        assert_eq!(
            custody_label(&TokenCustody::Keychain),
            "the macOS login keychain"
        );
        assert_eq!(
            custody_label(&TokenCustody::UserCreds(d.join("c"))),
            "a systemd-creds user credential"
        );
        assert_eq!(
            custody_label(&TokenCustody::Residual(d.join("r"))),
            "a 0600 file (systemd-creds --user is unavailable here)"
        );
    }

    #[test]
    fn the_systemd_version_is_the_first_lines_major() {
        let rows: [(&str, Option<u32>); 9] = [
            ("systemd 257 (257.4-1.el10)\n+PAM +AUDIT", Some(257)),
            ("systemd 252 (252-51.el9)", Some(252)),
            ("systemd 256", Some(256)),
            ("systemd 256~rc1 (x)", Some(256)),
            ("", None),
            ("libsystemd 257", None),
            ("systemd x", None),
            ("\nsystemd 257", None),
            ("systemd 99999999999", None),
        ];
        for (out, want) in rows {
            assert_eq!(systemd_major(out), want, "{out:?}");
        }
    }

    #[test]
    fn token_files_are_owner_only_single_link_regular_and_bounded() {
        assert_eq!(
            token_dir_required(501),
            AnchorRequired {
                owner: Some(501),
                mode_mask: Some(0o077)
            }
        );
        assert_eq!(
            token_file_required(501, 1067),
            TargetRequired {
                owner: Some(501),
                mode_mask: Some(0o077),
                nlink_exactly_one: true,
                regular_file: true,
                max_bytes: Some(1067)
            }
        );
        assert_eq!(TOKEN_FILE_MODE, 0o600);
        assert_eq!(MAX_CREDS_FILE_BYTES, 16 * 1024);
    }

    fn io(kind: IoKind) -> IoError {
        IoError::Io {
            path: "/h/.maknae/t".into(),
            kind,
        }
    }

    #[test]
    fn a_missing_token_or_directory_is_absent_and_anything_else_is_named() {
        assert!(token_dir_refusal(io(IoKind::NotFound)).is_none());
        assert!(matches!(
            token_dir_refusal(io(IoKind::PermissionDenied)),
            Some(VaultError::TokenStore(m)) if m.starts_with("token directory: ")
        ));
        assert!(matches!(
            token_file_refusal(io(IoKind::NotFound)),
            VaultError::TokenAbsent
        ));
        let insecure = IoError::InsecurePermissions {
            path: "/h/.maknae/t".into(),
            mode: 0o640,
        };
        assert!(matches!(
            token_file_refusal(insecure),
            VaultError::TokenUnreadable(_)
        ));
    }

    #[test]
    fn a_keychain_or_decrypt_refusal_on_read_points_at_login() {
        assert!(matches!(
            keychain_read_refusal(VaultError::Keychain {
                status: ITEM_NOT_FOUND
            }),
            VaultError::TokenAbsent
        ));
        assert!(matches!(
            keychain_read_refusal(VaultError::Keychain { status: -25293 }),
            VaultError::TokenUnreadable(m) if m == "keychain status -25293"
        ));
        assert!(matches!(
            keychain_read_refusal(VaultError::CredentialSource("not UTF-8".into())),
            VaultError::TokenUnreadable(m) if m == "not UTF-8"
        ));
        assert!(matches!(
            keychain_read_refusal(VaultError::FipsUnavailable),
            VaultError::FipsUnavailable
        ));
        assert!(matches!(
            decrypt_refusal("Failed to decrypt"),
            VaultError::TokenUnreadable(m) if m == "systemd-creds decrypt --user: Failed to decrypt"
        ));
    }

    #[test]
    fn a_keychain_erase_reports_absence_removal_or_the_manual_remedy() {
        assert!(!keychain_erase_outcome(Ok(KeychainDelete::Absent)).unwrap());
        assert!(keychain_erase_outcome(Ok(KeychainDelete::Removed)).unwrap());
        assert!(!keychain_erase_outcome(Err(VaultError::Keychain {
            status: ITEM_NOT_FOUND
        }))
        .unwrap());
        for refused in [
            Ok(KeychainDelete::StillPresent),
            Err(VaultError::Keychain { status: -25293 }),
            Err(VaultError::TokenAbsent),
        ] {
            match keychain_erase_outcome(refused) {
                Err(VaultError::TokenStore(m)) => {
                    assert!(
                        m.ends_with(&format!("remove it with `{TOKEN_DELETE_REMEDY}`")),
                        "{m}"
                    );
                    assert!(
                        !m.contains("maknae login") && !m.contains("maknae enroll"),
                        "{m}"
                    );
                }
                other => panic!("expected the manual remedy, got {other:?}"),
            }
        }
        match keychain_erase_outcome(Err(VaultError::Keychain { status: -25293 })) {
            Err(VaultError::TokenStore(m)) => {
                assert!(m.contains("-25293") && !m.contains("read"), "{m}");
            }
            other => panic!("expected the manual remedy, got {other:?}"),
        }
    }

    struct Trickle<'a> {
        rest: &'a [u8],
        interrupted: bool,
    }

    impl Read for Trickle<'_> {
        fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
            if !self.interrupted {
                self.interrupted = true;
                return Err(std::io::ErrorKind::Interrupted.into());
            }
            let Some((&first, rest)) = self.rest.split_first() else {
                return Ok(0);
            };
            buf[0] = first;
            self.rest = rest;
            Ok(1)
        }
    }

    struct BrokenOnce(bool);

    impl Read for BrokenOnce {
        fn read(&mut self, _: &mut [u8]) -> std::io::Result<usize> {
            assert!(!self.0, "a hard read error was retried");
            self.0 = true;
            Err(std::io::ErrorKind::BrokenPipe.into())
        }
    }

    #[test]
    fn a_record_is_read_whole_up_to_its_bound_and_never_grows() {
        let full = vec![b'a'; MAX_TOKEN_RECORD_BYTES];
        let got = read_record(&full[..], MAX_TOKEN_RECORD_BYTES).unwrap();
        assert_eq!(got.len(), MAX_TOKEN_RECORD_BYTES);
        assert_eq!(got.capacity(), MAX_TOKEN_RECORD_BYTES + 1);
        let over = vec![b'a'; MAX_TOKEN_RECORD_BYTES + 1];
        assert!(matches!(
            read_record(&over[..], MAX_TOKEN_RECORD_BYTES),
            Err(VaultError::TokenRecord("over its size bound"))
        ));
        assert!(read_record(&b""[..], MAX_TOKEN_RECORD_BYTES)
            .unwrap()
            .is_empty());
        let slow = Trickle {
            rest: b"hvs.x",
            interrupted: false,
        };
        assert!(read_record(slow, 8).unwrap().as_slice() == b"hvs.x");
        assert!(matches!(
            read_record(BrokenOnce(false), 8),
            Err(VaultError::TokenUnreadable(_))
        ));
    }
}
