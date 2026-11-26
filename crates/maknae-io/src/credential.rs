use std::fmt;
use std::io;

use zeroize::Zeroizing;

use crate::credential_io::deny_core_dumps;

/// A credential a front end holds to deliver to a tool. It never prints, copies, compares or
/// serializes; it leaves only through `deliver_to` (#751).
///
/// ```
/// use maknae_io::{credential::DeliveredCredential, Zeroizing};
/// let c = DeliveredCredential::new(Zeroizing::new(b"t".to_vec())).unwrap();
/// let _ = format!("{c:?}");
/// ```
///
/// ```compile_fail,E0277
/// use maknae_io::{credential::DeliveredCredential, Zeroizing};
/// let c = DeliveredCredential::new(Zeroizing::new(b"t".to_vec())).unwrap();
/// let _ = format!("{c}");
/// ```
///
/// ```compile_fail,E0599
/// use maknae_io::{credential::DeliveredCredential, Zeroizing};
/// let c = DeliveredCredential::new(Zeroizing::new(b"t".to_vec())).unwrap();
/// let _ = c.clone();
/// ```
///
/// ```compile_fail,E0616
/// use maknae_io::{credential::DeliveredCredential, Zeroizing};
/// let c = DeliveredCredential::new(Zeroizing::new(b"t".to_vec())).unwrap();
/// let _ = &c.0;
/// ```
///
/// ```compile_fail,E0624
/// use maknae_io::{credential::DeliveredCredential, Zeroizing};
/// let c = DeliveredCredential::new(Zeroizing::new(b"t".to_vec())).unwrap();
/// let _ = c.expose();
/// ```
///
/// ```compile_fail,E0369
/// use maknae_io::{credential::DeliveredCredential, Zeroizing};
/// let c = DeliveredCredential::new(Zeroizing::new(b"t".to_vec())).unwrap();
/// let _ = c == c;
/// ```
///
/// ```compile_fail,E0277
/// use maknae_io::{credential::DeliveredCredential, Zeroizing};
/// let c = DeliveredCredential::new(Zeroizing::new(b"t".to_vec())).unwrap();
/// let _ = serde_json::to_string(&c);
/// ```
pub struct DeliveredCredential(Zeroizing<Vec<u8>>);

impl DeliveredCredential {
    pub fn new(secret: Zeroizing<Vec<u8>>) -> io::Result<Self> {
        deny_core_dumps()?;
        Ok(Self(secret))
    }

    pub fn from_secret_string(mut secret: Zeroizing<String>) -> io::Result<Self> {
        Self::new(Zeroizing::new(std::mem::take(&mut *secret).into_bytes()))
    }

    pub(crate) fn expose(&self) -> &[u8] {
        &self.0
    }
}

impl fmt::Debug for DeliveredCredential {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("DeliveredCredential(<redacted>)")
    }
}

pub const MAX_CREDENTIALS: usize = 16;
pub const MAX_VALUE: usize = 65_536;
const MAX_NAME: usize = 64;
const FRAME_TAG: &[u8; 4] = b"MKLC";
const TAG_ENV: u8 = 1;
const TAG_GIT: u8 = 2;
const TAG_CARGO: u8 = 3;
const TAG_NETRC: u8 = 4;
const TAG_FILE: u8 = 5;
const HIJACK_ENV: [&str; 7] = [
    "PATH",
    "BASH_ENV",
    "ENV",
    "IFS",
    "SHELLOPTS",
    "PS4",
    "PROMPT_COMMAND",
];

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct EnvVarName(String);

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FileName(String);

/// Where a delivered credential is placed: a plug-in point the tool already supports
/// (ADR-0036 decision 13). The names are validated when the slot is built.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum CredentialSlot {
    EnvVar(EnvVarName),
    GitCredentialHelper,
    CargoCredentialProvider,
    Netrc,
    File(FileName),
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SlotError {
    InvalidName,
    Refused,
}

impl CredentialSlot {
    /// A loader or shell variable is refused; the bound that matters is the signed
    /// obligation naming the slot (#755).
    pub fn env_var(name: &str) -> Result<Self, SlotError> {
        let mut bytes = name.bytes();
        let first_ok = matches!(bytes.next(), Some(b'A'..=b'Z' | b'_'));
        if !first_ok
            || name.len() > MAX_NAME
            || !bytes.all(|b| matches!(b, b'A'..=b'Z' | b'0'..=b'9' | b'_'))
        {
            return Err(SlotError::InvalidName);
        }
        if name.starts_with("LD_") || name.starts_with("DYLD_") || HIJACK_ENV.contains(&name) {
            return Err(SlotError::Refused);
        }
        Ok(Self::EnvVar(EnvVarName(name.to_owned())))
    }

    pub fn file(name: &str) -> Result<Self, SlotError> {
        let charset = name
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'-'));
        if name.is_empty() || name.len() > MAX_NAME || !charset || name == "." || name == ".." {
            return Err(SlotError::InvalidName);
        }
        Ok(Self::File(FileName(name.to_owned())))
    }

    fn tag(&self) -> u8 {
        match self {
            Self::EnvVar(_) => TAG_ENV,
            Self::GitCredentialHelper => TAG_GIT,
            Self::CargoCredentialProvider => TAG_CARGO,
            Self::Netrc => TAG_NETRC,
            Self::File(_) => TAG_FILE,
        }
    }

    fn name(&self) -> &str {
        match self {
            Self::EnvVar(EnvVarName(n)) | Self::File(FileName(n)) => n,
            Self::GitCredentialHelper | Self::CargoCredentialProvider | Self::Netrc => "",
        }
    }

    fn from_wire(tag: u8, name: &[u8]) -> Result<Self, DecodeError> {
        let named = |f: fn(&str) -> Result<Self, SlotError>| {
            std::str::from_utf8(name)
                .ok()
                .and_then(|n| f(n).ok())
                .ok_or(DecodeError::BadName)
        };
        let nameless = |slot: Self| {
            if name.is_empty() {
                Ok(slot)
            } else {
                Err(DecodeError::BadName)
            }
        };
        match tag {
            TAG_ENV => named(Self::env_var),
            TAG_GIT => nameless(Self::GitCredentialHelper),
            TAG_CARGO => nameless(Self::CargoCredentialProvider),
            TAG_NETRC => nameless(Self::Netrc),
            TAG_FILE => named(Self::file),
            _ => Err(DecodeError::BadSlotTag),
        }
    }
}

/// The credentials half of a launch request: they travel beside the signed obligation,
/// bound by its invocation id (ADR-0036, amendment 2026-11-27, statement 2).
///
/// ```
/// use maknae_io::credential::{CredentialSlot, DeliveredCredential, LaunchCredentials};
/// use maknae_io::Zeroizing;
/// let mut lc = LaunchCredentials::new([0; 16]);
/// let c = DeliveredCredential::new(Zeroizing::new(b"t".to_vec())).unwrap();
/// c.deliver_to(&mut lc, CredentialSlot::Netrc).unwrap();
/// let _ = format!("{lc:?}");
/// ```
///
/// ```compile_fail,E0624
/// use maknae_io::credential::{CredentialSlot, DeliveredCredential, LaunchCredentials};
/// use maknae_io::Zeroizing;
/// let mut lc = LaunchCredentials::new([0; 16]);
/// let c = DeliveredCredential::new(Zeroizing::new(b"t".to_vec())).unwrap();
/// c.deliver_to(&mut lc, CredentialSlot::Netrc).unwrap();
/// let _ = lc.encode();
/// ```
pub struct LaunchCredentials {
    invocation: [u8; 16],
    entries: Vec<(CredentialSlot, DeliveredCredential)>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DeliverErrorKind {
    DuplicateSlot,
    TooMany,
}

#[derive(Debug)]
pub struct DeliverError {
    kind: DeliverErrorKind,
    credential: DeliveredCredential,
}

impl DeliverError {
    pub fn kind(&self) -> DeliverErrorKind {
        self.kind
    }

    pub fn into_credential(self) -> DeliveredCredential {
        self.credential
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DecodeError {
    Truncated,
    BadTag,
    TooMany,
    BadSlotTag,
    BadName,
    ValueTooLong,
    EmptyValue,
    DuplicateSlot,
    Trailing,
    Process,
}

/// One frame: the 4-byte tag, the invocation, the count, and at most `MAX_CREDENTIALS`
/// entries of a tag, a name, a length and the value.
pub(crate) const MAX_FRAME: usize = 4 + 16 + 1 + MAX_CREDENTIALS * (2 + MAX_NAME + 4 + MAX_VALUE);

#[derive(Debug)]
pub enum ReceiveError {
    NotBlocking,
    NoTimeout,
    TooLong,
    Io(io::Error),
    Decode(DecodeError),
}

impl DeliveredCredential {
    pub fn deliver_to(
        self,
        into: &mut LaunchCredentials,
        slot: CredentialSlot,
    ) -> Result<(), DeliverError> {
        let kind = if into.entries.iter().any(|(s, _)| *s == slot) {
            DeliverErrorKind::DuplicateSlot
        } else if into.entries.len() >= MAX_CREDENTIALS {
            DeliverErrorKind::TooMany
        } else {
            into.entries.push((slot, self));
            return Ok(());
        };
        Err(DeliverError {
            kind,
            credential: self,
        })
    }
}

impl LaunchCredentials {
    pub fn new(invocation: [u8; 16]) -> Self {
        Self {
            invocation,
            entries: Vec::new(),
        }
    }

    pub fn invocation(&self) -> [u8; 16] {
        self.invocation
    }

    pub fn slots(&self) -> impl Iterator<Item = &CredentialSlot> {
        self.entries.iter().map(|(slot, _)| slot)
    }

    pub(crate) fn encode(&self) -> Zeroizing<Vec<u8>> {
        let len = FRAME_TAG.len()
            + self.invocation.len()
            + 1
            + self
                .entries
                .iter()
                .map(|(s, c)| 2 + s.name().len() + 4 + c.expose().len())
                .sum::<usize>();
        let mut out = Zeroizing::new(Vec::with_capacity(len));
        out.extend_from_slice(FRAME_TAG);
        out.extend_from_slice(&self.invocation);
        out.push(self.entries.len() as u8);
        for (slot, cred) in &self.entries {
            out.push(slot.tag());
            out.push(slot.name().len() as u8);
            out.extend_from_slice(slot.name().as_bytes());
            out.extend_from_slice(&(cred.expose().len() as u32).to_be_bytes());
            out.extend_from_slice(cred.expose());
        }
        out
    }

    pub(crate) fn decode(bytes: &[u8]) -> Result<Self, DecodeError> {
        let mut r = Reader(bytes);
        if r.take(FRAME_TAG.len())? != FRAME_TAG {
            return Err(DecodeError::BadTag);
        }
        let invocation: [u8; 16] = r.take(16)?.try_into().map_err(|_| DecodeError::Truncated)?;
        let count = usize::from(r.byte()?);
        if count > MAX_CREDENTIALS {
            return Err(DecodeError::TooMany);
        }
        let mut lc = Self::new(invocation);
        for _ in 0..count {
            let tag = r.byte()?;
            let name_len = usize::from(r.byte()?);
            let slot = CredentialSlot::from_wire(tag, r.take(name_len)?)?;
            let value_len =
                u32::from_be_bytes(r.take(4)?.try_into().map_err(|_| DecodeError::Truncated)?)
                    as usize;
            if value_len > MAX_VALUE {
                return Err(DecodeError::ValueTooLong);
            }
            if value_len == 0 {
                return Err(DecodeError::EmptyValue);
            }
            let value = Zeroizing::new(r.take(value_len)?.to_vec());
            let cred = DeliveredCredential::new(value).map_err(|_| DecodeError::Process)?;
            cred.deliver_to(&mut lc, slot).map_err(|e| match e.kind() {
                DeliverErrorKind::DuplicateSlot => DecodeError::DuplicateSlot,
                DeliverErrorKind::TooMany => DecodeError::TooMany,
            })?;
        }
        if !r.0.is_empty() {
            return Err(DecodeError::Trailing);
        }
        Ok(lc)
    }
}

impl fmt::Debug for LaunchCredentials {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("LaunchCredentials")
            .field("slots", &self.slots().collect::<Vec<_>>())
            .finish_non_exhaustive()
    }
}

struct Reader<'a>(&'a [u8]);

impl<'a> Reader<'a> {
    fn take(&mut self, n: usize) -> Result<&'a [u8], DecodeError> {
        if self.0.len() < n {
            return Err(DecodeError::Truncated);
        }
        let (head, rest) = self.0.split_at(n);
        self.0 = rest;
        Ok(head)
    }

    fn byte(&mut self) -> Result<u8, DecodeError> {
        Ok(self.take(1)?[0])
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rustix::process::{getrlimit, Resource};
    use zeroize::Zeroizing;

    const SENTINEL: &str = "hunter2-sentinel-751";

    fn cred() -> DeliveredCredential {
        DeliveredCredential::new(Zeroizing::new(SENTINEL.as_bytes().to_vec())).unwrap()
    }

    #[test]
    fn debug_prints_the_marker_only() {
        let shown = format!("{:?}", cred());
        assert_eq!(shown, "DeliveredCredential(<redacted>)");
        assert!(!shown.contains("hunter2"));
    }

    #[test]
    fn expose_returns_the_bytes() {
        assert_eq!(cred().expose(), SENTINEL.as_bytes());
    }

    #[test]
    fn from_secret_string_holds_the_same_bytes() {
        let c =
            DeliveredCredential::from_secret_string(Zeroizing::new(SENTINEL.to_owned())).unwrap();
        assert_eq!(c.expose(), SENTINEL.as_bytes());
    }

    #[test]
    fn constructing_one_denies_core_dumps() {
        let _ = cred();
        assert_eq!(getrlimit(Resource::Core).current, Some(0));
        #[cfg(target_os = "linux")]
        assert_eq!(
            rustix::process::dumpable_behavior().unwrap(),
            rustix::process::DumpableBehavior::NotDumpable
        );
    }

    fn slot_env(n: &str) -> CredentialSlot {
        CredentialSlot::env_var(n).unwrap()
    }

    fn sample() -> LaunchCredentials {
        let mut lc = LaunchCredentials::new([7; 16]);
        cred().deliver_to(&mut lc, slot_env("GH_TOKEN")).unwrap();
        DeliveredCredential::new(Zeroizing::new(b"netrc-body".to_vec()))
            .unwrap()
            .deliver_to(&mut lc, CredentialSlot::Netrc)
            .unwrap();
        DeliveredCredential::new(Zeroizing::new(b"file-body".to_vec()))
            .unwrap()
            .deliver_to(&mut lc, CredentialSlot::file("token.txt").unwrap())
            .unwrap();
        lc
    }

    #[test]
    fn env_var_names_are_validated_and_hijack_names_refused() {
        for ok in ["GH_TOKEN", "_X", "A1"] {
            assert!(CredentialSlot::env_var(ok).is_ok(), "{ok}");
        }
        for bad in ["", "gh_token", "1A", "A-B", &"A".repeat(65)] {
            assert_eq!(
                CredentialSlot::env_var(bad),
                Err(SlotError::InvalidName),
                "{bad}"
            );
        }
        for refused in [
            "LD_PRELOAD",
            "LD_LIBRARY_PATH",
            "DYLD_INSERT_LIBRARIES",
            "PATH",
            "BASH_ENV",
            "ENV",
            "IFS",
            "SHELLOPTS",
            "PS4",
        ] {
            assert_eq!(
                CredentialSlot::env_var(refused),
                Err(SlotError::Refused),
                "{refused}"
            );
        }
    }

    #[test]
    fn file_names_are_validated() {
        for ok in ["token.txt", "a", "x-y_z.1"] {
            assert!(CredentialSlot::file(ok).is_ok(), "{ok}");
        }
        for bad in ["", ".", "..", "a/b", "../x", "a b", &"a".repeat(65)] {
            assert_eq!(
                CredentialSlot::file(bad),
                Err(SlotError::InvalidName),
                "{bad}"
            );
        }
    }

    #[test]
    fn deliver_to_refuses_a_duplicate_slot_and_returns_the_credential() {
        let mut lc = sample();
        let err = cred()
            .deliver_to(&mut lc, CredentialSlot::Netrc)
            .unwrap_err();
        assert_eq!(err.kind(), DeliverErrorKind::DuplicateSlot);
        assert_eq!(err.into_credential().expose(), SENTINEL.as_bytes());
    }

    #[test]
    fn deliver_to_refuses_the_seventeenth() {
        let mut lc = LaunchCredentials::new([0; 16]);
        for i in 0..MAX_CREDENTIALS {
            cred()
                .deliver_to(&mut lc, slot_env(&format!("T{i}")))
                .unwrap();
        }
        let err = cred().deliver_to(&mut lc, slot_env("T99")).unwrap_err();
        assert_eq!(err.kind(), DeliverErrorKind::TooMany);
    }

    #[test]
    fn encode_then_decode_returns_the_same_invocation_slots_and_values() {
        let lc = sample();
        let back = LaunchCredentials::decode(&lc.encode()).unwrap();
        assert_eq!(back.invocation(), [7; 16]);
        assert_eq!(
            back.slots().collect::<Vec<_>>(),
            lc.slots().collect::<Vec<_>>()
        );
        let values = |l: &LaunchCredentials| {
            l.entries
                .iter()
                .map(|(_, c)| c.expose().to_vec())
                .collect::<Vec<_>>()
        };
        assert_eq!(values(&back), values(&lc));
    }

    #[test]
    fn encode_allocates_exactly_once() {
        let bytes = sample().encode();
        assert_eq!(bytes.capacity(), bytes.len());
    }

    #[test]
    fn launch_credentials_debug_shows_slots_never_values() {
        let shown = format!("{:?}", sample());
        assert!(shown.contains("GH_TOKEN") && shown.contains("Netrc"));
        assert!(
            !shown.contains("hunter2")
                && !shown.contains("netrc-body")
                && !shown.contains("file-body")
        );
    }

    fn one_env(name: &[u8], value: &[u8]) -> Vec<u8> {
        let mut b = b"MKLC".to_vec();
        b.extend_from_slice(&[3; 16]);
        b.push(1);
        b.push(TAG_ENV);
        b.push(name.len() as u8);
        b.extend_from_slice(name);
        b.extend_from_slice(&(value.len() as u32).to_be_bytes());
        b.extend_from_slice(value);
        b
    }

    #[test]
    fn decode_refuses_each_malformed_input_with_its_reason() {
        assert!(LaunchCredentials::decode(&one_env(b"GH_TOKEN", b"v")).is_ok());
        let mut bad_tag = one_env(b"GH_TOKEN", b"v");
        bad_tag[0] = b'X';
        let mut count17 = one_env(b"GH_TOKEN", b"v");
        count17[20] = 17;
        let mut slot_tag = one_env(b"GH_TOKEN", b"v");
        slot_tag[21] = 99;
        let mut named_netrc = one_env(b"GH_TOKEN", b"v");
        named_netrc[21] = TAG_NETRC;
        let mut too_long = one_env(b"GH_TOKEN", b"v");
        let at = 21 + 2 + 8;
        too_long[at..at + 4].copy_from_slice(&(MAX_VALUE as u32 + 1).to_be_bytes());
        let mut trailing = one_env(b"GH_TOKEN", b"v");
        trailing.push(0);
        let mut dup = one_env(b"GH_TOKEN", b"v");
        dup[20] = 2;
        dup.extend_from_slice(&one_env(b"GH_TOKEN", b"w")[21..]);
        let cases: Vec<(&str, Vec<u8>, DecodeError)> = vec![
            ("bad tag", bad_tag, DecodeError::BadTag),
            ("count 17", count17, DecodeError::TooMany),
            ("unknown slot tag", slot_tag, DecodeError::BadSlotTag),
            (
                "a name on a nameless slot",
                named_netrc,
                DecodeError::BadName,
            ),
            ("value over the max", too_long, DecodeError::ValueTooLong),
            (
                "empty value",
                one_env(b"GH_TOKEN", b""),
                DecodeError::EmptyValue,
            ),
            ("trailing byte", trailing, DecodeError::Trailing),
            ("duplicate slot", dup, DecodeError::DuplicateSlot),
            (
                "bad env name",
                one_env(b"gh-token", b"v"),
                DecodeError::BadName,
            ),
            (
                "hijack env name",
                one_env(b"LD_PRELOAD", b"v"),
                DecodeError::BadName,
            ),
        ];
        for (what, bytes, want) in cases {
            assert_eq!(
                LaunchCredentials::decode(&bytes).unwrap_err(),
                want,
                "{what}"
            );
        }
        let good = one_env(b"GH_TOKEN", b"v");
        for cut in 0..good.len() {
            assert_eq!(
                LaunchCredentials::decode(&good[..cut]).unwrap_err(),
                DecodeError::Truncated,
                "cut at {cut}"
            );
        }
    }

    #[test]
    fn decode_never_panics_on_arbitrary_bytes() {
        let good = sample().encode().to_vec();
        for i in 0..good.len() {
            for flip in [0x00u8, 0x01, 0x7f, 0x80, 0xff] {
                let mut b = good.clone();
                b[i] ^= flip;
                let _ = LaunchCredentials::decode(&b);
            }
        }
    }
}
