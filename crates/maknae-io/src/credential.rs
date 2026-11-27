use std::fmt;
use std::io;

use zeroize::Zeroizing;

use crate::filter::{FilterError, Source, ValueFilter};
use crate::{MaknaeSecret, MaknaeSecretBytes, SecretError, MAX_SECRET_BYTES};

/// A credential a front end holds to deliver to a tool. It never prints, copies or compares,
/// and its only encoding is the frame `deliver_to` and `send` write (#751).
///
/// ```
/// use maknae_io::{MaknaeSecretBytes, Zeroizing};
/// let c = MaknaeSecretBytes::new(Zeroizing::new(b"t".to_vec())).unwrap().into_delivered();
/// let _ = format!("{c:?}");
/// ```
///
/// ```compile_fail,E0277
/// use maknae_io::{MaknaeSecretBytes, Zeroizing};
/// let c = MaknaeSecretBytes::new(Zeroizing::new(b"t".to_vec())).unwrap().into_delivered();
/// let _ = format!("{c}");
/// ```
///
/// ```compile_fail,E0599
/// use maknae_io::{MaknaeSecretBytes, Zeroizing};
/// let c = MaknaeSecretBytes::new(Zeroizing::new(b"t".to_vec())).unwrap().into_delivered();
/// let _ = c.clone();
/// ```
///
/// ```compile_fail,E0616
/// use maknae_io::{MaknaeSecretBytes, Zeroizing};
/// let c = MaknaeSecretBytes::new(Zeroizing::new(b"t".to_vec())).unwrap().into_delivered();
/// let _ = &c.0;
/// ```
///
/// ```compile_fail,E0624
/// use maknae_io::{MaknaeSecretBytes, Zeroizing};
/// let c = MaknaeSecretBytes::new(Zeroizing::new(b"t".to_vec())).unwrap().into_delivered();
/// let _ = c.expose();
/// ```
///
/// ```compile_fail,E0369
/// use maknae_io::{MaknaeSecretBytes, Zeroizing};
/// let c = MaknaeSecretBytes::new(Zeroizing::new(b"t".to_vec())).unwrap().into_delivered();
/// let _ = c == c;
/// ```
///
/// ```compile_fail,E0277
/// use maknae_io::{MaknaeSecretBytes, Zeroizing};
/// let c = MaknaeSecretBytes::new(Zeroizing::new(b"t".to_vec())).unwrap().into_delivered();
/// let _ = serde_json::to_string(&c);
/// ```
///
/// ```
/// use maknae_io::{MaknaeSecretBytes, Zeroizing};
/// let c = MaknaeSecretBytes::new(Zeroizing::new(b"t".to_vec())).unwrap().into_delivered();
/// let _ = c;
/// ```
///
/// ```compile_fail,E0599
/// use maknae_io::{MaknaeSecretBytes, Zeroizing};
/// let c = MaknaeSecretBytes::new(Zeroizing::new(b"t".to_vec())).unwrap().into_delivered();
/// let _ = c.into_secret();
/// ```
pub struct DeliveredCredential(MaknaeSecretBytes);

impl MaknaeSecret<String> {
    pub fn into_delivered(self) -> DeliveredCredential {
        DeliveredCredential(self.into_utf8_bytes())
    }
}

impl MaknaeSecretBytes {
    pub fn into_delivered(self) -> DeliveredCredential {
        DeliveredCredential(self)
    }
}

impl DeliveredCredential {
    fn expose(&self) -> &[u8] {
        self.0.expose()
    }
}

impl fmt::Debug for DeliveredCredential {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("DeliveredCredential(<redacted>)")
    }
}

pub const MAX_CREDENTIALS: usize = 16;
const MAX_NAME: usize = 64;
const FRAME_TAG: &[u8; 4] = b"MKLC";
const TAG_ENV: u8 = 1;
const TAG_GIT: u8 = 2;
const TAG_CARGO: u8 = 3;
const TAG_NETRC: u8 = 4;
const TAG_FILE: u8 = 5;
const HIJACK_ENV: [&str; 40] = [
    "PATH",
    "HOME",
    "TMPDIR",
    "BASH_ENV",
    "ENV",
    "IFS",
    "SHELLOPTS",
    "PS4",
    "PROMPT_COMMAND",
    "GCONV_PATH",
    "NODE_OPTIONS",
    "PYTHONPATH",
    "PYTHONSTARTUP",
    "PERL5OPT",
    "PERL5LIB",
    "RUBYOPT",
    "RUBYLIB",
    "JAVA_TOOL_OPTIONS",
    "GIT_SSH_COMMAND",
    "GIT_EXEC_PATH",
    "GIT_CONFIG_GLOBAL",
    "GIT_ASKPASS",
    "SSH_ASKPASS",
    "GIT_PROXY_COMMAND",
    "GIT_EXTERNAL_DIFF",
    "GIT_PAGER",
    "PAGER",
    "EDITOR",
    "VISUAL",
    "RUSTC_WRAPPER",
    "CARGO_BUILD_RUSTC_WRAPPER",
    "RUSTFLAGS",
    "PYTHONHOME",
    "NODE_PATH",
    "ZDOTDIR",
    "GIT_CONFIG",
    "HTTP_PROXY",
    "HTTPS_PROXY",
    "ALL_PROXY",
    "NO_PROXY",
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
        let prefixed = ["LD_", "DYLD_", "MALLOC_", "GIT_CONFIG_"]
            .iter()
            .any(|p| name.starts_with(p));
        if prefixed || HIJACK_ENV.contains(&name) {
            return Err(SlotError::Refused);
        }
        Ok(Self::EnvVar(EnvVarName(name.to_owned())))
    }

    pub fn file(name: &str) -> Result<Self, SlotError> {
        let charset = name
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'-'));
        if name.is_empty() || name.len() > MAX_NAME || !charset || name.starts_with(['.', '-']) {
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
/// use maknae_io::credential::{CredentialSlot, LaunchCredentials};
/// use maknae_io::{MaknaeSecretBytes, Zeroizing};
/// let mut lc = LaunchCredentials::new([0; 16]);
/// let c = MaknaeSecretBytes::new(Zeroizing::new(b"t".to_vec())).unwrap().into_delivered();
/// c.deliver_to(&mut lc, CredentialSlot::Netrc).unwrap();
/// let _ = format!("{lc:?}");
/// ```
///
/// ```compile_fail,E0624
/// use maknae_io::credential::{CredentialSlot, LaunchCredentials};
/// use maknae_io::{MaknaeSecretBytes, Zeroizing};
/// let mut lc = LaunchCredentials::new([0; 16]);
/// let c = MaknaeSecretBytes::new(Zeroizing::new(b"t".to_vec())).unwrap().into_delivered();
/// c.deliver_to(&mut lc, CredentialSlot::Netrc).unwrap();
/// let _ = lc.encode();
/// ```
///
/// ```compile_fail,E0277
/// use maknae_io::credential::{CredentialSlot, LaunchCredentials};
/// use maknae_io::{MaknaeSecretBytes, Zeroizing};
/// let mut lc = LaunchCredentials::new([0; 16]);
/// let c = MaknaeSecretBytes::new(Zeroizing::new(b"t".to_vec())).unwrap().into_delivered();
/// c.deliver_to(&mut lc, CredentialSlot::Netrc).unwrap();
/// let _ = format!("{lc}");
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
pub(crate) const MAX_FRAME: usize =
    4 + 16 + 1 + MAX_CREDENTIALS * (2 + MAX_NAME + 4 + MAX_SECRET_BYTES);

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

    pub fn value_filter(&self) -> Result<ValueFilter, FilterError> {
        let mut builder = ValueFilter::builder();
        for (slot, credential) in &self.entries {
            builder = match slot {
                CredentialSlot::EnvVar(_) => {
                    builder.source(Source::Slot(slot.clone()), credential.expose())
                }
                CredentialSlot::GitCredentialHelper
                | CredentialSlot::CargoCredentialProvider
                | CredentialSlot::Netrc
                | CredentialSlot::File(_) => builder.skip(),
            };
        }
        builder.build()
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
            if value_len > MAX_SECRET_BYTES {
                return Err(DecodeError::ValueTooLong);
            }
            if value_len == 0 {
                return Err(DecodeError::EmptyValue);
            }
            let value = Zeroizing::new(r.take(value_len)?.to_vec());
            let cred = MaknaeSecretBytes::new(value)
                .map_err(|_: SecretError| DecodeError::Process)?
                .into_delivered();
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
    use crate::filter::{LeakHook, Screened};
    use rustix::process::{getrlimit, Resource};
    use zeroize::Zeroizing;

    const SENTINEL: &str = "hunter2-sentinel-751";

    fn cred() -> DeliveredCredential {
        MaknaeSecretBytes::new(Zeroizing::new(SENTINEL.as_bytes().to_vec()))
            .unwrap()
            .into_delivered()
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
    fn a_text_secret_becomes_a_delivered_credential_without_a_copy() {
        let text = Zeroizing::new(SENTINEL.to_owned());
        let at = text.as_ptr();
        let c = MaknaeSecret::new(text).unwrap().into_delivered();
        assert_eq!(c.expose(), SENTINEL.as_bytes());
        assert_eq!(c.expose().as_ptr(), at);
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
        MaknaeSecretBytes::new(Zeroizing::new(b"netrc-body".to_vec()))
            .unwrap()
            .into_delivered()
            .deliver_to(&mut lc, CredentialSlot::Netrc)
            .unwrap();
        MaknaeSecretBytes::new(Zeroizing::new(b"file-body".to_vec()))
            .unwrap()
            .into_delivered()
            .deliver_to(&mut lc, CredentialSlot::file("token.txt").unwrap())
            .unwrap();
        lc
    }

    const GH: &[u8] = b"ghp_AAAAaaaa1111BBBBbbbb2222CCCC";
    const NPM: &[u8] = b"npm_ZZZZzzzz9999YYYYyyyy8888XXXX";

    #[derive(Default)]
    struct Recorder {
        calls: usize,
        seen: Vec<Source>,
    }

    impl LeakHook for Recorder {
        fn leaked(&mut self, sources: &[Source]) {
            self.calls += 1;
            self.seen.clear();
            self.seen.extend_from_slice(sources);
        }
    }

    fn deliver(lc: &mut LaunchCredentials, slot: CredentialSlot, value: &[u8]) {
        MaknaeSecretBytes::new(Zeroizing::new(value.to_vec()))
            .unwrap()
            .into_delivered()
            .deliver_to(lc, slot)
            .unwrap();
    }

    fn two_env() -> LaunchCredentials {
        let mut lc = LaunchCredentials::new([0; 16]);
        deliver(&mut lc, slot_env("GH_TOKEN"), GH);
        deliver(&mut lc, slot_env("NPM_TOKEN"), NPM);
        lc
    }

    fn output(parts: &[&[u8]]) -> Zeroizing<Vec<u8>> {
        Zeroizing::new(parts.concat())
    }

    fn screened(lc: &LaunchCredentials, out: Zeroizing<Vec<u8>>) -> (Screened, Recorder) {
        let mut rec = Recorder::default();
        let s = lc.value_filter().unwrap().screen(out, &mut rec);
        (s, rec)
    }

    #[test]
    fn output_echoing_one_credential_is_withheld_and_its_slot_reported() {
        let lc = two_env();
        for (value, name) in [(GH, "GH_TOKEN"), (NPM, "NPM_TOKEN")] {
            let out = output(&[b"token is ", value, b"\n"]);
            let len = out.len();
            let (s, rec) = screened(&lc, out);
            assert_eq!(s, Screened::Withheld { len });
            assert_eq!(rec.calls, 1);
            assert_eq!(rec.seen, [Source::Slot(slot_env(name))]);
            let shown = format!("{:?}", rec.seen);
            assert!(!shown.contains(std::str::from_utf8(&value[..16]).unwrap()));
        }
    }

    #[test]
    fn two_credentials_in_one_output_are_reported_once_in_one_call() {
        let (s, rec) = screened(&two_env(), output(&[NPM, b" ", GH, b" ", NPM, GH]));
        assert_eq!(
            s,
            Screened::Withheld {
                len: 2 * (GH.len() + NPM.len()) + 2
            }
        );
        assert_eq!(rec.calls, 1);
        assert_eq!(
            rec.seen,
            [
                Source::Slot(slot_env("NPM_TOKEN")),
                Source::Slot(slot_env("GH_TOKEN"))
            ]
        );
    }

    #[test]
    fn clean_output_is_returned_unchanged_and_not_reported() {
        let out = output(&[b"ok ", &GH[..15], b" ", &NPM[1..16], b" done"]);
        let expected = out.to_vec();
        let at = out.as_ptr();
        let (s, rec) = screened(&two_env(), out);
        let Screened::Clean(back) = s else {
            panic!("withheld clean output");
        };
        assert_eq!(*back, expected);
        assert_eq!(back.as_ptr(), at);
        assert_eq!(rec.calls, 0);
        assert!(rec.seen.is_empty());
    }

    #[test]
    fn output_ending_in_a_value_s_prefix_is_clean() {
        let lc = two_env();
        for n in [1, 15] {
            let (s, rec) = screened(&lc, output(&[b"partial ", &GH[..n]]));
            assert!(matches!(s, Screened::Clean(_)), "{n}");
            assert_eq!(rec.calls, 0, "{n}");
        }
    }

    #[test]
    fn slots_other_than_env_vars_are_skipped_and_counted() {
        let others = [
            (
                CredentialSlot::GitCredentialHelper,
                &b"protocol=https host=example password=gitHELPERsecret0001"[..],
            ),
            (
                CredentialSlot::CargoCredentialProvider,
                &b"cargoPROVIDERsecret0002cargoPROVIDER"[..],
            ),
            (
                CredentialSlot::Netrc,
                &b"machine example login u password netrcSECRET0003"[..],
            ),
            (
                CredentialSlot::file("token.txt").unwrap(),
                &b"fileSLOTsecret0004fileSLOTsecret0004"[..],
            ),
        ];
        for (slot, value) in &others {
            let mut lc = LaunchCredentials::new([0; 16]);
            deliver(&mut lc, slot_env("GH_TOKEN"), GH);
            deliver(&mut lc, slot.clone(), value);
            let f = lc.value_filter().unwrap();
            assert_eq!(f.skipped(), 1, "{slot:?}");
            let mut rec = Recorder::default();
            let s = f.screen(output(&[b"echo ", value]), &mut rec);
            assert!(matches!(s, Screened::Clean(_)), "{slot:?}");
            assert_eq!(rec.calls, 0, "{slot:?}");
        }

        assert_eq!(two_env().value_filter().unwrap().skipped(), 0);

        let mut lc = two_env();
        for (slot, value) in &others {
            deliver(&mut lc, slot.clone(), value);
        }
        deliver(&mut lc, slot_env("SHORT"), b"tiny");
        let f = lc.value_filter().unwrap();
        assert_eq!(f.skipped(), 5);
        assert_eq!(format!("{f:?}"), "ValueFilter(2 values)");
    }

    #[test]
    fn an_empty_set_screens_everything_clean() {
        let lc = LaunchCredentials::new([0; 16]);
        let (s, rec) = screened(&lc, output(&[GH]));
        assert_eq!(s, Screened::Clean(output(&[GH])));
        assert_eq!(rec.calls, 0);
    }

    #[test]
    fn env_var_names_are_validated_and_hijack_names_refused() {
        for ok in ["GH_TOKEN", "_X", "A1", &"A".repeat(64)] {
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
            "MALLOC_CONF",
            "GIT_CONFIG_COUNT",
            "HOME",
            "NODE_OPTIONS",
            "PYTHONPATH",
            "GIT_SSH_COMMAND",
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
        for ok in ["token.txt", "a", "x-y_z.1", &"a".repeat(64)] {
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
        too_long[at..at + 4].copy_from_slice(&(MAX_SECRET_BYTES as u32 + 1).to_be_bytes());
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
            (
                "bad file name",
                {
                    let mut b = one_env(b"../x", b"v");
                    b[21] = TAG_FILE;
                    b
                },
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

    fn largest() -> LaunchCredentials {
        let mut lc = LaunchCredentials::new([1; 16]);
        for i in 0..MAX_CREDENTIALS {
            let name = format!("T{i:02}{}", "A".repeat(MAX_NAME - 3));
            MaknaeSecretBytes::new(Zeroizing::new(vec![b'v'; MAX_SECRET_BYTES]))
                .unwrap()
                .into_delivered()
                .deliver_to(&mut lc, CredentialSlot::env_var(&name).unwrap())
                .unwrap();
        }
        lc
    }

    #[test]
    fn the_largest_bundle_encodes_to_exactly_the_frame_bound_and_decodes() {
        let bytes = largest().encode();
        assert_eq!(bytes.len(), MAX_FRAME);
        let back = LaunchCredentials::decode(&bytes).unwrap();
        assert_eq!(back.slots().count(), MAX_CREDENTIALS);
    }

    #[test]
    fn every_nameless_slot_round_trips() {
        let mut lc = LaunchCredentials::new([2; 16]);
        for slot in [
            CredentialSlot::GitCredentialHelper,
            CredentialSlot::CargoCredentialProvider,
            CredentialSlot::Netrc,
        ] {
            cred().deliver_to(&mut lc, slot).unwrap();
        }
        let back = LaunchCredentials::decode(&lc.encode()).unwrap();
        assert_eq!(
            back.slots().collect::<Vec<_>>(),
            lc.slots().collect::<Vec<_>>()
        );
    }

    #[test]
    fn the_largest_frame_travels_over_a_socket() {
        let (mut a, mut b) = std::os::unix::net::UnixStream::pair().unwrap();
        for s in [&a, &b] {
            s.set_read_timeout(Some(std::time::Duration::from_secs(5)))
                .unwrap();
            s.set_write_timeout(Some(std::time::Duration::from_secs(5)))
                .unwrap();
        }
        let sender = std::thread::spawn(move || largest().send(&mut a));
        let got = LaunchCredentials::receive(&mut b).unwrap();
        sender.join().unwrap().unwrap();
        assert_eq!(got.slots().count(), MAX_CREDENTIALS);
    }

    #[test]
    fn file_names_that_hide_or_look_like_options_are_refused() {
        for bad in [".netrc", ".git-credentials", ".bashrc", "-rf", "-"] {
            assert_eq!(
                CredentialSlot::file(bad),
                Err(SlotError::InvalidName),
                "{bad}"
            );
        }
    }

    #[test]
    fn more_hijack_names_are_refused() {
        for refused in [
            "GIT_ASKPASS",
            "SSH_ASKPASS",
            "GIT_PROXY_COMMAND",
            "GIT_EXTERNAL_DIFF",
            "GIT_PAGER",
            "PAGER",
            "EDITOR",
            "VISUAL",
            "RUSTC_WRAPPER",
            "CARGO_BUILD_RUSTC_WRAPPER",
            "RUSTFLAGS",
            "PYTHONHOME",
            "NODE_PATH",
            "ZDOTDIR",
            "GIT_CONFIG",
            "HTTP_PROXY",
            "HTTPS_PROXY",
            "ALL_PROXY",
            "NO_PROXY",
        ] {
            assert_eq!(
                CredentialSlot::env_var(refused),
                Err(SlotError::Refused),
                "{refused}"
            );
        }
        assert!(CredentialSlot::env_var("CARGO_REGISTRY_TOKEN").is_ok());
    }
}
