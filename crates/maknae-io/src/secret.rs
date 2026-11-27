use std::fmt;
use std::io;

use serde::de::{Deserialize, Deserializer, Error as _, Visitor};
use zeroize::{Zeroize, Zeroizing};

pub const MAX_SECRET_BYTES: usize = 65_536;
const MAX_VAULT_TOKEN_BYTES: usize = 1024;

mod sealed {
    pub trait Sealed {
        fn bytes(&self) -> &[u8];
        fn len_ok(&self) -> Result<(), crate::SecretError>;
    }
}

/// A storage form a `MaknaeSecret` can hold: `String`, `Vec<u8>` or `[u8; N]`.
pub trait SecretBuf: sealed::Sealed + Zeroize {}

fn within_limit(len: usize) -> Result<(), SecretError> {
    match len {
        0 => Err(SecretError::Empty),
        1..=MAX_SECRET_BYTES => Ok(()),
        _ => Err(SecretError::TooLong),
    }
}

impl sealed::Sealed for String {
    fn bytes(&self) -> &[u8] {
        self.as_bytes()
    }

    fn len_ok(&self) -> Result<(), SecretError> {
        within_limit(self.len())
    }
}

impl SecretBuf for String {}

impl sealed::Sealed for Vec<u8> {
    fn bytes(&self) -> &[u8] {
        self
    }

    fn len_ok(&self) -> Result<(), SecretError> {
        within_limit(self.len())
    }
}

impl SecretBuf for Vec<u8> {}

impl<const N: usize> sealed::Sealed for [u8; N] {
    fn bytes(&self) -> &[u8] {
        self
    }

    fn len_ok(&self) -> Result<(), SecretError> {
        if N == 0 {
            Err(SecretError::Empty)
        } else {
            Ok(())
        }
    }
}

impl<const N: usize> SecretBuf for [u8; N] {}

#[derive(Debug)]
#[non_exhaustive]
pub enum SecretError {
    Empty,
    TooLong,
    NotAVaultToken,
    NotUtf8,
    CoreDumps(io::Error),
}

impl SecretError {
    pub fn why(&self) -> &'static str {
        match self {
            Self::Empty => "is empty",
            Self::TooLong => "is longer than its limit",
            Self::NotAVaultToken => "has a character outside [A-Za-z0-9._-]",
            Self::NotUtf8 => "is not UTF-8",
            Self::CoreDumps(_) => "core dumps could not be denied",
        }
    }
}

impl fmt::Display for SecretError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.why())
    }
}

impl std::error::Error for SecretError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::CoreDumps(e) => Some(e),
            _ => None,
        }
    }
}

/// A secret held in a buffer wiped on drop. It never prints, copies, compares or
/// serializes, and building one denies core dumps for the process (#752).
///
/// ```
/// use maknae_io::{MaknaeSecret, SecretBuf, Zeroizing};
/// let s = MaknaeSecret::new(Zeroizing::new(String::from("t"))).unwrap();
/// let _ = format!("{s:?}");
/// let _ = s.expose();
/// let _ = MaknaeSecret::new(Zeroizing::new([1u8; 1])).unwrap();
/// fn holds<B: SecretBuf>() {}
/// holds::<String>();
/// let _ = serde_json::to_string(&1);
/// struct Mine(Vec<u8>);
/// impl zeroize::Zeroize for Mine {
///     fn zeroize(&mut self) {
///         self.0.zeroize();
///     }
/// }
/// ```
///
/// ```compile_fail,E0277
/// use maknae_io::{MaknaeSecret, Zeroizing};
/// let s = MaknaeSecret::new(Zeroizing::new(String::from("t"))).unwrap();
/// let _ = format!("{s}");
/// ```
///
/// ```compile_fail,E0599
/// use maknae_io::{MaknaeSecret, Zeroizing};
/// let s = MaknaeSecret::new(Zeroizing::new(String::from("t"))).unwrap();
/// let _ = s.clone();
/// ```
///
/// ```compile_fail,E0369
/// use maknae_io::{MaknaeSecret, Zeroizing};
/// let s = MaknaeSecret::new(Zeroizing::new(String::from("t"))).unwrap();
/// let _ = s == s;
/// ```
///
/// ```compile_fail,E0277
/// use maknae_io::{MaknaeSecret, Zeroizing};
/// let s = MaknaeSecret::new(Zeroizing::new(String::from("t"))).unwrap();
/// let _ = serde_json::to_string(&s);
/// ```
///
/// ```compile_fail,E0616
/// use maknae_io::{MaknaeSecret, Zeroizing};
/// let s = MaknaeSecret::new(Zeroizing::new(String::from("t"))).unwrap();
/// let _ = &s.0;
/// ```
///
/// ```compile_fail,E0277
/// struct Mine(Vec<u8>);
/// impl zeroize::Zeroize for Mine {
///     fn zeroize(&mut self) {
///         self.0.zeroize();
///     }
/// }
/// impl maknae_io::SecretBuf for Mine {}
/// ```
pub struct MaknaeSecret<B: SecretBuf = String>(Zeroizing<B>);

pub type MaknaeSecretBytes = MaknaeSecret<Vec<u8>>;

impl<B: SecretBuf> MaknaeSecret<B> {
    pub fn new(value: Zeroizing<B>) -> Result<Self, SecretError> {
        crate::deny_core_dumps().map_err(SecretError::CoreDumps)?;
        value.len_ok()?;
        Ok(Self(value))
    }
}

impl MaknaeSecret<String> {
    pub fn vault_token(value: Zeroizing<String>) -> Result<Self, SecretError> {
        let secret = Self::new(value)?;
        if secret.0.len() > MAX_VAULT_TOKEN_BYTES {
            return Err(SecretError::TooLong);
        }
        if !secret
            .0
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'-'))
        {
            return Err(SecretError::NotAVaultToken);
        }
        Ok(secret)
    }

    pub fn from_opened(mut bytes: Zeroizing<Vec<u8>>) -> Result<Self, SecretError> {
        match String::from_utf8(std::mem::take(&mut *bytes)) {
            Ok(s) => Self::vault_token(Zeroizing::new(s)),
            Err(e) => {
                let _wiped = Zeroizing::new(e.into_bytes());
                Err(SecretError::NotUtf8)
            }
        }
    }

    pub fn expose(&self) -> &str {
        &self.0
    }
}

impl MaknaeSecret<Vec<u8>> {
    pub fn expose(&self) -> &[u8] {
        &self.0
    }
}

impl<const N: usize> MaknaeSecret<[u8; N]> {
    pub fn expose(&self) -> &[u8; N] {
        &self.0
    }

    pub fn into_zeroizing(self) -> Zeroizing<[u8; N]> {
        self.0
    }
}

impl<B: SecretBuf> fmt::Debug for MaknaeSecret<B> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("MaknaeSecret(<redacted>)")
    }
}

struct ZeroizingStringVisitor;

impl Visitor<'_> for ZeroizingStringVisitor {
    type Value = Zeroizing<String>;

    fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("a string")
    }

    fn visit_str<E: serde::de::Error>(self, v: &str) -> Result<Self::Value, E> {
        Ok(Zeroizing::new(v.to_owned()))
    }

    fn visit_string<E: serde::de::Error>(self, v: String) -> Result<Self::Value, E> {
        Ok(Zeroizing::new(v))
    }
}

pub fn de_zeroizing_string<'de, D: Deserializer<'de>>(d: D) -> Result<Zeroizing<String>, D::Error> {
    d.deserialize_str(ZeroizingStringVisitor)
}

impl<'de> Deserialize<'de> for MaknaeSecret<String> {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        Self::new(de_zeroizing_string(d)?).map_err(|e| D::Error::custom(e.why()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const SENTINEL: &str = "SENTINEL-752";

    fn text(s: &str) -> Result<MaknaeSecret, SecretError> {
        MaknaeSecret::new(Zeroizing::new(s.to_owned()))
    }

    fn bytes(b: &[u8]) -> Result<MaknaeSecretBytes, SecretError> {
        MaknaeSecret::new(Zeroizing::new(b.to_vec()))
    }

    fn token(s: &str) -> Result<MaknaeSecret, SecretError> {
        MaknaeSecret::vault_token(Zeroizing::new(s.to_owned()))
    }

    #[test]
    fn new_infers_the_storage_form() {
        assert!(MaknaeSecret::new(Zeroizing::new(String::from("a"))).is_ok());
        assert!(MaknaeSecret::new(Zeroizing::new(vec![1u8])).is_ok());
        assert!(MaknaeSecret::new(Zeroizing::new([7u8; 32])).is_ok());
    }

    #[test]
    fn text_and_bytes_accept_one_and_the_maximum() {
        assert_eq!(MAX_SECRET_BYTES, 65_536);
        for len in [1, 65_536] {
            assert_eq!(text(&"a".repeat(len)).unwrap().expose().len(), len);
            assert_eq!(bytes(&vec![1u8; len]).unwrap().expose().len(), len);
        }
    }

    #[test]
    fn text_and_bytes_refuse_empty_and_one_over() {
        assert!(matches!(text(""), Err(SecretError::Empty)));
        assert!(matches!(bytes(b""), Err(SecretError::Empty)));
        let over = 65_537;
        assert!(matches!(text(&"a".repeat(over)), Err(SecretError::TooLong)));
        assert!(matches!(bytes(&vec![1u8; over]), Err(SecretError::TooLong)));
    }

    #[test]
    fn vault_token_accepts_the_token_alphabet_up_to_1024() {
        assert_eq!(token("hvs.A-b_9").unwrap().expose(), "hvs.A-b_9");
        assert!(token(&"a".repeat(1024)).is_ok());
        assert!(matches!(
            token(&"a".repeat(1025)),
            Err(SecretError::TooLong)
        ));
        assert!(matches!(token(""), Err(SecretError::Empty)));
        for bad in ["hvs token", "hvs/x", "a\"b"] {
            assert!(
                matches!(token(bad), Err(SecretError::NotAVaultToken)),
                "{bad}"
            );
        }
    }

    #[test]
    fn from_opened_refuses_invalid_utf8_and_a_non_token() {
        let opened = |b: &[u8]| MaknaeSecret::from_opened(Zeroizing::new(b.to_vec()));
        assert!(matches!(opened(&[0xff]), Err(SecretError::NotUtf8)));
        assert!(matches!(opened(b"a b"), Err(SecretError::NotAVaultToken)));
        assert_eq!(opened(b"hvs.ok").unwrap().expose(), "hvs.ok");
    }

    #[test]
    fn debug_prints_only_the_redaction_marker() {
        let shown = [
            format!("{:?}", text(SENTINEL).unwrap()),
            format!("{:?}", bytes(SENTINEL.as_bytes()).unwrap()),
            format!(
                "{:?}",
                MaknaeSecret::new(Zeroizing::new(*b"SENTINEL-752")).unwrap()
            ),
        ];
        for s in shown {
            assert_eq!(s, "MaknaeSecret(<redacted>)");
            assert!(!s.contains(SENTINEL));
        }
    }

    #[test]
    fn expose_returns_the_value_for_each_form() {
        assert_eq!(text(SENTINEL).unwrap().expose(), SENTINEL);
        assert_eq!(
            bytes(SENTINEL.as_bytes()).unwrap().expose(),
            SENTINEL.as_bytes()
        );
        let arr = MaknaeSecret::new(Zeroizing::new([9u8; 4])).unwrap();
        assert_eq!(arr.expose(), &[9u8; 4]);
    }

    #[test]
    fn the_array_form_round_trips_its_exact_bytes_through_into_zeroizing() {
        let key: [u8; 32] = std::array::from_fn(|i| i as u8);
        let s = MaknaeSecret::new(Zeroizing::new(key)).unwrap();
        assert_eq!(*s.into_zeroizing(), key);
    }

    #[test]
    fn an_empty_array_secret_is_refused() {
        assert!(matches!(
            MaknaeSecret::new(Zeroizing::new([0u8; 0])),
            Err(SecretError::Empty)
        ));
        assert!(MaknaeSecret::new(Zeroizing::new([7u8; 1])).is_ok());
    }

    #[test]
    fn the_sealed_read_returns_each_form_bytes() {
        assert_eq!(sealed::Sealed::bytes(&String::from("ab")), b"ab");
        assert_eq!(sealed::Sealed::bytes(&vec![1u8, 2]), &[1u8, 2]);
        assert_eq!(sealed::Sealed::bytes(&[3u8; 2]), &[3u8, 3]);
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn construction_denies_core_dumps() {
        use rustix::process::{getrlimit, setrlimit, Resource, Rlimit};
        let hard = getrlimit(Resource::Core).maximum;
        let rlimit_checked = hard != Some(0);
        rustix::process::set_dumpable_behavior(rustix::process::DumpableBehavior::Dumpable)
            .unwrap();
        assert_eq!(
            rustix::process::dumpable_behavior().unwrap(),
            rustix::process::DumpableBehavior::Dumpable
        );
        if rlimit_checked {
            setrlimit(
                Resource::Core,
                Rlimit {
                    current: hard,
                    maximum: hard,
                },
            )
            .unwrap();
            assert_ne!(getrlimit(Resource::Core).current, Some(0));
        } else {
            eprintln!("host hard RLIMIT_CORE is 0: checking dumpability only");
        }
        text(SENTINEL).unwrap();
        if rlimit_checked {
            assert_eq!(getrlimit(Resource::Core).current, Some(0));
        }
        assert_eq!(
            rustix::process::dumpable_behavior().unwrap(),
            rustix::process::DumpableBehavior::NotDumpable,
            "host hard RLIMIT_CORE is {hard:?}"
        );
    }

    #[cfg(not(target_os = "linux"))]
    #[test]
    fn construction_lowers_the_soft_core_limit() {
        use rustix::process::{getrlimit, setrlimit, Resource, Rlimit};
        let hard = getrlimit(Resource::Core).maximum;
        if hard == Some(0) {
            eprintln!("host hard RLIMIT_CORE is 0: nothing to check");
            return;
        }
        setrlimit(
            Resource::Core,
            Rlimit {
                current: hard,
                maximum: hard,
            },
        )
        .unwrap();
        assert_ne!(getrlimit(Resource::Core).current, Some(0));
        text(SENTINEL).unwrap();
        assert_eq!(getrlimit(Resource::Core).current, Some(0));
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn proc_self_fd_still_resolves_after_a_secret_is_built() {
        text(SENTINEL).unwrap();
        let file = tempfile::NamedTempFile::new().unwrap();
        let want = std::fs::canonicalize(file.path()).unwrap();
        assert_eq!(crate::syscall::linux_fd_path(file.as_file()).unwrap(), want);
    }

    #[test]
    fn json_decodes_a_string_into_a_secret() {
        let s: MaknaeSecret = serde_json::from_str("\"SENTINEL-752\"").unwrap();
        assert_eq!(s.expose(), SENTINEL);
    }

    #[test]
    fn json_refuses_a_number_null_an_object_and_an_empty_string() {
        for bad in ["1", "null", "{}", "\"\""] {
            assert!(serde_json::from_str::<MaknaeSecret>(bad).is_err(), "{bad}");
        }
    }

    #[test]
    fn de_zeroizing_string_takes_an_owned_string_without_a_copy() {
        use serde::de::IntoDeserializer;
        let owned = String::from(SENTINEL);
        let at = owned.as_ptr();
        let de: serde::de::value::StringDeserializer<serde::de::value::Error> =
            owned.into_deserializer();
        let got = de_zeroizing_string(de).unwrap();
        assert_eq!(got.as_str(), SENTINEL);
        assert_eq!(got.as_ptr(), at);
    }

    #[test]
    fn de_zeroizing_string_reads_only_a_string() {
        let mut de = serde_json::Deserializer::from_str("\"a\\\"b\"");
        assert_eq!(de_zeroizing_string(&mut de).unwrap().as_str(), "a\"b");
        let mut de = serde_json::Deserializer::from_str("7");
        let err = de_zeroizing_string(&mut de).unwrap_err().to_string();
        assert!(err.contains("a string"), "{err}");
    }

    #[test]
    fn secret_error_why_never_contains_input() {
        let mut not_utf8 = SENTINEL.as_bytes().to_vec();
        not_utf8.push(0xff);
        let errors = [
            text("").unwrap_err(),
            text(&SENTINEL.repeat(MAX_SECRET_BYTES / SENTINEL.len() + 1)).unwrap_err(),
            token(&format!("{SENTINEL} x")).unwrap_err(),
            MaknaeSecret::from_opened(Zeroizing::new(not_utf8)).unwrap_err(),
            SecretError::CoreDumps(std::io::Error::from_raw_os_error(1)),
        ];
        let mut seen = Vec::new();
        for e in &errors {
            let why = e.why();
            assert!(!why.is_empty());
            assert!(!why.contains(SENTINEL), "{why}");
            assert_eq!(e.to_string(), why);
            assert!(!format!("{e:?}").contains(SENTINEL));
            assert!(!seen.contains(&why), "{why} repeats");
            let has_source = std::error::Error::source(e).is_some();
            assert_eq!(has_source, matches!(e, SecretError::CoreDumps(_)), "{why}");
            seen.push(why);
        }
    }
}
