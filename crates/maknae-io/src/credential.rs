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
#[cfg_attr(
    not(test),
    expect(
        dead_code,
        reason = "read by the launch-credential encoder (#751 Task 3)"
    )
)]
pub struct DeliveredCredential(Zeroizing<Vec<u8>>);

impl DeliveredCredential {
    pub fn new(secret: Zeroizing<Vec<u8>>) -> io::Result<Self> {
        deny_core_dumps()?;
        Ok(Self(secret))
    }

    pub fn from_secret_string(mut secret: Zeroizing<String>) -> io::Result<Self> {
        Self::new(Zeroizing::new(std::mem::take(&mut *secret).into_bytes()))
    }

    #[cfg_attr(
        not(test),
        expect(
            dead_code,
            reason = "read by the launch-credential encoder (#751 Task 3)"
        )
    )]
    pub(crate) fn expose(&self) -> &[u8] {
        &self.0
    }
}

impl fmt::Debug for DeliveredCredential {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("DeliveredCredential(<redacted>)")
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
}
