use crate::VaultError;
use maknae_config::Value;
use zeroize::Zeroizing;

pub const SYSTEM_KEYCHAIN: &str = "/Library/Keychains/System.keychain";
pub const KEYCHAIN_ACCOUNT: &str = "secret-id";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KeychainPlane {
    Daemon,
    Egress,
}

impl KeychainPlane {
    pub const fn service(self) -> &'static str {
        match self {
            KeychainPlane::Daemon => "io.maknae.maknaed",
            KeychainPlane::Egress => "io.maknae.maknae-egress",
        }
    }

    pub const fn account_name(self) -> &'static str {
        match self {
            KeychainPlane::Daemon => "_maknae",
            KeychainPlane::Egress => "_maknae-egress",
        }
    }

    pub const fn pointer_file(self) -> &'static str {
        match self {
            KeychainPlane::Daemon => "maknaed-secret-id.keychain",
            KeychainPlane::Egress => "maknae-egress-secret-id.keychain",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct KeychainItem {
    pub service: &'static str,
    pub account: &'static str,
}

fn field<'a>(doc: &'a Value, key: &str) -> Option<&'a str> {
    match doc {
        Value::Map(entries) => entries.iter().find(|(k, _)| k == key).and_then(|(_, v)| match v {
            Value::Str(s) => Some(s.as_str()),
            _ => None,
        }),
        _ => None,
    }
}

pub fn parse_pointer(doc: &Value, plane: KeychainPlane) -> Result<KeychainItem, VaultError> {
    let expect = |key: &str, want: &str| match field(doc, key) {
        Some(got) if got == want => Ok(()),
        Some(got) => Err(VaultError::KeychainPointer(format!("{key} is {got:?}, expected {want:?}"))),
        None => Err(VaultError::KeychainPointer(format!("{key} is missing"))),
    };
    expect("keychain", SYSTEM_KEYCHAIN)?;
    expect("service", plane.service())?;
    expect("account", KEYCHAIN_ACCOUNT)?;
    Ok(KeychainItem {
        service: plane.service(),
        account: KEYCHAIN_ACCOUNT,
    })
}

pub fn gate(euid: u32, expected_uid: Option<u32>, plane: KeychainPlane) -> Result<(), VaultError> {
    match expected_uid {
        Some(uid) if uid == euid => Ok(()),
        _ => Err(VaultError::WrongAccount {
            expected: plane.account_name(),
            euid,
        }),
    }
}

pub fn read_gated<P, K>(
    plane: KeychainPlane,
    euid: u32,
    expected_uid: Option<u32>,
    read_pointer: P,
    read_item: K,
) -> Result<Zeroizing<String>, VaultError>
where
    P: FnOnce() -> Result<Value, VaultError>,
    K: FnOnce(&KeychainItem) -> Result<Zeroizing<String>, VaultError>,
{
    gate(euid, expected_uid, plane)?;
    let item = parse_pointer(&read_pointer()?, plane)?;
    read_item(&item)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn doc(yaml: &str) -> Value {
        maknae_config::load_str(yaml).unwrap()
    }

    fn good(plane: KeychainPlane) -> Value {
        doc(&format!(
            "keychain: {SYSTEM_KEYCHAIN}\nservice: {}\naccount: {KEYCHAIN_ACCOUNT}\n",
            plane.service()
        ))
    }

    fn never_pointer() -> Result<Value, VaultError> {
        panic!("the pointer must not be read")
    }

    fn never_item(_: &KeychainItem) -> Result<Zeroizing<String>, VaultError> {
        panic!("the keychain must not be touched")
    }

    #[test]
    fn plane_constants() {
        assert_eq!(KeychainPlane::Daemon.service(), "io.maknae.maknaed");
        assert_eq!(KeychainPlane::Egress.service(), "io.maknae.maknae-egress");
        assert_eq!(KeychainPlane::Daemon.account_name(), "_maknae");
        assert_eq!(KeychainPlane::Egress.account_name(), "_maknae-egress");
        assert_eq!(KeychainPlane::Daemon.pointer_file(), "maknaed-secret-id.keychain");
        assert_eq!(KeychainPlane::Egress.pointer_file(), "maknae-egress-secret-id.keychain");
    }

    #[test]
    fn a_valid_pointer_names_its_own_plane_item() {
        for plane in [KeychainPlane::Daemon, KeychainPlane::Egress] {
            assert_eq!(
                parse_pointer(&good(plane), plane).unwrap(),
                KeychainItem { service: plane.service(), account: KEYCHAIN_ACCOUNT }
            );
        }
    }

    #[test]
    fn a_pointer_cannot_redirect_the_read() {
        let foreign_keychain = doc(
            "keychain: /Users/x/evil.keychain\nservice: io.maknae.maknaed\naccount: secret-id\n",
        );
        let other_plane = good(KeychainPlane::Egress);
        let other_account = doc(&format!(
            "keychain: {SYSTEM_KEYCHAIN}\nservice: io.maknae.maknaed\naccount: root\n"
        ));
        let missing = doc(&format!("keychain: {SYSTEM_KEYCHAIN}\nservice: io.maknae.maknaed\n"));
        let not_a_map = doc("- a\n- b\n");
        let not_a_string = doc(&format!("keychain: {SYSTEM_KEYCHAIN}\nservice: 5\naccount: secret-id\n"));
        for d in [foreign_keychain, other_plane, other_account, missing, not_a_map, not_a_string] {
            assert!(matches!(
                parse_pointer(&d, KeychainPlane::Daemon),
                Err(VaultError::KeychainPointer(_))
            ));
        }
    }

    #[test]
    fn the_gate_admits_only_the_plane_account() {
        assert!(gate(992, Some(992), KeychainPlane::Daemon).is_ok());
        assert!(matches!(
            gate(501, Some(992), KeychainPlane::Daemon),
            Err(VaultError::WrongAccount { expected: "_maknae", euid: 501 })
        ));
        assert!(matches!(
            gate(0, Some(992), KeychainPlane::Daemon),
            Err(VaultError::WrongAccount { euid: 0, .. })
        ));
        assert!(matches!(
            gate(991, None, KeychainPlane::Egress),
            Err(VaultError::WrongAccount { expected: "_maknae-egress", .. })
        ));
    }

    #[test]
    fn a_wrong_account_reads_nothing() {
        assert!(matches!(
            read_gated(KeychainPlane::Daemon, 501, Some(992), never_pointer, never_item),
            Err(VaultError::WrongAccount { .. })
        ));
        assert!(matches!(
            read_gated(KeychainPlane::Egress, 991, None, never_pointer, never_item),
            Err(VaultError::WrongAccount { .. })
        ));
    }

    #[test]
    fn a_bad_pointer_never_reaches_the_keychain() {
        let bad = || Ok(good(KeychainPlane::Egress));
        assert!(matches!(
            read_gated(KeychainPlane::Daemon, 992, Some(992), bad, never_item),
            Err(VaultError::KeychainPointer(_))
        ));
        let unreadable = || Err(VaultError::CredentialSource("pointer unreadable".into()));
        assert!(matches!(
            read_gated(KeychainPlane::Daemon, 992, Some(992), unreadable, never_item),
            Err(VaultError::CredentialSource(_))
        ));
    }

    #[test]
    fn the_item_read_gets_the_plane_item() {
        let got = read_gated(
            KeychainPlane::Egress,
            991,
            Some(991),
            || Ok(good(KeychainPlane::Egress)),
            |item| {
                assert_eq!(item.service, "io.maknae.maknae-egress");
                assert_eq!(item.account, "secret-id");
                Ok(Zeroizing::new("sid".to_string()))
            },
        )
        .unwrap();
        assert_eq!(got.as_str(), "sid");
    }
}
