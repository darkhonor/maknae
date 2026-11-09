use crate::{
    user_providers_from_document, ConfigError, SensitiveList, UserProviders, SENSITIVE_FILE,
    USER_PROVIDERS_FILE,
};
use std::path::Path;

pub fn load_user_providers(cli_dir: &Path) -> Result<UserProviders, ConfigError> {
    match crate::load_file(&cli_dir.join(USER_PROVIDERS_FILE)) {
        Ok(doc) => user_providers_from_document(&doc),
        Err(ConfigError::NotFound { .. }) => Ok(UserProviders::empty()),
        Err(e) => Err(e),
    }
}

pub fn load_user_sensitive(cli_dir: &Path) -> Result<SensitiveList, ConfigError> {
    #[cfg(not(unix))]
    {
        let _ = cli_dir;
        Err(ConfigError::PermissionsUnsupported)
    }
    #[cfg(unix)]
    {
        match crate::loader::read_secure(&cli_dir.join(SENSITIVE_FILE)) {
            Ok(body) => SensitiveList::parse(&body).map_err(|e| match e {
                ConfigError::InvalidSensitive(_) => e,
                other => ConfigError::InvalidSensitive(other.to_string()),
            }),
            Err(ConfigError::NotFound { .. }) => Ok(SensitiveList::empty()),
            Err(e) => Err(e),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[cfg(unix)]
    struct Dir(std::path::PathBuf);

    #[cfg(unix)]
    impl Dir {
        fn new(tag: &str) -> Self {
            use std::os::unix::fs::PermissionsExt;
            let p = std::env::temp_dir().join(format!(
                "maknae-user-providers-{}-{tag}",
                std::process::id()
            ));
            let _ = std::fs::remove_dir_all(&p);
            std::fs::create_dir_all(&p).unwrap();
            std::fs::set_permissions(&p, std::fs::Permissions::from_mode(0o700)).unwrap();
            Dir(p)
        }

        fn write(&self, body: &str, mode: u32) {
            use std::os::unix::fs::PermissionsExt;
            let f = self.0.join(crate::USER_PROVIDERS_FILE);
            std::fs::write(&f, body).unwrap();
            std::fs::set_permissions(&f, std::fs::Permissions::from_mode(mode)).unwrap();
        }
    }

    #[cfg(unix)]
    impl Drop for Dir {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    #[cfg(unix)]
    impl Dir {
        fn write_sensitive(&self, body: &str, mode: u32) {
            use std::os::unix::fs::PermissionsExt;
            let f = self.0.join(crate::SENSITIVE_FILE);
            std::fs::write(&f, body).unwrap();
            std::fs::set_permissions(&f, std::fs::Permissions::from_mode(mode)).unwrap();
        }
    }

    #[cfg(unix)]
    #[test]
    fn an_absent_personal_file_is_no_entries() {
        let d = Dir::new("sensitive-absent");
        assert_eq!(load_user_sensitive(&d.0).unwrap(), SensitiveList::empty());
    }

    #[cfg(unix)]
    #[test]
    fn a_personal_file_is_read_and_parsed() {
        let d = Dir::new("sensitive-present");
        d.write_sensitive(
            "schema_version: 1\nsensitive: [\"~/sentinel-617-a/**\", \"/srv/sentinel-617\"]\n",
            0o600,
        );
        let list = load_user_sensitive(&d.0).unwrap();
        assert_eq!(
            list.entries().collect::<Vec<_>>(),
            ["~/sentinel-617-a/**", "/srv/sentinel-617"]
        );
    }

    #[cfg(unix)]
    #[test]
    fn a_malformed_personal_file_is_refused_with_its_cause() {
        let d = Dir::new("sensitive-malformed");
        d.write_sensitive("schema_version: 1\nsensitive: [\"~bob/x\"]\n", 0o600);
        let err = load_user_sensitive(&d.0).unwrap_err();
        assert!(
            matches!(&err, ConfigError::InvalidSensitive(m) if m.contains("~bob/x")),
            "{err:?}"
        );
        d.write_sensitive("schema_version: 1\nsensitive: [\n", 0o600);
        assert!(matches!(
            load_user_sensitive(&d.0),
            Err(ConfigError::InvalidSensitive(_))
        ));
    }

    #[cfg(unix)]
    #[test]
    fn a_personal_file_other_users_can_read_is_refused() {
        let d = Dir::new("sensitive-other-readable");
        d.write_sensitive("schema_version: 1\nsensitive: []\n", 0o604);
        assert!(matches!(
            load_user_sensitive(&d.0),
            Err(ConfigError::InsecurePermissions { .. })
        ));
    }

    #[cfg(unix)]
    const ONE: &str = "providers:\n  - label: a\n    provider: openai\n    model: m\n    key:\n      subpath: s\n      field: f\n    context_tokens: 4096\n";

    #[cfg(unix)]
    #[test]
    fn an_absent_file_means_no_providers() {
        let d = Dir::new("absent");
        assert_eq!(
            load_user_providers(&d.0).unwrap(),
            crate::UserProviders::empty()
        );
    }

    #[cfg(unix)]
    #[test]
    fn a_present_file_is_read_through_maknae_io_and_parsed() {
        let d = Dir::new("present");
        d.write(ONE, 0o600);
        let p = load_user_providers(&d.0).unwrap();
        assert_eq!(p.entries().len(), 1);
        assert_eq!(p.entries()[0].label, "a");
    }

    #[cfg(unix)]
    #[test]
    fn a_file_other_users_can_read_is_refused() {
        let d = Dir::new("other-readable");
        d.write(ONE, 0o604);
        assert!(matches!(
            load_user_providers(&d.0),
            Err(ConfigError::InsecurePermissions { .. })
        ));
    }

    #[cfg(unix)]
    #[test]
    fn a_malformed_file_is_refused_not_treated_as_absent() {
        let d = Dir::new("malformed");
        d.write("providers: openai\n", 0o600);
        assert!(matches!(
            load_user_providers(&d.0),
            Err(ConfigError::UserProviders(_))
        ));
    }
}
