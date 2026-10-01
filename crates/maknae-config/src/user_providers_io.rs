use crate::{user_providers_from_document, ConfigError, UserProviders, USER_PROVIDERS_FILE};
use std::path::Path;

pub fn load_user_providers(cli_dir: &Path) -> Result<UserProviders, ConfigError> {
    match crate::load_file(&cli_dir.join(USER_PROVIDERS_FILE)) {
        Ok(doc) => user_providers_from_document(&doc),
        Err(ConfigError::NotFound { .. }) => Ok(UserProviders::empty()),
        Err(e) => Err(e),
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
