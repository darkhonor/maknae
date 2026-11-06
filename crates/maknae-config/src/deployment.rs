//! The `deployment` section: what kind of host `maknaed` runs on, and which
//! account-state source it consults. Required; boot verifies the mode against
//! the host.

use crate::{ConfigError, Value};

pub const DEPLOYMENT_SECTION: &str = "deployment";

pub(crate) const DEPLOYMENT_KEYS: [&str; 2] = ["mode", "account_source"];

const MODES: &str = "linux-host, macos-host, container";

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DeploymentMode {
    LinuxHost,
    MacosHost,
    Container,
}

impl DeploymentMode {
    pub fn as_str(self) -> &'static str {
        match self {
            DeploymentMode::LinuxHost => "linux-host",
            DeploymentMode::MacosHost => "macos-host",
            DeploymentMode::Container => "container",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AccountSource {
    Userdb,
    None,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Deployment {
    pub mode: DeploymentMode,
    pub account_source: AccountSource,
}

fn invalid_mode(found: &str) -> ConfigError {
    ConfigError::InvalidDeployment(format!(
        "deployment.mode: {found}; it must be one of {MODES}"
    ))
}

fn invalid_source(reason: &str) -> ConfigError {
    ConfigError::InvalidDeployment(format!("deployment.account_source: {reason}"))
}

pub fn deployment_from_section(v: Option<&Value>) -> Result<Deployment, ConfigError> {
    let entries = match v {
        None => return Err(invalid_mode("missing (the deployment section is absent)")),
        Some(Value::Map(entries)) => entries,
        Some(_) => {
            return Err(invalid_mode(
                "missing (the deployment section is not a map)",
            ))
        }
    };
    crate::reject_unknown_keys(DEPLOYMENT_SECTION, entries, &DEPLOYMENT_KEYS)?;
    let field = |key: &str| entries.iter().find(|(k, _)| k == key).map(|(_, v)| v);
    let mode = match field("mode") {
        None => return Err(invalid_mode("missing")),
        Some(Value::Str(s)) => match s.as_str() {
            "linux-host" => DeploymentMode::LinuxHost,
            "macos-host" => DeploymentMode::MacosHost,
            "container" => DeploymentMode::Container,
            other => return Err(invalid_mode(&format!("'{other}' is not a mode"))),
        },
        Some(_) => return Err(invalid_mode("not a string")),
    };
    let declared = match field("account_source") {
        None => None,
        Some(Value::Str(s)) => match s.as_str() {
            "userdb" => Some(AccountSource::Userdb),
            "none" => Some(AccountSource::None),
            other => {
                return Err(invalid_source(&format!(
                    "'{other}' is not a source; it must be userdb or none"
                )))
            }
        },
        Some(_) => return Err(invalid_source("not a string")),
    };
    let account_source = match (mode, declared) {
        (DeploymentMode::LinuxHost, None) => AccountSource::Userdb,
        (DeploymentMode::LinuxHost, Some(s)) => s,
        (DeploymentMode::MacosHost, None | Some(AccountSource::None)) => AccountSource::None,
        (DeploymentMode::MacosHost, Some(AccountSource::Userdb)) => {
            return Err(invalid_source(
                "userdb is not available on macos-host; omit the key or set none",
            ))
        }
        (DeploymentMode::Container, _) => AccountSource::None,
    };
    Ok(Deployment {
        mode,
        account_source,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn section(pairs: &[(&str, &str)]) -> Value {
        Value::Map(
            pairs
                .iter()
                .map(|(k, v)| (k.to_string(), Value::Str(v.to_string())))
                .collect(),
        )
    }

    fn parse(pairs: &[(&str, &str)]) -> Result<Deployment, ConfigError> {
        deployment_from_section(Some(&section(pairs)))
    }

    fn names_the_key_and_every_mode(e: &ConfigError) {
        let ConfigError::InvalidDeployment(m) = e else {
            panic!("{e:?}");
        };
        assert!(m.contains("deployment.mode"), "{m}");
        for mode in ["linux-host", "macos-host", "container"] {
            assert!(m.contains(mode), "{m}");
        }
    }

    #[test]
    fn each_mode_parses() {
        for (text, mode) in [
            ("linux-host", DeploymentMode::LinuxHost),
            ("macos-host", DeploymentMode::MacosHost),
            ("container", DeploymentMode::Container),
        ] {
            assert_eq!(parse(&[("mode", text)]).unwrap().mode, mode);
            assert_eq!(mode.as_str(), text);
        }
    }

    #[test]
    fn an_absent_section_names_the_key_and_the_modes() {
        names_the_key_and_every_mode(&deployment_from_section(None).unwrap_err());
    }

    #[test]
    fn a_missing_mode_names_the_key_and_the_modes() {
        names_the_key_and_every_mode(&parse(&[]).unwrap_err());
        names_the_key_and_every_mode(&parse(&[("account_source", "userdb")]).unwrap_err());
    }

    #[test]
    fn a_mode_matches_exactly() {
        for bad in ["Linux-Host", "linux_host", "linux", " linux-host", ""] {
            names_the_key_and_every_mode(&parse(&[("mode", bad)]).unwrap_err());
        }
        let not_a_string = Value::Map(vec![("mode".into(), Value::Int(1))]);
        names_the_key_and_every_mode(&deployment_from_section(Some(&not_a_string)).unwrap_err());
    }

    #[test]
    fn a_section_that_is_not_a_map_refuses() {
        for v in [
            Value::Str("linux-host".into()),
            Value::Seq(vec![Value::Str("linux-host".into())]),
            Value::Null,
        ] {
            names_the_key_and_every_mode(&deployment_from_section(Some(&v)).unwrap_err());
        }
    }

    #[test]
    fn an_unknown_key_refuses() {
        assert_eq!(
            parse(&[("mode", "linux-host"), ("mdoe", "x")]),
            Err(ConfigError::UnknownKey {
                section: "deployment".into(),
                key: "mdoe".into(),
            })
        );
    }

    #[test]
    fn linux_host_defaults_to_userdb_and_takes_a_declared_source() {
        assert_eq!(
            parse(&[("mode", "linux-host")]).unwrap().account_source,
            AccountSource::Userdb
        );
        assert_eq!(
            parse(&[("mode", "linux-host"), ("account_source", "userdb")])
                .unwrap()
                .account_source,
            AccountSource::Userdb
        );
        assert_eq!(
            parse(&[("mode", "linux-host"), ("account_source", "none")])
                .unwrap()
                .account_source,
            AccountSource::None
        );
    }

    #[test]
    fn macos_host_has_no_account_source_and_refuses_userdb() {
        assert_eq!(
            parse(&[("mode", "macos-host")]).unwrap().account_source,
            AccountSource::None
        );
        assert_eq!(
            parse(&[("mode", "macos-host"), ("account_source", "none")])
                .unwrap()
                .account_source,
            AccountSource::None
        );
        let e = parse(&[("mode", "macos-host"), ("account_source", "userdb")]).unwrap_err();
        assert!(
            matches!(&e, ConfigError::InvalidDeployment(m) if m.contains("deployment.account_source")),
            "{e:?}"
        );
    }

    #[test]
    fn container_ignores_the_account_source() {
        for source in [None, Some("userdb"), Some("none")] {
            let mut pairs = vec![("mode", "container")];
            pairs.extend(source.map(|s| ("account_source", s)));
            assert_eq!(parse(&pairs).unwrap().account_source, AccountSource::None);
        }
    }

    #[test]
    fn any_other_account_source_refuses() {
        for bad in ["Userdb", "nss", ""] {
            let e = parse(&[("mode", "linux-host"), ("account_source", bad)]).unwrap_err();
            assert!(
                matches!(&e, ConfigError::InvalidDeployment(m) if m.contains("deployment.account_source")),
                "{bad}: {e:?}"
            );
        }
        let not_a_string = Value::Map(vec![
            ("mode".into(), Value::Str("linux-host".into())),
            ("account_source".into(), Value::Bool(true)),
        ]);
        assert!(matches!(
            deployment_from_section(Some(&not_a_string)),
            Err(ConfigError::InvalidDeployment(_))
        ));
    }
}
