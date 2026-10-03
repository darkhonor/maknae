//! Connection-admission decision (spec §5). Pure; T1/0-missed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ConnDecision {
    Permit,
    Deny { reason: String },
}

pub fn authorize_connection(cert_verified: bool, uid_in_group: bool) -> ConnDecision {
    match (cert_verified, uid_in_group) {
        (true, true) => ConnDecision::Permit,
        (false, _) => ConnDecision::Deny {
            reason: "plane cert not verified".into(),
        },
        (true, false) => ConnDecision::Deny {
            reason: "peer uid not in `maknae` group".into(),
        },
    }
}

pub fn home_if_member(
    in_group: bool,
    resolve: impl FnOnce() -> Option<std::path::PathBuf>,
) -> Option<std::path::PathBuf> {
    if in_group {
        resolve()
    } else {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_a_member_has_its_home_resolved() {
        let called = std::cell::Cell::new(false);
        let resolve = || {
            called.set(true);
            Some(std::path::PathBuf::from("/home/b"))
        };
        assert_eq!(home_if_member(false, resolve), None);
        assert!(!called.get(), "a non-member's home is never resolved");
        assert_eq!(
            home_if_member(true, || Some("/home/b".into())),
            Some("/home/b".into())
        );
    }
    #[test]
    fn permit_only_when_both() {
        assert!(matches!(
            authorize_connection(true, true),
            ConnDecision::Permit
        ));
    }
    #[test]
    fn deny_when_not_in_group() {
        assert_eq!(
            authorize_connection(true, false),
            ConnDecision::Deny {
                reason: "peer uid not in `maknae` group".into()
            }
        );
    }
    #[test]
    fn deny_when_cert_unverified() {
        assert_eq!(
            authorize_connection(false, true),
            ConnDecision::Deny {
                reason: "plane cert not verified".into()
            }
        );
    }
    #[test]
    fn deny_when_neither() {
        assert_eq!(
            authorize_connection(false, false),
            ConnDecision::Deny {
                reason: "plane cert not verified".into()
            }
        );
    }
}
