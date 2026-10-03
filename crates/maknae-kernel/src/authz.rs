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

pub fn admission_facts(
    looked_up: Option<crate::groupres::Membership>,
) -> (bool, Option<String>, Option<std::path::PathBuf>) {
    match looked_up {
        Some(m) => (m.in_group, Some(m.user), m.home),
        None => (false, None, None),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_looked_up_member_carries_its_user_and_home_through() {
        let m = crate::groupres::Membership {
            in_group: true,
            user: "b-435-sentinel".into(),
            home: Some("/home/b-435-sentinel".into()),
        };
        assert_eq!(
            admission_facts(Some(m)),
            (
                true,
                Some("b-435-sentinel".to_string()),
                Some(std::path::PathBuf::from("/home/b-435-sentinel"))
            )
        );
        let outsider = crate::groupres::Membership {
            in_group: false,
            user: "c-435-sentinel".into(),
            home: None,
        };
        assert_eq!(
            admission_facts(Some(outsider)),
            (false, Some("c-435-sentinel".to_string()), None)
        );
    }

    #[test]
    fn a_failed_lookup_admits_no_one_and_carries_no_home() {
        assert_eq!(admission_facts(None), (false, None, None));
    }

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
