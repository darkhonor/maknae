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

#[cfg(test)]
mod tests {
    use super::*;
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
