//! en_US catalog strings. Declaration-only string-table match arms — see
//! `coverage-tiers.toml` T3 justification.

use crate::MsgId;

pub(crate) fn text(id: MsgId) -> &'static str {
    match id {
        MsgId::EnrollStarted => "Starting enrollment",
        MsgId::EnrollGroupAdded => "Added {user} to the maknae group",
        MsgId::EnrollAlreadyMember => "{user} is already a member of the maknae group",
        MsgId::EnrollFailed => "Enrollment failed",
        MsgId::AuthzDenied => "Access denied",
        MsgId::AuthzPostureRefused => "Request refused: posture requirements not met",
        MsgId::AuthzUnknownSubject => "Unknown subject",
        MsgId::DaemonNotRunning => "maknae daemon is not running",
        MsgId::DaemonStartFailed => "Failed to start maknae daemon",
        MsgId::AuthzConfigRefused => {
            "maknae daemon refused to start: the authorization policy could not be loaded"
        }
        MsgId::PostureDegraded => {
            "warning: this boot's credential posture is not hardware-root-of-trust sealed"
        }
    }
}
