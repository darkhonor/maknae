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
        MsgId::AuditOffloadUnsupported => {
            "maknae daemon refused to start: audit.siem is configured but off-host audit offload is not implemented"
        }
        MsgId::PostureDegraded => {
            "warning: this boot's credential posture is not hardware-root-of-trust sealed"
        }
        MsgId::EnrollPreflightFailed => "Enrollment preflight check failed",
        MsgId::EnrollProbeStarted => "Verifying this host can seal a credential in your context",
        MsgId::EnrollProbeFailed => {
            "Credential-sealing capability check failed — nothing has been changed in Vault"
        }
        MsgId::EnrollProbeOk => "Credential-sealing capability confirmed",
        MsgId::EnrollTokenPrompt => "Vault token: ",
        MsgId::EnrollVaultOpsStarted => "Requesting credentials from Vault",
        MsgId::EnrollWritingDaemonConfig => "Writing the daemon's configuration",
        MsgId::EnrollSealingDaemonCredential => "Sealing the daemon's credential",
        MsgId::EnrollProvisioningCli => "Provisioning your CLI credentials",
        MsgId::EnrollPostureSummary => "Enrollment complete. CLI config: {cli_dir}",
        MsgId::EnrollReloginNote => {
            "Log out and back in (or run `newgrp maknae`) before using the CLI"
        }
        MsgId::EnrollEnableDaemonHint => "Start the daemon with: systemctl enable --now maknaed",
        MsgId::EnrollRotating => "Existing enrollment found — rotating credentials",
        MsgId::EnrollRollbackDestroyed => {
            "Enrollment failed — destroyed the credentials just issued"
        }
        MsgId::EnrollRollbackDestroyPartial => {
            "Enrollment failed — attempted to destroy the credentials just issued, but the rollback itself partially failed (see below)"
        }
        MsgId::HelperContextMismatch => {
            "Operator-context helper did not land in the expected identity"
        }
        MsgId::HelperStillPrivileged => {
            "Operator-context helper still holds root's group membership — refusing"
        }
    }
}
