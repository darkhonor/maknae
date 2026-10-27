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
        MsgId::EnrollTokenPrompt => "Vault token: ",
        MsgId::EnrollVaultOpsStarted => "Requesting credentials from Vault",
        MsgId::EnrollWritingDaemonConfig => "Writing the daemon's configuration",
        MsgId::EnrollSealingDaemonCredential => "Sealing the daemon's credential",
        MsgId::EnrollSealKeyGenerated => {
            "Generated the Egress Daemon's sealing key and published its public key at {path}. An Egress Daemon that is already running still holds the previous key: restart it with `sudo {restart}`"
        }
        MsgId::EnrollSealKeyKept => {
            "Kept the Egress Daemon's sealing key and its published public key; pass --rotate-seal-key to replace them"
        }
        MsgId::EnrollGraphKeyCreated => "Created the kernel graph key at {path}",
        MsgId::EnrollGraphKeyKept => {
            "Kept the kernel graph key at {path}; it is never rotated, because a new key cannot read the existing graph store"
        }
        MsgId::EnrollGraphStoreExists => {
            "a kernel graph store already exists and cannot be opened with the new key; run sudo maknae reseed"
        }
        MsgId::EnrollProvisioningCli => "Writing your CLI configuration",
        MsgId::EnrollPostureSummary => "Enrollment complete. CLI config: {cli_dir}",
        MsgId::EnrollReloginNote => {
            "Log out and back in (or run `newgrp maknae`), then run `maknae login` before using the CLI"
        }
        MsgId::EnrollEgressBoundsHint => {
            "maknae-egress: enroll wrote /etc/maknae/egress-bounds.yaml; start the deputy with: systemctl enable --now maknae-egress.socket — the socket unit is preset-disabled, and without it every permitted prompt is refused as not ready"
        }
        MsgId::EnrollEnableDaemonHint => "Start the daemon with: systemctl enable --now maknaed",
        MsgId::EnrollEgressBoundsHintMacos => {
            "maknae-egress: enroll wrote /etc/maknae/egress-bounds.yaml; start the deputy with: sudo launchctl enable system/io.maknae.maknae-egress && sudo launchctl bootstrap system /Library/LaunchDaemons/io.maknae.maknae-egress.plist — the job ships disabled, and without it every permitted prompt is refused as not ready"
        }
        MsgId::EnrollEnableDaemonHintMacos => {
            "Start the daemon with: sudo launchctl enable system/io.maknae.maknaed && sudo launchctl bootstrap system /Library/LaunchDaemons/io.maknae.maknaed.plist"
        }
        MsgId::EnrollRotating => "Existing enrollment found — rotating credentials",
        MsgId::EnrollRotatePreviousDestroyed => "Destroyed the previous enrollment's credentials",
        MsgId::EnrollRollbackDestroyed => {
            "Enrollment failed — destroyed the credentials just issued"
        }
        MsgId::EnrollRollbackDestroyPartial => {
            "Enrollment failed — attempted to destroy the credentials just issued, but the rollback itself partially failed (see below)"
        }
        MsgId::EnrollBindingsWritten => {
            "Wrote {user} to bindings.yaml as admin"
        }
        MsgId::EnrollBindingsAlreadyAdmin => {
            "{user} already holds admin in bindings.yaml; bindings.yaml was not changed"
        }
        MsgId::EnrollBindingsLost => {
            "maknaed enforces explicit bindings, but bindings.yaml is missing or has no bindings: key; restore it first at a terminal with sudo maknae policy sync, then enroll again"
        }
        MsgId::EnrollBindingsOtherRole => {
            "{user} holds {role}; enroll adds admin only for a user who holds no other role. If {user} should hold admin, change that binding first"
        }
        MsgId::EnrollBindingsReloadHint => {
            "If maknaed is running, reload it to apply bindings.yaml: sudo systemctl reload maknaed"
        }
        MsgId::EnrollBindingsReloadHintMacos => {
            "If maknaed is running, reload it to apply bindings.yaml: sudo launchctl kill SIGHUP system/io.maknae.maknaed"
        }
        MsgId::EnrollBindingsContained => {
            "{user} is contained; enroll does not change a containment. Release it first if that is intended"
        }
        MsgId::EnrollBindingsLookupFailed => {
            "cannot look up the account {name} named in the bindings: {error}; nothing was written"
        }
        MsgId::EnrollAgentStarted => "Enrolling the Agent Daemon {agent}",
        MsgId::EnrollAgentEnrolled => {
            "Agent Daemon {agent} is enrolled: the SecretID for {role} is sealed on this host and works only from {cidrs}"
        }
        MsgId::EnrollAgentRetired => "Destroyed {count} earlier SecretID(s) of this agent",
        MsgId::HelperContextMismatch => {
            "Operator-context helper did not land in the expected identity"
        }
        MsgId::HelperStillPrivileged => {
            "Operator-context helper still holds root's group membership — refusing"
        }
        MsgId::CryptoFipsUnavailable => {
            "refused to start: the FIPS cryptographic provider is not active"
        }
        MsgId::CryptoKxGroupsDrift => {
            "refused to start: the TLS provider does not carry the required key-exchange groups"
        }
    }
}
