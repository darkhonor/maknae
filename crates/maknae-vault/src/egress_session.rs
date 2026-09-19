//! The deputy's per-read token lifecycle — the DECISION half (#240b).
//!
//! `egress.rs` performs the three Vault operations; this module decides how
//! they compose, over a seam, so the composition is a unit-tested, mutation-
//! visible decision rather than three lines buried behind a network call.
//! The seam is a trait, not a fake server: the same shape as the deputy's
//! `KeySource` — this project has no Vault stub and deliberately uses none.
//!
//! **The invariant, stated by the review that found it missing (PR #317):**
//! no token stands between reads, and a step that fails is never reported as
//! a step that succeeded. `revoke-self` is therefore not best-effort. The
//! deputy's AppRole role bounds its tokens to three uses and two minutes
//! (`deploy/vault-pki`), so a token whose revoke failed is usable for at most
//! that — but usable, so:
//!
//! - the boot probe is login AND revoke, and reports the revoke's failure;
//! - a key read whose revoke failed WITHHOLDS the secret, so nothing enters
//!   the process-wide cache on the strength of a token the deputy knows it
//!   left behind, and the refusal names the token it left.
//!
//! Stated plainly: "no token stands between reads" is a SERVER-side property.
//! The token string itself lives in plain `String`s inside vaultrs's client
//! and settings for the session and is not wiped on drop — the same shape as
//! the daemon's plane client, and not changed here.

use crate::VaultError;
use std::future::Future;
use zeroize::Zeroizing;

/// One authenticated session's three operations. `Session` is whatever the
/// implementation needs to carry between them (a token-bearing client);
/// `revoke` consumes it, so a session cannot be used after its token is gone.
/// Crate-private, deliberately: the only way OUT of this crate is through
/// `probe`/`read_one`, so no caller can login and skip the revoke.
pub(crate) trait EgressOps {
    type Session;
    fn login(&self) -> impl Future<Output = Result<Self::Session, VaultError>> + Send;
    fn read(
        &self,
        session: &Self::Session,
        key_vault_path: &str,
        field: &str,
    ) -> impl Future<Output = Result<Zeroizing<String>, VaultError>> + Send;
    fn revoke(&self, session: Self::Session)
        -> impl Future<Output = Result<(), VaultError>> + Send;
}

/// Login and revoke. Proves the credential without leaving a token — and says
/// so only when BOTH halves completed.
pub(crate) async fn probe<O: EgressOps>(ops: &O) -> Result<(), VaultError>
where
    O::Session: Send,
{
    let session = ops.login().await?;
    ops.revoke(session).await.map_err(|e| {
        VaultError::Revoke(format!(
            "login probe: the login succeeded but revoke-self failed, leaving a usable token: {e}"
        ))
    })
}

/// Login, read one field, revoke. The secret is returned only when the token
/// that read it is gone; a read whose revoke failed is a refusal that names
/// the leftover token, never a value.
pub(crate) async fn read_one<O: EgressOps>(
    ops: &O,
    key_vault_path: &str,
    field: &str,
) -> Result<Zeroizing<String>, VaultError>
where
    O::Session: Send,
{
    let session = ops.login().await?;
    let read = ops.read(&session, key_vault_path, field).await;
    // Revoke is attempted whether or not the read succeeded: the token exists
    // either way.
    let revoked = ops.revoke(session).await;
    match (read, revoked) {
        (Ok(value), Ok(())) => Ok(value),
        (Err(read_err), Ok(())) => Err(read_err),
        (Err(read_err), Err(revoke_err)) => Err(VaultError::Revoke(format!(
            "{read_err}; and revoke-self failed afterwards, leaving a usable token: {revoke_err}"
        ))),
        (Ok(_withheld), Err(revoke_err)) => Err(VaultError::Revoke(format!(
            "the key read succeeded but revoke-self failed — the secret is withheld and the token stays usable until its uses or TTL run out: {revoke_err}"
        ))),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;

    /// A scripted seam: each step succeeds or fails on command, and every
    /// call is recorded in order. Not a Vault — a record of what the decision
    /// asked for.
    struct Scripted {
        login_ok: bool,
        read_ok: bool,
        revoke_ok: bool,
        calls: Mutex<Vec<&'static str>>,
    }

    impl Scripted {
        fn new(login_ok: bool, read_ok: bool, revoke_ok: bool) -> Self {
            Self {
                login_ok,
                read_ok,
                revoke_ok,
                calls: Mutex::new(vec![]),
            }
        }
        fn calls(&self) -> Vec<&'static str> {
            self.calls.lock().unwrap().clone()
        }
    }

    impl EgressOps for Scripted {
        type Session = u32;
        async fn login(&self) -> Result<u32, VaultError> {
            self.calls.lock().unwrap().push("login");
            if self.login_ok {
                Ok(7)
            } else {
                Err(VaultError::Auth("bad secret id".into()))
            }
        }
        async fn read(&self, s: &u32, p: &str, f: &str) -> Result<Zeroizing<String>, VaultError> {
            assert_eq!(*s, 7, "the read uses the session the login produced");
            self.calls.lock().unwrap().push("read");
            if self.read_ok {
                Ok(Zeroizing::new(format!("{p}#{f}")))
            } else {
                Err(VaultError::MissingKvField {
                    path: p.into(),
                    field: f.into(),
                })
            }
        }
        async fn revoke(&self, s: u32) -> Result<(), VaultError> {
            assert_eq!(s, 7);
            self.calls.lock().unwrap().push("revoke");
            if self.revoke_ok {
                Ok(())
            } else {
                Err(VaultError::Auth("403 on revoke-self".into()))
            }
        }
    }

    fn run<F: Future>(f: F) -> F::Output {
        tokio::runtime::Builder::new_current_thread()
            .build()
            .unwrap()
            .block_on(f)
    }

    #[test]
    fn a_read_is_login_then_read_then_revoke_and_returns_the_value() {
        let ops = Scripted::new(true, true, true);
        let v = run(read_one(
            &ops,
            "maknae-kv/data/maknae/providers/openai",
            "api-key",
        ))
        .unwrap();
        assert_eq!(&*v, "maknae-kv/data/maknae/providers/openai#api-key");
        assert_eq!(ops.calls(), ["login", "read", "revoke"]);
    }

    /// A failed login reads nothing and revokes nothing: there is no token.
    #[test]
    fn a_failed_login_stops_before_any_read() {
        let ops = Scripted::new(false, true, true);
        assert!(matches!(
            run(read_one(&ops, "p", "f")),
            Err(VaultError::Auth(_))
        ));
        assert_eq!(ops.calls(), ["login"]);
    }

    /// A failed read still revokes — the token exists — and reports the read.
    #[test]
    fn a_failed_read_still_revokes_and_reports_the_read() {
        let ops = Scripted::new(true, false, true);
        assert!(matches!(
            run(read_one(&ops, "p", "f")),
            Err(VaultError::MissingKvField { .. })
        ));
        assert_eq!(ops.calls(), ["login", "read", "revoke"]);
    }

    /// THE finding (PR #317, four heads): a successful read whose revoke failed
    /// must NOT return the secret. The token stays usable until its uses or
    /// TTL run out; the
    /// refusal names that, and nothing reaches the cache.
    #[test]
    fn a_successful_read_whose_revoke_failed_withholds_the_secret() {
        let ops = Scripted::new(true, true, false);
        let out = run(read_one(&ops, "p", "f"));
        match out {
            Err(VaultError::Revoke(m)) => {
                assert!(m.contains("withheld"), "{m}");
                assert!(m.contains("403 on revoke-self"), "{m}");
            }
            other => panic!("a read whose revoke failed must refuse, got {other:?}"),
        }
        assert_eq!(ops.calls(), ["login", "read", "revoke"]);
    }

    /// Both halves failing names both: the read's reason and the token left.
    #[test]
    fn a_failed_read_and_a_failed_revoke_name_both() {
        let ops = Scripted::new(true, false, false);
        match run(read_one(&ops, "p", "f")) {
            Err(VaultError::Revoke(m)) => {
                assert!(m.contains("missing") || m.contains("field"), "{m}");
                assert!(m.contains("leaving a usable token"), "{m}");
            }
            other => panic!("expected Revoke naming both, got {other:?}"),
        }
    }

    /// The probe is login AND revoke; a failed revoke is a failed probe.
    #[test]
    fn the_probe_fails_when_its_revoke_fails() {
        let ops = Scripted::new(true, true, false);
        assert!(matches!(run(probe(&ops)), Err(VaultError::Revoke(_))));
        assert_eq!(ops.calls(), ["login", "revoke"]);
        let ops = Scripted::new(true, true, true);
        assert!(run(probe(&ops)).is_ok());
        assert_eq!(ops.calls(), ["login", "revoke"]);
        let ops = Scripted::new(false, true, true);
        assert!(matches!(run(probe(&ops)), Err(VaultError::Auth(_))));
        assert_eq!(ops.calls(), ["login"]);
    }
}
