//! Shared fixtures for the kernel integration suites. Each tests/*.rs is its
//! own crate and uses a subset of these — hence the allow (`-D warnings`
//! clippy would otherwise red on unused-in-one-crate items).
#![allow(dead_code)]

use std::future::Future;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use maknae_audit_append::{AuditEmit, AuditError, AuditRecord};
use maknae_security::{Authorizer, Obligation, Request, Verdict};

/// The labeled ALWAYS-PERMIT fixture for transport-behavior tests (read
/// timeout, frame cap, admission gating, audit-then-respond): their claims
/// are not PDP verdicts — the real-PDP proofs live in enforce_loop.rs with
/// HermeticAuthorizer. Carries the standard audit obligation so the permit
/// path exercises the discharge gate.
pub struct AlwaysPermit;

impl Authorizer for AlwaysPermit {
    fn decide(&self, _r: &Request) -> Verdict {
        Verdict::Permit {
            obligations: vec![Obligation {
                id: "audit".into(),
                params: maknae_security::Attributes::new(),
            }],
        }
    }
}

/// A hostile/wedged backend: sleeps synchronously (a REAL blocking sleep —
/// the decide runs on the blocking pool, where virtual time cannot reach it)
/// then permits. Drives the two-sided decide-timeout proofs.
pub struct SleepAuthorizer(pub Duration);

impl Authorizer for SleepAuthorizer {
    fn decide(&self, _r: &Request) -> Verdict {
        std::thread::sleep(self.0);
        AlwaysPermit.decide(_r)
    }
}

/// A backend returning an obligation the PEP has no handler for.
pub struct HostileObligation;

impl Authorizer for HostileObligation {
    fn decide(&self, _r: &Request) -> Verdict {
        Verdict::Permit {
            obligations: vec![Obligation {
                id: "exfil".into(),
                params: maknae_security::Attributes::new(),
            }],
        }
    }
}

/// Fails ONLY the Nth emit() call (1-based); records every offer
/// synchronously. n=2 fails the REQUEST record while the admission record
/// (call 1) succeeds — the deny/permit-record withhold scenarios need exactly
/// that, which neither RecEmit (fails all) nor FailFirstEmit (fails call 1 →
/// admission gate trips first) can reach.
pub struct FailNthEmit {
    recs: Mutex<Vec<AuditRecord>>,
    calls: Mutex<u32>,
    n: u32,
}

impl FailNthEmit {
    pub fn new(n: u32) -> Arc<Self> {
        Arc::new(FailNthEmit {
            recs: Mutex::new(Vec::new()),
            calls: Mutex::new(0),
            n,
        })
    }
    pub fn records(&self) -> Vec<AuditRecord> {
        self.recs.lock().unwrap().clone()
    }
}

impl AuditEmit for FailNthEmit {
    fn emit(&self, rec: &AuditRecord) -> impl Future<Output = Result<(), AuditError>> + Send {
        self.recs.lock().unwrap().push(rec.clone());
        let mut calls = self.calls.lock().unwrap();
        *calls += 1;
        let fail = *calls == self.n;
        drop(calls);
        async move {
            if fail {
                Err(AuditError::WritePrimary("forced (nth call)".into()))
            } else {
                Ok(())
            }
        }
    }
}

/// The standard test principal: uid 501 matches the suites' peer_uid so the
/// bindings-absent defaults resolve `admin` where a real PDP is in play.
pub fn fixture_principal() -> maknae_config::Principal {
    maknae_config::Principal {
        name: "operator".into(),
        uid: 501,
        home: "/home/operator".into(),
    }
}

/// Standard extra args for `handle()` in transport-behavior tests.
pub fn permissive_authz() -> (Arc<AlwaysPermit>, Arc<maknae_config::Principal>, Duration) {
    (
        Arc::new(AlwaysPermit),
        Arc::new(fixture_principal()),
        Duration::from_secs(5),
    )
}

/// A backend whose `backend_name()` PANICS. Permits, so the request reaches
/// dispatch — the kernel calls `backend_name` INLINE on the async worker, and
/// unlike `subjects` it has no `spawn_blocking` backstop, so an unguarded
/// panic there unwinds through `handle()` after the audit record already said
/// permit/authorized.
pub struct PanickingName;

impl Authorizer for PanickingName {
    fn decide(&self, _r: &maknae_security::Request) -> Verdict {
        Verdict::Permit {
            obligations: vec![maknae_security::Obligation {
                id: "audit".into(),
                params: maknae_security::Attributes::new(),
            }],
        }
    }
    fn backend_name(&self) -> String {
        panic!("hostile backend name")
    }
}
