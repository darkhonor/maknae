//! The seam through which the App JWT's signing input is signed by Vault Transit.

use std::future::Future;
use std::sync::{Arc, Mutex, PoisonError};
use std::time::{Duration, Instant};
use zeroize::Zeroizing;

/// A cached Vault token is not used within this margin of its expiry.
pub const TOKEN_EXPIRY_MARGIN: Duration = Duration::from_secs(30);

/// The signature could not be had. Opaque: no Vault detail reaches the frame.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SignError;

pub trait Signer {
    fn sign(
        &self,
        mount: &str,
        key: &str,
        input: &[u8],
    ) -> impl Future<Output = Result<Zeroizing<Vec<u8>>, SignError>> + Send;
}

/// Why Vault refused a Transit sign: a refused token is the only one worth a re-login.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VaultSignError {
    TokenRefused,
    Failed,
}

pub trait VaultLogin: Send + Sync {
    type Token: Send + Sync;

    fn login(&self) -> impl Future<Output = Result<(Self::Token, Duration), SignError>> + Send;

    fn sign(
        &self,
        token: &Self::Token,
        mount: &str,
        key: &str,
        input: &[u8],
    ) -> impl Future<Output = Result<Zeroizing<Vec<u8>>, VaultSignError>> + Send;

    /// Vault refused a token it had just issued, so its policy may lack this Transit sign.
    fn refused_after_fresh_login(&self);
}

pub type Clock = Box<dyn Fn() -> Instant + Send + Sync>;

/// A Transit signer over a lazily logged-in Vault token, re-logging in at most once per sign.
/// Logins are single-flight: concurrent signs that need a token share one login.
pub struct ServiceSigner<L: VaultLogin> {
    login: L,
    now: Clock,
    slot: Mutex<Slot<Arc<L::Token>>>,
    refresh: tokio::sync::Mutex<()>,
}

struct Slot<T> {
    entry: Option<(T, Instant)>,
    generation: u64,
}

impl<L: VaultLogin> std::fmt::Debug for ServiceSigner<L> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ServiceSigner").finish_non_exhaustive()
    }
}

impl<L: VaultLogin> ServiceSigner<L> {
    pub fn new(login: L) -> Self {
        Self::with_clock(login, Box::new(Instant::now))
    }

    pub fn with_clock(login: L, now: Clock) -> Self {
        Self {
            login,
            now,
            slot: Mutex::new(Slot {
                entry: None,
                generation: 0,
            }),
            refresh: tokio::sync::Mutex::new(()),
        }
    }
}

impl<L: VaultLogin> ServiceSigner<L> {
    fn cached(&self) -> Option<(Arc<L::Token>, u64)> {
        let usable_until = (self.now)() + TOKEN_EXPIRY_MARGIN;
        // The slot is only ever replaced whole, so a poisoned one still holds a valid value.
        let slot = self.slot.lock().unwrap_or_else(PoisonError::into_inner);
        match &slot.entry {
            Some((token, expiry)) if usable_until < *expiry => {
                Some((Arc::clone(token), slot.generation))
            }
            _ => None,
        }
    }

    fn refusal(&self, after_fresh_login: VaultSignError) -> SignError {
        if after_fresh_login == VaultSignError::TokenRefused {
            self.login.refused_after_fresh_login();
        }
        SignError
    }

    /// A token newer than `stale` (the generation just refused, or none), from
    /// the cache if another sign refreshed it meanwhile, else from one login.
    async fn fresh(&self, stale: Option<u64>) -> Result<Arc<L::Token>, SignError> {
        let _single_flight = self.refresh.lock().await;
        if let Some((token, generation)) = self.cached() {
            if Some(generation) != stale {
                return Ok(token);
            }
        }
        let started = (self.now)();
        let (token, ttl) = self.login.login().await?;
        let token = Arc::new(token);
        let entry = started.checked_add(ttl).map(|e| (Arc::clone(&token), e));
        let mut slot = self.slot.lock().unwrap_or_else(PoisonError::into_inner);
        slot.entry = entry;
        slot.generation = slot.generation.wrapping_add(1);
        Ok(token)
    }
}

impl<L: VaultLogin> Signer for ServiceSigner<L> {
    async fn sign(
        &self,
        mount: &str,
        key: &str,
        input: &[u8],
    ) -> Result<Zeroizing<Vec<u8>>, SignError> {
        let (token, cached) = match self.cached() {
            Some((t, generation)) => (t, Some(generation)),
            None => (self.fresh(None).await?, None),
        };
        let token = match self.login.sign(&token, mount, key, input).await {
            Ok(signature) => return Ok(signature),
            Err(VaultSignError::TokenRefused) if cached.is_some() => self.fresh(cached).await?,
            Err(e) => return Err(self.refusal(e)),
        };
        self.login
            .sign(&token, mount, key, input)
            .await
            .map_err(|e| self.refusal(e))
    }
}

#[cfg(any(test, feature = "test-support"))]
pub struct FakeSigner {
    signature: Option<Vec<u8>>,
    calls: std::sync::Mutex<Vec<FakeSignCall>>,
}

#[cfg(any(test, feature = "test-support"))]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FakeSignCall {
    pub mount: String,
    pub key: String,
    pub input: Vec<u8>,
}

#[cfg(any(test, feature = "test-support"))]
impl FakeSigner {
    pub fn signing(signature: &[u8]) -> Self {
        Self {
            signature: Some(signature.to_vec()),
            calls: std::sync::Mutex::new(Vec::new()),
        }
    }

    pub fn failing() -> Self {
        Self {
            signature: None,
            calls: std::sync::Mutex::new(Vec::new()),
        }
    }

    pub fn calls(&self) -> Vec<FakeSignCall> {
        self.calls
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .clone()
    }
}

#[cfg(any(test, feature = "test-support"))]
impl Signer for FakeSigner {
    fn sign(
        &self,
        mount: &str,
        key: &str,
        input: &[u8],
    ) -> impl Future<Output = Result<Zeroizing<Vec<u8>>, SignError>> + Send {
        self.calls
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .push(FakeSignCall {
                mount: mount.to_owned(),
                key: key.to_owned(),
                input: input.to_vec(),
            });
        let out = match &self.signature {
            Some(sig) => Ok(Zeroizing::new(sig.clone())),
            None => Err(SignError),
        };
        std::future::ready(out)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::VecDeque;

    struct Tok(u32);

    struct FakeLogin {
        ttl: Duration,
        clock: Arc<Mutex<Instant>>,
        login_takes: Duration,
        logins: Mutex<Vec<Result<(), ()>>>,
        login_calls: Mutex<u32>,
        sign_script: Mutex<VecDeque<Result<(), VaultSignError>>>,
        signed_with: Mutex<Vec<u32>>,
        refused_fresh: Mutex<u32>,
    }

    impl FakeLogin {
        fn new(ttl: Duration, signs: Vec<Result<(), VaultSignError>>) -> Self {
            Self {
                ttl,
                clock: Arc::new(Mutex::new(Instant::now())),
                login_takes: Duration::ZERO,
                logins: Mutex::new(Vec::new()),
                login_calls: Mutex::new(0),
                sign_script: Mutex::new(signs.into()),
                signed_with: Mutex::new(Vec::new()),
                refused_fresh: Mutex::new(0),
            }
        }

        fn failing_login(self) -> Self {
            self.logins.lock().unwrap().push(Err(()));
            self
        }
    }

    impl VaultLogin for Arc<FakeLogin> {
        type Token = Tok;

        async fn login(&self) -> Result<(Tok, Duration), SignError> {
            let n = {
                let mut n = self.login_calls.lock().unwrap();
                *n += 1;
                *n
            };
            tokio::task::yield_now().await;
            *self.clock.lock().unwrap() += self.login_takes;
            if self.logins.lock().unwrap().pop() == Some(Err(())) {
                return Err(SignError);
            }
            Ok((Tok(n), self.ttl))
        }

        async fn sign(
            &self,
            token: &Tok,
            mount: &str,
            key: &str,
            input: &[u8],
        ) -> Result<Zeroizing<Vec<u8>>, VaultSignError> {
            assert_eq!((mount, key, input), ("transit", "app", &b"in"[..]));
            self.signed_with.lock().unwrap().push(token.0);
            let next = self
                .sign_script
                .lock()
                .unwrap()
                .pop_front()
                .unwrap_or(Ok(()));
            next.map(|()| Zeroizing::new(vec![token.0 as u8]))
        }

        fn refused_after_fresh_login(&self) {
            *self.refused_fresh.lock().unwrap() += 1;
        }
    }

    struct Rig {
        fake: Arc<FakeLogin>,
        clock: Arc<Mutex<Instant>>,
        signer: ServiceSigner<Arc<FakeLogin>>,
    }

    fn rig(fake: FakeLogin) -> Rig {
        let fake = Arc::new(fake);
        let clock = Arc::clone(&fake.clock);
        let c = Arc::clone(&clock);
        let signer =
            ServiceSigner::with_clock(Arc::clone(&fake), Box::new(move || *c.lock().unwrap()));
        Rig {
            fake,
            clock,
            signer,
        }
    }

    impl Rig {
        async fn sign(&self) -> Result<Vec<u8>, SignError> {
            self.signer
                .sign("transit", "app", b"in")
                .await
                .map(|s| s.to_vec())
        }

        fn advance(&self, by: Duration) {
            *self.clock.lock().unwrap() += by;
        }

        fn logins(&self) -> u32 {
            *self.fake.login_calls.lock().unwrap()
        }

        fn signed_with(&self) -> Vec<u32> {
            self.fake.signed_with.lock().unwrap().clone()
        }

        fn refused_fresh(&self) -> u32 {
            *self.fake.refused_fresh.lock().unwrap()
        }
    }

    const TTL: Duration = Duration::from_secs(900);

    #[tokio::test]
    async fn concurrent_signs_on_an_empty_cache_log_in_once() {
        let r = rig(FakeLogin::new(TTL, vec![]));
        let (a, b, c, d) = tokio::join!(r.sign(), r.sign(), r.sign(), r.sign());
        assert_eq!(
            [a, b, c, d],
            [Ok(vec![1]), Ok(vec![1]), Ok(vec![1]), Ok(vec![1])]
        );
        assert_eq!(r.logins(), 1);
        r.advance(TTL);
        let (a, b) = tokio::join!(r.sign(), r.sign());
        assert_eq!([a, b], [Ok(vec![2]), Ok(vec![2])]);
        assert_eq!(r.logins(), 2, "an expired token is replaced once");
    }

    #[tokio::test]
    async fn concurrent_refusals_of_one_token_replace_it_once() {
        let r = rig(FakeLogin::new(TTL, vec![]));
        assert_eq!(r.sign().await, Ok(vec![1]));
        r.fake.sign_script.lock().unwrap().extend([
            Err(VaultSignError::TokenRefused),
            Err(VaultSignError::TokenRefused),
        ]);
        let (a, b) = tokio::join!(r.sign(), r.sign());
        assert_eq!([a, b], [Ok(vec![2]), Ok(vec![2])]);
        assert_eq!(r.logins(), 2);
        assert_eq!(r.signed_with(), [1, 1, 1, 2, 2]);
        assert_eq!(r.sign().await, Ok(vec![2]), "the newer token stays cached");
    }

    #[tokio::test]
    async fn an_expired_vault_token_is_replaced_once() {
        let r = rig(FakeLogin::new(TTL, vec![]));
        assert_eq!(r.sign().await, Ok(vec![1]));
        assert_eq!(r.sign().await, Ok(vec![1]));
        assert_eq!(r.logins(), 1);
        r.advance(TTL - TOKEN_EXPIRY_MARGIN - Duration::from_secs(1));
        assert_eq!(r.sign().await, Ok(vec![1]), "still outside the margin");
        assert_eq!(r.logins(), 1);
        r.advance(Duration::from_secs(1));
        assert_eq!(r.sign().await, Ok(vec![2]), "inside the margin: replaced");
        assert_eq!(r.sign().await, Ok(vec![2]));
        assert_eq!(r.logins(), 2);
        assert_eq!(r.signed_with(), [1, 1, 1, 2, 2]);
        assert_eq!(TOKEN_EXPIRY_MARGIN, Duration::from_secs(30));
    }

    #[tokio::test]
    async fn the_expiry_is_counted_from_before_the_login() {
        let slow = Duration::from_secs(10);
        let r = rig(FakeLogin {
            login_takes: slow,
            ..FakeLogin::new(TTL, vec![])
        });
        assert_eq!(r.sign().await, Ok(vec![1]));
        r.advance(TTL - TOKEN_EXPIRY_MARGIN - slow);
        assert_eq!(r.sign().await, Ok(vec![2]));
        assert_eq!(r.logins(), 2);
    }

    #[tokio::test]
    async fn a_sign_403_does_not_relogin_in_a_loop() {
        let refused = Err(VaultSignError::TokenRefused);
        let fresh = rig(FakeLogin::new(TTL, vec![refused, refused, refused]));
        assert_eq!(fresh.sign().await, Err(SignError), "a fresh token refused");
        assert_eq!(fresh.logins(), 1);
        assert_eq!(fresh.signed_with(), [1]);
        assert_eq!(fresh.refused_fresh(), 1);

        let cached = rig(FakeLogin::new(TTL, vec![Ok(()), refused, refused, refused]));
        assert_eq!(cached.sign().await, Ok(vec![1]));
        assert_eq!(cached.sign().await, Err(SignError));
        assert_eq!(cached.logins(), 2, "one re-login, then the refusal stands");
        assert_eq!(cached.signed_with(), [1, 1, 2]);
        assert_eq!(
            cached.refused_fresh(),
            1,
            "the cached token's refusal is not it"
        );
    }

    #[tokio::test]
    async fn a_refused_cached_token_is_replaced_and_the_sign_retried_once() {
        let r = rig(FakeLogin::new(
            TTL,
            vec![Ok(()), Err(VaultSignError::TokenRefused)],
        ));
        assert_eq!(r.sign().await, Ok(vec![1]));
        assert_eq!(r.sign().await, Ok(vec![2]));
        assert_eq!(r.sign().await, Ok(vec![2]));
        assert_eq!(r.logins(), 2);
        assert_eq!(r.signed_with(), [1, 1, 2, 2]);
        assert_eq!(r.refused_fresh(), 0);
    }

    #[tokio::test]
    async fn a_sign_failure_that_is_not_a_refused_token_is_not_retried() {
        let r = rig(FakeLogin::new(
            TTL,
            vec![Ok(()), Err(VaultSignError::Failed)],
        ));
        assert_eq!(r.sign().await, Ok(vec![1]));
        assert_eq!(r.sign().await, Err(SignError));
        assert_eq!(r.logins(), 1);
        assert_eq!(r.signed_with(), [1, 1]);
        assert_eq!(r.sign().await, Ok(vec![1]), "the token is still cached");
        assert_eq!(r.refused_fresh(), 0);
    }

    #[tokio::test]
    async fn a_failure_after_a_fresh_login_that_is_not_a_refusal_is_not_reported_as_one() {
        let failed = Err(VaultSignError::Failed);
        let fresh = rig(FakeLogin::new(TTL, vec![failed]));
        assert_eq!(fresh.sign().await, Err(SignError));
        let relogged = rig(FakeLogin::new(
            TTL,
            vec![Ok(()), Err(VaultSignError::TokenRefused), failed],
        ));
        assert_eq!(relogged.sign().await, Ok(vec![1]));
        assert_eq!(relogged.sign().await, Err(SignError));
        assert_eq!(relogged.logins(), 2);
        assert_eq!((fresh.refused_fresh(), relogged.refused_fresh()), (0, 0));
    }

    #[tokio::test]
    async fn a_failed_login_signs_nothing_and_caches_nothing() {
        let r = rig(FakeLogin::new(TTL, vec![]).failing_login());
        assert_eq!(r.sign().await, Err(SignError));
        assert!(r.signed_with().is_empty());
        assert_eq!(r.sign().await, Ok(vec![2]));
        assert_eq!(r.logins(), 2);
    }

    #[tokio::test]
    async fn a_failed_re_login_is_a_sign_error() {
        let r = rig(FakeLogin::new(
            TTL,
            vec![Ok(()), Err(VaultSignError::TokenRefused)],
        ));
        assert_eq!(r.sign().await, Ok(vec![1]));
        r.fake.logins.lock().unwrap().push(Err(()));
        assert_eq!(r.sign().await, Err(SignError));
        assert_eq!(r.logins(), 2);
        assert_eq!(r.signed_with(), [1, 1]);
    }

    #[tokio::test]
    async fn a_ttl_past_the_clock_s_range_is_used_once_and_not_cached() {
        let r = rig(FakeLogin::new(Duration::MAX, vec![]));
        assert_eq!(r.sign().await, Ok(vec![1]));
        assert_eq!(r.sign().await, Ok(vec![2]));
        assert_eq!(r.logins(), 2);
    }

    #[tokio::test]
    async fn a_poisoned_token_slot_still_signs() {
        let r = rig(FakeLogin::new(TTL, vec![]));
        assert_eq!(r.sign().await, Ok(vec![1]));
        let _ = std::thread::scope(|s| {
            s.spawn(|| {
                let _held = r.signer.slot.lock().unwrap();
                panic!("poison the slot");
            })
            .join()
        });
        assert!(r.signer.slot.is_poisoned());
        assert_eq!(r.sign().await, Ok(vec![1]));
        assert_eq!(r.logins(), 1);
        assert_eq!(format!("{:?}", r.signer), "ServiceSigner { .. }");
    }

    #[tokio::test]
    async fn the_fake_records_each_call_and_answers_as_built() {
        let ok = FakeSigner::signing(&[1, 2, 3]);
        assert_eq!(
            ok.sign("transit", "deploy", b"in")
                .await
                .unwrap()
                .as_slice(),
            &[1, 2, 3]
        );
        assert_eq!(
            ok.calls(),
            vec![FakeSignCall {
                mount: "transit".into(),
                key: "deploy".into(),
                input: b"in".to_vec(),
            }]
        );
        let bad = FakeSigner::failing();
        assert_eq!(bad.sign("m", "k", b"x").await, Err(SignError));
        assert_eq!(bad.calls().len(), 1);
    }
}
