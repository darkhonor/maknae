//! Reach frames (ADR-0037 d7) wired to `maknae-deputy`'s driver: the loaded
//! `minting.yaml`, mint's signer and GitHub client, the forge opener and one
//! process-wide permit gate.

use crate::serve::ReachFrames;
use maknae_config::{EgressBounds, MintingFile};
use maknae_deputy::mint::github::GithubClient;
use maknae_deputy::mint::signer::{SignError, Signer};
use maknae_deputy::reach::admit::ReachConfig;
use maknae_deputy::reach::drive::{reach, ReachDeps, ReachGate};
use maknae_deputy::unseal::ForgeOpener;
use maknae_proto::{ReachRefusal, ReachReply, ReachRequest};
use std::future::Future;
use std::sync::Arc;
use zeroize::Zeroizing;

pub(crate) struct EgressReach<S, O> {
    file: Option<MintingFile>,
    minter: Option<Arc<S>>,
    opener: Arc<O>,
    github: Option<GithubClient>,
    bounds: Arc<EgressBounds>,
    gate: ReachGate,
    rt: tokio::runtime::Handle,
    journal: fn(&str),
}

pub(crate) struct Parts<S, O> {
    pub(crate) file: Option<MintingFile>,
    pub(crate) minter: Option<Arc<S>>,
    pub(crate) opener: Arc<O>,
    pub(crate) github: Option<GithubClient>,
    pub(crate) bounds: Arc<EgressBounds>,
    pub(crate) rt: tokio::runtime::Handle,
    pub(crate) journal: fn(&str),
}

impl<S, O> EgressReach<S, O> {
    pub(crate) fn new(p: Parts<S, O>) -> Self {
        Self {
            file: p.file,
            minter: p.minter,
            opener: p.opener,
            github: p.github,
            bounds: p.bounds,
            gate: ReachGate::new(),
            rt: p.rt,
            journal: p.journal,
        }
    }
}

/// Mint's signer when the minter is up; otherwise every sign is refused,
/// though admission never reaches one without it.
struct MinterSigner<'a, S>(Option<&'a S>);

impl<S: Signer + Sync> Signer for MinterSigner<'_, S> {
    fn sign(
        &self,
        mount: &str,
        key: &str,
        input: &[u8],
    ) -> impl Future<Output = Result<Zeroizing<Vec<u8>>, SignError>> + Send {
        let signer = self.0;
        async move {
            match signer {
                Some(s) => s.sign(mount, key, input).await,
                None => Err(SignError),
            }
        }
    }
}

impl<S, O> ReachFrames for EgressReach<S, O>
where
    S: Signer + Send + Sync,
    O: ForgeOpener + Send + Sync,
{
    fn reach(&self, req: &ReachRequest) -> ReachReply {
        let Some(github) = &self.github else {
            (self.journal)("reach is unavailable: the GitHub client could not be built");
            return ReachReply::Refused(ReachRefusal::Unanswered);
        };
        let cfg = ReachConfig {
            file: self.file.as_ref(),
            minter_ready: self.minter.is_some(),
            bounds: &self.bounds,
        };
        let signer = MinterSigner(self.minter.as_deref());
        let mut log = |l: &str| (self.journal)(l);
        let mut d = ReachDeps {
            signer: &signer,
            opener: &*self.opener,
            github,
            gate: &self.gate,
            clock: &crate::minting::unix_now,
            journal: &mut log,
        };
        self.rt.block_on(reach(req, &cfg, &mut d))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_frames::{agent_reach, bounds, tasker_reach};
    use maknae_deputy::mint::signer::FakeSigner;
    use maknae_deputy::unseal::{ForgeOpenRequest, OpenFailure};
    use std::io::{Read, Write};
    use std::sync::Mutex;

    const REPO_PUSH: &str = r#"{"id":1,"full_name":"o/r","permissions":{"admin":false,"maintain":false,"push":true,"triage":true,"pull":true}}"#;
    const APIS: &str = concat!(
        "apis:\n",
        "  github.example:\n",
        "    provider: github\n",
        "    api: https://api.github.example\n",
    );

    thread_local! {
        static LINES: std::cell::RefCell<Vec<String>> = const { std::cell::RefCell::new(Vec::new()) };
    }

    fn record(line: &str) {
        LINES.with(|l| l.borrow_mut().push(line.to_owned()));
    }

    fn recorded() -> Vec<String> {
        LINES.with(|l| std::mem::take(&mut *l.borrow_mut()))
    }

    struct Opener(Mutex<Vec<String>>);

    impl ForgeOpener for Opener {
        async fn open(
            &self,
            _sealed: &[u8],
            req: &ForgeOpenRequest<'_>,
        ) -> Result<Zeroizing<String>, OpenFailure> {
            self.0.lock().unwrap().push(req.expected_path().to_owned());
            Ok(Zeroizing::new("ghp_TASKERSENTINEL".into()))
        }
    }

    fn one_answer(body: &'static str) -> (String, std::thread::JoinHandle<String>) {
        let l = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let base = format!("http://{}", l.local_addr().unwrap());
        let h = std::thread::spawn(move || {
            let (mut s, _) = l.accept().unwrap();
            let mut seen = Vec::new();
            let mut buf = [0u8; 4096];
            while !seen.windows(4).any(|w| w == b"\r\n\r\n") {
                let n = s.read(&mut buf).unwrap();
                if n == 0 {
                    break;
                }
                seen.extend_from_slice(&buf[..n]);
            }
            let reply = format!(
                "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                body.len()
            );
            s.write_all(reply.as_bytes()).unwrap();
            String::from_utf8_lossy(&seen)
                .lines()
                .next()
                .unwrap_or_default()
                .to_owned()
        });
        (base, h)
    }

    fn rig(
        github: Option<GithubClient>,
        minter: Option<Arc<FakeSigner>>,
        rt: &tokio::runtime::Runtime,
    ) -> EgressReach<FakeSigner, Opener> {
        EgressReach::new(Parts {
            file: Some(
                maknae_config::minting_from_document(&maknae_config::load_str(APIS).unwrap())
                    .unwrap(),
            ),
            minter,
            opener: Arc::new(Opener(Mutex::new(vec![]))),
            github,
            bounds: Arc::new(bounds()),
            rt: rt.handle().clone(),
            journal: record,
        })
    }

    fn fips() {
        static ONCE: std::sync::Once = std::sync::Once::new();
        ONCE.call_once(|| maknae_crypto::init().unwrap());
    }

    #[test]
    fn a_tasker_frame_is_observed_through_the_driver_with_the_opened_token() {
        fips();
        let rt = crate::runtime().unwrap();
        let (base, stub) = one_answer(REPO_PUSH);
        let r = rig(Some(GithubClient::loopback_for_tests(&base)), None, &rt);
        recorded();
        let reply = r.reach(&tasker_reach("github.example"));
        assert!(matches!(reply, ReachReply::Observed(_)), "{reply:?}");
        assert_eq!(stub.join().unwrap(), "GET /repos/o/r HTTP/1.1");
        assert_eq!(
            *r.opener.0.lock().unwrap(),
            ["maknae/users/alice/forges/github.example"]
        );
        let lines = recorded();
        assert_eq!(lines.len(), 1, "{lines:?}");
        assert!(lines[0].ends_with(": observed"), "{lines:?}");
        assert!(!lines[0].contains("SENTINEL"), "{lines:?}");
    }

    #[test]
    fn without_a_minter_the_agent_side_has_no_forge_credential_and_signs_nothing() {
        fips();
        let rt = crate::runtime().unwrap();
        let r = rig(
            Some(GithubClient::loopback_for_tests("http://127.0.0.1:1")),
            None,
            &rt,
        );
        assert_eq!(
            r.reach(&agent_reach("github.example", "deploy")),
            ReachReply::NoForgeCredential
        );
        let signer = MinterSigner::<FakeSigner>(None);
        assert_eq!(
            rt.block_on(signer.sign("transit", "k", b"x")),
            Err(SignError)
        );
    }

    #[test]
    fn without_a_github_client_a_reach_frame_is_unanswered() {
        let rt = crate::runtime().unwrap();
        let r = rig(None, Some(Arc::new(FakeSigner::signing(b"sig"))), &rt);
        recorded();
        assert_eq!(
            r.reach(&tasker_reach("github.example")),
            ReachReply::Refused(ReachRefusal::Unanswered)
        );
        assert_eq!(
            recorded(),
            ["reach is unavailable: the GitHub client could not be built"]
        );
    }
}
