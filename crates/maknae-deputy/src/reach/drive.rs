//! One reach frame end to end: admission, a permit, then the forge's observer
//! driven against the API under the frame's deadline, revoking any token it minted.

use super::admit::{admit_reach, AdmittedReach, AdmittedSide, ReachConfig};
use super::open::{open_refusal, tasker_token_is_usable};
use crate::mint::github::{forge_status, ForgeError, GithubClient, GrantError};
use crate::mint::jwt::{assemble_jwt, signing_input};
use crate::mint::minter::live_token_may_remain;
use crate::mint::signer::Signer;
use crate::unseal::ForgeOpener;
use maknae_config::{ApiBase, GithubAppConfig, REACH_CONCURRENCY_MAX};
use maknae_forge::{Auth, HttpReply, Step};
use maknae_io::MaknaeSecret;
use maknae_proto::{Observations, ReachRefusal, ReachReply, ReachRequest, ReachSide};
use std::time::Duration;

/// The deputy's own bound on concurrent reach exchanges; waiting for one counts against the frame's deadline.
pub struct ReachGate(tokio::sync::Semaphore);

impl ReachGate {
    pub fn new() -> Self {
        Self::with_permits(REACH_CONCURRENCY_MAX)
    }

    fn with_permits(n: usize) -> Self {
        Self(tokio::sync::Semaphore::new(n))
    }
}

impl Default for ReachGate {
    fn default() -> Self {
        Self::new()
    }
}

pub struct ReachDeps<'a, S: Signer, O: ForgeOpener> {
    pub signer: &'a S,
    pub opener: &'a O,
    pub github: &'a GithubClient,
    pub gate: &'a ReachGate,
    /// Unix seconds, read once for the frame's App JWT; `None` refuses `Signer`.
    pub clock: &'a dyn Fn() -> Option<u64>,
    pub journal: &'a mut dyn FnMut(&str),
}

struct Held {
    github: GithubClient,
    api: ApiBase,
    token: Option<MaknaeSecret>,
    minting: bool,
}

impl Held {
    fn new(github: &GithubClient, api: &ApiBase) -> Self {
        Self {
            github: github.clone(),
            api: api.clone(),
            token: None,
            minting: false,
        }
    }
}

/// An exchange that unwinds while holding a token cannot await its revoke, so it is sent from a thread of its own.
impl Drop for Held {
    fn drop(&mut self) {
        let Some(token) = self.token.take() else {
            return;
        };
        let github = self.github.clone();
        let api = self.api.clone();
        let spawned = std::thread::Builder::new()
            .name("maknae-reach-revoke".into())
            .spawn(move || {
                let status = tokio::runtime::Builder::new_current_thread()
                    .enable_all()
                    .build()
                    .ok()
                    .and_then(|rt| rt.block_on(github.revoke_status(&api, token.expose())).ok());
                if let Some(line) = unwound_line(status) {
                    eprintln!("{line}");
                }
            });
        if spawned.is_err() {
            eprintln!("{UNWOUND}");
        }
    }
}

fn unwound_line(revoke_status: Option<u16>) -> Option<&'static str> {
    match revoke_status {
        Some(204 | 401) => None,
        _ => Some(UNWOUND),
    }
}

const UNWOUND: &str =
    "maknae-egress: a reach exchange unwound holding a metadata-read token that could not be revoked";

pub async fn reach<S: Signer, O: ForgeOpener>(
    req: &ReachRequest,
    cfg: &ReachConfig<'_>,
    d: &mut ReachDeps<'_, S, O>,
) -> ReachReply {
    let by = tokio::time::Instant::now() + Duration::from_millis(req.deadline_ms());
    let (reply, unknown) = match admit_reach(req, cfg) {
        Ok(admitted) => drive(&admitted, d, by).await,
        Err(r) => (ReachReply::Refused(r), None),
    };
    (d.journal)(&journal_line(req, &reply, unknown));
    reply
}

async fn drive<S: Signer, O: ForgeOpener>(
    a: &AdmittedReach<'_>,
    d: &mut ReachDeps<'_, S, O>,
    by: tokio::time::Instant,
) -> (ReachReply, Option<&'static str>) {
    if let AdmittedSide::NoForgeCredential = a.side() {
        return (ReachReply::NoForgeCredential, None);
    }
    let Ok(Ok(_permit)) = tokio::time::timeout_at(by, d.gate.0.acquire()).await else {
        return (
            ReachReply::Refused(ReachRefusal::Unanswered),
            Some("at capacity"),
        );
    };
    let mut held = Held::new(d.github, a.api());
    let outcome = tokio::time::timeout_at(by, exchange(a, d, &mut held)).await;
    if held.minting {
        possibly_live(a.req().server(), ForgeError::Unanswered, d.journal);
    }
    if let Some(token) = held.token.take() {
        revoke(
            d.github,
            a.api(),
            token.expose(),
            a.req().server(),
            d.journal,
        )
        .await;
    }
    match outcome {
        Ok(Ok(observed)) => (ReachReply::Observed(observed), None),
        Ok(Err(r)) => (ReachReply::Refused(r), None),
        Err(_) => (
            ReachReply::Refused(ReachRefusal::Unanswered),
            Some("deadline"),
        ),
    }
}

async fn exchange<S: Signer, O: ForgeOpener>(
    a: &AdmittedReach<'_>,
    d: &mut ReachDeps<'_, S, O>,
    held: &mut Held,
) -> Result<Observations, ReachRefusal> {
    let asks = a.req().asks();
    let (mut observer, tasker, app) = match a.side() {
        AdmittedSide::Tasker { open, sealed } => {
            let token = d
                .opener
                .open(sealed.as_bytes(), open)
                .await
                .map_err(open_refusal)?;
            if !tasker_token_is_usable(token.expose()) {
                return Err(ReachRefusal::Login);
            }
            (a.reach().tasker(asks), Some(token), None)
        }
        AdmittedSide::App(app) => (a.reach().agent(app.installation_id, asks), None, Some(*app)),
        AdmittedSide::NoForgeCredential => return Err(ReachRefusal::Request),
    };
    let server = a.req().server();
    let mut jwt = None;
    let mut last = None;
    for _ in 0..=observer.calls_max() {
        last = match observer.next(last.take()) {
            Step::Done(result) => return result,
            Step::Get { path, auth } => {
                let bearer = match (auth, app) {
                    (Auth::Tasker, _) => tasker.as_ref().map(|t| t.expose()),
                    (Auth::AppJwt, Some(app)) => Some(app_jwt(app, d, &mut jwt).await?),
                    (Auth::AppJwt, None) => None,
                    (Auth::Installation, _) => held.token.as_ref().map(|t| t.expose()),
                };
                match bearer {
                    Some(bearer) => d.github.get(a.api(), &path, bearer).await.ok(),
                    None => None,
                }
            }
            Step::MintMetadataRead { installation } => match app {
                Some(app) if installation == app.installation_id && held.token.is_none() => {
                    let bearer = app_jwt(app, d, &mut jwt).await?;
                    held.minting = true;
                    let minted = d
                        .github
                        .mint_metadata_read(a.api(), installation, bearer)
                        .await;
                    held.minting = false;
                    match minted {
                        Ok(minted) => {
                            held.token = Some(minted.token);
                            Some(empty(201))
                        }
                        Err(e) => {
                            let (reply, forge) = match e {
                                GrantError::Status(code) => {
                                    (Some(empty(code)), ForgeError::Status(forge_status(code)))
                                }
                                GrantError::Undocumented { status, revoked } => {
                                    (Some(empty(status)), ForgeError::Undocumented { revoked })
                                }
                                GrantError::Forge(e) => (None, e),
                            };
                            if live_token_may_remain(forge) {
                                possibly_live(server, forge, d.journal);
                            }
                            reply
                        }
                    }
                }
                _ => None,
            },
            Step::Revoke => {
                let sent = match held.token.as_ref() {
                    Some(token) => Some(d.github.revoke_status(a.api(), token.expose()).await),
                    None => None,
                };
                match sent {
                    Some(Ok(status)) => {
                        if matches!(status, 204 | 401) {
                            held.token = None;
                        }
                        Some(empty(status))
                    }
                    Some(Err(_)) | None => None,
                }
            }
        };
    }
    Err(ReachRefusal::Request)
}

fn empty(status: u16) -> HttpReply {
    HttpReply {
        status,
        body: Vec::new(),
    }
}

async fn app_jwt<'j, S: Signer, O: ForgeOpener>(
    app: &GithubAppConfig,
    d: &mut ReachDeps<'_, S, O>,
    jwt: &'j mut Option<MaknaeSecret>,
) -> Result<&'j str, ReachRefusal> {
    let token = match jwt.take() {
        Some(token) => token,
        None => {
            let now = (d.clock)().ok_or(ReachRefusal::Signer)?;
            let input = signing_input(app.app_id, now);
            let signature = d
                .signer
                .sign(&app.transit_mount, &app.transit_key, input.as_bytes())
                .await
                .map_err(|_| ReachRefusal::Signer)?;
            let held = assemble_jwt(&input, &signature);
            drop(signature);
            held.map_err(|e| {
                (d.journal)(&format!("reach: the App JWT could not be held: {e:?}"));
                ReachRefusal::Signer
            })?
        }
    };
    Ok(jwt.insert(token).expose())
}

async fn revoke(
    github: &GithubClient,
    api: &ApiBase,
    token: &str,
    server: &str,
    journal: &mut dyn FnMut(&str),
) {
    let failure = match github.revoke_status(api, token).await {
        Ok(204 | 401) => return,
        Ok(status) => format!("HTTP {status}"),
        Err(e) => format!("{e:?}"),
    };
    unrevoked(server, &failure, journal);
}

fn possibly_live(server: &str, why: ForgeError, journal: &mut dyn FnMut(&str)) {
    journal(&format!(
        "reach mint server={server:?}: a live token may exist and cannot be revoked: {why:?}"
    ));
}

fn unrevoked(server: &str, failure: &str, journal: &mut dyn FnMut(&str)) {
    journal(&format!(
        "reach revoke server={server:?}: a minted metadata-read token could not be revoked: {failure}"
    ));
}

fn journal_line(req: &ReachRequest, reply: &ReachReply, unknown: Option<&str>) -> String {
    let side = match req.side() {
        ReachSide::Tasker { .. } => "tasker",
        ReachSide::Agent { .. } => "agent",
    };
    let class = match reply {
        ReachReply::Observed(_) => "observed".to_owned(),
        ReachReply::NoForgeCredential => "no_forge_credential".to_owned(),
        ReachReply::Refused(r) => format!("refused {}", refusal_name(*r)),
    };
    let mut line = format!(
        "reach server={:?} provider={:?} side={side} asks={}: {class}",
        req.server(),
        req.provider(),
        req.asks().len()
    );
    if let Some(why) = unknown {
        line.push_str("; reach outcome unknown: ");
        line.push_str(why);
    }
    line
}

fn refusal_name(r: ReachRefusal) -> &'static str {
    match r {
        ReachRefusal::Request => "request",
        ReachRefusal::Seal => "seal",
        ReachRefusal::Login => "login",
        ReachRefusal::NotFound => "not_found",
        ReachRefusal::Unauthorized => "unauthorized",
        ReachRefusal::Forbidden => "forbidden",
        ReachRefusal::Moved => "moved",
        ReachRefusal::Upstream => "upstream",
        ReachRefusal::Unanswered => "unanswered",
        ReachRefusal::Shape => "shape",
        ReachRefusal::Suspended => "suspended",
        ReachRefusal::AmbiguousCredential => "ambiguous_credential",
        ReachRefusal::Signer => "signer",
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::mint::signer::FakeSigner;
    use crate::reach::testutil::{app_frame, bounds, file, tasker_frame, MINTING};
    use crate::unseal::{ForgeOpenRequest, OpenFailure};
    use maknae_config::{EgressBounds, MintingFile};
    use maknae_forge::{ForgeReach, Observer};
    use maknae_proto::{ForgeOp, RepoAsk};
    use std::sync::Mutex;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use zeroize::Zeroizing;

    const TASKER_TOKEN: &str = "ghp_TASKER_TOKEN_SENTINEL";
    const INSTALLATION_TOKEN: &str = "ghs_INSTALLATION_TOKEN_SENTINEL";
    const SIGNATURE: &[u8] = b"transit-signature-sentinel";
    const NOW: u64 = 1_800_000_000;
    const APP: &str = "github-app-installation";
    const INSTALLATION: &str = r#"{"id":77,"account":{"login":"o"},"app_id":5834363,"permissions":{"contents":"write","metadata":"read","pull_requests":"write","issues":"write"},"repository_selection":"selected","suspended_at":null}"#;
    const REPO_PUSH: &str = r#"{"id":1,"full_name":"o/r","permissions":{"admin":false,"maintain":false,"push":true,"triage":true,"pull":true}}"#;

    fn fips() {
        static ONCE: std::sync::Once = std::sync::Once::new();
        ONCE.call_once(|| maknae_crypto::init().unwrap());
    }

    fn jwt() -> String {
        assemble_jwt(&signing_input(5834363, NOW), SIGNATURE)
            .unwrap()
            .expose()
            .to_owned()
    }

    fn metadata_grant(perms: &str) -> String {
        format!(
            r#"{{"token":"{INSTALLATION_TOKEN}","expires_at":"2026-11-23T01:00:00Z","permissions":{perms},"repository_selection":"selected"}}"#
        )
    }

    fn listing(names: &[&str]) -> String {
        let repos: Vec<String> = names
            .iter()
            .map(|n| format!(r#"{{"id":1,"name":"r","full_name":"{n}","private":true}}"#))
            .collect();
        format!(
            r#"{{"total_count":{},"repositories":[{}]}}"#,
            names.len(),
            repos.join(",")
        )
    }

    enum Answer {
        Reply(&'static str, String),
        Late(Duration, &'static str, String),
        Close,
    }

    fn ok(body: &str) -> Answer {
        Answer::Reply("200 OK", body.into())
    }

    fn status(line: &'static str) -> Answer {
        Answer::Reply(line, r#"{"message":"x"}"#.into())
    }

    fn http(status: &str, body: &str) -> String {
        format!(
            "HTTP/1.1 {status}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
            body.len()
        )
    }

    struct Seen {
        requests: Vec<String>,
        extra: usize,
        abandoned: usize,
    }

    impl Seen {
        fn lines(&self) -> Vec<String> {
            self.requests
                .iter()
                .map(|r| r.lines().next().unwrap_or_default().to_owned())
                .collect()
        }

        fn bearer(&self, i: usize) -> String {
            self.requests[i]
                .lines()
                .find_map(|l| l.strip_prefix("authorization: Bearer "))
                .unwrap_or_default()
                .to_owned()
        }
    }

    async fn read_request(s: &mut tokio::net::TcpStream) -> String {
        let mut seen = Vec::new();
        let mut buf = vec![0u8; 8192];
        loop {
            let n = s.read(&mut buf).await.unwrap_or(0);
            if n == 0 {
                break;
            }
            seen.extend_from_slice(&buf[..n]);
            let Some(brk) = seen.windows(4).position(|w| w == b"\r\n\r\n") else {
                continue;
            };
            let head = String::from_utf8_lossy(&seen[..brk]).to_lowercase();
            let want = head
                .lines()
                .find_map(|l| l.strip_prefix("content-length:"))
                .and_then(|v| v.trim().parse::<usize>().ok())
                .unwrap_or(0);
            if seen.len() - (brk + 4) >= want {
                break;
            }
        }
        let text = String::from_utf8_lossy(&seen).to_string();
        let (head, body) = text.split_once("\r\n\r\n").unwrap_or((&text, ""));
        let mut lines = head.lines();
        let first = lines.next().unwrap_or_default().to_string();
        let rest: Vec<String> = lines
            .map(|l| match l.split_once(':') {
                Some((k, v)) => format!("{}:{v}", k.to_lowercase()),
                None => l.to_string(),
            })
            .collect();
        format!("{first}\n{}\n\n{body}", rest.join("\n"))
    }

    async fn stub(script: Vec<Answer>) -> (String, tokio::task::JoinHandle<Seen>) {
        let l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = l.local_addr().unwrap();
        let h = tokio::spawn(async move {
            let mut requests = Vec::new();
            let mut abandoned = 0;
            for answer in script {
                let Ok(accepted) = tokio::time::timeout(Duration::from_secs(5), l.accept()).await
                else {
                    break;
                };
                let (mut s, _) = accepted.unwrap();
                requests.push(read_request(&mut s).await);
                match answer {
                    Answer::Reply(st, body) => {
                        let _ = s.write_all(http(st, &body).as_bytes()).await;
                        let _ = s.flush().await;
                    }
                    Answer::Late(wait, st, body) => {
                        tokio::time::sleep(wait).await;
                        let mut probe = [0u8; 1];
                        let hung_up = matches!(
                            tokio::time::timeout(Duration::from_millis(50), s.read(&mut probe))
                                .await,
                            Ok(Ok(0) | Err(_))
                        );
                        abandoned += usize::from(hung_up);
                        let _ = s.write_all(http(st, &body).as_bytes()).await;
                    }
                    Answer::Close => drop(s),
                }
            }
            let extra = usize::from(
                tokio::time::timeout(Duration::from_millis(300), l.accept())
                    .await
                    .is_ok(),
            );
            Seen {
                requests,
                extra,
                abandoned,
            }
        });
        (format!("http://{addr}"), h)
    }

    struct FakeOpener {
        token: Result<&'static str, OpenFailure>,
        opened: Mutex<Vec<String>>,
    }

    impl FakeOpener {
        fn giving(token: &'static str) -> Self {
            Self {
                token: Ok(token),
                opened: Mutex::new(vec![]),
            }
        }

        fn failing(f: OpenFailure) -> Self {
            Self {
                token: Err(f),
                opened: Mutex::new(vec![]),
            }
        }
    }

    impl ForgeOpener for FakeOpener {
        async fn open(
            &self,
            sealed: &[u8],
            req: &ForgeOpenRequest<'_>,
        ) -> Result<MaknaeSecret, OpenFailure> {
            self.opened.lock().unwrap().push(format!(
                "{}|{}|{}|{}",
                req.server(),
                req.expected_path(),
                req.key_field(),
                sealed.len()
            ));
            self.token
                .map(|t| MaknaeSecret::new(Zeroizing::new(t.to_owned())).unwrap())
        }
    }

    struct Rig {
        file: MintingFile,
        bounds: EgressBounds,
        minter_ready: bool,
        signer: FakeSigner,
        opener: FakeOpener,
        gate: std::sync::Arc<ReachGate>,
        clock: Option<u64>,
        journal: Vec<String>,
    }

    impl Rig {
        fn new() -> Self {
            fips();
            Self {
                file: file(MINTING),
                bounds: bounds(),
                minter_ready: true,
                signer: FakeSigner::signing(SIGNATURE),
                opener: FakeOpener::giving(TASKER_TOKEN),
                gate: std::sync::Arc::new(ReachGate::new()),
                clock: Some(NOW),
                journal: vec![],
            }
        }

        async fn run(&mut self, req: &ReachRequest, script: Vec<Answer>) -> (ReachReply, Seen) {
            let (base, h) = stub(script).await;
            let github = GithubClient::loopback_for_tests(&base);
            let cfg = ReachConfig {
                file: Some(&self.file),
                minter_ready: self.minter_ready,
                bounds: &self.bounds,
            };
            let clock = self.clock;
            let mut journal = |l: &str| self.journal.push(l.to_owned());
            let mut d = ReachDeps {
                signer: &self.signer,
                opener: &self.opener,
                github: &github,
                gate: &self.gate,
                clock: &move || clock,
                journal: &mut journal,
            };
            let reply = reach(req, &cfg, &mut d).await;
            (reply, h.await.unwrap())
        }

        async fn observed_by(
            &mut self,
            req: &ReachRequest,
            reach: &'static dyn ForgeReach,
            script: Vec<Answer>,
        ) -> (ReachReply, Seen) {
            let (base, h) = stub(script).await;
            let github = GithubClient::loopback_for_tests(&base);
            let cfg = ReachConfig {
                file: Some(&self.file),
                minter_ready: self.minter_ready,
                bounds: &self.bounds,
            };
            let clock = self.clock;
            let mut journal = |l: &str| self.journal.push(l.to_owned());
            let mut d = ReachDeps {
                signer: &self.signer,
                opener: &self.opener,
                github: &github,
                gate: &self.gate,
                clock: &move || clock,
                journal: &mut journal,
            };
            let admitted = admit_reach(req, &cfg).unwrap().observed_by(reach);
            let by = tokio::time::Instant::now() + Duration::from_millis(req.deadline_ms());
            let (reply, _) = drive(&admitted, &mut d, by).await;
            (reply, h.await.unwrap())
        }
    }

    struct Scripted {
        steps: Vec<Step>,
        answered: std::sync::Arc<Mutex<Vec<Option<u16>>>>,
    }

    struct ScriptedObserver {
        steps: std::vec::IntoIter<Step>,
        answered: std::sync::Arc<Mutex<Vec<Option<u16>>>>,
        started: bool,
    }

    impl Observer for ScriptedObserver {
        fn next(&mut self, last: Option<HttpReply>) -> Step {
            if self.started {
                self.answered.lock().unwrap().push(last.map(|r| r.status));
            }
            self.started = true;
            self.steps
                .next()
                .unwrap_or(Step::Done(Err(ReachRefusal::Shape)))
        }

        fn calls_max(&self) -> usize {
            8
        }
    }

    impl ForgeReach for Scripted {
        fn tasker(&self, _: &[RepoAsk]) -> Box<dyn Observer> {
            unreachable!("only the agent side is scripted")
        }

        fn agent(&self, _: u64, _: &[RepoAsk]) -> Box<dyn Observer> {
            Box::new(ScriptedObserver {
                steps: self.steps.clone().into_iter(),
                answered: std::sync::Arc::clone(&self.answered),
                started: false,
            })
        }
    }

    fn scripted(steps: Vec<Step>) -> &'static Scripted {
        Box::leak(Box::new(Scripted {
            steps,
            answered: std::sync::Arc::default(),
        }))
    }

    fn tasker() -> ReachRequest {
        tasker_frame("github.com", "github", 20_000)
    }

    fn agent() -> ReachRequest {
        app_frame("github.com", "github", &[(APP, "deploy")])
    }

    fn app_flow_until_listing() -> Vec<Answer> {
        vec![
            ok(INSTALLATION),
            Answer::Reply("201 Created", metadata_grant(r#"{"metadata":"read"}"#)),
        ]
    }

    fn refused(r: &ReachReply) -> Option<ReachRefusal> {
        match r {
            ReachReply::Refused(c) => Some(*c),
            ReachReply::Observed(_) | ReachReply::NoForgeCredential => None,
        }
    }

    #[tokio::test]
    async fn a_tasker_frame_is_observed_with_the_opened_token() {
        let mut rig = Rig::new();
        let (reply, seen) = rig.run(&tasker(), vec![ok(REPO_PUSH)]).await;
        let ReachReply::Observed(o) = reply else {
            panic!("{reply:?}")
        };
        let base = o.as_slice()[0].base();
        assert!(
            base.contains(ForgeOp::Read) && base.contains(ForgeOp::Merge),
            "{base:?}"
        );
        assert_eq!(
            (seen.lines(), seen.extra),
            (vec!["GET /repos/o/r HTTP/1.1".to_owned()], 0)
        );
        assert_eq!(seen.bearer(0), TASKER_TOKEN);
        assert_eq!(
            *rig.opener.opened.lock().unwrap(),
            ["github.com|maknae/users/alice/forges/github.com|token|200"]
        );
    }

    #[tokio::test]
    async fn the_reach_login_stays_in_the_minting_module() {
        let mut rig = Rig::new();
        rig.signer = FakeSigner::failing();
        rig.minter_ready = false;
        let (reply, _) = rig.run(&tasker(), vec![ok(REPO_PUSH)]).await;
        assert!(matches!(reply, ReachReply::Observed(_)), "{reply:?}");
        assert!(rig.signer.calls().is_empty());

        let mut rig = Rig::new();
        let mut script = app_flow_until_listing();
        script.extend([
            ok(&listing(&["o/r"])),
            Answer::Reply("204 No Content", String::new()),
        ]);
        let (reply, seen) = rig.run(&agent(), script).await;
        assert!(matches!(reply, ReachReply::Observed(_)), "{reply:?}");
        let calls = rig.signer.calls();
        assert_eq!(calls.len(), 1, "one JWT per frame");
        assert_eq!(
            (calls[0].mount.as_str(), calls[0].key.as_str()),
            ("transit", "deploy-app")
        );
        assert_eq!(calls[0].input, signing_input(5834363, NOW).into_bytes());
        assert_eq!((seen.bearer(0), seen.bearer(1)), (jwt(), jwt()));
        assert!(rig.opener.opened.lock().unwrap().is_empty());
    }

    #[tokio::test]
    async fn the_app_side_never_calls_get_repos() {
        let mut rig = Rig::new();
        let mut script = app_flow_until_listing();
        script.extend([
            ok(&listing(&["o/r"])),
            Answer::Reply("204 No Content", String::new()),
        ]);
        let (reply, seen) = rig.run(&agent(), script).await;
        let ReachReply::Observed(o) = reply else {
            panic!("{reply:?}")
        };
        assert!(o.as_slice()[0].covered());
        assert!(o.as_slice()[0].base().contains(ForgeOp::Merge));
        assert_eq!(
            seen.lines(),
            [
                "GET /app/installations/77 HTTP/1.1",
                "POST /app/installations/77/access_tokens HTTP/1.1",
                "GET /installation/repositories?per_page=100&page=1 HTTP/1.1",
                "DELETE /installation/token HTTP/1.1",
            ]
        );
        assert_eq!(seen.extra, 0);
        assert!(seen.lines().iter().all(|l| !l.starts_with("GET /repos")));
        assert_eq!(
            [seen.bearer(2), seen.bearer(3)],
            [INSTALLATION_TOKEN, INSTALLATION_TOKEN]
        );
        let (_, body) = seen.requests[1].split_once("\n\n").unwrap();
        assert_eq!(
            serde_json::from_str::<serde_json::Value>(body).unwrap(),
            serde_json::json!({"permissions":{"metadata":"read"}})
        );
    }

    #[tokio::test]
    async fn each_github_failure_reaches_its_class() {
        for (answer, class) in [
            (status("401 Unauthorized"), ReachRefusal::Unauthorized),
            (status("403 Forbidden"), ReachRefusal::Forbidden),
            (status("429 Too Many Requests"), ReachRefusal::Forbidden),
            (status("404 Not Found"), ReachRefusal::NotFound),
            (status("301 Moved Permanently"), ReachRefusal::Moved),
            (status("500 Internal Server Error"), ReachRefusal::Upstream),
            (ok(r#"{"full_name":"o/r"}"#), ReachRefusal::Shape),
            (Answer::Close, ReachRefusal::Unanswered),
        ] {
            let mut rig = Rig::new();
            let (reply, seen) = rig.run(&tasker(), vec![answer]).await;
            assert_eq!(refused(&reply), Some(class));
            assert_eq!(seen.requests.len(), 1, "{class:?}");
        }

        for (opener, class) in [
            (FakeOpener::failing(OpenFailure::Seal), ReachRefusal::Seal),
            (FakeOpener::failing(OpenFailure::Field), ReachRefusal::Login),
            (
                FakeOpener::failing(OpenFailure::Invalid),
                ReachRefusal::Login,
            ),
            (
                FakeOpener::giving("ghp_x\r\nX-Evil: 1"),
                ReachRefusal::Login,
            ),
        ] {
            let mut rig = Rig::new();
            rig.opener = opener;
            let (reply, seen) = rig.run(&tasker(), vec![]).await;
            assert_eq!(refused(&reply), Some(class));
            assert_eq!((seen.requests.len(), seen.extra), (0, 0), "{class:?}");
        }

        let mut rig = Rig::new();
        rig.signer = FakeSigner::failing();
        let (reply, seen) = rig.run(&agent(), vec![]).await;
        assert_eq!(refused(&reply), Some(ReachRefusal::Signer));
        assert_eq!((seen.requests.len(), seen.extra), (0, 0));

        let mut rig = Rig::new();
        rig.clock = None;
        let (reply, _) = rig.run(&agent(), vec![]).await;
        assert_eq!(refused(&reply), Some(ReachRefusal::Signer));

        let mut rig = Rig::new();
        let suspended = INSTALLATION.replace(
            r#""suspended_at":null"#,
            r#""suspended_at":"2026-11-01T00:00:00Z""#,
        );
        let (reply, seen) = rig.run(&agent(), vec![ok(&suspended)]).await;
        assert_eq!(refused(&reply), Some(ReachRefusal::Suspended));
        assert_eq!(seen.requests.len(), 1);

        for (answer, class) in [
            (status("401 Unauthorized"), ReachRefusal::Unauthorized),
            (status("404 Not Found"), ReachRefusal::NotFound),
            (status("422 Unprocessable Entity"), ReachRefusal::Upstream),
        ] {
            let mut rig = Rig::new();
            let (reply, seen) = rig.run(&agent(), vec![ok(INSTALLATION), answer]).await;
            assert_eq!(refused(&reply), Some(class));
            assert_eq!(seen.requests.len(), 2, "{class:?}: nothing to revoke");
        }
    }

    #[tokio::test]
    async fn the_deadline_refuses_unanswered() {
        let mut rig = Rig::new();
        let late = tasker_frame("github.com", "github", 300);
        let (reply, seen) = rig
            .run(
                &late,
                vec![Answer::Late(
                    Duration::from_millis(1500),
                    "200 OK",
                    REPO_PUSH.into(),
                )],
            )
            .await;
        assert_eq!(refused(&reply), Some(ReachRefusal::Unanswered));
        assert_eq!(seen.requests.len(), 1);
        assert!(
            rig.journal[0].ends_with("refused unanswered; reach outcome unknown: deadline"),
            "{}",
            rig.journal[0]
        );
    }

    #[tokio::test]
    async fn a_token_held_past_the_deadline_is_revoked() {
        let mut rig = Rig::new();
        let late = app_frame_with_deadline(600);
        let mut script = app_flow_until_listing();
        script.extend([
            Answer::Late(Duration::from_millis(1500), "200 OK", listing(&["o/r"])),
            Answer::Reply("204 No Content", String::new()),
        ]);
        let (reply, seen) = rig.run(&late, script).await;
        assert_eq!(refused(&reply), Some(ReachRefusal::Unanswered));
        assert_eq!(
            seen.lines().last().map(String::as_str),
            Some("DELETE /installation/token HTTP/1.1")
        );
        assert_eq!(seen.bearer(3), INSTALLATION_TOKEN);
        assert_eq!(seen.extra, 0);
    }

    fn app_frame_with_deadline(deadline_ms: u64) -> ReachRequest {
        ReachRequest::new(
            "github.com".into(),
            "github".into(),
            deadline_ms,
            ReachSide::Agent {
                agent: "coder".into(),
                credentials: vec![maknae_proto::CredentialRef {
                    kind: APP.into(),
                    name: "deploy".into(),
                }],
            },
            agent().asks().to_vec(),
        )
        .unwrap()
    }

    #[tokio::test]
    async fn a_revoke_cut_off_by_the_deadline_is_sent_again() {
        let mut rig = Rig::new();
        let mut script = app_flow_until_listing();
        script.extend([
            ok(&listing(&["o/r"])),
            Answer::Late(Duration::from_millis(1500), "204 No Content", String::new()),
            Answer::Reply("204 No Content", String::new()),
        ]);
        let (reply, seen) = rig.run(&app_frame_with_deadline(600), script).await;
        assert_eq!(refused(&reply), Some(ReachRefusal::Unanswered));
        assert_eq!(
            seen.lines()[3..],
            [
                "DELETE /installation/token HTTP/1.1",
                "DELETE /installation/token HTTP/1.1"
            ]
        );
        assert_eq!(seen.bearer(4), INSTALLATION_TOKEN);
    }

    #[tokio::test]
    async fn a_mint_cut_off_by_the_deadline_is_journaled_as_possibly_live() {
        let mut rig = Rig::new();
        let script = vec![
            ok(INSTALLATION),
            Answer::Late(
                Duration::from_millis(1500),
                "201 Created",
                metadata_grant(r#"{"metadata":"read"}"#),
            ),
        ];
        let (reply, _) = rig.run(&app_frame_with_deadline(600), script).await;
        assert_eq!(refused(&reply), Some(ReachRefusal::Unanswered));
        assert!(
            rig.journal
                .iter()
                .any(|l| l.contains("a live token may exist and cannot be revoked")),
            "{:?}",
            rig.journal
        );
    }

    #[tokio::test]
    async fn a_listing_failure_revokes_once_through_the_observer() {
        let mut rig = Rig::new();
        let mut script = app_flow_until_listing();
        script.extend([
            status("500 Internal Server Error"),
            Answer::Reply("204 No Content", String::new()),
        ]);
        let (reply, seen) = rig.run(&agent(), script).await;
        assert_eq!(refused(&reply), Some(ReachRefusal::Upstream));
        assert_eq!(seen.requests.len(), 4);
        assert_eq!(seen.extra, 0, "the token is revoked once");
    }

    #[tokio::test]
    async fn a_metadata_grant_wider_than_asked_is_revoked_and_unanswered() {
        let mut rig = Rig::new();
        let (reply, seen) = rig
            .run(
                &agent(),
                vec![
                    ok(INSTALLATION),
                    Answer::Reply(
                        "201 Created",
                        metadata_grant(r#"{"metadata":"read","contents":"write"}"#),
                    ),
                    Answer::Reply("204 No Content", String::new()),
                ],
            )
            .await;
        assert_eq!(refused(&reply), Some(ReachRefusal::Unanswered));
        assert_eq!(
            seen.lines().last().map(String::as_str),
            Some("DELETE /installation/token HTTP/1.1")
        );
        assert_eq!(seen.extra, 0);
    }

    #[tokio::test]
    async fn an_unrevokable_token_is_journaled_without_the_token() {
        let mut rig = Rig::new();
        let mut script = app_flow_until_listing();
        script.extend([
            status("500 Internal Server Error"),
            status("500 Internal Server Error"),
            status("500 Internal Server Error"),
        ]);
        let (reply, seen) = rig.run(&agent(), script).await;
        assert_eq!(refused(&reply), Some(ReachRefusal::Upstream));
        assert_eq!((seen.requests.len(), seen.extra), (5, 0));
        assert!(
            rig.journal
                .iter()
                .any(|l| l.contains("could not be revoked")),
            "{:?}",
            rig.journal
        );
    }

    #[tokio::test]
    async fn a_revoke_answered_other_than_204_or_401_is_sent_again_at_exit() {
        let mut rig = Rig::new();
        let mut script = app_flow_until_listing();
        script.extend([
            ok(&listing(&["o/r"])),
            status("503 Service Unavailable"),
            Answer::Reply("204 No Content", String::new()),
        ]);
        let (reply, seen) = rig.run(&agent(), script).await;
        assert_eq!(refused(&reply), Some(ReachRefusal::Upstream));
        assert_eq!((seen.requests.len(), seen.extra), (5, 0));
        assert_eq!(
            seen.lines()[3..],
            [
                "DELETE /installation/token HTTP/1.1",
                "DELETE /installation/token HTTP/1.1"
            ]
        );
        assert_eq!(seen.bearer(4), INSTALLATION_TOKEN);
        assert!(
            rig.journal
                .iter()
                .all(|l| !l.contains("could not be revoked")),
            "{:?}",
            rig.journal
        );
    }

    #[tokio::test]
    async fn a_malformed_grant_s_revoke_outlives_the_deadline() {
        let mut rig = Rig::new();
        let malformed =
            metadata_grant(r#"{"metadata":"read"}"#).replace("2026-11-23T01:00:00Z", "tomorrow");
        let script = vec![
            ok(INSTALLATION),
            Answer::Reply("201 Created", malformed),
            Answer::Late(Duration::from_millis(1500), "204 No Content", String::new()),
        ];
        let (reply, seen) = rig.run(&app_frame_with_deadline(600), script).await;
        assert_eq!(refused(&reply), Some(ReachRefusal::Unanswered));
        assert_eq!(
            seen.lines().last().map(String::as_str),
            Some("DELETE /installation/token HTTP/1.1")
        );
        assert_eq!(seen.bearer(2), INSTALLATION_TOKEN);
        assert_eq!(seen.abandoned, 0, "the revoke waited for its answer");
    }

    #[tokio::test]
    async fn only_a_201_mint_is_passed_to_the_observer_as_minted() {
        for line in ["200 OK", "202 Accepted"] {
            let mut rig = Rig::new();
            let (reply, seen) = rig
                .run(
                    &agent(),
                    vec![
                        ok(INSTALLATION),
                        Answer::Reply(line, metadata_grant(r#"{"metadata":"read"}"#)),
                        Answer::Reply("204 No Content", String::new()),
                    ],
                )
                .await;
            assert_eq!(refused(&reply), Some(ReachRefusal::Upstream), "{line}");
            assert_eq!((seen.requests.len(), seen.extra), (3, 0), "{line}");
            assert_eq!(seen.lines()[2], "DELETE /installation/token HTTP/1.1");
            assert_eq!(seen.bearer(2), INSTALLATION_TOKEN);
            assert!(
                rig.journal.iter().all(|l| !l.contains("may exist")),
                "{line}: {:?}",
                rig.journal
            );
        }
    }

    #[test]
    fn a_held_token_dropped_on_unwind_is_still_revoked() {
        fips();
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        let (base, h) = rt.block_on(stub(vec![Answer::Reply("204 No Content", String::new())]));
        let github = GithubClient::loopback_for_tests(&base);
        let api = ApiBase::parse("https://api.github.com").unwrap();
        let unwound = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let mut held = Held::new(&github, &api);
            held.token =
                Some(MaknaeSecret::new(Zeroizing::new(INSTALLATION_TOKEN.to_owned())).unwrap());
            panic!("an exchange unwinds while holding a token");
        }));
        assert!(unwound.is_err());
        let seen = rt.block_on(h).unwrap();
        assert_eq!(seen.lines(), ["DELETE /installation/token HTTP/1.1"]);
        assert_eq!(seen.bearer(0), INSTALLATION_TOKEN);
    }

    #[tokio::test]
    async fn a_reach_waits_for_a_permit_only_within_its_deadline() {
        let mut rig = Rig::new();
        rig.gate = std::sync::Arc::new(ReachGate::with_permits(0));
        let short = tasker_frame("github.com", "github", 200);
        let (reply, seen) = rig.run(&short, vec![]).await;
        assert_eq!(refused(&reply), Some(ReachRefusal::Unanswered));
        assert_eq!((seen.requests.len(), seen.extra), (0, 0));
        assert_eq!(rig.journal.len(), 1);
        assert!(
            rig.journal[0].ends_with("reach outcome unknown: at capacity"),
            "{}",
            rig.journal[0]
        );

        let mut rig = Rig::new();
        let gate = std::sync::Arc::new(ReachGate::with_permits(1));
        rig.gate = std::sync::Arc::clone(&gate);
        let held = gate.0.try_acquire().unwrap();
        let release = async {
            tokio::time::sleep(Duration::from_millis(100)).await;
            drop(held);
        };
        let req = tasker();
        let ((reply, _), ()) = tokio::join!(rig.run(&req, vec![ok(REPO_PUSH)]), release);
        assert!(matches!(reply, ReachReply::Observed(_)), "{reply:?}");
        assert_eq!(REACH_CONCURRENCY_MAX, 4);
        assert_eq!(
            ReachGate::new().0.available_permits(),
            REACH_CONCURRENCY_MAX
        );
    }

    #[tokio::test]
    async fn no_forge_credential_answers_without_io_or_a_permit() {
        let mut rig = Rig::new();
        rig.minter_ready = false;
        rig.gate = std::sync::Arc::new(ReachGate::with_permits(0));
        let (reply, seen) = rig.run(&agent(), vec![]).await;
        assert_eq!(reply, ReachReply::NoForgeCredential);
        assert_eq!((seen.requests.len(), seen.extra), (0, 0));
        assert_eq!(
            rig.journal,
            [
                r#"reach server="github.com" provider="github" side=agent asks=1: no_forge_credential"#
            ]
        );
    }

    #[tokio::test]
    async fn a_frame_refused_at_admission_sends_nothing_and_is_journaled_once() {
        let mut rig = Rig::new();
        let req = tasker_frame("unmapped.example", "github", 20_000);
        let (reply, seen) = rig.run(&req, vec![]).await;
        assert_eq!(refused(&reply), Some(ReachRefusal::Request));
        assert_eq!((seen.requests.len(), seen.extra), (0, 0));
        assert!(rig.opener.opened.lock().unwrap().is_empty());
        assert_eq!(
            rig.journal,
            [
                r#"reach server="unmapped.example" provider="github" side=tasker asks=1: refused request"#
            ]
        );
    }

    #[tokio::test]
    async fn the_token_and_jwt_appear_in_no_journal_line() {
        let mut lines = Vec::new();
        let mut frames = 0;
        let mut run = |rig: Rig| lines.extend(rig.journal);
        for script in [vec![ok(REPO_PUSH)], vec![status("404 Not Found")]] {
            let mut rig = Rig::new();
            rig.run(&tasker(), script).await;
            frames += 1;
            run(rig);
        }
        let mut rig = Rig::new();
        let mut script = app_flow_until_listing();
        script.extend([
            ok(&listing(&["o/r"])),
            Answer::Reply("204 No Content", String::new()),
        ]);
        rig.run(&agent(), script).await;
        frames += 1;
        run(rig);
        let mut rig = Rig::new();
        let mut script = app_flow_until_listing();
        script.extend([
            status("500 Internal Server Error"),
            status("500 Internal Server Error"),
            status("500 Internal Server Error"),
        ]);
        rig.run(&agent(), script).await;
        frames += 1;
        run(rig);

        assert_eq!(
            lines
                .iter()
                .filter(|l| l.starts_with("reach server="))
                .count(),
            frames
        );
        let sealed = format!("{:?}", vec![7u8; 200]);
        for line in &lines {
            for secret in [
                TASKER_TOKEN,
                INSTALLATION_TOKEN,
                jwt().as_str(),
                "transit-signature-sentinel",
                "0123456789abcdef0123456789abcdef",
                "maknae/users/alice",
                "7, 7, 7",
                sealed.as_str(),
            ] {
                assert!(!line.contains(secret), "{line}");
            }
        }
        assert!(lines.contains(
            &r#"reach server="github.com" provider="github" side=tasker asks=1: observed"#
                .to_owned()
        ));
        assert!(lines.contains(
            &r#"reach server="github.com" provider="github" side=tasker asks=1: refused not_found"#
                .to_owned()
        ));
        assert!(lines.contains(
            &r#"reach server="github.com" provider="github" side=agent asks=1: observed"#
                .to_owned()
        ));
    }

    #[tokio::test]
    async fn a_mint_for_another_installation_or_while_a_token_is_held_is_not_sent() {
        let mint = |installation| Step::MintMetadataRead { installation };
        let other = scripted(vec![mint(78)]);
        let mut rig = Rig::new();
        let (reply, seen) = rig.observed_by(&agent(), other, vec![]).await;
        assert_eq!(refused(&reply), Some(ReachRefusal::Shape));
        assert_eq!((seen.requests.len(), seen.extra), (0, 0));
        assert_eq!(*other.answered.lock().unwrap(), [None]);
        assert!(rig.signer.calls().is_empty());

        let twice = scripted(vec![mint(77), mint(77)]);
        let mut rig = Rig::new();
        let script = vec![
            Answer::Reply("201 Created", metadata_grant(r#"{"metadata":"read"}"#)),
            Answer::Reply("204 No Content", String::new()),
        ];
        let (reply, seen) = rig.observed_by(&agent(), twice, script).await;
        assert_eq!(refused(&reply), Some(ReachRefusal::Shape));
        assert_eq!(
            seen.lines(),
            [
                "POST /app/installations/77/access_tokens HTTP/1.1",
                "DELETE /installation/token HTTP/1.1",
            ]
        );
        assert_eq!(seen.extra, 0);
        assert_eq!(*twice.answered.lock().unwrap(), [Some(201), None]);
    }

    #[test]
    fn only_a_204_or_401_revoke_at_unwind_is_silent() {
        for status in [Some(204), Some(401)] {
            assert_eq!(unwound_line(status), None, "{status:?}");
        }
        for status in [None, Some(200), Some(500)] {
            assert_eq!(unwound_line(status), Some(UNWOUND), "{status:?}");
        }
    }
}
