//! One mint frame end to end: the recipient key, a fresh App JWT per set, one
//! installation token per set, each sealed to the agent and to egress itself.

use super::admit::{AdmittedMint, TrustPlaneKind};
use super::github::{ForgeError, GithubClient, MintedToken};
use super::grant::is_installation_token;
use super::jwt::{assemble_jwt, signing_input};
use super::recipient::recipient_key_owned_by;
use super::signer::Signer;
use maknae_config::{AgentId, ApiBase, CredentialKind, GithubAppConfig};
use maknae_io::{MaknaeSecret, SecretError};
use maknae_proto::{
    ForgeStatus, MintRefusal, MintReply, PermissionSet, RevokeReply, RevokeRequest,
    SealedCredential, SealedCredentialBytes,
};
use maknae_seal::{
    open_credential, seal_credential, CredentialDirection, CredentialSealContext, SealPrivateKey,
    SealPublicKey,
};
use std::path::Path;

pub struct MintDeps<'a, S: Signer> {
    pub signer: &'a S,
    pub github: &'a GithubClient,
    pub own_pub: &'a SealPublicKey,
    pub own_key: &'a SealPrivateKey,
    pub egress_dir: &'a Path,
    /// Unix seconds, read once for each set's JWT; `None` refuses `Signer`.
    pub clock: &'a dyn Fn() -> Option<u64>,
    pub journal: &'a mut dyn FnMut(&str),
}

/// The tokens behind a `Minted` reply, held until the reply is delivered so
/// they can be revoked if it is not.
pub struct LiveTokens {
    pub api: ApiBase,
    /// The frame's task, agent, class and App, for the journal.
    pub label: String,
    pub tokens: Vec<MaknaeSecret>,
}

impl std::fmt::Debug for LiveTokens {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "LiveTokens(<{} tokens>)", self.tokens.len())
    }
}

pub async fn mint<S: Signer>(
    m: &AdmittedMint<'_>,
    d: &mut MintDeps<'_, S>,
) -> (MintReply, LiveTokens) {
    mint_for(m, d, super::recipient::ROOT_UID).await
}

#[cfg(any(test, feature = "test-support"))]
pub async fn mint_with_recipient_owner<S: Signer>(
    m: &AdmittedMint<'_>,
    d: &mut MintDeps<'_, S>,
    owner: u32,
) -> (MintReply, LiveTokens) {
    mint_for(m, d, owner).await
}

async fn mint_for<S: Signer>(
    m: &AdmittedMint<'_>,
    d: &mut MintDeps<'_, S>,
    owner: u32,
) -> (MintReply, LiveTokens) {
    let label = frame_label("mint", &m.req.task, &m.agent, &m.req.class, &m.req.app);
    let mut live = LiveTokens {
        api: m.app.api.clone(),
        label: label.clone(),
        tokens: Vec::with_capacity(m.req.sets.len()),
    };
    let reply = match mint_sets(m, d, owner, &label, &mut live).await {
        Ok(sealed) => MintReply::Minted(sealed),
        Err(refusal) => {
            let minted = std::mem::replace(
                &mut live,
                LiveTokens {
                    api: m.app.api.clone(),
                    label: label.clone(),
                    tokens: Vec::new(),
                },
            );
            revoke_all(d.github, minted, d.journal).await;
            MintReply::Refused(refusal)
        }
    };
    (d.journal)(&format!("{label} sets={}: {reply:?}", m.req.sets.len()));
    (reply, live)
}

async fn mint_sets<S: Signer>(
    m: &AdmittedMint<'_>,
    d: &mut MintDeps<'_, S>,
    owner: u32,
    label: &str,
    live: &mut LiveTokens,
) -> Result<Vec<SealedCredential>, MintRefusal> {
    let recipient = recipient_key_owned_by(d.egress_dir, &m.agent, owner)?;
    let kind = kind_spelling(m.kind);
    let mut sealed = Vec::with_capacity(m.req.sets.len());
    for (i, set) in m.req.sets.iter().enumerate() {
        let index = u8::try_from(i).map_err(|_| MintRefusal::Request)?;
        let token = match mint_one(m.app, set, d).await {
            Ok(t) => t,
            Err(Failure::Signer) => return Err(MintRefusal::Signer),
            Err(Failure::Jwt(e)) => {
                (d.journal)(&format!(
                    "{label} set={index}: the App JWT could not be held: {e:?}"
                ));
                return Err(MintRefusal::Signer);
            }
            Err(Failure::Forge(e)) => {
                if live_token_may_remain(e) {
                    (d.journal)(&format!(
                        "{label} set={index}: a live token may exist and cannot be revoked: {e:?}"
                    ));
                }
                return Err(forge_refusal(e));
            }
        };
        let context = |direction| CredentialSealContext {
            direction,
            agent: m.agent.as_str(),
            task: &m.req.task,
            class: &m.req.class,
            kind,
            app: &m.req.app,
            set: index,
        };
        let pair = seal_to(
            &recipient,
            &context(CredentialDirection::ToAgent),
            token.token.expose(),
        )
        .and_then(|for_agent| {
            seal_to(
                d.own_pub,
                &context(CredentialDirection::ToRevoke),
                token.token.expose(),
            )
            .map(|for_revocation| (for_agent, for_revocation))
        });
        live.tokens.push(token.token);
        let (for_agent, for_revocation) = pair?;
        sealed.push(SealedCredential {
            set: index,
            expires_at: token.expires_at,
            for_agent,
            for_revocation,
        });
    }
    Ok(sealed)
}

enum Failure {
    Signer,
    Jwt(SecretError),
    Forge(ForgeError),
}

async fn mint_one<S: Signer>(
    app: &GithubAppConfig,
    set: &PermissionSet,
    d: &MintDeps<'_, S>,
) -> Result<MintedToken, Failure> {
    let now = (d.clock)().ok_or(Failure::Signer)?;
    let input = signing_input(app.app_id, now);
    let signature = d
        .signer
        .sign(&app.transit_mount, &app.transit_key, input.as_bytes())
        .await
        .map_err(|_| Failure::Signer)?;
    let jwt = assemble_jwt(&input, &signature).map_err(Failure::Jwt);
    drop(signature);
    let jwt = jwt?;
    d.github
        .mint(&app.api, app.installation_id, jwt.expose(), set)
        .await
        .map_err(Failure::Forge)
}

fn seal_to(
    to: &SealPublicKey,
    ctx: &CredentialSealContext<'_>,
    token: &str,
) -> Result<SealedCredentialBytes, MintRefusal> {
    seal_credential(to, ctx, token)
        .ok()
        .and_then(|blob| SealedCredentialBytes::new(blob.into_bytes()).ok())
        .ok_or(MintRefusal::Forge(ForgeStatus::Other))
}

fn forge_refusal(e: ForgeError) -> MintRefusal {
    match e {
        ForgeError::Status(s) => MintRefusal::Forge(s),
        ForgeError::Mismatch { .. } => MintRefusal::Mismatch,
        ForgeError::Transport
        | ForgeError::Unanswered
        | ForgeError::Unread
        | ForgeError::Oversize
        | ForgeError::Shape
        | ForgeError::Malformed { .. }
        | ForgeError::Undocumented { .. } => MintRefusal::Forge(ForgeStatus::Other),
    }
}

pub(crate) fn live_token_may_remain(e: ForgeError) -> bool {
    match e {
        ForgeError::Unanswered
        | ForgeError::Unread
        | ForgeError::Oversize
        | ForgeError::Shape
        | ForgeError::Mismatch { revoked: false }
        | ForgeError::Malformed { revoked: false }
        | ForgeError::Undocumented { revoked: false }
        | ForgeError::Status(ForgeStatus::Other) => true,
        ForgeError::Status(
            ForgeStatus::Unauthorized
            | ForgeStatus::Forbidden
            | ForgeStatus::NotFound
            | ForgeStatus::Unprocessable,
        )
        | ForgeError::Transport
        | ForgeError::Mismatch { revoked: true }
        | ForgeError::Malformed { revoked: true }
        | ForgeError::Undocumented { revoked: true } => false,
    }
}

fn frame_label(verb: &str, task: &str, agent: &AgentId, class: &str, app: &str) -> String {
    format!(
        "{verb} task={task:?} agent={} class={class:?} app={app:?}",
        agent.as_str()
    )
}

pub async fn revoke_all(github: &GithubClient, live: LiveTokens, journal: &mut dyn FnMut(&str)) {
    for (set, token) in live.tokens.iter().enumerate() {
        let failure = match github.revoke(&live.api, token.expose()).await {
            Ok(RevokeReply::Revoked | RevokeReply::AlreadyGone) => continue,
            Ok(RevokeReply::Refused(r)) => format!("{:?}", RevokeReply::Refused(r)),
            Err(e) => format!("{e:?}"),
        };
        journal(&format!(
            "{} set={set}: a minted token could not be revoked: {failure}",
            live.label
        ));
    }
}

pub async fn revoke<S: Signer>(
    r: &RevokeRequest,
    agent: &AgentId,
    app: &GithubAppConfig,
    d: &mut MintDeps<'_, S>,
) -> RevokeReply {
    let ctx = CredentialSealContext {
        direction: CredentialDirection::ToRevoke,
        agent: agent.as_str(),
        task: &r.task,
        class: &r.class,
        kind: &r.kind,
        app: &r.app,
        set: r.set,
    };
    let label = frame_label("revoke", &r.task, agent, &r.class, &r.app);
    let reply = match open_credential(d.own_key, &ctx, r.for_revocation.as_bytes()) {
        Err(e @ maknae_seal::SealError::CoreDumps(_)) => {
            (d.journal)(&format!(
                "{label} set={}: the revocation token could not be held: {e}",
                r.set
            ));
            RevokeReply::Refused(MintRefusal::Request)
        }
        Err(_) => RevokeReply::Refused(MintRefusal::Request),
        Ok(token) if !is_installation_token(token.expose()) => {
            RevokeReply::Refused(MintRefusal::Request)
        }
        Ok(token) => match d.github.revoke(&app.api, token.expose()).await {
            Ok(reply) => reply,
            Err(e) => {
                (d.journal)(&format!(
                    "{label} set={}: the token may still be live: {e:?}",
                    r.set
                ));
                RevokeReply::Refused(forge_refusal(e))
            }
        },
    };
    (d.journal)(&format!("{label} set={}: {reply:?}", r.set));
    reply
}

fn kind_spelling(kind: TrustPlaneKind) -> &'static str {
    match kind {
        TrustPlaneKind::GithubApp => CredentialKind::GithubAppInstallation.as_str(),
    }
}

#[cfg(test)]
mod tests {
    use super::super::admit::admit_mint;
    use super::super::signer::FakeSigner;
    use super::super::testutil::{coder, euid, EgressDir};
    use super::*;
    use maknae_config::{MintVault, MintingConfig};
    use maknae_proto::{
        AccessLevel, ForgeStatus, GithubPermission, MintRequest, PermissionSet,
        SealedCredentialBytes,
    };
    use maknae_seal::{open_credential, CredentialDirection, CredentialSealContext};
    use std::collections::BTreeMap;
    use std::time::Duration;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use zeroize::Zeroizing;

    const KIND: &str = "github-app-installation";
    const SIGNATURE: &[u8] = b"transit-signature-sentinel";
    const NOW: u64 = 1_800_000_000;

    fn fips() {
        static ONCE: std::sync::Once = std::sync::Once::new();
        ONCE.call_once(|| maknae_crypto::init().unwrap());
    }

    fn app(name_api: &str) -> GithubAppConfig {
        GithubAppConfig {
            app_id: 5834363,
            installation_id: 77,
            host: "github.example".into(),
            api: ApiBase::parse(name_api).unwrap(),
            transit_mount: "transit".into(),
            transit_key: "deploy-app".into(),
        }
    }

    fn minting() -> MintingConfig {
        MintingConfig {
            vault: MintVault {
                approle_mount: "approle".into(),
            },
            github_apps: BTreeMap::from([
                ("deploy".to_string(), app("https://api.github.example")),
                ("other".to_string(), app("https://api.github.example")),
            ]),
        }
    }

    fn set(repos: &[&str]) -> PermissionSet {
        PermissionSet {
            repositories: repos.iter().map(|r| r.to_string()).collect(),
            permissions: BTreeMap::from([(GithubPermission::Contents, AccessLevel::Write)]),
        }
    }

    fn request(sets: Vec<PermissionSet>) -> MintRequest {
        MintRequest {
            task: "task-1".into(),
            agent: "coder".into(),
            class: "git-write".into(),
            kind: KIND.into(),
            app: "deploy".into(),
            sets,
        }
    }

    enum Step {
        Reply(String),
        Close,
    }

    fn http(status: &str, body: &str) -> Step {
        Step::Reply(format!(
            "HTTP/1.1 {status}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
            body.len()
        ))
    }

    fn granted(token: &str, repos: &[&str]) -> Step {
        let repos: Vec<String> = repos
            .iter()
            .map(|r| format!(r#"{{"name":"{r}"}}"#))
            .collect();
        http(
            "201 Created",
            &format!(
                r#"{{"token":"{token}","expires_at":"2026-11-19T01:00:00Z","permissions":{{"contents":"write"}},"repository_selection":"selected","repositories":[{}]}}"#,
                repos.join(",")
            ),
        )
    }

    fn revoked() -> Step {
        Step::Reply("HTTP/1.1 204 No Content\r\nConnection: close\r\n\r\n".into())
    }

    struct Seen {
        requests: Vec<String>,
        extra: usize,
    }

    impl Seen {
        fn revoked_tokens(&self) -> Vec<String> {
            self.requests
                .iter()
                .filter(|r| r.starts_with("DELETE /installation/token "))
                .map(|r| {
                    r.lines()
                        .find_map(|l| l.strip_prefix("authorization: Bearer "))
                        .unwrap()
                        .trim()
                        .to_string()
                })
                .collect()
        }

        fn mints(&self) -> usize {
            self.requests
                .iter()
                .filter(|r| r.starts_with("POST /app/installations/77/access_tokens "))
                .count()
        }
    }

    async fn read_request(s: &mut tokio::net::TcpStream) -> String {
        let mut seen = Vec::new();
        let mut buf = vec![0u8; 8192];
        loop {
            let n = s.read(&mut buf).await.unwrap();
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

    async fn stub(script: Vec<Step>) -> (String, tokio::task::JoinHandle<Seen>) {
        let l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = l.local_addr().unwrap();
        let h = tokio::spawn(async move {
            let mut requests = Vec::new();
            for step in script {
                let Ok(accepted) = tokio::time::timeout(Duration::from_secs(5), l.accept()).await
                else {
                    break;
                };
                let (mut s, _) = accepted.unwrap();
                requests.push(read_request(&mut s).await);
                match step {
                    Step::Reply(r) => {
                        s.write_all(r.as_bytes()).await.unwrap();
                        s.flush().await.unwrap();
                    }
                    Step::Close => drop(s),
                }
            }
            let extra = usize::from(
                tokio::time::timeout(Duration::from_millis(300), l.accept())
                    .await
                    .is_ok(),
            );
            Seen { requests, extra }
        });
        (format!("http://{addr}"), h)
    }

    struct Rig {
        egress: EgressDir,
        agent_key: SealPrivateKey,
        own: SealPrivateKey,
        signer: FakeSigner,
        minting: MintingConfig,
        owner: u32,
        clock_steps: Option<Vec<Option<u64>>>,
        clock_reads: std::cell::Cell<usize>,
    }

    impl Rig {
        fn clock(&self) -> impl Fn() -> Option<u64> + '_ {
            move || {
                let n = self.clock_reads.get();
                self.clock_reads.set(n + 1);
                match &self.clock_steps {
                    None => Some(NOW),
                    Some(steps) => steps[n.min(steps.len() - 1)],
                }
            }
        }

        fn new() -> Self {
            fips();
            let egress = EgressDir::new();
            let agent_key = egress.publish_key("coder");
            Self {
                egress,
                agent_key,
                own: SealPrivateKey::generate().unwrap(),
                signer: FakeSigner::signing(SIGNATURE),
                minting: minting(),
                owner: euid(),
                clock_steps: None,
                clock_reads: std::cell::Cell::new(0),
            }
        }

        async fn mint(
            &self,
            req: &MintRequest,
            script: Vec<Step>,
        ) -> (MintReply, LiveTokens, Seen, Vec<String>) {
            let (base, h) = stub(script).await;
            let github = GithubClient::loopback_for_tests(&base);
            let admitted = admit_mint(req, Some(&self.minting)).unwrap();
            let mut lines = Vec::new();
            let mut journal = |l: &str| lines.push(l.to_string());
            let mut d = MintDeps {
                signer: &self.signer,
                github: &github,
                own_pub: self.own.public_key(),
                own_key: &self.own,
                egress_dir: self.egress.path(),
                clock: &self.clock(),
                journal: &mut journal,
            };
            let (reply, live) = mint_with_recipient_owner(&admitted, &mut d, self.owner).await;
            (reply, live, h.await.unwrap(), lines)
        }

        async fn revoke(
            &self,
            req: &RevokeRequest,
            script: Vec<Step>,
        ) -> (RevokeReply, Seen, Vec<String>) {
            let (base, h) = stub(script).await;
            let github = GithubClient::loopback_for_tests(&base);
            let agent = AgentId::parse(&req.agent).unwrap();
            let app = &self.minting.github_apps["deploy"];
            let mut lines = Vec::new();
            let mut journal = |l: &str| lines.push(l.to_string());
            let mut d = MintDeps {
                signer: &self.signer,
                github: &github,
                own_pub: self.own.public_key(),
                own_key: &self.own,
                egress_dir: self.egress.path(),
                clock: &self.clock(),
                journal: &mut journal,
            };
            let reply = revoke(req, &agent, app, &mut d).await;
            (reply, h.await.unwrap(), lines)
        }
    }

    fn ctx(direction: CredentialDirection, set: u8) -> CredentialSealContext<'static> {
        CredentialSealContext {
            direction,
            agent: "coder",
            task: "task-1",
            class: "git-write",
            kind: KIND,
            app: "deploy",
            set,
        }
    }

    fn minted(reply: MintReply) -> Vec<maknae_proto::SealedCredential> {
        match reply {
            MintReply::Minted(c) => c,
            other => panic!("expected Minted, got {other:?}"),
        }
    }

    fn revoke_request(set: u8, blob: SealedCredentialBytes) -> RevokeRequest {
        RevokeRequest {
            task: "task-1".into(),
            agent: "coder".into(),
            class: "git-write".into(),
            kind: KIND.into(),
            app: "deploy".into(),
            set,
            for_revocation: blob,
        }
    }

    #[tokio::test]
    async fn a_jwt_too_long_to_hold_is_a_signer_refusal_journaled_with_no_github_call() {
        let mut rig = Rig::new();
        rig.signer = FakeSigner::signing(&vec![0u8; 50_000]);
        let (reply, live, seen, journal) = rig.mint(&request(vec![set(&["a"])]), vec![]).await;
        assert_eq!(reply, MintReply::Refused(MintRefusal::Signer));
        assert!(live.tokens.is_empty());
        assert_eq!((seen.requests.len(), seen.extra), (0, 0));
        assert!(
            journal
                .iter()
                .any(|l| l.contains("the App JWT could not be held") && l.contains("TooLong")),
            "{journal:?}"
        );
    }

    #[tokio::test]
    async fn a_missing_or_unsafe_recipient_key_refuses_before_any_io() {
        let absent = Rig::new();
        std::fs::remove_file(absent.egress.key_file("coder")).unwrap();
        let writable = Rig::new();
        std::fs::set_permissions(
            writable.egress.key_file("coder"),
            std::os::unix::fs::PermissionsExt::from_mode(0o660),
        )
        .unwrap();
        let mut foreign = Rig::new();
        foreign.owner = euid() + 1;
        let not_a_key = Rig::new();
        not_a_key
            .egress
            .publish("coder", &[b'k'; maknae_seal::SEAL_PUB_PEM_LEN], 0o640);
        for (label, rig) in [
            ("absent", &absent),
            ("group-writable", &writable),
            ("not root-owned", &foreign),
            ("not a public key", &not_a_key),
        ] {
            let (reply, live, seen, _) = rig.mint(&request(vec![set(&["a"])]), vec![]).await;
            assert_eq!(reply, MintReply::Refused(MintRefusal::Recipient), "{label}");
            assert!(live.tokens.is_empty(), "{label}");
            assert!(rig.signer.calls().is_empty(), "{label}: signer called");
            assert_eq!(
                (seen.requests.len(), seen.extra),
                (0, 0),
                "{label}: GitHub called"
            );
        }
    }

    #[tokio::test]
    async fn each_set_s_jwt_is_dated_by_its_own_clock_reading() {
        let mut rig = Rig::new();
        rig.clock_steps = Some(vec![Some(NOW), Some(NOW + 400), Some(NOW + 900)]);
        let (reply, _, _, _) = rig
            .mint(
                &request(vec![set(&["a"]), set(&["b"]), set(&["c"])]),
                vec![
                    granted("ghs_one", &["a"]),
                    granted("ghs_two", &["b"]),
                    granted("ghs_three", &["c"]),
                ],
            )
            .await;
        assert_eq!(minted(reply).len(), 3);
        let inputs: Vec<Vec<u8>> = rig.signer.calls().into_iter().map(|c| c.input).collect();
        let want: Vec<Vec<u8>> = [NOW, NOW + 400, NOW + 900]
            .iter()
            .map(|t| super::super::jwt::signing_input(5834363, *t).into_bytes())
            .collect();
        assert_eq!(inputs, want);
        assert_eq!(rig.clock_reads.get(), 3);
    }

    #[tokio::test]
    async fn a_clock_before_1970_on_a_later_set_refuses_signer_and_revokes_the_earlier() {
        let mut rig = Rig::new();
        rig.clock_steps = Some(vec![Some(NOW), None]);
        let (reply, live, seen, _) = rig
            .mint(
                &request(vec![set(&["a"]), set(&["b"])]),
                vec![granted("ghs_one", &["a"]), revoked()],
            )
            .await;
        assert_eq!(reply, MintReply::Refused(MintRefusal::Signer));
        assert!(live.tokens.is_empty());
        assert_eq!(seen.mints(), 1);
        assert_eq!(seen.revoked_tokens(), ["ghs_one"]);
        assert_eq!(rig.signer.calls().len(), 1);
    }

    #[tokio::test]
    async fn each_set_signs_a_fresh_jwt_and_mints_with_it() {
        let rig = Rig::new();
        let req = request(vec![set(&["alpha"]), set(&["beta"])]);
        let (reply, live, seen, _) = rig
            .mint(
                &req,
                vec![
                    granted("ghs_one", &["alpha"]),
                    granted("ghs_two", &["beta"]),
                ],
            )
            .await;
        let creds = minted(reply);
        assert_eq!(creds.len(), 2);
        assert_eq!(creds[0].set, 0);
        assert_eq!(creds[1].set, 1);
        assert_eq!(creds[0].expires_at, "2026-11-19T01:00:00Z");
        let calls = rig.signer.calls();
        assert_eq!(calls.len(), 2);
        let input = super::super::jwt::signing_input(5834363, NOW);
        for c in &calls {
            assert_eq!(
                (c.mount.as_str(), c.key.as_str()),
                ("transit", "deploy-app")
            );
            assert_eq!(c.input, input.as_bytes());
        }
        let jwt = super::super::jwt::assemble_jwt(&input, SIGNATURE).unwrap();
        assert_eq!(seen.mints(), 2);
        for r in &seen.requests {
            assert!(
                r.contains(&format!("authorization: Bearer {}", jwt.expose())),
                "{r}"
            );
        }
        assert!(seen.requests[0].contains(r#""repositories":["alpha"]"#));
        assert!(seen.requests[1].contains(r#""repositories":["beta"]"#));
        assert_eq!(seen.extra, 0);
        assert_eq!(
            live.tokens.iter().map(|t| t.expose()).collect::<Vec<_>>(),
            ["ghs_one", "ghs_two"]
        );
        assert_eq!(live.api.as_str(), "https://api.github.example");
    }

    #[tokio::test]
    async fn for_agent_opens_with_the_agents_key_under_its_context_only() {
        let rig = Rig::new();
        let (reply, _live, _, _) = rig
            .mint(
                &request(vec![set(&["a"]), set(&["b"])]),
                vec![granted("ghs_one", &["a"]), granted("ghs_two", &["b"])],
            )
            .await;
        let creds = minted(reply);
        for (i, want) in [(0u8, "ghs_one"), (1, "ghs_two")] {
            let blob = creds[usize::from(i)].for_agent.as_bytes();
            let opened =
                open_credential(&rig.agent_key, &ctx(CredentialDirection::ToAgent, i), blob)
                    .unwrap();
            assert_eq!(opened.expose(), want);
            for wrong in [
                ctx(CredentialDirection::ToRevoke, i),
                ctx(CredentialDirection::ToAgent, 1 - i),
                CredentialSealContext {
                    task: "task-2",
                    ..ctx(CredentialDirection::ToAgent, i)
                },
                CredentialSealContext {
                    class: "git-read",
                    ..ctx(CredentialDirection::ToAgent, i)
                },
                CredentialSealContext {
                    agent: "coder2",
                    ..ctx(CredentialDirection::ToAgent, i)
                },
                CredentialSealContext {
                    app: "other",
                    ..ctx(CredentialDirection::ToAgent, i)
                },
                CredentialSealContext {
                    kind: "github-machine-user",
                    ..ctx(CredentialDirection::ToAgent, i)
                },
            ] {
                assert!(open_credential(&rig.agent_key, &wrong, blob).is_err());
            }
            assert!(
                open_credential(&rig.own, &ctx(CredentialDirection::ToAgent, i), blob).is_err()
            );
        }
    }

    #[tokio::test]
    async fn for_revocation_opens_only_with_egress_own_key_as_to_revoke() {
        let rig = Rig::new();
        let (reply, _live, _, _) = rig
            .mint(
                &request(vec![set(&["a"])]),
                vec![granted("ghs_one", &["a"])],
            )
            .await;
        let creds = minted(reply);
        let blob = creds[0].for_revocation.as_bytes();
        let opened =
            open_credential(&rig.own, &ctx(CredentialDirection::ToRevoke, 0), blob).unwrap();
        assert_eq!(opened.expose(), "ghs_one");
        assert!(open_credential(&rig.own, &ctx(CredentialDirection::ToAgent, 0), blob).is_err());
        assert!(
            open_credential(&rig.agent_key, &ctx(CredentialDirection::ToRevoke, 0), blob).is_err()
        );
        assert_ne!(creds[0].for_agent, creds[0].for_revocation);
    }

    #[tokio::test]
    async fn a_token_too_long_to_seal_is_shape_and_the_earlier_sets_are_revoked() {
        let rig = Rig::new();
        let long = "g".repeat(maknae_seal::MAX_PLAINTEXT_LEN + 1);
        let (reply, live, seen, lines) = rig
            .mint(
                &request(vec![set(&["a"]), set(&["b"]), set(&["c"])]),
                vec![
                    granted("ghs_one", &["a"]),
                    granted(&long, &["b"]),
                    revoked(),
                ],
            )
            .await;
        assert_eq!(
            reply,
            MintReply::Refused(MintRefusal::Forge(ForgeStatus::Other))
        );
        assert!(live.tokens.is_empty());
        assert_eq!(seen.mints(), 2, "set three is never asked for");
        assert_eq!(seen.revoked_tokens(), ["ghs_one"]);
        assert_eq!(seen.extra, 0);
        assert_eq!(rig.signer.calls().len(), 2);
        assert!(
            lines
                .iter()
                .any(|l| l.contains("set=1") && l.contains("live token") && l.contains("Shape")),
            "{lines:?}"
        );
        assert!(
            !lines.iter().any(|l| l.contains("could not be revoked")),
            "{lines:?}"
        );
    }

    #[tokio::test]
    async fn a_failure_on_set_two_revokes_set_one_and_seals_nothing() {
        let rig = Rig::new();
        let (reply, live, seen, lines) = rig
            .mint(
                &request(vec![set(&["a"]), set(&["b"])]),
                vec![
                    granted("ghs_one", &["a"]),
                    http("422 Unprocessable Entity", "{}"),
                    revoked(),
                ],
            )
            .await;
        assert_eq!(
            reply,
            MintReply::Refused(MintRefusal::Forge(ForgeStatus::Unprocessable))
        );
        assert!(live.tokens.is_empty());
        assert_eq!(seen.revoked_tokens(), ["ghs_one"]);
        assert_eq!(seen.extra, 0);
        assert!(!lines.iter().any(|l| l.contains("live token")), "{lines:?}");
    }

    #[tokio::test]
    async fn a_signer_failure_is_signer_and_reaches_no_forge() {
        let mut rig = Rig::new();
        rig.signer = FakeSigner::failing();
        let (reply, live, seen, _) = rig.mint(&request(vec![set(&["a"])]), vec![]).await;
        assert_eq!(reply, MintReply::Refused(MintRefusal::Signer));
        assert!(live.tokens.is_empty());
        assert_eq!((seen.requests.len(), seen.extra), (0, 0));
        assert_eq!(rig.signer.calls().len(), 1);
    }

    #[tokio::test]
    async fn a_signer_failure_on_set_two_revokes_set_one() {
        struct OnceSigner(std::sync::atomic::AtomicUsize);
        impl Signer for OnceSigner {
            fn sign(
                &self,
                _: &str,
                _: &str,
                _: &[u8],
            ) -> impl std::future::Future<
                Output = Result<Zeroizing<Vec<u8>>, super::super::signer::SignError>,
            > + Send {
                let n = self.0.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                std::future::ready(if n == 0 {
                    Ok(Zeroizing::new(SIGNATURE.to_vec()))
                } else {
                    Err(super::super::signer::SignError)
                })
            }
        }
        let rig = Rig::new();
        let (base, h) = stub(vec![granted("ghs_one", &["a"]), revoked()]).await;
        let github = GithubClient::loopback_for_tests(&base);
        let req = request(vec![set(&["a"]), set(&["b"])]);
        let admitted = admit_mint(&req, Some(&rig.minting)).unwrap();
        let signer = OnceSigner(std::sync::atomic::AtomicUsize::new(0));
        let mut journal = |_: &str| {};
        let mut d = MintDeps {
            signer: &signer,
            github: &github,
            own_pub: rig.own.public_key(),
            own_key: &rig.own,
            egress_dir: rig.egress.path(),
            clock: &|| Some(NOW),
            journal: &mut journal,
        };
        let (reply, live) = mint_with_recipient_owner(&admitted, &mut d, rig.owner).await;
        assert_eq!(reply, MintReply::Refused(MintRefusal::Signer));
        assert!(live.tokens.is_empty());
        assert_eq!(h.await.unwrap().revoked_tokens(), ["ghs_one"]);
    }

    #[tokio::test]
    async fn each_forge_failure_maps_to_its_refusal() {
        for (step, want) in [
            (
                http("401 Unauthorized", "{}"),
                MintRefusal::Forge(ForgeStatus::Unauthorized),
            ),
            (
                http("403 Forbidden", "{}"),
                MintRefusal::Forge(ForgeStatus::Forbidden),
            ),
            (
                http("201 Created", "not json"),
                MintRefusal::Forge(ForgeStatus::Other),
            ),
            (Step::Close, MintRefusal::Forge(ForgeStatus::Other)),
        ] {
            let rig = Rig::new();
            let (reply, live, _, _) = rig.mint(&request(vec![set(&["a"])]), vec![step]).await;
            assert_eq!(reply, MintReply::Refused(want));
            assert!(live.tokens.is_empty());
        }
        let rig = Rig::new();
        let (reply, _, seen, _) = rig
            .mint(
                &request(vec![set(&["a"])]),
                vec![granted("ghs_wide", &["a", "b"]), revoked()],
            )
            .await;
        assert_eq!(reply, MintReply::Refused(MintRefusal::Mismatch));
        assert_eq!(seen.revoked_tokens(), ["ghs_wide"]);
    }

    #[tokio::test]
    async fn an_outcome_that_may_leave_a_live_token_is_journaled_by_its_coordinates() {
        let live_cases: Vec<(&str, Vec<Step>)> = vec![
            ("Shape", vec![http("201 Created", "not json")]),
            ("Unanswered", vec![Step::Close]),
            (
                "Mismatch { revoked: false }",
                vec![
                    granted("ghs_wide", &["a", "z"]),
                    http("500 Internal Server Error", "{}"),
                ],
            ),
        ];
        for (variant, script) in live_cases {
            let rig = Rig::new();
            let (_, _, _, lines) = rig.mint(&request(vec![set(&["a"])]), script).await;
            let hits: Vec<&String> = lines.iter().filter(|l| l.contains("live token")).collect();
            assert_eq!(hits.len(), 1, "{variant}: {lines:?}");
            let line = hits[0];
            for part in [
                "task=\"task-1\"",
                "agent=coder",
                "class=\"git-write\"",
                "app=\"deploy\"",
                "set=0",
                variant,
            ] {
                assert!(line.contains(part), "{variant}: {part} not in {line}");
            }
        }
        for (label, script) in [
            ("Status", vec![http("403 Forbidden", "{}")]),
            (
                "Mismatch { revoked: true }",
                vec![granted("ghs_wide", &["a", "z"]), revoked()],
            ),
        ] {
            let rig = Rig::new();
            let (_, _, _, lines) = rig.mint(&request(vec![set(&["a"])]), script).await;
            assert!(
                !lines.iter().any(|l| l.contains("live token")),
                "{label}: {lines:?}"
            );
        }
    }

    fn granted_expiring(token: &str, expires_at: &str) -> Step {
        http(
            "201 Created",
            &format!(
                r#"{{"token":"{token}","expires_at":"{expires_at}","permissions":{{"contents":"write"}},"repository_selection":"selected","repositories":[{{"name":"a"}}]}}"#
            ),
        )
    }

    #[tokio::test]
    async fn a_malformed_grant_is_journaled_live_only_when_no_revoke_closed_it() {
        let cases: Vec<(&str, Vec<Step>, Vec<&str>, bool)> = vec![
            (
                "a revoked malformed expiry",
                vec![granted_expiring("ghs_one", "soon"), revoked()],
                vec!["ghs_one"],
                false,
            ),
            (
                "an unrevoked malformed expiry",
                vec![
                    granted_expiring("ghs_one", "soon"),
                    http("500 Internal Server Error", "{}"),
                ],
                vec!["ghs_one"],
                true,
            ),
            (
                "a token that is not a token",
                vec![granted("ghs not-a-token", &["a"]), revoked()],
                vec![],
                true,
            ),
        ];
        for (label, script, want_revoked, live) in cases {
            let rig = Rig::new();
            let (reply, held, seen, lines) = rig.mint(&request(vec![set(&["a"])]), script).await;
            assert_eq!(
                reply,
                MintReply::Refused(MintRefusal::Forge(ForgeStatus::Other)),
                "{label}"
            );
            assert!(held.tokens.is_empty(), "{label}");
            assert_eq!(seen.revoked_tokens(), want_revoked, "{label}");
            let hits = lines.iter().filter(|l| l.contains("live token")).count();
            assert_eq!(hits, usize::from(live), "{label}: {lines:?}");
        }
    }

    #[tokio::test]
    async fn a_revoke_blob_that_opens_to_no_token_is_refused_request_and_sends_nothing() {
        let rig = Rig::new();
        for plaintext in ["ghs bad", "ghs_x\r\nX-Injected: 1", "ghs-x"] {
            let blob = maknae_seal::seal_credential(
                rig.own.public_key(),
                &ctx(CredentialDirection::ToRevoke, 0),
                plaintext,
            )
            .unwrap();
            let blob = SealedCredentialBytes::new(blob.into_bytes()).unwrap();
            let (got, seen, _) = rig.revoke(&revoke_request(0, blob), vec![revoked()]).await;
            assert_eq!(
                got,
                RevokeReply::Refused(MintRefusal::Request),
                "{plaintext:?}"
            );
            assert_eq!(seen.requests.len(), 0, "{plaintext:?}");
        }
    }

    #[tokio::test]
    async fn an_ambiguous_status_is_journaled_live_and_a_definitive_one_is_not() {
        for (status, live) in [
            ("502 Bad Gateway", true),
            ("500 Internal Server Error", true),
            ("408 Request Timeout", true),
            ("429 Too Many Requests", true),
            ("400 Bad Request", true),
            ("401 Unauthorized", false),
            ("403 Forbidden", false),
            ("404 Not Found", false),
            ("422 Unprocessable Entity", false),
        ] {
            let rig = Rig::new();
            let (_, _, _, lines) = rig
                .mint(&request(vec![set(&["a"])]), vec![http(status, "{}")])
                .await;
            let hits = lines.iter().filter(|l| l.contains("live token")).count();
            assert_eq!(hits, usize::from(live), "{status}: {lines:?}");
        }
    }

    #[tokio::test]
    async fn a_rollback_revoke_that_fails_is_journaled_by_set() {
        let rig = Rig::new();
        let (reply, _, seen, lines) = rig
            .mint(
                &request(vec![set(&["a"]), set(&["b"]), set(&["c"])]),
                vec![
                    granted("ghs_one", &["a"]),
                    granted("ghs_two", &["b"]),
                    http("404 Not Found", "{}"),
                    http("500 Internal Server Error", "{}"),
                    revoked(),
                ],
            )
            .await;
        assert_eq!(
            reply,
            MintReply::Refused(MintRefusal::Forge(ForgeStatus::NotFound))
        );
        assert_eq!(seen.revoked_tokens(), ["ghs_one", "ghs_two"]);
        let hits: Vec<&String> = lines
            .iter()
            .filter(|l| l.contains("could not be revoked"))
            .collect();
        assert_eq!(hits.len(), 1, "{lines:?}");
        assert!(hits[0].contains("set=0"), "{}", hits[0]);
        assert!(hits[0].contains("Status(Other)"), "{}", hits[0]);
        assert!(hits[0].contains("task=\"task-1\""), "{}", hits[0]);
    }

    #[tokio::test]
    async fn revoke_all_revokes_every_token_and_journals_each_failure() {
        fips();
        let (base, h) = stub(vec![
            revoked(),
            http("401 Unauthorized", "{}"),
            Step::Close,
            http("503 Service Unavailable", "{}"),
        ])
        .await;
        let github = GithubClient::loopback_for_tests(&base);
        let live = LiveTokens {
            api: ApiBase::parse("https://api.github.example").unwrap(),
            label: "mint task=\"t\"".into(),
            tokens: ["t0", "t1", "t2", "t3"]
                .iter()
                .map(|t| MaknaeSecret::new(Zeroizing::new(t.to_string())).unwrap())
                .collect(),
        };
        let mut lines = Vec::new();
        revoke_all(&github, live, &mut |l| lines.push(l.to_string())).await;
        let seen = h.await.unwrap();
        assert_eq!(seen.revoked_tokens(), ["t0", "t1", "t2", "t3"]);
        assert_eq!(lines.len(), 2, "{lines:?}");
        assert!(
            lines[0].contains("set=2") && lines[0].contains("Unanswered"),
            "{lines:?}"
        );
        assert!(
            lines[1].contains("set=3") && lines[1].contains("Status(Other)"),
            "{lines:?}"
        );
    }

    #[tokio::test]
    async fn a_delivery_rollback_journals_the_frame_coordinates() {
        let rig = Rig::new();
        let (reply, live, _, _) = rig
            .mint(
                &request(vec![set(&["a"])]),
                vec![granted("ghs_one", &["a"])],
            )
            .await;
        assert_eq!(minted(reply).len(), 1);
        let (base, h) = stub(vec![http("500 Internal Server Error", "{}")]).await;
        let github = GithubClient::loopback_for_tests(&base);
        let mut lines = Vec::new();
        revoke_all(&github, live, &mut |l| lines.push(l.to_string())).await;
        assert_eq!(h.await.unwrap().revoked_tokens(), ["ghs_one"]);
        assert_eq!(lines.len(), 1, "{lines:?}");
        for part in [
            "mint task=\"task-1\"",
            "agent=coder",
            "class=\"git-write\"",
            "app=\"deploy\"",
            "set=0: a minted token could not be revoked",
        ] {
            assert!(lines[0].contains(part), "{part} not in {}", lines[0]);
        }
    }

    #[tokio::test]
    async fn revoke_opens_the_blob_and_deletes_with_that_token() {
        let rig = Rig::new();
        let (reply, _live, _, _) = rig
            .mint(
                &request(vec![set(&["a"]), set(&["b"])]),
                vec![granted("ghs_one", &["a"]), granted("ghs_two", &["b"])],
            )
            .await;
        let mut creds = minted(reply);
        let second = creds.pop().unwrap();
        let (got, seen, _) = rig
            .revoke(&revoke_request(1, second.for_revocation), vec![revoked()])
            .await;
        assert_eq!(got, RevokeReply::Revoked);
        assert_eq!(seen.revoked_tokens(), ["ghs_two"]);
        assert_eq!(seen.extra, 0);
        let first = creds.pop().unwrap();
        let (got, seen, _) = rig
            .revoke(
                &revoke_request(0, first.for_revocation),
                vec![http("401 Unauthorized", "{}")],
            )
            .await;
        assert_eq!(got, RevokeReply::AlreadyGone);
        assert_eq!(seen.revoked_tokens(), ["ghs_one"]);
    }

    #[tokio::test]
    async fn a_revoke_that_github_refuses_is_forge_and_journaled() {
        let rig = Rig::new();
        let (reply, _live, _, _) = rig
            .mint(
                &request(vec![set(&["a"])]),
                vec![granted("ghs_one", &["a"])],
            )
            .await;
        let blob = minted(reply).pop().unwrap().for_revocation;
        let (got, _, lines) = rig
            .revoke(&revoke_request(0, blob), vec![http("403 Forbidden", "{}")])
            .await;
        assert_eq!(
            got,
            RevokeReply::Refused(MintRefusal::Forge(ForgeStatus::Forbidden))
        );
        assert!(
            lines
                .iter()
                .any(|l| l.contains("Status(Forbidden)") && l.contains("set=0")),
            "{lines:?}"
        );
    }

    #[tokio::test]
    async fn a_revoke_blob_under_another_app_task_or_kind_is_refused_request() {
        let rig = Rig::new();
        let (reply, _live, _, _) = rig
            .mint(
                &request(vec![set(&["a"])]),
                vec![granted("ghs_one", &["a"])],
            )
            .await;
        let blob = minted(reply).pop().unwrap().for_revocation;
        type Edit = fn(&mut RevokeRequest);
        let edits: [(&str, Edit); 6] = [
            ("app", |r| r.app = "other".into()),
            ("task", |r| r.task = "task-2".into()),
            ("kind", |r| r.kind = "github-machine-user".into()),
            ("class", |r| r.class = "git-read".into()),
            ("set", |r| r.set = 1),
            ("agent", |r| r.agent = "coder2".into()),
        ];
        for (label, edit) in edits {
            let mut req = revoke_request(0, blob.clone());
            edit(&mut req);
            let (got, seen, _) = rig.revoke(&req, vec![]).await;
            assert_eq!(got, RevokeReply::Refused(MintRefusal::Request), "{label}");
            assert_eq!((seen.requests.len(), seen.extra), (0, 0), "{label}");
        }
        let creds_for_agent = {
            let (reply, _l, _, _) = rig
                .mint(&request(vec![set(&["a"])]), vec![granted("ghs_x", &["a"])])
                .await;
            minted(reply).pop().unwrap().for_agent
        };
        let (got, seen, _) = rig
            .revoke(&revoke_request(0, creds_for_agent), vec![])
            .await;
        assert_eq!(got, RevokeReply::Refused(MintRefusal::Request));
        assert_eq!(seen.requests.len(), 0);
    }

    #[tokio::test]
    async fn a_sentinel_token_appears_only_inside_sealed_bytes() {
        const SENTINEL: &str = "ghs_SENTINEL0123456789abcdefABCDEF";
        let jwt_sig = String::from_utf8_lossy(SIGNATURE).to_string();
        let rig = Rig::new();
        let mut shown = Vec::new();
        let (reply, live, _, lines) = rig
            .mint(&request(vec![set(&["a"])]), vec![granted(SENTINEL, &["a"])])
            .await;
        shown.extend(lines);
        shown.push(format!("{reply:?}"));
        shown.push(format!("{live:?}"));
        let creds = minted(reply);
        let blob = creds[0].for_revocation.clone();
        for c in &creds {
            shown.push(format!("{c:?}"));
            for bytes in [c.for_agent.as_bytes(), c.for_revocation.as_bytes()] {
                assert!(
                    !bytes
                        .windows(SENTINEL.len())
                        .any(|w| w == SENTINEL.as_bytes()),
                    "the token is sealed, never in clear"
                );
            }
        }
        let (got, _, lines) = rig
            .revoke(
                &revoke_request(0, blob),
                vec![http("500 Internal Server Error", "{}")],
            )
            .await;
        shown.extend(lines);
        shown.push(format!("{got:?}"));
        let (reply, live, _, lines) = rig
            .mint(
                &request(vec![set(&["a"]), set(&["b"])]),
                vec![
                    granted(SENTINEL, &["a"]),
                    granted("ghs_wide", &["b", "z"]),
                    http("500 Internal Server Error", "{}"),
                    http("500 Internal Server Error", "{}"),
                ],
            )
            .await;
        shown.extend(lines);
        shown.push(format!("{reply:?}"));
        shown.push(format!("{live:?}"));
        assert!(shown.iter().any(|l| l.contains("live token")), "{shown:?}");
        assert!(
            shown.iter().any(|l| l.contains("could not be revoked")),
            "{shown:?}"
        );
        for l in &shown {
            assert!(!l.contains(SENTINEL), "token in {l}");
            assert!(!l.contains("ghs_wide"), "token in {l}");
            assert!(!l.contains(&jwt_sig), "signature in {l}");
            assert!(!l.contains("eyJ"), "JWT in {l}");
        }
    }

    #[test]
    fn the_mint_request_names_no_key_field() {
        let MintRequest {
            task: _,
            agent: _,
            class: _,
            kind: _,
            app: _,
            sets: _,
        } = request(vec![]);
        let RevokeRequest {
            task: _,
            agent: _,
            class: _,
            kind: _,
            app: _,
            set: _,
            for_revocation: _,
        } = revoke_request(0, SealedCredentialBytes::new(vec![0; 200]).unwrap());
        let PermissionSet {
            repositories: _,
            permissions: _,
        } = set(&["a"]);
    }

    #[test]
    fn live_tokens_debug_shows_the_count_only() {
        let live = LiveTokens {
            api: ApiBase::parse("https://api.github.example").unwrap(),
            label: String::new(),
            tokens: vec![MaknaeSecret::new(Zeroizing::new("ghs_secret".into())).unwrap()],
        };
        assert_eq!(format!("{live:?}"), "LiveTokens(<1 tokens>)");
    }

    #[test]
    fn the_seal_context_kind_is_the_credential_kind_spelling() {
        assert_eq!(kind_spelling(TrustPlaneKind::GithubApp), KIND);
        let _ = coder();
    }
}
