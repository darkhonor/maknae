//! The GitHub App installation-token calls: mint one token per permission set,
//! revoke one, and refuse a grant that is not exactly what was asked.

use super::grant::{
    grant_is_metadata_read, grant_matches, is_github_timestamp, is_installation_token, level,
    Bearer, Grant,
};
use maknae_config::ApiBase;
use maknae_forge::HttpReply;
use maknae_proto::{ForgeStatus, GithubPermission, PermissionSet, RevokeReply};
use serde::Serialize;
use std::collections::BTreeMap;
use std::time::Duration;
use zeroize::Zeroizing;

pub const GITHUB_CALL_TIMEOUT: Duration =
    Duration::from_millis(maknae_config::FORGE_CALL_TIMEOUT_MS);
pub const GITHUB_REPLY_MAX_BYTES: usize = 1_048_576;

/// From `revoke`, `Transport` means nothing was sent (the token is still live);
/// `Status` and `Unanswered` mean the token's state is unknown.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ForgeError {
    /// GitHub answered non-2xx. 401, 403, 404 and 422 are definitive: no token
    /// was issued. Any other status (`Other`: 5xx, 408, 429, ...) may have come
    /// from a gateway after GitHub minted: a live token may exist.
    Status(ForgeStatus),
    /// The grant was not the set asked for: a live token may exist unless `revoked`.
    Mismatch { revoked: bool },
    /// Nothing was sent (no connection, FIPS refusal, client build): no token was issued.
    Transport,
    /// The request may have reached GitHub but no status came back: a live token may exist.
    Unanswered,
    /// The body failed after a 2xx: a live token may exist.
    Unread,
    /// The body exceeded the cap after a 2xx: a live token may exist.
    Oversize,
    /// After a 2xx, the body carried no single well-formed token: a live token
    /// may exist.
    Shape,
    /// The grant's token is well formed but the rest of the grant does not
    /// parse or is malformed: a live token may exist unless `revoked`.
    Malformed { revoked: bool },
}

pub struct MintedToken {
    pub token: Zeroizing<String>,
    pub expires_at: String,
}

impl std::fmt::Debug for MintedToken {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("MintedToken")
            .field("token", &format_args!("<{} bytes>", self.token.len()))
            .field("expires_at", &self.expires_at)
            .finish()
    }
}

/// A mint that answered non-2xx keeps its status, so a reach observer can class it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GrantError {
    Status(u16),
    Forge(ForgeError),
}

#[derive(Clone)]
pub struct GithubClient {
    http: reqwest::Client,
    #[cfg(any(test, feature = "test-support"))]
    loopback: Option<String>,
}

impl std::fmt::Debug for GithubClient {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("GithubClient").finish_non_exhaustive()
    }
}

impl GithubClient {
    pub fn new() -> Result<Self, ForgeError> {
        maknae_crypto::assert_fips_provider().map_err(|_| ForgeError::Transport)?;
        let http = builder()
            .https_only(true)
            .build()
            .map_err(|_| ForgeError::Transport)?;
        Ok(Self {
            http,
            #[cfg(any(test, feature = "test-support"))]
            loopback: None,
        })
    }

    #[cfg(any(test, feature = "test-support"))]
    pub fn loopback_for_tests(base: &str) -> Self {
        maknae_crypto::assert_fips_provider().expect("the FIPS provider is installed");
        Self {
            http: builder().build().expect("a loopback client builds"),
            loopback: Some(base.to_owned()),
        }
    }

    fn base<'a>(&'a self, api: &'a ApiBase) -> &'a str {
        #[cfg(any(test, feature = "test-support"))]
        if let Some(base) = &self.loopback {
            return base;
        }
        api.as_str()
    }

    pub async fn mint(
        &self,
        api: &ApiBase,
        installation_id: u64,
        jwt: &str,
        set: &PermissionSet,
    ) -> Result<MintedToken, ForgeError> {
        let body = MintBody {
            repositories: &set.repositories,
            permissions: set
                .permissions
                .iter()
                .map(|(p, l)| (p.as_str(), level(*l)))
                .collect(),
        };
        self.grant(api, installation_id, jwt, &body, |g| grant_matches(set, g))
            .await
            .map_err(|e| match e {
                GrantError::Status(code) => ForgeError::Status(forge_status(code)),
                GrantError::Forge(e) => e,
            })
    }

    /// An installation-wide token holding exactly `metadata: read` (ADR-0038 d3, as amended).
    pub async fn mint_metadata_read(
        &self,
        api: &ApiBase,
        installation_id: u64,
        jwt: &str,
    ) -> Result<MintedToken, GrantError> {
        let body = MetadataReadBody {
            permissions: BTreeMap::from([(GithubPermission::Metadata.as_str(), "read")]),
        };
        self.grant(api, installation_id, jwt, &body, grant_is_metadata_read)
            .await
    }

    async fn grant<B: Serialize>(
        &self,
        api: &ApiBase,
        installation_id: u64,
        jwt: &str,
        body: &B,
        matches: impl Fn(&Grant) -> bool,
    ) -> Result<MintedToken, GrantError> {
        let url = format!(
            "{}/app/installations/{installation_id}/access_tokens",
            self.base(api)
        );
        let forge = GrantError::Forge;
        let resp = with_headers(self.http.post(url), jwt)
            .json(body)
            .send()
            .await
            .map_err(|e| forge(send_failure(e)))?;
        let status = resp.status();
        if !status.is_success() {
            return Err(GrantError::Status(status.as_u16()));
        }
        let bytes = read_capped(resp).await.map_err(forge)?;
        let bearer: Bearer =
            serde_json::from_slice(&bytes).map_err(|_| forge(ForgeError::Shape))?;
        if !is_installation_token(&bearer.token) {
            return Err(forge(ForgeError::Shape));
        }
        let Ok(grant) = serde_json::from_slice::<Grant>(&bytes) else {
            let revoked = self.revoked(api, &bearer.token).await;
            return Err(forge(ForgeError::Malformed { revoked }));
        };
        if !matches(&grant) {
            let revoked = self.revoked(api, &bearer.token).await;
            return Err(forge(ForgeError::Mismatch { revoked }));
        }
        if !is_github_timestamp(&grant.expires_at) {
            let revoked = self.revoked(api, &bearer.token).await;
            return Err(forge(ForgeError::Malformed { revoked }));
        }
        Ok(MintedToken {
            token: grant.token,
            expires_at: grant.expires_at,
        })
    }

    /// `path` is rooted at the API base; only a 200's body is read, up to the cap.
    pub async fn get(
        &self,
        api: &ApiBase,
        path: &str,
        bearer: &str,
    ) -> Result<HttpReply, ForgeError> {
        if !path.starts_with('/') || path.starts_with("//") {
            return Err(ForgeError::Transport);
        }
        let url = format!("{}{path}", self.base(api));
        let resp = with_headers(self.http.get(url), bearer)
            .send()
            .await
            .map_err(send_failure)?;
        let status = resp.status().as_u16();
        if status != 200 {
            return Ok(HttpReply {
                status,
                body: Vec::new(),
            });
        }
        let mut body = read_capped(resp).await?;
        Ok(HttpReply {
            status,
            body: std::mem::take(&mut *body),
        })
    }

    async fn revoked(&self, api: &ApiBase, token: &str) -> bool {
        matches!(
            self.revoke(api, token).await,
            Ok(RevokeReply::Revoked | RevokeReply::AlreadyGone)
        )
    }

    pub async fn revoke(&self, api: &ApiBase, token: &str) -> Result<RevokeReply, ForgeError> {
        match self.revoke_status(api, token).await? {
            204 => Ok(RevokeReply::Revoked),
            401 => Ok(RevokeReply::AlreadyGone),
            code => Err(ForgeError::Status(forge_status(code))),
        }
    }

    pub async fn revoke_status(&self, api: &ApiBase, token: &str) -> Result<u16, ForgeError> {
        let url = format!("{}/installation/token", self.base(api));
        let resp = with_headers(self.http.delete(url), token)
            .send()
            .await
            .map_err(send_failure)?;
        Ok(resp.status().as_u16())
    }
}

fn builder() -> reqwest::ClientBuilder {
    reqwest::Client::builder()
        .timeout(GITHUB_CALL_TIMEOUT)
        .redirect(reqwest::redirect::Policy::none())
        .no_proxy()
        .retry(reqwest::retry::never())
        .pool_max_idle_per_host(0)
        .user_agent("maknae-egress")
}

fn with_headers(req: reqwest::RequestBuilder, bearer: &str) -> reqwest::RequestBuilder {
    req.bearer_auth(bearer)
        .header(reqwest::header::ACCEPT, "application/vnd.github+json")
        .header("X-GitHub-Api-Version", "2022-11-28")
}

fn send_failure(e: reqwest::Error) -> ForgeError {
    if e.is_connect() {
        ForgeError::Transport
    } else {
        ForgeError::Unanswered
    }
}

pub(crate) fn forge_status(code: u16) -> ForgeStatus {
    match code {
        401 => ForgeStatus::Unauthorized,
        403 => ForgeStatus::Forbidden,
        404 => ForgeStatus::NotFound,
        422 => ForgeStatus::Unprocessable,
        _ => ForgeStatus::Other,
    }
}

async fn read_capped(mut resp: reqwest::Response) -> Result<Zeroizing<Vec<u8>>, ForgeError> {
    if resp
        .content_length()
        .is_some_and(|len| len > GITHUB_REPLY_MAX_BYTES as u64)
    {
        return Err(ForgeError::Oversize);
    }
    let mut body = Zeroizing::new(Vec::with_capacity(GITHUB_REPLY_MAX_BYTES));
    while let Some(chunk) = resp.chunk().await.map_err(|_| ForgeError::Unread)? {
        if chunk.len() > GITHUB_REPLY_MAX_BYTES - body.len() {
            return Err(ForgeError::Oversize);
        }
        body.extend_from_slice(&chunk);
    }
    Ok(body)
}

#[derive(Serialize)]
struct MetadataReadBody {
    permissions: BTreeMap<&'static str, &'static str>,
}

#[derive(Serialize)]
struct MintBody<'a> {
    repositories: &'a [String],
    permissions: BTreeMap<&'static str, &'static str>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use maknae_proto::{AccessLevel, GithubPermission};
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    const JWT: &str = "eyJ.the-app-jwt.sig";

    fn fips() {
        static ONCE: std::sync::Once = std::sync::Once::new();
        ONCE.call_once(|| {
            maknae_crypto::init().unwrap();
        });
    }

    fn api() -> ApiBase {
        ApiBase::parse("https://api.github.example").unwrap()
    }

    fn set(repos: &[&str], perms: &[(GithubPermission, AccessLevel)]) -> PermissionSet {
        PermissionSet {
            repositories: repos.iter().map(|r| r.to_string()).collect(),
            permissions: perms.iter().copied().collect::<BTreeMap<_, _>>(),
        }
    }

    fn reply(status: &str, body: &str) -> String {
        format!(
            "HTTP/1.1 {status}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
            body.len()
        )
    }

    fn grant(token: &str, perms: &str, repos: &[&str]) -> String {
        let repos: Vec<String> = repos
            .iter()
            .map(|r| format!(r#"{{"id":1,"name":"{r}","full_name":"o/{r}","private":true}}"#))
            .collect();
        format!(
            r#"{{"token":"{token}","expires_at":"2026-11-19T01:00:00Z","permissions":{perms},"repository_selection":"selected","repositories":[{}]}}"#,
            repos.join(",")
        )
    }

    struct Seen {
        requests: Vec<String>,
        extra: usize,
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
        String::from_utf8_lossy(&seen).to_string()
    }

    async fn stub(script: Vec<String>) -> (String, tokio::task::JoinHandle<Seen>) {
        let l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = l.local_addr().unwrap();
        let h = tokio::spawn(async move {
            let mut requests = Vec::new();
            for resp in script {
                let Ok(accepted) = tokio::time::timeout(Duration::from_secs(5), l.accept()).await
                else {
                    break;
                };
                let (mut s, _) = accepted.unwrap();
                requests.push(read_request(&mut s).await);
                let _ = s.write_all(resp.as_bytes()).await;
                let _ = s.flush().await;
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

    fn body_of(request: &str) -> serde_json::Value {
        let (_, body) = request.split_once("\r\n\r\n").unwrap();
        serde_json::from_str(body).unwrap()
    }

    fn head_of(request: &str) -> String {
        request.split_once("\r\n\r\n").unwrap().0.to_lowercase()
    }

    #[tokio::test]
    async fn one_request_per_set_with_exactly_that_sets_repositories_and_permissions() {
        fips();
        let a = set(
            &["alpha", "beta"],
            &[
                (GithubPermission::Contents, AccessLevel::Write),
                (GithubPermission::PullRequests, AccessLevel::Write),
            ],
        );
        let b = set(&["gamma"], &[(GithubPermission::Issues, AccessLevel::Read)]);
        let (base, h) = stub(vec![
            reply(
                "201 Created",
                &grant(
                    "ghs_a",
                    r#"{"contents":"write","pull_requests":"write"}"#,
                    &["alpha", "beta"],
                ),
            ),
            reply(
                "201 Created",
                &grant("ghs_b", r#"{"issues":"read"}"#, &["gamma"]),
            ),
        ])
        .await;
        let c = GithubClient::loopback_for_tests(&base);
        let ta = c.mint(&api(), 42, JWT, &a).await.unwrap();
        let tb = c.mint(&api(), 42, JWT, &b).await.unwrap();
        assert_eq!((ta.token.as_str(), tb.token.as_str()), ("ghs_a", "ghs_b"));
        assert_eq!(ta.expires_at, "2026-11-19T01:00:00Z");

        let seen = h.await.unwrap();
        assert_eq!((seen.requests.len(), seen.extra), (2, 0));
        for (req, want) in seen.requests.iter().zip([
            serde_json::json!({"repositories":["alpha","beta"],"permissions":{"contents":"write","pull_requests":"write"}}),
            serde_json::json!({"repositories":["gamma"],"permissions":{"issues":"read"}}),
        ]) {
            let head = head_of(req);
            assert!(
                head.starts_with("post /app/installations/42/access_tokens http/1.1"),
                "{head}"
            );
            assert!(head.contains(&format!("authorization: bearer {}", JWT.to_lowercase())));
            assert!(head.contains("accept: application/vnd.github+json"), "{head}");
            assert!(head.contains("x-github-api-version: 2022-11-28"), "{head}");
            assert_eq!(body_of(req), want);
        }
    }

    #[tokio::test]
    async fn a_wider_grant_is_revoked_and_refused() {
        fips();
        let asked = set(
            &["alpha"],
            &[(GithubPermission::Contents, AccessLevel::Read)],
        );
        for (perms, revoke_status, revoked) in [
            (r#"{"contents":"write"}"#, "204 No Content", true),
            (
                r#"{"contents":"read","issues":"read"}"#,
                "204 No Content",
                true,
            ),
            (
                r#"{"contents":"write"}"#,
                "500 Internal Server Error",
                false,
            ),
        ] {
            let (base, h) = stub(vec![
                reply("201 Created", &grant("ghs_wider", perms, &["alpha"])),
                reply(revoke_status, ""),
            ])
            .await;
            let c = GithubClient::loopback_for_tests(&base);
            assert_eq!(
                c.mint(&api(), 7, JWT, &asked).await.unwrap_err(),
                ForgeError::Mismatch { revoked },
                "{perms}"
            );
            let seen = h.await.unwrap();
            assert_eq!((seen.requests.len(), seen.extra), (2, 0), "{perms}");
            let revoke = head_of(&seen.requests[1]);
            assert!(
                revoke.starts_with("delete /installation/token http/1.1"),
                "{revoke}"
            );
            assert!(
                revoke.contains("authorization: bearer ghs_wider"),
                "{revoke}"
            );
        }
    }

    #[tokio::test]
    async fn a_narrower_grant_is_revoked_and_refused() {
        fips();
        let asked = set(
            &["alpha"],
            &[
                (GithubPermission::Contents, AccessLevel::Read),
                (GithubPermission::Issues, AccessLevel::Read),
            ],
        );
        let (base, h) = stub(vec![
            reply(
                "201 Created",
                &grant("ghs_n", r#"{"contents":"read"}"#, &["alpha"]),
            ),
            reply("204 No Content", ""),
        ])
        .await;
        let c = GithubClient::loopback_for_tests(&base);
        assert_eq!(
            c.mint(&api(), 7, JWT, &asked).await.unwrap_err(),
            ForgeError::Mismatch { revoked: true }
        );
        assert_eq!(h.await.unwrap().requests.len(), 2);
    }

    #[tokio::test]
    async fn a_repository_granted_twice_is_a_mismatch_whatever_its_case() {
        fips();
        let asked = set(
            &["alpha"],
            &[(GithubPermission::Contents, AccessLevel::Read)],
        );
        for repos in [&["alpha", "alpha"][..], &["alpha", "ALPHA"][..]] {
            let (base, h) = stub(vec![
                reply(
                    "201 Created",
                    &grant("ghs_r", r#"{"contents":"read"}"#, repos),
                ),
                reply("204 No Content", ""),
            ])
            .await;
            let c = GithubClient::loopback_for_tests(&base);
            assert_eq!(
                c.mint(&api(), 7, JWT, &asked).await.unwrap_err(),
                ForgeError::Mismatch { revoked: true },
                "{repos:?}"
            );
            assert_eq!(h.await.unwrap().requests.len(), 2, "{repos:?}");
        }
    }

    #[tokio::test]
    async fn extra_repositories_in_the_grant_are_a_mismatch() {
        fips();
        let asked = set(
            &["alpha", "beta"],
            &[(GithubPermission::Contents, AccessLevel::Read)],
        );
        for repos in [
            &["alpha", "beta", "gamma"][..],
            &["alpha"][..],
            &["alpha", "delta"][..],
        ] {
            let (base, h) = stub(vec![
                reply(
                    "201 Created",
                    &grant("ghs_r", r#"{"contents":"read"}"#, repos),
                ),
                reply("204 No Content", ""),
            ])
            .await;
            let c = GithubClient::loopback_for_tests(&base);
            assert_eq!(
                c.mint(&api(), 7, JWT, &asked).await.unwrap_err(),
                ForgeError::Mismatch { revoked: true },
                "{repos:?}"
            );
            let seen = h.await.unwrap();
            assert_eq!(seen.requests.len(), 2, "{repos:?}");
            assert!(head_of(&seen.requests[1]).starts_with("delete /installation/token"));
        }
    }

    #[tokio::test]
    async fn a_grant_of_all_repositories_is_a_mismatch() {
        fips();
        let asked = set(
            &["alpha"],
            &[(GithubPermission::Contents, AccessLevel::Read)],
        );
        let all = r#"{"token":"ghs_all","expires_at":"2026-11-19T01:00:00Z","permissions":{"contents":"read"},"repository_selection":"all","repositories":[{"name":"alpha"}]}"#;
        let none = r#"{"token":"ghs_all","expires_at":"2026-11-19T01:00:00Z","permissions":{"contents":"read"}}"#;
        for body in [all, none] {
            let (base, h) = stub(vec![
                reply("201 Created", body),
                reply("204 No Content", ""),
            ])
            .await;
            let c = GithubClient::loopback_for_tests(&base);
            assert_eq!(
                c.mint(&api(), 7, JWT, &asked).await.unwrap_err(),
                ForgeError::Mismatch { revoked: true },
                "{body}"
            );
            assert_eq!(h.await.unwrap().requests.len(), 2, "{body}");
        }
    }

    #[tokio::test]
    async fn metadata_read_beyond_the_request_is_not_a_mismatch() {
        fips();
        let asked = set(
            &["alpha"],
            &[(GithubPermission::Contents, AccessLevel::Read)],
        );
        let (base, h) = stub(vec![reply(
            "201 Created",
            &grant(
                "ghs_m",
                r#"{"contents":"read","metadata":"read"}"#,
                &["alpha"],
            ),
        )])
        .await;
        let c = GithubClient::loopback_for_tests(&base);
        assert_eq!(
            c.mint(&api(), 7, JWT, &asked).await.unwrap().token.as_str(),
            "ghs_m"
        );
        let seen = h.await.unwrap();
        assert_eq!((seen.requests.len(), seen.extra), (1, 0));

        let (base, h) = stub(vec![
            reply(
                "201 Created",
                &grant(
                    "ghs_mw",
                    r#"{"contents":"read","metadata":"write"}"#,
                    &["alpha"],
                ),
            ),
            reply("204 No Content", ""),
        ])
        .await;
        let c = GithubClient::loopback_for_tests(&base);
        assert_eq!(
            c.mint(&api(), 7, JWT, &asked).await.unwrap_err(),
            ForgeError::Mismatch { revoked: true }
        );
        assert_eq!(h.await.unwrap().requests.len(), 2);

        let asked_write = set(
            &["alpha"],
            &[(GithubPermission::Metadata, AccessLevel::Write)],
        );
        let (base, h) = stub(vec![
            reply(
                "201 Created",
                &grant("ghs_mr", r#"{"metadata":"read"}"#, &["alpha"]),
            ),
            reply("204 No Content", ""),
        ])
        .await;
        let c = GithubClient::loopback_for_tests(&base);
        assert_eq!(
            c.mint(&api(), 7, JWT, &asked_write).await.unwrap_err(),
            ForgeError::Mismatch { revoked: true }
        );
        assert_eq!(h.await.unwrap().requests.len(), 2);
    }

    #[tokio::test]
    async fn repository_case_differences_are_not_a_mismatch() {
        fips();
        let asked = set(
            &["Alpha", "beta-Two"],
            &[(GithubPermission::Contents, AccessLevel::Read)],
        );
        let (base, h) = stub(vec![reply(
            "201 Created",
            &grant("ghs_c", r#"{"contents":"read"}"#, &["alpha", "BETA-two"]),
        )])
        .await;
        let c = GithubClient::loopback_for_tests(&base);
        assert_eq!(
            c.mint(&api(), 7, JWT, &asked).await.unwrap().token.as_str(),
            "ghs_c"
        );
        assert_eq!(h.await.unwrap().requests.len(), 1);
    }

    #[tokio::test]
    async fn a_duplicate_permission_in_the_grant_is_malformed_and_revoked() {
        fips();
        let asked = set(
            &["alpha"],
            &[(GithubPermission::Contents, AccessLevel::Read)],
        );
        let (base, h) = stub(vec![
            reply(
                "201 Created",
                &grant(
                    "ghs_d",
                    r#"{"contents":"admin","contents":"read"}"#,
                    &["alpha"],
                ),
            ),
            reply("204 No Content", ""),
        ])
        .await;
        let c = GithubClient::loopback_for_tests(&base);
        assert_eq!(
            c.mint(&api(), 7, JWT, &asked).await.unwrap_err(),
            ForgeError::Malformed { revoked: true }
        );
        assert_eq!(h.await.unwrap().requests.len(), 2);
    }

    #[tokio::test]
    async fn a_grant_that_fails_to_parse_around_a_usable_token_is_revoked() {
        fips();
        let asked = set(
            &["alpha"],
            &[(GithubPermission::Contents, AccessLevel::Read)],
        );
        for body in [
            r#"{"token":"ghs_ok","expires_at":5,"permissions":{"contents":"read"},"repository_selection":"selected","repositories":[{"name":"alpha"}]}"#,
            r#"{"token":"ghs_ok","expires_at":"2026-11-19T01:00:00Z","permissions":{"contents":"read"},"repository_selection":"selected","repositories":[{"id":1}]}"#,
            r#"{"token":"ghs_ok"}"#,
        ] {
            let (base, h) = stub(vec![
                reply("201 Created", body),
                reply("204 No Content", ""),
            ])
            .await;
            let c = GithubClient::loopback_for_tests(&base);
            assert_eq!(
                c.mint(&api(), 7, JWT, &asked).await.unwrap_err(),
                ForgeError::Malformed { revoked: true },
                "{body}"
            );
            let seen = h.await.unwrap();
            assert_eq!(seen.requests.len(), 2, "{body}");
            let head = head_of(&seen.requests[1]);
            assert!(
                head.starts_with("delete /installation/token http/1.1")
                    && head.contains("authorization: bearer ghs_ok"),
                "{head}"
            );
        }
    }

    #[tokio::test]
    async fn two_token_fields_are_shape_and_neither_is_used() {
        fips();
        let asked = set(
            &["alpha"],
            &[(GithubPermission::Contents, AccessLevel::Read)],
        );
        let body = r#"{"token":"ghs_a","token":"ghs_b","expires_at":"2026-11-19T01:00:00Z","permissions":{"contents":"read"},"repository_selection":"selected","repositories":[{"name":"alpha"}]}"#;
        let (base, h) = stub(vec![
            reply("201 Created", body),
            reply("204 No Content", ""),
        ])
        .await;
        let c = GithubClient::loopback_for_tests(&base);
        assert_eq!(
            c.mint(&api(), 7, JWT, &asked).await.unwrap_err(),
            ForgeError::Shape
        );
        assert_eq!(h.await.unwrap().requests.len(), 1);
    }

    #[test]
    fn forge_status_maps_each_class() {
        for (code, want) in [
            (401, ForgeStatus::Unauthorized),
            (403, ForgeStatus::Forbidden),
            (404, ForgeStatus::NotFound),
            (422, ForgeStatus::Unprocessable),
            (302, ForgeStatus::Other),
            (400, ForgeStatus::Other),
            (500, ForgeStatus::Other),
            (503, ForgeStatus::Other),
        ] {
            assert_eq!(forge_status(code), want, "{code}");
        }
    }

    #[tokio::test]
    async fn each_status_class_maps_to_its_forge_status() {
        fips();
        let asked = set(
            &["alpha"],
            &[(GithubPermission::Contents, AccessLevel::Read)],
        );
        for (status, want) in [
            ("401 Unauthorized", ForgeStatus::Unauthorized),
            ("403 Forbidden", ForgeStatus::Forbidden),
            ("404 Not Found", ForgeStatus::NotFound),
            ("422 Unprocessable Entity", ForgeStatus::Unprocessable),
            ("409 Conflict", ForgeStatus::Other),
            ("500 Internal Server Error", ForgeStatus::Other),
        ] {
            let (base, h) = stub(vec![reply(status, r#"{"message":"no"}"#)]).await;
            let c = GithubClient::loopback_for_tests(&base);
            assert_eq!(
                c.mint(&api(), 7, JWT, &asked).await.unwrap_err(),
                ForgeError::Status(want),
                "{status}"
            );
            let seen = h.await.unwrap();
            assert_eq!((seen.requests.len(), seen.extra), (1, 0), "{status}");
        }
    }

    async fn exactly_one_request(status: &str, want: ForgeStatus) {
        fips();
        let asked = set(
            &["alpha"],
            &[(GithubPermission::Contents, AccessLevel::Read)],
        );
        let (base, h) = stub(vec![reply(status, "{}")]).await;
        let c = GithubClient::loopback_for_tests(&base);
        assert_eq!(
            c.mint(&api(), 7, JWT, &asked).await.unwrap_err(),
            ForgeError::Status(want)
        );
        let seen = h.await.unwrap();
        assert_eq!((seen.requests.len(), seen.extra), (1, 0));
    }

    #[tokio::test]
    async fn a_401_on_mint_is_unauthorized_and_not_retried() {
        exactly_one_request("401 Unauthorized", ForgeStatus::Unauthorized).await;
    }

    #[tokio::test]
    async fn a_503_is_other_and_not_retried() {
        exactly_one_request("503 Service Unavailable", ForgeStatus::Other).await;
    }

    #[tokio::test]
    async fn a_redirect_is_not_followed() {
        fips();
        let elsewhere = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let target = format!(
            "http://{}/app/installations/7/access_tokens",
            elsewhere.local_addr().unwrap()
        );
        let (base, h) = stub(vec![format!(
            "HTTP/1.1 307 Temporary Redirect\r\nLocation: {target}\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
        )])
        .await;
        let c = GithubClient::loopback_for_tests(&base);
        let asked = set(
            &["alpha"],
            &[(GithubPermission::Contents, AccessLevel::Read)],
        );
        let got = tokio::time::timeout(Duration::from_secs(5), c.mint(&api(), 7, JWT, &asked))
            .await
            .expect("the redirect was followed to a target that never answers");
        assert_eq!(got.unwrap_err(), ForgeError::Status(ForgeStatus::Other));
        assert_eq!(h.await.unwrap().requests.len(), 1);
        assert!(
            tokio::time::timeout(Duration::from_millis(300), elsewhere.accept())
                .await
                .is_err(),
            "the redirect target was contacted"
        );
    }

    #[tokio::test]
    async fn a_reply_over_the_cap_is_oversize_before_parsing() {
        fips();
        let asked = set(
            &["alpha"],
            &[(GithubPermission::Contents, AccessLevel::Read)],
        );
        let over = "x".repeat(GITHUB_REPLY_MAX_BYTES + 1);
        let declared = reply("201 Created", &over);
        let undeclared = format!("HTTP/1.1 201 Created\r\nConnection: close\r\n\r\n{over}");
        let garbage = format!(
            "HTTP/1.1 201 Created\r\nContent-Length: 10\r\nConnection: close\r\n\r\n{}",
            "x".repeat(10)
        );
        for (resp, want) in [
            (declared, ForgeError::Oversize),
            (undeclared, ForgeError::Oversize),
            (garbage, ForgeError::Shape),
        ] {
            let (base, h) = stub(vec![resp]).await;
            let c = GithubClient::loopback_for_tests(&base);
            assert_eq!(c.mint(&api(), 7, JWT, &asked).await.unwrap_err(), want);
            let seen = h.await.unwrap();
            assert_eq!((seen.requests.len(), seen.extra), (1, 0));
        }

        let body = grant("ghs_cap", r#"{"contents":"read"}"#, &["alpha"]);
        let at_cap = format!("{body}{}", " ".repeat(GITHUB_REPLY_MAX_BYTES - body.len()));
        let (base, _h) = stub(vec![reply("201 Created", &at_cap)]).await;
        let c = GithubClient::loopback_for_tests(&base);
        assert_eq!(
            c.mint(&api(), 7, JWT, &asked).await.unwrap().token.as_str(),
            "ghs_cap"
        );

        let undeclared_at_cap =
            format!("HTTP/1.1 201 Created\r\nConnection: close\r\n\r\n{at_cap}");
        let (base, _h) = stub(vec![undeclared_at_cap]).await;
        let c = GithubClient::loopback_for_tests(&base);
        assert_eq!(
            c.mint(&api(), 7, JWT, &asked).await.unwrap().token.as_str(),
            "ghs_cap"
        );
    }

    #[tokio::test]
    async fn a_reply_that_does_not_parse_is_shape() {
        fips();
        let asked = set(
            &["alpha"],
            &[(GithubPermission::Contents, AccessLevel::Read)],
        );
        for body in [
            "not json",
            r#"{"expires_at":"2026-11-19T01:00:00Z","permissions":{},"repositories":[]}"#,
            r#"{"token":7,"expires_at":"2026-11-19T01:00:00Z","permissions":{}}"#,
        ] {
            let (base, h) = stub(vec![reply("201 Created", body)]).await;
            let c = GithubClient::loopback_for_tests(&base);
            assert_eq!(
                c.mint(&api(), 7, JWT, &asked).await.unwrap_err(),
                ForgeError::Shape,
                "{body}"
            );
            assert_eq!(h.await.unwrap().requests.len(), 1);
        }
    }

    #[tokio::test]
    async fn a_grant_whose_token_is_not_a_token_is_shape_and_never_used_as_a_bearer() {
        fips();
        let asked = set(
            &["alpha"],
            &[(GithubPermission::Contents, AccessLevel::Read)],
        );
        let long = "a".repeat(256);
        for token in [
            "",
            "ghs bad",
            "ghs-bad",
            "ghs\\r\\nX-Injected: 1",
            long.as_str(),
        ] {
            let (base, h) = stub(vec![
                reply(
                    "201 Created",
                    &grant(token, r#"{"contents":"read"}"#, &["alpha"]),
                ),
                reply("204 No Content", ""),
            ])
            .await;
            let c = GithubClient::loopback_for_tests(&base);
            assert_eq!(
                c.mint(&api(), 7, JWT, &asked).await.unwrap_err(),
                ForgeError::Shape,
                "{token:?}"
            );
            let seen = h.await.unwrap();
            assert_eq!(seen.requests.len(), 1, "{token:?}: no revoke is sent");
        }
    }

    fn with_expiry(token: &str, expires_at: &str) -> String {
        grant(token, r#"{"contents":"read"}"#, &["alpha"])
            .replace("2026-11-19T01:00:00Z", expires_at)
    }

    #[tokio::test]
    async fn a_grant_with_a_malformed_expiry_is_revoked_and_refused() {
        fips();
        let asked = set(
            &["alpha"],
            &[(GithubPermission::Contents, AccessLevel::Read)],
        );
        let long = "2".repeat(65);
        for (expires_at, revoke, revoked) in [
            ("tomorrow", reply("204 No Content", ""), true),
            (long.as_str(), reply("401 Unauthorized", ""), true),
            ("2026-11-19T01:00:00.5Z", reply("500 Oops", ""), false),
        ] {
            let (base, h) = stub(vec![
                reply("201 Created", &with_expiry("ghs_live", expires_at)),
                revoke,
            ])
            .await;
            let c = GithubClient::loopback_for_tests(&base);
            assert_eq!(
                c.mint(&api(), 7, JWT, &asked).await.unwrap_err(),
                ForgeError::Malformed { revoked },
                "{expires_at}"
            );
            let seen = h.await.unwrap();
            assert_eq!((seen.requests.len(), seen.extra), (2, 0), "{expires_at}");
            let head = head_of(&seen.requests[1]);
            assert!(
                head.starts_with("delete /installation/token http/1.1")
                    && head.contains("authorization: bearer ghs_live"),
                "{head}"
            );
        }
    }

    #[tokio::test]
    async fn a_refused_connection_is_transport() {
        fips();
        let l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let base = format!("http://{}", l.local_addr().unwrap());
        drop(l);
        let c = GithubClient::loopback_for_tests(&base);
        let asked = set(
            &["alpha"],
            &[(GithubPermission::Contents, AccessLevel::Read)],
        );
        assert_eq!(
            c.mint(&api(), 7, JWT, &asked).await.unwrap_err(),
            ForgeError::Transport
        );
        assert_eq!(
            c.revoke(&api(), "ghs_x").await.unwrap_err(),
            ForgeError::Transport
        );
    }

    #[tokio::test]
    async fn revoke_maps_204_401_and_500() {
        fips();
        for (status, want) in [
            ("204 No Content", Ok(RevokeReply::Revoked)),
            ("401 Unauthorized", Ok(RevokeReply::AlreadyGone)),
            (
                "500 Internal Server Error",
                Err(ForgeError::Status(ForgeStatus::Other)),
            ),
            (
                "403 Forbidden",
                Err(ForgeError::Status(ForgeStatus::Forbidden)),
            ),
            ("200 OK", Err(ForgeError::Status(ForgeStatus::Other))),
        ] {
            let (base, h) = stub(vec![reply(status, "")]).await;
            let c = GithubClient::loopback_for_tests(&base);
            assert_eq!(c.revoke(&api(), "ghs_gone").await, want, "{status}");
            let seen = h.await.unwrap();
            assert_eq!((seen.requests.len(), seen.extra), (1, 0), "{status}");
            let head = head_of(&seen.requests[0]);
            assert!(
                head.starts_with("delete /installation/token http/1.1"),
                "{head}"
            );
            assert!(head.contains("authorization: bearer ghs_gone"), "{head}");
            assert!(
                head.contains("accept: application/vnd.github+json"),
                "{head}"
            );
            assert!(head.contains("x-github-api-version: 2022-11-28"), "{head}");
        }
    }

    #[tokio::test]
    async fn the_token_is_never_in_debug_output() {
        fips();
        let sentinel = "ghs_debug_sentinel_7c1e";
        let asked = set(
            &["alpha"],
            &[(GithubPermission::Contents, AccessLevel::Read)],
        );
        let (base, _h) = stub(vec![reply(
            "201 Created",
            &grant(sentinel, r#"{"contents":"read"}"#, &["alpha"]),
        )])
        .await;
        let c = GithubClient::loopback_for_tests(&base);
        let minted = c.mint(&api(), 7, JWT, &asked).await.unwrap();
        assert_eq!(minted.token.as_str(), sentinel);
        let shown = format!("{minted:?} {c:?} {minted:#?} {c:#?}");
        assert!(!shown.contains(sentinel), "{shown}");
        assert!(shown.contains("2026-11-19T01:00:00Z"), "{shown}");
    }

    async fn mismatch_then_revoke(revoke: String) -> (Result<MintedToken, ForgeError>, Seen) {
        fips();
        let asked = set(
            &["alpha"],
            &[(GithubPermission::Contents, AccessLevel::Read)],
        );
        let (base, h) = stub(vec![
            reply(
                "201 Created",
                &grant("ghs_live", r#"{"contents":"write"}"#, &["alpha"]),
            ),
            revoke,
        ])
        .await;
        let c = GithubClient::loopback_for_tests(&base);
        let out = c.mint(&api(), 7, JWT, &asked).await;
        (out, h.await.unwrap())
    }

    #[tokio::test]
    async fn a_mismatch_whose_revoke_fails_reports_unrevoked() {
        for revoke in [
            reply("500 Internal Server Error", ""),
            reply("403 Forbidden", ""),
            reply("200 OK", ""),
            "HTTP/1.1 garbage\r\n\r\n".to_string(),
        ] {
            let (out, seen) = mismatch_then_revoke(revoke.clone()).await;
            assert_eq!(
                out.unwrap_err(),
                ForgeError::Mismatch { revoked: false },
                "{revoke}"
            );
            assert_eq!(seen.requests.len(), 2, "{revoke}");
        }
    }

    #[tokio::test]
    async fn a_mismatch_whose_revoke_succeeds_reports_revoked() {
        for revoke in [reply("204 No Content", ""), reply("401 Unauthorized", "")] {
            let (out, seen) = mismatch_then_revoke(revoke.clone()).await;
            assert_eq!(
                out.unwrap_err(),
                ForgeError::Mismatch { revoked: true },
                "{revoke}"
            );
            assert_eq!(seen.requests.len(), 2, "{revoke}");
        }
    }

    #[tokio::test]
    async fn a_body_cut_off_after_201_is_unread_not_transport() {
        fips();
        let asked = set(
            &["alpha"],
            &[(GithubPermission::Contents, AccessLevel::Read)],
        );
        let cut = format!(
            "HTTP/1.1 201 Created\r\nContent-Length: 1000\r\nConnection: close\r\n\r\n{}",
            r#"{"token":"ghs_cut""#
        );
        let (base, h) = stub(vec![cut]).await;
        let c = GithubClient::loopback_for_tests(&base);
        assert_eq!(
            c.mint(&api(), 7, JWT, &asked).await.unwrap_err(),
            ForgeError::Unread
        );
        let seen = h.await.unwrap();
        assert_eq!((seen.requests.len(), seen.extra), (1, 0));
    }

    #[tokio::test]
    async fn a_request_answered_by_a_close_is_unanswered_not_transport() {
        fips();
        let asked = set(
            &["alpha"],
            &[(GithubPermission::Contents, AccessLevel::Read)],
        );
        let (base, h) = stub(vec![String::new()]).await;
        let c = GithubClient::loopback_for_tests(&base);
        assert_eq!(
            c.mint(&api(), 7, JWT, &asked).await.unwrap_err(),
            ForgeError::Unanswered
        );
        let seen = h.await.unwrap();
        assert_eq!((seen.requests.len(), seen.extra), (1, 0));
        assert!(head_of(&seen.requests[0]).starts_with("post /app/installations/7/access_tokens"));

        let (base, h) = stub(vec![String::new()]).await;
        let c = GithubClient::loopback_for_tests(&base);
        assert_eq!(
            c.revoke(&api(), "ghs_x").await.unwrap_err(),
            ForgeError::Unanswered
        );
        let seen = h.await.unwrap();
        assert_eq!((seen.requests.len(), seen.extra), (1, 0));
    }

    fn metadata_grant(token: &str, perms: &str) -> String {
        format!(
            r#"{{"token":"{token}","expires_at":"2026-11-23T01:00:00Z","permissions":{perms},"repository_selection":"selected"}}"#
        )
    }

    #[tokio::test]
    async fn a_metadata_read_mint_asks_for_metadata_alone_with_no_repositories() {
        fips();
        let (base, h) = stub(vec![reply(
            "201 Created",
            &metadata_grant("ghs_meta", r#"{"metadata":"read"}"#),
        )])
        .await;
        let c = GithubClient::loopback_for_tests(&base);
        let t = c.mint_metadata_read(&api(), 77, JWT).await.unwrap();
        assert_eq!(t.token.as_str(), "ghs_meta");
        let seen = h.await.unwrap();
        assert_eq!((seen.requests.len(), seen.extra), (1, 0));
        let head = head_of(&seen.requests[0]);
        assert!(
            head.starts_with("post /app/installations/77/access_tokens http/1.1"),
            "{head}"
        );
        assert!(head.contains(&format!("authorization: bearer {}", JWT.to_lowercase())));
        assert_eq!(
            body_of(&seen.requests[0]),
            serde_json::json!({"permissions":{"metadata":"read"}})
        );
    }

    #[tokio::test]
    async fn a_metadata_grant_that_is_not_exactly_metadata_read_is_revoked() {
        fips();
        for perms in [
            r#"{"metadata":"read","contents":"read"}"#,
            r#"{"metadata":"write"}"#,
            r#"{}"#,
        ] {
            let (base, h) = stub(vec![
                reply("201 Created", &metadata_grant("ghs_wide", perms)),
                reply("204 No Content", ""),
            ])
            .await;
            let c = GithubClient::loopback_for_tests(&base);
            assert_eq!(
                c.mint_metadata_read(&api(), 77, JWT).await.unwrap_err(),
                GrantError::Forge(ForgeError::Mismatch { revoked: true }),
                "{perms}"
            );
            let seen = h.await.unwrap();
            assert_eq!(seen.requests.len(), 2, "{perms}");
            let revoke = head_of(&seen.requests[1]);
            assert!(revoke.starts_with("delete /installation/token"), "{revoke}");
            assert!(
                revoke.contains("authorization: bearer ghs_wide"),
                "{revoke}"
            );
        }
    }

    #[tokio::test]
    async fn a_metadata_mint_keeps_its_status_and_refuses_a_tokenless_grant() {
        fips();
        for (status, code) in [
            ("401 Unauthorized", 401),
            ("404 Not Found", 404),
            ("429 Too Many Requests", 429),
            ("301 Moved Permanently", 301),
        ] {
            let (base, h) = stub(vec![reply(status, "{}")]).await;
            let c = GithubClient::loopback_for_tests(&base);
            assert_eq!(
                c.mint_metadata_read(&api(), 77, JWT).await.unwrap_err(),
                GrantError::Status(code)
            );
            assert_eq!(h.await.unwrap().requests.len(), 1);
        }
        let (base, h) = stub(vec![reply("201 Created", r#"{"token":"bad token"}"#)]).await;
        let c = GithubClient::loopback_for_tests(&base);
        assert_eq!(
            c.mint_metadata_read(&api(), 77, JWT).await.unwrap_err(),
            GrantError::Forge(ForgeError::Shape)
        );
        assert_eq!(h.await.unwrap().requests.len(), 1);
    }

    #[tokio::test]
    async fn a_get_sends_the_bearer_to_the_rooted_path_and_reads_only_a_200() {
        fips();
        let (base, h) = stub(vec![
            reply("200 OK", r#"{"full_name":"o/r"}"#),
            reply("404 Not Found", r#"{"message":"Not Found"}"#),
            "HTTP/1.1 302 Found\r\nLocation: http://127.0.0.1:1/elsewhere\r\nContent-Length: 0\r\nConnection: close\r\n\r\n".to_owned(),
        ])
        .await;
        let c = GithubClient::loopback_for_tests(&base);
        let ok = c.get(&api(), "/repos/o/r?x=1", "ghp_tasker").await.unwrap();
        assert_eq!(
            (ok.status, ok.body.as_slice()),
            (200, &br#"{"full_name":"o/r"}"#[..])
        );
        let missing = c.get(&api(), "/repos/o/gone", "ghp_tasker").await.unwrap();
        assert_eq!((missing.status, missing.body.len()), (404, 0));
        let moved = c.get(&api(), "/repos/o/moved", "ghp_tasker").await.unwrap();
        assert_eq!(moved.status, 302);
        let seen = h.await.unwrap();
        assert_eq!((seen.requests.len(), seen.extra), (3, 0));
        let head = head_of(&seen.requests[0]);
        assert!(head.starts_with("get /repos/o/r?x=1 http/1.1"), "{head}");
        assert!(head.contains("authorization: bearer ghp_tasker"), "{head}");
        assert!(
            head.contains("accept: application/vnd.github+json"),
            "{head}"
        );
        assert!(head.contains("x-github-api-version: 2022-11-28"), "{head}");
    }

    #[tokio::test]
    async fn a_get_path_not_rooted_at_the_api_is_never_sent() {
        fips();
        let (base, h) = stub(vec![]).await;
        let c = GithubClient::loopback_for_tests(&base);
        for path in ["@evil.example/x", "", "repos/o/r", "//evil.example/x"] {
            assert_eq!(
                c.get(&api(), path, "ghp_tasker").await.unwrap_err(),
                ForgeError::Transport,
                "{path}"
            );
        }
        assert_eq!(h.await.unwrap().extra, 0);
    }

    #[tokio::test]
    async fn an_oversized_get_body_is_refused() {
        fips();
        let big = "x".repeat(GITHUB_REPLY_MAX_BYTES + 1);
        let (base, h) = stub(vec![reply("200 OK", &big)]).await;
        let c = GithubClient::loopback_for_tests(&base);
        assert_eq!(
            c.get(&api(), "/installation/repositories", "ghs_x")
                .await
                .unwrap_err(),
            ForgeError::Oversize
        );
        h.await.unwrap();
    }

    #[tokio::test]
    async fn revoke_status_passes_the_status_through() {
        fips();
        for (status, code) in [
            ("204 No Content", 204),
            ("401 Unauthorized", 401),
            ("500 Internal Server Error", 500),
        ] {
            let (base, h) = stub(vec![reply(status, "")]).await;
            let c = GithubClient::loopback_for_tests(&base);
            assert_eq!(c.revoke_status(&api(), "ghs_x").await, Ok(code));
            assert!(
                head_of(&h.await.unwrap().requests[0]).starts_with("delete /installation/token")
            );
        }
    }

    #[test]
    fn the_github_bounds_are_pinned() {
        assert_eq!(GITHUB_REPLY_MAX_BYTES, 1_048_576);
        assert_eq!(GITHUB_CALL_TIMEOUT, Duration::from_secs(20));
    }

    #[test]
    fn the_client_s_debug_shows_no_field() {
        fips();
        assert_eq!(
            format!(
                "{:?}",
                GithubClient::loopback_for_tests("http://127.0.0.1:1")
            ),
            "GithubClient { .. }"
        );
    }

    #[test]
    fn new_builds_once_the_fips_provider_is_installed() {
        fips();
        assert!(GithubClient::new().is_ok());
    }
}
