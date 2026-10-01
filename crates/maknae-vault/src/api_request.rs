use crate::api_shape::{addr_refusal, VaultOp};
use crate::user_login::{login_path, Password, UserToken};
use crate::wrap::{client_token, wrap_ttl_value, KvDataPath, WrappingToken};
use crate::{UserAuth, VaultError};
use reqwest::header::{HeaderValue, CONTENT_TYPE};
use reqwest::{Body, Client, Method, Request, RequestBuilder};
use serde::Serialize;
use std::time::Duration;
use zeroize::Zeroizing;

pub(crate) const X_VAULT_TOKEN: &str = "X-Vault-Token";
pub(crate) const X_VAULT_WRAP_TTL: &str = "X-Vault-Wrap-TTL";
const X_VAULT_REQUEST: &str = "X-Vault-Request";
const JSON: &str = "application/json";
const LOGIN_BODY_OVERHEAD: usize = r#"{"password":""}"#.len();
const LOOKUP_BODY_OVERHEAD: usize = r#"{"token":""}"#.len();

pub(crate) struct ApiBase(String);

impl ApiBase {
    pub(crate) fn new(addr: &str) -> Result<Self, VaultError> {
        let parsed = url::Url::parse(addr)
            .map_err(|_| VaultError::InvalidAddr("the Vault address is not a URL".into()))?;
        if let Some(part) = addr_refusal(&parsed, addr) {
            return Err(VaultError::InvalidAddr(format!(
                "the Vault address must not carry {part}"
            )));
        }
        let host = parsed
            .host_str()
            .ok_or_else(|| VaultError::InvalidAddr("the Vault address has no host".into()))?;
        let port = parsed.port().map(|p| format!(":{p}")).unwrap_or_default();
        Ok(Self(format!("https://{host}{port}/v1/")))
    }

    #[cfg(test)]
    fn as_str(&self) -> &str {
        &self.0
    }

    fn url(&self, path: &str) -> String {
        format!("{}{path}", self.0)
    }
}

#[derive(Serialize)]
struct LoginBody<'a> {
    password: &'a str,
}

#[derive(Serialize)]
struct LookupBody<'a> {
    token: &'a str,
}

fn json_body<T: Serialize>(capacity: usize, value: &T) -> Result<Zeroizing<Vec<u8>>, VaultError> {
    let mut body = Zeroizing::new(Vec::with_capacity(capacity));
    serde_json::to_writer(&mut *body, value).map_err(|e| VaultError::VaultBody {
        op: "request body",
        why: format!("{:?}", e.classify()),
    })?;
    Ok(body)
}

pub(crate) fn login_body(password: &Password) -> Result<Zeroizing<Vec<u8>>, VaultError> {
    let password = password.expose();
    json_body(
        LOGIN_BODY_OVERHEAD + 6 * password.len(),
        &LoginBody { password },
    )
}

pub(crate) fn lookup_body(token: &WrappingToken) -> Result<Zeroizing<Vec<u8>>, VaultError> {
    let token = token.expose();
    json_body(LOOKUP_BODY_OVERHEAD + token.len(), &LookupBody { token })
}

fn sensitive(value: &str) -> Result<HeaderValue, VaultError> {
    let mut header = HeaderValue::from_str(value).map_err(|_| VaultError::InvalidSecret {
        what: "token header",
        why: "not a valid HTTP header value",
    })?;
    header.set_sensitive(true);
    Ok(header)
}

fn start(http: &Client, method: Method, url: String) -> RequestBuilder {
    http.request(method, url).header(X_VAULT_REQUEST, "true")
}

fn authed(builder: RequestBuilder, token: Option<&str>) -> Result<RequestBuilder, VaultError> {
    match token {
        Some(t) => Ok(builder.header(X_VAULT_TOKEN, sensitive(t)?)),
        None => Ok(builder),
    }
}

fn body_request(builder: RequestBuilder, body: Zeroizing<Vec<u8>>) -> RequestBuilder {
    builder
        .header(CONTENT_TYPE, JSON)
        .body(Body::from(bytes::Bytes::from_owner(body)))
}

fn finish(builder: RequestBuilder) -> Result<Request, VaultError> {
    builder.build().map_err(|e| VaultError::VaultTransport {
        op: "request build",
        detail: e.without_url().to_string(),
    })
}

pub(crate) fn login_request(
    http: &Client,
    base: &ApiBase,
    auth: &UserAuth,
    username: &str,
    body: Zeroizing<Vec<u8>>,
) -> Result<Request, VaultError> {
    let path = login_path(auth, username)?;
    let token = client_token(VaultOp::UserpassLogin, None, None)?;
    let builder = authed(start(http, Method::POST, base.url(&path)), token)?;
    finish(body_request(builder, body))
}

pub(crate) fn wrapped_read_request(
    http: &Client,
    base: &ApiBase,
    token: &UserToken,
    path: &KvDataPath,
    wrap_ttl: Duration,
) -> Result<Request, VaultError> {
    let ttl = wrap_ttl_value(wrap_ttl)?;
    let token = client_token(VaultOp::WrappedRead, Some(token), None)?;
    let builder = authed(start(http, Method::GET, base.url(path.as_str())), token)?;
    finish(builder.header(X_VAULT_WRAP_TTL, ttl))
}

pub(crate) fn lookup_request(
    http: &Client,
    base: &ApiBase,
    body: Zeroizing<Vec<u8>>,
) -> Result<Request, VaultError> {
    let token = client_token(VaultOp::WrapLookup, None, None)?;
    let builder = authed(
        start(http, Method::POST, base.url("sys/wrapping/lookup")),
        token,
    )?;
    finish(body_request(builder, body))
}

pub(crate) fn unwrap_request(
    http: &Client,
    base: &ApiBase,
    token: &WrappingToken,
) -> Result<Request, VaultError> {
    let token = client_token(VaultOp::Unwrap, None, Some(token))?;
    finish(authed(
        start(http, Method::POST, base.url("sys/wrapping/unwrap")),
        token,
    )?)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::wrap::kv_data_path;
    use crate::{MAX_PASSWORD_BYTES, MAX_TOKEN_BYTES};

    fn http() -> Client {
        crate::install_default_crypto_provider();
        let d = std::env::temp_dir().join(format!("mv-api-request-{}", std::process::id()));
        std::fs::create_dir_all(&d).unwrap();
        let params = rcgen::CertificateParams::new(vec!["ca.test".to_string()]).unwrap();
        let key = rcgen::KeyPair::generate_for(&rcgen::PKCS_ECDSA_P384_SHA384).unwrap();
        let ca = d.join(format!("vault-ca-{:?}.crt", std::thread::current().id()));
        std::fs::write(&ca, params.self_signed(&key).unwrap().pem()).unwrap();
        let client = crate::http::hardened_http_client(&ca, Duration::from_secs(5)).unwrap();
        std::fs::remove_file(&ca).unwrap();
        client
    }

    fn base() -> ApiBase {
        ApiBase::new("https://vault.example:8200/").unwrap()
    }

    fn pw(s: &str) -> Password {
        Password::new(Zeroizing::new(s.to_string())).unwrap()
    }

    fn wrapping() -> WrappingToken {
        WrappingToken::new(Zeroizing::new("hvs.wrap".into())).unwrap()
    }

    fn body_json(req: &Request) -> serde_json::Value {
        serde_json::from_slice(req.body().and_then(|b| b.as_bytes()).unwrap()).unwrap()
    }

    #[test]
    fn the_base_address_carries_no_userinfo_query_fragment_or_path() {
        for ok in ["https://vault.example:8200", "https://vault.example:8200/"] {
            assert!(ApiBase::new(ok).is_ok(), "{ok}");
        }
        for bad in [
            "https://u:p@vault.example",
            "http://u:p@vault.example",
            "https://@vault.example",
            "https://:@vault.example",
            "ftp://vault.example",
            "https://vault.example/%2e%2e",
            "https://vault.example/.",
            "https://vault.example/x/..",
            "https://vault.example/?x=1",
            "https://vault.example/#f",
            "https://vault.example/prefix",
        ] {
            assert!(
                matches!(ApiBase::new(bad), Err(VaultError::InvalidAddr(_))),
                "{bad}"
            );
        }
        for leaky in ["https://u:p@vault.example", "http://u:p@vault.example"] {
            let msg = match ApiBase::new(leaky) {
                Err(e) => e.to_string(),
                Ok(_) => unreachable!(),
            };
            assert!(!msg.contains("p@") && !msg.contains("u:p"), "{msg}");
        }
        for (addr, base) in [
            (
                "https://vault.example:8200/",
                "https://vault.example:8200/v1/",
            ),
            ("https://[::1]:8200", "https://[::1]:8200/v1/"),
            ("https://vault.example:443", "https://vault.example/v1/"),
            ("HTTPS://vault.example", "https://vault.example/v1/"),
            (
                "https://bücher.example",
                "https://xn--bcher-kva.example/v1/",
            ),
        ] {
            assert_eq!(ApiBase::new(addr).unwrap().as_str(), base, "{addr}");
        }
    }

    fn header<'a>(req: &'a Request, name: &str) -> &'a str {
        req.headers().get(name).unwrap().to_str().unwrap()
    }

    #[test]
    fn a_plaintext_vault_address_is_refused() {
        assert!(matches!(
            ApiBase::new("http://vault.example:8200"),
            Err(VaultError::InvalidAddr(_))
        ));
    }

    #[test]
    fn the_login_posts_the_password_in_the_body_and_sends_no_token() {
        let corp = UserAuth::new(crate::UserAuthMethod::Userpass, "corp-userpass").unwrap();
        let body = login_body(&pw("p\"w")).unwrap();
        let req = login_request(&http(), &base(), &corp, "alice", body).unwrap();
        assert_eq!(*req.method(), Method::POST);
        assert_eq!(header(&req, "content-type"), JSON);
        assert_eq!(
            req.url().as_str(),
            "https://vault.example:8200/v1/auth/corp-userpass/login/alice"
        );
        assert!(req.headers().get(X_VAULT_TOKEN).is_none());
        assert_eq!(
            req.headers()
                .get(X_VAULT_REQUEST)
                .unwrap()
                .to_str()
                .unwrap(),
            "true"
        );
        assert!(body_json(&req) == serde_json::json!({ "password": "p\"w" }));
    }

    #[test]
    fn a_login_for_a_malformed_username_is_refused_before_any_request() {
        assert!(matches!(
            login_request(
                &http(),
                &base(),
                &UserAuth::userpass_default(),
                "../root",
                login_body(&pw("x")).unwrap()
            ),
            Err(VaultError::InvalidUsername(_))
        ));
    }

    #[test]
    fn the_wrapped_read_carries_the_user_token_and_the_wrap_ttl() {
        let token = UserToken::new(Zeroizing::new("hvs.user".into())).unwrap();
        let path = kv_data_path("maknae-kv", "maknae/users/alice/openai").unwrap();
        let req =
            wrapped_read_request(&http(), &base(), &token, &path, Duration::from_secs(60)).unwrap();
        assert_eq!(*req.method(), Method::GET);
        assert_eq!(header(&req, X_VAULT_REQUEST), "true");
        assert_eq!(
            req.url().as_str(),
            "https://vault.example:8200/v1/maknae-kv/data/maknae/users/alice/openai"
        );
        let t = req.headers().get(X_VAULT_TOKEN).unwrap();
        assert!(t.to_str().unwrap() == "hvs.user" && t.is_sensitive());
        assert_eq!(
            req.headers()
                .get(X_VAULT_WRAP_TTL)
                .unwrap()
                .to_str()
                .unwrap(),
            "60s"
        );
        assert!(req.body().is_none());
    }

    #[test]
    fn a_wrap_ttl_out_of_bounds_is_refused_before_any_request() {
        let token = UserToken::new(Zeroizing::new("hvs.user".into())).unwrap();
        let path = kv_data_path("maknae-kv", "a").unwrap();
        assert!(matches!(
            wrapped_read_request(&http(), &base(), &token, &path, Duration::ZERO),
            Err(VaultError::InvalidWrapTtl(_))
        ));
    }

    #[test]
    fn the_lookup_sends_the_token_in_the_body_and_no_client_token() {
        let body = lookup_body(&wrapping()).unwrap();
        let req = lookup_request(&http(), &base(), body).unwrap();
        assert_eq!(*req.method(), Method::POST);
        assert_eq!(header(&req, "content-type"), JSON);
        assert_eq!(header(&req, X_VAULT_REQUEST), "true");
        assert_eq!(
            req.url().as_str(),
            "https://vault.example:8200/v1/sys/wrapping/lookup"
        );
        assert!(req.headers().get(X_VAULT_TOKEN).is_none());
        assert!(body_json(&req) == serde_json::json!({ "token": "hvs.wrap" }));
    }

    #[test]
    fn the_unwrap_authenticates_with_the_wrapping_token_and_sends_no_body() {
        let req = unwrap_request(&http(), &base(), &wrapping()).unwrap();
        assert_eq!(*req.method(), Method::POST);
        assert_eq!(header(&req, X_VAULT_REQUEST), "true");
        assert_eq!(
            req.url().as_str(),
            "https://vault.example:8200/v1/sys/wrapping/unwrap"
        );
        let t = req.headers().get(X_VAULT_TOKEN).unwrap();
        assert!(t.to_str().unwrap() == "hvs.wrap" && t.is_sensitive());
        assert!(req.body().is_none());
    }

    fn sent(req: &Request) -> (*const u8, usize) {
        let bytes = req.body().and_then(|b| b.as_bytes()).unwrap();
        (bytes.as_ptr(), bytes.len())
    }

    #[test]
    fn the_login_request_sends_the_zeroizing_buffer_itself() {
        let body = login_body(&pw("p")).unwrap();
        let passed = (body.as_ptr(), body.len());
        let req = login_request(
            &http(),
            &base(),
            &UserAuth::userpass_default(),
            "alice",
            body,
        )
        .unwrap();
        assert_eq!(sent(&req), passed);
    }

    #[test]
    fn the_lookup_request_sends_the_zeroizing_buffer_itself() {
        let body = lookup_body(&wrapping()).unwrap();
        let passed = (body.as_ptr(), body.len());
        let req = lookup_request(&http(), &base(), body).unwrap();
        assert_eq!(sent(&req), passed);
    }

    #[test]
    fn request_bodies_are_sized_once_and_never_grow() {
        let worst = pw(&"\u{1}".repeat(MAX_PASSWORD_BYTES));
        let body = login_body(&worst).unwrap();
        let want = LOGIN_BODY_OVERHEAD + 6 * MAX_PASSWORD_BYTES;
        assert_eq!((body.len(), body.capacity()), (want, want));
        let token = WrappingToken::new(Zeroizing::new("a".repeat(MAX_TOKEN_BYTES))).unwrap();
        let body = lookup_body(&token).unwrap();
        let want = LOOKUP_BODY_OVERHEAD + MAX_TOKEN_BYTES;
        assert_eq!((body.len(), body.capacity()), (want, want));
    }
}
