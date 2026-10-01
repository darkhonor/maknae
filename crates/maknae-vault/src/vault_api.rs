use crate::api_request::{
    login_body, login_request, lookup_body, lookup_request, unwrap_request, wrapped_read_request,
    ApiBase,
};
use crate::api_shape::{append_bounded, refuse_status, VaultOp, MAX_VAULT_BODY_BYTES};
use crate::user_login::{parse_login, Password, UserLogin, UserToken};
use crate::wrap::{
    kv_data_path, parse_lookup, parse_wrapped_read, unwrap_checked, CheckedLookup, UnwrapOps,
    WrapExpectation, WrapLookup, WrappedSecret, WrappingToken,
};
use crate::{assert_fips_provider, UserAuth, UserAuthMethod, VaultError};
use std::path::Path;
use std::time::Duration;
use zeroize::Zeroizing;

const VAULT_API_TIMEOUT: Duration = Duration::from_secs(30);

pub struct VaultApi {
    base: ApiBase,
    http: reqwest::Client,
}

fn transport(op: VaultOp, e: reqwest::Error) -> VaultError {
    VaultError::VaultTransport {
        op: op.as_str(),
        detail: e.without_url().to_string(),
    }
}

fn oversize(op: VaultOp) -> VaultError {
    VaultError::VaultBody {
        op: op.as_str(),
        why: format!("body over {MAX_VAULT_BODY_BYTES} bytes"),
    }
}

impl VaultApi {
    pub fn new(addr: &str, vault_ca: &Path) -> Result<Self, VaultError> {
        assert_fips_provider()?;
        let base = ApiBase::new(addr)?;
        let http = crate::http::hardened_http_client(vault_ca, VAULT_API_TIMEOUT)?;
        Ok(Self { base, http })
    }

    pub async fn login(
        &self,
        auth: &UserAuth,
        username: &str,
        password: &Password,
    ) -> Result<UserLogin, VaultError> {
        match auth.method() {
            UserAuthMethod::Userpass => {
                let body = login_body(password)?;
                let req = login_request(&self.http, &self.base, auth, username, body)?;
                let body = self.execute(VaultOp::UserpassLogin, req).await?;
                parse_login(&body, username)
            }
        }
    }

    pub async fn read_wrapped(
        &self,
        token: &UserToken,
        kv_mount: &str,
        secret_path: &str,
        wrap_ttl: Duration,
    ) -> Result<WrappedSecret, VaultError> {
        let path = kv_data_path(kv_mount, secret_path)?;
        let req = wrapped_read_request(&self.http, &self.base, token, &path, wrap_ttl)?;
        let body = self.execute(VaultOp::WrappedRead, req).await?;
        parse_wrapped_read(&body, &path, wrap_ttl)
    }

    pub async fn lookup_wrapping(&self, token: &WrappingToken) -> Result<WrapLookup, VaultError> {
        let body = lookup_body(token)?;
        let req = lookup_request(&self.http, &self.base, body)?;
        let body = self.execute(VaultOp::WrapLookup, req).await?;
        parse_lookup(&body)
    }

    pub async fn unwrap_kv_field(
        &self,
        token: WrappingToken,
        expect: &WrapExpectation,
    ) -> Result<Zeroizing<String>, VaultError> {
        unwrap_checked(self, token, expect).await
    }

    async fn execute(
        &self,
        op: VaultOp,
        req: reqwest::Request,
    ) -> Result<Zeroizing<Vec<u8>>, VaultError> {
        let mut resp = self.http.execute(req).await.map_err(|e| transport(op, e))?;
        let status = resp.status();
        if !status.is_success() {
            return Err(refuse_status(op, status.as_u16()));
        }
        if resp
            .content_length()
            .is_some_and(|n| n > MAX_VAULT_BODY_BYTES as u64)
        {
            return Err(oversize(op));
        }
        let mut body = Zeroizing::new(Vec::with_capacity(MAX_VAULT_BODY_BYTES));
        while let Some(chunk) = resp.chunk().await.map_err(|e| transport(op, e))? {
            append_bounded(&mut body, &chunk).map_err(|_| oversize(op))?;
        }
        Ok(body)
    }
}

impl UnwrapOps for VaultApi {
    async fn lookup(&self, token: &WrappingToken) -> Result<WrapLookup, VaultError> {
        self.lookup_wrapping(token).await
    }

    async fn unwrap_body(
        &self,
        token: WrappingToken,
        _checked: &CheckedLookup,
    ) -> Result<Zeroizing<Vec<u8>>, VaultError> {
        let req = unwrap_request(&self.http, &self.base, &token)?;
        drop(token);
        self.execute(VaultOp::Unwrap, req).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ca() -> (tempfile::TempDir, std::path::PathBuf) {
        let dir = tempfile::tempdir().unwrap();
        let params = rcgen::CertificateParams::new(vec!["ca.test".to_string()]).unwrap();
        let key = rcgen::KeyPair::generate_for(&rcgen::PKCS_ECDSA_P384_SHA384).unwrap();
        let path = dir.path().join("vault-ca.crt");
        std::fs::write(&path, params.self_signed(&key).unwrap().pem()).unwrap();
        (dir, path)
    }

    #[test]
    fn construction_fails_closed_on_plaintext_addr_and_missing_ca() {
        crate::install_default_crypto_provider();
        assert!(matches!(
            VaultApi::new("http://127.0.0.1:1", &ca().1),
            Err(VaultError::InvalidAddr(_))
        ));
        let absent = std::env::temp_dir().join("mv-vault-api-absent/vault-ca.crt");
        assert!(matches!(
            VaultApi::new("https://127.0.0.1:1", &absent),
            Err(VaultError::Io { .. })
        ));
    }

    #[test]
    fn a_dead_vault_fails_every_call_as_a_transport_error() {
        crate::install_default_crypto_provider();
        let (_dir, ca) = ca();
        let api = VaultApi::new("https://127.0.0.1:1", &ca).unwrap();
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        let pw = Password::new(Zeroizing::new("pw".into())).unwrap();
        let wrapping = || WrappingToken::new(Zeroizing::new("hvs.w".into())).unwrap();
        let user = UserToken::new(Zeroizing::new("hvs.u".into())).unwrap();
        let expect = WrapExpectation::new(
            "maknae-kv",
            "maknae/users/alice/openai",
            "api_key",
            Duration::from_secs(60),
        )
        .unwrap();
        assert!(matches!(
            rt.block_on(api.login(&UserAuth::userpass_default(), "alice", &pw)),
            Err(VaultError::VaultTransport { .. })
        ));
        assert!(matches!(
            rt.block_on(api.read_wrapped(
                &user,
                "maknae-kv",
                "maknae/users/alice/openai",
                Duration::from_secs(60)
            )),
            Err(VaultError::VaultTransport { .. })
        ));
        assert!(matches!(
            rt.block_on(api.lookup_wrapping(&wrapping())),
            Err(VaultError::VaultTransport { .. })
        ));
        assert!(matches!(
            rt.block_on(api.unwrap_kv_field(wrapping(), &expect)),
            Err(VaultError::VaultTransport { .. })
        ));
    }

    #[test]
    fn a_malformed_path_is_refused_before_any_connection() {
        crate::install_default_crypto_provider();
        let (_dir, ca) = ca();
        let api = VaultApi::new("https://127.0.0.1:1", &ca).unwrap();
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        let user = UserToken::new(Zeroizing::new("hvs.u".into())).unwrap();
        assert!(matches!(
            rt.block_on(api.read_wrapped(&user, "maknae-kv", "../bob/x", Duration::from_secs(60))),
            Err(VaultError::InvalidKeyVaultPath(_))
        ));
    }
}
