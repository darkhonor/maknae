use crate::api_request::{
    approle_login_body, approle_login_request, delete_metadata_request, kv_write_body, login_body,
    login_request, lookup_body, lookup_request, revoke_self_request, transit_sign_body,
    transit_sign_request, unwrap_request, wrapped_read_request, wrapped_write_request, ApiBase,
};
use crate::api_shape::{admit_response, append_bounded, oversize, VaultOp, MAX_VAULT_BODY_BYTES};
use crate::transit::{parse_service_login, parse_sign_reply, ServiceLogin};
use crate::user_login::{parse_login, UserLogin};
use crate::wrap::{
    kv_data_path, kv_metadata_path, parse_lookup, parse_wrapped_read, parse_wrapped_write,
    unwrap_checked, CheckedLookup, UnwrapOps, WrapExpectation, WrapLookup, WrappedSecret,
};
use crate::{UserAuth, UserAuthMethod, VaultError};
use maknae_crypto::assert_fips_provider;
use maknae_io::MaknaeSecret;
use std::path::Path;
use std::time::Duration;
use zeroize::Zeroizing;

pub const VAULT_API_TIMEOUT: Duration = Duration::from_secs(30);

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

impl VaultApi {
    pub fn new(addr: &str, vault_ca: &Path) -> Result<Self, VaultError> {
        assert_fips_provider()?;
        let base = ApiBase::new(addr)?;
        let http = crate::http::hardened_http_client(vault_ca, VAULT_API_TIMEOUT)?;
        Ok(Self { base, http })
    }

    pub fn vault_addr(&self) -> &str {
        self.base.as_str()
    }

    pub async fn login(
        &self,
        auth: &UserAuth,
        username: &str,
        password: &MaknaeSecret,
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
        token: &MaknaeSecret,
        kv_mount: &str,
        secret_path: &str,
        wrap_ttl: Duration,
    ) -> Result<WrappedSecret, VaultError> {
        let path = kv_data_path(kv_mount, secret_path)?;
        let req = wrapped_read_request(&self.http, &self.base, token, &path, wrap_ttl)?;
        let body = self.execute(VaultOp::WrappedRead, req).await?;
        parse_wrapped_read(&body, &path, wrap_ttl)
    }

    pub async fn write_wrapped(
        &self,
        token: &MaknaeSecret,
        kv_mount: &str,
        secret_path: &str,
        field: &str,
        secret: &MaknaeSecret,
        wrap_ttl: Duration,
    ) -> Result<(), VaultError> {
        let path = kv_data_path(kv_mount, secret_path)?;
        let body = kv_write_body(field, secret)?;
        let req = wrapped_write_request(&self.http, &self.base, token, &path, wrap_ttl, body)?;
        let body = self.execute(VaultOp::WrappedWrite, req).await?;
        parse_wrapped_write(&body, &path, wrap_ttl)
    }

    pub async fn delete_metadata(
        &self,
        token: &MaknaeSecret,
        kv_mount: &str,
        secret_path: &str,
    ) -> Result<(), VaultError> {
        let path = kv_metadata_path(kv_mount, secret_path)?;
        let req = delete_metadata_request(&self.http, &self.base, token, &path)?;
        self.execute(VaultOp::DeleteMetadata, req).await.map(drop)
    }

    pub async fn lookup_wrapping(&self, token: &MaknaeSecret) -> Result<WrapLookup, VaultError> {
        let body = lookup_body(token)?;
        let req = lookup_request(&self.http, &self.base, body)?;
        let body = self.execute(VaultOp::WrapLookup, req).await?;
        parse_lookup(&body)
    }

    pub async fn unwrap_kv_field(
        &self,
        token: MaknaeSecret,
        expect: &WrapExpectation,
    ) -> Result<Zeroizing<String>, VaultError> {
        unwrap_checked(self, token, expect).await
    }

    pub async fn revoke_self(&self, token: &MaknaeSecret) -> Result<(), VaultError> {
        let req = revoke_self_request(&self.http, &self.base, token)?;
        self.execute(VaultOp::RevokeSelf, req).await.map(drop)
    }

    pub async fn approle_login(
        &self,
        mount: &str,
        role_id: &str,
        secret_id: &Zeroizing<String>,
    ) -> Result<ServiceLogin, VaultError> {
        let body = approle_login_body(role_id, secret_id)?;
        let req = approle_login_request(&self.http, &self.base, mount, body)?;
        let body = self.execute(VaultOp::AppRoleLogin, req).await?;
        parse_service_login(&body)
    }

    pub async fn transit_sign_rs256(
        &self,
        token: &MaknaeSecret,
        mount: &str,
        key: &str,
        input: &[u8],
    ) -> Result<Zeroizing<Vec<u8>>, VaultError> {
        let body = transit_sign_body(input)?;
        let req = transit_sign_request(&self.http, &self.base, token, mount, key, body)?;
        let body = self.execute(VaultOp::TransitSign, req).await?;
        parse_sign_reply(&body)
    }

    async fn execute(
        &self,
        op: VaultOp,
        req: reqwest::Request,
    ) -> Result<Zeroizing<Vec<u8>>, VaultError> {
        let mut resp = self.http.execute(req).await.map_err(|e| transport(op, e))?;
        admit_response(op, resp.status().as_u16(), resp.content_length())?;
        let mut body = Zeroizing::new(Vec::with_capacity(MAX_VAULT_BODY_BYTES));
        while let Some(chunk) = resp.chunk().await.map_err(|e| transport(op, e))? {
            append_bounded(&mut body, &chunk).map_err(|_| oversize(op))?;
        }
        Ok(body)
    }
}

impl UnwrapOps for VaultApi {
    async fn lookup(&self, token: &MaknaeSecret) -> Result<WrapLookup, VaultError> {
        self.lookup_wrapping(token).await
    }

    async fn unwrap_body(
        &self,
        token: MaknaeSecret,
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
    use crate::wrap::{kv_secret, FORGE_TOKEN_FIELD};
    use maknae_crypto::rcgen;

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
        maknae_crypto::init().unwrap();
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
        maknae_crypto::init().unwrap();
        let (_dir, ca) = ca();
        let api = VaultApi::new("https://127.0.0.1:1", &ca).unwrap();
        assert_eq!(api.vault_addr(), "https://127.0.0.1:1/v1/");
        assert_eq!(
            VaultApi::new("HTTPS://Vault.Example:443/", &ca)
                .unwrap()
                .vault_addr(),
            "https://vault.example/v1/"
        );
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        let pw = crate::password(Zeroizing::new("pw".into())).unwrap();
        let wrapping = || MaknaeSecret::vault_token(Zeroizing::new("hvs.w".into())).unwrap();
        let user = MaknaeSecret::vault_token(Zeroizing::new("hvs.u".into())).unwrap();
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
        assert!(matches!(
            rt.block_on(api.revoke_self(&user)),
            Err(VaultError::VaultTransport { .. })
        ));
        let secret = kv_secret(Zeroizing::new("github_pat_x".into())).unwrap();
        assert!(matches!(
            rt.block_on(api.write_wrapped(
                &user,
                "maknae-kv",
                "maknae/users/alice/forges/github.com",
                FORGE_TOKEN_FIELD,
                &secret,
                Duration::from_secs(60)
            )),
            Err(VaultError::VaultTransport {
                op: "wrapped KV write",
                ..
            })
        ));
        assert!(matches!(
            rt.block_on(api.delete_metadata(
                &user,
                "maknae-kv",
                "maknae/users/alice/forges/github.com"
            )),
            Err(VaultError::VaultTransport {
                op: "KV metadata delete",
                ..
            })
        ));
    }

    #[test]
    fn a_dead_vault_fails_the_service_calls_as_transport_errors() {
        maknae_crypto::init().unwrap();
        let (_dir, ca) = ca();
        let api = VaultApi::new("https://127.0.0.1:1", &ca).unwrap();
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        let secret = Zeroizing::new("0f1e2d3c".to_string());
        assert!(matches!(
            rt.block_on(api.approle_login("approle", "role", &secret)),
            Err(VaultError::VaultTransport {
                op: "AppRole login",
                ..
            })
        ));
        let service = MaknaeSecret::vault_token(Zeroizing::new("hvs.s".into())).unwrap();
        assert!(matches!(
            rt.block_on(api.transit_sign_rs256(&service, "transit", "github-app", b"a.b")),
            Err(VaultError::VaultTransport {
                op: "Transit sign",
                ..
            })
        ));
        assert!(matches!(
            rt.block_on(api.transit_sign_rs256(&service, "transit", "../k", b"a.b")),
            Err(VaultError::InvalidMount(_))
        ));
        assert!(matches!(
            rt.block_on(api.approle_login("approle", "role", &Zeroizing::new(String::new()))),
            Err(VaultError::InvalidSecret { .. })
        ));
    }

    #[test]
    fn a_malformed_path_is_refused_before_any_connection() {
        maknae_crypto::init().unwrap();
        let (_dir, ca) = ca();
        let api = VaultApi::new("https://127.0.0.1:1", &ca).unwrap();
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        let user = MaknaeSecret::vault_token(Zeroizing::new("hvs.u".into())).unwrap();
        assert!(matches!(
            rt.block_on(api.read_wrapped(&user, "maknae-kv", "../bob/x", Duration::from_secs(60))),
            Err(VaultError::InvalidKeyVaultPath(_))
        ));
        let secret = kv_secret(Zeroizing::new("github_pat_x".into())).unwrap();
        assert!(matches!(
            rt.block_on(api.write_wrapped(
                &user,
                "maknae-kv",
                "../bob/x",
                FORGE_TOKEN_FIELD,
                &secret,
                Duration::from_secs(60)
            )),
            Err(VaultError::InvalidKeyVaultPath(_))
        ));
        assert!(matches!(
            rt.block_on(api.delete_metadata(&user, "maknae-kv", "../bob/x")),
            Err(VaultError::InvalidKeyVaultPath(_))
        ));
    }
}
