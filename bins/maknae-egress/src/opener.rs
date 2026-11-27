//! The production `KeyOpener`: open the seal, check the wrapping token, unwrap the key field (#153).
use maknae_deputy::unseal::{
    open_forge_seal, ForgeOpenRequest, ForgeOpener, KeyOpener, OpenFailure, OpenRequest,
};
use maknae_io::{MaknaeSecret, SecretError};
use maknae_seal::{SealAad, SealContext, SealPrivateKey};
use maknae_vault::{
    aad_parts, VaultApi, VaultError, WrapExpectation, WrapMismatch, USER_KEY_WRAP_TTL,
};
use std::future::Future;
use std::sync::Arc;

pub struct SealedOpener {
    pub key: Arc<SealPrivateKey>,
    pub api: Arc<VaultApi>,
}

pub trait Unwrapper {
    fn unwrap_field(
        &self,
        token: MaknaeSecret,
        expect: &WrapExpectation,
    ) -> impl Future<Output = Result<MaknaeSecret, VaultError>> + Send;
}

impl Unwrapper for VaultApi {
    fn unwrap_field(
        &self,
        token: MaknaeSecret,
        expect: &WrapExpectation,
    ) -> impl Future<Output = Result<MaknaeSecret, VaultError>> + Send {
        self.unwrap_kv_field(token, expect)
    }
}

pub fn vault_diagnostic(e: &VaultError) -> Option<String> {
    match e {
        VaultError::WrapMismatch(
            WrapMismatch::CreationPath | WrapMismatch::CreationTtl { .. } | WrapMismatch::Invalid,
        )
        | VaultError::KvField { .. } => None,
        other => Some(format!("maknae-egress: the Vault unwrap failed: {other}")),
    }
}

pub fn vault_failure(e: VaultError) -> OpenFailure {
    if let Some(line) = vault_diagnostic(&e) {
        eprintln!("{line}");
    }
    match e {
        VaultError::WrapMismatch(WrapMismatch::CreationPath) => OpenFailure::WrongPath,
        VaultError::WrapMismatch(WrapMismatch::CreationTtl { .. }) => OpenFailure::Ttl,
        VaultError::WrapMismatch(WrapMismatch::Invalid) => OpenFailure::Invalid,
        VaultError::KvField { .. } => OpenFailure::Field,
        VaultError::CoreDumps(_) => OpenFailure::CoreDumps,
        _ => OpenFailure::Vault,
    }
}

pub fn token_failure(e: SecretError) -> OpenFailure {
    match e {
        SecretError::CoreDumps(io) => {
            eprintln!("maknae-egress: core dumps could not be denied: {io}");
            OpenFailure::CoreDumps
        }
        _ => OpenFailure::Token,
    }
}

pub fn unseal_token(
    key: &SealPrivateKey,
    sealed: &[u8],
    req: &OpenRequest<'_>,
) -> Result<(MaknaeSecret, WrapExpectation), OpenFailure> {
    let expectation = WrapExpectation::new(
        req.kv_mount,
        req.key_vault_path,
        req.key_field,
        USER_KEY_WRAP_TTL,
    )
    .map_err(|_| OpenFailure::Request)?;
    let parts = aad_parts(&expectation, req.conversation, req.provider, req.model);
    let aad = SealAad::new(&SealContext {
        conversation: parts.conversation,
        provider: parts.provider,
        model: parts.model,
        expected_path: parts.expected_path,
        key_field: parts.key_field,
    })
    .map_err(|_| OpenFailure::Seal)?;
    let opened = maknae_seal::open(key, &aad, sealed).map_err(|_| OpenFailure::Seal)?;
    let token = MaknaeSecret::from_opened(opened).map_err(token_failure)?;
    Ok((token, expectation))
}

pub fn open_with<'a, U: Unwrapper + Sync>(
    key: &SealPrivateKey,
    vault: &'a U,
    sealed: &[u8],
    req: &OpenRequest<'_>,
) -> impl Future<Output = Result<MaknaeSecret, OpenFailure>> + Send + 'a {
    let unsealed = unseal_token(key, sealed, req);
    async move {
        let (token, expectation) = unsealed?;
        vault
            .unwrap_field(token, &expectation)
            .await
            .map_err(vault_failure)
    }
}

/// The forge sibling of `unseal_token`: the seal's AAD is `ForgeOpenRequest`'s own.
pub fn unseal_forge_token(
    key: &SealPrivateKey,
    sealed: &[u8],
    req: &ForgeOpenRequest<'_>,
) -> Result<(MaknaeSecret, WrapExpectation), OpenFailure> {
    let expectation = WrapExpectation::new(
        req.kv_mount(),
        req.expected_path(),
        req.key_field(),
        USER_KEY_WRAP_TTL,
    )
    .map_err(|_| OpenFailure::Request)?;
    let opened = open_forge_seal(key, sealed, req)?;
    let token = MaknaeSecret::from_opened(opened).map_err(token_failure)?;
    Ok((token, expectation))
}

pub fn open_forge_with<'a, U: Unwrapper + Sync>(
    key: &SealPrivateKey,
    vault: &'a U,
    sealed: &[u8],
    req: &ForgeOpenRequest<'_>,
) -> impl Future<Output = Result<MaknaeSecret, OpenFailure>> + Send + 'a {
    let unsealed = unseal_forge_token(key, sealed, req);
    async move {
        let (token, expectation) = unsealed?;
        vault
            .unwrap_field(token, &expectation)
            .await
            .map_err(vault_failure)
    }
}

impl ForgeOpener for SealedOpener {
    fn open(
        &self,
        sealed: &[u8],
        req: &ForgeOpenRequest<'_>,
    ) -> impl Future<Output = Result<MaknaeSecret, OpenFailure>> + Send {
        open_forge_with(&self.key, &*self.api, sealed, req)
    }
}

impl KeyOpener for SealedOpener {
    fn open(
        &self,
        sealed: &[u8],
        req: &OpenRequest<'_>,
    ) -> impl Future<Output = Result<MaknaeSecret, OpenFailure>> + Send {
        open_with(&self.key, &*self.api, sealed, req)
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use maknae_deputy::reach::open::tasker_open_request;
    use std::sync::{Mutex, Once};
    use zeroize::Zeroizing;

    const ALICE: &str = "maknae/users/alice/openai/personal";
    const BOB: &str = "maknae/users/bob/openai/personal";
    const ALICE_CREATION_PATH: &str = "maknae-kv/data/maknae/users/alice/openai/personal";
    const BOB_CREATION_PATH: &str = "maknae-kv/data/maknae/users/bob/openai/personal";
    const TOKEN: &[u8] = b"hvs.CAESIJ-egress-opener-wrapping-token-sentinel";

    pub(crate) const TEST_CA_PEM: &str = "-----BEGIN CERTIFICATE-----
MIIBtTCCATygAwIBAgIUULDH6JmXYLo3iF5hxI4/L1j2+DYwCgYIKoZIzj0EAwIw
EjEQMA4GA1UEAwwHY2EudGVzdDAeFw0yNjA5MTQxMjE0NDhaFw0zNjA5MTExMjE0
NDhaMBIxEDAOBgNVBAMMB2NhLnRlc3QwdjAQBgcqhkjOPQIBBgUrgQQAIgNiAASZ
iOE81dyIcpd91xRH64m5BS55i8UtJCCmgFfbBtOSJ8AIl49LXXJ/n0oMJYMYTc4M
yYiZU829p8gs804BacFPR8iVw3Y1AXZMTP6aeY5OY+W0iNAfXb8kB2fYUBHaOhmj
UzBRMB0GA1UdDgQWBBRPCpNpo3yKdFLAJ9mDC4Q6Na1uwDAfBgNVHSMEGDAWgBRP
CpNpo3yKdFLAJ9mDC4Q6Na1uwDAPBgNVHRMBAf8EBTADAQH/MAoGCCqGSM49BAMC
A2cAMGQCMBIUOA0bc98jJmqncakndRWUnoFWQDYhkKiSKiDqvYS/uQFSz8CVlrDH
GsTOHSQ/TQIwTI0QPmUvWSWEtxmnn9qj+NCmu0XZXYB4fG/FqUk/ILFGmJu7DV5u
ampbv97Rcx9j
-----END CERTIFICATE-----
";

    fn fips() {
        static ONCE: Once = Once::new();
        ONCE.call_once(|| maknae_crypto::init().unwrap());
    }

    fn run<F: Future>(f: F) -> F::Output {
        tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap()
            .block_on(f)
    }

    fn alice() -> OpenRequest<'static> {
        OpenRequest {
            conversation: "conv1",
            provider: "openai",
            model: "gpt-5.6-luna",
            kv_mount: "maknae-kv",
            key_vault_path: ALICE,
            key_field: "api_key",
        }
    }

    fn sealed_like_the_cli(key: &SealPrivateKey, req: &OpenRequest<'_>, token: &[u8]) -> Vec<u8> {
        let expect = WrapExpectation::new(
            req.kv_mount,
            req.key_vault_path,
            req.key_field,
            USER_KEY_WRAP_TTL,
        )
        .unwrap();
        let parts = aad_parts(&expect, req.conversation, req.provider, req.model);
        let aad = SealAad::new(&SealContext {
            conversation: parts.conversation,
            provider: parts.provider,
            model: parts.model,
            expected_path: parts.expected_path,
            key_field: parts.key_field,
        })
        .unwrap();
        maknae_seal::seal(key.public_key(), &aad, token)
            .unwrap()
            .into_bytes()
    }

    struct MintedVault {
        creation_path: &'static str,
        calls: Mutex<Vec<String>>,
    }

    impl MintedVault {
        fn minted_on(creation_path: &'static str) -> Self {
            Self {
                creation_path,
                calls: Mutex::new(vec![]),
            }
        }
        fn calls(&self) -> Vec<String> {
            self.calls.lock().unwrap().clone()
        }
    }

    impl Unwrapper for MintedVault {
        async fn unwrap_field(
            &self,
            token: MaknaeSecret,
            expect: &WrapExpectation,
        ) -> Result<MaknaeSecret, VaultError> {
            assert!(token.expose().as_bytes() == TOKEN);
            self.calls.lock().unwrap().push(format!(
                "{}|{}|{}",
                expect.creation_path(),
                expect.field(),
                expect.max_ttl().as_secs()
            ));
            if expect.creation_path() != self.creation_path {
                return Err(VaultError::WrapMismatch(WrapMismatch::CreationPath));
            }
            Ok(MaknaeSecret::new(Zeroizing::new("sk-ALICE-SENTINEL".into())).unwrap())
        }
    }

    #[test]
    fn a_blob_sealed_for_one_request_opens_only_under_that_request() {
        fips();
        let key = SealPrivateKey::generate().unwrap();
        let blob = sealed_like_the_cli(&key, &alice(), TOKEN);
        let (token, expect) = unseal_token(&key, &blob, &alice()).unwrap();
        assert!(token.expose().as_bytes() == TOKEN);
        assert_eq!(expect.creation_path(), ALICE_CREATION_PATH);
        assert_eq!(expect.field(), "api_key");
        assert_eq!(expect.max_ttl(), USER_KEY_WRAP_TTL);
        for (what, req) in [
            (
                "path",
                OpenRequest {
                    key_vault_path: BOB,
                    ..alice()
                },
            ),
            (
                "provider",
                OpenRequest {
                    provider: "anthropic",
                    ..alice()
                },
            ),
            (
                "model",
                OpenRequest {
                    model: "gpt-5.6",
                    ..alice()
                },
            ),
            (
                "conversation",
                OpenRequest {
                    conversation: "conv2",
                    ..alice()
                },
            ),
            (
                "field",
                OpenRequest {
                    key_field: "token",
                    ..alice()
                },
            ),
            (
                "mount",
                OpenRequest {
                    kv_mount: "other-kv",
                    ..alice()
                },
            ),
        ] {
            assert!(
                matches!(unseal_token(&key, &blob, &req), Err(OpenFailure::Seal)),
                "a blob re-targeted to another {what} must not open"
            );
        }
        let other = SealPrivateKey::generate().unwrap();
        assert!(matches!(
            unseal_token(&other, &blob, &alice()),
            Err(OpenFailure::Seal)
        ));
    }

    #[test]
    fn a_request_that_cannot_name_a_key_path_is_refused_before_the_seal_is_opened() {
        fips();
        let key = SealPrivateKey::generate().unwrap();
        let blob = sealed_like_the_cli(&key, &alice(), TOKEN);
        for req in [
            OpenRequest {
                key_vault_path: "maknae/users/../bob/x",
                ..alice()
            },
            OpenRequest {
                key_field: "api key",
                ..alice()
            },
        ] {
            assert!(matches!(
                unseal_token(&key, &blob, &req),
                Err(OpenFailure::Request)
            ));
        }
    }

    #[test]
    fn a_sealed_value_that_is_not_a_wrapping_token_is_refused() {
        fips();
        let key = SealPrivateKey::generate().unwrap();
        let blob = sealed_like_the_cli(&key, &alice(), b"not a token");
        assert!(matches!(
            unseal_token(&key, &blob, &alice()),
            Err(OpenFailure::Token)
        ));
    }

    #[test]
    fn user_a_presenting_user_bs_wrapping_token_is_refused_at_the_path_check() {
        fips();
        let key = SealPrivateKey::generate().unwrap();
        let blob = sealed_like_the_cli(&key, &alice(), TOKEN);
        let bobs = MintedVault::minted_on(BOB_CREATION_PATH);
        assert_eq!(
            run(open_with(&key, &bobs, &blob, &alice())).map(|_| ()),
            Err(OpenFailure::WrongPath)
        );
        assert_eq!(bobs.calls(), [format!("{ALICE_CREATION_PATH}|api_key|60")]);
        let alices = MintedVault::minted_on(ALICE_CREATION_PATH);
        let got = run(open_with(&key, &alices, &blob, &alice())).unwrap();
        assert!(got.expose() == "sk-ALICE-SENTINEL");
    }

    #[test]
    fn each_vault_refusal_maps_to_its_own_open_failure() {
        let cases = [
            (
                VaultError::WrapMismatch(WrapMismatch::CreationPath),
                OpenFailure::WrongPath,
            ),
            (
                VaultError::WrapMismatch(WrapMismatch::CreationTtl {
                    ttl_secs: 61,
                    max_secs: 60,
                }),
                OpenFailure::Ttl,
            ),
            (
                VaultError::WrapMismatch(WrapMismatch::Invalid),
                OpenFailure::Invalid,
            ),
            (
                VaultError::KvField {
                    field: "api_key".into(),
                    why: "absent",
                },
                OpenFailure::Field,
            ),
            (
                VaultError::KvField {
                    field: "api_key".into(),
                    why: "empty",
                },
                OpenFailure::Field,
            ),
            (
                VaultError::CoreDumps(std::io::Error::other("rlimit")),
                OpenFailure::CoreDumps,
            ),
            (
                VaultError::WrapMismatch(WrapMismatch::NotWrapped),
                OpenFailure::Vault,
            ),
            (
                VaultError::VaultTransport {
                    op: "unwrap",
                    detail: "connection refused".into(),
                },
                OpenFailure::Vault,
            ),
        ];
        for (e, want) in cases {
            assert_eq!(vault_failure(e), want);
        }
    }

    #[test]
    fn a_collapsed_vault_failure_yields_one_diagnostic_line_naming_its_class() {
        assert_eq!(
            vault_diagnostic(&VaultError::VaultStatus {
                op: "unwrap",
                status: 403,
                hint: "permission denied",
            })
            .as_deref(),
            Some("maknae-egress: the Vault unwrap failed: Vault unwrap returned HTTP 403: permission denied")
        );
        assert_eq!(
            vault_diagnostic(&VaultError::VaultBody {
                op: "unwrap",
                why: "Syntax error at line 1 column 7".into(),
            })
            .as_deref(),
            Some("maknae-egress: the Vault unwrap failed: Vault unwrap response refused: Syntax error at line 1 column 7")
        );
        for mapped in [
            VaultError::WrapMismatch(WrapMismatch::CreationPath),
            VaultError::WrapMismatch(WrapMismatch::Invalid),
            VaultError::KvField {
                field: "api_key-FIELD-SENTINEL".into(),
                why: "absent",
            },
        ] {
            assert_eq!(vault_diagnostic(&mapped), None, "{mapped:?}");
        }
    }

    #[test]
    fn a_core_dump_failure_opening_the_token_is_not_reported_as_a_bad_token() {
        use maknae_io::SecretError;
        let denied = || std::io::Error::other("setrlimit refused");
        assert_eq!(
            token_failure(SecretError::CoreDumps(denied())),
            OpenFailure::CoreDumps
        );
        for shape in [
            SecretError::Empty,
            SecretError::TooLong,
            SecretError::NotAVaultToken,
            SecretError::NotUtf8,
        ] {
            assert_eq!(token_failure(shape), OpenFailure::Token);
        }
    }

    #[test]
    fn the_diagnostic_for_a_real_vault_failure_names_no_token_path_or_field() {
        fips();
        let d = tempfile::tempdir().unwrap();
        let ca = d.path().join(maknae_vault::EGRESS_VAULT_CA_FILE);
        std::fs::write(&ca, TEST_CA_PEM).unwrap();
        let api = VaultApi::new("https://127.0.0.1:1", &ca).unwrap();
        let token = || MaknaeSecret::from_opened(Zeroizing::new(TOKEN.to_vec())).unwrap();
        let expect = WrapExpectation::new(
            "maknae-kv",
            "maknae/users/alice/PATH-SENTINEL",
            "FIELD-SENTINEL",
            USER_KEY_WRAP_TTL,
        )
        .unwrap();
        let errors = [
            run(api.lookup_wrapping(&token())).unwrap_err(),
            run(api.unwrap_kv_field(token(), &expect)).unwrap_err(),
        ];
        for e in errors {
            let line = vault_diagnostic(&e).expect("a transport failure is collapsed");
            assert!(line.starts_with("maknae-egress: the Vault unwrap failed: "));
            for sentinel in [
                "egress-opener-wrapping-token-sentinel",
                "PATH-SENTINEL",
                "FIELD-SENTINEL",
            ] {
                assert!(!line.contains(sentinel), "{line}");
            }
        }
    }

    #[test]
    fn the_real_opener_reaches_vault_only_after_the_seal_opens() {
        fips();
        let d = tempfile::tempdir().unwrap();
        let ca = d.path().join(maknae_vault::EGRESS_VAULT_CA_FILE);
        std::fs::write(&ca, TEST_CA_PEM).unwrap();
        let key = SealPrivateKey::generate().unwrap();
        let blob = sealed_like_the_cli(&key, &alice(), TOKEN);
        let opener = SealedOpener {
            key: Arc::new(key),
            api: Arc::new(VaultApi::new("https://127.0.0.1:1", &ca).unwrap()),
        };
        assert_eq!(
            run(KeyOpener::open(&opener, &blob, &alice())).map(|_| ()),
            Err(OpenFailure::Vault)
        );
        let other_model = OpenRequest {
            model: "gpt-5.6",
            ..alice()
        };
        assert_eq!(
            run(KeyOpener::open(&opener, &blob, &other_model)).map(|_| ()),
            Err(OpenFailure::Seal)
        );
    }

    const ALICE_FORGE_CREATION_PATH: &str = "maknae-kv/data/maknae/users/alice/forges/github.com";

    fn forge_sealed(key: &SealPrivateKey, req: &ForgeOpenRequest<'_>, token: &[u8]) -> Vec<u8> {
        maknae_seal::seal(key.public_key(), &req.aad().unwrap(), token)
            .unwrap()
            .into_bytes()
    }

    #[test]
    fn a_forge_seal_opens_only_under_its_own_server_and_path() {
        fips();
        let key = SealPrivateKey::generate().unwrap();
        let bounds = crate::test_frames::bounds();
        let frame = crate::test_frames::tasker_reach("github.com");
        let req = tasker_open_request(&frame, &bounds).unwrap();
        let blob = forge_sealed(&key, &req, TOKEN);
        let (token, expect) = unseal_forge_token(&key, &blob, &req).unwrap();
        assert!(token.expose().as_bytes() == TOKEN);
        assert_eq!(expect.creation_path(), ALICE_FORGE_CREATION_PATH);
        assert_eq!(expect.field(), "token");
        assert_eq!(expect.max_ttl(), USER_KEY_WRAP_TTL);

        let other = crate::test_frames::tasker_reach("ghe.example");
        let other = tasker_open_request(&other, &bounds).unwrap();
        assert!(matches!(
            unseal_forge_token(&key, &blob, &other),
            Err(OpenFailure::Seal)
        ));
        let prompt_blob = sealed_like_the_cli(&key, &alice(), TOKEN);
        assert!(matches!(
            unseal_forge_token(&key, &prompt_blob, &req),
            Err(OpenFailure::Seal)
        ));
        assert!(matches!(
            unseal_forge_token(&SealPrivateKey::generate().unwrap(), &blob, &req),
            Err(OpenFailure::Seal)
        ));
        let not_a_token = forge_sealed(&key, &req, b"not a token");
        assert!(matches!(
            unseal_forge_token(&key, &not_a_token, &req),
            Err(OpenFailure::Token)
        ));
    }

    #[test]
    fn a_forge_token_unwraps_only_from_its_own_path() {
        fips();
        let key = SealPrivateKey::generate().unwrap();
        let bounds = crate::test_frames::bounds();
        let frame = crate::test_frames::tasker_reach("github.com");
        let req = tasker_open_request(&frame, &bounds).unwrap();
        let blob = forge_sealed(&key, &req, TOKEN);
        let bobs = MintedVault::minted_on(BOB_CREATION_PATH);
        assert_eq!(
            run(open_forge_with(&key, &bobs, &blob, &req)).map(|_| ()),
            Err(OpenFailure::WrongPath)
        );
        assert_eq!(
            bobs.calls(),
            [format!("{ALICE_FORGE_CREATION_PATH}|token|60")]
        );
        let alices = MintedVault::minted_on(ALICE_FORGE_CREATION_PATH);
        let got = run(open_forge_with(&key, &alices, &blob, &req)).unwrap();
        assert!(got.expose() == "sk-ALICE-SENTINEL");
    }

    #[test]
    fn the_real_forge_opener_reaches_vault_only_after_the_seal_opens() {
        fips();
        let d = tempfile::tempdir().unwrap();
        let ca = d.path().join(maknae_vault::EGRESS_VAULT_CA_FILE);
        std::fs::write(&ca, TEST_CA_PEM).unwrap();
        let key = SealPrivateKey::generate().unwrap();
        let bounds = crate::test_frames::bounds();
        let frame = crate::test_frames::tasker_reach("github.com");
        let req = tasker_open_request(&frame, &bounds).unwrap();
        let blob = forge_sealed(&key, &req, TOKEN);
        let opener = SealedOpener {
            key: Arc::new(key),
            api: Arc::new(VaultApi::new("https://127.0.0.1:1", &ca).unwrap()),
        };
        assert_eq!(
            run(ForgeOpener::open(&opener, &blob, &req)).map(|_| ()),
            Err(OpenFailure::Vault)
        );
        let other = crate::test_frames::tasker_reach("ghe.example");
        let other = tasker_open_request(&other, &bounds).unwrap();
        assert_eq!(
            run(ForgeOpener::open(&opener, &blob, &other)).map(|_| ()),
            Err(OpenFailure::Seal)
        );
    }
}
