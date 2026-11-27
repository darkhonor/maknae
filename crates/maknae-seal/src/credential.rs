use crate::{
    open, seal, CredentialSealContext, SealAad, SealError, SealPrivateKey, SealPublicKey,
    SealedBlob,
};
use maknae_io::{MaknaeSecret, SecretError};
use zeroize::Zeroizing;

pub fn seal_credential(
    to: &SealPublicKey,
    ctx: &CredentialSealContext<'_>,
    token: &str,
) -> Result<SealedBlob, SealError> {
    seal(to, &SealAad::credential(ctx)?, token.as_bytes())
}

pub fn open_credential(
    key: &SealPrivateKey,
    ctx: &CredentialSealContext<'_>,
    sealed: &[u8],
) -> Result<MaknaeSecret, SealError> {
    let mut bytes = open(key, &SealAad::credential(ctx)?, sealed)?;
    match String::from_utf8(std::mem::take(&mut *bytes)) {
        Ok(token) => MaknaeSecret::new(Zeroizing::new(token)).map_err(seal_secret_error),
        Err(e) => {
            drop(Zeroizing::new(e.into_bytes()));
            Err(SealError::Open)
        }
    }
}

fn seal_secret_error(e: SecretError) -> SealError {
    match e {
        SecretError::CoreDumps(io) => SealError::CoreDumps(io.raw_os_error()),
        SecretError::Empty | SecretError::TooLong => SealError::PlaintextLength,
        _ => SealError::Open,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{CredentialDirection, SealContext, MAX_PLAINTEXT_LEN};

    const TOKEN: &str = "ghs_credentialSentinel0123456789";

    fn cctx() -> CredentialSealContext<'static> {
        CredentialSealContext {
            direction: CredentialDirection::ToAgent,
            agent: "agent-1",
            task: "task-1",
            class: "git-write",
            kind: "github-app-installation",
            app: "app-1",
            set: 3,
        }
    }

    #[test]
    fn each_secret_error_maps_to_its_named_seal_error() {
        let denied = SecretError::CoreDumps(std::io::Error::from_raw_os_error(1));
        assert_eq!(seal_secret_error(denied), SealError::CoreDumps(Some(1)));
        for (e, want) in [
            (SecretError::Empty, SealError::PlaintextLength),
            (SecretError::TooLong, SealError::PlaintextLength),
            (SecretError::NotUtf8, SealError::Open),
            (SecretError::NotAVaultToken, SealError::Open),
        ] {
            assert_eq!(seal_secret_error(e), want);
        }
    }

    #[test]
    fn a_credential_blob_opens_only_under_its_own_context() {
        let key = SealPrivateKey::generate().unwrap();
        let blob = seal_credential(key.public_key(), &cctx(), TOKEN).unwrap();
        let opened = open_credential(&key, &cctx(), blob.as_bytes()).unwrap();
        assert_eq!(opened.expose(), TOKEN);

        let changed = [
            CredentialSealContext {
                agent: "agent-2",
                ..cctx()
            },
            CredentialSealContext {
                task: "task-2",
                ..cctx()
            },
            CredentialSealContext {
                class: "git-read",
                ..cctx()
            },
            CredentialSealContext {
                kind: "github-machine-user",
                ..cctx()
            },
            CredentialSealContext {
                app: "app-2",
                ..cctx()
            },
            CredentialSealContext { set: 4, ..cctx() },
            CredentialSealContext {
                direction: CredentialDirection::ToRevoke,
                ..cctx()
            },
        ];
        for (i, c) in changed.iter().enumerate() {
            assert_eq!(
                open_credential(&key, c, blob.as_bytes()).unwrap_err(),
                SealError::Open,
                "case {i}"
            );
        }

        let provider = SealAad::new(&SealContext {
            conversation: "agent-1",
            provider: "task-1",
            model: "git-write",
            expected_path: "github-app-installation",
            key_field: "app-1",
        })
        .unwrap();
        let pblob = seal(key.public_key(), &provider, TOKEN.as_bytes()).unwrap();
        assert_eq!(
            open_credential(&key, &cctx(), pblob.as_bytes()).unwrap_err(),
            SealError::Open
        );
        let cblob = seal_credential(key.public_key(), &cctx(), TOKEN).unwrap();
        assert!(open(&key, &provider, cblob.as_bytes()).is_err());
    }

    #[test]
    fn a_token_over_the_plaintext_cap_is_refused() {
        let key = SealPrivateKey::generate().unwrap();
        assert!(seal_credential(key.public_key(), &cctx(), &"x".repeat(MAX_PLAINTEXT_LEN)).is_ok());
        assert_eq!(
            seal_credential(
                key.public_key(),
                &cctx(),
                &"x".repeat(MAX_PLAINTEXT_LEN + 1)
            )
            .unwrap_err(),
            SealError::PlaintextLength
        );
    }

    #[test]
    fn a_non_utf8_plaintext_is_refused_on_open() {
        let key = SealPrivateKey::generate().unwrap();
        let aad = SealAad::credential(&cctx()).unwrap();
        let plaintext = [0xff; 64];
        let blob = seal(key.public_key(), &aad, &plaintext).unwrap();
        assert_eq!(
            open(&key, &aad, blob.as_bytes()).unwrap().as_slice(),
            plaintext,
            "the blob itself opens, so only the UTF-8 check can refuse it"
        );
        assert_eq!(
            open_credential(&key, &cctx(), blob.as_bytes()).unwrap_err(),
            SealError::Open
        );
    }

    #[test]
    fn an_empty_context_field_is_refused_before_sealing_or_opening() {
        let key = SealPrivateKey::generate().unwrap();
        let blob = seal_credential(key.public_key(), &cctx(), TOKEN).unwrap();
        let empty = CredentialSealContext { app: "", ..cctx() };
        assert_eq!(
            seal_credential(key.public_key(), &empty, TOKEN).unwrap_err(),
            SealError::AadField
        );
        assert_eq!(
            open_credential(&key, &empty, blob.as_bytes()).unwrap_err(),
            SealError::AadField
        );
    }
}
