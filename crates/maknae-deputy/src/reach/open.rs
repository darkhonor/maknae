//! The tasker side's sealed token: the Vault path it may come from, and the
//! refusal class of each way opening it fails.

use crate::unseal::{ForgeOpenRequest, OpenFailure};
use maknae_config::{user_key_path, EgressBounds};
use maknae_proto::{ReachRefusal, ReachRequest, ReachSide};
use maknae_vault::{forge_token_subpath, FORGE_TOKEN_FIELD};

pub const TASKER_TOKEN_MAX_BYTES: usize = 1024;

/// The frame's `expected_path` must be the tasker's own forge-token path for the frame's server.
pub fn tasker_open_request<'a>(
    req: &'a ReachRequest,
    bounds: &'a EgressBounds,
) -> Result<ForgeOpenRequest<'a>, ReachRefusal> {
    let ReachSide::Tasker {
        tasker,
        expected_path,
        key_field,
        nonce,
        sealed: _,
    } = req.side()
    else {
        return Err(ReachRefusal::Request);
    };
    let own = forge_token_subpath(req.server())
        .and_then(|sub| user_key_path(&bounds.user_prefix, tasker, sub.as_str()).ok())
        .ok_or(ReachRefusal::Request)?;
    if key_field != FORGE_TOKEN_FIELD || *expected_path != own {
        return Err(ReachRefusal::Request);
    }
    Ok(ForgeOpenRequest::checked(
        req.server(),
        nonce,
        &bounds.kv_mount,
        expected_path,
    ))
}

pub fn open_refusal(f: OpenFailure) -> ReachRefusal {
    match f {
        OpenFailure::Request => ReachRefusal::Request,
        OpenFailure::Seal | OpenFailure::Token | OpenFailure::WrongPath | OpenFailure::Ttl => {
            ReachRefusal::Seal
        }
        OpenFailure::Invalid | OpenFailure::Field | OpenFailure::Vault => ReachRefusal::Login,
    }
}

/// The alphabet a stored forge token is written in; anything else is never sent as a bearer.
pub fn tasker_token_is_usable(token: &str) -> bool {
    (1..=TASKER_TOKEN_MAX_BYTES).contains(&token.len())
        && token
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'-'))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::unseal::open_forge_seal;
    use maknae_proto::{RepoAsk, SealedKey};
    use maknae_seal::{ForgePurpose, ForgeSealContext, SealAad, SealPrivateKey};

    const NONCE: &str = "0123456789abcdef0123456789abcdef";
    const ALICE: &str = "maknae/users/alice/forges/github.com";
    const WRAPPING: &[u8] = b"hvs.CAESIJ-forge-wrapping-token-sentinel";

    fn fips() {
        static ONCE: std::sync::Once = std::sync::Once::new();
        ONCE.call_once(|| maknae_crypto::init().unwrap());
    }

    pub(crate) fn bounds() -> EgressBounds {
        EgressBounds {
            call_timeout_ms: maknae_config::DEFAULT_CALL_TIMEOUT_MS,
            kv_mount: "maknae-kv".into(),
            user_prefix: "maknae/users".into(),
            agent_prefix: None,
            vault_addr: "https://vault.example:8200".into(),
        }
    }

    fn sealed_like_the_client(key: &SealPrivateKey, server: &str, path: &str) -> Vec<u8> {
        let aad = SealAad::forge(&ForgeSealContext {
            purpose: ForgePurpose::TaskerReach,
            nonce: NONCE,
            server,
            expected_path: path,
            key_field: "token",
        })
        .unwrap();
        maknae_seal::seal(key.public_key(), &aad, WRAPPING)
            .unwrap()
            .into_bytes()
    }

    fn frame(server: &str, tasker: &str, path: &str, field: &str, sealed: Vec<u8>) -> ReachRequest {
        ReachRequest::new(
            server.into(),
            "github".into(),
            20_000,
            ReachSide::Tasker {
                tasker: tasker.into(),
                expected_path: path.into(),
                key_field: field.into(),
                nonce: NONCE.into(),
                sealed: SealedKey::new(sealed).unwrap(),
            },
            vec![RepoAsk {
                base: "o/r".into(),
                change: None,
                head: None,
            }],
        )
        .unwrap()
    }

    fn sealed(req: &ReachRequest) -> &[u8] {
        match req.side() {
            ReachSide::Tasker { sealed, .. } => sealed.as_bytes(),
            ReachSide::Agent { .. } => unreachable!(),
        }
    }

    #[test]
    fn the_tasker_token_opens_only_under_its_own_path_and_server() {
        fips();
        let key = SealPrivateKey::generate().unwrap();
        let b = bounds();
        let blob = sealed_like_the_client(&key, "github.com", ALICE);
        let own = frame("github.com", "alice", ALICE, "token", blob.clone());
        let open = tasker_open_request(&own, &b).unwrap();
        assert_eq!(
            (
                open.server(),
                open.kv_mount(),
                open.expected_path(),
                open.key_field()
            ),
            ("github.com", "maknae-kv", ALICE, "token")
        );
        assert!(
            open_forge_seal(&key, sealed(&own), &open)
                .unwrap()
                .as_slice()
                == WRAPPING
        );

        for (server, tasker, path, field) in [
            ("github.com", "bob", ALICE, "token"),
            (
                "github.com",
                "alice",
                "maknae/users/bob/forges/github.com",
                "token",
            ),
            (
                "github.com",
                "alice",
                "maknae/users/alice/forges/ghe.example",
                "token",
            ),
            (
                "github.com",
                "alice",
                "maknae/users/alice/openai/personal",
                "token",
            ),
            (
                "github.com",
                "alice",
                "maknae/users/alice/forges/github.com/x",
                "token",
            ),
            ("github.com", "alice", ALICE, "api_key"),
            ("github.com:443", "alice", ALICE, "token"),
            (
                "github.com",
                "data",
                "maknae/users/data/forges/github.com",
                "token",
            ),
            (
                "github.com",
                "a/b",
                "maknae/users/a/b/forges/github.com",
                "token",
            ),
        ] {
            let f = frame(server, tasker, path, field, blob.clone());
            assert_eq!(
                tasker_open_request(&f, &b).map(|_| ()),
                Err(ReachRefusal::Request),
                "{server} {tasker} {path} {field}"
            );
        }

        let ghe = "maknae/users/alice/forges/ghe.example";
        let elsewhere = frame("ghe.example", "alice", ghe, "token", blob.clone());
        let open = tasker_open_request(&elsewhere, &b).unwrap();
        assert_eq!(
            open_forge_seal(&key, sealed(&elsewhere), &open).map(|_| ()),
            Err(OpenFailure::Seal),
            "a token sealed for one server must not open for another"
        );
        let other = SealPrivateKey::generate().unwrap();
        let open = tasker_open_request(&own, &b).unwrap();
        assert_eq!(
            open_forge_seal(&other, sealed(&own), &open).map(|_| ()),
            Err(OpenFailure::Seal)
        );
    }

    #[test]
    fn an_agent_frame_has_no_tasker_token_to_open() {
        let f = ReachRequest::new(
            "github.com".into(),
            "github".into(),
            20_000,
            ReachSide::Agent {
                agent: "coder".into(),
                credentials: vec![maknae_proto::CredentialRef {
                    kind: "github-app-installation".into(),
                    name: "deploy".into(),
                }],
            },
            vec![RepoAsk {
                base: "o/r".into(),
                change: None,
                head: None,
            }],
        )
        .unwrap();
        assert_eq!(
            tasker_open_request(&f, &bounds()).map(|_| ()),
            Err(ReachRefusal::Request)
        );
    }

    #[test]
    fn each_open_failure_reaches_its_class() {
        use OpenFailure::*;
        assert_eq!(
            [Request, Seal, Token, WrongPath, Ttl, Invalid, Field, Vault].map(open_refusal),
            [
                ReachRefusal::Request,
                ReachRefusal::Seal,
                ReachRefusal::Seal,
                ReachRefusal::Seal,
                ReachRefusal::Seal,
                ReachRefusal::Login,
                ReachRefusal::Login,
                ReachRefusal::Login,
            ]
        );
    }

    #[test]
    fn only_a_token_in_the_stored_alphabet_is_usable() {
        for ok in [
            "ghp_abc123",
            "github_pat_11AA_bb",
            "glpat-x.y",
            &"a".repeat(1024),
        ] {
            assert!(tasker_token_is_usable(ok), "{ok}");
        }
        for bad in ["", "a b", "a\r\nX-Evil: 1", "tok\u{e9}n", &"a".repeat(1025)] {
            assert!(!tasker_token_is_usable(bad), "{bad:?}");
        }
    }

    #[test]
    fn a_forge_open_request_debug_omits_the_nonce_and_path() {
        let b = bounds();
        let f = frame("github.com", "alice", ALICE, "token", vec![7; 200]);
        assert_eq!(
            format!("{:?}", tasker_open_request(&f, &b).unwrap()),
            r#"ForgeOpenRequest { server: "github.com", kv_mount: "maknae-kv", nonce: "<omitted>", expected_path: "<omitted>" }"#
        );
    }
}
