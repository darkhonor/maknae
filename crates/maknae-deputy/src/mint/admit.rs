//! Admission of a mint or revoke request against the pinned bounds and
//! `minting.yaml`, before any Vault or GitHub I/O.

use maknae_config::{AgentId, CredentialKind, GithubAppConfig, MintingConfig};
use maknae_proto::{
    AccessLevel, GithubPermission, MintRefusal, MintRequest, PermissionSet, RevokeRequest,
    MINT_MAX_PERMISSIONS_PER_SET, MINT_MAX_REPOS_PER_SET, MINT_MAX_SETS,
};
use maknae_seal::MAX_AAD_FIELD_BYTES;

pub const REPO_NAME_MAX_BYTES: usize = 100;

/// A credential kind the trust plane can mint.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TrustPlaneKind {
    GithubApp,
}

pub fn trust_plane_kind(kind: CredentialKind) -> Option<TrustPlaneKind> {
    match kind {
        CredentialKind::GithubAppInstallation => Some(TrustPlaneKind::GithubApp),
        CredentialKind::GithubMachineUser
        | CredentialKind::GitlabProjectToken
        | CredentialKind::GitlabBotToken
        | CredentialKind::VaultChildToken
        | CredentialKind::VaultDynamicSecret => None,
    }
}

#[derive(Debug)]
pub struct AdmittedMint<'a> {
    pub req: &'a MintRequest,
    pub agent: AgentId,
    pub kind: TrustPlaneKind,
    pub app: &'a GithubAppConfig,
}

pub fn admit_mint<'a>(
    req: &'a MintRequest,
    minting: Option<&'a MintingConfig>,
) -> Result<AdmittedMint<'a>, MintRefusal> {
    let (agent, kind, app) = admit_target(minting, &req.agent, &req.kind, &req.app)?;
    if !(1..=MINT_MAX_SETS).contains(&req.sets.len()) || !req.sets.iter().all(set_is_admissible) {
        return Err(MintRefusal::Request);
    }
    if req.sets.iter().any(asks_metadata_write) {
        return Err(MintRefusal::Request);
    }
    fields_fit_aad(&[&req.task, &req.agent, &req.class, &req.kind, &req.app])?;
    Ok(AdmittedMint {
        req,
        agent,
        kind,
        app,
    })
}

pub fn admit_revoke<'a>(
    req: &'a RevokeRequest,
    minting: Option<&'a MintingConfig>,
) -> Result<(AgentId, TrustPlaneKind, &'a GithubAppConfig), MintRefusal> {
    let admitted = admit_target(minting, &req.agent, &req.kind, &req.app)?;
    fields_fit_aad(&[&req.task, &req.agent, &req.class, &req.kind, &req.app])?;
    Ok(admitted)
}

fn admit_target<'a>(
    minting: Option<&'a MintingConfig>,
    agent: &str,
    kind: &str,
    app: &str,
) -> Result<(AgentId, TrustPlaneKind, &'a GithubAppConfig), MintRefusal> {
    let minting = minting.ok_or(MintRefusal::Request)?;
    let agent = AgentId::parse(agent).map_err(|_| MintRefusal::Request)?;
    let kind = CredentialKind::parse(kind)
        .and_then(trust_plane_kind)
        .ok_or(MintRefusal::Request)?;
    let app = minting.github_apps.get(app).ok_or(MintRefusal::Request)?;
    Ok((agent, kind, app))
}

fn set_is_admissible(set: &PermissionSet) -> bool {
    (1..=MINT_MAX_REPOS_PER_SET).contains(&set.repositories.len())
        && (1..=MINT_MAX_PERMISSIONS_PER_SET).contains(&set.permissions.len())
        && set
            .repositories
            .iter()
            .all(|r| repository_name_is_admissible(r))
}

fn repository_name_is_admissible(name: &str) -> bool {
    (1..=REPO_NAME_MAX_BYTES).contains(&name.len())
        && name
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'-'))
        && name != "."
        && name != ".."
}

fn asks_metadata_write(set: &PermissionSet) -> bool {
    set.permissions.get(&GithubPermission::Metadata) == Some(&AccessLevel::Write)
}

fn fields_fit_aad(fields: &[&str]) -> Result<(), MintRefusal> {
    if fields
        .iter()
        .all(|f| (1..=MAX_AAD_FIELD_BYTES).contains(&f.len()))
    {
        Ok(())
    } else {
        Err(MintRefusal::Request)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use maknae_config::{ApiBase, MintVault};
    use maknae_proto::SealedCredentialBytes;
    use std::collections::BTreeMap;

    const KIND: &str = "github-app-installation";

    fn minting() -> MintingConfig {
        let app = GithubAppConfig {
            app_id: 5834363,
            installation_id: 77,
            api: ApiBase::parse("https://api.github.com").expect("api base"),
            transit_mount: "transit".into(),
            transit_key: "deploy-app".into(),
        };
        MintingConfig {
            vault: MintVault {
                approle_mount: "approle".into(),
            },
            github_apps: BTreeMap::from([("deploy".to_string(), app)]),
        }
    }

    fn set(repos: &[&str], perms: &[(GithubPermission, AccessLevel)]) -> PermissionSet {
        PermissionSet {
            repositories: repos.iter().map(|r| r.to_string()).collect(),
            permissions: perms.iter().copied().collect(),
        }
    }

    fn one_set() -> PermissionSet {
        set(
            &["maknae"],
            &[(GithubPermission::Contents, AccessLevel::Read)],
        )
    }

    fn mint() -> MintRequest {
        MintRequest {
            task: "task-1".into(),
            agent: "coder".into(),
            class: "github".into(),
            kind: KIND.into(),
            app: "deploy".into(),
            sets: vec![one_set()],
        }
    }

    fn revoke() -> RevokeRequest {
        RevokeRequest {
            task: "task-1".into(),
            agent: "coder".into(),
            class: "github".into(),
            kind: KIND.into(),
            app: "deploy".into(),
            set: 0,
            for_revocation: SealedCredentialBytes::new(vec![7; 200]).expect("sealed"),
        }
    }

    fn mint_with(edit: impl FnOnce(&mut MintRequest)) -> Result<(), MintRefusal> {
        let m = minting();
        let mut req = mint();
        edit(&mut req);
        admit_mint(&req, Some(&m)).map(|_| ())
    }

    fn revoke_with(edit: impl FnOnce(&mut RevokeRequest)) -> Result<(), MintRefusal> {
        let m = minting();
        let mut req = revoke();
        edit(&mut req);
        admit_revoke(&req, Some(&m)).map(|_| ())
    }

    #[test]
    fn every_credential_kind_is_decided() {
        let all = [
            CredentialKind::GithubAppInstallation,
            CredentialKind::GithubMachineUser,
            CredentialKind::GitlabProjectToken,
            CredentialKind::GitlabBotToken,
            CredentialKind::VaultChildToken,
            CredentialKind::VaultDynamicSecret,
        ];
        for kind in all {
            let expected = match kind {
                CredentialKind::GithubAppInstallation => Some(TrustPlaneKind::GithubApp),
                CredentialKind::GithubMachineUser
                | CredentialKind::GitlabProjectToken
                | CredentialKind::GitlabBotToken
                | CredentialKind::VaultChildToken
                | CredentialKind::VaultDynamicSecret => None,
            };
            assert_eq!(trust_plane_kind(kind), expected, "{kind:?}");
            let refused = expected.is_none();
            assert_eq!(
                mint_with(|r| r.kind = kind.as_str().into()).is_err(),
                refused,
                "{kind:?}"
            );
            assert_eq!(
                revoke_with(|r| r.kind = kind.as_str().into()).is_err(),
                refused,
                "{kind:?}"
            );
        }
    }

    #[test]
    fn an_unknown_kind_spelling_is_refused_request() {
        for kind in [
            "github_app_installation",
            "GithubAppInstallation",
            "",
            "github-app",
        ] {
            assert_eq!(
                mint_with(|r| r.kind = kind.into()),
                Err(MintRefusal::Request)
            );
            assert_eq!(
                revoke_with(|r| r.kind = kind.into()),
                Err(MintRefusal::Request)
            );
        }
    }

    #[test]
    fn absent_minting_refuses_every_mint_and_revoke() {
        assert!(admit_mint(&mint(), None).is_err_and(|e| e == MintRefusal::Request));
        assert!(admit_revoke(&revoke(), None).is_err_and(|e| e == MintRefusal::Request));
        let m = minting();
        let (mreq, rreq) = (mint(), revoke());
        let admitted = admit_mint(&mreq, Some(&m)).expect("admitted");
        assert_eq!(admitted.agent.as_str(), "coder");
        assert_eq!(admitted.kind, TrustPlaneKind::GithubApp);
        assert_eq!(admitted.app.app_id, 5834363);
        assert_eq!(admitted.req.task, "task-1");
        let (agent, kind, app) = admit_revoke(&rreq, Some(&m)).expect("admitted");
        assert_eq!(agent.as_str(), "coder");
        assert_eq!(kind, TrustPlaneKind::GithubApp);
        assert_eq!(app.app_id, 5834363);
    }

    #[test]
    fn an_agent_id_outside_the_grammar_is_refused() {
        for agent in ["../x", "a/b", "", "data", "Coder"] {
            assert_eq!(
                mint_with(|r| r.agent = agent.into()),
                Err(MintRefusal::Request)
            );
            assert_eq!(
                revoke_with(|r| r.agent = agent.into()),
                Err(MintRefusal::Request)
            );
        }
    }

    #[test]
    fn an_unconfigured_app_is_refused_request() {
        for app in ["other", "", "Deploy"] {
            assert_eq!(mint_with(|r| r.app = app.into()), Err(MintRefusal::Request));
            assert_eq!(
                revoke_with(|r| r.app = app.into()),
                Err(MintRefusal::Request)
            );
        }
    }

    #[test]
    fn each_bound_is_refused_one_above_and_admitted_at_its_limit() {
        assert_eq!(mint_with(|r| r.sets.clear()), Err(MintRefusal::Request));
        assert_eq!(
            mint_with(|r| r.sets = (0..MINT_MAX_SETS).map(|_| one_set()).collect()),
            Ok(())
        );
        assert_eq!(
            mint_with(|r| r.sets = (0..=MINT_MAX_SETS).map(|_| one_set()).collect()),
            Err(MintRefusal::Request)
        );

        let read = [(GithubPermission::Contents, AccessLevel::Read)];
        let names = |n: usize| (0..n).map(|i| format!("r{i}")).collect::<Vec<_>>();
        let at = names(MINT_MAX_REPOS_PER_SET);
        let over = names(MINT_MAX_REPOS_PER_SET + 1);
        fn refs(v: &[String]) -> Vec<&str> {
            v.iter().map(String::as_str).collect()
        }
        assert_eq!(mint_with(|r| r.sets = vec![set(&refs(&at), &read)]), Ok(()));
        assert_eq!(
            mint_with(|r| r.sets = vec![set(&refs(&over), &read)]),
            Err(MintRefusal::Request)
        );
        assert_eq!(
            mint_with(|r| r.sets = vec![set(&[], &read)]),
            Err(MintRefusal::Request)
        );
        assert_eq!(
            mint_with(|r| r.sets = vec![one_set(), set(&[], &read)]),
            Err(MintRefusal::Request)
        );

        let all_perms = [
            (GithubPermission::Contents, AccessLevel::Write),
            (GithubPermission::PullRequests, AccessLevel::Write),
            (GithubPermission::Issues, AccessLevel::Read),
            (GithubPermission::Checks, AccessLevel::Read),
            (GithubPermission::Statuses, AccessLevel::Write),
            (GithubPermission::Metadata, AccessLevel::Read),
        ];
        assert_eq!(all_perms.len(), MINT_MAX_PERMISSIONS_PER_SET);
        assert_eq!(
            mint_with(|r| r.sets = vec![set(&["a"], &all_perms)]),
            Ok(())
        );
        assert_eq!(
            mint_with(|r| r.sets = vec![set(&["a"], &[])]),
            Err(MintRefusal::Request)
        );
        assert_eq!(
            mint_with(|r| r.sets = vec![one_set(), set(&["a"], &[])]),
            Err(MintRefusal::Request)
        );

        let long = "a".repeat(REPO_NAME_MAX_BYTES);
        let too_long = "a".repeat(REPO_NAME_MAX_BYTES + 1);
        for ok in [long.as_str(), "a", "A-z_0.9", "...", ".a", "a.."] {
            assert_eq!(
                mint_with(|r| r.sets = vec![set(&[ok], &read)]),
                Ok(()),
                "{ok}"
            );
        }
        for bad in [
            too_long.as_str(),
            "",
            ".",
            "..",
            "a/b",
            "a b",
            "ä",
            "a\0",
            "o/../x",
        ] {
            assert_eq!(
                mint_with(|r| r.sets = vec![set(&["ok", bad], &read)]),
                Err(MintRefusal::Request),
                "{bad:?}"
            );
        }
    }

    #[test]
    fn metadata_write_is_refused() {
        let write = [(GithubPermission::Metadata, AccessLevel::Write)];
        let read = [(GithubPermission::Metadata, AccessLevel::Read)];
        assert_eq!(
            mint_with(|r| r.sets = vec![set(&["a"], &write)]),
            Err(MintRefusal::Request)
        );
        assert_eq!(
            mint_with(|r| r.sets = vec![one_set(), set(&["a"], &write)]),
            Err(MintRefusal::Request)
        );
        assert_eq!(mint_with(|r| r.sets = vec![set(&["a"], &read)]), Ok(()));
        for perm in [
            GithubPermission::Contents,
            GithubPermission::PullRequests,
            GithubPermission::Issues,
            GithubPermission::Checks,
            GithubPermission::Statuses,
        ] {
            assert_eq!(
                mint_with(|r| r.sets = vec![set(&["a"], &[(perm, AccessLevel::Write)])]),
                Ok(()),
                "{perm:?}"
            );
        }
    }

    #[test]
    fn every_string_field_is_held_to_the_aad_field_limit() {
        let at = "t".repeat(MAX_AAD_FIELD_BYTES);
        let over = "t".repeat(MAX_AAD_FIELD_BYTES + 1);
        assert_eq!(mint_with(|r| r.task = at.clone()), Ok(()));
        assert_eq!(mint_with(|r| r.class = at.clone()), Ok(()));
        assert_eq!(revoke_with(|r| r.task = at.clone()), Ok(()));
        assert_eq!(revoke_with(|r| r.class = at.clone()), Ok(()));
        for (field, value) in [
            ("task", &over),
            ("class", &over),
            ("task", &String::new()),
            ("class", &String::new()),
        ] {
            let edit_m = |r: &mut MintRequest| match field {
                "task" => r.task = value.clone(),
                _ => r.class = value.clone(),
            };
            let edit_r = |r: &mut RevokeRequest| match field {
                "task" => r.task = value.clone(),
                _ => r.class = value.clone(),
            };
            assert_eq!(
                mint_with(edit_m),
                Err(MintRefusal::Request),
                "{field} {}",
                value.len()
            );
            assert_eq!(
                revoke_with(edit_r),
                Err(MintRefusal::Request),
                "{field} {}",
                value.len()
            );
        }
    }
}
