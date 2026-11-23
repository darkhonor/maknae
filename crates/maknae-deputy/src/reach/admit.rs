//! Admission of a reach frame before any I/O: its bounds, the server's API in
//! `minting.yaml`'s `apis:`, a forge that observes reach, and the side's credential.

use super::open::tasker_open_request;
use crate::mint::admit::{trust_plane_kind, TrustPlaneKind};
use crate::unseal::ForgeOpenRequest;
use maknae_config::{
    AgentId, ApiBase, CredentialKind, EgressBounds, GithubAppConfig, MintingConfig, MintingFile,
    REACH_DEADLINE_MS_MAX,
};
use maknae_forge::{forge, AgentSide, CredentialForge, ForgeProvider, ForgeReach};
use maknae_proto::{CredentialRef, ReachRefusal, ReachRequest, ReachSide, SealedKey};

pub struct ReachConfig<'a> {
    /// `minting.yaml`; absent, no server has an API and every frame is refused.
    pub file: Option<&'a MintingFile>,
    /// Down, the agent side has no forge credential to observe with.
    pub minter_ready: bool,
    pub bounds: &'a EgressBounds,
}

pub struct AdmittedReach<'a> {
    req: &'a ReachRequest,
    api: &'a ApiBase,
    reach: &'static dyn ForgeReach,
    side: AdmittedSide<'a>,
}

pub enum AdmittedSide<'a> {
    Tasker {
        open: ForgeOpenRequest<'a>,
        sealed: &'a SealedKey,
    },
    App(&'a GithubAppConfig),
    NoForgeCredential,
}

impl<'a> AdmittedReach<'a> {
    pub fn req(&self) -> &'a ReachRequest {
        self.req
    }

    pub fn api(&self) -> &'a ApiBase {
        self.api
    }

    pub fn reach(&self) -> &'static dyn ForgeReach {
        self.reach
    }

    pub fn side(&self) -> &AdmittedSide<'a> {
        &self.side
    }

    #[cfg(test)]
    pub(super) fn observed_by(self, reach: &'static dyn ForgeReach) -> Self {
        Self { reach, ..self }
    }
}

impl std::fmt::Debug for AdmittedReach<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let side = match &self.side {
            AdmittedSide::Tasker { .. } => "tasker",
            AdmittedSide::App(_) => "app",
            AdmittedSide::NoForgeCredential => "no_forge_credential",
        };
        f.debug_struct("AdmittedReach")
            .field("server", &self.req.server())
            .field("provider", &self.req.provider())
            .field("side", &side)
            .finish_non_exhaustive()
    }
}

pub fn admit_reach<'a>(
    req: &'a ReachRequest,
    cfg: &ReachConfig<'a>,
) -> Result<AdmittedReach<'a>, ReachRefusal> {
    let file = cfg.file.ok_or(ReachRefusal::Request)?;
    if req.deadline_ms() > REACH_DEADLINE_MS_MAX {
        return Err(ReachRefusal::Request);
    }
    let provider = ForgeProvider::parse(req.provider()).ok_or(ReachRefusal::Request)?;
    let api = file
        .api(req.server())
        .filter(|a| a.provider == provider)
        .ok_or(ReachRefusal::Request)?;
    let reach = forge(provider).reach().ok_or(ReachRefusal::Request)?;
    let side = match req.side() {
        ReachSide::Tasker { sealed, .. } => AdmittedSide::Tasker {
            open: tasker_open_request(req, cfg.bounds)?,
            sealed,
        },
        ReachSide::Agent { agent, credentials } => {
            AgentId::parse(agent).map_err(|_| ReachRefusal::Request)?;
            let apps = file.minting().filter(|_| cfg.minter_ready);
            app_side(provider, req.server(), credentials, apps)?
        }
    };
    Ok(AdmittedReach {
        req,
        api: &api.api,
        reach,
        side,
    })
}

/// The one credential whose kind this forge observes and whose App serves `server`.
fn app_side<'a>(
    provider: ForgeProvider,
    server: &str,
    credentials: &[CredentialRef],
    apps: Option<&'a MintingConfig>,
) -> Result<AdmittedSide<'a>, ReachRefusal> {
    let mut found = Vec::with_capacity(credentials.len());
    for c in credentials {
        let kind = CredentialKind::parse(&c.kind).ok_or(ReachRefusal::Request)?;
        let side = kind.forge().map(|k| forge(provider).agent_side(k));
        if !matches!(
            (side, trust_plane_kind(kind)),
            (Some(AgentSide::Observe), Some(TrustPlaneKind::GithubApp))
        ) {
            continue;
        }
        if let Some(app) = apps
            .and_then(|m| m.github_apps.get(&c.name))
            .filter(|app| app.host == server)
        {
            found.push(app);
        }
    }
    match found.as_slice() {
        [] => Ok(AdmittedSide::NoForgeCredential),
        [app] => Ok(AdmittedSide::App(app)),
        _ => Err(ReachRefusal::AmbiguousCredential),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::reach::testutil::{app_frame, ask, bounds, file, tasker_frame, MINTING};

    const APP: &str = "github-app-installation";

    fn admitted<'a>(
        req: &'a ReachRequest,
        f: Option<&'a MintingFile>,
        minter_ready: bool,
        b: &'a EgressBounds,
    ) -> Result<String, ReachRefusal> {
        let cfg = ReachConfig {
            file: f,
            minter_ready,
            bounds: b,
        };
        admit_reach(req, &cfg).map(|a| {
            let side = match a.side() {
                AdmittedSide::Tasker { open, .. } => format!("tasker {}", open.server()),
                AdmittedSide::App(app) => format!("app {}", app.installation_id),
                AdmittedSide::NoForgeCredential => "none".into(),
            };
            format!("{} {side}", a.api().as_str())
        })
    }

    #[test]
    fn a_reach_frame_for_an_unmapped_server_or_wrong_provider_is_refused_before_io() {
        let f = file(MINTING);
        let b = bounds();
        assert_eq!(
            admitted(
                &tasker_frame("github.com", "github", 20_000),
                Some(&f),
                true,
                &b
            ),
            Ok("https://api.github.com tasker github.com".into())
        );
        for req in [
            tasker_frame("unmapped.example", "github", 20_000),
            tasker_frame("github.com", "gitlab", 20_000),
            tasker_frame("github.com", "bitbucket", 20_000),
            tasker_frame("github.com", "GitHub", 20_000),
            tasker_frame("github.com:443", "github", 20_000),
            tasker_frame("github.com", "github", REACH_DEADLINE_MS_MAX + 1),
            app_frame("unmapped.example", "github", &[(APP, "deploy")]),
            app_frame("github.com", "gitlab", &[(APP, "deploy")]),
        ] {
            assert_eq!(
                admitted(&req, Some(&f), true, &b),
                Err(ReachRefusal::Request),
                "{req:?}"
            );
        }
        assert_eq!(
            admitted(
                &tasker_frame("github.com", "github", REACH_DEADLINE_MS_MAX),
                Some(&f),
                true,
                &b
            )
            .map(|_| ()),
            Ok(())
        );
    }

    #[test]
    fn without_minting_yaml_every_reach_frame_is_refused() {
        let b = bounds();
        for req in [
            tasker_frame("github.com", "github", 20_000),
            app_frame("github.com", "github", &[(APP, "deploy")]),
        ] {
            assert_eq!(admitted(&req, None, true, &b), Err(ReachRefusal::Request));
        }
    }

    #[test]
    fn the_tasker_side_needs_only_the_apis_map() {
        let f =
            file("apis:\n  github.com:\n    provider: github\n    api: https://api.github.com\n");
        let b = bounds();
        assert_eq!(
            admitted(
                &tasker_frame("github.com", "github", 20_000),
                Some(&f),
                false,
                &b
            ),
            Ok("https://api.github.com tasker github.com".into())
        );
        assert_eq!(
            admitted(
                &app_frame("github.com", "github", &[(APP, "deploy")]),
                Some(&f),
                false,
                &b
            ),
            Ok("https://api.github.com none".into())
        );
    }

    #[test]
    fn a_gitlab_reach_frame_is_refused_before_io() {
        let f = file(MINTING);
        let b = bounds();
        for req in [
            tasker_frame("gitlab.example", "gitlab", 20_000),
            app_frame("gitlab.example", "gitlab", &[("gitlab-project-token", "p")]),
        ] {
            assert_eq!(
                admitted(&req, Some(&f), true, &b),
                Err(ReachRefusal::Request)
            );
        }
    }

    #[test]
    fn two_apps_on_one_host_for_one_agent_refuse() {
        let f = file(MINTING);
        let b = bounds();
        let two = app_frame("github.com", "github", &[(APP, "deploy"), (APP, "review")]);
        assert_eq!(
            admitted(&two, Some(&f), true, &b),
            Err(ReachRefusal::AmbiguousCredential)
        );
        let one_here = app_frame(
            "github.com",
            "github",
            &[(APP, "deploy"), (APP, "enterprise")],
        );
        assert_eq!(
            admitted(&one_here, Some(&f), true, &b),
            Ok("https://api.github.com app 77".into())
        );
        let with_others = app_frame(
            "github.com",
            "github",
            &[
                ("github-machine-user", "bot"),
                ("vault-child-token", "v"),
                (APP, "review"),
            ],
        );
        assert_eq!(
            admitted(&with_others, Some(&f), true, &b),
            Ok("https://api.github.com app 78".into())
        );
    }

    #[test]
    fn no_app_on_the_host_is_no_forge_credential() {
        let f = file(MINTING);
        let b = bounds();
        for (req, ready) in [
            (
                app_frame("github.com", "github", &[(APP, "enterprise")]),
                true,
            ),
            (
                app_frame("github.com", "github", &[(APP, "unconfigured")]),
                true,
            ),
            (
                app_frame("github.com", "github", &[("github-machine-user", "bot")]),
                true,
            ),
            (app_frame("github.com", "github", &[(APP, "deploy")]), false),
            (app_frame("ghe.example", "github", &[(APP, "deploy")]), true),
        ] {
            assert_eq!(
                admitted(&req, Some(&f), ready, &b),
                Ok(format!(
                    "{} none",
                    f.api(req.server()).unwrap().api.as_str()
                )),
                "{req:?} {ready}"
            );
        }
    }

    #[test]
    fn a_malformed_agent_or_credential_kind_is_refused() {
        let f = file(MINTING);
        let b = bounds();
        for req in [
            app_frame("github.com", "github", &[("github-app", "deploy")]),
            ReachRequest::new(
                "github.com".into(),
                "github".into(),
                20_000,
                ReachSide::Agent {
                    agent: "Not An Agent".into(),
                    credentials: vec![CredentialRef {
                        kind: APP.into(),
                        name: "deploy".into(),
                    }],
                },
                vec![ask("o/r")],
            )
            .unwrap(),
        ] {
            assert_eq!(
                admitted(&req, Some(&f), true, &b),
                Err(ReachRefusal::Request)
            );
        }
    }

    #[test]
    fn an_admitted_reach_debug_names_no_path_or_token() {
        let f = file(MINTING);
        let b = bounds();
        let req = tasker_frame("github.com", "github", 20_000);
        let cfg = ReachConfig {
            file: Some(&f),
            minter_ready: true,
            bounds: &b,
        };
        assert_eq!(
            format!("{:?}", admit_reach(&req, &cfg).unwrap()),
            r#"AdmittedReach { server: "github.com", provider: "github", side: "tasker", .. }"#
        );
    }
}
