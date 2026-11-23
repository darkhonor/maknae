//! The forge seam (ADR-0038 decision 2, as amended): what is specific to one
//! forge, behind one narrow interface. No I/O and no token enter this crate.

mod github;
mod gitlab;
mod observe;

pub use github::reserved_first_segment as github_reserved_first_segment;
pub use gitlab::{
    reserved_first_segment as gitlab_reserved_first_segment, route_segment as gitlab_route_segment,
};
pub use maknae_config::{CredentialKind, ForgeProvider};
pub use observe::{Auth, ForgeReach, HttpReply, Observer, Step};

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Sigil {
    Hash,
    Bang,
}

/// What the path of a link on a forge's own host names.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum LinkPath<'p> {
    Repository { base: &'p str, change: Option<u64> },
    AmbiguousRoute,
    NoRepository,
}

#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Debug)]
pub enum AgentSide {
    Observe,
    AtHandOut,
    NotThisForge,
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Minting {
    TrustPlane,
    FrontEnd,
    NotThisForge,
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum GithubKind {
    AppInstallation,
    MachineUser,
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum GitlabKind {
    ProjectToken,
    BotToken,
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum ForgeKind {
    Github(GithubKind),
    Gitlab(GitlabKind),
}

impl ForgeKind {
    pub fn provider(self) -> ForgeProvider {
        match self {
            ForgeKind::Github(_) => ForgeProvider::Github,
            ForgeKind::Gitlab(_) => ForgeProvider::Gitlab,
        }
    }
}

pub trait CredentialForge {
    /// The forge kind this credential kind is, or `None` for a kind no forge owns.
    fn forge(self) -> Option<ForgeKind>;
}

impl CredentialForge for CredentialKind {
    fn forge(self) -> Option<ForgeKind> {
        match self {
            CredentialKind::GithubAppInstallation => {
                Some(ForgeKind::Github(GithubKind::AppInstallation))
            }
            CredentialKind::GithubMachineUser => Some(ForgeKind::Github(GithubKind::MachineUser)),
            CredentialKind::GitlabProjectToken => Some(ForgeKind::Gitlab(GitlabKind::ProjectToken)),
            CredentialKind::GitlabBotToken => Some(ForgeKind::Gitlab(GitlabKind::BotToken)),
            CredentialKind::VaultChildToken | CredentialKind::VaultDynamicSecret => None,
        }
    }
}

pub trait Forge: Sync {
    /// `path` has no leading `/`, query or fragment.
    fn link_path<'p>(&self, path: &'p str) -> LinkPath<'p>;
    fn names_a_repository(&self, base: &str) -> bool;
    /// Whether `owner/repo<sigil>N` names change `N` (`Some(true)`), only the
    /// repository (`Some(false)`), or is not a shorthand here (`None`).
    fn shorthand(&self, sigil: Sigil) -> Option<bool>;
    fn reach(&self) -> Option<&dyn ForgeReach>;
    fn agent_side(&self, kind: ForgeKind) -> AgentSide;
    fn minting(&self, kind: ForgeKind) -> Minting;
}

pub fn forge(p: ForgeProvider) -> &'static dyn Forge {
    match p {
        ForgeProvider::Github => &github::GITHUB,
        ForgeProvider::Gitlab => &gitlab::GITLAB,
    }
}

pub fn observes_reach(p: ForgeProvider) -> bool {
    forge(p).reach().is_some()
}

pub fn without_git(segment: &str) -> &str {
    segment.strip_suffix(".git").unwrap_or(segment)
}

/// A change number: positive, decimal digits only.
pub fn change_number(s: &str) -> Option<u64> {
    if s.is_empty() || !s.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    s.parse().ok().filter(|n| *n > 0)
}

#[cfg(test)]
mod tests {
    use super::*;

    const KINDS: [CredentialKind; 6] = [
        CredentialKind::GithubAppInstallation,
        CredentialKind::GithubMachineUser,
        CredentialKind::GitlabProjectToken,
        CredentialKind::GitlabBotToken,
        CredentialKind::VaultChildToken,
        CredentialKind::VaultDynamicSecret,
    ];

    const PROVIDERS: [ForgeProvider; 2] = [ForgeProvider::Github, ForgeProvider::Gitlab];

    #[test]
    fn the_kind_and_provider_lists_are_complete() {
        for kind in KINDS {
            match kind {
                CredentialKind::GithubAppInstallation
                | CredentialKind::GithubMachineUser
                | CredentialKind::GitlabProjectToken
                | CredentialKind::GitlabBotToken
                | CredentialKind::VaultChildToken
                | CredentialKind::VaultDynamicSecret => {}
            }
        }
        for p in PROVIDERS {
            match p {
                ForgeProvider::Github | ForgeProvider::Gitlab => {}
            }
        }
        assert_eq!(KINDS.len(), 6);
        assert_eq!(PROVIDERS.len(), 2);
    }

    #[test]
    fn every_kind_belongs_to_at_most_one_forge_and_foreign_kinds_are_refused_before_io() {
        for kind in KINDS {
            let Some(fk) = kind.forge() else {
                assert!(
                    matches!(
                        kind,
                        CredentialKind::VaultChildToken | CredentialKind::VaultDynamicSecret
                    ),
                    "{kind:?}"
                );
                continue;
            };
            assert_eq!(
                kind.as_str().split('-').next(),
                Some(fk.provider().as_str()),
                "{kind:?}"
            );
            for p in PROVIDERS {
                let f = forge(p);
                if p == fk.provider() {
                    assert_ne!(f.agent_side(fk), AgentSide::NotThisForge, "{kind:?}");
                    assert_ne!(f.minting(fk), Minting::NotThisForge, "{kind:?}");
                } else {
                    assert_eq!(f.agent_side(fk), AgentSide::NotThisForge, "{kind:?} {p:?}");
                    assert_eq!(f.minting(fk), Minting::NotThisForge, "{kind:?} {p:?}");
                }
            }
        }
    }

    #[test]
    fn has_reach_check_agrees_with_each_forges_agent_side() {
        for kind in KINDS {
            let observed = kind
                .forge()
                .is_some_and(|fk| forge(fk.provider()).agent_side(fk) == AgentSide::Observe);
            assert_eq!(kind.has_reach_check(), observed, "{kind:?}");
            if let Some(fk) = kind.forge().filter(|_| observed) {
                assert!(observes_reach(fk.provider()), "{kind:?}");
            }
        }
    }

    #[test]
    fn gitlab_offers_no_reach_check() {
        assert!(forge(ForgeProvider::Gitlab).reach().is_none());
        assert!(!observes_reach(ForgeProvider::Gitlab));
        assert!(forge(ForgeProvider::Github).reach().is_some());
        assert!(observes_reach(ForgeProvider::Github));
        for kind in [GitlabKind::ProjectToken, GitlabKind::BotToken] {
            assert_eq!(
                forge(ForgeProvider::Gitlab).agent_side(ForgeKind::Gitlab(kind)),
                AgentSide::AtHandOut,
                "{kind:?}"
            );
        }
    }

    #[test]
    fn each_forge_decides_its_own_kinds() {
        let gh = forge(ForgeProvider::Github);
        let gl = forge(ForgeProvider::Gitlab);
        let app = ForgeKind::Github(GithubKind::AppInstallation);
        let user = ForgeKind::Github(GithubKind::MachineUser);
        let project = ForgeKind::Gitlab(GitlabKind::ProjectToken);
        let bot = ForgeKind::Gitlab(GitlabKind::BotToken);
        assert_eq!(gh.agent_side(app), AgentSide::Observe);
        assert_eq!(gh.agent_side(user), AgentSide::AtHandOut);
        assert_eq!(gh.minting(app), Minting::TrustPlane);
        assert_eq!(gh.minting(user), Minting::FrontEnd);
        assert_eq!(gl.minting(project), Minting::TrustPlane);
        assert_eq!(gl.minting(bot), Minting::FrontEnd);
    }

    #[test]
    fn the_shorthand_sigil_is_read_per_provider() {
        let gh = forge(ForgeProvider::Github);
        let gl = forge(ForgeProvider::Gitlab);
        assert_eq!(gh.shorthand(Sigil::Hash), Some(true));
        assert_eq!(gh.shorthand(Sigil::Bang), None);
        assert_eq!(gl.shorthand(Sigil::Hash), Some(false));
        assert_eq!(gl.shorthand(Sigil::Bang), Some(true));
    }

    #[test]
    fn a_github_link_path_names_owner_repo_and_a_pull() {
        let gh = forge(ForgeProvider::Github);
        let repo = |base, change| LinkPath::Repository { base, change };
        assert_eq!(gh.link_path("o/r"), repo("o/r", None));
        assert_eq!(gh.link_path("o/r.git"), repo("o/r", None));
        assert_eq!(gh.link_path("o/r/pull/3"), repo("o/r", Some(3)));
        assert_eq!(gh.link_path("o/r/pull/3/files"), repo("o/r", Some(3)));
        assert_eq!(gh.link_path("o/r/issues/3"), repo("o/r", None));
        assert_eq!(gh.link_path("o/r/pull/0"), repo("o/r", None));
        assert_eq!(gh.link_path("o/r/-/merge_requests/3"), repo("o/r", None));
        assert_eq!(gh.link_path("o"), LinkPath::NoRepository);
        assert_eq!(gh.link_path(""), LinkPath::NoRepository);
    }

    #[test]
    fn a_gitlab_link_path_names_its_project_and_a_merge_request() {
        let gl = forge(ForgeProvider::Gitlab);
        let repo = |base, change| LinkPath::Repository { base, change };
        assert_eq!(gl.link_path("g/sub/p"), repo("g/sub/p", None));
        assert_eq!(gl.link_path("g/p.git/"), repo("g/p", None));
        assert_eq!(
            gl.link_path("g/sub/p/-/merge_requests/4"),
            repo("g/sub/p", Some(4))
        );
        assert_eq!(gl.link_path("g/p/-/issues/4"), repo("g/p", None));
        assert_eq!(gl.link_path("g/p/-/merge_requests"), repo("g/p", None));
        assert_eq!(gl.link_path("g/p/tree"), LinkPath::AmbiguousRoute);
        assert_eq!(
            gl.link_path("g/sub/p/merge_requests/3"),
            LinkPath::AmbiguousRoute
        );
        assert_eq!(gl.link_path("o/r/pull/3"), repo("o/r/pull/3", None));
        assert_eq!(gl.link_path("tree/p"), repo("tree/p", None));
    }

    #[test]
    fn each_forge_names_a_repository_by_its_own_rules() {
        let gh = forge(ForgeProvider::Github);
        let gl = forge(ForgeProvider::Gitlab);
        assert!(gh.names_a_repository("o/r"));
        assert!(!gh.names_a_repository("g/sub/p"));
        assert!(!gh.names_a_repository("o"));
        assert!(!gh.names_a_repository("Settings/x"));
        assert!(!gh.names_a_repository(""));
        assert!(gl.names_a_repository("g/sub/p"));
        assert!(gl.names_a_repository("settings/x"));
        assert!(!gl.names_a_repository("Users/x"));
        assert!(!gl.names_a_repository(""));
        assert!(!gl.names_a_repository("g/../p"));
    }

    #[test]
    fn reserved_and_route_segments_match_as_each_forge_does() {
        assert!(github_reserved_first_segment("settings"));
        assert!(github_reserved_first_segment("SETTINGS"));
        assert!(github_reserved_first_segment("why-github"));
        assert!(!github_reserved_first_segment("darkhonor"));
        assert!(gitlab_reserved_first_segment("-"));
        assert!(gitlab_reserved_first_segment("V2"));
        assert!(!gitlab_reserved_first_segment("settings"));
        assert!(gitlab_route_segment("update"));
        assert!(!gitlab_route_segment("Tree"));
        assert!(!gitlab_route_segment("pull"));
    }

    #[test]
    fn a_change_number_is_positive_decimal_digits() {
        for (n, want) in [
            ("5", Some(5)),
            ("05", Some(5)),
            ("+5", None),
            ("0", None),
            ("", None),
            ("5a", None),
            ("99999999999999999999", None),
        ] {
            assert_eq!(change_number(n), want, "{n}");
        }
        assert_eq!(without_git("r.git"), "r");
        assert_eq!(without_git("r.git.git"), "r.git");
        assert_eq!(without_git("r"), "r");
    }
}
