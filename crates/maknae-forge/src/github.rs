mod tasker;

use crate::{
    change_number, without_git, AgentSide, Forge, ForgeKind, ForgeReach, GithubKind, LinkPath,
    Minting, Observer, Sigil,
};
use maknae_proto::{ReachRefusal, RepoAsk};

pub(crate) struct Github;

pub(crate) static GITHUB: Github = Github;

impl ForgeReach for Github {
    fn tasker(&self, asks: &[RepoAsk]) -> Box<dyn Observer> {
        Box::new(tasker::Tasker::new(asks))
    }
}

/// The refusal class of a reply status, or `None` for 200, the only status read.
pub(crate) fn status_refusal(status: u16) -> Option<ReachRefusal> {
    match status {
        200 => None,
        401 => Some(ReachRefusal::Unauthorized),
        403 | 429 => Some(ReachRefusal::Forbidden),
        404 => Some(ReachRefusal::NotFound),
        300..=399 => Some(ReachRefusal::Moved),
        _ => Some(ReachRefusal::Upstream),
    }
}

impl Forge for Github {
    fn link_path<'p>(&self, path: &'p str) -> LinkPath<'p> {
        let mut segments = path.split('/');
        let (Some(owner), Some(repo)) = (segments.next(), segments.next()) else {
            return LinkPath::NoRepository;
        };
        let change = match (segments.next(), segments.next()) {
            (Some("pull"), Some(n)) => change_number(n),
            _ => None,
        };
        LinkPath::Repository {
            base: &path[..owner.len() + 1 + without_git(repo).len()],
            change,
        }
    }

    fn names_a_repository(&self, base: &str) -> bool {
        maknae_proto::repository_path_is_acceptable(base) && {
            let mut segments = base.split('/');
            segments
                .next()
                .is_some_and(|owner| !reserved_first_segment(owner))
                && segments.count() == 1
        }
    }

    fn shorthand(&self, sigil: Sigil) -> Option<bool> {
        match sigil {
            Sigil::Hash => Some(true),
            Sigil::Bang => None,
        }
    }

    fn reach(&self) -> Option<&dyn ForgeReach> {
        Some(self)
    }

    fn agent_side(&self, kind: ForgeKind) -> AgentSide {
        let ForgeKind::Github(kind) = kind else {
            return AgentSide::NotThisForge;
        };
        match kind {
            GithubKind::AppInstallation => AgentSide::Observe,
            GithubKind::MachineUser => AgentSide::AtHandOut,
        }
    }

    fn minting(&self, kind: ForgeKind) -> Minting {
        let ForgeKind::Github(kind) = kind else {
            return Minting::NotThisForge;
        };
        match kind {
            GithubKind::AppInstallation => Minting::TrustPlane,
            GithubKind::MachineUser => Minting::FrontEnd,
        }
    }
}

/// First path segments that are GitHub's own pages, not owners.
const GITHUB_RESERVED: [&str; 55] = [
    "about",
    "account",
    "advisories",
    "apps",
    "codespaces",
    "collections",
    "contact",
    "copilot",
    "customer-stories",
    "dashboard",
    "discussions",
    "education",
    "enterprise",
    "enterprises",
    "events",
    "explore",
    "features",
    "github-copilot",
    "home",
    "issues",
    "join",
    "login",
    "logout",
    "marketplace",
    "mobile",
    "models",
    "new",
    "nonprofit",
    "notifications",
    "open-source",
    "organizations",
    "orgs",
    "partners",
    "password_reset",
    "premium-support",
    "pricing",
    "pulls",
    "readme",
    "resources",
    "search",
    "security",
    "sessions",
    "settings",
    "signup",
    "site",
    "solutions",
    "sponsors",
    "stars",
    "team",
    "topics",
    "trending",
    "user-attachments",
    "users",
    "watching",
    "why-github",
];

pub fn reserved_first_segment(segment: &str) -> bool {
    GITHUB_RESERVED
        .iter()
        .any(|r| r.eq_ignore_ascii_case(segment))
}
