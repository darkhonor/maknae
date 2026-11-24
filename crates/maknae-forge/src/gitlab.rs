use crate::{
    change_number, without_git, AgentSide, Forge, ForgeCredentialKind, ForgeReach, GithubKind,
    GitlabKind, LinkPath, Minting, Sigil,
};

pub(crate) struct Gitlab;

pub(crate) static GITLAB: Gitlab = Gitlab;

impl Forge for Gitlab {
    fn link_path<'p>(&self, path: &'p str) -> LinkPath<'p> {
        let (project, change) = match path.split_once("/-/") {
            Some((project, rest)) => {
                let mut rest = rest.split('/');
                let change = match (rest.next(), rest.next()) {
                    (Some("merge_requests"), Some(n)) => change_number(n),
                    _ => None,
                };
                (project, change)
            }
            None => {
                let project = path.trim_end_matches('/');
                if project.split('/').skip(2).any(route_segment) {
                    return LinkPath::AmbiguousRoute;
                }
                (project, None)
            }
        };
        LinkPath::Repository {
            base: without_git(project),
            change,
        }
    }

    fn names_a_repository(&self, base: &str) -> bool {
        maknae_proto::repository_path_is_acceptable(base)
            && base
                .split('/')
                .next()
                .is_some_and(|group| !reserved_first_segment(group))
    }

    fn shorthand(&self, sigil: Sigil) -> Option<bool> {
        match sigil {
            Sigil::Hash => Some(false),
            Sigil::Bang => Some(true),
        }
    }

    fn reach(&self) -> Option<&dyn ForgeReach> {
        None
    }

    fn agent_side(&self, kind: ForgeCredentialKind) -> AgentSide {
        match kind {
            ForgeCredentialKind::Gitlab(GitlabKind::ProjectToken)
            | ForgeCredentialKind::Gitlab(GitlabKind::BotToken) => AgentSide::AtHandOut,
            ForgeCredentialKind::Github(GithubKind::AppInstallation | GithubKind::MachineUser) => {
                AgentSide::NotThisForge
            }
        }
    }

    fn minting(&self, kind: ForgeCredentialKind) -> Minting {
        match kind {
            ForgeCredentialKind::Gitlab(GitlabKind::ProjectToken) => Minting::TrustPlane,
            ForgeCredentialKind::Gitlab(GitlabKind::BotToken) => Minting::FrontEnd,
            ForgeCredentialKind::Github(GithubKind::AppInstallation | GithubKind::MachineUser) => {
                Minting::NotThisForge
            }
        }
    }
}

/// GitLab's reserved top-level group names (its "Reserved project and group names").
const GITLAB_RESERVED: [&str; 39] = [
    "-",
    ".well-known",
    "404.html",
    "422.html",
    "500.html",
    "502.html",
    "503.html",
    "admin",
    "api",
    "apple-touch-icon.png",
    "assets",
    "dashboard",
    "deploy.html",
    "explore",
    "favicon.ico",
    "favicon.png",
    "files",
    "groups",
    "health_check",
    "help",
    "import",
    "jwt",
    "login",
    "oauth",
    "profile",
    "projects",
    "public",
    "robots.txt",
    "s",
    "search",
    "sitemap",
    "sitemap.xml",
    "sitemap.xml.gz",
    "slash-command-logo.png",
    "snippets",
    "unsubscribes",
    "uploads",
    "users",
    "v2",
];

pub fn reserved_first_segment(segment: &str) -> bool {
    GITLAB_RESERVED
        .iter()
        .any(|r| r.eq_ignore_ascii_case(segment))
}

/// Route segments a GitLab path without `/-/` may carry after its project: the
/// legacy routes and GitLab's reserved project names.
const GITLAB_ROUTES: [&str; 22] = [
    "merge_requests",
    "issues",
    "tree",
    "blob",
    "commit",
    "commits",
    "pipelines",
    "jobs",
    "wikis",
    "edit",
    "badges",
    "blame",
    "builds",
    "create",
    "create_dir",
    "files",
    "find_file",
    "new",
    "preview",
    "raw",
    "refs",
    "update",
];

pub fn route_segment(segment: &str) -> bool {
    GITLAB_ROUTES.contains(&segment)
}
