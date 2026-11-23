use maknae_proto::{
    ForgeOp, ForgeOps, Observations, ReachRefusal, RepoAsk, RepoObservation, REACH_ASKS_MAX,
};
use serde_json::Value;

use super::{answer, status_refusal, GITHUB};
use crate::{Auth, Forge, HttpReply, Observer, Step};

const PER_PAGE: usize = 100;
/// Past this many pages of `/installation/repositories`, an unlisted repository is not covered.
const LIST_PAGES_MAX: usize = 10;
const CALLS_MAX: usize = 1 + 1 + LIST_PAGES_MAX + 1;

/// The App side: `GET /app/installations/{id}` for the granted permissions, then a
/// `metadata: read` mint, the installation's repository list with that token, and its revoke.
pub(crate) struct Agent {
    installation: u64,
    asks: Vec<RepoAsk>,
    stage: Stage,
}

enum Stage {
    Start,
    Installation,
    Mint(Granted),
    List {
        granted: Granted,
        page: usize,
        listed: Vec<Listed>,
    },
    Revoke(Result<Observations, ReachRefusal>),
    Done(Result<Observations, ReachRefusal>),
}

#[derive(Clone, Copy)]
struct Granted {
    base: ForgeOps,
    head: ForgeOps,
}

#[derive(Clone, Copy, Default)]
struct Listed {
    base: bool,
    head: bool,
}

#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
enum Level {
    NoAccess,
    Read,
    Write,
}

impl Granted {
    fn of(installation: u64, body: &Value) -> Result<Self, ReachRefusal> {
        if body.get("id").and_then(Value::as_u64) != Some(installation) {
            return Err(ReachRefusal::Shape);
        }
        let perms = body
            .get("permissions")
            .and_then(Value::as_object)
            .ok_or(ReachRefusal::Shape)?;
        let level = |name: &str| match perms.get(name) {
            None => Ok(Level::NoAccess),
            Some(Value::String(l)) => match l.as_str() {
                "read" => Ok(Level::Read),
                "write" | "admin" => Ok(Level::Write),
                _ => Err(ReachRefusal::Shape),
            },
            Some(_) => Err(ReachRefusal::Shape),
        };
        let contents = level("contents")?;
        let pulls = level("pull_requests")?;
        let issues = level("issues")?;
        let metadata = level("metadata")?;
        match body.get("suspended_at") {
            Some(Value::Null) => {}
            Some(Value::String(_)) => return Err(ReachRefusal::Suspended),
            _ => return Err(ReachRefusal::Shape),
        }
        let read = [contents, metadata, pulls, issues]
            .into_iter()
            .all(|l| l >= Level::Read);
        let base = [
            (read, ForgeOp::Read),
            (pulls == Level::Write, ForgeOp::Review),
            (issues == Level::Write, ForgeOp::IssueWrite),
            (
                contents == Level::Write && pulls == Level::Write,
                ForgeOp::Merge,
            ),
        ]
        .into_iter()
        .filter_map(|(held, op)| held.then_some(op))
        .collect();
        let head = match contents {
            Level::Write => ForgeOps::EMPTY.with(ForgeOp::PushHead),
            Level::NoAccess | Level::Read => ForgeOps::EMPTY,
        };
        Ok(Self { base, head })
    }
}

impl Agent {
    pub(crate) fn new(installation: u64, asks: &[RepoAsk]) -> Self {
        Self {
            installation,
            asks: asks.to_vec(),
            stage: Stage::Start,
        }
    }

    fn advance(&self, stage: Stage, last: Option<HttpReply>) -> Stage {
        match stage {
            Stage::Start => {
                if last.is_some() || self.installation == 0 || !asks_are_github(&self.asks) {
                    return Stage::Done(Err(ReachRefusal::Request));
                }
                Stage::Installation
            }
            Stage::Installation => {
                match answer(last).and_then(|body| Granted::of(self.installation, &body)) {
                    Ok(granted) => Stage::Mint(granted),
                    Err(refusal) => Stage::Done(Err(refusal)),
                }
            }
            Stage::Mint(granted) => match last {
                None => Stage::Done(Err(ReachRefusal::Unanswered)),
                Some(reply) => match expect(reply.status, 201) {
                    Err(refusal) => Stage::Done(Err(refusal)),
                    Ok(()) if !reply.body.is_empty() => Stage::Revoke(Err(ReachRefusal::Request)),
                    Ok(()) => Stage::List {
                        granted,
                        page: 1,
                        listed: vec![Listed::default(); self.asks.len()],
                    },
                },
            },
            Stage::List {
                granted,
                page,
                mut listed,
            } => match self.list(last, &mut listed) {
                Err(refusal) => Stage::Revoke(Err(refusal)),
                Ok(true) if page < LIST_PAGES_MAX && !self.all_listed(&listed) => Stage::List {
                    granted,
                    page: page + 1,
                    listed,
                },
                Ok(_) => Stage::Revoke(self.observations(granted, &listed)),
            },
            Stage::Revoke(outcome) => {
                let revoked = match last {
                    None => Err(ReachRefusal::Unanswered),
                    Some(HttpReply { status: 401, .. }) => Ok(()),
                    Some(reply) => expect(reply.status, 204),
                };
                Stage::Done(outcome.and_then(|seen| revoked.map(|()| seen)))
            }
            Stage::Done(outcome) => Stage::Done(outcome),
        }
    }

    /// Marks each ask's base and head found on this page; `true` when the page is full.
    fn list(&self, last: Option<HttpReply>, listed: &mut [Listed]) -> Result<bool, ReachRefusal> {
        let body = answer(last)?;
        let repos = body
            .get("repositories")
            .and_then(Value::as_array)
            .ok_or(ReachRefusal::Shape)?;
        for repo in repos {
            let name = repo
                .get("full_name")
                .and_then(Value::as_str)
                .ok_or(ReachRefusal::Shape)?;
            for (ask, found) in self.asks.iter().zip(listed.iter_mut()) {
                found.base |= ask.base.eq_ignore_ascii_case(name);
                found.head |= ask
                    .head
                    .as_deref()
                    .is_some_and(|head| head.eq_ignore_ascii_case(name));
            }
        }
        Ok(repos.len() >= PER_PAGE)
    }

    fn all_listed(&self, listed: &[Listed]) -> bool {
        self.asks
            .iter()
            .zip(listed)
            .all(|(ask, found)| found.base && (ask.head.is_none() || found.head))
    }

    /// An ask is covered when its base is listed; its head ops need the head listed too.
    fn observations(
        &self,
        granted: Granted,
        listed: &[Listed],
    ) -> Result<Observations, ReachRefusal> {
        let seen = self
            .asks
            .iter()
            .zip(listed)
            .map(|(ask, found)| {
                let ops = |held: bool, ops: ForgeOps| if held { ops } else { ForgeOps::EMPTY };
                RepoObservation::new(
                    ops(found.base, granted.base),
                    ask.head.clone(),
                    ops(found.base && found.head, granted.head),
                    false,
                    found.base,
                )
                .map_err(|_| ReachRefusal::Shape)
            })
            .collect::<Result<Vec<_>, _>>()?;
        Observations::new(seen).map_err(|_| ReachRefusal::Request)
    }

    fn step(&self) -> Step {
        match &self.stage {
            Stage::Start => Step::Done(Err(ReachRefusal::Request)),
            Stage::Installation => Step::Get {
                path: format!("/app/installations/{}", self.installation),
                auth: Auth::AppJwt,
            },
            Stage::Mint(_) => Step::MintMetadataRead {
                installation: self.installation,
            },
            Stage::List { page, .. } => Step::Get {
                path: format!("/installation/repositories?per_page={PER_PAGE}&page={page}"),
                auth: Auth::Installation,
            },
            Stage::Revoke(_) => Step::Revoke,
            Stage::Done(outcome) => Step::Done(outcome.clone()),
        }
    }
}

impl Observer for Agent {
    fn next(&mut self, last: Option<HttpReply>) -> Step {
        let stage = std::mem::replace(&mut self.stage, Stage::Done(Err(ReachRefusal::Request)));
        self.stage = self.advance(stage, last);
        self.step()
    }

    fn calls_max(&self) -> usize {
        CALLS_MAX
    }
}

fn asks_are_github(asks: &[RepoAsk]) -> bool {
    let names = |r: &str| GITHUB.names_a_repository(r);
    (1..=REACH_ASKS_MAX).contains(&asks.len())
        && asks
            .iter()
            .all(|a| names(&a.base) && a.head.as_deref().is_none_or(names) && a.change != Some(0))
}

fn expect(status: u16, ok: u16) -> Result<(), ReachRefusal> {
    if status == ok {
        return Ok(());
    }
    Err(status_refusal(status).unwrap_or(ReachRefusal::Upstream))
}

#[cfg(test)]
mod tests {
    use maknae_proto::{ForgeOp, ForgeOps, Observations, ReachRefusal, RepoAsk, REACH_ASKS_MAX};

    use crate::{forge, Auth, ForgeProvider, HttpReply, Observer, Step};

    const INSTALLATION: u64 = 77;
    const LIST: &str = "/installation/repositories?per_page=100&page=";

    fn installation(permissions: &str, suspended_at: &str) -> HttpReply {
        ok(format!(
            r#"{{"id":{INSTALLATION},"account":{{"login":"o"}},"app_id":1,"target_type":"Organization",
            "permissions":{permissions},"repository_selection":"selected",
            "suspended_at":{suspended_at},"suspended_by":null}}"#
        ))
    }

    fn granted(permissions: &str) -> HttpReply {
        installation(permissions, "null")
    }

    const ALL_WRITE: &str =
        r#"{"contents":"write","metadata":"read","pull_requests":"write","issues":"write"}"#;

    fn page(names: &[String]) -> HttpReply {
        let repos: Vec<String> = names
            .iter()
            .map(|n| format!(r#"{{"id":1,"name":"r","full_name":"{n}","private":true}}"#))
            .collect();
        ok(format!(
            r#"{{"total_count":{},"repository_selection":"selected","repositories":[{}]}}"#,
            names.len(),
            repos.join(",")
        ))
    }

    fn listing(names: &[&str]) -> HttpReply {
        page(&names.iter().map(|n| n.to_string()).collect::<Vec<_>>())
    }

    fn ok(body: String) -> HttpReply {
        status(200, body.as_bytes())
    }

    fn status(status: u16, body: &[u8]) -> HttpReply {
        HttpReply {
            status,
            body: body.to_vec(),
        }
    }

    fn minted() -> Option<HttpReply> {
        Some(status(201, b""))
    }

    fn revoked() -> Option<HttpReply> {
        Some(status(204, b""))
    }

    fn ask(base: &str, head: Option<&str>) -> RepoAsk {
        RepoAsk {
            base: base.into(),
            change: head.map(|_| 5),
            head: head.map(Into::into),
        }
    }

    fn observer(installation: u64, asks: &[RepoAsk]) -> Box<dyn Observer> {
        forge(ForgeProvider::Github)
            .reach()
            .expect("github observes reach")
            .agent(installation, asks)
    }

    /// Each step as `GET <path>`, `MINT` or `REVOKE`; an installation-token `GET` must follow
    /// a mint and precede the revoke, and every mint is answered before the outcome.
    fn label(step: &Step) -> String {
        match step {
            Step::Get { path, auth } => {
                let want = if path.starts_with("/app/installations/") {
                    Auth::AppJwt
                } else {
                    Auth::Installation
                };
                assert_eq!(*auth, want, "{path}");
                format!("GET {path}")
            }
            Step::MintMetadataRead { installation } => {
                assert_eq!(*installation, INSTALLATION);
                "MINT".into()
            }
            Step::Revoke => "REVOKE".into(),
            Step::Done(_) => unreachable!(),
        }
    }

    fn drive_with(
        installation: u64,
        asks: &[RepoAsk],
        mut answer: impl FnMut(&str) -> Option<HttpReply>,
    ) -> (Result<Observations, ReachRefusal>, Vec<String>) {
        let mut obs = observer(installation, asks);
        let mut asked: Vec<String> = Vec::new();
        let mut last = None;
        loop {
            let step = obs.next(last.take());
            if let Step::Done(outcome) = step {
                let mints = asked.iter().filter(|s| *s == "MINT").count();
                let revokes = asked.iter().filter(|s| *s == "REVOKE").count();
                assert!(mints <= 1 && revokes <= mints, "{asked:?}");
                return (outcome, asked);
            }
            let label = label(&step);
            assert!(asked.len() < obs.calls_max(), "over the bound at {label}");
            if label.starts_with(&format!("GET {LIST}")) {
                assert!(
                    asked.iter().any(|s| s == "MINT") && !asked.iter().any(|s| s == "REVOKE"),
                    "{label} outside the token's life: {asked:?}"
                );
            }
            last = answer(&label);
            asked.push(label);
        }
    }

    fn drive(
        asks: &[RepoAsk],
        answer: impl FnMut(&str) -> Option<HttpReply>,
    ) -> (Result<Observations, ReachRefusal>, Vec<String>) {
        drive_with(INSTALLATION, asks, answer)
    }

    /// A well-behaved installation of `permissions` whose one-page listing is `names`.
    fn fine<'a>(
        permissions: &'a str,
        names: &'a [&'a str],
    ) -> impl Fn(&str) -> Option<HttpReply> + 'a {
        move |label| match label {
            "GET /app/installations/77" => Some(granted(permissions)),
            "MINT" => minted(),
            "REVOKE" => revoked(),
            l if l == format!("GET {LIST}1") => Some(listing(names)),
            other => panic!("{other}"),
        }
    }

    fn ops(ops: &[ForgeOp]) -> ForgeOps {
        ops.iter().copied().collect()
    }

    fn exchange(pages: usize) -> Vec<String> {
        let mut steps = vec!["GET /app/installations/77".to_owned(), "MINT".into()];
        steps.extend((1..=pages).map(|p| format!("GET {LIST}{p}")));
        steps.push("REVOKE".into());
        steps
    }

    #[test]
    fn each_installation_permission_maps_to_its_ops() {
        use ForgeOp::*;
        let read_all =
            r#"{"contents":"read","metadata":"read","pull_requests":"read","issues":"read"}"#;
        let cases: [(&str, &[ForgeOp], &[ForgeOp]); 12] = [
            ("{}", &[], &[]),
            (r#"{"metadata":"read"}"#, &[], &[]),
            (read_all, &[Read], &[]),
            (
                r#"{"contents":"read","metadata":"read","pull_requests":"read"}"#,
                &[],
                &[],
            ),
            (
                r#"{"contents":"read","metadata":"read","issues":"read"}"#,
                &[],
                &[],
            ),
            (
                r#"{"metadata":"read","pull_requests":"read","issues":"read"}"#,
                &[],
                &[],
            ),
            (
                r#"{"contents":"read","pull_requests":"read","issues":"read"}"#,
                &[],
                &[],
            ),
            (
                r#"{"metadata":"read","pull_requests":"write"}"#,
                &[Review],
                &[],
            ),
            (
                r#"{"metadata":"read","issues":"write"}"#,
                &[IssueWrite],
                &[],
            ),
            (
                r#"{"metadata":"read","contents":"write"}"#,
                &[],
                &[PushHead],
            ),
            (
                r#"{"metadata":"read","contents":"write","pull_requests":"write"}"#,
                &[Review, Merge],
                &[PushHead],
            ),
            (ALL_WRITE, &[Read, Review, IssueWrite, Merge], &[PushHead]),
        ];
        let admin = r#"{"contents":"admin","metadata":"read","pull_requests":"admin","issues":"admin",
            "checks":"write","administration":"write","members":"read"}"#;
        for (permissions, base, head) in cases.into_iter().chain([(
            admin,
            &[Read, Review, IssueWrite, Merge][..],
            &[PushHead][..],
        )]) {
            let (out, asked) = drive(
                &[ask("o/r", Some("f/r"))],
                fine(permissions, &["o/r", "f/r"]),
            );
            assert_eq!(asked, exchange(1), "{permissions}");
            let out = out.expect(permissions);
            let [o] = out.as_slice() else {
                panic!("{permissions}")
            };
            assert_eq!(o.base(), ops(base), "{permissions}");
            assert_eq!(o.head(), ops(head), "{permissions}");
            assert_eq!(o.head_path(), Some("f/r"), "{permissions}");
            assert!(o.covered() && !o.head_gone(), "{permissions}");
        }
    }

    #[test]
    fn an_unreadable_installation_refuses_before_any_mint() {
        let bodies = [
            r#"{"id":77,"suspended_at":null}"#.to_owned(),
            r#"{"id":77,"permissions":null,"suspended_at":null}"#.into(),
            r#"{"id":77,"permissions":[],"suspended_at":null}"#.into(),
            r#"{"id":77,"permissions":{"contents":"none"},"suspended_at":null}"#.into(),
            r#"{"id":77,"permissions":{"issues":true},"suspended_at":null}"#.into(),
            r#"{"id":77,"permissions":{}}"#.into(),
            r#"{"id":77,"permissions":{},"suspended_at":7}"#.into(),
            r#"{"id":78,"permissions":{},"suspended_at":null}"#.into(),
            r#"{"permissions":{},"suspended_at":null}"#.into(),
            "not json".into(),
        ];
        for body in bodies {
            let (out, asked) = drive(&[ask("o/r", None)], |_| Some(ok(body.clone())));
            assert_eq!(out, Err(ReachRefusal::Shape), "{body}");
            assert_eq!(asked, ["GET /app/installations/77"], "{body}");
        }
    }

    #[test]
    fn a_suspended_installation_refuses() {
        let (out, asked) = drive(&[ask("o/r", None)], |_| {
            Some(installation(ALL_WRITE, r#""2026-11-20T00:00:00Z""#))
        });
        assert_eq!(out, Err(ReachRefusal::Suspended));
        assert_eq!(asked, ["GET /app/installations/77"]);
    }

    #[test]
    fn an_uncovered_repository_is_not_covered_not_refused() {
        use ForgeOp::*;
        let asks = [
            ask("o/a", Some("f/a")),
            ask("o/b", Some("f/b")),
            ask("O/C", Some("o/c")),
            ask("o/d", None),
        ];
        let (out, asked) = drive(&asks, fine(ALL_WRITE, &["o/a", "f/b", "o/c"]));
        assert_eq!(asked, exchange(1));
        let out = out.expect("an uncovered repository is observed");
        let [a, b, c, d] = out.as_slice() else {
            panic!()
        };
        let writer = ops(&[Read, Review, IssueWrite, Merge]);
        assert_eq!(
            (a.base(), a.head(), a.covered()),
            (writer, ForgeOps::EMPTY, true)
        );
        assert_eq!(a.head_path(), Some("f/a"));
        assert_eq!(
            (b.base(), b.head(), b.covered()),
            (ForgeOps::EMPTY, ForgeOps::EMPTY, false)
        );
        assert_eq!(
            (c.base(), c.head(), c.covered()),
            (writer, ops(&[PushHead]), true)
        );
        assert_eq!(
            (d.base(), d.head(), d.covered(), d.head_path()),
            (ForgeOps::EMPTY, ForgeOps::EMPTY, false, None)
        );
        assert!(out.as_slice().iter().all(|o| !o.head_gone()));
    }

    #[test]
    fn the_agent_observer_never_asks_for_get_repos() {
        let asks: Vec<RepoAsk> = (0..REACH_ASKS_MAX)
            .map(|i| ask(&format!("o/r{i}"), Some(&format!("f/r{i}"))))
            .collect();
        let names: Vec<String> = (0..REACH_ASKS_MAX).map(|i| format!("o/r{i}")).collect();
        let names: Vec<&str> = names.iter().map(String::as_str).collect();
        let (out, asked) = drive(&asks, fine(ALL_WRITE, &names));
        out.expect("observed");
        assert_eq!(asked, exchange(1));
        assert!(asked.iter().all(|s| !s.contains("/repos/")), "{asked:?}");
    }

    #[test]
    fn each_agent_status_refuses_with_its_class() {
        let classes: [(Option<u16>, ReachRefusal); 9] = [
            (Some(401), ReachRefusal::Unauthorized),
            (Some(403), ReachRefusal::Forbidden),
            (Some(429), ReachRefusal::Forbidden),
            (Some(404), ReachRefusal::NotFound),
            (Some(302), ReachRefusal::Moved),
            (Some(500), ReachRefusal::Upstream),
            (Some(422), ReachRefusal::Upstream),
            (Some(202), ReachRefusal::Upstream),
            (None, ReachRefusal::Unanswered),
        ];
        let asks = [ask("o/r", Some("f/r"))];
        let base = fine(ALL_WRITE, &["o/r", "f/r"]);
        let at = |stage: &'static str, reply: Option<HttpReply>| {
            let base = &base;
            drive(&asks, move |label| {
                if label.starts_with(stage) {
                    reply.clone()
                } else {
                    base(label)
                }
            })
        };
        for (code, class) in classes {
            let reply = code.map(|c| status(c, br#"{"message":"x"}"#));
            let (out, asked) = at("GET /app/", reply.clone());
            assert_eq!((out, asked.len()), (Err(class), 1), "installation {code:?}");

            let mint = code.map(|c| status(c, b""));
            let (out, asked) = at("MINT", mint);
            assert_eq!(out, Err(class), "mint {code:?}");
            assert_eq!(
                asked,
                exchange(0)[..2],
                "no revoke without a token: {code:?}"
            );

            let (out, asked) = at("GET /installation/", reply);
            assert_eq!(out, Err(class), "list {code:?}");
            assert_eq!(asked, exchange(1), "the token is revoked: {code:?}");

            if code == Some(401) {
                continue;
            }
            let (out, asked) = at("REVOKE", code.map(|c| status(c, b"")));
            assert_eq!(out, Err(class), "revoke {code:?}");
            assert_eq!(asked, exchange(1), "revoke {code:?}");
        }
        let (out, _) = at("REVOKE", Some(status(401, b"")));
        out.expect("401 on revoke is a token already gone");
        let (out, _) = at("MINT", Some(status(200, b"")));
        assert_eq!(out, Err(ReachRefusal::Upstream), "a mint answers 201");

        for body in [
            &b"not json"[..],
            b"[]",
            b"{}",
            br#"{"repositories":null}"#,
            br#"{"repositories":[{"name":"r"}]}"#,
            br#"{"repositories":[{"full_name":7}]}"#,
        ] {
            let (out, asked) = at("GET /installation/", Some(status(200, body)));
            assert_eq!(out, Err(ReachRefusal::Shape), "{body:?}");
            assert_eq!(asked, exchange(1), "{body:?}");
        }
        let (out, asked) = drive(&asks, |label| match label {
            "REVOKE" => Some(status(500, b"")),
            l if l.starts_with("GET /installation/") => Some(status(404, b"")),
            l => base(l),
        });
        assert_eq!(out, Err(ReachRefusal::NotFound), "the first refusal stands");
        assert_eq!(asked, exchange(1));
    }

    #[test]
    fn a_mint_reply_carrying_a_body_is_refused_and_revoked() {
        let base = fine(ALL_WRITE, &["o/r"]);
        let (out, asked) = drive(&[ask("o/r", None)], |label| match label {
            "MINT" => Some(status(201, br#"{"token":"ghs_x"}"#)),
            l => base(l),
        });
        assert_eq!(out, Err(ReachRefusal::Request));
        assert_eq!(asked, ["GET /app/installations/77", "MINT", "REVOKE"]);
    }

    #[test]
    fn the_listing_pages_until_every_ask_is_found() {
        let full = |from: usize| -> Vec<String> {
            (from..from + 100).map(|i| format!("x/r{i}")).collect()
        };
        let asks = [ask("o/a", Some("f/a")), ask("o/b", None)];
        let (out, asked) = drive(&asks, |label| {
            match label.strip_prefix(&format!("GET {LIST}")) {
                Some("1") => Some(page(&[vec!["O/A".into()], full(0)].concat()[..100])),
                Some("2") => Some(page(
                    &[vec!["f/a".to_owned(), "o/b".into()], full(2)].concat()[..100],
                )),
                Some(p) => panic!("page {p}"),
                None => fine(ALL_WRITE, &[])(label),
            }
        });
        assert_eq!(asked, exchange(2));
        let out = out.expect("observed");
        assert!(out.as_slice().iter().all(|o| o.covered()));
        assert_eq!(out.as_slice()[0].head(), ops(&[ForgeOp::PushHead]));

        let (out, asked) = drive(&asks, |label| {
            match label.strip_prefix(&format!("GET {LIST}")) {
                Some("1") => Some(page(&full(0))),
                Some("2") => Some(listing(&["o/a"])),
                Some(p) => panic!("page {p}"),
                None => fine(ALL_WRITE, &[])(label),
            }
        });
        assert_eq!(asked, exchange(2), "a short page is the last");
        let out = out.expect("observed");
        let [a, b] = out.as_slice() else { panic!() };
        assert!(a.covered() && a.head().is_empty() && !b.covered());
    }

    #[test]
    fn an_agent_observer_asks_at_most_its_bound_of_calls() {
        let asks = [ask("o/r", Some("f/r"))];
        let mut pages = 0;
        let (out, asked) = drive(&asks, |label| {
            match label.strip_prefix(&format!("GET {LIST}")) {
                Some(p) => {
                    pages += 1;
                    assert_eq!(p, pages.to_string());
                    Some(page(
                        &(0..100).map(|i| format!("x/p{p}r{i}")).collect::<Vec<_>>(),
                    ))
                }
                None => fine(ALL_WRITE, &[])(label),
            }
        });
        assert_eq!(asked.len(), observer(INSTALLATION, &asks).calls_max());
        assert_eq!(asked, exchange(10));
        let out = out.expect("past the cap, a repository is not covered");
        let [o] = out.as_slice() else { panic!() };
        assert!(!o.covered() && o.base().is_empty() && o.head().is_empty());

        let mut obs = observer(INSTALLATION, &asks);
        assert!(matches!(obs.next(None), Step::Get { .. }));
        let done = obs.next(Some(status(404, b"")));
        assert_eq!(done, Step::Done(Err(ReachRefusal::NotFound)));
        assert_eq!(obs.next(Some(granted(ALL_WRITE))), done);
        assert_eq!(obs.next(None), done);
    }

    #[test]
    fn an_agent_ask_outside_the_github_grammar_is_refused_before_any_call() {
        let many: Vec<RepoAsk> = (0..=REACH_ASKS_MAX)
            .map(|i| ask(&format!("o/r{i}"), None))
            .collect();
        let zero = RepoAsk {
            change: Some(0),
            ..ask("o/r", None)
        };
        for (installation, asks) in [
            (INSTALLATION, vec![]),
            (INSTALLATION, many),
            (INSTALLATION, vec![ask("g/sub/p", None)]),
            (INSTALLATION, vec![ask("settings/r", None)]),
            (INSTALLATION, vec![ask("o/r", Some("f/r/x"))]),
            (INSTALLATION, vec![ask("o/r", Some("orgs/r"))]),
            (INSTALLATION, vec![zero]),
            (0, vec![ask("o/r", None)]),
        ] {
            let (out, asked) = drive_with(installation, &asks, |p| panic!("asked {p}"));
            assert_eq!(out, Err(ReachRefusal::Request), "{installation} {asks:?}");
            assert!(asked.is_empty());
        }
        let mut obs = observer(INSTALLATION, &[ask("o/r", None)]);
        assert_eq!(
            obs.next(Some(granted(ALL_WRITE))),
            Step::Done(Err(ReachRefusal::Request)),
            "a first reply answers no request"
        );
    }
}
