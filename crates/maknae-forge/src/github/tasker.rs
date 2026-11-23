use maknae_proto::{
    ForgeOp, ForgeOps, Observations, ReachRefusal, RepoAsk, RepoObservation, REACH_ASKS_MAX,
};
use serde_json::Value;

use super::{status_refusal, GITHUB};
use crate::{Auth, Forge, HttpReply, Observer, Step};

const CALLS_PER_ASK: usize = 3;

/// The tasker side: `GET /repos/{base}`, then for a change `pulls/{n}` and the head repository.
pub(crate) struct Tasker {
    asks: Vec<RepoAsk>,
    seen: Vec<RepoObservation>,
    stage: Stage,
}

enum Stage {
    Start,
    Base,
    Pull { base: Role, change: u64 },
    Head { base: ForgeOps, path: String },
    Done(Result<Observations, ReachRefusal>),
}

#[derive(Clone, Copy)]
enum Role {
    NoRole,
    Pull,
    Triage,
    Push,
    Maintain,
    Admin,
}

impl Role {
    fn base_ops(self) -> ForgeOps {
        let read = [ForgeOp::Read, ForgeOp::Review, ForgeOp::IssueWrite];
        match self {
            Role::NoRole => ForgeOps::EMPTY,
            Role::Pull | Role::Triage => read.into_iter().collect(),
            Role::Push | Role::Maintain | Role::Admin => {
                read.into_iter().chain([ForgeOp::Merge]).collect()
            }
        }
    }

    fn head_ops(self) -> ForgeOps {
        match self {
            Role::NoRole | Role::Pull | Role::Triage => ForgeOps::EMPTY,
            Role::Push | Role::Maintain | Role::Admin => ForgeOps::EMPTY.with(ForgeOp::PushHead),
        }
    }

    /// The caller's role from the repository's `permissions` booleans; `maintain` and
    /// `triage` are optional in GitHub's schema, the other three are not.
    fn of(repo: &Value) -> Result<Self, ReachRefusal> {
        let perms = repo
            .get("permissions")
            .and_then(Value::as_object)
            .ok_or(ReachRefusal::Shape)?;
        let flag = |name: &str, required: bool| match perms.get(name) {
            Some(Value::Bool(b)) => Ok(*b),
            None if !required => Ok(false),
            _ => Err(ReachRefusal::Shape),
        };
        let held = [
            (flag("admin", true)?, Role::Admin),
            (flag("maintain", false)?, Role::Maintain),
            (flag("push", true)?, Role::Push),
            (flag("triage", false)?, Role::Triage),
            (flag("pull", true)?, Role::Pull),
        ];
        Ok(held
            .into_iter()
            .find_map(|(held, role)| held.then_some(role))
            .unwrap_or(Role::NoRole))
    }
}

impl Tasker {
    pub(crate) fn new(asks: &[RepoAsk]) -> Self {
        Self {
            asks: asks.to_vec(),
            seen: Vec::new(),
            stage: Stage::Start,
        }
    }

    fn ask(&self) -> &RepoAsk {
        &self.asks[self.seen.len()]
    }

    fn advance(&mut self, stage: Stage, last: Option<HttpReply>) -> Result<Stage, ReachRefusal> {
        match stage {
            Stage::Start => {
                if last.is_some() || !asks_are_github(&self.asks) {
                    return Err(ReachRefusal::Request);
                }
                Ok(Stage::Base)
            }
            Stage::Base => {
                let role = Role::of(&answer(last)?)?;
                match self.ask().change {
                    Some(change) => Ok(Stage::Pull { base: role, change }),
                    None => self.observe(role.base_ops(), None, ForgeOps::EMPTY, false),
                }
            }
            Stage::Pull { base, .. } => match head_repository(&answer(last)?)? {
                None => self.observe(base.base_ops(), None, ForgeOps::EMPTY, true),
                Some(path) if path.eq_ignore_ascii_case(&self.ask().base) => {
                    self.observe(base.base_ops(), Some(path), base.head_ops(), false)
                }
                Some(path) => Ok(Stage::Head {
                    base: base.base_ops(),
                    path,
                }),
            },
            Stage::Head { base, path } => {
                let role = Role::of(&answer(last)?)?;
                self.observe(base, Some(path), role.head_ops(), false)
            }
            Stage::Done(outcome) => Ok(Stage::Done(outcome)),
        }
    }

    fn observe(
        &mut self,
        base: ForgeOps,
        head_path: Option<String>,
        head: ForgeOps,
        head_gone: bool,
    ) -> Result<Stage, ReachRefusal> {
        let seen = RepoObservation::new(base, head_path, head, head_gone, true)
            .map_err(|_| ReachRefusal::Shape)?;
        self.seen.push(seen);
        if self.seen.len() < self.asks.len() {
            return Ok(Stage::Base);
        }
        Observations::new(std::mem::take(&mut self.seen))
            .map(|all| Stage::Done(Ok(all)))
            .map_err(|_| ReachRefusal::Request)
    }

    fn step(&self) -> Step {
        let get = |path| Step::Get {
            path,
            auth: Auth::Tasker,
        };
        match &self.stage {
            Stage::Start => Step::Done(Err(ReachRefusal::Request)),
            Stage::Base => get(format!("/repos/{}", self.ask().base)),
            Stage::Pull { change, .. } => get(format!("/repos/{}/pulls/{change}", self.ask().base)),
            Stage::Head { path, .. } => get(format!("/repos/{path}")),
            Stage::Done(outcome) => Step::Done(outcome.clone()),
        }
    }
}

impl Observer for Tasker {
    fn next(&mut self, last: Option<HttpReply>) -> Step {
        let stage = std::mem::replace(&mut self.stage, Stage::Done(Err(ReachRefusal::Request)));
        self.stage = self
            .advance(stage, last)
            .unwrap_or_else(|refusal| Stage::Done(Err(refusal)));
        self.step()
    }

    fn calls_max(&self) -> usize {
        CALLS_PER_ASK * self.asks.len()
    }
}

fn asks_are_github(asks: &[RepoAsk]) -> bool {
    (1..=REACH_ASKS_MAX).contains(&asks.len())
        && asks
            .iter()
            .all(|a| GITHUB.names_a_repository(&a.base) && a.head.is_none() && a.change != Some(0))
}

fn answer(last: Option<HttpReply>) -> Result<Value, ReachRefusal> {
    let reply = last.ok_or(ReachRefusal::Unanswered)?;
    if let Some(refusal) = status_refusal(reply.status) {
        return Err(refusal);
    }
    serde_json::from_slice(&reply.body).map_err(|_| ReachRefusal::Shape)
}

/// `head.repo.full_name`, or `None` when `head.repo` is null: the fork was deleted.
fn head_repository(pull: &Value) -> Result<Option<String>, ReachRefusal> {
    match pull.get("head").and_then(|h| h.get("repo")) {
        Some(Value::Null) => Ok(None),
        Some(repo) => repo
            .get("full_name")
            .and_then(Value::as_str)
            .filter(|name| GITHUB.names_a_repository(name))
            .map(|name| Some(name.to_owned()))
            .ok_or(ReachRefusal::Shape),
        None => Err(ReachRefusal::Shape),
    }
}

#[cfg(test)]
mod tests {
    use maknae_proto::{ForgeOp, ForgeOps, Observations, ReachRefusal, RepoAsk, REACH_ASKS_MAX};

    use crate::{forge, Auth, ForgeProvider, HttpReply, Observer, Step};

    const ROLES: [(&str, [bool; 5]); 6] = [
        ("none", [false, false, false, false, false]),
        ("pull", [false, false, false, false, true]),
        ("triage", [false, false, false, true, true]),
        ("push", [false, false, true, true, true]),
        ("maintain", [false, true, true, true, true]),
        ("admin", [true, true, true, true, true]),
    ];

    fn repo(full_name: &str, role: &str) -> HttpReply {
        let [admin, maintain, push, triage, pull] =
            ROLES.iter().find(|(r, _)| *r == role).expect("role").1;
        ok(format!(
            r#"{{"id":1,"name":"r","full_name":"{full_name}","private":true,"fork":false,
            "permissions":{{"admin":{admin},"maintain":{maintain},"push":{push},"triage":{triage},"pull":{pull}}},
            "role_name":"read"}}"#
        ))
    }

    fn pull(head: Option<&str>) -> HttpReply {
        let repo = head.map_or("null".to_owned(), |h| {
            format!(r#"{{"id":2,"full_name":"{h}","fork":true}}"#)
        });
        ok(format!(
            r#"{{"number":5,"state":"open",
            "head":{{"label":"f:topic","ref":"topic","sha":"0123abcd","repo":{repo}}},
            "base":{{"label":"o:main","ref":"main","sha":"4567ef01","repo":{{"full_name":"o/r"}}}}}}"#
        ))
    }

    fn ok(body: String) -> HttpReply {
        HttpReply {
            status: 200,
            body: body.into_bytes(),
        }
    }

    fn ask(base: &str, change: Option<u64>) -> RepoAsk {
        RepoAsk {
            base: base.into(),
            change,
            head: None,
        }
    }

    fn observer(asks: &[RepoAsk]) -> Box<dyn Observer> {
        forge(ForgeProvider::Github)
            .reach()
            .expect("github observes reach")
            .tasker(asks)
    }

    /// Drives an observer against `answer`, returning its outcome and every path it asked for.
    fn drive(
        asks: &[RepoAsk],
        mut answer: impl FnMut(&str) -> Option<HttpReply>,
    ) -> (Result<Observations, ReachRefusal>, Vec<String>) {
        let mut obs = observer(asks);
        let mut asked = Vec::new();
        let mut last = None;
        loop {
            match obs.next(last.take()) {
                Step::Get { path, auth } => {
                    assert_eq!(auth, Auth::Tasker, "{path}");
                    assert!(asked.len() < obs.calls_max(), "over the bound at {path}");
                    last = answer(&path);
                    asked.push(path);
                }
                Step::Done(outcome) => return (outcome, asked),
            }
        }
    }

    fn base_ops(ops: &[ForgeOp]) -> ForgeOps {
        ops.iter().copied().collect()
    }

    const READER: [ForgeOp; 3] = [ForgeOp::Read, ForgeOp::Review, ForgeOp::IssueWrite];
    const WRITER: [ForgeOp; 4] = [
        ForgeOp::Read,
        ForgeOp::Review,
        ForgeOp::IssueWrite,
        ForgeOp::Merge,
    ];

    #[test]
    fn each_role_maps_to_its_ops() {
        for (role, _) in ROLES {
            let (base, head) = match role {
                "none" => (ForgeOps::EMPTY, ForgeOps::EMPTY),
                "pull" | "triage" => (base_ops(&READER), ForgeOps::EMPTY),
                "push" | "maintain" | "admin" => {
                    (base_ops(&WRITER), base_ops(&[ForgeOp::PushHead]))
                }
                other => panic!("{other}"),
            };
            let (out, asked) = drive(&[ask("o/r", None)], |_| Some(repo("o/r", role)));
            let out = out.expect(role);
            assert_eq!(asked, ["/repos/o/r"], "{role}");
            let [o] = out.as_slice() else {
                panic!("{role}")
            };
            assert_eq!(o.base(), base, "{role}");
            assert_eq!(o.head(), ForgeOps::EMPTY, "{role}");
            assert_eq!(o.head_path(), None, "{role}");
            assert!(o.covered() && !o.head_gone(), "{role}");

            let (out, asked) = drive(&[ask("O/R", Some(5))], |path| match path {
                "/repos/O/R" => Some(repo("o/r", role)),
                "/repos/O/R/pulls/5" => Some(pull(Some("o/r"))),
                other => panic!("{other}"),
            });
            let out = out.expect(role);
            assert_eq!(asked, ["/repos/O/R", "/repos/O/R/pulls/5"], "{role}");
            let [o] = out.as_slice() else {
                panic!("{role}")
            };
            assert_eq!((o.base(), o.head()), (base, head), "{role}");
            assert_eq!(o.head_path(), Some("o/r"), "{role}");
        }
    }

    #[test]
    fn each_tasker_status_refuses_with_its_class() {
        let classes: [(Option<u16>, ReachRefusal); 14] = [
            (Some(401), ReachRefusal::Unauthorized),
            (Some(403), ReachRefusal::Forbidden),
            (Some(429), ReachRefusal::Forbidden),
            (Some(404), ReachRefusal::NotFound),
            (Some(301), ReachRefusal::Moved),
            (Some(302), ReachRefusal::Moved),
            (Some(307), ReachRefusal::Moved),
            (Some(399), ReachRefusal::Moved),
            (Some(500), ReachRefusal::Upstream),
            (Some(503), ReachRefusal::Upstream),
            (Some(204), ReachRefusal::Upstream),
            (Some(410), ReachRefusal::Upstream),
            (Some(422), ReachRefusal::Upstream),
            (None, ReachRefusal::Unanswered),
        ];
        let asks = [ask("o/r", Some(5))];
        let stages = ["/repos/o/r", "/repos/o/r/pulls/5", "/repos/f/r"];
        for (at, stage) in stages.iter().enumerate() {
            let fine = |path: &str| match path {
                "/repos/o/r" => repo("o/r", "admin"),
                "/repos/o/r/pulls/5" => pull(Some("f/r")),
                "/repos/f/r" => repo("f/r", "push"),
                other => panic!("{other}"),
            };
            for (status, class) in classes {
                let (out, asked) = drive(&asks, |path| {
                    if path == *stage {
                        status.map(|status| HttpReply {
                            status,
                            body: br#"{"message":"x"}"#.to_vec(),
                        })
                    } else {
                        Some(fine(path))
                    }
                });
                assert_eq!(out, Err(class), "{stage} {status:?}");
                assert_eq!(asked, stages[..=at], "{stage} {status:?}");
            }
            for body in [&b"not json"[..], b"[]", b"", b"{\"permissions\":"] {
                let (out, _) = drive(&asks, |path| {
                    Some(if path == *stage {
                        HttpReply {
                            status: 200,
                            body: body.to_vec(),
                        }
                    } else {
                        fine(path)
                    })
                });
                assert_eq!(out, Err(ReachRefusal::Shape), "{stage} {body:?}");
            }
        }
        let (out, _) = drive(&asks, |path| match path {
            "/repos/o/r" => Some(repo("o/r", "admin")),
            _ => Some(ok(
                r#"{"number":5,"head":{"repo":{"full_name":"f/r/x"}}}"#.into()
            )),
        });
        assert_eq!(
            out,
            Err(ReachRefusal::Shape),
            "a head that is no github repository"
        );
        for body in [
            r#"{"number":5}"#,
            r#"{"number":5,"head":null}"#,
            r#"{"number":5,"head":{"ref":"topic"}}"#,
            r#"{"number":5,"head":{"repo":{"id":2}}}"#,
            r#"{"number":5,"head":{"repo":{"full_name":7}}}"#,
        ] {
            let (out, _) = drive(&asks, |path| match path {
                "/repos/o/r" => Some(repo("o/r", "admin")),
                _ => Some(ok(body.into())),
            });
            assert_eq!(out, Err(ReachRefusal::Shape), "{body}");
        }
    }

    #[test]
    fn a_fork_reads_its_head_and_checks_push_there() {
        for (head_role, head) in [
            ("none", ForgeOps::EMPTY),
            ("pull", ForgeOps::EMPTY),
            ("triage", ForgeOps::EMPTY),
            ("push", base_ops(&[ForgeOp::PushHead])),
            ("maintain", base_ops(&[ForgeOp::PushHead])),
            ("admin", base_ops(&[ForgeOp::PushHead])),
        ] {
            let (out, asked) = drive(&[ask("o/r", Some(5))], |path| match path {
                "/repos/o/r" => Some(repo("o/r", "pull")),
                "/repos/o/r/pulls/5" => Some(pull(Some("f/r"))),
                "/repos/f/r" => Some(repo("f/r", head_role)),
                other => panic!("{other}"),
            });
            assert_eq!(
                asked,
                ["/repos/o/r", "/repos/o/r/pulls/5", "/repos/f/r"],
                "{head_role}"
            );
            let out = out.expect(head_role);
            let [o] = out.as_slice() else {
                panic!("{head_role}")
            };
            assert_eq!(o.base(), base_ops(&READER), "{head_role}");
            assert_eq!(o.head(), head, "{head_role}");
            assert_eq!(o.head_path(), Some("f/r"), "{head_role}");
            assert!(!o.head_gone(), "{head_role}");
        }
    }

    #[test]
    fn a_deleted_fork_is_head_gone_not_a_refusal() {
        let (out, asked) = drive(&[ask("o/r", Some(5))], |path| match path {
            "/repos/o/r" => Some(repo("o/r", "admin")),
            "/repos/o/r/pulls/5" => Some(pull(None)),
            other => panic!("{other}"),
        });
        assert_eq!(asked, ["/repos/o/r", "/repos/o/r/pulls/5"]);
        let out = out.expect("a deleted fork is observed");
        let [o] = out.as_slice() else { panic!() };
        assert!(o.head_gone());
        assert_eq!(o.head_path(), None);
        assert_eq!(o.head(), ForgeOps::EMPTY);
        assert_eq!(o.base(), base_ops(&WRITER));
    }

    #[test]
    fn a_missing_permissions_block_refuses() {
        let unread = [
            r#"{"full_name":"o/r"}"#,
            r#"{"full_name":"o/r","permissions":null}"#,
            r#"{"full_name":"o/r","permissions":[]}"#,
            r#"{"full_name":"o/r","permissions":{"admin":false,"push":false}}"#,
            r#"{"full_name":"o/r","permissions":{"admin":false,"pull":true}}"#,
            r#"{"full_name":"o/r","permissions":{"push":true,"pull":true}}"#,
            r#"{"full_name":"o/r","permissions":{"admin":false,"push":false,"pull":"true"}}"#,
            r#"{"full_name":"o/r","permissions":{"admin":false,"push":false,"pull":true,"maintain":1}}"#,
            r#"{"full_name":"o/r","permissions":{"admin":false,"push":false,"pull":true,"triage":null}}"#,
        ];
        for body in unread {
            let (out, _) = drive(&[ask("o/r", None)], |_| Some(ok(body.into())));
            assert_eq!(out, Err(ReachRefusal::Shape), "base {body}");
            let (out, _) = drive(&[ask("o/r", Some(5))], |path| match path {
                "/repos/o/r" => Some(repo("o/r", "admin")),
                "/repos/o/r/pulls/5" => Some(pull(Some("f/r"))),
                _ => Some(ok(body.into())),
            });
            assert_eq!(out, Err(ReachRefusal::Shape), "head {body}");
        }
        let (out, _) = drive(&[ask("o/r", None)], |_| {
            Some(ok(
                r#"{"permissions":{"admin":false,"push":true,"pull":true}}"#.into(),
            ))
        });
        let out = out.expect("maintain and triage may be absent");
        assert_eq!(out.as_slice()[0].base(), base_ops(&WRITER));
    }

    #[test]
    fn an_observer_asks_at_most_its_bound_of_calls() {
        let asks: Vec<RepoAsk> = (0..REACH_ASKS_MAX)
            .map(|i| ask(&format!("o/r{i}"), Some(i as u64 + 1)))
            .collect();
        let (out, asked) = drive(&asks, |path| {
            let rest = path.strip_prefix("/repos/").expect(path);
            Some(match rest.split_once("/pulls/") {
                Some((base, _)) => pull(Some(&format!("f/{}", &base[2..]))),
                None => repo(rest, "push"),
            })
        });
        let out = out.expect("every ask is observed");
        assert_eq!(asked.len(), observer(&asks).calls_max());
        assert_eq!(asked.len(), 3 * REACH_ASKS_MAX);
        for (i, o) in out.as_slice().iter().enumerate() {
            assert_eq!(o.head_path(), Some(format!("f/r{i}").as_str()));
            assert_eq!(o.head(), base_ops(&[ForgeOp::PushHead]));
            assert_eq!(o.base(), base_ops(&WRITER));
        }
        assert!(asked.iter().all(|p| p.starts_with("/repos/")));

        let mut obs = observer(&asks[..1]);
        assert!(matches!(obs.next(None), Step::Get { .. }));
        let done = obs.next(Some(HttpReply {
            status: 404,
            body: Vec::new(),
        }));
        assert_eq!(done, Step::Done(Err(ReachRefusal::NotFound)));
        assert_eq!(obs.next(Some(repo("o/r0", "admin"))), done);
        assert_eq!(obs.next(None), done);
    }

    #[test]
    fn an_ask_outside_the_github_grammar_is_refused_before_any_call() {
        let headed = RepoAsk {
            head: Some("f/r".into()),
            ..ask("o/r", Some(5))
        };
        let many: Vec<RepoAsk> = (0..=REACH_ASKS_MAX)
            .map(|i| ask(&format!("o/r{i}"), None))
            .collect();
        for asks in [
            vec![],
            many,
            vec![ask("g/sub/p", None)],
            vec![ask("settings/r", None)],
            vec![ask("o/r", Some(0))],
            vec![ask("o/r", None), headed],
        ] {
            let (out, asked) = drive(&asks, |p| panic!("asked {p}"));
            assert_eq!(out, Err(ReachRefusal::Request), "{asks:?}");
            assert!(asked.is_empty());
        }
        let mut obs = observer(&[ask("o/r", None)]);
        assert_eq!(
            obs.next(Some(repo("o/r", "admin"))),
            Step::Done(Err(ReachRefusal::Request)),
            "a first reply answers no request"
        );
    }
}
