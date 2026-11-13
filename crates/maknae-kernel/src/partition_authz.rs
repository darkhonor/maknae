//! The partition operand (#628, ADR-0008 amendment 2026-11-11): a mandatory deny that
//! keeps an agent's file verbs inside the partition of the task it cites. It abstains
//! for every subject off the agent channel, and it never permits.

use maknae_config::{fold_path, Fold, Reach};
use maknae_security::{
    AttrValue, Authorizer, Decided, FsOperation, Request, Verdict, CHANNEL_AGENT, CHANNEL_CLIENT,
    CONTEXT_FS_OPERATION, SUBJECT_CHANNEL, SUBJECT_HOME, SUBJECT_ROOT_TASKER,
};

use crate::sensitive_authz::FILE_VERBS;

pub const PARTITION_BACKEND_NAME: &str = "maknae-partition";

/// The directory under an agent's home that holds one partition per root tasker.
pub(crate) const TASKS_DIR: &str = "tasks";

const KINDS: [&str; 2] = ["users", "agents"];

/// The composition's named field. It holds no state: every fact it decides on is
/// stamped on the request by the kernel.
pub struct PartitionOperand;

impl Authorizer for PartitionOperand {
    fn decide_cited_all(&self, reqs: &[Request]) -> Vec<Decided> {
        maknae_security::decide_each_cited(self, reqs)
    }

    fn decide(&self, req: &Request) -> Verdict {
        decide_partition(req, maknae_config::native_fold())
    }

    fn backend_name(&self) -> String {
        PARTITION_BACKEND_NAME.to_string()
    }
}

fn decide_partition(req: &Request, fold: Fold) -> Verdict {
    const ABSTAIN: Verdict = Verdict::NotApplicable { note: None };
    let action = req.action.0.as_str();
    match req.subject.0.get(SUBJECT_CHANNEL) {
        None if action.starts_with("fs.") => return Verdict::Indeterminate,
        None => return ABSTAIN,
        Some(AttrValue::Str(c)) if c == CHANNEL_CLIENT => return ABSTAIN,
        Some(AttrValue::Str(c)) if c == CHANNEL_AGENT => {}
        Some(_) => return Verdict::Indeterminate,
    }
    if !FILE_VERBS.contains(&action) {
        return if action.starts_with("fs.") {
            Verdict::Indeterminate
        } else {
            ABSTAIN
        };
    }
    let Some(AttrValue::Str(path)) = req.resource.0.get(maknae_authz_basic::RESOURCE_PATH_KEY)
    else {
        return Verdict::Indeterminate;
    };
    let Some(AttrValue::Str(home)) = req.subject.0.get(SUBJECT_HOME) else {
        return Verdict::Indeterminate;
    };
    if [path, home]
        .iter()
        .any(|p| crate::handler::lexical_pregate(p).is_err())
    {
        return Verdict::Indeterminate;
    }
    let own = match req.subject.0.get(SUBJECT_ROOT_TASKER) {
        None => None,
        Some(AttrValue::Str(key)) if is_partition_key(key) => Some(key.as_str()),
        Some(_) => return Verdict::Indeterminate,
    };
    let delete = match req.context.0.get(CONTEXT_FS_OPERATION) {
        None => action == "fs.delete",
        Some(AttrValue::Str(op)) => match FsOperation::parse(op) {
            Some(op) => {
                matches!(op, FsOperation::DeleteEntry | FsOperation::DeleteTree)
                    || action == "fs.delete"
            }
            None => return Verdict::Indeterminate,
        },
        Some(_) => return Verdict::Indeterminate,
    };
    let under = |tail: &str| {
        let joined = format!("{}/{TASKS_DIR}{tail}", home.trim_end_matches('/'));
        fold_path(&joined, fold, Reach::Path).into_one()
    };
    let tasks = under("");
    let own = own.map(|key| under(&format!("/{key}")));
    let ancestor = |p: &str| p == tasks || KINDS.iter().any(|k| p == under(&format!("/{k}")));
    let outside = |p: &str| within(p, &tasks) && !own.as_deref().is_some_and(|own| within(p, own));
    let deny = |why: &str| Verdict::Deny {
        reason: format!("partition: {why}"),
    };
    let reach = if delete { Reach::Subtree } else { Reach::Path };
    let asked = fold_path(path, fold, reach);
    if delete && asked.mapped().iter().any(|p| within(&tasks, p)) {
        return deny("the delete would remove the tasks directory");
    }
    let Some(p) = asked.mapped().iter().find(|p| outside(p)) else {
        return ABSTAIN;
    };
    if ancestor(p) {
        return match action {
            "fs.list" | "fs.stat" | "fs.mkdir" => ABSTAIN,
            _ => deny("the partitions' parent directories are listed and made, nothing else"),
        };
    }
    match own {
        Some(_) => deny("the path is in another tasker's partition"),
        None => deny("the request cites no task"),
    }
}

/// `users/<name>` or `agents/<name>`, as `RootTasker::partition` writes it.
fn is_partition_key(key: &str) -> bool {
    key.split_once('/').is_some_and(|(kind, name)| {
        KINDS.contains(&kind) && !matches!(name, "" | "." | "..") && !name.contains('/')
    })
}

/// Whether `path` is `dir` or lies beneath it, by whole components.
fn within(path: &str, dir: &str) -> bool {
    path == dir
        || dir == "/"
        || path
            .strip_prefix(dir)
            .is_some_and(|rest| rest.starts_with('/'))
}

#[cfg(test)]
mod tests {
    use super::*;
    use maknae_security::{Action, Attributes, Context, Resource, Subject};

    const HOME: &str = "/home/hobi-svc";
    const NA: Verdict = Verdict::NotApplicable { note: None };

    fn agent(action: &str, path: Option<&str>, root: Option<&str>) -> Request {
        asked(Some(CHANNEL_AGENT), Some(HOME), action, path, root)
    }

    fn asked(
        channel: Option<&str>,
        home: Option<&str>,
        action: &str,
        path: Option<&str>,
        root: Option<&str>,
    ) -> Request {
        let mut subject = Attributes::new();
        subject.insert("uid", AttrValue::Int(2001));
        if let Some(c) = channel {
            subject.insert(SUBJECT_CHANNEL, AttrValue::Str(c.into()));
        }
        if let Some(h) = home {
            subject.insert(SUBJECT_HOME, AttrValue::Str(h.into()));
        }
        if let Some(r) = root {
            subject.insert(SUBJECT_ROOT_TASKER, AttrValue::Str(r.into()));
        }
        let mut resource = Attributes::new();
        if let Some(p) = path {
            resource.insert("path", AttrValue::Str(p.into()));
        }
        Request {
            subject: Subject(subject),
            resource: Resource(resource),
            action: Action(action.into()),
            context: Context(Attributes::new()),
        }
    }

    fn person(mut r: Request) -> Request {
        r.subject
            .0
            .insert(SUBJECT_CHANNEL, AttrValue::Str(CHANNEL_CLIENT.into()));
        r
    }

    fn decide(r: &Request) -> Verdict {
        decide_partition(r, Fold::None)
    }

    fn denied(r: &Request) -> bool {
        matches!(decide(r), Verdict::Deny { ref reason } if reason.starts_with("partition: "))
    }

    const MINE: Option<&str> = Some("users/1000");

    #[test]
    fn another_taskers_partition_is_denied_on_every_file_verb() {
        for action in FILE_VERBS {
            for path in [
                "/home/hobi-svc/tasks/users/1001",
                "/home/hobi-svc/tasks/users/1001/notes",
                "/home/hobi-svc/tasks/users/10000",
                "/home/hobi-svc/tasks/agents/jin/x",
                "/home/hobi-svc/tasks/stray",
                "/home/hobi-svc/tasks/users/1000x",
            ] {
                assert!(
                    denied(&agent(action, Some(path), MINE)),
                    "{action} {path}: {:?}",
                    decide(&agent(action, Some(path), MINE))
                );
            }
            for path in [
                "/home/hobi-svc/tasks/users/1000",
                "/home/hobi-svc/tasks/users/1000/notes",
                "/home/hobi-svc/tasks/users/1000/a/b",
                "/home/hobi-svc/notes",
                "/home/hobi-svc/tasksx/users/1001",
                "/home/jin-svc/tasks/users/1001/x",
                "/etc/hosts",
            ] {
                assert_eq!(
                    decide(&agent(action, Some(path), MINE)),
                    NA,
                    "{action} {path}"
                );
            }
        }
    }

    #[test]
    fn an_uncited_request_cannot_touch_any_partition() {
        for action in FILE_VERBS {
            for path in [
                "/home/hobi-svc/tasks/users/1000",
                "/home/hobi-svc/tasks/users/1000/notes",
                "/home/hobi-svc/tasks/agents/jin",
            ] {
                assert!(denied(&agent(action, Some(path), None)), "{action} {path}");
            }
            assert_eq!(
                decide(&agent(action, Some("/home/hobi-svc/notes"), None)),
                NA
            );
        }
        assert_eq!(
            decide(&agent("fs.list", Some("/home/hobi-svc/tasks/users"), None)),
            NA
        );
    }

    #[test]
    fn a_sub_task_works_in_the_root_persons_partition() {
        let sub = |path| agent("fs.write", Some(path), Some("users/1000"));
        assert_eq!(decide(&sub("/home/hobi-svc/tasks/users/1000/out")), NA);
        assert!(denied(&sub("/home/hobi-svc/tasks/agents/jin/out")));
        let rooted_in_an_agent = agent(
            "fs.write",
            Some("/home/hobi-svc/tasks/agents/jin/out"),
            Some("agents/jin"),
        );
        assert_eq!(decide(&rooted_in_an_agent), NA);
    }

    #[test]
    fn ancestors_list_stat_and_mkdir_but_never_delete() {
        let ancestors = [
            "/home/hobi-svc/tasks",
            "/home/hobi-svc/tasks/users",
            "/home/hobi-svc/tasks/agents",
        ];
        for root in [MINE, None] {
            for path in ancestors {
                for action in ["fs.list", "fs.stat", "fs.mkdir"] {
                    assert_eq!(
                        decide(&agent(action, Some(path), root)),
                        NA,
                        "{action} {path}"
                    );
                }
                for action in ["fs.write", "fs.read", "fs.delete"] {
                    assert!(denied(&agent(action, Some(path), root)), "{action} {path}");
                }
            }
            for path in ["/home/hobi-svc", "/home", "/"] {
                assert_eq!(
                    decide(&agent("fs.delete", Some(path), root)),
                    Verdict::Deny {
                        reason: "partition: the delete would remove the tasks directory".into()
                    },
                    "{path}"
                );
                for action in ["fs.list", "fs.stat", "fs.mkdir", "fs.write", "fs.read"] {
                    assert_eq!(
                        decide(&agent(action, Some(path), root)),
                        NA,
                        "{action} {path}"
                    );
                }
            }
        }
        for op in [
            FsOperation::DeleteEntry,
            FsOperation::DeleteTree,
            FsOperation::Read,
        ] {
            let mut r = agent("fs.delete", Some("/home/hobi-svc"), MINE);
            r.context
                .0
                .insert(CONTEXT_FS_OPERATION, AttrValue::Str(op.as_str().into()));
            assert!(denied(&r), "{op:?}");
        }
        for op in [FsOperation::DeleteEntry, FsOperation::DeleteTree] {
            for action in ["fs.write", "fs.mkdir", "fs.list"] {
                let mut r = agent(action, Some("/home/hobi-svc"), MINE);
                r.context
                    .0
                    .insert(CONTEXT_FS_OPERATION, AttrValue::Str(op.as_str().into()));
                assert!(
                    denied(&r),
                    "{action} carrying {op:?} is decided as a delete"
                );
            }
        }
        assert_eq!(
            decide(&agent(
                "fs.delete",
                Some("/home/hobi-svc/tasks/users/1000"),
                MINE
            )),
            NA,
            "its own partition is the caller's to remove"
        );
        assert_eq!(
            decide(&agent("fs.delete", Some("/home/hobi-svc/projects"), MINE)),
            NA
        );
    }

    #[test]
    fn listing_the_partitions_root_shows_only_the_current_partition() {
        let entry = |dir: &str, name: &str, root| {
            let mut r = agent("fs.list", Some(&format!("{dir}/{name}")), root);
            r.context.0.insert(
                CONTEXT_FS_OPERATION,
                AttrValue::Str(FsOperation::Read.as_str().into()),
            );
            decide(&r) == NA
        };
        let users = "/home/hobi-svc/tasks/users";
        assert_eq!(decide(&agent("fs.list", Some(users), MINE)), NA);
        let shown: Vec<&str> = ["1000", "1001", "1002", "10000"]
            .into_iter()
            .filter(|n| entry(users, n, MINE))
            .collect();
        assert_eq!(shown, ["1000"]);
        let agents = "/home/hobi-svc/tasks/agents";
        assert!(!entry(agents, "jin", MINE));
        assert!(entry(agents, "jin", Some("agents/jin")));
        assert!(!entry(users, "1000", None), "no task cited, nothing shown");
        let tasks = "/home/hobi-svc/tasks";
        assert!(entry(tasks, "users", MINE) && entry(tasks, "agents", MINE));
        assert!(!entry(tasks, "stray", MINE));
    }

    #[test]
    fn the_shared_fold_decides_every_macos_spelling() {
        let folded = |path: &str| {
            let mut r = agent("fs.read", Some(path), Some("users/1000"));
            r.subject
                .0
                .insert(SUBJECT_HOME, AttrValue::Str("/Users/hobi".into()));
            decide_partition(&r, Fold::Case)
        };
        for other in [
            "/Users/hobi/tasks/users/1001/x",
            "/users/HOBI/TASKS/Users/1001/x",
            "/System/Volumes/Data/Users/hobi/tasks/users/1001/x",
            "/Users/hobi/Tasks/agents/caf\u{e9}/x",
            "/Users/hobi/tasks/AGENTS/cafe\u{301}/x",
        ] {
            assert!(
                matches!(folded(other), Verdict::Deny { .. }),
                "{other}: {:?}",
                folded(other)
            );
        }
        for own in [
            "/Users/hobi/tasks/users/1000/x",
            "/USERS/Hobi/TASKS/USERS/1000/x",
            "/System/Volumes/Data/Users/hobi/tasks/users/1000/x",
        ] {
            assert_eq!(folded(own), NA, "{own}");
        }
        let delete = |path: &str, home: &str| {
            let mut r = agent("fs.delete", Some(path), Some("users/1000"));
            r.subject
                .0
                .insert(SUBJECT_HOME, AttrValue::Str(home.into()));
            decide_partition(&r, Fold::Case)
        };
        for (path, home) in [
            ("/System/Volumes", "/Users/hobi"),
            ("/System/Volumes/Data/Users", "/Users/hobi"),
            ("/USERS/HOBI", "/Users/hobi"),
            ("/private", "/private/var/hobi"),
            ("/var", "/private/var/hobi"),
        ] {
            assert!(
                matches!(delete(path, home), Verdict::Deny { .. }),
                "{path} {home}"
            );
        }
        assert_eq!(delete("/private", "/Users/hobi"), NA);
        let mut cased = agent(
            "fs.read",
            Some("/home/hobi-svc/Tasks/users/1001/x"),
            Some("users/1000"),
        );
        assert_eq!(decide(&cased), NA, "without a fold, a spelling is a path");
        cased.resource.0.insert(
            "path",
            AttrValue::Str("/home/hobi-svc/tasks/users/1001/x".into()),
        );
        assert!(denied(&cased));
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn macos_spellings_of_another_partition_are_denied() {
        let op = PartitionOperand;
        for other in [
            "/home/hobi-svc/TASKS/users/1001/x",
            "/Home/Hobi-Svc/tasks/Users/1001/x",
            "/System/Volumes/Data/home/hobi-svc/tasks/users/1001/x",
        ] {
            assert!(
                matches!(
                    op.decide(&agent("fs.read", Some(other), MINE)),
                    Verdict::Deny { .. }
                ),
                "{other}"
            );
        }
        assert_eq!(
            op.decide(&agent(
                "fs.read",
                Some("/HOME/hobi-svc/Tasks/Users/1000/x"),
                MINE
            )),
            NA
        );
    }

    #[test]
    fn the_operand_abstains_for_people_and_never_permits() {
        let actions = FILE_VERBS.iter().copied().chain([
            "fs.move",
            "fs.link",
            "fs.chmod",
            "fs.chown",
            "session.prompt",
            "session.task",
            "admin.status",
        ]);
        for action in actions {
            for path in [
                Some("/home/hobi-svc/tasks/users/1001/x"),
                Some("/home/hobi-svc/tasks"),
                Some("/home/hobi-svc"),
                Some("/etc/hosts"),
                None,
            ] {
                for root in [MINE, None] {
                    let on_agent = agent(action, path, root);
                    assert!(
                        !matches!(decide(&on_agent), Verdict::Permit { .. }),
                        "{action} {path:?}"
                    );
                    assert_eq!(decide(&person(on_agent)), NA, "{action} {path:?}");
                    let unstamped = asked(None, Some(HOME), action, path, root);
                    let want = if action.starts_with("fs.") {
                        Verdict::Indeterminate
                    } else {
                        NA
                    };
                    assert_eq!(decide(&unstamped), want, "{action} {path:?}");
                }
            }
        }
        for action in [
            "session.prompt",
            "session.task",
            "admin.status",
            "fs",
            "fsx.read",
        ] {
            assert_eq!(
                decide(&agent(
                    action,
                    Some("/home/hobi-svc/tasks/users/1001"),
                    MINE
                )),
                NA,
                "{action}"
            );
        }
        let op = PartitionOperand;
        assert_eq!(op.backend_name(), "maknae-partition");
        assert_eq!(op.subjects(), None);
        assert!(matches!(
            op.decide_cited_all(&[agent(
                "fs.read",
                Some("/home/hobi-svc/tasks/users/1001"),
                MINE
            )])[0]
                .verdict,
            Verdict::Deny { .. }
        ));
    }

    #[test]
    fn move_link_chmod_chown_from_an_agent_are_indeterminate() {
        for action in ["fs.move", "fs.link", "fs.chmod", "fs.chown", "fs.reads"] {
            for path in ["/home/hobi-svc/tasks/users/1000/x", "/etc/hosts"] {
                assert_eq!(
                    decide(&agent(action, Some(path), MINE)),
                    Verdict::Indeterminate,
                    "{action} {path}"
                );
            }
        }
    }

    #[test]
    fn a_request_it_cannot_evaluate_is_indeterminate() {
        let ok = || agent("fs.read", Some("/home/hobi-svc/notes"), MINE);
        assert_eq!(decide(&ok()), NA);
        let homeless = asked(
            Some(CHANNEL_AGENT),
            None,
            "fs.read",
            Some("/home/hobi-svc/notes"),
            MINE,
        );
        assert_eq!(decide(&homeless), Verdict::Indeterminate);
        for home in [
            AttrValue::Int(1),
            AttrValue::Str("home/x".into()),
            AttrValue::Str("/home/../x".into()),
        ] {
            let mut r = ok();
            r.subject.0.insert(SUBJECT_HOME, home);
            assert_eq!(decide(&r), Verdict::Indeterminate);
        }
        assert_eq!(
            decide(&agent("fs.read", None, MINE)),
            Verdict::Indeterminate
        );
        for bad in ["home/x", "/home/../etc", "/home//x", "/home/x/"] {
            assert_eq!(
                decide(&agent("fs.read", Some(bad), MINE)),
                Verdict::Indeterminate,
                "{bad}"
            );
        }
        let mut typed = ok();
        typed.resource.0.insert("path", AttrValue::Int(1));
        assert_eq!(decide(&typed), Verdict::Indeterminate);
        for root in [
            AttrValue::Int(1000),
            AttrValue::Str("users".into()),
            AttrValue::Str("users/".into()),
            AttrValue::Str("users/..".into()),
            AttrValue::Str("users/.".into()),
            AttrValue::Str("users/1000/x".into()),
            AttrValue::Str("remote/x".into()),
            AttrValue::Str("/users/1000".into()),
        ] {
            let mut r = ok();
            r.subject.0.insert(SUBJECT_ROOT_TASKER, root.clone());
            assert_eq!(decide(&r), Verdict::Indeterminate, "{root:?}");
        }
        let mut channel = ok();
        channel
            .subject
            .0
            .insert(SUBJECT_CHANNEL, AttrValue::Str("gateway".into()));
        assert_eq!(decide(&channel), Verdict::Indeterminate);
        channel.subject.0.insert(SUBJECT_CHANNEL, AttrValue::Int(1));
        assert_eq!(decide(&channel), Verdict::Indeterminate);
        let mut kind = ok();
        kind.context
            .0
            .insert(CONTEXT_FS_OPERATION, AttrValue::Str("rename".into()));
        assert_eq!(decide(&kind), Verdict::Indeterminate);
        kind.context
            .0
            .insert(CONTEXT_FS_OPERATION, AttrValue::Int(1));
        assert_eq!(decide(&kind), Verdict::Indeterminate);
    }

    #[test]
    fn a_home_at_the_root_still_bounds_its_tasks() {
        let at_root = |action, path| {
            let mut r = agent(action, Some(path), MINE);
            r.subject.0.insert(SUBJECT_HOME, AttrValue::Str("/".into()));
            decide(&r)
        };
        assert!(matches!(
            at_root("fs.read", "/tasks/users/1001/x"),
            Verdict::Deny { .. }
        ));
        assert_eq!(at_root("fs.read", "/tasks/users/1000/x"), NA);
        assert!(matches!(at_root("fs.delete", "/"), Verdict::Deny { .. }));
    }
}
