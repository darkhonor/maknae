//! The `sensitive.yaml` operand (#617, ADR-0034): a mandatory deny, over the host list
//! and the conversation's personal list, on every file verb. It never permits, and an
//! `fs.*` action it does not decide is `Indeterminate`.

use std::path::Path;

use maknae_config::{Fold, SensitiveList};
use maknae_security::{
    AttrValue, Authorizer, Decided, FsOperation, Request, Verdict, CONTEXT_FS_OPERATION,
    CONTEXT_SENSITIVE_PERSONAL, SUBJECT_HOME,
};

pub const SENSITIVE_BACKEND_NAME: &str = "maknae-sensitive";

const FILE_VERBS: [&str; 6] = [
    "fs.read",
    "fs.write",
    "fs.delete",
    "fs.mkdir",
    "fs.stat",
    "fs.list",
];

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum SensitiveMatch {
    None,
    Host(String),
    Personal(String),
    Unbound,
}

/// The first host entry, then the first personal entry, matching `asked`. `Unbound`
/// only when neither matches and a `~` entry could not be evaluated without a home.
pub fn sensitive_match(
    asked: &Path,
    home: Option<&Path>,
    host: &SensitiveList,
    personal: &SensitiveList,
    fold: Fold,
) -> SensitiveMatch {
    first_match(asked, home, host, personal, fold, false)
}

/// As [`sensitive_match`], for any entry that could match `dir` or a path beneath it.
pub fn sensitive_subtree_match(
    dir: &Path,
    home: Option<&Path>,
    host: &SensitiveList,
    personal: &SensitiveList,
    fold: Fold,
) -> SensitiveMatch {
    first_match(dir, home, host, personal, fold, true)
}

fn first_match(
    asked: &Path,
    home: Option<&Path>,
    host: &SensitiveList,
    personal: &SensitiveList,
    fold: Fold,
    subtree: bool,
) -> SensitiveMatch {
    let test = |list: &SensitiveList| {
        if subtree {
            list.subtree_matching(asked, home, fold)
                .map(|m| m.map(str::to_owned))
        } else {
            list.matching(asked, home, fold)
                .map(|m| m.map(str::to_owned))
        }
    };
    let host = test(host);
    if let Ok(Some(entry)) = host {
        return SensitiveMatch::Host(entry);
    }
    let personal = test(personal);
    if let Ok(Some(entry)) = personal {
        return SensitiveMatch::Personal(entry);
    }
    if host.is_err() || personal.is_err() {
        SensitiveMatch::Unbound
    } else {
        SensitiveMatch::None
    }
}

/// The installed host `sensitive.yaml` list.
pub trait SensitiveNow {
    fn sensitive_now(&self) -> std::sync::Arc<SensitiveList>;
}

impl<B: maknae_authz_basic::Baseline> SensitiveNow for B {
    fn sensitive_now(&self) -> std::sync::Arc<SensitiveList> {
        std::sync::Arc::clone(self.snapshot().sensitive())
    }
}

/// The operand over one snapshot's host list; the composition builds it per decision
/// batch from the snapshot the baseline decides on.
pub struct SensitiveAuthorizer<'s> {
    host: &'s SensitiveList,
}

impl<'s> SensitiveAuthorizer<'s> {
    pub fn new(host: &'s SensitiveList) -> Self {
        Self { host }
    }
}

impl Authorizer for SensitiveAuthorizer<'_> {
    fn decide_cited_all(&self, reqs: &[Request]) -> Vec<Decided> {
        maknae_security::decide_each_cited(self, reqs)
    }

    fn decide(&self, req: &Request) -> Verdict {
        decide_sensitive(self.host, req, maknae_config::native_fold())
    }

    fn backend_name(&self) -> String {
        SENSITIVE_BACKEND_NAME.to_string()
    }
}

/// The composition's named field: it names the operand and contributes no subjects.
/// Decisions are made by a [`SensitiveAuthorizer`] over a snapshot, never by this.
pub struct SensitiveOperand;

impl Authorizer for SensitiveOperand {
    fn decide_cited_all(&self, reqs: &[Request]) -> Vec<Decided> {
        maknae_security::decide_each_cited(self, reqs)
    }

    fn decide(&self, _: &Request) -> Verdict {
        Verdict::Indeterminate
    }

    fn backend_name(&self) -> String {
        SENSITIVE_BACKEND_NAME.to_string()
    }
}

fn decide_sensitive(host: &SensitiveList, req: &Request, fold: Fold) -> Verdict {
    let action = req.action.0.as_str();
    if !FILE_VERBS.contains(&action) {
        return if action.starts_with("fs.") {
            Verdict::Indeterminate
        } else {
            Verdict::NotApplicable { note: None }
        };
    }
    let Some(AttrValue::Str(path)) = req.resource.0.get(maknae_authz_basic::RESOURCE_PATH_KEY)
    else {
        return Verdict::Indeterminate;
    };
    if crate::handler::lexical_pregate(path).is_err() {
        return Verdict::Indeterminate;
    }
    let home = match req.subject.0.get(SUBJECT_HOME) {
        None => None,
        Some(AttrValue::Str(h)) => Some(Path::new(h.as_str())),
        Some(_) => return Verdict::Indeterminate,
    };
    let personal = match req.context.0.get(CONTEXT_SENSITIVE_PERSONAL) {
        None => SensitiveList::empty(),
        Some(AttrValue::Set(entries)) => {
            match SensitiveList::from_entries(&entries.iter().cloned().collect::<Vec<_>>()) {
                Ok(list) => list,
                Err(_) => return Verdict::Indeterminate,
            }
        }
        Some(_) => return Verdict::Indeterminate,
    };
    let subtree = match req.context.0.get(CONTEXT_FS_OPERATION) {
        None => req.action.0 == "fs.delete",
        Some(AttrValue::Str(op)) => match FsOperation::parse(op) {
            Some(op) => {
                matches!(op, FsOperation::DeleteEntry | FsOperation::DeleteTree)
                    || req.action.0 == "fs.delete"
            }
            None => return Verdict::Indeterminate,
        },
        Some(_) => return Verdict::Indeterminate,
    };
    match first_match(Path::new(path), home, host, &personal, fold, subtree) {
        SensitiveMatch::None => Verdict::NotApplicable { note: None },
        SensitiveMatch::Host(entry) => Verdict::Deny {
            reason: format!("sensitive: host {entry}"),
        },
        SensitiveMatch::Personal(entry) => Verdict::Deny {
            reason: format!("sensitive: personal {entry}"),
        },
        SensitiveMatch::Unbound => Verdict::Indeterminate,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use maknae_security::{Action, Attributes, Context, Resource, Subject};
    use std::collections::BTreeSet;

    fn list(entries: &[&str]) -> SensitiveList {
        SensitiveList::from_entries(&entries.iter().map(|e| e.to_string()).collect::<Vec<_>>())
            .unwrap()
    }

    fn req(action: &str, path: Option<&str>, home: Option<&str>) -> Request {
        let mut subject = Attributes::new();
        subject.insert("uid", AttrValue::Int(1000));
        if let Some(h) = home {
            subject.insert(SUBJECT_HOME, AttrValue::Str(h.into()));
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

    fn with_op(mut r: Request, op: FsOperation) -> Request {
        r.context
            .0
            .insert(CONTEXT_FS_OPERATION, AttrValue::Str(op.as_str().into()));
        r
    }

    fn with_personal(mut r: Request, entries: &[&str]) -> Request {
        r.context.0.insert(
            CONTEXT_SENSITIVE_PERSONAL,
            AttrValue::Set(
                entries
                    .iter()
                    .map(|e| e.to_string())
                    .collect::<BTreeSet<_>>(),
            ),
        );
        r
    }

    fn deny(reason: &str) -> Verdict {
        Verdict::Deny {
            reason: reason.into(),
        }
    }

    const NA: Verdict = Verdict::NotApplicable { note: None };

    #[test]
    fn it_never_permits() {
        let host = list(&["/etc/shadow", "~/.ssh/**"]);
        let op = SensitiveAuthorizer::new(&host);
        let actions = FILE_VERBS.iter().chain(&[
            "session.prompt",
            "admin.status",
            "kernel.contain",
            "fs.unknown",
        ]);
        for action in actions {
            for path in ["/etc/shadow", "/home/u/.ssh/id", "/home/u/notes", "/"] {
                for home in [Some("/home/u"), None] {
                    let v = op.decide(&req(action, Some(path), home));
                    assert!(
                        !matches!(v, Verdict::Permit { .. }),
                        "{action} {path}: {v:?}"
                    );
                }
            }
        }
        assert_eq!(op.backend_name(), SENSITIVE_BACKEND_NAME);
    }

    #[test]
    fn it_abstains_off_the_file_verbs() {
        let host = list(&["/etc/shadow"]);
        let op = SensitiveAuthorizer::new(&host);
        for action in ["session.prompt", "admin.status", "fs", "fsx.read"] {
            assert_eq!(
                op.decide(&req(action, Some("/etc/shadow"), None)),
                NA,
                "{action}"
            );
        }
    }

    #[test]
    fn a_file_action_it_does_not_decide_fails_closed() {
        let host = list(&["/etc/shadow"]);
        let op = SensitiveAuthorizer::new(&host);
        for action in ["fs.move", "fs.link", "fs.chmod", "fs.chown", "fs.reads"] {
            for path in ["/etc/shadow", "/etc/hosts"] {
                assert_eq!(
                    op.decide(&req(action, Some(path), Some("/home/u"))),
                    Verdict::Indeterminate,
                    "{action} {path}"
                );
            }
        }
    }

    #[test]
    fn every_file_verb_is_decided() {
        let host = list(&["/etc/shadow"]);
        let op = SensitiveAuthorizer::new(&host);
        for action in FILE_VERBS {
            assert_eq!(
                op.decide(&req(action, Some("/etc/shadow"), Some("/home/u"))),
                deny("sensitive: host /etc/shadow"),
                "{action}"
            );
            assert_eq!(
                op.decide(&req(action, Some("/etc/hosts"), Some("/home/u"))),
                NA,
                "{action}"
            );
        }
    }

    #[test]
    fn a_host_match_denies_with_the_entry() {
        let host = list(&["/etc/passwd", "/etc/shadow"]);
        let op = SensitiveAuthorizer::new(&host);
        assert_eq!(
            op.decide(&req("fs.read", Some("/etc/shadow"), Some("/home/u"))),
            deny("sensitive: host /etc/shadow")
        );
    }

    #[test]
    fn a_personal_match_denies_from_the_context_set() {
        let host = list(&["/etc/shadow"]);
        let op = SensitiveAuthorizer::new(&host);
        let asked = req(
            "fs.read",
            Some("/home/u/.openrouter-api-key"),
            Some("/home/u"),
        );
        assert_eq!(op.decide(&asked), NA);
        assert_eq!(
            op.decide(&with_personal(asked, &["~/.openrouter-api-key"])),
            deny("sensitive: personal ~/.openrouter-api-key")
        );
    }

    #[test]
    fn the_host_entry_is_named_before_a_personal_one() {
        let host = list(&["~/.ssh/**"]);
        let op = SensitiveAuthorizer::new(&host);
        let asked = with_personal(
            req("fs.read", Some("/home/u/.ssh/id"), Some("/home/u")),
            &["~/.ssh/id"],
        );
        assert_eq!(op.decide(&asked), deny("sensitive: host ~/.ssh/**"));
    }

    #[test]
    fn an_unbound_home_is_indeterminate() {
        let host = list(&["~/.ssh/**", "/etc/shadow"]);
        let op = SensitiveAuthorizer::new(&host);
        assert_eq!(
            op.decide(&req("fs.read", Some("/home/u/.ssh/id"), None)),
            Verdict::Indeterminate
        );
        assert_eq!(
            op.decide(&req("fs.read", Some("/etc/shadow"), None)),
            deny("sensitive: host /etc/shadow")
        );
        let personal_only = list(&["/etc/shadow"]);
        let op = SensitiveAuthorizer::new(&personal_only);
        assert_eq!(
            op.decide(&with_personal(
                req("fs.read", Some("/home/u/notes"), None),
                &["~/.key"]
            )),
            Verdict::Indeterminate
        );
        assert_eq!(
            op.decide(&req("fs.read", Some("/home/u/notes"), None)),
            NA,
            "absolute entries alone need no home"
        );
    }

    #[test]
    fn every_delete_of_a_protected_parent_denies() {
        let host = list(&["~/.ssh/**"]);
        let op = SensitiveAuthorizer::new(&host);
        let home = Some("/home/u");
        assert_eq!(
            op.decide(&with_op(
                req("fs.delete", Some("/home/u"), home),
                FsOperation::DeleteTree
            )),
            deny("sensitive: host ~/.ssh/**")
        );
        assert_eq!(
            op.decide(&with_op(
                req("fs.delete", Some("/home/u"), home),
                FsOperation::DeleteEntry
            )),
            deny("sensitive: host ~/.ssh/**"),
            "an entry delete answers by path, not by whether the directory is empty"
        );
        assert_eq!(
            op.decide(&req("fs.delete", Some("/home/u"), home)),
            deny("sensitive: host ~/.ssh/**"),
            "a delete that names no operation is decided as a tree"
        );
        assert_eq!(
            op.decide(&with_op(
                req("fs.delete", Some("/home/u"), home),
                FsOperation::Read
            )),
            deny("sensitive: host ~/.ssh/**"),
            "a delete carrying any other operation is still decided as a tree"
        );
        assert_eq!(
            op.decide(&req("fs.write", Some("/home/u"), home)),
            NA,
            "only a delete is decided as a tree"
        );
        assert_eq!(
            op.decide(&with_op(
                req("fs.delete", Some("/home/u/projects"), home),
                FsOperation::DeleteTree
            )),
            NA
        );
    }

    #[test]
    fn a_malformed_request_is_indeterminate() {
        let host = list(&["/etc/shadow"]);
        let op = SensitiveAuthorizer::new(&host);
        let ok = || req("fs.read", Some("/etc/hosts"), Some("/home/u"));
        assert_eq!(op.decide(&ok()), NA);
        assert_eq!(
            op.decide(&req("fs.read", None, Some("/home/u"))),
            Verdict::Indeterminate
        );
        let mut typed = ok();
        typed.resource.0.insert("path", AttrValue::Int(1));
        assert_eq!(op.decide(&typed), Verdict::Indeterminate);
        for bad in [
            "etc/shadow",
            "/etc/../etc/shadow",
            "/etc//shadow",
            "/etc/shadow/",
        ] {
            assert_eq!(
                op.decide(&req("fs.read", Some(bad), Some("/home/u"))),
                Verdict::Indeterminate,
                "{bad}"
            );
        }
        let mut home = ok();
        home.subject.0.insert(SUBJECT_HOME, AttrValue::Int(1));
        assert_eq!(op.decide(&home), Verdict::Indeterminate);
        let mut personal = ok();
        personal
            .context
            .0
            .insert(CONTEXT_SENSITIVE_PERSONAL, AttrValue::Str("~/.key".into()));
        assert_eq!(op.decide(&personal), Verdict::Indeterminate);
        assert_eq!(
            op.decide(&with_personal(ok(), &["~name/x"])),
            Verdict::Indeterminate
        );
        assert_eq!(op.decide(&with_personal(ok(), &["~/.key"])), NA);
        let mut kind = ok();
        kind.context
            .0
            .insert(CONTEXT_FS_OPERATION, AttrValue::Str("rename".into()));
        assert_eq!(op.decide(&kind), Verdict::Indeterminate);
        kind.context
            .0
            .insert(CONTEXT_FS_OPERATION, AttrValue::Int(1));
        assert_eq!(op.decide(&kind), Verdict::Indeterminate);
    }

    #[test]
    fn sensitive_match_names_the_list_and_the_entry() {
        let host = list(&["/etc/shadow", "~/.ssh/**"]);
        let personal = list(&["~/.key"]);
        let home = Some(Path::new("/home/u"));
        let m = |p: &str, h| sensitive_match(Path::new(p), h, &host, &personal, Fold::None);
        assert_eq!(
            m("/etc/shadow", home),
            SensitiveMatch::Host("/etc/shadow".into())
        );
        assert_eq!(
            m("/home/u/.ssh/a", home),
            SensitiveMatch::Host("~/.ssh/**".into())
        );
        assert_eq!(
            m("/home/u/.key", home),
            SensitiveMatch::Personal("~/.key".into())
        );
        assert_eq!(m("/home/u/notes", home), SensitiveMatch::None);
        assert_eq!(m("/home/u/notes", None), SensitiveMatch::Unbound);
        assert_eq!(
            m("/etc/shadow", None),
            SensitiveMatch::Host("/etc/shadow".into())
        );
        assert_eq!(
            sensitive_match(
                Path::new("/home/u/.ssh"),
                home,
                &list(&["~/.ssh/id"]),
                &SensitiveList::empty(),
                Fold::None
            ),
            SensitiveMatch::None,
            "an exact match is not a subtree match"
        );
    }

    #[test]
    fn the_case_fold_is_the_native_one() {
        let host = list(&["/Users/u/.ssh/**"]);
        let op = SensitiveAuthorizer::new(&host);
        let v = op.decide(&req("fs.read", Some("/Users/u/.SSH/id"), Some("/Users/u")));
        if cfg!(target_os = "macos") {
            assert_eq!(v, deny("sensitive: host /Users/u/.ssh/**"));
        } else {
            assert_eq!(v, NA);
        }
    }

    #[test]
    fn the_marker_decides_nothing() {
        let op = SensitiveOperand;
        assert_eq!(
            op.decide(&req("admin.status", None, None)),
            Verdict::Indeterminate
        );
        assert_eq!(
            op.decide_cited_all(&[req("fs.read", Some("/x"), None)])[0].verdict,
            Verdict::Indeterminate
        );
        assert_eq!(op.backend_name(), "maknae-sensitive");
        assert_eq!(op.subjects(), None);
    }
}
