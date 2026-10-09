use crate::bindings::{entry, section_roles, BindingEntry, Bindings, BindingsError, RoleRuleError};
use crate::value::{canonical_json, Value};
use std::collections::{BTreeMap, BTreeSet};

const MISSING: &str = "missing";
const ABSENT: &str = "null";
const ADVERSARY: &str = "adversary";
const BOUND: [&str; 3] = ["admin", "user", "guest"];

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Section {
    Missing,
    Absent,
    Present(BTreeMap<String, Vec<BindingEntry>>),
}

fn entry_value(e: &BindingEntry) -> Value {
    match e {
        BindingEntry::Name(n) => Value::Str(n.clone()),
        BindingEntry::Uid(u) => Value::Map(vec![("uid".into(), Value::Int(i64::from(*u)))]),
    }
}

impl Section {
    pub fn of(b: &Bindings) -> Self {
        match (&b.roles, b.is_missing()) {
            (_, true) => Self::Missing,
            (None, false) => Self::Absent,
            (Some(m), false) => Self::Present(m.clone()),
        }
    }

    pub fn canonical(&self) -> String {
        match self {
            Self::Missing => MISSING.into(),
            Self::Absent => ABSENT.into(),
            Self::Present(m) => canonical_json(&Value::Map(
                m.iter()
                    .map(|(k, v)| (k.clone(), Value::Seq(v.iter().map(entry_value).collect())))
                    .collect(),
            )),
        }
    }

    pub fn from_canonical(s: &str) -> Result<Self, BindingsError> {
        match s {
            MISSING => return Ok(Self::Missing),
            ABSENT => return Ok(Self::Absent),
            _ => {}
        }
        let v =
            crate::value_from_canonical_json(s).map_err(|e| BindingsError::Yaml(e.to_string()))?;
        let section = Self::Present(section_roles(&v)?);
        crate::check_roles(&Bindings::from_section(&section))
            .map_err(|e| BindingsError::Yaml(e.to_string()))?;
        Ok(section)
    }

    pub fn roles_of(&self, e: &BindingEntry) -> BTreeSet<&str> {
        match self {
            Self::Present(m) => m
                .iter()
                .filter(|(_, v)| v.contains(e))
                .map(|(k, _)| k.as_str())
                .collect(),
            _ => BTreeSet::new(),
        }
    }

    pub fn entries(&self) -> Vec<&BindingEntry> {
        let mut out: Vec<&BindingEntry> = Vec::new();
        if let Self::Present(m) = self {
            for e in m.values().flatten() {
                if !out.contains(&e) {
                    out.push(e);
                }
            }
        }
        out
    }
}

pub fn conflicts_canonical(c: &BTreeSet<BindingEntry>) -> String {
    canonical_json(&Value::Seq(c.iter().map(entry_value).collect()))
}

pub fn conflicts_from_canonical(s: &str) -> Result<BTreeSet<BindingEntry>, BindingsError> {
    let Value::Seq(items) =
        crate::value_from_canonical_json(s).map_err(|e| BindingsError::Yaml(e.to_string()))?
    else {
        return Err(BindingsError::Yaml("a conflict list is a sequence".into()));
    };
    let set: BTreeSet<BindingEntry> = items.iter().map(entry).collect::<Result<_, _>>()?;
    if conflicts_canonical(&set) != s {
        return Err(BindingsError::Yaml(
            "a conflict list is sorted and unique".into(),
        ));
    }
    Ok(set)
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SyncKind {
    Created,
    Unchanged,
    Adopted,
    RootFile,
    Lost,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ResolvedBy {
    RootEdit,
    Sync,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum MergeEvent {
    Conflict {
        entry: BindingEntry,
        contained: bool,
    },
    Resolved {
        entry: BindingEntry,
        by: ResolvedBy,
    },
    /// Base is present and the file is missing (`missing`) or has no `bindings:` key (#491).
    Lost {
        missing: bool,
    },
}

pub struct Stored<'a> {
    pub base: &'a Section,
    pub live: &'a Section,
    pub conflicts: &'a BTreeSet<BindingEntry>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Merged {
    pub base: Section,
    pub live: Section,
    pub conflicts: BTreeSet<BindingEntry>,
    pub kind: SyncKind,
    pub events: Vec<MergeEvent>,
}

type Values<'a> = Vec<(BindingEntry, BTreeSet<&'a str>)>;

fn merged_section(shape: &Section, live: &Section, values: &Values<'_>) -> Section {
    let Section::Present(file) = shape else {
        return shape.clone();
    };
    let value: BTreeMap<&BindingEntry, &BTreeSet<&str>> =
        values.iter().map(|(e, r)| (e, r)).collect();
    let mut out: BTreeMap<String, Vec<BindingEntry>> =
        file.keys().map(|k| (k.clone(), Vec::new())).collect();
    let mut add = |role: &str, e: &BindingEntry| {
        if value.get(e).is_some_and(|r| r.contains(role)) {
            let list = out.entry(role.to_string()).or_default();
            if !list.contains(e) {
                list.push(e.clone());
            }
        }
    };
    let empty = BTreeMap::new();
    let live = match live {
        Section::Present(m) => m,
        _ => &empty,
    };
    for (role, list) in file.iter().chain(live) {
        for e in list {
            add(role, e);
        }
    }
    for (e, roles) in values {
        for role in roles {
            add(role, e);
        }
    }
    Section::Present(out)
}

pub fn merge(stored: Option<Stored<'_>>, file: &Section) -> Merged {
    let Some(st) = stored else {
        return Merged {
            base: file.clone(),
            live: file.clone(),
            conflicts: BTreeSet::new(),
            kind: SyncKind::Created,
            events: Vec::new(),
        };
    };
    if matches!(st.base, Section::Present(_)) && !matches!(file, Section::Present(_)) {
        return Merged {
            base: st.base.clone(),
            live: st.live.clone(),
            conflicts: st.conflicts.clone(),
            kind: SyncKind::Lost,
            events: vec![MergeEvent::Lost {
                missing: *file == Section::Missing,
            }],
        };
    }
    let mut universe: Vec<&BindingEntry> = file.entries();
    for e in st
        .live
        .entries()
        .into_iter()
        .chain(st.base.entries())
        .chain(st.conflicts.iter())
    {
        if !universe.contains(&e) {
            universe.push(e);
        }
    }
    let mut values: Values<'_> = Vec::new();
    let (mut conflicts, mut events) = (BTreeSet::new(), Vec::new());
    let (mut root, mut agreed) = (false, false);
    for e in universe {
        let (b, l, f) = (st.base.roles_of(e), st.live.roles_of(e), file.roles_of(e));
        let value = if st.conflicts.contains(e) {
            if f != b || f == l {
                let by = if f == l {
                    ResolvedBy::Sync
                } else {
                    ResolvedBy::RootEdit
                };
                root |= by == ResolvedBy::RootEdit;
                agreed |= by == ResolvedBy::Sync;
                events.push(MergeEvent::Resolved {
                    entry: e.clone(),
                    by,
                });
                f
            } else {
                conflicts.insert(e.clone());
                l
            }
        } else if f == b {
            l
        } else if l == b {
            root = true;
            f
        } else if f == l {
            agreed = true;
            f
        } else {
            root = true;
            let safe: BTreeSet<&str> = if f.contains(ADVERSARY) || l.contains(ADVERSARY) {
                [ADVERSARY].into()
            } else {
                BTreeSet::new()
            };
            if safe != f {
                events.push(MergeEvent::Conflict {
                    entry: e.clone(),
                    contained: !safe.is_empty(),
                });
                conflicts.insert(e.clone());
            }
            safe
        };
        values.push((e.clone(), value));
    }
    let text_changed = file.canonical() != st.base.canonical();
    let kind = if root {
        SyncKind::RootFile
    } else if agreed || (text_changed && file.canonical() == st.live.canonical()) {
        SyncKind::Adopted
    } else if text_changed {
        SyncKind::RootFile
    } else {
        SyncKind::Unchanged
    };
    let live = merged_section(file, st.live, &values);
    Merged {
        base: file.clone(),
        live,
        conflicts,
        kind,
        events,
    }
}

fn differs(a: &Section, b: &Section, e: &BindingEntry) -> bool {
    a.roles_of(e) != b.roles_of(e)
}

pub fn unsynced(base: &Section, live: &Section) -> usize {
    let mut seen: BTreeSet<&BindingEntry> = BTreeSet::new();
    base.entries()
        .into_iter()
        .chain(live.entries())
        .filter(|e| seen.insert(e) && differs(base, live, e))
        .count()
}

pub fn equivalent(a: &Section, b: &Section) -> bool {
    matches!(a, Section::Present(_)) == matches!(b, Section::Present(_))
        && !a
            .entries()
            .into_iter()
            .chain(b.entries())
            .any(|e| differs(a, b, e))
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BoundRole {
    Admin,
    User,
    Guest,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum LiveEdit {
    Contain(BindingEntry),
    Release(BindingEntry),
    Bind { name: String, role: BoundRole },
    Unbind(String),
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum EditError {
    NoExplicitBindings,
    Rules(RoleRuleError),
}

impl std::fmt::Display for EditError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::NoExplicitBindings => f.write_str(
                "bindings.yaml has no bindings: key; a live identity edit needs explicit bindings",
            ),
            Self::Rules(e) => e.fmt(f),
        }
    }
}

impl std::error::Error for EditError {}

impl BoundRole {
    fn key(self) -> &'static str {
        match self {
            Self::Admin => "admin",
            Self::User => "user",
            Self::Guest => "guest",
        }
    }
}

pub fn apply_edit(
    base: &Section,
    live: &Section,
    edit: &LiveEdit,
) -> Result<Option<Section>, EditError> {
    if !matches!(live, Section::Present(_)) {
        return Err(EditError::NoExplicitBindings);
    }
    let named;
    let target = match edit {
        LiveEdit::Contain(e) | LiveEdit::Release(e) => e,
        LiveEdit::Bind { name, .. } | LiveEdit::Unbind(name) => {
            named = BindingEntry::Name(name.clone());
            &named
        }
    };
    let old = live.roles_of(target);
    let mut new = old.clone();
    match edit {
        LiveEdit::Contain(_) => {
            new.insert(ADVERSARY);
        }
        LiveEdit::Release(_) => {
            new.remove(ADVERSARY);
        }
        LiveEdit::Bind { role, .. } => {
            new.retain(|r| !BOUND.contains(r));
            new.insert(role.key());
        }
        LiveEdit::Unbind(_) => new.retain(|r| !BOUND.contains(r)),
    }
    if new == old {
        return Ok(None);
    }
    let mut values: Values<'_> = live
        .entries()
        .into_iter()
        .filter(|e| *e != target)
        .map(|e| (e.clone(), live.roles_of(e)))
        .collect();
    values.push((target.clone(), new));
    let next = merged_section(base, live, &values);
    crate::check_roles(&Bindings::from_section(&next)).map_err(EditError::Rules)?;
    Ok(Some(next))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{parse_bindings, Bindings};

    const FIXTURES: [&str; 6] = [
        "schema_version: 1\n",
        "schema_version: 1\nbindings: {}\n",
        "schema_version: 1\nbindings:\n  guest: []\n",
        "schema_version: 1\nbindings:\n  user: [\"bob\", \"carol\"]\n  admin: [\"alice\"]\n",
        "schema_version: 1\nbindings:\n  adversary:\n    - \"mallory\"\n    - uid: 4242\n    - uid: 0\n",
        "schema_version: 1\nbindings:\n  admin: [\"a\\\"b\\\\c\", \"\\u00e9\"]\n  adversary: [\"a\\\"b\\\\c\"]\n",
    ];

    #[test]
    fn a_section_prints_the_text_the_parser_hashes() {
        for f in FIXTURES {
            let b = parse_bindings(f).unwrap();
            let s = Section::of(&b);
            assert_eq!(
                s.canonical(),
                b.section_canonical().unwrap_or("null"),
                "{f}"
            );
            assert_eq!(Section::from_canonical(&s.canonical()).unwrap(), s, "{f}");
            assert_eq!(Bindings::from_section(&s), b, "{f}");
        }
        assert_eq!(Section::of(&Bindings::missing()).canonical(), "missing");
        assert_eq!(
            Section::from_canonical("missing").unwrap(),
            Section::Missing
        );
        assert_eq!(Section::from_canonical("null").unwrap(), Section::Absent);
        assert_eq!(
            Bindings::from_section(&Section::Missing),
            Bindings::missing()
        );
        assert_eq!(Bindings::from_section(&Section::Absent), Bindings::absent());
    }

    #[test]
    fn from_canonical_takes_canonical_text_only() {
        for bad in [
            "",
            "{ }",
            r#"{"user":["b"],"admin":["a"]}"#,
            r#"{"admin":"a"}"#,
            "[]",
            "\"null\"",
            r#"{"admin":[{"uid":7}]}"#,
            r#"{"root":["a"]}"#,
            r#"{"admin":["a","a"]}"#,
        ] {
            assert!(Section::from_canonical(bad).is_err(), "{bad:?}");
        }
    }

    #[test]
    fn roles_of_an_entry_is_every_list_holding_it() {
        let s = Section::of(&parse_bindings(
            "schema_version: 1\nbindings:\n  user: [\"eve\"]\n  adversary: [\"eve\", {uid: 7}]\n",
        ).unwrap());
        let eve = BindingEntry::Name("eve".into());
        assert_eq!(
            s.roles_of(&eve).into_iter().collect::<Vec<_>>(),
            ["adversary", "user"]
        );
        assert!(Section::Absent.roles_of(&eve).is_empty());
        assert_eq!(s.entries(), [&eve, &BindingEntry::Uid(7)]);
    }

    #[test]
    fn the_conflict_list_round_trips_in_entry_order() {
        let c: BTreeSet<_> = [
            BindingEntry::Uid(7),
            BindingEntry::Name("b".into()),
            BindingEntry::Name("a".into()),
        ]
        .into();
        assert_eq!(conflicts_canonical(&c), r#"["a","b",{"uid":7}]"#);
        assert_eq!(
            conflicts_from_canonical(&conflicts_canonical(&c)).unwrap(),
            c
        );
        assert_eq!(conflicts_canonical(&BTreeSet::new()), "[]");
        for bad in [
            "",
            r#"["b","a"]"#,
            r#"["a","a"]"#,
            r#"[1]"#,
            r#"[""]"#,
            r#"["a:b"]"#,
        ] {
            assert!(conflicts_from_canonical(bad).is_err(), "{bad:?}");
        }
    }

    const DOMAIN: [&[&str]; 6] = [
        &[],
        &["admin"],
        &["user"],
        &["guest"],
        &["adversary"],
        &["adversary", "user"],
    ];

    fn section_with(e: &BindingEntry, roles: &[&str]) -> Section {
        let mut m: BTreeMap<String, Vec<BindingEntry>> = BTreeMap::new();
        m.insert("guest".into(), Vec::new());
        for r in roles {
            m.entry((*r).into()).or_default().push(e.clone());
        }
        Section::Present(m)
    }

    fn oracle(
        base: &[&'static str],
        live: &[&'static str],
        file: &[&'static str],
        listed: bool,
    ) -> (BTreeSet<&'static str>, bool) {
        let set = |v: &[&'static str]| v.iter().copied().collect::<BTreeSet<&'static str>>();
        let (b, l, f) = (set(base), set(live), set(file));
        let fail_closed = if f.contains("adversary") || l.contains("adversary") {
            set(&["adversary"])
        } else {
            BTreeSet::new()
        };
        if listed {
            return if f != b || f == l {
                (f, false)
            } else {
                (l, true)
            };
        }
        if f == b {
            (l, false)
        } else if l == b || f == l || fail_closed == f {
            (f, false)
        } else {
            (fail_closed, true)
        }
    }

    fn state(s: &Section) -> u8 {
        match s {
            Section::Missing => 0,
            Section::Absent => 1,
            Section::Present(_) => 2,
        }
    }

    #[test]
    fn merge_matches_the_truth_table_for_every_value_triple() {
        let e = BindingEntry::Name("e".into());
        let mut checked = 0;
        let present = |v: &[&'static str]| (section_with(&e, v), v.to_vec());
        let mut bases: Vec<(Section, Vec<&'static str>)> =
            DOMAIN.iter().map(|v| present(v)).collect();
        bases.extend([(Section::Absent, vec![]), (Section::Missing, vec![])]);
        let mut files = bases.clone();
        files.truncate(DOMAIN.len());
        files.extend([(Section::Absent, vec![]), (Section::Missing, vec![])]);
        for (b, base) in &bases {
            let lives: Vec<(Section, Vec<&'static str>)> = match b {
                Section::Present(_) => DOMAIN.iter().map(|v| present(v)).collect(),
                other => vec![(other.clone(), vec![])],
            };
            for (l, live) in &lives {
                for (f, file) in &files {
                    for listed in [false, true] {
                        let prior: BTreeSet<_> = if listed {
                            [e.clone()].into()
                        } else {
                            BTreeSet::new()
                        };
                        let m = merge(
                            Some(Stored {
                                base: b,
                                live: l,
                                conflicts: &prior,
                            }),
                            f,
                        );
                        let lost =
                            matches!(b, Section::Present(_)) && !matches!(f, Section::Present(_));
                        let at = format!("base {b:?} live {l:?} file {f:?} listed {listed}");
                        if lost {
                            assert_eq!(
                                (m.kind, &m.base, &m.live, &m.conflicts),
                                (SyncKind::Lost, b, l, &prior),
                                "{at}"
                            );
                            assert_eq!(
                                m.events,
                                [MergeEvent::Lost {
                                    missing: *f == Section::Missing
                                }],
                                "{at}"
                            );
                        } else {
                            let (want, conflict) = oracle(base, live, file, listed);
                            assert_eq!(m.live.roles_of(&e), want, "{at}");
                            assert_eq!(m.conflicts.contains(&e), conflict, "{at}");
                            assert_eq!(&m.base, f, "base := the file: {at}");
                        }
                        assert_eq!(
                            state(&m.live),
                            state(&m.base),
                            "live and base keep one state: {at}"
                        );
                        checked += 1;
                    }
                }
            }
        }
        assert_eq!(checked, 6 * 6 * 8 * 2 + 2 * 8 * 2);
    }

    #[test]
    fn a_lost_file_keeps_base_live_and_conflicts() {
        let s = |b: &str| Section::of(&crate::parse_bindings(b).unwrap());
        let base = s("schema_version: 1\nbindings:\n  admin: [\"a\"]\n");
        let live = s("schema_version: 1\nbindings:\n  admin: [\"a\"]\n  adversary: [\"m\"]\n");
        let listed: BTreeSet<_> = [BindingEntry::Name("m".into())].into();
        for (file, missing) in [(Section::Absent, false), (Section::Missing, true)] {
            let m = merge(
                Some(Stored {
                    base: &base,
                    live: &live,
                    conflicts: &listed,
                }),
                &file,
            );
            assert_eq!(
                m,
                Merged {
                    base: base.clone(),
                    live: live.clone(),
                    conflicts: listed.clone(),
                    kind: SyncKind::Lost,
                    events: vec![MergeEvent::Lost { missing }]
                }
            );
        }
    }

    #[test]
    fn a_file_that_adds_bindings_over_an_absent_base_is_a_root_edit() {
        let s = |b: &str| Section::of(&crate::parse_bindings(b).unwrap());
        let file = s("schema_version: 1\nbindings:\n  admin: [\"a\"]\n");
        for base in [Section::Absent, Section::Missing] {
            let m = merge(
                Some(Stored {
                    base: &base,
                    live: &base,
                    conflicts: &BTreeSet::new(),
                }),
                &file,
            );
            assert_eq!(
                (m.kind, m.base.clone(), m.live.clone()),
                (SyncKind::RootFile, file.clone(), file.clone())
            );
            assert!(m.events.is_empty());
        }
        let m = merge(
            Some(Stored {
                base: &Section::Absent,
                live: &Section::Absent,
                conflicts: &BTreeSet::new(),
            }),
            &Section::Missing,
        );
        assert_eq!(
            (m.kind, m.live),
            (SyncKind::RootFile, Section::Missing),
            "absent to missing with nothing enforced is not a loss"
        );
    }

    #[test]
    fn every_conflict_and_resolution_is_an_event() {
        let e = BindingEntry::Name("e".into());
        let none = BTreeSet::new();
        let (b, l, f) = (
            section_with(&e, &["user"]),
            section_with(&e, &["guest"]),
            section_with(&e, &["admin"]),
        );
        let m = merge(
            Some(Stored {
                base: &b,
                live: &l,
                conflicts: &none,
            }),
            &f,
        );
        assert_eq!(
            m.events,
            [MergeEvent::Conflict {
                entry: e.clone(),
                contained: false
            }]
        );
        assert_eq!(m.kind, SyncKind::RootFile);
        let l2 = section_with(&e, &["adversary"]);
        let m = merge(
            Some(Stored {
                base: &b,
                live: &l2,
                conflicts: &none,
            }),
            &f,
        );
        assert_eq!(
            m.events,
            [MergeEvent::Conflict {
                entry: e.clone(),
                contained: true
            }]
        );
        let listed: BTreeSet<_> = [e.clone()].into();
        let again = section_with(&e, &["guest"]);
        let m = merge(
            Some(Stored {
                base: &f,
                live: &l2,
                conflicts: &listed,
            }),
            &again,
        );
        assert_eq!(
            m.events,
            [MergeEvent::Resolved {
                entry: e.clone(),
                by: ResolvedBy::RootEdit
            }]
        );
        let m = merge(
            Some(Stored {
                base: &f,
                live: &l2,
                conflicts: &listed,
            }),
            &l2,
        );
        assert_eq!(
            m.events,
            [MergeEvent::Resolved {
                entry: e.clone(),
                by: ResolvedBy::Sync
            }]
        );
        assert_eq!(m.kind, SyncKind::Adopted);
    }

    #[test]
    fn the_kind_is_created_unchanged_adopted_or_root_file() {
        let s = |b: &str| Section::of(&crate::parse_bindings(b).unwrap());
        let (a, c) = (
            s("schema_version: 1\nbindings:\n  admin: [\"a\"]\n"),
            s("schema_version: 1\nbindings:\n  admin: [\"a\"]\n  adversary: [\"m\"]\n"),
        );
        let none = BTreeSet::new();
        assert_eq!(
            merge(None, &a),
            Merged {
                base: a.clone(),
                live: a.clone(),
                conflicts: none.clone(),
                kind: SyncKind::Created,
                events: vec![]
            }
        );
        assert_eq!(
            merge(
                Some(Stored {
                    base: &a,
                    live: &c,
                    conflicts: &none
                }),
                &a
            )
            .kind,
            SyncKind::Unchanged
        );
        assert_eq!(
            merge(
                Some(Stored {
                    base: &a,
                    live: &c,
                    conflicts: &none
                }),
                &a
            )
            .live
            .canonical(),
            c.canonical(),
            "unchanged keeps live"
        );
        let adopted = merge(
            Some(Stored {
                base: &a,
                live: &c,
                conflicts: &none,
            }),
            &c,
        );
        assert_eq!(
            (adopted.kind, adopted.base.clone(), adopted.live.clone()),
            (SyncKind::Adopted, c.clone(), c.clone())
        );
        let other = s("schema_version: 1\nbindings:\n  admin: [\"a\", \"b\"]\n");
        let m = merge(
            Some(Stored {
                base: &a,
                live: &c,
                conflicts: &none,
            }),
            &other,
        );
        assert_eq!(m.kind, SyncKind::RootFile);
        assert_eq!(
            m.live,
            s("schema_version: 1\nbindings:\n  admin: [\"a\", \"b\"]\n  adversary: [\"m\"]\n"),
            "root's edit and the live edit both stand"
        );
    }

    #[test]
    fn a_resolution_decides_the_kind_beside_other_entries() {
        let s = |b: &str| Section::of(&crate::parse_bindings(b).unwrap());
        let base = s("schema_version: 1\nbindings:\n  admin: [\"e\"]\n");
        let live = s("schema_version: 1\nbindings:\n  user: [\"x\"]\n  adversary: [\"e\"]\n");
        let listed: BTreeSet<_> = [BindingEntry::Name("e".into())].into();
        let stored = || Stored {
            base: &base,
            live: &live,
            conflicts: &listed,
        };
        let root = merge(
            Some(stored()),
            &s("schema_version: 1\nbindings:\n  guest: [\"e\"]\n  user: [\"x\"]\n"),
        );
        assert_eq!(
            root.kind,
            SyncKind::RootFile,
            "a root edit beside an agreed entry"
        );
        let synced = merge(
            Some(stored()),
            &s("schema_version: 1\nbindings:\n  adversary: [\"e\"]\n"),
        );
        assert_eq!(
            synced.kind,
            SyncKind::Adopted,
            "a sync beside a kept live edit"
        );
    }

    #[test]
    fn a_collision_whose_safe_value_root_already_wrote_is_not_listed() {
        let e = BindingEntry::Name("e".into());
        let none = BTreeSet::new();
        let (b, l, f) = (
            section_with(&e, &["user"]),
            section_with(&e, &["adversary", "user"]),
            section_with(&e, &["adversary"]),
        );
        let m = merge(
            Some(Stored {
                base: &b,
                live: &l,
                conflicts: &none,
            }),
            &f,
        );
        assert_eq!(m.live.roles_of(&e), ["adversary"].into());
        assert!(m.conflicts.is_empty() && m.events.is_empty(), "{m:?}");
        assert_eq!(m.kind, SyncKind::RootFile);
        let again = merge(
            Some(Stored {
                base: &m.base,
                live: &m.live,
                conflicts: &m.conflicts,
            }),
            &f,
        );
        assert_eq!(
            (again.kind, again.live.clone()),
            (SyncKind::Unchanged, m.live.clone()),
            "nothing stuck at the next load"
        );
    }

    #[test]
    fn an_unchanged_file_returns_live_byte_for_byte() {
        let s = |b: &str| Section::of(&crate::parse_bindings(b).unwrap());
        let base = s("schema_version: 1\nbindings:\n  user: [\"a\", \"b\"]\n");
        let live = s(
            "schema_version: 1\nbindings:\n  user: [\"a\", \"b\", \"z\"]\n  adversary: [\"m\"]\n",
        );
        let listed: BTreeSet<_> = [BindingEntry::Name("m".into())].into();
        for c in [BTreeSet::new(), listed] {
            let m = merge(
                Some(Stored {
                    base: &base,
                    live: &live,
                    conflicts: &c,
                }),
                &base,
            );
            assert_eq!(
                (m.kind, m.live.canonical(), m.conflicts.clone()),
                (SyncKind::Unchanged, live.canonical(), c.clone())
            );
        }
    }

    #[test]
    fn the_kind_is_derived_per_entry() {
        let s = |b: &str| Section::of(&crate::parse_bindings(b).unwrap());
        let base = s("schema_version: 1\nbindings:\n  user: [\"a\"]\n");
        let live = s("schema_version: 1\nbindings:\n  user: [\"a\"]\n  adversary: [\"m\"]\n");
        let reordered = s(
            "schema_version: 1\nbindings:\n  adversary: [\"m\"]\n  user: [\"a\"]\n  guest: []\n",
        );
        let none = BTreeSet::new();
        assert_eq!(
            merge(
                Some(Stored {
                    base: &base,
                    live: &live,
                    conflicts: &none
                }),
                &reordered
            )
            .kind,
            SyncKind::Adopted,
            "agreement without byte equality"
        );
        let mixed =
            s("schema_version: 1\nbindings:\n  user: [\"a\", \"b\"]\n  adversary: [\"m\"]\n");
        assert_eq!(
            merge(
                Some(Stored {
                    base: &base,
                    live: &live,
                    conflicts: &none
                }),
                &mixed
            )
            .kind,
            SyncKind::RootFile,
            "an agreed entry and a root edit is a root edit"
        );
    }

    #[test]
    fn merged_entries_keep_file_order_then_live_additions() {
        let s = |b: &str| Section::of(&crate::parse_bindings(b).unwrap());
        let base = s("schema_version: 1\nbindings:\n  user: [\"b\", \"a\"]\n");
        let live = s("schema_version: 1\nbindings:\n  user: [\"b\", \"a\", \"z\"]\n");
        let file = s("schema_version: 1\nbindings:\n  user: [\"c\", \"a\", \"b\"]\n");
        let m = merge(
            Some(Stored {
                base: &base,
                live: &live,
                conflicts: &BTreeSet::new(),
            }),
            &file,
        );
        assert_eq!(
            m.live.canonical(),
            s("schema_version: 1\nbindings:\n  user: [\"c\", \"a\", \"b\", \"z\"]\n").canonical()
        );
    }

    #[test]
    fn a_reorder_or_an_empty_key_is_roots_edit_and_settles() {
        let s = |b: &str| Section::of(&crate::parse_bindings(b).unwrap());
        let base = s("schema_version: 1\nbindings:\n  user: [\"a\", \"b\"]\n");
        let none = BTreeSet::new();
        for file in [
            s("schema_version: 1\nbindings:\n  user: [\"b\", \"a\"]\n"),
            s("schema_version: 1\nbindings:\n  user: [\"a\", \"b\"]\n  guest: []\n"),
        ] {
            let m = merge(
                Some(Stored {
                    base: &base,
                    live: &base,
                    conflicts: &none,
                }),
                &file,
            );
            assert_eq!(m.kind, SyncKind::RootFile, "root's edit");
            assert_eq!(
                m.live.canonical(),
                file.canonical(),
                "root's order and keys persist"
            );
            let next = merge(
                Some(Stored {
                    base: &m.base,
                    live: &m.live,
                    conflicts: &m.conflicts,
                }),
                &file,
            );
            assert_eq!(next.kind, SyncKind::Unchanged);
            assert!(
                equivalent(&next.live, &file),
                "the next mirror holds nothing to install"
            );
        }
    }

    #[test]
    fn the_daemons_installed_write_is_adopted_and_settles_in_one_load() {
        let s = |b: &str| Section::of(&crate::parse_bindings(b).unwrap());
        let base = s("schema_version: 1\nbindings:\n  user: [\"a\"]\n");
        let live = s("schema_version: 1\nbindings:\n  user: [\"a\"]\n  adversary: [\"m\"]\n");
        let none = BTreeSet::new();
        let installed = live.clone();
        let m = merge(
            Some(Stored {
                base: &base,
                live: &live,
                conflicts: &none,
            }),
            &installed,
        );
        assert_eq!(m.kind, SyncKind::Adopted);
        let next = merge(
            Some(Stored {
                base: &m.base,
                live: &m.live,
                conflicts: &m.conflicts,
            }),
            &installed,
        );
        assert_eq!(
            (next.kind, next.live.canonical()),
            (SyncKind::Unchanged, live.canonical())
        );
        let lost = merge(
            Some(Stored {
                base: &base,
                live: &live,
                conflicts: &none,
            }),
            &Section::Missing,
        );
        assert_eq!(lost.kind, SyncKind::Lost);
        let restored = merge(
            Some(Stored {
                base: &lost.base,
                live: &lost.live,
                conflicts: &lost.conflicts,
            }),
            &installed,
        );
        assert_eq!(
            restored.kind,
            SyncKind::Adopted,
            "a restore is the daemon's own write, never root-file"
        );
        let again = merge(
            Some(Stored {
                base: &restored.base,
                live: &restored.live,
                conflicts: &restored.conflicts,
            }),
            &installed,
        );
        assert_eq!(again.kind, SyncKind::Unchanged);
        let plain = merge(
            Some(Stored {
                base: &base,
                live: &base,
                conflicts: &none,
            }),
            &Section::Missing,
        );
        let r = merge(
            Some(Stored {
                base: &plain.base,
                live: &plain.live,
                conflicts: &plain.conflicts,
            }),
            &base,
        );
        assert_eq!(
            r.kind,
            SyncKind::Unchanged,
            "a restore of an unedited file changes nothing"
        );
    }

    #[test]
    fn equivalent_ignores_order_and_empty_keys_and_nothing_else() {
        let s = |b: &str| Section::of(&crate::parse_bindings(b).unwrap());
        let a = s("schema_version: 1\nbindings:\n  user: [\"a\", \"b\"]\n");
        assert!(equivalent(
            &a,
            &s("schema_version: 1\nbindings:\n  user: [\"b\", \"a\"]\n  guest: []\n")
        ));
        assert!(!equivalent(
            &a,
            &s("schema_version: 1\nbindings:\n  user: [\"a\"]\n  guest: [\"b\"]\n")
        ));
        assert!(!equivalent(
            &a,
            &s("schema_version: 1\nbindings:\n  user: [\"a\"]\n")
        ));
        assert!(equivalent(&Section::Absent, &Section::Missing));
        assert!(
            !equivalent(&Section::Absent, &s("schema_version: 1\nbindings: {}\n")),
            "explicit empty is not absent"
        );
        assert!(equivalent(
            &s("schema_version: 1\nbindings: {}\n"),
            &s("schema_version: 1\nbindings:\n  guest: []\n")
        ));
    }

    #[test]
    fn live_is_always_the_merged_section_with_edits_appended() {
        let s = |b: &str| Section::of(&crate::parse_bindings(b).unwrap());
        let (a, seven) = (BindingEntry::Name("a".into()), BindingEntry::Uid(7));
        let edits = [
            LiveEdit::Contain(a.clone()),
            LiveEdit::Release(a.clone()),
            LiveEdit::Contain(seven.clone()),
            LiveEdit::Release(seven.clone()),
            LiveEdit::Bind {
                name: "a".into(),
                role: BoundRole::Admin,
            },
            LiveEdit::Bind {
                name: "a".into(),
                role: BoundRole::User,
            },
            LiveEdit::Bind {
                name: "a".into(),
                role: BoundRole::Guest,
            },
            LiveEdit::Unbind("a".into()),
        ];
        let bases = [
            s("schema_version: 1\nbindings:\n  user: [\"a\", \"b\"]\n"),
            s("schema_version: 1\nbindings:\n  user: [\"b\", \"a\"]\n  adversary: []\n"),
            s("schema_version: 1\nbindings: {}\n"),
        ];
        let none = BTreeSet::new();
        let mut checked = 0;
        for base in &bases {
            for e1 in &edits {
                for e2 in &edits {
                    for e3 in &edits {
                        let mut live = base.clone();
                        for e in [e1, e2, e3] {
                            if let Some(next) = apply_edit(base, &live, e).unwrap() {
                                live = next;
                            }
                        }
                        let m = merge(
                            Some(Stored {
                                base,
                                live: &live,
                                conflicts: &none,
                            }),
                            base,
                        );
                        assert_eq!(
                            (m.kind, m.live.canonical()),
                            (SyncKind::Unchanged, live.canonical()),
                            "{base:?} {e1:?} {e2:?} {e3:?}"
                        );
                        checked += 1;
                    }
                }
            }
        }
        assert_eq!(checked, 3 * 8 * 8 * 8);
        let base = &bases[0];
        let mut live = base.clone();
        for e in [
            LiveEdit::Contain(seven.clone()),
            LiveEdit::Contain(a.clone()),
        ] {
            live = apply_edit(base, &live, &e).unwrap().unwrap();
        }
        assert!(
            live.canonical().contains(r#""adversary":[{"uid":7},"a"]"#),
            "live keeps edit order: {}",
            live.canonical()
        );
        let m = merge(
            Some(Stored {
                base,
                live: &live,
                conflicts: &none,
            }),
            base,
        );
        assert_eq!(
            m.live.canonical(),
            live.canonical(),
            "the tail follows live's per-role list, not the universe order"
        );
        for (on, off) in [
            (
                LiveEdit::Contain(seven.clone()),
                LiveEdit::Release(seven.clone()),
            ),
            (
                LiveEdit::Bind {
                    name: "z".into(),
                    role: BoundRole::Guest,
                },
                LiveEdit::Unbind("z".into()),
            ),
        ] {
            let up = apply_edit(base, base, &on).unwrap().unwrap();
            let down = apply_edit(base, &up, &off).unwrap().unwrap();
            assert_eq!(
                down.canonical(),
                base.canonical(),
                "a role the file lacks is not left behind as an empty key"
            );
            let m = merge(
                Some(Stored {
                    base,
                    live: &down,
                    conflicts: &none,
                }),
                base,
            );
            assert_eq!(
                (m.kind, m.live.canonical()),
                (SyncKind::Unchanged, down.canonical())
            );
        }
    }

    #[test]
    fn unsynced_counts_entries_whose_roles_differ() {
        let s = |b: &str| Section::of(&crate::parse_bindings(b).unwrap());
        let base = s("schema_version: 1\nbindings:\n  user: [\"a\", \"b\"]\n");
        assert_eq!(unsynced(&base, &base), 0);
        assert_eq!(
            unsynced(
                &base,
                &s("schema_version: 1\nbindings:\n  user: [\"b\", \"a\"]\n")
            ),
            0,
            "order is not a difference"
        );
        assert_eq!(unsynced(&base, &s("schema_version: 1\nbindings:\n  user: [\"a\"]\n  adversary: [\"b\", {uid: 7}]\n")), 2);
        assert_eq!(unsynced(&Section::Absent, &Section::Missing), 0);
    }

    #[test]
    fn live_edits_apply_refuse_and_report_no_ops() {
        let s = |b: &str| Section::of(&crate::parse_bindings(b).unwrap());
        let live = s("schema_version: 1\nbindings:\n  user: [\"eve\"]\n");
        let eve = BindingEntry::Name("eve".into());
        let contained = apply_edit(&live, &live, &LiveEdit::Contain(eve.clone()))
            .unwrap()
            .unwrap();
        assert_eq!(
            contained,
            s("schema_version: 1\nbindings:\n  user: [\"eve\"]\n  adversary: [\"eve\"]\n")
        );
        assert_eq!(
            apply_edit(&live, &contained, &LiveEdit::Contain(eve.clone())),
            Ok(None)
        );
        assert_eq!(
            apply_edit(&live, &contained, &LiveEdit::Release(eve.clone()))
                .unwrap()
                .unwrap(),
            s("schema_version: 1\nbindings:\n  user: [\"eve\"]\n"),
            "base has no adversary key, so the emptied key goes"
        );
        let keyed = s("schema_version: 1\nbindings:\n  user: [\"eve\"]\n  adversary: []\n");
        let kc = apply_edit(&keyed, &keyed, &LiveEdit::Contain(eve.clone()))
            .unwrap()
            .unwrap();
        assert_eq!(
            apply_edit(&keyed, &kc, &LiveEdit::Release(eve.clone()))
                .unwrap()
                .unwrap(),
            keyed,
            "base's empty key is kept"
        );
        assert_eq!(
            apply_edit(&live, &live, &LiveEdit::Release(eve.clone())),
            Ok(None)
        );
        assert_eq!(
            apply_edit(
                &live,
                &live,
                &LiveEdit::Bind {
                    name: "eve".into(),
                    role: BoundRole::Admin
                }
            )
            .unwrap()
            .unwrap(),
            s("schema_version: 1\nbindings:\n  user: []\n  admin: [\"eve\"]\n")
        );
        assert_eq!(
            apply_edit(&live, &live, &LiveEdit::Unbind("eve".into()))
                .unwrap()
                .unwrap(),
            s("schema_version: 1\nbindings:\n  user: []\n")
        );
        assert_eq!(
            apply_edit(&live, &live, &LiveEdit::Contain(BindingEntry::Uid(7)))
                .unwrap()
                .unwrap(),
            s("schema_version: 1\nbindings:\n  user: [\"eve\"]\n  adversary:\n    - uid: 7\n")
        );
        for absent in [Section::Absent, Section::Missing] {
            assert_eq!(
                apply_edit(&absent, &absent, &LiveEdit::Contain(eve.clone())),
                Err(EditError::NoExplicitBindings)
            );
        }
        assert_eq!(
            EditError::NoExplicitBindings.to_string(),
            "bindings.yaml has no bindings: key; a live identity edit needs explicit bindings"
        );
    }

    #[test]
    fn an_edit_over_a_live_section_breaking_the_role_rules_is_refused() {
        let mut m: BTreeMap<String, Vec<BindingEntry>> = BTreeMap::new();
        m.insert("user".into(), vec![BindingEntry::Uid(7)]);
        let live = Section::Present(m);
        let err = apply_edit(
            &live,
            &live,
            &LiveEdit::Contain(BindingEntry::Name("a".into())),
        )
        .unwrap_err();
        let EditError::Rules(rule) = &err else {
            panic!("{err:?}")
        };
        assert_eq!(err.to_string(), rule.to_string());
        assert!(std::error::Error::source(&err).is_none());
    }
}
