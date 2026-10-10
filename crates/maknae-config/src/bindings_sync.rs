use crate::bindings::{
    effective, entry, section_roles, subjects_by_uid, BindingEntry, Bindings, BindingsError,
    Effective, RoleRuleError,
};
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
    LiveEdit,
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

fn loosens(file: &Section, mirror: &Section, e: &BindingEntry) -> bool {
    let (was, now) = (file.roles_of(e), mirror.roles_of(e));
    now.iter().any(|r| *r != ADVERSARY && !was.contains(r))
        || (was.contains(ADVERSARY) && !now.contains(ADVERSARY))
}

pub fn loosenings(file: &Section, mirror: &Section) -> Vec<BindingEntry> {
    let keyless = matches!(file, Section::Present(_)) && !matches!(mirror, Section::Present(_));
    let all: BTreeSet<&BindingEntry> = file.entries().into_iter().chain(mirror.entries()).collect();
    all.into_iter()
        .filter(|e| keyless || loosens(file, mirror, e))
        .cloned()
        .collect()
}

fn indexed(s: &Section) -> Vec<(usize, &[BindingEntry])> {
    match s {
        Section::Present(m) => m
            .iter()
            .filter_map(|(k, v)| {
                crate::BINDING_ROLES
                    .iter()
                    .position(|r| r == k)
                    .map(|i| (i, v.as_slice()))
            })
            .collect(),
        _ => Vec::new(),
    }
}

fn may_install(file: Option<Effective>, mirror: Option<Effective>) -> bool {
    let held = matches!(file, Some(Effective::Bound(_) | Effective::Unbound));
    mirror == Some(Effective::Contained)
        || mirror == file
        || (mirror == Some(Effective::Unbound) && matches!(file, Some(Effective::Bound(_))))
        || (mirror.is_none() && held)
}

pub fn effective_loosenings(
    file: &Section,
    mirror: &Section,
    uids: &BTreeMap<String, u32>,
) -> Vec<BindingEntry> {
    let uid_of = |e: &BindingEntry| match e {
        BindingEntry::Uid(u) => Some(*u),
        BindingEntry::Name(n) => uids.get(n).copied(),
    };
    let (fi, mi) = (indexed(file), indexed(mirror));
    let (was, was_unresolved) = subjects_by_uid(&fi, uid_of);
    let (now, now_unresolved) = subjects_by_uid(&mi, uid_of);
    let outcome = |h: Option<&Vec<(usize, &BindingEntry)>>| {
        h.and_then(|h| effective(&h.iter().map(|(i, _)| *i).collect::<Vec<_>>()))
    };
    let mut out: BTreeSet<BindingEntry> = BTreeSet::new();
    for uid in was.keys().chain(now.keys()) {
        let (w, n) = (was.get(uid), now.get(uid));
        if !may_install(outcome(w), outcome(n)) {
            out.extend(w.into_iter().chain(n).flatten().map(|(_, e)| (*e).clone()));
        }
    }
    let by_name = |held: Vec<(usize, &BindingEntry)>| {
        let mut m: BTreeMap<BindingEntry, Vec<usize>> = BTreeMap::new();
        for (i, e) in held {
            m.entry(e.clone()).or_default().push(i);
        }
        m
    };
    let (w, n) = (by_name(was_unresolved), by_name(now_unresolved));
    for e in w.keys().chain(n.keys()) {
        let own = |m: &BTreeMap<BindingEntry, Vec<usize>>| m.get(e).and_then(|r| effective(r));
        if !may_install(own(&w), own(&n)) {
            out.insert(e.clone());
        }
    }
    out.into_iter().collect()
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

impl LiveEdit {
    fn target(&self) -> BindingEntry {
        match self {
            Self::Contain(e) | Self::Release(e) => e.clone(),
            Self::Bind { name, .. } | Self::Unbind(name) => BindingEntry::Name(name.clone()),
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Edited {
    pub live: Section,
    pub conflicts: BTreeSet<BindingEntry>,
    pub events: Vec<MergeEvent>,
}

pub fn apply_edit(
    base: &Section,
    live: &Section,
    conflicts: &BTreeSet<BindingEntry>,
    edit: &LiveEdit,
) -> Result<Option<Edited>, EditError> {
    let Some(next) = edit_section(base, live, edit)? else {
        return Ok(None);
    };
    let entry = edit.target();
    let mut conflicts = conflicts.clone();
    let events = if conflicts.remove(&entry) {
        vec![MergeEvent::Resolved {
            entry,
            by: ResolvedBy::LiveEdit,
        }]
    } else {
        Vec::new()
    };
    Ok(Some(Edited {
        live: next,
        conflicts,
        events,
    }))
}

fn edit_section(
    base: &Section,
    live: &Section,
    edit: &LiveEdit,
) -> Result<Option<Section>, EditError> {
    if !matches!(base, Section::Present(_)) || !matches!(live, Section::Present(_)) {
        return Err(EditError::NoExplicitBindings);
    }
    let target = &edit.target();
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
                            let events = match (listed, conflict) {
                                (true, false) => vec![MergeEvent::Resolved {
                                    entry: e.clone(),
                                    by: if file == live {
                                        ResolvedBy::Sync
                                    } else {
                                        ResolvedBy::RootEdit
                                    },
                                }],
                                (false, true) => vec![MergeEvent::Conflict {
                                    entry: e.clone(),
                                    contained: want.contains(ADVERSARY),
                                }],
                                _ => vec![],
                            };
                            assert_eq!(m.events, events, "one event per entry at most: {at}");
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
    fn a_root_containment_over_an_unsynced_live_binding_is_taken_without_a_conflict() {
        let e = BindingEntry::Name("e".into());
        let (b, l, f) = (
            section_with(&e, &[]),
            section_with(&e, &["guest"]),
            section_with(&e, &["adversary"]),
        );
        let m = merge(
            Some(Stored {
                base: &b,
                live: &l,
                conflicts: &BTreeSet::new(),
            }),
            &f,
        );
        assert_eq!(m.live.roles_of(&e), BTreeSet::from(["adversary"]));
        assert!(m.conflicts.is_empty());
        assert!(m.events.is_empty(), "{:?}", m.events);
        assert_eq!(m.kind, SyncKind::RootFile);
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
                            if let Some(next) = edit_section(base, &live, e).unwrap() {
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
            live = edit_section(base, &live, &e).unwrap().unwrap();
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
            let up = edit_section(base, base, &on).unwrap().unwrap();
            let down = edit_section(base, &up, &off).unwrap().unwrap();
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
        let contained = edit_section(&live, &live, &LiveEdit::Contain(eve.clone()))
            .unwrap()
            .unwrap();
        assert_eq!(
            contained,
            s("schema_version: 1\nbindings:\n  user: [\"eve\"]\n  adversary: [\"eve\"]\n")
        );
        assert_eq!(
            edit_section(&live, &contained, &LiveEdit::Contain(eve.clone())),
            Ok(None)
        );
        assert_eq!(
            edit_section(&live, &contained, &LiveEdit::Release(eve.clone()))
                .unwrap()
                .unwrap(),
            s("schema_version: 1\nbindings:\n  user: [\"eve\"]\n"),
            "base has no adversary key, so the emptied key goes"
        );
        let keyed = s("schema_version: 1\nbindings:\n  user: [\"eve\"]\n  adversary: []\n");
        let kc = edit_section(&keyed, &keyed, &LiveEdit::Contain(eve.clone()))
            .unwrap()
            .unwrap();
        assert_eq!(
            edit_section(&keyed, &kc, &LiveEdit::Release(eve.clone()))
                .unwrap()
                .unwrap(),
            keyed,
            "base's empty key is kept"
        );
        assert_eq!(
            edit_section(&live, &live, &LiveEdit::Release(eve.clone())),
            Ok(None)
        );
        assert_eq!(
            edit_section(
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
            edit_section(&live, &live, &LiveEdit::Unbind("eve".into()))
                .unwrap()
                .unwrap(),
            s("schema_version: 1\nbindings:\n  user: []\n")
        );
        assert_eq!(
            edit_section(&live, &live, &LiveEdit::Contain(BindingEntry::Uid(7)))
                .unwrap()
                .unwrap(),
            s("schema_version: 1\nbindings:\n  user: [\"eve\"]\n  adversary:\n    - uid: 7\n")
        );
        for absent in [Section::Absent, Section::Missing] {
            for (b, l) in [(&absent, &absent), (&absent, &live)] {
                assert_eq!(
                    edit_section(b, l, &LiveEdit::Contain(eve.clone())),
                    Err(EditError::NoExplicitBindings),
                    "base {b:?} live {l:?}"
                );
            }
        }
        assert_eq!(
            EditError::NoExplicitBindings.to_string(),
            "bindings.yaml has no bindings: key; a live identity edit needs explicit bindings"
        );
    }

    #[test]
    fn a_live_edit_takes_its_own_entry_off_the_conflict_list_and_says_so() {
        let s = |b: &str| Section::of(&crate::parse_bindings(b).unwrap());
        let (alice, bob) = (
            BindingEntry::Name("alice".into()),
            BindingEntry::Name("bob".into()),
        );
        let base = s("schema_version: 1\nbindings:\n  user: [\"alice\", \"bob\"]\n");
        let live = s("schema_version: 1\nbindings:\n  user: []\n");
        let listed: BTreeSet<_> = [alice.clone(), bob.clone()].into();
        let got = apply_edit(&base, &live, &listed, &LiveEdit::Contain(alice.clone()))
            .unwrap()
            .unwrap();
        assert_eq!(
            got,
            Edited {
                live: s("schema_version: 1\nbindings:\n  user: []\n  adversary: [\"alice\"]\n"),
                conflicts: [bob.clone()].into(),
                events: vec![MergeEvent::Resolved {
                    entry: alice.clone(),
                    by: ResolvedBy::LiveEdit
                }],
            }
        );
        let carol = apply_edit(
            &base,
            &live,
            &listed,
            &LiveEdit::Contain(BindingEntry::Uid(7)),
        )
        .unwrap()
        .unwrap();
        assert_eq!((carol.conflicts, carol.events), (listed.clone(), vec![]));
        assert_eq!(
            apply_edit(&base, &live, &listed, &LiveEdit::Unbind("alice".into())),
            Ok(None),
            "a no-op leaves the entry listed"
        );
        assert_eq!(
            apply_edit(
                &Section::Absent,
                &Section::Absent,
                &listed,
                &LiveEdit::Contain(alice.clone())
            ),
            Err(EditError::NoExplicitBindings)
        );

        let file = s("schema_version: 1\nbindings:\n  admin: [\"alice\"]\n");
        let m = merge(
            Some(Stored {
                base: &base,
                live: &got.live,
                conflicts: &got.conflicts,
            }),
            &file,
        );
        assert_eq!(m.live.roles_of(&alice), [ADVERSARY].into());
        assert!(m.conflicts.contains(&alice));
        assert!(m.events.contains(&MergeEvent::Conflict {
            entry: alice,
            contained: true
        }));
    }

    #[test]
    fn an_edit_over_a_live_section_breaking_the_role_rules_is_refused() {
        let mut m: BTreeMap<String, Vec<BindingEntry>> = BTreeMap::new();
        m.insert("user".into(), vec![BindingEntry::Uid(7)]);
        let live = Section::Present(m);
        let err = edit_section(
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

    const ROLES: [&str; 4] = ["admin", "user", "guest", "adversary"];

    fn roles_in(mask: u8) -> Vec<&'static str> {
        ROLES
            .iter()
            .enumerate()
            .filter(|(i, _)| mask & (1 << i) != 0)
            .map(|(_, r)| *r)
            .collect()
    }

    fn loosens_by_the_rule(file: &[&str], mirror: &[&str]) -> bool {
        let gains = ["admin", "user", "guest"]
            .iter()
            .any(|r| mirror.contains(r) && !file.contains(r));
        let releases = file.contains(&"adversary") && !mirror.contains(&"adversary");
        gains || releases
    }

    fn with_bystander(e: &BindingEntry, roles: &[&str]) -> Section {
        let mut s = section_with(e, roles);
        if let Section::Present(m) = &mut s {
            m.entry("admin".into())
                .or_default()
                .push(BindingEntry::Name("root".into()));
        }
        s
    }

    #[test]
    fn loosenings_are_exactly_the_gains_and_releases_over_every_role_set() {
        for e in [BindingEntry::Name("x".into()), BindingEntry::Uid(7)] {
            for f in 0..16u8 {
                for m in 0..16u8 {
                    let (fr, mr) = (roles_in(f), roles_in(m));
                    let want: Vec<BindingEntry> = if loosens_by_the_rule(&fr, &mr) {
                        vec![e.clone()]
                    } else {
                        Vec::new()
                    };
                    assert_eq!(
                        loosenings(&with_bystander(&e, &fr), &with_bystander(&e, &mr)),
                        want,
                        "{e:?} {fr:?} -> {mr:?}"
                    );
                }
            }
        }
    }

    fn sec(text: &str) -> Section {
        Section::of(&parse_bindings(text).unwrap())
    }

    #[test]
    fn a_new_entry_loosens_unless_it_is_only_contained() {
        let file = sec("schema_version: 1\nbindings:\n  admin: [\"root\"]\n");
        for (mirror, want) in [
            ("  user: [\"x\"]\n", vec![BindingEntry::Name("x".into())]),
            ("  guest: [{uid: 9}]\n", vec![BindingEntry::Uid(9)]),
            ("  adversary: [\"x\", {uid: 9}]\n", vec![]),
            (
                "  user: [\"x\"]\n  adversary: [\"x\"]\n",
                vec![BindingEntry::Name("x".into())],
            ),
        ] {
            let mirror = sec(&format!(
                "schema_version: 1\nbindings:\n  admin: [\"root\"]\n{mirror}"
            ));
            assert_eq!(loosenings(&file, &mirror), want, "{mirror:?}");
        }
    }

    #[test]
    fn a_removed_entry_tightens_unless_it_was_contained() {
        let mirror = sec("schema_version: 1\nbindings:\n  admin: [\"root\"]\n");
        for (file, want) in [
            ("  user: [\"x\"]\n  guest: [{uid: 9}]\n", vec![]),
            (
                "  adversary: [\"x\", {uid: 9}]\n",
                vec![BindingEntry::Name("x".into()), BindingEntry::Uid(9)],
            ),
            (
                "  user: [\"x\"]\n  adversary: [\"x\"]\n",
                vec![BindingEntry::Name("x".into())],
            ),
        ] {
            let file = sec(&format!(
                "schema_version: 1\nbindings:\n  admin: [\"root\"]\n{file}"
            ));
            assert_eq!(loosenings(&file, &mirror), want, "{file:?}");
        }
    }

    #[test]
    fn a_name_and_a_uid_are_distinct_entries() {
        let file = sec("schema_version: 1\nbindings:\n  adversary: [{uid: 7}]\n");
        let mirror = sec("schema_version: 1\nbindings:\n  adversary: [\"7\"]\n");
        assert_eq!(loosenings(&file, &mirror), [BindingEntry::Uid(7)]);
        assert_eq!(loosenings(&mirror, &file), [BindingEntry::Name("7".into())]);
    }

    #[test]
    fn empty_role_keys_change_nothing() {
        let file = sec("schema_version: 1\nbindings:\n  admin: [\"root\"]\n");
        let mirror = sec(
            "schema_version: 1\nbindings:\n  admin: [\"root\"]\n  user: []\n  guest: []\n  adversary: []\n",
        );
        assert!(loosenings(&file, &mirror).is_empty());
        assert!(loosenings(&mirror, &file).is_empty());
    }

    #[test]
    fn a_section_gaining_or_losing_its_key_loosens_by_the_rule() {
        let e = BindingEntry::Name("x".into());
        let root = BindingEntry::Name("root".into());
        let states = || {
            [Section::Missing, Section::Absent]
                .into_iter()
                .chain((0..16u8).map(|m| with_bystander(&e, &roles_in(m))))
        };
        for file in states() {
            for mirror in states() {
                let present = |s: &Section| matches!(s, Section::Present(_));
                let (fr, mr): (Vec<&str>, Vec<&str>) = (
                    file.roles_of(&e).into_iter().collect(),
                    mirror.roles_of(&e).into_iter().collect(),
                );
                let want: Vec<BindingEntry> = if present(&file) && !present(&mirror) {
                    let mut all = vec![root.clone()];
                    if !fr.is_empty() {
                        all.push(e.clone());
                    }
                    all
                } else {
                    let mut out = Vec::new();
                    if !present(&file) && present(&mirror) {
                        out.push(root.clone());
                    }
                    if loosens_by_the_rule(&fr, &mr) {
                        out.push(e.clone());
                    }
                    out
                };
                assert_eq!(loosenings(&file, &mirror), want, "{file:?} -> {mirror:?}");
            }
        }
    }

    #[test]
    fn losing_the_key_loosens_every_entry_the_file_held() {
        let file = sec(
            "schema_version: 1\nbindings:\n  admin: [\"root\"]\n  guest: [{uid: 9}]\n  adversary: [\"m\"]\n",
        );
        for mirror in [
            Section::Missing,
            Section::Absent,
            sec("schema_version: 1\n"),
        ] {
            assert_eq!(
                loosenings(&file, &mirror),
                [
                    BindingEntry::Name("m".into()),
                    BindingEntry::Name("root".into()),
                    BindingEntry::Uid(9)
                ],
                "{mirror:?}"
            );
            assert_eq!(
                loosenings(&mirror, &file),
                [BindingEntry::Name("root".into()), BindingEntry::Uid(9)],
                "{mirror:?}"
            );
        }
    }

    fn uids(pairs: &[(&str, u32)]) -> BTreeMap<String, u32> {
        pairs.iter().map(|(n, u)| ((*n).to_string(), *u)).collect()
    }

    fn name(n: &str) -> BindingEntry {
        BindingEntry::Name(n.into())
    }

    #[test]
    fn dropping_one_of_two_roles_binds_the_subject_and_loosens() {
        let file = sec("schema_version: 1\nbindings:\n  admin: [\"alice\"]\n  user: [\"alice\"]\n");
        let mirror = sec("schema_version: 1\nbindings:\n  admin: [\"alice\"]\n");
        assert!(loosenings(&file, &mirror).is_empty());
        let map = uids(&[("alice", 1000)]);
        assert_eq!(effective_loosenings(&file, &mirror, &map), [name("alice")]);
        assert!(effective_loosenings(&mirror, &file, &map).is_empty());
    }

    #[test]
    fn two_names_for_one_uid_are_one_subject() {
        let file = sec("schema_version: 1\nbindings:\n  admin: [\"alice\"]\n  user: [\"al\"]\n");
        let mirror = sec("schema_version: 1\nbindings:\n  admin: [\"alice\"]\n");
        assert!(loosenings(&file, &mirror).is_empty());
        let map = uids(&[("alice", 1000), ("al", 1000)]);
        assert_eq!(
            effective_loosenings(&file, &mirror, &map),
            [name("al"), name("alice")]
        );
        let apart = uids(&[("alice", 1000), ("al", 1001)]);
        assert!(effective_loosenings(&file, &mirror, &apart).is_empty());
    }

    #[test]
    fn a_uid_entry_and_a_name_for_it_are_one_subject() {
        let file = sec("schema_version: 1\nbindings:\n  adversary: [{uid: 7}]\n");
        let mirror = sec("schema_version: 1\nbindings:\n  admin: [\"alice\"]\n");
        let map = uids(&[("alice", 7)]);
        assert_eq!(
            effective_loosenings(&file, &mirror, &map),
            [name("alice"), BindingEntry::Uid(7)]
        );
        let held =
            sec("schema_version: 1\nbindings:\n  admin: [\"alice\"]\n  adversary: [{uid: 7}]\n");
        assert!(effective_loosenings(&mirror, &held, &map).is_empty());
    }

    #[test]
    fn an_unresolved_name_is_its_own_subject() {
        let file = sec("schema_version: 1\nbindings:\n  admin: [\"root\"]\n");
        let mirror = sec("schema_version: 1\nbindings:\n  admin: [\"root\", \"ghost\"]\n");
        let map = uids(&[("root", 0)]);
        assert_eq!(effective_loosenings(&file, &mirror, &map), [name("ghost")]);
        let two = sec("schema_version: 1\nbindings:\n  admin: [\"alice\"]\n  user: [\"alice\"]\n");
        let one = sec("schema_version: 1\nbindings:\n  admin: [\"alice\"]\n");
        assert!(loosenings(&two, &one).is_empty());
        assert_eq!(effective_loosenings(&two, &one, &map), [name("alice")]);
        assert!(effective_loosenings(&one, &two, &map).is_empty());
    }

    fn outcome_by_the_rule(roles: &BTreeSet<&str>) -> Option<&'static str> {
        if roles.is_empty() {
            None
        } else if roles.contains("adversary") {
            Some("contained")
        } else if roles.len() == 1 {
            Some(
                ["admin", "user", "guest"]
                    .into_iter()
                    .find(|r| roles.contains(r))
                    .unwrap(),
            )
        } else {
            Some("unbound")
        }
    }

    fn allowed_by_the_rule(file: Option<&str>, mirror: Option<&str>) -> bool {
        let bound = |o: Option<&str>| matches!(o, Some("admin" | "user" | "guest"));
        mirror == Some("contained")
            || mirror == file
            || (mirror == Some("unbound") && bound(file))
            || (mirror.is_none() && (bound(file) || file == Some("unbound")))
    }

    #[test]
    fn effective_loosenings_follow_the_subject_rule_for_two_names_of_one_uid() {
        effective_loosenings_by_the_rule(true);
    }

    #[test]
    fn effective_loosenings_follow_the_subject_rule_for_two_unresolved_names() {
        effective_loosenings_by_the_rule(false);
    }

    fn effective_loosenings_by_the_rule(resolved: bool) {
        let (a, b) = (name("a"), name("b"));
        let map = if resolved {
            uids(&[("a", 5), ("b", 5)])
        } else {
            uids(&[])
        };
        let other: [&[&str]; 3] = [&[], &["user"], &["adversary"]];
        let build = |ar: &[&str], br: &[&str]| {
            let mut m: BTreeMap<String, Vec<BindingEntry>> = BTreeMap::new();
            for r in ar {
                m.entry((*r).into()).or_default().push(a.clone());
            }
            for r in br {
                m.entry((*r).into()).or_default().push(b.clone());
            }
            Section::Present(m)
        };
        for fa in 0..16u8 {
            for ma in 0..16u8 {
                for fb in other {
                    for mb in other {
                        let (far, mar) = (roles_in(fa), roles_in(ma));
                        let (file, mirror) = (build(&far, fb), build(&mar, mb));
                        let set =
                            |x: &[&'static str], y: &[&'static str]| -> BTreeSet<&'static str> {
                                x.iter().chain(y).copied().collect()
                            };
                        let (fo, mo) = (
                            outcome_by_the_rule(&set(&far, fb)),
                            outcome_by_the_rule(&set(&mar, mb)),
                        );
                        let mut want = Vec::new();
                        if resolved {
                            if !allowed_by_the_rule(fo, mo) {
                                if !far.is_empty() || !mar.is_empty() {
                                    want.push(a.clone());
                                }
                                if !fb.is_empty() || !mb.is_empty() {
                                    want.push(b.clone());
                                }
                            }
                        } else {
                            let own = |x: &[&'static str]| set(x, &[]);
                            if !allowed_by_the_rule(
                                outcome_by_the_rule(&own(&far)),
                                outcome_by_the_rule(&own(&mar)),
                            ) {
                                want.push(a.clone());
                            }
                            if !allowed_by_the_rule(
                                outcome_by_the_rule(&own(fb)),
                                outcome_by_the_rule(&own(mb)),
                            ) {
                                want.push(b.clone());
                            }
                        }
                        assert_eq!(
                            effective_loosenings(&file, &mirror, &map),
                            want,
                            "{far:?}+{fb:?} -> {mar:?}+{mb:?}"
                        );
                    }
                }
            }
        }
    }
}
