use crate::bindings::{entry, BindingEntry};
use crate::bindings_sync::{equivalent, Section};
use crate::value::Value;
use std::collections::BTreeSet;

pub const MIRROR_BANNER: &str =
    "# maknae bindings mirror v1: install it with sudo maknae policy sync; do not edit\n";
pub const MIRROR_MAX_BYTES: u64 = 1 << 20;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MirrorHeader {
    pub revision: u64,
    pub config_dir: String,
    pub base: String,
    pub conflicts: BTreeSet<BindingEntry>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Mirror {
    pub header: MirrorHeader,
    pub section: Section,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum MirrorError {
    Header(&'static str),
    Body(String),
    NotCanonical,
}

impl std::fmt::Display for MirrorError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Header(w) => write!(f, "header: {w}"),
            Self::Body(e) => write!(f, "body: {e}"),
            Self::NotCanonical => f.write_str("not exactly a render of its own content"),
        }
    }
}

impl std::error::Error for MirrorError {}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum SyncPlan {
    OtherConfigDir {
        found: String,
    },
    NothingToInstall,
    Restore {
        diff: Vec<String>,
        conflicts: Vec<BindingEntry>,
        bytes: String,
    },
    BaseChanged {
        file: String,
        base: String,
    },
    Install {
        diff: Vec<String>,
        conflicts: Vec<BindingEntry>,
        bytes: String,
    },
}

fn quoted(n: &str) -> String {
    let mut out = String::from("\"");
    for c in n.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            ' '..='~' => out.push(c),
            c if (c as u32) <= 0xFFFF => out.push_str(&format!("\\u{:04X}", c as u32)),
            c => out.push_str(&format!("\\U{:08X}", c as u32)),
        }
    }
    out.push('"');
    out
}

fn inline(e: &BindingEntry) -> String {
    match e {
        BindingEntry::Name(n) => quoted(n),
        BindingEntry::Uid(u) => format!("uid: {u}"),
    }
}

fn body(live: &Section) -> String {
    let mut out = String::from("schema_version: 1\n");
    let Section::Present(roles) = live else {
        return out;
    };
    if roles.is_empty() {
        out.push_str("bindings: {}\n");
        return out;
    }
    out.push_str("bindings:\n");
    for role in crate::BINDING_ROLES
        .iter()
        .filter(|r| roles.contains_key(**r))
    {
        let list = &roles[*role];
        if list.is_empty() {
            out.push_str(&format!("  {role}: []\n"));
            continue;
        }
        out.push_str(&format!("  {role}:\n"));
        for e in list {
            out.push_str(&format!("    - {}\n", inline(e)));
        }
    }
    out
}

pub fn render_mirror(h: &MirrorHeader, live: &Section) -> String {
    let mut out = format!(
        "{MIRROR_BANNER}# revision: {}\n# config: {}\n# base: {}\n# conflicts: {}\n",
        h.revision,
        quoted(&h.config_dir),
        h.base,
        h.conflicts.len()
    );
    for c in &h.conflicts {
        out.push_str(&format!("# conflict: {}\n", inline(c)));
    }
    out.push_str(&body(live));
    out
}

fn field<'a>(
    lines: &mut impl Iterator<Item = &'a str>,
    prefix: &str,
    what: &'static str,
) -> Result<&'a str, MirrorError> {
    lines
        .next()
        .and_then(|l| l.strip_suffix('\n'))
        .and_then(|l| l.strip_prefix(prefix))
        .ok_or(MirrorError::Header(what))
}

fn quoted_str(text: &str, what: &'static str) -> Result<String, MirrorError> {
    match crate::load_str(text) {
        Ok(Value::Str(s)) => Ok(s),
        _ => Err(MirrorError::Header(what)),
    }
}

fn conflict_entry(text: &str) -> Result<BindingEntry, MirrorError> {
    const WHAT: &str = "a conflict is a quoted name or `uid: <n>`";
    if let Some(n) = text.strip_prefix("uid: ") {
        return n
            .parse::<u32>()
            .ok()
            .filter(|u| *u != u32::MAX)
            .map(BindingEntry::Uid)
            .ok_or(MirrorError::Header(WHAT));
    }
    entry(&Value::Str(quoted_str(text, WHAT)?)).map_err(|_| MirrorError::Header(WHAT))
}

fn base_is_token(b: &str) -> bool {
    match b.strip_prefix("sha256:") {
        Some(hex) => hex.len() == 64 && hex.bytes().all(|c| matches!(c, b'0'..=b'9' | b'a'..=b'f')),
        None => b == "absent" || b == "missing",
    }
}

pub fn parse_mirror(text: &str) -> Result<Mirror, MirrorError> {
    if text.len() as u64 > MIRROR_MAX_BYTES {
        return Err(MirrorError::Header("the mirror is larger than 1 MiB"));
    }
    let mut lines = text.split_inclusive('\n');
    if lines.next() != Some(MIRROR_BANNER) {
        return Err(MirrorError::Header(
            "the first line is not the mirror banner",
        ));
    }
    let revision = field(&mut lines, "# revision: ", "no revision line")?
        .parse::<u64>()
        .map_err(|_| MirrorError::Header("the revision is not a whole number"))?;
    let config_dir = quoted_str(
        field(&mut lines, "# config: ", "no config line")?,
        "the config directory is not a quoted string",
    )?;
    let base = field(&mut lines, "# base: ", "no base line")?;
    if !base_is_token(base) {
        return Err(MirrorError::Header(
            "the base is not absent, missing or sha256:<64 hex>",
        ));
    }
    let count = field(&mut lines, "# conflicts: ", "no conflicts line")?
        .parse::<usize>()
        .map_err(|_| MirrorError::Header("the conflict count is not a whole number"))?;
    let mut conflicts = BTreeSet::new();
    for _ in 0..count {
        conflicts.insert(conflict_entry(field(
            &mut lines,
            "# conflict: ",
            "fewer conflict lines than the count",
        )?)?);
    }
    let rest: String = lines.collect();
    let bindings = crate::parse_bindings(&rest).map_err(|e| MirrorError::Body(e.to_string()))?;
    crate::check_roles(&bindings).map_err(|e| MirrorError::Body(e.to_string()))?;
    let mirror = Mirror {
        header: MirrorHeader {
            revision,
            config_dir,
            base: base.into(),
            conflicts,
        },
        section: Section::of(&bindings),
    };
    if render_mirror(&mirror.header, &mirror.section) != text {
        return Err(MirrorError::NotCanonical);
    }
    Ok(mirror)
}

pub fn base_token(s: &Section, digest: fn(&[u8]) -> [u8; 32]) -> String {
    match s {
        Section::Missing => "missing".into(),
        Section::Absent => "absent".into(),
        Section::Present(_) => {
            let hex: String = digest(s.canonical().as_bytes())
                .iter()
                .map(|b| format!("{b:02x}"))
                .collect();
            format!("sha256:{hex}")
        }
    }
}

pub fn installable(m: &Mirror) -> String {
    format!(
        "# installed by sudo maknae policy sync from maknaed's mirror at revision {}\n{}",
        m.header.revision,
        body(&m.section)
    )
}

fn role_list<'a>(s: &'a Section, role: &str) -> &'a [BindingEntry] {
    match s {
        Section::Present(m) => m.get(role).map_or(&[], Vec::as_slice),
        _ => &[],
    }
}

fn state(s: &Section) -> &'static str {
    match s {
        Section::Present(_) => "present",
        _ => "absent",
    }
}

pub fn diff_lines(file: &Section, mirror: &Section) -> Vec<String> {
    let mut out = Vec::new();
    if state(file) != state(mirror) {
        out.push(format!("bindings: {} -> {}", state(file), state(mirror)));
    }
    for role in crate::BINDING_ROLES {
        let (f, m) = (role_list(file, role), role_list(mirror, role));
        out.extend(
            m.iter()
                .filter(|e| !f.contains(e))
                .map(|e| format!("{role}: +{}", e.render())),
        );
        out.extend(
            f.iter()
                .filter(|e| !m.contains(e))
                .map(|e| format!("{role}: -{}", e.render())),
        );
    }
    out
}

pub fn plan_sync(
    m: &Mirror,
    file: &Section,
    digest: fn(&[u8]) -> [u8; 32],
    config_dir: &str,
) -> SyncPlan {
    if m.header.config_dir != config_dir {
        return SyncPlan::OtherConfigDir {
            found: m.header.config_dir.clone(),
        };
    }
    if equivalent(file, &m.section) {
        return SyncPlan::NothingToInstall;
    }
    let diff = diff_lines(file, &m.section);
    let conflicts = m.header.conflicts.iter().cloned().collect();
    let bytes = installable(m);
    if !matches!(file, Section::Present(_)) {
        return SyncPlan::Restore {
            diff,
            conflicts,
            bytes,
        };
    }
    let found = base_token(file, digest);
    if found != m.header.base {
        return SyncPlan::BaseChanged {
            file: found,
            base: m.header.base.clone(),
        };
    }
    SyncPlan::Install {
        diff,
        conflicts,
        bytes,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::parse_bindings;
    use std::collections::BTreeMap;

    fn fake_digest(b: &[u8]) -> [u8; 32] {
        let mut d = [0u8; 32];
        for (i, x) in b.iter().enumerate() {
            d[i % 32] ^= *x;
        }
        d
    }

    const NAMES: [&str; 10] = [
        "alice",
        "a\"q",
        "b\\s",
        "é",
        "日本",
        "#x",
        "- y",
        " lead",
        "\u{FFFD}\u{FFFF}",
        "\u{10000}x",
    ];

    fn universe() -> Vec<Section> {
        let mut out = vec![Section::Absent, Section::Present(Default::default())];
        let entries: Vec<BindingEntry> = NAMES
            .iter()
            .map(|n| BindingEntry::Name((*n).into()))
            .chain([BindingEntry::Uid(0), BindingEntry::Uid(4_294_967_294)])
            .collect();
        for mask in 0u32..(1 << 6) {
            let mut m: BTreeMap<String, Vec<BindingEntry>> = BTreeMap::new();
            for (i, role) in crate::BINDING_ROLES.iter().enumerate() {
                if mask & (1 << i) != 0 {
                    m.insert((*role).into(), Vec::new());
                }
            }
            for (i, e) in entries.iter().enumerate() {
                let role = if matches!(e, BindingEntry::Uid(_)) {
                    "adversary"
                } else {
                    crate::BINDING_ROLES[(i + mask as usize) % 4]
                };
                if mask & 0b11_0000 != 0 && !(i as u32 + mask).is_multiple_of(3) {
                    m.entry(role.into()).or_default().push(e.clone());
                }
            }
            out.push(Section::Present(m));
        }
        out
    }

    fn plan_sync_etc(m: &Mirror, file: &Section, d: fn(&[u8]) -> [u8; 32]) -> SyncPlan {
        plan_sync(m, file, d, "/etc/maknae")
    }

    #[test]
    fn a_mirror_from_another_configuration_directory_is_never_planned() {
        let mut h = header(&[]);
        h.config_dir = "/opt/maknae/etc".into();
        let m = parse_mirror(&render_mirror(&h, &Section::Present(Default::default()))).unwrap();
        for file in [
            Section::Missing,
            Section::Absent,
            Section::Present(Default::default()),
        ] {
            assert_eq!(
                plan_sync(&m, &file, fake_digest, "/etc/maknae"),
                SyncPlan::OtherConfigDir {
                    found: "/opt/maknae/etc".into()
                }
            );
        }
    }

    #[test]
    fn nothing_to_install_ignores_order_and_empty_keys() {
        let s = |b: &str| Section::of(&parse_bindings(b).unwrap());
        let live = s("schema_version: 1\nbindings:\n  user: [\"a\", \"b\"]\n");
        let m = parse_mirror(&render_mirror(&header(&[]), &live)).unwrap();
        assert_eq!(
            plan_sync_etc(
                &m,
                &s("schema_version: 1\nbindings:\n  user: [\"b\", \"a\"]\n  guest: []\n"),
                fake_digest
            ),
            SyncPlan::NothingToInstall
        );
    }

    fn header(conflicts: &[BindingEntry]) -> MirrorHeader {
        MirrorHeader {
            revision: 42,
            config_dir: "/etc/maknae".into(),
            base: "absent".into(),
            conflicts: conflicts.iter().cloned().collect(),
        }
    }

    #[test]
    fn render_then_parse_returns_the_same_section_and_section_hash() {
        for s in universe() {
            for c in [
                &[][..],
                &[BindingEntry::Name("a\"q".into()), BindingEntry::Uid(7)][..],
            ] {
                let text = render_mirror(&header(c), &s);
                let m = parse_mirror(&text).unwrap_or_else(|e| panic!("{e:?}\n{text}"));
                assert_eq!(m.section.canonical(), s.canonical(), "{text}");
                assert_eq!(m.header, header(c));
                let installed = parse_bindings(&installable(&m)).unwrap();
                assert_eq!(
                    installed.section_canonical().unwrap_or("null"),
                    s.canonical(),
                    "the installed file hashes as live"
                );
            }
        }
    }

    #[test]
    fn the_render_is_fixed_role_order_live_order_and_uid_as_a_map() {
        let s = Section::of(&parse_bindings(
            "schema_version: 1\nbindings:\n  adversary: [\"m\", {uid: 7}]\n  guest: []\n  user: [\"z\", \"a\"]\n  admin: [\"r\"]\n",
        ).unwrap());
        assert_eq!(render_mirror(&MirrorHeader { revision: 3, config_dir: "/etc/maknae".into(), base: format!("sha256:{}", "0".repeat(64)), conflicts: [BindingEntry::Uid(7)].into() }, &s),
            format!("{MIRROR_BANNER}# revision: 3\n# config: \"/etc/maknae\"\n# base: sha256:{}\n# conflicts: 1\n# conflict: uid: 7\nschema_version: 1\nbindings:\n  admin:\n    - \"r\"\n  user:\n    - \"z\"\n    - \"a\"\n  guest: []\n  adversary:\n    - \"m\"\n    - uid: 7\n", "0".repeat(64)));
        assert_eq!(render_mirror(&header(&[]), &Section::Absent), format!("{MIRROR_BANNER}# revision: 42\n# config: \"/etc/maknae\"\n# base: absent\n# conflicts: 0\nschema_version: 1\n"));
        assert!(
            render_mirror(&header(&[]), &Section::Present(Default::default()))
                .ends_with("bindings: {}\n")
        );
    }

    #[test]
    fn a_name_renders_printable_ascii_raw_and_every_other_character_escaped() {
        let names = [
            "~ a",
            "a\"q",
            "b\\s",
            "\u{7F}",
            "é",
            "\u{FFFF}",
            "\u{10000}x",
        ];
        let s = Section::Present(BTreeMap::from([(
            "user".into(),
            names
                .iter()
                .map(|n| BindingEntry::Name((*n).into()))
                .collect(),
        )]));
        let text = render_mirror(&header(&[]), &s);
        assert!(
            text.ends_with(concat!(
                "  user:\n",
                "    - \"~ a\"\n",
                "    - \"a\\\"q\"\n",
                "    - \"b\\\\s\"\n",
                "    - \"\\u007F\"\n",
                "    - \"\\u00E9\"\n",
                "    - \"\\uFFFF\"\n",
                "    - \"\\U00010000x\"\n",
            )),
            "{text}"
        );
    }

    #[test]
    fn a_mirror_that_is_not_exactly_a_render_is_refused() {
        let good = render_mirror(
            &header(&[]),
            &Section::of(
                &parse_bindings("schema_version: 1\nbindings:\n  admin: [\"a\"]\n").unwrap(),
            ),
        );
        let bad = [
            good.replacen("# maknae", "#maknae", 1),
            good.replacen("# revision: 42", "# revision: 042", 1),
            good.replacen("# base: absent", "# base: sha256:AB", 1),
            good.replacen("# conflicts: 0", "# conflicts: 1", 1),
            good.replacen("    - \"a\"", "    - a", 1),
            good.replacen("  admin:", "  root:", 1),
            good.replacen("schema_version: 1\n", "schema_version: 1\n# note\n", 1),
            format!("{good}  user: [\"b\"]\n"),
            good.replacen("    - \"a\"\n", "    - \"a\"\n    - \"a\"\n", 1),
            good.replacen("  admin:\n    - \"a\"\n", "  user:\n    - uid: 7\n", 1),
            String::new(),
        ];
        for b in &bad {
            assert!(parse_mirror(b).is_err(), "accepted:\n{b}");
        }
    }

    #[test]
    fn the_header_base_is_absent_missing_or_a_lowercase_sha256() {
        let with = |base: String| {
            let mut h = header(&[]);
            h.base = base;
            parse_mirror(&render_mirror(&h, &Section::Absent)).map(|m| m.header.base)
        };
        for ok in [
            "absent".into(),
            "missing".into(),
            format!("sha256:{}", "0123456789abcdef".repeat(4)),
        ] {
            assert_eq!(with(ok.clone()), Ok(ok));
        }
        for bad in [
            "present".into(),
            format!("sha256:{}", "A".repeat(64)),
            format!("sha256:{}", "a".repeat(63)),
            format!("sha256:{}", "a".repeat(65)),
        ] {
            assert!(
                matches!(with(bad.clone()), Err(MirrorError::Header(_))),
                "{bad}"
            );
        }
    }

    #[test]
    fn a_mirror_of_exactly_the_size_limit_parses_and_one_byte_more_does_not() {
        let sized = |len: u64| {
            let fixed = render_mirror(
                &header(&[]),
                &Section::Present(BTreeMap::from([(
                    "user".into(),
                    vec![BindingEntry::Name(String::new())],
                )])),
            )
            .len() as u64;
            let name = "x".repeat(usize::try_from(len - fixed).unwrap());
            let text = render_mirror(
                &header(&[]),
                &Section::Present(BTreeMap::from([(
                    "user".into(),
                    vec![BindingEntry::Name(name)],
                )])),
            );
            assert_eq!(text.len() as u64, len);
            parse_mirror(&text)
        };
        assert!(sized(MIRROR_MAX_BYTES).is_ok());
        assert_eq!(
            sized(MIRROR_MAX_BYTES + 1),
            Err(MirrorError::Header("the mirror is larger than 1 MiB"))
        );
    }

    #[test]
    fn a_conflict_line_is_a_valid_entry_or_the_mirror_is_refused() {
        let good = render_mirror(&header(&[BindingEntry::Uid(7)]), &Section::Absent);
        assert!(parse_mirror(&good).is_ok());
        for bad in [
            "uid: 4294967295",
            "uid: -1",
            "uid: 07x",
            "\"a:b\"",
            "\"\"",
            "[\"a\"]",
            "\"a",
        ] {
            let text = good.replacen("# conflict: uid: 7", &format!("# conflict: {bad}"), 1);
            assert_eq!(
                parse_mirror(&text),
                Err(MirrorError::Header(
                    "a conflict is a quoted name or `uid: <n>`"
                )),
                "{bad}"
            );
        }
    }

    #[test]
    fn a_mirror_error_names_its_part() {
        assert_eq!(
            MirrorError::Header("no base line").to_string(),
            "header: no base line"
        );
        assert_eq!(MirrorError::Body("x".into()).to_string(), "body: x");
        assert_eq!(
            MirrorError::NotCanonical.to_string(),
            "not exactly a render of its own content"
        );
    }

    #[test]
    fn the_base_token_names_the_state_or_the_section_hash() {
        assert_eq!(base_token(&Section::Missing, fake_digest), "missing");
        assert_eq!(base_token(&Section::Absent, fake_digest), "absent");
        let s = Section::of(&parse_bindings("schema_version: 1\nbindings: {}\n").unwrap());
        let d = fake_digest(b"{}");
        let hex: String = d.iter().map(|b| format!("{b:02x}")).collect();
        assert_eq!(base_token(&s, fake_digest), format!("sha256:{hex}"));
    }

    #[test]
    fn the_plan_is_nothing_then_base_changed_then_install() {
        let s = |b: &str| Section::of(&parse_bindings(b).unwrap());
        let base = s("schema_version: 1\nbindings:\n  admin: [\"a\"]\n");
        let live = s("schema_version: 1\nbindings:\n  admin: [\"a\"]\n  adversary: [\"m\"]\n");
        let m = parse_mirror(&render_mirror(
            &MirrorHeader {
                revision: 9,
                config_dir: "/etc/maknae".into(),
                base: base_token(&base, fake_digest),
                conflicts: Default::default(),
            },
            &live,
        ))
        .unwrap();
        assert_eq!(
            plan_sync_etc(&m, &live, fake_digest),
            SyncPlan::NothingToInstall
        );
        let edited = s("schema_version: 1\nbindings:\n  admin: [\"b\"]\n");
        assert_eq!(
            plan_sync_etc(&m, &edited, fake_digest),
            SyncPlan::BaseChanged {
                file: base_token(&edited, fake_digest),
                base: base_token(&base, fake_digest)
            }
        );
        let SyncPlan::Install {
            diff,
            conflicts,
            bytes,
        } = plan_sync_etc(&m, &base, fake_digest)
        else {
            panic!()
        };
        assert_eq!(diff, ["adversary: +m"]);
        assert!(conflicts.is_empty());
        assert_eq!(bytes, installable(&m));
        let absent = parse_mirror(&render_mirror(
            &MirrorHeader {
                revision: 1,
                config_dir: "/etc/maknae".into(),
                base: "absent".into(),
                conflicts: Default::default(),
            },
            &Section::Absent,
        ))
        .unwrap();
        assert_eq!(
            plan_sync_etc(&absent, &Section::Missing, fake_digest),
            SyncPlan::NothingToInstall,
            "missing is absent"
        );
    }

    #[test]
    fn a_lost_file_is_restored_whatever_the_base_says() {
        let s = |b: &str| Section::of(&parse_bindings(b).unwrap());
        let base = s("schema_version: 1\nbindings:\n  admin: [\"a\"]\n");
        let live = s("schema_version: 1\nbindings:\n  admin: [\"a\"]\n  adversary: [\"m\"]\n");
        let m = parse_mirror(&render_mirror(
            &MirrorHeader {
                revision: 9,
                config_dir: "/etc/maknae".into(),
                base: base_token(&base, fake_digest),
                conflicts: [BindingEntry::Name("m".into())].into(),
            },
            &live,
        ))
        .unwrap();
        for lost in [Section::Missing, Section::Absent] {
            let SyncPlan::Restore {
                diff,
                conflicts,
                bytes,
            } = plan_sync_etc(&m, &lost, fake_digest)
            else {
                panic!("{lost:?}")
            };
            assert_eq!(
                diff,
                ["bindings: absent -> present", "admin: +a", "adversary: +m"]
            );
            assert_eq!(conflicts, [BindingEntry::Name("m".into())]);
            assert_eq!(bytes, installable(&m));
        }
        let empty = Section::of(&parse_bindings("schema_version: 1\nbindings: {}\n").unwrap());
        assert!(
            matches!(
                plan_sync_etc(&m, &empty, fake_digest),
                SyncPlan::BaseChanged { .. }
            ),
            "an emptied key is an edit, not a loss"
        );
    }

    #[test]
    fn the_diff_is_per_role_and_per_entry() {
        let s = |b: &str| Section::of(&parse_bindings(b).unwrap());
        assert_eq!(
            diff_lines(
                &s("schema_version: 1\nbindings:\n  user: [\"a\", \"b\"]\n"),
                &s("schema_version: 1\nbindings:\n  user: [\"b\"]\n  adversary:\n    - uid: 7\n")
            ),
            ["user: -a", "adversary: +uid:7"]
        );
        assert_eq!(
            diff_lines(&Section::Absent, &s("schema_version: 1\nbindings: {}\n")),
            ["bindings: absent -> present"]
        );
        assert_eq!(
            diff_lines(
                &s("schema_version: 1\nbindings:\n  admin: [\"a\"]\n"),
                &Section::Absent
            ),
            ["bindings: present -> absent", "admin: -a"]
        );
    }
}
