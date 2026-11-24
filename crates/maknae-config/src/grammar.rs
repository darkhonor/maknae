//! A tool grammar file (#674 PR 3): the argv shapes one program may be called with.

use crate::{ConfigError, Value};
use maknae_proto::{ForgeOp, ForgeOps, SideReach};
use regex::{Regex, RegexBuilder};
use std::collections::{BTreeMap, BTreeSet};
use std::fmt;

const PATTERN_SIZE_LIMIT: usize = 1 << 16;

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum GrammarError {
    Config(ConfigError),
    Invalid(String),
}

impl fmt::Display for GrammarError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Config(e) => write!(f, "grammar: {e}"),
            Self::Invalid(reason) => write!(f, "grammar: {reason}"),
        }
    }
}

impl std::error::Error for GrammarError {}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Tested {
    pub version: String,
    pub date: String,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ShapeClass {
    Read,
    Write,
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct ForgeNeed {
    pub base: ForgeOps,
    pub head: ForgeOps,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ArgvToken {
    Literal(String),
    Bound { kind: String, field: String },
    Slot(String),
    OptionSlot { prefix: String, slot: String },
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SlotAt {
    Token,
    Option,
    Stdin,
    File,
}

#[derive(Clone, Debug)]
pub enum Constraint {
    Enum(BTreeSet<String>),
    Pattern(Regex),
}

impl PartialEq for Constraint {
    fn eq(&self, other: &Self) -> bool {
        match (self, other) {
            (Self::Enum(a), Self::Enum(b)) => a == b,
            (Self::Pattern(a), Self::Pattern(b)) => a.as_str() == b.as_str(),
            (Self::Enum(_), Self::Pattern(_)) | (Self::Pattern(_), Self::Enum(_)) => false,
        }
    }
}

impl Eq for Constraint {}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Slot {
    pub at: SlotAt,
    pub constraint: Option<Constraint>,
    pub description: String,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Shape {
    pub description: String,
    pub class: ShapeClass,
    pub forge: ForgeNeed,
    pub argv: Vec<ArgvToken>,
    pub slots: BTreeMap<String, Slot>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Grammar {
    pub program: String,
    pub tested: Tested,
    pub shapes: BTreeMap<String, Shape>,
    pub disabled: Vec<(String, String)>,
    pub canonical: String,
}

type Fields = [(String, Value)];

const TOP_KEYS: &[&str] = &["schema_version", "program", "tested", "shapes"];
const TESTED_KEYS: &[&str] = &["version", "date"];
const SHAPE_KEYS: &[&str] = &["description", "class", "forge", "argv", "slots"];
const FORGE_KEYS: &[&str] = &["base", "head"];
const SLOT_KEYS: &[&str] = &["at", "enum", "pattern", "description"];

impl Grammar {
    pub fn parse(stem: &str, text: &str) -> Result<Self, GrammarError> {
        let invalid = |reason: &str| GrammarError::Invalid(reason.to_string());
        let Value::Map(top) = crate::load_str(text).map_err(GrammarError::Config)? else {
            return Err(invalid("the document must be a mapping"));
        };
        closed("grammar", &top, TOP_KEYS)?;
        if !matches!(get(&top, "schema_version"), Some(Value::Int(1))) {
            return Err(invalid("schema_version must be 1"));
        }
        let program = match get(&top, "program") {
            Some(Value::Str(p)) if crate::tools::tool_program_name_ok(p) => p.clone(),
            _ => return Err(invalid("program must be a program name")),
        };
        if program != stem {
            return Err(GrammarError::Invalid(format!(
                "program `{program}` must equal the file name `{stem}`"
            )));
        }
        let tested = parse_tested(get(&top, "tested"))?;
        let Some(Value::Map(shape_nodes)) = get(&top, "shapes") else {
            return Err(invalid("shapes must be a mapping"));
        };
        for (_, node) in shape_nodes {
            check_shape_keys(node)?;
        }
        let mut grammar = Self {
            program,
            tested,
            shapes: BTreeMap::new(),
            disabled: Vec::new(),
            canonical: crate::canonical_json(&Value::Map(top.clone())),
        };
        for (name, node) in shape_nodes {
            match parse_shape(name, node) {
                Ok(shape) => {
                    grammar.shapes.insert(name.clone(), shape);
                }
                Err(reason) => grammar.disabled.push((name.clone(), reason)),
            }
        }
        Ok(grammar)
    }
}

pub fn shape_name_ok(name: &str) -> bool {
    name.split('.').all(|segment| {
        !segment.is_empty()
            && segment
                .bytes()
                .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
    })
}

fn ident_ok(name: &str) -> bool {
    name.starts_with(|c: char| c.is_ascii_lowercase())
        && name
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || matches!(b, b'_' | b'-'))
}

fn get<'a>(map: &'a Fields, key: &str) -> Option<&'a Value> {
    map.iter().find(|(k, _)| k == key).map(|(_, v)| v)
}

fn closed(section: &str, map: &Fields, allowed: &[&str]) -> Result<(), GrammarError> {
    crate::reject_unknown_keys(section, map, allowed).map_err(GrammarError::Config)
}

fn check_shape_keys(node: &Value) -> Result<(), GrammarError> {
    let Value::Map(shape) = node else {
        return Ok(());
    };
    closed("grammar.shapes", shape, SHAPE_KEYS)?;
    if let Some(Value::Map(forge)) = get(shape, "forge") {
        closed("grammar.shapes.forge", forge, FORGE_KEYS)?;
    }
    if let Some(Value::Map(slots)) = get(shape, "slots") {
        for (_, slot) in slots {
            if let Value::Map(slot) = slot {
                closed("grammar.shapes.slots", slot, SLOT_KEYS)?;
            }
        }
    }
    Ok(())
}

fn parse_tested(node: Option<&Value>) -> Result<Tested, GrammarError> {
    let Some(Value::Map(map)) = node else {
        return Err(GrammarError::Invalid("tested must be a mapping".into()));
    };
    closed("grammar.tested", map, TESTED_KEYS)?;
    let field = |key: &str| match get(map, key) {
        Some(Value::Str(s)) if !s.is_empty() => Ok(s.clone()),
        _ => Err(GrammarError::Invalid(format!(
            "tested.{key} must be a non-empty string"
        ))),
    };
    Ok(Tested {
        version: field("version")?,
        date: field("date")?,
    })
}

fn text<'a>(v: Option<&'a Value>, what: &str) -> Result<&'a str, String> {
    match v {
        Some(Value::Str(s)) if !s.is_empty() => Ok(s),
        _ => Err(format!("{what} must be a non-empty string")),
    }
}

fn parse_shape(name: &str, node: &Value) -> Result<Shape, String> {
    if !shape_name_ok(name) {
        return Err(
            "the shape name must be lowercase letters, digits and `-` in `.`-joined segments"
                .into(),
        );
    }
    let Value::Map(map) = node else {
        return Err("the shape must be a mapping".into());
    };
    let description = text(get(map, "description"), "description")?.to_string();
    let class = match text(get(map, "class"), "class")? {
        "read" => ShapeClass::Read,
        "write" => ShapeClass::Write,
        other => return Err(format!("class `{other}` is not read or write")),
    };
    let forge = parse_forge(get(map, "forge"))?;
    let slots = parse_slots(get(map, "slots"))?;
    let Some(Value::Seq(tokens)) = get(map, "argv") else {
        return Err("argv must be a list".into());
    };
    let argv = tokens
        .iter()
        .map(|t| match t {
            Value::Str(s) => parse_token(s),
            _ => Err("an argv token must be a string".to_string()),
        })
        .collect::<Result<Vec<_>, _>>()?;
    check_slot_use(&argv, &slots)?;
    Ok(Shape {
        description,
        class,
        forge,
        argv,
        slots,
    })
}

fn parse_forge(node: Option<&Value>) -> Result<ForgeNeed, String> {
    let Some(node) = node else {
        return Ok(ForgeNeed::default());
    };
    let Value::Map(map) = node else {
        return Err("forge must be a mapping".into());
    };
    let side = |key: &str| -> Result<ForgeOps, String> {
        match get(map, key) {
            None => Ok(ForgeOps::EMPTY),
            Some(Value::Seq(items)) => items
                .iter()
                .map(|item| match item {
                    Value::Str(s) => s.parse::<ForgeOp>(),
                    _ => Err(format!("forge.{key} entries must be strings")),
                })
                .collect(),
            Some(_) => Err(format!("forge.{key} must be a list")),
        }
    };
    let need = SideReach::new(side("base")?, side("head")?)?;
    Ok(ForgeNeed {
        base: need.base(),
        head: need.head(),
    })
}

fn parse_slots(node: Option<&Value>) -> Result<BTreeMap<String, Slot>, String> {
    let map = match node {
        None => return Ok(BTreeMap::new()),
        Some(Value::Map(map)) => map,
        Some(_) => return Err("slots must be a mapping".into()),
    };
    let mut slots = BTreeMap::new();
    for (name, body) in map {
        if !ident_ok(name) {
            return Err(format!(
                "slot name `{name}` must be lowercase letters, digits, `_` or `-`"
            ));
        }
        slots.insert(name.clone(), parse_slot(name, body)?);
    }
    Ok(slots)
}

fn parse_slot(name: &str, node: &Value) -> Result<Slot, String> {
    let Value::Map(map) = node else {
        return Err(format!("slot `{name}` must be a mapping"));
    };
    let at = match text(get(map, "at"), "at")? {
        "token" => SlotAt::Token,
        "option" => SlotAt::Option,
        "stdin" => SlotAt::Stdin,
        "file" => SlotAt::File,
        other => {
            return Err(format!(
                "slot `{name}`: at `{other}` is not token, option, stdin or file"
            ))
        }
    };
    let description = text(get(map, "description"), "description")
        .map_err(|e| format!("slot `{name}`: {e}"))?
        .to_string();
    let constraint = match (get(map, "enum"), get(map, "pattern")) {
        (None, None) => None,
        (Some(_), Some(_)) => return Err(format!("slot `{name}`: enum and pattern are exclusive")),
        (Some(Value::Seq(items)), None) => Some(parse_enum(name, items)?),
        (Some(_), None) => return Err(format!("slot `{name}`: enum must be a list")),
        (None, Some(p)) => Some(compile_pattern(name, p)?),
    };
    match (at, &constraint) {
        (SlotAt::Token, None) => Err(format!("token slot `{name}` needs an enum or a pattern")),
        (SlotAt::Stdin | SlotAt::File, Some(_)) => Err(format!(
            "slot `{name}` carries free text and takes no constraint"
        )),
        (SlotAt::Token, Some(_)) | (SlotAt::Option, _) | (SlotAt::Stdin | SlotAt::File, None) => {
            Ok(Slot {
                at,
                constraint,
                description,
            })
        }
    }
}

fn parse_enum(name: &str, items: &[Value]) -> Result<Constraint, String> {
    let mut members = BTreeSet::new();
    for item in items {
        let Value::Str(s) = item else {
            return Err(format!("slot `{name}`: enum members must be strings"));
        };
        if s.is_empty() || !members.insert(s.clone()) {
            return Err(format!(
                "slot `{name}`: enum members must be non-empty and distinct"
            ));
        }
    }
    if members.is_empty() {
        return Err(format!("slot `{name}`: enum must not be empty"));
    }
    Ok(Constraint::Enum(members))
}

fn compile_pattern(name: &str, node: &Value) -> Result<Constraint, String> {
    let source = text(Some(node), "pattern").map_err(|e| format!("slot `{name}`: {e}"))?;
    let build = |pattern: &str| {
        RegexBuilder::new(pattern)
            .size_limit(PATTERN_SIZE_LIMIT)
            .build()
            .map_err(|e| format!("slot `{name}`: pattern: {e}"))
    };
    build(source)?;
    build(&format!("^(?:{source})$")).map(Constraint::Pattern)
}

fn parse_token(s: &str) -> Result<ArgvToken, String> {
    if s.chars().any(char::is_control) {
        return Err(format!(
            "argv token `{}` has a control character",
            s.escape_debug()
        ));
    }
    if let Some(inner) = whole_braced(s) {
        return match inner.split_once('.') {
            Some((kind, field)) if ident_ok(kind) && ident_ok(field) => Ok(ArgvToken::Bound {
                kind: kind.to_string(),
                field: field.to_string(),
            }),
            Some(_) => Err(format!("bound value `{s}` is not `{{kind.field}}`")),
            None if ident_ok(inner) => Ok(ArgvToken::Slot(inner.to_string())),
            None => Err(format!("slot reference `{s}` is not a slot name")),
        };
    }
    if s.starts_with('-') {
        if let Some((prefix, rest)) = s.split_once('=') {
            if let Some(slot) = whole_braced(rest).filter(|n| ident_ok(n)) {
                if prefix.contains(['{', '}']) {
                    return Err(format!("partial interpolation in `{s}`"));
                }
                return Ok(ArgvToken::OptionSlot {
                    prefix: format!("{prefix}="),
                    slot: slot.to_string(),
                });
            }
        }
    }
    if s.contains(['{', '}']) {
        return Err(format!("partial interpolation in argv token `{s}`"));
    }
    Ok(ArgvToken::Literal(s.to_string()))
}

fn whole_braced(s: &str) -> Option<&str> {
    let inner = s.strip_prefix('{')?.strip_suffix('}')?;
    (!inner.contains(['{', '}'])).then_some(inner)
}

fn check_slot_use(argv: &[ArgvToken], slots: &BTreeMap<String, Slot>) -> Result<(), String> {
    let mut uses: BTreeMap<&str, usize> = BTreeMap::new();
    for token in argv {
        let (name, wants): (&str, &[SlotAt]) = match token {
            ArgvToken::Slot(name) => (name, &[SlotAt::Token, SlotAt::File]),
            ArgvToken::OptionSlot { slot, .. } => (slot, &[SlotAt::Option]),
            ArgvToken::Literal(_) | ArgvToken::Bound { .. } => continue,
        };
        let Some(slot) = slots.get(name) else {
            return Err(format!("argv uses the undeclared slot `{name}`"));
        };
        if !wants.contains(&slot.at) {
            return Err(format!(
                "slot `{name}` is used where its `at` does not belong"
            ));
        }
        *uses.entry(name).or_default() += 1;
    }
    let mut stdin = 0;
    for (name, slot) in slots {
        let used = uses.get(name.as_str()).copied().unwrap_or(0);
        match slot.at {
            SlotAt::Stdin => {
                stdin += 1;
                if stdin > 1 {
                    return Err("at most one stdin slot".into());
                }
                if used != 0 {
                    return Err(format!("stdin slot `{name}` must not appear in argv"));
                }
            }
            SlotAt::Token | SlotAt::Option | SlotAt::File => {
                if used != 1 {
                    return Err(format!(
                        "slot `{name}` must be used exactly once, found {used}"
                    ));
                }
            }
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    const PR_COMMENT_AND_ISSUE_LIST: &str = r#"
schema_version: 1
program: gh
tested: { version: "2.105.0", date: 2026-11-24 }
shapes:
  pr.comment:
    description: Add a comment to the pull request this task is about.
    class: write
    forge: { base: [review] }
    argv: [pr, comment, "{git.change}", -R, "{git.base}", --body-file, "-"]
    slots:
      body: { at: stdin, description: "The comment, in Markdown." }
  issue.list:
    description: List issues in the repository this task is about.
    class: read
    forge: { base: [read] }
    argv: [issue, list, -R, "{git.base}", "--state={state}"]
    slots:
      state: { at: option, enum: [open, closed, all], description: Which issues to list. }
"#;

    fn parse(text: &str) -> Grammar {
        Grammar::parse("gh", text).unwrap()
    }

    fn lit(s: &str) -> ArgvToken {
        ArgvToken::Literal(s.to_string())
    }

    fn bound(kind: &str, field: &str) -> ArgvToken {
        ArgvToken::Bound {
            kind: kind.into(),
            field: field.into(),
        }
    }

    fn with_shape(name: &str, body: &str) -> String {
        format!(
            "schema_version: 1\nprogram: gh\ntested: {{ version: \"1\", date: 2026-11-24 }}\nshapes:\n  ok.shape:\n    description: A good sibling.\n    class: read\n    argv: [view]\n  {name}:\n{body}"
        )
    }

    fn assert_disabled(name: &str, body: &str, needle: &str) {
        let g = parse(&with_shape(name, body));
        assert!(g.shapes.contains_key("ok.shape"), "sibling must load");
        assert!(!g.shapes.contains_key(name), "{name} must not load");
        let (n, reason) = g.disabled.iter().find(|(n, _)| n == name).unwrap();
        assert_eq!(n, name);
        assert!(reason.contains(needle), "{reason} lacks {needle}");
        assert_eq!(g.disabled.len(), 1);
    }

    const HEAD: &str = "    description: d\n    class: read\n";

    fn body(rest: &str) -> String {
        format!("{HEAD}{rest}")
    }

    #[test]
    fn grammar_parses_pr_comment_and_issue_list() {
        let g = parse(PR_COMMENT_AND_ISSUE_LIST);
        assert_eq!(g.program, "gh");
        assert_eq!(
            g.tested,
            Tested {
                version: "2.105.0".into(),
                date: "2026-11-24".into()
            }
        );
        assert!(g.disabled.is_empty());
        assert_eq!(g.shapes.len(), 2);

        let pr = &g.shapes["pr.comment"];
        assert_eq!(pr.class, ShapeClass::Write);
        assert_eq!(
            pr.description,
            "Add a comment to the pull request this task is about."
        );
        assert_eq!(pr.forge.base, ForgeOps::EMPTY.with(ForgeOp::Review));
        assert_eq!(pr.forge.head, ForgeOps::EMPTY);
        assert_eq!(
            pr.argv,
            [
                lit("pr"),
                lit("comment"),
                bound("git", "change"),
                lit("-R"),
                bound("git", "base"),
                lit("--body-file"),
                lit("-"),
            ]
        );
        let body = &pr.slots["body"];
        assert_eq!(body.at, SlotAt::Stdin);
        assert_eq!(body.constraint, None);
        assert_eq!(body.description, "The comment, in Markdown.");

        let list = &g.shapes["issue.list"];
        assert_eq!(list.class, ShapeClass::Read);
        assert_eq!(list.forge.base, ForgeOps::EMPTY.with(ForgeOp::Read));
        assert_eq!(
            list.argv[4],
            ArgvToken::OptionSlot {
                prefix: "--state=".into(),
                slot: "state".into()
            }
        );
        assert_eq!(list.argv.len(), 5);
        let state = &list.slots["state"];
        assert_eq!(state.at, SlotAt::Option);
        assert_eq!(
            state.constraint,
            Some(Constraint::Enum(
                ["open", "closed", "all"].map(String::from).into()
            ))
        );
        assert!(g.canonical.starts_with("{\"program\":\"gh\""));
    }

    #[test]
    fn program_case_mismatch_refuses_the_file() {
        let err = Grammar::parse("GH", PR_COMMENT_AND_ISSUE_LIST).unwrap_err();
        assert!(
            matches!(err, GrammarError::Invalid(ref r) if r.contains("`gh`") && r.contains("`GH`"))
        );
        assert!(Grammar::parse("gh", PR_COMMENT_AND_ISSUE_LIST).is_ok());
    }

    #[test]
    fn unknown_key_refuses_the_file() {
        let top = PR_COMMENT_AND_ISSUE_LIST.replacen("shapes:", "extra: 1\nshapes:", 1);
        let shape = PR_COMMENT_AND_ISSUE_LIST.replacen(
            "    class: read",
            "    class: read\n    cost: 1",
            1,
        );
        let slot = PR_COMMENT_AND_ISSUE_LIST.replacen("at: stdin,", "at: stdin, size: 3,", 1);
        let forge = PR_COMMENT_AND_ISSUE_LIST.replacen(
            "forge: { base: [read] }",
            "forge: { base: [read], tail: [] }",
            1,
        );
        let tested = PR_COMMENT_AND_ISSUE_LIST.replacen(
            "date: 2026-11-24 }",
            "date: 2026-11-24, by: x }",
            1,
        );
        for doc in [top, shape, slot, forge, tested] {
            assert!(
                matches!(
                    Grammar::parse("gh", &doc),
                    Err(GrammarError::Config(ConfigError::UnknownKey { .. }))
                ),
                "{doc}"
            );
        }
    }

    #[test]
    fn file_level_faults_refuse_the_file() {
        let doc = PR_COMMENT_AND_ISSUE_LIST;
        for bad in [
            doc.replacen("schema_version: 1", "schema_version: 2", 1),
            doc.replacen("program: gh\n", "", 1),
            doc.replacen(
                "tested: { version: \"2.105.0\", date: 2026-11-24 }\n",
                "",
                1,
            ),
            doc.replacen("version: \"2.105.0\", ", "", 1),
            doc.replacen("shapes:", "shapes: 3\nx:", 1),
            "- a\n".to_string(),
            "a: [\n".to_string(),
        ] {
            assert!(Grammar::parse("gh", &bad).is_err(), "{bad}");
        }
    }

    #[test]
    fn unused_slot_disables_shape() {
        assert_disabled(
            "bad.unused",
            &body("    argv: [view]\n    slots:\n      n: { at: token, pattern: '[0-9]+', description: n }\n"),
            "exactly once",
        );
    }

    #[test]
    fn slot_used_twice_disables_shape() {
        assert_disabled(
            "bad.twice",
            &body("    argv: [\"{n}\", \"{n}\"]\n    slots:\n      n: { at: token, pattern: '[0-9]+', description: n }\n"),
            "exactly once",
        );
    }

    #[test]
    fn undeclared_slot_disables_shape() {
        assert_disabled(
            "bad.undeclared",
            &body("    argv: [view, \"{n}\"]\n"),
            "undeclared",
        );
        assert_disabled(
            "bad.undeclared-opt",
            &body("    argv: [\"--n={n}\"]\n"),
            "undeclared",
        );
    }

    #[test]
    fn two_stdin_slots_disable_shape() {
        assert_disabled(
            "bad.stdin",
            &body("    argv: [view]\n    slots:\n      a: { at: stdin, description: a }\n      b: { at: stdin, description: b }\n"),
            "at most one stdin",
        );
    }

    #[test]
    fn stdin_slot_in_argv_disables_shape() {
        assert_disabled(
            "bad.stdin-argv",
            &body("    argv: [\"{a}\"]\n    slots:\n      a: { at: stdin, description: a }\n"),
            "does not belong",
        );
    }

    #[test]
    fn slot_used_at_the_wrong_position_disables_shape() {
        assert_disabled(
            "bad.position",
            &body("    argv: [\"--x={a}\"]\n    slots:\n      a: { at: token, enum: [x], description: a }\n"),
            "does not belong",
        );
        assert_disabled(
            "bad.position2",
            &body("    argv: [\"{a}\"]\n    slots:\n      a: { at: option, enum: [x], description: a }\n"),
            "does not belong",
        );
    }

    #[test]
    fn token_slot_without_constraint_disables_shape() {
        assert_disabled(
            "bad.token",
            &body("    argv: [\"{a}\"]\n    slots:\n      a: { at: token, description: a }\n"),
            "needs an enum or a pattern",
        );
    }

    #[test]
    fn stdin_slot_with_constraint_disables_shape() {
        for (at, c) in [("stdin", "enum: [a]"), ("file", "pattern: 'a'")] {
            let argv = if at == "file" { "[\"{a}\"]" } else { "[view]" };
            assert_disabled(
                "bad.free-text",
                &body(&format!(
                    "    argv: {argv}\n    slots:\n      a: {{ at: {at}, {c}, description: a }}\n"
                )),
                "takes no constraint",
            );
        }
    }

    #[test]
    fn option_and_file_slots_parse_with_their_rules() {
        let g = parse(&with_shape(
            "good.mix",
            &body("    argv: [run, \"--t={t}\", \"--u={u}\", \"{f}\"]\n    slots:\n      t: { at: option, description: t }\n      u: { at: option, pattern: '[a-z]+', description: u }\n      f: { at: file, description: f }\n"),
        ));
        assert!(g.disabled.is_empty());
        let s = &g.shapes["good.mix"];
        assert_eq!(s.slots["t"].constraint, None);
        assert_eq!(s.slots["f"].at, SlotAt::File);
        assert_eq!(s.argv[3], ArgvToken::Slot("f".into()));
    }

    #[test]
    fn bad_regex_disables_shape() {
        for pat in ["'['", "'a)|(b'", "'(?x)a #'", "'(a{1000}){1000}'", "'\\pL'"] {
            assert_disabled(
                "bad.regex",
                &body(&format!("    argv: [\"{{a}}\"]\n    slots:\n      a: {{ at: token, pattern: {pat}, description: a }}\n")),
                "pattern",
            );
        }
    }

    #[test]
    fn pattern_matches_the_whole_value() {
        let g = parse(&with_shape(
            "good.pat",
            &body("    argv: [\"{a}\"]\n    slots:\n      a: { at: token, pattern: 'a|bc', description: a }\n"),
        ));
        let Some(Constraint::Pattern(re)) = &g.shapes["good.pat"].slots["a"].constraint else {
            panic!("pattern expected");
        };
        assert!(re.is_match("a") && re.is_match("bc"));
        assert!(
            !re.is_match("ab") && !re.is_match("xbc") && !re.is_match("bcx") && !re.is_match("")
        );
        assert!(!re.is_match("a\n") && !re.is_match("\na"));
    }

    #[test]
    fn push_head_on_base_disables_shape() {
        assert_disabled(
            "bad.push",
            &body("    forge: { base: [push-head] }\n    argv: [view]\n"),
            "PushHead",
        );
        let g = parse(&with_shape(
            "good.push",
            &body("    forge: { head: [push-head] }\n    argv: [view]\n"),
        ));
        assert_eq!(
            g.shapes["good.push"].forge.head,
            ForgeOps::EMPTY.with(ForgeOp::PushHead)
        );
    }

    #[test]
    fn bad_forge_disables_shape() {
        assert_disabled(
            "bad.forge1",
            &body("    forge: { base: [nope] }\n    argv: [view]\n"),
            "nope",
        );
        assert_disabled(
            "bad.forge2",
            &body("    forge: { base: read }\n    argv: [view]\n"),
            "list",
        );
        assert_disabled(
            "bad.forge3",
            &body("    forge: [read]\n    argv: [view]\n"),
            "mapping",
        );
        assert_disabled(
            "bad.forge4",
            &body("    forge: { base: [3] }\n    argv: [view]\n"),
            "strings",
        );
    }

    #[test]
    fn partial_interpolation_disables_shape() {
        for tok in [
            "pre{a}",
            "{a}post",
            "--x=pre{a}",
            "{a",
            "a}",
            "--x={a}{b}",
            "{{a}}",
            "{}",
            "{git.}",
            "{A}",
            "--{a}=v",
            "{a.b.c}",
        ] {
            assert_disabled(
                "bad.partial",
                &body(&format!(
                    "    argv: [\"{tok}\"]\n    slots:\n      a: {{ at: token, enum: [x], description: a }}\n"
                )),
                "",
            );
        }
    }

    #[test]
    fn bad_shape_name_disables_shape() {
        for name in [
            "Pr.view", "pr..view", ".pr", "pr.", "pr_view", "pr view", "pr.vi/ew",
        ] {
            let g = parse(&with_shape(
                &format!("'{name}'"),
                &body("    argv: [view]\n"),
            ));
            assert_eq!(g.shapes.len(), 1, "{name}");
            assert_eq!(g.disabled.len(), 1, "{name}");
            assert!(g.disabled[0].1.contains("shape name"));
        }
        assert!(shape_name_ok("pr.review-2.x9"));
        assert!(!shape_name_ok(""));
    }

    #[test]
    fn malformed_shape_bodies_disable_the_shape() {
        assert_disabled("bad.body", "    3\n", "mapping");
        for bad in [
            "    class: read\n    argv: [view]\n",
            "    description: d\n    argv: [view]\n",
            "    description: d\n    class: both\n    argv: [view]\n",
            "    description: d\n    class: read\n",
            "    description: d\n    class: read\n    argv: view\n",
            "    description: d\n    class: read\n    argv: [3]\n",
            "    description: d\n    class: read\n    argv: [\"a\\u0001\"]\n",
            "    description: d\n    class: read\n    argv: [view]\n    slots: 3\n",
            "    description: d\n    class: read\n    argv: [view]\n    slots:\n      a: 3\n",
            "    description: d\n    class: read\n    argv: [view]\n    slots:\n      A: { at: stdin, description: a }\n",
        ] {
            let g = parse(&with_shape("bad.x", bad));
            assert!(g.disabled.iter().any(|(n, _)| n == "bad.x"), "{bad}");
            assert!(g.shapes.contains_key("ok.shape"));
        }
    }

    #[test]
    fn malformed_slots_disable_the_shape() {
        for slot in [
            "{ at: edge, enum: [a], description: a }",
            "{ at: token, enum: [a] }",
            "{ at: token, enum: [a], pattern: a, description: a }",
            "{ at: token, enum: a, description: a }",
            "{ at: token, enum: [], description: a }",
            "{ at: token, enum: [a, a], description: a }",
            "{ at: token, enum: [\"\"], description: a }",
            "{ at: token, enum: [1], description: a }",
            "{ at: token, pattern: \"\", description: a }",
            "{ description: a, enum: [a] }",
        ] {
            assert_disabled(
                "bad.slot",
                &body(&format!(
                    "    argv: [\"{{a}}\"]\n    slots:\n      a: {slot}\n"
                )),
                "",
            );
        }
    }

    #[test]
    fn bound_tokens_are_whole_kind_dot_field() {
        let g = parse(&with_shape(
            "good.bound",
            &body("    argv: [\"{git.base}\", \"{x-y.z_1}\"]\n"),
        ));
        assert_eq!(
            g.shapes["good.bound"].argv,
            [bound("git", "base"), bound("x-y", "z_1")]
        );
    }

    #[test]
    fn literal_with_equals_and_dash_stays_literal() {
        let g = parse(&with_shape(
            "good.lit",
            &body("    argv: [\"--state=open\", \"=x\", \"-\"]\n"),
        ));
        assert_eq!(
            g.shapes["good.lit"].argv,
            [lit("--state=open"), lit("=x"), lit("-")]
        );
    }

    #[test]
    fn catalogs_with_equal_pattern_text_are_equal() {
        let doc = |pat: &str| {
            with_shape(
                "good.pat",
                &body(&format!(
                    "    argv: [\"{{a}}\"]\n    slots:\n      a: {{ at: token, pattern: '{pat}', description: a }}\n"
                )),
            )
        };
        assert_eq!(parse(&doc("[0-9]+")), parse(&doc("[0-9]+")));
        assert_ne!(parse(&doc("[0-9]+")), parse(&doc("[0-8]+")));
        let en = with_shape(
            "good.pat",
            &body("    argv: [\"{a}\"]\n    slots:\n      a: { at: token, enum: [x], description: a }\n"),
        );
        assert_ne!(parse(&en), parse(&doc("x")));
        assert_eq!(parse(&en), parse(&en));
        let en2 = en.replace("[x]", "[y]");
        assert_ne!(parse(&en), parse(&en2));
    }

    #[test]
    fn malformed_names_name_their_fault() {
        for (tok, needle) in [
            ("{A}", "not a slot name"),
            ("{a b}", "not a slot name"),
            ("{A.b}", "not `{kind.field}`"),
            ("{a.B}", "not `{kind.field}`"),
            ("{1a.b}", "not `{kind.field}`"),
            ("{a.1b}", "not `{kind.field}`"),
        ] {
            assert_disabled(
                "bad.name",
                &body(&format!("    argv: [\"{tok}\"]\n")),
                needle,
            );
        }
        for slot in ["aB", "1a", "a.b", "a b", "_a"] {
            assert_disabled(
                "bad.slotname",
                &body(&format!(
                    "    argv: [view]\n    slots:\n      '{slot}': {{ at: stdin, description: a }}\n"
                )),
                "slot name",
            );
        }
    }

    #[test]
    fn program_and_tested_must_be_well_formed() {
        let doc = PR_COMMENT_AND_ISSUE_LIST;
        for bad in ["a/b", "a b", ""] {
            let text = doc.replacen("program: gh", &format!("program: \"{bad}\""), 1);
            assert!(Grammar::parse(bad, &text).is_err(), "{bad:?}");
        }
        assert!(Grammar::parse(
            "g+h.1_x-y",
            &doc.replacen("program: gh", "program: g+h.1_x-y", 1)
        )
        .is_ok());
        for field in ["version: \"2.105.0\"", "date: 2026-11-24"] {
            let key = field.split(':').next().unwrap();
            let text = doc.replacen(field, &format!("{key}: \"\""), 1);
            assert!(Grammar::parse("gh", &text).is_err(), "{key}");
        }
    }

    #[test]
    fn constraints_compare_by_kind_members_and_pattern_text() {
        let re = |p: &str| Constraint::Pattern(Regex::new(p).unwrap());
        let en = |m: &[&str]| Constraint::Enum(m.iter().map(|s| s.to_string()).collect());
        assert_eq!(re("a"), re("a"));
        assert_ne!(re("a"), re("b"));
        assert_eq!(en(&["a", "b"]), en(&["b", "a"]));
        assert_ne!(en(&["a"]), en(&["b"]));
        assert_ne!(en(&["a"]), re("a"));
        assert_ne!(re("a"), en(&["a"]));
    }

    #[test]
    fn display_names_the_fault() {
        let e = Grammar::parse("gh", "schema_version: 2\n").unwrap_err();
        assert!(e.to_string().starts_with("grammar: schema_version"));
        let e = Grammar::parse("gh", "a: [\n").unwrap_err();
        assert!(e.to_string().starts_with("grammar: "));
    }
}
