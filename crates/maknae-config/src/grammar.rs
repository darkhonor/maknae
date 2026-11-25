//! A tool grammar file (#674 PR 3): the argv shapes one program may be called with.

use crate::{Bound, ConfigError, Value};
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

impl ShapeClass {
    pub const ALL: [ShapeClass; 2] = [ShapeClass::Read, ShapeClass::Write];

    pub fn as_str(self) -> &'static str {
        match self {
            ShapeClass::Read => "read",
            ShapeClass::Write => "write",
        }
    }

    pub fn parse(text: &str) -> Option<Self> {
        Self::ALL.into_iter().find(|v| v.as_str() == text)
    }
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

impl SlotAt {
    pub const ALL: [SlotAt; 4] = [SlotAt::Token, SlotAt::Option, SlotAt::Stdin, SlotAt::File];

    pub fn as_str(self) -> &'static str {
        match self {
            SlotAt::Token => "token",
            SlotAt::Option => "option",
            SlotAt::Stdin => "stdin",
            SlotAt::File => "file",
        }
    }

    pub fn parse(text: &str) -> Option<Self> {
        Self::ALL.into_iter().find(|v| v.as_str() == text)
    }
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
        let doc = crate::load_str(text).map_err(GrammarError::Config)?;
        let Value::Map(top) = &doc else {
            return Err(invalid("the document must be a mapping"));
        };
        closed("grammar", top, TOP_KEYS)?;
        if !matches!(get(top, "schema_version"), Some(Value::Int(1))) {
            return Err(invalid("schema_version must be 1"));
        }
        let program = match get(top, "program") {
            Some(Value::Str(p)) if crate::tools::tool_program_name_ok(p) => p.clone(),
            _ => return Err(invalid("program must be a program name")),
        };
        if program != stem {
            return Err(GrammarError::Invalid(format!(
                "program `{program}` must equal the file name `{stem}`"
            )));
        }
        let tested = parse_tested(get(top, "tested"))?;
        let Some(Value::Map(shape_nodes)) = get(top, "shapes") else {
            return Err(invalid("shapes must be a mapping"));
        };
        let mut grammar = Self {
            program,
            tested,
            shapes: BTreeMap::new(),
            disabled: Vec::new(),
            canonical: crate::canonical_json(&doc),
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

fn closed_in_shape(section: &str, map: &Fields, allowed: &[&str]) -> Result<(), String> {
    crate::reject_unknown_keys(section, map, allowed).map_err(|e| e.to_string())
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
    closed_in_shape("grammar.shapes", map, SHAPE_KEYS)?;
    let description = text(get(map, "description"), "description")?.to_string();
    let class = text(get(map, "class"), "class")?;
    let class =
        ShapeClass::parse(class).ok_or_else(|| format!("class `{class}` is not read or write"))?;
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
    closed_in_shape("grammar.shapes.forge", map, FORGE_KEYS)?;
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
    closed_in_shape("grammar.shapes.slots", map, SLOT_KEYS)?;
    let at = text(get(map, "at"), "at").map_err(|e| format!("slot `{name}`: {e}"))?;
    let at = match SlotAt::parse(at) {
        Some(at) => at,
        None => {
            return Err(format!(
                "slot `{name}`: at `{at}` is not token, option, stdin or file"
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

const SLOT_FILE_DIR: &str = "/run/maknae/slots";
const TOKEN_MAX: usize = 256;
const OPTION_MAX: usize = 4096;
const BODY_MAX: usize = 65_536;
const OPEN_TOKENS_MAX: usize = 64;
const OPEN_TOKEN_MAX: usize = 4096;

/// A slot name or bound key the grammar defines; only this module builds one, so a refusal
/// never carries request input.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct GrammarName(String);

impl GrammarName {
    fn of(name: &str) -> Self {
        Self(name.to_owned())
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl std::fmt::Display for GrammarName {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum CallRefusal {
    MissingSlot(GrammarName),
    UnexpectedSlot,
    Invariant {
        slot: GrammarName,
        rule: &'static str,
    },
    Constraint {
        slot: GrammarName,
    },
    UnresolvedBound(GrammarName),
    BadBound(GrammarName),
    OpenToken {
        index: usize,
        rule: &'static str,
    },
    OpenTooMany,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SlotFile {
    pub path: String,
    pub content: Vec<u8>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Rendered {
    pub argv: Vec<String>,
    pub stdin: Option<Vec<u8>>,
    pub files: Vec<SlotFile>,
}

fn check_value(name: &str, slot: &Slot, value: &str) -> Result<(), CallRefusal> {
    let refuse = |rule| {
        Err(CallRefusal::Invariant {
            slot: GrammarName::of(name),
            rule,
        })
    };
    match slot.at {
        SlotAt::Token => {
            if value.is_empty() {
                return refuse("empty");
            }
            if value.len() > TOKEN_MAX {
                return refuse("too_long");
            }
            if value.starts_with('-') {
                return refuse("leading_dash");
            }
            if value.chars().any(char::is_control) {
                return refuse("control");
            }
        }
        SlotAt::Option => {
            if value.len() > OPTION_MAX {
                return refuse("too_long");
            }
            if value.contains('\0') {
                return refuse("nul");
            }
        }
        SlotAt::Stdin | SlotAt::File => {
            if value.len() > BODY_MAX {
                return refuse("too_long");
            }
        }
    }
    match &slot.constraint {
        None => Ok(()),
        Some(Constraint::Enum(members)) if members.contains(value) => Ok(()),
        Some(Constraint::Pattern(re)) if re.is_match(value) => Ok(()),
        Some(Constraint::Enum(_)) | Some(Constraint::Pattern(_)) => Err(CallRefusal::Constraint {
            slot: GrammarName::of(name),
        }),
    }
}

fn bound_value<'a>(kind: &str, field: &str, bound: &'a Bound) -> Result<&'a str, CallRefusal> {
    let key = || GrammarName(format!("{kind}.{field}"));
    let value = bound
        .get(kind, field)
        .ok_or_else(|| CallRefusal::UnresolvedBound(key()))?;
    if value.is_empty() || value.starts_with('-') || value.chars().any(char::is_control) {
        return Err(CallRefusal::BadBound(key()));
    }
    Ok(value)
}

fn slot_file_path(slot: &str) -> String {
    format!("{SLOT_FILE_DIR}/{slot}")
}

impl Shape {
    pub fn render(
        &self,
        slots: &BTreeMap<String, String>,
        bound: &Bound,
    ) -> Result<Rendered, CallRefusal> {
        if slots.keys().any(|k| !self.slots.contains_key(k)) {
            return Err(CallRefusal::UnexpectedSlot);
        }
        let given = |name: &str| {
            slots
                .get(name)
                .ok_or_else(|| CallRefusal::MissingSlot(GrammarName::of(name)))
        };
        for (name, slot) in &self.slots {
            check_value(name, slot, given(name)?)?;
        }
        let position = |name: &str| CallRefusal::Invariant {
            slot: GrammarName::of(name),
            rule: "position",
        };
        let mut argv = Vec::with_capacity(self.argv.len());
        for token in &self.argv {
            match token {
                ArgvToken::Literal(text) => argv.push(text.clone()),
                ArgvToken::Bound { kind, field } => {
                    argv.push(bound_value(kind, field, bound)?.to_string());
                }
                ArgvToken::Slot(name) => {
                    let slot = self.slots.get(name).ok_or_else(|| position(name))?;
                    match slot.at {
                        SlotAt::Token => argv.push(given(name)?.clone()),
                        SlotAt::File => argv.push(slot_file_path(name)),
                        SlotAt::Option | SlotAt::Stdin => return Err(position(name)),
                    }
                }
                ArgvToken::OptionSlot { prefix, slot: name } => {
                    let slot = self.slots.get(name).ok_or_else(|| position(name))?;
                    match slot.at {
                        SlotAt::Option => argv.push(format!("{prefix}{}", given(name)?)),
                        SlotAt::Token | SlotAt::File | SlotAt::Stdin => {
                            return Err(position(name));
                        }
                    }
                }
            }
        }
        let mut stdin = None;
        let mut files = Vec::new();
        for (name, slot) in &self.slots {
            match slot.at {
                SlotAt::Stdin => stdin = Some(given(name)?.clone().into_bytes()),
                SlotAt::File => files.push(SlotFile {
                    path: slot_file_path(name),
                    content: given(name)?.clone().into_bytes(),
                }),
                SlotAt::Token | SlotAt::Option => {}
            }
        }
        Ok(Rendered { argv, stdin, files })
    }

    pub fn matches_argv(&self, argv: &[String], bound: &Bound) -> bool {
        if argv.len() != self.argv.len() {
            return false;
        }
        self.argv
            .iter()
            .zip(argv)
            .all(|(token, actual)| match token {
                ArgvToken::Literal(text) => text == actual,
                ArgvToken::Bound { kind, field } => {
                    bound_value(kind, field, bound).is_ok_and(|v| v == actual)
                }
                ArgvToken::Slot(name) => self.slots.get(name).is_some_and(|slot| match slot.at {
                    SlotAt::Token => check_value(name, slot, actual).is_ok(),
                    SlotAt::File => *actual == slot_file_path(name),
                    SlotAt::Option | SlotAt::Stdin => false,
                }),
                ArgvToken::OptionSlot { prefix, slot: name } => {
                    self.slots.get(name).is_some_and(|slot| match slot.at {
                        SlotAt::Option => actual
                            .strip_prefix(prefix.as_str())
                            .is_some_and(|value| check_value(name, slot, value).is_ok()),
                        SlotAt::Token | SlotAt::File | SlotAt::Stdin => false,
                    })
                }
            })
    }
}

pub fn check_open_argv(argv: &[String]) -> Result<(), CallRefusal> {
    if argv.len() > OPEN_TOKENS_MAX {
        return Err(CallRefusal::OpenTooMany);
    }
    for (index, token) in argv.iter().enumerate() {
        let rule = if token.len() > OPEN_TOKEN_MAX {
            "too_long"
        } else if token.contains('\0') {
            "nul"
        } else if token.chars().any(|c| c != '\t' && c.is_control()) {
            "control"
        } else {
            continue;
        };
        return Err(CallRefusal::OpenToken { index, rule });
    }
    Ok(())
}

pub const GRAMMARS_DIR: &str = "grammars";

#[cfg(target_os = "macos")]
pub const VENDOR_GRAMMAR_DIR: &str = "/usr/local/share/maknae/grammars";
#[cfg(not(target_os = "macos"))]
pub const VENDOR_GRAMMAR_DIR: &str = "/usr/share/maknae/grammars";

const GRAMMAR_SUFFIX: &str = ".yaml";

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DisabledGrammar {
    pub file: String,
    pub reason: String,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct GrammarSet {
    pub grammars: BTreeMap<String, Grammar>,
    pub disabled: Vec<DisabledGrammar>,
}

impl GrammarSet {
    pub fn empty() -> Self {
        Self {
            grammars: BTreeMap::new(),
            disabled: Vec::new(),
        }
    }
}

#[cfg(any(test, feature = "hermetic-test-seam"))]
pub fn shipped_grammars() -> GrammarSet {
    let text = include_str!("../../../packaging/common/grammars/gh.yaml");
    let mut set = GrammarSet::empty();
    set.grammars
        .insert("gh".to_string(), Grammar::parse("gh", text).unwrap());
    set
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum GrammarLoadError {
    Directory(std::path::PathBuf),
    Io(String),
}

impl fmt::Display for GrammarLoadError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Directory(dir) => write!(
                f,
                "the grammar directory {} must be owned by root (uid 0), not group-writable and with no world access",
                dir.display()
            ),
            Self::Io(reason) => write!(f, "grammar directory: {reason}"),
        }
    }
}

impl std::error::Error for GrammarLoadError {}

#[cfg(unix)]
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct GrammarRequirement {
    pub dir: maknae_io::AnchorRequired,
    pub member: maknae_io::TargetRequired,
    pub vendor: maknae_io::AnchorRequired,
}

#[cfg(unix)]
impl GrammarRequirement {
    pub fn from_member(member: maknae_io::TargetRequired) -> Self {
        Self {
            dir: maknae_io::AnchorRequired {
                owner: member.owner,
                mode_mask: Some(0o027),
            },
            vendor: maknae_io::AnchorRequired {
                owner: member.owner,
                mode_mask: Some(0o022),
            },
            member,
        }
    }
}

pub fn load_grammars(
    config_dir: &std::path::Path,
    vendor_dir: &std::path::Path,
) -> Result<GrammarSet, GrammarLoadError> {
    #[cfg(not(unix))]
    {
        let _ = (config_dir, vendor_dir);
        Err(GrammarLoadError::Io(
            "grammar permission enforcement is unavailable on this platform".into(),
        ))
    }
    #[cfg(unix)]
    {
        load_required(
            config_dir,
            vendor_dir,
            &GrammarRequirement::from_member(crate::authz::root_policy_file_required()),
        )
    }
}

#[cfg(all(unix, feature = "hermetic-test-seam"))]
pub fn load_grammars_with_requirement(
    config_dir: &std::path::Path,
    vendor_dir: &std::path::Path,
    req: GrammarRequirement,
) -> Result<GrammarSet, GrammarLoadError> {
    load_required(config_dir, vendor_dir, &req)
}

#[cfg(unix)]
fn load_required(
    config_dir: &std::path::Path,
    vendor_dir: &std::path::Path,
    req: &GrammarRequirement,
) -> Result<GrammarSet, GrammarLoadError> {
    use maknae_io::{IoError, IoKind, Kind, StrategyPref};
    let io_err = |e: std::io::Error| GrammarLoadError::Io(e.to_string());
    let dir = std::path::absolute(config_dir.join(GRAMMARS_DIR)).map_err(io_err)?;
    let vendor_path = std::path::absolute(vendor_dir).map_err(io_err)?;
    let anchor = match maknae_io::open_anchor(&dir, req.dir.clone(), StrategyPref::Auto) {
        Ok(anchor) => anchor,
        Err(IoError::Io {
            kind: IoKind::NotFound,
            path,
        }) if path == dir => return Ok(GrammarSet::empty()),
        Err(IoError::InsecurePermissions { .. } | IoError::NotOwned { .. }) => {
            return Err(GrammarLoadError::Directory(dir))
        }
        Err(other) => return Err(GrammarLoadError::Io(other.to_string())),
    };
    let mut entries = anchor
        .enumerate(std::path::Path::new(""), None)
        .map_err(|e| GrammarLoadError::Io(e.to_string()))?
        .value;
    entries.retain(|entry| {
        let name = entry.name.to_string_lossy();
        !name.starts_with('.') && name.ends_with(GRAMMAR_SUFFIX)
    });
    entries.sort_by(|a, b| a.name.cmp(&b.name));
    let vendor =
        maknae_io::open_anchor_resolved(&vendor_path, req.vendor.clone(), StrategyPref::Auto);
    let mut set = GrammarSet::empty();
    for entry in entries {
        let file = entry.name.to_string_lossy().into_owned();
        let Some(stem) = entry
            .name
            .to_str()
            .and_then(|name| name.strip_suffix(GRAMMAR_SUFFIX))
        else {
            set.disabled.push(DisabledGrammar {
                file,
                reason: "the file name is not valid UTF-8".to_string(),
            });
            continue;
        };
        if !crate::tools::tool_program_name_ok(stem) || stem.ends_with(GRAMMAR_SUFFIX) {
            let reason = format!("`{stem}` is not a program name");
            set.disabled.push(DisabledGrammar { file, reason });
            continue;
        }
        let read = match &vendor {
            Ok(vendor) => anchor
                .read_enabled_member(&file, vendor, &vendor_path, req.member.clone())
                .map(|member| match member {
                    maknae_io::EnabledMember::Local(bytes)
                    | maknae_io::EnabledMember::Vendor(bytes) => bytes,
                })
                .map_err(|e| e.to_string()),
            Err(_) if entry.kind == Kind::File => anchor
                .read(std::path::Path::new(&file), None, req.member.clone())
                .map(|outcome| outcome.value)
                .map_err(|e| e.to_string()),
            Err(e) => Err(format!("the vendor grammar directory is unavailable: {e}")),
        };
        let parsed = read.and_then(|bytes| {
            let text = std::str::from_utf8(&bytes).map_err(|e| format!("invalid UTF-8: {e}"))?;
            Grammar::parse(stem, text).map_err(|e| e.to_string())
        });
        match parsed {
            Ok(grammar) => {
                set.grammars.insert(stem.to_owned(), grammar);
            }
            Err(reason) => set.disabled.push(DisabledGrammar { file, reason }),
        }
    }
    Ok(set)
}

#[cfg(test)]
mod tests {
    use super::*;

    const PR_COMMENT_AND_ISSUE_LIST: &str =
        include_str!("testdata/grammar_pr_comment_and_issue_list.yaml");

    #[test]
    fn grammar_name_exposes_and_displays_its_text() {
        let name = GrammarName::of("state");
        assert_eq!(name.as_str(), "state");
        assert_eq!(name.to_string(), "state");
    }

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
    fn unknown_top_level_key_refuses_the_file() {
        let top = PR_COMMENT_AND_ISSUE_LIST.replacen("shapes:", "extra: 1\nshapes:", 1);
        assert!(matches!(
            Grammar::parse("gh", &top),
            Err(GrammarError::Config(ConfigError::UnknownKey { ref key, .. })) if key == "extra"
        ));
    }

    #[test]
    fn unknown_tested_key_refuses_the_file() {
        let tested = PR_COMMENT_AND_ISSUE_LIST.replacen(
            "date: 2026-11-24 }",
            "date: 2026-11-24, by: x }",
            1,
        );
        assert!(matches!(
            Grammar::parse("gh", &tested),
            Err(GrammarError::Config(ConfigError::UnknownKey { ref key, .. })) if key == "by"
        ));
    }

    #[test]
    fn unknown_key_inside_a_shape_slot_or_forge_disables_only_that_shape() {
        let doc = PR_COMMENT_AND_ISSUE_LIST;
        for (bad, key) in [
            (
                doc.replacen("    class: read", "    class: read\n    cost: 1", 1),
                "cost",
            ),
            (doc.replacen("at: stdin,", "at: stdin, size: 3,", 1), "size"),
            (
                doc.replacen(
                    "forge: { base: [read] }",
                    "forge: { base: [read], tail: [] }",
                    1,
                ),
                "tail",
            ),
        ] {
            let g = parse(&bad);
            assert_eq!(g.disabled.len(), 1, "{key}");
            assert!(g.disabled[0].1.contains(key), "{}", g.disabled[0].1);
            assert_eq!(g.shapes.len(), 1, "{key}");
        }
    }

    #[test]
    fn canonical_is_the_canonical_json_of_the_whole_authored_document() {
        let text = with_shape("bad.x", &body("    argv: [\"{n}\"]\n"));
        let g = parse(&text);
        assert_eq!(g.disabled.len(), 1);
        assert_eq!(
            g.canonical,
            crate::canonical_json(&crate::load_str(&text).unwrap())
        );
        assert!(g.canonical.contains("bad.x"));
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

    fn slots(pairs: &[(&str, &str)]) -> BTreeMap<String, String> {
        pairs
            .iter()
            .map(|(k, v)| ((*k).to_string(), (*v).to_string()))
            .collect()
    }

    fn git_bound() -> Bound {
        let mut b = Bound::empty();
        b.insert("git.change", "12");
        b.insert("git.base", "o/r");
        b
    }

    const RENDER_GRAMMAR: &str = include_str!("testdata/grammar_render.yaml");

    fn shape(name: &str) -> Shape {
        let g = parse(RENDER_GRAMMAR);
        assert!(g.disabled.is_empty(), "{:?}", g.disabled);
        g.shapes[name].clone()
    }

    fn s(v: &[&str]) -> Vec<String> {
        v.iter().map(|t| (*t).to_string()).collect()
    }

    #[test]
    fn pr_comment_renders_with_bound_values_and_stdin() {
        let r = shape("pr.comment")
            .render(&slots(&[("body", "hello")]), &git_bound())
            .unwrap();
        assert_eq!(
            r.argv,
            s(&["pr", "comment", "12", "-R", "o/r", "--body-file", "-"])
        );
        assert_eq!(r.stdin, Some(b"hello".to_vec()));
        assert!(r.files.is_empty());
        let r = shape("issue.list")
            .render(&slots(&[("state", "open")]), &git_bound())
            .unwrap();
        assert_eq!(r.stdin, None);
    }

    #[test]
    fn option_slot_starting_with_dash_renders_as_one_token() {
        let r = shape("issue.edit")
            .render(&slots(&[("number", "1"), ("title", "-x")]), &Bound::empty())
            .unwrap();
        assert_eq!(r.argv, s(&["issue", "edit", "1", "--title=-x"]));
        let r = shape("issue.edit")
            .render(&slots(&[("number", "1"), ("title", "")]), &Bound::empty())
            .unwrap();
        assert_eq!(r.argv[3], "--title=");
    }

    #[test]
    fn token_slot_leading_dash_is_refused() {
        let e = shape("issue.word")
            .render(&slots(&[("word", "--exec=x")]), &Bound::empty())
            .unwrap_err();
        assert_eq!(
            e,
            CallRefusal::Invariant {
                slot: GrammarName::of("word"),
                rule: "leading_dash"
            }
        );
        for (v, rule) in [("", "empty"), ("a\nb", "control"), ("a\u{7f}", "control")] {
            let e = shape("issue.word")
                .render(&slots(&[("word", v)]), &Bound::empty())
                .unwrap_err();
            assert_eq!(
                e,
                CallRefusal::Invariant {
                    slot: GrammarName::of("word"),
                    rule
                }
            );
        }
    }

    #[test]
    fn enum_slot_outside_members_is_refused() {
        let e = shape("issue.list")
            .render(&slots(&[("state", "merged")]), &git_bound())
            .unwrap_err();
        assert_eq!(
            e,
            CallRefusal::Constraint {
                slot: GrammarName::of("state")
            }
        );
    }

    #[test]
    fn pattern_slot_must_match_fully() {
        let view = shape("issue.view");
        assert!(view
            .render(&slots(&[("number", "12")]), &Bound::empty())
            .is_ok());
        for bad in ["12a", "a12", "012", "12345678901"] {
            let e = view
                .render(&slots(&[("number", bad)]), &Bound::empty())
                .unwrap_err();
            assert_eq!(
                e,
                CallRefusal::Constraint {
                    slot: GrammarName::of("number")
                }
            );
        }
    }

    #[test]
    fn slot_at_limit_accepted_one_over_refused_multibyte() {
        let euro = "\u{20ac}";
        let stdin_ok = format!("a{}", euro.repeat(21_845));
        assert_eq!(stdin_ok.len(), 65_536);
        let r = shape("pr.comment")
            .render(&slots(&[("body", &stdin_ok)]), &git_bound())
            .unwrap();
        assert_eq!(r.stdin.unwrap(), stdin_ok.as_bytes());
        let over = format!("{stdin_ok}a");
        assert_eq!(over.len(), 65_537);
        let e = shape("pr.comment")
            .render(&slots(&[("body", &over)]), &git_bound())
            .unwrap_err();
        assert_eq!(
            e,
            CallRefusal::Invariant {
                slot: GrammarName::of("body"),
                rule: "too_long"
            }
        );
        let split = format!("{}{euro}", "a".repeat(65_535));
        assert_eq!(split.len(), 65_538);
        assert!(shape("pr.comment")
            .render(&slots(&[("body", &split)]), &git_bound())
            .is_err());

        let tok_ok = format!("a{}", euro.repeat(85));
        assert_eq!(tok_ok.len(), 256);
        assert!(shape("issue.word")
            .render(&slots(&[("word", &tok_ok)]), &Bound::empty())
            .is_ok());
        let tok_over = format!("{tok_ok}a");
        assert!(shape("issue.word")
            .render(&slots(&[("word", &tok_over)]), &Bound::empty())
            .is_err());
        let tok_split = format!("aa{}", euro.repeat(85));
        assert_eq!(tok_split.len(), 257);
        assert_eq!(
            shape("issue.word")
                .render(&slots(&[("word", &tok_split)]), &Bound::empty())
                .unwrap_err(),
            CallRefusal::Invariant {
                slot: GrammarName::of("word"),
                rule: "too_long"
            }
        );

        let opt_ok = format!("a{}", euro.repeat(1365));
        assert_eq!(opt_ok.len(), 4096);
        let edit = shape("issue.edit");
        assert!(edit
            .render(
                &slots(&[("number", "1"), ("title", &opt_ok)]),
                &Bound::empty()
            )
            .is_ok());
        let opt_over = format!("{opt_ok}a");
        assert!(edit
            .render(
                &slots(&[("number", "1"), ("title", &opt_over)]),
                &Bound::empty()
            )
            .is_err());
        assert!(edit
            .render(
                &slots(&[("number", "1"), ("title", "a\0b")]),
                &Bound::empty()
            )
            .is_err());
        assert!(edit
            .render(
                &slots(&[("number", "1"), ("title", "a\tb\nc")]),
                &Bound::empty()
            )
            .is_ok());
    }

    #[test]
    fn missing_and_unexpected_slots_are_refused() {
        let e = shape("issue.list")
            .render(&slots(&[]), &git_bound())
            .unwrap_err();
        assert_eq!(e, CallRefusal::MissingSlot(GrammarName::of("state")));
        let e = shape("issue.list")
            .render(&slots(&[("state", "open"), ("extra", "x")]), &git_bound())
            .unwrap_err();
        assert_eq!(e, CallRefusal::UnexpectedSlot);
    }

    #[test]
    fn unresolved_and_dash_bound_values_are_refused() {
        let pr = shape("pr.comment");
        let given = slots(&[("body", "x")]);
        let mut only_base = Bound::empty();
        only_base.insert("git.base", "o/r");
        assert_eq!(
            pr.render(&given, &only_base).unwrap_err(),
            CallRefusal::UnresolvedBound(GrammarName::of("git.change"))
        );
        for bad in ["-12", "1\n2", ""] {
            let mut b = git_bound();
            b.insert("git.change", bad);
            assert_eq!(
                pr.render(&given, &b).unwrap_err(),
                CallRefusal::BadBound(GrammarName::of("git.change"))
            );
        }
    }

    #[test]
    fn file_slot_gets_maknae_path() {
        let r = shape("issue.file")
            .render(&slots(&[("body", "text")]), &Bound::empty())
            .unwrap();
        assert_eq!(
            r.argv,
            s(&["issue", "create", "--body-file", "/run/maknae/slots/body"])
        );
        assert_eq!(
            r.files,
            vec![SlotFile {
                path: "/run/maknae/slots/body".into(),
                content: b"text".to_vec()
            }]
        );
        assert_eq!(r.stdin, None);
    }

    #[test]
    fn open_argv_limits() {
        let n = |k: usize| vec!["a".to_string(); k];
        assert_eq!(check_open_argv(&[]), Ok(()));
        assert_eq!(check_open_argv(&n(64)), Ok(()));
        assert_eq!(check_open_argv(&n(65)), Err(CallRefusal::OpenTooMany));
        let ok = vec!["a".repeat(4096)];
        assert_eq!(check_open_argv(&ok), Ok(()));
        let over = vec!["ok".to_string(), "a".repeat(4097)];
        assert_eq!(
            check_open_argv(&over),
            Err(CallRefusal::OpenToken {
                index: 1,
                rule: "too_long"
            })
        );
        let multi = vec![format!("a{}", "\u{20ac}".repeat(1365))];
        assert_eq!(multi[0].len(), 4096);
        assert_eq!(check_open_argv(&multi), Ok(()));
        assert!(check_open_argv(&[format!("{}a", multi[0])]).is_err());
        assert_eq!(
            check_open_argv(&s(&["a\0b"])),
            Err(CallRefusal::OpenToken {
                index: 0,
                rule: "nul"
            })
        );
        assert_eq!(
            check_open_argv(&s(&["ok", "a\nb"])),
            Err(CallRefusal::OpenToken {
                index: 1,
                rule: "control"
            })
        );
        assert_eq!(check_open_argv(&s(&["a\tb"])), Ok(()));
    }

    #[test]
    fn refusals_never_carry_the_value() {
        let probe = "PROBE-VALUE";
        let word = shape("issue.word");
        let list = shape("issue.list");
        let mut refusals = vec![
            word.render(&slots(&[("word", &format!("-{probe}"))]), &Bound::empty())
                .unwrap_err(),
            list.render(&slots(&[("state", probe)]), &git_bound())
                .unwrap_err(),
            list.render(&slots(&[("state", "open"), (probe, "x")]), &git_bound())
                .unwrap_err(),
            list.render(&slots(&[]), &git_bound()).unwrap_err(),
            check_open_argv(&[format!("{probe}\0")]).unwrap_err(),
            check_open_argv(&vec![probe.to_string(); 65]).unwrap_err(),
        ];
        let mut b = git_bound();
        b.insert("git.base", &format!("-{probe}"));
        refusals.push(list.render(&slots(&[("state", "open")]), &b).unwrap_err());
        refusals.push(
            list.render(&slots(&[("state", "open")]), &Bound::empty())
                .unwrap_err(),
        );
        assert_eq!(refusals.len(), 8);
        for r in &refusals {
            let shown = format!("{r:?}");
            assert!(!shown.contains(probe), "{shown}");
        }
    }

    #[test]
    fn matches_argv_accepts_what_render_produces() {
        let cases: Vec<(&str, Vec<(&str, &str)>)> = vec![
            ("pr.comment", vec![("body", "hi")]),
            ("issue.list", vec![("state", "closed")]),
            ("issue.view", vec![("number", "42")]),
            ("issue.edit", vec![("number", "2"), ("title", "-x y")]),
            ("issue.file", vec![("body", "t")]),
            ("issue.word", vec![("word", "needle")]),
        ];
        for (name, given) in cases {
            let sh = shape(name);
            let given = slots(&given);
            let r = sh.render(&given, &git_bound()).unwrap();
            assert!(sh.matches_argv(&r.argv, &git_bound()), "{name}");
        }
    }

    #[test]
    fn matches_argv_refuses_a_changed_literal() {
        let sh = shape("pr.comment");
        let mut argv = sh
            .render(&slots(&[("body", "x")]), &git_bound())
            .unwrap()
            .argv;
        argv[1] = "close".into();
        assert!(!sh.matches_argv(&argv, &git_bound()));
    }

    #[test]
    fn matches_argv_refuses_a_different_bound_value() {
        let sh = shape("pr.comment");
        let argv = sh
            .render(&slots(&[("body", "x")]), &git_bound())
            .unwrap()
            .argv;
        let mut other = git_bound();
        other.insert("git.change", "13");
        assert!(!sh.matches_argv(&argv, &other));
        assert!(!sh.matches_argv(&argv, &Bound::empty()));
        let mut dash = git_bound();
        dash.insert("git.change", "-12");
        let mut dashed = argv.clone();
        dashed[2] = "-12".into();
        assert!(!sh.matches_argv(&dashed, &dash));
    }

    #[test]
    fn matches_argv_refuses_a_slot_failing_its_constraint() {
        let list = shape("issue.list");
        let argv = s(&["issue", "list", "-R", "o/r", "--state=merged"]);
        assert!(!list.matches_argv(&argv, &git_bound()));
        let view = shape("issue.view");
        assert!(!view.matches_argv(&s(&["issue", "view", "12a"]), &Bound::empty()));
        assert!(!view.matches_argv(&s(&["issue", "view", "-1"]), &Bound::empty()));
        let word = shape("issue.word");
        assert!(!word.matches_argv(&s(&["search", "--exec=x"]), &Bound::empty()));
        assert!(!word.matches_argv(&s(&["search", ""]), &Bound::empty()));
        let edit = shape("issue.edit");
        assert!(!edit.matches_argv(&s(&["issue", "edit", "1", "--title=a\0b"]), &Bound::empty()));
        assert!(!edit.matches_argv(&s(&["issue", "edit", "1", "title=a"]), &Bound::empty()));
        assert!(edit.matches_argv(&s(&["issue", "edit", "1", "--title="]), &Bound::empty()));
    }

    #[test]
    fn matches_argv_refuses_extra_or_missing_tokens() {
        let sh = shape("issue.view");
        let good = s(&["issue", "view", "7"]);
        assert!(sh.matches_argv(&good, &Bound::empty()));
        let mut extra = good.clone();
        extra.push("x".into());
        assert!(!sh.matches_argv(&extra, &Bound::empty()));
        assert!(!sh.matches_argv(&good[..2], &Bound::empty()));
        assert!(!sh.matches_argv(&[], &Bound::empty()));
        let pr = shape("pr.comment");
        let mut full = pr
            .render(&slots(&[("body", "x")]), &git_bound())
            .unwrap()
            .argv;
        full.push("--extra".into());
        assert!(!pr.matches_argv(&full, &git_bound()));
    }

    #[test]
    fn matches_argv_refuses_a_file_slot_path_other_than_maknaes() {
        let sh = shape("issue.file");
        let ok = s(&["issue", "create", "--body-file", "/run/maknae/slots/body"]);
        assert!(sh.matches_argv(&ok, &Bound::empty()));
        for bad in [
            "/etc/passwd",
            "/run/maknae/slots/other",
            "/run/maknae/slots/body/",
            "body",
        ] {
            let argv = s(&["issue", "create", "--body-file", bad]);
            assert!(!sh.matches_argv(&argv, &Bound::empty()), "{bad}");
        }
    }

    #[cfg(all(unix, feature = "hermetic-test-seam"))]
    mod load_tests {
        use super::*;
        use std::os::unix::fs::{MetadataExt, PermissionsExt};
        use std::path::{Path, PathBuf};

        const GH: &str = "schema_version: 1\nprogram: gh\ntested: { version: \"2.105.0\", date: 2026-11-24 }\nshapes:\n  issue.list:\n    description: List issues.\n    class: read\n    forge: { base: [read] }\n    argv: [issue, list, -R, \"{git.base}\"]\n";

        struct Fixture {
            root: PathBuf,
            config: PathBuf,
            vendor: PathBuf,
        }

        impl Fixture {
            fn new(tag: &str) -> Self {
                let root =
                    std::env::temp_dir().join(format!("grammar_{tag}_{}", std::process::id()));
                let _ = std::fs::remove_dir_all(&root);
                let config = root.join("etc");
                let vendor = root.join("vendor");
                for d in [&root, &config, &vendor] {
                    std::fs::create_dir_all(d).unwrap();
                }
                let root = root.canonicalize().unwrap();
                let config = root.join("etc");
                let vendor = root.join("vendor");
                set_mode(&root, 0o755);
                set_mode(&config, 0o750);
                set_mode(&vendor, 0o755);
                Self {
                    root,
                    config,
                    vendor,
                }
            }

            fn grammars(&self) -> PathBuf {
                let d = self.config.join(GRAMMARS_DIR);
                if !d.exists() {
                    std::fs::create_dir(&d).unwrap();
                    set_mode(&d, 0o750);
                }
                d
            }

            fn local(&self, name: &str, text: &str) {
                let p = self.grammars().join(name);
                std::fs::write(&p, text).unwrap();
                set_mode(&p, 0o640);
            }

            fn vendor_file(&self, name: &str, text: &str) {
                let p = self.vendor.join(name);
                std::fs::write(&p, text).unwrap();
                set_mode(&p, 0o644);
            }

            fn link(&self, name: &str) {
                std::os::unix::fs::symlink(self.vendor.join(name), self.grammars().join(name))
                    .unwrap();
            }

            fn requirement(&self) -> GrammarRequirement {
                GrammarRequirement::from_member(member(
                    std::fs::metadata(&self.root).unwrap().uid(),
                ))
            }

            fn load(&self) -> Result<GrammarSet, GrammarLoadError> {
                load_grammars_with_requirement(&self.config, &self.vendor, self.requirement())
            }
        }

        impl Drop for Fixture {
            fn drop(&mut self) {
                let _ = std::fs::remove_dir_all(&self.root);
            }
        }

        fn member(owner: u32) -> maknae_io::TargetRequired {
            maknae_io::TargetRequired {
                owner: Some(owner),
                mode_mask: Some(0o027),
                nlink_exactly_one: false,
                regular_file: true,
                max_bytes: None,
            }
        }

        fn set_mode(p: &Path, mode: u32) {
            std::fs::set_permissions(p, std::fs::Permissions::from_mode(mode)).unwrap();
        }

        fn only_disabled(set: &GrammarSet) -> &DisabledGrammar {
            assert_eq!(set.disabled.len(), 1, "{:?}", set.disabled);
            &set.disabled[0]
        }

        #[test]
        fn requirement_derives_dir_and_vendor_masks_from_the_member() {
            let m = member(7);
            let got = GrammarRequirement::from_member(m.clone());
            assert_eq!(
                got.dir,
                maknae_io::AnchorRequired {
                    owner: Some(7),
                    mode_mask: Some(0o027)
                }
            );
            assert_eq!(
                got.vendor,
                maknae_io::AnchorRequired {
                    owner: Some(7),
                    mode_mask: Some(0o022)
                }
            );
            assert_eq!(got.member, m);
        }

        #[test]
        fn vendor_dir_default_is_the_per_os_path() {
            assert!(Path::new(VENDOR_GRAMMAR_DIR).is_absolute());
            assert!(VENDOR_GRAMMAR_DIR.ends_with("/maknae/grammars"));
        }

        #[test]
        fn absent_grammar_dir_is_empty() {
            let f = Fixture::new("absent");
            assert_eq!(f.load(), Ok(GrammarSet::empty()));
        }

        #[test]
        fn linked_and_local_grammars_load() {
            let f = Fixture::new("both");
            f.vendor_file("gh.yaml", GH);
            f.link("gh.yaml");
            f.local("glab.yaml", &GH.replace("program: gh", "program: glab"));
            let set = f.load().unwrap();
            assert!(set.disabled.is_empty(), "{:?}", set.disabled);
            assert_eq!(set.grammars.keys().collect::<Vec<_>>(), ["gh", "glab"]);
            assert_eq!(set.grammars["gh"].program, "gh");
            assert!(set.grammars["gh"].shapes.contains_key("issue.list"));
        }

        #[test]
        fn local_file_overrides_by_being_the_member() {
            let f = Fixture::new("override");
            f.vendor_file("gh.yaml", GH);
            f.local("gh.yaml", &GH.replace("List issues.", "Local text."));
            let set = f.load().unwrap();
            assert!(set.disabled.is_empty(), "{:?}", set.disabled);
            assert_eq!(
                set.grammars["gh"].shapes["issue.list"].description,
                "Local text."
            );
        }

        #[test]
        fn members_without_the_yaml_suffix_are_ignored() {
            let f = Fixture::new("suffix");
            f.local("gh.yaml.bak", "not: [a grammar");
            f.local("README", "x");
            f.local("gh.yml", "x");
            assert_eq!(f.load(), Ok(GrammarSet::empty()));
        }

        #[test]
        fn doubled_suffix_member_cannot_shadow_a_grammar() {
            let f = Fixture::new("doubled");
            f.local("gh.yaml", GH);
            f.local("gh.yaml.yaml", GH);
            let set = f.load().unwrap();
            assert_eq!(set.grammars.keys().collect::<Vec<_>>(), ["gh"]);
            assert_eq!(
                set.grammars["gh"].shapes["issue.list"].description,
                "List issues."
            );
            let d = only_disabled(&set);
            assert_eq!(d.file, "gh.yaml.yaml");
            assert!(d.reason.contains("not a program name"), "{}", d.reason);
        }

        #[test]
        fn doubled_suffix_member_alone_loads_nothing() {
            let f = Fixture::new("doubled_alone");
            f.local("gh.yaml.yaml", GH);
            let set = f.load().unwrap();
            assert!(set.grammars.is_empty());
            assert_eq!(only_disabled(&set).file, "gh.yaml.yaml");
        }

        #[test]
        fn dot_members_are_ignored_as_in_tools_d() {
            let f = Fixture::new("dot");
            f.local(".yaml", GH);
            f.local(".#gh.yaml", GH);
            f.local("..yaml", GH);
            assert_eq!(f.load(), Ok(GrammarSet::empty()));
        }

        #[cfg(target_os = "linux")]
        #[test]
        fn non_utf8_member_name_is_disabled_with_its_own_reason() {
            use std::os::unix::ffi::OsStrExt;
            let f = Fixture::new("badname");
            let p = f
                .grammars()
                .join(std::ffi::OsStr::from_bytes(b"g\xffh.yaml"));
            std::fs::write(&p, GH).unwrap();
            set_mode(&p, 0o640);
            let set = f.load().unwrap();
            assert!(set.grammars.is_empty());
            assert_eq!(
                only_disabled(&set).reason,
                "the file name is not valid UTF-8"
            );
        }

        #[test]
        fn dangling_link_disables_only_that_grammar() {
            let f = Fixture::new("dangling");
            f.link("gh.yaml");
            f.local("glab.yaml", &GH.replace("program: gh", "program: glab"));
            let set = f.load().unwrap();
            assert_eq!(set.grammars.keys().collect::<Vec<_>>(), ["glab"]);
            assert_eq!(only_disabled(&set).file, "gh.yaml");
        }

        #[test]
        fn absent_vendor_dir_disables_links_keeps_local_files() {
            let f = Fixture::new("novendor");
            f.link("gh.yaml");
            f.local("glab.yaml", &GH.replace("program: gh", "program: glab"));
            std::fs::remove_dir(&f.vendor).unwrap();
            let set = f.load().unwrap();
            assert_eq!(set.grammars.keys().collect::<Vec<_>>(), ["glab"]);
            let d = only_disabled(&set);
            assert_eq!(d.file, "gh.yaml");
            assert!(
                d.reason.contains("vendor grammar directory"),
                "{}",
                d.reason
            );
        }

        #[test]
        fn wrong_link_target_disables_only_that_grammar() {
            let f = Fixture::new("wrong");
            f.vendor_file("gh.yaml", GH);
            let elsewhere = f.root.join("elsewhere.yaml");
            std::fs::write(&elsewhere, GH).unwrap();
            std::os::unix::fs::symlink(&elsewhere, f.grammars().join("gh.yaml")).unwrap();
            f.local("glab.yaml", &GH.replace("program: gh", "program: glab"));
            let set = f.load().unwrap();
            assert_eq!(set.grammars.keys().collect::<Vec<_>>(), ["glab"]);
            assert_eq!(only_disabled(&set).file, "gh.yaml");
        }

        #[test]
        fn unparseable_grammar_disables_only_that_grammar() {
            let f = Fixture::new("bad");
            f.local("gh.yaml", "schema_version: 1\nprogram: other\n");
            f.local("glab.yaml", &GH.replace("program: gh", "program: glab"));
            let set = f.load().unwrap();
            assert_eq!(set.grammars.keys().collect::<Vec<_>>(), ["glab"]);
            let d = only_disabled(&set);
            assert_eq!(d.file, "gh.yaml");
            assert!(
                d.reason.contains("must equal the file name"),
                "{}",
                d.reason
            );
        }

        #[test]
        fn non_utf8_grammar_disables_only_that_grammar() {
            let f = Fixture::new("utf8");
            let p = f.grammars().join("gh.yaml");
            std::fs::write(&p, [0xff, 0xfe]).unwrap();
            set_mode(&p, 0o640);
            let set = f.load().unwrap();
            assert!(set.grammars.is_empty());
            assert!(only_disabled(&set).reason.contains("invalid UTF-8"));
        }

        #[test]
        fn group_writable_grammar_dir_refuses_the_load() {
            let f = Fixture::new("gw");
            f.local("gh.yaml", GH);
            set_mode(&f.grammars(), 0o770);
            assert_eq!(f.load(), Err(GrammarLoadError::Directory(f.grammars())));
        }

        #[test]
        fn world_readable_grammar_dir_refuses_the_load() {
            let f = Fixture::new("wr");
            f.local("gh.yaml", GH);
            set_mode(&f.grammars(), 0o754);
            assert_eq!(f.load(), Err(GrammarLoadError::Directory(f.grammars())));
        }

        #[test]
        fn group_writable_grammar_member_is_disabled() {
            let f = Fixture::new("memberw");
            f.local("gh.yaml", GH);
            set_mode(&f.grammars().join("gh.yaml"), 0o660);
            let set = f.load().unwrap();
            assert!(set.grammars.is_empty());
            assert_eq!(only_disabled(&set).file, "gh.yaml");
        }

        #[test]
        fn insecure_vendor_dir_disables_links_keeps_local_files() {
            let f = Fixture::new("vendorw");
            f.vendor_file("gh.yaml", GH);
            f.link("gh.yaml");
            f.local("glab.yaml", &GH.replace("program: gh", "program: glab"));
            set_mode(&f.vendor, 0o775);
            let set = f.load().unwrap();
            assert_eq!(set.grammars.keys().collect::<Vec<_>>(), ["glab"]);
            assert_eq!(only_disabled(&set).file, "gh.yaml");
        }

        #[test]
        fn directory_member_is_disabled() {
            let f = Fixture::new("dirmember");
            std::fs::create_dir(f.grammars().join("gh.yaml")).unwrap();
            let set = f.load().unwrap();
            assert_eq!(only_disabled(&set).file, "gh.yaml");
        }

        #[test]
        fn foreign_owned_grammar_dir_refuses_the_load() {
            let f = Fixture::new("owner");
            f.local("gh.yaml", GH);
            let mut req = f.requirement();
            req.dir.owner = Some(std::fs::metadata(&f.root).unwrap().uid().wrapping_add(1));
            assert_eq!(
                load_grammars_with_requirement(&f.config, &f.vendor, req),
                Err(GrammarLoadError::Directory(f.grammars()))
            );
        }

        #[test]
        fn absent_config_dir_is_an_io_error() {
            let f = Fixture::new("noconfig");
            std::fs::remove_dir(&f.config).unwrap();
            assert!(matches!(f.load(), Err(GrammarLoadError::Io(_))));
        }

        #[test]
        fn grammars_dir_that_is_a_file_is_an_io_error() {
            let f = Fixture::new("notdir");
            std::fs::write(f.config.join(GRAMMARS_DIR), "x").unwrap();
            assert!(matches!(f.load(), Err(GrammarLoadError::Io(_))));
        }

        #[test]
        fn production_door_refuses_a_dir_root_does_not_own() {
            let f = Fixture::new("prod");
            f.local("gh.yaml", GH);
            crate::tests::test_owner::hand_to_nobody_when_root(&[&f.config, &f.grammars()]);
            assert_eq!(
                load_grammars(&f.config, &f.vendor),
                Err(GrammarLoadError::Directory(f.grammars()))
            );
        }

        #[test]
        fn load_error_names_the_directory() {
            let dir = GrammarLoadError::Directory(PathBuf::from("/etc/maknae/grammars"));
            assert!(dir.to_string().contains("/etc/maknae/grammars"));
            assert!(GrammarLoadError::Io("boom".into())
                .to_string()
                .contains("boom"));
        }
    }

    mod shipped_gh_tests {
        use super::*;

        const SHAPES: [&str; 22] = [
            "pr.view",
            "pr.diff",
            "pr.checks",
            "pr.review.comment",
            "pr.review.request-changes",
            "pr.review.approve",
            "pr.comment",
            "issue.list",
            "issue.status",
            "issue.view",
            "issue.create",
            "issue.comment",
            "issue.edit.title",
            "issue.edit.body",
            "issue.edit.add-label",
            "issue.edit.remove-label",
            "issue.edit.add-assignee",
            "issue.edit.remove-assignee",
            "issue.close",
            "issue.reopen",
            "issue.lock",
            "issue.unlock",
        ];

        fn gh() -> Grammar {
            shipped_grammars().grammars.remove("gh").unwrap()
        }

        fn slots(pairs: &[(&str, &str)]) -> BTreeMap<String, String> {
            pairs
                .iter()
                .map(|(k, v)| ((*k).to_string(), (*v).to_string()))
                .collect()
        }

        fn bound() -> Bound {
            let mut b = Bound::empty();
            b.insert("git.change", "345");
            b.insert("git.base", "o/r");
            b
        }

        #[test]
        fn shipped_gh_grammar_loads_with_no_disabled_shapes() {
            let g = gh();
            assert!(g.disabled.is_empty(), "{:?}", g.disabled);
            assert_eq!(g.program, "gh");
            assert_eq!(g.tested.version, "2.105.0");
            assert_eq!(g.tested.date, "2026-11-24");
        }

        #[test]
        fn shipped_gh_grammar_has_the_spec_shape_list() {
            let want: BTreeSet<&str> = SHAPES.iter().copied().collect();
            let got = gh();
            let got: BTreeSet<&str> = got.shapes.keys().map(String::as_str).collect();
            assert_eq!(got, want);
            assert!(!got.contains("issue.artifact"));
        }

        #[test]
        fn every_write_shape_declares_forge() {
            for (name, shape) in &gh().shapes {
                assert!(!shape.forge.base.is_empty(), "{name}");
                assert!(shape.forge.head.is_empty(), "{name}");
                let (want, class) = match name.as_str() {
                    n if n.starts_with("pr.review.") || n == "pr.comment" => {
                        (ForgeOp::Review, ShapeClass::Write)
                    }
                    "pr.view" | "pr.diff" | "pr.checks" | "issue.list" | "issue.status"
                    | "issue.view" => (ForgeOp::Read, ShapeClass::Read),
                    _ => (ForgeOp::IssueWrite, ShapeClass::Write),
                };
                assert!(shape.forge.base.contains(want), "{name}");
                assert_eq!(shape.class, class, "{name}");
            }
        }

        #[test]
        fn every_pull_request_shape_targets_the_change_and_base() {
            for (name, shape) in gh().shapes.iter().filter(|(n, _)| n.starts_with("pr.")) {
                let r = shape
                    .render(
                        &slots(&[("body", "x")][..usize::from(!shape.slots.is_empty())]),
                        &bound(),
                    )
                    .unwrap_or_else(|e| panic!("{name}: {e:?}"));
                assert_eq!(r.argv[0], "pr", "{name}");
                assert_eq!(r.argv[2..5], ["345", "-R", "o/r"], "{name}");
                assert_eq!(r.stdin.is_some(), !shape.slots.is_empty(), "{name}");
                if r.stdin.is_some() {
                    assert_eq!(r.argv[r.argv.len() - 2..], ["--body-file", "-"], "{name}");
                }
            }
        }

        #[test]
        fn issue_shapes_render_the_help_checked_argv() {
            let g = gh();
            let render = |shape: &str, pairs: &[(&str, &str)]| {
                g.shapes[shape]
                    .render(&slots(pairs), &bound())
                    .unwrap()
                    .argv
            };
            assert_eq!(
                render("issue.list", &[("state", "all")]),
                ["issue", "list", "-R", "o/r", "--state=all"]
            );
            assert_eq!(
                render("issue.create", &[("title", "-x"), ("body", "b")]),
                [
                    "issue",
                    "create",
                    "-R",
                    "o/r",
                    "--title=-x",
                    "--body-file",
                    "-"
                ]
            );
            assert_eq!(
                render("issue.edit.add-label", &[("number", "7"), ("label", "bug")]),
                ["issue", "edit", "7", "-R", "o/r", "--add-label", "bug"]
            );
        }

        #[test]
        fn issue_slots_refuse_values_outside_their_patterns() {
            let g = gh();
            let refuses = |shape: &str, pairs: &[(&str, &str)]| {
                g.shapes[shape].render(&slots(pairs), &bound()).is_err()
            };
            for number in ["0", "01", "-1", "12345678901", "7 ", "1e3", ""] {
                assert!(refuses("issue.close", &[("number", number)]), "{number:?}");
            }
            assert!(refuses("issue.list", &[("state", "merged")]));
            assert!(refuses(
                "issue.edit.add-label",
                &[("number", "1"), ("label", "-x")]
            ));
            assert!(refuses(
                "issue.edit.add-assignee",
                &[("number", "1"), ("login", "@me")]
            ));
            assert!(refuses(
                "issue.edit.title",
                &[("number", "1"), ("title", "two\nlines")]
            ));
            assert!(!refuses(
                "issue.edit.title",
                &[("number", "1"), ("title", "--force")]
            ));
        }
    }

    #[cfg(unix)]
    mod anchored_tests {
        use super::*;
        use std::os::unix::fs::PermissionsExt;

        const GH: &str = "schema_version: 1\nprogram: gh\ntested: { version: \"2.105.0\", date: 2026-11-24 }\nshapes:\n  issue.list:\n    description: List issues.\n    class: read\n    forge: { base: [read] }\n    argv: [issue, list, -R, \"{git.base}\"]\n";

        fn set_mode(p: &std::path::Path, mode: u32) {
            std::fs::set_permissions(p, std::fs::Permissions::from_mode(mode)).unwrap();
        }

        #[test]
        fn load_errors_display_their_exact_text() {
            assert_eq!(
                GrammarLoadError::Directory(std::path::PathBuf::from("/etc/maknae/grammars")).to_string(),
                "the grammar directory /etc/maknae/grammars must be owned by root (uid 0), not group-writable and with no world access"
            );
            assert_eq!(
                GrammarLoadError::Io("boom".into()).to_string(),
                "grammar directory: boom"
            );
        }

        #[test]
        fn hidden_and_non_yaml_members_are_ignored_and_a_yaml_member_loads() {
            let root = std::env::temp_dir().join(format!("grammar_anch_{}", std::process::id()));
            let _ = std::fs::remove_dir_all(&root);
            std::fs::create_dir_all(&root).unwrap();
            let root = root.canonicalize().unwrap();
            let config = root.join("etc");
            let vendor = root.join("vendor");
            let grammars = config.join(GRAMMARS_DIR);
            for d in [&config, &vendor, &grammars] {
                std::fs::create_dir_all(d).unwrap();
            }
            set_mode(&root, 0o755);
            set_mode(&config, 0o750);
            set_mode(&vendor, 0o755);
            set_mode(&grammars, 0o750);
            for (name, body) in [
                ("gh.yaml", GH),
                (".hidden.yaml", GH),
                ("README", "x"),
                ("notes.txt", "x"),
            ] {
                let p = grammars.join(name);
                std::fs::write(&p, body).unwrap();
                set_mode(&p, 0o640);
            }
            let req = GrammarRequirement::from_member(maknae_io::TargetRequired {
                owner: None,
                mode_mask: Some(0o027),
                nlink_exactly_one: false,
                regular_file: true,
                max_bytes: None,
            });
            let got = load_required(&config, &vendor, &req);
            let _ = std::fs::remove_dir_all(&root);
            let set = got.unwrap();
            assert!(set.disabled.is_empty(), "{:?}", set.disabled);
            assert_eq!(set.grammars.keys().collect::<Vec<_>>(), ["gh"]);
        }
    }
}
