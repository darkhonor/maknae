//! `tools.yaml` (#674): the catalog of tools a subject may be granted, bounded here.

use crate::argpattern::{ArgPattern, DenyArg};
use crate::grammar::{ArgvToken, ForgeNeed, GrammarSet, Shape};
use crate::{ConfigError, Value};
use std::collections::{BTreeMap, BTreeSet};
use std::fmt;
use std::path::Path;
use std::sync::Arc;

pub const TOOLS_FILE: &str = "tools.yaml";
pub const TOOLS_DROPIN_DIR: &str = "tools.d";

#[cfg(target_os = "macos")]
pub const VENDOR_TOOLS_DIR: &str = "/usr/local/share/maknae/tools.d";
#[cfg(not(target_os = "macos"))]
pub const VENDOR_TOOLS_DIR: &str = "/usr/share/maknae/tools.d";

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum CredentialKind {
    GithubAppInstallation,
    GithubMachineUser,
    GitlabProjectToken,
    GitlabBotToken,
    VaultChildToken,
    VaultDynamicSecret,
}

impl CredentialKind {
    pub fn parse(s: &str) -> Option<Self> {
        match s {
            "github-app-installation" => Some(Self::GithubAppInstallation),
            "github-machine-user" => Some(Self::GithubMachineUser),
            "gitlab-project-token" => Some(Self::GitlabProjectToken),
            "gitlab-bot-token" => Some(Self::GitlabBotToken),
            "vault-child-token" => Some(Self::VaultChildToken),
            "vault-dynamic-secret" => Some(Self::VaultDynamicSecret),
            _ => None,
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Self::GithubAppInstallation => "github-app-installation",
            Self::GithubMachineUser => "github-machine-user",
            Self::GitlabProjectToken => "gitlab-project-token",
            Self::GitlabBotToken => "gitlab-bot-token",
            Self::VaultChildToken => "vault-child-token",
            Self::VaultDynamicSecret => "vault-dynamic-secret",
        }
    }

    pub fn has_reach_check(self) -> bool {
        match self {
            Self::GithubAppInstallation => true,
            Self::GithubMachineUser
            | Self::GitlabProjectToken
            | Self::GitlabBotToken
            | Self::VaultChildToken
            | Self::VaultDynamicSecret => false,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CredentialSource {
    MintedPerTask,
    MintedPerInvocation,
    Stored,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CredentialNarrowing {
    Provider,
    Maknae,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CredentialMinting {
    TrustPlane,
    FrontEnd,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CredentialRevokeOn {
    TaskOutcome,
    InvocationOutcome,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ClassLifetime {
    pub expires: Option<String>,
    pub ttl: Option<String>,
    pub revoke_on: CredentialRevokeOn,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CredentialClass {
    pub name: String,
    pub kind: CredentialKind,
    pub app: Option<String>,
    pub source: Option<CredentialSource>,
    pub narrowing: Option<CredentialNarrowing>,
    pub minting: Option<CredentialMinting>,
    pub lifetime: Option<ClassLifetime>,
    pub policies: Vec<String>,
    pub delivery: Vec<String>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ToolVerify {
    Required,
    Optional,
}

impl ToolVerify {
    pub const ALL: [ToolVerify; 2] = [ToolVerify::Required, ToolVerify::Optional];

    pub fn as_str(self) -> &'static str {
        match self {
            ToolVerify::Required => "required",
            ToolVerify::Optional => "optional",
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ToolImage {
    pub reference: String,
    pub signature: Option<ToolVerify>,
    pub sbom: Option<ToolVerify>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ToolIsolation {
    Container,
    Vm,
}

impl ToolIsolation {
    pub const ALL: [ToolIsolation; 2] = [ToolIsolation::Container, ToolIsolation::Vm];

    pub fn as_str(self) -> &'static str {
        match self {
            ToolIsolation::Container => "container",
            ToolIsolation::Vm => "vm",
        }
    }

    pub fn parse(text: &str) -> Option<Self> {
        Self::ALL.into_iter().find(|v| v.as_str() == text)
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ToolNetwork {
    None,
    Proxy { sites: Vec<String> },
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ToolWorkspaceAccess {
    Rw,
    Ro,
    None,
}

impl ToolWorkspaceAccess {
    pub const ALL: [ToolWorkspaceAccess; 3] = [
        ToolWorkspaceAccess::Rw,
        ToolWorkspaceAccess::Ro,
        ToolWorkspaceAccess::None,
    ];

    pub fn as_str(self) -> &'static str {
        match self {
            ToolWorkspaceAccess::Rw => "rw",
            ToolWorkspaceAccess::Ro => "ro",
            ToolWorkspaceAccess::None => "none",
        }
    }

    pub fn parse(text: &str) -> Option<Self> {
        Self::ALL.into_iter().find(|v| v.as_str() == text)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ToolVolumeAccess {
    Ro,
    Rw,
}

impl ToolVolumeAccess {
    pub const ALL: [ToolVolumeAccess; 2] = [ToolVolumeAccess::Ro, ToolVolumeAccess::Rw];

    pub fn as_str(self) -> &'static str {
        match self {
            ToolVolumeAccess::Ro => "ro",
            ToolVolumeAccess::Rw => "rw",
        }
    }

    pub fn parse(text: &str) -> Option<Self> {
        Self::ALL.into_iter().find(|v| v.as_str() == text)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ToolVolumeScope {
    Task,
    Tasker,
}

impl ToolVolumeScope {
    pub const ALL: [ToolVolumeScope; 2] = [ToolVolumeScope::Task, ToolVolumeScope::Tasker];

    pub fn as_str(self) -> &'static str {
        match self {
            ToolVolumeScope::Task => "task",
            ToolVolumeScope::Tasker => "tasker",
        }
    }

    pub fn parse(text: &str) -> Option<Self> {
        Self::ALL.into_iter().find(|v| v.as_str() == text)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ToolVolume {
    pub access: ToolVolumeAccess,
    pub scope: Option<ToolVolumeScope>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum OutputToModel {
    Redacted,
    StatusOnly,
}

impl OutputToModel {
    pub const ALL: [OutputToModel; 2] = [OutputToModel::Redacted, OutputToModel::StatusOnly];

    pub fn as_str(self) -> &'static str {
        match self {
            OutputToModel::Redacted => "redacted",
            OutputToModel::StatusOnly => "status_only",
        }
    }

    pub fn parse(text: &str) -> Option<Self> {
        Self::ALL.into_iter().find(|v| v.as_str() == text)
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ToolResources {
    pub cpus: Option<String>,
    pub memory: Option<String>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum CommandForm {
    Positional(Vec<ArgPattern>),
    Grammar {
        grammar: String,
        grammar_canonical: Arc<str>,
        shapes: BTreeMap<String, Arc<Shape>>,
    },
    Open,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ToolCommand {
    pub form: CommandForm,
    pub deny_args: Vec<DenyArg>,
    pub timeout: Option<String>,
    pub output: Option<String>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ToolEntry {
    pub name: String,
    pub credential: Option<String>,
    pub binds: BTreeSet<String>,
    pub commands: BTreeMap<String, ToolCommand>,
    pub description: Option<String>,
    pub image: Option<ToolImage>,
    pub isolation: ToolIsolation,
    pub executes_workspace: bool,
    pub network: ToolNetwork,
    pub workspace: ToolWorkspaceAccess,
    pub volumes: BTreeMap<String, ToolVolume>,
    pub output_to_model: OutputToModel,
    pub resources: Option<ToolResources>,
    pub lifetime_max: Option<String>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Disabled {
    pub entry: String,
    pub reason: String,
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct ToolsCatalog {
    entries: BTreeMap<String, ToolEntry>,
    classes: BTreeMap<String, CredentialClass>,
    disabled: Vec<Disabled>,
    canonical: String,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ToolsError {
    Config(ConfigError),
    Invalid(String),
    DropIns(String),
}

impl fmt::Display for ToolsError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Config(e) => write!(f, "{TOOLS_FILE}: {e}"),
            Self::Invalid(reason) => write!(f, "{TOOLS_FILE}: {reason}"),
            Self::DropIns(reason) => write!(f, "{TOOLS_DROPIN_DIR}: {reason}"),
        }
    }
}

impl std::error::Error for ToolsError {}

struct Doc {
    top: Vec<(String, Value)>,
    classes: Vec<(String, Value)>,
    tools: Vec<(String, Value)>,
}

enum DropIn {
    Read { file: String, text: String },
    Unreadable { file: String, reason: String },
}

struct CommandContext<'a> {
    credential: bool,
    network: bool,
    binds: &'a BTreeSet<String>,
    grammars: &'a GrammarSet,
}

impl ToolsCatalog {
    pub fn empty() -> Self {
        Self::default()
    }

    pub fn parse(text: &str) -> Result<Self, ToolsError> {
        Self::parse_with(text, &GrammarSet::empty())
    }

    pub fn parse_with(text: &str, grammars: &GrammarSet) -> Result<Self, ToolsError> {
        Self::assemble(Some(text), Vec::new(), Vec::new(), grammars)
    }

    pub fn load(config_dir: &Path, grammars: &GrammarSet) -> Result<Self, ToolsError> {
        #[cfg(not(unix))]
        {
            let _ = (config_dir, grammars);
            Err(ToolsError::Config(ConfigError::PermissionsUnsupported))
        }
        #[cfg(unix)]
        {
            load_required(config_dir, host_tools_required(), grammars)
        }
    }

    pub fn from_texts(
        main: Option<&str>,
        dropins: &[(&str, &str)],
        grammars: &GrammarSet,
    ) -> Result<Self, ToolsError> {
        let mut named: Vec<&(&str, &str)> = dropins
            .iter()
            .filter(|(name, _)| is_dropin_name(name))
            .collect();
        named.sort_by(|a, b| a.0.cmp(b.0));
        let read = named
            .into_iter()
            .map(|(name, text)| DropIn::Read {
                file: dropin_file(name),
                text: (*text).to_string(),
            })
            .collect();
        Self::assemble(main, read, Vec::new(), grammars)
    }

    #[cfg(all(unix, feature = "hermetic-test-seam"))]
    pub fn load_with_requirement(
        config_dir: &Path,
        req: maknae_io::TargetRequired,
        grammars: &GrammarSet,
    ) -> Result<Self, ToolsError> {
        load_required(config_dir, req, grammars)
    }

    fn assemble(
        main: Option<&str>,
        dropins: Vec<DropIn>,
        skipped: Vec<Disabled>,
        grammars: &GrammarSet,
    ) -> Result<Self, ToolsError> {
        let main = main.map(|text| parse_top(TOOLS_FILE, text)).transpose()?;
        let mut catalog = Self::empty();
        catalog.disabled = skipped;
        let mut dropin_canonical = Vec::new();
        let mut docs: Vec<(String, Doc)> = Vec::new();
        let mut unparsed: Vec<(String, Vec<String>, Vec<String>)> = Vec::new();
        for dropin in dropins {
            match dropin {
                DropIn::Read { file, text } => match parse_top(&file, &text) {
                    Ok(doc) => {
                        dropin_canonical.push((file.clone(), Value::Map(doc.top.clone())));
                        docs.push((file, doc));
                    }
                    Err(e) => {
                        let (classes, tools) = defined_names(&text);
                        unparsed.push((file.clone(), classes, tools));
                        dropin_canonical.push((file.clone(), Value::Str(text)));
                        catalog.disabled.push(Disabled {
                            entry: file,
                            reason: e.reason(),
                        });
                    }
                },
                DropIn::Unreadable { file, reason } => {
                    dropin_canonical.push((file.clone(), Value::Str(reason.clone())));
                    catalog.disabled.push(Disabled {
                        entry: file,
                        reason,
                    });
                }
            }
        }
        let sources: Vec<(&str, &Doc)> = main
            .iter()
            .map(|doc| (TOOLS_FILE, doc))
            .chain(docs.iter().map(|(file, doc)| (file.as_str(), doc)))
            .collect();
        let defined = |pick: fn(&Doc) -> &[(String, Value)]| {
            let mut files: BTreeMap<&str, Vec<&str>> = BTreeMap::new();
            for (file, doc) in &sources {
                for (name, _) in pick(doc) {
                    files.entry(name.as_str()).or_default().push(file);
                }
            }
            files
        };
        let mut class_files = defined(|d| &d.classes);
        let mut tool_files = defined(|d| &d.tools);
        for (file, classes, tools) in &unparsed {
            for (files, names) in [(&mut class_files, classes), (&mut tool_files, tools)] {
                for name in names {
                    files.entry(name.as_str()).or_default().push(file.as_str());
                }
            }
        }
        let mut classes: BTreeMap<&str, Result<CredentialClass, String>> = BTreeMap::new();
        for (file, doc) in &sources {
            for (name, body) in &doc.classes {
                let parsed = match class_files.get(name.as_str()).map(Vec::as_slice) {
                    Some([_]) | None => parse_class(name, body).map_err(|r| in_file(file, r)),
                    Some(several) => Err(defined_in(several)),
                };
                classes.insert(name, parsed);
            }
        }
        for (name, class) in &classes {
            if let Err(reason) = class {
                catalog.disabled.push(Disabled {
                    entry: format!("credential_classes.{name}"),
                    reason: reason.clone(),
                });
            }
        }
        let mut reported: BTreeSet<&str> = BTreeSet::new();
        for (file, doc) in &sources {
            for (name, body) in &doc.tools {
                let parsed = match tool_files.get(name.as_str()).map(Vec::as_slice) {
                    Some([_]) | None => {
                        parse_entry(name, body, &classes, grammars).map_err(|r| in_file(file, r))
                    }
                    Some(several) => {
                        if !reported.insert(name) {
                            continue;
                        }
                        Err(defined_in(several))
                    }
                };
                match parsed {
                    Ok((true, entry)) => {
                        catalog.entries.insert(name.clone(), entry);
                    }
                    Ok((false, _)) => {}
                    Err(reason) => catalog.disabled.push(Disabled {
                        entry: name.clone(),
                        reason,
                    }),
                }
            }
        }
        catalog.classes = classes
            .into_iter()
            .filter_map(|(name, class)| Some((name.to_string(), class.ok()?)))
            .collect();
        let named: BTreeMap<&str, Value> = catalog
            .entries
            .values()
            .flat_map(|e| e.commands.values())
            .filter_map(|c| match &c.form {
                CommandForm::Grammar { grammar, .. } => grammars
                    .grammars
                    .get(grammar)
                    .map(|g| (grammar.as_str(), Value::Str(g.canonical.clone()))),
                CommandForm::Positional(_) | CommandForm::Open => None,
            })
            .collect();
        catalog.canonical = match (main, dropin_canonical.is_empty() && named.is_empty()) {
            (None, true) => String::new(),
            (Some(doc), true) => crate::canonical_json(&Value::Map(doc.top)),
            (main, false) => crate::canonical_json(&Value::Map(vec![
                (
                    "grammars".to_string(),
                    Value::Map(
                        named
                            .into_iter()
                            .map(|(name, canonical)| (name.to_string(), canonical))
                            .collect(),
                    ),
                ),
                (TOOLS_DROPIN_DIR.to_string(), Value::Map(dropin_canonical)),
                (
                    TOOLS_FILE.to_string(),
                    Value::Map(main.map(|doc| doc.top).unwrap_or_default()),
                ),
            ])),
        };
        Ok(catalog)
    }

    pub fn entry(&self, name: &str) -> Option<&ToolEntry> {
        self.entries.get(name)
    }

    pub fn entries(&self) -> impl Iterator<Item = &ToolEntry> {
        self.entries.values()
    }

    pub fn class(&self, name: &str) -> Option<&CredentialClass> {
        self.classes.get(name)
    }

    pub fn class_names(&self) -> impl Iterator<Item = &str> {
        self.classes.keys().map(String::as_str)
    }

    pub fn disabled(&self) -> &[Disabled] {
        &self.disabled
    }

    pub fn canonical(&self) -> String {
        if self.canonical.is_empty() {
            "{}".to_string()
        } else {
            self.canonical.clone()
        }
    }

    pub fn is_empty(&self) -> bool {
        self.entries.is_empty() && self.classes.is_empty() && self.disabled.is_empty()
    }
}

impl ToolsError {
    fn reason(self) -> String {
        match self {
            Self::Config(e) => e.to_string(),
            Self::Invalid(reason) | Self::DropIns(reason) => reason,
        }
    }
}

fn in_file(file: &str, reason: String) -> String {
    if file == TOOLS_FILE {
        reason
    } else {
        format!("{file}: {reason}")
    }
}

fn is_dropin_name(name: &str) -> bool {
    !name.starts_with('.') && name.ends_with(".yaml")
}

fn dropin_file(name: &str) -> String {
    format!("{TOOLS_DROPIN_DIR}/{name}")
}

fn defined_in(files: &[&str]) -> String {
    format!("defined in more than one file: {}", files.join(", "))
}

pub fn defined_names(text: &str) -> (Vec<String>, Vec<String>) {
    let Ok(Value::Map(top)) = crate::load_str(text) else {
        return (Vec::new(), Vec::new());
    };
    let keys = |key: &str| match get(&top, key) {
        Some(Value::Map(items)) => items.iter().map(|(name, _)| name.clone()).collect(),
        Some(_) | None => Vec::new(),
    };
    (keys("credential_classes"), keys("tools"))
}

pub fn grammar_uses(text: &str) -> BTreeSet<String> {
    let Ok(Value::Map(top)) = crate::load_str(text) else {
        return BTreeSet::new();
    };
    let Some(Value::Map(tools)) = get(&top, "tools") else {
        return BTreeSet::new();
    };
    tools
        .iter()
        .filter_map(|(_, entry)| match entry {
            Value::Map(fields) => match get(fields, "commands") {
                Some(Value::Map(commands)) => Some(commands),
                Some(_) | None => None,
            },
            _ => None,
        })
        .flatten()
        .filter_map(|(_, command)| match command {
            Value::Map(fields) => match get(fields, "grammar") {
                Some(Value::Str(name)) => Some(name.clone()),
                Some(_) | None => None,
            },
            _ => None,
        })
        .collect()
}

fn parse_top(file: &str, text: &str) -> Result<Doc, ToolsError> {
    let invalid = |reason: &str| ToolsError::Invalid(reason.to_string());
    let Value::Map(top) = crate::load_str(text).map_err(ToolsError::Config)? else {
        return Err(invalid("the document must be a mapping"));
    };
    crate::reject_unknown_keys(
        file,
        &top,
        &["schema_version", "credential_classes", "tools"],
    )
    .map_err(ToolsError::Config)?;
    if !matches!(get(&top, "schema_version"), Some(Value::Int(1))) {
        return Err(invalid("schema_version must be 1"));
    }
    let section = |key: &str| match get(&top, key) {
        None => Ok(Vec::new()),
        Some(Value::Map(items)) => Ok(items.clone()),
        Some(_) => Err(ToolsError::Invalid(format!("`{key}` must be a mapping"))),
    };
    let classes = section("credential_classes")?;
    if classes.iter().any(|(name, _)| name == "none") {
        return Err(invalid(
            "`none` is reserved and cannot name a credential class",
        ));
    }
    let tools = section("tools")?;
    Ok(Doc {
        top,
        classes,
        tools,
    })
}

#[cfg(unix)]
fn host_tools_required() -> maknae_io::TargetRequired {
    crate::authz::root_policy_file_required()
}

#[cfg(unix)]
fn load_required(
    config_dir: &Path,
    target: maknae_io::TargetRequired,
    grammars: &GrammarSet,
) -> Result<ToolsCatalog, ToolsError> {
    let main = read_main(config_dir, target.clone())?;
    let (dropins, skipped) = read_dropins(config_dir, target)?;
    ToolsCatalog::assemble(main.as_deref(), dropins, skipped, grammars)
}

#[cfg(unix)]
fn read_main(
    config_dir: &Path,
    target: maknae_io::TargetRequired,
) -> Result<Option<String>, ToolsError> {
    use crate::authz::RootReadError;
    let absolute = std::path::absolute(config_dir.join(TOOLS_FILE))
        .map_err(|e| ToolsError::Config(ConfigError::Io(e.to_string())))?;
    let bytes = match crate::authz::read_in_root_dir(&absolute, target) {
        Ok(bytes) => bytes,
        Err(RootReadError::Io(maknae_io::IoError::Io {
            kind: maknae_io::IoKind::NotFound,
            path: missing,
        })) if missing == absolute => return Ok(None),
        Err(RootReadError::Directory(d)) => {
            return Err(ToolsError::Config(ConfigError::Io(
                crate::authz::insecure_directory(&d.display().to_string(), TOOLS_FILE),
            )))
        }
        Err(RootReadError::Io(e)) => return Err(ToolsError::Config(crate::loader::map_io(e))),
    };
    let body = std::str::from_utf8(&bytes).map_err(|e| {
        ToolsError::Config(ConfigError::Io(format!(
            "{}: invalid UTF-8: {e}",
            absolute.display()
        )))
    })?;
    Ok(Some(body.to_string()))
}

fn dropin_dir_refusal(dir: &Path, owner: Option<u32>) -> String {
    let need = match owner {
        Some(uid) => format!("be owned by uid {uid}, not group-writable and with no world access"),
        None => "not be group-writable and have no world access".to_string(),
    };
    format!("the drop-in directory {} must {need}", dir.display())
}

#[cfg(unix)]
fn read_dropins(
    config_dir: &Path,
    target: maknae_io::TargetRequired,
) -> Result<(Vec<DropIn>, Vec<Disabled>), ToolsError> {
    use maknae_io::{IoError, IoKind, Kind, StrategyPref};
    let dir = std::path::absolute(config_dir.join(TOOLS_DROPIN_DIR))
        .map_err(|e| ToolsError::DropIns(e.to_string()))?;
    let required = maknae_io::AnchorRequired {
        owner: target.owner,
        mode_mask: Some(0o027),
    };
    let anchor = match maknae_io::open_anchor(&dir, required, StrategyPref::Auto) {
        Ok(anchor) => anchor,
        Err(IoError::Io {
            kind: IoKind::NotFound,
            ..
        }) => return Ok((Vec::new(), Vec::new())),
        Err(IoError::InsecurePermissions { .. } | IoError::NotOwned { .. }) => {
            return Err(ToolsError::DropIns(dropin_dir_refusal(&dir, target.owner)));
        }
        Err(other) => return Err(ToolsError::DropIns(other.to_string())),
    };
    let mut entries = anchor
        .enumerate(Path::new(""), None)
        .map_err(|e| ToolsError::DropIns(e.to_string()))?
        .value;
    entries.sort_by(|a, b| a.name.cmp(&b.name));
    let mut read = Vec::new();
    let mut skipped = Vec::new();
    for entry in entries {
        let name = entry.name.to_string_lossy().into_owned();
        if !is_dropin_name(&name) {
            continue;
        }
        let file = dropin_file(&name);
        if entry.kind != Kind::File {
            let what = if entry.kind == Kind::Symlink {
                "a symlink"
            } else if entry.kind == Kind::Dir {
                "a directory"
            } else {
                "not a regular file"
            };
            skipped.push(Disabled {
                entry: file,
                reason: format!("skipped: the drop-in is {what}, and drop-ins are regular files"),
            });
            continue;
        }
        let got = anchor
            .read(Path::new(&entry.name), None, target.clone())
            .map_err(|e| e.to_string())
            .and_then(|outcome| {
                std::str::from_utf8(&outcome.value)
                    .map(str::to_string)
                    .map_err(|e| format!("invalid UTF-8: {e}"))
            });
        read.push(match got {
            Ok(text) => DropIn::Read { file, text },
            Err(reason) => DropIn::Unreadable { file, reason },
        });
    }
    Ok((read, skipped))
}

type Fields = [(String, Value)];

fn get<'a>(map: &'a Fields, key: &str) -> Option<&'a Value> {
    map.iter().find(|(k, _)| k == key).map(|(_, v)| v)
}

fn fields<'a>(v: &'a Value, what: &str, allowed: &[&str]) -> Result<&'a Fields, String> {
    let Value::Map(map) = v else {
        return Err(format!("{what} must be a mapping"));
    };
    if let Some((key, _)) = map.iter().find(|(k, _)| !allowed.contains(&k.as_str())) {
        return Err(format!("{what}: unknown key '{key}'"));
    }
    Ok(map)
}

fn text<'a>(v: &'a Value, what: &str) -> Result<&'a str, String> {
    match v {
        Value::Str(s) if !s.is_empty() => Ok(s),
        _ => Err(format!("{what} must be a non-empty string")),
    }
}

fn strings<'a>(v: &'a Value, what: &str) -> Result<Vec<&'a str>, String> {
    let Value::Seq(items) = v else {
        return Err(format!("{what} must be a list"));
    };
    items.iter().map(|i| text(i, what)).collect()
}

fn flag(v: &Value, what: &str) -> Result<bool, String> {
    match v {
        Value::Bool(b) => Ok(*b),
        _ => Err(format!("{what} must be true or false")),
    }
}

fn choice<T: Copy>(v: &Value, what: &str, table: &[(&str, T)]) -> Result<T, String> {
    let s = text(v, what)?;
    table
        .iter()
        .find(|(spelling, _)| *spelling == s)
        .map(|(_, t)| *t)
        .ok_or_else(|| {
            let names: Vec<&str> = table.iter().map(|(n, _)| *n).collect();
            format!("{what} `{s}` is not one of {}", names.join(", "))
        })
}

fn quantity(v: &Value, what: &str, units: &[&str]) -> Result<String, String> {
    let s = text(v, what)?;
    let digits = s.bytes().take_while(u8::is_ascii_digit).count();
    let (n, unit) = s.split_at(digits);
    if n.is_empty() || n.len() > 9 || n.bytes().all(|b| b == b'0') || !units.contains(&unit) {
        return Err(format!("{what} `{s}` is not a number followed by a unit"));
    }
    Ok(s.to_string())
}

const DURATION_UNITS: &[&str] = &["ms", "s", "m", "h", "d"];
const SIZE_UNITS: &[&str] = &[
    "B", "K", "M", "G", "T", "KB", "MB", "GB", "TB", "Ki", "Mi", "Gi", "Ti", "KiB", "MiB", "GiB",
    "TiB",
];

fn duration(v: &Value, what: &str) -> Result<String, String> {
    quantity(v, what, DURATION_UNITS)
}

fn size(v: &Value, what: &str) -> Result<String, String> {
    quantity(v, what, SIZE_UNITS)
}

fn name_ok(name: &str) -> bool {
    !name.is_empty()
        && name
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'-'))
}

pub fn tool_entry_name_ok(name: &str) -> bool {
    name.starts_with(|c: char| c.is_ascii_lowercase() || c.is_ascii_digit())
        && name
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || matches!(b, b'_' | b'-'))
}

pub fn tool_program_name_ok(name: &str) -> bool {
    !matches!(name, "" | "." | "..")
        && name
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'+' | b'-'))
}

fn parse_class(name: &str, v: &Value) -> Result<CredentialClass, String> {
    if !name_ok(name) {
        return Err("the class name must be letters, digits, `.`, `_` or `-`".to_string());
    }
    let map = fields(
        v,
        "the class",
        &[
            "kind",
            "source",
            "narrowing",
            "lifetime",
            "minting",
            "delivery",
            "app",
            "policies",
        ],
    )?;
    let spelled = text(get(map, "kind").ok_or("`kind` is required")?, "kind")?;
    let kind = CredentialKind::parse(spelled)
        .ok_or_else(|| format!("kind `{spelled}` is not a known credential kind"))?;
    let source = get(map, "source")
        .map(|v| {
            choice(
                v,
                "source",
                &[
                    ("minted-per-task", CredentialSource::MintedPerTask),
                    (
                        "minted-per-invocation",
                        CredentialSource::MintedPerInvocation,
                    ),
                    ("stored", CredentialSource::Stored),
                ],
            )
        })
        .transpose()?;
    let narrowing = get(map, "narrowing")
        .map(|v| {
            choice(
                v,
                "narrowing",
                &[
                    ("provider", CredentialNarrowing::Provider),
                    ("maknae", CredentialNarrowing::Maknae),
                ],
            )
        })
        .transpose()?;
    let minting = get(map, "minting")
        .map(|v| {
            choice(
                v,
                "minting",
                &[
                    ("trust-plane", CredentialMinting::TrustPlane),
                    ("front-end", CredentialMinting::FrontEnd),
                ],
            )
        })
        .transpose()?;
    let vault = matches!(
        kind,
        CredentialKind::VaultChildToken | CredentialKind::VaultDynamicSecret
    );
    let policies = match get(map, "policies") {
        None => Vec::new(),
        Some(_) if !vault => return Err("policies applies to vault kinds only".to_string()),
        Some(v) => {
            let items = strings(v, "policies")?;
            if items.is_empty() {
                return Err("policies must not be empty".to_string());
            }
            items.into_iter().map(str::to_string).collect()
        }
    };
    let lifetime = get(map, "lifetime")
        .map(|v| {
            let m = fields(v, "lifetime", &["expires", "ttl", "revoke_on"])?;
            let expires = get(m, "expires")
                .map(|v| duration(v, "lifetime.expires"))
                .transpose()?;
            let ttl = get(m, "ttl")
                .map(|v| match v {
                    Value::Str(s) if s == "invocation-timeout" => Ok(s.clone()),
                    _ => duration(v, "lifetime.ttl"),
                })
                .transpose()?;
            if ttl.is_some() && !vault {
                return Err("lifetime.ttl applies to vault kinds only".to_string());
            }
            if expires.is_some() == ttl.is_some() {
                return Err("lifetime needs exactly one of expires and ttl".to_string());
            }
            Ok::<_, String>(ClassLifetime {
                expires,
                ttl,
                revoke_on: choice(
                    get(m, "revoke_on").ok_or("lifetime.revoke_on is required")?,
                    "lifetime.revoke_on",
                    &[
                        ("task-outcome", CredentialRevokeOn::TaskOutcome),
                        ("invocation-outcome", CredentialRevokeOn::InvocationOutcome),
                    ],
                )?,
            })
        })
        .transpose()?;
    let delivery = match get(map, "delivery") {
        None => Vec::new(),
        Some(v) => {
            let items = strings(v, "delivery")?;
            if items.is_empty() {
                return Err("delivery must not be empty".to_string());
            }
            items
                .into_iter()
                .map(|d| {
                    if delivery_ok(d) {
                        Ok(d.to_string())
                    } else {
                        Err(format!(
                            "delivery `{d}` is not `env:<NAME>` or `git-credential-file`"
                        ))
                    }
                })
                .collect::<Result<_, _>>()?
        }
    };
    let app = get(map, "app")
        .map(|v| text(v, "app").map(str::to_string))
        .transpose()?;
    if kind == CredentialKind::GithubAppInstallation {
        if source != Some(CredentialSource::MintedPerTask)
            || narrowing != Some(CredentialNarrowing::Provider)
            || minting != Some(CredentialMinting::TrustPlane)
            || app.is_none()
        {
            return Err("github-app-installation requires source minted-per-task, narrowing provider, minting trust-plane and an app".to_string());
        }
    } else if app.is_some() {
        return Err("`app` applies to github-app-installation only".to_string());
    }
    Ok(CredentialClass {
        name: name.to_string(),
        kind,
        app,
        source,
        narrowing,
        minting,
        lifetime,
        policies,
        delivery,
    })
}

fn delivery_ok(d: &str) -> bool {
    d == "git-credential-file"
        || d.strip_prefix("env:").is_some_and(|n| {
            !n.is_empty()
                && n.bytes()
                    .all(|b| b.is_ascii_uppercase() || b.is_ascii_digit() || b == b'_')
        })
}

fn image_ref_ok(r: &str) -> bool {
    let Some((name, digest)) = r.split_once("@sha256:") else {
        return false;
    };
    let slash = |c: char| c == '/';
    let first = name.split(slash).next().unwrap_or_default();
    let last = name.rsplit(slash).next().unwrap_or_default();
    name.contains('/')
        && (first.contains(['.', ':']) || first == "localhost")
        && !last.is_empty()
        && !name.contains(char::is_whitespace)
        && !name.contains('@')
        && digest.len() == 64
        && digest
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

fn host_ok(h: &str) -> bool {
    !h.is_empty()
        && h.bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'-'))
}

fn parse_entry(
    name: &str,
    v: &Value,
    classes: &BTreeMap<&str, Result<CredentialClass, String>>,
    grammars: &GrammarSet,
) -> Result<(bool, ToolEntry), String> {
    if !tool_entry_name_ok(name) {
        return Err(
            "the entry name must be lowercase letters, digits, `_` or `-`, starting with a letter or digit"
                .to_string(),
        );
    }
    let map = fields(
        v,
        "the entry",
        &[
            "enabled",
            "description",
            "image",
            "isolation",
            "executes_workspace",
            "network",
            "workspace",
            "volumes",
            "credential",
            "output_to_model",
            "resources",
            "lifetime",
            "binds",
            "labels",
            "commands",
        ],
    )?;
    match get(map, "labels") {
        None => {}
        Some(Value::Map(labels)) if labels.is_empty() => {}
        Some(Value::Map(_)) => return Err("unclaimed label".to_string()),
        Some(_) => return Err("labels must be a mapping".to_string()),
    }
    let enabled = get(map, "enabled").map_or(Ok(true), |v| flag(v, "enabled"))?;
    let description = get(map, "description")
        .map(|v| text(v, "description").map(str::to_string))
        .transpose()?;
    let image = get(map, "image").map(parse_image).transpose()?;
    let isolation = get(map, "isolation").map_or(Ok(ToolIsolation::Container), |v| {
        choice(v, "isolation", &ToolIsolation::ALL.map(|t| (t.as_str(), t)))
    })?;
    let executes_workspace = flag(
        get(map, "executes_workspace").ok_or("executes_workspace is required")?,
        "executes_workspace",
    )?;
    let network = get(map, "network").map_or(Ok(ToolNetwork::None), parse_network)?;
    let workspace = get(map, "workspace").map_or(Ok(ToolWorkspaceAccess::None), |v| {
        choice(
            v,
            "workspace",
            &ToolWorkspaceAccess::ALL.map(|t| (t.as_str(), t)),
        )
    })?;
    let volumes = get(map, "volumes").map_or(Ok(BTreeMap::new()), parse_volumes)?;
    let credential = match get(map, "credential") {
        None => None,
        Some(v) => match text(v, "credential")? {
            "none" => None,
            class => match classes.get(class) {
                None => return Err(format!("credential class `{class}` is not defined")),
                Some(Err(why)) => {
                    return Err(format!("credential class `{class}` is disabled: {why}"))
                }
                Some(Ok(_)) => Some(class.to_string()),
            },
        },
    };
    if executes_workspace && credential.is_some() {
        if let ToolNetwork::Proxy { sites } = &network {
            if sites.iter().any(|h| h.contains('*')) {
                return Err("executes_workspace with a credential and network must name its sites explicitly, with no `*` (ADR-0036 decision 8)".to_string());
            }
        }
    }
    if let ToolNetwork::Proxy { sites } = &network {
        if let Some(bad) = sites.iter().find(|h| !host_ok(h)) {
            return Err(format!("network site `{bad}` is not a host name"));
        }
    }
    let output_to_model = choice(
        get(map, "output_to_model").ok_or("output_to_model is required")?,
        "output_to_model",
        &OutputToModel::ALL.map(|t| (t.as_str(), t)),
    )?;
    let resources = get(map, "resources")
        .map(|v| {
            let m = fields(v, "resources", &["cpus", "memory"])?;
            Ok::<_, String>(ToolResources {
                cpus: get(m, "cpus").map(cpus).transpose()?,
                memory: get(m, "memory")
                    .map(|v| size(v, "resources.memory"))
                    .transpose()?,
            })
        })
        .transpose()?;
    let lifetime_max = get(map, "lifetime")
        .map(|v| {
            let m = fields(v, "lifetime", &["max"])?;
            duration(
                get(m, "max").ok_or("lifetime.max is required")?,
                "lifetime.max",
            )
        })
        .transpose()?;
    let binds = get(map, "binds").map_or(Ok(BTreeSet::new()), parse_binds)?;
    let context = CommandContext {
        credential: credential.is_some(),
        network: match network {
            ToolNetwork::None => false,
            ToolNetwork::Proxy { .. } => true,
        },
        binds: &binds,
        grammars,
    };
    let commands =
        get(map, "commands").map_or(Ok(BTreeMap::new()), |v| parse_commands(v, &context))?;
    if enabled && image.is_none() {
        return Err("an enabled entry needs an image".to_string());
    }
    Ok((
        enabled,
        ToolEntry {
            name: name.to_string(),
            credential,
            binds,
            commands,
            description,
            image,
            isolation,
            executes_workspace,
            network,
            workspace,
            volumes,
            output_to_model,
            resources,
            lifetime_max,
        },
    ))
}

fn parse_image(v: &Value) -> Result<ToolImage, String> {
    let m = fields(v, "image", &["ref", "verify"])?;
    let reference = text(get(m, "ref").ok_or("image.ref is required")?, "image.ref")?;
    if !image_ref_ok(reference) {
        return Err(format!(
            "image.ref `{reference}` must be `<registry>/<name>@sha256:<64 lowercase hex>`"
        ));
    }
    let verify = |m: &Fields, key: &str| {
        get(m, key)
            .map(|v| choice(v, key, &ToolVerify::ALL.map(|t| (t.as_str(), t))))
            .transpose()
    };
    let (signature, sbom) = match get(m, "verify") {
        None => (None, None),
        Some(v) => {
            let vm = fields(v, "image.verify", &["signature", "sbom"])?;
            (verify(vm, "signature")?, verify(vm, "sbom")?)
        }
    };
    Ok(ToolImage {
        reference: reference.to_string(),
        signature,
        sbom,
    })
}

fn parse_network(v: &Value) -> Result<ToolNetwork, String> {
    if matches!(v, Value::Str(s) if s == "none") {
        return Ok(ToolNetwork::None);
    }
    let m = fields(v, "network", &["via", "sites"])?;
    if !matches!(get(m, "via"), Some(Value::Str(s)) if s == "maknae-proxy") {
        return Err("network must be `none` or { via: maknae-proxy, sites: [...] }".to_string());
    }
    let sites = strings(
        get(m, "sites").ok_or("network.sites is required")?,
        "network.sites",
    )?;
    if sites.is_empty() {
        return Err("network.sites must not be empty (use `network: none`)".to_string());
    }
    Ok(ToolNetwork::Proxy {
        sites: sites.into_iter().map(str::to_string).collect(),
    })
}

fn parse_volumes(v: &Value) -> Result<BTreeMap<String, ToolVolume>, String> {
    let Value::Map(items) = v else {
        return Err("volumes must be a mapping".to_string());
    };
    items
        .iter()
        .map(|(role, body)| {
            if !name_ok(role) {
                return Err(format!("volume role `{role}` is not a name"));
            }
            let m = fields(body, "the volume", &["access", "scope"])?;
            let access = choice(
                get(m, "access").ok_or("volume access is required")?,
                "volume access",
                &ToolVolumeAccess::ALL.map(|t| (t.as_str(), t)),
            )?;
            let scope = get(m, "scope")
                .map(|v| {
                    choice(
                        v,
                        "volume scope",
                        &ToolVolumeScope::ALL.map(|t| (t.as_str(), t)),
                    )
                })
                .transpose()?;
            Ok((role.clone(), ToolVolume { access, scope }))
        })
        .collect()
}

fn cpus(v: &Value) -> Result<String, String> {
    match v {
        Value::Int(n) if *n > 0 => Ok(n.to_string()),
        Value::Float(f) if f.is_finite() && *f > 0.0 => Ok(f.to_string()),
        _ => Err("resources.cpus must be a positive number".to_string()),
    }
}

fn parse_binds(v: &Value) -> Result<BTreeSet<String>, String> {
    let Value::Map(items) = v else {
        return Err("binds must be a mapping".to_string());
    };
    items
        .iter()
        .map(|(kind, body)| {
            let m = fields(body, "the binding", &["resolver"])?;
            let resolver = text(
                get(m, "resolver").ok_or("binding resolver is required")?,
                "resolver",
            )?;
            match (kind.as_str(), resolver) {
                ("git", "git") => Ok(kind.clone()),
                ("git", other) => Err(format!("unknown resolver `{other}` for binding kind `git`")),
                (other, _) => Err(format!("unknown binding kind `{other}`")),
            }
        })
        .collect()
}

fn parse_commands(
    v: &Value,
    context: &CommandContext<'_>,
) -> Result<BTreeMap<String, ToolCommand>, String> {
    let Value::Map(items) = v else {
        return Err("commands must be a mapping".to_string());
    };
    items
        .iter()
        .map(|(program, body)| {
            if !tool_program_name_ok(program) {
                return Err(format!(
                    "command `{program}` must be a program name of letters, digits, `.`, `_`, `+` or `-`"
                ));
            }
            let m = fields(
                body,
                &format!("command `{program}`"),
                &[
                    "subcommands",
                    "grammar",
                    "shapes",
                    "open",
                    "deny_args",
                    "timeout",
                    "output",
                ],
            )?;
            let form = parse_form(program, m, context)?;
            let deny_args = match get(m, "deny_args") {
                None => Vec::new(),
                Some(v) => strings(v, "deny_args")?
                    .into_iter()
                    .map(|p| {
                        DenyArg::parse(p)
                            .map_err(|e| format!("command `{program}` deny_args `{p}`: {e}"))
                    })
                    .collect::<Result<_, _>>()?,
            };
            Ok((
                program.clone(),
                ToolCommand {
                    form,
                    deny_args,
                    timeout: get(m, "timeout")
                        .map(|v| duration(v, "timeout"))
                        .transpose()?,
                    output: get(m, "output").map(|v| size(v, "output")).transpose()?,
                },
            ))
        })
        .collect()
}

fn parse_form(
    program: &str,
    m: &Fields,
    context: &CommandContext<'_>,
) -> Result<CommandForm, String> {
    let named = match (get(m, "grammar"), get(m, "shapes")) {
        (None, None) => None,
        (Some(grammar), Some(shapes)) => Some((grammar, shapes)),
        (Some(_), None) | (None, Some(_)) => {
            return Err(format!(
                "command `{program}` needs both `grammar` and `shapes`"
            ))
        }
    };
    match (get(m, "subcommands"), named, get(m, "open")) {
        (Some(patterns), None, None) => Ok(CommandForm::Positional(
            strings(patterns, "subcommands")?
                .into_iter()
                .map(|p| {
                    ArgPattern::parse(p)
                        .map_err(|e| format!("command `{program}` subcommand `{p}`: {e}"))
                })
                .collect::<Result<_, _>>()?,
        )),
        (None, Some((grammar, shapes)), None) => resolve_shapes(
            program,
            text(grammar, "grammar")?,
            &strings(shapes, "shapes")?,
            context,
        ),
        (None, None, Some(open)) => {
            if !flag(open, "open")? {
                return Err(format!("command `{program}`: `open` must be true when given"));
            }
            if context.credential || context.network {
                return Err(format!(
                    "command `{program}` is open, but a tool holding a credential or network access needs a grammar"
                ));
            }
            Ok(CommandForm::Open)
        }
        (None, None, None)
        | (Some(_), Some(_), _)
        | (Some(_), None, Some(_))
        | (None, Some(_), Some(_)) => Err(format!(
            "command `{program}` needs exactly one of `grammar` with `shapes`, `open: true` or `subcommands`"
        )),
    }
}

fn resolve_shapes(
    program: &str,
    grammar: &str,
    names: &[&str],
    context: &CommandContext<'_>,
) -> Result<CommandForm, String> {
    if grammar != program {
        return Err(format!(
            "command `{program}` names grammar `{grammar}`; a grammar serves only its own program"
        ));
    }
    if names.is_empty() {
        return Err(format!("command `{program}`: shapes must not be empty"));
    }
    let Some(g) = context.grammars.grammars.get(grammar) else {
        let file = format!("{grammar}.yaml");
        return Err(
            match context.grammars.disabled.iter().find(|d| d.file == file) {
                Some(d) => format!("grammar `{grammar}` is disabled: {}", d.reason),
                None => format!("grammar `{grammar}` is not enabled"),
            },
        );
    };
    let mut shapes = BTreeMap::new();
    for name in names {
        if let Some((_, why)) = g.disabled.iter().find(|(n, _)| n == name) {
            return Err(format!(
                "shape `{name}` of grammar `{grammar}` is disabled: {why}"
            ));
        }
        let Some(shape) = g.shapes.get(*name) else {
            return Err(format!("shape `{name}` is not in grammar `{grammar}`"));
        };
        let uncovered = shape.argv.iter().find_map(|token| match token {
            ArgvToken::Bound { kind, .. } if !context.binds.contains(kind) => Some(kind),
            ArgvToken::Bound { .. }
            | ArgvToken::Literal(_)
            | ArgvToken::Slot(_)
            | ArgvToken::OptionSlot { .. } => None,
        });
        if let Some(kind) = uncovered {
            return Err(format!(
                "shape `{name}` uses bound kind `{kind}`, which the entry's binds do not cover"
            ));
        }
        if context.credential && shape.forge == ForgeNeed::default() {
            return Err(format!(
                "shape `{name}` declares no forge, and the entry holds a credential"
            ));
        }
        if shapes
            .insert((*name).to_string(), Arc::new(shape.clone()))
            .is_some()
        {
            return Err(format!("shape `{name}` is listed more than once"));
        }
    }
    Ok(CommandForm::Grammar {
        grammar: grammar.to_string(),
        grammar_canonical: Arc::from(g.canonical.as_str()),
        shapes,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::first_denied;

    const HOMELAB: &str = include_str!("../../../packaging/common/tools-homelab.yaml");
    const SENTINEL: &str = "sentinel-674-bad-entry";
    const DIGEST: &str = "0000000000000000000000000000000000000000000000000000000000000000";

    fn catalog(text: &str) -> ToolsCatalog {
        ToolsCatalog::parse_with(text, &crate::grammar::shipped_grammars()).unwrap()
    }

    fn argv(items: &[&str]) -> Vec<String> {
        items.iter().map(|s| (*s).to_string()).collect()
    }

    fn reason<'a>(c: &'a ToolsCatalog, entry: &str) -> &'a str {
        c.disabled()
            .iter()
            .find(|d| d.entry == entry)
            .map(|d| d.reason.as_str())
            .unwrap_or_else(|| panic!("{entry} is not disabled: {:?}", c.disabled()))
    }

    const IMAGE: &str =
        "registry.example/x@sha256:0000000000000000000000000000000000000000000000000000000000000000";
    const ESS: &str = "    image: { ref: \"registry.example/x@sha256:0000000000000000000000000000000000000000000000000000000000000000\" }\n    output_to_model: redacted\n";
    const GOOD: &str = "  good:\n    executes_workspace: false\n    image: { ref: \"registry.example/x@sha256:0000000000000000000000000000000000000000000000000000000000000000\" }\n    output_to_model: redacted\n    commands:\n      echo: { subcommands: [\"hi *\"] }\n";

    fn doc(classes: &str, tools: &str) -> String {
        format!("schema_version: 1\ncredential_classes:\n{classes}\ntools:\n{tools}{GOOD}")
    }

    const APP_CLASS: &str = "  app-class:\n    kind: github-app-installation\n    source: minted-per-task\n    narrowing: provider\n    minting: trust-plane\n    app: my-app\n";

    #[test]
    fn entries_are_every_enabled_entry_in_name_order() {
        let c = catalog(HOMELAB);
        let names: Vec<&str> = c.entries().map(|e| e.name.as_str()).collect();
        assert_eq!(
            names,
            [
                "github-issues-read",
                "github-issues-write",
                "github-post",
                "github-read",
                "rust-build",
                "rust-fetch",
                "rust-scratch"
            ]
        );
        assert_eq!(
            c.entries()
                .map(|e| e as *const ToolEntry)
                .collect::<Vec<_>>(),
            names
                .iter()
                .map(|n| c.entry(n).unwrap() as *const ToolEntry)
                .collect::<Vec<_>>()
        );
        assert_eq!(ToolsCatalog::empty().entries().count(), 0);
    }

    #[test]
    fn empty_catalog_has_nothing() {
        let c = ToolsCatalog::empty();
        assert!(c.is_empty());
        assert!(c.entry("x").is_none());
        assert!(c.class("x").is_none());
        assert!(c.disabled().is_empty());
    }

    #[test]
    fn unknown_top_level_key_fails_whole_file() {
        let got = ToolsCatalog::parse(&format!("schema_version: 1\n{SENTINEL}: 1\n"));
        assert!(
            matches!(&got, Err(ToolsError::Config(ConfigError::UnknownKey { key, .. })) if key == SENTINEL),
            "{got:?}"
        );
    }

    #[test]
    fn wrong_schema_version_fails_whole_file() {
        for text in [
            "schema_version: 2\n",
            "tools: {}\n",
            "schema_version: \"1\"\n",
        ] {
            let got = ToolsCatalog::parse(text);
            assert!(
                matches!(got, Err(ToolsError::Invalid(ref m)) if m.contains("schema_version")),
                "{text}: {got:?}"
            );
        }
    }

    #[test]
    fn syntax_error_fails_whole_file() {
        assert!(matches!(
            ToolsCatalog::parse("schema_version: 1\ntools: [\n"),
            Err(ToolsError::Config(_))
        ));
    }

    #[test]
    fn class_named_none_fails_whole_file() {
        let text = doc("  none:\n    kind: github-machine-user\n", "");
        let got = ToolsCatalog::parse(&text);
        assert!(
            matches!(got, Err(ToolsError::Invalid(ref m)) if m.contains("none")),
            "{got:?}"
        );
    }

    #[test]
    fn a_sound_file_loads_its_entry() {
        let c = catalog(&doc(APP_CLASS, ""));
        assert!(c.disabled().is_empty(), "{:?}", c.disabled());
        let e = c.entry("good").unwrap();
        assert_eq!(e.name, "good");
        assert_eq!(e.credential, None);
        assert!(
            positional(&e.commands["echo"])[0].matches(&argv(&["hi", "x"]), &crate::Bound::empty())
        );
        assert_eq!(c.class("app-class").unwrap().app.as_deref(), Some("my-app"));
    }

    #[test]
    fn unknown_entry_field_disables_only_that_entry() {
        let c = catalog(&doc(
            "  {}\n",
            &format!("  {SENTINEL}:\n    executes_workspace: false\n{ESS}    nonsense: 1\n"),
        ));
        assert!(c.entry(SENTINEL).is_none());
        assert!(c.entry("good").is_some());
        assert!(reason(&c, SENTINEL).contains("nonsense"));
        assert_eq!(c.disabled().len(), 1);
    }

    #[test]
    fn tag_image_ref_disables_entry() {
        for bad in [
            "registry.example/x/rust:1.80".to_string(),
            format!("registry.example/x@sha256:{}", &DIGEST[..63]),
            format!("x@sha256:{DIGEST}"),
            format!("/x@sha256:{DIGEST}"),
            format!("reg/@sha256:{DIGEST}"),
            format!(
                "registry.example/x@sha256:{}",
                DIGEST.to_uppercase().replace('0', "A")
            ),
            format!("@sha256:{DIGEST}"),
            format!("reg istry/x@sha256:{DIGEST}"),
        ] {
            let c = catalog(&doc(
                "  {}\n",
                &format!("  {SENTINEL}:\n    executes_workspace: false\n    output_to_model: redacted\n    image: {{ ref: \"{bad}\" }}\n"),
            ));
            assert!(c.entry(SENTINEL).is_none(), "{bad}");
            assert!(reason(&c, SENTINEL).contains("image.ref"), "{bad}");
        }
        let ok = format!("registry.example/x@sha256:{DIGEST}");
        let c = catalog(&doc(
            "  {}\n",
            &format!("  fine:\n    executes_workspace: false\n    output_to_model: redacted\n    image: {{ ref: \"{ok}\" }}\n"),
        ));
        assert!(c.entry("fine").is_some());
    }

    #[test]
    fn undefined_credential_class_disables_entry() {
        let c = catalog(&doc(
            "  {}\n",
            &format!(
                "  {SENTINEL}:\n    executes_workspace: false\n{ESS}    credential: missing-class\n"
            ),
        ));
        assert!(c.entry(SENTINEL).is_none());
        assert!(reason(&c, SENTINEL).contains("missing-class"));
        let c = catalog(&doc(
            "  {}\n",
            &format!(
                "  explicit-none:\n    executes_workspace: false\n{ESS}    credential: none\n"
            ),
        ));
        assert_eq!(c.entry("explicit-none").unwrap().credential, None);
    }

    #[test]
    fn inconsistent_github_app_class_disables_naming_entries() {
        let variants = [
            "    kind: github-app-installation\n    source: stored\n    narrowing: provider\n    minting: trust-plane\n    app: a\n",
            "    kind: github-app-installation\n    source: minted-per-task\n    narrowing: maknae\n    minting: trust-plane\n    app: a\n",
            "    kind: github-app-installation\n    source: minted-per-task\n    narrowing: provider\n    minting: front-end\n    app: a\n",
            "    kind: github-app-installation\n    source: minted-per-task\n    narrowing: provider\n    minting: trust-plane\n",
        ];
        for body in variants {
            let classes = format!("  bad-class:\n{body}");
            let c = catalog(&doc(
                &classes,
                &format!(
                    "  {SENTINEL}:\n    executes_workspace: false\n{ESS}    credential: bad-class\n"
                ),
            ));
            assert!(c.class("bad-class").is_none(), "{body}");
            assert!(c.entry(SENTINEL).is_none(), "{body}");
            assert!(reason(&c, SENTINEL).contains("bad-class"), "{body}");
            assert!(c.entry("good").is_some());
        }
    }

    #[test]
    fn unknown_credential_kind_disables_class_and_entries() {
        let classes = "  weird:\n    kind: sentinel-674-kind\n";
        let c = catalog(&doc(
            classes,
            &format!("  {SENTINEL}:\n    executes_workspace: false\n{ESS}    credential: weird\n"),
        ));
        assert!(c.class("weird").is_none());
        assert!(c.entry(SENTINEL).is_none());
        assert!(reason(&c, SENTINEL).contains("weird"));
        assert!(c.entry("good").is_some());
    }

    #[test]
    fn unknown_resolver_disables_entry() {
        for binds in [
            "{ git: { resolver: sentinel-674-resolver } }",
            "{ sentinel-674-kind: { resolver: git } }",
        ] {
            let c = catalog(&doc(
                "  {}\n",
                &format!("  {SENTINEL}:\n    executes_workspace: false\n{ESS}    binds: {binds}\n"),
            ));
            assert!(c.entry(SENTINEL).is_none(), "{binds}");
            assert!(reason(&c, SENTINEL).contains("sentinel-674"), "{binds}");
        }
        let c = catalog(&doc(
            "  {}\n",
            &format!("  bound:\n    executes_workspace: false\n{ESS}    binds: {{ git: {{ resolver: git }} }}\n"),
        ));
        assert!(c.entry("bound").unwrap().binds.contains("git"));
    }

    #[test]
    fn labelled_entry_is_disabled_unclaimed() {
        let c = catalog(&doc(
            "  {}\n",
            &format!("  {SENTINEL}:\n    executes_workspace: false\n{ESS}    labels: {{ entry.tier: high }}\n"),
        ));
        assert!(c.entry(SENTINEL).is_none());
        assert!(reason(&c, SENTINEL).contains("unclaimed label"));
    }

    #[test]
    fn malformed_fields_disable_the_entry() {
        for field in [
            "timeout_x: 1",
            "isolation: sentinel",
            "workspace: sentinel",
            "network: sentinel",
            "network: { via: elsewhere, sites: [a.example] }",
            "network: { via: maknae-proxy, sites: [] }",
            "network: { via: maknae-proxy, sites: [\"a b\"] }",
            "network: { via: maknae-proxy, sites: [\"*\"] }",
            "network: { via: maknae-proxy, sites: [\"**\"] }",
            "network: { via: maknae-proxy, sites: [\"a*b\"] }",
            "network: { via: maknae-proxy, sites: [\"*.*\"] }",
            "volumes: { v: { access: sentinel } }",
            "volumes: { v: { access: ro, scope: sentinel } }",
            "resources: { memory: lots }",
            "resources: { cpus: 0 }",
            "lifetime: { max: soon }",
            "commands: { echo: { subcommands: [\"* x\"] } }",
            "commands: { echo: { subcommands: [x], deny_args: [\"a*b\"] } }",
            "commands: { echo: { subcommands: [x], timeout: \"\" } }",
            "commands: { echo: { subcommands: [x], output: 16 } }",
        ] {
            let c = catalog(&doc(
                "  {}\n",
                &format!("  {SENTINEL}:\n    executes_workspace: false\n{ESS}    {field}\n"),
            ));
            assert!(c.entry(SENTINEL).is_none(), "{field}");
            assert!(!reason(&c, SENTINEL).is_empty(), "{field}");
        }
    }

    #[test]
    fn malformed_class_fields_disable_the_class() {
        for body in [
            "    kind: github-machine-user\n    delivery: []\n",
            "    kind: github-machine-user\n    delivery: [\"env:lower\"]\n",
            "    kind: github-machine-user\n    delivery: [\"file\"]\n",
            "    kind: github-machine-user\n    app: nope\n",
            "    kind: github-machine-user\n    source: sentinel\n",
            "    kind: github-machine-user\n    lifetime: { expires: 1h }\n",
            "    kind: github-machine-user\n    extra: 1\n",
            "    source: stored\n",
        ] {
            let c = catalog(&doc(
                &format!("  c:\n{body}"),
                &format!("  user:\n    executes_workspace: false\n{ESS}    credential: c\n"),
            ));
            assert!(c.class("c").is_none(), "{body}");
            assert!(c.entry("user").is_none(), "{body}");
        }
        let ok = "    kind: vault-child-token\n    delivery: [\"env:VAULT_TOKEN\", git-credential-file]\n";
        assert!(catalog(&doc(&format!("  c:\n{ok}"), ""))
            .class("c")
            .is_some());
    }

    #[test]
    fn workspace_executing_credentialed_entry_must_name_sites() {
        let class = "  c:\n    kind: github-machine-user\n";
        let entry = |net: &str, exec: &str| {
            format!("  {SENTINEL}:\n    executes_workspace: {exec}\n{ESS}    credential: c\n    network: {net}\n")
        };
        let wild = "{ via: maknae-proxy, sites: [\"*.github.com\"] }";
        let named = "{ via: maknae-proxy, sites: [github.com] }";
        let c = catalog(&doc(class, &entry(wild, "true")));
        assert!(c.entry(SENTINEL).is_none());
        assert!(reason(&c, SENTINEL).contains("decision 8"));
        let c = catalog(&doc(class, &entry(named, "true")));
        assert!(c.entry(SENTINEL).is_some(), "{:?}", c.disabled());
        let c = catalog(&doc(class, &entry(wild, "false")));
        assert!(c.entry(SENTINEL).is_none());
        assert!(reason(&c, SENTINEL).contains("not a host name"));
        let c = catalog(&doc(class, &entry("none", "true")));
        assert!(c.entry(SENTINEL).is_some());
    }

    #[test]
    fn workspace_executing_credentialed_entry_without_sites_is_disabled() {
        let class = "  c:\n    kind: github-machine-user\n";
        let text = format!("  {SENTINEL}:\n    executes_workspace: true\n{ESS}    credential: c\n    network: {{ via: maknae-proxy }}\n");
        let c = catalog(&doc(class, &text));
        assert!(c.entry(SENTINEL).is_none());
        assert!(reason(&c, SENTINEL).contains("sites"));
    }

    #[test]
    fn vault_classes_take_ttl_and_policies() {
        let adr = "  vault-invocation:\n    kind: vault-child-token\n    source: minted-per-invocation\n    narrowing: provider\n    lifetime: { ttl: invocation-timeout, revoke_on: invocation-outcome }\n    minting: front-end\n    policies: [kv-read-infra]\n    delivery: [env:VAULT_TOKEN]\n";
        let c = catalog(&doc(adr, ""));
        assert!(c.disabled().is_empty(), "{:?}", c.disabled());
        let class = c.class("vault-invocation").unwrap();
        assert_eq!(class.policies, ["kv-read-infra"]);
        assert_eq!(
            class.lifetime.as_ref().unwrap().ttl.as_deref(),
            Some("invocation-timeout")
        );
        let timed = "  v:\n    kind: vault-dynamic-secret\n    lifetime: { ttl: 30m, revoke_on: task-outcome }\n";
        assert!(catalog(&doc(timed, "")).class("v").is_some());
        for body in [
            "    kind: github-machine-user\n    policies: [p]\n",
            "    kind: github-machine-user\n    lifetime: { ttl: 30m, revoke_on: task-outcome }\n",
            "    kind: vault-child-token\n    policies: []\n",
            "    kind: vault-child-token\n    lifetime: { ttl: soon, revoke_on: task-outcome }\n",
            "    kind: vault-child-token\n    lifetime: { ttl: 1h, expires: 1h, revoke_on: task-outcome }\n",
        ] {
            assert!(catalog(&doc(&format!("  c:\n{body}"), "")).class("c").is_none(), "{body}");
        }
    }

    #[test]
    fn failed_class_is_reported_even_when_unnamed() {
        let c = catalog(&doc("  weird:\n    kind: sentinel-674-kind\n", ""));
        assert!(c.class("weird").is_none());
        assert!(reason(&c, "credential_classes.weird").contains("sentinel-674-kind"));
        assert_eq!(c.disabled().len(), 1);
    }

    #[test]
    fn executes_workspace_is_required_and_boolean() {
        for body in ["    description: x\n", "    executes_workspace: maybe\n"] {
            let c = catalog(&doc("  {}\n", &format!("  {SENTINEL}:\n{body}")));
            assert!(c.entry(SENTINEL).is_none(), "{body}");
            assert!(
                reason(&c, SENTINEL).contains("executes_workspace"),
                "{body}"
            );
        }
    }

    #[test]
    fn canonical_is_the_authored_document_as_sorted_compact_json() {
        let text = "schema_version: 1\ntools:\n  sentinel-674-t:\n    executes_workspace: false\n";
        assert_eq!(
            catalog(text).canonical(),
            r#"{"schema_version":1,"tools":{"sentinel-674-t":{"executes_workspace":false}}}"#
        );
        assert_eq!(ToolsCatalog::empty().canonical(), "{}");
    }

    #[test]
    fn canonical_ignores_key_order_and_whitespace() {
        let a = "schema_version: 1\ntools:\n  t:\n    executes_workspace: false\n    isolation: container\n";
        let b = "tools:   {t: {isolation: container,   executes_workspace: false}}\n\nschema_version:    1\n";
        assert_eq!(catalog(a).canonical(), catalog(b).canonical());
        let c = a.replace("container", "vm");
        assert_ne!(catalog(a).canonical(), catalog(&c).canonical());
    }

    #[test]
    fn canonical_includes_disabled_entries() {
        let c = catalog(&doc(
            "  {}\n",
            "  sentinel-674-bad:\n    isolation: nope\n    executes_workspace: false\n",
        ));
        assert!(c.canonical().contains("sentinel-674-bad"));
    }

    #[test]
    fn errors_display_their_cause() {
        let invalid = ToolsError::Invalid("because".to_string());
        assert_eq!(invalid.to_string(), "tools.yaml: because");
        let config = ToolsError::Config(ConfigError::Io("disk".to_string()));
        assert_eq!(
            config.to_string(),
            format!("tools.yaml: {}", ConfigError::Io("disk".to_string()))
        );
    }

    #[test]
    fn whole_file_shapes_are_checked() {
        for text in [
            "- a\n",
            "schema_version: 1\ntools: 3\n",
            "schema_version: 1\ncredential_classes: [a]\n",
        ] {
            assert!(
                matches!(ToolsCatalog::parse(text), Err(ToolsError::Invalid(_))),
                "{text}"
            );
        }
        assert!(ToolsCatalog::parse("schema_version: 1\n")
            .unwrap()
            .is_empty());
    }

    #[test]
    fn ill_formed_nested_values_disable_the_entry() {
        for field in [
            "labels: 3",
            "volumes: 3",
            "volumes: { \"a b\": { access: ro } }",
            "binds: 3",
            "binds: { git: { resolver: git, extra: 1 } }",
            "binds: { git: {} }",
            "commands: 3",
            "commands: { \"a b\": {} }",
            "commands: { echo: { nonsense: 1 } }",
            "commands: { echo: { subcommands: x } }",
            "network: { via: maknae-proxy, sites: x }",
            "resources: { cpus: soon }",
            "resources: { cpus: -1.5 }",
            "lifetime: { max: 5m, extra: 1 }",
        ] {
            let c = catalog(&doc(
                "  {}\n",
                &format!("  {SENTINEL}:\n    executes_workspace: false\n{ESS}    {field}\n"),
            ));
            assert!(c.entry(SENTINEL).is_none(), "{field}");
            assert!(!reason(&c, SENTINEL).is_empty(), "{field}");
        }
        let c = catalog(&doc(
            "  {}\n",
            &format!("  fine:\n    executes_workspace: false\n{ESS}    resources: {{ cpus: 1.5, memory: 8Gi }}\n"),
        ));
        assert_eq!(
            c.entry("fine")
                .unwrap()
                .resources
                .as_ref()
                .unwrap()
                .cpus
                .as_deref(),
            Some("1.5")
        );
    }

    #[test]
    fn bad_names_are_refused_where_they_are_keys() {
        let c = catalog(&doc(
            "  \"a b\":\n    kind: github-machine-user\n",
            "  \"c d\":\n    executes_workspace: false\n",
        ));
        assert!(reason(&c, "credential_classes.a b").contains("class name"));
        assert!(reason(&c, "c d").contains("entry name"));
    }

    #[test]
    fn class_lifetime_errors_are_reported() {
        for body in [
            "    kind: vault-child-token\n    lifetime: { expires: 1h, revoke_on: sometime }\n",
            "    kind: vault-child-token\n    lifetime: { expires: 1h }\n",
            "    kind: vault-child-token\n    lifetime: { revoke_on: task-outcome }\n",
            "    kind: vault-child-token\n    delivery: x\n",
        ] {
            assert!(
                catalog(&doc(&format!("  c:\n{body}"), ""))
                    .class("c")
                    .is_none(),
                "{body}"
            );
        }
    }

    #[test]
    fn every_tool_enum_spelling_round_trips_and_unknown_is_none() {
        for v in ToolIsolation::ALL {
            assert_eq!(ToolIsolation::parse(v.as_str()), Some(v));
        }
        for v in ToolWorkspaceAccess::ALL {
            assert_eq!(ToolWorkspaceAccess::parse(v.as_str()), Some(v));
        }
        for v in ToolVolumeAccess::ALL {
            assert_eq!(ToolVolumeAccess::parse(v.as_str()), Some(v));
        }
        for v in ToolVolumeScope::ALL {
            assert_eq!(ToolVolumeScope::parse(v.as_str()), Some(v));
        }
        for v in OutputToModel::ALL {
            assert_eq!(OutputToModel::parse(v.as_str()), Some(v));
        }
        for bad in ["", "bogus", "RW", "Container"] {
            assert_eq!(ToolIsolation::parse(bad), None);
            assert_eq!(ToolWorkspaceAccess::parse(bad), None);
            assert_eq!(ToolVolumeAccess::parse(bad), None);
            assert_eq!(ToolVolumeScope::parse(bad), None);
            assert_eq!(OutputToModel::parse(bad), None);
        }
    }

    #[test]
    fn defined_names_harvests_class_and_tool_keys_only() {
        assert_eq!(
            defined_names("credential_classes:\n  c1: 1\n  c2: 2\ntools:\n  t1: 1\n  t2: 2\n"),
            (
                vec!["c1".to_string(), "c2".to_string()],
                vec!["t1".to_string(), "t2".to_string()]
            )
        );
        assert_eq!(
            defined_names("tools:\n  t1: 1\n"),
            (Vec::new(), vec!["t1".to_string()])
        );
        assert_eq!(
            defined_names("credential_classes: 3\ntools: [a]\n"),
            (Vec::new(), Vec::new())
        );
        assert_eq!(defined_names("tools: [\n"), (Vec::new(), Vec::new()));
    }

    #[test]
    fn grammar_uses_reads_every_grammar_command() {
        assert_eq!(grammar_uses(HOMELAB), BTreeSet::from(["gh".to_string()]));
    }

    #[test]
    fn grammar_uses_is_empty_for_unloadable_or_shapeless_text() {
        for text in [
            "::",
            "tools: 3",
            "tools:\n  a:\n    commands: [x]\n",
            "tools:\n  a:\n    commands:\n      gh: { grammar: 7 }\n",
        ] {
            assert!(grammar_uses(text).is_empty(), "{text}");
        }
    }

    #[test]
    fn vendor_tools_dir_sits_beside_the_vendor_grammars() {
        assert_eq!(
            Path::new(VENDOR_TOOLS_DIR).parent(),
            Path::new(crate::VENDOR_GRAMMAR_DIR).parent()
        );
        assert!(VENDOR_TOOLS_DIR.ends_with("/maknae/tools.d"));
    }

    #[cfg(unix)]
    mod anchored {
        use super::*;
        use std::os::unix::fs::PermissionsExt;

        fn own() -> maknae_io::TargetRequired {
            maknae_io::TargetRequired {
                owner: None,
                ..crate::authz::root_policy_file_required()
            }
        }

        fn dir(tag: &str) -> std::path::PathBuf {
            let d = std::env::temp_dir().join(format!("tools_anch_{tag}_{}", std::process::id()));
            let _ = std::fs::remove_dir_all(&d);
            std::fs::create_dir_all(&d).unwrap();
            std::fs::set_permissions(&d, std::fs::Permissions::from_mode(0o700)).unwrap();
            d.canonicalize().unwrap()
        }

        fn put(path: &Path, body: &str) {
            std::fs::write(path, body).unwrap();
            std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o640)).unwrap();
        }

        fn loaded(tag: &str, main: Option<&str>, dropins: &[(&str, &str)]) -> ToolsCatalog {
            let d = dir(tag);
            if let Some(main) = main {
                put(&d.join(TOOLS_FILE), main);
            }
            if !dropins.is_empty() {
                let sub = d.join(TOOLS_DROPIN_DIR);
                std::fs::create_dir(&sub).unwrap();
                std::fs::set_permissions(&sub, std::fs::Permissions::from_mode(0o750)).unwrap();
                for (name, body) in dropins {
                    put(&sub.join(name), body);
                }
            }
            let got = load_required(&d, own(), &crate::grammar::shipped_grammars());
            let _ = std::fs::remove_dir_all(&d);
            got.unwrap()
        }

        fn entry_doc(name: &str) -> String {
            format!(
                "schema_version: 1\ntools:\n  {name}:\n    executes_workspace: false\n    image: {{ ref: \"{IMAGE}\" }}\n    output_to_model: redacted\n    commands:\n      echo: {{ subcommands: [\"hi *\"] }}\n"
            )
        }

        #[test]
        fn a_dropin_in_tools_d_loads_its_entry() {
            let c = loaded(
                "dropin_loads",
                None,
                &[("50-extra.yaml", &entry_doc("sentinel-674-extra"))],
            );
            assert!(c.disabled().is_empty(), "{:?}", c.disabled());
            assert!(c.entry("sentinel-674-extra").is_some());
        }

        #[test]
        fn a_schema_failed_dropin_disables_a_name_defined_elsewhere() {
            let bad =
                entry_doc("sentinel-674-main").replace("schema_version: 1", "schema_version: 2");
            let c = loaded(
                "dropin_dup_bad",
                Some(&entry_doc("sentinel-674-main")),
                &[("a.yaml", &bad)],
            );
            assert!(c.entry("sentinel-674-main").is_none(), "{:?}", c.disabled());
            assert!(c.disabled().iter().any(|d| d.entry == "sentinel-674-main"
                && d.reason.contains("more than one file")
                && d.reason.contains("tools.d/a.yaml")));
        }
    }

    #[cfg(unix)]
    #[test]
    fn the_production_door_refuses_a_file_root_does_not_own() {
        use std::os::unix::fs::PermissionsExt;
        let d = std::env::temp_dir().join(format!("tools_door_{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(&d).unwrap();
        std::fs::set_permissions(&d, std::fs::Permissions::from_mode(0o750)).unwrap();
        let d = d.canonicalize().unwrap();
        let p = d.join(TOOLS_FILE);
        std::fs::write(&p, "schema_version: 1\n").unwrap();
        std::fs::set_permissions(&p, std::fs::Permissions::from_mode(0o640)).unwrap();
        crate::tests::test_owner::hand_to_nobody_when_root(&[&d, &p]);
        let got = ToolsCatalog::load(&d, &GrammarSet::empty());
        let _ = std::fs::remove_dir_all(&d);
        assert_eq!(
            got,
            Err(ToolsError::Config(ConfigError::Io(
                crate::authz::insecure_directory(&d.display().to_string(), TOOLS_FILE)
            )))
        );
    }

    #[cfg(unix)]
    #[test]
    fn the_production_door_requires_root_ownership_and_no_world_access() {
        assert_eq!(
            host_tools_required(),
            maknae_io::TargetRequired {
                owner: Some(0),
                mode_mask: Some(0o027),
                nlink_exactly_one: false,
                regular_file: true,
                max_bytes: None,
            }
        );
        let src = include_str!("tools.rs");
        let door = &src[src.find("    pub fn load(config_dir").unwrap()..];
        let door = &door[..door.find("\n    }\n").unwrap()];
        assert_eq!(door.matches("load_required(").count(), 1, "{door}");
        assert!(door.contains("load_required(config_dir, host_tools_required(), grammars)"));
    }

    #[test]
    fn has_reach_check_only_for_github_app_installation() {
        use CredentialKind::*;
        for (kind, want) in [
            (GithubAppInstallation, true),
            (GithubMachineUser, false),
            (GitlabProjectToken, false),
            (GitlabBotToken, false),
            (VaultChildToken, false),
            (VaultDynamicSecret, false),
        ] {
            assert_eq!(kind.has_reach_check(), want, "{kind:?}");
        }
    }

    const KINDS: [CredentialKind; 6] = {
        use CredentialKind::*;
        [
            GithubAppInstallation,
            GithubMachineUser,
            GitlabProjectToken,
            GitlabBotToken,
            VaultChildToken,
            VaultDynamicSecret,
        ]
    };

    fn kind_is_listed(k: CredentialKind) -> bool {
        match k {
            CredentialKind::GithubAppInstallation
            | CredentialKind::GithubMachineUser
            | CredentialKind::GitlabProjectToken
            | CredentialKind::GitlabBotToken
            | CredentialKind::VaultChildToken
            | CredentialKind::VaultDynamicSecret => KINDS.contains(&k),
        }
    }

    #[test]
    fn credential_kind_spellings_round_trip() {
        for k in KINDS {
            assert!(kind_is_listed(k), "{k:?}");
            assert_eq!(CredentialKind::parse(k.as_str()), Some(k));
        }
        let spellings: std::collections::BTreeSet<_> = KINDS.iter().map(|k| k.as_str()).collect();
        assert_eq!(spellings.len(), KINDS.len());
        for bad in ["GithubAppInstallation", "", "github-app"] {
            assert_eq!(CredentialKind::parse(bad), None, "{bad}");
        }
    }

    #[test]
    fn every_credential_kind_spelling_parses() {
        for (spelling, kind) in [
            (
                "github-app-installation",
                CredentialKind::GithubAppInstallation,
            ),
            ("github-machine-user", CredentialKind::GithubMachineUser),
            ("gitlab-project-token", CredentialKind::GitlabProjectToken),
            ("gitlab-bot-token", CredentialKind::GitlabBotToken),
            ("vault-child-token", CredentialKind::VaultChildToken),
            ("vault-dynamic-secret", CredentialKind::VaultDynamicSecret),
        ] {
            let body = if kind == CredentialKind::GithubAppInstallation {
                "    source: minted-per-task\n    narrowing: provider\n    minting: trust-plane\n    app: a\n"
            } else {
                ""
            };
            let c = catalog(&doc(&format!("  c:\n    kind: {spelling}\n{body}"), ""));
            assert_eq!(c.class("c").map(|c| c.kind), Some(kind), "{spelling}");
        }
    }

    #[test]
    fn disabled_entry_is_not_returned_by_entry() {
        let text = doc(
            "  {}\n",
            &format!("  {SENTINEL}:\n    executes_workspace: false\n{ESS}    nonsense: 1\n  off:\n    executes_workspace: false\n{ESS}    enabled: false\n"),
        );
        let c = catalog(&text);
        assert!(c.entry(SENTINEL).is_none());
        assert!(c.entry("off").is_none());
        assert!(c.entry("good").is_some());
    }

    #[test]
    fn homelab_baseline_loads_with_the_gh_grammar_and_no_disabled_entries() {
        let c = catalog(HOMELAB);
        assert!(c.disabled().is_empty(), "{:?}", c.disabled());
        let without = ToolsCatalog::parse(HOMELAB).unwrap();
        assert_eq!(without.disabled().len(), 4, "{:?}", without.disabled());
        for name in [
            "github-read",
            "github-post",
            "github-issues-read",
            "github-issues-write",
            "rust-fetch",
            "rust-build",
            "rust-scratch",
        ] {
            assert!(c.entry(name).is_some(), "{name}");
        }
        assert_eq!(
            c.entry("github-read").unwrap().credential.as_deref(),
            Some("github-read")
        );
        assert!(c.entry("github-read").unwrap().binds.contains("git"));
        assert_eq!(c.entry("rust-build").unwrap().network, ToolNetwork::None);
        assert!(c.class("github-post").unwrap().kind.has_reach_check());
    }

    #[test]
    fn homelab_header_installs_a_file_maknaed_can_read() {
        assert!(HOMELAB.contains("install -o root -g _maknae -m 0640 "));
        assert!(!HOMELAB.contains("-g root"));
        assert!(HOMELAB.contains("before you install this file"));
    }

    fn sound(name: &str, extra: &str) -> String {
        format!("  \"{name}\":\n    executes_workspace: false\n    image: {{ ref: \"{IMAGE}\" }}\n    output_to_model: redacted\n{extra}")
    }

    #[test]
    fn entry_and_program_names_follow_the_tool_capability_grammar() {
        for name in ["a", "0", "a_b-9", "sentinel-674-x"] {
            let c = catalog(&doc("  {}\n", &sound(name, "")));
            assert!(c.entry(name).is_some(), "{name}: {:?}", c.disabled());
        }
        for name in ["A", "aB", "-a", "_a", "a.b", "a+b"] {
            let c = catalog(&doc("  {}\n", &sound(name, "")));
            assert!(c.entry(name).is_none(), "{name}");
            assert!(reason(&c, name).contains("entry name"), "{name}");
        }
        for program in ["cargo", "Cargo", "x86_64-gcc", "g++", "a.b-c"] {
            let c = catalog(&doc(
                "  {}\n",
                &sound(
                    SENTINEL,
                    &format!("    commands: {{ \"{program}\": {{ subcommands: [x] }} }}\n"),
                ),
            ));
            assert!(c.entry(SENTINEL).is_some(), "{program}: {:?}", c.disabled());
        }
        for program in ["a b", "a/b", "a@b", "a*b", "a:b", "a=b", ".", ".."] {
            let c = catalog(&doc(
                "  {}\n",
                &sound(
                    SENTINEL,
                    &format!("    commands: {{ \"{program}\": {{ subcommands: [x] }} }}\n"),
                ),
            ));
            assert!(c.entry(SENTINEL).is_none(), "{program}");
            assert!(reason(&c, SENTINEL).contains("program name"), "{program}");
        }
    }

    #[test]
    fn a_name_tools_yaml_enables_is_one_a_tool_grant_can_name() {
        let names = [
            ("a", "p"),
            ("a_b-9", "x86_64-gcc"),
            ("A", "p"),
            ("a.b", "p"),
            ("-a", "p"),
            ("a", "g++"),
            ("a", "a@b"),
            ("a", "a*b"),
        ];
        for (entry, program) in names {
            let c = catalog(&doc(
                "  {}\n",
                &sound(
                    entry,
                    &format!("    commands: {{ \"{program}\": {{ subcommands: [x] }} }}\n"),
                ),
            ));
            let granted = crate::parse_authz(&format!(
                "schema_version: 1\npermissions:\n  allow: [\"Tool({entry} {program} x)\"]\n"
            ));
            assert_eq!(
                c.entry(entry).is_some(),
                granted.is_ok(),
                "{entry} {program}: {granted:?}"
            );
        }
    }

    #[test]
    fn an_enabled_entry_needs_an_image() {
        let c = catalog(&doc(
            "  {}\n",
            &format!(
                "  {SENTINEL}:\n    executes_workspace: false\n    output_to_model: redacted\n"
            ),
        ));
        assert!(c.entry(SENTINEL).is_none());
        assert!(reason(&c, SENTINEL).contains("image"));
        let off = catalog(&doc(
            "  {}\n",
            "  off:\n    enabled: false\n    executes_workspace: false\n    output_to_model: redacted\n",
        ));
        assert!(off.disabled().is_empty(), "{:?}", off.disabled());
    }

    #[test]
    fn every_entry_needs_output_to_model() {
        for enabled in ["true", "false"] {
            let c = catalog(&doc(
                "  {}\n",
                &format!("  {SENTINEL}:\n    enabled: {enabled}\n    executes_workspace: false\n    image: {{ ref: \"{IMAGE}\" }}\n"),
            ));
            assert!(c.entry(SENTINEL).is_none(), "{enabled}");
            assert!(
                reason(&c, SENTINEL).contains("output_to_model"),
                "{enabled}"
            );
        }
        let c = catalog(&doc(
            "  {}\n",
            &format!("  {SENTINEL}:\n    executes_workspace: false\n    image: {{ ref: \"{IMAGE}\" }}\n    output_to_model: sentinel\n"),
        ));
        assert!(reason(&c, SENTINEL).contains("output_to_model `sentinel`"));
    }

    #[test]
    fn image_ref_names_a_registry_host_first() {
        for bad in ["example/x", "library/rust", "a/b/c"] {
            let r = format!("{bad}@sha256:{DIGEST}");
            assert!(!image_ref_ok(&r), "{r}");
        }
        for good in [
            "localhost/x",
            "registry.example/x",
            "reg:5000/x",
            "ghcr.io/a/b",
        ] {
            let r = format!("{good}@sha256:{DIGEST}");
            assert!(image_ref_ok(&r), "{r}");
        }
    }

    fn post_bound() -> crate::Bound {
        let mut b = crate::Bound::empty();
        b.insert("git.change", "345");
        b.insert("git.base", "o/r");
        b
    }

    fn grammar_shapes(c: &ToolCommand) -> &BTreeMap<String, Arc<crate::Shape>> {
        match &c.form {
            CommandForm::Grammar { shapes, .. } => shapes,
            CommandForm::Positional(_) | CommandForm::Open => panic!("{:?}", c.form),
        }
    }

    fn accepted(c: &ToolCommand, args: &[&str]) -> bool {
        let args = argv(args);
        grammar_shapes(c)
            .values()
            .any(|s| s.matches_argv(&args, &post_bound()))
            && first_denied(&c.deny_args, &args).is_none()
    }

    #[test]
    fn homelab_post_refuses_off_shape_forms() {
        let c = catalog(HOMELAB);
        let gh = &c.entry("github-post").unwrap().commands["gh"];
        for refused in [
            &[
                "pr",
                "review",
                "345",
                "-R",
                "o/r",
                "--comment",
                "--body-file",
                "-",
                "-a",
            ][..],
            &[
                "pr",
                "review",
                "345",
                "-R",
                "o/r",
                "-ca",
                "--body-file",
                "-",
            ],
            &[
                "pr",
                "review",
                "345",
                "-R",
                "o/r",
                "--comment",
                "--body-file",
                "-",
                "--approve",
            ],
            &["pr", "review", "345", "-R", "o/r", "-a=true"],
            &["pr", "review", "345", "-ab", "x"],
            &["pr", "review", "--approve"],
            &[
                "pr",
                "review",
                "345",
                "-R",
                "o/r",
                "--approve=true",
                "--body-file",
                "-",
            ],
            &[
                "pr",
                "comment",
                "345",
                "-R",
                "o/r",
                "--body-file",
                "/workspace/x",
            ],
            &[
                "pr",
                "comment",
                "345",
                "-R",
                "o/r",
                "--body-file",
                "/workspace/../run/secrets/x",
            ],
            &["pr", "comment", "345", "-R", "o/r", "--body", "x"],
            &["pr", "comment", "345", "-R", "o/r", "--body=x"],
            &["pr", "comment", "345", "-R", "o/r", "-b", "x"],
            &["issue", "close", "7", "-R", "o/r"],
            &["pr", "view", "345", "-R", "o/r"],
        ] {
            assert!(!accepted(gh, refused), "{refused:?}");
        }
    }

    #[test]
    fn homelab_post_allows_only_the_exact_shapes() {
        let c = catalog(HOMELAB);
        let gh = &c.entry("github-post").unwrap().commands["gh"];
        assert_eq!(
            grammar_shapes(gh)
                .keys()
                .map(String::as_str)
                .collect::<Vec<_>>(),
            [
                "pr.comment",
                "pr.review.approve",
                "pr.review.comment",
                "pr.review.request-changes"
            ]
        );
        for ok in [
            &["pr", "comment", "345", "-R", "o/r", "--body-file", "-"][..],
            &[
                "pr",
                "review",
                "345",
                "-R",
                "o/r",
                "--comment",
                "--body-file",
                "-",
            ],
            &[
                "pr",
                "review",
                "345",
                "-R",
                "o/r",
                "--request-changes",
                "--body-file",
                "-",
            ],
            &[
                "pr",
                "review",
                "345",
                "-R",
                "o/r",
                "--approve",
                "--body-file",
                "-",
            ],
        ] {
            assert!(accepted(gh, ok), "{ok:?}");
        }
        let ok = argv(&["pr", "comment", "345", "-R", "o/r", "--body-file", "-"]);
        assert!(!grammar_shapes(gh)
            .values()
            .any(|s| s.matches_argv(&ok, &crate::Bound::empty())));
    }

    #[test]
    fn homelab_issue_entries_split_the_shapes_by_credential_class() {
        let c = catalog(HOMELAB);
        let shapes = |entry: &str| -> Vec<String> {
            grammar_shapes(&c.entry(entry).unwrap().commands["gh"])
                .keys()
                .cloned()
                .collect()
        };
        assert_eq!(
            shapes("github-issues-read"),
            ["issue.list", "issue.status", "issue.view"]
        );
        assert_eq!(shapes("github-issues-write").len(), 12);
        for (entry, app) in [
            ("github-issues-read", "maknae-github-issues-read"),
            ("github-issues-write", "maknae-github-issues-write"),
        ] {
            let e = c.entry(entry).unwrap();
            assert_eq!(e.credential.as_deref(), Some(entry));
            assert!(e.binds.contains("git"), "{entry}");
            assert!(e.network != ToolNetwork::None, "{entry}");
            assert!(c.class(entry).unwrap().kind.has_reach_check(), "{entry}");
            assert!(
                format!("{:?}", c.class(entry).unwrap()).contains(app),
                "{entry}"
            );
        }
    }

    #[test]
    fn tools_yaml_subcommands_lone_star_still_refused() {
        let c =
            ToolsCatalog::parse(&doc(CRED, &with_command("", "{ subcommands: [\"*\"] }"))).unwrap();
        assert!(reason(&c, SENTINEL).contains("subcommand `*`"));
        assert!(DenyArg::parse("*").is_err());
    }

    #[test]
    fn rust_scratch_is_open_mode() {
        let c = catalog(HOMELAB);
        let e = c.entry("rust-scratch").unwrap();
        assert_eq!(e.credential, None);
        assert_eq!(e.network, ToolNetwork::None);
        assert_eq!(e.workspace, ToolWorkspaceAccess::Rw);
        assert!(e.executes_workspace);
        assert_eq!(
            e.commands.keys().map(String::as_str).collect::<Vec<_>>(),
            ["cargo", "rustc"]
        );
        for command in e.commands.values() {
            assert_eq!(command.form, CommandForm::Open);
        }
        assert_eq!(
            e.image,
            c.entry("rust-build").unwrap().image,
            "the baseline's reference image"
        );
    }

    #[test]
    fn homelab_git_denies_configuration_overrides() {
        let c = catalog(HOMELAB);
        let git = &c.entry("github-read").unwrap().commands["git"];
        for refused in ["--upl=x", "-c", "-ccore.x=1", "--config=x"] {
            assert!(
                first_denied(&git.deny_args, &argv(&["fetch", refused])).is_some(),
                "{refused}"
            );
        }
    }

    fn positional(c: &ToolCommand) -> &[ArgPattern] {
        match &c.form {
            CommandForm::Positional(patterns) => patterns,
            CommandForm::Grammar { .. } | CommandForm::Open => panic!("{:?}", c.form),
        }
    }

    const GH_GRAMMAR: &str = "schema_version: 1\nprogram: gh\ntested: { version: \"2.105.0\", date: 2026-11-24 }\nshapes:\n  issue.list:\n    description: List issues.\n    class: read\n    forge: { base: [read] }\n    argv: [issue, list, -R, \"{git.base}\"]\n  pr.view:\n    description: View a pull request.\n    class: read\n    argv: [pr, view]\n  pr.broken:\n    description: Broken.\n    class: sentinel-674-class\n    argv: [pr]\n";

    fn gh_grammars() -> GrammarSet {
        let mut set = GrammarSet::empty();
        set.grammars.insert(
            "gh".to_string(),
            crate::Grammar::parse("gh", GH_GRAMMAR).unwrap(),
        );
        set
    }

    const CRED: &str = "  c:\n    kind: github-machine-user\n";

    fn with_command(extra: &str, command: &str) -> String {
        format!("  {SENTINEL}:\n    executes_workspace: false\n{ESS}{extra}    commands:\n      gh: {command}\n")
    }

    fn formed(extra: &str, command: &str) -> ToolsCatalog {
        ToolsCatalog::parse_with(&doc(CRED, &with_command(extra, command)), &gh_grammars()).unwrap()
    }

    #[test]
    fn command_with_two_forms_disables_entry() {
        for command in [
            "{ subcommands: [x], open: true }",
            "{ subcommands: [x], grammar: gh, shapes: [pr.view] }",
            "{ open: true, grammar: gh, shapes: [pr.view] }",
            "{ subcommands: [x], open: true, grammar: gh, shapes: [pr.view] }",
            "{}",
            "{ deny_args: [x] }",
        ] {
            let c = formed("", command);
            assert!(c.entry(SENTINEL).is_none(), "{command}");
            assert!(reason(&c, SENTINEL).contains("exactly one of"), "{command}");
            assert!(c.entry("good").is_some());
        }
        for command in ["{ grammar: gh }", "{ shapes: [pr.view] }"] {
            let c = formed("", command);
            assert!(
                reason(&c, SENTINEL).contains("both `grammar` and `shapes`"),
                "{command}"
            );
        }
    }

    #[test]
    fn open_with_credential_disables_entry() {
        let c = formed("    credential: c\n", "{ open: true }");
        assert!(c.entry(SENTINEL).is_none());
        assert!(reason(&c, SENTINEL).contains("needs a grammar"));
    }

    #[test]
    fn open_with_network_disables_entry() {
        let c = formed(
            "    network: { via: maknae-proxy, sites: [github.com] }\n",
            "{ open: true }",
        );
        assert!(c.entry(SENTINEL).is_none());
        assert!(reason(&c, SENTINEL).contains("needs a grammar"));
    }

    #[test]
    fn open_without_either_loads() {
        for extra in ["", "    credential: none\n    network: none\n"] {
            let c = formed(extra, "{ open: true, deny_args: [\"--x*\"] }");
            assert!(c.disabled().is_empty(), "{:?}", c.disabled());
            let gh = &c.entry(SENTINEL).unwrap().commands["gh"];
            assert_eq!(gh.form, CommandForm::Open);
            assert_eq!(gh.deny_args.len(), 1);
        }
        let c = formed("", "{ open: false }");
        assert!(reason(&c, SENTINEL).contains("`open` must be true"));
        let c = formed("", "{ open: yes-please }");
        assert!(reason(&c, SENTINEL).contains("open must be true or false"));
    }

    #[test]
    fn grammar_command_holds_the_resolved_shapes() {
        let c = formed(
            "    credential: c\n    binds: { git: { resolver: git } }\n",
            "{ grammar: gh, shapes: [issue.list] }",
        );
        assert!(c.disabled().is_empty(), "{:?}", c.disabled());
        let set = gh_grammars();
        let grammar = &set.grammars["gh"];
        let CommandForm::Grammar {
            grammar: name,
            grammar_canonical,
            shapes,
        } = &c.entry(SENTINEL).unwrap().commands["gh"].form
        else {
            panic!("not a grammar command");
        };
        assert_eq!(name, "gh");
        assert_eq!(&**grammar_canonical, grammar.canonical.as_str());
        assert!(grammar_canonical.starts_with('{'), "{grammar_canonical}");
        assert_eq!(shapes.keys().collect::<Vec<_>>(), ["issue.list"]);
        assert_eq!(*shapes["issue.list"], grammar.shapes["issue.list"]);
    }

    #[test]
    fn without_grammars_a_grammar_command_disables_its_entry() {
        let text = doc(
            CRED,
            &with_command("", "{ grammar: gh, shapes: [pr.view] }"),
        );
        let c = ToolsCatalog::parse(&text).unwrap();
        assert!(c.entry(SENTINEL).is_none());
        assert!(reason(&c, SENTINEL).contains("grammar `gh` is not enabled"));
        assert_eq!(
            c,
            ToolsCatalog::parse_with(&text, &GrammarSet::empty()).unwrap()
        );
        assert!(c.entry("good").is_some());
    }

    #[test]
    fn a_disabled_grammar_is_named_with_its_reason() {
        let mut set = GrammarSet::empty();
        set.disabled.push(crate::DisabledGrammar {
            file: "gh.yaml".to_string(),
            reason: "sentinel-674-why".to_string(),
        });
        let text = doc(
            CRED,
            &with_command("", "{ grammar: gh, shapes: [pr.view] }"),
        );
        let c = ToolsCatalog::parse_with(&text, &set).unwrap();
        let why = reason(&c, SENTINEL);
        assert!(why.contains("grammar `gh` is disabled"), "{why}");
        assert!(why.contains("sentinel-674-why"), "{why}");
    }

    #[test]
    fn a_grammar_serves_only_its_own_program() {
        let c = ToolsCatalog::parse_with(
            &doc(
                CRED,
                &format!("  {SENTINEL}:\n    executes_workspace: false\n{ESS}    commands:\n      glab: {{ grammar: gh, shapes: [pr.view] }}\n"),
            ),
            &gh_grammars(),
        )
        .unwrap();
        assert!(reason(&c, SENTINEL).contains("only its own program"));
    }

    #[test]
    fn unknown_shape_disables_entry() {
        let c = formed("", "{ grammar: gh, shapes: [pr.view, sentinel-674-shape] }");
        assert!(c.entry(SENTINEL).is_none());
        assert!(reason(&c, SENTINEL).contains("shape `sentinel-674-shape` is not in grammar `gh`"));
        let c = formed("", "{ grammar: gh, shapes: [] }");
        assert!(reason(&c, SENTINEL).contains("shapes must not be empty"));
    }

    #[test]
    fn disabled_shape_disables_entry() {
        assert!(gh_grammars().grammars["gh"]
            .disabled
            .iter()
            .any(|(n, _)| n == "pr.broken"));
        let c = formed("", "{ grammar: gh, shapes: [pr.view, pr.broken] }");
        assert!(c.entry(SENTINEL).is_none());
        let why = reason(&c, SENTINEL);
        assert!(
            why.contains("shape `pr.broken` of grammar `gh` is disabled"),
            "{why}"
        );
        assert!(why.contains("sentinel-674-class"), "{why}");
    }

    #[test]
    fn binds_not_covering_shape_disables_entry() {
        let c = formed(
            "    credential: c\n",
            "{ grammar: gh, shapes: [issue.list] }",
        );
        assert!(c.entry(SENTINEL).is_none());
        assert!(reason(&c, SENTINEL).contains("bound kind `git`"));
        let c = formed("", "{ grammar: gh, shapes: [pr.view] }");
        assert!(c.entry(SENTINEL).is_some(), "{:?}", c.disabled());
    }

    #[test]
    fn credential_shape_without_forge_disables_entry() {
        let c = formed("    credential: c\n", "{ grammar: gh, shapes: [pr.view] }");
        assert!(c.entry(SENTINEL).is_none());
        assert!(reason(&c, SENTINEL).contains("shape `pr.view` declares no forge"));
        let c = formed(
            "    credential: none\n",
            "{ grammar: gh, shapes: [pr.view] }",
        );
        assert!(c.entry(SENTINEL).is_some(), "{:?}", c.disabled());
    }

    #[test]
    fn a_shape_listed_twice_disables_entry() {
        let c = formed("", "{ grammar: gh, shapes: [pr.view, pr.view] }");
        assert!(c.entry(SENTINEL).is_none());
        assert!(reason(&c, SENTINEL).contains("shape `pr.view` is listed more than once"));
    }

    #[test]
    fn the_dropin_directory_refusal_names_the_required_owner() {
        let dir = Path::new("/etc/maknae/tools.d");
        assert_eq!(
            dropin_dir_refusal(dir, Some(0)),
            "the drop-in directory /etc/maknae/tools.d must be owned by uid 0, not group-writable and with no world access"
        );
        assert_eq!(
            dropin_dir_refusal(dir, None),
            "the drop-in directory /etc/maknae/tools.d must not be group-writable and have no world access"
        );
        assert_eq!(
            ToolsError::DropIns("x".to_string()).to_string(),
            "tools.d: x"
        );
    }

    #[test]
    fn unknown_keys_name_the_section_not_a_file() {
        let c = catalog(&doc(
            "  {}\n",
            &format!("  {SENTINEL}:\n    executes_workspace: false\n{ESS}    nonsense: 1\n"),
        ));
        assert_eq!(reason(&c, SENTINEL), "the entry: unknown key 'nonsense'");
    }

    #[test]
    fn canonical_covers_the_grammars_enabled_entries_name() {
        let plain = doc(CRED, "");
        let grammar_entry = doc(
            CRED,
            &with_command("", "{ grammar: gh, shapes: [pr.view] }"),
        );
        let set = gh_grammars();
        assert_eq!(
            ToolsCatalog::parse_with(&plain, &set).unwrap().canonical(),
            ToolsCatalog::parse(&plain).unwrap().canonical()
        );
        let named = ToolsCatalog::parse_with(&grammar_entry, &set).unwrap();
        assert!(named.entry(SENTINEL).is_some());
        let canonical = named.canonical();
        assert!(
            canonical.starts_with("{\"grammars\":{\"gh\":"),
            "{canonical}"
        );
        assert!(canonical.contains(&crate::canonical_json(&Value::Str(
            set.grammars["gh"].canonical.clone()
        ))));
        assert!(canonical.contains("\"tools.d\":{}"), "{canonical}");
        let mut edited = gh_grammars();
        edited.grammars.get_mut("gh").unwrap().canonical.push(' ');
        assert_ne!(
            ToolsCatalog::parse_with(&grammar_entry, &edited)
                .unwrap()
                .canonical(),
            canonical
        );
        let off = grammar_entry.replace(
            &format!("  {SENTINEL}:\n"),
            &format!("  {SENTINEL}:\n    enabled: false\n"),
        );
        let off = ToolsCatalog::parse_with(&off, &set).unwrap();
        assert!(off.entry(SENTINEL).is_none());
        assert!(!off.canonical().contains("grammars"), "{}", off.canonical());
    }

    #[cfg(all(unix, feature = "hermetic-test-seam"))]
    mod seam {
        use super::*;
        use std::os::unix::fs::PermissionsExt;

        fn own() -> maknae_io::TargetRequired {
            maknae_io::TargetRequired {
                owner: None,
                ..crate::authz::root_policy_file_required()
            }
        }

        fn dir(tag: &str) -> std::path::PathBuf {
            let d = std::env::temp_dir().join(format!("tools_{tag}_{}", std::process::id()));
            let _ = std::fs::remove_dir_all(&d);
            std::fs::create_dir_all(&d).unwrap();
            std::fs::set_permissions(&d, std::fs::Permissions::from_mode(0o700)).unwrap();
            d.canonicalize().unwrap()
        }

        fn write(d: &Path, body: &[u8], mode: u32) {
            let p = d.join(TOOLS_FILE);
            std::fs::write(&p, body).unwrap();
            std::fs::set_permissions(&p, std::fs::Permissions::from_mode(mode)).unwrap();
        }

        fn dropin(d: &Path, name: &str, body: &str) -> std::path::PathBuf {
            let dir = d.join(TOOLS_DROPIN_DIR);
            if !dir.exists() {
                std::fs::create_dir(&dir).unwrap();
                std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o750)).unwrap();
            }
            let p = dir.join(name);
            std::fs::write(&p, body).unwrap();
            std::fs::set_permissions(&p, std::fs::Permissions::from_mode(0o640)).unwrap();
            p
        }

        fn load(d: &Path) -> Result<ToolsCatalog, ToolsError> {
            ToolsCatalog::load_with_requirement(d, own(), &crate::grammar::shipped_grammars())
        }

        fn loaded(tag: &str, main: Option<&str>, dropins: &[(&str, &str)]) -> ToolsCatalog {
            let d = dir(tag);
            if let Some(main) = main {
                write(&d, main.as_bytes(), 0o640);
            }
            for (name, body) in dropins {
                dropin(&d, name, body);
            }
            let got = load(&d);
            let _ = std::fs::remove_dir_all(&d);
            got.unwrap()
        }

        fn entry_doc(name: &str, extra: &str) -> String {
            format!("schema_version: 1\ntools:\n{}", sound(name, extra))
        }

        const ECHO: &str = "    commands:\n      echo: { subcommands: [\"hi *\"] }\n";

        #[test]
        fn dropin_entry_loads_beside_tools_yaml() {
            let c = loaded(
                "dropin_beside",
                Some(HOMELAB),
                &[("50-extra.yaml", &entry_doc("sentinel-674-extra", ECHO))],
            );
            assert!(c.disabled().is_empty(), "{:?}", c.disabled());
            assert!(c.entry("sentinel-674-extra").is_some());
            assert!(c.entry("rust-build").is_some());
            let alone = loaded(
                "dropin_alone",
                None,
                &[("50-extra.yaml", &entry_doc("sentinel-674-extra", ECHO))],
            );
            assert!(alone.entry("sentinel-674-extra").is_some());
            let ignored = loaded(
                "dropin_ignored",
                None,
                &[
                    ("notes.txt", &entry_doc("sentinel-674-txt", ECHO)),
                    (".hidden.yaml", &entry_doc("sentinel-674-dot", ECHO)),
                ],
            );
            assert!(ignored.is_empty(), "{ignored:?}");
            assert_eq!(ignored.canonical(), "{}");
        }

        #[test]
        fn dropin_entry_uses_class_from_tools_yaml() {
            let main = "schema_version: 1\ncredential_classes:\n  sentinel-674-class:\n    kind: github-machine-user\n";
            let c = loaded(
                "dropin_class",
                Some(main),
                &[(
                    "a.yaml",
                    &entry_doc(
                        "sentinel-674-user",
                        &format!("    credential: sentinel-674-class\n{ECHO}"),
                    ),
                )],
            );
            assert!(c.disabled().is_empty(), "{:?}", c.disabled());
            assert_eq!(
                c.entry("sentinel-674-user").unwrap().credential.as_deref(),
                Some("sentinel-674-class")
            );
        }

        #[test]
        fn duplicate_entry_across_files_disables_it_everywhere() {
            let main = entry_doc("sentinel-674-dup", ECHO);
            let c = loaded(
                "dropin_dup_entry",
                Some(&main),
                &[
                    ("a.yaml", &entry_doc("sentinel-674-dup", ECHO)),
                    ("b.yaml", &entry_doc("sentinel-674-other", ECHO)),
                ],
            );
            assert!(c.entry("sentinel-674-dup").is_none());
            assert!(c.entry("sentinel-674-other").is_some());
            assert_eq!(c.disabled().len(), 1, "{:?}", c.disabled());
            assert_eq!(
                reason(&c, "sentinel-674-dup"),
                "defined in more than one file: tools.yaml, tools.d/a.yaml"
            );
            let c = loaded(
                "dropin_dup_two",
                None,
                &[
                    ("a.yaml", &entry_doc("sentinel-674-dup", ECHO)),
                    ("b.yaml", &entry_doc("sentinel-674-dup", ECHO)),
                    ("c.yaml", &entry_doc("sentinel-674-dup", ECHO)),
                ],
            );
            assert_eq!(c.disabled().len(), 1, "{:?}", c.disabled());
            assert_eq!(
                reason(&c, "sentinel-674-dup"),
                "defined in more than one file: tools.d/a.yaml, tools.d/b.yaml, tools.d/c.yaml"
            );
        }

        #[test]
        fn duplicate_class_across_files_disables_it() {
            let class = "schema_version: 1\ncredential_classes:\n  sentinel-674-class:\n    kind: github-machine-user\n";
            let user = entry_doc(
                "sentinel-674-user",
                &format!("    credential: sentinel-674-class\n{ECHO}"),
            );
            let c = loaded(
                "dropin_dup_class",
                Some(class),
                &[("a.yaml", class), ("b.yaml", &user)],
            );
            assert!(c.class("sentinel-674-class").is_none());
            assert_eq!(
                reason(&c, "credential_classes.sentinel-674-class"),
                "defined in more than one file: tools.yaml, tools.d/a.yaml"
            );
            assert!(c.entry("sentinel-674-user").is_none());
            assert!(reason(&c, "sentinel-674-user").contains("tools.d/b.yaml: "));
            assert!(reason(&c, "sentinel-674-user").contains("more than one file"));
        }

        #[test]
        fn a_schema_failed_dropin_still_counts_its_names_as_duplicates() {
            let bad = entry_doc("sentinel-674-main", ECHO)
                .replace("schema_version: 1", "schema_version: 2");
            let c = loaded(
                "dropin_dup_bad",
                Some(&entry_doc("sentinel-674-main", ECHO)),
                &[("a.yaml", &bad)],
            );
            assert!(c.entry("sentinel-674-main").is_none(), "{:?}", c.disabled());
            assert!(reason(&c, "sentinel-674-main").contains("more than one file"));
            assert!(reason(&c, "sentinel-674-main").contains("tools.d/a.yaml"));
            let unloadable = "schema_version: 1\ntools: [\n";
            let c = loaded(
                "dropin_dup_yaml",
                Some(&entry_doc("sentinel-674-main", ECHO)),
                &[("a.yaml", unloadable)],
            );
            assert!(c.entry("sentinel-674-main").is_some(), "{:?}", c.disabled());
        }

        #[test]
        fn unparseable_dropin_disables_only_its_names() {
            for bad in [
                "schema_version: 1\ntools: [\n".to_string(),
                entry_doc("sentinel-674-mine", ECHO)
                    .replace("schema_version: 1", "schema_version: 2"),
                format!(
                    "{}sentinel-674-key: 1\n",
                    entry_doc("sentinel-674-mine", ECHO)
                ),
                "schema_version: 1\ncredential_classes:\n  none:\n    kind: github-machine-user\n"
                    .to_string(),
            ] {
                let c = loaded(
                    "dropin_bad",
                    Some(&entry_doc("sentinel-674-main", ECHO)),
                    &[
                        ("a.yaml", &bad),
                        ("b.yaml", &entry_doc("sentinel-674-other", ECHO)),
                    ],
                );
                assert!(c.entry("sentinel-674-main").is_some(), "{bad}");
                assert!(c.entry("sentinel-674-other").is_some(), "{bad}");
                assert!(c.entry("sentinel-674-mine").is_none(), "{bad}");
                assert_eq!(c.disabled().len(), 1, "{bad}: {:?}", c.disabled());
                let why = reason(&c, "tools.d/a.yaml");
                let shown = ToolsCatalog::parse(&bad).unwrap_err().to_string();
                let want = shown.strip_prefix("tools.yaml: ").unwrap().to_string();
                assert_eq!(
                    why,
                    want.replace("'tools.yaml'", "'tools.d/a.yaml'"),
                    "{bad}"
                );
                assert!(!why.contains(TOOLS_FILE), "{why}");
            }
            let d = dir("dropin_badbytes");
            dropin(&d, "a.yaml", "x");
            std::fs::write(d.join(TOOLS_DROPIN_DIR).join("a.yaml"), [0xff, 0xfe]).unwrap();
            dropin(&d, "b.yaml", &entry_doc("sentinel-674-other", ECHO));
            let p = dropin(&d, "c.yaml", &entry_doc("sentinel-674-loose", ECHO));
            std::fs::set_permissions(&p, std::fs::Permissions::from_mode(0o644)).unwrap();
            let c = load(&d).unwrap();
            let _ = std::fs::remove_dir_all(&d);
            assert!(c.entry("sentinel-674-other").is_some());
            assert!(c.entry("sentinel-674-loose").is_none());
            assert!(reason(&c, "tools.d/a.yaml").contains("UTF-8"));
            assert!(!reason(&c, "tools.d/c.yaml").is_empty());
        }

        #[test]
        fn from_texts_assembles_what_load_reads() {
            let dup = entry_doc("sentinel-674-dup", ECHO);
            let class = "schema_version: 1\ncredential_classes:\n  sentinel-674-class:\n    kind: github-machine-user\n";
            let user = entry_doc(
                "sentinel-674-user",
                &format!("    credential: sentinel-674-class\n{ECHO}"),
            );
            let gh = entry_doc(
                "sentinel-674-gh",
                "    commands:\n      gh: { grammar: gh, shapes: [pr.comment] }\n",
            );
            type Case<'a> = (&'a str, Option<&'a str>, Vec<(&'a str, &'a str)>);
            let cases: [Case; 4] = [
                ("ft_empty", None, vec![]),
                (
                    "ft_mixed",
                    Some(HOMELAB),
                    vec![
                        ("b.yaml", &dup),
                        ("a.yaml", &dup),
                        ("c.yaml", class),
                        ("d.yaml", &user),
                        ("e.yaml", &gh),
                        ("notes.txt", &user),
                        (".hidden.yaml", &user),
                    ],
                ),
                (
                    "ft_unparsed",
                    Some(&dup),
                    vec![
                        (
                            "z.yaml",
                            "schema_version: 2\ntools:\n  sentinel-674-dup: {}\n",
                        ),
                        ("y.yaml", "schema_version: 1\ntools: [\n"),
                    ],
                ),
                (
                    "ft_class",
                    Some(class),
                    vec![("a.yaml", class), ("b.yaml", &user)],
                ),
            ];
            for (tag, main, dropins) in cases {
                let want = loaded(tag, main, &dropins);
                let got =
                    ToolsCatalog::from_texts(main, &dropins, &crate::grammar::shipped_grammars())
                        .unwrap();
                assert_eq!(got, want, "{tag}");
            }
            let got =
                ToolsCatalog::from_texts(None, &[("e.yaml", &gh)], &GrammarSet::empty()).unwrap();
            assert!(got.entry("sentinel-674-gh").is_none());
            assert!(ToolsCatalog::from_texts(
                Some("schema_version: 2\n"),
                &[],
                &GrammarSet::empty()
            )
            .is_err());
        }

        #[test]
        fn class_names_lists_the_enabled_classes() {
            let class = "schema_version: 1\ncredential_classes:\n  sentinel-674-class:\n    kind: github-machine-user\n  sentinel-674-b:\n    kind: github-machine-user\n";
            let c = loaded("class_names", Some(class), &[("a.yaml", "schema_version: 1\ncredential_classes:\n  sentinel-674-b:\n    kind: github-machine-user\n")]);
            assert_eq!(c.class_names().collect::<Vec<_>>(), ["sentinel-674-class"]);
        }

        #[test]
        fn symlinked_dropin_is_skipped_with_warning() {
            let d = dir("dropin_link");
            let target = dropin(&d, "real.yaml", &entry_doc("sentinel-674-real", ECHO));
            let dropins = d.join(TOOLS_DROPIN_DIR);
            std::os::unix::fs::symlink(&target, dropins.join("link.yaml")).unwrap();
            std::fs::create_dir(dropins.join("sub.yaml")).unwrap();
            let c = load(&d).unwrap();
            let _ = std::fs::remove_dir_all(&d);
            assert!(c.entry("sentinel-674-real").is_some());
            assert_eq!(c.disabled().len(), 2, "{:?}", c.disabled());
            assert!(reason(&c, "tools.d/link.yaml").contains("a symlink"));
            assert!(reason(&c, "tools.d/sub.yaml").contains("a directory"));
            assert!(!c.canonical().contains("link.yaml"));
        }

        #[test]
        fn a_world_readable_dropin_directory_fails_the_load() {
            let d = dir("dropin_rdir");
            dropin(&d, "a.yaml", &entry_doc("sentinel-674-a", ECHO));
            std::fs::set_permissions(
                d.join(TOOLS_DROPIN_DIR),
                std::fs::Permissions::from_mode(0o755),
            )
            .unwrap();
            let got = load(&d);
            let _ = std::fs::remove_dir_all(&d);
            assert!(
                matches!(&got, Err(ToolsError::DropIns(m)) if *m == dropin_dir_refusal(&d.join(TOOLS_DROPIN_DIR), None)),
                "{got:?}"
            );
        }

        #[test]
        fn an_insecure_dropin_directory_fails_the_load() {
            let d = dir("dropin_wdir");
            dropin(&d, "a.yaml", &entry_doc("sentinel-674-a", ECHO));
            std::fs::set_permissions(
                d.join(TOOLS_DROPIN_DIR),
                std::fs::Permissions::from_mode(0o770),
            )
            .unwrap();
            let got = load(&d);
            let _ = std::fs::remove_dir_all(&d);
            assert!(
                matches!(&got, Err(ToolsError::DropIns(m)) if *m == dropin_dir_refusal(&d.join(TOOLS_DROPIN_DIR), None)),
                "{got:?}"
            );
            let shown = got.unwrap_err().to_string();
            assert!(shown.starts_with("tools.d: "), "{shown}");
        }

        #[test]
        fn canonical_covers_every_dropin_in_name_order() {
            let main = entry_doc("sentinel-674-main", ECHO);
            let base = loaded("canon_base", Some(&main), &[]);
            assert_eq!(
                base.canonical(),
                ToolsCatalog::parse(&main).unwrap().canonical()
            );
            let one = loaded(
                "canon_one",
                Some(&main),
                &[("b.yaml", &entry_doc("sentinel-674-b", ECHO))],
            );
            assert_ne!(one.canonical(), base.canonical());
            assert!(one.canonical().contains("\"tools.d\":{\"tools.d/b.yaml\":"));
            let two = loaded(
                "canon_two",
                Some(&main),
                &[
                    ("b.yaml", &entry_doc("sentinel-674-b", ECHO)),
                    ("a.yaml", "schema_version: 1\n"),
                ],
            );
            let canonical = two.canonical();
            let a = canonical.find("tools.d/a.yaml").unwrap();
            let b = canonical.find("tools.d/b.yaml").unwrap();
            assert!(a < b, "{canonical}");
            let bad = loaded(
                "canon_bad",
                Some(&main),
                &[("a.yaml", "schema_version: 1\ntools: [\n")],
            );
            assert!(bad.canonical().contains("tools: ["), "{}", bad.canonical());
        }

        #[test]
        fn a_missing_config_dir_is_refused() {
            let d = dir("missing_parent");
            let got = load(&d.join("sentinel-674-absent"));
            let _ = std::fs::remove_dir_all(&d);
            assert!(matches!(got, Err(ToolsError::Config(_))), "{got:?}");
        }

        #[test]
        fn absent_file_is_empty_catalog() {
            let d = dir("absent");
            let got = ToolsCatalog::load_with_requirement(&d, own(), &GrammarSet::empty());
            let _ = std::fs::remove_dir_all(&d);
            assert_eq!(got, Ok(ToolsCatalog::empty()));
        }

        #[test]
        fn a_sound_file_loads() {
            let d = dir("ok");
            write(&d, HOMELAB.as_bytes(), 0o640);
            let got =
                ToolsCatalog::load_with_requirement(&d, own(), &crate::grammar::shipped_grammars());
            let _ = std::fs::remove_dir_all(&d);
            assert_eq!(
                got,
                ToolsCatalog::parse_with(HOMELAB, &crate::grammar::shipped_grammars())
            );
            assert!(got.unwrap().entry("rust-build").is_some());
        }

        #[test]
        fn a_malformed_or_insecure_file_is_refused() {
            let d = dir("bad");
            write(&d, b"schema_version: 2\n", 0o640);
            assert!(matches!(
                ToolsCatalog::load_with_requirement(&d, own(), &GrammarSet::empty()),
                Err(ToolsError::Invalid(_))
            ));
            write(&d, &[0xff, 0xfe], 0o640);
            assert!(matches!(
                ToolsCatalog::load_with_requirement(&d, own(), &GrammarSet::empty()),
                Err(ToolsError::Config(ConfigError::Io(ref m))) if m.contains("UTF-8")
            ));
            write(&d, HOMELAB.as_bytes(), 0o644);
            let got = ToolsCatalog::load_with_requirement(&d, own(), &GrammarSet::empty());
            let _ = std::fs::remove_dir_all(&d);
            assert!(matches!(
                got,
                Err(ToolsError::Config(ConfigError::InsecurePermissions { .. }))
            ));
        }

        #[test]
        fn a_writable_directory_is_refused() {
            let d = dir("wdir");
            write(&d, HOMELAB.as_bytes(), 0o640);
            std::fs::set_permissions(&d, std::fs::Permissions::from_mode(0o770)).unwrap();
            let got = ToolsCatalog::load_with_requirement(&d, own(), &GrammarSet::empty());
            let _ = std::fs::remove_dir_all(&d);
            assert!(
                matches!(&got, Err(ToolsError::Config(ConfigError::Io(m))) if m.contains("must be owned by root") && m.contains(TOOLS_FILE)),
                "{got:?}"
            );
        }
    }
}
