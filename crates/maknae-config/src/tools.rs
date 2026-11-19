//! `tools.yaml` (#674): the catalog of tools a subject may be granted, bounded here.

use crate::argpattern::{ArgPattern, DenyArg};
use crate::{ConfigError, Value};
use std::collections::{BTreeMap, BTreeSet};
use std::fmt;
use std::path::Path;

pub const TOOLS_FILE: &str = "tools.yaml";

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
pub enum Narrowing {
    Provider,
    Maknae,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Minting {
    TrustPlane,
    FrontEnd,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RevokeOn {
    TaskOutcome,
    InvocationOutcome,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ClassLifetime {
    pub expires: String,
    pub revoke_on: RevokeOn,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CredentialClass {
    pub name: String,
    pub kind: CredentialKind,
    pub app: Option<String>,
    pub source: Option<CredentialSource>,
    pub narrowing: Option<Narrowing>,
    pub minting: Option<Minting>,
    pub lifetime: Option<ClassLifetime>,
    pub delivery: Vec<String>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Verify {
    Required,
    Optional,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Image {
    pub reference: String,
    pub signature: Option<Verify>,
    pub sbom: Option<Verify>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Isolation {
    Container,
    Vm,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Network {
    None,
    Proxy { sites: Vec<String> },
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum WorkspaceAccess {
    Rw,
    Ro,
    None,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum VolumeAccess {
    Ro,
    Rw,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum VolumeScope {
    Task,
    Tasker,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Volume {
    pub access: VolumeAccess,
    pub scope: Option<VolumeScope>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum OutputToModel {
    Redacted,
    StatusOnly,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Resources {
    pub cpus: Option<String>,
    pub memory: Option<String>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Command {
    pub subcommands: Vec<ArgPattern>,
    pub deny_args: Vec<DenyArg>,
    pub timeout: Option<String>,
    pub output: Option<String>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ToolEntry {
    pub name: String,
    pub credential: Option<String>,
    pub binds: BTreeSet<String>,
    pub commands: BTreeMap<String, Command>,
    pub description: Option<String>,
    pub image: Option<Image>,
    pub isolation: Isolation,
    pub executes_workspace: bool,
    pub network: Network,
    pub workspace: WorkspaceAccess,
    pub volumes: BTreeMap<String, Volume>,
    pub output_to_model: OutputToModel,
    pub resources: Option<Resources>,
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
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ToolsError {
    Config(ConfigError),
    Invalid(String),
}

impl fmt::Display for ToolsError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Config(e) => write!(f, "{e}"),
            Self::Invalid(reason) => write!(f, "{TOOLS_FILE}: {reason}"),
        }
    }
}

impl std::error::Error for ToolsError {}

impl ToolsCatalog {
    pub fn empty() -> Self {
        Self::default()
    }

    pub fn parse(text: &str) -> Result<Self, ToolsError> {
        let invalid = |reason: &str| ToolsError::Invalid(reason.to_string());
        let Value::Map(top) = crate::load_str(text).map_err(ToolsError::Config)? else {
            return Err(invalid("the document must be a mapping"));
        };
        crate::reject_unknown_keys(
            TOOLS_FILE,
            &top,
            &["schema_version", "credential_classes", "tools"],
        )
        .map_err(ToolsError::Config)?;
        if !matches!(get(&top, "schema_version"), Some(Value::Int(1))) {
            return Err(invalid("schema_version must be 1"));
        }
        let section = |key: &str| match get(&top, key) {
            None => Ok(&[][..]),
            Some(Value::Map(items)) => Ok(items.as_slice()),
            Some(_) => Err(ToolsError::Invalid(format!("`{key}` must be a mapping"))),
        };
        let mut catalog = Self::empty();
        let mut classes: BTreeMap<&str, Result<CredentialClass, String>> = BTreeMap::new();
        for (name, body) in section("credential_classes")? {
            if name == "none" {
                return Err(invalid(
                    "`none` is reserved and cannot name a credential class",
                ));
            }
            classes.insert(name, parse_class(name, body));
        }
        for (name, body) in section("tools")? {
            let parsed = parse_entry(name, body, &classes);
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
        catalog.classes = classes
            .into_iter()
            .filter_map(|(name, class)| Some((name.to_string(), class.ok()?)))
            .collect();
        Ok(catalog)
    }

    pub fn entry(&self, name: &str) -> Option<&ToolEntry> {
        self.entries.get(name)
    }

    pub fn class(&self, name: &str) -> Option<&CredentialClass> {
        self.classes.get(name)
    }

    pub fn disabled(&self) -> &[Disabled] {
        &self.disabled
    }

    pub fn is_empty(&self) -> bool {
        self.entries.is_empty() && self.classes.is_empty() && self.disabled.is_empty()
    }
}

pub fn load_host_tools(config_dir: &Path) -> Result<ToolsCatalog, ToolsError> {
    #[cfg(not(unix))]
    {
        let _ = config_dir;
        Err(ToolsError::Config(ConfigError::PermissionsUnsupported))
    }
    #[cfg(unix)]
    {
        load_required(config_dir, crate::authz::root_policy_file_required())
    }
}

#[cfg(all(unix, feature = "hermetic-test-seam"))]
pub fn load_tools_with_requirement(
    config_dir: &Path,
    req: maknae_io::TargetRequired,
) -> Result<ToolsCatalog, ToolsError> {
    load_required(config_dir, req)
}

#[cfg(unix)]
fn load_required(
    config_dir: &Path,
    target: maknae_io::TargetRequired,
) -> Result<ToolsCatalog, ToolsError> {
    use crate::authz::RootReadError;
    let absolute = std::path::absolute(config_dir.join(TOOLS_FILE))
        .map_err(|e| ToolsError::Config(ConfigError::Io(e.to_string())))?;
    let bytes = match crate::authz::read_in_root_dir(&absolute, target) {
        Ok(bytes) => bytes,
        Err(RootReadError::Io(maknae_io::IoError::Io {
            kind: maknae_io::IoKind::NotFound,
            path: missing,
        })) if missing == absolute => return Ok(ToolsCatalog::empty()),
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
    ToolsCatalog::parse(body)
}

type Fields = [(String, Value)];

fn get<'a>(map: &'a Fields, key: &str) -> Option<&'a Value> {
    map.iter().find(|(k, _)| k == key).map(|(_, v)| v)
}

fn fields<'a>(v: &'a Value, what: &str, allowed: &[&str]) -> Result<&'a Fields, String> {
    let Value::Map(map) = v else {
        return Err(format!("{what} must be a mapping"));
    };
    crate::reject_unknown_keys(TOOLS_FILE, map, allowed).map_err(|e| format!("{what}: {e}"))?;
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
        ],
    )?;
    let kind = choice(
        get(map, "kind").ok_or("`kind` is required")?,
        "kind",
        &[
            (
                "github-app-installation",
                CredentialKind::GithubAppInstallation,
            ),
            ("github-machine-user", CredentialKind::GithubMachineUser),
            ("gitlab-project-token", CredentialKind::GitlabProjectToken),
            ("gitlab-bot-token", CredentialKind::GitlabBotToken),
            ("vault-child-token", CredentialKind::VaultChildToken),
            ("vault-dynamic-secret", CredentialKind::VaultDynamicSecret),
        ],
    )?;
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
                    ("provider", Narrowing::Provider),
                    ("maknae", Narrowing::Maknae),
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
                    ("trust-plane", Minting::TrustPlane),
                    ("front-end", Minting::FrontEnd),
                ],
            )
        })
        .transpose()?;
    let lifetime = get(map, "lifetime")
        .map(|v| {
            let m = fields(v, "lifetime", &["expires", "revoke_on"])?;
            Ok::<_, String>(ClassLifetime {
                expires: duration(
                    get(m, "expires").ok_or("lifetime.expires is required")?,
                    "lifetime.expires",
                )?,
                revoke_on: choice(
                    get(m, "revoke_on").ok_or("lifetime.revoke_on is required")?,
                    "lifetime.revoke_on",
                    &[
                        ("task-outcome", RevokeOn::TaskOutcome),
                        ("invocation-outcome", RevokeOn::InvocationOutcome),
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
            || narrowing != Some(Narrowing::Provider)
            || minting != Some(Minting::TrustPlane)
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
    !name.is_empty()
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
) -> Result<(bool, ToolEntry), String> {
    if !name_ok(name) {
        return Err("the entry name must be letters, digits, `.`, `_` or `-`".to_string());
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
    let isolation = get(map, "isolation").map_or(Ok(Isolation::Container), |v| {
        choice(
            v,
            "isolation",
            &[("container", Isolation::Container), ("vm", Isolation::Vm)],
        )
    })?;
    let executes_workspace =
        get(map, "executes_workspace").map_or(Ok(false), |v| flag(v, "executes_workspace"))?;
    let network = get(map, "network").map_or(Ok(Network::None), parse_network)?;
    let workspace = get(map, "workspace").map_or(Ok(WorkspaceAccess::None), |v| {
        choice(
            v,
            "workspace",
            &[
                ("rw", WorkspaceAccess::Rw),
                ("ro", WorkspaceAccess::Ro),
                ("none", WorkspaceAccess::None),
            ],
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
    let output_to_model = get(map, "output_to_model").map_or(Ok(OutputToModel::Redacted), |v| {
        choice(
            v,
            "output_to_model",
            &[
                ("redacted", OutputToModel::Redacted),
                ("status_only", OutputToModel::StatusOnly),
            ],
        )
    })?;
    let resources = get(map, "resources")
        .map(|v| {
            let m = fields(v, "resources", &["cpus", "memory"])?;
            Ok::<_, String>(Resources {
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
    let commands = get(map, "commands").map_or(Ok(BTreeMap::new()), parse_commands)?;
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

fn parse_image(v: &Value) -> Result<Image, String> {
    let m = fields(v, "image", &["ref", "verify"])?;
    let reference = text(get(m, "ref").ok_or("image.ref is required")?, "image.ref")?;
    if !image_ref_ok(reference) {
        return Err(format!(
            "image.ref `{reference}` must be `<registry>/<name>@sha256:<64 lowercase hex>`"
        ));
    }
    let verify = |m: &Fields, key: &str| {
        get(m, key)
            .map(|v| {
                choice(
                    v,
                    key,
                    &[
                        ("required", Verify::Required),
                        ("optional", Verify::Optional),
                    ],
                )
            })
            .transpose()
    };
    let (signature, sbom) = match get(m, "verify") {
        None => (None, None),
        Some(v) => {
            let vm = fields(v, "image.verify", &["signature", "sbom"])?;
            (verify(vm, "signature")?, verify(vm, "sbom")?)
        }
    };
    Ok(Image {
        reference: reference.to_string(),
        signature,
        sbom,
    })
}

fn parse_network(v: &Value) -> Result<Network, String> {
    if matches!(v, Value::Str(s) if s == "none") {
        return Ok(Network::None);
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
    if let Some(bad) = sites.iter().find(|h| !host_ok(h)) {
        return Err(format!("network site `{bad}` is not a host name"));
    }
    Ok(Network::Proxy {
        sites: sites.into_iter().map(str::to_string).collect(),
    })
}

fn parse_volumes(v: &Value) -> Result<BTreeMap<String, Volume>, String> {
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
                &[("ro", VolumeAccess::Ro), ("rw", VolumeAccess::Rw)],
            )?;
            let scope = get(m, "scope")
                .map(|v| {
                    choice(
                        v,
                        "volume scope",
                        &[("task", VolumeScope::Task), ("tasker", VolumeScope::Tasker)],
                    )
                })
                .transpose()?;
            Ok((role.clone(), Volume { access, scope }))
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

fn parse_commands(v: &Value) -> Result<BTreeMap<String, Command>, String> {
    let Value::Map(items) = v else {
        return Err("commands must be a mapping".to_string());
    };
    items
        .iter()
        .map(|(program, body)| {
            if program.is_empty() || program.contains(char::is_whitespace) || program.contains('/')
            {
                return Err(format!("command `{program}` must be a bare program name"));
            }
            let m = fields(
                body,
                &format!("command `{program}`"),
                &["subcommands", "deny_args", "timeout", "output"],
            )?;
            let subcommands = match get(m, "subcommands") {
                None => Vec::new(),
                Some(v) => strings(v, "subcommands")?
                    .into_iter()
                    .map(|p| {
                        ArgPattern::parse(p)
                            .map_err(|e| format!("command `{program}` subcommand `{p}`: {e}"))
                    })
                    .collect::<Result<_, _>>()?,
            };
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
                Command {
                    subcommands,
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::first_denied;

    const HOMELAB: &str = include_str!("../../../packaging/common/tools-homelab.yaml");
    const SENTINEL: &str = "sentinel-674-bad-entry";
    const DIGEST: &str = "0000000000000000000000000000000000000000000000000000000000000000";

    fn catalog(text: &str) -> ToolsCatalog {
        ToolsCatalog::parse(text).unwrap()
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

    const GOOD: &str = "  good:\n    commands:\n      echo: { subcommands: [\"hi *\"] }\n";

    fn doc(classes: &str, tools: &str) -> String {
        format!("schema_version: 1\ncredential_classes:\n{classes}\ntools:\n{tools}{GOOD}")
    }

    const APP_CLASS: &str = "  app-class:\n    kind: github-app-installation\n    source: minted-per-task\n    narrowing: provider\n    minting: trust-plane\n    app: my-app\n";

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
            e.commands["echo"].subcommands[0].matches(&argv(&["hi", "x"]), &crate::Bound::empty())
        );
        assert_eq!(c.class("app-class").unwrap().app.as_deref(), Some("my-app"));
    }

    #[test]
    fn unknown_entry_field_disables_only_that_entry() {
        let c = catalog(&doc("  {}\n", &format!("  {SENTINEL}:\n    nonsense: 1\n")));
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
            format!(
                "registry.example/x@sha256:{}",
                DIGEST.to_uppercase().replace('0', "A")
            ),
            format!("@sha256:{DIGEST}"),
            format!("reg istry/x@sha256:{DIGEST}"),
        ] {
            let c = catalog(&doc(
                "  {}\n",
                &format!("  {SENTINEL}:\n    image: {{ ref: \"{bad}\" }}\n"),
            ));
            assert!(c.entry(SENTINEL).is_none(), "{bad}");
            assert!(reason(&c, SENTINEL).contains("image.ref"), "{bad}");
        }
        let ok = format!("registry.example/x@sha256:{DIGEST}");
        let c = catalog(&doc(
            "  {}\n",
            &format!("  fine:\n    image: {{ ref: \"{ok}\" }}\n"),
        ));
        assert!(c.entry("fine").is_some());
    }

    #[test]
    fn undefined_credential_class_disables_entry() {
        let c = catalog(&doc(
            "  {}\n",
            &format!("  {SENTINEL}:\n    credential: missing-class\n"),
        ));
        assert!(c.entry(SENTINEL).is_none());
        assert!(reason(&c, SENTINEL).contains("missing-class"));
        let c = catalog(&doc("  {}\n", "  explicit-none:\n    credential: none\n"));
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
                &format!("  {SENTINEL}:\n    credential: bad-class\n"),
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
            &format!("  {SENTINEL}:\n    credential: weird\n"),
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
                &format!("  {SENTINEL}:\n    binds: {binds}\n"),
            ));
            assert!(c.entry(SENTINEL).is_none(), "{binds}");
            assert!(reason(&c, SENTINEL).contains("sentinel-674"), "{binds}");
        }
        let c = catalog(&doc(
            "  {}\n",
            "  bound:\n    binds: { git: { resolver: git } }\n",
        ));
        assert!(c.entry("bound").unwrap().binds.contains("git"));
    }

    #[test]
    fn labelled_entry_is_disabled_unclaimed() {
        let c = catalog(&doc(
            "  {}\n",
            &format!("  {SENTINEL}:\n    labels: {{ entry.tier: high }}\n"),
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
            "output_to_model: sentinel",
            "network: sentinel",
            "network: { via: elsewhere, sites: [a.example] }",
            "network: { via: maknae-proxy, sites: [] }",
            "network: { via: maknae-proxy, sites: [\"a b\"] }",
            "volumes: { v: { access: sentinel } }",
            "volumes: { v: { access: ro, scope: sentinel } }",
            "resources: { memory: lots }",
            "resources: { cpus: 0 }",
            "lifetime: { max: soon }",
            "executes_workspace: maybe",
            "commands: { echo: { subcommands: [\"* x\"] } }",
            "commands: { echo: { deny_args: [\"a*b\"] } }",
            "commands: { echo: { timeout: \"\" } }",
            "commands: { echo: { output: 16 } }",
        ] {
            let c = catalog(&doc("  {}\n", &format!("  {SENTINEL}:\n    {field}\n")));
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
                "  user:\n    credential: c\n",
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
            &format!("  {SENTINEL}:\n    nonsense: 1\n  off:\n    enabled: false\n"),
        );
        let c = catalog(&text);
        assert!(c.entry(SENTINEL).is_none());
        assert!(c.entry("off").is_none());
        assert!(c.entry("good").is_some());
    }

    #[test]
    fn homelab_baseline_loads_with_every_entry_enabled() {
        let c = catalog(HOMELAB);
        assert!(c.disabled().is_empty(), "{:?}", c.disabled());
        for name in ["github-read", "github-post", "rust-fetch", "rust-build"] {
            assert!(c.entry(name).is_some(), "{name}");
        }
        assert_eq!(
            c.entry("github-read").unwrap().credential.as_deref(),
            Some("github-read")
        );
        assert!(c.entry("github-read").unwrap().binds.contains("git"));
        assert_eq!(c.entry("rust-build").unwrap().network, Network::None);
        assert!(c.class("github-post").unwrap().kind.has_reach_check());
    }

    #[test]
    fn homelab_post_denies_approve() {
        let c = catalog(HOMELAB);
        let gh = &c.entry("github-post").unwrap().commands["gh"];
        for refused in [
            &["pr", "review", "--approve"][..],
            &["pr", "review", "-a"],
            &["pr", "review", "--comment", "--approve"],
            &["pr", "review", "--approve=true"],
        ] {
            assert!(
                first_denied(&gh.deny_args, &argv(refused)).is_some(),
                "{refused:?}"
            );
        }
        assert_eq!(
            first_denied(&gh.deny_args, &argv(&["pr", "review", "--comment"])),
            None
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

        #[test]
        fn absent_file_is_empty_catalog() {
            let d = dir("absent");
            let got = load_tools_with_requirement(&d, own());
            let _ = std::fs::remove_dir_all(&d);
            assert_eq!(got, Ok(ToolsCatalog::empty()));
        }

        #[test]
        fn a_sound_file_loads() {
            let d = dir("ok");
            write(&d, HOMELAB.as_bytes(), 0o640);
            let got = load_tools_with_requirement(&d, own());
            let _ = std::fs::remove_dir_all(&d);
            assert_eq!(got, ToolsCatalog::parse(HOMELAB));
            assert!(got.unwrap().entry("rust-build").is_some());
        }

        #[test]
        fn a_malformed_or_insecure_file_is_refused() {
            let d = dir("bad");
            write(&d, b"schema_version: 2\n", 0o640);
            assert!(matches!(
                load_tools_with_requirement(&d, own()),
                Err(ToolsError::Invalid(_))
            ));
            write(&d, &[0xff, 0xfe], 0o640);
            assert!(matches!(
                load_tools_with_requirement(&d, own()),
                Err(ToolsError::Config(ConfigError::Io(ref m))) if m.contains("UTF-8")
            ));
            write(&d, HOMELAB.as_bytes(), 0o644);
            let got = load_tools_with_requirement(&d, own());
            let _ = std::fs::remove_dir_all(&d);
            assert!(matches!(
                got,
                Err(ToolsError::Config(ConfigError::InsecurePermissions { .. }))
            ));
        }
    }
}
