use crate::value::{canonical_json, Value};
use crate::ConfigError;
use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;

pub const BINDINGS_FILE: &str = "bindings.yaml";

pub const BINDING_ROLES: [&str; 4] = ["admin", "user", "guest", "adversary"];

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum BindingEntry {
    Name(String),
    Uid(u32),
}

impl BindingEntry {
    pub fn render(&self) -> String {
        match self {
            Self::Name(n) => n.clone(),
            Self::Uid(u) => format!("uid:{u}"),
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Bindings {
    pub roles: Option<BTreeMap<String, Vec<BindingEntry>>>,
    section: Option<String>,
    missing: bool,
}

impl Bindings {
    pub fn absent() -> Self {
        Self {
            roles: None,
            section: None,
            missing: false,
        }
    }

    pub fn missing() -> Self {
        Self {
            roles: None,
            section: None,
            missing: true,
        }
    }

    pub fn from_section(s: &crate::bindings_sync::Section) -> Self {
        use crate::bindings_sync::Section;
        match s {
            Section::Missing => Self::missing(),
            Section::Absent => Self::absent(),
            Section::Present(m) => Self {
                roles: Some(m.clone()),
                section: Some(s.canonical()),
                missing: false,
            },
        }
    }

    pub fn is_missing(&self) -> bool {
        self.missing
    }

    pub fn section_canonical(&self) -> Option<&str> {
        self.section.as_deref()
    }

    /// The `bindings:` key is present and lists no entry under any role.
    pub fn lists_nobody(&self) -> bool {
        self.roles
            .as_ref()
            .is_some_and(|m| m.values().all(Vec::is_empty))
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum BindingsError {
    UnknownSchemaVersion(i64),
    Config(ConfigError),
    InsecurePermissions,
    Symlink,
    NotRootOwned,
    /// The directory holding `bindings.yaml` is not root-owned, or is group- or
    /// other-writable; carries the directory.
    InsecureDirectory(String),
    Io(String),
    Yaml(String),
}

impl std::fmt::Display for BindingsError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::UnknownSchemaVersion(v) => write!(f, "unknown bindings.yaml schema_version: {v}"),
            Self::Config(e) => write!(f, "bindings.yaml: {e}"),
            Self::InsecurePermissions => f.write_str(
                "bindings.yaml has insecure permissions: world/other-accessible or group/other-writable",
            ),
            Self::Symlink => f.write_str("bindings.yaml path is a symlink (refused)"),
            Self::NotRootOwned => f.write_str("bindings.yaml is not owned by root (uid 0)"),
            Self::InsecureDirectory(d) => {
                f.write_str(&crate::authz::insecure_directory(d, "bindings.yaml"))
            }
            Self::Io(m) => write!(f, "bindings.yaml i/o error: {m}"),
            Self::Yaml(m) => write!(f, "bindings.yaml yaml error: {m}"),
        }
    }
}

impl std::error::Error for BindingsError {}

fn yaml(m: &str) -> BindingsError {
    BindingsError::Yaml(m.into())
}

pub(crate) fn entry(v: &Value) -> Result<BindingEntry, BindingsError> {
    match v {
        Value::Str(s) if s.is_empty() => Err(yaml("an empty name binds nobody; remove it")),
        Value::Str(s) if s.contains(':') => Err(yaml(
            "a name cannot contain ':'; write `uid: 7` for a numeric uid",
        )),
        Value::Str(s) if s.contains(',') => Err(yaml("a name cannot contain ','")),
        Value::Str(s) if s.chars().any(char::is_control) => {
            Err(yaml("a name cannot contain a control character"))
        }
        Value::Str(s) => Ok(BindingEntry::Name(s.clone())),
        Value::Map(m) => match m.as_slice() {
            [(k, Value::Int(n))] if k == "uid" => u32::try_from(*n)
                .ok()
                .filter(|u| *u != u32::MAX)
                .map(BindingEntry::Uid)
                .ok_or_else(|| yaml("a `uid:` entry is a whole number from 0 to 4294967294")),
            _ => Err(yaml("a map entry is exactly `uid: <0..4294967294>`")),
        },
        Value::Int(_) => Err(yaml("quote every name; write `uid: <n>` for a numeric uid")),
        _ => Err(yaml("bindings entries are quoted names or `uid: <n>`")),
    }
}

pub(crate) fn section_roles(
    section: &Value,
) -> Result<BTreeMap<String, Vec<BindingEntry>>, BindingsError> {
    let Value::Map(by_role) = section else {
        return Err(yaml(
            "the bindings section must be a map of role to member list",
        ));
    };
    let mut roles = BTreeMap::new();
    for (role, members) in by_role {
        let Value::Seq(items) = members else {
            return Err(yaml(
                "a bindings member list must be a sequence (write `role: []` for empty)",
            ));
        };
        roles.insert(
            role.clone(),
            items.iter().map(entry).collect::<Result<_, _>>()?,
        );
    }
    Ok(roles)
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum RoleRuleError {
    UnknownRole(String),
    Duplicate(String),
    UidOutsideAdversary(String),
}

impl std::fmt::Display for RoleRuleError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::UnknownRole(k) => write!(f, "bindings names unknown role '{k}'"),
            Self::Duplicate(n) => write!(f, "identity '{n}' listed twice in one role"),
            Self::UidOutsideAdversary(k) => write!(
                f,
                "role '{k}' lists a uid entry; `uid:` entries are accepted under adversary only"
            ),
        }
    }
}

impl std::error::Error for RoleRuleError {}

pub fn checked_roles(b: &Bindings) -> Result<Vec<(usize, &[BindingEntry])>, RoleRuleError> {
    let Some(map) = &b.roles else {
        return Ok(Vec::new());
    };
    let adversary = BINDING_ROLES.len() - 1;
    let mut out = Vec::with_capacity(map.len());
    for (key, entries) in map {
        let idx = BINDING_ROLES
            .iter()
            .position(|r| r == key)
            .ok_or_else(|| RoleRuleError::UnknownRole(key.clone()))?;
        let mut seen = BTreeSet::new();
        for e in entries {
            if !seen.insert(e.render()) {
                return Err(RoleRuleError::Duplicate(e.render()));
            }
            if matches!(e, BindingEntry::Uid(_)) && idx != adversary {
                return Err(RoleRuleError::UidOutsideAdversary(key.clone()));
            }
        }
        out.push((idx, entries.as_slice()));
    }
    Ok(out)
}

pub fn check_roles(b: &Bindings) -> Result<(), RoleRuleError> {
    checked_roles(b).map(|_| ())
}

pub fn parse_bindings(body: &str) -> Result<Bindings, BindingsError> {
    let root = crate::load_str(body).map_err(|e| BindingsError::Yaml(e.to_string()))?;
    let Value::Map(map) = root else {
        return Err(yaml("the bindings.yaml root must be a mapping"));
    };
    crate::reject_unknown_keys("bindings.yaml", &map, &["schema_version", "bindings"])
        .map_err(BindingsError::Config)?;
    let get = |k: &str| map.iter().find(|(key, _)| key == k).map(|(_, v)| v);
    match get("schema_version") {
        Some(Value::Int(1)) => {}
        Some(Value::Int(n)) => return Err(BindingsError::UnknownSchemaVersion(*n)),
        _ => return Err(BindingsError::UnknownSchemaVersion(0)),
    }
    let Some(section) = get("bindings") else {
        return Ok(Bindings::absent());
    };
    let roles = section_roles(section)?;
    Ok(Bindings {
        roles: Some(roles),
        section: Some(canonical_json(section)),
        missing: false,
    })
}

pub fn load_bindings(path: &Path) -> Result<Bindings, BindingsError> {
    #[cfg(not(unix))]
    {
        let _ = path;
        return Err(BindingsError::Io(
            "bindings permission enforcement is unavailable on this platform; refusing to load"
                .into(),
        ));
    }
    #[cfg(unix)]
    {
        load_required(path, crate::authz::root_policy_file_required())
    }
}

#[cfg(all(unix, feature = "hermetic-test-seam"))]
pub fn load_bindings_with_requirement(
    path: &Path,
    target: maknae_io::TargetRequired,
) -> Result<Bindings, BindingsError> {
    load_required(path, target)
}

#[cfg(unix)]
fn load_required(
    path: &Path,
    target: maknae_io::TargetRequired,
) -> Result<Bindings, BindingsError> {
    let absolute = std::path::absolute(path).map_err(|e| BindingsError::Io(e.to_string()))?;
    use crate::authz::RootReadError;
    match crate::authz::read_in_root_dir(&absolute, target) {
        Ok(bytes) => {
            let body = std::str::from_utf8(&bytes)
                .map_err(|e| BindingsError::Io(format!("invalid UTF-8: {e}")))?;
            parse_bindings(body)
        }
        Err(RootReadError::Directory(d)) => {
            Err(BindingsError::InsecureDirectory(d.display().to_string()))
        }
        Err(RootReadError::Io(maknae_io::IoError::Io {
            kind: maknae_io::IoKind::NotFound,
            path: missing,
        })) if missing == absolute => Ok(Bindings::missing()),
        Err(RootReadError::Io(maknae_io::IoError::Symlink { .. })) => Err(BindingsError::Symlink),
        Err(RootReadError::Io(maknae_io::IoError::InsecurePermissions { .. })) => {
            Err(BindingsError::InsecurePermissions)
        }
        Err(RootReadError::Io(maknae_io::IoError::NotOwned { .. })) => {
            Err(BindingsError::NotRootOwned)
        }
        Err(RootReadError::Io(other)) => Err(BindingsError::Io(other.to_string())),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;

    fn names(v: &[&str]) -> Vec<BindingEntry> {
        v.iter().map(|n| BindingEntry::Name((*n).into())).collect()
    }

    #[test]
    fn no_bindings_key_is_absent_and_an_empty_map_is_present() {
        let absent = parse_bindings("schema_version: 1\n").unwrap();
        assert_eq!(absent, Bindings::absent());
        assert_eq!(absent.roles, None);
        assert_eq!(absent.section_canonical(), None);
        assert!(!absent.is_missing());
        let missing = Bindings::missing();
        assert!(missing.is_missing());
        assert_eq!(
            (missing.roles.clone(), missing.section_canonical()),
            (None, None)
        );
        assert_ne!(
            missing, absent,
            "the reader keeps which spelling of absent it saw"
        );
        let empty = parse_bindings("schema_version: 1\nbindings: {}\n").unwrap();
        assert_eq!(empty.roles, Some(std::collections::BTreeMap::new()));
        assert!(!empty.is_missing());
        assert_eq!(empty.section_canonical(), Some("{}"));
    }

    #[test]
    fn names_and_uid_entries_parse_in_file_order() {
        let b = parse_bindings(
            "schema_version: 1\nbindings:\n  admin: [\"alice\"]\n  user: [\"bob\", \"carol\"]\n  guest: []\n  adversary:\n    - \"mallory\"\n    - uid: 4242\n    - uid: 0\n",
        )
        .unwrap();
        let roles = b.roles.as_ref().unwrap();
        assert_eq!(roles["admin"], names(&["alice"]));
        assert_eq!(roles["user"], names(&["bob", "carol"]));
        assert_eq!(roles["guest"], vec![]);
        assert_eq!(
            roles["adversary"],
            vec![
                BindingEntry::Name("mallory".into()),
                BindingEntry::Uid(4242),
                BindingEntry::Uid(0)
            ]
        );
        assert_eq!(
            b.section_canonical(),
            Some(
                r#"{"admin":["alice"],"adversary":["mallory",{"uid":4242},{"uid":0}],"guest":[],"user":["bob","carol"]}"#
            )
        );
    }

    #[test]
    fn the_canonical_section_ignores_comments_order_and_whitespace_but_not_content() {
        let a = parse_bindings(
            "schema_version: 1\nbindings:\n  user: [\"bob\"]\n  admin: [\"alice\"]\n",
        )
        .unwrap();
        let b = parse_bindings("# c\nbindings:\n  admin:\n    - \"alice\"   # t\n  user: [ \"bob\" ]\nschema_version: 1\n").unwrap();
        assert_eq!(a.section_canonical(), b.section_canonical());
        let c = parse_bindings(
            "schema_version: 1\nbindings:\n  user: [\"bob\"]\n  admin: [\"alicia\"]\n",
        )
        .unwrap();
        assert_ne!(a.section_canonical(), c.section_canonical());
    }

    #[test]
    fn the_role_rules_refuse_the_whole_file_naming_the_token() {
        let rules = |body: &str| check_roles(&parse_bindings(body).unwrap());
        assert_eq!(
            rules("schema_version: 1\nbindings:\n  root: [\"a\"]\n"),
            Err(RoleRuleError::UnknownRole("root".into()))
        );
        assert_eq!(
            rules("schema_version: 1\nbindings:\n  user: [\"a\", \"a\"]\n"),
            Err(RoleRuleError::Duplicate("a".into()))
        );
        assert_eq!(
            rules("schema_version: 1\nbindings:\n  user:\n    - uid: 7\n"),
            Err(RoleRuleError::UidOutsideAdversary("user".into()))
        );
        assert_eq!(
            rules("schema_version: 1\nbindings:\n  user: [\"a\"]\n  adversary: [\"a\"]\n"),
            Ok(())
        );
        assert_eq!(rules("schema_version: 1\n"), Ok(()));
        assert_eq!(
            RoleRuleError::Duplicate("a".into()).to_string(),
            "identity 'a' listed twice in one role"
        );
    }

    #[test]
    fn render_is_the_name_or_uid_colon_n() {
        assert_eq!(BindingEntry::Name("bob".into()).render(), "bob");
        assert_eq!(BindingEntry::Uid(4242).render(), "uid:4242");
    }

    #[test]
    fn every_shape_defect_refuses_naming_bindings() {
        let yaml = |body: &str| match parse_bindings(body) {
            Err(BindingsError::Yaml(m)) => m,
            other => panic!("{body:?}: expected Yaml, got {other:?}"),
        };
        let pre = "schema_version: 1\nbindings:\n";
        assert!(yaml(&format!("{pre}  admin: [1001]\n")).contains("quote every name"));
        assert!(yaml(&format!("{pre}  admin: \"alice\"\n")).contains("sequence"));
        assert!(yaml(&format!("{pre}  admin:\n")).contains("sequence"));
        assert!(yaml("schema_version: 1\nbindings: [admin]\n").contains("map of role"));
        assert!(
            yaml(&format!("{pre}  adversary:\n    - uid: 1\n      name: x\n")).contains("uid:")
        );
        assert!(yaml(&format!("{pre}  adversary:\n    - uid: -1\n")).contains("uid:"));
        assert!(yaml(&format!("{pre}  adversary:\n    - uid: 4294967295\n")).contains("uid:"));
        assert!(yaml(&format!("{pre}  adversary:\n    - uid: \"7\"\n")).contains("uid:"));
        assert!(yaml(&format!("{pre}  adversary:\n    - gid: 7\n")).contains("uid:"));
        assert!(yaml(&format!("{pre}  admin: [\"\"]\n")).contains("empty"));
        assert!(yaml(&format!("{pre}  admin: [\"uid:7\"]\n")).contains("uid: 7"));
        assert!(yaml(&format!("{pre}  admin: [\"a,b\"]\n")).contains("','"));
        assert!(yaml(&format!("{pre}  admin: [\"a\\tb\"]\n")).contains("control"));
        assert!(yaml(&format!("{pre}  admin: [\"a\\u001b[0m\"]\n")).contains("control"));
        assert!(yaml(&format!("{pre}  admin: [[\"x\"]]\n")).contains("names"));
        assert!(yaml("- 1\n").contains("mapping"));
        assert_eq!(
            parse_bindings(&format!("{pre}  adversary:\n    - uid: 4294967294\n"))
                .unwrap()
                .roles
                .unwrap()["adversary"],
            vec![BindingEntry::Uid(4_294_967_294)]
        );
    }

    #[test]
    fn schema_version_and_unknown_keys_refuse() {
        assert_eq!(
            parse_bindings("bindings: {}\n"),
            Err(BindingsError::UnknownSchemaVersion(0))
        );
        assert_eq!(
            parse_bindings("schema_version: 2\n"),
            Err(BindingsError::UnknownSchemaVersion(2))
        );
        assert_eq!(
            parse_bindings("schema_version: \"1\"\n"),
            Err(BindingsError::UnknownSchemaVersion(0))
        );
        assert!(matches!(
            parse_bindings("schema_version: 1\npermissions: {}\n"),
            Err(BindingsError::Config(_))
        ));
        assert!(matches!(
            parse_bindings("schema_version: 1\nbindings:\n  admin: []\n  admin: []\n"),
            Err(BindingsError::Yaml(_))
        ));
    }

    #[test]
    fn a_block_moved_unchanged_keeps_every_section_digest_input() {
        let authz = "schema_version: 1\nroles:\n  admin:\n    allow: [\"admin.status\"]\n";
        let block = "bindings:\n  user: [ \"bob\" ]   # c\n  admin: [\"alice\"]\n  adversary:\n    - \"mallory\"\n";
        let Value::Map(combined) = crate::load_str(&format!("{authz}{block}")).unwrap() else {
            unreachable!()
        };
        let before: BTreeMap<String, String> = combined
            .iter()
            .map(|(k, v)| (k.clone(), canonical_json(v)))
            .collect();
        let mut after: BTreeMap<String, String> = crate::parse_authz(authz)
            .unwrap()
            .sections()
            .map(|(k, v)| (k.to_string(), v.to_string()))
            .collect();
        let moved = parse_bindings(&format!("schema_version: 1\n{block}")).unwrap();
        after.insert(
            "bindings".into(),
            moved.section_canonical().unwrap().to_string(),
        );
        assert_eq!(after, before);
    }

    #[test]
    fn only_a_present_key_with_no_entry_lists_nobody() {
        for (body, nobody) in [
            ("schema_version: 1\nbindings: {}\n", true),
            (
                "schema_version: 1\nbindings:\n  admin: []\n  user: []\n",
                true,
            ),
            (
                "schema_version: 1\nbindings:\n  admin: []\n  user: [\"bob\"]\n",
                false,
            ),
            ("schema_version: 1\n", false),
        ] {
            assert_eq!(
                parse_bindings(body).unwrap().lists_nobody(),
                nobody,
                "{body}"
            );
        }
        assert!(!Bindings::missing().lists_nobody());
    }

    #[test]
    fn every_error_renders_naming_bindings_yaml() {
        for e in [
            BindingsError::UnknownSchemaVersion(3),
            BindingsError::InsecurePermissions,
            BindingsError::Symlink,
            BindingsError::NotRootOwned,
            BindingsError::InsecureDirectory("/etc/maknae".into()),
            BindingsError::Io("x".into()),
            BindingsError::Yaml("y".into()),
        ] {
            assert!(e.to_string().contains("bindings.yaml"), "{e}");
        }
    }

    fn dir(tag: &str) -> std::path::PathBuf {
        let d = std::env::temp_dir().join(format!("bindings_{tag}_{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(&d).unwrap();
        std::fs::set_permissions(&d, std::fs::Permissions::from_mode(0o700)).unwrap();
        d.canonicalize().unwrap()
    }

    fn runs_as_root(d: &std::path::Path) -> bool {
        use std::os::unix::fs::MetadataExt;
        std::fs::metadata(d).map(|m| m.uid() == 0).unwrap_or(false)
    }

    fn own() -> maknae_io::TargetRequired {
        maknae_io::TargetRequired {
            owner: None,
            ..crate::authz::root_policy_file_required()
        }
    }

    #[test]
    fn a_missing_file_is_missing_through_the_requirement_seam() {
        let d = dir("missing");
        assert_eq!(
            load_required(&d.join(BINDINGS_FILE), own()),
            Ok(Bindings::missing())
        );
        let _ = std::fs::remove_dir_all(&d);
    }

    #[test]
    fn a_missing_file_through_the_production_reader_needs_a_root_owned_directory() {
        let d = dir("missing_prod");
        let root = runs_as_root(&d);
        let got = load_bindings(&d.join(BINDINGS_FILE));
        let _ = std::fs::remove_dir_all(&d);
        if root {
            assert_eq!(
                got,
                Ok(Bindings::missing()),
                "as root the temp directory IS root-owned"
            );
        } else {
            assert_eq!(
                got,
                Err(BindingsError::InsecureDirectory(d.display().to_string())),
                "the directory anchor requires owner 0"
            );
        }
    }

    #[test]
    fn a_missing_directory_is_a_refusal_not_absent() {
        let d = dir("nodir");
        let gone = d.join("gone").join(BINDINGS_FILE);
        assert!(matches!(
            load_required(&gone, own()),
            Err(BindingsError::Io(_))
        ));
        let _ = std::fs::remove_dir_all(&d);
    }

    #[test]
    fn a_group_writable_directory_refuses_both_files() {
        let d = dir("gw");
        std::fs::write(d.join(BINDINGS_FILE), "schema_version: 1\n").unwrap();
        std::fs::write(d.join("authz.yaml"), "schema_version: 1\n").unwrap();
        for f in [BINDINGS_FILE, "authz.yaml"] {
            std::fs::set_permissions(d.join(f), std::fs::Permissions::from_mode(0o640)).unwrap();
        }
        std::fs::set_permissions(&d, std::fs::Permissions::from_mode(0o770)).unwrap();
        let named = d.display().to_string();
        assert_eq!(
            load_required(&d.join(BINDINGS_FILE), own()),
            Err(BindingsError::InsecureDirectory(named.clone()))
        );
        assert!(
            matches!(
                load_required(&d.join("missing.yaml"), own()),
                Err(BindingsError::InsecureDirectory(_))
            ),
            "a missing file in a writable dir is not absent"
        );
        assert!(matches!(
            crate::authz::security_load_required(&d.join("authz.yaml"), own()),
            Err(crate::AuthzError::InsecureDirectory(n)) if n == named
        ));
        std::fs::set_permissions(&d, std::fs::Permissions::from_mode(0o750)).unwrap();
        assert_eq!(
            load_required(&d.join(BINDINGS_FILE), own()),
            Ok(Bindings::absent()),
            "root:_maknae 0750 is the shipped mode and passes"
        );
        let _ = std::fs::remove_dir_all(&d);
    }

    #[test]
    fn the_production_reader_requires_root_ownership() {
        let d = dir("owner");
        let p = d.join(BINDINGS_FILE);
        std::fs::write(&p, "schema_version: 1\n").unwrap();
        std::fs::set_permissions(&p, std::fs::Permissions::from_mode(0o640)).unwrap();
        let got = load_bindings(&p);
        if runs_as_root(&d) {
            assert_eq!(got, Ok(Bindings::absent()));
        } else {
            assert_eq!(
                got,
                Err(BindingsError::InsecureDirectory(d.display().to_string()))
            );
        }
        let _ = std::fs::remove_dir_all(&d);
    }

    #[test]
    fn a_directory_that_fails_its_check_is_refused_naming_the_directory() {
        use std::os::unix::fs::MetadataExt;
        let probe = dir("whoami");
        let me = std::fs::metadata(&probe).unwrap().uid();
        let _ = std::fs::remove_dir_all(&probe);
        for (tag, mode, owner) in [
            ("dir_g", 0o770, None),
            ("dir_o", 0o757, None),
            ("dir_u", 0o750, Some(me.wrapping_add(1))),
        ] {
            let d = dir(tag);
            let p = d.join(BINDINGS_FILE);
            std::fs::write(&p, "schema_version: 1\n").unwrap();
            std::fs::set_permissions(&p, std::fs::Permissions::from_mode(0o640)).unwrap();
            std::fs::set_permissions(&d, std::fs::Permissions::from_mode(mode)).unwrap();
            let got = load_required(&p, maknae_io::TargetRequired { owner, ..own() });
            let missing = load_required(
                &d.join("gone.yaml"),
                maknae_io::TargetRequired { owner, ..own() },
            );
            let _ = std::fs::remove_dir_all(&d);
            let want = d.display().to_string();
            assert_eq!(
                got,
                Err(BindingsError::InsecureDirectory(want.clone())),
                "{tag}"
            );
            assert_eq!(missing, got, "{tag}: not missing");
            assert_eq!(
                got.unwrap_err().to_string(),
                format!("the directory {want} holding bindings.yaml must be owned by root (uid 0) and not group- or other-writable")
            );
        }
    }

    #[test]
    fn mode_symlink_utf8_and_empty_file_refuse() {
        let d = dir("mode");
        let p = d.join(BINDINGS_FILE);
        std::fs::write(&p, "schema_version: 1\nbindings:\n  admin: [\"a\"]\n").unwrap();
        for (mode, ok) in [
            (0o640, true),
            (0o600, true),
            (0o644, false),
            (0o660, false),
            (0o641, false),
        ] {
            std::fs::set_permissions(&p, std::fs::Permissions::from_mode(mode)).unwrap();
            let got = load_required(&p, own());
            assert_eq!(got.is_ok(), ok, "mode {mode:o}: {got:?}");
            if !ok {
                assert_eq!(got, Err(BindingsError::InsecurePermissions));
            }
        }
        let link = d.join("link.yaml");
        std::os::unix::fs::symlink(&p, &link).unwrap();
        assert_eq!(load_required(&link, own()), Err(BindingsError::Symlink));
        std::fs::write(&p, [0xff, 0xfe]).unwrap();
        std::fs::set_permissions(&p, std::fs::Permissions::from_mode(0o640)).unwrap();
        assert!(
            matches!(load_required(&p, own()), Err(BindingsError::Io(m)) if m.contains("UTF-8"))
        );
        std::fs::write(&p, "").unwrap();
        assert!(matches!(
            load_required(&p, own()),
            Err(BindingsError::Yaml(_))
        ));
        let _ = std::fs::remove_dir_all(&d);
    }

    #[test]
    fn the_shipped_file_is_bindings_absent() {
        let shipped = include_str!("../../../packaging/common/bindings.yaml");
        assert_eq!(parse_bindings(shipped), Ok(Bindings::absent()));
        let d = dir("shipped");
        std::fs::set_permissions(&d, std::fs::Permissions::from_mode(0o750)).unwrap();
        let p = d.join(BINDINGS_FILE);
        std::fs::write(&p, shipped).unwrap();
        std::fs::set_permissions(&p, std::fs::Permissions::from_mode(0o640)).unwrap();
        let through_reader = load_required(&p, own());
        let production = load_bindings(&p);
        let root = runs_as_root(&d);
        let _ = std::fs::remove_dir_all(&d);
        assert_eq!(through_reader, Ok(Bindings::absent()));
        if root {
            assert_eq!(production, Ok(Bindings::absent()));
        } else {
            assert_eq!(
                production,
                Err(BindingsError::InsecureDirectory(d.display().to_string()))
            );
        }
    }

    #[cfg(feature = "hermetic-test-seam")]
    #[test]
    fn the_seam_reads_under_the_requirement_it_is_given() {
        let d = dir("seam");
        let p = d.join(BINDINGS_FILE);
        std::fs::write(&p, "schema_version: 1\nbindings: {}\n").unwrap();
        std::fs::set_permissions(&p, std::fs::Permissions::from_mode(0o640)).unwrap();
        let got = load_bindings_with_requirement(&p, own());
        let _ = std::fs::remove_dir_all(&d);
        assert_eq!(got.unwrap().section_canonical(), Some("{}"));
    }
}
