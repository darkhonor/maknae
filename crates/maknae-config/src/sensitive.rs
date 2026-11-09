//! `sensitive.yaml` (#617): paths no file verb may reach, whatever a role grants.

use crate::authz::{HomeUnbound, PathGlob};
use crate::{ConfigError, Value};
use std::path::Path;

pub const SENSITIVE_FILE: &str = "sensitive.yaml";

/// How a path is compared with the entries: `Case` is the macOS form, where
/// the default volume is case-insensitive and one file has several spellings.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Fold {
    None,
    Case,
}

pub fn native_fold() -> Fold {
    if cfg!(target_os = "macos") {
        Fold::Case
    } else {
        Fold::None
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct Entry {
    glob: PathGlob,
    lowered: PathGlob,
    mapped: PathGlob,
    text: String,
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct SensitiveList {
    entries: Vec<Entry>,
}

fn invalid(reason: impl Into<String>) -> ConfigError {
    ConfigError::InvalidSensitive(reason.into())
}

impl SensitiveList {
    pub fn parse(yaml: &str) -> Result<Self, ConfigError> {
        let Value::Map(map) = crate::load_str(yaml)? else {
            return Err(invalid("the document must be a mapping"));
        };
        crate::reject_unknown_keys(SENSITIVE_FILE, &map, &["schema_version", "sensitive"])?;
        let get = |key: &str| map.iter().find(|(k, _)| k == key).map(|(_, v)| v);
        if !matches!(get("schema_version"), Some(Value::Int(1))) {
            return Err(invalid("schema_version must be 1"));
        }
        let entries = match get("sensitive") {
            Some(Value::Seq(items)) => items
                .iter()
                .map(|item| match item {
                    Value::Str(s) => Ok(s.clone()),
                    _ => Err(invalid("every `sensitive` entry must be a quoted string")),
                })
                .collect::<Result<Vec<_>, _>>()?,
            Some(_) => return Err(invalid("`sensitive` must be a list")),
            None => {
                return Err(invalid(
                    "`sensitive` is required (write `sensitive: []` for none)",
                ))
            }
        };
        Self::from_entries(&entries)
    }

    pub fn from_entries(entries: &[String]) -> Result<Self, ConfigError> {
        entries
            .iter()
            .map(|text| entry(text))
            .collect::<Result<Vec<_>, _>>()
            .map(|entries| SensitiveList { entries })
    }

    pub fn empty() -> Self {
        Self::default()
    }

    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    pub fn entries(&self) -> impl Iterator<Item = &str> {
        self.entries.iter().map(|e| e.text.as_str())
    }

    pub fn canonical(&self) -> String {
        crate::canonical_json(&Value::Seq(
            self.entries
                .iter()
                .map(|e| Value::Str(e.text.clone()))
                .collect(),
        ))
    }

    /// The first entry that matches `path`. `HomeUnbound` only when no entry
    /// matches and a `~` entry could not be evaluated.
    pub fn matching(
        &self,
        path: &Path,
        home: Option<&Path>,
        fold: Fold,
    ) -> Result<Option<&str>, HomeUnbound> {
        self.first(path, home, fold, false, |glob, p, h| {
            glob.matches(Path::new(p), h)
        })
    }

    /// The first entry that could match `dir` or a path beneath it.
    pub fn subtree_matching(
        &self,
        dir: &Path,
        home: Option<&Path>,
        fold: Fold,
    ) -> Result<Option<&str>, HomeUnbound> {
        self.first(dir, home, fold, true, |glob, p, h| {
            glob.may_intersect_subtree(p, h)
        })
    }

    fn first(
        &self,
        path: &Path,
        home: Option<&Path>,
        fold: Fold,
        subtree: bool,
        test: impl Fn(&PathGlob, &str, Option<&Path>) -> Result<bool, HomeUnbound>,
    ) -> Result<Option<&str>, HomeUnbound> {
        let path = path.to_string_lossy();
        let folded = (fold == Fold::Case).then(|| Folded::new(&path, home, subtree));
        let mut unbound = false;
        for e in &self.entries {
            let hit = match &folded {
                None => test(&e.glob, &path, home),
                Some(f) => test(
                    &e.lowered,
                    &f.lowered,
                    f.home_lowered.as_deref().map(Path::new),
                )
                .and_then(|hit| {
                    let home = f.home_mapped.as_deref().map(Path::new);
                    if hit {
                        return Ok(true);
                    }
                    for root in &f.mapped {
                        if test(&e.mapped, root, home)? {
                            return Ok(true);
                        }
                    }
                    Ok(false)
                }),
            };
            match hit {
                Ok(true) => return Ok(Some(&e.text)),
                Ok(false) => {}
                Err(HomeUnbound) => unbound = true,
            }
        }
        if unbound {
            Err(HomeUnbound)
        } else {
            Ok(None)
        }
    }
}

/// Read the host list through the `authz.yaml` door: root-owned, `mode & 0o027 == 0`,
/// in a root-owned directory no group or other can write. Absent is an error.
pub fn load_host_sensitive(path: &Path) -> Result<SensitiveList, ConfigError> {
    #[cfg(not(unix))]
    {
        let _ = path;
        return Err(ConfigError::PermissionsUnsupported);
    }
    #[cfg(unix)]
    {
        load_host_required(path, crate::authz::root_policy_file_required())
    }
}

#[cfg(all(unix, feature = "hermetic-test-seam"))]
pub fn load_host_sensitive_with_requirement(
    path: &Path,
    target: maknae_io::TargetRequired,
) -> Result<SensitiveList, ConfigError> {
    load_host_required(path, target)
}

#[cfg(unix)]
fn load_host_required(
    path: &Path,
    target: maknae_io::TargetRequired,
) -> Result<SensitiveList, ConfigError> {
    use crate::authz::RootReadError;
    let absolute = std::path::absolute(path).map_err(|e| ConfigError::Io(e.to_string()))?;
    let bytes = crate::authz::read_in_root_dir(&absolute, target).map_err(|e| match e {
        RootReadError::Directory(d) => ConfigError::Io(crate::authz::insecure_directory(
            &d.display().to_string(),
            SENSITIVE_FILE,
        )),
        RootReadError::Io(e) => crate::loader::map_io(e),
    })?;
    let body = std::str::from_utf8(&bytes)
        .map_err(|e| ConfigError::Io(format!("{}: invalid UTF-8: {e}", absolute.display())))?;
    SensitiveList::parse(body).map_err(|e| match e {
        ConfigError::InvalidSensitive(_) => e,
        other => invalid(other.to_string()),
    })
}

fn entry(text: &str) -> Result<Entry, ConfigError> {
    let bad = || {
        invalid(format!(
            "entry '{text}' must be an absolute path or start with `~/`, without `.` or `..` components (`~name` is refused)"
        ))
    };
    if text.split('/').any(|c| matches!(c, "." | "..")) {
        return Err(bad());
    }
    let glob = |spec: &str| PathGlob::parse(spec).map_err(|_| bad());
    let lowered = case_folded(text);
    Ok(Entry {
        glob: glob(text)?,
        mapped: glob(&mapped(&lowered))?,
        lowered: glob(&lowered)?,
        text: text.to_string(),
    })
}

/// One spelling for names APFS treats as the same: NFC, lowercase, NFC again,
/// so neither the input's form nor a lowercase mapping leaves a decomposed form.
fn case_folded(text: &str) -> String {
    let nfc = icu_normalizer::ComposingNormalizerBorrowed::new_nfc();
    nfc.normalize(&nfc.normalize(text).to_lowercase())
        .into_owned()
}

/// The one spelling macOS gives a path the kernel may report under another:
/// the Data volume's firmlink prefix removed, then `/private/{etc,tmp,var}`
/// as `/{etc,tmp,var}`. Expects lowercase; a relative text is returned as is.
fn mapped(text: &str) -> String {
    if !text.starts_with('/') {
        return text.to_string();
    }
    let mut comps: Vec<&str> = text.split('/').filter(|c| !c.is_empty()).collect();
    if comps.starts_with(&["system", "volumes", "data"]) {
        comps.drain(..3);
    }
    if comps.len() >= 2 && comps[0] == "private" && matches!(comps[1], "etc" | "tmp" | "var") {
        comps.remove(0);
    }
    format!("/{}", comps.join("/"))
}

/// The mapped roots a subtree at `lowered` spans: an ancestor of the Data
/// volume prefix holds the whole mapped namespace, and `/private` holds
/// `/etc`, `/tmp` and `/var`.
fn mapped_roots(lowered: &str) -> Vec<String> {
    let comps: Vec<&str> = lowered.split('/').filter(|c| !c.is_empty()).collect();
    if lowered.starts_with('/') && ["system", "volumes", "data"].starts_with(&comps) {
        return vec!["/".to_string()];
    }
    let root = mapped(lowered);
    if root == "/private" {
        return ["/private", "/etc", "/tmp", "/var"]
            .map(String::from)
            .to_vec();
    }
    vec![root]
}

struct Folded {
    lowered: String,
    mapped: Vec<String>,
    home_lowered: Option<String>,
    home_mapped: Option<String>,
}

impl Folded {
    fn new(path: &str, home: Option<&Path>, subtree: bool) -> Self {
        let lowered = case_folded(path);
        let home_lowered = home.and_then(Path::to_str).map(case_folded);
        Folded {
            mapped: if subtree {
                mapped_roots(&lowered)
            } else {
                vec![mapped(&lowered)]
            },
            lowered,
            home_mapped: home_lowered.as_deref().map(mapped),
            home_lowered,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::Path;

    const LIST: &str = "schema_version: 1\nsensitive:\n  - \"/etc/shadow\"\n  - \"~/.ssh/**\"\n";

    fn list(entries: &[&str]) -> SensitiveList {
        let owned: Vec<String> = entries.iter().map(|e| (*e).to_string()).collect();
        SensitiveList::from_entries(&owned).unwrap()
    }

    fn at<'a>(
        l: &'a SensitiveList,
        path: &str,
        home: Option<&str>,
        fold: Fold,
    ) -> Result<Option<&'a str>, HomeUnbound> {
        l.matching(Path::new(path), home.map(Path::new), fold)
    }

    fn below<'a>(
        l: &'a SensitiveList,
        dir: &str,
        home: Option<&str>,
        fold: Fold,
    ) -> Result<Option<&'a str>, HomeUnbound> {
        l.subtree_matching(Path::new(dir), home.map(Path::new), fold)
    }

    #[test]
    fn a_list_parses_and_matches_absolute_and_home_entries() {
        let l = SensitiveList::parse(LIST).unwrap();
        let h = Some("/home/u");
        assert_eq!(
            l.entries().collect::<Vec<_>>(),
            ["/etc/shadow", "~/.ssh/**"]
        );
        assert!(!l.is_empty());
        assert_eq!(
            at(&l, "/etc/shadow", h, Fold::None),
            Ok(Some("/etc/shadow"))
        );
        assert_eq!(at(&l, "/home/u/.ssh", h, Fold::None), Ok(Some("~/.ssh/**")));
        assert_eq!(
            at(&l, "/home/u/.ssh/id_rsa", h, Fold::None),
            Ok(Some("~/.ssh/**"))
        );
        assert_eq!(at(&l, "/home/u/.sshx", h, Fold::None), Ok(None));
        assert_eq!(at(&l, "/etc/shadow-", h, Fold::None), Ok(None));
    }

    #[test]
    fn an_empty_list_matches_nothing() {
        for l in [
            SensitiveList::empty(),
            SensitiveList::parse("schema_version: 1\nsensitive: []\n").unwrap(),
            SensitiveList::from_entries(&[]).unwrap(),
        ] {
            assert!(l.is_empty());
            assert_eq!(l.entries().count(), 0);
            assert_eq!(at(&l, "/etc/shadow", None, Fold::Case), Ok(None));
            assert_eq!(below(&l, "/", None, Fold::Case), Ok(None));
        }
    }

    #[test]
    fn unknown_keys_tilde_name_and_bad_patterns_refuse() {
        for body in [
            "schema_version: 1\nsensitive: []\nsensitive_extra: []\n",
            "schema_version: 1\nsensitive:\n  - \"~bob/x\"\n",
            "schema_version: 1\nsensitive:\n  - \"relative/x\"\n",
            "schema_version: 1\nsensitive:\n  - \"Read(/x)\"\n",
            "schema_version: 1\nsensitive:\n  - \"\"\n",
            "schema_version: 1\nsensitive:\n  - \"/etc/../shadow\"\n",
            "schema_version: 1\nsensitive:\n  - \"~/./x\"\n",
            "schema_version: 1\nsensitive:\n  - 7\n",
            "schema_version: 1\nsensitive: \"/etc/shadow\"\n",
            "schema_version: 2\nsensitive: []\n",
            "schema_version: \"1\"\nsensitive: []\n",
            "sensitive: []\n",
            "schema_version: 1\n",
            "- \"/etc/shadow\"\n",
            "schema_version: 1\nsensitive: [\n",
        ] {
            assert!(SensitiveList::parse(body).is_err(), "{body:?}");
        }
        assert!(matches!(
            SensitiveList::parse("schema_version: 1\nsensitive: []\nsensitive_extra: []\n"),
            Err(ConfigError::UnknownKey { ref key, .. }) if key == "sensitive_extra"
        ));
        let bad = SensitiveList::parse("schema_version: 1\nsensitive:\n  - \"~bob/x\"\n")
            .unwrap_err()
            .to_string();
        assert!(
            bad.starts_with("sensitive.yaml: ") && bad.contains("'~bob/x'"),
            "{bad}"
        );
        for entry in ["~bob/x", "relative/x", "Read(/x)", "", "/a/../b"] {
            assert!(
                SensitiveList::from_entries(&[entry.to_string()]).is_err(),
                "{entry:?}"
            );
        }
    }

    #[test]
    fn a_home_entry_with_no_home_is_unbound() {
        let l = list(&["~/.ssh/**", "/etc/shadow"]);
        assert_eq!(at(&l, "/home/u/.ssh/k", None, Fold::None), Err(HomeUnbound));
        assert_eq!(
            at(&l, "/etc/shadow", None, Fold::None),
            Ok(Some("/etc/shadow"))
        );
        assert_eq!(
            at(&l, "/home/u/.ssh/k", Some("relative"), Fold::None),
            Err(HomeUnbound)
        );
        assert_eq!(
            at(&l, "/home/u/.ssh/k", Some("/"), Fold::Case),
            Err(HomeUnbound)
        );
        assert_eq!(
            at(&l, "/home/u/.ssh/k", Some("home/u"), Fold::Case),
            Err(HomeUnbound)
        );
        assert_eq!(
            at(&l, "/x", Some("/System/Volumes/Data"), Fold::Case),
            Err(HomeUnbound)
        );
        let absolute = list(&["/etc/shadow"]);
        assert_eq!(
            at(&absolute, "private/etc/shadow", None, Fold::Case),
            Ok(None)
        );
        assert_eq!(below(&l, "/home/u", None, Fold::None), Err(HomeUnbound));
        assert_eq!(below(&l, "/etc", None, Fold::None), Ok(Some("/etc/shadow")));
        assert_eq!(at(&absolute, "/home/u/x", None, Fold::None), Ok(None));
    }

    #[test]
    fn case_fold_matches_case_variants_and_strips_the_data_volume() {
        let l = list(&["~/.ssh/**"]);
        let h = Some("/Users/u");
        for path in [
            "/Users/u/.SSH/id",
            "/Users/U/.ssh/id",
            "/System/Volumes/Data/Users/u/.ssh/id",
            "/system/volumes/data/USERS/u/.Ssh/id",
        ] {
            assert_eq!(at(&l, path, h, Fold::Case), Ok(Some("~/.ssh/**")), "{path}");
            assert_eq!(at(&l, path, h, Fold::None), Ok(None), "{path}");
        }
        assert_eq!(
            at(&l, "/Users/u/.ssh/id", Some("/USERS/U"), Fold::Case),
            Ok(Some("~/.ssh/**"))
        );
        let upper = list(&["/Library/Keychains/**", "~/Library/Mail/**"]);
        assert_eq!(
            at(&upper, "/library/keychains/x", h, Fold::Case),
            Ok(Some("/Library/Keychains/**"))
        );
        assert_eq!(
            at(&upper, "/Users/u/library/MAIL/inbox", h, Fold::Case),
            Ok(Some("~/Library/Mail/**"))
        );
        let unicode = list(&["~/Ünïcode/**"]);
        assert_eq!(
            at(&unicode, "/Users/u/üNÏCODE/f", h, Fold::Case),
            Ok(Some("~/Ünïcode/**"))
        );
        assert_eq!(
            at(&l, "/System/Volumes/Datax/Users/u/.ssh/id", h, Fold::Case),
            Ok(None)
        );
    }

    #[test]
    fn case_fold_matches_either_normalization_form() {
        let nfc = "Caf\u{e9}";
        let nfd = "Cafe\u{301}";
        for (entry, path, home) in [
            (nfc, nfd, "/Users/u"),
            (nfd, nfc, "/Users/u"),
            (nfc, nfc, "/Users/J\u{f6}"),
            (nfd, nfd, "/Users/J\u{f6}"),
        ] {
            let l = list(&[&format!("/srv/{entry}/**"), &format!("~/{entry}/**")]);
            let base = if home == "/Users/u" {
                "/Users/u".to_string()
            } else {
                "/Users/Jo\u{308}".to_string()
            };
            let h = Some(home);
            let under_srv = format!("/srv/{path}/key");
            let under_home = format!("{base}/{path}/key");
            let srv_entry = format!("/srv/{entry}/**");
            let home_entry = format!("~/{entry}/**");
            assert_eq!(
                at(&l, &under_srv, h, Fold::Case),
                Ok(Some(srv_entry.as_str())),
                "{entry:?} {path:?}"
            );
            assert_eq!(
                at(&l, &under_home, h, Fold::Case),
                Ok(Some(home_entry.as_str())),
                "{entry:?} {path:?} {home:?}"
            );
            assert_eq!(
                below(&l, &format!("/srv/{path}"), h, Fold::Case),
                Ok(Some(srv_entry.as_str())),
                "{entry:?} {path:?}"
            );
        }
        let l = list(&[&format!("/srv/{nfc}/**")]);
        assert_eq!(
            at(&l, &format!("/srv/{nfd}/key"), None, Fold::None),
            Ok(None)
        );
        assert_eq!(
            at(&l, &format!("/srv/{nfc}/key"), None, Fold::None),
            Ok(Some(format!("/srv/{nfc}/**").as_str()))
        );
    }

    #[test]
    fn private_spellings_match_either_way_on_macos() {
        let l = list(&["/etc/foo.conf", "/private/var/db/x/**", "/tmp/krb5cc_*"]);
        let h = Some("/Users/u");
        for (path, entry) in [
            ("/private/etc/foo.conf", "/etc/foo.conf"),
            ("/etc/foo.conf", "/etc/foo.conf"),
            ("/var/db/x/y", "/private/var/db/x/**"),
            ("/private/var/db/x/y", "/private/var/db/x/**"),
            (
                "/System/Volumes/Data/private/var/db/x/y",
                "/private/var/db/x/**",
            ),
            ("/private/tmp/krb5cc_501", "/tmp/krb5cc_*"),
        ] {
            assert_eq!(at(&l, path, h, Fold::Case), Ok(Some(entry)), "{path}");
        }
        assert_eq!(at(&l, "/private/etc/foo.conf", h, Fold::None), Ok(None));
        assert_eq!(at(&l, "/var/db/x/y", h, Fold::None), Ok(None));
        assert_eq!(at(&l, "/private/usr/foo.conf", h, Fold::Case), Ok(None));
        assert_eq!(at(&l, "/privatex/etc/foo.conf", h, Fold::Case), Ok(None));
    }

    #[test]
    fn an_entry_written_with_a_prefix_the_fold_rewrites_still_binds() {
        let h = Some("/Users/u");
        let l = list(&["/private/**", "/System/Volumes/Data/Users/u/secret/**"]);
        assert_eq!(
            at(&l, "/private/etc/foo", h, Fold::Case),
            Ok(Some("/private/**"))
        );
        assert_eq!(
            at(&l, "/Users/u/secret/k", h, Fold::Case),
            Ok(Some("/System/Volumes/Data/Users/u/secret/**"))
        );
        assert_eq!(
            below(&l, "/private", h, Fold::Case),
            Ok(Some("/private/**"))
        );
        let root_home = list(&["~/.ssh/**"]);
        for path in ["/private/var/root/.ssh/k", "/var/root/.ssh/k"] {
            for home in ["/private/var/root", "/var/root"] {
                assert_eq!(
                    at(&root_home, path, Some(home), Fold::Case),
                    Ok(Some("~/.ssh/**")),
                    "{path} under {home}"
                );
            }
        }
    }

    #[test]
    fn a_subtree_with_a_protected_descendant_matches() {
        let l = SensitiveList::parse(LIST).unwrap();
        let h = Some("/home/u");
        assert_eq!(below(&l, "/home/u", h, Fold::None), Ok(Some("~/.ssh/**")));
        assert_eq!(below(&l, "/home", h, Fold::None), Ok(Some("~/.ssh/**")));
        assert_eq!(below(&l, "/", h, Fold::None), Ok(Some("/etc/shadow")));
        assert_eq!(
            below(&l, "/home/u/.ssh/sub", h, Fold::None),
            Ok(Some("~/.ssh/**"))
        );
        assert_eq!(below(&l, "/home/u/proj", h, Fold::None), Ok(None));
        assert_eq!(below(&l, "/etc/shadow.d", h, Fold::None), Ok(None));
        assert_eq!(
            below(&l, "/private/etc", h, Fold::Case),
            Ok(Some("/etc/shadow"))
        );
        assert_eq!(below(&l, "/private/etc", h, Fold::None), Ok(None));
        assert_eq!(below(&l, "/Home/U", h, Fold::Case), Ok(Some("~/.ssh/**")));
    }

    #[test]
    fn an_ancestor_of_a_rewritten_prefix_holds_what_the_rewrite_reaches() {
        let h = Some("/Users/u");
        let var = list(&["/var/db/x/**"]);
        let home = list(&["~/.ssh/**"]);
        let literal = list(&["/private/**"]);
        for (l, root, entry) in [
            (&var, "/private", "/var/db/x/**"),
            (&var, "/Private", "/var/db/x/**"),
            (&var, "/System/Volumes/Data/private", "/var/db/x/**"),
            (&var, "/System", "/var/db/x/**"),
            (&home, "/System/Volumes", "~/.ssh/**"),
            (&home, "/System", "~/.ssh/**"),
            (&home, "/System/Volumes/Data", "~/.ssh/**"),
            (&home, "/", "~/.ssh/**"),
            (&literal, "/System/Volumes/Data/private", "/private/**"),
        ] {
            assert_eq!(below(l, root, h, Fold::Case), Ok(Some(entry)), "{root}");
        }
        for (l, root) in [
            (&var, "/private"),
            (&var, "/System/Volumes/Data/private"),
            (&home, "/System/Volumes"),
            (&home, "/System"),
            (&home, "/System/Volumes/Data"),
        ] {
            assert_eq!(below(l, root, h, Fold::None), Ok(None), "{root}");
        }
        assert_eq!(
            below(&var, "/private/var", h, Fold::Case),
            Ok(Some("/var/db/x/**"))
        );
        assert_eq!(below(&var, "/private/etc", h, Fold::Case), Ok(None));
        assert_eq!(below(&var, "/System/Library", h, Fold::Case), Ok(None));
        assert_eq!(below(&home, "/private", h, Fold::Case), Ok(None));
        assert_eq!(at(&var, "/private", h, Fold::Case), Ok(None));
    }

    #[test]
    fn a_star_segment_reaches_one_component_only() {
        let h = Some("/home/u");
        let history = list(&["~/.*_history"]);
        assert_eq!(
            below(&history, "/home/u/projects/build", h, Fold::None),
            Ok(None)
        );
        assert_eq!(
            below(&history, "/home/u", h, Fold::None),
            Ok(Some("~/.*_history"))
        );
        assert_eq!(
            at(&history, "/home/u/.bash_history", h, Fold::None),
            Ok(Some("~/.*_history"))
        );
        let mid = list(&["~/a/*/c"]);
        assert_eq!(
            below(&mid, "/home/u/a/b", h, Fold::None),
            Ok(Some("~/a/*/c"))
        );
        assert_eq!(below(&mid, "/home/u/x/b", h, Fold::None), Ok(None));
    }

    #[cfg(unix)]
    #[test]
    fn a_path_that_is_not_utf8_is_still_matched() {
        use std::ffi::OsStr;
        use std::os::unix::ffi::OsStrExt;
        let l = list(&["~/.ssh/**"]);
        let h = Some(Path::new("/home/u"));
        let path = Path::new(OsStr::from_bytes(b"/home/u/.ssh/\xff"));
        assert_eq!(l.matching(path, h, Fold::None), Ok(Some("~/.ssh/**")));
        let dir = Path::new(OsStr::from_bytes(b"/home/u/\xff"));
        assert_eq!(l.subtree_matching(dir, h, Fold::None), Ok(None));
        let parent = Path::new(OsStr::from_bytes(b"/home/u/.ssh/\xff/x"));
        assert_eq!(
            l.subtree_matching(parent, h, Fold::None),
            Ok(Some("~/.ssh/**"))
        );
        let raw_home = Some(Path::new(OsStr::from_bytes(b"/home/\xff")));
        for fold in [Fold::None, Fold::Case] {
            assert_eq!(
                l.matching(Path::new("/home/u/.ssh/k"), raw_home, fold),
                Err(HomeUnbound)
            );
        }
    }

    #[test]
    fn the_native_fold_is_case_on_macos_only() {
        let want = if cfg!(target_os = "macos") {
            Fold::Case
        } else {
            Fold::None
        };
        assert_eq!(native_fold(), want);
    }

    #[test]
    fn the_file_name_is_sensitive_yaml() {
        assert_eq!(SENSITIVE_FILE, "sensitive.yaml");
    }

    #[test]
    fn the_shipped_sensitive_yaml_parses_and_protects_the_named_defaults() {
        let l = SensitiveList::parse(include_str!("../../../packaging/common/sensitive.yaml"))
            .expect("the shipped sensitive.yaml parses");
        let h = Some("/home/u");
        for fold in [Fold::None, Fold::Case] {
            for path in [
                "/etc/shadow",
                "/etc/passwd",
                "/etc/group",
                "/home/u/.ssh",
                "/home/u/.ssh/id_ed25519",
                "/home/u/.aws/credentials",
                "/home/u/.maknae/providers.yaml",
                "/etc/maknae/authz.yaml",
                "/proc/1/environ",
                "/proc/1/task/2/environ",
                "/proc/thread-self/environ",
                "/run/user/1000/keyring/control",
                "/tmp/krb5cc_1000",
            ] {
                assert!(
                    matches!(at(&l, path, h, fold), Ok(Some(_))),
                    "{path} under {fold:?}"
                );
            }
            for path in [
                "/home/u/notes.txt",
                "/home/u/projects/x/src/main.rs",
                "/usr/bin/env",
            ] {
                assert_eq!(at(&l, path, h, fold), Ok(None), "{path} under {fold:?}");
            }
        }
        for path in [
            "/private/etc/master.passwd",
            "/private/etc/shadow",
            "/private/var/db/dslocal/nodes/Default/users/u.plist",
            "/private/tmp/krb5cc_501",
            "/Users/u/Library/Keychains/login.keychain-db",
        ] {
            assert!(
                matches!(at(&l, path, Some("/Users/u"), Fold::Case), Ok(Some(_))),
                "{path}"
            );
        }
        for e in l.entries() {
            assert!(
                !e.starts_with("/private/") && !e.starts_with("/System/Volumes/Data"),
                "{e}: the macOS fold maps these spellings, so an entry is written once"
            );
        }
    }

    #[test]
    fn the_canonical_form_is_the_entries_in_order() {
        assert_eq!(SensitiveList::empty().canonical(), "[]");
        let a = SensitiveList::parse(LIST).unwrap();
        let b = SensitiveList::parse(
            "# c\nsensitive: [\"/etc/shadow\",   \"~/.ssh/**\"]\nschema_version: 1\n",
        )
        .unwrap();
        assert_eq!(a.canonical(), r#"["/etc/shadow","~/.ssh/**"]"#);
        assert_eq!(a.canonical(), b.canonical());
        assert_ne!(
            a.canonical(),
            list(&["~/.ssh/**", "/etc/shadow"]).canonical()
        );
    }

    #[cfg(unix)]
    mod host_file {
        use super::super::*;
        use super::LIST;
        use std::os::unix::fs::PermissionsExt;

        fn dir(tag: &str) -> std::path::PathBuf {
            let d = std::env::temp_dir().join(format!("sensitive_{tag}_{}", std::process::id()));
            let _ = std::fs::remove_dir_all(&d);
            std::fs::create_dir_all(&d).unwrap();
            std::fs::set_permissions(&d, std::fs::Permissions::from_mode(0o700)).unwrap();
            d.canonicalize().unwrap()
        }

        fn write(d: &Path, body: &[u8], mode: u32) -> std::path::PathBuf {
            let p = d.join(SENSITIVE_FILE);
            std::fs::write(&p, body).unwrap();
            std::fs::set_permissions(&p, std::fs::Permissions::from_mode(mode)).unwrap();
            p
        }

        fn runs_as_root(d: &Path) -> bool {
            use std::os::unix::fs::MetadataExt;
            std::fs::metadata(d).map(|m| m.uid() == 0).unwrap_or(false)
        }

        #[test]
        fn the_production_door_requires_root_ownership() {
            let d = dir("prod");
            let p = write(&d, b"schema_version: 1\nsensitive: []\n", 0o640);
            let got = load_host_sensitive(&p);
            let root = runs_as_root(&d);
            let _ = std::fs::remove_dir_all(&d);
            if root {
                assert_eq!(got, Ok(SensitiveList::empty()));
            } else {
                assert!(
                    matches!(&got, Err(ConfigError::Io(m)) if m.contains(SENSITIVE_FILE) && m.contains("root")),
                    "{got:?}"
                );
            }
        }

        #[cfg(feature = "hermetic-test-seam")]
        mod seam {
            use super::*;

            fn own() -> maknae_io::TargetRequired {
                maknae_io::TargetRequired {
                    owner: None,
                    ..crate::authz::root_policy_file_required()
                }
            }

            #[test]
            fn a_sound_file_loads_its_entries() {
                let d = dir("ok");
                let p = write(&d, LIST.as_bytes(), 0o640);
                let got = load_host_sensitive_with_requirement(&p, own());
                let _ = std::fs::remove_dir_all(&d);
                assert_eq!(got, SensitiveList::parse(LIST));
            }

            #[test]
            fn an_absent_file_is_refused_naming_it() {
                let d = dir("absent");
                let p = d.join(SENSITIVE_FILE);
                let got = load_host_sensitive_with_requirement(&p, own());
                let _ = std::fs::remove_dir_all(&d);
                assert_eq!(
                    got,
                    Err(ConfigError::NotFound {
                        path: p.display().to_string()
                    })
                );
            }

            #[test]
            fn every_malformed_file_is_refused_naming_the_file() {
                let d = dir("bad");
                for body in [
                    &b"schema_version: 1\nsensitive: [\n"[..],
                    b"schema_version: 1\n",
                    b"schema_version: 2\nsensitive: []\n",
                    b"schema_version: 1\nsensitive: [\"relative\"]\n",
                    b"schema_version: 1\nsensitive: []\nextra: 1\n",
                    b"",
                ] {
                    let p = write(&d, body, 0o640);
                    let got = load_host_sensitive_with_requirement(&p, own());
                    let shown = got.as_ref().map_err(ToString::to_string);
                    assert!(
                        matches!(&shown, Err(m) if m.contains(SENSITIVE_FILE)),
                        "{:?}: {shown:?}",
                        String::from_utf8_lossy(body)
                    );
                }
                let p = write(&d, &[0xff, 0xfe], 0o640);
                let got = load_host_sensitive_with_requirement(&p, own());
                assert!(
                    matches!(&got, Err(ConfigError::Io(m)) if m.contains("UTF-8") && m.contains(SENSITIVE_FILE)),
                    "{got:?}"
                );
                let _ = std::fs::remove_dir_all(&d);
            }

            #[test]
            fn the_mode_mask_is_the_authz_yaml_one() {
                let d = dir("mode");
                for (mode, ok) in [
                    (0o600, true),
                    (0o640, true),
                    (0o660, false),
                    (0o644, false),
                    (0o604, false),
                ] {
                    let p = write(&d, b"schema_version: 1\nsensitive: []\n", mode);
                    let got = load_host_sensitive_with_requirement(&p, own());
                    assert_eq!(got.is_ok(), ok, "mode {mode:o}: {got:?}");
                    if !ok {
                        assert!(
                            matches!(&got, Err(ConfigError::InsecurePermissions { path, .. }) if path.ends_with(SENSITIVE_FILE)),
                            "{got:?}"
                        );
                    }
                }
                let p = write(&d, b"schema_version: 1\nsensitive: []\n", 0o640);
                let link = d.join("link.yaml");
                std::os::unix::fs::symlink(&p, &link).unwrap();
                assert!(matches!(
                    load_host_sensitive_with_requirement(&link, own()),
                    Err(ConfigError::Symlink { .. })
                ));
                std::fs::set_permissions(&d, std::fs::Permissions::from_mode(0o770)).unwrap();
                let got = load_host_sensitive_with_requirement(&p, own());
                let _ = std::fs::remove_dir_all(&d);
                assert!(
                    matches!(&got, Err(ConfigError::Io(m)) if m.contains("must be owned by root") && m.contains(SENSITIVE_FILE)),
                    "{got:?}"
                );
            }
        }
    }
}
