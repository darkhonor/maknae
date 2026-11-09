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

    /// The first entry that matches `path`. `HomeUnbound` only when no entry
    /// matches and a `~` entry could not be evaluated.
    pub fn matching(
        &self,
        path: &Path,
        home: Option<&Path>,
        fold: Fold,
    ) -> Result<Option<&str>, HomeUnbound> {
        self.first(path, home, fold, |glob, p, h| glob.matches(Path::new(p), h))
    }

    /// The first entry that could match `dir` or a path beneath it.
    pub fn subtree_matching(
        &self,
        dir: &Path,
        home: Option<&Path>,
        fold: Fold,
    ) -> Result<Option<&str>, HomeUnbound> {
        self.first(dir, home, fold, |glob, p, h| {
            glob.may_intersect_subtree(p, h)
        })
    }

    fn first(
        &self,
        path: &Path,
        home: Option<&Path>,
        fold: Fold,
        test: impl Fn(&PathGlob, &str, Option<&Path>) -> Result<bool, HomeUnbound>,
    ) -> Result<Option<&str>, HomeUnbound> {
        let path = path.to_string_lossy();
        let folded = (fold == Fold::Case).then(|| Folded::new(&path, home));
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
                    Ok(hit
                        || test(
                            &e.mapped,
                            &f.mapped,
                            f.home_mapped.as_deref().map(Path::new),
                        )?)
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
    let lowered = text.to_lowercase();
    Ok(Entry {
        glob: glob(text)?,
        mapped: glob(&mapped(&lowered))?,
        lowered: glob(&lowered)?,
        text: text.to_string(),
    })
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

struct Folded {
    lowered: String,
    mapped: String,
    home_lowered: Option<String>,
    home_mapped: Option<String>,
}

impl Folded {
    fn new(path: &str, home: Option<&Path>) -> Self {
        let lowered = path.to_lowercase();
        let home_lowered = home.and_then(Path::to_str).map(str::to_lowercase);
        Folded {
            mapped: mapped(&lowered),
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
        let absolute_only = list(&["/etc/shadow"]);
        assert_eq!(at(&absolute_only, "/home/u/x", None, Fold::None), Ok(None));
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
}
