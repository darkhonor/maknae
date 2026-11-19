//! The tool argument-pattern grammar (#674): grants match argv per argument.

use std::collections::BTreeMap;
use std::fmt;

#[derive(Clone, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum ArgPatternError {
    Empty,
    Spacing,
    RestNotLast,
    LoneRest,
    MalformedBound(String),
    BoundWithStar(String),
    StarInsideToken(String),
}

impl fmt::Display for ArgPatternError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Empty => f.write_str("the pattern is empty"),
            Self::Spacing => f.write_str("a leading, trailing or doubled space"),
            Self::RestNotLast => f.write_str("`*` must be the final token"),
            Self::LoneRest => f.write_str("`*` cannot be the only token"),
            Self::MalformedBound(t) => write!(f, "`{t}` is not `{{<kind>.<field>}}`"),
            Self::BoundWithStar(t) => write!(f, "`{t}` combines a binding and `*`"),
            Self::StarInsideToken(t) => write!(f, "`{t}` has `*` other than at its end"),
        }
    }
}

impl std::error::Error for ArgPatternError {}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ArgToken {
    Literal(String),
    Prefix(String),
    Rest,
    Bound { kind: String, field: String },
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ArgPattern(Vec<ArgToken>);

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Bound(BTreeMap<String, String>);

impl Bound {
    pub fn empty() -> Self {
        Self::default()
    }

    pub fn insert(&mut self, key: &str, value: &str) {
        self.0.insert(key.to_string(), value.to_string());
    }

    fn get(&self, kind: &str, field: &str) -> Option<&str> {
        self.0.get(&format!("{kind}.{field}")).map(String::as_str)
    }
}

fn segment(s: &str) -> bool {
    !s.is_empty()
        && s.bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'_')
}

fn token(text: &str) -> Result<ArgToken, ArgPatternError> {
    let braced = text.contains('{') || text.contains('}');
    if braced {
        if text.ends_with('*') {
            return Err(ArgPatternError::BoundWithStar(text.to_string()));
        }
        let malformed = || ArgPatternError::MalformedBound(text.to_string());
        let inner = text
            .strip_prefix('{')
            .and_then(|t| t.strip_suffix('}'))
            .ok_or_else(malformed)?;
        let (kind, field) = inner.split_once('.').ok_or_else(malformed)?;
        if !segment(kind) || !segment(field) {
            return Err(malformed());
        }
        return Ok(ArgToken::Bound {
            kind: kind.to_string(),
            field: field.to_string(),
        });
    }
    match text.strip_suffix('*') {
        Some("") => Ok(ArgToken::Rest),
        Some(prefix) if prefix.contains('*') => {
            Err(ArgPatternError::StarInsideToken(text.to_string()))
        }
        Some(prefix) => Ok(ArgToken::Prefix(prefix.to_string())),
        None if text.contains('*') => Err(ArgPatternError::StarInsideToken(text.to_string())),
        None => Ok(ArgToken::Literal(text.to_string())),
    }
}

impl ArgPattern {
    pub fn parse(spec: &str) -> Result<Self, ArgPatternError> {
        if spec.is_empty() {
            return Err(ArgPatternError::Empty);
        }
        let tokens = spec
            .split(' ')
            .map(|t| {
                if t.is_empty() {
                    Err(ArgPatternError::Spacing)
                } else {
                    token(t)
                }
            })
            .collect::<Result<Vec<_>, _>>()?;
        if let Some(at) = tokens.iter().position(|t| matches!(t, ArgToken::Rest)) {
            if at + 1 != tokens.len() {
                return Err(ArgPatternError::RestNotLast);
            }
            if tokens.len() == 1 {
                return Err(ArgPatternError::LoneRest);
            }
        }
        Ok(Self(tokens))
    }

    pub fn matches(&self, argv: &[String], bound: &Bound) -> bool {
        let (fixed, open) = match self.0.split_last() {
            Some((ArgToken::Rest, fixed)) => (fixed, true),
            _ => (self.0.as_slice(), false),
        };
        if argv.len() < fixed.len() || (!open && argv.len() != fixed.len()) {
            return false;
        }
        fixed.iter().zip(argv).all(|(t, arg)| match t {
            ArgToken::Literal(s) => arg == s,
            ArgToken::Prefix(p) => arg.starts_with(p.as_str()),
            ArgToken::Bound { kind, field } => bound.get(kind, field) == Some(arg.as_str()),
            ArgToken::Rest => false,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DenyArg {
    text: String,
    prefix: bool,
}

impl DenyArg {
    pub fn parse(s: &str) -> Result<Self, ArgPatternError> {
        if s.is_empty() {
            return Err(ArgPatternError::Empty);
        }
        match s.strip_suffix('*') {
            Some("") => Err(ArgPatternError::LoneRest),
            Some(text) if text.contains('*') => {
                Err(ArgPatternError::StarInsideToken(s.to_string()))
            }
            Some(text) => Ok(Self {
                text: text.to_string(),
                prefix: true,
            }),
            None if s.contains('*') => Err(ArgPatternError::StarInsideToken(s.to_string())),
            None => Ok(Self {
                text: s.to_string(),
                prefix: false,
            }),
        }
    }

    fn hits(&self, arg: &str) -> bool {
        if self.prefix {
            arg.starts_with(self.text.as_str())
        } else {
            arg == self.text
        }
    }
}

pub fn first_denied(denies: &[DenyArg], argv: &[String]) -> Option<usize> {
    argv.iter().position(|a| denies.iter().any(|d| d.hits(a)))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn argv(items: &[&str]) -> Vec<String> {
        items.iter().map(|s| (*s).to_string()).collect()
    }

    fn matches(spec: &str, args: &[&str]) -> bool {
        ArgPattern::parse(spec)
            .unwrap()
            .matches(&argv(args), &Bound::empty())
    }

    fn bound(pairs: &[(&str, &str)]) -> Bound {
        let mut b = Bound::empty();
        for (k, v) in pairs {
            b.insert(k, v);
        }
        b
    }

    #[test]
    fn literal_tokens_match_exact_count() {
        assert!(matches("test", &["test"]));
        assert!(matches("status --short", &["status", "--short"]));
        assert!(!matches("status", &["status", "--short"]));
        assert!(!matches("status --short", &["status"]));
        assert!(!matches("status", &["Status"]));
    }

    #[test]
    fn rest_matches_zero_or_more() {
        assert!(matches("test *", &["test"]));
        assert!(matches("test *", &["test", "a", "b", "c"]));
        assert!(!matches("test *", &["build"]));
    }

    #[test]
    fn prefix_token_matches_one_argument() {
        assert!(matches("log --format*", &["log", "--format=oneline"]));
        assert!(matches("log --format*", &["log", "--format"]));
        assert!(!matches("log --format*", &["log"]));
        assert!(!matches("log --format*", &["log", "--format=a", "x"]));
        assert!(!matches("log --format*", &["log", "-x--format"]));
    }

    #[test]
    fn arguments_with_spaces_are_one_token() {
        assert!(matches("test *", &["test", "a b"]));
        assert!(!matches("test a", &["test", "a b"]));
        assert!(!matches("test a b", &["test", "a b"]));
    }

    #[test]
    fn empty_argument_is_one_token() {
        assert!(matches("test *", &["test", ""]));
        assert!(!matches("test", &["test", ""]));
    }

    #[test]
    fn bound_token_matches_bound_value_only() {
        let p = ArgPattern::parse("diff {git.base}").unwrap();
        let b = bound(&[("git.base", "sentinel-674-main")]);
        assert!(p.matches(&argv(&["diff", "sentinel-674-main"]), &b));
        assert!(!p.matches(&argv(&["diff", "other"]), &b));
        assert!(!p.matches(&argv(&["diff"]), &b));
    }

    #[test]
    fn bound_token_never_matches_when_absent() {
        let p = ArgPattern::parse("diff {git.base}").unwrap();
        assert!(!p.matches(&argv(&["diff", "{git.base}"]), &Bound::empty()));
        assert!(!p.matches(&argv(&["diff", ""]), &Bound::empty()));
        let other = bound(&[("git.head", "x")]);
        assert!(!p.matches(&argv(&["diff", "x"]), &other));
    }

    #[test]
    fn rest_not_last_is_rejected() {
        assert!(ArgPattern::parse("* test").is_err());
        assert!(ArgPattern::parse("a * b").is_err());
        assert!(ArgPattern::parse("*").is_err());
        assert!(ArgPattern::parse("a*b").is_err());
    }

    #[test]
    fn double_space_is_rejected() {
        assert!(ArgPattern::parse("").is_err());
        assert!(ArgPattern::parse("a  b").is_err());
        assert!(ArgPattern::parse(" a").is_err());
        assert!(ArgPattern::parse("a ").is_err());
    }

    #[test]
    fn malformed_bound_is_rejected() {
        for bad in [
            "{git}",
            "{git.}",
            "{.base}",
            "{git.base",
            "git.base}",
            "{Git.base}",
            "{git.a.b}",
            "{git.ba-se}",
            "{}",
            "x{git.base}",
        ] {
            assert!(ArgPattern::parse(bad).is_err(), "{bad}");
        }
        assert!(ArgPattern::parse("{git_2.base_1}").is_ok());
    }

    #[test]
    fn bound_with_star_is_rejected() {
        assert!(ArgPattern::parse("{git.base}*").is_err());
        assert!(ArgPattern::parse("diff {git.base}*").is_err());
    }

    fn deny(texts: &[&str]) -> Vec<DenyArg> {
        texts.iter().map(|t| DenyArg::parse(t).unwrap()).collect()
    }

    #[test]
    fn deny_prefix_hits_equals_and_joined_short_flags() {
        let d = deny(&["--config*", "-Z*"]);
        assert_eq!(first_denied(&d, &argv(&["build", "--config=x"])), Some(1));
        assert_eq!(first_denied(&d, &argv(&["build", "--config"])), Some(1));
        assert_eq!(first_denied(&d, &argv(&["-Zfoo"])), Some(0));
        assert_eq!(first_denied(&d, &argv(&["build", "--release"])), None);
    }

    #[test]
    fn deny_applies_after_double_dash() {
        let d = deny(&["--config*"]);
        assert_eq!(
            first_denied(&d, &argv(&["run", "--", "--config=x"])),
            Some(2)
        );
    }

    #[test]
    fn deny_is_case_sensitive() {
        let d = deny(&["--config*", "-Z*"]);
        assert_eq!(first_denied(&d, &argv(&["--CONFIG=x", "-zfoo"])), None);
    }

    #[test]
    fn exact_deny_matches_only_itself() {
        let d = deny(&["--config"]);
        assert_eq!(first_denied(&d, &argv(&["--config"])), Some(0));
        assert_eq!(first_denied(&d, &argv(&["--config=x"])), None);
    }

    #[test]
    fn upl_prefix_denies_git_abbreviation() {
        let d = deny(&["--upl*"]);
        assert_eq!(first_denied(&d, &argv(&["fetch", "--upl=sh"])), Some(1));
    }

    #[test]
    fn every_pattern_error_has_its_own_message() {
        let shown = [
            ArgPatternError::Empty,
            ArgPatternError::Spacing,
            ArgPatternError::RestNotLast,
            ArgPatternError::LoneRest,
            ArgPatternError::MalformedBound("{x}".to_string()),
            ArgPatternError::BoundWithStar("{a.b}*".to_string()),
            ArgPatternError::StarInsideToken("a*b".to_string()),
        ]
        .map(|e| e.to_string());
        assert_eq!(
            shown
                .iter()
                .collect::<std::collections::BTreeSet<_>>()
                .len(),
            7
        );
        assert!(
            shown[4].contains("{x}") && shown[5].contains("{a.b}*") && shown[6].contains("a*b")
        );
    }

    #[test]
    fn empty_or_bare_star_deny_is_rejected() {
        assert!(matches!(DenyArg::parse(""), Err(ArgPatternError::Empty)));
        assert!(matches!(
            DenyArg::parse("*"),
            Err(ArgPatternError::LoneRest)
        ));
    }

    #[test]
    fn deny_star_other_than_trailing_is_rejected() {
        for bad in ["--c*nfig", "**", "a**", "*a", "*a*"] {
            assert!(
                matches!(
                    DenyArg::parse(bad),
                    Err(ArgPatternError::StarInsideToken(_))
                ),
                "{bad}"
            );
        }
    }

    #[test]
    fn rejections_name_their_reason() {
        let err = |s: &str| ArgPattern::parse(s).unwrap_err();
        assert!(matches!(err(""), ArgPatternError::Empty));
        assert!(matches!(err("a  b"), ArgPatternError::Spacing));
        assert!(matches!(err("* a"), ArgPatternError::RestNotLast));
        assert!(matches!(err("*"), ArgPatternError::LoneRest));
        assert!(matches!(err("{git}"), ArgPatternError::MalformedBound(_)));
        assert!(matches!(
            err("{git.base}*"),
            ArgPatternError::BoundWithStar(_)
        ));
        assert!(matches!(err("a**"), ArgPatternError::StarInsideToken(_)));
        assert!(matches!(err("a*b"), ArgPatternError::StarInsideToken(_)));
    }
}
