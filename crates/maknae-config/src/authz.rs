//! DAC authz policy schema v1 (spec §7, PR-J1 Task 6) — the Claude-Code/Codex-
//! style capability grammar (`Read(...)`, `Bash(...)`) that a FUTURE per-request
//! PDP evaluates. This module ships and VALIDATES the contract (parse +
//! fail-closed validation + the matching grammar as an executable pin) — it
//! does not wire evaluation into any request path yet.
//!
//! **The grammar is a durable contract:** operators write policy files against
//! it and it is hard to change once shipped, so parse/match semantics are
//! specified precisely (spec §7) and pinned exhaustively by test.
//!
//! `AuthzError` is deliberately its own type, not `ConfigError`: `authz.yaml`
//! is a standalone file (not a `maknae.yaml` section), the `Value` tree is
//! span-free (no line numbers survive parsing), so every variant here names
//! the offending KEY or PATTERN text rather than a location. Mapping each
//! variant to a `MsgId` is the daemon call site's job (`run.rs`), not this
//! crate's — keeps `maknae-config` off the `maknae-msgs` dependency (spec §4.3).

use crate::{ConfigError, Value};
use std::path::Path;

// ============================================================================
// Public policy schema
// ============================================================================

/// The parsed `permissions:` wrapper (spec §7): an allow list and a deny list
/// of patterns. Deny beats allow; anything matching neither is denied
/// (default-deny) — see [`AuthzPolicy::evaluate`].
#[derive(Clone, Debug, PartialEq, Eq, Default)]
pub struct AuthzPolicy {
    pub allow: Vec<Pattern>,
    pub deny: Vec<Pattern>,
}

/// A single request the (future) PDP asks the policy about.
#[derive(Clone, Copy, Debug)]
pub enum Request<'a> {
    Read(&'a Path),
    Bash(&'a [String]),
}

/// The policy's answer for a [`Request`] (spec §7): there is no `ask`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Decision {
    Allow,
    Deny,
}

impl AuthzPolicy {
    /// Deny-wins, default-deny (spec §7): a deny match refuses regardless of
    /// any allow match; a request matching neither list is refused. The empty
    /// policy (`allow`/`deny` both empty) therefore permits nothing.
    pub fn evaluate(&self, req: &Request<'_>) -> Decision {
        if self.deny.iter().any(|p| p.matches_req(req)) {
            return Decision::Deny;
        }
        if self.allow.iter().any(|p| p.matches_req(req)) {
            return Decision::Allow;
        }
        Decision::Deny
    }
}

/// One `Capability(specifier)` entry (spec §7). v1 capabilities: `Read`,
/// `Bash` only — any other capability name is `AuthzError::BadPattern`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Pattern {
    Read(PathGlob),
    Bash { tokens: Vec<String>, any_args: bool },
}

impl Pattern {
    fn matches_req(&self, req: &Request<'_>) -> bool {
        match (self, req) {
            (Pattern::Read(glob), Request::Read(path)) => glob.matches(path),
            (Pattern::Bash { tokens, any_args }, Request::Bash(argv)) => {
                if argv.len() < tokens.len() {
                    return false;
                }
                if argv[..tokens.len()] != tokens[..] {
                    return false;
                }
                if argv.len() == tokens.len() {
                    return true; // exact-length prefix match — always accepted
                }
                *any_args // argv has EXTRA tokens beyond the pattern — only ":*" allows this
            }
            _ => false,
        }
    }
}

// ============================================================================
// PathGlob — the hand-rolled glob matcher (spec §7)
// ============================================================================

/// A compiled `Read(<glob>)` specifier: an absolute path split into
/// `/`-separated segments, each either a literal component (which may itself
/// contain `*` wildcards, e.g. `*.json`) or `**` (matches across zero or more
/// components — see [`PathGlob::matches`]).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PathGlob {
    segments: Vec<GlobSeg>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
enum GlobSeg {
    DoubleStar,
    Comp(String),
}

impl PathGlob {
    /// Compile a `Read(<glob>)` specifier's inner text. `~` expands to
    /// `principal_home` (a `~` pattern with no principal is refused); any
    /// other pattern must already be absolute (spec §7: "matched against
    /// canonical absolute paths" — a relative glob can never match one).
    fn parse(spec: &str, principal_home: Option<&Path>) -> Result<PathGlob, AuthzError> {
        let bad = || AuthzError::BadPattern(spec.to_string());
        let resolved = if let Some(rest) = spec.strip_prefix('~') {
            if !rest.is_empty() && !rest.starts_with('/') {
                // `~otheruser/...` — not supported; only the enrolled
                // principal's own home is a valid `~` referent.
                return Err(bad());
            }
            let home = principal_home
                .ok_or_else(|| AuthzError::TildeWithoutPrincipal(spec.to_string()))?;
            let home_str = home.to_str().ok_or_else(bad)?;
            format!("{home_str}{rest}")
        } else if spec.starts_with('/') {
            spec.to_string()
        } else {
            return Err(bad());
        };

        let segments = resolved
            .split('/')
            .filter(|c| !c.is_empty())
            .map(|c| {
                if c == "**" {
                    GlobSeg::DoubleStar
                } else {
                    GlobSeg::Comp(c.to_string())
                }
            })
            .collect();
        Ok(PathGlob { segments })
    }

    /// Match a canonical absolute path against the compiled glob (spec §7):
    /// `*` matches within one path component; `**` matches across components
    /// — INCLUDING zero components, so `X/**` also matches `X` itself. Both
    /// `*` and `**` match dotfiles (no special-casing of a leading `.`).
    /// Matching is byte-wise case-sensitive.
    pub fn matches(&self, path: &Path) -> bool {
        let Some(s) = path.to_str() else {
            return false;
        };
        let comps: Vec<&str> = s.split('/').filter(|c| !c.is_empty()).collect();
        match_segs(&self.segments, &comps)
    }
}

/// `**`-aware recursive matcher: `**` may consume zero or more remaining
/// components (zero-consumption is the `X/**` ⇒ `X` rule); a literal segment
/// must consume exactly one component that satisfies [`component_matches`].
fn match_segs(pat: &[GlobSeg], comps: &[&str]) -> bool {
    match pat.split_first() {
        None => comps.is_empty(),
        Some((GlobSeg::DoubleStar, rest)) => {
            if match_segs(rest, comps) {
                return true;
            }
            match comps.split_first() {
                Some((_, tail)) => match_segs(pat, tail),
                None => false,
            }
        }
        Some((GlobSeg::Comp(p), rest)) => match comps.split_first() {
            Some((c, tail)) if component_matches(p, c) => match_segs(rest, tail),
            _ => false,
        },
    }
}

/// `*`-only wildcard match WITHIN one path component: split the pattern on
/// `*` into literal fragments and require them to appear in `text`, in
/// order, non-overlapping — the first fragment anchored at the start (unless
/// the pattern itself starts with `*`) and the last anchored at the end
/// (unless the pattern itself ends with `*`); interior fragments are found
/// greedily left-to-right. `*` never crosses a `/` because this function only
/// ever sees one path component's bytes. Byte-wise, case-sensitive (`&str`
/// slicing below is on UTF-8 boundaries only, which `split`/`find` respect).
///
/// Start-anchor and end-anchor are INDEPENDENT constraints, not mutually
/// exclusive: a pattern with no `*` at all (e.g. `passwd`) splits into a
/// SINGLE fragment where `i == 0` and `i == last` coincide, and BOTH anchors
/// must apply to that one fragment — i.e. exact equality, not merely a
/// prefix. (An earlier version used `if … else if …`, so the end-anchor was
/// silently skipped whenever it coincided with the start-anchor, making
/// every starless literal component behave like an implicit trailing `*` —
/// an over-ALLOW: `Read(/etc/passwd)` matched `/etc/passwd-backup`, and the
/// shipped-default `Read(~/**)` matched a different user's home directory
/// whenever its name shared the principal's name as a prefix, e.g.
/// `/home/operatorbot` under principal home `/home/operator`.)
fn component_matches(pattern: &str, text: &str) -> bool {
    let fragments: Vec<&str> = pattern.split('*').collect();
    let last = fragments.len() - 1;
    let anchored_start = !pattern.starts_with('*');
    let anchored_end = !pattern.ends_with('*');
    let mut pos = 0usize;
    for (i, frag) in fragments.iter().enumerate() {
        if frag.is_empty() {
            continue; // a `*` itself, or two adjacent `*`s — no constraint here
        }
        let is_first = i == 0;
        let is_last = i == last;

        if is_first && anchored_start {
            if !text[pos..].starts_with(frag) {
                return false;
            }
            pos += frag.len();
            if is_last && anchored_end {
                // Single-fragment pattern (no `*` anywhere): both anchors
                // apply to this SAME occurrence, so it must consume the
                // entire remaining text — a prefix match is not enough.
                return pos == text.len();
            }
            continue;
        }

        if is_last && anchored_end {
            if !text[pos..].ends_with(frag) {
                return false;
            }
            // last fragment — no `pos` advance needed, nothing follows it
            continue;
        }

        match text[pos..].find(frag) {
            Some(offset) => pos += offset + frag.len(),
            None => return false,
        }
    }
    true
}

// ============================================================================
// AuthzError
// ============================================================================

/// Fail-closed error for the DAC authz policy (spec §7). Span-free by design
/// (the `Value` tree carries no line numbers) — every variant names the
/// offending key or pattern text instead.
#[derive(Clone, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum AuthzError {
    /// `schema_version` is missing, not an integer, or not `1`.
    UnknownSchemaVersion(i64),
    /// A key not defined by the grammar appeared at some level of the document.
    UnknownKey(String),
    /// A pattern specifier failed to parse (bad shape, unknown capability,
    /// empty `Bash` tokens, non-absolute `Read` glob, …).
    BadPattern(String),
    /// A pattern used `~` but no principal is enrolled to resolve it against.
    TildeWithoutPrincipal(String),
    /// `authz.yaml` carries world/other-accessible permission bits.
    InsecurePermissions,
    /// `authz.yaml` (or a path component) is a symlink — refused.
    Symlink,
    /// `authz.yaml` is not owned by root (uid 0) — spec §4.6/§7: root
    /// ownership is the control that stops a compromised `_maknae` from
    /// widening its own DAC by editing this file.
    NotRootOwned,
    /// File I/O failure (missing file, unreadable, non-UTF-8, …).
    Io(String),
    /// The document is not well-formed YAML, or a section has the wrong shape
    /// (root not a mapping, `permissions` not a mapping, an `allow`/`deny`
    /// entry not a string, …).
    Yaml(String),
}

impl std::fmt::Display for AuthzError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            AuthzError::UnknownSchemaVersion(v) => {
                write!(f, "unknown authz schema_version: {v}")
            }
            AuthzError::UnknownKey(k) => write!(f, "unknown authz policy key: '{k}'"),
            AuthzError::BadPattern(p) => write!(f, "malformed authz pattern: '{p}'"),
            AuthzError::TildeWithoutPrincipal(p) => write!(
                f,
                "pattern '{p}' uses '~' but no principal is enrolled to resolve it"
            ),
            AuthzError::InsecurePermissions => write!(
                f,
                "authz.yaml has insecure (world/other-accessible) permissions"
            ),
            AuthzError::Symlink => write!(f, "authz.yaml path is a symlink (refused)"),
            AuthzError::NotRootOwned => write!(f, "authz.yaml is not owned by root (uid 0)"),
            AuthzError::Io(m) => write!(f, "authz i/o error: {m}"),
            AuthzError::Yaml(m) => write!(f, "authz yaml error: {m}"),
        }
    }
}

impl std::error::Error for AuthzError {}

// ============================================================================
// Grammar parsing (pure — no file I/O)
// ============================================================================

fn get<'a>(map: &'a [(String, Value)], key: &str) -> Option<&'a Value> {
    map.iter().find(|(k, _)| k == key).map(|(_, v)| v)
}

/// Fail-closed unknown-key gate (spec §7: "unknown keys at ANY level →
/// refuse"). Applied to the top-level map and separately to the `permissions`
/// map, so a typo like `denny:` is caught wherever it appears.
fn check_known_keys(map: &[(String, Value)], allowed: &[&str]) -> Result<(), AuthzError> {
    for (k, _) in map {
        if !allowed.contains(&k.as_str()) {
            return Err(AuthzError::UnknownKey(k.clone()));
        }
    }
    Ok(())
}

fn str_seq(v: &Value) -> Result<Vec<String>, AuthzError> {
    match v {
        Value::Seq(items) => items
            .iter()
            .map(|item| match item {
                Value::Str(s) => Ok(s.clone()),
                _ => Err(AuthzError::Yaml(
                    "permissions list entries must be strings".into(),
                )),
            })
            .collect(),
        _ => Err(AuthzError::Yaml(
            "permissions list must be a sequence".into(),
        )),
    }
}

/// Parse one `Capability(specifier)` string (spec §7).
fn parse_pattern(spec: &str, principal_home: Option<&Path>) -> Result<Pattern, AuthzError> {
    let bad = || AuthzError::BadPattern(spec.to_string());
    let open = spec.find('(').ok_or_else(bad)?;
    if !spec.ends_with(')') {
        return Err(bad());
    }
    let capability = &spec[..open];
    let inner = &spec[open + 1..spec.len() - 1];
    match capability {
        "Read" => Ok(Pattern::Read(PathGlob::parse(inner, principal_home)?)),
        "Bash" => {
            let (body, any_args) = match inner.strip_suffix(":*") {
                Some(b) => (b, true),
                None => (inner, false),
            };
            let tokens: Vec<String> = body.split_whitespace().map(String::from).collect();
            if tokens.is_empty() {
                return Err(bad());
            }
            Ok(Pattern::Bash { tokens, any_args })
        }
        _ => Err(bad()),
    }
}

/// Parse a `schema_version: 1 / permissions: {allow, deny}` document (spec
/// §7) into an [`AuthzPolicy`]. Pure — takes already-read YAML text, no file
/// I/O (that's [`load_authz`]'s job); factored out so the grammar/contract
/// tests can pin parse semantics without touching the filesystem.
fn parse_policy(body: &str, principal_home: Option<&Path>) -> Result<AuthzPolicy, AuthzError> {
    let root = crate::load_str(body).map_err(|e| AuthzError::Yaml(e.to_string()))?;
    let map = match root {
        Value::Map(m) => m,
        _ => return Err(AuthzError::Yaml("authz root must be a mapping".into())),
    };
    check_known_keys(&map, &["schema_version", "permissions"])?;

    // Missing or non-integer schema_version is represented by the sentinel 0
    // (valid versions start at 1) so both cases refuse via the same variant.
    let schema_version = match get(&map, "schema_version") {
        Some(Value::Int(n)) => *n,
        _ => 0,
    };
    if schema_version != 1 {
        return Err(AuthzError::UnknownSchemaVersion(schema_version));
    }

    let (allow_raw, deny_raw) = match get(&map, "permissions") {
        None => (Vec::new(), Vec::new()),
        Some(Value::Map(pm)) => {
            check_known_keys(pm, &["allow", "deny"])?;
            let allow = get(pm, "allow")
                .map(str_seq)
                .transpose()?
                .unwrap_or_default();
            let deny = get(pm, "deny")
                .map(str_seq)
                .transpose()?
                .unwrap_or_default();
            (allow, deny)
        }
        Some(_) => return Err(AuthzError::Yaml("permissions section must be a map".into())),
    };

    let allow = allow_raw
        .iter()
        .map(|s| parse_pattern(s, principal_home))
        .collect::<Result<Vec<_>, _>>()?;
    let deny = deny_raw
        .iter()
        .map(|s| parse_pattern(s, principal_home))
        .collect::<Result<Vec<_>, _>>()?;

    Ok(AuthzPolicy { allow, deny })
}

// ============================================================================
// Secure load (spec §4.6/§7)
// ============================================================================

/// Pure owner-check boundary, factored out so it is unit-testable without
/// filesystem access or root privilege (mirrors the mode-mask precedent in
/// `loader.rs::mode_is_secure`).
#[cfg(unix)]
fn assert_root_owned(uid: u32) -> Result<(), AuthzError> {
    if uid == 0 {
        Ok(())
    } else {
        Err(AuthzError::NotRootOwned)
    }
}

/// Read `authz.yaml` via the loader's existing secure read (symlink refusal +
/// `mode & 0o007 == 0` gate, `loader.rs:33`) PLUS an explicit root-ownership
/// assertion (spec §4.6/§7: root ownership is the control that stops a
/// compromised `_maknae` from widening its own DAC by editing this file).
///
/// The owner check is a SEPARATE `symlink_metadata` re-resolve of `path`, not
/// fused into `read_secure`'s already-open fd — `read_secure` returns only a
/// `String` and checks no owner. This is safe because `authz.yaml` lives in
/// the root-owned `/etc/maknae` (spec §4.6): `_maknae` cannot write that
/// directory, so it cannot win a swap between the two resolves — the same
/// bounded lstat-then-open race the loader itself already accepts, not a new
/// one (a fused `read_secure_owned` that fstats uid on the same fd is future
/// work, out of scope here).
///
/// `owner_of` is an injected seam (real caller: [`real_owner_of`]) so the
/// SUCCESS path is unit-testable without an actual root-owned fixture file
/// (which a non-privileged test process cannot create) — the real resolver
/// and `assert_root_owned`'s comparison are each tested directly too.
///
/// One function with an INLINE `#[cfg(unix)]`/`#[cfg(not(unix))]` split
/// (mirrors `loader.rs::load_config`'s idiom), not two separate `fn` items —
/// a standalone `#[cfg(not(unix))] fn security_load` would still exist as
/// its own mutation target on a unix build even though its body never
/// compiles in, which is not exercisable/killable on a unix CI runner and
/// would report as a permanently-missed mutant for dead code.
fn security_load(
    path: &Path,
    owner_of: impl Fn(&Path) -> std::io::Result<u32>,
) -> Result<String, AuthzError> {
    #[cfg(not(unix))]
    {
        // The permission/ownership model this control depends on is
        // unavailable on this target — refuse to load rather than proceed
        // unchecked (fail-closed). Not exercisable on a unix CI runner,
        // hence no mutation/coverage obligation on this arm.
        let _ = (path, owner_of);
        return Err(AuthzError::Io(
            "authz permission enforcement is unavailable on this platform; refusing to load".into(),
        ));
    }
    #[cfg(unix)]
    {
        let body = crate::loader::read_secure(path).map_err(|e| match e {
            ConfigError::Symlink { .. } => AuthzError::Symlink,
            ConfigError::InsecurePermissions { .. } => AuthzError::InsecurePermissions,
            other => AuthzError::Io(other.to_string()),
        })?;

        let uid = owner_of(path).map_err(|e| AuthzError::Io(e.to_string()))?;
        assert_root_owned(uid)?;
        Ok(body)
    }
}

/// The real `owner_of` resolver `load_authz` injects into [`security_load`]
/// (tests inject a stub instead — see `security_load_succeeds_with_injected_root_owner`).
fn real_owner_of(path: &Path) -> std::io::Result<u32> {
    #[cfg(not(unix))]
    {
        // Dead on a unix build: `security_load`'s non-unix arm refuses
        // before ever calling `owner_of`. Kept as one function (not a second
        // `#[cfg(not(unix))] fn`) for the same dead-mutant reason as above.
        let _ = path;
        Ok(0)
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        std::fs::symlink_metadata(path).map(|m| m.uid())
    }
}

/// Load and validate `/etc/maknae/authz.yaml` (spec §5.4/§7): secure read +
/// root-ownership assertion, then fail-closed grammar validation. `~` in any
/// pattern resolves against `principal_home` (spec §7's enrolled operator).
pub fn load_authz(path: &Path, principal_home: Option<&Path>) -> Result<AuthzPolicy, AuthzError> {
    let body = security_load(path, real_owner_of)?;
    parse_policy(&body, principal_home)
}

#[cfg(test)]
mod tests {
    use super::*;

    // ---- the exact spec §7 shipped default ----

    // A raw multi-line string here would put un-indented YAML text at column
    // 0, which the coverage gate's "test module extends to EOF" scanner
    // mistakes for top-level production code — hence the `\n`-joined single
    // line, matching this crate's existing test-fixture convention
    // (loader.rs, principal.rs, …).
    const SHIPPED_DEFAULT: &str = "schema_version: 1\npermissions:\n  allow:\n    - \"Read(~/**)\"\n  deny:\n    - \"Read(~/.ssh/**)\"\n    - \"Read(~/.gnupg/**)\"\n    - \"Read(~/.aws/**)\"\n    - \"Read(~/.vault-token)\"\n    - \"Read(~/.netrc)\"\n    - \"Read(~/.git-credentials)\"\n    - \"Read(~/.kube/**)\"\n    - \"Read(~/.docker/config.json)\"\n    - \"Read(~/.maknae/**)\"\n";

    fn home() -> std::path::PathBuf {
        std::path::PathBuf::from("/home/operator")
    }

    // ---- grammar / contract-as-tests (pure, via parse_policy) ----

    #[test]
    fn shipped_default_validates_clean() {
        let policy = parse_policy(SHIPPED_DEFAULT, Some(&home())).unwrap();
        assert_eq!(policy.allow.len(), 1);
        assert_eq!(policy.deny.len(), 9);
        assert!(matches!(policy.allow[0], Pattern::Read(_)));
        for p in &policy.deny {
            assert!(matches!(p, Pattern::Read(_)));
        }
    }

    #[test]
    fn unknown_schema_version_refused() {
        let yaml = "schema_version: 2\npermissions:\n  allow: []\n";
        assert!(matches!(
            parse_policy(yaml, Some(&home())),
            Err(AuthzError::UnknownSchemaVersion(2))
        ));
    }

    #[test]
    fn schema_version_missing_is_unknown_schema_version() {
        let yaml = "permissions:\n  allow: []\n";
        assert!(matches!(
            parse_policy(yaml, Some(&home())),
            Err(AuthzError::UnknownSchemaVersion(0))
        ));
    }

    #[test]
    fn schema_version_non_integer_is_unknown_schema_version() {
        let yaml = "schema_version: \"1\"\npermissions:\n  allow: []\n";
        assert!(matches!(
            parse_policy(yaml, Some(&home())),
            Err(AuthzError::UnknownSchemaVersion(0))
        ));
    }

    #[test]
    fn unknown_key_refused_naming_key() {
        let yaml = "schema_version: 1\npermissions:\n  allow: []\n  denny: []\n";
        match parse_policy(yaml, Some(&home())) {
            Err(AuthzError::UnknownKey(k)) => assert_eq!(k, "denny"),
            other => panic!("expected UnknownKey(\"denny\"), got {other:?}"),
        }
    }

    #[test]
    fn unknown_top_level_key_refused() {
        let yaml = "schema_version: 1\nextra_top_key: 1\n";
        match parse_policy(yaml, Some(&home())) {
            Err(AuthzError::UnknownKey(k)) => assert_eq!(k, "extra_top_key"),
            other => panic!("expected UnknownKey(\"extra_top_key\"), got {other:?}"),
        }
    }

    #[test]
    fn unknown_capability_refused() {
        let yaml = "schema_version: 1\npermissions:\n  allow:\n    - \"WebSearch(x)\"\n";
        assert!(matches!(
            parse_policy(yaml, Some(&home())),
            Err(AuthzError::BadPattern(p)) if p == "WebSearch(x)"
        ));
    }

    #[test]
    fn tilde_without_principal_refused() {
        let yaml = "schema_version: 1\npermissions:\n  allow:\n    - \"Read(~/x)\"\n";
        assert!(matches!(
            parse_policy(yaml, None),
            Err(AuthzError::TildeWithoutPrincipal(p)) if p == "~/x"
        ));
    }

    #[test]
    fn tilde_other_user_is_bad_pattern() {
        let yaml = "schema_version: 1\npermissions:\n  allow:\n    - \"Read(~alice/x)\"\n";
        assert!(matches!(
            parse_policy(yaml, Some(&home())),
            Err(AuthzError::BadPattern(_))
        ));
    }

    #[test]
    fn read_relative_pattern_without_tilde_or_slash_is_bad_pattern() {
        let yaml = "schema_version: 1\npermissions:\n  allow:\n    - \"Read(relative/x)\"\n";
        assert!(matches!(
            parse_policy(yaml, Some(&home())),
            Err(AuthzError::BadPattern(_))
        ));
    }

    #[test]
    fn read_absolute_pattern_parses() {
        let yaml = "schema_version: 1\npermissions:\n  allow:\n    - \"Read(/etc/passwd)\"\n";
        let policy = parse_policy(yaml, Some(&home())).unwrap();
        match &policy.allow[0] {
            Pattern::Read(glob) => assert!(glob.matches(Path::new("/etc/passwd"))),
            other => panic!("expected Pattern::Read, got {other:?}"),
        }
    }

    #[test]
    fn pattern_missing_open_paren_is_bad_pattern() {
        let yaml = "schema_version: 1\npermissions:\n  allow:\n    - \"ReadNoParens\"\n";
        assert!(matches!(
            parse_policy(yaml, Some(&home())),
            Err(AuthzError::BadPattern(_))
        ));
    }

    #[test]
    fn pattern_missing_close_paren_is_bad_pattern() {
        let yaml = "schema_version: 1\npermissions:\n  allow:\n    - \"Read(~/x\"\n";
        assert!(matches!(
            parse_policy(yaml, Some(&home())),
            Err(AuthzError::BadPattern(_))
        ));
    }

    #[test]
    fn bash_empty_tokens_is_bad_pattern() {
        let yaml = "schema_version: 1\npermissions:\n  allow:\n    - \"Bash()\"\n";
        assert!(matches!(
            parse_policy(yaml, Some(&home())),
            Err(AuthzError::BadPattern(_))
        ));
    }

    #[test]
    fn permissions_not_a_map_is_yaml_error() {
        let yaml = "schema_version: 1\npermissions: 5\n";
        assert!(matches!(
            parse_policy(yaml, Some(&home())),
            Err(AuthzError::Yaml(_))
        ));
    }

    #[test]
    fn allow_not_a_sequence_is_yaml_error() {
        let yaml = "schema_version: 1\npermissions:\n  allow: 5\n";
        assert!(matches!(
            parse_policy(yaml, Some(&home())),
            Err(AuthzError::Yaml(_))
        ));
    }

    #[test]
    fn allow_entry_not_a_string_is_yaml_error() {
        let yaml = "schema_version: 1\npermissions:\n  allow:\n    - 5\n";
        assert!(matches!(
            parse_policy(yaml, Some(&home())),
            Err(AuthzError::Yaml(_))
        ));
    }

    #[test]
    fn root_not_a_map_is_yaml_error() {
        assert!(matches!(
            parse_policy("- 1\n- 2\n", Some(&home())),
            Err(AuthzError::Yaml(_))
        ));
    }

    #[test]
    fn malformed_yaml_is_yaml_error() {
        assert!(matches!(
            parse_policy("schema_version: [1\n", Some(&home())),
            Err(AuthzError::Yaml(_))
        ));
    }

    #[test]
    fn permissions_absent_is_empty_policy() {
        let policy = parse_policy("schema_version: 1\n", Some(&home())).unwrap();
        assert!(policy.allow.is_empty());
        assert!(policy.deny.is_empty());
    }

    // ---- glob matching semantics (spec §7) ----

    fn read_glob(pattern: &str) -> PathGlob {
        match parse_pattern(&format!("Read({pattern})"), Some(&home())).unwrap() {
            Pattern::Read(g) => g,
            other => panic!("expected Read, got {other:?}"),
        }
    }

    #[test]
    fn double_star_matches_dotfiles() {
        let glob = read_glob("~/**");
        assert!(glob.matches(Path::new("/home/operator/.ssh/id_ed25519")));
    }

    #[test]
    fn literal_component_is_exact_not_prefix() {
        // A no-`*` component pattern must require EXACT component equality,
        // not merely a start-anchor with no end check — `component_matches`
        // splits on `*`, so a starless pattern is a single fragment where
        // `i == 0` and `i == last` coincide; the start/end anchor branches
        // must both apply to that one fragment (over-ALLOW otherwise).
        let glob = read_glob("/etc/passwd");
        assert!(glob.matches(Path::new("/etc/passwd")));
        assert!(!glob.matches(Path::new("/etc/passwdX")));
        assert!(!glob.matches(Path::new("/etc/passwd-backup")));
    }

    #[test]
    fn double_star_home_does_not_leak_prefix_sharing_user() {
        // principal home /home/operator (see `home()`); a DIFFERENT user
        // whose name merely shares the "operator" prefix — /home/operatorbot
        // — must NOT match `Read(~/**)`. Each path component ("operator" vs
        // "operatorbot") must be compared for exact equality, not prefix.
        let glob = read_glob("~/**");
        assert!(glob.matches(Path::new("/home/operator/.ssh/id_ed25519")));
        assert!(!glob.matches(Path::new("/home/operatorbot/.ssh/id_ed25519")));
    }

    #[test]
    fn double_star_matches_multiple_components_deep() {
        let glob = read_glob("~/**");
        assert!(glob.matches(Path::new("/home/operator/.ssh/nested/deep/file")));
    }

    #[test]
    fn x_slash_doublestar_matches_x_itself() {
        let glob = read_glob("~/.ssh/**");
        assert!(glob.matches(Path::new("/home/operator/.ssh")));
    }

    #[test]
    fn matching_is_byte_case_sensitive() {
        let glob = read_glob("~/.ssh/**");
        assert!(!glob.matches(Path::new("/home/operator/.SSH")));
        assert!(!glob.matches(Path::new("/home/operator/.SSH/id_rsa")));
    }

    #[test]
    fn literal_star_matches_within_component_only() {
        let glob = read_glob("~/*.txt");
        assert!(glob.matches(Path::new("/home/operator/foo.txt")));
        assert!(!glob.matches(Path::new("/home/operator/sub/foo.txt")));
    }

    #[test]
    fn read_pattern_does_not_match_unrelated_path() {
        let glob = read_glob("~/.ssh/**");
        assert!(!glob.matches(Path::new("/home/operator/.gnupg/pubring.kbx")));
    }

    #[test]
    fn non_utf8_candidate_path_never_matches() {
        use std::ffi::OsStr;
        use std::os::unix::ffi::OsStrExt;
        let glob = read_glob("~/**");
        let bad = OsStr::from_bytes(&[0x66, 0xff, 0x6f]);
        assert!(!glob.matches(Path::new(bad)));
    }

    #[test]
    fn non_utf8_principal_home_is_bad_pattern() {
        use std::ffi::OsStr;
        use std::os::unix::ffi::OsStrExt;
        let bad_home = OsStr::from_bytes(&[0x2f, 0xff, 0x2f]);
        assert!(matches!(
            PathGlob::parse("~/x", Some(Path::new(bad_home))),
            Err(AuthzError::BadPattern(_))
        ));
    }

    // ---- Bash argv matching (spec §7) ----

    #[test]
    fn bash_exact_vs_any_args() {
        let exact = Pattern::Bash {
            tokens: vec!["git".into(), "status".into()],
            any_args: false,
        };
        let any = Pattern::Bash {
            tokens: vec!["git".into(), "status".into()],
            any_args: true,
        };
        let argv = vec!["git".to_string(), "status".to_string(), "-v".to_string()];
        assert!(!exact.matches_req(&Request::Bash(&argv)));
        assert!(any.matches_req(&Request::Bash(&argv)));
    }

    #[test]
    fn bash_shorter_argv_is_denied_default() {
        let exact = Pattern::Bash {
            tokens: vec!["git".into(), "status".into()],
            any_args: false,
        };
        let argv = vec!["git".to_string()];
        assert!(!exact.matches_req(&Request::Bash(&argv)));
    }

    #[test]
    fn bash_exact_length_match_succeeds() {
        // Pins the `<` boundary in matches_req (argv.len() < tokens.len()):
        // argv EXACTLY as long as tokens, with every token equal, must match
        // even without `:*` — an off-by-one (`<=`) would wrongly reject this.
        let exact = Pattern::Bash {
            tokens: vec!["git".into(), "status".into()],
            any_args: false,
        };
        let argv = vec!["git".to_string(), "status".to_string()];
        assert!(exact.matches_req(&Request::Bash(&argv)));
    }

    #[test]
    fn bash_colon_star_parses_any_args() {
        match parse_pattern("Bash(git status:*)", None).unwrap() {
            Pattern::Bash { tokens, any_args } => {
                assert_eq!(tokens, vec!["git".to_string(), "status".to_string()]);
                assert!(any_args);
            }
            other => panic!("expected Bash, got {other:?}"),
        }
    }

    #[test]
    fn pattern_type_mismatch_never_matches() {
        let read = Pattern::Read(read_glob("~/**"));
        let bash = Pattern::Bash {
            tokens: vec!["git".into()],
            any_args: true,
        };
        let argv = vec!["git".to_string()];
        assert!(!read.matches_req(&Request::Bash(&argv)));
        assert!(!bash.matches_req(&Request::Read(Path::new("/home/operator/x"))));
    }

    // ---- evaluate: deny-wins, default-deny (spec §7) ----

    #[test]
    fn deny_beats_allow_and_default_deny() {
        let yaml = "schema_version: 1\npermissions:\n  allow:\n    - \"Read(~/**)\"\n  deny:\n    - \"Read(~/.ssh/**)\"\n";
        let policy = parse_policy(yaml, Some(&home())).unwrap();

        // deny beats allow: inside ~ AND inside the denied ~/.ssh subtree.
        let denied = Request::Read(Path::new("/home/operator/.ssh/id_rsa"));
        assert_eq!(policy.evaluate(&denied), Decision::Deny);

        // allowed: inside ~ but outside the deny list.
        let allowed = Request::Read(Path::new("/home/operator/docs/notes.txt"));
        assert_eq!(policy.evaluate(&allowed), Decision::Allow);

        // default-deny: matches neither list (outside the allow's ~ scope).
        let unmatched = Request::Read(Path::new("/etc/passwd"));
        assert_eq!(policy.evaluate(&unmatched), Decision::Deny);
    }

    #[test]
    fn empty_policy_permits_nothing() {
        let policy = AuthzPolicy::default();
        let req = Request::Read(Path::new("/home/operator/anything"));
        assert_eq!(policy.evaluate(&req), Decision::Deny);
    }

    // ---- AuthzError Display ----

    #[test]
    fn display_covers_every_variant() {
        let cases = vec![
            AuthzError::UnknownSchemaVersion(2),
            AuthzError::UnknownKey("denny".into()),
            AuthzError::BadPattern("WebSearch(x)".into()),
            AuthzError::TildeWithoutPrincipal("~/x".into()),
            AuthzError::InsecurePermissions,
            AuthzError::Symlink,
            AuthzError::NotRootOwned,
            AuthzError::Io("boom".into()),
            AuthzError::Yaml("bad shape".into()),
        ];
        for e in &cases {
            let s = format!("{e}");
            assert!(!s.is_empty(), "empty Display for {e:?}");
            let _: &dyn std::error::Error = e;
        }
    }

    // ---- owner-check pure helper (no filesystem / root needed) ----

    #[test]
    fn owner_check_helper_boundary() {
        assert!(assert_root_owned(0).is_ok());
        assert!(matches!(
            assert_root_owned(1),
            Err(AuthzError::NotRootOwned)
        ));
        assert!(matches!(
            assert_root_owned(65_534),
            Err(AuthzError::NotRootOwned)
        ));
    }

    // ---- secure load (cfg(unix)): symlink / mode / owner / io ----

    fn tmp(name: &str) -> std::path::PathBuf {
        std::env::temp_dir().join(format!("maknae_authz_{}_{name}", std::process::id()))
    }

    fn write_mode(path: &Path, body: &str, mode: u32) {
        use std::io::Write;
        use std::os::unix::fs::PermissionsExt;
        let mut f = std::fs::File::create(path).unwrap();
        f.write_all(body.as_bytes()).unwrap();
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(mode)).unwrap();
    }

    #[test]
    fn symlink_authz_refused() {
        let target = tmp("sl_target");
        let link = tmp("sl_link");
        write_mode(&target, SHIPPED_DEFAULT, 0o640);
        let _ = std::fs::remove_file(&link);
        std::os::unix::fs::symlink(&target, &link).unwrap();
        let got = load_authz(&link, Some(&home()));
        let _ = std::fs::remove_file(&link);
        let _ = std::fs::remove_file(&target);
        assert!(matches!(got, Err(AuthzError::Symlink)));
    }

    #[test]
    fn world_accessible_authz_refused() {
        let p = tmp("world");
        write_mode(&p, SHIPPED_DEFAULT, 0o666);
        let got = load_authz(&p, Some(&home()));
        let _ = std::fs::remove_file(&p);
        assert!(matches!(got, Err(AuthzError::InsecurePermissions)));
    }

    #[test]
    fn non_root_owned_authz_refused() {
        let p = tmp("nonroot");
        write_mode(&p, SHIPPED_DEFAULT, 0o640);
        // Best-effort: if this test process happens to run as root (uid 0),
        // chown the file away from 0 (root may chown to any uid) so the
        // scenario — an authz.yaml NOT owned by root — is reproduced either
        // way, without requiring a #[ignore]-gated privileged test.
        let _ = std::os::unix::fs::chown(&p, Some(65_534), None);
        let got = load_authz(&p, Some(&home()));
        let _ = std::fs::remove_file(&p);
        assert!(matches!(got, Err(AuthzError::NotRootOwned)));
    }

    #[test]
    fn missing_authz_file_is_io() {
        let got = load_authz(&tmp("nope_never_created"), Some(&home()));
        assert!(matches!(got, Err(AuthzError::Io(_))));
    }

    #[test]
    fn security_load_succeeds_with_injected_root_owner() {
        // `load_authz` can never observe a genuinely root-owned fixture file
        // without real root privilege — so the SUCCESS arm of `security_load`
        // (symlink refusal + mode gate both pass, owner check passes) is
        // pinned here via the injected `owner_of` seam instead: same function,
        // same code path, a deterministic stand-in only for "what uid does
        // this path resolve to".
        let p = tmp("owner_injected_ok");
        write_mode(&p, SHIPPED_DEFAULT, 0o640);
        let got = security_load(&p, |_| Ok(0));
        let _ = std::fs::remove_file(&p);
        assert_eq!(got.unwrap(), SHIPPED_DEFAULT);
    }

    #[test]
    fn security_load_propagates_owner_of_io_error() {
        let p = tmp("owner_of_io_err");
        write_mode(&p, SHIPPED_DEFAULT, 0o640);
        let got = security_load(&p, |_| Err(std::io::Error::other("boom")));
        let _ = std::fs::remove_file(&p);
        assert!(matches!(got, Err(AuthzError::Io(m)) if m.contains("boom")));
    }

    #[test]
    fn real_owner_of_matches_symlink_metadata() {
        let p = tmp("real_owner_of");
        write_mode(&p, SHIPPED_DEFAULT, 0o640);
        use std::os::unix::fs::MetadataExt;
        let want = std::fs::symlink_metadata(&p).unwrap().uid();
        let got = real_owner_of(&p).unwrap();
        let _ = std::fs::remove_file(&p);
        assert_eq!(got, want);
    }

    // ---- glob matching: remaining state-machine edges ----

    #[test]
    fn double_star_mid_pattern_requires_a_trailing_component() {
        // `**` between two literals must still consume components until the
        // literal AFTER it is satisfied; running out of path before that
        // literal is found is a non-match (match_segs's DoubleStar `None`
        // arm — comps exhausted without ever matching `id_rsa`).
        let glob = read_glob("~/**/id_rsa");
        assert!(!glob.matches(Path::new("/home/operator")));
        assert!(!glob.matches(Path::new("/home/operator/.ssh")));
        assert!(glob.matches(Path::new("/home/operator/id_rsa")));
        assert!(glob.matches(Path::new("/home/operator/.ssh/id_rsa")));
    }

    #[test]
    fn component_trailing_star_matches_zero_or_more() {
        // A literal component ending in `*` (not the whole-segment `**`):
        // the last fragment is empty (nothing follows the trailing `*`), so
        // only the start-anchor check applies.
        let glob = read_glob("~/foo*");
        assert!(glob.matches(Path::new("/home/operator/foo")));
        assert!(glob.matches(Path::new("/home/operator/foobar")));
        assert!(!glob.matches(Path::new("/home/operator/fo")));
    }

    #[test]
    fn component_start_anchor_rejects_literal_appearing_later() {
        // `a*c` (no leading `*`) requires text to START with `a` literally —
        // `a` merely APPEARING somewhere in the text is not enough. Pins the
        // `i == 0` / `!starts_with('*')` guard against both an `==`→`!=` (or
        // `delete !`) mutation, which would relax this to "found anywhere".
        let glob = read_glob("~/a*c");
        assert!(!glob.matches(Path::new("/home/operator/Xac")));
        assert!(glob.matches(Path::new("/home/operator/aXc")));
    }

    #[test]
    fn component_end_anchor_rejects_literal_appearing_earlier() {
        // `a*c` (no trailing `*`) requires text to END with `c` literally —
        // `c` appearing mid-string is not enough. Pins the `i == last` /
        // `!ends_with('*')` guard the same way as the start-anchor test above.
        let glob = read_glob("~/a*c");
        assert!(!glob.matches(Path::new("/home/operator/acX")));
    }

    #[test]
    fn component_middle_fragment_requires_a_gap_anchored_neither_end() {
        // Three fragments (`abc` / `def` / `ghi`): pins `last = fragments.len()
        // - 1` (a 3-fragment pattern is the smallest case where `- 1` differs
        // observably from `+ 1` / `/ 1`), the `&&`-not-`||` composition of the
        // start/end anchor guards (a `||` would wrongly anchor the MIDDLE
        // fragment too), and the `pos += offset + frag.len()` bookkeeping the
        // middle (non-anchored) `find` branch depends on — chosen with a
        // real, non-trivial gap so `+`/`-`/`*` corruptions of that expression
        // land on a visibly different (or underflow-panicking) position.
        let glob = read_glob("~/abc*def*ghi");
        assert!(glob.matches(Path::new("/home/operator/abcZZdefWWWghi")));
        assert!(!glob.matches(Path::new("/home/operator/abcZZdeXWWWghi")));
    }

    #[test]
    fn component_start_anchor_advance_prevents_decoy_middle_match() {
        // `abxy*xy*z`: the start-anchor fragment "abxy" itself CONTAINS "xy"
        // as a substring. If `pos` were not correctly advanced (`pos +=
        // frag.len()`) past the anchored prefix before searching for the
        // middle "xy" fragment, that search would spuriously match the
        // DECOY "xy" inside "abxy" instead of correctly failing to find
        // "xy" anywhere after it (there is none) — an end-anchor check on
        // its own can't pin this: whether text ends in "z" doesn't depend
        // on `pos`, only a downstream `find` being fooled does.
        let glob = read_glob("~/abxy*xy*z");
        assert!(!glob.matches(Path::new("/home/operator/abxyPPPz")));
    }

    #[test]
    fn component_middle_offset_arithmetic_lands_exactly_at_the_final_fragment() {
        // `abc*xy*ghi` against a text engineered so the middle fragment's
        // offset (5) and length (2) diverge meaningfully under `+` vs `*`:
        // correct pos = 3 + (5 + 2) = 10, landing exactly at "ghi"; a `+`→`*`
        // corruption gives 3 + (5 * 2) = 13 == the text's length, overrunning
        // straight past "ghi" so the end-anchor check sees an empty slice
        // instead — pins `pos += offset + frag.len()` in the middle branch.
        let glob = read_glob("~/abc*xy*ghi");
        assert!(glob.matches(Path::new("/home/operator/abcZZZZZxyghi")));
    }
}
