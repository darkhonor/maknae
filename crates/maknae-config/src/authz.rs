//! Capability-grant policy schema v1 (spec §7, PR-J1 Task 6) — the
//! Claude-Code/Codex-style capability grammar (`Read(...)`) the per-request PDP
//! evaluates. This module ships and VALIDATES the contract: parse, fail-closed
//! validation, and the matching grammar as an executable pin.
//!
//! **Vocabulary (ADR-0020, CNSSI 4009-aligned).** This is the *capability-grant
//! policy*. In CNSSI 4009 terms it is **discretionary in policy type**, and it
//! is **decided by RBAC** (`maknae-authz-basic`) — policy type and decision
//! model are orthogonal axes, not synonyms. It was formerly called "the DAC
//! authz policy", which collided with **OS DAC** (file permissions and ACLs,
//! the thing ADR-0009's descriptor delegation asks the kernel about). Two
//! different controls, one label; renamed 2026-08-31 per #108. Where this tree
//! says "OS DAC" it means file permissions; where it says "capability-grant
//! policy" it means this file.
//!
//! *(Corrected 2026-08-31: the header previously said a "FUTURE per-request
//! PDP" evaluates this and that evaluation "does not wire into any request path
//! yet". Superseded by #77 — every request is decided through the
//! `maknae-security` seam, and the shipped deny list is enforced on the `Read`
//! verb's PEP.)*
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

use crate::Value;
use std::path::Path;

// ============================================================================
// Public policy schema
// ============================================================================

/// One role's action grants as they appear on disk (#162): the `allow` and
/// `deny` lists under `roles.<name>.actions`. **Raw strings, deliberately** —
/// whether `"admin"` names a real role and whether `"admin.status"` names a
/// real term are `maknae-authz-basic`'s questions, and answering them here
/// would put policy semantics in the parser. This crate owns grammar.
#[derive(Clone, Debug, PartialEq, Eq, Default)]
pub struct RawActionGrants {
    pub allow: Vec<String>,
    pub deny: Vec<String>,
}

/// The parsed `permissions:` wrapper (spec §7): an allow list and a deny list
/// of patterns. Deny beats allow; anything matching neither is denied
/// (default-deny) — see [`AuthzPolicy::evaluate`].
#[derive(Clone, Debug, PartialEq, Eq, Default)]
pub struct AuthzPolicy {
    pub allow: Vec<Pattern>,
    pub deny: Vec<Pattern>,
    /// Role → member-identity lists from the additive `bindings:` key (#85).
    /// `None` = key ABSENT (defaults apply); `Some` — even empty — = key
    /// PRESENT (defaults suppressed entirely; spec §3 precedence). Raw strings:
    /// role-name semantics belong to `maknae-authz-basic`, never this crate
    /// (grammar, not decision).
    pub bindings: Option<std::collections::BTreeMap<String, Vec<String>>>,
    /// Original entry text for each `allow`/`deny` pattern, index-aligned
    /// (#85): [`AuthzPolicy::evaluate3`] reports WHICH deny entry matched for
    /// the audit record. Private — provenance is not a matching input, and
    /// keeping it un-constructible outside the parser means the pair can
    /// never drift out of alignment.
    /// Role → action-term grants from the additive `roles:` key (#162).
    /// **A plain map, NOT an `Option`** — unlike `bindings`, an absent `roles:`
    /// and an empty one behave identically under the additivity ruling, so an
    /// `Option` would make the `None`↔`Some(empty)` mutant undetectable by
    /// construction: reported MISSED with no killable test available, and the
    /// T1 zero-missed gate goes red with nothing to write.
    pub action_grants: std::collections::BTreeMap<String, RawActionGrants>,
    allow_sources: Vec<String>,
    deny_sources: Vec<String>,
}

/// [`AuthzPolicy::evaluate3`]'s answer (#85): three-valued where
/// [`Decision`] is two-valued — the PDP backend maps `NoMatch` to
/// `NotApplicable` (deny-by-default happens at `finalize`, with the reason
/// "no grant" distinguishable from "explicit deny").
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Match3 {
    AllowMatch,
    DenyMatch { source: String },
    NoMatch,
}

/// A single request the (future) PDP asks the policy about.
#[derive(Clone, Copy, Debug)]
pub enum Request<'a> {
    Read(&'a Path),
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

    /// Three-valued evaluation with deny provenance (#85, spec §6a.1). Deny
    /// checked first (deny-overrides within the operand, same order as
    /// [`AuthzPolicy::evaluate`]); the matched deny entry's ORIGINAL text
    /// rides in `source` for the audit record (audit-only — never onto the
    /// wire, spec §4.4). Reuses the same private matcher as `evaluate` — no
    /// second matching implementation exists to drift.
    pub fn evaluate3(&self, req: &Request<'_>) -> Match3 {
        if let Some(i) = self.deny.iter().position(|p| p.matches_req(req)) {
            return Match3::DenyMatch {
                source: self
                    .deny_sources
                    .get(i)
                    .cloned()
                    .unwrap_or_else(|| "<unknown deny entry>".into()),
            };
        }
        if self.allow.iter().any(|p| p.matches_req(req)) {
            return Match3::AllowMatch;
        }
        Match3::NoMatch
    }
}

/// One `Capability(specifier)` entry (spec §7). v1 capabilities: `Read`,
/// `Read` only — any other capability name is `AuthzError::BadPattern`.
/// `Bash` was RETIRED by #67 in favour of the `terminal.*` action class: it was a
/// second way to express execution authority, and argv matching is a
/// categorically harder problem than the path globs this grammar was built for.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Pattern {
    Read(PathGlob),
}

impl Pattern {
    fn matches_req(&self, req: &Request<'_>) -> bool {
        // Both enums are single-variant since `Bash` was retired (#67), so this
        // destructure is irrefutable. It regains a `match` the moment the
        // non-resource capability form D3 requires lands.
        let (Pattern::Read(glob), Request::Read(path)) = (self, req);
        glob.matches(path)
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

/// Fail-closed error for the capability-grant policy (spec §7). Span-free by design
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
    /// non-absolute `Read` glob, unknown capability name, …).
    BadPattern(String),
    /// A pattern used `~` but no principal is enrolled to resolve it against.
    TildeWithoutPrincipal(String),
    /// `authz.yaml` is world/other-accessible OR writable by group/other
    /// (spec §4.6/§7 — the refusal mask is `0o027`, both halves).
    ///
    /// World/other-accessible: ANY other-class bit (`0o007` — read, write, or
    /// execute) exposes the capability-grant policy to every local account; the shipped
    /// mode is `0640`, which grants nothing to `other`.
    ///
    /// Group/other-writable (`0o022`): `authz.yaml` is `root:_maknae` and the
    /// daemon runs as `_maknae`, whose primary group is `_maknae` — a
    /// group-writable file lets a compromised daemon rewrite its own grants
    /// policy even though root ownership and a world-bit-only gate both pass.
    /// Group READ is deliberately permitted, so the daemon can read it.
    InsecurePermissions,
    /// `authz.yaml` (or a path component) is a symlink — refused.
    Symlink,
    /// `authz.yaml` is not owned by root (uid 0) — spec §4.6/§7: root
    /// ownership is the control that stops a compromised `_maknae` from
    /// widening its own grants by editing this file.
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
            AuthzError::InsecurePermissions => {
                write!(
                    f,
                    "authz.yaml has insecure permissions: world/other-accessible or group/other-writable"
                )
            }
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
        _ => Err(bad()),
    }
}

/// A `bindings:` member list: a sequence of strings, refused otherwise with a
/// bindings-specific message (NOT `str_seq`'s "permissions list…" text — an
/// operator debugging a bindings typo must not be sent to the wrong section).
fn bindings_member_list(v: &Value) -> Result<Vec<String>, AuthzError> {
    match v {
        Value::Seq(items) => items
            .iter()
            .map(|item| match item {
                Value::Str(s) => Ok(s.clone()),
                _ => Err(AuthzError::Yaml(
                    "bindings member entries must be strings (quote every name; spec §3)".into(),
                )),
            })
            .collect(),
        _ => Err(AuthzError::Yaml(
            "bindings member list must be a sequence (write `role: []` for empty)".into(),
        )),
    }
}

/// A `roles.<name>.actions.{allow,deny}` term list: a sequence of strings,
/// refused otherwise with a roles-specific message. **Not `str_seq`** — whose
/// text reads "permissions list entries must be strings" and would send an
/// operator debugging a `roles:` typo to the wrong section of the file. Same
/// reasoning as [`bindings_member_list`], and the same reason it is a third
/// function rather than a shared one with a passed-in noun: the message is the
/// diagnostic, so it is written out where a reader can see it.
fn roles_term_list(v: &Value) -> Result<Vec<String>, AuthzError> {
    match v {
        Value::Seq(items) => items
            .iter()
            .map(|item| match item {
                Value::Str(s) => Ok(s.clone()),
                _ => Err(AuthzError::Yaml(
                    "roles action entries must be strings (quote every term; #162)".into(),
                )),
            })
            .collect(),
        _ => Err(AuthzError::Yaml(
            "roles action list must be a sequence (write `allow: []` for empty)".into(),
        )),
    }
}

/// Public pure parse (#85, spec §6a.3): already-read authz YAML text →
/// [`AuthzPolicy`], no file I/O and no ownership requirement — the hermetic
/// door for the PDP backend's proofs. Production loading stays [`load_authz`]
/// (root-owned, hardened path); this function never touches the filesystem.
pub fn parse_authz(body: &str, principal_home: Option<&Path>) -> Result<AuthzPolicy, AuthzError> {
    parse_policy(body, principal_home)
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
    check_known_keys(&map, &["schema_version", "permissions", "bindings", "roles"])?;

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

    let bindings = match get(&map, "bindings") {
        None => None,
        Some(Value::Map(bm)) => {
            let mut out = std::collections::BTreeMap::new();
            for (role, members) in bm {
                out.insert(role.clone(), bindings_member_list(members)?);
            }
            Some(out)
        }
        Some(_) => {
            return Err(AuthzError::Yaml(
                "bindings section must be a map of role to member list".into(),
            ))
        }
    };

    let action_grants = match get(&map, "roles") {
        None => std::collections::BTreeMap::new(),
        Some(Value::Map(rm)) => {
            let mut out = std::collections::BTreeMap::new();
            for (role, body) in rm {
                // A bare `admin:` parses Null, not an empty map. Refuse rather
                // than silently treating it as "no grants" — fail-closed, and
                // the same stance `bindings` takes on a bare member list.
                let rb = match body {
                    Value::Map(m) => m,
                    _ => {
                        return Err(AuthzError::Yaml(
                            "roles entries must be a map with an `actions` key".into(),
                        ))
                    }
                };
                check_known_keys(rb, &["actions"])?;
                let (allow, deny) = match get(rb, "actions") {
                    None => (Vec::new(), Vec::new()),
                    Some(Value::Map(am)) => {
                        check_known_keys(am, &["allow", "deny"])?;
                        let allow = get(am, "allow")
                            .map(roles_term_list)
                            .transpose()?
                            .unwrap_or_default();
                        let deny = get(am, "deny")
                            .map(roles_term_list)
                            .transpose()?
                            .unwrap_or_default();
                        (allow, deny)
                    }
                    Some(_) => {
                        return Err(AuthzError::Yaml(
                            "roles actions section must be a map of allow/deny".into(),
                        ))
                    }
                };
                out.insert(role.clone(), RawActionGrants { allow, deny });
            }
            out
        }
        Some(_) => {
            return Err(AuthzError::Yaml(
                "roles section must be a map of role to action grants".into(),
            ))
        }
    };

    Ok(AuthzPolicy {
        allow,
        deny,
        bindings,
        action_grants,
        allow_sources: allow_raw,
        deny_sources: deny_raw,
    })
}

// ============================================================================
// Secure load (spec §4.6/§7)
// ============================================================================

/// Pure owner-check boundary, factored out so it is unit-testable without
/// filesystem access or root privilege (mirrors the mode-mask precedent in
/// `loader.rs::mode_is_secure`).
#[cfg(unix)]
fn authz_target_required() -> maknae_io::TargetRequired {
    maknae_io::TargetRequired {
        owner: Some(0),
        // 0o027 = 0o007 (ANY other/world access: read, write, or execute)
        // | 0o022 (group- or other-WRITE). Composed, not either alone.
        //
        // The failure that motivated restoring it (issue #129, review of PR
        // #128): the pre-#128 loader refused on `mode & 0o007 != 0` AND on
        // `mode & 0o022 != 0`, an effective 0o027. The maknae-io migration
        // named only 0o022 here, dropping the world-any half — so a
        // root-owned but world-READABLE `authz.yaml` (0644, 0604) loaded at
        // boot where it had previously been refused, exposing the capability-grant policy
        // to every local account. Group READ stays permitted on purpose:
        // spec §4.6 ships `root:_maknae 0640` and the daemon must read it.
        mode_mask: Some(0o027),
        nlink_exactly_one: false,
        regular_file: true,
        max_bytes: None,
    }
}

/// Read `authz.yaml` through a pinned [`maknae_io`] anchor with an explicit
/// root-owner requirement and a `mode & 0o027 == 0` target requirement. Root
/// ownership stops a compromised `_maknae` process from replacing its own
/// policy; the mode mask separately rejects world/other-accessible policy
/// (`0o007`) and group- or other-writable policy (`0o022`).
///
/// The world-any half keeps the capability-grant policy unreadable to every local account
/// — a root-owned `0644` is not writable by anyone but root, yet publishes
/// the policy. The group-write half closes a gap the two controls above leave
/// open: `authz.yaml` is `root:_maknae` (spec §4.6), and the daemon runs as
/// `_maknae`, whose primary group is `_maknae` — so `root:_maknae 0660` is
/// root-owned but still writable by the daemon's group. Spec §4.6's shipped
/// mode is `0640`, which deliberately permits group read. `maknae-io` checks
/// ownership, type, mode, and the bytes read against the same opened inode.
///
/// One function with an INLINE `#[cfg(unix)]`/`#[cfg(not(unix))]` split
/// (mirrors `loader.rs::load_config`'s idiom), not two separate `fn` items —
/// a standalone `#[cfg(not(unix))] fn security_load` would still exist as
/// its own mutation target on a unix build even though its body never
/// compiles in, which is not exercisable/killable on a unix CI runner and
/// would report as a permanently-missed mutant for dead code.
fn security_load(path: &Path) -> Result<String, AuthzError> {
    #[cfg(not(unix))]
    {
        // The permission/ownership model this control depends on is
        // unavailable on this target — refuse to load rather than proceed
        // unchecked (fail-closed). Not exercisable on a unix CI runner,
        // hence no mutation/coverage obligation on this arm.
        let _ = path;
        return Err(AuthzError::Io(
            "authz permission enforcement is unavailable on this platform; refusing to load".into(),
        ));
    }
    #[cfg(unix)]
    {
        // Absolutization, parent pinning and the anchor-relative open all live in
        // `maknae_io::read_absolute` (issue #137). The copy that stood here was one
        // of three identical hand-rolled adapters; what remains is this module's
        // error mapping and UTF-8 decode. Directory traversal and replacement
        // authority come from the current process's OS DAC rights — named inside
        // the adapter — while the opened policy inode is separately required to
        // remain root-owned by `authz_target_required()`.
        security_load_required(path, authz_target_required())
    }
}

/// [`security_load`]'s unix body with the artifact requirement supplied by the
/// caller instead of fixed at [`authz_target_required`]. Crate-private (the
/// `load_required_file` property, issue #138/PR #139: nothing outside this
/// crate can choose a weaker requirement) — the ONLY external door is the
/// non-default `hermetic-test-seam` feature below, which production consumers
/// never enable.
#[cfg(unix)]
fn security_load_required(
    path: &Path,
    target: maknae_io::TargetRequired,
) -> Result<String, AuthzError> {
    let bytes = maknae_io::read_absolute(path, target, maknae_io::StrategyPref::Auto)
        .map_err(map_authz_io)?
        .value;
    decode_policy_utf8(&bytes)
}

/// Hermetic-test seam (#85 spec §6a.4): [`load_authz`] with a caller-supplied
/// artifact requirement, so a PDP-backend test can drive the IDENTICAL
/// load→parse path against a fixture its own euid genuinely owns. Exists only
/// under the non-default `hermetic-test-seam` feature; `load_authz` itself
/// still hardcodes the root-owned requirement and a CI check pins the daemon's
/// normal-dependency feature resolution to exclude this.
#[cfg(all(unix, feature = "hermetic-test-seam"))]
pub fn load_authz_with_requirement(
    path: &Path,
    target: maknae_io::TargetRequired,
    principal_home: Option<&Path>,
) -> Result<AuthzPolicy, AuthzError> {
    let body = security_load_required(path, target)?;
    parse_policy(&body, principal_home)
}

/// Decode the bytes `maknae-io` returned for `authz.yaml` as UTF-8.
///
/// Split out of [`security_load`] as its own item because it is the only part
/// of that function reachable without a genuinely root-owned fixture: the
/// target requirement is `owner: Some(0)`, which an unprivileged test process
/// cannot satisfy and must not be given a seam to fake (the injected-owner
/// stand-in this module used before the `maknae-io` adoption is exactly what
/// that adoption removed). As a free function it is the REAL decoder under
/// test — both arms exercised directly — rather than a stubbed stand-in.
#[cfg(unix)]
fn decode_policy_utf8(bytes: &[u8]) -> Result<String, AuthzError> {
    std::str::from_utf8(bytes)
        .map(str::to_owned)
        .map_err(|e| AuthzError::Io(format!("invalid UTF-8: {e}")))
}

#[cfg(unix)]
fn map_authz_io(e: maknae_io::IoError) -> AuthzError {
    match e {
        maknae_io::IoError::Symlink { .. } => AuthzError::Symlink,
        maknae_io::IoError::InsecurePermissions { .. } => AuthzError::InsecurePermissions,
        maknae_io::IoError::NotOwned { .. } => AuthzError::NotRootOwned,
        other => AuthzError::Io(other.to_string()),
    }
}

/// Load and validate `/etc/maknae/authz.yaml` (spec §5.4/§7): secure read +
/// root-ownership assertion, then fail-closed grammar validation. `~` in any
/// pattern resolves against `principal_home` (spec §7's enrolled operator).
pub fn load_authz(path: &Path, principal_home: Option<&Path>) -> Result<AuthzPolicy, AuthzError> {
    let body = security_load(path)?;
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
        // `Pattern` is single-variant since `Bash` was retired (#67), so this
        // destructure is irrefutable; it regains a `match` when the
        // non-resource capability form D3 requires lands.
        let Pattern::Read(glob) = &policy.allow[0];
        assert!(glob.matches(Path::new("/etc/passwd")));
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

    /// `Bash` was RETIRED by #67 in favour of the `terminal.*` action class. A
    /// policy still carrying it is a fail-closed BOOT REFUSAL, not a silently
    /// ignored line — nothing shipped uses it, so the break costs nothing now
    /// and prevents a second execution-authority vocabulary later.
    #[test]
    fn the_retired_bash_capability_is_refused_at_parse() {
        for spec in ["Bash(ls)", "Bash(git status:*)", "Bash()"] {
            let yaml = format!("schema_version: 1\npermissions:\n  allow:\n    - \"{spec}\"\n");
            assert!(
                matches!(
                    parse_policy(&yaml, Some(&home())),
                    Err(AuthzError::BadPattern(_))
                ),
                "{spec} must be refused as an unknown capability"
            );
        }
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
        let Pattern::Read(g) = parse_pattern(&format!("Read({pattern})"), Some(&home())).unwrap();
        g
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
    fn authz_target_contract_is_root_owned_not_world_accessible_not_group_writable() {
        let req = authz_target_required();
        assert_eq!(req.owner, Some(0));
        // 0o027 = 0o007 (ANY world/other access) | 0o022 (group/other write).
        // PR #128 named only 0o022 here, which let a root-owned WORLD-READABLE
        // authz.yaml (0644, 0604) load where it was refused at boot before.
        assert_eq!(req.mode_mask, Some(0o027));
        assert!(req.regular_file);
        assert!(!req.nlink_exactly_one);
    }

    #[test]
    fn authz_mask_admits_shipped_0640_and_refuses_world_readable_modes() {
        // Shipped-mode compatibility (spec §4.6): `root:_maknae 0640` — group
        // READ is required so the daemon (`_maknae`) can read its own policy —
        // must still satisfy the mask, while every world-accessible and
        // group/other-writable mode must violate it. Pinned against the mask
        // itself because a root-owned fixture cannot be created unprivileged.
        let mask = authz_target_required().mode_mask.unwrap();
        assert_eq!(0o640 & mask, 0, "shipped 0640 must remain loadable");
        assert_eq!(0o600 & mask, 0, "0600 must remain loadable");
        for refused in [0o644, 0o604, 0o641, 0o660, 0o620, 0o666] {
            assert_ne!(refused & mask, 0, "mode {refused:o} must be refused");
        }
    }

    // ---- secure load (cfg(unix)): symlink / mode / owner / io ----

    fn tmp(name: &str) -> std::path::PathBuf {
        use std::os::unix::fs::PermissionsExt;

        let dir = std::env::temp_dir().join(format!("maknae_authz_{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o700)).unwrap();
        dir.join(name)
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
    fn policy_bytes_decode_as_utf8() {
        // The success arm of the real decoder — unreachable through
        // `security_load` without a root-owned fixture, so exercised here
        // directly rather than through a stand-in.
        assert_eq!(
            decode_policy_utf8(SHIPPED_DEFAULT.as_bytes()).unwrap(),
            SHIPPED_DEFAULT
        );
    }

    #[test]
    fn non_utf8_policy_bytes_are_io_error() {
        // A lone 0xFF is not valid UTF-8 in any position — a binary or
        // mis-encoded authz.yaml must be refused, not lossily decoded.
        assert!(matches!(
            decode_policy_utf8(&[0x73, 0xff, 0x3a]),
            Err(AuthzError::Io(_))
        ));
    }

    #[test]
    fn missing_authz_file_is_io() {
        let got = load_authz(&tmp("nope_never_created"), Some(&home()));
        assert!(matches!(got, Err(AuthzError::Io(_))));
    }

    #[test]
    fn shipped_0640_mode_passes_the_mask_and_is_refused_only_for_ownership() {
        // End-to-end shipped-mode compatibility (spec §4.6 `root:_maknae
        // 0640`): an unprivileged test cannot create a root-owned fixture, so
        // the strongest available pin is that a 0640 file gets PAST the mode
        // gate and is refused by the OWNER check instead. `maknae-io`'s
        // `check_target` runs mode BEFORE owner (checks.rs), so `NotRootOwned`
        // here proves the mask admitted 0640 — a mask that wrongly refused
        // group-read (e.g. 0o077, or 0o027|0o040) would surface
        // `InsecurePermissions` and fail this test, which is how the daemon
        // keeps being able to read its own policy.
        let p = tmp("shipped_0640");
        write_mode(&p, SHIPPED_DEFAULT, 0o640);
        let _ = std::os::unix::fs::chown(&p, Some(65_534), None); // no-op unless root
        let got = security_load(&p);
        let _ = std::fs::remove_file(&p);
        assert!(
            matches!(got, Err(AuthzError::NotRootOwned)),
            "0640 must clear the mode mask and stop at the owner check, got {got:?}"
        );
    }

    #[test]
    fn group_writable_root_owned_authz_refused() {
        // The finding this test pins: `root:_maknae 0660` is root-owned and
        // has no world bits, but the daemon's group can rewrite it. The
        // group-write bit must reject it.
        let p = tmp("group_writable");
        write_mode(&p, SHIPPED_DEFAULT, 0o660);
        let got = security_load(&p);
        let _ = std::fs::remove_file(&p);
        assert!(matches!(got, Err(AuthzError::InsecurePermissions)));
    }

    #[test]
    fn world_readable_non_writable_authz_refused() {
        // THIS is the hermetic form of the issue-#129 regression pin, and since
        // issue #138 it is the only one. A sibling test reproduced the same verdict
        // against a real `/etc/hosts` — root-owned `0644` on a stock host — which
        // made a security control depend on host state: a runner shipping a
        // different mode or owner (a hardened image, a container with a rewritten
        // hosts file) either failed for a reason unrelated to the control or passed
        // without exercising it. Neither outcome says anything about the mask. The
        // fixture below refuses for exactly the same reason, from bytes this test
        // wrote itself.
        //
        // Issue #129: `0644` is NOT group/other-writable, so a 0o022-only mask
        // admits it — a world-readable capability-grant policy loaded at boot where the
        // pre-PR-#128 gate (world-any + group/other-write) refused it. The
        // fixture is owned by the test user, not root, so this test can only
        // discriminate because `maknae-io`'s `check_target` pins the order
        // symlink -> regular-file -> MODE -> owner -> nlink (checks.rs): mode
        // fires before ownership, so a too-permissive mask surfaces as
        // `NotRootOwned` and a correct 0o027 mask as `InsecurePermissions`.
        let p = tmp("world_readable");
        write_mode(&p, SHIPPED_DEFAULT, 0o644);
        let got = security_load(&p);
        let _ = std::fs::remove_file(&p);
        assert!(
            matches!(got, Err(AuthzError::InsecurePermissions)),
            "0644 authz.yaml must be refused for insecure permissions, got {got:?}"
        );
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

    // ---- hermetic-test seam (#85 §6a.4): feature-gated, door unweakened ----

    #[cfg(all(unix, feature = "hermetic-test-seam"))]
    #[test]
    fn seam_loads_euid_owned_fixture_and_production_door_still_refuses_it() {
        use std::os::unix::fs::PermissionsExt;
        let dir = std::env::temp_dir().join(format!("maknae_authz_seam_{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o700)).unwrap();
        let p = dir.join("authz.yaml");
        std::fs::write(&p, SHIPPED_DEFAULT).unwrap();
        std::fs::set_permissions(&p, std::fs::Permissions::from_mode(0o640)).unwrap();

        let relaxed = maknae_io::TargetRequired {
            owner: None,
            mode_mask: Some(0o022),
            nlink_exactly_one: false,
            regular_file: true,
            max_bytes: None,
        };
        let via_seam = load_authz_with_requirement(&p, relaxed, Some(&home()));
        let via_door = load_authz(&p, Some(&home()));
        let _ = std::fs::remove_dir_all(&dir);

        let policy = via_seam.expect("seam loads a fixture the current euid owns");
        assert_eq!(policy.allow.len(), 1);
        // The PRODUCTION door on the same fixture must still demand root
        // ownership — proves adding the seam weakened nothing.
        assert!(
            matches!(via_door, Err(AuthzError::NotRootOwned)),
            "production load_authz must refuse a non-root fixture: {via_door:?}"
        );
    }

    // ---- evaluate3 (#85): three-valued with pattern provenance ----

    #[test]
    fn evaluate3_deny_match_carries_full_source_text() {
        let p = parse_authz(SHIPPED_DEFAULT, Some(&home())).unwrap();
        match p.evaluate3(&Request::Read(Path::new("/home/operator/.ssh/id_rsa"))) {
            Match3::DenyMatch { source } => assert_eq!(source, "Read(~/.ssh/**)"),
            other => panic!("expected DenyMatch with source, got {other:?}"),
        }
    }

    #[test]
    fn evaluate3_allow_and_nomatch_are_distinct() {
        // The two-valued evaluate() collapses no-match into deny; the PDP
        // backend needs the distinction (NoMatch → NotApplicable, spec §4.4).
        let p = parse_authz(SHIPPED_DEFAULT, Some(&home())).unwrap();
        assert!(matches!(
            p.evaluate3(&Request::Read(Path::new("/home/operator/notes.txt"))),
            Match3::AllowMatch
        ));
        assert!(matches!(
            p.evaluate3(&Request::Read(Path::new("/etc/hosts"))),
            Match3::NoMatch
        ));
    }

    #[test]
    fn evaluate3_deny_overrides_allow() {
        // ~/.ssh/** is inside ~/** — both lists match; deny must win and
        // report ITS source, mirroring evaluate()'s deny-wins contract.
        let p = parse_authz(SHIPPED_DEFAULT, Some(&home())).unwrap();
        let r = Request::Read(Path::new("/home/operator/.ssh/config"));
        assert_eq!(p.evaluate(&r), Decision::Deny);
        assert!(matches!(p.evaluate3(&r), Match3::DenyMatch { .. }));
    }

    // ---- bindings grammar (#85): additive, role-agnostic, fail-closed ----

    #[test]
    fn bindings_key_absent_is_none() {
        // Absent vs present-empty is load-bearing (spec §3 defaults precedence):
        // an absent key means defaults apply; a present key suppresses them.
        let p = parse_authz(SHIPPED_DEFAULT, Some(&home())).unwrap();
        assert!(p.bindings.is_none());
    }

    #[test]
    fn bindings_parse_role_to_string_lists() {
        let body = "schema_version: 1\npermissions:\n  allow: []\n  deny: []\nbindings:\n  admin: [\"alex\"]\n  guest: []\n";
        let p = parse_authz(body, None).unwrap();
        let b = p.bindings.unwrap();
        assert_eq!(b["admin"], vec!["alex".to_string()]);
        assert!(b["guest"].is_empty());
    }

    #[test]
    fn bindings_present_but_empty_map_is_some_empty() {
        let body = "schema_version: 1\npermissions:\n  allow: []\n  deny: []\nbindings: {}\n";
        let p = parse_authz(body, None).unwrap();
        assert_eq!(p.bindings, Some(std::collections::BTreeMap::new()));
    }

    #[test]
    fn bindings_non_string_member_refused_with_bindings_message() {
        let body =
            "schema_version: 1\npermissions:\n  allow: []\n  deny: []\nbindings:\n  admin: [1001]\n";
        let e = parse_authz(body, None).unwrap_err();
        assert!(
            matches!(&e, AuthzError::Yaml(m) if m.contains("bindings")),
            "error must name bindings, not permissions: {e:?}"
        );
    }

    #[test]
    fn bindings_null_member_list_refused_with_bindings_message() {
        // A bare `guest:` parses as Null, not an empty sequence — refuse, do
        // not silently treat as empty (fail-closed; spec §3 says write `[]`).
        let body =
            "schema_version: 1\npermissions:\n  allow: []\n  deny: []\nbindings:\n  guest:\n";
        let e = parse_authz(body, None).unwrap_err();
        assert!(matches!(&e, AuthzError::Yaml(m) if m.contains("bindings")));
    }

    #[test]
    fn bindings_non_map_refused() {
        let body = "schema_version: 1\npermissions:\n  allow: []\n  deny: []\nbindings: [admin]\n";
        let e = parse_authz(body, None).unwrap_err();
        assert!(matches!(&e, AuthzError::Yaml(m) if m.contains("bindings")));
    }

    // ---- `roles:` action grants — STRUCTURAL parse only (#162) ----
    //
    // No term or role-name validation lives here. This crate owns grammar, not
    // decision: whether "admin" is a real role and whether "admin.status" is a
    // real term are `maknae-authz-basic`'s questions, and answering them here
    // would put policy semantics in the parser.

    const PREAMBLE: &str = "schema_version: 1\npermissions:\n  allow: []\n  deny: []\n";

    #[test]
    fn roles_key_absent_is_empty_map() {
        // Plain map, NOT Option: absent and `roles: {}` are behaviourally
        // identical under the additivity ruling, so an Option would make the
        // None<->Some(empty) mutant undetectable by construction.
        let p = parse_authz(PREAMBLE, None).unwrap();
        assert!(p.action_grants.is_empty());
    }

    #[test]
    fn roles_parse_allow_and_deny_term_lists() {
        let body = format!(
            "{PREAMBLE}roles:\n  admin:\n    actions:\n      allow: [\"admin.status\"]\n      deny: [\"admin.config.show\"]\n"
        );
        let p = parse_authz(&body, None).unwrap();
        let g = p.action_grants.get("admin").expect("admin entry");
        assert_eq!(g.allow, vec!["admin.status".to_string()]);
        assert_eq!(g.deny, vec!["admin.config.show".to_string()]);
    }

    #[test]
    fn roles_entry_with_empty_actions_parses_to_empty_lists() {
        let body = format!("{PREAMBLE}roles:\n  admin:\n    actions: {{}}\n");
        let p = parse_authz(&body, None).unwrap();
        assert_eq!(p.action_grants.get("admin"), Some(&RawActionGrants::default()));
    }

    #[test]
    fn roles_unknown_key_under_role_refused() {
        // `roles.<name>` allows exactly `actions` — a `permissions:` typo here
        // must not be silently accepted as a second, unenforced grant surface.
        let body = format!("{PREAMBLE}roles:\n  admin:\n    permissions:\n      allow: []\n");
        let e = parse_authz(&body, None).unwrap_err();
        assert!(
            matches!(&e, AuthzError::UnknownKey(k) if k == "permissions"),
            "must name the offending key: {e:?}"
        );
    }

    #[test]
    fn roles_unknown_key_under_actions_refused() {
        let body =
            format!("{PREAMBLE}roles:\n  admin:\n    actions:\n      allwo: [\"admin.status\"]\n");
        let e = parse_authz(&body, None).unwrap_err();
        assert!(
            matches!(&e, AuthzError::UnknownKey(k) if k == "allwo"),
            "a typo'd allow must refuse, not parse to an empty grant: {e:?}"
        );
    }

    #[test]
    fn roles_non_string_term_refused_with_roles_message() {
        // NOT str_seq's "permissions list entries must be strings" — an
        // operator debugging a roles typo must not be sent to the wrong section.
        let body = format!("{PREAMBLE}roles:\n  admin:\n    actions:\n      allow: [1001]\n");
        let e = parse_authz(&body, None).unwrap_err();
        assert!(
            matches!(&e, AuthzError::Yaml(m) if m.contains("roles") && !m.contains("permissions list")),
            "error must name roles: {e:?}"
        );
    }

    #[test]
    fn roles_null_term_list_refused_with_roles_message() {
        // A bare `allow:` parses Null, not an empty sequence. Refuse; do not
        // silently treat as empty — same fail-closed stance as bindings.
        let body = format!("{PREAMBLE}roles:\n  admin:\n    actions:\n      allow:\n");
        let e = parse_authz(&body, None).unwrap_err();
        assert!(matches!(&e, AuthzError::Yaml(m) if m.contains("roles")), "{e:?}");
    }

    #[test]
    fn roles_null_role_body_refused_with_roles_message() {
        let body = format!("{PREAMBLE}roles:\n  admin:\n");
        let e = parse_authz(&body, None).unwrap_err();
        assert!(matches!(&e, AuthzError::Yaml(m) if m.contains("roles")), "{e:?}");
    }

    #[test]
    fn roles_non_map_refused() {
        let body = format!("{PREAMBLE}roles: [admin]\n");
        let e = parse_authz(&body, None).unwrap_err();
        assert!(matches!(&e, AuthzError::Yaml(m) if m.contains("roles")), "{e:?}");
    }

    #[test]
    fn roles_actions_non_map_refused() {
        let body = format!("{PREAMBLE}roles:\n  admin:\n    actions: [admin.status]\n");
        let e = parse_authz(&body, None).unwrap_err();
        assert!(matches!(&e, AuthzError::Yaml(m) if m.contains("roles")), "{e:?}");
    }

    #[test]
    fn roles_does_not_disturb_bindings_or_permissions() {
        // The two additive surfaces are independent; parsing one must not
        // suppress or alter the other.
        let body = "schema_version: 1\npermissions:\n  allow: [\"Read(~/**)\"]\n  deny: []\nbindings:\n  admin: [\"alex\"]\nroles:\n  admin:\n    actions:\n      allow: [\"admin.status\"]\n";
        let p = parse_authz(body, Some(Path::new("/home/operator"))).unwrap();
        assert_eq!(p.allow.len(), 1);
        assert_eq!(
            p.bindings.as_ref().and_then(|b| b.get("admin")),
            Some(&vec!["alex".to_string()])
        );
        assert_eq!(p.action_grants["admin"].allow, vec!["admin.status".to_string()]);
    }
}
