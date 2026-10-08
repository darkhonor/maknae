//! Capability-grant policy schema v1 (spec §7, PR-J1 Task 6) — the
//! Claude-Code/Codex-style capability grammar (`Read(...)`, `Write(...)`) the PDP
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
//! *(Corrected 2026-08-31: the header above describes `authz.yaml` as the
//! capability grammar alone, which has been incomplete since #85. The file now
//! carries **three independent surfaces**, and each answers a different
//! question: `permissions:` decides PATHS by capability pattern; `bindings:`
//! decides IDENTITY→role (#85); `roles:` decides ACTIONS per role, per term
//! (#162, [ADR-0010]). They do not compose with one another here — each is
//! parsed structurally and handed to `maknae-authz-basic` to decide. Prose
//! elsewhere that treats `authz.yaml` as "the capability grammar" is describing
//! one of the three.)*
//!
//! *(Corrected 2026-10-08, #496: `bindings:` moved to its own root-owned file,
//! `bindings.yaml` ([`crate::parse_bindings`]); `authz.yaml` refuses the key.
//! The surfaces here are `permissions:`, `roles:` and `destinations:`.)*
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

/// Per-role egress destination allowlist (`destinations:`, #172). Raw strings:
/// role-name semantics belong to `maknae-authz-basic`, never this crate. Allow only:
/// an allowlist over one registered provider has nothing to deny, and a
/// `deny:` key refuses at load so it cannot be silently ignored.
#[derive(Clone, Debug, PartialEq, Eq, Default)]
pub struct RawDestinations {
    pub allow: Vec<String>,
}

/// `provider:<name>`, `<name>` in #243's provider-name charset
/// (`[A-Za-z0-9._-]+`) and within its length bound
/// (`MAX_PROVIDER_NAME_BYTES`): an entry no provider could ever be registered
/// under would load and never match, which is the silent-inert grant this
/// surface exists to refuse. URL patterns are #147's later grammar: refused now.
pub fn destination_entry_is_acceptable(entry: &str) -> bool {
    entry
        .strip_prefix("provider:")
        .is_some_and(crate::provider_name_is_acceptable)
}

/// One role's action grants as they appear on disk (#162): the `allow` and
/// `deny` lists under `roles.<name>`. **Raw strings, deliberately** —
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
/// (default-deny) — see [`AuthzPolicy::evaluate3`].
#[derive(Clone, Debug, PartialEq, Eq, Default)]
pub struct AuthzPolicy {
    pub allow: Vec<Pattern>,
    pub deny: Vec<Pattern>,
    /// Role → action-term grants from the additive `roles:` key (#162).
    /// **A plain map, NOT an `Option`**: an absent `roles:`
    /// and an empty one behave identically under the additivity ruling, so an
    /// `Option` would make the `None`↔`Some(empty)` mutant undetectable by
    /// construction: reported MISSED with no killable test available, and the
    /// T1 zero-missed gate goes red with nothing to write.
    pub action_grants: std::collections::BTreeMap<String, RawActionGrants>,
    /// Role → egress destination allowlist from the additive `destinations:`
    /// key (#172). A plain map like `action_grants`, for the same mutant
    /// reason: absent and empty behave identically (both refuse every prompt).
    /// Raw strings: role-name semantics belong to `maknae-authz-basic`.
    pub destinations: std::collections::BTreeMap<String, RawDestinations>,
    /// Original entry text for each `allow`/`deny` pattern, index-aligned
    /// (#85): [`AuthzPolicy::evaluate3`] reports WHICH entry matched for
    /// the audit record. Private — provenance is not a matching input, and
    /// keeping it un-constructible outside the parser means the pair can
    /// never drift out of alignment.
    allow_sources: Vec<String>,
    deny_sources: Vec<String>,
    sections: std::collections::BTreeMap<String, String>,
}

/// [`AuthzPolicy::evaluate3`]'s answer (#85): three-valued. The PDP backend
/// maps `NoMatch` to `NotApplicable`; deny-by-default happens at `finalize`,
/// with the reason "no grant" distinguishable from "explicit deny". The backend
/// annotates that absence (#181): `NotApplicable { note }` carries the role and
/// term testimony the audit trail renders.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Match3 {
    AllowMatch { source: String },
    DenyMatch { source: String },
    NoMatch,
}

/// A single filesystem capability request the PDP asks the policy about.
#[derive(Clone, Copy, Debug)]
pub enum Request<'a> {
    Read(&'a Path),
    Write(&'a Path),
}

/// A `~` pattern was evaluated with no home, or with one that is not an
/// absolute, `.`/`..`-free, UTF-8 path other than `/` (#435).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct HomeUnbound;

fn valid_home(home: Option<&Path>) -> Option<&Path> {
    home.filter(|h| {
        h.to_str().is_some_and(|s| {
            let comps: Vec<&str> = s.split('/').filter(|c| !c.is_empty()).collect();
            s.starts_with('/')
                && !comps.is_empty()
                && !comps.iter().any(|c| matches!(*c, "." | ".."))
        })
    })
}

impl AuthzPolicy {
    fn needs_unbound_home(
        &self,
        home: Option<&Path>,
        mut wants: impl FnMut(&Pattern) -> bool,
    ) -> bool {
        home.is_none() && self.deny.iter().chain(&self.allow).any(&mut wants)
    }

    /// Canonical JSON of each top-level key present in the file, by key.
    pub fn section_canonical(&self, key: &str) -> Option<&str> {
        self.sections.get(key).map(String::as_str)
    }

    pub fn sections(&self) -> impl Iterator<Item = (&str, &str)> {
        self.sections.iter().map(|(k, v)| (k.as_str(), v.as_str()))
    }

    pub fn allow_sources(&self) -> &[String] {
        &self.allow_sources
    }

    pub fn deny_sources(&self) -> &[String] {
        &self.deny_sources
    }

    fn allow_source(&self, i: usize) -> String {
        self.allow_sources
            .get(i)
            .cloned()
            .unwrap_or_else(|| "<unknown allow entry>".into())
    }

    fn deny_source(&self, i: usize) -> String {
        self.deny_sources
            .get(i)
            .cloned()
            .unwrap_or_else(|| "<unknown deny entry>".into())
    }

    /// Three-valued evaluation with deny provenance (#85, spec §6a.1).
    /// Deny-wins, default-deny (spec §7): deny is checked first; the matched
    /// deny entry's ORIGINAL text rides in `source` for the audit record
    /// (audit-only — never onto the wire, spec §4.4). `HomeUnbound` when any
    /// `~` pattern of the request's capability has no valid `home`, whatever
    /// its position in either list.
    pub fn evaluate3(&self, req: &Request<'_>, home: Option<&Path>) -> Result<Match3, HomeUnbound> {
        let home = valid_home(home);
        if self.needs_unbound_home(home, |p| p.glob_for(req).is_some_and(|(g, _)| g.is_home())) {
            return Err(HomeUnbound);
        }
        for (i, p) in self.deny.iter().enumerate() {
            if p.matches_req(req, home)? {
                return Ok(Match3::DenyMatch {
                    source: self.deny_source(i),
                });
            }
        }
        for (i, p) in self.allow.iter().enumerate() {
            if p.matches_req(req, home)? {
                return Ok(Match3::AllowMatch {
                    source: self.allow_source(i),
                });
            }
        }
        Ok(Match3::NoMatch)
    }

    /// Authorize the whole subtree for recursive deletion (#158). A point grant
    /// cannot authorize destruction of descendants. Denies use conservative
    /// intersection; allows require a provable literal-prefix/** covering grant.
    /// This examines policy only, never a potentially changing directory walk.
    pub fn evaluate_write_subtree(
        &self,
        root: &Path,
        home: Option<&Path>,
    ) -> Result<Match3, HomeUnbound> {
        let Some(text) = root.to_str() else {
            return Ok(Match3::NoMatch);
        };
        if !text.starts_with('/')
            || text.contains('\0')
            || (text != "/" && text[1..].split('/').any(|c| matches!(c, "" | "." | "..")))
        {
            return Ok(Match3::NoMatch);
        }
        let home = valid_home(home);
        if self.needs_unbound_home(home, |p| matches!(p, Pattern::Write(g) if g.is_home())) {
            return Err(HomeUnbound);
        }
        for (i, pattern) in self.deny.iter().enumerate() {
            if let Pattern::Write(glob) = pattern {
                if glob.may_intersect_subtree(text, home)? {
                    return Ok(Match3::DenyMatch {
                        source: self.deny_source(i),
                    });
                }
            }
        }
        for (i, pattern) in self.allow.iter().enumerate() {
            if let Pattern::Write(glob) = pattern {
                if glob.covers_subtree(text, home)? {
                    return Ok(Match3::AllowMatch {
                        source: self.allow_source(i),
                    });
                }
            }
        }
        Ok(Match3::NoMatch)
    }
}

/// One `Capability(specifier)` entry. `Read` and `Write` are independent
/// filesystem capabilities; neither grants the other (#158).
/// `Bash` was RETIRED by #67 in favour of the `terminal.*` action class: it was a
/// second way to express execution authority, and argv matching is a
/// categorically harder problem than the path globs this grammar was built for.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Pattern {
    Read(PathGlob),
    Write(PathGlob),
}

impl Pattern {
    fn glob_for<'a>(&'a self, req: &Request<'a>) -> Option<(&'a PathGlob, &'a Path)> {
        match (self, req) {
            (Pattern::Read(g), Request::Read(p)) | (Pattern::Write(g), Request::Write(p)) => {
                Some((g, *p))
            }
            _ => None,
        }
    }

    fn matches_req(&self, req: &Request<'_>, home: Option<&Path>) -> Result<bool, HomeUnbound> {
        self.glob_for(req)
            .map_or(Ok(false), |(g, p)| g.matches(p, home))
    }
}

// ============================================================================
// PathGlob — the hand-rolled glob matcher (spec §7)
// ============================================================================

/// A compiled filesystem capability's path specifier: a path anchored at the root
/// or at the home, split into `/`-separated segments, each either a literal
/// component (which may itself contain `*` wildcards, e.g. `*.json`) or `**`
/// (matches across zero or more components — see [`PathGlob::matches`]).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PathGlob {
    anchor: Anchor,
    segments: Vec<GlobSeg>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Anchor {
    Root,
    Home,
}

#[derive(Clone, Debug, PartialEq, Eq)]
enum GlobSeg {
    DoubleStar,
    Comp(String),
}

impl PathGlob {
    /// `~` is kept symbolic and bound at match time to the home the request carries (#435);
    /// `~name` is refused (#438).
    fn parse(spec: &str) -> Result<PathGlob, AuthzError> {
        let bad = || AuthzError::BadPattern(spec.to_string());
        let (anchor, rest) = if let Some(rest) = spec.strip_prefix('~') {
            if !rest.is_empty() && !rest.starts_with('/') {
                return Err(bad());
            }
            (Anchor::Home, rest)
        } else if spec.starts_with('/') {
            (Anchor::Root, spec)
        } else {
            return Err(bad());
        };
        let segments = rest
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
        Ok(PathGlob { anchor, segments })
    }

    fn is_home(&self) -> bool {
        self.anchor == Anchor::Home
    }

    fn base<'h>(&self, home: Option<&'h Path>) -> Result<Vec<&'h str>, HomeUnbound> {
        if self.anchor == Anchor::Root {
            return Ok(Vec::new());
        }
        let h = valid_home(home).and_then(Path::to_str).ok_or(HomeUnbound)?;
        Ok(h.split('/').filter(|c| !c.is_empty()).collect())
    }

    /// Match a canonical absolute path against the compiled glob (spec §7):
    /// `*` matches within one path component; `**` matches across components
    /// — INCLUDING zero components, so `X/**` also matches `X` itself. Both
    /// `*` and `**` match dotfiles (no special-casing of a leading `.`).
    /// Matching is byte-wise case-sensitive. A `~` glob's home is a literal
    /// prefix compared component by component, never a pattern.
    pub fn matches(&self, path: &Path, home: Option<&Path>) -> Result<bool, HomeUnbound> {
        let base = self.base(home)?;
        let Some(s) = path.to_str() else {
            return Ok(false);
        };
        let comps: Vec<&str> = s.split('/').filter(|c| !c.is_empty()).collect();
        Ok(comps.starts_with(&base) && match_segs(&self.segments, &comps[base.len()..]))
    }

    fn covers_subtree(&self, root: &str, home: Option<&Path>) -> Result<bool, HomeUnbound> {
        let base = self.base(home)?;
        let Some((GlobSeg::DoubleStar, prefix)) = self.segments.split_last() else {
            return Ok(false);
        };
        let mut components = root.split('/').filter(|c| !c.is_empty());
        Ok(base.iter().all(|b| components.next() == Some(*b))
            && prefix.iter().all(|seg| match seg {
                // Exact component equality is sufficient even when the actual
                // directory name contains '*': that glob matches its own text.
                // Other wildcard matches are deliberately not inferred here.
                GlobSeg::Comp(literal) => components.next() == Some(literal.as_str()),
                _ => false,
            }))
    }

    fn may_intersect_subtree(&self, root: &str, home: Option<&Path>) -> Result<bool, HomeUnbound> {
        let base = self.base(home)?;
        let fixed = self.segments.iter().map_while(|seg| match seg {
            GlobSeg::Comp(literal) if !literal.contains('*') => Some(literal.as_str()),
            _ => None,
        });
        // Either prefix may end first. Only a conflicting fixed component proves
        // disjointness; a wildcard could reach anywhere after its fixed prefix.
        Ok(base
            .into_iter()
            .chain(fixed)
            .zip(root.split('/').filter(|c| !c.is_empty()))
            .all(|(a, b)| a == b))
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
/// whose name extended the home's last component, e.g. `/home/operatorbot`
/// when `~` was `/home/operator`.)
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
    /// A shared `maknae-config` refusal raised on the authz path — today that is
    /// [`ConfigError::UnknownKey`] (#210). This variant replaced a private
    /// `UnknownKey(String)` of its own: an unknown key is the SAME defect
    /// wherever it appears, so there is one error for it and one sentence, not a
    /// per-file lookalike. Nothing outside this module ever matched the old
    /// variant, so the convergence cost no caller.
    Config(ConfigError),
    /// A pattern specifier failed to parse (bad shape, unknown capability,
    /// non-absolute `Read` glob, unknown capability name, …).
    BadPattern(String),
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
    /// `bindings:` moved to bindings.yaml (#496).
    BindingsMoved,
}

impl std::fmt::Display for AuthzError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            AuthzError::UnknownSchemaVersion(v) => {
                write!(f, "unknown authz schema_version: {v}")
            }
            AuthzError::Config(e) => write!(f, "{e}"),
            AuthzError::BadPattern(p) => write!(f, "malformed authz pattern: '{p}'"),
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
            AuthzError::BindingsMoved => f.write_str(
                "authz.yaml no longer carries `bindings:`; move the block unchanged to bindings.yaml in the same directory (docs/upgrading.md)",
            ),
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
/// #210: the authz grammar's closed-vocabulary check, now a thin adapter over
/// the shared [`crate::reject_unknown_keys`]. `level` is the DOTTED path being
/// checked (`authz`, `authz.permissions`, `authz.roles.<role>`), so a nested
/// typo names where it appeared instead of just which token was wrong.
fn check_known_keys(
    level: &str,
    map: &[(String, Value)],
    allowed: &[&str],
) -> Result<(), AuthzError> {
    crate::reject_unknown_keys(level, map, allowed).map_err(AuthzError::Config)
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
fn parse_pattern(spec: &str) -> Result<Pattern, AuthzError> {
    let bad = || AuthzError::BadPattern(spec.to_string());
    let open = spec.find('(').ok_or_else(bad)?;
    if !spec.ends_with(')') {
        return Err(bad());
    }
    let capability = &spec[..open];
    let inner = &spec[open + 1..spec.len() - 1];
    match capability {
        "Read" => Ok(Pattern::Read(PathGlob::parse(inner)?)),
        "Write" => Ok(Pattern::Write(PathGlob::parse(inner)?)),
        _ => Err(bad()),
    }
}

/// A `roles.<name>.{allow,deny}` term list: a sequence of strings,
/// refused otherwise with a roles-specific message. **Not `str_seq`** — whose
/// text reads "permissions list entries must be strings" and would send an
/// operator debugging a `roles:` typo to the wrong section of the file. It is
/// a separate function rather than a shared one with a passed-in noun: the
/// message is the diagnostic, so it is written out where a reader can see it.
/// `destinations:` allow lists: the same YAML-shape checks as `roles_term_list`;
/// the entry grammar is `destination_entry_is_acceptable`'s, applied by the caller.
fn destination_list(v: &Value) -> Result<Vec<String>, AuthzError> {
    match v {
        Value::Seq(items) => items
            .iter()
            .map(|item| match item {
                Value::Str(s) => Ok(s.clone()),
                _ => Err(AuthzError::Yaml(
                    "destinations allow entries must be strings (quote every entry; #172)".into(),
                )),
            })
            .collect(),
        _ => Err(AuthzError::Yaml(
            "destinations allow list must be a sequence (write `allow: []` for empty)".into(),
        )),
    }
}

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
pub fn parse_authz(body: &str) -> Result<AuthzPolicy, AuthzError> {
    parse_policy(body)
}

/// Parse a `schema_version: 1 / permissions: {allow, deny}` document (spec
/// §7) into an [`AuthzPolicy`]. Pure — takes already-read YAML text, no file
/// I/O (that's [`load_authz`]'s job); factored out so the grammar/contract
/// tests can pin parse semantics without touching the filesystem.
fn parse_policy(body: &str) -> Result<AuthzPolicy, AuthzError> {
    let root = crate::load_str(body).map_err(|e| AuthzError::Yaml(e.to_string()))?;
    let map = match root {
        Value::Map(m) => m,
        _ => return Err(AuthzError::Yaml("authz root must be a mapping".into())),
    };
    if get(&map, "bindings").is_some() {
        return Err(AuthzError::BindingsMoved);
    }
    check_known_keys(
        "authz",
        &map,
        &["schema_version", "permissions", "roles", "destinations"],
    )?;
    let sections = map
        .iter()
        .map(|(k, v)| (k.clone(), crate::value::canonical_json(v)))
        .collect();

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
            check_known_keys("authz.permissions", pm, &["allow", "deny"])?;
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
        .map(|s| parse_pattern(s))
        .collect::<Result<Vec<_>, _>>()?;
    let deny = deny_raw
        .iter()
        .map(|s| parse_pattern(s))
        .collect::<Result<Vec<_>, _>>()?;

    let action_grants = match get(&map, "roles") {
        None => std::collections::BTreeMap::new(),
        Some(Value::Map(rm)) => {
            let mut out = std::collections::BTreeMap::new();
            for (role, body) in rm {
                // A bare `admin:` parses Null, not an empty map. Refuse rather
                // than silently treating it as "no grants" — fail-closed.
                let rb = match body {
                    Value::Map(m) => m,
                    _ => {
                        return Err(AuthzError::Yaml(
                            "roles entries must be a map of allow/deny".into(),
                        ))
                    }
                };
                check_known_keys(&format!("authz.roles.{role}"), rb, &["allow", "deny"])?;
                let allow = get(rb, "allow")
                    .map(roles_term_list)
                    .transpose()?
                    .unwrap_or_default();
                let deny = get(rb, "deny")
                    .map(roles_term_list)
                    .transpose()?
                    .unwrap_or_default();
                // `insert` is last-wins, and that is SAFE only because a
                // duplicate role key never reaches here: `crate::load_str`
                // refuses the document with `DuplicateKey` before this runs.
                // The invariant is cross-module, so it is pinned from this
                // layer by `roles_duplicate_role_key_refused_by_the_loader` --
                // without that test, swapping the loader for a last-wins one
                // would turn a written `deny:` into a silent permit, and
                // nothing here would notice.
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

    let destinations = match get(&map, "destinations") {
        None => std::collections::BTreeMap::new(),
        Some(Value::Map(dm)) => {
            let mut out = std::collections::BTreeMap::new();
            for (role, body) in dm {
                // Any key parses here; which roles may hold an allowlist is
                // maknae-authz-basic's decision (validate_destinations), like `roles:`.
                let Value::Map(rb) = body else {
                    return Err(AuthzError::Yaml(format!(
                        "destinations: role `{role}` must be a map with `allow`"
                    )));
                };
                check_known_keys(&format!("authz.destinations.{role}"), rb, &["allow"])?;
                let allow = get(rb, "allow")
                    .map(destination_list)
                    .transpose()?
                    .unwrap_or_default();
                if let Some(e) = allow.iter().find(|e| !destination_entry_is_acceptable(e)) {
                    return Err(AuthzError::Yaml(format!(
                        "destinations: entry `{e}` for role `{role}` is not `provider:<name>`"
                    )));
                }
                out.insert(role.clone(), RawDestinations { allow });
            }
            out
        }
        Some(_) => {
            return Err(AuthzError::Yaml(
                "destinations section must be a map of role to allowlist".into(),
            ))
        }
    };

    Ok(AuthzPolicy {
        allow,
        deny,
        action_grants,
        destinations,
        allow_sources: allow_raw,
        deny_sources: deny_raw,
        sections,
    })
}

// ============================================================================
// Secure load (spec §4.6/§7)
// ============================================================================

/// Pure owner-check boundary, factored out so it is unit-testable without
/// filesystem access or root privilege (mirrors the mode-mask precedent in
/// `loader.rs::mode_is_secure`).
#[cfg(unix)]
pub(crate) fn root_policy_file_required() -> maknae_io::TargetRequired {
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
        security_load_required(path, root_policy_file_required())
    }
}

/// [`security_load`]'s unix body with the artifact requirement supplied by the
/// caller instead of fixed at [`root_policy_file_required`]. Crate-private (the
/// `load_required_file` property, issue #138/PR #139: nothing outside this
/// crate can choose a weaker requirement) — the ONLY external door is the
/// non-default `hermetic-test-seam` feature below, which production consumers
/// never enable.
#[cfg(unix)]
pub(crate) fn security_load_required(
    path: &Path,
    target: maknae_io::TargetRequired,
) -> Result<String, AuthzError> {
    let absolute = std::path::absolute(path).map_err(|e| AuthzError::Io(e.to_string()))?;
    let bytes = read_in_root_dir(&absolute, target).map_err(map_authz_io)?;
    decode_policy_utf8(&bytes)
}

/// Read a root policy file through an anchor on its directory that requires the
/// file's owner and no group or other write, so only that owner can add, replace
/// or remove the file. `path` is absolute.
#[cfg(unix)]
pub(crate) fn read_in_root_dir(
    path: &Path,
    target: maknae_io::TargetRequired,
) -> Result<maknae_io::Zeroizing<Vec<u8>>, maknae_io::IoError> {
    let parent = path.parent().ok_or(maknae_io::IoError::RootAnchor)?;
    let name = path
        .file_name()
        .ok_or_else(|| maknae_io::IoError::AnchorEndsInDotDot {
            path: path.to_path_buf(),
        })?;
    let dir = maknae_io::AnchorRequired {
        owner: target.owner,
        mode_mask: Some(0o022),
    };
    let anchor = maknae_io::open_anchor_resolved(parent, dir, maknae_io::StrategyPref::Auto)?;
    Ok(anchor.read(Path::new(name), None, target)?.value)
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
) -> Result<AuthzPolicy, AuthzError> {
    let body = security_load_required(path, target)?;
    parse_policy(&body)
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
/// pattern stays symbolic until evaluation binds it at match time to the home the request
/// carries.
pub fn load_authz(path: &Path) -> Result<AuthzPolicy, AuthzError> {
    let body = security_load(path)?;
    parse_policy(&body)
}

#[cfg(test)]
mod tests {
    use super::*;

    const DEST_BASE: &str = "schema_version: 1\npermissions:\n  allow: []\n  deny: []\n";
    fn parse_dest(body: &str) -> Result<AuthzPolicy, AuthzError> {
        parse_authz(body)
    }

    #[test]
    fn destinations_absent_means_empty_for_every_role() {
        assert!(parse_dest(DEST_BASE).unwrap().destinations.is_empty());
    }

    #[test]
    fn destinations_parse_per_role_allow_lists() {
        let p = parse_dest(&format!(
            "{DEST_BASE}destinations:\n  user:\n    allow: [\"provider:openai\"]\n  admin:\n    allow: []\n"
        ))
        .unwrap();
        assert_eq!(
            p.destinations["user"].allow,
            vec!["provider:openai".to_string()]
        );
        assert!(p.destinations["admin"].allow.is_empty());
    }

    #[test]
    fn destinations_refuse_a_deny_key_an_unknown_key_a_non_map_and_a_non_map_section() {
        // The last two reach destination_list's two error arms (T1: both regions, both mutants).
        for tail in [
            "destinations:\n  user:\n    deny: [\"provider:x\"]\n",
            "destinations:\n  user:\n    allow: []\n    extra: 1\n",
            "destinations:\n  user: [\"provider:x\"]\n",
            "destinations: 3\n",
            "destinations:\n  user:\n    allow: 3\n",
            "destinations:\n  user:\n    allow: [3]\n",
        ] {
            assert!(parse_dest(&format!("{DEST_BASE}{tail}")).is_err(), "{tail}");
        }
    }

    #[test]
    fn destination_entries_must_be_provider_colon_name_and_the_error_names_the_entry() {
        for bad in [
            "openai",
            "provider:",
            "provider:open ai",
            "https://api.openai.com/v1",
            "provider:a/b",
            "PROVIDER:x",
        ] {
            let err = parse_dest(&format!(
                "{DEST_BASE}destinations:\n  user:\n    allow: [\"{bad}\"]\n"
            ))
            .unwrap_err();
            assert!(err.to_string().contains(bad), "{bad}: {err}");
        }
        assert!(destination_entry_is_acceptable("provider:open-ai_2.0"));
        assert!(!destination_entry_is_acceptable("provider:"));
        // The registration bound applies: an entry no provider can carry never loads.
        let at = format!("provider:{}", "n".repeat(crate::MAX_PROVIDER_NAME_BYTES));
        let over = format!(
            "provider:{}",
            "n".repeat(crate::MAX_PROVIDER_NAME_BYTES + 1)
        );
        assert!(destination_entry_is_acceptable(&at));
        assert!(!destination_entry_is_acceptable(&over));
        assert!(parse_dest(&format!(
            "{DEST_BASE}destinations:\n  user:\n    allow: [\"{over}\"]\n"
        ))
        .is_err());
    }

    #[test]
    fn destinations_parse_any_role_key_because_role_semantics_are_not_this_crates() {
        // Role-name semantics belong to maknae-authz-basic (grammar, not decision):
        // `guest`/`adversary`/unknown keys refuse at boot in `validate_destinations`, not here.
        let p = parse_dest(&format!(
            "{DEST_BASE}destinations:\n  guest:\n    allow: [\"provider:x\"]\n"
        ))
        .unwrap();
        assert_eq!(
            p.destinations["guest"].allow,
            vec!["provider:x".to_string()]
        );
    }

    // ---- the exact spec §7 shipped default ----

    // Exercise the actual packaged policy: a hand-copied fixture can stay green
    // when the file operators install loses a deny (#158).
    const SHIPPED_DEFAULT: &str = include_str!("../../../packaging/common/authz.yaml");

    fn home() -> std::path::PathBuf {
        std::path::PathBuf::from("/home/operator")
    }

    // ---- grammar / contract-as-tests (pure, via parse_policy) ----

    #[test]
    fn shipped_default_validates_clean() {
        let policy = parse_policy(SHIPPED_DEFAULT).unwrap();
        assert_eq!(policy.allow.len(), 2);
        assert_eq!(policy.deny.len(), 18);
        assert!(matches!(policy.allow[0], Pattern::Read(_)));
        assert!(matches!(policy.allow[1], Pattern::Write(_)));
        assert_eq!(
            policy
                .deny
                .iter()
                .filter(|p| matches!(p, Pattern::Read(_)))
                .count(),
            9
        );
        assert_eq!(
            policy
                .deny
                .iter()
                .filter(|p| matches!(p, Pattern::Write(_)))
                .count(),
            9
        );
    }

    #[test]
    fn shipped_write_authority_is_limited_to_projects() {
        let policy = parse_policy(SHIPPED_DEFAULT).unwrap();
        assert_eq!(
            policy
                .evaluate3(
                    &Request::Write(&home().join("projects/code.rs")),
                    Some(&home())
                )
                .unwrap(),
            Match3::AllowMatch {
                source: "Write(~/projects/**)".into()
            }
        );
        for relative in [
            "notes",
            "projects-other/code.rs",
            ".ssh/key",
            ".bashrc",
            ".maknae/config.yaml",
        ] {
            assert!(
                !matches!(
                    policy
                        .evaluate3(&Request::Write(&home().join(relative)), Some(&home()))
                        .unwrap(),
                    Match3::AllowMatch { .. }
                ),
                "{relative}"
            );
        }
        assert_eq!(
            policy
                .evaluate_write_subtree(&home().join("projects/repo"), Some(&home()))
                .unwrap(),
            Match3::AllowMatch {
                source: "Write(~/projects/**)".into()
            }
        );
    }

    #[test]
    fn unknown_schema_version_refused() {
        let yaml = "schema_version: 2\npermissions:\n  allow: []\n";
        assert!(matches!(
            parse_policy(yaml),
            Err(AuthzError::UnknownSchemaVersion(2))
        ));
    }

    #[test]
    fn schema_version_missing_is_unknown_schema_version() {
        let yaml = "permissions:\n  allow: []\n";
        assert!(matches!(
            parse_policy(yaml),
            Err(AuthzError::UnknownSchemaVersion(0))
        ));
    }

    #[test]
    fn schema_version_non_integer_is_unknown_schema_version() {
        let yaml = "schema_version: \"1\"\npermissions:\n  allow: []\n";
        assert!(matches!(
            parse_policy(yaml),
            Err(AuthzError::UnknownSchemaVersion(0))
        ));
    }

    #[test]
    fn unknown_key_refused_naming_key() {
        let yaml = "schema_version: 1\npermissions:\n  allow: []\n  denny: []\n";
        match parse_policy(yaml) {
            Err(AuthzError::Config(ConfigError::UnknownKey { key, .. })) => {
                assert_eq!(key, "denny")
            }
            other => panic!("expected UnknownKey(\"denny\"), got {other:?}"),
        }
    }

    #[test]
    fn unknown_top_level_key_refused() {
        let yaml = "schema_version: 1\nextra_top_key: 1\n";
        match parse_policy(yaml) {
            Err(AuthzError::Config(ConfigError::UnknownKey { key, .. })) => {
                assert_eq!(key, "extra_top_key")
            }
            other => panic!("expected UnknownKey(\"extra_top_key\"), got {other:?}"),
        }
    }

    #[test]
    fn unknown_capability_refused() {
        let yaml = "schema_version: 1\npermissions:\n  allow:\n    - \"WebSearch(x)\"\n";
        assert!(matches!(
            parse_policy(yaml),
            Err(AuthzError::BadPattern(p)) if p == "WebSearch(x)"
        ));
    }

    #[test]
    fn write_policy_is_a_distinct_filesystem_capability() {
        let policy =
            parse_policy("schema_version: 1\npermissions:\n  allow: [\"Write(~/projects/**)\"]\n")
                .expect("Write must be expressible without role action grants");
        assert_eq!(
            policy
                .evaluate3(
                    &Request::Read(&home().join("projects/sentinel")),
                    Some(&home())
                )
                .unwrap(),
            Match3::NoMatch,
            "write authority must never imply read authority",
        );
    }

    #[test]
    fn shipped_read_denies_have_write_pairs() {
        let policy = parse_policy(SHIPPED_DEFAULT).unwrap();
        let mut reads = 0;
        for (pattern, source) in policy.deny.iter().zip(&policy.deny_sources) {
            if let Pattern::Read(glob) = pattern {
                reads += 1;
                assert!(
                    policy.deny.contains(&Pattern::Write(glob.clone())),
                    "shipped deny {source} is missing its Write counterpart",
                );
            }
        }
        assert!(reads > 0, "the shipped deny inventory must not disappear");
    }

    #[test]
    fn recursive_write_requires_whole_subtree_authority() {
        for (allow, root, expected) in [
            (
                "Write(/h/u/projects/**)",
                "/h/u/projects/p",
                Match3::AllowMatch {
                    source: "Write(/h/u/projects/**)".into(),
                },
            ),
            (
                "Write(/h/u/projects/**)",
                "/h/u/projects",
                Match3::AllowMatch {
                    source: "Write(/h/u/projects/**)".into(),
                },
            ),
            ("Write(/h/u/projects/p)", "/h/u/projects/p", Match3::NoMatch),
            (
                "Write(/h/u/projects/p/*)",
                "/h/u/projects/p",
                Match3::NoMatch,
            ),
            (
                "Write(/h/u/projects/*/**)",
                "/h/u/projects/p",
                Match3::NoMatch,
            ),
            ("Write(/h/**/p/**)", "/h/u/projects/p", Match3::NoMatch),
            (
                "Write(/**)",
                "/",
                Match3::AllowMatch {
                    source: "Write(/**)".into(),
                },
            ),
            ("Read(/h/u/projects/**)", "/h/u/projects/p", Match3::NoMatch),
            (
                "Write(/h/u/projects/**)",
                "/h/u/projects-other",
                Match3::NoMatch,
            ),
            (
                "Write(/h/u/projects/p/**)",
                "/h/u/projects",
                Match3::NoMatch,
            ),
        ] {
            let yaml = format!("schema_version: 1\npermissions:\n  allow: [\"{allow}\"]\n");
            let policy = parse_policy(&yaml).unwrap();
            assert_eq!(
                policy
                    .evaluate_write_subtree(Path::new(root), None)
                    .unwrap(),
                expected,
                "{allow} on {root}"
            );
        }
    }

    #[test]
    fn recursive_write_denies_possible_descendants_with_original_provenance() {
        for (deny, intersects) in [
            ("Write(/h/u/projects/p/secret/**)", true),
            ("Write(/h/u/projects/p/secret)", true),
            ("Write(/h/u/projects/p)", true),
            ("Write(/h/u/projects/**)", true),
            ("Write(/h/u/**/.aws/**)", true),
            ("Write(/**/secret)", true),
            ("Write(/h/u/proj*/secret)", true),
            ("Write(/h/u/.ssh/**)", false),
            ("Write(/h/u/projects/private/**)", false),
            ("Write(/h/u/projects/p-other/**)", false),
            ("Read(/h/u/projects/p/secret/**)", false),
        ] {
            let yaml = format!("schema_version: 1\npermissions:\n  allow: [\"Write(/h/u/projects/**)\"]\n  deny: [\"{deny}\"]\n");
            let policy = parse_policy(&yaml).unwrap();
            let expected = if intersects {
                Match3::DenyMatch {
                    source: deny.into(),
                }
            } else {
                Match3::AllowMatch {
                    source: "Write(/h/u/projects/**)".into(),
                }
            };
            assert_eq!(
                policy
                    .evaluate_write_subtree(Path::new("/h/u/projects/p"), None)
                    .unwrap(),
                expected,
                "{deny}"
            );
        }
    }

    #[test]
    fn recursive_write_rejects_malformed_roots_and_absent_grants() {
        let policy =
            parse_policy("schema_version: 1\npermissions:\n  allow: [\"Write(/**)\"]\n").unwrap();
        for root in [
            "",
            "h/u",
            "/h//u",
            "/h/./u",
            "/h/../u",
            "/h/u/",
            "/h/u\0bad",
        ] {
            assert_eq!(
                policy
                    .evaluate_write_subtree(Path::new(root), None)
                    .unwrap(),
                Match3::NoMatch,
                "{root:?}"
            );
        }
        let empty = parse_policy("schema_version: 1\npermissions: {}\n").unwrap();
        assert_eq!(
            empty
                .evaluate_write_subtree(Path::new("/h/u"), None)
                .unwrap(),
            Match3::NoMatch
        );
        let deny_only =
            parse_policy("schema_version: 1\npermissions:\n  deny: [\"Write(/h/u/secret/**)\"]\n")
                .unwrap();
        assert_eq!(
            deny_only
                .evaluate_write_subtree(Path::new("/h/u"), None)
                .unwrap(),
            Match3::DenyMatch {
                source: "Write(/h/u/secret/**)".into()
            }
        );
    }

    #[cfg(unix)]
    #[test]
    fn recursive_write_never_normalizes_invalid_utf8_into_a_grant() {
        use std::os::unix::ffi::OsStrExt;
        let policy =
            parse_policy("schema_version: 1\npermissions:\n  allow: [\"Write(/**)\"]\n").unwrap();
        assert_eq!(
            policy
                .evaluate_write_subtree(Path::new(std::ffi::OsStr::from_bytes(b"/h/\xff")), None)
                .unwrap(),
            Match3::NoMatch
        );
    }

    #[test]
    fn recursive_write_retains_denial_without_source_metadata() {
        let mut policy = parse_policy("schema_version: 1\npermissions:\n  allow: [\"Write(/**)\"]\n  deny: [\"Write(/h/u/secret/**)\"]\n").unwrap();
        policy.deny_sources.clear();
        assert_eq!(
            policy
                .evaluate_write_subtree(Path::new("/h/u"), None)
                .unwrap(),
            Match3::DenyMatch {
                source: "<unknown deny entry>".into()
            }
        );
    }

    #[test]
    fn write_matching_is_independent_and_preserves_deny_provenance() {
        let policy = parse_policy(
            "schema_version: 1\npermissions:\n  allow: [\"Read(~/read-only/**)\", \"Write(~/projects/**)\"]\n  deny: [\"Write(~/projects/private/**)\", \"Read(~/projects/opaque/**)\"]\n"
        ).unwrap();
        for (path, expected) in [
            ("read-only/notes", Match3::NoMatch),
            (
                "projects/source.rs",
                Match3::AllowMatch {
                    source: "Write(~/projects/**)".into(),
                },
            ),
            (
                "projects/opaque/output",
                Match3::AllowMatch {
                    source: "Write(~/projects/**)".into(),
                },
            ),
            (
                "projects/private/key",
                Match3::DenyMatch {
                    source: "Write(~/projects/private/**)".into(),
                },
            ),
            ("elsewhere/file", Match3::NoMatch),
        ] {
            let path = home().join(path);
            let request = Request::Write(&path);
            assert_eq!(
                policy.evaluate3(&request, Some(&home())).unwrap(),
                expected,
                "{}",
                path.display()
            );
        }
        let read_policy = parse_policy(
            "schema_version: 1\npermissions:\n  allow: [\"Read(~/projects/**)\"]\n  deny: [\"Write(~/projects/**)\"]\n"
        ).unwrap();
        assert_eq!(
            read_policy
                .evaluate3(
                    &Request::Read(&home().join("projects/source.rs")),
                    Some(&home())
                )
                .unwrap(),
            Match3::AllowMatch {
                source: "Read(~/projects/**)".into()
            }
        );
    }

    #[test]
    fn tilde_other_user_is_bad_pattern() {
        let yaml = "schema_version: 1\npermissions:\n  allow:\n    - \"Read(~alice/x)\"\n";
        assert!(matches!(parse_policy(yaml), Err(AuthzError::BadPattern(_))));
    }

    #[test]
    fn read_relative_pattern_without_tilde_or_slash_is_bad_pattern() {
        let yaml = "schema_version: 1\npermissions:\n  allow:\n    - \"Read(relative/x)\"\n";
        assert!(matches!(parse_policy(yaml), Err(AuthzError::BadPattern(_))));
    }

    #[test]
    fn read_absolute_pattern_parses() {
        let yaml = "schema_version: 1\npermissions:\n  allow:\n    - \"Read(/etc/passwd)\"\n";
        let policy = parse_policy(yaml).unwrap();
        // The parsed pattern must retain the requested capability.
        let Pattern::Read(glob) = &policy.allow[0] else {
            panic!("Read policy must retain its capability");
        };
        assert!(glob
            .matches(Path::new("/etc/passwd"), Some(&home()))
            .unwrap());
    }

    #[test]
    fn pattern_missing_open_paren_is_bad_pattern() {
        let yaml = "schema_version: 1\npermissions:\n  allow:\n    - \"ReadNoParens\"\n";
        assert!(matches!(parse_policy(yaml), Err(AuthzError::BadPattern(_))));
    }

    #[test]
    fn pattern_missing_close_paren_is_bad_pattern() {
        let yaml = "schema_version: 1\npermissions:\n  allow:\n    - \"Read(~/x\"\n";
        assert!(matches!(parse_policy(yaml), Err(AuthzError::BadPattern(_))));
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
                matches!(parse_policy(&yaml), Err(AuthzError::BadPattern(_))),
                "{spec} must be refused as an unknown capability"
            );
        }
    }

    #[test]
    fn permissions_not_a_map_is_yaml_error() {
        let yaml = "schema_version: 1\npermissions: 5\n";
        assert!(matches!(parse_policy(yaml), Err(AuthzError::Yaml(_))));
    }

    #[test]
    fn allow_not_a_sequence_is_yaml_error() {
        let yaml = "schema_version: 1\npermissions:\n  allow: 5\n";
        assert!(matches!(parse_policy(yaml), Err(AuthzError::Yaml(_))));
    }

    #[test]
    fn allow_entry_not_a_string_is_yaml_error() {
        let yaml = "schema_version: 1\npermissions:\n  allow:\n    - 5\n";
        assert!(matches!(parse_policy(yaml), Err(AuthzError::Yaml(_))));
    }

    #[test]
    fn root_not_a_map_is_yaml_error() {
        assert!(matches!(
            parse_policy("- 1\n- 2\n"),
            Err(AuthzError::Yaml(_))
        ));
    }

    #[test]
    fn malformed_yaml_is_yaml_error() {
        assert!(matches!(
            parse_policy("schema_version: [1\n"),
            Err(AuthzError::Yaml(_))
        ));
    }

    #[test]
    fn permissions_absent_is_empty_policy() {
        let policy = parse_policy("schema_version: 1\n").unwrap();
        assert!(policy.allow.is_empty());
        assert!(policy.deny.is_empty());
    }

    // ---- glob matching semantics (spec §7) ----

    fn read_glob(pattern: &str) -> PathGlob {
        let Pattern::Read(g) = parse_pattern(&format!("Read({pattern})")).unwrap() else {
            panic!("Read pattern must parse as Read");
        };
        g
    }

    #[test]
    fn double_star_matches_dotfiles() {
        let glob = read_glob("~/**");
        assert!(glob
            .matches(Path::new("/home/operator/.ssh/id_ed25519"), Some(&home()))
            .unwrap());
    }

    #[test]
    fn literal_component_is_exact_not_prefix() {
        // A no-`*` component pattern must require EXACT component equality,
        // not merely a start-anchor with no end check — `component_matches`
        // splits on `*`, so a starless pattern is a single fragment where
        // `i == 0` and `i == last` coincide; the start/end anchor branches
        // must both apply to that one fragment (over-ALLOW otherwise).
        let glob = read_glob("/etc/passwd");
        assert!(glob
            .matches(Path::new("/etc/passwd"), Some(&home()))
            .unwrap());
        assert!(!glob
            .matches(Path::new("/etc/passwdX"), Some(&home()))
            .unwrap());
        assert!(!glob
            .matches(Path::new("/etc/passwd-backup"), Some(&home()))
            .unwrap());
    }

    #[test]
    fn double_star_home_does_not_leak_prefix_sharing_user() {
        // `~` is /home/operator (see `home()`); a DIFFERENT user
        // whose name merely shares the "operator" prefix — /home/operatorbot
        // — must NOT match `Read(~/**)`. Each path component ("operator" vs
        // "operatorbot") must be compared for exact equality, not prefix.
        let glob = read_glob("~/**");
        assert!(glob
            .matches(Path::new("/home/operator/.ssh/id_ed25519"), Some(&home()))
            .unwrap());
        assert!(!glob
            .matches(
                Path::new("/home/operatorbot/.ssh/id_ed25519"),
                Some(&home())
            )
            .unwrap());
    }

    #[test]
    fn double_star_matches_multiple_components_deep() {
        let glob = read_glob("~/**");
        assert!(glob
            .matches(
                Path::new("/home/operator/.ssh/nested/deep/file"),
                Some(&home())
            )
            .unwrap());
    }

    #[test]
    fn x_slash_doublestar_matches_x_itself() {
        let glob = read_glob("~/.ssh/**");
        assert!(glob
            .matches(Path::new("/home/operator/.ssh"), Some(&home()))
            .unwrap());
    }

    #[test]
    fn matching_is_byte_case_sensitive() {
        let glob = read_glob("~/.ssh/**");
        assert!(!glob
            .matches(Path::new("/home/operator/.SSH"), Some(&home()))
            .unwrap());
        assert!(!glob
            .matches(Path::new("/home/operator/.SSH/id_rsa"), Some(&home()))
            .unwrap());
    }

    #[test]
    fn literal_star_matches_within_component_only() {
        let glob = read_glob("~/*.txt");
        assert!(glob
            .matches(Path::new("/home/operator/foo.txt"), Some(&home()))
            .unwrap());
        assert!(!glob
            .matches(Path::new("/home/operator/sub/foo.txt"), Some(&home()))
            .unwrap());
    }

    #[test]
    fn read_pattern_does_not_match_unrelated_path() {
        let glob = read_glob("~/.ssh/**");
        assert!(!glob
            .matches(
                Path::new("/home/operator/.gnupg/pubring.kbx"),
                Some(&home())
            )
            .unwrap());
    }

    #[test]
    fn non_utf8_candidate_path_never_matches() {
        use std::ffi::OsStr;
        use std::os::unix::ffi::OsStrExt;
        let glob = read_glob("~/**");
        let bad = OsStr::from_bytes(&[0x66, 0xff, 0x6f]);
        assert!(!glob.matches(Path::new(bad), Some(&home())).unwrap());
    }

    #[test]
    fn a_non_utf8_home_is_unbound() {
        use std::ffi::OsStr;
        use std::os::unix::ffi::OsStrExt;
        let bad_home = OsStr::from_bytes(&[0x2f, 0xff, 0x2f]);
        assert_eq!(
            read_glob("~/x").matches(Path::new("/x"), Some(Path::new(bad_home))),
            Err(HomeUnbound)
        );
    }

    // ---- evaluate3: deny-wins, default-deny (spec §7) ----

    #[test]
    fn deny_beats_allow_and_default_deny() {
        let yaml = "schema_version: 1\npermissions:\n  allow:\n    - \"Read(~/**)\"\n  deny:\n    - \"Read(~/.ssh/**)\"\n";
        let policy = parse_policy(yaml).unwrap();

        // deny beats allow: inside ~ AND inside the denied ~/.ssh subtree.
        let denied = Request::Read(Path::new("/home/operator/.ssh/id_rsa"));
        assert_eq!(
            policy.evaluate3(&denied, Some(&home())),
            Ok(Match3::DenyMatch {
                source: "Read(~/.ssh/**)".into()
            })
        );

        // allowed: inside ~ but outside the deny list.
        let allowed = Request::Read(Path::new("/home/operator/docs/notes.txt"));
        assert_eq!(
            policy.evaluate3(&allowed, Some(&home())),
            Ok(Match3::AllowMatch {
                source: "Read(~/**)".into()
            })
        );

        // default-deny: matches neither list (outside the allow's ~ scope).
        let unmatched = Request::Read(Path::new("/etc/passwd"));
        assert_eq!(
            policy.evaluate3(&unmatched, Some(&home())),
            Ok(Match3::NoMatch)
        );
    }

    #[test]
    fn empty_policy_permits_nothing() {
        let policy = AuthzPolicy::default();
        let req = Request::Read(Path::new("/home/operator/anything"));
        assert_eq!(policy.evaluate3(&req, Some(&home())), Ok(Match3::NoMatch));
    }

    // ---- AuthzError Display ----

    #[test]
    fn display_covers_every_variant() {
        let cases = vec![
            AuthzError::UnknownSchemaVersion(2),
            AuthzError::Config(ConfigError::UnknownKey {
                section: "authz.permissions".into(),
                key: "denny".into(),
            }),
            AuthzError::BadPattern("WebSearch(x)".into()),
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
    fn root_policy_file_required_is_root_owned_and_masks_0o027() {
        assert_eq!(
            root_policy_file_required(),
            maknae_io::TargetRequired {
                owner: Some(0),
                mode_mask: Some(0o027),
                nlink_exactly_one: false,
                regular_file: true,
                max_bytes: None
            }
        );
    }

    #[test]
    fn authz_mask_admits_shipped_0640_and_refuses_world_readable_modes() {
        // Shipped-mode compatibility (spec §4.6): `root:_maknae 0640` — group
        // READ is required so the daemon (`_maknae`) can read its own policy —
        // must still satisfy the mask, while every world-accessible and
        // group/other-writable mode must violate it. Pinned against the mask
        // itself because a root-owned fixture cannot be created unprivileged.
        let mask = root_policy_file_required().mode_mask.unwrap();
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

    fn mine() -> maknae_io::TargetRequired {
        use std::os::unix::fs::MetadataExt;
        let dir = tmp("x").parent().unwrap().to_path_buf();
        let uid = std::fs::metadata(dir).unwrap().uid();
        maknae_io::TargetRequired {
            owner: Some(uid),
            ..root_policy_file_required()
        }
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
        let got = security_load_required(&link, mine());
        let _ = std::fs::remove_file(&link);
        let _ = std::fs::remove_file(&target);
        assert!(matches!(got, Err(AuthzError::Symlink)));
    }

    #[test]
    fn world_accessible_authz_refused() {
        let p = tmp("world");
        write_mode(&p, SHIPPED_DEFAULT, 0o666);
        let got = security_load_required(&p, mine());
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
        let got = load_authz(&p);
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
        let got = security_load_required(&tmp("nope_never_created"), mine());
        assert!(matches!(got, Err(AuthzError::Io(_))), "{got:?}");
    }

    #[test]
    fn shipped_0640_mode_passes_the_mask() {
        let p = tmp("shipped_0640");
        write_mode(&p, SHIPPED_DEFAULT, 0o640);
        let got = security_load_required(&p, mine());
        let _ = std::fs::remove_file(&p);
        assert_eq!(got.as_deref(), Ok(SHIPPED_DEFAULT));
    }

    #[test]
    fn group_writable_root_owned_authz_refused() {
        let p = tmp("group_writable");
        write_mode(&p, SHIPPED_DEFAULT, 0o660);
        let got = security_load_required(&p, mine());
        let _ = std::fs::remove_file(&p);
        assert!(matches!(got, Err(AuthzError::InsecurePermissions)));
    }

    #[test]
    fn world_readable_non_writable_authz_refused() {
        // Issue #129: 0644 is not group/other-writable, so a 0o022-only mask admits it.
        let p = tmp("world_readable");
        write_mode(&p, SHIPPED_DEFAULT, 0o644);
        let got = security_load_required(&p, mine());
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
        assert!(!glob
            .matches(Path::new("/home/operator"), Some(&home()))
            .unwrap());
        assert!(!glob
            .matches(Path::new("/home/operator/.ssh"), Some(&home()))
            .unwrap());
        assert!(glob
            .matches(Path::new("/home/operator/id_rsa"), Some(&home()))
            .unwrap());
        assert!(glob
            .matches(Path::new("/home/operator/.ssh/id_rsa"), Some(&home()))
            .unwrap());
    }

    #[test]
    fn component_trailing_star_matches_zero_or_more() {
        // A literal component ending in `*` (not the whole-segment `**`):
        // the last fragment is empty (nothing follows the trailing `*`), so
        // only the start-anchor check applies.
        let glob = read_glob("~/foo*");
        assert!(glob
            .matches(Path::new("/home/operator/foo"), Some(&home()))
            .unwrap());
        assert!(glob
            .matches(Path::new("/home/operator/foobar"), Some(&home()))
            .unwrap());
        assert!(!glob
            .matches(Path::new("/home/operator/fo"), Some(&home()))
            .unwrap());
    }

    #[test]
    fn component_start_anchor_rejects_literal_appearing_later() {
        // `a*c` (no leading `*`) requires text to START with `a` literally —
        // `a` merely APPEARING somewhere in the text is not enough. Pins the
        // `i == 0` / `!starts_with('*')` guard against both an `==`→`!=` (or
        // `delete !`) mutation, which would relax this to "found anywhere".
        let glob = read_glob("~/a*c");
        assert!(!glob
            .matches(Path::new("/home/operator/Xac"), Some(&home()))
            .unwrap());
        assert!(glob
            .matches(Path::new("/home/operator/aXc"), Some(&home()))
            .unwrap());
    }

    #[test]
    fn component_end_anchor_rejects_literal_appearing_earlier() {
        // `a*c` (no trailing `*`) requires text to END with `c` literally —
        // `c` appearing mid-string is not enough. Pins the `i == last` /
        // `!ends_with('*')` guard the same way as the start-anchor test above.
        let glob = read_glob("~/a*c");
        assert!(!glob
            .matches(Path::new("/home/operator/acX"), Some(&home()))
            .unwrap());
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
        assert!(glob
            .matches(Path::new("/home/operator/abcZZdefWWWghi"), Some(&home()))
            .unwrap());
        assert!(!glob
            .matches(Path::new("/home/operator/abcZZdeXWWWghi"), Some(&home()))
            .unwrap());
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
        assert!(!glob
            .matches(Path::new("/home/operator/abxyPPPz"), Some(&home()))
            .unwrap());
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
        assert!(glob
            .matches(Path::new("/home/operator/abcZZZZZxyghi"), Some(&home()))
            .unwrap());
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
        let via_seam = load_authz_with_requirement(&p, relaxed);
        let via_door = load_authz(&p);
        let _ = std::fs::remove_dir_all(&dir);

        let policy = via_seam.expect("seam loads a fixture the current euid owns");
        assert_eq!(policy.allow.len(), 2);
        // The PRODUCTION door on the same fixture must still demand root
        // ownership — proves adding the seam weakened nothing.
        assert!(
            matches!(via_door, Err(AuthzError::NotRootOwned)),
            "production load_authz must refuse a non-root fixture: {via_door:?}"
        );
    }

    // ---- evaluate3 (#85): three-valued with pattern provenance ----

    #[test]
    fn section_canonical_ignores_comments_whitespace_and_key_order_but_not_values() {
        let a = parse_authz("schema_version: 1\npermissions:\n  allow: [\"Read(~/**)\"]\n  deny: []\nroles:\n  admin:\n    allow: [\"admin.status\"]\n  user: {}\n").unwrap();
        let b = parse_authz("# comment\nschema_version: 1\n\nroles:\n  user: {}\n  admin:\n    allow:\n      - \"admin.status\"   # trailing\npermissions:\n  deny: []\n  allow:\n    - \"Read(~/**)\"\n").unwrap();
        assert_eq!(a.section_canonical("roles"), b.section_canonical("roles"));
        assert_eq!(
            a.section_canonical("permissions"),
            b.section_canonical("permissions")
        );
        assert_eq!(
            a.section_canonical("roles"),
            Some(r#"{"admin":{"allow":["admin.status"]},"user":{}}"#)
        );
        let c = parse_authz("schema_version: 1\npermissions:\n  allow: []\n  deny: []\nroles:\n  admin:\n    allow: [\"admin.status\"]\n  user:\n    allow: [\"admin.status\"]\n").unwrap();
        assert_ne!(a.section_canonical("roles"), c.section_canonical("roles"));
        assert_eq!(a.section_canonical("destinations"), None);
        let empty =
            parse_authz("schema_version: 1\npermissions:\n  allow: []\n  deny: []\nroles: {}\n")
                .unwrap();
        assert_eq!(empty.section_canonical("roles"), Some("{}"));
        let keys: Vec<&str> = a.sections().map(|(k, _)| k).collect();
        assert_eq!(keys, ["permissions", "roles", "schema_version"]);
        let values: Vec<&str> = a.sections().map(|(_, v)| v).collect();
        assert_eq!(values[2], "1");
    }

    #[test]
    fn allow_match_names_its_entry() {
        let p = parse_authz("schema_version: 1\npermissions:\n  allow: [\"Read(~/**)\", \"Read(/opt/**)\"]\n  deny: []\n").unwrap();
        let home = Path::new("/home/x");
        assert_eq!(
            p.evaluate3(&Request::Read(Path::new("/opt/a")), Some(home))
                .unwrap(),
            Match3::AllowMatch {
                source: "Read(/opt/**)".into()
            }
        );
        assert_eq!(
            p.allow_sources(),
            &["Read(~/**)".to_string(), "Read(/opt/**)".to_string()]
        );
        assert!(p.deny_sources().is_empty());
    }

    #[test]
    fn write_subtree_allow_match_names_its_entry() {
        let p = parse_authz("schema_version: 1\npermissions:\n  allow: [\"Write(/srv/**)\", \"Write(/opt/**)\"]\n  deny: [\"Read(/x)\"]\n").unwrap();
        assert_eq!(
            p.evaluate_write_subtree(Path::new("/opt/a"), None).unwrap(),
            Match3::AllowMatch {
                source: "Write(/opt/**)".into()
            }
        );
        assert_eq!(p.deny_sources(), &["Read(/x)".to_string()]);
    }

    #[test]
    fn evaluate3_deny_match_carries_full_source_text() {
        let p = parse_authz(SHIPPED_DEFAULT).unwrap();
        match p
            .evaluate3(
                &Request::Read(Path::new("/home/operator/.ssh/id_rsa")),
                Some(&home()),
            )
            .unwrap()
        {
            Match3::DenyMatch { source } => assert_eq!(source, "Read(~/.ssh/**)"),
            other => panic!("expected DenyMatch with source, got {other:?}"),
        }
    }

    #[test]
    fn evaluate3_allow_and_nomatch_are_distinct() {
        // The PDP backend needs the no-match/allow distinction (NoMatch → NotApplicable, spec
        // §4.4); since #181 it annotates that absence with WHY, audit-only.
        let p = parse_authz(SHIPPED_DEFAULT).unwrap();
        assert!(matches!(
            p.evaluate3(
                &Request::Read(Path::new("/home/operator/notes.txt")),
                Some(&home())
            )
            .unwrap(),
            Match3::AllowMatch { .. }
        ));
        assert!(matches!(
            p.evaluate3(&Request::Read(Path::new("/etc/hosts")), Some(&home()))
                .unwrap(),
            Match3::NoMatch
        ));
    }

    #[test]
    fn evaluate3_deny_overrides_allow() {
        // ~/.ssh/** is inside ~/** — both lists match; deny must win and
        // report ITS source.
        let p = parse_authz(SHIPPED_DEFAULT).unwrap();
        let r = Request::Read(Path::new("/home/operator/.ssh/config"));
        assert_eq!(
            p.evaluate3(&r, Some(&home())),
            Ok(Match3::DenyMatch {
                source: "Read(~/.ssh/**)".into()
            })
        );
    }

    #[test]
    fn a_bindings_key_refuses_and_names_bindings_yaml() {
        for body in [
            "schema_version: 1\nbindings:\n  admin: [\"alex\"]\n",
            "schema_version: 1\nbindings: {}\n",
            "schema_version: 1\npermissions:\n  allow: []\nbindings:\n  adversary: []\n",
        ] {
            let e = parse_authz(body).unwrap_err();
            assert_eq!(e, AuthzError::BindingsMoved, "{body:?}");
            assert!(e.to_string().contains("bindings.yaml"));
            assert!(e.to_string().contains("authz.yaml"));
        }
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
        let p = parse_authz(PREAMBLE).unwrap();
        assert!(p.action_grants.is_empty());
    }

    #[test]
    fn roles_parse_allow_and_deny_term_lists() {
        let body = format!(
            "{PREAMBLE}roles:\n  admin:\n    allow: [\"admin.status\"]\n    deny: [\"admin.config.show\"]\n"
        );
        let p = parse_authz(&body).unwrap();
        let g = p.action_grants.get("admin").expect("admin entry");
        assert_eq!(g.allow, vec!["admin.status".to_string()]);
        assert_eq!(g.deny, vec!["admin.config.show".to_string()]);
    }

    #[test]
    fn roles_entry_with_no_lists_parses_to_empty_lists() {
        // `admin: {}` is a MAP, so it is not the refused Null, and neither
        // `allow` nor `deny` is present. One shape, one arm -- flattening the
        // grammar collapsed what were two distinct paths to the same result.
        let body = format!("{PREAMBLE}roles:\n  admin: {{}}\n");
        let p = parse_authz(&body).unwrap();
        assert_eq!(
            p.action_grants.get("admin"),
            Some(&RawActionGrants::default())
        );
    }

    #[test]
    fn roles_unknown_key_under_role_refused() {
        // `roles.<name>` allows exactly `allow` and `deny` — a `permissions:`
        // typo here must not be silently accepted as a second, unenforced
        // grant surface.
        let body = format!("{PREAMBLE}roles:\n  admin:\n    permissions:\n    allow: []\n");
        let e = parse_authz(&body).unwrap_err();
        assert!(
            matches!(&e, AuthzError::Config(ConfigError::UnknownKey { key, .. }) if key == "permissions"),
            "must name the offending key: {e:?}"
        );
    }

    #[test]
    fn roles_typod_allow_key_refused() {
        let body = format!("{PREAMBLE}roles:\n  admin:\n    allwo: [\"admin.status\"]\n");
        let e = parse_authz(&body).unwrap_err();
        assert!(
            matches!(&e, AuthzError::Config(ConfigError::UnknownKey { key, .. }) if key == "allwo"),
            "a typo'd allow must refuse, not parse to an empty grant: {e:?}"
        );
    }

    #[test]
    fn roles_non_string_term_refused_with_roles_message() {
        // NOT str_seq's "permissions list entries must be strings" — an
        // operator debugging a roles typo must not be sent to the wrong section.
        let body = format!("{PREAMBLE}roles:\n  admin:\n    allow: [1001]\n");
        let e = parse_authz(&body).unwrap_err();
        assert!(
            matches!(&e, AuthzError::Yaml(m) if m.contains("roles") && !m.contains("permissions list")),
            "error must name roles: {e:?}"
        );
    }

    #[test]
    fn roles_null_term_list_refused_with_roles_message() {
        // A bare `allow:` parses Null, not an empty sequence. Refuse; do not
        // silently treat as empty.
        let body = format!("{PREAMBLE}roles:\n  admin:\n    allow:\n");
        let e = parse_authz(&body).unwrap_err();
        assert!(
            matches!(&e, AuthzError::Yaml(m) if m.contains("roles")),
            "{e:?}"
        );
    }

    #[test]
    fn roles_null_role_body_refused_with_roles_message() {
        let body = format!("{PREAMBLE}roles:\n  admin:\n");
        let e = parse_authz(&body).unwrap_err();
        assert!(
            matches!(&e, AuthzError::Yaml(m) if m.contains("roles")),
            "{e:?}"
        );
    }

    #[test]
    fn roles_non_map_refused() {
        let body = format!("{PREAMBLE}roles: [admin]\n");
        let e = parse_authz(&body).unwrap_err();
        assert!(
            matches!(&e, AuthzError::Yaml(m) if m.contains("roles")),
            "{e:?}"
        );
    }

    #[test]
    fn roles_entry_that_is_a_sequence_refused() {
        let body = format!("{PREAMBLE}roles:\n  admin: [admin.status]\n");
        let e = parse_authz(&body).unwrap_err();
        assert!(
            matches!(&e, AuthzError::Yaml(m) if m.contains("roles")),
            "{e:?}"
        );
    }

    /// A duplicate role key REFUSES the document. Reading `parse_policy` alone
    /// this looks last-wins (`out.insert`), which would mean a first `admin:`
    /// block carrying an explicit `deny:` could be nullified by a later
    /// duplicate carrying an `allow:` -- a written denial silently becoming a
    /// permit. It cannot happen, because `crate::load_str` refuses duplicate
    /// keys before the map reaches this function.
    ///
    /// That defense lives in another module, so this pins it from here. An
    /// external reviewer raised exactly this fail-open against `out.insert`;
    /// the concern was sound and the mechanism it assumed was absent, and the
    /// gap it actually found was that nothing at this layer held the invariant.
    #[test]
    fn roles_duplicate_role_key_refused_by_the_loader() {
        let body = format!(
            "{PREAMBLE}roles:\n  admin:\n    deny: [\"admin.status\"]\n  admin:\n    allow: [\"admin.status\"]\n"
        );
        let e = parse_authz(&body).unwrap_err();
        assert!(
            matches!(&e, AuthzError::Yaml(m) if m.contains("duplicate")),
            "a second `admin:` block must refuse the document, not overwrite the first: {e:?}"
        );
    }

    /// The same invariant one level down: a duplicate `allow:` inside one
    /// role's block. `get()` returns the FIRST match, so last-wins
    /// is not even the failure here -- an operator's second list would be
    /// silently ignored.
    #[test]
    fn roles_duplicate_allow_key_refused_by_the_loader() {
        let body = format!(
            "{PREAMBLE}roles:\n  admin:\n    allow: [\"admin.status\"]\n    allow: [\"admin.config.show\"]\n"
        );
        let e = parse_authz(&body).unwrap_err();
        assert!(
            matches!(&e, AuthzError::Yaml(m) if m.contains("duplicate")),
            "{e:?}"
        );
    }

    #[test]
    fn roles_does_not_disturb_permissions() {
        let body = "schema_version: 1\npermissions:\n  allow: [\"Read(~/**)\"]\n  deny: []\nroles:\n  admin:\n    allow: [\"admin.status\"]\n";
        let p = parse_authz(body).unwrap();
        assert_eq!(p.allow.len(), 1);
        assert_eq!(
            p.action_grants["admin"].allow,
            vec!["admin.status".to_string()]
        );
    }

    #[test]
    fn a_tilde_pattern_binds_to_the_home_it_is_given() {
        let g = read_glob("~/projects/**");
        let a = Path::new("/home/a");
        let b = Path::new("/home/b");
        assert_eq!(
            g.matches(Path::new("/home/a/projects/x"), Some(a)),
            Ok(true)
        );
        assert_eq!(
            g.matches(Path::new("/home/a/projects/x"), Some(b)),
            Ok(false)
        );
        assert_eq!(
            g.matches(Path::new("/home/b/projects/x"), Some(b)),
            Ok(true)
        );
    }

    #[test]
    fn a_tilde_pattern_with_no_home_is_unbound_not_a_miss() {
        let g = read_glob("~/**");
        assert_eq!(g.matches(Path::new("/home/a/x"), None), Err(HomeUnbound));
    }

    #[test]
    fn an_absolute_pattern_needs_no_home() {
        let g = read_glob("/etc/passwd");
        assert_eq!(g.matches(Path::new("/etc/passwd"), None), Ok(true));
    }

    #[test]
    fn a_home_is_a_literal_prefix_never_a_pattern() {
        let g = read_glob("~/**");
        let starred = Path::new("/home/a*");
        assert_eq!(g.matches(Path::new("/home/a*/x"), Some(starred)), Ok(true));
        assert_eq!(
            g.matches(Path::new("/home/abc/x"), Some(starred)),
            Ok(false)
        );
    }

    #[test]
    fn a_sibling_home_sharing_a_prefix_is_not_matched() {
        let g = read_glob("~/**");
        assert_eq!(
            g.matches(Path::new("/home/bob/x"), Some(Path::new("/home/b"))),
            Ok(false)
        );
    }

    #[test]
    fn trailing_and_doubled_slashes_in_the_home_bind_identically() {
        let g = read_glob("~/**");
        for h in ["/home/b", "/home/b/", "//home//b"] {
            assert_eq!(
                g.matches(Path::new("/home/b/x"), Some(Path::new(h))),
                Ok(true),
                "{h}"
            );
        }
    }

    #[test]
    fn a_home_that_is_not_canonical_and_absolute_is_unbound() {
        let g = read_glob("~/**");
        for h in ["/", "home/b", "/home/../b", "/home/./b"] {
            assert_eq!(
                g.matches(Path::new("/home/b/x"), Some(Path::new(h))),
                Err(HomeUnbound),
                "{h}"
            );
        }
    }

    #[test]
    fn tilde_other_user_is_still_a_bad_pattern() {
        assert!(matches!(
            parse_pattern("Read(~other/x)"),
            Err(AuthzError::BadPattern(_))
        ));
    }

    #[test]
    fn an_unbound_home_is_unbound_for_deny_rules_too() {
        let p = parse_authz(
            "schema_version: 1\npermissions:\n  allow:\n    - \"Read(/**)\"\n  deny:\n    - \"Read(~/.maknae/**)\"\n",
        )
        .unwrap();
        assert_eq!(
            p.evaluate3(&Request::Read(Path::new("/home/b/.maknae/token")), None),
            Err(HomeUnbound)
        );
        assert_eq!(
            p.evaluate3(
                &Request::Read(Path::new("/home/b/.maknae/token")),
                Some(Path::new("/home/b"))
            ),
            Ok(Match3::DenyMatch {
                source: "Read(~/.maknae/**)".into()
            })
        );
    }

    #[test]
    fn an_unbound_home_is_unbound_whatever_order_the_allows_are_in() {
        let p = parse_authz(
            "schema_version: 1\npermissions:\n  allow:\n    - \"Read(/srv/**)\"\n    - \"Read(~/**)\"\n  deny: []\n",
        )
        .unwrap();
        assert_eq!(
            p.evaluate3(&Request::Read(Path::new("/srv/x")), None),
            Err(HomeUnbound)
        );
    }

    #[test]
    fn an_invalid_home_is_unbound_whatever_order_the_allows_are_in() {
        let p = parse_authz(
            "schema_version: 1\npermissions:\n  allow:\n    - \"Read(/srv/**)\"\n    - \"Read(~/**)\"\n  deny: []\n",
        )
        .unwrap();
        for h in ["/", "home/b", "/home/../b"] {
            assert_eq!(
                p.evaluate3(&Request::Read(Path::new("/srv/x")), Some(Path::new(h))),
                Err(HomeUnbound),
                "{h}"
            );
        }
    }

    #[test]
    fn a_home_pattern_of_the_other_capability_does_not_need_a_home() {
        let p = parse_authz(
            "schema_version: 1\npermissions:\n  allow:\n    - \"Read(/srv/**)\"\n    - \"Write(~/**)\"\n  deny: []\n",
        )
        .unwrap();
        assert_eq!(
            p.evaluate3(&Request::Read(Path::new("/srv/x")), None),
            Ok(Match3::AllowMatch {
                source: "Read(/srv/**)".into()
            })
        );
    }

    #[test]
    fn the_subtree_checks_honour_the_home() {
        let p = parse_authz(
            "schema_version: 1\npermissions:\n  allow:\n    - \"Write(~/projects/**)\"\n  deny:\n    - \"Write(~/projects/keep/**)\"\n",
        )
        .unwrap();
        let b = Some(Path::new("/home/b"));
        assert_eq!(
            p.evaluate_write_subtree(Path::new("/home/b/projects/repo"), b),
            Ok(Match3::AllowMatch {
                source: "Write(~/projects/**)".into()
            })
        );
        assert!(matches!(
            p.evaluate_write_subtree(Path::new("/home/b/projects"), b),
            Ok(Match3::DenyMatch { .. })
        ));
        assert_eq!(
            p.evaluate_write_subtree(Path::new("/home/a/projects/repo"), b),
            Ok(Match3::NoMatch)
        );
        assert!(matches!(
            p.evaluate_write_subtree(Path::new("/home"), b),
            Ok(Match3::DenyMatch { .. })
        ));
        assert_eq!(
            p.evaluate_write_subtree(Path::new("/home/b/projects/repo"), None),
            Err(HomeUnbound)
        );
    }

    #[test]
    fn the_subtree_checks_consume_the_home_before_the_pattern() {
        let p = parse_authz(
            "schema_version: 1\npermissions:\n  allow:\n    - \"Write(~/projects/**)\"\n  deny:\n    - \"Write(~/projects/keep/**)\"\n",
        )
        .unwrap();
        let b = Some(Path::new("/home/b"));
        assert_eq!(
            p.evaluate_write_subtree(Path::new("/projects/repo"), b),
            Ok(Match3::NoMatch)
        );
        assert!(!matches!(
            p.evaluate_write_subtree(Path::new("/projects/keep/x"), b),
            Ok(Match3::DenyMatch { .. })
        ));
    }

    #[test]
    fn an_unbound_home_is_unbound_for_subtrees_whatever_order_the_allows_are_in() {
        let p = parse_authz(
            "schema_version: 1\npermissions:\n  allow:\n    - \"Write(/srv/**)\"\n    - \"Write(~/**)\"\n  deny: []\n",
        )
        .unwrap();
        assert_eq!(
            p.evaluate_write_subtree(Path::new("/srv/x"), None),
            Err(HomeUnbound)
        );
    }

    #[test]
    fn a_read_home_pattern_does_not_make_a_subtree_write_need_a_home() {
        let p = parse_authz(
            "schema_version: 1\npermissions:\n  allow:\n    - \"Write(/srv/**)\"\n  deny:\n    - \"Read(~/**)\"\n",
        )
        .unwrap();
        assert_eq!(
            p.evaluate_write_subtree(Path::new("/srv/x"), None),
            Ok(Match3::AllowMatch {
                source: "Write(/srv/**)".into()
            })
        );
    }

    #[test]
    fn a_policy_with_tilde_parses_with_no_home_at_all() {
        assert!(parse_authz(
            "schema_version: 1\npermissions:\n  allow:\n    - \"Read(~/**)\"\n  deny: []\n"
        )
        .is_ok());
    }
}
