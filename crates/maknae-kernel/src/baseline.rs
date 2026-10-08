//! The baseline decision table (#490): which baseline a boot runs, the pending
//! change set and its hash, the apply class of a change, and the accept decision.

use std::path::{Path, PathBuf};
use std::sync::{Arc, PoisonError, RwLock};

use maknae_config::{canonical_json, value_from_canonical_json, BaselineSections, Value};
use maknae_graph::identity::hex;
use maknae_state::envelope::sha256;

pub const ROOT_FILE: &str = "root-file";
pub const FOLLOWED_AT_BOOT: [&str; 2] = ["audit", "vault"];
pub const SEEDED_EVENT: &str =
    "baseline seeded from maknae.yaml and config.d (no accepted baseline yet)";

const SHORT_HEX: usize = 12;

pub fn reseeded_event(replaced: &[u8; 32]) -> String {
    let full = hex(replaced);
    format!(
        "baseline replaced by an authorized reseed from maknae.yaml and config.d; the accepted baseline sha256:{} is set aside",
        short(&full)
    )
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Apply {
    Live,
    Restart,
}

#[derive(Clone, PartialEq, Eq)]
pub enum PendingState {
    Valid {
        proposed: BaselineSections,
        apply: Apply,
        sections: Vec<String>,
    },
    Invalid {
        cause: String,
        proposed: Option<BaselineSections>,
    },
}

/// The cause is withheld: validator text can quote a value.
impl std::fmt::Debug for PendingState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Valid {
                proposed,
                apply,
                sections,
            } => f
                .debug_struct("Valid")
                .field("proposed", proposed)
                .field("apply", apply)
                .field("sections", sections)
                .finish(),
            Self::Invalid { proposed, .. } => f
                .debug_struct("Invalid")
                .field("proposed", proposed)
                .finish_non_exhaustive(),
        }
    }
}

/// A file that did not parse (`proposed: None`) or parsed and did not validate.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InvalidFile {
    pub cause: String,
    pub proposed: Option<BaselineSections>,
}

impl From<String> for InvalidFile {
    fn from(cause: String) -> Self {
        Self {
            cause,
            proposed: None,
        }
    }
}

impl From<&str> for InvalidFile {
    fn from(cause: &str) -> Self {
        cause.to_string().into()
    }
}

#[derive(Clone, PartialEq, Eq)]
pub struct PendingSet {
    pub source: &'static str,
    pub hash: String,
    pub state: PendingState,
}

/// The full hash appears only in the `admin.baseline.show` reply.
impl std::fmt::Debug for PendingSet {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PendingSet")
            .field("source", &self.source)
            .field("hash", &format_args!("sha256:{}", short(&self.hash)))
            .field("state", &self.state)
            .finish()
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Start {
    /// What this process runs and persists as the accepted baseline.
    pub run: BaselineSections,
    /// Written ahead of the persist when `run` differs from what the store holds.
    pub events: Vec<String>,
    pub pending: Option<PendingSet>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Move {
    pub from: PathBuf,
    pub to: PathBuf,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AcceptRefusal {
    NothingPending,
    Stale,
    Invalid,
    Malformed,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AcceptPlan {
    pub proposed: BaselineSections,
    pub apply: Apply,
    pub sections: Vec<String>,
}

fn sections_value(s: &BaselineSections) -> Value {
    Value::Map(
        s.iter()
            .map(|(k, v)| (k.clone(), Value::Str(v.clone())))
            .collect(),
    )
}

pub fn accepted_digest(s: &BaselineSections) -> [u8; 32] {
    sha256(canonical_json(&sections_value(s)).as_bytes())
}

pub fn change_set_hash(accepted: &BaselineSections, state: &PendingState) -> String {
    let mut doc = vec![
        (
            "accepted".to_string(),
            Value::Str(hex(&accepted_digest(accepted))),
        ),
        ("source".to_string(), Value::Str(ROOT_FILE.to_string())),
    ];
    let proposed = match state {
        PendingState::Valid { proposed, .. } => Some(proposed),
        PendingState::Invalid { cause, proposed } => {
            doc.push(("invalid".to_string(), Value::Str(cause.clone())));
            proposed.as_ref()
        }
    };
    if let Some(p) = proposed {
        doc.push(("proposed".to_string(), sections_value(p)));
    }
    let doc = Value::Map(doc);
    hex(&sha256(canonical_json(&doc).as_bytes()))
}

pub fn changed_sections(a: &BaselineSections, b: &BaselineSections) -> Vec<String> {
    let names: std::collections::BTreeSet<&String> = a.keys().chain(b.keys()).collect();
    names
        .into_iter()
        .filter(|n| a.get(n) != b.get(n))
        .cloned()
        .collect()
}

pub fn apply_of(a: &BaselineSections, b: &BaselineSections) -> Apply {
    let all_live = changed_sections(a, b).iter().all(|name| {
        let (old, new) = (a.get(name), b.get(name));
        match name.as_str() {
            "principal" => true,
            "providers" => non_empty_seq(old) && non_empty_seq(new),
            "audit" => equal_without(old, new, &["readers"]),
            "core" => equal_without(old, new, &["handling", "ceiling"]),
            _ => false,
        }
    });
    if all_live {
        Apply::Live
    } else {
        Apply::Restart
    }
}

fn non_empty_seq(v: Option<&String>) -> bool {
    matches!(
        v.map(|s| value_from_canonical_json(s)),
        Some(Ok(Value::Seq(items))) if !items.is_empty()
    )
}

fn equal_without(old: Option<&String>, new: Option<&String>, path: &[&str]) -> bool {
    let strip = |s: Option<&String>| -> Option<String> {
        let mut v = value_from_canonical_json(s?).ok()?;
        remove_path(&mut v, path);
        Some(canonical_json(&v))
    };
    match (strip(old), strip(new)) {
        (Some(o), Some(n)) => o == n,
        _ => false,
    }
}

/// Removes the key at `path`, and an intermediate map that this removal empties.
/// Returns whether a key was removed.
fn remove_path(v: &mut Value, path: &[&str]) -> bool {
    let (Value::Map(entries), Some((key, rest))) = (v, path.split_first()) else {
        return false;
    };
    let Some(at) = entries.iter().position(|(k, _)| k == key) else {
        return false;
    };
    if rest.is_empty() {
        entries.remove(at);
        return true;
    }
    let child = &mut entries[at].1;
    let removed = remove_path(child, rest);
    if removed && matches!(child, Value::Map(m) if m.is_empty()) {
        entries.remove(at);
    }
    removed
}

pub fn pending(
    accepted: &BaselineSections,
    file: &Result<BaselineSections, InvalidFile>,
) -> Option<PendingSet> {
    let state = match file {
        Ok(f) if f == accepted => return None,
        Ok(f) => PendingState::Valid {
            proposed: f.clone(),
            apply: apply_of(accepted, f),
            sections: changed_sections(accepted, f),
        },
        Err(invalid) => PendingState::Invalid {
            cause: invalid.cause.clone(),
            proposed: invalid.proposed.clone(),
        },
    };
    Some(PendingSet {
        source: ROOT_FILE,
        hash: change_set_hash(accepted, &state),
        state,
    })
}

/// `Err(cause)` only when there is no accepted baseline and the file is invalid.
pub fn at_boot(
    accepted: Option<&BaselineSections>,
    file: Result<BaselineSections, InvalidFile>,
    mix_valid: impl Fn(&BaselineSections) -> Result<(), String>,
) -> Result<Start, String> {
    let Some(acc) = accepted else {
        return file
            .map(|f| Start {
                run: f,
                events: vec![SEEDED_EVENT.into()],
                pending: None,
            })
            .map_err(|invalid| invalid.cause);
    };
    let f = match file {
        Ok(f) => f,
        Err(invalid) => {
            return Ok(Start {
                run: acc.clone(),
                events: vec![],
                pending: pending(acc, &Err(invalid)),
            })
        }
    };
    let mut mix = acc.clone();
    for name in FOLLOWED_AT_BOOT {
        match f.get(name) {
            Some(v) => {
                mix.insert(name.into(), v.clone());
            }
            None => {
                mix.remove(name);
            }
        }
    }
    if let Err(cause) = mix_valid(&mix) {
        let cause = if mix == *acc {
            format!("the accepted baseline no longer validates: {cause}")
        } else {
            format!("the file's vault and audit sections cannot start: {cause}")
        };
        return Ok(Start {
            run: acc.clone(),
            events: vec![],
            pending: pending(
                acc,
                &Err(InvalidFile {
                    cause,
                    proposed: Some(f),
                }),
            ),
        });
    }
    let events = FOLLOWED_AT_BOOT
        .iter()
        .filter(|n| acc.get(n) != mix.get(n))
        .map(|n| format!("{n} follows maknae.yaml at start"))
        .collect();
    let pending = pending(&mix, &Ok(f));
    Ok(Start {
        run: mix,
        events,
        pending,
    })
}

/// `accepted` is the trail the store last ran: its `moved_from` when an accept moved it, else the accepted path.
pub fn move_of(accepted: Option<&Path>, run: &Path) -> Result<Option<Move>, String> {
    let Some(from) = accepted.filter(|from| *from != run) else {
        return Ok(None);
    };
    let sibling = run.is_absolute()
        && run.file_name().is_some()
        && from.file_name().is_some()
        && from.parent() == run.parent();
    if !sibling {
        return Err(format!(
            "the audit trail may move only within {}",
            from.parent().unwrap_or(from).display()
        ));
    }
    Ok(Some(Move {
        from: from.into(),
        to: run.into(),
    }))
}

pub fn decide_accept(
    current: Option<&PendingSet>,
    named: &str,
) -> Result<AcceptPlan, AcceptRefusal> {
    let well_formed = named.len() == 64
        && named
            .bytes()
            .all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f'));
    if !well_formed {
        return Err(AcceptRefusal::Malformed);
    }
    let p = current.ok_or(AcceptRefusal::NothingPending)?;
    if named != p.hash {
        return Err(AcceptRefusal::Stale);
    }
    match &p.state {
        PendingState::Invalid { .. } => Err(AcceptRefusal::Invalid),
        PendingState::Valid {
            proposed,
            apply,
            sections,
        } => Ok(AcceptPlan {
            proposed: proposed.clone(),
            apply: *apply,
            sections: sections.clone(),
        }),
    }
}

fn class(p: &PendingSet) -> &'static str {
    match p.state {
        PendingState::Valid {
            apply: Apply::Live, ..
        } => "live",
        PendingState::Valid {
            apply: Apply::Restart,
            ..
        } => "restart",
        PendingState::Invalid { .. } => "invalid",
    }
}

pub fn status_line(p: &PendingSet) -> String {
    format!("baseline: 1 pending ({})", class(p))
}

pub fn record_fields(p: &PendingSet) -> (&'static str, String, &'static str) {
    match &p.state {
        PendingState::Valid { sections, .. } => (
            "deny",
            format!(
                "baseline change pending acceptance: {} sha256:{} (apply: {}; sections: {})",
                p.source,
                short(&p.hash),
                class(p),
                sections.join(",")
            ),
            "unauthorized",
        ),
        PendingState::Invalid { cause, .. } => (
            "deny",
            format!("baseline change refused: invalid: {cause}"),
            "unavailable",
        ),
    }
}

/// What the journal may say about a pending set: never its hash.
pub fn journal_line(p: &PendingSet) -> String {
    match &p.state {
        PendingState::Valid { .. } => format!(
            "baseline change pending acceptance: {} (apply: {})",
            p.source,
            class(p)
        ),
        PendingState::Invalid { cause, .. } => {
            format!("baseline change refused: {} invalid: {cause}", p.source)
        }
    }
}

/// The 12-hex correlation prefix the audit trail carries.
pub fn short(hash: &str) -> &str {
    hash.get(..SHORT_HEX).unwrap_or(hash)
}

/// The accepted baseline this process runs and the set pending against it, as last published.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BaselineState {
    pub accepted: BaselineSections,
    pub pending: Option<PendingSet>,
}

#[derive(Debug, Clone)]
pub struct BaselineStatus(Arc<RwLock<Arc<BaselineState>>>);

impl BaselineStatus {
    pub fn new(state: BaselineState) -> Self {
        Self(Arc::new(RwLock::new(Arc::new(state))))
    }

    pub fn current(&self) -> Arc<BaselineState> {
        Arc::clone(&self.0.read().unwrap_or_else(PoisonError::into_inner))
    }

    /// Replaces the state; returns whether the pending set's hash changed.
    pub fn publish(&self, state: BaselineState) -> bool {
        let mut slot = self.0.write().unwrap_or_else(PoisonError::into_inner);
        let hash = |s: &BaselineState| s.pending.as_ref().map(|p| p.hash.clone());
        let changed = hash(&slot) != hash(&state);
        *slot = Arc::new(state);
        changed
    }

    pub fn lines(&self) -> Vec<String> {
        self.current().pending.iter().map(status_line).collect()
    }
}

/// The old trail's last record before a move.
pub fn move_record(to: &Path) -> String {
    format!("audit trail moves to {} at start", to.display())
}

/// The new trail's first record after a move.
pub fn back_link_record(from: &Path, carried: Option<u64>, old_open: Option<&str>) -> String {
    let revision = carried.map_or_else(|| "none".to_string(), |r| r.to_string());
    let link = format!(
        "audit trail continues from {}; last checkpoint revision {revision}",
        from.display()
    );
    match old_open {
        Some(e) => format!("{link}; the previous trail could not be opened: {e}"),
        None => link,
    }
}

/// The store transition's record of a move the boot performed.
pub fn moved_event(from: &Path, to: &Path) -> String {
    format!(
        "audit trail moved from {} to {}",
        from.display(),
        to.display()
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    fn s(pairs: &[(&str, &str)]) -> BaselineSections {
        pairs
            .iter()
            .map(|(k, v)| (k.to_string(), v.to_string()))
            .collect()
    }
    const CORE: &str = r#"{"deployment_id":"d"}"#;
    const CORE_SECRET: &str =
        r#"{"deployment_id":"d","handling":{"ceiling":{"classification":"SECRET"}}}"#;
    const CORE_AUS: &str = r#"{"deployment_id":"d","handling":{"policy":"AUS"}}"#;
    const AUDIT_A: &str = r#"{"jsonl_path":"/var/log/maknae/audit.jsonl"}"#;
    const AUDIT_B: &str = r#"{"jsonl_path":"/var/log/maknae/audit-2.jsonl"}"#;
    const AUDIT_A_READERS: &str =
        r#"{"jsonl_path":"/var/log/maknae/audit.jsonl","readers":["vector"]}"#;
    const VAULT_A: &str = r#"{"addr":"https://a:8200"}"#;
    const VAULT_B: &str = r#"{"addr":"https://b:8200"}"#;
    const PRINCIPAL_A: &str = r#"{"name":"op","uid":1000}"#;
    const PRINCIPAL_B: &str = r#"{"name":"op2","uid":1001}"#;
    const PROVIDERS_1: &str = r#"[{"name":"openai"}]"#;
    const PROVIDERS_2: &str = r#"[{"name":"openai"},{"name":"other"}]"#;
    const PROVIDERS_0: &str = r#"[]"#;
    fn ok(_: &BaselineSections) -> Result<(), String> {
        Ok(())
    }

    #[test]
    fn first_boot_seeds_from_a_valid_file_with_no_pending_set() {
        let f = s(&[("core", CORE), ("audit", AUDIT_A)]);
        let st = at_boot(None, Ok(f.clone()), ok).unwrap();
        assert_eq!(st.run, f);
        assert_eq!(st.events, vec![SEEDED_EVENT.to_string()]);
        assert_eq!(st.pending, None);
    }

    #[test]
    fn first_boot_with_an_invalid_file_refuses() {
        assert_eq!(
            at_boot(None, Err("bad yaml".into()), ok),
            Err("bad yaml".into())
        );
    }

    #[test]
    fn first_boot_does_not_consult_the_mix() {
        let f = s(&[("core", CORE)]);
        let st = at_boot(None, Ok(f.clone()), |_| Err("unused".into())).unwrap();
        assert_eq!(st.run, f);
    }

    #[test]
    fn a_restart_never_accepts_a_pending_change() {
        let acc = s(&[("core", CORE), ("audit", AUDIT_A)]);
        let f = s(&[("core", CORE_SECRET), ("audit", AUDIT_A)]);
        let st = at_boot(Some(&acc), Ok(f.clone()), ok).unwrap();
        assert_eq!(st.run, acc);
        assert!(st.events.is_empty());
        let p = st.pending.unwrap();
        assert_eq!(p.source, ROOT_FILE);
        assert_eq!(
            p.state,
            PendingState::Valid {
                proposed: f,
                apply: Apply::Live,
                sections: vec!["core".into()]
            }
        );
    }

    #[test]
    fn an_unchanged_file_runs_the_accepted_baseline_with_nothing_pending() {
        let acc = s(&[("core", CORE), ("audit", AUDIT_A), ("vault", VAULT_A)]);
        let st = at_boot(Some(&acc), Ok(acc.clone()), ok).unwrap();
        assert_eq!(
            st,
            Start {
                run: acc,
                events: vec![],
                pending: None
            }
        );
    }

    #[test]
    fn vault_and_audit_follow_the_file_at_boot_and_nothing_else_does() {
        let acc = s(&[("core", CORE), ("audit", AUDIT_A), ("vault", VAULT_A)]);
        let f = s(&[
            ("core", CORE_SECRET),
            ("audit", AUDIT_B),
            ("vault", VAULT_B),
        ]);
        let st = at_boot(Some(&acc), Ok(f.clone()), ok).unwrap();
        assert_eq!(
            st.run,
            s(&[("core", CORE), ("audit", AUDIT_B), ("vault", VAULT_B)])
        );
        assert_eq!(
            st.events,
            vec![
                "audit follows maknae.yaml at start".to_string(),
                "vault follows maknae.yaml at start".to_string()
            ]
        );
        assert!(
            matches!(st.pending.unwrap().state, PendingState::Valid { ref sections, .. } if sections == &vec!["core".to_string()])
        );
    }

    #[test]
    fn a_file_differing_only_in_followed_sections_runs_it_with_nothing_pending() {
        let acc = s(&[("core", CORE), ("audit", AUDIT_A), ("vault", VAULT_A)]);
        let f = s(&[("core", CORE), ("audit", AUDIT_A), ("vault", VAULT_B)]);
        let st = at_boot(Some(&acc), Ok(f.clone()), ok).unwrap();
        assert_eq!(st.run, f);
        assert_eq!(
            st.events,
            vec!["vault follows maknae.yaml at start".to_string()]
        );
        assert_eq!(st.pending, None);
    }

    #[test]
    fn a_followed_section_added_by_the_file_is_added_to_the_run() {
        let acc = s(&[("core", CORE), ("audit", AUDIT_A)]);
        let f = s(&[("core", CORE), ("audit", AUDIT_A), ("vault", VAULT_A)]);
        let st = at_boot(Some(&acc), Ok(f.clone()), ok).unwrap();
        assert_eq!(st.run, f);
        assert_eq!(
            st.events,
            vec!["vault follows maknae.yaml at start".to_string()]
        );
        assert_eq!(st.pending, None);
    }

    #[test]
    fn a_followed_section_removed_from_the_file_is_removed_from_the_run() {
        let acc = s(&[("core", CORE), ("audit", AUDIT_A), ("vault", VAULT_A)]);
        let f = s(&[("core", CORE), ("audit", AUDIT_A)]);
        let st = at_boot(Some(&acc), Ok(f), ok).unwrap();
        assert!(!st.run.contains_key("vault"));
        assert_eq!(
            st.events,
            vec!["vault follows maknae.yaml at start".to_string()]
        );
        assert_eq!(st.pending, None);
    }

    #[test]
    fn the_mix_validated_is_the_accepted_baseline_with_the_files_followed_sections() {
        let acc = s(&[("core", CORE), ("audit", AUDIT_A), ("vault", VAULT_A)]);
        let f = s(&[("core", CORE_SECRET), ("audit", AUDIT_B)]);
        let seen = std::cell::RefCell::new(None);
        at_boot(Some(&acc), Ok(f), |m| {
            *seen.borrow_mut() = Some(m.clone());
            Ok(())
        })
        .unwrap();
        assert_eq!(
            seen.into_inner(),
            Some(s(&[("core", CORE), ("audit", AUDIT_B)]))
        );
    }

    #[test]
    fn an_invalid_file_keeps_the_accepted_baseline_and_is_pending_invalid() {
        let acc = s(&[("core", CORE), ("audit", AUDIT_A)]);
        let st = at_boot(Some(&acc), Err("unknown key".into()), ok).unwrap();
        assert_eq!(st.run, acc);
        assert!(st.events.is_empty());
        let p = st.pending.unwrap();
        assert!(
            matches!(p.state, PendingState::Invalid { ref cause, .. } if cause == "unknown key")
        );
        assert_eq!(p, pending(&acc, &Err("unknown key".into())).unwrap());
    }

    #[test]
    fn a_mix_that_does_not_validate_follows_nothing_and_is_pending_invalid() {
        let acc = s(&[("core", CORE), ("audit", AUDIT_A)]);
        let f = s(&[("core", CORE), ("audit", AUDIT_B)]);
        let st = at_boot(Some(&acc), Ok(f), |_| Err("not prepared".into())).unwrap();
        assert_eq!(st.run, acc);
        assert!(st.events.is_empty());
        let p = st.pending.unwrap();
        assert_eq!(
            p.state,
            PendingState::Invalid {
                cause: "the file's vault and audit sections cannot start: not prepared".into(),
                proposed: Some(s(&[("core", CORE), ("audit", AUDIT_B)]))
            }
        );
        assert_eq!(
            decide_accept(Some(&p), &p.hash),
            Err(AcceptRefusal::Invalid)
        );
    }

    #[test]
    fn a_file_equal_to_the_accepted_baseline_has_no_pending_set() {
        let acc = s(&[("core", CORE)]);
        assert_eq!(pending(&acc, &Ok(acc.clone())), None);
    }

    #[test]
    fn the_hash_binds_the_accepted_baseline_the_source_and_the_proposal() {
        let a = s(&[("core", CORE)]);
        let b = s(&[("core", CORE_SECRET)]);
        let h = |acc: &BaselineSections, f: &BaselineSections| {
            pending(acc, &Ok(f.clone())).unwrap().hash
        };
        assert_eq!(h(&a, &b), h(&a, &b));
        assert_ne!(h(&a, &b), h(&b, &a));
        assert_ne!(h(&a, &b), h(&s(&[("core", CORE), ("lake", "{}")]), &b));
        assert_eq!(h(&a, &b).len(), 64);
        assert!(h(&a, &b)
            .bytes()
            .all(|c| c.is_ascii_hexdigit() && !c.is_ascii_uppercase()));
        let invalid = pending(&a, &Err("x".into())).unwrap().hash;
        assert_ne!(invalid, pending(&a, &Err("y".into())).unwrap().hash);
    }

    #[test]
    fn the_hash_is_sha256_of_the_canonical_change_document() {
        let a = s(&[("core", CORE)]);
        let acc = hex(&accepted_digest(&a));
        let valid = pending(&a, &Ok(s(&[("core", CORE_SECRET)]))).unwrap();
        let doc = format!(
            r#"{{"accepted":"{acc}","proposed":{{"core":"{}"}},"source":"root-file"}}"#,
            CORE_SECRET.replace('"', "\\\"")
        );
        assert_eq!(valid.hash, hex(&sha256(doc.as_bytes())));
        let invalid = pending(&a, &Err("bad".into())).unwrap();
        let doc = format!(r#"{{"accepted":"{acc}","invalid":"bad","source":"root-file"}}"#);
        assert_eq!(invalid.hash, hex(&sha256(doc.as_bytes())));
    }

    #[test]
    fn two_invalid_files_failing_for_the_same_cause_hash_apart() {
        let a = s(&[("core", CORE)]);
        let invalid = |f: BaselineSections| {
            pending(
                &a,
                &Err(InvalidFile {
                    cause: "same".into(),
                    proposed: Some(f),
                }),
            )
            .unwrap()
            .hash
        };
        let one = invalid(s(&[("core", CORE_SECRET)]));
        let two = invalid(s(&[("core", CORE_AUS)]));
        assert_ne!(one, two);
        assert_ne!(one, pending(&a, &Err("same".into())).unwrap().hash);
        let acc = hex(&accepted_digest(&a));
        let doc = format!(
            r#"{{"accepted":"{acc}","invalid":"same","proposed":{{"core":"{}"}},"source":"root-file"}}"#,
            CORE_SECRET.replace('"', "\\\"")
        );
        assert_eq!(one, hex(&sha256(doc.as_bytes())));
    }

    #[test]
    fn a_file_that_did_not_parse_hashes_by_its_cause_alone() {
        let a = s(&[("core", CORE)]);
        let once = pending(&a, &Err("bad yaml".into())).unwrap();
        assert_eq!(once, pending(&a, &Err("bad yaml".into())).unwrap());
        assert_eq!(
            once.state,
            PendingState::Invalid {
                cause: "bad yaml".into(),
                proposed: None
            }
        );
    }

    #[test]
    fn every_edit_of_a_file_whose_mix_fails_is_a_new_set() {
        let acc = s(&[("core", CORE), ("audit", AUDIT_A)]);
        let fail = |_: &BaselineSections| Err("not prepared".to_string());
        let hash = |f: BaselineSections| {
            at_boot(Some(&acc), Ok(f), fail)
                .unwrap()
                .pending
                .unwrap()
                .hash
        };
        assert_ne!(
            hash(s(&[("core", CORE), ("audit", AUDIT_B)])),
            hash(s(&[("core", CORE_SECRET), ("audit", AUDIT_B)]))
        );
    }

    #[test]
    fn a_failing_mix_equal_to_the_accepted_baseline_names_the_accepted_baseline() {
        let acc = s(&[("core", CORE), ("audit", AUDIT_A)]);
        let f = s(&[("core", CORE_SECRET), ("audit", AUDIT_A)]);
        let st = at_boot(Some(&acc), Ok(f.clone()), |_| Err("gone".into())).unwrap();
        assert_eq!(st.run, acc);
        assert!(st.events.is_empty());
        assert_eq!(
            st.pending.unwrap().state,
            PendingState::Invalid {
                cause: "the accepted baseline no longer validates: gone".into(),
                proposed: Some(f)
            }
        );
    }

    #[test]
    fn a_valid_set_hash_is_pinned() {
        let p = pending(&s(&[("core", CORE)]), &Ok(s(&[("core", CORE_SECRET)]))).unwrap();
        assert_eq!(
            p.hash,
            "900f017f9f6980cec7e8331657da437eb8d72ded7fc6cd2fd14833db89b3c07f"
        );
    }

    #[test]
    fn the_accepted_digest_is_the_one_the_boot_seed_already_stores() {
        let fixed = s(&[
            ("audit", r#"{"jsonl_path":"/var/log/maknae/audit.jsonl"}"#),
            ("core", r#"{"deployment_id":"test"}"#),
            ("vault", r#"{"addr":"https://a:8200"}"#),
        ]);
        assert_eq!(
            hex(&accepted_digest(&fixed)),
            "435326f94e81c0ddecb9eb8770589e9af94e55d7b62cac53e6d3a536d486f0c0"
        );
    }

    #[test]
    fn changed_sections_are_the_sorted_differing_union() {
        let a = s(&[("audit", AUDIT_A), ("core", CORE), ("vault", VAULT_A)]);
        let b = s(&[
            ("core", CORE),
            ("principal", PRINCIPAL_A),
            ("vault", VAULT_B),
        ]);
        assert_eq!(
            changed_sections(&a, &b),
            vec!["audit".to_string(), "principal".into(), "vault".into()]
        );
        assert!(changed_sections(&a, &a).is_empty());
    }

    #[test]
    fn apply_classes() {
        let base = s(&[
            ("core", CORE),
            ("audit", AUDIT_A),
            ("principal", PRINCIPAL_A),
            ("providers", PROVIDERS_1),
            ("vault", VAULT_A),
        ]);
        let with = |k: &str, v: &str| {
            let mut b = base.clone();
            b.insert(k.into(), v.into());
            b
        };
        let without = |k: &str| {
            let mut b = base.clone();
            b.remove(k);
            b
        };
        assert_eq!(apply_of(&base, &base), Apply::Live);
        assert_eq!(apply_of(&base, &with("core", CORE_SECRET)), Apply::Live);
        assert_eq!(apply_of(&base, &with("core", CORE_AUS)), Apply::Restart);
        assert_eq!(
            apply_of(&base, &with("core", r#"{"deployment_id":"e"}"#)),
            Apply::Restart
        );
        assert_eq!(
            apply_of(&base, &with("principal", PRINCIPAL_B)),
            Apply::Live
        );
        assert_eq!(apply_of(&base, &without("principal")), Apply::Live);
        assert_eq!(apply_of(&without("principal"), &base), Apply::Live);
        assert_eq!(
            apply_of(&base, &with("providers", PROVIDERS_2)),
            Apply::Live
        );
        assert_eq!(
            apply_of(&base, &with("providers", PROVIDERS_0)),
            Apply::Restart
        );
        assert_eq!(
            apply_of(&with("providers", PROVIDERS_0), &base),
            Apply::Restart
        );
        assert_eq!(
            apply_of(&base, &with("providers", r#"{"name":"openai"}"#)),
            Apply::Restart
        );
        assert_eq!(apply_of(&base, &without("providers")), Apply::Restart);
        assert_eq!(apply_of(&without("providers"), &base), Apply::Restart);
        assert_eq!(
            apply_of(&base, &with("audit", AUDIT_A_READERS)),
            Apply::Live
        );
        assert_eq!(
            apply_of(&with("audit", AUDIT_A_READERS), &base),
            Apply::Live
        );
        assert_eq!(apply_of(&base, &with("audit", AUDIT_B)), Apply::Restart);
        assert_eq!(apply_of(&base, &without("audit")), Apply::Restart);
        assert_eq!(apply_of(&base, &without("core")), Apply::Restart);
        assert_eq!(apply_of(&base, &with("vault", VAULT_B)), Apply::Restart);
        assert_eq!(apply_of(&base, &with("transport", "{}")), Apply::Restart);
        assert_eq!(apply_of(&base, &with("lake", "{}")), Apply::Restart);
        let mut both = with("principal", PRINCIPAL_B);
        both.insert("vault".into(), VAULT_B.into());
        assert_eq!(apply_of(&base, &both), Apply::Restart);
    }

    #[test]
    fn only_the_ceiling_subtree_of_core_is_live() {
        let us = r#"{"deployment_id":"d","handling":{"policy":"US"}}"#;
        let us_secret = r#"{"deployment_id":"d","handling":{"ceiling":{"classification":"SECRET"},"policy":"US"}}"#;
        let aus_secret = r#"{"deployment_id":"d","handling":{"ceiling":{"classification":"SECRET"},"policy":"AUS"}}"#;
        let empty_handling = r#"{"deployment_id":"d","handling":{}}"#;
        let a = |v: &str, w: &str| apply_of(&s(&[("core", v)]), &s(&[("core", w)]));
        assert_eq!(a(us, us_secret), Apply::Live);
        assert_eq!(a(us_secret, us), Apply::Live);
        assert_eq!(a(CORE_SECRET, us_secret), Apply::Restart);
        assert_eq!(a(us, aus_secret), Apply::Restart);
        assert_eq!(a(CORE, empty_handling), Apply::Restart);
        assert_eq!(a(CORE_SECRET, CORE), Apply::Live);
        assert_eq!(a(r#"{"ceiling":1}"#, r#"{"ceiling":2}"#), Apply::Restart);
        assert_eq!(
            a(r#"{"handling":"x"}"#, r#"{"handling":"y"}"#),
            Apply::Restart
        );
        assert_eq!(a(r#"[1]"#, r#"[2]"#), Apply::Restart);
    }

    #[test]
    fn an_unparseable_section_value_is_restart_class() {
        let a = s(&[("core", CORE)]);
        assert_eq!(apply_of(&a, &s(&[("core", "not json")])), Apply::Restart);
        assert_eq!(apply_of(&s(&[("core", "not json")]), &a), Apply::Restart);
        let p = s(&[("providers", PROVIDERS_1)]);
        assert_eq!(apply_of(&p, &s(&[("providers", "[")])), Apply::Restart);
    }

    #[test]
    fn a_reseed_event_names_only_the_replaced_digest_prefix() {
        let d = accepted_digest(&s(&[("core", CORE)]));
        let e = reseeded_event(&d);
        let hex = maknae_graph::identity::hex(&d);
        assert_eq!(e, format!("baseline replaced by an authorized reseed from maknae.yaml and config.d; the accepted baseline sha256:{} is set aside", &hex[..12]));
        assert!(!e.contains(&hex));
    }

    #[test]
    fn decide_accept_refuses_every_hash_but_the_current_valid_one() {
        let a = s(&[("core", CORE)]);
        let p = pending(&a, &Ok(s(&[("core", CORE_SECRET)]))).unwrap();
        let inv = pending(&a, &Err("x".into())).unwrap();
        assert_eq!(
            decide_accept(None, &p.hash),
            Err(AcceptRefusal::NothingPending)
        );
        assert_eq!(decide_accept(None, ""), Err(AcceptRefusal::Malformed));
        assert_eq!(
            decide_accept(Some(&inv), &inv.hash),
            Err(AcceptRefusal::Invalid)
        );
        assert_eq!(
            decide_accept(Some(&inv), &p.hash),
            Err(AcceptRefusal::Stale)
        );
        assert_eq!(
            decide_accept(Some(&p), &"0".repeat(64)),
            Err(AcceptRefusal::Stale)
        );
        assert_eq!(
            decide_accept(Some(&p), &p.hash.to_uppercase()),
            Err(AcceptRefusal::Malformed)
        );
        assert_eq!(
            decide_accept(Some(&p), &p.hash[..63]),
            Err(AcceptRefusal::Malformed)
        );
        assert_eq!(
            decide_accept(Some(&p), &format!("{}0", p.hash)),
            Err(AcceptRefusal::Malformed)
        );
        assert_eq!(
            decide_accept(Some(&p), &format!("g{}", &p.hash[1..])),
            Err(AcceptRefusal::Malformed)
        );
        assert_eq!(decide_accept(Some(&p), ""), Err(AcceptRefusal::Malformed));
        let plan = decide_accept(Some(&p), &p.hash).unwrap();
        assert_eq!(
            plan,
            AcceptPlan {
                proposed: s(&[("core", CORE_SECRET)]),
                apply: Apply::Live,
                sections: vec!["core".to_string()]
            }
        );
        let restart = pending(&a, &Ok(s(&[("core", CORE_AUS)]))).unwrap();
        assert_eq!(
            decide_accept(Some(&restart), &restart.hash).unwrap().apply,
            Apply::Restart
        );
    }

    #[test]
    fn a_set_changed_since_it_was_shown_is_stale() {
        let a = s(&[("core", CORE)]);
        let shown = pending(&a, &Ok(s(&[("core", CORE_SECRET)]))).unwrap();
        let now = pending(&a, &Ok(s(&[("core", CORE_SECRET), ("lake", "{}")]))).unwrap();
        assert_eq!(
            decide_accept(Some(&now), &shown.hash),
            Err(AcceptRefusal::Stale)
        );
        let now_invalid = pending(&a, &Err("broken".into())).unwrap();
        assert_eq!(
            decide_accept(Some(&now_invalid), &shown.hash),
            Err(AcceptRefusal::Stale)
        );
    }

    #[test]
    fn a_shown_set_cannot_be_replayed_after_the_baseline_moves() {
        let a = s(&[("core", CORE), ("vault", VAULT_A)]);
        let f = s(&[("core", CORE_SECRET), ("vault", VAULT_B)]);
        let shown = at_boot(Some(&a), Ok(f.clone()), ok)
            .unwrap()
            .pending
            .unwrap();
        let moved = s(&[("core", CORE), ("vault", VAULT_B)]);
        let replayed = pending(&moved, &Ok(f.clone())).unwrap();
        assert_eq!(shown, replayed);
        let moved_again = s(&[
            ("core", CORE),
            ("principal", PRINCIPAL_A),
            ("vault", VAULT_B),
        ]);
        let now = pending(&moved_again, &Ok(f)).unwrap();
        assert_eq!(
            match &now.state {
                PendingState::Valid { proposed, .. } => proposed,
                PendingState::Invalid { .. } => unreachable!(),
            },
            match &shown.state {
                PendingState::Valid { proposed, .. } => proposed,
                PendingState::Invalid { .. } => unreachable!(),
            }
        );
        assert_ne!(now.hash, shown.hash);
        assert_eq!(
            decide_accept(Some(&now), &shown.hash),
            Err(AcceptRefusal::Stale)
        );
    }

    #[test]
    fn a_trail_moves_only_to_a_sibling() {
        let a = Path::new("/var/log/maknae/audit.jsonl");
        assert_eq!(move_of(Some(a), a), Ok(None));
        assert_eq!(move_of(None, a), Ok(None));
        assert_eq!(
            move_of(Some(a), Path::new("/var/log/maknae/audit-2.jsonl")),
            Ok(Some(Move {
                from: a.into(),
                to: "/var/log/maknae/audit-2.jsonl".into()
            }))
        );
        assert_eq!(
            move_of(Some(a), Path::new("/var/log/other/audit.jsonl")),
            Err("the audit trail may move only within /var/log/maknae".into())
        );
        assert!(move_of(Some(a), Path::new("/var/log/maknae/sub/audit.jsonl")).is_err());
        assert!(move_of(Some(a), Path::new("audit.jsonl")).is_err());
        assert!(move_of(Some(Path::new("rel/a.jsonl")), Path::new("rel/b.jsonl")).is_err());
        assert!(move_of(Some(a), Path::new("/var/log/maknae/sub/..")).is_err());
        assert!(move_of(Some(Path::new("/var/log/maknae/sub/..")), a).is_err());
        assert_eq!(
            move_of(Some(Path::new("/")), a),
            Err("the audit trail may move only within /".into())
        );
    }

    #[test]
    fn status_lines_carry_counts_only() {
        let a = s(&[("core", CORE)]);
        let p = pending(&a, &Ok(s(&[("core", CORE), ("vault", VAULT_A)]))).unwrap();
        assert_eq!(status_line(&p), "baseline: 1 pending (restart)");
        let live = pending(&a, &Ok(s(&[("core", CORE_SECRET)]))).unwrap();
        assert_eq!(status_line(&live), "baseline: 1 pending (live)");
        let inv = pending(&a, &Err("x".into())).unwrap();
        assert_eq!(status_line(&inv), "baseline: 1 pending (invalid)");
        for line in [status_line(&p), status_line(&live)] {
            assert!(
                !line.contains(&p.hash[..12])
                    && !line.contains(&live.hash[..12])
                    && !line.contains("core")
                    && !line.contains("vault"),
                "{line}"
            );
        }
    }

    #[test]
    fn status_lines_never_carry_the_hash() {
        let a = s(&[("core", CORE)]);
        for p in [
            pending(&a, &Ok(s(&[("core", CORE_SECRET)]))).unwrap(),
            pending(&a, &Ok(s(&[("core", CORE_AUS)]))).unwrap(),
            pending(&a, &Err("x".into())).unwrap(),
        ] {
            assert!(!status_line(&p).contains(short(&p.hash)));
            assert!(!journal_line(&p).contains(short(&p.hash)));
        }
    }

    #[test]
    fn records_carry_a_short_prefix_never_the_hash() {
        let a = s(&[("core", CORE)]);
        let p = pending(&a, &Ok(s(&[("core", CORE_SECRET)]))).unwrap();
        let (result, reason, posture) = record_fields(&p);
        assert_eq!((result, posture), ("deny", "unauthorized"));
        assert_eq!(
            reason,
            format!(
                "baseline change pending acceptance: root-file sha256:{} (apply: live; sections: core)",
                &p.hash[..12]
            )
        );
        assert!(!reason.contains(&p.hash));
        assert_eq!(
            journal_line(&p),
            "baseline change pending acceptance: root-file (apply: live)"
        );
        let inv = pending(&a, &Err("bad".into())).unwrap();
        assert_eq!(
            record_fields(&inv),
            (
                "deny",
                "baseline change refused: invalid: bad".to_string(),
                "unavailable"
            )
        );
        assert_eq!(
            journal_line(&inv),
            "baseline change refused: root-file invalid: bad"
        );
        assert_eq!(short(&p.hash), &p.hash[..12]);
        assert_eq!(short("abc"), "abc");
    }

    #[test]
    fn a_restart_record_names_every_changed_section() {
        let a = s(&[("core", CORE)]);
        let p = pending(&a, &Ok(s(&[("core", CORE_SECRET), ("vault", VAULT_A)]))).unwrap();
        let (_, reason, _) = record_fields(&p);
        assert!(
            reason.ends_with("(apply: restart; sections: core,vault)"),
            "{reason}"
        );
        assert_eq!(
            journal_line(&p),
            "baseline change pending acceptance: root-file (apply: restart)"
        );
    }

    fn state(pending_on: Option<&BaselineSections>, accepted: &BaselineSections) -> BaselineState {
        BaselineState {
            accepted: accepted.clone(),
            pending: pending_on.and_then(|f| pending(accepted, &Ok(f.clone()))),
        }
    }

    #[test]
    fn publishing_reports_only_a_changed_pending_hash() {
        let a = s(&[("core", CORE)]);
        let b = s(&[("core", CORE_SECRET)]);
        let c = s(&[("core", CORE_AUS)]);
        let status = BaselineStatus::new(state(None, &a));
        assert!(
            !status.publish(state(None, &b)),
            "only the accepted baseline changed"
        );
        assert!(status.publish(state(Some(&c), &b)), "None -> Some");
        assert!(!status.publish(state(Some(&c), &b)), "the same set again");
        assert!(status.publish(state(Some(&a), &b)), "another set");
        assert!(status.publish(state(None, &b)), "Some -> None");
        assert_eq!(*status.current(), state(None, &b));
    }

    #[test]
    fn the_status_lines_are_the_pending_sets_line_or_nothing() {
        let a = s(&[("core", CORE)]);
        let status = BaselineStatus::new(state(None, &a));
        assert!(status.lines().is_empty());
        let next = state(Some(&s(&[("core", CORE_SECRET)])), &a);
        let line = status_line(next.pending.as_ref().unwrap());
        status.publish(next);
        assert_eq!(status.lines(), vec![line]);
    }

    #[test]
    fn a_poisoned_status_still_answers() {
        let a = s(&[("core", CORE)]);
        let status = BaselineStatus::new(state(None, &a));
        let held = status.clone();
        let joined = std::thread::spawn(move || {
            let _guard = held.0.write().unwrap();
            panic!("poison the lock");
        })
        .join();
        assert!(joined.is_err());
        assert!(status.0.is_poisoned());
        assert_eq!(status.current().accepted, a);
        let b = s(&[("core", CORE_AUS)]);
        assert!(status.publish(state(Some(&b), &a)));
        assert_eq!(status.lines().len(), 1);
    }

    #[test]
    fn the_move_records_name_both_trails() {
        let from = Path::new("/var/log/maknae/audit.jsonl");
        let to = Path::new("/var/log/maknae/audit-2.jsonl");
        assert_eq!(
            move_record(to),
            "audit trail moves to /var/log/maknae/audit-2.jsonl at start"
        );
        assert_eq!(
            back_link_record(from, Some(7), None),
            "audit trail continues from /var/log/maknae/audit.jsonl; last checkpoint revision 7"
        );
        assert_eq!(
            back_link_record(from, None, Some("EACCES")),
            "audit trail continues from /var/log/maknae/audit.jsonl; last checkpoint revision none; \
             the previous trail could not be opened: EACCES"
        );
        assert_eq!(
            moved_event(from, to),
            "audit trail moved from /var/log/maknae/audit.jsonl to /var/log/maknae/audit-2.jsonl"
        );
    }
}
