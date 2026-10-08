//! The `audit` section (Stage-3a, ADR-0019) — the audit sink config consumed by
//! `maknae-audit-append` (later task): the append-only JSONL sink path, an
//! optional external SIEM offload endpoint (AU-9(2)), and the caller-supplied
//! `au3_1` structured extension, pre-converted to `serde_json::Value` so it
//! matches `AuditRecord.au3_1` end-to-end with no run-loop conversion glue.

use crate::{ConfigError, Value};
use std::path::{Path, PathBuf};

/// The registered section name for `audit` (spec/task-brief §Interfaces).
pub const AUDIT_SECTION: &str = "audit";

/// #210: the keys this section's parser reads — the closed vocabulary.
pub(crate) const AUDIT_KEYS: [&str; 4] = ["jsonl_path", "siem", "au3_1", "readers"];

/// The audit-sink configuration (ADR-0019).
#[derive(Clone, Debug)]
pub struct AuditConfig {
    pub jsonl_path: PathBuf,
    pub siem: Option<String>,
    pub au3_1: serde_json::Value,
    pub readers: Vec<String>,
}

/// One `audit.readers` account as the account database reports it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ReaderAccount {
    pub name: String,
    pub uid: u32,
    pub gid: u32,
    /// Supplementary group ids, as the account database lists them.
    pub groups: Vec<u32>,
}

/// The account database [`resolve_readers`] consults.
pub trait ReaderLookup {
    /// `Ok(None)` when no such account exists.
    fn account(&self, name: &str) -> Result<Option<ReaderAccount>, String>;
    /// The daemon account's primary gid, `Ok(None)` when it does not exist.
    fn daemon_gid(&self) -> Result<Option<u32>, String>;
}

/// The lowest uid an `audit.readers` account may have.
pub const READER_UID_FLOOR: u32 = 100;

/// Accounts refused as readers by name, before any lookup.
pub const REFUSED_READER_NAMES: [&str; 3] = ["root", "_maknae", "_maknae-egress"];

const NOBODY_UID: u32 = 65534;

fn get<'a>(v: &'a Value, key: &str) -> Option<&'a Value> {
    match v {
        Value::Map(entries) => entries.iter().find(|(k, _)| k == key).map(|(_, v)| v),
        _ => None,
    }
}

fn as_str(v: &Value) -> Option<&str> {
    match v {
        Value::Str(s) => Some(s.as_str()),
        _ => None,
    }
}

/// Convert a `maknae_config::Value` tree into a `serde_json::Value` tree,
/// field-for-field. A non-finite `Float` (NaN/±inf — `serde_json::Number`
/// cannot represent these) maps to JSON `null` rather than failing, since
/// `au3_1` is an open-ended extension field, not a validated schema.
fn to_json(v: &Value) -> serde_json::Value {
    match v {
        Value::Null => serde_json::Value::Null,
        Value::Bool(b) => serde_json::Value::Bool(*b),
        Value::Int(n) => serde_json::Value::Number((*n).into()),
        Value::Float(f) => serde_json::Number::from_f64(*f)
            .map(serde_json::Value::Number)
            .unwrap_or(serde_json::Value::Null),
        Value::Str(s) => serde_json::Value::String(s.clone()),
        Value::Seq(items) => serde_json::Value::Array(items.iter().map(to_json).collect()),
        Value::Map(entries) => serde_json::Value::Object(
            entries
                .iter()
                .map(|(k, v)| (k.clone(), to_json(v)))
                .collect(),
        ),
    }
}

/// Read the `audit` section (ADR-0019, spec/task-brief §Interfaces, spec §11).
/// `None` (section ABSENT) → `Err(ConfigError::MissingSection)`: absence fails
/// closed rather than landing the sink's default path inside `/etc/maknae`
/// (unwritable by `_maknae` per §4.6 — first boot would otherwise fail closed
/// anyway, just later and less legibly, at `AuditSink::open`). A daemon config
/// MUST carry an explicit `audit:` section; `maknae enroll` (forthcoming, PR-J1
/// Task 8) and the PR-J2 packaging default will write it so operators don't
/// hand-author it — **until those land, a host needs a hand-authored `audit:`
/// block**, or the daemon refuses to start (this is current-state, not yet the
/// steady-state operator experience). A present-but-non-map section (e.g.
/// `audit: disabled`) is rejected (`ConfigError::InvalidAudit`) rather than
/// silently falling through to all defaults (codex round-6 P2 — mirrors
/// `transport`'s guard). Within a present MAP section, a per-field wrong shape
/// (e.g. a non-string `jsonl_path`) still defaults that ONE field rather than
/// refusing the whole section — this is deliberate, not an asymmetry to fix: a
/// present-but-mistyped field still resolves to `runtime_dir/audit.jsonl`, and
/// THAT path is then independently fail-closed-checked later at sink-open (the
/// §4.6 mode/owner/MAC-append-not-create checks) — only an ABSENT section is
/// caught here, at parse.
pub fn audit_from_section(
    v: Option<&Value>,
    runtime_dir: &Path,
) -> Result<AuditConfig, ConfigError> {
    let default_jsonl_path = runtime_dir.join("audit.jsonl");
    let section = match v {
        None => {
            return Err(ConfigError::MissingSection {
                section: AUDIT_SECTION.to_string(),
            })
        }
        Some(section) => section,
    };
    let Value::Map(entries) = section else {
        return Err(ConfigError::InvalidAudit(
            "audit section must be a map".into(),
        ));
    };
    // #210: closed vocabulary. Every key below is one this function reads; a
    // transposed one refuses rather than leaving its field at the default.
    crate::reject_unknown_keys(AUDIT_SECTION, entries, &AUDIT_KEYS)?;

    let jsonl_path = get(section, "jsonl_path")
        .and_then(as_str)
        .map(PathBuf::from)
        .unwrap_or(default_jsonl_path);
    let siem = get(section, "siem").and_then(as_str).map(String::from);
    let au3_1 = get(section, "au3_1")
        .map(to_json)
        .unwrap_or_else(|| serde_json::Value::Object(serde_json::Map::new()));

    let readers = match get(section, "readers") {
        None => Vec::new(),
        Some(v) => readers_from(v)?,
    };

    Ok(AuditConfig {
        jsonl_path,
        siem,
        au3_1,
        readers,
    })
}

fn readers_from(v: &Value) -> Result<Vec<String>, ConfigError> {
    let not_a_list =
        || ConfigError::InvalidAudit("audit.readers must be a list of account names".into());
    let Value::Seq(items) = v else {
        return Err(not_a_list());
    };
    let mut readers: Vec<String> = Vec::with_capacity(items.len());
    for item in items {
        let name = as_str(item).ok_or_else(not_a_list)?;
        if !portable_name(name) {
            return Err(ConfigError::InvalidAudit(format!(
                "audit.readers entry {name:?} is not a portable account name"
            )));
        }
        if readers.iter().any(|r| r == name) {
            return Err(ConfigError::InvalidAudit(format!(
                "audit.readers names {name} twice"
            )));
        }
        readers.push(name.to_string());
    }
    Ok(readers)
}

/// `^[a-z_][a-z0-9_-]{0,30}[$]?$`
fn portable_name(s: &str) -> bool {
    let b = s.as_bytes();
    let body = b.strip_suffix(b"$").unwrap_or(b);
    let Some((first, rest)) = body.split_first() else {
        return false;
    };
    (first.is_ascii_lowercase() || *first == b'_')
        && rest.len() <= 30
        && rest
            .iter()
            .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || *c == b'_' || *c == b'-')
}

/// Resolve `audit.readers` through `lookup`, refusing any account that must not read the trail (#500).
pub fn resolve_readers(
    readers: &[String],
    lookup: &dyn ReaderLookup,
) -> Result<Vec<ReaderAccount>, ConfigError> {
    let refuse =
        |name: &str, why: &str| ConfigError::InvalidAudit(format!("audit.readers {name}: {why}"));
    let mut resolved = Vec::with_capacity(readers.len());
    for name in readers {
        if REFUSED_READER_NAMES.contains(&name.as_str()) {
            return Err(refuse(name, "this account may not be a trail reader"));
        }
        let account = match lookup.account(name) {
            Err(e) => return Err(refuse(name, &format!("account lookup failed: {e}"))),
            Ok(None) => return Err(refuse(name, "no such account")),
            Ok(Some(a)) => a,
        };
        if account.uid < READER_UID_FLOOR || account.uid == NOBODY_UID {
            return Err(refuse(
                name,
                &format!(
                    "uid {} is root, a system account below {READER_UID_FLOOR}, or nobody",
                    account.uid
                ),
            ));
        }
        let daemon_gid =
            match lookup.daemon_gid() {
                Ok(Some(g)) => g,
                Ok(None) | Err(_) => return Err(refuse(
                    name,
                    "the daemon account _maknae does not resolve, so its group cannot be excluded",
                )),
            };
        if account.gid == daemon_gid || account.groups.contains(&daemon_gid) {
            return Err(refuse(
                name,
                "a member of _maknae's group may not read the trail",
            ));
        }
        resolved.push(account);
    }
    Ok(resolved)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn rt() -> PathBuf {
        PathBuf::from("/var/lib/maknae")
    }

    #[test]
    fn absent_audit_section_fails_closed() {
        // spec §11 / round-1 C12: an ABSENT `audit` section must refuse to load
        // rather than silently default into the (possibly-unwritable) config dir.
        match audit_from_section(None, &rt()) {
            Err(ConfigError::MissingSection { section }) => {
                assert_eq!(section, AUDIT_SECTION);
            }
            other => panic!("expected Err(MissingSection), got {other:?}"),
        }
    }

    #[test]
    fn defaults_when_section_present_but_empty() {
        let v = Value::Map(vec![]);
        let c = audit_from_section(Some(&v), &rt()).unwrap();
        assert_eq!(c.jsonl_path, PathBuf::from("/var/lib/maknae/audit.jsonl"));
        assert_eq!(c.siem, None);
        assert_eq!(c.au3_1, serde_json::json!({}));
    }

    /// #210: a TRANSPOSED key must refuse the load, not take the default. The
    /// issue's own example — `jsonl_pth` for `jsonl_path` — where the shipped
    /// `maknae.yaml` comment says the path is "pinned here so it is never
    /// defaulted", and silently defaulting it lands the sink in a directory
    /// `_maknae` cannot write.
    #[test]
    fn a_transposed_key_refuses_rather_than_defaulting() {
        let v = Value::Map(vec![(
            "jsonl_pth".into(),
            Value::Str("/var/log/maknae/audit.jsonl".into()),
        )]);
        match audit_from_section(Some(&v), &rt()) {
            Err(ConfigError::UnknownKey { section, key }) => {
                assert_eq!(section, AUDIT_SECTION);
                assert_eq!(key, "jsonl_pth");
            }
            other => panic!("expected Err(UnknownKey), got {other:?}"),
        }
    }

    /// The companion to the above: every key the parser DOES read still loads.
    /// Without this, closing the vocabulary could silently reject a valid config
    /// and the test above would still pass.
    #[test]
    fn every_key_the_parser_reads_is_accepted() {
        let v = Value::Map(vec![
            (
                "jsonl_path".into(),
                Value::Str("/var/log/maknae/audit.jsonl".into()),
            ),
            ("siem".into(), Value::Str("udp://127.0.0.1:514".into())),
            ("au3_1".into(), Value::Map(vec![])),
            ("readers".into(), Value::Seq(vec![])),
        ]);
        assert!(audit_from_section(Some(&v), &rt()).is_ok());
    }

    #[test]
    fn rejects_non_map_scalar_section() {
        let v = Value::Str("disabled".into());
        assert!(matches!(
            audit_from_section(Some(&v), &rt()),
            Err(ConfigError::InvalidAudit(_))
        ));
    }

    #[test]
    fn rejects_non_map_seq_section() {
        let v = Value::Seq(vec![Value::Str("a".into())]);
        assert!(matches!(
            audit_from_section(Some(&v), &rt()),
            Err(ConfigError::InvalidAudit(_))
        ));
    }

    #[test]
    fn jsonl_path_override_respected() {
        let v = Value::Map(vec![(
            "jsonl_path".into(),
            Value::Str("/var/log/maknae/audit.jsonl".into()),
        )]);
        let c = audit_from_section(Some(&v), &rt()).unwrap();
        assert_eq!(c.jsonl_path, PathBuf::from("/var/log/maknae/audit.jsonl"));
    }

    #[test]
    fn siem_parsed_when_present() {
        let v = Value::Map(vec![(
            "siem".into(),
            Value::Str("https://siem.example.mil:8443/ingest".into()),
        )]);
        let c = audit_from_section(Some(&v), &rt()).unwrap();
        assert_eq!(
            c.siem,
            Some("https://siem.example.mil:8443/ingest".to_string())
        );
    }

    #[test]
    fn wrong_type_jsonl_path_falls_back_to_default() {
        let v = Value::Map(vec![("jsonl_path".into(), Value::Int(1))]);
        let c = audit_from_section(Some(&v), &rt()).unwrap();
        assert_eq!(c.jsonl_path, PathBuf::from("/var/lib/maknae/audit.jsonl"));
    }

    #[test]
    fn wrong_type_siem_is_none() {
        let v = Value::Map(vec![("siem".into(), Value::Bool(true))]);
        let c = audit_from_section(Some(&v), &rt()).unwrap();
        assert_eq!(c.siem, None);
    }

    #[test]
    fn au3_1_defaults_to_empty_map_when_absent() {
        let v = Value::Map(vec![("siem".into(), Value::Str("x".into()))]);
        let c = audit_from_section(Some(&v), &rt()).unwrap();
        assert_eq!(c.au3_1, serde_json::json!({}));
    }

    #[test]
    fn au3_1_scalars_convert() {
        for (input, want) in [
            (Value::Null, serde_json::json!(null)),
            (Value::Bool(true), serde_json::json!(true)),
            (Value::Int(-7), serde_json::json!(-7)),
            (Value::Str("hi".into()), serde_json::json!("hi")),
        ] {
            let v = Value::Map(vec![("au3_1".into(), input)]);
            let c = audit_from_section(Some(&v), &rt()).unwrap();
            assert_eq!(c.au3_1, want);
        }
    }

    #[test]
    fn au3_1_float_converts() {
        let v = Value::Map(vec![("au3_1".into(), Value::Float(2.5))]);
        let c = audit_from_section(Some(&v), &rt()).unwrap();
        assert_eq!(c.au3_1, serde_json::json!(2.5));
    }

    #[test]
    fn au3_1_non_finite_float_becomes_null() {
        let v = Value::Map(vec![("au3_1".into(), Value::Float(f64::NAN))]);
        let c = audit_from_section(Some(&v), &rt()).unwrap();
        assert_eq!(c.au3_1, serde_json::json!(null));
    }

    #[test]
    fn au3_1_nested_seq_and_map_convert() {
        let v = Value::Map(vec![(
            "au3_1".into(),
            Value::Map(vec![
                ("actor".into(), Value::Str("cn=svc-maknae".into())),
                (
                    "tags".into(),
                    Value::Seq(vec![Value::Str("AU-3(1)".into()), Value::Int(1)]),
                ),
            ]),
        )]);
        let c = audit_from_section(Some(&v), &rt()).unwrap();
        assert_eq!(
            c.au3_1,
            serde_json::json!({"actor": "cn=svc-maknae", "tags": ["AU-3(1)", 1]})
        );
    }

    struct Accounts(Vec<ReaderAccount>, Option<u32>);
    impl ReaderLookup for Accounts {
        fn account(&self, name: &str) -> Result<Option<ReaderAccount>, String> {
            if name == "flaky" {
                return Err("EIO".into());
            }
            Ok(self.0.iter().find(|a| a.name == name).cloned())
        }
        fn daemon_gid(&self) -> Result<Option<u32>, String> {
            Ok(self.1)
        }
    }

    struct BrokenDaemon;
    impl ReaderLookup for BrokenDaemon {
        fn account(&self, name: &str) -> Result<Option<ReaderAccount>, String> {
            Ok(Some(acct(name, 991, 991, &[])))
        }
        fn daemon_gid(&self) -> Result<Option<u32>, String> {
            Err("ENOENT".into())
        }
    }

    fn acct(name: &str, uid: u32, gid: u32, groups: &[u32]) -> ReaderAccount {
        ReaderAccount {
            name: name.into(),
            uid,
            gid,
            groups: groups.to_vec(),
        }
    }

    fn readers_section(list: &str) -> Value {
        crate::load_str(&format!("readers: {list}\n")).unwrap()
    }

    #[test]
    fn readers_parse_as_a_list_of_names_and_default_empty() {
        let cfg = audit_from_section(Some(&Value::Map(vec![])), &rt()).unwrap();
        assert!(cfg.readers.is_empty());
        let cfg =
            audit_from_section(Some(&readers_section("[vector, \"fluent-bit\"]")), &rt()).unwrap();
        assert_eq!(cfg.readers, ["vector", "fluent-bit"]);
    }

    #[test]
    fn a_reader_that_is_not_a_portable_account_name_refuses_at_parse() {
        for bad in [
            "[\"Vector\"]",
            "[\"a b\"]",
            "[\"u:x\"]",
            "[\"\"]",
            "[1001]",
            "vector",
            "[\"a/b\"]",
            "[\"-x\"]",
            "[\"1a\"]",
            "[\"$\"]",
            "[\"a$$\"]",
            "[\"a$b\"]",
            "[\"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\"]",
        ] {
            let got = audit_from_section(Some(&readers_section(bad)), &rt());
            assert!(
                matches!(got, Err(ConfigError::InvalidAudit(_))),
                "{bad}: {got:?}"
            );
        }
    }

    #[test]
    fn every_portable_shape_is_admitted() {
        let longest = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
        assert_eq!(longest.len(), 31);
        let list = format!("[_svc, a, a-b_9, \"host$\", {longest}, \"{longest}$\"]");
        let cfg = audit_from_section(Some(&readers_section(&list)), &rt()).unwrap();
        assert_eq!(cfg.readers.len(), 6);
    }

    #[test]
    fn the_same_reader_twice_refuses() {
        let got = audit_from_section(Some(&readers_section("[vector, vector]")), &rt());
        assert!(
            matches!(got, Err(ConfigError::InvalidAudit(ref m)) if m.contains("vector")),
            "{got:?}"
        );
    }

    #[test]
    fn resolve_readers_admits_an_ordinary_service_account() {
        let l = Accounts(vec![acct("vector", 991, 991, &[4])], Some(980));
        assert_eq!(
            resolve_readers(&["vector".into()], &l).unwrap(),
            vec![acct("vector", 991, 991, &[4])]
        );
        assert_eq!(resolve_readers(&[], &l).unwrap(), vec![]);
    }

    #[test]
    fn resolve_readers_refuses_every_forbidden_reader() {
        let l = Accounts(
            vec![
                acct("root", 0, 0, &[]),
                acct("zero", 0, 5, &[]),
                acct("bin", 1, 1, &[]),
                acct("ninetynine", 99, 99, &[]),
                acct("nobody", 65534, 65534, &[]),
                acct("_maknae", 980, 980, &[]),
                acct("_maknae-egress", 981, 981, &[]),
                acct("primary", 990, 980, &[]),
                acct("member", 992, 992, &[980]),
            ],
            Some(980),
        );
        for name in [
            "root",
            "zero",
            "bin",
            "ninetynine",
            "nobody",
            "_maknae",
            "_maknae-egress",
            "primary",
            "member",
            "ghost",
            "flaky",
        ] {
            let got = resolve_readers(&[name.to_string()], &l);
            assert!(
                matches!(got, Err(ConfigError::InvalidAudit(ref m)) if m.contains(name)),
                "{name}: {got:?}"
            );
        }
    }

    #[test]
    fn one_refused_reader_refuses_the_whole_list() {
        let l = Accounts(
            vec![acct("vector", 991, 991, &[]), acct("bin", 1, 1, &[])],
            Some(980),
        );
        let got = resolve_readers(&["vector".into(), "bin".into()], &l);
        assert!(
            matches!(got, Err(ConfigError::InvalidAudit(ref m)) if m.contains("bin")),
            "{got:?}"
        );
    }

    #[test]
    fn the_uid_floor_is_inclusive_of_one_hundred() {
        let l = Accounts(vec![acct("edge", READER_UID_FLOOR, 500, &[])], Some(980));
        assert!(resolve_readers(&["edge".into()], &l).is_ok());
        let l = Accounts(
            vec![acct("edge", READER_UID_FLOOR - 1, 500, &[])],
            Some(980),
        );
        assert!(resolve_readers(&["edge".into()], &l).is_err());
    }

    #[test]
    fn a_missing_daemon_account_refuses_rather_than_skipping_the_group_check() {
        let l = Accounts(vec![acct("vector", 991, 991, &[])], None);
        assert!(resolve_readers(&["vector".into()], &l).is_err());
        let got = resolve_readers(&["vector".into()], &BrokenDaemon);
        assert!(
            matches!(got, Err(ConfigError::InvalidAudit(ref m)) if m.contains("vector")),
            "{got:?}"
        );
    }
}
