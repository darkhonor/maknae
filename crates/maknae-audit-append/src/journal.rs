//! The journald wire encoder (ADR-0019 D3, #189) — pure, no I/O.
//!
//! Split from the socket in [`crate::journal_io`] so it carries a real T1 tier
//! and is mutation-proven. Bundling them would smuggle the encoder past the
//! I/O half's T3 mutation exclusion.
//!
//! **No `libsystemd`.** The native journal protocol is a documented plain-text
//! datagram, written directly; linking a C library would contradict ADR-0002's
//! 100% Rust TCB.
use crate::error::AuditError;
use crate::record::{canonical_json, AuditRecord};

/// The `SYSLOG_IDENTIFIER` every record carries, so `journalctl -t maknaed`
/// finds them whether or not the daemon is running under its systemd unit.
///
/// `pub(crate)` because the macOS formatter builds its identity token from this
/// one definition rather than repeating the literal — two literals drift, and
/// the token is what an operator greps for on either platform.
pub(crate) const SYSLOG_IDENTIFIER: &str = "maknaed";

/// Which primary-sink condition produced this mirrored copy.
///
/// **Why it exists.** Three of the four mirror call sites fire *because* the
/// primary did not durably write, so records legitimately exist in journald
/// that are absent from the JSONL. Without the marker the two sinks diverge
/// silently and an auditor cannot distinguish "missing from the JSONL" from
/// "never generated" — an integrity question with no answer.
///
/// No `Default` derive: on a type returned by a mutated function it makes a
/// mutant equivalent-and-reported-missed, which is unkillable.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum PrimaryOutcome {
    /// The primary JSONL append succeeded; this is a true second copy.
    Ok,
    /// The blocking-write circuit breaker was open; the primary never wrote.
    RefusedBreakerOpen,
    /// The blocking-write worker pool was exhausted; the primary never wrote.
    RefusedAtCapacity,
    /// The primary append was attempted and did not durably complete —
    /// including a `spawn_blocking` join failure (panic or cancellation),
    /// where the record would otherwise reach neither sink.
    WriteFailed,
}

impl PrimaryOutcome {
    pub(crate) fn as_field(self) -> &'static str {
        match self {
            Self::Ok => "ok",
            Self::RefusedBreakerOpen => "refused-breaker-open",
            Self::RefusedAtCapacity => "refused-at-capacity",
            Self::WriteFailed => "write-failed",
        }
    }
}

/// journald field names are `[A-Z0-9_]`, non-empty, never leading-underscore
/// (reserved for the trusted fields journald adds itself — a submitted one is
/// silently dropped) and never leading-digit.
pub(crate) fn is_valid_field_name(name: &str) -> bool {
    let Some(first) = name.chars().next() else {
        return false;
    };
    if first == '_' || first.is_ascii_digit() {
        return false;
    }
    name.chars()
        .all(|c| c.is_ascii_uppercase() || c.is_ascii_digit() || c == '_')
}

/// Append one field, choosing the plain or binary form.
///
/// **An invalid name is dropped, not written.** A malformed name corrupts the
/// WHOLE datagram — journald parses it as a field separator — so emitting one
/// would lose every field after it, not merely the bad one. This is the spec's
/// "reject or sanitize" requirement, enforced at the only place a field can
/// enter the buffer.
pub(crate) fn push_field(buf: &mut Vec<u8>, name: &str, value: &[u8]) {
    if !is_valid_field_name(name) {
        return;
    }
    if value.contains(&b'\n') {
        // Binary form: NAME \n <8-byte LE length> <raw bytes> \n
        buf.extend_from_slice(name.as_bytes());
        buf.push(b'\n');
        buf.extend_from_slice(&(value.len() as u64).to_le_bytes());
        buf.extend_from_slice(value);
        buf.push(b'\n');
    } else {
        buf.extend_from_slice(name.as_bytes());
        buf.push(b'=');
        buf.extend_from_slice(value);
        buf.push(b'\n');
    }
}

/// What an audit record exposes to a log sink, decided ONCE.
///
/// **Why this type exists.** Two platform serializers each need "which parts of
/// a record does a mirrored copy carry, and what stands in for an absent one".
/// Deciding that twice is how the two mirrors drift: a sentinel changes on one
/// platform and not the other, and the divergence is invisible until an auditor
/// compares them. The *serializations* differ per platform and are mechanism;
/// this is the decision, and it is shared.
///
/// No `Default` derive — see [`PrimaryOutcome`]'s note; the same reasoning binds
/// every type returned by a function in this `[t1]` file.
pub(crate) struct RecordFields<'a> {
    pub(crate) action: &'a str,
    pub(crate) outcome: &'a str,
    /// `"unknown"` when the record carries no subject user.
    pub(crate) subject: &'a str,
    /// `"-"` when the record names no object.
    pub(crate) object: &'a str,
    pub(crate) primary: &'static str,
    /// Linux-only consumer: [`encode`] derives the journald `PRIORITY` from it
    /// (4 vs 6). **The macOS formatter MUST NOT** — its severity is pinned to
    /// `LOG_WARNING` unconditionally (spec D4), because `LOG_INFO` lands in the
    /// unified log's memory-backed info tier and a `permit` may never reach
    /// disk. Severity is not where macOS carries deny/permit; `MAKNAE_OUTCOME`
    /// is.
    pub(crate) is_deny: bool,
    pub(crate) session_id: u64,
    pub(crate) seq: u64,
}

/// Project one audit record into the shared field set.
pub(crate) fn fields_of(rec: &AuditRecord, primary: PrimaryOutcome) -> RecordFields<'_> {
    RecordFields {
        action: &rec.action,
        outcome: &rec.outcome.result,
        subject: rec.subject.user.as_deref().unwrap_or("unknown"),
        object: rec.object.as_deref().unwrap_or("-"),
        primary: primary.as_field(),
        is_deny: rec.outcome.result == "deny",
        session_id: rec.session_id,
        seq: rec.seq,
    }
}

/// The operator-facing one-line summary carried as journald's `MESSAGE`.
///
/// **This is the JOURNALD summary and it carries `object=` deliberately.** The
/// macOS summary is a DIFFERENT function that omits it (spec D4b): on darwin the
/// message text is the only queryable surface, so a subject-controlled path
/// could forge `MAKNAE_OUTCOME=permit` into its own deny record. journald has
/// structured fields alongside the message, so the same string is not a
/// forgery surface there and the operator keeps the object.
pub(crate) fn summary_line(f: &RecordFields<'_>) -> String {
    format!(
        "maknae audit: {} {} subject={} object={} session={} seq={}",
        f.action, f.outcome, f.subject, f.object, f.session_id, f.seq
    )
}

/// Encode one audit record as a systemd native-journal datagram.
///
/// `MAKNAE_RECORD` carries the canonical JSON **verbatim**, so the journald
/// copy and the JSONL line can never disagree. The filterable `MAKNAE_*` fields
/// are duplicates of record content for `journalctl` querying, never a second
/// source of truth.
pub(crate) fn encode(rec: &AuditRecord, primary: PrimaryOutcome) -> Result<Vec<u8>, AuditError> {
    let canonical = canonical_json(rec)?;
    let f = fields_of(rec, primary);
    // syslog severity: a denial is operationally interesting, a permit is not.
    let priority = if f.is_deny { "4" } else { "6" };
    let message = summary_line(&f);

    // `Vec::new()`, NOT `with_capacity(a + b + n)`: a capacity hint has no
    // observable effect on the output, so every arithmetic mutant cargo-mutants
    // generates on it is equivalent-and-reported-MISSED -- and this file is [t1]
    // zero-missed, with no exclusion available.
    let mut buf = Vec::new();
    push_field(&mut buf, "SYSLOG_IDENTIFIER", SYSLOG_IDENTIFIER.as_bytes());
    push_field(&mut buf, "MESSAGE", message.as_bytes());
    push_field(&mut buf, "PRIORITY", priority.as_bytes());
    push_field(&mut buf, "MAKNAE_ACTION", f.action.as_bytes());
    push_field(&mut buf, "MAKNAE_OUTCOME", f.outcome.as_bytes());
    push_field(&mut buf, "MAKNAE_SUBJECT", f.subject.as_bytes());
    push_field(&mut buf, "MAKNAE_PRIMARY", f.primary.as_bytes());
    push_field(&mut buf, "MAKNAE_RECORD", canonical.as_bytes());
    Ok(buf)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::record::{AuditRecord, Integrity, Outcome, Source, Subject, Where};

    fn rec(reason: &str) -> AuditRecord {
        // Built LITERALLY -- `sample_record()` at sink.rs:290 is private to that
        // module, and neither `Where` nor `Integrity` derives `Default` or has a
        // test constructor. Do NOT add `Default` to record.rs to make this
        // compile: it is a [t1] mutated file, and a `Default` makes mutants
        // unkillable.
        AuditRecord {
            ts: "2026-09-05T00:00:00.000Z".into(),
            event: "request".into(),
            where_: Where {
                host: "maknaed-01".into(),
                component: "kernel".into(),
                socket: "/run/maknae/plane.sock".into(),
            },
            source: Source {
                uid: 1000,
                gid: Some(1000),
                pid: Some(42),
                plane_uri_san: None,
            },
            subject: Subject {
                user: Some("byeori".into()),
                plane_uri_san: None,
            },
            action: "fs.read".into(),
            object: Some("/home/byeori/.ssh/id_rsa".into()),
            object_requested: None,
            mutation: None,
            outcome: Outcome {
                result: "deny".into(),
                reason: reason.into(),
                posture: "unauthorized".into(),
            },
            session_id: 7,
            seq: 3,
            au3_1: serde_json::Value::Null,
            integrity: Integrity {
                prev_hash: None,
                sig: None,
            },
        }
    }

    /// An INDEPENDENT decoder, written against the journal format spec rather
    /// than by calling back into `encode`. Handles both the plain
    /// `NAME=value\n` form and the binary `NAME\n<8-byte LE len><bytes>\n` form.
    fn parse(buf: &[u8]) -> Vec<(String, Vec<u8>)> {
        let mut out = Vec::new();
        let mut i = 0usize;
        while i < buf.len() {
            let nl = buf[i..]
                .iter()
                .position(|&b| b == b'\n')
                .expect("field must end")
                + i;
            let line = &buf[i..nl];
            match line.iter().position(|&b| b == b'=') {
                Some(eq) => {
                    out.push((
                        String::from_utf8(line[..eq].to_vec()).unwrap(),
                        line[eq + 1..].to_vec(),
                    ));
                    i = nl + 1;
                }
                None => {
                    let name = String::from_utf8(line.to_vec()).unwrap();
                    let lstart = nl + 1;
                    let len =
                        u64::from_le_bytes(buf[lstart..lstart + 8].try_into().unwrap()) as usize;
                    let vstart = lstart + 8;
                    out.push((name, buf[vstart..vstart + len].to_vec()));
                    i = vstart + len + 1;
                }
            }
        }
        out
    }

    fn field(buf: &[u8], name: &str) -> Option<Vec<u8>> {
        parse(buf)
            .into_iter()
            .find(|(n, _)| n == name)
            .map(|(_, v)| v)
    }

    #[test]
    fn emits_the_filterable_fields_and_the_syslog_identifier() {
        let b = encode(&rec("policy denied"), PrimaryOutcome::Ok).unwrap();
        // SYSLOG_IDENTIFIER is what `journalctl -t maknaed` matches on. Without
        // it the acceptance round-trip would query an empty set and silently
        // "pass" -- the #219 ok-on-nothing class.
        assert_eq!(field(&b, "SYSLOG_IDENTIFIER").unwrap(), b"maknaed");
        assert_eq!(field(&b, "MAKNAE_ACTION").unwrap(), b"fs.read");
        assert_eq!(field(&b, "MAKNAE_OUTCOME").unwrap(), b"deny");
        assert_eq!(field(&b, "MAKNAE_SUBJECT").unwrap(), b"byeori");
        assert_eq!(field(&b, "MAKNAE_PRIMARY").unwrap(), b"ok");
    }

    #[test]
    fn record_field_is_byte_identical_to_canonical_json() {
        let r = rec("policy denied");
        let b = encode(&r, PrimaryOutcome::Ok).unwrap();
        assert_eq!(
            field(&b, "MAKNAE_RECORD").unwrap(),
            crate::record::canonical_json(&r).unwrap().as_bytes()
        );
    }

    #[test]
    fn newline_bearing_value_uses_the_binary_form() {
        // A value carrying a newline MUST NOT use `NAME=value\n`: the embedded
        // newline would be read as a field separator, truncating this field AND
        // corrupting every field after it.
        let mut buf = Vec::new();
        push_field(&mut buf, "MAKNAE_TEST", b"line one\nline two");
        assert!(buf.starts_with(b"MAKNAE_TEST\n"), "binary form not used");
        assert_eq!(field(&buf, "MAKNAE_TEST").unwrap(), b"line one\nline two");
        let at = "MAKNAE_TEST\n".len();
        assert_eq!(
            u64::from_le_bytes(buf[at..at + 8].try_into().unwrap()),
            "line one\nline two".len() as u64
        );
    }

    #[test]
    fn newline_free_values_use_the_plain_form() {
        // The negative half. Without it, an encoder that ALWAYS used the binary
        // form would pass the test above and still be wrong.
        let mut buf = Vec::new();
        push_field(&mut buf, "MAKNAE_TEST", b"no newlines here");
        assert!(buf.starts_with(b"MAKNAE_TEST="), "plain form not used");
        assert_eq!(field(&buf, "MAKNAE_TEST").unwrap(), b"no newlines here");
    }

    #[test]
    fn an_invalid_field_name_is_skipped_not_emitted() {
        // The runtime control. A malformed name corrupts the WHOLE datagram,
        // not just its own field, so it is dropped rather than written.
        let mut buf = Vec::new();
        push_field(&mut buf, "_RESERVED", b"x");
        push_field(&mut buf, "bad-name", b"y");
        assert!(buf.is_empty(), "invalid names must not reach the datagram");
        push_field(&mut buf, "MAKNAE_OK", b"z");
        assert_eq!(field(&buf, "MAKNAE_OK").unwrap(), b"z");
    }

    #[test]
    fn every_primary_outcome_has_a_distinct_field_value() {
        use PrimaryOutcome as P; // NOT a glob: `Ok` would shadow `Result::Ok`
        let all = [
            P::Ok,
            P::RefusedBreakerOpen,
            P::RefusedAtCapacity,
            P::WriteFailed,
        ];
        let mut seen: Vec<&str> = all.iter().map(|p| p.as_field()).collect();
        seen.sort_unstable();
        let before = seen.len();
        seen.dedup();
        assert_eq!(
            before,
            seen.len(),
            "two PrimaryOutcome variants share a field value"
        );
        assert_eq!(P::Ok.as_field(), "ok");
        assert_eq!(P::RefusedBreakerOpen.as_field(), "refused-breaker-open");
        assert_eq!(P::RefusedAtCapacity.as_field(), "refused-at-capacity");
        assert_eq!(P::WriteFailed.as_field(), "write-failed");
    }

    #[test]
    fn deny_and_permit_get_the_exact_syslog_priorities() {
        // Asserting INEQUALITY would let the `==` -> `!=` mutant survive (it
        // merely swaps the two values, which are still different). Assert the
        // values themselves.
        let mut permit = rec("ok");
        permit.outcome.result = "permit".into();
        assert_eq!(
            field(&encode(&rec("no"), PrimaryOutcome::Ok).unwrap(), "PRIORITY").unwrap(),
            b"4"
        );
        assert_eq!(
            field(&encode(&permit, PrimaryOutcome::Ok).unwrap(), "PRIORITY").unwrap(),
            b"6"
        );
    }

    #[test]
    fn field_name_validator_rejects_the_forms_journald_rejects() {
        assert!(is_valid_field_name("MAKNAE_ACTION"));
        assert!(
            is_valid_field_name("MAKNAE_FIELD9"),
            "digits are legal after the first char"
        );
        assert!(!is_valid_field_name(""), "empty");
        assert!(
            !is_valid_field_name("_LEADING"),
            "leading underscore is journald-reserved"
        );
        assert!(!is_valid_field_name("9LEADING"), "leading digit");
        assert!(!is_valid_field_name("lower"), "lowercase");
        assert!(!is_valid_field_name("HAS-DASH"), "non [A-Z0-9_]");
    }

    /// Derived cross-check: the name set is DISCOVERED from the datagram, not
    /// listed in a constant. A new field that is malformed fails here with
    /// nobody updating anything.
    #[test]
    fn every_emitted_field_name_is_valid() {
        let b = encode(&rec("policy denied"), PrimaryOutcome::WriteFailed).unwrap();
        let names: Vec<String> = parse(&b).into_iter().map(|(n, _)| n).collect();
        assert!(!names.is_empty(), "encoder emitted nothing");
        for n in names {
            assert!(
                is_valid_field_name(&n),
                "invalid journald field name emitted: {n}"
            );
        }
    }

    #[test]
    fn subject_without_a_user_encodes_the_unknown_sentinel() {
        let mut r = rec("no");
        r.subject.user = None;
        let b = encode(&r, PrimaryOutcome::Ok).unwrap();
        assert_eq!(field(&b, "MAKNAE_SUBJECT").unwrap(), b"unknown");
    }

    #[test]
    fn fields_of_supplies_the_absent_value_sentinels() {
        let mut r = rec("no");
        r.subject.user = None;
        r.object = None;
        let f = fields_of(&r, PrimaryOutcome::Ok);
        assert_eq!(f.subject, "unknown");
        assert_eq!(f.object, "-");
        assert_eq!(f.primary, "ok");
    }

    #[test]
    fn fields_of_flags_deny_and_not_permit() {
        assert!(fields_of(&rec("no"), PrimaryOutcome::Ok).is_deny);
        let mut p = rec("ok");
        p.outcome.result = "permit".into();
        assert!(!fields_of(&p, PrimaryOutcome::Ok).is_deny);
    }

    #[test]
    fn the_summary_line_carries_the_operator_facing_facts() {
        let s = summary_line(&fields_of(&rec("no"), PrimaryOutcome::RefusedAtCapacity));
        // `object=` is LOAD-BEARING here: the natural instinct after reading D4b is
        // to delete it from the shared summary_line, which silently changes
        // journald's MESSAGE. Nothing else catches that -- not the three
        // must-pass-unmodified tests, and not a mutant.
        for needle in [
            "fs.read",
            "deny",
            "byeori",
            "object=/home/byeori/.ssh/id_rsa",
            "session=7",
            "seq=3",
        ] {
            assert!(s.contains(needle), "summary must carry {needle}: {s}");
        }
    }
}
