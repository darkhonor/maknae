//! The macOS unified-log message formatter (spec D3/D4/D4b, #222) — pure, no I/O.
//!
//! Split from the socket in [`crate::syslog_io`] so it carries a real T1 tier
//! and is mutation-proven, exactly as [`crate::journal`] is split from
//! [`crate::journal_io`].
//!
//! **Why a whole second formatter.** `syslog(3)` delivers ONE undelimited line.
//! journald takes `NAME=value\n` per field and has a binary form for embedded
//! newlines, so its message text is not the queryable surface; here it is the
//! only surface there is. That difference drives two decisions this file exists
//! to hold: an oversize line is DROPPED rather than truncated (the platform
//! would clip mid-JSON), and no subject-controlled text reaches the structured
//! prefix (spec D4b).
//!
//! **The line is PARSED, never grepped whole:** the structured prefix, then
//! everything after the FIRST `MAKNAE_RECORD=`. The payload is canonical JSON
//! carried verbatim, so a hostile object legitimately puts the literal bytes
//! `MAKNAE_OUTCOME=permit` *inside* it on a deny record. What D4b guarantees is
//! an uncontaminated prefix and a trustworthy extraction anchor — not the
//! absence of those bytes from the line.
//!
//! Compiles on every platform (it is pure), so both CI lanes keep full coverage
//! and no mutants exclusion is needed. Only the production CALLER is
//! platform-selected, which is what the file-level attribute below records.
#![cfg_attr(not(target_os = "macos"), allow(dead_code))]

use crate::error::AuditError;
use crate::journal::{fields_of, PrimaryOutcome, SYSLOG_IDENTIFIER};
use crate::record::{canonical_json, AuditRecord};

/// The measured macOS `syslog(3)` delivery cap, in **bytes of the message we
/// submit**. Beyond this the platform truncates and **marks** the result with a
/// trailing `<…>`; a truncated audit record is corrupt JSON regardless of the
/// marker, so we drop instead.
///
/// BISECTED on macOS 26.6.2 (Apple Silicon), 2026-09-05, emitting a message of
/// exactly N bytes and reading the delivered length back out of
/// `/usr/bin/log show --style json`:
///
/// ```text
///   sent 1012 -> delivered 1012, unmarked, intact
///   sent 1013 -> delivered 1013, unmarked, intact
///   sent 1014 -> delivered 1014, unmarked, intact
///   sent 1015 -> delivered 1015, unmarked, intact     <-- last intact
///   sent 1016 -> delivered 1020, MARKED  <…>, truncated
///   sent 1017 -> delivered 1020, MARKED  <…>, truncated
///   sent 1018 -> delivered 1020, MARKED  <…>, truncated
/// ```
///
/// TWO EARLIER REVISIONS OF THIS CONSTANT WERE WRONG, both by reading a length
/// off a TRUNCATED record: the first used 1024; the second used 1018.
/// **1018 is the CHARACTER count of the truncated record** — 1015 kept chars
/// plus the 3-char `<…>` marker. In BYTES that same record is 1020, because
/// `…` is 3 bytes in UTF-8. Neither number is the cap; the cap is the last
/// INTACT length, 1015. The cap is on bytes, not chars — confirmed with
/// multi-byte padding. Invariant under ident length and `LOG_PID`.
///
/// The acceptance test proves this against the PLATFORM, not against this
/// constant: a record formatted to exactly `MACOS_SYSLOG_MAX` must round-trip
/// unmarked through the real unified log.
#[allow(dead_code)] // wired in Task 3
pub(crate) const MACOS_SYSLOG_MAX: usize = 1015;

/// A value that has passed [`scrub`].
///
/// Its constructor is private to this inner module, so a function taking
/// `Scrubbed<'_>` cannot be handed a raw field — and cannot be handed a forged
/// wrapper either.
///
/// **The inner module is load-bearing, not decoration.** Rust field privacy is
/// MODULE-scoped: a bare tuple struct declared beside `scrub` could still be
/// forged as `Scrubbed(raw)` anywhere in this file, which compiles clean under
/// `-D warnings`. An earlier design took bare `&str` and asserted the same
/// "structurally impossible" property; measured, `macos_summary(f.action,
/// f.outcome, f.subject, …)` was type-correct, so the defence rested entirely
/// on one test. The newtype makes the claim true, and it survives someone
/// deleting that test.
mod scrubbed {
    #[derive(Clone, Copy)]
    pub(crate) struct Scrubbed<'a>(&'a str);

    impl<'a> Scrubbed<'a> {
        pub(crate) fn as_str(self) -> &'a str {
            self.0
        }
    }

    /// Reject-not-escape: any value containing `MAKNAE_`, `=`, `\n` or `\r`
    /// becomes `invalid` wholesale. Escaping would still let a token through a
    /// `contains`. This is the ONLY constructor of [`Scrubbed`], and it is the
    /// only item in this module that can build one.
    ///
    /// **Two limits, documented rather than tested — do not read more into
    /// this than it does.** It is a *structural-token* defence, not a rendering
    /// one: it does not reject U+202E and friends, so a bidi override can
    /// reorder a rendered `log show` line without forging any token (machine
    /// parsing is unaffected). And `invalid` is not reserved — a value literally
    /// equal to `invalid` is indistinguishable from a scrubbed one.
    pub(crate) fn scrub(v: &str) -> Scrubbed<'_> {
        if v.contains("MAKNAE_") || v.contains('=') || v.contains('\n') || v.contains('\r') {
            Scrubbed("invalid")
        } else {
            Scrubbed(v)
        }
    }
}
use scrubbed::{scrub, Scrubbed};

/// The macOS operator-facing summary.
///
/// **Deliberately NOT [`crate::journal::summary_line`]**, which carries
/// `object` and must keep doing so on Linux. `object` is controlled by the
/// subject the record is about (ADR-0009: the kernel-reported path of the
/// subject's own delegated descriptor), and in a single undelimited line
/// interpolating it raw lets that subject forge structured fields into their
/// own audit record. It is already carried verbatim inside `MAKNAE_RECORD`, so
/// omitting it here loses nothing.
///
/// **Takes `Scrubbed` values, so passing a raw field WILL NOT COMPILE.**
fn macos_summary(
    action: Scrubbed<'_>,
    outcome: Scrubbed<'_>,
    subject: Scrubbed<'_>,
    session_id: u64,
    seq: u64,
) -> String {
    format!(
        "maknae audit: {} {} subject={} session={} seq={}",
        action.as_str(),
        outcome.as_str(),
        subject.as_str(),
        session_id,
        seq
    )
}

/// Build the macOS line WITHOUT the cap check.
///
/// Exists so the boundary tests can measure a line past the cap.
/// `#[cfg(test)]` would hide it from the production caller chain, so it is
/// ordinary `pub(crate)`; [`format_record`] is its only production caller.
pub(crate) fn format_line_unchecked(
    rec: &AuditRecord,
    primary: PrimaryOutcome,
) -> Result<String, AuditError> {
    let canonical = canonical_json(rec)?;
    let f = fields_of(rec, primary);
    // Scrub every interpolated value. `f.primary` is a pinned &'static
    // vocabulary from `PrimaryOutcome::as_field`, not record content, so it has
    // no untrusted path in. `f.is_deny` is deliberately unused: severity is
    // pinned to LOG_WARNING (spec D4) because LOG_INFO lands in the unified
    // log's memory-backed tier and a `permit` may never reach disk.
    let action = scrub(f.action);
    let outcome = scrub(f.outcome);
    let subject = scrub(f.subject);

    // `String::new()` + `push_str`, no capacity arithmetic: an arithmetic
    // mutant on an unobservable capacity hint is equivalent-and-reported-MISSED,
    // and this is a [t1] zero-missed file with no exclusion available.
    let mut line = String::new();
    line.push_str(&macos_summary(
        action,
        outcome,
        subject,
        f.session_id,
        f.seq,
    ));
    // The unified log DISCARDS `openlog`'s ident (measured: subsystem and
    // category come back empty and the ident appears nowhere in the JSON
    // record), so there is no `journalctl -t maknaed` counterpart. The identity
    // token must be literal text IN the message or spec D5's parity is not
    // delivered.
    line.push_str(" SYSLOG_IDENTIFIER=");
    line.push_str(SYSLOG_IDENTIFIER);
    line.push_str(" MAKNAE_ACTION=");
    line.push_str(action.as_str());
    line.push_str(" MAKNAE_OUTCOME=");
    line.push_str(outcome.as_str());
    line.push_str(" MAKNAE_SUBJECT=");
    line.push_str(subject.as_str());
    line.push_str(" MAKNAE_PRIMARY=");
    line.push_str(f.primary);
    // LAST, always: the canonical JSON contains spaces, so it cannot be
    // whitespace-delimited. It is extracted as "everything after the FIRST
    // MAKNAE_RECORD=", which only works if nothing follows it.
    line.push_str(" MAKNAE_RECORD=");
    line.push_str(&canonical);
    Ok(line)
}

/// Format one audit record as a single macOS unified-log line.
///
/// `Ok(None)` means the line exceeds [`MACOS_SYSLOG_MAX`] and is DROPPED rather
/// than handed to a platform that would clip it mid-JSON and mark the wreckage
/// with `<…>`. A dropped record is visibly absent; a truncated one is corrupt
/// while looking present.
#[allow(dead_code)] // wired in Task 3
pub(crate) fn format_record(
    rec: &AuditRecord,
    primary: PrimaryOutcome,
) -> Result<Option<String>, AuditError> {
    let line = format_line_unchecked(rec, primary)?;
    if line.len() > MACOS_SYSLOG_MAX {
        return Ok(None);
    }
    Ok(Some(line))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Built LITERALLY. It CANNOT be shared: `journal.rs`'s and
    /// `journal_io.rs`'s test modules are private to their own files, and their
    /// two versions differ in arity. `Where`/`Integrity` derive no `Default` and
    /// MUST NOT gain one — this is a `[t1]` file, and a `Default` on a mutated
    /// return type makes its mutant equivalent-and-unkillable.
    fn rec(reason: &str) -> crate::record::AuditRecord {
        use crate::record::{AuditRecord, Integrity, Outcome, Source, Subject, Where};
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

    #[test]
    fn the_identity_token_is_in_the_message_because_the_ident_is_discarded() {
        // MEASURED on macOS 26.6.2: `openlog(ident, ...)` is DISCARDED by the
        // unified log. A record emitted with ident "maknaedCAP" came back with
        // subsystem="", category="", and the ident string appearing NOWHERE in
        // the JSON record — only processID and senderImagePath identify it.
        // There is no `journalctl -t maknaed` counterpart, so the identity token
        // must be literal text IN the message or spec D5's parity is not
        // delivered.
        let s = format_record(&rec("no"), PrimaryOutcome::Ok)
            .unwrap()
            .unwrap();
        assert!(
            s.contains("SYSLOG_IDENTIFIER=maknaed"),
            "identity token absent: {s}"
        );
    }

    #[test]
    fn maknae_record_is_last_so_it_can_be_extracted_unambiguously() {
        // The canonical JSON contains SPACES, so it cannot be
        // whitespace-delimited. The acceptance test extracts it as "everything
        // after MAKNAE_RECORD=", which only works if it is last.
        let s = format_record(&rec("policy denied"), PrimaryOutcome::Ok)
            .unwrap()
            .unwrap();
        let at = s
            .find("MAKNAE_RECORD=")
            .expect("MAKNAE_RECORD= must be present");
        let tail = &s[at + "MAKNAE_RECORD=".len()..];
        assert_eq!(
            tail,
            crate::record::canonical_json(&rec("policy denied")).unwrap()
        );
    }

    #[test]
    fn the_summary_carries_the_operator_facing_facts() {
        // KILLS `replace macos_summary -> String with String::new()` and with
        // "xyzzy". MEASURED: without this, 2 MISSED mutants on a [t1]
        // zero-missed file — every other test looks at MAKNAE_* tokens, the
        // payload tail, or lengths, all of which survive an empty summary.
        let s = format_record(&rec("no"), PrimaryOutcome::Ok)
            .unwrap()
            .unwrap();
        assert!(
            s.starts_with("maknae audit: fs.read deny subject=byeori session=7 seq=3 "),
            "summary text not as specified: {s}"
        );
    }

    #[test]
    fn a_hostile_subject_cannot_forge_structured_fields_into_the_prefix() {
        // `subject` IS interpolated, so it is the live injection vector once
        // `object` is removed. RED-PROOF, since a raw-field build no longer
        // compiles: temporarily neuter `scrub` to return `Scrubbed(v)`
        // unconditionally — possible only from INSIDE the `scrubbed` module,
        // which is the point — and this test fails.
        let mut r = rec("policy denied");
        r.subject.user = Some("byeori MAKNAE_OUTCOME=permit MAKNAE_PRIMARY=ok".into());
        let s = format_record(&r, PrimaryOutcome::WriteFailed)
            .unwrap()
            .unwrap();
        let prefix = &s[..s.find("MAKNAE_RECORD=").unwrap()];

        assert_eq!(
            prefix.matches("MAKNAE_OUTCOME=").count(),
            1,
            "one outcome token: {prefix}"
        );
        assert_eq!(
            prefix.matches("MAKNAE_PRIMARY=").count(),
            1,
            "one primary token: {prefix}"
        );
        assert!(
            !prefix.contains("MAKNAE_OUTCOME=permit"),
            "deny must not read as permit: {prefix}"
        );
        assert!(
            !prefix.contains("MAKNAE_PRIMARY=ok"),
            "write-failed must not read as ok: {prefix}"
        );
    }

    #[test]
    fn a_hostile_object_cannot_forge_structured_fields() {
        // THE security test. `object` is subject-controlled (ADR-0009: the
        // kernel-reported path of the subject's own delegated descriptor), and
        // the macOS line is undelimited.
        let mut r = rec("policy denied");
        r.object =
            Some("/home/byeori/x MAKNAE_OUTCOME=permit MAKNAE_PRIMARY=ok MAKNAE_RECORD={}".into());
        let s = format_record(&r, PrimaryOutcome::WriteFailed)
            .unwrap()
            .unwrap();

        // SCOPE EVERY ASSERTION TO THE PREFIX. The hostile string legitimately
        // reappears inside MAKNAE_RECORD — the payload is canonical JSON and
        // MUST be verbatim. Asserting over the WHOLE line is unsatisfiable by
        // any correct implementation: measured, `matches("MAKNAE_RECORD=")` is 2
        // and `contains("MAKNAE_OUTCOME=permit")` is true on a CORRECT build.
        // What D4b buys is an uncontaminated PREFIX and a trustworthy anchor.
        let at = s.find("MAKNAE_RECORD=").expect("anchor present");
        let prefix = &s[..at];

        assert_eq!(
            prefix.matches("MAKNAE_OUTCOME=").count(),
            1,
            "one outcome token in the prefix: {prefix}"
        );
        assert_eq!(
            prefix.matches("MAKNAE_PRIMARY=").count(),
            1,
            "one primary token in the prefix: {prefix}"
        );
        assert!(
            !prefix.contains("MAKNAE_OUTCOME=permit"),
            "a deny record must not read as permit: {prefix}"
        );
        assert!(
            !prefix.contains("MAKNAE_PRIMARY=ok"),
            "a write-failed record must not read as ok: {prefix}"
        );
        // NOT `assert!(!prefix.contains("MAKNAE_RECORD="))` — that is a
        // TAUTOLOGY: `find` returns the FIRST occurrence, so the slice before it
        // cannot contain the needle by construction. Assert the real property.
        assert_eq!(
            s.matches("MAKNAE_RECORD=").count(),
            2,
            "one anchor + one inside the verbatim payload: {s}"
        );

        // The extraction contract holds: FIRST occurrence, never rfind — under
        // hostile input the LAST occurrence is inside the payload.
        let tail = &s[at + "MAKNAE_RECORD=".len()..];
        assert_eq!(tail, crate::record::canonical_json(&r).unwrap());
    }

    #[test]
    fn the_scrub_rejects_every_hostile_shape_and_keeps_clean_values() {
        // Kills the `||` -> `&&` mutants on the scrub predicate. Without this,
        // MEASURED: 3 MISSED mutants on a [t1] zero-missed file — because with
        // `object` no longer interpolated, nothing else feeds a hostile value
        // in. Drive them through `subject`, which IS interpolated.
        for hostile in ["by=eori", "byMAKNAE_x", "bye\nori", "bye\rori"] {
            let mut r = rec("no");
            r.subject.user = Some(hostile.to_string());
            let s = format_record(&r, PrimaryOutcome::Ok).unwrap().unwrap();
            let at = s.find("MAKNAE_RECORD=").unwrap();
            assert!(
                s[..at].contains("MAKNAE_SUBJECT=invalid"),
                "not scrubbed: {hostile}"
            );
        }
        // The negative half — without it, a scrub that rejects EVERYTHING passes.
        let clean = format_record(&rec("no"), PrimaryOutcome::Ok)
            .unwrap()
            .unwrap();
        let at = clean.find("MAKNAE_RECORD=").unwrap();
        assert!(
            clean[..at].contains("MAKNAE_SUBJECT=byeori"),
            "a clean value must survive"
        );
        // Do NOT additionally assert `!s.contains(hostile)` — the payload
        // legitimately carries it. Same trap as the test above.
    }

    #[test]
    fn no_field_value_may_carry_a_newline() {
        // NOTE: after D4b this is subsumed by the scrub test above (its `\n` and
        // `\r` cases). The old rationale — "summary_line interpolates `object`
        // raw" — is FALSIFIED: `object` is no longer interpolated, and this test
        // passes even with no newline handling at all. Keep it as a line-shape
        // guard; do NOT treat it as the control.
        let mut r = rec("no");
        r.object = Some("/home/byeori/we\nird".into());
        let s = format_record(&r, PrimaryOutcome::Ok).unwrap().unwrap();
        assert!(
            !s.contains('\n'),
            "an embedded newline reached the line: {s:?}"
        );
    }

    #[test]
    fn a_normal_record_carries_every_filterable_field_and_the_canonical_json() {
        let s = format_record(&rec("policy denied"), PrimaryOutcome::Ok)
            .unwrap()
            .unwrap();
        for needle in [
            "MAKNAE_ACTION=fs.read",
            "MAKNAE_OUTCOME=deny",
            "MAKNAE_SUBJECT=byeori",
            "MAKNAE_PRIMARY=ok",
        ] {
            assert!(s.contains(needle), "missing {needle} in: {s}");
        }
        let canonical = crate::record::canonical_json(&rec("policy denied")).unwrap();
        assert!(
            s.contains(&canonical),
            "the canonical record must appear VERBATIM"
        );
    }

    #[test]
    fn an_oversize_record_is_dropped_not_truncated() {
        // THE decision this file exists for. macOS clips at 1015 bytes and MARKS
        // the result with a trailing `<…>`; a clipped record is corrupt JSON
        // regardless of the marker. We drop instead.
        let mut r = rec("no");
        r.au3_1 = serde_json::json!({ "pad": "x".repeat(4096) });
        assert!(format_record(&r, PrimaryOutcome::Ok).unwrap().is_none());
    }

    #[test]
    fn the_cap_constant_is_the_bisected_value() {
        assert_eq!(
            MACOS_SYSLOG_MAX, 1015,
            "the cap is a BISECTED value; see the constant's doc"
        );
    }

    /// Grow `au3_1`'s pad one byte at a time until the formatted line is EXACTLY
    /// n bytes. Each pad character adds exactly one byte, because the pad appears
    /// only inside `MAKNAE_RECORD`'s canonical JSON and never in the summary.
    fn record_formatting_to_exactly(n: usize) -> crate::record::AuditRecord {
        // BOUNDED, deliberately. An unbounded `loop` here produces TIMEOUT
        // mutants: cargo-mutants replaces `format_line_unchecked`'s body with a
        // constant-length string, the loop never reaches `len == n`, and the
        // test binary hangs. `coverage-tiers.sh:400-401` fails on missed OR
        // TIMEOUT, and the pre-push gate would NOT catch it — it runs
        // coverage-tiers without --mutants-all. (Measured against cargo-mutants
        // 27.1.0: unbounded -> 6 caught / 2 timeouts, exit 3; bounded -> 8/8
        // caught, exit 0.)
        for pad in 0..=n {
            let mut r = rec("no");
            r.au3_1 = serde_json::json!({ "p": "x".repeat(pad) });
            // Format WITHOUT the cap so we can measure past it.
            let len = format_line_unchecked(&r, PrimaryOutcome::Ok).unwrap().len();
            if len == n {
                return r;
            }
            assert!(
                len < n,
                "overshot {n} at pad {pad} (len {len}) — the step is not 1 byte"
            );
        }
        panic!("never reached exactly {n} bytes — the pad step is not 1 byte per char");
    }

    #[test]
    fn a_line_of_exactly_the_cap_is_kept_and_one_byte_more_is_dropped() {
        // THE test that kills `replace > with >=`. Every other assertion in this
        // file compares the code to its own constant and tolerates an
        // off-by-one predicate; this one pins both sides of the boundary.
        let at = record_formatting_to_exactly(MACOS_SYSLOG_MAX);
        assert!(
            format_record(&at, PrimaryOutcome::Ok).unwrap().is_some(),
            "a line of exactly MACOS_SYSLOG_MAX bytes must be KEPT"
        );

        let over = record_formatting_to_exactly(MACOS_SYSLOG_MAX + 1);
        assert!(
            format_record(&over, PrimaryOutcome::Ok).unwrap().is_none(),
            "a line one byte past the cap must be DROPPED"
        );
    }

    #[test]
    fn a_record_at_the_boundary_is_kept_and_one_past_it_is_dropped() {
        // Derived, not a pinned literal: grow the padding until the formatter
        // drops, then assert the last kept length is within the cap.
        let mut last_kept = 0usize;
        for pad in (0..2000).step_by(16) {
            let mut r = rec("no");
            r.au3_1 = serde_json::json!({ "p": "x".repeat(pad) });
            match format_record(&r, PrimaryOutcome::Ok).unwrap() {
                Some(s) => {
                    assert!(s.len() <= MACOS_SYSLOG_MAX);
                    last_kept = s.len();
                }
                None => {
                    assert!(last_kept > 0, "dropped before ever keeping one");
                    return;
                }
            }
        }
        panic!("formatter never dropped — the oversize predicate is not firing");
    }

    #[test]
    fn every_emitted_key_is_a_valid_journald_field_name() {
        // Cross-platform consistency: the macOS line uses the SAME key names as
        // the journald datagram, so an operator greps one string on both.
        let s = format_record(&rec("no"), PrimaryOutcome::WriteFailed)
            .unwrap()
            .unwrap();
        for kv in s.split_whitespace().filter(|w| w.starts_with("MAKNAE_")) {
            let key = kv.split('=').next().unwrap();
            assert!(crate::journal::is_valid_field_name(key), "bad key: {key}");
        }
    }

    #[test]
    fn every_primary_outcome_is_representable_and_distinct() {
        use PrimaryOutcome as P;
        let mut seen: Vec<String> = [
            P::Ok,
            P::RefusedBreakerOpen,
            P::RefusedAtCapacity,
            P::WriteFailed,
        ]
        .iter()
        .map(|p| {
            let s = format_record(&rec("no"), *p).unwrap().unwrap();
            s.split_whitespace()
                .find(|w| w.starts_with("MAKNAE_PRIMARY="))
                .unwrap()
                .to_string()
        })
        .collect();
        let before = seen.len();
        seen.sort();
        seen.dedup();
        assert_eq!(
            before,
            seen.len(),
            "two outcomes share a MAKNAE_PRIMARY rendering"
        );
    }
}
