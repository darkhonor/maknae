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
use crate::journal::{fields_of, PrimaryOutcome, RecordFields, SYSLOG_IDENTIFIER};
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
    role: Scrubbed<'_>,
    session_id: u64,
    seq: u64,
) -> String {
    format!(
        "maknae audit: {} {} subject={} role={} session={} seq={}",
        action.as_str(),
        outcome.as_str(),
        subject.as_str(),
        role.as_str(),
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
    let role = scrub(f.role);

    // `String::new()` + `push_str`, no capacity arithmetic: an arithmetic
    // mutant on an unobservable capacity hint is equivalent-and-reported-MISSED,
    // and this is a [t1] zero-missed file with no exclusion available.
    let mut line = String::new();
    line.push_str(&macos_summary(
        action,
        outcome,
        subject,
        role,
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
    line.push_str(" MAKNAE_ROLE=");
    line.push_str(role.as_str());
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

/// Longest `action` / `outcome.result` the DEGRADED line will carry.
///
/// Both are `String` on the record, and [`format_record`] accepts any
/// [`AuditRecord`], so "they come from a closed vocabulary" is a caller
/// convention, not a type guarantee. Truncating here makes the degraded line's
/// bound a property of THIS builder rather than of its callers — which is what
/// lets [`Mirrored::Degraded`]'s fit be asserted unconditionally (#275).
pub(crate) const DEGRADED_TOKEN_MAX: usize = 48;

/// What the formatter produced for the mirror.
///
/// **There is no silent absence.** Before #275 an over-cap record returned
/// `Ok(None)` and nothing counted it, so the unified log showed a
/// complete-looking trail with holes exactly where the widest — and most
/// interesting — records were.
///
/// [`Mirrored::Degraded`] is an **AVAILABILITY MARKER, not a second AU-3
/// surface**: it deliberately does not attempt the six AU-3 elements. The
/// AU-3-complete record is durable in the primary append-only JSONL sink, which
/// has no size cap on either platform; this line proves the record existed and
/// says where to read it. `session_id` + `seq` ARE that pointer — they locate
/// the record in the JSONL — so no digest is carried and no hash primitive is
/// added to this crate.
///
/// `MAKNAE_PRIMARY` rides along because three of [`PrimaryOutcome`]'s four
/// values mean the primary never durably wrote; a marker that says "read the
/// JSONL" for a record that was never written is worse than silence.
pub(crate) enum Mirrored {
    Full(String),
    Degraded(String),
}

// Test-surface helpers. `#[allow(dead_code)]` rather than `#[cfg(test)]`: the
// coverage gate requires a column-0 `#[cfg(test)]` to introduce a `mod`, and
// these are inherent methods. They are exercised by this file's tests, so they
// cost no uncovered regions.
#[allow(dead_code)]
impl Mirrored {
    /// The full line, or `None` when the record could only be degraded.
    /// Existing assertions that mean "this record mirrors in full" read
    /// through here, so their meaning is unchanged by #275.
    pub(crate) fn into_full(self) -> Option<String> {
        match self {
            Mirrored::Full(l) => Some(l),
            Mirrored::Degraded(_) => None,
        }
    }
    pub(crate) fn is_full(&self) -> bool {
        matches!(self, Mirrored::Full(_))
    }
    pub(crate) fn is_degraded(&self) -> bool {
        matches!(self, Mirrored::Degraded(_))
    }
}

/// Count of records the mirror could only emit in degraded form.
///
/// The AU-5 product half: emit a detectable signal. Maknae does not alert —
/// that is the enclave's (AU-5a is Inherited). Shared by BOTH platform mirrors,
/// because a silent drop is the same defect on either.
static DEGRADED_MIRRORS: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);

/// Read the counter. `#[cfg(test)]` for now: this slice deliberately does not
/// disclose it on the wire (no `admin.status` field, no disclosure-manifest
/// row), and a `[t1]` file needs an observer or the `fetch_add` mutant is
/// unkillable. Wiring it to an operator surface is a follow-on.
#[allow(dead_code)]
pub(crate) fn degraded_mirror_count() -> u64 {
    DEGRADED_MIRRORS.load(std::sync::atomic::Ordering::Relaxed)
}

pub(crate) fn note_degraded_mirror() {
    DEGRADED_MIRRORS.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
}

/// The degraded line. Every field is either a fixed literal, an integer, or a
/// token truncated at [`DEGRADED_TOKEN_MAX`], so its length is bounded by
/// construction and carries no operator-controlled string — no host, no socket,
/// no object, no `au3_1`, no path.
fn degraded_line(f: &RecordFields<'_>) -> String {
    let mut action = scrub(f.action).as_str().to_string();
    action.truncate(DEGRADED_TOKEN_MAX);
    let mut outcome = scrub(f.outcome).as_str().to_string();
    outcome.truncate(DEGRADED_TOKEN_MAX);
    // Only an actually-durable primary may be pointed at.
    let where_to_read = if f.primary == PrimaryOutcome::Ok.as_field() {
        "read-primary-jsonl"
    } else {
        "primary-did-not-write"
    };
    format!(
        "maknae audit: DEGRADED {action} {outcome} session={} seq={} SYSLOG_IDENTIFIER={} MAKNAE_PRIMARY={} MAKNAE_DEGRADED={}",
        f.session_id, f.seq, SYSLOG_IDENTIFIER, f.primary, where_to_read
    )
}

/// Format one audit record for the macOS unified log.
///
/// Never silently absent: a record that will not fit [`MACOS_SYSLOG_MAX`] comes
/// back as [`Mirrored::Degraded`] and is counted. The platform would otherwise
/// clip mid-JSON and mark the wreckage with `<…>`; a truncated record is corrupt
/// while looking present, which is why the full line is never truncated.
pub(crate) fn format_record(
    rec: &AuditRecord,
    primary: PrimaryOutcome,
) -> Result<Mirrored, AuditError> {
    let line = format_line_unchecked(rec, primary)?;
    if line.len() > MACOS_SYSLOG_MAX {
        note_degraded_mirror();
        return Ok(Mirrored::Degraded(degraded_line(&fields_of(rec, primary))));
    }
    Ok(Mirrored::Full(line))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::record::{EgressAudit, EgressStatus};

    fn egress_record(
        status: EgressStatus,
        reply_length: Option<u64>,
        result: &str,
        reason: &str,
        posture: &str,
    ) -> crate::record::AuditRecord {
        let mut r = rec(reason);
        r.where_.host = "maknaed-01".into();
        r.where_.socket = "/var/run/maknae/plane.sock".into();
        r.source.plane_uri_san = Some("maknae://d/plane/cli".into());
        r.subject.plane_uri_san = Some("maknae://d/plane/cli".into());
        r.source.uid = u32::MAX;
        // production make_record never sets these; measure the production shape
        r.subject.user = None;
        r.source.gid = None;
        r.source.pid = None;
        r.action = "session.prompt".into();
        r.object = Some(format!("provider:{}", "p".repeat(32)));
        r.outcome.result = result.into();
        r.outcome.posture = posture.into();
        r.session_id = 999_999;
        r.seq = 999_999;
        r.au3_1 = serde_json::json!({"mutation": "untrusted extension"});
        r.egress = Some(EgressAudit {
            status,
            content_length: 999_999_999,
            content_digest: "f".repeat(32),
            conversation: "c".repeat(32),
            reply_length,
        });
        r
    }

    /// **The test that did not exist until #275.** Every other cap test takes
    /// the record as an INPUT and asks whether the formatter behaves at a given
    /// length; the two strongest CONSTRUCT a record at exactly the cap by
    /// padding `au3_1`, so by construction neither can reveal that a REAL
    /// record reaches it. The cap is a property of the record schema × the
    /// deployment's field widths, and until now no test owned that product.
    ///
    /// Replaces `every_egress_record_kind_fits_..._at_the_pinned_bounds` and its
    /// `EGRESS_RECORD_MARGIN`. That assertion was "the widest record must fit
    /// with 16 bytes to spare", which is the wrong invariant once degradation is
    /// the contract — and it was measured with `user: None`, i.e. the 7-byte
    /// `unknown` sentinel, which is exactly the state #275 abolishes. MEASURED
    /// with a real identity: `alice`+`role=user` = 1027, `aackerman`+`admin` =
    /// 1042, a 32-byte user + `adversary` = 1123, against a 1015 cap. So the
    /// widest content-plane records degrade on macOS as the NORMAL case.
    #[test]
    fn every_record_mirrors_something_and_the_degraded_line_always_fits() {
        let mut saw_degraded = false;
        for (label, r) in widest_shapes() {
            match format_record(&r, PrimaryOutcome::Ok).unwrap() {
                Mirrored::Full(l) => assert!(
                    l.len() <= MACOS_SYSLOG_MAX,
                    "{label}: full line {} > {MACOS_SYSLOG_MAX}",
                    l.len()
                ),
                Mirrored::Degraded(l) => {
                    saw_degraded = true;
                    // THE load-bearing assertion: the degraded line fits
                    // UNCONDITIONALLY, which is provable because it carries no
                    // operator-controlled string and truncates its two tokens.
                    assert!(
                        l.len() <= MACOS_SYSLOG_MAX,
                        "{label}: DEGRADED line {} > {MACOS_SYSLOG_MAX}",
                        l.len()
                    );
                    assert!(
                        !l.contains("MAKNAE_RECORD="),
                        "{label}: the degraded line must not carry the payload"
                    );
                }
            }
        }
        assert!(
            saw_degraded,
            "the pathological shape must degrade — otherwise this proves nothing"
        );
    }

    /// The AU-5 product half: a degraded emission is COUNTED, so the condition
    /// is detectable. Maknae does not alert — that is the enclave's (AU-5a is
    /// Inherited). Also the observer that makes the `fetch_add` killable.
    #[test]
    fn a_degraded_emission_is_counted() {
        let before = degraded_mirror_count();
        let mut r = rec("no");
        r.au3_1 = serde_json::json!({ "pad": "x".repeat(4096) });
        let m = format_record(&r, PrimaryOutcome::Ok).unwrap();
        assert!(m.is_degraded(), "the pathological record must degrade");
        assert!(
            degraded_mirror_count() > before,
            "a degraded emission must be counted: {before} -> {}",
            degraded_mirror_count()
        );
    }

    /// The degraded line's CONTENT, pinned. Kills the two
    /// `degraded_line -> String` stubs: every other assertion looks at lengths
    /// or at the absence of the payload, both of which an empty string
    /// satisfies.
    #[test]
    fn the_degraded_line_carries_the_pointer_into_the_primary_jsonl() {
        let mut r = rec("no");
        r.session_id = 4242;
        r.seq = 77;
        r.au3_1 = serde_json::json!({ "pad": "x".repeat(4096) });
        let Mirrored::Degraded(l) = format_record(&r, PrimaryOutcome::Ok).unwrap() else {
            panic!("the pathological record must degrade");
        };
        // session + seq ARE the pointer -- without them the marker proves a
        // record existed but not WHICH one, which is not a pointer at all.
        assert!(l.contains("session=4242"), "{l}");
        assert!(l.contains("seq=77"), "{l}");
        assert!(l.contains("MAKNAE_DEGRADED="), "{l}");
        assert!(l.contains(SYSLOG_IDENTIFIER), "{l}");
        assert!(l.contains("DEGRADED"), "{l}");
        assert!(!l.contains("MAKNAE_RECORD="), "{l}");
    }

    /// Both branches of the primary-outcome test. Kills `== -> !=`.
    ///
    /// The distinction is load-bearing: three of `PrimaryOutcome`'s four values
    /// mean the primary never durably wrote, and a marker that says "read the
    /// JSONL" for a record that was never written is worse than silence.
    #[test]
    fn the_degraded_line_only_points_at_a_primary_that_actually_wrote() {
        let mut r = rec("no");
        r.au3_1 = serde_json::json!({ "pad": "x".repeat(4096) });

        let Mirrored::Degraded(ok) = format_record(&r, PrimaryOutcome::Ok).unwrap() else {
            panic!("must degrade");
        };
        assert!(
            ok.contains("MAKNAE_DEGRADED=read-primary-jsonl"),
            "a durable primary must be pointed at: {ok}"
        );

        for p in [
            PrimaryOutcome::WriteFailed,
            PrimaryOutcome::RefusedBreakerOpen,
            PrimaryOutcome::RefusedAtCapacity,
        ] {
            let Mirrored::Degraded(bad) = format_record(&r, p).unwrap() else {
                panic!("must degrade");
            };
            assert!(
                bad.contains("MAKNAE_DEGRADED=primary-did-not-write"),
                "{p:?}: must NOT send the operator to a record that was never written: {bad}"
            );
        }
    }

    /// `is_full` / `is_degraded` must disagree on the same value — kills the
    /// `-> true` stubs, which every existing use survives because each is only
    /// ever asserted in the direction it already holds.
    #[test]
    fn the_two_mirror_predicates_are_exclusive() {
        let full = format_record(&rec("no"), PrimaryOutcome::Ok).unwrap();
        assert!(full.is_full() && !full.is_degraded());
        let mut r = rec("no");
        r.au3_1 = serde_json::json!({ "pad": "x".repeat(4096) });
        let deg = format_record(&r, PrimaryOutcome::Ok).unwrap();
        assert!(deg.is_degraded() && !deg.is_full());
    }

    /// The eight #172 egress shapes at a REAL identity, plus a deliberately
    /// pathological deployment. `host`, `socket`, `object` and `au3_1` are
    /// unbounded by design, so no sample is "the widest legal width" — the
    /// pathological case is here so the degraded arm is always exercised.
    fn widest_shapes() -> Vec<(String, crate::record::AuditRecord)> {
        let mut out = Vec::new();
        for (label, status, reply, result, reason, posture) in [
            (
                "intent",
                EgressStatus::IntentOnly,
                None,
                "permit",
                "intent recorded",
                "authorized",
            ),
            (
                "sent",
                EgressStatus::Sent,
                Some(999_999_999),
                "permit",
                "sent",
                "authorized",
            ),
            (
                "failed",
                EgressStatus::Failed,
                None,
                "deny",
                "send failed",
                "unavailable",
            ),
            (
                "undelivered",
                EgressStatus::LandedUndelivered,
                Some(999_999_999),
                "permit",
                "reply over the frame cap",
                "refused-oversize",
            ),
        ] {
            let mut r = egress_record(status, reply, result, reason, posture);
            r.subject.user = Some("aackerman".into());
            r.subject.role = Some("adversary".into());
            out.push((format!("{label} (real identity)"), r));
        }
        let mut path = egress_record(
            EgressStatus::LandedUndelivered,
            Some(999_999_999),
            "permit",
            "reply over the frame cap",
            "refused-oversize",
        );
        path.where_.host = "h".repeat(255);
        path.where_.socket = format!("/{}", "s".repeat(254));
        path.subject.user = Some("u".repeat(32));
        path.subject.role = Some("adversary".into());
        path.au3_1 = serde_json::json!({ "pad": "x".repeat(4096) });
        out.push(("pathological deployment".into(), path));
        out
    }

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
                user: Some("alice".into()),
                role: None,
                plane_uri_san: None,
            },
            action: "fs.read".into(),
            object: Some("/home/alice/.ssh/id_rsa".into()),
            object_requested: None,
            mutation: None,
            egress: None,
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
            .into_full()
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
            .into_full()
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
            .into_full()
            .unwrap();
        assert!(
            s.starts_with("maknae audit: fs.read deny subject=alice role=none session=7 seq=3 "),
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
        r.subject.user = Some("alice MAKNAE_OUTCOME=permit MAKNAE_PRIMARY=ok".into());
        let s = format_record(&r, PrimaryOutcome::WriteFailed)
            .unwrap()
            .into_full()
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
            Some("/home/alice/x MAKNAE_OUTCOME=permit MAKNAE_PRIMARY=ok MAKNAE_RECORD={}".into());
        let s = format_record(&r, PrimaryOutcome::WriteFailed)
            .unwrap()
            .into_full()
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
            let s = format_record(&r, PrimaryOutcome::Ok)
                .unwrap()
                .into_full()
                .unwrap();
            let at = s.find("MAKNAE_RECORD=").unwrap();
            assert!(
                s[..at].contains("MAKNAE_SUBJECT=invalid"),
                "not scrubbed: {hostile}"
            );
        }
        // The negative half — without it, a scrub that rejects EVERYTHING passes.
        let clean = format_record(&rec("no"), PrimaryOutcome::Ok)
            .unwrap()
            .into_full()
            .unwrap();
        let at = clean.find("MAKNAE_RECORD=").unwrap();
        assert!(
            clean[..at].contains("MAKNAE_SUBJECT=alice"),
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
        r.object = Some("/home/alice/we\nird".into());
        let s = format_record(&r, PrimaryOutcome::Ok)
            .unwrap()
            .into_full()
            .unwrap();
        assert!(
            !s.contains('\n'),
            "an embedded newline reached the line: {s:?}"
        );
    }

    #[test]
    fn a_normal_record_carries_every_filterable_field_and_the_canonical_json() {
        let s = format_record(&rec("policy denied"), PrimaryOutcome::Ok)
            .unwrap()
            .into_full()
            .unwrap();
        for needle in [
            "MAKNAE_ACTION=fs.read",
            "MAKNAE_OUTCOME=deny",
            "MAKNAE_SUBJECT=alice",
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
        assert!(format_record(&r, PrimaryOutcome::Ok).unwrap().is_degraded());
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
            format_record(&at, PrimaryOutcome::Ok).unwrap().is_full(),
            "a line of exactly MACOS_SYSLOG_MAX bytes must be KEPT"
        );

        let over = record_formatting_to_exactly(MACOS_SYSLOG_MAX + 1);
        assert!(
            format_record(&over, PrimaryOutcome::Ok)
                .unwrap()
                .is_degraded(),
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
                Mirrored::Full(s) => {
                    assert!(s.len() <= MACOS_SYSLOG_MAX);
                    last_kept = s.len();
                }
                Mirrored::Degraded(s) => {
                    assert!(last_kept > 0, "degraded before ever keeping one");
                    // #275: the degraded line must fit too — that is the whole
                    // point of it existing.
                    assert!(s.len() <= MACOS_SYSLOG_MAX, "degraded line {}", s.len());
                    return;
                }
            }
        }
        panic!("formatter never degraded — the oversize predicate is not firing");
    }

    #[test]
    fn every_emitted_key_is_a_valid_journald_field_name() {
        // Cross-platform consistency: the macOS line uses the SAME key names as
        // the journald datagram, so an operator greps one string on both.
        let s = format_record(&rec("no"), PrimaryOutcome::WriteFailed)
            .unwrap()
            .into_full()
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
            let s = format_record(&rec("no"), *p).unwrap().into_full().unwrap();
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
