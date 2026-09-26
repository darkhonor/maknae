//! Tool name → kernel verb. A ROUTING TABLE, closed and exact: the two names
//! the compiled baseline-tools.json publishes, and nothing else. Never a
//! decision — the kernel decides the verb this produces.
use maknae_proto::ProposedToolCall;
use serde::Deserialize;
use zeroize::Zeroizing;

pub enum ToolRequest {
    Read {
        call_id: String,
        path: String,
    },
    Write {
        call_id: String,
        path: String,
        content: Zeroizing<Vec<u8>>,
    },
}

/// Redacting, by hand — the crate convention (`maknae-proto/src/bytes.rs:25-32`,
/// and `impl Debug for SecretText` at `wire.rs:44-48`): a derived `Debug` would
/// dump the model's write bytes into any `{:?}`, including a test's
/// `panic!("{other:?}")`.
impl std::fmt::Debug for ToolRequest {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ToolRequest::Read { call_id, path } => f
                .debug_struct("Read")
                .field("call_id", call_id)
                .field("path", path)
                .finish(),
            ToolRequest::Write {
                call_id,
                path,
                content,
            } => f
                .debug_struct("Write")
                .field("call_id", call_id)
                .field("path", path)
                .field("content", &format_args!("<{} bytes>", content.len()))
                .finish(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RouteError {
    UnknownTool(String),
    BadArguments(String),
    EmptyPath,
    RelativePath,
    /// Non-canonical, over-long, or NUL-bearing: an empty (`//`), `.` or `..`
    /// segment; longer than `maknae_proto::MAX_MUTATION_PATH_BYTES`; or
    /// carrying a NUL byte. A trailing `/` is subsumed by the empty-segment
    /// rule and has no branch of its own HERE — past the bare-`/` early
    /// return, a path ending in `/` always splits to a trailing empty segment
    /// (see `checked_path`). All three causes are pinned in the model-facing
    /// tool-error text by `drive.rs`'s
    /// `the_malformed_path_tool_error_names_every_rule_that_produces_it` —
    /// and that text still LISTS a trailing `/` as a rule, which is right on
    /// both counts: the kernel's `lexical_pregate` does carry a
    /// `"trailing slash"` branch of its own (`maknae-kernel`'s `handler.rs`),
    /// and what the model needs is the rule it broke rather than which branch
    /// here caught it. `checked_path` records why this crate needs no such
    /// branch.
    MalformedPath,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ReadArgs {
    path: String,
}

/// The model's write bytes, owned by a zeroizing allocation from the moment
/// serde hands them over — and never by a plain `String` on the way in.
///
/// Why the field cannot just be a `String` moved into `Zeroizing` on the
/// success path (codex round 1, critical 1): the whole argument object is
/// deserialized BEFORE `checked_path` is consulted, so a write refused for
/// its path — and a deserialization that fails on a later field after
/// `content` was read — drops a plain owned allocation that nothing wipes.
/// There must be no plain owner to drop, which means the zeroizing type has
/// to be the field's own type.
///
/// What this does NOT protect, stated here because the doc comment is the
/// only place a reader will look: serde_json's own scratch buffer. A JSON
/// string carrying an escape is un-escaped into an allocation serde_json
/// owns and frees, outside anything this crate can reach — ruled deferred
/// (R39), not fixed here. The `visit_str` arm below receives a borrow of that
/// buffer and copies out of it; the copy is zeroizing, the scratch is not.
struct ZeroizingString(Zeroizing<String>);

/// Redacting, by hand — the crate convention (`ToolRequest` above,
/// `maknae-proto`'s `Bytes` and `SecretText`). `WriteArgs` derives `Debug`
/// and prints through this, so a `{:?}` of the parsed arguments — the value
/// that exists before any path check — shows a length and not the bytes.
/// zeroize 1.9 derives `Debug` on `Zeroizing` and forwards to the inner
/// value, so a derive here would print the content in full.
impl std::fmt::Debug for ZeroizingString {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "<{} bytes>", self.0.len())
    }
}

struct ZeroizingStringVisitor;

impl<'de> serde::de::Visitor<'de> for ZeroizingStringVisitor {
    type Value = ZeroizingString;
    fn expecting(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("a JSON string")
    }
    /// serde_json's only arm for a `&str` input, for both a borrowed
    /// fragment and one copied out of its un-escaping scratch. The
    /// destination is the ZEROIZING owner from the first byte written — the
    /// fragment is never copied into a plain `String` and moved afterwards.
    /// (`with_capacity` is for clarity about the one allocation, not a
    /// control: `push_str` from an empty `String` also allocates exactly
    /// once, so no test can tell the two apart and none pretends to.)
    fn visit_str<E: serde::de::Error>(self, v: &str) -> Result<Self::Value, E> {
        let mut s = Zeroizing::new(String::with_capacity(v.len()));
        s.push_str(v);
        Ok(ZeroizingString(s))
    }
    /// MOVED, never copied: a `String` the deserializer already owns becomes
    /// the zeroizing allocation itself. Unreachable through `serde_json::
    /// from_str` (it hands out `&str`), implemented because serde permits
    /// either call and a silent fall-back to `visit_str` would copy.
    fn visit_string<E: serde::de::Error>(self, v: String) -> Result<Self::Value, E> {
        Ok(ZeroizingString(Zeroizing::new(v)))
    }
}

impl<'de> Deserialize<'de> for ZeroizingString {
    fn deserialize<D: serde::Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        d.deserialize_string(ZeroizingStringVisitor)
    }
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct WriteArgs {
    path: String,
    content: ZeroizingString,
}

/// serde's DERIVED struct visitor accepts a positional ARRAY as well as a
/// map, and `#[serde(deny_unknown_fields)]` does not turn that off — so
/// `["/allowed/file"]` deserialized into `ReadArgs` and executed, for a tool
/// whose published schema declares an object with named properties (codex
/// round 1, important 1). Required before deserializing, on both legs.
///
/// A CHARACTER check on the trimmed text, deliberately, and never a
/// `serde_json::Value` round-trip: parsing into a `Value` first to inspect
/// its shape would copy the model's write bytes into a plain `String`, which
/// is exactly what [`ZeroizingString`] exists to prevent. It is a shape
/// admission, not a parse: anything that starts with `{` and is not a valid
/// object still fails in `from_str` below, with serde's own message.
fn require_object(args: &str) -> Result<(), RouteError> {
    if args.trim_start().starts_with('{') {
        Ok(())
    } else {
        Err(RouteError::BadArguments(
            "tool arguments must be a JSON object".into(),
        ))
    }
}

/// Absolute AND canonical only, within the kernel's byte bound, and never NUL
/// bearing. Never resolved against the CWD.
///
/// MIRRORS both of the kernel's pre-PDP path gates by RE-STATING their rules,
/// never by importing them — the brain links no kernel: `lexical_pregate`
/// (`maknae-kernel/src/handler.rs`), which both legs run, and `checked`
/// (`maknae-kernel/src/mutation.rs`), which the WRITE leg runs before
/// `authorize` and which adds the length and NUL rules below.
/// Rule for rule: absolute; bare `/` passes vacuously (it matches no glob
/// downstream, so the kernel answers it with a decision rather than a shape
/// fault); no trailing `/`; no empty (`//`), `.` or `..` segment. A divergence
/// is a test failure on either side, exactly as the kernel's own duplicate of
/// the rules in maknae-authz-basic is.
///
/// The kernel's `trailing slash` rule has no branch of its own here, and that
/// is not a gap: past the bare-`/` early return, a path ending in `/` always
/// splits to a trailing EMPTY segment, so the segment pass already refuses it.
/// The kernel keeps the two apart only to name two audit strings; this variant
/// is one, so a separate branch would be code no input can distinguish — a
/// surviving mutant, measured 2026-09-22 on the branch that removed it
/// (`69dc510`) and re-measured 2026-09-22 against this tree: adding the
/// explicit `ends_with` branch back leaves the WHOLE crate suite green, so no
/// test discriminates it in either direction. (The earlier wording named a
/// test count, which went stale the next time the crate grew a test.)
///
/// Why it is refused HERE and not left to the kernel: the pre-gate fails as
/// the malformed-request class, before the PDP and before anything is opened.
/// A read then comes back `BadRequest` and renders as `read unavailable — do
/// not retry`; a write comes back `Unauthorized` and renders as "the write may
/// have happened". Both are false, and both are outcomes the compiled prompt
/// forbids the model to appeal — for a typo the model could fix from a tool
/// error.
///
/// The length and NUL rules are applied to READS as well, although the read
/// leg states neither, and that is not the router outrunning the kernel:
/// neither shape can ever be SERVED. Such a read travels, and then the
/// subject's own `open_path_for_delegation` cannot open it — a NUL byte is not a
/// filename, and `MAX_MUTATION_PATH_BYTES` is 4096, the whole of Linux's
/// `PATH_MAX` and four times macOS's — so the request goes UNARMED. What the
/// kernel answers then depends on the gate the path meets first: a NUL byte
/// and an over-long length are not things `lexical_pregate` looks at, so such
/// a path, if otherwise canonical, reaches the descriptor check and is denied
/// for want of one (ADR-0009 decision 2); one that also carries an empty, `.`
/// or `..` segment is answered `BadRequest` for its shape before that. Both
/// render the same way, which is the point here: the model was told
/// `read unavailable — do not retry`, just as unappealable as the write lane's
/// "may have happened", for a path it could have corrected.
fn checked_path(p: String) -> Result<String, RouteError> {
    if p.is_empty() {
        return Err(RouteError::EmptyPath);
    }
    // The kernel's write gate runs these two BEFORE its lexical pre-gate, so
    // they are mirrored in that order, with its constant and its comparator:
    // `>`, so a path of exactly `MAX_MUTATION_PATH_BYTES` is accepted. `>=`
    // would refuse a write the kernel takes.
    if p.len() > maknae_proto::MAX_MUTATION_PATH_BYTES || p.contains('\0') {
        return Err(RouteError::MalformedPath);
    }
    if !p.starts_with('/') {
        return Err(RouteError::RelativePath);
    }
    if p == "/" {
        return Ok(p);
    }
    for seg in p[1..].split('/') {
        if matches!(seg, "" | "." | "..") {
            return Err(RouteError::MalformedPath);
        }
    }
    Ok(p)
}

pub fn route(call: &ProposedToolCall) -> Result<ToolRequest, RouteError> {
    let args: &str = &call.arguments.0;
    match call.name.as_str() {
        "read_file" => {
            require_object(args)?;
            let a: ReadArgs =
                serde_json::from_str(args).map_err(|e| RouteError::BadArguments(e.to_string()))?;
            Ok(ToolRequest::Read {
                call_id: call.call_id.clone(),
                path: checked_path(a.path)?,
            })
        }
        "write_file" => {
            require_object(args)?;
            let mut a: WriteArgs =
                serde_json::from_str(args).map_err(|e| RouteError::BadArguments(e.to_string()))?;
            let path = checked_path(a.path)?;
            // The ONE allocation, handed along: `mem::take` moves the
            // `String` out of its zeroizing owner (which is left holding an
            // unallocated `String`), and `into_bytes` re-labels that same
            // buffer as the `Vec<u8>` the new owner wipes. Nothing is copied
            // and nothing is freed, so there is no window in which the bytes
            // sit in an allocation with no zeroizing owner. `Zeroizing` has
            // no `into_inner` — it implements `Drop` — so this is the move.
            let content = Zeroizing::new(std::mem::take(&mut *a.content.0).into_bytes());
            Ok(ToolRequest::Write {
                call_id: call.call_id.clone(),
                path,
                content,
            })
        }
        other => Err(RouteError::UnknownTool(other.to_string())),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use maknae_proto::{ProposedToolCall, SecretText};
    use zeroize::Zeroizing;
    fn call(name: &str, args: &str) -> ProposedToolCall {
        ProposedToolCall {
            name: name.into(),
            call_id: "c1".into(),
            arguments: SecretText(Zeroizing::new(args.into())),
        }
    }
    #[test]
    fn read_file_routes_to_a_read_of_the_named_path() {
        match route(&call("read_file", r#"{"path":"/home/u/notes.txt"}"#)).unwrap() {
            ToolRequest::Read { call_id, path } => {
                assert_eq!(call_id, "c1");
                assert_eq!(path, "/home/u/notes.txt");
            }
            other => panic!("{other:?}"),
        }
    }
    #[test]
    fn write_file_routes_to_a_write_carrying_exactly_the_models_bytes() {
        match route(&call(
            "write_file",
            r#"{"path":"/home/u/a.txt","content":"héllo\n"}"#,
        ))
        .unwrap()
        {
            ToolRequest::Write { path, content, .. } => {
                assert_eq!(path, "/home/u/a.txt");
                assert_eq!(&content[..], "héllo\n".as_bytes());
            }
            other => panic!("{other:?}"),
        }
    }
    #[test]
    fn a_relative_path_is_a_tool_error_never_silently_resolved_against_the_cwd() {
        // Resolving against the CLI's CWD would let the launch directory
        // decide what the model's path means, and would make the delegated
        // descriptor's path differ from the wire's — the `object_requested`
        // symlink-probe signal. Refused here, as a tool error the model can fix.
        assert!(matches!(
            route(&call("read_file", r#"{"path":"notes.txt"}"#)),
            Err(RouteError::RelativePath)
        ));
        assert!(matches!(
            route(&call("write_file", r#"{"path":"./a","content":"x"}"#)),
            Err(RouteError::RelativePath)
        ));
        // A home-relative path is refused, never expanded — this crate has
        // no environment to expand `~` against, and must never acquire one.
        assert!(matches!(
            route(&call("read_file", r#"{"path":"~/foo"}"#)),
            Err(RouteError::RelativePath)
        ));
    }
    #[test]
    fn an_unknown_tool_fails_closed_without_guessing() {
        assert!(
            matches!(route(&call("read", r#"{"path":"x"}"#)), Err(RouteError::UnknownTool(n)) if n == "read")
        );
        assert!(matches!(
            route(&call("fs.read", r#"{"path":"x"}"#)),
            Err(RouteError::UnknownTool(_))
        ));
    }
    #[test]
    fn malformed_or_over_specified_arguments_are_refused_before_any_plane_call() {
        assert!(matches!(
            route(&call("read_file", "not json")),
            Err(RouteError::BadArguments(_))
        ));
        assert!(matches!(
            route(&call("read_file", r#"{"path":"x","extra":1}"#)),
            Err(RouteError::BadArguments(_))
        ));
        assert!(matches!(
            route(&call("write_file", r#"{"path":"x"}"#)),
            Err(RouteError::BadArguments(_))
        ));
        assert!(matches!(
            route(&call("read_file", r#"{"path":""}"#)),
            Err(RouteError::EmptyPath)
        ));
        // The kernel's `lexical_pregate` (maknae-kernel/src/handler.rs) refuses
        // these LEXICALLY, before the PDP and before anything is opened: a read
        // comes back `BadRequest` and renders as `read unavailable - do not
        // retry`; a write comes back `Unauthorized` and renders as "the write
        // may have happened". Both are false, and both are unappealable, for a
        // typo the model could have fixed from a tool error. Mirrored here rule
        // for rule (never imported - the brain links no kernel).
        for bad in [
            "/home/u/p/../q/f.txt",
            "/home/u//f.txt",
            "/home/u/./f.txt",
            "/home/u/dir/",
        ] {
            assert!(
                matches!(
                    route(&call("read_file", &format!(r#"{{"path":"{bad}"}}"#))),
                    Err(RouteError::MalformedPath)
                ),
                "read {bad}"
            );
            assert!(
                matches!(
                    route(&call(
                        "write_file",
                        &format!(r#"{{"path":"{bad}","content":"x"}}"#)
                    )),
                    Err(RouteError::MalformedPath)
                ),
                "write {bad}"
            );
        }
        // Bare `/` is what the kernel's pre-gate ACCEPTS - vacuously, it matches
        // no glob downstream, so the kernel answers it with a real DECISION
        // (deny) rather than a shape fault. Mirrored: accepted here too, so the
        // model sees the decision and not a router opinion.
        assert!(matches!(
            route(&call("read_file", r#"{"path":"/"}"#)),
            Ok(ToolRequest::Read { .. })
        ));
        assert!(matches!(
            route(&call("write_file", r#"{"path":"/","content":"x"}"#)),
            Ok(ToolRequest::Write { .. })
        ));
        // The kernel's WRITE gate adds two rules its READ pre-gate does not
        // state (`maknae-kernel/src/mutation.rs`'s `checked`, run BEFORE
        // `authorize`): a NUL byte, and a path longer than
        // `MAX_MUTATION_PATH_BYTES`. Pre-PDP they answer `Unauthorized`, which
        // the write lane cannot tell from a decision — so a typo rendered as
        // "the write may have happened … do not touch that file again".
        //
        // Applied to READS too, and that is NOT the router being stricter than
        // the kernel: neither shape can ever be SERVED. The read leg states no
        // NUL or length rule, so such a read travels — and then the subject's
        // own `open_path_for_delegation` cannot open it (a NUL byte is not a
        // filename; the constant is 4096, which is the whole of Linux's
        // PATH_MAX and four times macOS's), the request goes UNARMED — and,
        // if the path is otherwise lexically canonical, the kernel denies it
        // for want of a descriptor; if it also carries an empty, `.` or `..`
        // segment, the lexical pre-gate answers `BadRequest` for the shape
        // first. Both render as `read unavailable — do not retry`, equally
        // unappealable, which is the point. Refused here, on both legs, as a
        // tool error the model can fix.
        //
        // A NUL rides in as JSON's `\u0000`, which serde decodes to the byte;
        // a raw NUL in the JSON would be a control character serde rejects
        // first, and would prove nothing about this rule.
        assert!(matches!(
            route(&call("read_file", r#"{"path":"/home/u/a\u0000.txt"}"#)),
            Err(RouteError::MalformedPath)
        ));
        assert!(matches!(
            route(&call(
                "write_file",
                r#"{"path":"/home/u/a\u0000.txt","content":"x"}"#
            )),
            Err(RouteError::MalformedPath)
        ));
        // Built the way the kernel's own `checked` vector table builds them
        // (mutation.rs): the leading `/` counts toward the length.
        let over = format!("/{}", "x".repeat(maknae_proto::MAX_MUTATION_PATH_BYTES));
        let exact = format!("/{}", "x".repeat(maknae_proto::MAX_MUTATION_PATH_BYTES - 1));
        assert_eq!(over.len(), maknae_proto::MAX_MUTATION_PATH_BYTES + 1);
        assert_eq!(exact.len(), maknae_proto::MAX_MUTATION_PATH_BYTES);
        assert!(matches!(
            route(&call("read_file", &format!(r#"{{"path":"{over}"}}"#))),
            Err(RouteError::MalformedPath)
        ));
        assert!(matches!(
            route(&call(
                "write_file",
                &format!(r#"{{"path":"{over}","content":"x"}}"#)
            )),
            Err(RouteError::MalformedPath)
        ));
        // The comparator is the kernel's `>`, not `>=`: a path of EXACTLY
        // `MAX_MUTATION_PATH_BYTES` is accepted, on both legs. Without these
        // two rows a `>` → `>=` mutant survives, and the router would refuse
        // a write the kernel would have taken.
        assert!(matches!(
            route(&call("read_file", &format!(r#"{{"path":"{exact}"}}"#))),
            Ok(ToolRequest::Read { .. })
        ));
        assert!(matches!(
            route(&call(
                "write_file",
                &format!(r#"{{"path":"{exact}","content":"x"}}"#)
            )),
            Ok(ToolRequest::Write { .. })
        ));
    }
    #[test]
    fn a_write_requests_debug_never_prints_the_models_bytes() {
        let r = route(&call(
            "write_file",
            r#"{"path":"/a","content":"SECRET-BYTES"}"#,
        ))
        .unwrap();
        let d = format!("{r:?}");
        assert!(!d.contains("SECRET-BYTES"), "{d}");
        // A `#[derive(Debug)]` substitution prints `Zeroizing([...])`, so the
        // absence assertion fails on its own — not only the `<12 bytes>` marker.
        assert!(!d.contains("Zeroizing"), "{d}");
        assert!(d.contains("<12 bytes>"), "{d}");
        // The Read arm of the hand-written impl is a T1 region too (measured:
        // without this, route.rs sits at 88% against the 95 floor).
        let rd = format!(
            "{:?}",
            route(&call("read_file", r#"{"path":"/a"}"#)).unwrap()
        );
        assert!(rd.contains("Read") && rd.contains("/a"), "{rd}");
    }
    /// codex round 1, critical 1 — the REFUSAL path. `checked_path` is
    /// consulted only after the whole argument object has been deserialized,
    /// so on a bad path the model's write bytes are already an owned
    /// allocation that nothing wipes; a deserialization failure occurring
    /// after `content` was read is the same shape. The bytes must sit in a
    /// zeroizing owner from the moment serde hands them over, not from the
    /// success path onward — and the value that exists before `checked_path`
    /// runs must redact, because that is the one a `{:?}` of a parse error
    /// or a debug line would print.
    #[test]
    fn a_write_refused_for_its_path_never_owned_the_content_in_a_plain_string() {
        // The refusal itself, unchanged.
        assert!(matches!(
            route(&call(
                "write_file",
                r#"{"path":"relative.txt","content":"SECRET-CONTENT"}"#
            )),
            Err(RouteError::RelativePath)
        ));
        let args: WriteArgs =
            serde_json::from_str(r#"{"path":"relative.txt","content":"SECRET-CONTENT"}"#).unwrap();
        let d = format!("{args:?}");
        assert!(!d.contains("SECRET-CONTENT"), "{d}");
        // A `#[derive(Debug)]` substitution on the newtype prints
        // `Zeroizing("SECRET-CONTENT")` (zeroize 1.9 derives `Debug` on
        // `Zeroizing` and names it), so the marker assertion below fails on
        // its own, not only the absence one.
        assert!(!d.contains("Zeroizing"), "{d}");
        assert!(d.contains("<14 bytes>"), "{d}");
    }
    /// The visitor's two arms and its `expecting` text. `visit_string` — the
    /// arm that MOVES an owned `String` instead of copying it — is
    /// unreachable through `serde_json::from_str`, which hands out `&str`
    /// for every input, so it is exercised directly rather than left as an
    /// uncovered region in a T1 file.
    #[test]
    fn the_content_visitor_takes_an_owned_string_by_move_and_a_borrowed_one_by_copy() {
        use serde::de::Visitor;
        let moved = ZeroizingStringVisitor
            .visit_string::<serde_json::Error>("SECRET-MOVED".to_string())
            .unwrap();
        assert_eq!(&*moved.0, "SECRET-MOVED");
        let copied = ZeroizingStringVisitor
            .visit_str::<serde_json::Error>("SECRET-COPIED")
            .unwrap();
        assert_eq!(&*copied.0, "SECRET-COPIED");
        // `expecting` reaches the model as the tool error's own text, and a
        // non-string `content` is the input that produces it.
        let e = serde_json::from_str::<WriteArgs>(r#"{"path":"/a","content":7}"#).unwrap_err();
        assert!(e.to_string().contains("a JSON string"), "{e}");
    }
    /// codex round 1, important 1: serde's DERIVED struct visitor accepts a
    /// positional ARRAY as well as a map, and `deny_unknown_fields` does not
    /// turn that representation off — `["/allowed/file"]` deserialized into
    /// `ReadArgs` and EXECUTED. The tool schemas the model is handed declare
    /// objects with named properties, so an array is a malformed call, and it
    /// is refused before anything is deserialized: parsing it into a
    /// `serde_json::Value` first to inspect its shape would copy the model's
    /// write bytes into a plain `String`, which is the very thing critical 1
    /// above closes.
    #[test]
    fn positional_array_arguments_are_refused_never_deserialized_by_position() {
        for (name, args) in [
            ("read_file", r#"["/allowed/file"]"#),
            ("write_file", r#"["/allowed/file","SECRET-POSITIONAL"]"#),
            // Leading whitespace is skipped exactly as the parser would skip
            // it, so a padded array is still an array.
            ("read_file", "  [\"/allowed/file\"]"),
            // Every other JSON value meets the same check.
            ("read_file", "null"),
            ("write_file", r#""just a string""#),
        ] {
            assert!(
                matches!(route(&call(name, args)), Err(RouteError::BadArguments(m)) if m == "tool arguments must be a JSON object"),
                "{name} {args} routed"
            );
        }
        // And a padded OBJECT still routes — the check trims first, so this
        // row is the discriminator against a mutant dropping the trim.
        assert!(matches!(
            route(&call("read_file", "\n\t {\"path\":\"/a\"}")),
            Ok(ToolRequest::Read { .. })
        ));
    }
}
