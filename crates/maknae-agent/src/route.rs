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
    /// Non-canonical: a trailing `/`, or an empty (`//`), `.` or `..` segment.
    MalformedPath,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ReadArgs {
    path: String,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct WriteArgs {
    path: String,
    content: String,
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
/// surviving mutant, measured 2026-09-22 (dropping the explicit `ends_with`
/// check left all 30 tests green).
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
/// subject's own `open_for_delegation` cannot open it — a NUL byte is not a
/// filename, and `MAX_MUTATION_PATH_BYTES` is 4096, the whole of Linux's
/// `PATH_MAX` and four times macOS's — so the request goes UNARMED and the
/// kernel denies it for want of a descriptor (ADR-0009 decision 2). The model
/// was told `read unavailable — do not retry`, just as unappealable as the
/// write lane's "may have happened", for a path it could have corrected.
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
            let a: ReadArgs =
                serde_json::from_str(args).map_err(|e| RouteError::BadArguments(e.to_string()))?;
            Ok(ToolRequest::Read {
                call_id: call.call_id.clone(),
                path: checked_path(a.path)?,
            })
        }
        "write_file" => {
            let a: WriteArgs =
                serde_json::from_str(args).map_err(|e| RouteError::BadArguments(e.to_string()))?;
            Ok(ToolRequest::Write {
                call_id: call.call_id.clone(),
                path: checked_path(a.path)?,
                content: Zeroizing::new(a.content.into_bytes()),
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
        // own `open_for_delegation` cannot open it (a NUL byte is not a
        // filename; the constant is 4096, which is the whole of Linux's
        // PATH_MAX and four times macOS's), the request goes UNARMED, and the
        // kernel denies it for want of a descriptor. That renders as `read
        // unavailable — do not retry`, equally unappealable. Refused here, on
        // both legs, as a tool error the model can fix.
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
}
