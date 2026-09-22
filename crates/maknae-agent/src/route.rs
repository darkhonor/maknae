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

/// Absolute only. Never resolved against the CWD.
fn checked_path(p: String) -> Result<String, RouteError> {
    if p.is_empty() {
        return Err(RouteError::EmptyPath);
    }
    if !p.starts_with('/') {
        return Err(RouteError::RelativePath);
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
