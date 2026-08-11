//! `maknae-audit-append` error type — fail-closed audit-sink failures (ADR-0019
//! AU-5: inability to open the primary sink at boot, or a runtime write
//! failure to it, must not be silently swallowed).
use std::path::PathBuf;

#[derive(Debug)]
pub enum AuditError {
    /// The primary JSONL sink could not be opened at boot — the daemon fails
    /// closed rather than starting without a durable audit path.
    OpenPrimary { path: PathBuf, detail: String },
    /// A write to the primary JSONL sink failed at runtime — the offending
    /// request must not be served (AU-5 fail-closed).
    WritePrimary(String),
    /// The record could not be canonicalized to JSON.
    Serialize(String),
}

impl std::fmt::Display for AuditError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            AuditError::OpenPrimary { path, detail } => write!(
                f,
                "cannot open primary audit sink {}: {detail} (failing closed)",
                path.display()
            ),
            AuditError::WritePrimary(msg) => {
                write!(f, "primary audit sink write failed: {msg} (failing closed)")
            }
            AuditError::Serialize(msg) => {
                write!(f, "audit record canonicalization failed: {msg}")
            }
        }
    }
}

impl std::error::Error for AuditError {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn variants_display_non_empty() {
        let cases = [
            AuditError::OpenPrimary {
                path: PathBuf::from("/var/lib/maknae/audit.jsonl"),
                detail: "permission denied".into(),
            },
            AuditError::WritePrimary("disk full".into()),
            AuditError::Serialize("bad utf8".into()),
        ];
        for e in cases {
            assert!(!format!("{e}").is_empty());
            assert!(!format!("{e:?}").is_empty());
        }
    }
}
