use crate::journal::PrimaryOutcome;
use crate::record::AuditRecord;
use crate::syslog_fmt::{format_line_unchecked, format_record, Mirrored};

pub const MACOS_SYSLOG_MAX: usize = crate::syslog_fmt::MACOS_SYSLOG_MAX;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MacosMirror {
    pub full_len: usize,
    pub full_line: String,
    pub mirrored_in_full: bool,
    pub degraded_len: Option<usize>,
    pub degraded_line: Option<String>,
}

pub fn macos_mirror(r: &AuditRecord) -> MacosMirror {
    let full_line =
        format_line_unchecked(r, PrimaryOutcome::Ok).expect("the formatter accepts the record");
    let full_len = full_line.len();
    match format_record(r, PrimaryOutcome::Ok).expect("the formatter accepts the record") {
        Mirrored::Full(_) => MacosMirror {
            full_len,
            full_line,
            mirrored_in_full: true,
            degraded_len: None,
            degraded_line: None,
        },
        Mirrored::Degraded(l) => MacosMirror {
            full_len,
            full_line,
            mirrored_in_full: false,
            degraded_len: Some(l.len()),
            degraded_line: Some(l),
        },
    }
}
