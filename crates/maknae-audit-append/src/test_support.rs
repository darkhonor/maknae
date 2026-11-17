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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::syslog_fmt::tests::record_formatting_to_exactly;

    #[test]
    fn a_record_over_the_cap_is_reported_degraded_and_one_under_in_full() {
        let at = macos_mirror(&record_formatting_to_exactly(MACOS_SYSLOG_MAX));
        assert!(at.mirrored_in_full);
        assert_eq!(at.full_len, MACOS_SYSLOG_MAX);
        assert_eq!(at.degraded_len, None);
        assert_eq!(at.degraded_line, None);
        assert_eq!(at.full_line.len(), at.full_len);

        let over = macos_mirror(&record_formatting_to_exactly(MACOS_SYSLOG_MAX + 1));
        assert!(!over.mirrored_in_full);
        assert_eq!(over.full_len, MACOS_SYSLOG_MAX + 1);
        assert!(over.degraded_len.unwrap() <= MACOS_SYSLOG_MAX);
        assert_eq!(over.full_line.len(), over.full_len);
        assert_eq!(
            over.degraded_line.unwrap().len(),
            over.degraded_len.unwrap()
        );
    }
}
