//! What one sent verb came back as, and its conversion into the loop's
//! I/O-free `WireOutcome`.
/// What one sent verb came back as, with no RESULT printed — the caller decides what a
/// terminal (or a model) is told. [`crate::send::send_verb`] hands its arming and
/// attempt lines to the caller's `diag` sink.
///
/// `Refused` carries the code AND the message because the CLI's `round_trip` prints both; dropping
/// the message would be a silent behaviour change no CLI test captures. `Debug` because a
/// caller that expected a different variant formats the whole outcome to say so.
#[derive(Debug)]
pub enum SentOutcome {
    /// A successful payload, NOT yet checked against the verb that asked for it —
    /// the CLI's `print_payload_for_verb` is what rejects an answer to a different question.
    Payload(maknae_proto::Payload),
    /// A mutation reached a terminal state. `applied` is true ONLY for a client-reported
    /// `Ok(true)` — a CLAIM (ADR-0023 decision 4), never a kernel assertion.
    ///
    /// `stale` (#388): the client's own read-before-write check refused it before
    /// any write syscall, so it is certain nothing was written. `withheld` is set
    /// for any other failure decided before a write syscall. `version` is the written
    /// file's, when known.
    WriteDone {
        applied: bool,
        stale: bool,
        withheld: bool,
        version: Option<[i64; 7]>,
    },
    /// A read attempt ended; `read` is `Some` only after an acknowledged client-reported `Success`.
    ReadDone {
        read: Option<crate::mutation::ReadResult>,
    },
    /// The daemon refused, with the wire's own code and message (ADR-0019). `armed` is false, on a filesystem verb, iff the CLI delegated no descriptor, so no decision was made about the object.
    Refused {
        code: maknae_proto::ProtoErrCode,
        message: String,
        armed: bool,
    },
}

impl From<SentOutcome> for maknae_agent::wire::WireOutcome {
    fn from(sent: SentOutcome) -> Self {
        use maknae_agent::wire::{WireOutcome, WireRead};
        match sent {
            SentOutcome::Payload(p) => WireOutcome::Payload(p),
            SentOutcome::WriteDone {
                applied,
                stale,
                withheld,
                version,
            } => WireOutcome::WriteDone {
                applied,
                stale,
                withheld,
                version,
            },
            SentOutcome::ReadDone { read } => WireOutcome::ReadDone {
                read: read.map(|r| WireRead {
                    content: r.content,
                    level: r.label.level,
                    lines: r.page.lines,
                    complete_last: r.page.complete_last,
                    next: r.page.next,
                    eof: r.page.eof,
                    version: r.page.version.key(),
                }),
            },
            SentOutcome::Refused {
                code,
                message,
                armed,
            } => WireOutcome::Refused {
                code,
                message,
                armed,
            },
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sent_outcome_converts_field_for_field() {
        use maknae_agent::wire::WireOutcome;
        use maknae_proto::{Payload, ProtoErrCode};
        let version = maknae_io::FileVersion {
            dev: 1,
            ino: 2,
            size: 3,
            mtime: 4,
            mtime_nsec: 5,
            ctime: 6,
            ctime_nsec: 7,
        };
        let read = crate::mutation::ReadResult {
            content: zeroize::Zeroizing::new(b"body".to_vec()),
            label: maknae_proto::ObjectLabel {
                level: "SECRET".into(),
                categories: vec![],
            },
            page: crate::mutation::PageMeta {
                start: 0,
                lines: Some((3, 9)),
                complete_last: false,
                next: Some((10, 2)),
                eof: false,
                version,
            },
        };
        match WireOutcome::from(SentOutcome::ReadDone { read: Some(read) }) {
            WireOutcome::ReadDone { read: Some(r) } => {
                assert_eq!(&r.content[..], b"body");
                assert_eq!(r.level, "SECRET");
                assert_eq!(r.lines, Some((3, 9)));
                assert!(!r.complete_last);
                assert_eq!(r.next, Some((10, 2)));
                assert!(!r.eof);
                assert_eq!(r.version, version.key());
            }
            other => panic!("{other:?}"),
        }
        assert!(matches!(
            WireOutcome::from(SentOutcome::ReadDone { read: None }),
            WireOutcome::ReadDone { read: None }
        ));
        for (applied, stale, withheld, version) in [
            (true, false, false, Some([9; 7])),
            (false, true, false, None),
            (false, false, true, None),
        ] {
            match WireOutcome::from(SentOutcome::WriteDone {
                applied,
                stale,
                withheld,
                version,
            }) {
                WireOutcome::WriteDone {
                    applied: a,
                    stale: s,
                    withheld: w,
                    version: v,
                } => assert_eq!((a, s, w, v), (applied, stale, withheld, version)),
                other => panic!("{other:?}"),
            }
        }
        for armed in [true, false] {
            match WireOutcome::from(SentOutcome::Refused {
                code: ProtoErrCode::BadRequest,
                message: "m".into(),
                armed,
            }) {
                WireOutcome::Refused {
                    code,
                    message,
                    armed: a,
                } => assert_eq!(
                    (code, message.as_str(), a),
                    (ProtoErrCode::BadRequest, "m", armed)
                ),
                other => panic!("{other:?}"),
            }
        }
        assert!(matches!(
            WireOutcome::from(SentOutcome::Payload(Payload::Pong)),
            WireOutcome::Payload(Payload::Pong)
        ));
    }
}
