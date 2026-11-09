//! The wire's answers, as the loop reads them. Pure: the client that produced a
//! [`WireOutcome`] converts into it, so the decisions below stay in this crate,
//! where they are mutation-tested.
use crate::plane::{PlaneError, ProtectedBy, ReadBasis, ReadOutcome, ReadPage, WriteOutcome};
use maknae_proto::{ConversationId, ConversationView, Payload};

/// What an existing file must be before a replace writes it (#388). The
/// agent's loop sends `Unread` or `Read`; `maknae write` sends `Unchecked`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WriteCheck {
    Unchecked,
    Unread,
    Read([i64; 7]),
}

/// One acknowledged page. `content` is the client's zeroizing read buffer,
/// moved through, never copied.
pub struct WireRead {
    pub content: zeroize::Zeroizing<Vec<u8>>,
    pub level: String,
    pub lines: Option<(u64, u64)>,
    pub complete_last: bool,
    pub next: Option<(u64, u64)>,
    pub eof: bool,
    pub version: [i64; 7],
}

impl std::fmt::Debug for WireRead {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("WireRead")
            .field("content", &format_args!("<{} bytes>", self.content.len()))
            .field("level", &self.level)
            .field("lines", &self.lines)
            .field("next", &self.next)
            .field("eof", &self.eof)
            .finish()
    }
}

/// What one sent verb came back as. `Refused` carries the wire's own code and
/// message (ADR-0019); `armed` is false, on a filesystem verb, iff the client
/// delegated no descriptor, so no decision was made about the object.
/// `withheld` is set when the attempt failed before any write syscall and no
/// stale result may be released.
#[derive(Debug)]
pub enum WireOutcome {
    Payload(Payload),
    WriteDone {
        applied: bool,
        stale: bool,
        withheld: bool,
        version: Option<[i64; 7]>,
    },
    ReadDone {
        read: Option<WireRead>,
    },
    Refused {
        code: maknae_proto::ProtoErrCode,
        message: String,
        armed: bool,
    },
}

/// A CONTROL, and a pure function so it is testable. An armed `Unauthorized` is
/// `Refused`; every other refusal, any protocol surprise, any transport error and
/// a grant that ends without an acknowledged `Success` is `Unavailable`. The model
/// is told both in the same words (ADR-0034 decision 7); only `Protected`, decided
/// first, reads differently.
pub fn read_outcome(sent: Result<WireOutcome, String>) -> ReadOutcome {
    if let Some(by) = protected(&sent) {
        return ReadOutcome::Protected(by);
    }
    match sent {
        Ok(WireOutcome::ReadDone { read: Some(r) }) => ReadOutcome::Content(ReadPage {
            content: r.content,
            level: r.level,
            lines: r.lines,
            complete_line: r.complete_last,
            next: r.next,
            eof: r.eof,
            version: r.version,
            changed: false,
        }),
        Ok(WireOutcome::Refused { armed: false, .. }) => ReadOutcome::Unavailable,
        Ok(WireOutcome::Refused {
            code: maknae_proto::ProtoErrCode::Unauthorized,
            ..
        }) => ReadOutcome::Refused,
        _ => ReadOutcome::Unavailable,
    }
}

/// The write half, pure for the same reason. Only a clean `WriteDone { applied:
/// true }` is `Applied`. A `Refused` frame is `Unavailable`: the kernel refuses
/// only in place of the grant, before any effect. So is a `withheld` completion,
/// which the client sets when it certifies no effect syscall was attempted,
/// including a failure before the grant (the client's `NotAttempted`); a `stale`
/// one is `Stale`. Every `Err` and every other completion is `Unknown` (ADR-0023
/// d4). `NotSent` is decided from `write_request`'s `Err`, before `send_verb`.
pub fn write_outcome(sent: Result<WireOutcome, String>) -> WriteOutcome {
    if let Some(by) = protected(&sent) {
        return WriteOutcome::Protected(by);
    }
    match sent {
        Ok(WireOutcome::WriteDone {
            applied: true,
            version,
            ..
        }) => WriteOutcome::Applied(version),
        Ok(WireOutcome::WriteDone {
            applied: false,
            stale: true,
            ..
        }) => WriteOutcome::Stale,
        Ok(WireOutcome::WriteDone {
            applied: false,
            withheld: true,
            ..
        })
        | Ok(WireOutcome::Refused { .. }) => WriteOutcome::Unavailable,
        _ => WriteOutcome::Unknown,
    }
}

/// A `Protected` refusal, decided before `armed` is looked at: the kernel answers it on
/// the asked path alone, so an unarmed request renders exactly as an armed one.
fn protected(sent: &Result<WireOutcome, String>) -> Option<ProtectedBy> {
    match sent {
        Ok(WireOutcome::Refused {
            code: maknae_proto::ProtoErrCode::Protected,
            message,
            ..
        }) => maknae_proto::protected_parts(message).map(|(list, entry)| ProtectedBy {
            list: list.into(),
            entry: entry.into(),
        }),
        _ => None,
    }
}

/// The loop's knowledge of a file, as the client's write check (#388). The
/// loop never sends `Unchecked`: that is `maknae write`'s, for a human.
pub fn check_for(basis: ReadBasis) -> WriteCheck {
    match basis {
        ReadBasis::Unread => WriteCheck::Unread,
        ReadBasis::Read(k) => WriteCheck::Read(k),
    }
}

/// The prompt leg's mapper, pure and tested for the same reason the read and
/// write mappers are: it is a CONTROL. A `BadRequest` on `session.prompt` is a
/// pre-gate fault on the request's own shape — `maknae agent "   "` is refused
/// for carrying no text to send, and provably never reached the provider: no
/// egress block was opened and no intent record was written. Reporting that
/// with the host's refusal line (`PROMPT_REFUSED` in `maknae agent`) would send
/// the subject to their providers.yaml and their login for a fault they can fix
/// from the message. What
/// the trail does hold is the pre-gate deny: the kernel appends
/// `emit_request_outcome` with a `deny` and the reason
/// `prompt fails operand pre-gate: …` before it writes the `BadRequest` back,
/// and it writes that error only under `may_respond(appended)`, so a subject
/// who saw it is proof the record landed. Both facts, and neither more: no
/// provider contact, and a recorded pre-gate deny. `ReplyUnusable` carries the
/// provider-side reason (#524).
pub fn prompt_outcome(
    sent: Result<WireOutcome, String>,
) -> Result<maknae_proto::PromptReply, PlaneError> {
    match sent {
        Ok(WireOutcome::Payload(Payload::PromptReply(r))) => Ok(r),
        Ok(WireOutcome::Refused {
            code: maknae_proto::ProtoErrCode::BadRequest,
            ..
        }) => Err(PlaneError::Malformed),
        Ok(WireOutcome::Refused {
            code: maknae_proto::ProtoErrCode::ReplyUnusable(d),
            ..
        }) => Err(PlaneError::ReplyUnusable(d)),
        Ok(WireOutcome::Refused {
            code: maknae_proto::ProtoErrCode::EgressUnavailable,
            ..
        }) => Err(PlaneError::Unavailable),
        Ok(WireOutcome::Refused { .. }) => Err(PlaneError::Refused),
        Ok(other) => Err(PlaneError::Transport(format!(
            "protocol error: unexpected reply to session.prompt: {other:?}"
        ))),
        Err(m) => Err(PlaneError::Transport(m)),
    }
}

pub fn open_outcome(sent: Result<WireOutcome, String>) -> Result<ConversationId, PlaneError> {
    match sent {
        Ok(WireOutcome::Payload(Payload::ConversationOpened(v))) => Ok(v.conversation),
        other => Err(conversation_failure("session.new", other)),
    }
}

pub fn close_outcome(
    asked: &ConversationId,
    sent: Result<WireOutcome, String>,
) -> Result<ConversationView, PlaneError> {
    match sent {
        Ok(WireOutcome::Payload(Payload::ConversationClosed(v))) if v.conversation == *asked => {
            Ok(v)
        }
        other => Err(conversation_failure("session.close", other)),
    }
}

fn conversation_failure(verb: &str, sent: Result<WireOutcome, String>) -> PlaneError {
    match sent {
        Ok(WireOutcome::Refused {
            code: maknae_proto::ProtoErrCode::Unauthorized,
            ..
        }) => PlaneError::Refused,
        Ok(WireOutcome::Refused { code, message, .. }) => PlaneError::Declined {
            code,
            reason: message,
        },
        Ok(other) => PlaneError::Transport(format!(
            "protocol error: unexpected reply to {verb}: {other:?}"
        )),
        Err(m) => PlaneError::Transport(m),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn page(content: &[u8]) -> WireRead {
        WireRead {
            content: zeroize::Zeroizing::new(content.to_vec()),
            level: "UNCLASSIFIED".into(),
            lines: Some((1, 1)),
            complete_last: true,
            next: None,
            eof: true,
            version: [0; 7],
        }
    }

    #[test]
    fn the_loops_basis_becomes_the_clients_check() {
        assert_eq!(check_for(ReadBasis::Unread), WriteCheck::Unread);
        assert_eq!(check_for(ReadBasis::Read([4; 7])), WriteCheck::Read([4; 7]));
    }

    #[test]
    fn a_write_is_applied_only_for_a_clean_completion() {
        use maknae_proto::Payload;
        assert_eq!(
            write_outcome(Ok(WireOutcome::WriteDone {
                applied: true,
                stale: false,
                withheld: false,
                version: None
            })),
            WriteOutcome::Applied(None)
        );
        assert_eq!(
            write_outcome(Ok(WireOutcome::WriteDone {
                applied: true,
                stale: false,
                withheld: false,
                version: Some([2; 7])
            })),
            WriteOutcome::Applied(Some([2; 7]))
        );
        assert_eq!(
            write_outcome(Ok(WireOutcome::WriteDone {
                applied: false,
                stale: true,
                withheld: false,
                version: None
            })),
            WriteOutcome::Stale
        );
        assert_eq!(
            write_outcome(Ok(WireOutcome::WriteDone {
                applied: false,
                stale: false,
                withheld: false,
                version: None
            })),
            WriteOutcome::Unknown
        );
        assert_eq!(
            write_outcome(Ok(WireOutcome::Payload(Payload::Pong))),
            WriteOutcome::Unknown
        );
        assert_eq!(
            write_outcome(Err("no response from daemon within 5000ms".into())),
            WriteOutcome::Unknown
        );
    }

    fn every_code_but_protected() -> Vec<maknae_proto::ProtoErrCode> {
        use maknae_proto::ProtoErrCode;
        let mut codes = vec![
            ProtoErrCode::Unauthorized,
            ProtoErrCode::BadRequest,
            ProtoErrCode::Internal,
            ProtoErrCode::TooLarge,
            ProtoErrCode::UnknownVerb,
            ProtoErrCode::NotImplemented,
            ProtoErrCode::EgressUnavailable,
        ];
        codes.extend(maknae_proto::ReplyDefect::ALL.map(ProtoErrCode::ReplyUnusable));
        codes
    }

    #[test]
    fn a_write_refused_before_the_grant_is_unavailable() {
        for code in every_code_but_protected() {
            for armed in [true, false] {
                assert_eq!(
                    write_outcome(Ok(WireOutcome::Refused {
                        code: code.clone(),
                        message: "not authorized".into(),
                        armed,
                    })),
                    WriteOutcome::Unavailable,
                    "{code:?} {armed}"
                );
            }
        }
        assert_eq!(
            write_outcome(Ok(WireOutcome::WriteDone {
                applied: false,
                stale: false,
                withheld: true,
                version: None
            })),
            WriteOutcome::Unavailable,
            "a stale or unread result the loop could not read back is withheld"
        );
    }

    #[test]
    fn a_failure_after_the_grant_stays_outcome_unknown() {
        use maknae_proto::Payload;
        assert_eq!(
            write_outcome(Ok(WireOutcome::WriteDone {
                applied: false,
                stale: false,
                withheld: false,
                version: None
            })),
            WriteOutcome::Unknown
        );
        assert_eq!(
            write_outcome(Ok(WireOutcome::Payload(Payload::Pong))),
            WriteOutcome::Unknown
        );
        assert_eq!(
            write_outcome(Ok(WireOutcome::ReadDone { read: None })),
            WriteOutcome::Unknown
        );
        assert_eq!(
            write_outcome(Err(
                "mutation acknowledgment timed out; effects may already have occurred".into()
            )),
            WriteOutcome::Unknown
        );
    }

    #[test]
    fn a_reply_unusable_refusal_is_its_own_plane_error() {
        for d in maknae_proto::ReplyDefect::ALL {
            assert_eq!(
                prompt_outcome(Ok(WireOutcome::Refused {
                    code: maknae_proto::ProtoErrCode::ReplyUnusable(d),
                    message: "reply unusable".into(),
                    armed: false,
                })),
                Err(PlaneError::ReplyUnusable(d)),
            );
        }
    }

    #[test]
    fn an_egress_unavailable_refusal_is_unavailable() {
        assert_eq!(
            prompt_outcome(Ok(WireOutcome::Refused {
                code: maknae_proto::ProtoErrCode::EgressUnavailable,
                message: maknae_proto::EGRESS_UNAVAILABLE_MESSAGE.into(),
                armed: false,
            })),
            Err(PlaneError::Unavailable)
        );
    }

    #[test]
    fn an_unauthorized_prompt_refusal_is_refused() {
        assert_eq!(
            prompt_outcome(Ok(WireOutcome::Refused {
                code: maknae_proto::ProtoErrCode::Unauthorized,
                message: "not authorized".into(),
                armed: false,
            })),
            Err(PlaneError::Refused)
        );
    }

    #[test]
    fn a_prompt_is_malformed_only_for_bad_request_and_refused_for_every_other_code_but_reply_unusable(
    ) {
        use maknae_proto::{Payload, PromptReply, ProtoErrCode};
        let refused = |code| {
            prompt_outcome(Ok(WireOutcome::Refused {
                code,
                message: "prompt carries no text to send".into(),
                armed: false,
            }))
        };
        assert_eq!(
            refused(ProtoErrCode::BadRequest),
            Err(PlaneError::Malformed)
        );
        for code in [
            ProtoErrCode::Unauthorized,
            ProtoErrCode::Internal,
            ProtoErrCode::TooLarge,
            ProtoErrCode::UnknownVerb,
            ProtoErrCode::NotImplemented,
        ] {
            assert_eq!(refused(code.clone()), Err(PlaneError::Refused), "{code:?}");
        }
        assert_eq!(
            prompt_outcome(Ok(WireOutcome::Payload(Payload::PromptReply(
                PromptReply {
                    reasoning: None,
                    blocks: vec![],
                    tool_calls: vec![],
                    usage: None,
                }
            )))),
            Ok(PromptReply {
                reasoning: None,
                blocks: vec![],
                tool_calls: vec![],
                usage: None,
            })
        );
        assert!(matches!(
            prompt_outcome(Ok(WireOutcome::Payload(Payload::Pong))),
            Err(PlaneError::Transport(_))
        ));
        assert!(matches!(
            prompt_outcome(Err("handshake timed out".into())),
            Err(PlaneError::Transport(_))
        ));
    }

    #[test]
    fn a_read_is_refused_only_for_unauthorized_and_unavailable_for_every_other_outcome() {
        use maknae_proto::{Payload, ProtoErrCode};
        assert_eq!(
            read_outcome(Ok(WireOutcome::ReadDone {
                read: Some(page(b"x"))
            })),
            ReadOutcome::Content(ReadPage {
                content: zeroize::Zeroizing::new(b"x".to_vec()),
                level: "UNCLASSIFIED".into(),
                lines: Some((1, 1)),
                complete_line: true,
                next: None,
                eof: true,
                version: [0; 7],
                changed: false,
            })
        );
        assert_eq!(
            read_outcome(Ok(WireOutcome::ReadDone { read: None })),
            ReadOutcome::Unavailable
        );
        assert_eq!(
            read_outcome(Ok(WireOutcome::Payload(Payload::Pong))),
            ReadOutcome::Unavailable
        );
        assert_eq!(
            read_outcome(Ok(WireOutcome::Refused {
                code: ProtoErrCode::Unauthorized,
                message: "not authorized".into(),
                armed: true
            })),
            ReadOutcome::Refused
        );
        assert_eq!(
            read_outcome(Ok(WireOutcome::Refused {
                code: ProtoErrCode::BadRequest,
                message: "not absolute".into(),
                armed: true
            })),
            ReadOutcome::Unavailable
        );
        assert_eq!(
            read_outcome(Ok(WireOutcome::Refused {
                code: ProtoErrCode::Unauthorized,
                message: "no delegated descriptor".into(),
                armed: false
            })),
            ReadOutcome::Unavailable,
            "a read the subject could not arm was never decided"
        );
        assert_eq!(
            read_outcome(Ok(WireOutcome::Refused {
                code: ProtoErrCode::BadRequest,
                message: "not absolute".into(),
                armed: false
            })),
            ReadOutcome::Unavailable
        );
        assert_eq!(
            read_outcome(Ok(WireOutcome::WriteDone {
                applied: true,
                stale: false,
                withheld: false,
                version: None
            })),
            ReadOutcome::Unavailable
        );
        assert_eq!(
            read_outcome(Err("handshake timed out".into())),
            ReadOutcome::Unavailable
        );
    }

    #[test]
    fn an_armed_and_an_unarmed_read_refusal_render_the_same_bytes() {
        use crate::render::{render, ToolOutcome};
        let rendered = |armed| {
            let outcome = match read_outcome(Ok(WireOutcome::Refused {
                code: maknae_proto::ProtoErrCode::Unauthorized,
                message: "not authorized".into(),
                armed,
            })) {
                ReadOutcome::Refused => ToolOutcome::ReadRefused,
                ReadOutcome::Unavailable => ToolOutcome::ReadUnavailable,
                other => panic!("{other:?}"),
            };
            render(&outcome, 1)
        };
        assert_eq!(rendered(true).as_str(), rendered(false).as_str());
        assert_eq!(
            rendered(true).as_str(),
            "unavailable — do not retry\n\nsteps remaining: 1"
        );
    }

    fn protected_frame(armed: bool) -> Result<WireOutcome, String> {
        Ok(WireOutcome::Refused {
            code: maknae_proto::ProtoErrCode::Protected,
            message: maknae_proto::protected_message(
                maknae_proto::HOST_SENSITIVE_LIST,
                "~/.ssh/**",
            ),
            armed,
        })
    }

    fn by() -> ProtectedBy {
        ProtectedBy {
            list: maknae_proto::HOST_SENSITIVE_LIST.into(),
            entry: "~/.ssh/**".into(),
        }
    }

    #[test]
    fn a_protected_refusal_is_protected_whether_or_not_it_was_armed() {
        for armed in [true, false] {
            assert_eq!(
                read_outcome(protected_frame(armed)),
                ReadOutcome::Protected(by()),
                "{armed}"
            );
            assert_eq!(
                write_outcome(protected_frame(armed)),
                WriteOutcome::Protected(by()),
                "{armed}"
            );
        }
        let malformed = Ok(WireOutcome::Refused {
            code: maknae_proto::ProtoErrCode::Protected,
            message: "not authorized".into(),
            armed: true,
        });
        assert_eq!(read_outcome(malformed), ReadOutcome::Unavailable);
        let unauthorized = Ok(WireOutcome::Refused {
            code: maknae_proto::ProtoErrCode::Unauthorized,
            message: maknae_proto::protected_message(
                maknae_proto::HOST_SENSITIVE_LIST,
                "~/.ssh/**",
            ),
            armed: true,
        });
        assert_eq!(read_outcome(unauthorized), ReadOutcome::Refused);
    }

    #[test]
    fn a_wire_outcomes_debug_never_prints_the_served_bytes() {
        let d = format!(
            "{:?}",
            WireOutcome::ReadDone {
                read: Some(page(b"SENTINEL-WIRE-BYTES"))
            }
        );
        assert!(!d.contains("SENTINEL-WIRE-BYTES"), "{d}");
        assert!(!d.contains("Zeroizing"), "{d}");
        assert!(d.contains("<19 bytes>"), "{d}");
    }

    fn view(id: &str) -> ConversationView {
        ConversationView {
            conversation: ConversationId::parse(id).unwrap(),
            cwd: "/home/a/w".into(),
            opened_at: 1,
            last_active: 2,
            turns: 0,
            bytes: 0,
            chain_head: "h".into(),
        }
    }

    fn refused(code: maknae_proto::ProtoErrCode) -> Result<WireOutcome, String> {
        Ok(WireOutcome::Refused {
            code,
            message: "too many active conversations".into(),
            armed: true,
        })
    }

    const A: &str = "0123456789abcdef0123456789abcdef";
    const B: &str = "fedcba9876543210fedcba9876543210";

    #[test]
    fn only_an_opened_conversation_opens_and_an_unauthorized_open_is_refused() {
        assert_eq!(
            open_outcome(Ok(WireOutcome::Payload(Payload::ConversationOpened(view(
                A
            ))))),
            Ok(ConversationId::parse(A).unwrap())
        );
        assert_eq!(
            open_outcome(refused(maknae_proto::ProtoErrCode::Unauthorized)),
            Err(PlaneError::Refused)
        );
        assert_eq!(
            open_outcome(Ok(WireOutcome::Refused {
                code: maknae_proto::ProtoErrCode::Unauthorized,
                message: "not authorized".into(),
                armed: false,
            })),
            Err(PlaneError::Refused)
        );
        assert_eq!(
            open_outcome(refused(maknae_proto::ProtoErrCode::TooLarge)),
            Err(PlaneError::Declined {
                code: maknae_proto::ProtoErrCode::TooLarge,
                reason: "too many active conversations".into(),
            })
        );
        match open_outcome(Ok(WireOutcome::Payload(Payload::ConversationClosed(view(
            A,
        ))))) {
            Err(PlaneError::Transport(m)) => {
                assert!(
                    m.starts_with("protocol error: unexpected reply to session.new"),
                    "{m}"
                )
            }
            other => panic!("{other:?}"),
        }
        assert_eq!(
            open_outcome(Err("connection reset".into())),
            Err(PlaneError::Transport("connection reset".into()))
        );
    }

    #[test]
    fn a_close_is_accepted_only_for_the_conversation_asked_about() {
        let a = ConversationId::parse(A).unwrap();
        let closed = |id| Ok(WireOutcome::Payload(Payload::ConversationClosed(view(id))));
        assert_eq!(close_outcome(&a, closed(A)), Ok(view(A)));
        match close_outcome(&a, closed(B)) {
            Err(PlaneError::Transport(m)) => {
                assert!(
                    m.starts_with("protocol error: unexpected reply to session.close"),
                    "{m}"
                )
            }
            other => panic!("{other:?}"),
        }
        assert_eq!(
            close_outcome(&a, refused(maknae_proto::ProtoErrCode::Unauthorized)),
            Err(PlaneError::Refused)
        );
        assert_eq!(
            close_outcome(
                &a,
                Ok(WireOutcome::Payload(Payload::ConversationOpened(view(A))))
            ),
            Err(PlaneError::Transport(format!(
                "protocol error: unexpected reply to session.close: {:?}",
                WireOutcome::Payload(Payload::ConversationOpened(view(A)))
            )))
        );
    }
}
