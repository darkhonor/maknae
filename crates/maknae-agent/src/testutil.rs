//! Test-only helpers shared across the crate's module test suites.
use crate::wire::WireOutcome;
use maknae_proto::Payload;

/// Every refusal and failure a listing or stat can come back as, armed or not.
pub(crate) fn every_refusal_after_a_list_or_stat() -> Vec<Result<WireOutcome, String>> {
    use maknae_proto::ProtoErrCode;
    let mut sent = vec![];
    for armed in [true, false] {
        for (code, message) in [
            (ProtoErrCode::Unauthorized, "not authorized"),
            (ProtoErrCode::Unauthorized, "read descriptor missing"),
            (ProtoErrCode::Unauthorized, "stat descriptor missing"),
            (
                ProtoErrCode::Unauthorized,
                "denied by policy entry Read(~/denied/**)",
            ),
            (ProtoErrCode::Unauthorized, "sensitive: host ~/.ssh/**"),
            (ProtoErrCode::Unauthorized, "sensitive: personal ~/keys/**"),
            (
                ProtoErrCode::Unauthorized,
                "ceiling: TOP SECRET is not a level of the US system",
            ),
            (
                ProtoErrCode::Unauthorized,
                "listing reached 65536 names without a page; 3 permitted, 65533 withheld",
            ),
            (ProtoErrCode::Unauthorized, "listing order violated"),
            (
                ProtoErrCode::Unauthorized,
                "the subject reports it could not list the directory (unverified)",
            ),
            (
                ProtoErrCode::Unauthorized,
                "answer exceeds the response frame",
            ),
            (
                ProtoErrCode::BadRequest,
                "list fails operand pre-gate: cursor not acceptable",
            ),
            (ProtoErrCode::TooLarge, "frame too large"),
            (ProtoErrCode::Internal, "internal"),
            (ProtoErrCode::EgressUnavailable, "at capacity"),
            (ProtoErrCode::Protected, "not a protected message"),
        ] {
            sent.push(Ok(WireOutcome::Refused {
                code,
                message: message.into(),
                armed,
            }));
        }
    }
    sent.push(Err("list not performed: enumeration timed out".into()));
    sent.push(Err(
        "TLS handshake to the daemon timed out after 5000ms".into()
    ));
    sent.push(Ok(WireOutcome::ReadDone { read: None }));
    sent.push(Ok(WireOutcome::WriteDone {
        applied: true,
        stale: false,
        withheld: false,
        version: None,
    }));
    sent.push(Ok(WireOutcome::Payload(Payload::ListContinue)));
    sent
}
