//! `maknae board settings` and `maknae board clear`: which settings a change
//! sends, when a clear stops, and what the person is told.
use crate::tasking::text::{
    board_cleared_line, board_refused_line, board_settings_lines, board_stopped_line,
    board_unknown_line, safe, BoardCommand,
};
use crate::wire::WireOutcome;
use maknae_proto::{
    BoardCleared, BoardOp, BoardReport, BoardSettings, Payload, ProtoErrCode, Verb,
};
use std::future::Future;
use std::io::{BufRead, Read, Write};

pub const BOARD_CLEAR_REQUESTS_MAX: u32 = 64;
pub const CONFIRM_ANSWER_MAX_BYTES: u64 = 64;
const CONFIRM_PROMPT: &[u8] = b"clear every post on your board that is not held? [y/N] ";
const NOT_A_BOARD_REPLY: &str = "protocol error: the kernel's answer was not a board reply";
const HELD_OTHER: &str = "the kernel holds settings other than the ones asked for";

/// The settings a person named; `None` leaves that setting as it is.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct SettingsChange {
    pub enabled: Option<bool>,
    pub participate: Option<bool>,
    pub report: Option<BoardReport>,
}

impl SettingsChange {
    pub fn is_empty(&self) -> bool {
        self.enabled.is_none() && self.participate.is_none() && self.report.is_none()
    }

    pub fn is_whole(&self) -> bool {
        self.enabled.is_some() && self.participate.is_some() && self.report.is_some()
    }

    pub fn over(&self, current: BoardSettings) -> BoardSettings {
        BoardSettings {
            enabled: self.enabled.unwrap_or(current.enabled),
            participate: self.participate.unwrap_or(current.participate),
            report: self.report.unwrap_or(current.report),
        }
    }
}

/// What the caller prints and how it exits. `err` lines carry no `maknae: ` prefix.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Said {
    pub out: Vec<String>,
    pub err: Vec<String>,
    pub ok: bool,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Confirm {
    Go,
    Declined,
    NeedsYes,
}

/// `Unconfirmed`: no answer the request could be judged by, so a change may have landed.
enum Stop {
    Answered(String),
    Unconfirmed(String),
}

impl Stop {
    fn err(self, command: BoardCommand, sent_a_change: bool) -> Vec<String> {
        match self {
            Stop::Answered(line) => vec![line],
            Stop::Unconfirmed(line) if sent_a_change => {
                vec![line, board_unknown_line(command).into()]
            }
            Stop::Unconfirmed(line) => vec![line],
        }
    }
}

fn answer(sent: Result<WireOutcome, String>, command: BoardCommand) -> Result<Payload, Stop> {
    match sent {
        Ok(WireOutcome::Payload(payload)) => Ok(payload),
        Ok(WireOutcome::Refused { code, message, .. }) => {
            Err(Stop::Answered(refused_line(code, &message, command)))
        }
        Ok(WireOutcome::WriteDone { .. } | WireOutcome::ReadDone { .. }) => {
            Err(Stop::Unconfirmed(NOT_A_BOARD_REPLY.into()))
        }
        Err(error) => Err(Stop::Unconfirmed(one_line(&error))),
    }
}

fn refused_line(code: ProtoErrCode, message: &str, command: BoardCommand) -> String {
    match code {
        ProtoErrCode::BoardRefused(defect) => board_refused_line(defect, command),
        ProtoErrCode::Unauthorized => format!("you may not manage a board: {}", one_line(message)),
        _ => format!("the kernel refused the request: {}", one_line(message)),
    }
}

fn one_line(s: &str) -> String {
    safe(&s.replace(['\n', '\r'], " "))
}

fn settings_reply(sent: Result<WireOutcome, String>) -> Result<BoardSettings, Stop> {
    match answer(sent, BoardCommand::Settings)? {
        Payload::BoardSettings(settings) => Ok(settings),
        _ => Err(Stop::Unconfirmed(NOT_A_BOARD_REPLY.into())),
    }
}

fn cleared_reply(sent: Result<WireOutcome, String>) -> Result<BoardCleared, Stop> {
    match answer(sent, BoardCommand::Clear)? {
        Payload::BoardCleared(cleared) => Ok(cleared),
        _ => Err(Stop::Unconfirmed(NOT_A_BOARD_REPLY.into())),
    }
}

fn manage(op: BoardOp) -> Verb {
    Verb::BoardManage { op }
}

pub async fn settings<F, Fut>(change: SettingsChange, mut send: F) -> Said
where
    F: FnMut(Verb) -> Fut,
    Fut: Future<Output = Result<WireOutcome, String>>,
{
    let set = if change.is_empty() {
        None
    } else if change.is_whole() {
        Some(change.over(BoardSettings::default()))
    } else {
        match settings_reply(send(manage(BoardOp::Settings { set: None })).await) {
            Ok(current) => Some(change.over(current)),
            Err(stop) => {
                return Said {
                    out: vec![],
                    err: stop.err(BoardCommand::Settings, false),
                    ok: false,
                }
            }
        }
    };
    match settings_reply(send(manage(BoardOp::Settings { set })).await) {
        Ok(held) if set.is_some_and(|asked| asked != held) => Said {
            out: board_settings_lines(&held),
            err: vec![HELD_OTHER.into()],
            ok: false,
        },
        Ok(held) => Said {
            out: board_settings_lines(&held),
            err: vec![],
            ok: true,
        },
        Err(stop) => Said {
            out: vec![],
            err: stop.err(BoardCommand::Settings, set.is_some()),
            ok: false,
        },
    }
}

/// The caller has already confirmed.
pub async fn clear<F, Fut>(mut send: F) -> Said
where
    F: FnMut(Verb) -> Fut,
    Fut: Future<Output = Result<WireOutcome, String>>,
{
    let mut total: u64 = 0;
    let mut requests: u32 = 0;
    loop {
        requests += 1;
        let page = match cleared_reply(send(manage(BoardOp::Clear)).await) {
            Ok(page) => page,
            Err(stop) => {
                return Said {
                    out: if total > 0 {
                        vec![board_stopped_line(total)]
                    } else {
                        vec![]
                    },
                    err: stop.err(BoardCommand::Clear, true),
                    ok: false,
                }
            }
        };
        total = total.saturating_add(u64::from(page.removed));
        if !(page.more && page.removed > 0 && requests < BOARD_CLEAR_REQUESTS_MAX) {
            return Said {
                out: vec![board_cleared_line(total, page.more)],
                err: vec![],
                ok: true,
            };
        }
    }
}

/// Whether a clear may be sent; otherwise what is said and how the command exits.
pub fn clear_gate(confirmed: std::io::Result<Confirm>) -> Result<(), Said> {
    match confirmed {
        Ok(Confirm::Go) => Ok(()),
        Ok(Confirm::Declined) => Err(Said {
            out: vec!["nothing was cleared".into()],
            err: vec![],
            ok: true,
        }),
        Ok(Confirm::NeedsYes) => Err(Said {
            out: vec![],
            err: vec!["board clear needs --yes when not run on a terminal".into()],
            ok: false,
        }),
        Err(error) => Err(Said {
            out: vec![],
            err: vec![format!(
                "cannot ask for confirmation: {}",
                one_line(&error.to_string())
            )],
            ok: false,
        }),
    }
}

/// `yes` skips the question; off a terminal the question cannot be asked.
pub fn confirm(
    yes: bool,
    terminal: bool,
    answer: &mut dyn BufRead,
    prompt: &mut dyn Write,
) -> std::io::Result<Confirm> {
    if yes {
        return Ok(Confirm::Go);
    }
    if !terminal {
        return Ok(Confirm::NeedsYes);
    }
    prompt.write_all(CONFIRM_PROMPT)?;
    prompt.flush()?;
    let mut bytes = Vec::new();
    answer
        .take(CONFIRM_ANSWER_MAX_BYTES)
        .read_until(b'\n', &mut bytes)?;
    let Some(entered) = bytes.strip_suffix(b"\n") else {
        return Ok(Confirm::Declined);
    };
    let Ok(line) = std::str::from_utf8(entered) else {
        return Ok(Confirm::Declined);
    };
    let line = line.trim();
    Ok(
        if line.eq_ignore_ascii_case("y") || line.eq_ignore_ascii_case("yes") {
            Confirm::Go
        } else {
            Confirm::Declined
        },
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use maknae_proto::BoardDefect;
    use std::collections::VecDeque;
    use BoardReport::{Every, Off, Summary};

    const SETTINGS_UNKNOWN: &str =
        "the outcome is unknown; run maknae board settings to see what is in force";
    const CLEAR_UNKNOWN: &str = "the outcome is unknown; run maknae board clear again";
    const MORE: &str = "; more remain, run maknae board clear again";
    const HELD_OTHER: &str = "the kernel holds settings other than the ones asked for";

    fn s(enabled: bool, participate: bool, report: BoardReport) -> BoardSettings {
        BoardSettings {
            enabled,
            participate,
            report,
        }
    }

    fn read() -> Verb {
        Verb::BoardManage {
            op: BoardOp::Settings { set: None },
        }
    }

    fn write(set: BoardSettings) -> Verb {
        Verb::BoardManage {
            op: BoardOp::Settings { set: Some(set) },
        }
    }

    fn clear_verb() -> Verb {
        Verb::BoardManage { op: BoardOp::Clear }
    }

    fn settled(set: BoardSettings) -> Result<WireOutcome, String> {
        Ok(WireOutcome::Payload(Payload::BoardSettings(set)))
    }

    fn cleared(removed: u32, more: bool) -> Result<WireOutcome, String> {
        Ok(WireOutcome::Payload(Payload::BoardCleared(BoardCleared {
            removed,
            more,
        })))
    }

    fn refused(code: ProtoErrCode, message: &str) -> Result<WireOutcome, String> {
        Ok(WireOutcome::Refused {
            code,
            message: message.into(),
            armed: true,
        })
    }

    fn write_done() -> Result<WireOutcome, String> {
        Ok(WireOutcome::WriteDone {
            applied: true,
            stale: false,
            withheld: false,
            version: None,
        })
    }

    fn read_done() -> Result<WireOutcome, String> {
        Ok(WireOutcome::ReadDone { read: None })
    }

    fn change(
        enabled: Option<bool>,
        participate: Option<bool>,
        report: Option<BoardReport>,
    ) -> SettingsChange {
        SettingsChange {
            enabled,
            participate,
            report,
        }
    }

    fn lines(l: &[&str]) -> Vec<String> {
        l.iter().map(|s| (*s).to_owned()).collect()
    }

    fn said(out: &[&str], err: &[&str], ok: bool) -> Said {
        Said {
            out: lines(out),
            err: lines(err),
            ok,
        }
    }

    async fn run_settings(
        c: SettingsChange,
        replies: Vec<Result<WireOutcome, String>>,
    ) -> (Said, Vec<Verb>) {
        let mut replies: VecDeque<_> = replies.into();
        let mut sent = vec![];
        let said = settings(c, |v| {
            sent.push(v);
            let r = replies.pop_front().expect("script exhausted");
            async move { r }
        })
        .await;
        (said, sent)
    }

    async fn run_clear(replies: Vec<Result<WireOutcome, String>>) -> (Said, Vec<Verb>) {
        let mut replies: VecDeque<_> = replies.into();
        let mut sent = vec![];
        let said = clear(|v| {
            sent.push(v);
            let r = replies.pop_front().expect("script exhausted");
            async move { r }
        })
        .await;
        (said, sent)
    }

    const ALL: [BoardSettings; 12] = {
        const fn s(e: bool, p: bool, r: BoardReport) -> BoardSettings {
            BoardSettings {
                enabled: e,
                participate: p,
                report: r,
            }
        }
        [
            s(false, false, Off),
            s(false, false, Summary),
            s(false, false, Every),
            s(false, true, Off),
            s(false, true, Summary),
            s(false, true, Every),
            s(true, false, Off),
            s(true, false, Summary),
            s(true, false, Every),
            s(true, true, Off),
            s(true, true, Summary),
            s(true, true, Every),
        ]
    };

    #[test]
    fn over_changes_only_the_named_field() {
        for current in ALL {
            for v in [false, true] {
                assert_eq!(
                    change(Some(v), None, None).over(current),
                    BoardSettings {
                        enabled: v,
                        ..current
                    }
                );
                assert_eq!(
                    change(None, Some(v), None).over(current),
                    BoardSettings {
                        participate: v,
                        ..current
                    }
                );
            }
            for r in [Off, Summary, Every] {
                assert_eq!(
                    change(None, None, Some(r)).over(current),
                    BoardSettings {
                        report: r,
                        ..current
                    }
                );
            }
            assert_eq!(SettingsChange::default().over(current), current);
        }
        assert_eq!(
            change(Some(true), Some(false), Some(Every)).over(s(false, true, Off)),
            s(true, false, Every)
        );
    }

    #[test]
    fn is_empty_and_is_whole_truth_tables() {
        let e = Some(true);
        let p = Some(false);
        let r = Some(Summary);
        let table = [
            (change(None, None, None), true, false),
            (change(e, None, None), false, false),
            (change(None, p, None), false, false),
            (change(None, None, r), false, false),
            (change(e, p, None), false, false),
            (change(e, None, r), false, false),
            (change(None, p, r), false, false),
            (change(e, p, r), false, true),
        ];
        for (c, empty, whole) in table {
            assert_eq!(c.is_empty(), empty, "{c:?}");
            assert_eq!(c.is_whole(), whole, "{c:?}");
        }
    }

    #[tokio::test]
    async fn an_empty_change_reads_once_and_prints_the_reply() {
        let (said_, sent) = run_settings(
            SettingsChange::default(),
            vec![settled(s(true, false, Every))],
        )
        .await;
        assert_eq!(sent, vec![read()]);
        assert_eq!(
            said_,
            said(
                &["enabled      on", "participate  off", "report       every"],
                &[],
                true
            )
        );
    }

    #[tokio::test]
    async fn a_whole_change_writes_once_with_no_read() {
        let (said_, sent) = run_settings(
            change(Some(true), Some(true), Some(Summary)),
            vec![settled(s(true, true, Summary))],
        )
        .await;
        assert_eq!(sent, vec![write(s(true, true, Summary))]);
        assert_eq!(
            said_,
            said(
                &["enabled      on", "participate  on", "report       summary"],
                &[],
                true
            )
        );
        let (_, sent) = run_settings(
            change(Some(false), Some(false), Some(Off)),
            vec![settled(s(false, false, Off))],
        )
        .await;
        assert_eq!(sent, vec![write(s(false, false, Off))]);
    }

    #[tokio::test]
    async fn report_every_keeps_enabled_and_participate_as_read() {
        for (e, p) in [(false, false), (false, true), (true, false), (true, true)] {
            let (said_, sent) = run_settings(
                change(None, None, Some(Every)),
                vec![settled(s(e, p, Summary)), settled(s(e, p, Every))],
            )
            .await;
            assert_eq!(sent, vec![read(), write(s(e, p, Every))]);
            assert!(said_.ok);
            assert_eq!(said_.out[2], "report       every");
        }
    }

    #[tokio::test]
    async fn each_single_field_change_reads_then_writes_only_that_field() {
        let (_, sent) = run_settings(
            change(Some(true), None, None),
            vec![
                settled(s(false, true, Summary)),
                settled(s(true, true, Summary)),
            ],
        )
        .await;
        assert_eq!(sent, vec![read(), write(s(true, true, Summary))]);
        let (_, sent) = run_settings(
            change(None, Some(false), None),
            vec![
                settled(s(true, true, Every)),
                settled(s(true, false, Every)),
            ],
        )
        .await;
        assert_eq!(sent, vec![read(), write(s(true, false, Every))]);
        let (_, sent) = run_settings(
            change(Some(false), None, Some(Off)),
            vec![settled(s(true, true, Every)), settled(s(false, true, Off))],
        )
        .await;
        assert_eq!(sent, vec![read(), write(s(false, true, Off))]);
    }

    #[tokio::test]
    async fn a_write_whose_reply_differs_is_not_a_success() {
        let (said_, sent) = run_settings(
            change(Some(true), None, None),
            vec![settled(s(false, false, Off)), settled(s(false, false, Off))],
        )
        .await;
        assert_eq!(sent, vec![read(), write(s(true, false, Off))]);
        assert_eq!(
            said_,
            said(
                &["enabled      off", "participate  off", "report       off"],
                &[HELD_OTHER],
                false
            )
        );
        let (said_, sent) = run_settings(
            change(Some(true), Some(true), Some(Every)),
            vec![settled(s(true, true, Summary))],
        )
        .await;
        assert_eq!(sent, vec![write(s(true, true, Every))]);
        assert_eq!(
            said_,
            said(
                &["enabled      on", "participate  on", "report       summary"],
                &[HELD_OTHER],
                false
            )
        );
        let (said_, _) = run_settings(
            change(Some(true), Some(true), Some(Every)),
            vec![settled(s(true, true, Every))],
        )
        .await;
        assert_eq!(
            said_,
            said(
                &["enabled      on", "participate  on", "report       every"],
                &[],
                true
            )
        );
    }

    #[tokio::test]
    async fn the_lines_after_a_write_are_the_writes_reply() {
        let (said_, sent) = run_settings(
            change(Some(true), None, None),
            vec![
                settled(s(false, false, Off)),
                settled(s(false, true, Summary)),
            ],
        )
        .await;
        assert_eq!(sent, vec![read(), write(s(true, false, Off))]);
        assert_eq!(
            said_,
            said(
                &[
                    "enabled      off",
                    "participate  on",
                    "report       summary"
                ],
                &[HELD_OTHER],
                false
            )
        );
    }

    #[tokio::test]
    async fn a_refused_read_sends_no_write() {
        let (said_, sent) = run_settings(
            change(Some(true), None, None),
            vec![refused(
                ProtoErrCode::BoardRefused(BoardDefect::TryAgain),
                "try again",
            )],
        )
        .await;
        assert_eq!(sent, vec![read()]);
        assert_eq!(
            said_,
            said(&[], &["the board store did not do it; try again"], false)
        );
    }

    #[tokio::test]
    async fn an_unknown_write_prints_no_settings_and_the_unknown_sentence() {
        let (said_, sent) = run_settings(
            change(Some(true), None, None),
            vec![
                settled(s(false, false, Off)),
                refused(
                    ProtoErrCode::BoardRefused(BoardDefect::OutcomeUnknown),
                    "outcome unknown",
                ),
            ],
        )
        .await;
        assert_eq!(sent, vec![read(), write(s(true, false, Off))]);
        assert_eq!(said_, said(&[], &[SETTINGS_UNKNOWN], false));
    }

    #[tokio::test]
    async fn a_send_error_on_the_read_is_one_line_and_on_a_write_two() {
        let (said_, sent) = run_settings(
            change(Some(true), None, None),
            vec![Err("connection reset".into())],
        )
        .await;
        assert_eq!(sent, vec![read()]);
        assert_eq!(said_, said(&[], &["connection reset"], false));

        let (said_, sent) = run_settings(
            SettingsChange::default(),
            vec![Err("connection reset".into())],
        )
        .await;
        assert_eq!(sent, vec![read()]);
        assert_eq!(said_, said(&[], &["connection reset"], false));

        let (said_, sent) = run_settings(
            change(Some(true), None, None),
            vec![
                settled(s(false, false, Off)),
                Err("broken\u{1b}pipe".into()),
            ],
        )
        .await;
        assert_eq!(sent.len(), 2);
        assert_eq!(
            said_,
            said(&[], &["broken\\u{001b}pipe", SETTINGS_UNKNOWN], false)
        );

        let (said_, sent) = run_settings(
            change(Some(true), Some(true), Some(Every)),
            vec![Err("connection reset".into())],
        )
        .await;
        assert_eq!(sent, vec![write(s(true, true, Every))]);
        assert_eq!(
            said_,
            said(&[], &["connection reset", SETTINGS_UNKNOWN], false)
        );
    }

    #[tokio::test]
    async fn refusal_codes_map_to_their_sentences() {
        let (said_, _) = run_settings(
            SettingsChange::default(),
            vec![refused(ProtoErrCode::Unauthorized, "denied\u{1b}[2J")],
        )
        .await;
        assert_eq!(
            said_,
            said(
                &[],
                &["you may not manage a board: denied\\u{001b}[2J"],
                false
            )
        );
        let (said_, _) = run_settings(
            SettingsChange::default(),
            vec![refused(ProtoErrCode::Internal, "boom\u{7}")],
        )
        .await;
        assert_eq!(
            said_,
            said(
                &[],
                &["the kernel refused the request: boom\\u{0007}"],
                false
            )
        );
        let (said_, _) = run_settings(
            change(None, None, Some(Every)),
            vec![
                settled(s(false, false, Off)),
                refused(ProtoErrCode::BoardRefused(BoardDefect::Full), "board full"),
            ],
        )
        .await;
        assert_eq!(said_, said(&[], &["the kernel refused: board full"], false));
    }

    #[tokio::test]
    async fn kernel_and_transport_text_is_one_line() {
        let (said_, _) = run_settings(
            SettingsChange::default(),
            vec![refused(ProtoErrCode::Unauthorized, "x\nmaknae: done")],
        )
        .await;
        assert_eq!(
            said_,
            said(&[], &["you may not manage a board: x maknae: done"], false)
        );
        let (said_, _) = run_settings(
            SettingsChange::default(),
            vec![refused(ProtoErrCode::Internal, "x\r\nmaknae: done")],
        )
        .await;
        assert_eq!(
            said_,
            said(
                &[],
                &["the kernel refused the request: x  maknae: done"],
                false
            )
        );
        let (said_, _) = run_settings(
            SettingsChange::default(),
            vec![Err("reset\r\nmaknae: done\n".into())],
        )
        .await;
        assert_eq!(said_, said(&[], &["reset  maknae: done "], false));
        let (said_, _) = run_clear(vec![Err("reset\nmaknae: done".into())]).await;
        assert_eq!(
            said_,
            said(&[], &["reset maknae: done", CLEAR_UNKNOWN], false)
        );
    }

    #[tokio::test]
    async fn a_reply_that_is_not_board_settings_is_a_protocol_error() {
        for bad in [cleared(1, false), write_done(), read_done()] {
            let (said_, sent) = run_settings(SettingsChange::default(), vec![bad]).await;
            assert_eq!(sent.len(), 1);
            assert_eq!(said_, said(&[], &[NOT_A_BOARD_REPLY], false));
        }
        for bad in [cleared(1, false), write_done(), read_done()] {
            let (said_, sent) = run_settings(
                change(None, Some(true), None),
                vec![settled(s(false, false, Off)), bad],
            )
            .await;
            assert_eq!(sent.len(), 2);
            assert_eq!(
                said_,
                said(&[], &[NOT_A_BOARD_REPLY, SETTINGS_UNKNOWN], false)
            );
        }
        for bad in [cleared(1, false), write_done(), read_done()] {
            let (said_, sent) =
                run_settings(change(Some(true), Some(true), Some(Every)), vec![bad]).await;
            assert_eq!(sent, vec![write(s(true, true, Every))]);
            assert_eq!(
                said_,
                said(&[], &[NOT_A_BOARD_REPLY, SETTINGS_UNKNOWN], false)
            );
        }
        let (said_, sent) =
            run_settings(change(None, Some(true), None), vec![cleared(0, false)]).await;
        assert_eq!(sent, vec![read()]);
        assert_eq!(said_, said(&[], &[NOT_A_BOARD_REPLY], false));
    }

    #[tokio::test]
    async fn clear_adds_pages_until_none_remain() {
        let (said_, sent) = run_clear(vec![
            cleared(32, true),
            cleared(32, true),
            cleared(5, false),
        ])
        .await;
        assert_eq!(sent, vec![clear_verb(); 3]);
        assert_eq!(said_, said(&["cleared 69 posts"], &[], true));
    }

    #[tokio::test]
    async fn an_empty_board_has_no_posts_to_clear() {
        let (said_, sent) = run_clear(vec![cleared(0, false)]).await;
        assert_eq!(sent, vec![clear_verb()]);
        assert_eq!(said_, said(&["the board has no posts to clear"], &[], true));
        let (said_, _) = run_clear(vec![cleared(1, false)]).await;
        assert_eq!(said_, said(&["cleared 1 post"], &[], true));
    }

    #[tokio::test]
    async fn a_page_of_held_posts_stops_after_one_request_and_says_more_remain() {
        let (said_, sent) = run_clear(vec![cleared(0, true)]).await;
        assert_eq!(sent, vec![clear_verb()]);
        assert_eq!(
            said_,
            said(&[&format!("cleared no posts{MORE}")], &[], true)
        );
        let (said_, sent) = run_clear(vec![cleared(5, true), cleared(0, true)]).await;
        assert_eq!(sent, vec![clear_verb(); 2]);
        assert_eq!(said_, said(&[&format!("cleared 5 posts{MORE}")], &[], true));
    }

    #[tokio::test]
    async fn clear_stops_at_the_request_cap() {
        let (said_, sent) = run_clear((0..64).map(|_| cleared(1, true)).collect::<Vec<_>>()).await;
        assert_eq!(sent.len(), 64);
        assert_eq!(
            said_,
            said(&[&format!("cleared 64 posts{MORE}")], &[], true)
        );
        let mut last_page_ends = (0..63).map(|_| cleared(1, true)).collect::<Vec<_>>();
        last_page_ends.push(cleared(1, false));
        let (said_, sent) = run_clear(last_page_ends).await;
        assert_eq!(sent.len(), 64);
        assert_eq!(said_, said(&["cleared 64 posts"], &[], true));
    }

    #[tokio::test]
    async fn absurd_counts_saturate_without_a_panic() {
        let (said_, sent) =
            run_clear((0..64).map(|_| cleared(u32::MAX, true)).collect::<Vec<_>>()).await;
        assert_eq!(sent.len(), 64);
        assert_eq!(
            said_,
            said(
                &["cleared 274877906880 posts; more remain, run maknae board clear again"],
                &[],
                true
            )
        );
    }

    #[tokio::test]
    async fn a_refusal_after_some_pages_reports_what_was_cleared() {
        let (said_, sent) = run_clear(vec![
            cleared(32, true),
            refused(
                ProtoErrCode::BoardRefused(BoardDefect::TryAgain),
                "try again",
            ),
        ])
        .await;
        assert_eq!(sent, vec![clear_verb(); 2]);
        assert_eq!(
            said_,
            said(
                &["cleared 32 posts before stopping"],
                &["the clear stopped; run maknae board clear again"],
                false
            )
        );
    }

    #[tokio::test]
    async fn a_send_error_during_a_clear_is_the_error_and_the_unknown_sentence() {
        let (said_, sent) = run_clear(vec![cleared(1, true), Err("connection reset".into())]).await;
        assert_eq!(sent.len(), 2);
        assert_eq!(
            said_,
            said(
                &["cleared 1 post before stopping"],
                &["connection reset", CLEAR_UNKNOWN],
                false
            )
        );
        let (said_, _) = run_clear(vec![Err("connection\u{1b}reset".into())]).await;
        assert_eq!(
            said_,
            said(&[], &["connection\\u{001b}reset", CLEAR_UNKNOWN], false)
        );
    }

    #[tokio::test]
    async fn a_first_clear_refusal_prints_nothing_on_stdout() {
        let (said_, sent) = run_clear(vec![refused(
            ProtoErrCode::BoardRefused(BoardDefect::OutcomeUnknown),
            "outcome unknown",
        )])
        .await;
        assert_eq!(sent.len(), 1);
        assert_eq!(said_, said(&[], &[CLEAR_UNKNOWN], false));
        let (said_, _) = run_clear(vec![refused(ProtoErrCode::Unauthorized, "no")]).await;
        assert_eq!(said_, said(&[], &["you may not manage a board: no"], false));
        let (said_, _) = run_clear(vec![refused(ProtoErrCode::TooLarge, "big")]).await;
        assert_eq!(
            said_,
            said(&[], &["the kernel refused the request: big"], false)
        );
    }

    #[tokio::test]
    async fn a_clear_reply_that_is_not_board_cleared_is_a_protocol_error() {
        for bad in [settled(s(true, true, Every)), write_done(), read_done()] {
            let (said_, sent) = run_clear(vec![bad]).await;
            assert_eq!(sent.len(), 1);
            assert_eq!(said_, said(&[], &[NOT_A_BOARD_REPLY, CLEAR_UNKNOWN], false));
        }
        let (said_, sent) = run_clear(vec![cleared(2, true), write_done()]).await;
        assert_eq!(sent.len(), 2);
        assert_eq!(
            said_,
            said(
                &["cleared 2 posts before stopping"],
                &[NOT_A_BOARD_REPLY, CLEAR_UNKNOWN],
                false
            )
        );
    }

    struct NoRead;
    impl Read for NoRead {
        fn read(&mut self, _: &mut [u8]) -> std::io::Result<usize> {
            panic!("the answer was read")
        }
    }
    impl BufRead for NoRead {
        fn fill_buf(&mut self) -> std::io::Result<&[u8]> {
            panic!("the answer was read")
        }
        fn consume(&mut self, _: usize) {}
    }

    struct BrokenRead;
    impl Read for BrokenRead {
        fn read(&mut self, _: &mut [u8]) -> std::io::Result<usize> {
            Err(std::io::Error::other("read broke"))
        }
    }
    impl BufRead for BrokenRead {
        fn fill_buf(&mut self) -> std::io::Result<&[u8]> {
            Err(std::io::Error::other("read broke"))
        }
        fn consume(&mut self, _: usize) {}
    }

    struct BrokenWrite {
        write_fails: bool,
    }
    impl Write for BrokenWrite {
        fn write(&mut self, b: &[u8]) -> std::io::Result<usize> {
            if self.write_fails {
                Err(std::io::Error::other("write broke"))
            } else {
                Ok(b.len())
            }
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Err(std::io::Error::other("flush broke"))
        }
    }

    fn ask(answer: &[u8]) -> (Confirm, Vec<u8>) {
        let mut prompt = vec![];
        let got = confirm(false, true, &mut &answer[..], &mut prompt).unwrap();
        (got, prompt)
    }

    #[test]
    fn yes_goes_without_prompting() {
        let mut prompt = vec![];
        assert_eq!(
            confirm(true, true, &mut NoRead, &mut prompt).unwrap(),
            Confirm::Go
        );
        assert_eq!(
            confirm(true, false, &mut NoRead, &mut prompt).unwrap(),
            Confirm::Go
        );
        assert!(prompt.is_empty());
    }

    #[test]
    fn off_a_terminal_it_needs_yes_and_asks_nothing() {
        let mut prompt = vec![];
        assert_eq!(
            confirm(false, false, &mut NoRead, &mut prompt).unwrap(),
            Confirm::NeedsYes
        );
        assert!(prompt.is_empty());
    }

    #[test]
    fn y_and_yes_in_any_case_go() {
        for a in [
            &b"y\n"[..],
            b"Y\n",
            b"yes\n",
            b" YES \n",
            b"yEs\n",
            b"YES\r\n",
        ] {
            let (got, prompt) = ask(a);
            assert_eq!(got, Confirm::Go, "{a:?}");
            assert_eq!(
                prompt,
                b"clear every post on your board that is not held? [y/N] "
            );
        }
    }

    #[test]
    fn anything_else_declines() {
        for a in [
            &b"n\n"[..],
            b"\n",
            b"yy\n",
            b"",
            b"no\n",
            b"yes please\n",
            b"y",
            b"yes",
            b"Y",
        ] {
            assert_eq!(ask(a).0, Confirm::Declined, "{a:?}");
        }
        assert_eq!(ask(&[b'y'; 65]).0, Confirm::Declined);
        let mut long = vec![b' '; 64];
        long.extend_from_slice(b"y\n");
        assert_eq!(ask(&long).0, Confirm::Declined);
        let mut fits = vec![b' '; 62];
        fits.extend_from_slice(b"y\n");
        assert_eq!(fits.len(), 64);
        assert_eq!(ask(&fits).0, Confirm::Go);
    }

    #[test]
    fn an_answer_that_is_not_text_declines() {
        let mut cut_in_a_character = vec![b' '; 63];
        cut_in_a_character.extend_from_slice("é\n".as_bytes());
        assert_eq!(ask(&cut_in_a_character).0, Confirm::Declined);
        assert_eq!(ask(b"\xff\n").0, Confirm::Declined);
        assert_eq!(ask(b"y\xff\n").0, Confirm::Declined);
        assert_eq!(ask(b"y\n").0, Confirm::Go);
        assert_eq!(ask(b"YES\r\n").0, Confirm::Go);
        let mut whole = b"yes".to_vec();
        whole.extend_from_slice(&[b' '; 60]);
        whole.push(b'\n');
        assert_eq!(ask(&whole).0, Confirm::Go);
    }

    #[test]
    fn an_answer_cut_at_the_bound_declines() {
        let mut y_then_n = b"y".to_vec();
        y_then_n.extend_from_slice(&[b' '; 70]);
        y_then_n.extend_from_slice(b"n\n");
        assert_eq!(ask(&y_then_n).0, Confirm::Declined);
        let mut yes_please = b"yes".to_vec();
        yes_please.extend_from_slice(&[b' '; 61]);
        yes_please.extend_from_slice(b"please\n");
        assert_eq!(ask(&yes_please).0, Confirm::Declined);
        let mut cut_before_newline = vec![b' '; 63];
        cut_before_newline.extend_from_slice(b"y\n");
        assert_eq!(ask(&cut_before_newline).0, Confirm::Declined);
        let mut whole = b"y".to_vec();
        whole.extend_from_slice(&[b' '; 62]);
        whole.push(b'\n');
        assert_eq!(whole.len(), 64);
        assert_eq!(ask(&whole).0, Confirm::Go);
    }

    #[test]
    fn a_broken_prompt_or_answer_is_an_error() {
        let err = confirm(
            false,
            true,
            &mut NoRead,
            &mut BrokenWrite { write_fails: true },
        )
        .unwrap_err();
        assert_eq!(err.to_string(), "write broke");
        let err = confirm(
            false,
            true,
            &mut NoRead,
            &mut BrokenWrite { write_fails: false },
        )
        .unwrap_err();
        assert_eq!(err.to_string(), "flush broke");
        let err = confirm(false, true, &mut BrokenRead, &mut Vec::new()).unwrap_err();
        assert_eq!(err.to_string(), "read broke");
    }

    #[test]
    fn the_clear_gate_says_what_each_answer_means() {
        assert_eq!(clear_gate(Ok(Confirm::Go)), Ok(()));
        assert_eq!(
            clear_gate(Ok(Confirm::Declined)),
            Err(said(&["nothing was cleared"], &[], true))
        );
        assert_eq!(
            clear_gate(Ok(Confirm::NeedsYes)),
            Err(said(
                &[],
                &["board clear needs --yes when not run on a terminal"],
                false
            ))
        );
        assert_eq!(
            clear_gate(Err(std::io::Error::other("input\u{7}gone\nmaknae: done"))),
            Err(said(
                &[],
                &["cannot ask for confirmation: input\\u{0007}gone maknae: done"],
                false
            ))
        );
    }
}
