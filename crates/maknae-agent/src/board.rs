//! `maknae board`, `maknae board settings` and `maknae board clear`: which pages a
//! listing asks for, which settings a change sends, when a clear stops, and what the
//! person is told.
use crate::tasking::text::{
    board_attachment_line, board_cleared_line, board_entry_header, board_list_stopped_line,
    board_refused_line, board_settings_lines, board_stopped_line, board_unknown_line, one_line,
    write_board_text, BoardCommand, BOARD_NO_POSTS, BOARD_OLDER,
};
use crate::wire::WireOutcome;
use maknae_proto::{
    BoardCleared, BoardEntry, BoardListing, BoardOp, BoardReport, BoardSettings, Payload,
    ProtoErrCode, Verb,
};
use std::future::Future;
use std::io::{BufRead, Read, Write};

pub const BOARD_CLEAR_REQUESTS_MAX: u32 = 64;
pub const BOARD_LIST_REQUESTS_MAX: u32 = 64;
pub const BOARD_LIST_LAST_MAX: u16 = 1024;
pub const CONFIRM_ANSWER_MAX_BYTES: u64 = 64;
const CONFIRM_PROMPT: &[u8] = b"clear every post on your board that is not held? [y/N] ";
const NOT_A_BOARD_REPLY: &str = "protocol error: the kernel's answer was not a board reply";
const HELD_OTHER: &str = "the kernel holds settings other than the ones asked for";
const NOT_MOVED_BACK: &str = "protocol error: the kernel's listing did not move back";

/// How much of the board a listing asks for.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ListWant {
    Latest,
    Last(u16),
    All,
}

/// The posts listed, oldest first; `older`: posts older than these remain.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Listed {
    pub entries: Vec<BoardEntry>,
    pub older: bool,
}

/// The settings a person named; `None` leaves that setting as it is.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct SettingsChange {
    pub enabled: Option<bool>,
    pub report: Option<BoardReport>,
}

impl SettingsChange {
    pub fn is_empty(&self) -> bool {
        self.enabled.is_none() && self.report.is_none()
    }

    pub fn is_whole(&self) -> bool {
        self.enabled.is_some() && self.report.is_some()
    }

    pub fn over(&self, current: BoardSettings) -> BoardSettings {
        BoardSettings {
            enabled: self.enabled.unwrap_or(current.enabled),
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
        ProtoErrCode::Unauthorized => match command {
            BoardCommand::List => format!("you may not read your board: {}", one_line(message)),
            BoardCommand::Settings | BoardCommand::Clear => {
                format!("you may not manage a board: {}", one_line(message))
            }
        },
        _ => format!("the kernel refused the request: {}", one_line(message)),
    }
}

fn listing_reply(sent: Result<WireOutcome, String>) -> Result<BoardListing, Stop> {
    match answer(sent, BoardCommand::List)? {
        Payload::BoardListing(listing) => Ok(listing),
        _ => Err(Stop::Unconfirmed(NOT_A_BOARD_REPLY.into())),
    }
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

/// Walks back from the newest page; the `Said`, when there is one, is why the walk stopped.
pub async fn list<F, Fut>(want: ListWant, mut send: F) -> (Listed, Option<Said>)
where
    F: FnMut(Verb) -> Fut,
    Fut: Future<Output = Result<WireOutcome, String>>,
{
    let mut pages: Vec<Vec<BoardEntry>> = vec![];
    let mut collected: usize = 0;
    let mut before = None;
    let mut older = None;
    let mut requests: u32 = 0;
    let stop = loop {
        requests += 1;
        let page = match listing_reply(send(Verb::BoardList { before }).await) {
            Ok(page) => page,
            Err(stop) => break Some(stop.err(BoardCommand::List, false)),
        };
        let ascending = page.entries.windows(2).all(|w| w[0].seq < w[1].seq);
        let below = before.is_none_or(|sent| {
            page.entries.iter().all(|e| e.seq < sent) && page.older.is_none_or(|n| n < sent)
        });
        if !(ascending && below) {
            break Some(vec![NOT_MOVED_BACK.into()]);
        }
        collected += page.entries.len();
        pages.push(page.entries);
        older = page.older;
        let enough = match want {
            ListWant::Latest => collected > 0,
            ListWant::Last(n) => collected >= usize::from(n),
            ListWant::All => false,
        };
        if older.is_none() || enough {
            break None;
        }
        if requests >= BOARD_LIST_REQUESTS_MAX {
            break Some(vec![board_list_stopped_line(collected as u64)]);
        }
        before = older;
    };
    let mut entries: Vec<BoardEntry> = pages.into_iter().rev().flatten().collect();
    let dropped = match want {
        ListWant::Last(n) => entries.len().saturating_sub(usize::from(n)),
        ListWant::Latest | ListWant::All => 0,
    };
    entries.drain(..dropped);
    (
        Listed {
            entries,
            older: older.is_some() || dropped > 0,
        },
        stop.map(|err| Said {
            out: vec![],
            err,
            ok: false,
        }),
    )
}

/// What follows the posts: why the walk stopped; otherwise `no posts` or the hint that older
/// posts remain.
pub fn listing_said(want: ListWant, listed: &Listed, stop: Option<Said>) -> Said {
    let mut said = stop.unwrap_or(Said {
        out: vec![],
        err: vec![],
        ok: true,
    });
    if !said.ok {
        return said;
    }
    if listed.older && want != ListWant::All {
        said.out.push(BOARD_OLDER.into());
    } else if listed.entries.is_empty() {
        said.out.push(BOARD_NO_POSTS.into());
    }
    said
}

/// Each post's header, its body line by line, then its attachments; a body and an
/// attachment's content are written straight from the reply, never copied.
pub fn print_listing(
    listed: &Listed,
    attachments: bool,
    out: &mut dyn Write,
) -> std::io::Result<()> {
    for e in &listed.entries {
        let reply_seq = e.post.draft.in_reply_to.and_then(|id| {
            listed
                .entries
                .iter()
                .find(|t| t.post.id == id)
                .map(|t| t.seq)
        });
        writeln!(out, "{}", board_entry_header(e, reply_seq))?;
        write_board_text(out, "    ", &e.post.draft.body.0)?;
        for a in &e.post.draft.attachments {
            writeln!(out, "{}", board_attachment_line(a))?;
            if attachments {
                write_board_text(out, "      ", &a.content.0)?;
            }
        }
    }
    Ok(())
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
    use maknae_proto::{
        Addressee, Attachment, Author, BoardDefect, BoardHold, Labels, Media, Post, PostDraft,
        PostId, PostKind, SecretText, TaskId,
    };
    use std::collections::VecDeque;
    use BoardReport::{Every, Off, Summary};

    const SETTINGS_UNKNOWN: &str =
        "the outcome is unknown; run maknae board settings to see what is in force";
    const CLEAR_UNKNOWN: &str = "the outcome is unknown; run maknae board clear again";
    const MORE: &str = "; more remain, run maknae board clear again";
    const HELD_OTHER: &str = "the kernel holds settings other than the ones asked for";

    fn s(enabled: bool, report: BoardReport) -> BoardSettings {
        BoardSettings { enabled, report }
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

    fn change(enabled: Option<bool>, report: Option<BoardReport>) -> SettingsChange {
        SettingsChange { enabled, report }
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

    const ALL: [BoardSettings; 6] = {
        const fn s(e: bool, r: BoardReport) -> BoardSettings {
            BoardSettings {
                enabled: e,
                report: r,
            }
        }
        [
            s(false, Off),
            s(false, Summary),
            s(false, Every),
            s(true, Off),
            s(true, Summary),
            s(true, Every),
        ]
    };

    #[test]
    fn over_changes_only_the_named_field() {
        for current in ALL {
            for v in [false, true] {
                assert_eq!(
                    change(Some(v), None).over(current),
                    BoardSettings {
                        enabled: v,
                        ..current
                    }
                );
            }
            for r in [Off, Summary, Every] {
                assert_eq!(
                    change(None, Some(r)).over(current),
                    BoardSettings {
                        report: r,
                        ..current
                    }
                );
            }
            assert_eq!(SettingsChange::default().over(current), current);
        }
        assert_eq!(
            change(Some(true), Some(Every)).over(s(false, Off)),
            s(true, Every)
        );
    }

    #[test]
    fn is_empty_and_is_whole_truth_tables() {
        let e = Some(true);
        let r = Some(Summary);
        let table = [
            (change(None, None), true, false),
            (change(e, None), false, false),
            (change(None, r), false, false),
            (change(e, r), false, true),
        ];
        for (c, empty, whole) in table {
            assert_eq!(c.is_empty(), empty, "{c:?}");
            assert_eq!(c.is_whole(), whole, "{c:?}");
        }
    }

    #[tokio::test]
    async fn an_empty_change_reads_once_and_prints_the_reply() {
        let (said_, sent) =
            run_settings(SettingsChange::default(), vec![settled(s(true, Every))]).await;
        assert_eq!(sent, vec![read()]);
        assert_eq!(
            said_,
            said(&["enabled      on", "report       every"], &[], true)
        );
    }

    #[tokio::test]
    async fn a_whole_change_writes_once_with_no_read() {
        let (said_, sent) = run_settings(
            change(Some(true), Some(Summary)),
            vec![settled(s(true, Summary))],
        )
        .await;
        assert_eq!(sent, vec![write(s(true, Summary))]);
        assert_eq!(
            said_,
            said(&["enabled      on", "report       summary"], &[], true)
        );
        let (_, sent) =
            run_settings(change(Some(false), Some(Off)), vec![settled(s(false, Off))]).await;
        assert_eq!(sent, vec![write(s(false, Off))]);
    }

    #[tokio::test]
    async fn report_every_keeps_enabled_as_read() {
        for e in [false, true] {
            let (said_, sent) = run_settings(
                change(None, Some(Every)),
                vec![settled(s(e, Summary)), settled(s(e, Every))],
            )
            .await;
            assert_eq!(sent, vec![read(), write(s(e, Every))]);
            assert!(said_.ok);
            assert_eq!(said_.out[1], "report       every");
        }
    }

    #[tokio::test]
    async fn each_single_field_change_reads_then_writes_only_that_field() {
        let (_, sent) = run_settings(
            change(Some(true), None),
            vec![settled(s(false, Summary)), settled(s(true, Summary))],
        )
        .await;
        assert_eq!(sent, vec![read(), write(s(true, Summary))]);
        let (_, sent) = run_settings(
            change(None, Some(Off)),
            vec![settled(s(true, Every)), settled(s(true, Off))],
        )
        .await;
        assert_eq!(sent, vec![read(), write(s(true, Off))]);
    }

    #[tokio::test]
    async fn a_write_whose_reply_differs_is_not_a_success() {
        let (said_, sent) = run_settings(
            change(Some(true), None),
            vec![settled(s(false, Off)), settled(s(false, Off))],
        )
        .await;
        assert_eq!(sent, vec![read(), write(s(true, Off))]);
        assert_eq!(
            said_,
            said(
                &["enabled      off", "report       off"],
                &[HELD_OTHER],
                false
            )
        );
        let (said_, sent) = run_settings(
            change(Some(true), Some(Every)),
            vec![settled(s(true, Summary))],
        )
        .await;
        assert_eq!(sent, vec![write(s(true, Every))]);
        assert_eq!(
            said_,
            said(
                &["enabled      on", "report       summary"],
                &[HELD_OTHER],
                false
            )
        );
        let (said_, _) = run_settings(
            change(Some(true), Some(Every)),
            vec![settled(s(true, Every))],
        )
        .await;
        assert_eq!(
            said_,
            said(&["enabled      on", "report       every"], &[], true)
        );
    }

    #[tokio::test]
    async fn the_lines_after_a_write_are_the_writes_reply() {
        let (said_, sent) = run_settings(
            change(Some(true), None),
            vec![settled(s(false, Off)), settled(s(false, Summary))],
        )
        .await;
        assert_eq!(sent, vec![read(), write(s(true, Off))]);
        assert_eq!(
            said_,
            said(
                &["enabled      off", "report       summary"],
                &[HELD_OTHER],
                false
            )
        );
    }

    #[tokio::test]
    async fn a_refused_read_sends_no_write() {
        let (said_, sent) = run_settings(
            change(Some(true), None),
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
            change(Some(true), None),
            vec![
                settled(s(false, Off)),
                refused(
                    ProtoErrCode::BoardRefused(BoardDefect::OutcomeUnknown),
                    "outcome unknown",
                ),
            ],
        )
        .await;
        assert_eq!(sent, vec![read(), write(s(true, Off))]);
        assert_eq!(said_, said(&[], &[SETTINGS_UNKNOWN], false));
    }

    #[tokio::test]
    async fn a_send_error_on_the_read_is_one_line_and_on_a_write_two() {
        let (said_, sent) = run_settings(
            change(Some(true), None),
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
            change(Some(true), None),
            vec![settled(s(false, Off)), Err("broken\u{1b}pipe".into())],
        )
        .await;
        assert_eq!(sent.len(), 2);
        assert_eq!(
            said_,
            said(&[], &["broken\\u{001b}pipe", SETTINGS_UNKNOWN], false)
        );

        let (said_, sent) = run_settings(
            change(Some(true), Some(Every)),
            vec![Err("connection reset".into())],
        )
        .await;
        assert_eq!(sent, vec![write(s(true, Every))]);
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
            change(None, Some(Every)),
            vec![
                settled(s(false, Off)),
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
            let (said_, sent) =
                run_settings(change(Some(true), None), vec![settled(s(false, Off)), bad]).await;
            assert_eq!(sent.len(), 2);
            assert_eq!(
                said_,
                said(&[], &[NOT_A_BOARD_REPLY, SETTINGS_UNKNOWN], false)
            );
        }
        for bad in [cleared(1, false), write_done(), read_done()] {
            let (said_, sent) = run_settings(change(Some(true), Some(Every)), vec![bad]).await;
            assert_eq!(sent, vec![write(s(true, Every))]);
            assert_eq!(
                said_,
                said(&[], &[NOT_A_BOARD_REPLY, SETTINGS_UNKNOWN], false)
            );
        }
        let (said_, sent) = run_settings(change(Some(true), None), vec![cleared(0, false)]).await;
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
        for bad in [settled(s(true, Every)), write_done(), read_done()] {
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

    const CONTAINED: &str = "subject contained: role=adversary";
    const NOT_READ: &str = "the board could not be read; try again";
    const OLDER: &str = "older posts remain; run maknae board --all to see them";
    const NOT_MOVED: &str = "protocol error: the kernel's listing did not move back";

    fn secret(s: &str) -> SecretText {
        SecretText(zeroize::Zeroizing::new(s.into()))
    }

    fn entry(seq: u64) -> BoardEntry {
        BoardEntry {
            seq,
            post: Post {
                id: PostId([u8::try_from(seq % 256).unwrap(); 16]),
                author: Author::Agent("hobi".into()),
                task: None,
                at_secs: 1_795_654_923,
                labels: Labels {},
                draft: PostDraft {
                    kind: PostKind::Note,
                    to: Addressee::Board,
                    in_reply_to: None,
                    body: secret(&format!("post {seq}")),
                    attachments: vec![],
                },
            },
            held: vec![],
        }
    }

    fn page(seqs: &[u64], older: Option<u64>) -> Result<WireOutcome, String> {
        Ok(WireOutcome::Payload(Payload::BoardListing(BoardListing {
            entries: seqs.iter().copied().map(entry).collect(),
            older,
        })))
    }

    fn at(before: Option<u64>) -> Verb {
        Verb::BoardList { before }
    }

    fn seqs(listed: &Listed) -> Vec<u64> {
        listed.entries.iter().map(|e| e.seq).collect()
    }

    async fn run_list(
        want: ListWant,
        replies: Vec<Result<WireOutcome, String>>,
    ) -> (Listed, Option<Said>, Vec<Verb>) {
        let mut replies: VecDeque<_> = replies.into();
        let mut sent = vec![];
        let (listed, stop) = list(want, |v| {
            sent.push(v);
            let r = replies.pop_front().expect("script exhausted");
            async move { r }
        })
        .await;
        (listed, stop, sent)
    }

    fn printed(listed: &Listed, attachments: bool) -> String {
        let mut out = vec![];
        print_listing(listed, attachments, &mut out).unwrap();
        String::from_utf8(out).unwrap()
    }

    fn listed(entries: Vec<BoardEntry>) -> Listed {
        Listed {
            entries,
            older: false,
        }
    }

    #[tokio::test]
    async fn latest_sends_one_request_from_the_top() {
        let (l, stop, sent) = run_list(ListWant::Latest, vec![page(&[1, 2], None)]).await;
        assert_eq!(sent, vec![at(None)]);
        assert_eq!((seqs(&l), l.older, stop), (vec![1, 2], false, None));
        let (l, stop, sent) = run_list(ListWant::Latest, vec![page(&[7, 9], Some(7))]).await;
        assert_eq!(sent, vec![at(None)]);
        assert_eq!((seqs(&l), l.older, stop), (vec![7, 9], true, None));
    }

    #[tokio::test]
    async fn latest_walks_past_an_empty_page_with_older() {
        let (l, stop, sent) = run_list(
            ListWant::Latest,
            vec![
                page(&[], Some(40)),
                page(&[], Some(8)),
                page(&[5, 6], Some(5)),
            ],
        )
        .await;
        assert_eq!(sent, vec![at(None), at(Some(40)), at(Some(8))]);
        assert_eq!((seqs(&l), l.older, stop), (vec![5, 6], true, None));
        let (l, stop, sent) =
            run_list(ListWant::Latest, vec![page(&[], Some(40)), page(&[], None)]).await;
        assert_eq!(sent, vec![at(None), at(Some(40))]);
        assert_eq!((seqs(&l), l.older, stop), (vec![], false, None));
    }

    #[tokio::test]
    async fn last_n_collects_pages_and_keeps_the_newest_n() {
        let (l, stop, sent) = run_list(
            ListWant::Last(3),
            vec![page(&[10, 11], Some(10)), page(&[8, 9], Some(8))],
        )
        .await;
        assert_eq!(sent, vec![at(None), at(Some(10))]);
        assert_eq!((seqs(&l), l.older, stop), (vec![9, 10, 11], true, None));
        let (l, stop, sent) = run_list(
            ListWant::Last(4),
            vec![page(&[10, 11], Some(10)), page(&[8, 9], None)],
        )
        .await;
        assert_eq!(sent.len(), 2);
        assert_eq!((seqs(&l), l.older, stop), (vec![8, 9, 10, 11], false, None));
        let (l, stop, sent) = run_list(
            ListWant::Last(5),
            vec![page(&[10, 11], Some(10)), page(&[8, 9], None)],
        )
        .await;
        assert_eq!(sent.len(), 2);
        assert_eq!((seqs(&l), l.older, stop), (vec![8, 9, 10, 11], false, None));
        let (l, _, sent) = run_list(ListWant::Last(2), vec![page(&[10, 11], Some(10))]).await;
        assert_eq!(sent.len(), 1);
        assert_eq!((seqs(&l), l.older), (vec![10, 11], true));
        let (l, _, _) = run_list(ListWant::Last(1), vec![page(&[10, 11], None)]).await;
        assert_eq!((seqs(&l), l.older), (vec![11], true));
    }

    #[tokio::test]
    async fn all_walks_to_the_start_and_prints_oldest_first() {
        let (l, stop, sent) = run_list(
            ListWant::All,
            vec![
                page(&[5, 6], Some(5)),
                page(&[], Some(3)),
                page(&[1, 2], None),
            ],
        )
        .await;
        assert_eq!(sent, vec![at(None), at(Some(5)), at(Some(3))]);
        assert_eq!(
            (seqs(&l), l.older, stop.clone()),
            (vec![1, 2, 5, 6], false, None)
        );
        let text = printed(&l, false);
        let headers: Vec<&str> = text.lines().filter(|l| l.starts_with('#')).collect();
        assert_eq!(headers.len(), 4);
        for (h, seq) in headers.iter().zip([1, 2, 5, 6]) {
            assert!(h.starts_with(&format!("#{seq}  ")), "{h}");
        }
        assert_eq!(listing_said(ListWant::All, &l, stop), said(&[], &[], true));
    }

    #[tokio::test]
    async fn a_walk_stops_after_64_requests_and_says_so() {
        let pages = (0..64)
            .map(|i| page(&[1000 - i], Some(1000 - i)))
            .collect::<Vec<_>>();
        let (l, stop, sent) = run_list(ListWant::All, pages).await;
        assert_eq!(sent.len(), 64);
        assert_eq!(sent[1], at(Some(1000)));
        assert_eq!(seqs(&l), (937..=1000).collect::<Vec<_>>());
        assert!(l.older);
        let stopped = "stopped after 64 requests and 64 posts; older posts remain";
        assert_eq!(stop, Some(said(&[], &[stopped], false)));
        assert_eq!(
            listing_said(ListWant::All, &l, stop),
            said(&[], &[stopped], false)
        );

        let mut pages = (0..63)
            .map(|i| page(&[1000 - i], Some(1000 - i)))
            .collect::<Vec<_>>();
        pages.push(page(&[1], None));
        let (l, stop, sent) = run_list(ListWant::All, pages).await;
        assert_eq!(
            (sent.len(), l.entries.len(), l.older, stop),
            (64, 64, false, None)
        );

        let empty = (0..64)
            .map(|i| page(&[], Some(1000 - i)))
            .collect::<Vec<_>>();
        let (l, stop, sent) = run_list(ListWant::Latest, empty).await;
        assert_eq!(sent.len(), 64);
        assert!(l.entries.is_empty());
        assert_eq!(
            stop,
            Some(said(
                &[],
                &["stopped after 64 requests and 0 posts; older posts remain"],
                false
            ))
        );
    }

    #[tokio::test]
    async fn a_page_that_does_not_move_back_stops_the_walk() {
        for stuck in [5, 6] {
            let (l, stop, sent) = run_list(
                ListWant::All,
                vec![page(&[5], Some(5)), page(&[4], Some(stuck))],
            )
            .await;
            assert_eq!(sent, vec![at(None), at(Some(5))]);
            assert_eq!(seqs(&l), vec![5]);
            assert!(l.older);
            assert_eq!(stop, Some(said(&[], &[NOT_MOVED], false)));
        }
        let (l, stop, _) = run_list(
            ListWant::All,
            vec![page(&[5], Some(5)), page(&[4], Some(4)), page(&[], None)],
        )
        .await;
        assert_eq!((seqs(&l), stop), (vec![4, 5], None));
    }

    fn strictly_ascending(l: &Listed) -> bool {
        l.entries.windows(2).all(|w| w[0].seq < w[1].seq)
    }

    #[tokio::test]
    async fn a_page_that_repeats_a_printed_post_stops_the_walk() {
        let (l, stop, sent) = run_list(
            ListWant::All,
            vec![page(&[5, 6], Some(5)), page(&[4, 5], Some(4))],
        )
        .await;
        assert_eq!(sent, vec![at(None), at(Some(5))]);
        assert_eq!(seqs(&l), vec![5, 6]);
        assert!(strictly_ascending(&l));
        assert_eq!(stop, Some(said(&[], &[NOT_MOVED], false)));
    }

    #[tokio::test]
    async fn a_page_with_an_entry_at_or_above_before_stops_the_walk() {
        for bad in [&[5][..], &[9], &[2, 7]] {
            let (l, stop, _) = run_list(
                ListWant::All,
                vec![page(&[5, 6], Some(5)), page(bad, Some(1))],
            )
            .await;
            assert_eq!(seqs(&l), vec![5, 6], "{bad:?}");
            assert_eq!(stop, Some(said(&[], &[NOT_MOVED], false)), "{bad:?}");
        }
        let (l, stop, _) = run_list(
            ListWant::All,
            vec![page(&[5, 6], Some(5)), page(&[4], None)],
        )
        .await;
        assert_eq!((seqs(&l), stop), (vec![4, 5, 6], None));
    }

    #[tokio::test]
    async fn a_page_out_of_order_stops_the_walk() {
        let (l, stop, _) = run_list(ListWant::All, vec![page(&[6, 5], None)]).await;
        assert!(l.entries.is_empty());
        assert_eq!(stop, Some(said(&[], &[NOT_MOVED], false)));
        let (l, stop, _) = run_list(ListWant::All, vec![page(&[5, 5], None)]).await;
        assert!(l.entries.is_empty());
        assert_eq!(stop, Some(said(&[], &[NOT_MOVED], false)));
        let (l, stop, _) = run_list(
            ListWant::All,
            vec![page(&[5, 6], Some(5)), page(&[3, 2], Some(1))],
        )
        .await;
        assert_eq!(
            (seqs(&l), stop),
            (vec![5, 6], Some(said(&[], &[NOT_MOVED], false)))
        );
        let (l, stop, _) = run_list(ListWant::All, vec![page(&[900, 1000], None)]).await;
        assert_eq!((seqs(&l), stop), (vec![900, 1000], None));
    }

    #[tokio::test]
    async fn a_stopped_walk_gives_no_all_hint() {
        let empty = (0..64)
            .map(|i| page(&[], Some(1000 - i)))
            .collect::<Vec<_>>();
        let (l, stop, _) = run_list(ListWant::Latest, empty).await;
        assert!(l.older);
        assert_eq!(
            listing_said(ListWant::Latest, &l, stop),
            said(
                &[],
                &["stopped after 64 requests and 0 posts; older posts remain"],
                false
            )
        );
        let (l, stop, _) = run_list(
            ListWant::Last(5),
            vec![
                page(&[5, 6], Some(5)),
                refused(ProtoErrCode::Unauthorized, CONTAINED),
            ],
        )
        .await;
        assert!(l.older);
        assert_eq!(
            listing_said(ListWant::Last(5), &l, stop),
            said(
                &[],
                &["you may not read your board: subject contained: role=adversary"],
                false
            )
        );
        let (l, stop, _) = run_list(ListWant::Latest, vec![page(&[7], Some(7))]).await;
        assert_eq!(
            listing_said(ListWant::Latest, &l, stop),
            said(&[OLDER], &[], true)
        );
    }

    #[tokio::test]
    async fn a_refused_listing_says_so_and_exits_one() {
        let (l, stop, sent) = run_list(
            ListWant::Latest,
            vec![refused(ProtoErrCode::Unauthorized, CONTAINED)],
        )
        .await;
        assert_eq!(sent, vec![at(None)]);
        assert!(l.entries.is_empty());
        let want = said(
            &[],
            &["you may not read your board: subject contained: role=adversary"],
            false,
        );
        assert_eq!(stop, Some(want.clone()));
        assert_eq!(listing_said(ListWant::Latest, &l, stop), want);
        for defect in [BoardDefect::TryAgain, BoardDefect::OutcomeUnknown] {
            let (_, stop, _) = run_list(
                ListWant::Latest,
                vec![refused(ProtoErrCode::BoardRefused(defect), "x")],
            )
            .await;
            assert_eq!(stop, Some(said(&[], &[NOT_READ], false)));
        }
        let (l, stop, _) = run_list(
            ListWant::All,
            vec![page(&[5, 6], Some(5)), Err("connection\u{1b}reset".into())],
        )
        .await;
        assert_eq!(seqs(&l), vec![5, 6]);
        assert_eq!(stop, Some(said(&[], &["connection\\u{001b}reset"], false)));
        for bad in [
            cleared(1, false),
            settled(s(true, Every)),
            write_done(),
            read_done(),
        ] {
            let (_, stop, _) = run_list(ListWant::Latest, vec![bad]).await;
            assert_eq!(stop, Some(said(&[], &[NOT_A_BOARD_REPLY], false)));
        }
    }

    #[tokio::test]
    async fn settings_and_clear_refusals_still_say_manage() {
        let (said_, _) = run_settings(
            SettingsChange::default(),
            vec![refused(ProtoErrCode::Unauthorized, CONTAINED)],
        )
        .await;
        assert_eq!(
            said_,
            said(
                &[],
                &["you may not manage a board: subject contained: role=adversary"],
                false
            )
        );
        let (said_, _) = run_clear(vec![refused(ProtoErrCode::Unauthorized, CONTAINED)]).await;
        assert_eq!(
            said_,
            said(
                &[],
                &["you may not manage a board: subject contained: role=adversary"],
                false
            )
        );
    }

    #[test]
    fn a_hostile_post_prints_escaped_line_by_line() {
        let mut e = entry(3);
        e.post.draft.body = secret("a\u{1b}[2J\rb\nc\td\u{0}\n\u{1b}]0;x\u{7}");
        e.post.draft.attachments = vec![Attachment {
            label: "log".into(),
            media: Media::TextPlain,
            content: secret("p\u{1b}q\r\nr\ts\u{0}"),
        }];
        let text = printed(&listed(vec![e]), true);
        for b in [0x1b, 0x0d, 0x00, 0x09, 0x07] {
            assert!(!text.as_bytes().contains(&b), "{b:#x} in {text:?}");
        }
        assert_eq!(
            text.lines().skip(1).collect::<Vec<_>>(),
            [
                "    a\\u{001b}[2J\\u{000d}b",
                "    c\\u{0009}d\\u{0000}",
                "    \\u{001b}]0;x\\u{0007}",
                "  attachment log  text/plain  9 bytes",
                "      p\\u{001b}q\\u{000d}",
                "      r\\u{0009}s\\u{0000}",
            ]
        );
    }

    #[test]
    fn attachments_print_contents_only_when_asked() {
        let mut e = entry(4);
        e.post.draft.attachments = vec![
            Attachment {
                label: "a.diff".into(),
                media: Media::TextDiff,
                content: secret("-x\n+y"),
            },
            Attachment {
                label: "b.md".into(),
                media: Media::TextMarkdown,
                content: secret("# b"),
            },
        ];
        let l = listed(vec![e]);
        assert_eq!(
            printed(&l, false),
            "#4  2026-11-26T01:02:03.000Z  hobi  to board  note\n    post 4\n  attachment a.diff  text/x-diff  5 bytes\n  attachment b.md  text/markdown  3 bytes\n"
        );
        assert_eq!(
            printed(&l, true),
            "#4  2026-11-26T01:02:03.000Z  hobi  to board  note\n    post 4\n  attachment a.diff  text/x-diff  5 bytes\n      -x\n      +y\n  attachment b.md  text/markdown  3 bytes\n      # b\n"
        );
    }

    #[test]
    fn a_board_prints_as_the_person_reads_it() {
        let plain = entry(5);
        let mut reply = entry(6);
        reply.post.author = Author::Agent("jin".into());
        reply.post.task = Some(TaskId([0xab; 16]));
        reply.post.draft.kind = PostKind::Answer;
        reply.post.draft.to = Addressee::Agents(vec!["hobi".into()]);
        reply.post.draft.in_reply_to = Some(plain.post.id);
        reply.post.draft.body = secret("yes\nsee the diff");
        reply.post.draft.attachments = vec![Attachment {
            label: "fix.diff".into(),
            media: Media::TextDiff,
            content: secret("-a\n+b"),
        }];
        let mut held = entry(7);
        held.post.author = Author::Agent("suga".into());
        held.post.draft.kind = PostKind::Question;
        held.post.draft.in_reply_to = Some(PostId([0x02; 16]));
        held.held = vec![BoardHold::Author, BoardHold::Person];
        let mut hostile = entry(8);
        hostile.post.author = Author::Agent("ev\u{1b}il\nx".into());
        hostile.post.draft.body = secret("\u{1b}[2Jgone\r\nmaknae: done\u{202e}");
        let l = listed(vec![plain, reply, held, hostile]);
        let task = "ab".repeat(16);
        let target = "02".repeat(16);
        assert_eq!(
            printed(&l, true),
            format!(
                "#5  2026-11-26T01:02:03.000Z  hobi  to board  note\n    post 5\n\
                 #6  2026-11-26T01:02:03.000Z  jin  to agents: hobi  answer  task {task}  reply to #5\n    yes\n    see the diff\n  attachment fix.diff  text/x-diff  5 bytes\n      -a\n      +b\n\
                 #7  2026-11-26T01:02:03.000Z  suga  to board  question  reply to {target}  HELD (author contained)  HELD (you were contained)\n    post 7\n\
                 #8  2026-11-26T01:02:03.000Z  ev\\u{{001b}}il x  to board  note\n    \\u{{001b}}[2Jgone\\u{{000d}}\n    maknae: done\\u{{202e}}\n"
            )
        );
    }

    #[test]
    fn an_empty_board_prints_no_posts() {
        let l = listed(vec![]);
        assert_eq!(printed(&l, true), "");
        for want in [ListWant::Latest, ListWant::Last(3), ListWant::All] {
            assert_eq!(listing_said(want, &l, None), said(&["no posts"], &[], true));
        }
    }

    #[test]
    fn a_reply_without_a_link_prints_no_reply_to() {
        let target = entry(5);
        let mut reply = entry(6);
        reply.post.draft.in_reply_to = None;
        let text = printed(&listed(vec![target.clone(), reply.clone()]), false);
        assert!(!text.contains("reply to"), "{text}");
        reply.post.draft.in_reply_to = Some(target.post.id);
        let text = printed(&listed(vec![target.clone(), reply.clone()]), false);
        assert!(text.contains("note  reply to #5\n"), "{text}");
        let text = printed(&listed(vec![reply]), false);
        assert!(
            text.contains(&format!("note  reply to {}\n", "05".repeat(16))),
            "{text}"
        );
    }

    #[test]
    fn older_names_all_when_not_asked_for() {
        let mut l = listed(vec![entry(5)]);
        l.older = true;
        for want in [ListWant::Latest, ListWant::Last(1)] {
            assert_eq!(listing_said(want, &l, None), said(&[OLDER], &[], true));
        }
        assert_eq!(listing_said(ListWant::All, &l, None), said(&[], &[], true));
        let stop = said(&[], &["x"], false);
        assert_eq!(
            listing_said(ListWant::Latest, &l, Some(stop.clone())),
            said(&[], &["x"], false)
        );
        assert_eq!(
            listing_said(ListWant::All, &l, Some(stop)),
            said(&[], &["x"], false)
        );
        l.older = false;
        assert_eq!(
            listing_said(ListWant::Latest, &l, None),
            said(&[], &[], true)
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
