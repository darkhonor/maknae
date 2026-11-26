use crate::hints::{Reason, Subject, Unbound};
use crate::render::display_piece;
use crate::render::DISPLAY_PIECE_MAX;
use crate::screen::MenuItem;
use maknae_proto::{
    Addressee, AgentEntry, AgentStanding, Attachment, Author, Binding, BoardDefect, BoardEntry,
    BoardHold, BoardReport, BoardSettings, EmptyReason, ForgeOp, ForgeOps, Media, ReachSummary,
    TaskClose, TaskState,
};

pub const NO_AGENTS: &str = "no agents can be tasked by you";
pub const LIST_INCOMPLETE: &str = "the list may be incomplete; try again";
pub const HELD: &str = "on hold: its tasker or the agent was contained; an administrator can release it with maknae held release";
pub const CONNECTING: &str = "connecting";
pub const CONNECTED: &str = "connected";
pub const UNREACHABLE: &str = "kernel unreachable, retrying";
pub const UNREADABLE: &str = "kernel answer unreadable, retrying";
pub const NO_IDENTITY: &str = "cannot get a plane identity, retrying";
pub const CLOCK: &str = "the system clock reads before 1970; set the clock";
pub const MORE_NOTICES: &str = "more notices were not shown";
pub const LOGIN_STOPPED: &str = "not sent: your Vault login expired";
pub const LOGIN_ENDED: &str = "login expired";
pub const AWAY: &str = "while you were away";
pub const UNKNOWN_COMMAND: &str = "unknown command; /help lists them";
pub const CONVERSATION_FULL: &str =
    "unread reports fill the conversation: scroll down to read them, then send this again";

const COMMANDS: [(&str, &str); 7] = [
    ("/add", "[n] <text>: add to task n, or the newest open task"),
    ("/stop", "[n]: stop task n, or the newest open task"),
    ("/drop", "[n]: drop task n, or the newest open task"),
    ("/status", "[n]: one task in full, or every open task"),
    ("/list", "every task you have with this agent"),
    ("/bye", "leave; tasks keep running and their reports wait"),
    ("/help", "the commands and keys"),
];

const KEYS: [&str; 6] = [
    "Enter sends; Ctrl-J starts a new line; plain text starts a new task",
    "Up/Down and the wheel scroll a line, PgUp/PgDn a page, Home/End the top and bottom",
    "Ctrl-A/E start and end, Ctrl-B/F and Alt-B/F move, Ctrl-U/K/W kill",
    "Ctrl-P/Ctrl-N recall this session's earlier requests",
    "Ctrl-C clears the line; twice on an empty line leaves",
    "Ctrl-D on an empty line leaves; Ctrl-Z suspends",
];

/// What a close notice says; the agent's text is never read for it.
pub fn close_line(close: TaskClose) -> &'static str {
    match close {
        TaskClose::Stopped => "stopped at your request",
        TaskClose::Dropped => "dropped",
        TaskClose::AgentGone => "the agent was removed",
        TaskClose::AgentLost => "the agent stopped responding",
        TaskClose::Withdrawn => "your authority to task this agent was withdrawn",
        TaskClose::ParentEnded => "the task that asked for it ended",
    }
}

pub fn held_line() -> &'static str {
    HELD
}

pub fn state_word(state: TaskState) -> &'static str {
    match state {
        TaskState::Queued => "queued",
        TaskState::Working => "working",
        TaskState::Held => "held",
        TaskState::Reported => "reported",
        TaskState::Closed => "closed",
    }
}

/// A request whose answer was a refusal or never came back once it was sent.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Unknown {
    Submit,
    Add(u32),
    Stop(u32),
    Drop(u32),
    Collect,
}

pub fn outcome_unknown_line(op: Unknown) -> String {
    match op {
        Unknown::Submit => {
            "your request was refused or its outcome is unknown; it was not sent again, and the kernel is asked what it holds".into()
        }
        Unknown::Add(n) => format!(
            "adding to #{n} was refused or its outcome is unknown; it was not sent again, and the kernel is asked again"
        ),
        Unknown::Stop(n) => format!(
            "stopping #{n} was refused or its outcome is unknown; the kernel is asked again"
        ),
        Unknown::Drop(n) => format!(
            "dropping #{n} was refused or its outcome is unknown; the kernel is asked again"
        ),
        Unknown::Collect => {
            "collecting reports was refused or its outcome is unknown; reports already shown may be shown again".into()
        }
    }
}

pub fn not_answered_yet(n: usize) -> String {
    match n {
        1 => "1 request is not yet sent or answered: /bye or Ctrl-D again leaves without it".into(),
        n => format!(
            "{n} requests are not yet sent or answered: /bye or Ctrl-D again leaves without them"
        ),
    }
}

pub fn not_sent(n: usize, agent: &str) -> String {
    match n {
        1 => format!("1 request was not sent; it was not given to {agent}"),
        n => format!("{n} requests were not sent; they were not given to {agent}"),
    }
}

pub fn not_taken(n: usize) -> String {
    match n {
        1 => "1 request was refused, not sent, or of unknown outcome".into(),
        n => format!("{n} requests were refused, not sent, or of unknown outcome"),
    }
}

/// `m:ss`, or `h:mm:ss` from an hour.
pub fn elapsed(secs: u64) -> String {
    let (h, m, s) = (secs / 3600, secs / 60 % 60, secs % 60);
    if h > 0 {
        format!("{h}:{m:02}:{s:02}")
    } else {
        format!("{m}:{s:02}")
    }
}

/// `s` with every character a terminal would act on made visible.
pub fn safe(s: &str) -> String {
    let mut buf = [0; DISPLAY_PIECE_MAX];
    s.chars()
        .map(|c| display_piece(c, &mut buf).to_owned())
        .collect()
}

/// `s` on one line: a line break or carriage return becomes a space, then [`safe`].
pub fn one_line(s: &str) -> String {
    safe(&s.replace(['\n', '\r'], " "))
}

/// One `maknae agent list` line per entry, then the incomplete-list line.
pub fn agent_list_lines(entries: &[AgentEntry], undecided: u32) -> Vec<String> {
    let mut lines: Vec<String> = entries
        .iter()
        .map(|e| {
            let mut line = safe(&e.agent);
            if e.board {
                line.push_str("  board on");
            }
            let standing = match e.standing {
                AgentStanding::Enrolled => None,
                AgentStanding::Removed => Some("removed"),
                AgentStanding::Contained => Some("on hold: contained"),
                AgentStanding::Withdrawn => Some("you can no longer task this agent"),
                AgentStanding::Undecided => Some("could not be checked right now"),
            };
            if let Some(standing) = standing {
                line.push_str(&format!("  ({standing})"));
            }
            match e.waiting {
                0 => {}
                1 => line.push_str("  1 report waiting"),
                n => line.push_str(&format!("  {n} reports waiting")),
            }
            line
        })
        .collect();
    if undecided > 0 {
        lines.push(LIST_INCOMPLETE.into());
    } else if lines.is_empty() {
        lines.push(NO_AGENTS.into());
    }
    lines
}

pub fn board_settings_lines(s: &BoardSettings) -> Vec<String> {
    let on_off = |on: bool| if on { "on" } else { "off" };
    let report = match s.report {
        BoardReport::Off => "off",
        BoardReport::Summary => "summary",
        BoardReport::Every => "every",
    };
    vec![
        format!("enabled      {}", on_off(s.enabled)),
        format!("report       {report}"),
    ]
}

fn posts(n: u64) -> String {
    match n {
        1 => "1 post".into(),
        n => format!("{n} posts"),
    }
}

pub fn board_cleared_line(removed: u64, more: bool) -> String {
    match (removed, more) {
        (0, false) => "the board has no posts to clear".into(),
        (n, false) => format!("cleared {}", posts(n)),
        (0, true) => "cleared no posts; more remain, run maknae board clear again".into(),
        (n, true) => format!(
            "cleared {}; more remain, run maknae board clear again",
            posts(n)
        ),
    }
}

pub fn board_stopped_line(removed: u64) -> String {
    format!("cleared {} before stopping", posts(removed))
}

pub const BOARD_NO_POSTS: &str = "no posts";
pub const BOARD_OLDER: &str = "older posts remain; run maknae board --all to see them";
const BOARD_LIST_NOT_READ: &str = "the board could not be read; try again";

pub fn board_list_stopped_line(listed: u64) -> String {
    format!(
        "stopped after {} requests and {}; older posts remain",
        crate::board::BOARD_LIST_REQUESTS_MAX,
        posts(listed)
    )
}

/// One line: no body text, and every field the kernel sent through [`one_line`].
/// `reply_seq` is the sequence of the post `in_reply_to` names, when it is among those fetched.
pub fn board_entry_header(e: &BoardEntry, reply_seq: Option<u64>) -> String {
    let maknae_proto::Labels {} = &e.post.labels;
    let Author::Agent(author) = &e.post.author;
    let to = match &e.post.draft.to {
        Addressee::Board => "board".to_owned(),
        Addressee::Agents(ids) => format!(
            "agents: {}",
            ids.iter()
                .map(|id| one_line(id))
                .collect::<Vec<_>>()
                .join(", ")
        ),
    };
    let at = maknae_proto::epoch_to_rfc3339(u64::try_from(e.post.at_secs).unwrap_or(0), 0);
    let mut line = format!(
        "#{}  {at}  {}  to {to}  {}",
        e.seq,
        one_line(author),
        one_line(e.post.draft.kind.as_str())
    );
    if let Some(task) = e.post.task {
        line.push_str(&format!("  task {}", one_line(&task.to_string())));
    }
    match (e.post.draft.in_reply_to, reply_seq) {
        (Some(_), Some(seq)) => line.push_str(&format!("  reply to #{seq}")),
        (Some(id), None) => line.push_str(&format!("  reply to {}", one_line(&id.to_string()))),
        (None, _) => {}
    }
    for hold in &e.held {
        line.push_str(match hold {
            BoardHold::Author => "  HELD (author contained)",
            BoardHold::Person => "  HELD (you were contained)",
        });
    }
    line
}

/// The attachment's label, media and size; never its content.
pub fn board_attachment_line(a: &Attachment) -> String {
    let media = match a.media {
        Media::TextPlain => "text/plain",
        Media::TextMarkdown => "text/markdown",
        Media::TextDiff => "text/x-diff",
    };
    format!(
        "  attachment {}  {media}  {} bytes",
        one_line(&a.label),
        a.content.0.len()
    )
}

/// `text` one line per `\n`-separated piece, each after `indent` and escaped by
/// [`display_piece`] character by character, so no copy of `text` is made.
pub fn write_board_text(
    out: &mut dyn std::io::Write,
    indent: &str,
    text: &str,
) -> std::io::Result<()> {
    let mut buf = [0; DISPLAY_PIECE_MAX];
    for piece in text.split('\n') {
        out.write_all(indent.as_bytes())?;
        for c in piece.chars() {
            out.write_all(display_piece(c, &mut buf).as_bytes())?;
        }
        out.write_all(b"\n")?;
    }
    Ok(())
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BoardCommand {
    List,
    Settings,
    Clear,
}

pub fn board_unknown_line(command: BoardCommand) -> &'static str {
    match command {
        BoardCommand::List => BOARD_LIST_NOT_READ,
        BoardCommand::Settings => {
            "the outcome is unknown; run maknae board settings to see what is in force"
        }
        BoardCommand::Clear => "the outcome is unknown; run maknae board clear again",
    }
}

pub fn board_refused_line(defect: BoardDefect, command: BoardCommand) -> String {
    match defect {
        BoardDefect::TryAgain => match command {
            BoardCommand::List => BOARD_LIST_NOT_READ.into(),
            BoardCommand::Settings => "the board store did not do it; try again".into(),
            BoardCommand::Clear => "the clear stopped; run maknae board clear again".into(),
        },
        BoardDefect::OutcomeUnknown => board_unknown_line(command).into(),
        BoardDefect::Full | BoardDefect::AuthorAtCap | BoardDefect::NoSuchPost => format!(
            "the kernel refused: {}",
            maknae_proto::board_refused_message(defect)
        ),
    }
}

pub fn not_an_agent(name: &str) -> String {
    format!(
        "maknae: {} is not an agent you can task; see maknae agent list",
        safe(name)
    )
}

pub fn undecided_agent(name: &str) -> String {
    format!(
        "maknae: the kernel could not decide whether you can task {}; try again",
        safe(name)
    )
}

pub const LIST_INCOMPLETE_REFUSAL: &str =
    "maknae: could not check every agent right now; try again";

pub fn binding_name(binding: &Binding) -> String {
    let Binding::Git(g) = binding;
    ref_name(&g.server, &g.base, g.change)
}

fn ref_name(server: &str, base: &str, change: Option<u64>) -> String {
    let mut name = safe(&format!("{server}/{base}"));
    if let Some(n) = change {
        name.push_str(&format!(" change {n}"));
    }
    name
}

fn unbound_reason(reason: Reason) -> String {
    match reason {
        Reason::UnknownServer => "unknown server".into(),
        Reason::NotHttps => "not https".into(),
        Reason::AmbiguousShorthand => "ambiguous shorthand: more than one forge is known".into(),
        Reason::AmbiguousForge => "ambiguous forge: the host matches more than one forge".into(),
        Reason::OverTheBound => format!(
            "over the bound of {} bindings or {} bytes",
            maknae_proto::TASK_BINDINGS_MAX,
            maknae_proto::TASK_BINDING_REQUESTS_MAX_BYTES
        ),
        Reason::NotInParent => "not in the parent task".into(),
        Reason::NoForgeList => "no forge list".into(),
        Reason::AmbiguousGitlabPath => "ambiguous GitLab path".into(),
        Reason::NotListed => format!(
            "notes past the first {} are not listed",
            crate::hints::NOTES_MAX
        ),
    }
}

fn unbound_line(u: &Unbound) -> String {
    let subject = match &u.subject {
        Subject::Host(s) => safe(s),
        Subject::Written(w) => safe(w.as_str()),
        Subject::Ref(g) => ref_name(&g.server, &g.base, g.change),
        Subject::More(k) => format!("{k} more candidates"),
    };
    format!("not bound: {subject}: {}", unbound_reason(u.reason))
}

fn op_word(op: ForgeOp) -> &'static str {
    match op {
        ForgeOp::Read => "read",
        ForgeOp::Review => "review",
        ForgeOp::IssueWrite => "write issues",
        ForgeOp::PushHead => "push",
        ForgeOp::Merge => "merge",
    }
}

fn ops_words(ops: ForgeOps) -> String {
    let words: Vec<&str> = ForgeOp::ALL
        .into_iter()
        .filter(|op| ops.contains(*op))
        .map(op_word)
        .collect();
    if words.is_empty() {
        "none".into()
    } else {
        words.join(", ")
    }
}

fn empty_reason(why: EmptyReason) -> &'static str {
    match why {
        EmptyReason::HeadGone => "the change's head repository is gone",
        EmptyReason::AgentNotCovered => "the agent's credential does not cover it",
        EmptyReason::NoForgeCredential => "no forge credential observed it",
        EmptyReason::NoReachCheck => "this forge has no reach check",
    }
}

fn reach_text(reach: ReachSummary) -> String {
    let mut text = format!("reach: {}", ops_words(reach.base()));
    if !reach.head().is_empty() {
        text.push_str(&format!("; head: {}", ops_words(reach.head())));
    }
    if let Some(why) = reach.why() {
        text.push_str(&format!(" ({})", empty_reason(why)));
    }
    text
}

/// One line per binding the kernel sealed, with its effective reach when the view carries one
/// per binding, then one per candidate not bound and why.
pub fn echo_lines(
    bindings: &[Binding],
    reach: &[ReachSummary],
    unbound: &[Unbound],
) -> Vec<String> {
    let aligned = reach.len() == bindings.len();
    bindings
        .iter()
        .enumerate()
        .map(|(i, b)| match reach.get(i).filter(|_| aligned) {
            Some(r) => format!("bound: {}; {}", binding_name(b), reach_text(*r)),
            None => format!("bound: {}", binding_name(b)),
        })
        .chain(unbound.iter().map(unbound_line))
        .collect()
}

pub fn menu(prefix: &str) -> Vec<MenuItem> {
    COMMANDS
        .iter()
        .filter(|(name, _)| name.starts_with(prefix))
        .map(|(name, help)| MenuItem {
            name: (*name).into(),
            help: (*help).into(),
        })
        .collect()
}

pub fn help_lines() -> Vec<String> {
    COMMANDS
        .iter()
        .map(|(name, help)| format!("{name} {help}"))
        .chain(KEYS.iter().map(|k| (*k).to_string()))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn board_settings_print_enabled_and_report_only() {
        assert_eq!(
            board_settings_lines(&BoardSettings::default()),
            ["enabled      off", "report       off"]
        );
    }

    #[test]
    fn board_settings_print_one_padded_line_each() {
        let lines = |enabled, report| board_settings_lines(&BoardSettings { enabled, report });
        assert_eq!(
            lines(false, BoardReport::Off),
            ["enabled      off", "report       off"]
        );
        assert_eq!(
            lines(true, BoardReport::Summary),
            ["enabled      on", "report       summary"]
        );
        assert_eq!(
            lines(false, BoardReport::Every),
            ["enabled      off", "report       every"]
        );
    }

    #[test]
    fn board_cleared_line_counts_and_says_when_more_remain() {
        let more = "; more remain, run maknae board clear again";
        assert_eq!(
            board_cleared_line(0, false),
            "the board has no posts to clear"
        );
        assert_eq!(board_cleared_line(1, false), "cleared 1 post");
        assert_eq!(board_cleared_line(2, false), "cleared 2 posts");
        assert_eq!(
            board_cleared_line(0, true),
            format!("cleared no posts{more}")
        );
        assert_eq!(board_cleared_line(1, true), format!("cleared 1 post{more}"));
        assert_eq!(
            board_cleared_line(69, true),
            format!("cleared 69 posts{more}")
        );
        assert_eq!(
            board_cleared_line(u64::MAX, false),
            "cleared 18446744073709551615 posts"
        );
    }

    #[test]
    fn board_stopped_line_counts() {
        assert_eq!(board_stopped_line(1), "cleared 1 post before stopping");
        assert_eq!(board_stopped_line(2), "cleared 2 posts before stopping");
    }

    #[test]
    fn board_refusals_name_the_defect_and_the_command() {
        use BoardCommand::{Clear, Settings};
        use BoardDefect::*;
        assert_eq!(
            board_refused_line(TryAgain, Settings),
            "the board store did not do it; try again"
        );
        assert_eq!(
            board_refused_line(TryAgain, Clear),
            "the clear stopped; run maknae board clear again"
        );
        for command in [Settings, Clear] {
            assert_eq!(
                board_refused_line(Full, command),
                "the kernel refused: board full"
            );
            assert_eq!(
                board_refused_line(AuthorAtCap, command),
                "the kernel refused: author at cap"
            );
            assert_eq!(
                board_refused_line(NoSuchPost, command),
                "the kernel refused: no such post"
            );
        }
        assert_eq!(
            board_refused_line(OutcomeUnknown, Settings),
            "the outcome is unknown; run maknae board settings to see what is in force"
        );
        assert_eq!(
            board_refused_line(OutcomeUnknown, Clear),
            "the outcome is unknown; run maknae board clear again"
        );
    }

    #[test]
    fn board_unknown_lines_per_command() {
        assert_eq!(
            board_unknown_line(BoardCommand::Settings),
            "the outcome is unknown; run maknae board settings to see what is in force"
        );
        assert_eq!(
            board_unknown_line(BoardCommand::Clear),
            "the outcome is unknown; run maknae board clear again"
        );
    }

    fn secret(s: &str) -> maknae_proto::SecretText {
        maknae_proto::SecretText(zeroize::Zeroizing::new(s.into()))
    }

    fn board_entry(seq: u64, author: &str, to: Addressee) -> BoardEntry {
        BoardEntry {
            seq,
            post: maknae_proto::Post {
                id: maknae_proto::PostId([u8::try_from(seq).unwrap_or(0xff); 16]),
                author: Author::Agent(author.into()),
                task: None,
                at_secs: 1_795_654_923,
                labels: maknae_proto::Labels {},
                draft: maknae_proto::PostDraft {
                    kind: maknae_proto::PostKind::Note,
                    to,
                    in_reply_to: None,
                    body: secret("hello"),
                    attachments: vec![],
                },
            },
            held: vec![],
        }
    }

    fn written(indent: &str, text: &str) -> Vec<u8> {
        let mut out = vec![];
        write_board_text(&mut out, indent, text).unwrap();
        out
    }

    #[test]
    fn one_line_turns_breaks_into_spaces_then_escapes() {
        assert_eq!(one_line("a\nb\r\nc\u{1b}d"), "a b  c\\u{001b}d");
        assert_eq!(one_line("plain"), "plain");
    }

    #[test]
    fn board_text_escapes_every_control_and_splits_lines() {
        assert_eq!(
            written("    ", "a\u{1b}[31mb\r\n\tc\u{2028}d\u{202e}\u{200b}\u{0}"),
            b"    a\\u{001b}[31mb\\u{000d}\n    \\u{0009}c\\u{2028}d\\u{202e}\\u{200b}\\u{0000}\n"
        );
        assert_eq!(written("  ", "one"), b"  one\n");
        assert_eq!(written("  ", "a\n\nb\n"), b"  a\n  \n  b\n  \n");
    }

    #[test]
    fn a_32_kib_line_prints_whole_and_escaped() {
        let mut line = "x".repeat(32 * 1024 - 1);
        line.push('\u{7}');
        let mut want = b"    ".to_vec();
        want.extend_from_slice("x".repeat(32 * 1024 - 1).as_bytes());
        want.extend_from_slice(b"\\u{0007}\n");
        assert_eq!(written("    ", &line), want);
    }

    #[test]
    fn the_entry_header_names_every_field() {
        let mut e = board_entry(
            7,
            "hobi",
            Addressee::Agents(vec!["jin".into(), "suga".into()]),
        );
        e.post.draft.kind = maknae_proto::PostKind::Question;
        e.post.task = Some(maknae_proto::TaskId([0xab; 16]));
        e.post.draft.in_reply_to = Some(maknae_proto::PostId([5; 16]));
        e.held = vec![BoardHold::Author, BoardHold::Person];
        let task = "ab".repeat(16);
        assert_eq!(
            board_entry_header(&e, Some(5)),
            format!(
                "#7  2026-11-26T01:02:03.000Z  hobi  to agents: jin, suga  question  task {task}  reply to #5  HELD (author contained)  HELD (you were contained)"
            )
        );
        assert_eq!(
            board_entry_header(&e, None),
            format!(
                "#7  2026-11-26T01:02:03.000Z  hobi  to agents: jin, suga  question  task {task}  reply to {}  HELD (author contained)  HELD (you were contained)",
                "05".repeat(16)
            )
        );
        e.held = vec![BoardHold::Person];
        assert!(board_entry_header(&e, Some(5)).ends_with("reply to #5  HELD (you were contained)"));
        e.held = vec![BoardHold::Author];
        assert!(board_entry_header(&e, Some(5)).ends_with("reply to #5  HELD (author contained)"));
        let mut plain = board_entry(9, "jin", Addressee::Board);
        assert_eq!(
            board_entry_header(&plain, None),
            "#9  2026-11-26T01:02:03.000Z  jin  to board  note"
        );
        assert_eq!(
            board_entry_header(&plain, Some(3)),
            "#9  2026-11-26T01:02:03.000Z  jin  to board  note"
        );
        plain.post.at_secs = -5;
        plain.post.draft.kind = maknae_proto::PostKind::Answer;
        assert_eq!(
            board_entry_header(&plain, None),
            "#9  1970-01-01T00:00:00.000Z  jin  to board  answer"
        );
        plain.post.draft.kind = maknae_proto::PostKind::Intent;
        assert!(board_entry_header(&plain, None).ends_with("  intent"));
    }

    #[test]
    fn a_hostile_author_or_label_is_escaped_in_the_header() {
        let mut e = board_entry(
            3,
            "ev\u{1b}[2Jil\nmaknae: x\r",
            Addressee::Agents(vec!["j\u{1b}in\r\nx".into(), "suga".into()]),
        );
        e.post.draft.attachments = vec![Attachment {
            label: "la\u{1b}]0;t\u{7}b\nc\rd".into(),
            media: Media::TextPlain,
            content: secret("c"),
        }];
        assert_eq!(
            board_entry_header(&e, None),
            "#3  2026-11-26T01:02:03.000Z  ev\\u{001b}[2Jil maknae: x   to agents: j\\u{001b}in  x, suga  note"
        );
        assert_eq!(
            board_attachment_line(&e.post.draft.attachments[0]),
            "  attachment la\\u{001b}]0;t\\u{0007}b c d  text/plain  1 bytes"
        );
    }

    #[test]
    fn the_attachment_line_names_label_media_and_size() {
        let a = |media, content: &str| Attachment {
            label: "fix.diff".into(),
            media,
            content: secret(content),
        };
        assert_eq!(
            board_attachment_line(&a(Media::TextDiff, "0123456789")),
            "  attachment fix.diff  text/x-diff  10 bytes"
        );
        assert_eq!(
            board_attachment_line(&a(Media::TextPlain, "")),
            "  attachment fix.diff  text/plain  0 bytes"
        );
        assert_eq!(
            board_attachment_line(&a(Media::TextMarkdown, "# é")),
            "  attachment fix.diff  text/markdown  4 bytes"
        );
    }

    #[test]
    fn the_list_refusals_say_read_not_manage() {
        use BoardDefect::*;
        assert_eq!(
            board_refused_line(TryAgain, BoardCommand::List),
            "the board could not be read; try again"
        );
        assert_eq!(
            board_refused_line(OutcomeUnknown, BoardCommand::List),
            "the board could not be read; try again"
        );
        assert_eq!(
            board_unknown_line(BoardCommand::List),
            "the board could not be read; try again"
        );
        assert_eq!(
            board_refused_line(Full, BoardCommand::List),
            "the kernel refused: board full"
        );
    }

    #[test]
    fn board_list_stopped_line_counts() {
        assert_eq!(
            board_list_stopped_line(64),
            "stopped after 64 requests and 64 posts; older posts remain"
        );
        assert_eq!(
            board_list_stopped_line(1),
            "stopped after 64 requests and 1 post; older posts remain"
        );
        assert_eq!(
            board_list_stopped_line(0),
            "stopped after 64 requests and 0 posts; older posts remain"
        );
    }

    #[test]
    fn each_close_reason_has_its_line() {
        assert_eq!(close_line(TaskClose::Stopped), "stopped at your request");
        assert_eq!(close_line(TaskClose::Dropped), "dropped");
        assert_eq!(close_line(TaskClose::AgentGone), "the agent was removed");
        assert_eq!(
            close_line(TaskClose::AgentLost),
            "the agent stopped responding"
        );
        assert_eq!(
            close_line(TaskClose::Withdrawn),
            "your authority to task this agent was withdrawn"
        );
        assert_eq!(
            close_line(TaskClose::ParentEnded),
            "the task that asked for it ended"
        );
        assert_eq!(
            held_line(),
            "on hold: its tasker or the agent was contained; an administrator can release it with maknae held release"
        );
    }

    #[test]
    fn every_state_has_its_word() {
        assert_eq!(state_word(TaskState::Queued), "queued");
        assert_eq!(state_word(TaskState::Working), "working");
        assert_eq!(state_word(TaskState::Held), "held");
        assert_eq!(state_word(TaskState::Reported), "reported");
        assert_eq!(state_word(TaskState::Closed), "closed");
    }

    #[test]
    fn elapsed_is_minutes_and_seconds_then_hours() {
        assert_eq!(elapsed(0), "0:00");
        assert_eq!(elapsed(42), "0:42");
        assert_eq!(elapsed(60), "1:00");
        assert_eq!(elapsed(3599), "59:59");
        assert_eq!(elapsed(3600), "1:00:00");
        assert_eq!(elapsed(3661), "1:01:01");
    }

    fn entry(agent: &str, standing: AgentStanding, waiting: u32) -> AgentEntry {
        AgentEntry {
            agent: agent.into(),
            standing,
            waiting,
            board: false,
        }
    }

    fn boarded(agent: &str, standing: AgentStanding, waiting: u32) -> AgentEntry {
        AgentEntry {
            board: true,
            ..entry(agent, standing, waiting)
        }
    }

    #[test]
    fn agent_list_lines_mark_a_board_that_is_on() {
        assert_eq!(
            agent_list_lines(
                &[
                    boarded("hobi", AgentStanding::Enrolled, 0),
                    entry("jin", AgentStanding::Enrolled, 0),
                    boarded("suga", AgentStanding::Contained, 2),
                ],
                0,
            ),
            [
                "hobi  board on",
                "jin",
                "suga  board on  (on hold: contained)  2 reports waiting",
            ]
        );
    }

    #[test]
    fn agent_list_lines_render_every_standing() {
        let lines = agent_list_lines(
            &[
                entry("hobi", AgentStanding::Enrolled, 0),
                entry("jin", AgentStanding::Enrolled, 1),
                entry("rm", AgentStanding::Removed, 3),
                entry("suga", AgentStanding::Contained, 0),
                entry("jk", AgentStanding::Withdrawn, 2),
                entry("v", AgentStanding::Undecided, 0),
            ],
            0,
        );
        assert_eq!(
            lines,
            [
                "hobi",
                "jin  1 report waiting",
                "rm  (removed)  3 reports waiting",
                "suga  (on hold: contained)",
                "jk  (you can no longer task this agent)  2 reports waiting",
                "v  (could not be checked right now)",
            ]
        );
        assert_eq!(agent_list_lines(&[], 0), [NO_AGENTS]);
        assert_eq!(
            agent_list_lines(&[entry("hobi", AgentStanding::Enrolled, 0)], 2),
            ["hobi", "the list may be incomplete; try again"]
        );
        assert_eq!(agent_list_lines(&[], 1), [LIST_INCOMPLETE]);
        assert_eq!(
            agent_list_lines(&[entry("a\u{1b}[2J", AgentStanding::Enrolled, 0)], 0),
            ["a\\u{001b}[2J"]
        );
    }

    #[test]
    fn the_refusals_name_the_agent_escaped() {
        assert_eq!(
            not_an_agent("summarize my files"),
            "maknae: summarize my files is not an agent you can task; see maknae agent list"
        );
        assert_eq!(
            undecided_agent("hobi"),
            "maknae: the kernel could not decide whether you can task hobi; try again"
        );
        assert_eq!(
            not_an_agent("x\u{202e}"),
            "maknae: x\\u{202e} is not an agent you can task; see maknae agent list"
        );
    }

    #[test]
    fn every_outcome_unknown_line_says_refused_or_unknown_and_never_resent() {
        for op in [
            Unknown::Submit,
            Unknown::Add(2),
            Unknown::Stop(2),
            Unknown::Drop(2),
            Unknown::Collect,
        ] {
            let line = outcome_unknown_line(op);
            assert!(line.contains("refused or its outcome is unknown"), "{line}");
        }
        assert!(outcome_unknown_line(Unknown::Stop(7)).starts_with("stopping #7 "));
        assert!(outcome_unknown_line(Unknown::Drop(7)).starts_with("dropping #7 "));
        assert!(outcome_unknown_line(Unknown::Add(7)).starts_with("adding to #7 "));
        assert!(outcome_unknown_line(Unknown::Submit).contains("not sent again"));
    }

    #[test]
    fn the_leaving_lines_count_what_was_not_sent_or_not_taken() {
        assert_eq!(
            not_sent(1, "hobi"),
            "1 request was not sent; it was not given to hobi"
        );
        assert_eq!(
            not_sent(3, "hobi"),
            "3 requests were not sent; they were not given to hobi"
        );
        assert_eq!(
            not_taken(1),
            "1 request was refused, not sent, or of unknown outcome"
        );
        assert_eq!(
            not_taken(2),
            "2 requests were refused, not sent, or of unknown outcome"
        );
    }

    #[test]
    fn the_menu_offers_the_commands_that_match() {
        let names: Vec<_> = menu("/").into_iter().map(|m| m.name).collect();
        assert_eq!(
            names,
            ["/add", "/stop", "/drop", "/status", "/list", "/bye", "/help"]
        );
        let names: Vec<_> = menu("/s").into_iter().map(|m| m.name).collect();
        assert_eq!(names, ["/stop", "/status"]);
        assert!(menu("/x").is_empty());
        assert_eq!(help_lines().len(), 13);
        assert!(help_lines()[0].starts_with("/add "));
    }

    fn sealed(server: &str, base: &str, change: Option<u64>) -> Binding {
        Binding::Git(maknae_proto::GitBinding {
            server: server.into(),
            base: base.into(),
            head: None,
            change,
        })
    }

    #[test]
    fn the_reach_echo_shows_effective_ops_and_why() {
        let summary = |ops: u16, why: Option<u8>| ReachSummary::try_from((ops, why)).unwrap();
        let bindings = [
            sealed("github.com", "o/r", Some(12)),
            sealed("github.com", "o/s", None),
            sealed("gitlab.lab.local:8443", "g/s/p", None),
            sealed("github.com", "o/t", Some(3)),
            sealed("github.com", "o/u", None),
        ];
        let reach = [
            summary(0b00011 | 0b01000 << 5, None),
            summary(0, Some(1)),
            summary(0, Some(3)),
            summary(0b10101, Some(0)),
            summary(0, Some(2)),
        ];
        assert_eq!(
            echo_lines(&bindings, &reach, &[]),
            [
                "bound: github.com/o/r change 12; reach: read, review; head: push",
                "bound: github.com/o/s; reach: none (the agent's credential does not cover it)",
                "bound: gitlab.lab.local:8443/g/s/p; reach: none (this forge has no reach check)",
                "bound: github.com/o/t change 3; reach: read, write issues, merge (the change's head repository is gone)",
                "bound: github.com/o/u; reach: none (no forge credential observed it)",
            ]
        );
        assert_eq!(
            echo_lines(&bindings[..1], &[], &[]),
            ["bound: github.com/o/r change 12"]
        );
    }

    #[test]
    fn echo_lines_name_each_sealed_binding_and_each_unbound_reason() {
        let git = |base: &str, change| maknae_proto::GitRef {
            server: "github.com".into(),
            base: base.into(),
            change,
        };
        let not = |subject, reason| Unbound { subject, reason };
        let lines = echo_lines(
            &[
                sealed("github.com", "o/r", Some(12)),
                sealed("gitlab.lab.local:8443", "g/s/p", None),
            ],
            &[],
            &[
                not(Subject::Host("evil.example".into()), Reason::UnknownServer),
                not(Subject::Host("github.com".into()), Reason::NotHttps),
                not(Subject::Written("o/r#5".into()), Reason::AmbiguousShorthand),
                not(Subject::Host("ghe.example".into()), Reason::AmbiguousForge),
                not(Subject::Ref(git("o/r", Some(9))), Reason::OverTheBound),
                not(Subject::Ref(git("o/s", None)), Reason::NotInParent),
                not(Subject::Host("github.com".into()), Reason::NoForgeList),
                not(
                    Subject::Host("gitlab.lab.local:8443".into()),
                    Reason::AmbiguousGitlabPath,
                ),
                not(Subject::Host("a\u{1b}[2Jb".into()), Reason::UnknownServer),
                not(Subject::More(9960), Reason::NotListed),
            ],
        );
        assert_eq!(
            lines,
            [
                "bound: github.com/o/r change 12",
                "bound: gitlab.lab.local:8443/g/s/p",
                "not bound: evil.example: unknown server",
                "not bound: github.com: not https",
                "not bound: o/r#5: ambiguous shorthand: more than one forge is known",
                "not bound: ghe.example: ambiguous forge: the host matches more than one forge",
                "not bound: github.com/o/r change 9: over the bound of 8 bindings or 976 bytes",
                "not bound: github.com/o/s: not in the parent task",
                "not bound: github.com: no forge list",
                "not bound: gitlab.lab.local:8443: ambiguous GitLab path",
                "not bound: a\\u{001b}[2Jb: unknown server",
                "not bound: 9960 more candidates: notes past the first 32 are not listed",
            ]
        );
        assert!(echo_lines(&[], &[], &[]).is_empty());
        assert_eq!(
            binding_name(&sealed("x\u{202e}", "o/r", None)),
            "x\\u{202e}/o/r"
        );
    }
}
