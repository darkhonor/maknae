use crate::render::display_piece;
use crate::render::DISPLAY_PIECE_MAX;
use crate::screen::MenuItem;
use maknae_proto::{AgentEntry, AgentStanding, TaskClose, TaskState};

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

/// One `maknae agent list` line per entry, then the incomplete-list line.
pub fn agent_list_lines(entries: &[AgentEntry], undecided: u32) -> Vec<String> {
    let mut lines: Vec<String> = entries
        .iter()
        .map(|e| {
            let mut line = safe(&e.agent);
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
        }
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
}
