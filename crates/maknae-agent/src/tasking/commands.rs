/// One entered line, read. Text is borrowed from the line, never copied.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Parsed<'a> {
    /// Nothing but white space.
    Empty,
    /// Plain text: the whole line is the request.
    Request,
    Add {
        number: Option<u32>,
        text: &'a str,
    },
    Stop(Option<u32>),
    Drop(Option<u32>),
    Status(Option<u32>),
    List,
    Bye,
    Help,
    /// A `/word` the session does not know.
    Unknown(&'a str),
    /// A known command written wrongly: the line that says how to write it.
    Usage(&'static str),
}

pub const ADD_USAGE: &str = "usage: /add [n] <text>";
pub const STOP_USAGE: &str = "usage: /stop [n]";
pub const DROP_USAGE: &str = "usage: /drop [n]";
pub const STATUS_USAGE: &str = "usage: /status [n]";
pub const LIST_USAGE: &str = "usage: /list";
pub const BYE_USAGE: &str = "usage: /bye";
pub const HELP_USAGE: &str = "usage: /help";

pub fn parse(line: &str) -> Parsed<'_> {
    if line.trim().is_empty() {
        return Parsed::Empty;
    }
    let Some(rest) = line.strip_prefix('/') else {
        return Parsed::Request;
    };
    let (word, args) = match rest.find(char::is_whitespace) {
        Some(at) => (&rest[..at], rest[at..].trim()),
        None => (rest, ""),
    };
    match word {
        "add" => add(args),
        "stop" => number_only(args, Parsed::Stop, STOP_USAGE),
        "drop" => number_only(args, Parsed::Drop, DROP_USAGE),
        "status" => number_only(args, Parsed::Status, STATUS_USAGE),
        "list" => bare(args, Parsed::List, LIST_USAGE),
        "bye" => bare(args, Parsed::Bye, BYE_USAGE),
        "help" => bare(args, Parsed::Help, HELP_USAGE),
        _ => Parsed::Unknown(&line[..=word.len()]),
    }
}

fn add(args: &str) -> Parsed<'_> {
    let (first, rest) = match args.find(char::is_whitespace) {
        Some(at) => (&args[..at], args[at..].trim_start()),
        None => (args, ""),
    };
    match number(first) {
        Some(n) if !rest.is_empty() => Parsed::Add {
            number: Some(n),
            text: rest,
        },
        Some(_) => Parsed::Usage(ADD_USAGE),
        None if args.is_empty() => Parsed::Usage(ADD_USAGE),
        None => Parsed::Add {
            number: None,
            text: args,
        },
    }
}

fn number_only<'a>(
    args: &str,
    make: fn(Option<u32>) -> Parsed<'a>,
    usage: &'static str,
) -> Parsed<'a> {
    if args.is_empty() {
        return make(None);
    }
    match number(args) {
        Some(n) => make(Some(n)),
        None => Parsed::Usage(usage),
    }
}

fn bare<'a>(args: &str, parsed: Parsed<'a>, usage: &'static str) -> Parsed<'a> {
    if args.is_empty() {
        parsed
    } else {
        Parsed::Usage(usage)
    }
}

/// A task number as typed: `2` or `#2`, never zero.
fn number(word: &str) -> Option<u32> {
    let digits = word.strip_prefix('#').unwrap_or(word);
    if digits.is_empty() || !digits.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    digits.parse().ok().filter(|n| *n > 0)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn an_unknown_slash_word_is_never_sent_as_a_task() {
        assert_eq!(
            parse("/frobnicate the files"),
            Parsed::Unknown("/frobnicate")
        );
        assert_eq!(parse("/etc/hosts please"), Parsed::Unknown("/etc/hosts"));
        assert_eq!(parse("/"), Parsed::Unknown("/"));
        assert_eq!(parse("/Stop"), Parsed::Unknown("/Stop"));
        assert_eq!(parse("summarise /etc/hosts"), Parsed::Request);
        assert_eq!(parse(" /stop"), Parsed::Request);
    }

    #[test]
    fn every_command_parses_with_and_without_a_number() {
        assert_eq!(parse("/stop"), Parsed::Stop(None));
        assert_eq!(parse("/stop 2"), Parsed::Stop(Some(2)));
        assert_eq!(parse("/stop #2"), Parsed::Stop(Some(2)));
        assert_eq!(parse("/drop  3 "), Parsed::Drop(Some(3)));
        assert_eq!(parse("/drop"), Parsed::Drop(None));
        assert_eq!(parse("/status"), Parsed::Status(None));
        assert_eq!(parse("/status 1"), Parsed::Status(Some(1)));
        assert_eq!(parse("/list"), Parsed::List);
        assert_eq!(parse("/bye"), Parsed::Bye);
        assert_eq!(parse("/help"), Parsed::Help);
        assert_eq!(
            parse("/add 1 also the logs"),
            Parsed::Add {
                number: Some(1),
                text: "also the logs"
            }
        );
        assert_eq!(
            parse("/add also the logs"),
            Parsed::Add {
                number: None,
                text: "also the logs"
            }
        );
        assert_eq!(
            parse("/add\tx"),
            Parsed::Add {
                number: None,
                text: "x"
            }
        );
    }

    #[test]
    fn a_malformed_command_says_how_to_write_it_and_sends_nothing() {
        assert_eq!(parse("/stop two"), Parsed::Usage(STOP_USAGE));
        assert_eq!(parse("/stop 0"), Parsed::Usage(STOP_USAGE));
        assert_eq!(parse("/stop 2 3"), Parsed::Usage(STOP_USAGE));
        assert_eq!(parse("/stop 99999999999"), Parsed::Usage(STOP_USAGE));
        assert_eq!(parse("/drop -1"), Parsed::Usage(DROP_USAGE));
        assert_eq!(parse("/status x"), Parsed::Usage(STATUS_USAGE));
        assert_eq!(parse("/add"), Parsed::Usage(ADD_USAGE));
        assert_eq!(parse("/add   "), Parsed::Usage(ADD_USAGE));
        assert_eq!(parse("/add 2"), Parsed::Usage(ADD_USAGE));
        assert_eq!(parse("/list all"), Parsed::Usage(LIST_USAGE));
        assert_eq!(parse("/bye now"), Parsed::Usage(BYE_USAGE));
        assert_eq!(parse("/help me"), Parsed::Usage(HELP_USAGE));
    }

    #[test]
    fn blank_lines_are_empty_and_text_is_a_request() {
        assert_eq!(parse(""), Parsed::Empty);
        assert_eq!(parse("  \t"), Parsed::Empty);
        assert_eq!(parse("tidy my downloads"), Parsed::Request);
    }
}
