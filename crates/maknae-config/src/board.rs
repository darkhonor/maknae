//! The `board` section: the site switch for the agent message board. Off by
//! default; every value that is not the boolean `true` is refused or off.

use crate::{ConfigError, Value};

pub const BOARD_SECTION: &str = "board";

pub(crate) const BOARD_KEYS: [&str; 1] = ["enabled"];

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct BoardSite {
    pub enabled: bool,
}

fn invalid(reason: &str) -> ConfigError {
    ConfigError::InvalidBoard(reason.to_string())
}

pub fn board_from_section(v: Option<&Value>) -> Result<BoardSite, ConfigError> {
    let entries = match v {
        None => return Ok(BoardSite::default()),
        Some(Value::Map(entries)) => entries,
        Some(_) => return Err(invalid("board: not a map")),
    };
    crate::reject_unknown_keys(BOARD_SECTION, entries, &BOARD_KEYS)?;
    let enabled = match entries.iter().find(|(k, _)| k == "enabled") {
        None => false,
        Some((_, Value::Bool(b))) => *b,
        Some(_) => return Err(invalid("board.enabled: not a boolean")),
    };
    Ok(BoardSite { enabled })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn map(pairs: Vec<(&str, Value)>) -> Value {
        Value::Map(pairs.into_iter().map(|(k, v)| (k.to_string(), v)).collect())
    }

    fn enabled(v: Value) -> Result<bool, ConfigError> {
        board_from_section(Some(&map(vec![("enabled", v)]))).map(|b| b.enabled)
    }

    fn refusal(r: Result<BoardSite, ConfigError>) -> String {
        match r {
            Err(ConfigError::InvalidBoard(m)) => m,
            other => panic!("expected InvalidBoard, got {other:?}"),
        }
    }

    #[test]
    fn an_absent_section_is_off() {
        assert_eq!(board_from_section(None), Ok(BoardSite { enabled: false }));
    }

    #[test]
    fn an_empty_map_is_off() {
        assert_eq!(
            board_from_section(Some(&Value::Map(vec![]))),
            Ok(BoardSite { enabled: false })
        );
    }

    #[test]
    fn a_boolean_is_carried() {
        assert_eq!(enabled(Value::Bool(true)), Ok(true));
        assert_eq!(enabled(Value::Bool(false)), Ok(false));
    }

    #[test]
    fn an_unknown_key_is_refused() {
        let v = map(vec![
            ("enabled", Value::Bool(true)),
            ("enable", Value::Bool(true)),
        ]);
        assert_eq!(
            board_from_section(Some(&v)),
            Err(ConfigError::UnknownKey {
                section: "board".into(),
                key: "enable".into(),
            })
        );
    }

    #[test]
    fn a_non_boolean_enabled_is_refused_naming_the_key() {
        for v in [
            Value::Str("true".into()),
            Value::Int(1),
            Value::Null,
            Value::Seq(vec![Value::Bool(true)]),
        ] {
            let got = refusal(board_from_section(Some(&map(vec![("enabled", v.clone())]))));
            assert_eq!(got, "board.enabled: not a boolean", "{v:?}");
        }
    }

    #[test]
    fn a_non_map_section_is_refused() {
        for v in [
            Value::Bool(true),
            Value::Null,
            Value::Str("on".into()),
            Value::Seq(vec![]),
        ] {
            assert_eq!(
                refusal(board_from_section(Some(&v))),
                "board: not a map",
                "{v:?}"
            );
        }
    }
}
