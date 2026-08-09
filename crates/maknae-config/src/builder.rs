//! The event→tree receiver (spec §4). Drives yaml-rust2's low-level event stream
//! into an owned [`Value`], enforcing the restricted, reject-exotic subset:
//! duplicate-key rejection, no aliases/tags/multi-doc/non-string-keys, anchors
//! ignored (inert), and a 128 container-nesting ceiling enforced by a controlled
//! `panic!` (the only way to halt the parser, whose `on_event` returns `()`).

use crate::error::ConfigError;
use crate::scalar::resolve_scalar;
use crate::value::Value;
use std::collections::BTreeSet;
use yaml_rust2::parser::MarkedEventReceiver;
use yaml_rust2::scanner::Marker;
use yaml_rust2::Event;

const MAX_DEPTH: usize = 128;

enum Partial {
    Seq(Vec<Value>),
    Map {
        entries: Vec<(String, Value)>,
        seen: BTreeSet<String>,
        pending_key: Option<String>,
    },
}

pub(crate) struct Builder {
    stack: Vec<Partial>,
    root: Option<Value>,
    depth: usize,
    doc_count: usize,
    error: Option<ConfigError>,
    depth_loc: (usize, usize),
}

impl Builder {
    pub(crate) fn new() -> Self {
        Self {
            stack: Vec::new(),
            root: None,
            depth: 0,
            doc_count: 0,
            error: None,
            depth_loc: (0, 0),
        }
    }

    /// The `(line, col)` stashed just before the depth `panic!`, read after
    /// `catch_unwind` catches it. Our depth panic is the only panic that occurs
    /// (yaml-rust2's internal asserts are unreachable in practice), so this is
    /// always the depth violation's location when a catch fires.
    pub(crate) fn depth_loc(&self) -> (usize, usize) {
        self.depth_loc
    }

    /// The recorded first-violation error is preferred over the built tree.
    pub(crate) fn finish(self) -> Result<Value, ConfigError> {
        if let Some(e) = self.error {
            return Err(e);
        }
        Ok(self.root.unwrap_or(Value::Null))
    }

    fn fail(&mut self, err: ConfigError) {
        if self.error.is_none() {
            self.error = Some(err);
        }
    }

    /// Place a completed value into the current container (or set the root).
    /// A map's first child of a pair is its key (must be a `Str`, deduped).
    /// (Only ever called with `self.error == None` — `on_event` gates first.)
    fn push_value(&mut self, v: Value, mark: Marker) {
        let mut violation: Option<ConfigError> = None;
        match self.stack.last_mut() {
            None => self.root = Some(v),
            Some(Partial::Seq(items)) => items.push(v),
            Some(Partial::Map {
                entries,
                seen,
                pending_key,
            }) => match pending_key.take() {
                None => match v {
                    Value::Str(k) => {
                        if seen.contains(&k) {
                            violation = Some(ConfigError::DuplicateKey {
                                key: k,
                                line: mark.line(),
                                col: mark.col(),
                            });
                        } else {
                            seen.insert(k.clone());
                            *pending_key = Some(k);
                        }
                    }
                    _ => {
                        violation = Some(ConfigError::Parse {
                            message: "non-string mapping key".into(),
                            line: mark.line(),
                            col: mark.col(),
                        });
                    }
                },
                Some(k) => entries.push((k, v)),
            },
        }
        if let Some(e) = violation {
            self.fail(e);
        }
    }

    fn enter_container(&mut self, container: Partial, mark: Marker) {
        self.depth += 1;
        if self.depth > MAX_DEPTH {
            self.depth_loc = (mark.line(), mark.col());
            panic!("maknae-config: nesting depth exceeded");
        }
        self.stack.push(container);
    }
}

impl MarkedEventReceiver for Builder {
    fn on_event(&mut self, ev: Event, mark: Marker) {
        // First violation wins; ignore everything after (parser keeps going).
        if self.error.is_some() {
            return;
        }
        match ev {
            Event::StreamStart | Event::StreamEnd | Event::DocumentEnd | Event::Nothing => {}
            Event::DocumentStart => {
                self.doc_count += 1;
                if self.doc_count > 1 {
                    self.fail(ConfigError::Parse {
                        message: "multiple documents not permitted".into(),
                        line: mark.line(),
                        col: mark.col(),
                    });
                }
            }
            Event::Alias(_) => self.fail(ConfigError::Parse {
                message: "aliases not permitted".into(),
                line: mark.line(),
                col: mark.col(),
            }),
            Event::Scalar(value, style, _anchor, tag) => {
                if tag.is_some() {
                    self.fail(ConfigError::Parse {
                        message: "tags not permitted".into(),
                        line: mark.line(),
                        col: mark.col(),
                    });
                } else {
                    match resolve_scalar(value, style) {
                        Ok(val) => self.push_value(val, mark),
                        Err(()) => self.fail(ConfigError::Parse {
                            message: "unparseable scalar".into(),
                            line: mark.line(),
                            col: mark.col(),
                        }),
                    }
                }
            }
            Event::SequenceStart(_anchor, tag) => {
                if tag.is_some() {
                    self.fail(ConfigError::Parse {
                        message: "tagged container not permitted".into(),
                        line: mark.line(),
                        col: mark.col(),
                    });
                } else {
                    self.enter_container(Partial::Seq(Vec::new()), mark);
                }
            }
            Event::MappingStart(_anchor, tag) => {
                if tag.is_some() {
                    self.fail(ConfigError::Parse {
                        message: "tagged container not permitted".into(),
                        line: mark.line(),
                        col: mark.col(),
                    });
                } else {
                    self.enter_container(
                        Partial::Map {
                            entries: Vec::new(),
                            seen: BTreeSet::new(),
                            pending_key: None,
                        },
                        mark,
                    );
                }
            }
            Event::SequenceEnd => {
                self.depth = self.depth.saturating_sub(1);
                if let Some(Partial::Seq(items)) = self.stack.pop() {
                    self.push_value(Value::Seq(items), mark);
                }
            }
            Event::MappingEnd => {
                self.depth = self.depth.saturating_sub(1);
                if let Some(Partial::Map { entries, .. }) = self.stack.pop() {
                    self.push_value(Value::Map(entries), mark);
                }
            }
        }
    }
}
