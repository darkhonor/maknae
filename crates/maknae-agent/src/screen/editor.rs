use super::fixed::FixedText;
use super::keys::Key;
use zeroize::Zeroizing;

pub const RECALL_SLOTS: usize = 16;

pub enum EditOutcome {
    Submitted(Zeroizing<String>),
    Changed,
    Full,
    Nothing,
    Cleared,
    LeaveRequested,
}

impl std::fmt::Debug for EditOutcome {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Submitted(s) => write!(f, "Submitted(<{} bytes>)", s.len()),
            Self::Changed => f.write_str("Changed"),
            Self::Full => f.write_str("Full"),
            Self::Nothing => f.write_str("Nothing"),
            Self::Cleared => f.write_str("Cleared"),
            Self::LeaveRequested => f.write_str("LeaveRequested"),
        }
    }
}

struct Recall {
    slots: Vec<FixedText>,
    cap: usize,
    next: usize,
}

/// The input line: one zeroizing allocation of `cap` bytes, never grown; the
/// recall ring's slots are each `cap` bytes, allocated on first use.
pub struct Editor {
    text: FixedText,
    cursor: usize,
    recall: Recall,
    browsing: Option<usize>,
    draft: Option<FixedText>,
    leave_armed: bool,
}

impl std::fmt::Debug for Editor {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Editor")
            .field("text", &self.text)
            .field("cursor", &self.cursor)
            .field("recalled", &self.recall.slots.len())
            .finish()
    }
}

impl Editor {
    pub fn new(cap: usize) -> Editor {
        Editor {
            text: FixedText::with_capacity(cap),
            cursor: 0,
            recall: Recall {
                slots: Vec::new(),
                cap,
                next: 0,
            },
            browsing: None,
            draft: None,
            leave_armed: false,
        }
    }

    pub fn text(&self) -> &str {
        self.text.as_str()
    }

    /// A byte offset into [`Editor::text`].
    pub fn cursor(&self) -> usize {
        self.cursor
    }

    pub fn capacity(&self) -> usize {
        self.text.capacity()
    }

    /// True after a Ctrl-C on an empty line: a second one leaves. The driver
    /// calls [`Editor::disarm_leave`] when its window passes.
    pub fn leave_armed(&self) -> bool {
        self.leave_armed
    }

    pub fn disarm_leave(&mut self) {
        self.leave_armed = false;
    }

    /// The text when it is a slash command being typed: `/` first, no whitespace.
    pub fn slash_prefix(&self) -> Option<&str> {
        let text = self.text();
        (text.starts_with('/') && !text.contains(char::is_whitespace)).then_some(text)
    }

    pub fn apply(&mut self, key: &Key) -> EditOutcome {
        let ctrl_c = *key == Key::Ctrl('c');
        if !ctrl_c {
            self.leave_armed = false;
        }
        if !matches!(key, Key::Ctrl('p' | 'n')) {
            self.browsing = None;
        }
        match *key {
            Key::Char(c) => self.insert(c),
            Key::CtrlJ => self.insert('\n'),
            Key::Enter => self.submit(),
            Key::Backspace => match self.before(self.cursor) {
                Some(at) => self.remove(at..self.cursor),
                None => EditOutcome::Nothing,
            },
            Key::Delete => self.delete(),
            Key::Left | Key::Ctrl('b') => self.move_to(self.before(self.cursor)),
            Key::Right | Key::Ctrl('f') => self.move_to(self.after(self.cursor)),
            Key::Ctrl('a') => self.move_to(Some(self.line_start())),
            Key::Ctrl('e') => self.move_to(Some(self.line_end())),
            Key::Alt('b') => self.move_to(Some(self.word_back(char::is_alphanumeric))),
            Key::Alt('f') => self.move_to(Some(self.word_forward())),
            Key::Ctrl('u') => self.remove(self.line_start()..self.cursor),
            Key::Ctrl('k') => self.remove(self.cursor..self.line_end()),
            Key::Ctrl('w') => {
                self.remove(self.word_back(|c: char| !c.is_whitespace())..self.cursor)
            }
            Key::Ctrl('p') => self.recall_older(),
            Key::Ctrl('n') => self.recall_newer(),
            Key::Ctrl('c') if !self.text.is_empty() => {
                self.wipe();
                EditOutcome::Cleared
            }
            Key::Ctrl('c') if self.leave_armed => EditOutcome::LeaveRequested,
            Key::Ctrl('c') => {
                self.leave_armed = true;
                EditOutcome::Nothing
            }
            Key::Ctrl('d') if self.text.is_empty() => EditOutcome::LeaveRequested,
            Key::Ctrl('d') => self.delete(),
            _ => EditOutcome::Nothing,
        }
    }

    fn insert(&mut self, c: char) -> EditOutcome {
        match self
            .text
            .insert_str(self.cursor, c.encode_utf8(&mut [0; 4]))
        {
            Ok(()) => {
                self.cursor += c.len_utf8();
                EditOutcome::Changed
            }
            Err(_) => EditOutcome::Full,
        }
    }

    fn submit(&mut self) -> EditOutcome {
        if self.text.is_empty() {
            return EditOutcome::Nothing;
        }
        let mut sent = Zeroizing::new(String::with_capacity(self.text.len()));
        sent.push_str(self.text());
        self.recall.store(self.text.as_str());
        self.wipe();
        if let Some(draft) = self.draft.as_mut() {
            draft.clear();
        }
        EditOutcome::Submitted(sent)
    }

    fn wipe(&mut self) {
        self.text.clear();
        self.cursor = 0;
    }

    fn delete(&mut self) -> EditOutcome {
        match self.after(self.cursor) {
            Some(at) => self.remove(self.cursor..at),
            None => EditOutcome::Nothing,
        }
    }

    fn remove(&mut self, range: std::ops::Range<usize>) -> EditOutcome {
        if range.is_empty() {
            return EditOutcome::Nothing;
        }
        self.cursor = range.start;
        self.text.remove_range(range);
        EditOutcome::Changed
    }

    fn move_to(&mut self, at: Option<usize>) -> EditOutcome {
        match at {
            Some(at) if at != self.cursor => {
                self.cursor = at;
                EditOutcome::Changed
            }
            _ => EditOutcome::Nothing,
        }
    }

    fn before(&self, at: usize) -> Option<usize> {
        self.text()[..at].char_indices().next_back().map(|(i, _)| i)
    }

    fn after(&self, at: usize) -> Option<usize> {
        self.text()[at..].chars().next().map(|c| at + c.len_utf8())
    }

    fn line_start(&self) -> usize {
        self.text()[..self.cursor].rfind('\n').map_or(0, |i| i + 1)
    }

    fn line_end(&self) -> usize {
        self.text()[self.cursor..]
            .find('\n')
            .map_or(self.text.len(), |i| self.cursor + i)
    }

    fn word_back(&self, word: impl Fn(char) -> bool) -> usize {
        let head = &self.text()[..self.cursor];
        let mut chars = head.char_indices().rev().skip_while(|&(_, c)| !word(c));
        let mut at = None;
        for (i, c) in chars.by_ref() {
            if !word(c) {
                break;
            }
            at = Some(i);
        }
        at.unwrap_or(0)
    }

    fn word_forward(&self) -> usize {
        let tail = &self.text()[self.cursor..];
        tail.char_indices()
            .skip_while(|&(_, c)| !c.is_alphanumeric())
            .find(|&(_, c)| !c.is_alphanumeric())
            .map_or(self.text.len(), |(i, _)| self.cursor + i)
    }

    fn recall_older(&mut self) -> EditOutcome {
        let age = self.browsing.map_or(0, |a| a + 1);
        if self.browsing.is_none() && self.recall.get(0).is_some() {
            let cap = self.text.capacity();
            let draft = self
                .draft
                .get_or_insert_with(|| FixedText::with_capacity(cap));
            draft.clear();
            let _ = draft.push_str(self.text.as_str());
        }
        self.load_recalled(age)
    }

    fn recall_newer(&mut self) -> EditOutcome {
        match self.browsing {
            None => EditOutcome::Nothing,
            Some(0) => {
                self.browsing = None;
                self.wipe();
                if let Some(draft) = self.draft.as_mut() {
                    let _ = self.text.push_str(draft.as_str());
                    draft.clear();
                }
                self.cursor = self.text.len();
                EditOutcome::Changed
            }
            Some(age) => self.load_recalled(age - 1),
        }
    }

    fn load_recalled(&mut self, age: usize) -> EditOutcome {
        let Some(slot) = self.recall.get(age) else {
            return EditOutcome::Nothing;
        };
        self.text.clear();
        if self.text.push_str(slot.as_str()).is_err() {
            return EditOutcome::Full;
        }
        self.cursor = self.text.len();
        self.browsing = Some(age);
        EditOutcome::Changed
    }
}

impl Recall {
    fn store(&mut self, text: &str) {
        if self.slots.len() < RECALL_SLOTS {
            if self.slots.capacity() == 0 {
                self.slots.reserve_exact(RECALL_SLOTS);
            }
            self.slots.push(FixedText::with_capacity(self.cap));
        }
        let slot = &mut self.slots[self.next];
        slot.clear();
        let _ = slot.push_str(text);
        self.next = (self.next + 1) % RECALL_SLOTS;
    }

    fn get(&self, age: usize) -> Option<&FixedText> {
        if age >= self.slots.len() {
            return None;
        }
        self.slots
            .get((self.next + RECALL_SLOTS - 1 - age) % RECALL_SLOTS)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn typed(e: &mut Editor, s: &str) {
        for c in s.chars() {
            let key = if c == '\n' { Key::CtrlJ } else { Key::Char(c) };
            assert!(matches!(e.apply(&key), EditOutcome::Changed), "{c:?}");
        }
    }

    fn submit(e: &mut Editor) -> String {
        match e.apply(&Key::Enter) {
            EditOutcome::Submitted(s) => s.to_string(),
            other => panic!("{other:?}"),
        }
    }

    #[test]
    fn typing_past_the_cap_is_full_and_nothing_grows() {
        let mut e = Editor::new(8);
        let ptr = e.text().as_ptr();
        let alloc = e.text.allocated();
        typed(&mut e, "abcd한");
        assert!(matches!(e.apply(&Key::Char('é')), EditOutcome::Full));
        assert!(matches!(e.apply(&Key::Char('x')), EditOutcome::Changed));
        assert!(matches!(e.apply(&Key::Char('y')), EditOutcome::Full));
        assert!(matches!(e.apply(&Key::CtrlJ), EditOutcome::Full));
        assert_eq!(e.text(), "abcd한x");
        assert_eq!(e.text().len(), 8);
        assert_eq!(e.capacity(), 8);
        assert_eq!(e.text().as_ptr(), ptr);
        assert_eq!(e.text.allocated(), alloc);
    }

    #[test]
    fn enter_submits_ctrl_j_inserts_a_newline_and_an_empty_enter_is_nothing() {
        let mut e = Editor::new(64);
        assert!(matches!(e.apply(&Key::Enter), EditOutcome::Nothing));
        typed(&mut e, "one\ntwo");
        let ptr = e.text().as_ptr();
        let sent = match e.apply(&Key::Enter) {
            EditOutcome::Submitted(s) => s,
            other => panic!("{other:?}"),
        };
        assert_eq!(sent.as_str(), "one\ntwo");
        assert_eq!(sent.capacity(), sent.len());
        assert_eq!(e.text(), "");
        assert_eq!(e.cursor(), 0);
        assert_eq!(e.text().as_ptr(), ptr);
    }

    #[test]
    fn line_keys_move_and_kill() {
        let mut e = Editor::new(128);
        typed(&mut e, "first line\nsecond word here");
        e.apply(&Key::Ctrl('a'));
        assert_eq!(e.cursor(), 11);
        e.apply(&Key::Ctrl('f'));
        e.apply(&Key::Right);
        assert_eq!(e.cursor(), 13);
        e.apply(&Key::Ctrl('b'));
        e.apply(&Key::Left);
        assert_eq!(e.cursor(), 11);
        e.apply(&Key::Ctrl('e'));
        assert_eq!(e.cursor(), e.text().len());
        e.apply(&Key::Alt('b'));
        assert_eq!(&e.text()[e.cursor()..], "here");
        e.apply(&Key::Alt('b'));
        assert_eq!(&e.text()[e.cursor()..], "word here");
        e.apply(&Key::Alt('f'));
        assert_eq!(&e.text()[e.cursor()..], " here");
        e.apply(&Key::Ctrl('k'));
        assert_eq!(e.text(), "first line\nsecond word");
        e.apply(&Key::Ctrl('w'));
        assert_eq!(e.text(), "first line\nsecond ");
        e.apply(&Key::Backspace);
        assert_eq!(e.text(), "first line\nsecond");
        e.apply(&Key::Ctrl('u'));
        assert_eq!(e.text(), "first line\n");
        e.apply(&Key::Backspace);
        assert_eq!(e.text(), "first line");
        e.apply(&Key::Ctrl('a'));
        e.apply(&Key::Delete);
        assert_eq!(e.text(), "irst line");
        e.apply(&Key::Ctrl('d'));
        assert_eq!(e.text(), "rst line");
        assert!(matches!(e.apply(&Key::Backspace), EditOutcome::Nothing));
        assert!(matches!(e.apply(&Key::Left), EditOutcome::Nothing));
        e.apply(&Key::Ctrl('e'));
        assert!(matches!(e.apply(&Key::Delete), EditOutcome::Nothing));
        assert!(matches!(e.apply(&Key::Right), EditOutcome::Nothing));
    }

    #[test]
    fn cursor_moves_by_whole_characters() {
        let mut e = Editor::new(64);
        typed(&mut e, "가나다");
        e.apply(&Key::Left);
        assert_eq!(e.cursor(), 6);
        e.apply(&Key::Backspace);
        assert_eq!(e.text(), "가다");
        e.apply(&Key::Char('x'));
        assert_eq!(e.text(), "가x다");
        e.apply(&Key::Delete);
        assert_eq!(e.text(), "가x");
    }

    #[test]
    fn scroll_keys_and_paste_markers_leave_the_line_alone() {
        let mut e = Editor::new(16);
        typed(&mut e, "ab");
        for k in [
            Key::Up,
            Key::Down,
            Key::PageUp,
            Key::PageDown,
            Key::Home,
            Key::End,
            Key::PasteStart,
            Key::PasteEnd,
            Key::Resize,
            Key::Unknown,
            Key::Ctrl('z'),
            Key::Alt('x'),
        ] {
            assert!(matches!(e.apply(&k), EditOutcome::Nothing), "{k:?}");
        }
        assert_eq!(e.text(), "ab");
    }

    #[test]
    fn ctrl_c_clears_then_second_requests_leave() {
        let mut e = Editor::new(16);
        typed(&mut e, "draft");
        assert!(matches!(e.apply(&Key::Ctrl('c')), EditOutcome::Cleared));
        assert_eq!(e.text(), "");
        assert!(!e.leave_armed());
        assert!(matches!(e.apply(&Key::Ctrl('c')), EditOutcome::Nothing));
        assert!(e.leave_armed());
        assert!(matches!(
            e.apply(&Key::Ctrl('c')),
            EditOutcome::LeaveRequested
        ));

        let mut e = Editor::new(16);
        e.apply(&Key::Ctrl('c'));
        e.disarm_leave();
        assert!(matches!(e.apply(&Key::Ctrl('c')), EditOutcome::Nothing));

        let mut e = Editor::new(16);
        e.apply(&Key::Ctrl('c'));
        e.apply(&Key::Up);
        assert!(!e.leave_armed());
        assert!(matches!(e.apply(&Key::Ctrl('c')), EditOutcome::Nothing));
    }

    #[test]
    fn ctrl_d_leaves_only_on_an_empty_line() {
        let mut e = Editor::new(16);
        typed(&mut e, "a");
        e.apply(&Key::Left);
        assert!(matches!(e.apply(&Key::Ctrl('d')), EditOutcome::Changed));
        assert!(matches!(
            e.apply(&Key::Ctrl('d')),
            EditOutcome::LeaveRequested
        ));
    }

    #[test]
    fn ctrl_p_recalls_from_memory_only() {
        let mut e = Editor::new(32);
        assert!(matches!(e.apply(&Key::Ctrl('p')), EditOutcome::Nothing));
        assert_eq!(e.recall.slots.len(), 0);
        typed(&mut e, "one");
        submit(&mut e);
        typed(&mut e, "two");
        submit(&mut e);
        e.apply(&Key::Ctrl('p'));
        assert_eq!(e.text(), "two");
        assert_eq!(e.cursor(), 3);
        e.apply(&Key::Ctrl('p'));
        assert_eq!(e.text(), "one");
        assert!(matches!(e.apply(&Key::Ctrl('p')), EditOutcome::Nothing));
        assert_eq!(e.text(), "one");
        e.apply(&Key::Ctrl('n'));
        assert_eq!(e.text(), "two");
        e.apply(&Key::Ctrl('n'));
        assert_eq!(e.text(), "");
        assert!(matches!(e.apply(&Key::Ctrl('n')), EditOutcome::Nothing));
        e.apply(&Key::Ctrl('p'));
        e.apply(&Key::Char('!'));
        assert_eq!(e.text(), "two!");
        e.apply(&Key::Ctrl('p'));
        assert_eq!(e.text(), "two");
        e.apply(&Key::Ctrl('n'));
        assert_eq!(e.text(), "two!");
        e.apply(&Key::Ctrl('p'));
        assert_eq!(submit(&mut e), "two");
    }

    #[test]
    fn ctrl_n_past_the_newest_restores_the_draft() {
        let mut e = Editor::new(32);
        typed(&mut e, "sent");
        submit(&mut e);
        assert!(e.draft.is_none());
        typed(&mut e, "half typed");
        e.apply(&Key::Left);
        e.apply(&Key::Ctrl('p'));
        assert_eq!(e.text(), "sent");
        let draft = e.draft.as_ref().unwrap();
        assert_eq!(draft.capacity(), 32);
        let ptr = draft.as_str().as_ptr();
        assert!(matches!(e.apply(&Key::Ctrl('n')), EditOutcome::Changed));
        assert_eq!(e.text(), "half typed");
        assert_eq!(e.cursor(), "half typed".len());
        assert!(e.draft.as_ref().unwrap().is_empty());
        e.apply(&Key::Ctrl('u'));
        typed(&mut e, "next");
        e.apply(&Key::Ctrl('p'));
        assert_eq!(e.draft.as_ref().unwrap().as_str(), "next");
        assert_eq!(e.draft.as_ref().unwrap().as_str().as_ptr(), ptr);
        assert_eq!(submit(&mut e), "sent");
        assert!(e.draft.as_ref().unwrap().is_empty());
        e.apply(&Key::Ctrl('p'));
        e.apply(&Key::Ctrl('n'));
        assert_eq!(e.text(), "");
    }

    #[test]
    fn the_recall_ring_is_sixteen_lazy_slots_of_the_cap_wiped_on_reuse() {
        let mut e = Editor::new(24);
        assert_eq!(e.recall.slots.capacity(), 0);
        typed(&mut e, "request number 0 long");
        submit(&mut e);
        assert_eq!(e.recall.slots.len(), 1);
        assert_eq!(e.recall.slots[0].capacity(), 24);
        let ptrs: Vec<*const u8> = (1..RECALL_SLOTS)
            .map(|i| {
                typed(&mut e, &format!("r{i}"));
                submit(&mut e);
                e.recall.slots[i].as_str().as_ptr()
            })
            .collect();
        let first = e.recall.slots[0].as_str().as_ptr();
        assert_eq!(e.recall.slots.len(), RECALL_SLOTS);
        typed(&mut e, "x");
        submit(&mut e);
        assert_eq!(e.recall.slots.len(), RECALL_SLOTS);
        assert_eq!(e.recall.slots.capacity(), RECALL_SLOTS);
        assert_eq!(e.recall.slots[0].as_str(), "x");
        assert_eq!(e.recall.slots[0].as_str().as_ptr(), first);
        for (i, p) in ptrs.iter().enumerate() {
            assert_eq!(e.recall.slots[i + 1].as_str().as_ptr(), *p);
            assert_eq!(e.recall.slots[i + 1].capacity(), 24);
        }
        let mut seen = Vec::new();
        while let EditOutcome::Changed = e.apply(&Key::Ctrl('p')) {
            seen.push(e.text().to_string());
        }
        assert_eq!(seen.len(), RECALL_SLOTS);
        assert_eq!(seen[0], "x");
        assert_eq!(seen[1], "r15");
        assert_eq!(seen[15], "r1");
    }

    #[test]
    fn a_slash_menu_opens_only_on_a_leading_slash_word() {
        let mut e = Editor::new(32);
        assert_eq!(e.slash_prefix(), None);
        typed(&mut e, "/st");
        assert_eq!(e.slash_prefix(), Some("/st"));
        typed(&mut e, " 2");
        assert_eq!(e.slash_prefix(), None);
        let mut e = Editor::new(32);
        typed(&mut e, "a/st");
        assert_eq!(e.slash_prefix(), None);
        let mut e = Editor::new(32);
        typed(&mut e, "/x\n");
        assert_eq!(e.slash_prefix(), None);
    }

    #[test]
    fn debug_never_prints_the_draft_or_a_submission() {
        let mut e = Editor::new(32);
        typed(&mut e, "sentinel-91c2");
        assert!(!format!("{e:?}").contains("sentinel"));
        let out = e.apply(&Key::Enter);
        assert!(!format!("{out:?}").contains("sentinel"));
    }
}
