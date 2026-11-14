use unicode_width::UnicodeWidthChar;

/// A row of text: the byte range `start..end`, end exclusive; a line break is in neither row.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct RowSpan {
    pub start: usize,
    pub end: usize,
}

/// The columns `c` takes on screen: the length of its visible escape for a
/// character [`maknae_proto::is_display_unsafe`] refuses, else its display width.
pub fn cell_width(c: char) -> usize {
    if maknae_proto::is_display_unsafe(c) {
        crate::render::display_piece(c, &mut [0; crate::render::DISPLAY_PIECE_MAX]).len()
    } else {
        c.width().unwrap_or(0)
    }
}

/// Streams rows out of text fed one character at a time, so text held in
/// several blocks wraps as one.
#[derive(Clone, Copy, Debug)]
pub struct Wrapper {
    width: usize,
    start: usize,
    col: usize,
}

impl Wrapper {
    pub fn new(width: u16, start: usize) -> Self {
        Self {
            width: usize::from(width.max(1)),
            start,
            col: 0,
        }
    }

    /// `off` is `c`'s byte offset; returns the row `c` closed, if any.
    pub fn feed(&mut self, off: usize, c: char) -> Option<RowSpan> {
        if c == '\n' {
            let row = RowSpan {
                start: self.start,
                end: off,
            };
            self.start = off + 1;
            self.col = 0;
            return Some(row);
        }
        let w = cell_width(c);
        if w > 0 && self.col > 0 && self.col + w > self.width {
            let row = RowSpan {
                start: self.start,
                end: off,
            };
            self.start = off;
            self.col = w;
            return Some(row);
        }
        self.col += w;
        None
    }

    pub fn finish(self, end: usize) -> RowSpan {
        RowSpan {
            start: self.start,
            end,
        }
    }
}

pub fn rows_for(text: &str, width: u16, out: &mut Vec<RowSpan>) {
    out.clear();
    let mut wrapper = Wrapper::new(width, 0);
    for (off, c) in text.char_indices() {
        out.extend(wrapper.feed(off, c));
    }
    out.push(wrapper.finish(text.len()));
}

#[cfg(test)]
mod tests {
    use super::*;

    fn rows(text: &str, width: u16) -> Vec<&str> {
        let mut out = Vec::new();
        rows_for(text, width, &mut out);
        out.iter().map(|r| &text[r.start..r.end]).collect()
    }

    fn width_of(s: &str) -> usize {
        s.chars().map(cell_width).sum()
    }

    #[test]
    fn wide_characters_never_split() {
        assert_eq!(rows("ab한글", 3), ["ab", "한", "글"]);
        assert_eq!(rows("a😀b", 2), ["a", "😀", "b"]);
        assert_eq!(rows("한", 1), ["한"]);
        for w in 1..8 {
            for row in rows("x한글😀y가나다", w) {
                assert!(width_of(row) <= usize::from(w) || row.chars().count() == 1);
            }
        }
    }

    #[test]
    fn korean_text_wraps_by_display_width() {
        let text = "안녕하세요 세계";
        assert_eq!(rows(text, 10), ["안녕하세요", " 세계"]);
        assert_eq!(rows(text, 4), ["안녕", "하세", "요 ", "세계"]);
        assert_eq!(rows(text, 15), [text]);
    }

    #[test]
    fn combining_marks_stay_with_their_base() {
        let text = "ab\u{301}c\u{301}\u{302}d";
        assert_eq!(rows(text, 2), ["ab\u{301}", "c\u{301}\u{302}d"]);
        assert_eq!(rows(text, 1), ["a", "b\u{301}", "c\u{301}\u{302}", "d"]);
    }

    #[test]
    fn line_breaks_end_rows_and_are_in_none() {
        assert_eq!(rows("ab\ncd\n", 10), ["ab", "cd", ""]);
        assert_eq!(rows("", 10), [""]);
        assert_eq!(rows("\n\n", 10), ["", "", ""]);
        assert_eq!(rows("abc\nd", 2), ["ab", "c", "d"]);
    }

    #[test]
    fn a_zero_width_is_one_column() {
        assert_eq!(rows("abc", 0), ["a", "b", "c"]);
    }

    #[test]
    fn an_unsafe_character_is_as_wide_as_its_escape() {
        assert_eq!(cell_width('\u{1b}'), 8);
        assert_eq!(cell_width('\u{202e}'), 8);
        assert_eq!(cell_width('\u{e0001}'), 9);
        assert_eq!(cell_width('a'), 1);
        assert_eq!(cell_width('한'), 2);
        assert_eq!(cell_width('\u{301}'), 0);
    }

    #[test]
    fn rows_are_reused_not_appended() {
        let mut out = vec![RowSpan { start: 9, end: 9 }];
        rows_for("ab", 5, &mut out);
        assert_eq!(out, [RowSpan { start: 0, end: 2 }]);
    }
}
