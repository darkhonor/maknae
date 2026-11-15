use super::blocks::{Conversation, EntryId};
use super::editor::Editor;
use super::keys::Key;
use super::wrap::{rows_for, RowSpan};
use super::{HeaderLine, MenuItem};
use crate::render::{display_piece, DISPLAY_PIECE_MAX};
use maknae_proto::{BannerColor, BannerSpec, Contrast};
use std::ops::{Range, RangeInclusive};
use unicode_width::UnicodeWidthChar;
use zeroize::{Zeroize, Zeroizing};

pub const TOO_SMALL: &str = "terminal too small";
/// The largest window the composer lays out; a larger one is drawn at this size.
pub const MAX_ROWS: u16 = 512;
pub const MAX_COLS: u16 = 1024;
const MIN_CONVERSATION_ROWS: usize = 3;
const STATUS_ROWS_MAX: usize = 3;
const INPUT_ROWS_MAX: usize = 3;
const MENU_ROWS_MAX: usize = 5;
const BANNER_MARGINS: usize = 2;
const PROMPT: &str = "> ";
const CONTINUATION: &str = "  ";
/// A content row's byte budget is its columns times this.
pub const CELL_BYTES: usize = 16;
/// A row's control bytes at most: its position, the erase, and a banner's
/// background, foreground and reset.
pub const ROW_CONTROL_BYTES: usize = 48;
/// The most bytes a banner's text takes in its row.
pub const BANNER_ROW_TEXT_BYTES: usize =
    crate::render::DISPLAY_EXPANSION * maknae_proto::BANNER_TEXT_MAX;
/// The frame's own control bytes: synchronized output on and off and the cursor.
pub const FRAME_CONTROL_BYTES: usize = 32;

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct TerminalSize {
    pub rows: u16,
    pub cols: u16,
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum FrameError {
    /// The frame did not fit the buffer; nothing was grown.
    Overflow,
}

impl std::fmt::Display for FrameError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("the frame does not fit its buffer")
    }
}

impl std::error::Error for FrameError {}

/// The capacity the caller allocates the frame buffer at, once per size.
pub fn frame_capacity(size: TerminalSize) -> usize {
    let (rows, cols) = clamped(size);
    let (all_rows, all_cols) = (usize::from(size.rows), usize::from(size.cols));
    rows * (cols * CELL_BYTES + ROW_CONTROL_BYTES)
        + (all_rows - rows) * ROW_CONTROL_BYTES
        + 2 * banner_row_bytes(all_cols)
        + FRAME_CONTROL_BYTES
}

fn banner_row_bytes(cols: usize) -> usize {
    cols + BANNER_ROW_TEXT_BYTES + ROW_CONTROL_BYTES
}

fn clamped(size: TerminalSize) -> (usize, usize) {
    (
        usize::from(size.rows.min(MAX_ROWS)),
        usize::from(size.cols.min(MAX_COLS)),
    )
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
struct Pos {
    item: EntryId,
    row: u32,
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Scroll {
    Up(u32),
    Down(u32),
    PageUp,
    PageDown,
    Top,
    Bottom,
}

/// Where the conversation region looks: following the newest row, or held at a
/// row while new output arrives below it.
#[derive(Debug, Default)]
pub struct Viewport {
    anchor: Option<Pos>,
    width: u16,
    height: u16,
}

impl Viewport {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn following(&self) -> bool {
        self.anchor.is_none()
    }

    /// Scrolls for the conversation keys of §7; false for any other key.
    pub fn key(&mut self, conv: &mut Conversation, key: &Key) -> bool {
        let by = match key {
            Key::Up => Scroll::Up(1),
            Key::Down => Scroll::Down(1),
            Key::PageUp => Scroll::PageUp,
            Key::PageDown => Scroll::PageDown,
            Key::Home => Scroll::Top,
            Key::End => Scroll::Bottom,
            _ => return false,
        };
        self.scroll(conv, by);
        true
    }

    /// Scrolls by rows of the last composed frame's conversation region.
    pub fn scroll(&mut self, conv: &mut Conversation, by: Scroll) {
        let (width, height) = (self.width, u32::from(self.height));
        match by {
            Scroll::Bottom => self.anchor = None,
            Scroll::Top => {
                self.anchor = conv.first_item().map(|item| Pos { item, row: 0 });
            }
            _ if height == 0 => return,
            Scroll::Up(n) => self.anchor = self.top(conv).map(|top| up(conv, width, top, n)),
            Scroll::PageUp => {
                self.anchor = self.top(conv).map(|top| up(conv, width, top, height));
            }
            Scroll::Down(n) => self.anchor = self.top(conv).map(|top| down(conv, width, top, n)),
            Scroll::PageDown => {
                self.anchor = self.top(conv).map(|top| down(conv, width, top, height));
            }
        }
        if let Some(anchor) = self.anchor {
            if !overflows(conv, width, anchor, height) {
                self.anchor = None;
            }
        }
    }

    /// The first row on screen: the held row, still valid, or the one that
    /// shows the newest row last.
    fn top(&mut self, conv: &mut Conversation) -> Option<Pos> {
        let (width, height) = (self.width, u32::from(self.height));
        if let Some(anchor) = self.anchor {
            let anchor = if conv.has_item(anchor.item) {
                let rows = conv.item_rows(anchor.item, width);
                Pos {
                    item: anchor.item,
                    row: anchor.row.min(rows.saturating_sub(1)),
                }
            } else {
                Pos {
                    item: conv.first_item()?,
                    row: 0,
                }
            };
            if overflows(conv, width, anchor, height) {
                self.anchor = Some(anchor);
                return Some(anchor);
            }
            self.anchor = None;
        }
        let last = conv.last_item()?;
        let bottom = Pos {
            item: last,
            row: conv.item_rows(last, width).saturating_sub(1),
        };
        Some(up(conv, width, bottom, height.saturating_sub(1)))
    }
}

fn up(conv: &mut Conversation, width: u16, mut pos: Pos, mut n: u32) -> Pos {
    loop {
        if n <= pos.row {
            pos.row -= n;
            return pos;
        }
        n -= pos.row + 1;
        match conv.prev_item(pos.item) {
            Some(prev) => {
                pos = Pos {
                    item: prev,
                    row: conv.item_rows(prev, width).saturating_sub(1),
                };
            }
            None => {
                pos.row = 0;
                return pos;
            }
        }
    }
}

fn down(conv: &mut Conversation, width: u16, mut pos: Pos, mut n: u32) -> Pos {
    loop {
        let rows = conv.item_rows(pos.item, width);
        if pos.row + n < rows {
            pos.row += n;
            return pos;
        }
        n -= rows - pos.row;
        match conv.next_item(pos.item) {
            Some(next) => pos = Pos { item: next, row: 0 },
            None => {
                pos.row = rows.saturating_sub(1);
                return pos;
            }
        }
    }
}

/// Whether more than `height` rows run from `pos` to the end.
fn overflows(conv: &mut Conversation, width: u16, pos: Pos, height: u32) -> bool {
    let mut count = conv.item_rows(pos.item, width).saturating_sub(pos.row);
    let mut item = pos.item;
    while count <= height {
        match conv.next_item(item) {
            Some(next) => {
                count += conv.item_rows(next, width);
                item = next;
            }
            None => return false,
        }
    }
    true
}

pub struct ScreenState<'a> {
    pub banner: Option<&'a BannerSpec>,
    pub header: &'a HeaderLine,
    pub conversation: &'a mut Conversation,
    pub viewport: &'a mut Viewport,
    /// One line per open task; past three, the rest are counted.
    pub status: &'a [String],
    pub editor: &'a Editor,
    pub menu: &'a [MenuItem],
}

/// What a frame put on screen, for the caller to act on once it is written.
#[derive(Clone, PartialEq, Eq, Debug, Default)]
pub struct Drawn {
    /// The entries with a cell on every one of their rows on screen, as runs of
    /// consecutive ids.
    pub seen: Vec<RangeInclusive<EntryId>>,
    /// The rows on screen of each entry only partly on screen.
    pub rows: Vec<(EntryId, Range<u32>)>,
    pub width: u16,
    pub new_below: u32,
    pub too_small: bool,
}

impl Drawn {
    /// Records in `conv` what this frame showed, once it is written.
    pub fn mark(&self, conv: &mut Conversation) {
        if self.width == 0 {
            return;
        }
        conv.drawn_at(self.width);
        for ids in &self.seen {
            conv.mark_seen(ids.clone());
        }
        for (id, rows) in &self.rows {
            conv.mark_rows(*id, self.width, rows.clone());
        }
    }
}

/// Composes one frame into `out`, which holds at least
/// [`frame_capacity`]`(size)` and is never grown.
pub fn compose(
    state: &mut ScreenState<'_>,
    size: TerminalSize,
    out: &mut Zeroizing<Vec<u8>>,
) -> Result<Drawn, FrameError> {
    out.zeroize();
    let drawn = frame(state, size, &mut Out { buf: out });
    if drawn.is_err() {
        out.zeroize();
    }
    drawn
}

fn frame(
    state: &mut ScreenState<'_>,
    size: TerminalSize,
    out: &mut Out<'_>,
) -> Result<Drawn, FrameError> {
    let window = Window {
        rows: usize::from(size.rows),
        cols: usize::from(size.cols),
    };
    out.put(b"\x1b[?2026h")?;
    let drawn = if window.rows == 0 || window.cols == 0 {
        Drawn {
            too_small: true,
            ..Drawn::default()
        }
    } else {
        let (rows, cols) = clamped(size);
        layout(state, window, rows, cols, out)?
    };
    out.put(b"\x1b[?2026l")?;
    Ok(drawn)
}

/// The real window: the banners use all of it, the rest of the frame at most
/// [`MAX_ROWS`] by [`MAX_COLS`] of it.
#[derive(Clone, Copy)]
struct Window {
    rows: usize,
    cols: usize,
}

struct Out<'a> {
    buf: &'a mut Vec<u8>,
}

impl Out<'_> {
    fn put(&mut self, bytes: &[u8]) -> Result<(), FrameError> {
        if self.buf.capacity() - self.buf.len() < bytes.len() {
            return Err(FrameError::Overflow);
        }
        self.buf.extend_from_slice(bytes);
        Ok(())
    }

    fn num(&mut self, n: usize) -> Result<(), FrameError> {
        let mut digits = [0u8; 20];
        let mut at = digits.len();
        let mut n = n;
        loop {
            at -= 1;
            digits[at] = b'0' + (n % 10) as u8;
            n /= 10;
            if n == 0 {
                break;
            }
        }
        self.put(&digits[at..])
    }

    fn cup(&mut self, row: usize, col: usize) -> Result<(), FrameError> {
        self.put(b"\x1b[")?;
        self.num(row)?;
        self.put(b";")?;
        self.num(col)?;
        self.put(b"H")
    }

    fn row(&mut self, row: usize) -> Result<(), FrameError> {
        self.cup(row, 1)?;
        self.put(b"\x1b[K")
    }

    fn len(&self) -> usize {
        self.buf.len()
    }

    fn wipe_from(&mut self, at: usize) {
        self.buf[at..].fill(0);
        self.buf.truncate(at);
    }
}

/// Ends a row cut short by its byte budget.
const CUT: &str = "…";

/// One row's writing: columns and bytes it has left.
struct Line<'o, 'b> {
    out: &'o mut Out<'b>,
    cols: usize,
    bytes: usize,
    cell: Option<(usize, usize)>,
    cut: bool,
    wrote: bool,
}

impl<'o, 'b> Line<'o, 'b> {
    fn new(out: &'o mut Out<'b>, cols: usize) -> Self {
        Self::with_bytes(out, cols, cols * CELL_BYTES)
    }

    /// `bytes` includes the room [`CUT`] needs.
    fn with_bytes(out: &'o mut Out<'b>, cols: usize, bytes: usize) -> Self {
        Self {
            out,
            cols,
            bytes: bytes.saturating_sub(CUT.len()),
            cell: None,
            cut: false,
            wrote: false,
        }
    }

    /// Writes what fits of `chars`. Stops at a character wider than the
    /// columns left; past the byte budget, ends the row at its last whole cell
    /// with [`CUT`].
    fn chars(&mut self, chars: impl Iterator<Item = char>) -> Result<(), FrameError> {
        let mut buf = [0; DISPLAY_PIECE_MAX];
        for c in chars {
            if self.cut {
                return Ok(());
            }
            let (piece, width) = screen_piece(c, &mut buf);
            if width == 0 && self.cell.is_none() {
                continue;
            }
            if width > self.cols {
                return Ok(());
            }
            if piece.len() > self.bytes {
                return self.cut_at_last_whole_cell(width == 0);
            }
            if width > 0 {
                self.cell = Some((self.out.len(), width));
            }
            self.out.put(piece.as_bytes())?;
            self.cols -= width;
            self.bytes -= piece.len();
            self.wrote = true;
        }
        Ok(())
    }

    fn cut_at_last_whole_cell(&mut self, cell_is_partial: bool) -> Result<(), FrameError> {
        self.cut = true;
        if let Some((at, width)) = self.cell.filter(|_| cell_is_partial) {
            self.cols += width;
            self.out.wipe_from(at);
        }
        if let Some(cols) = self.cols.checked_sub(1) {
            self.out.put(CUT.as_bytes())?;
            self.cols = cols;
            self.wrote = true;
        }
        Ok(())
    }

    fn text(&mut self, text: &str) -> Result<(), FrameError> {
        self.chars(text.chars())
    }

    fn spaces(&mut self, n: usize) -> Result<(), FrameError> {
        self.chars(std::iter::repeat_n(' ', n))
    }
}

/// What the composer writes for `c`, and its columns. Unlike the stored
/// form, a line break is escaped too: no row ever writes one.
fn screen_piece(c: char, buf: &mut [u8; DISPLAY_PIECE_MAX]) -> (&str, usize) {
    if c == '\n' {
        return ("\\u{000a}", 8);
    }
    let piece = display_piece(c, buf);
    if maknae_proto::is_display_unsafe(c) {
        (piece, piece.len())
    } else {
        (piece, c.width().unwrap_or(0))
    }
}

fn text_width(text: &str) -> usize {
    let mut buf = [0; DISPLAY_PIECE_MAX];
    text.chars().map(|c| screen_piece(c, &mut buf).1).sum()
}

fn status_rows(status: &[String]) -> usize {
    status.len().min(STATUS_ROWS_MAX) + usize::from(status.len() > STATUS_ROWS_MAX)
}

fn banner_row(out: &mut Out<'_>, banner: &BannerSpec, cols: usize) -> Result<(), FrameError> {
    let basic = |n: u8| [0x1b, b'[', b'4', b'0' + n, b'm'];
    match banner.color {
        None => out.put(b"\x1b[7m")?,
        Some(BannerColor::Rgb(r, g, b)) => {
            out.put(b"\x1b[48;2;")?;
            out.num(r.into())?;
            out.put(b";")?;
            out.num(g.into())?;
            out.put(b";")?;
            out.num(b.into())?;
            out.put(b"m")?;
        }
        Some(BannerColor::Black) => out.put(&basic(0))?,
        Some(BannerColor::Red) => out.put(&basic(1))?,
        Some(BannerColor::Green) => out.put(&basic(2))?,
        Some(BannerColor::Yellow) => out.put(&basic(3))?,
        Some(BannerColor::Blue) => out.put(&basic(4))?,
        Some(BannerColor::Magenta) => out.put(&basic(5))?,
        Some(BannerColor::Cyan) => out.put(&basic(6))?,
        Some(BannerColor::White) => out.put(&basic(7))?,
    }
    match banner.color.map(BannerColor::contrast) {
        Some(Contrast::BlackText) => out.put(b"\x1b[30m")?,
        Some(Contrast::WhiteText) => out.put(b"\x1b[97m")?,
        None => {}
    }
    let width = text_width(&banner.text);
    let left = cols.saturating_sub(width) / 2;
    let mut line = Line::with_bytes(out, cols, cols + BANNER_ROW_TEXT_BYTES);
    line.spaces(left)?;
    line.text(&banner.text)?;
    let rest = line.cols;
    line.spaces(rest)?;
    out.put(b"\x1b[0m")
}

fn layout(
    state: &mut ScreenState<'_>,
    window: Window,
    rows: usize,
    cols: usize,
    out: &mut Out<'_>,
) -> Result<Drawn, FrameError> {
    let banner = state.banner;
    let banner_rows = if banner.is_some() { 2 } else { 0 };
    let banner_fits = banner.is_none_or(|b| text_width(&b.text) + BANNER_MARGINS <= window.cols);
    let status_rows = status_rows(state.status);
    let fixed = banner_rows + 1 + status_rows;
    if !banner_fits || rows < fixed + MIN_CONVERSATION_ROWS + 1 {
        return too_small(
            banner.filter(|_| banner_fits && rows >= 3),
            window,
            cols,
            out,
        );
    }

    let text = state.editor.text();
    let cursor = state.editor.cursor();
    let input_width = cols.saturating_sub(PROMPT.len()).max(1);
    let mut input = Vec::new();
    rows_for(
        text,
        u16::try_from(input_width).unwrap_or(u16::MAX),
        &mut input,
    );
    let cursor_row = input.iter().rposition(|r| r.start <= cursor).unwrap_or(0);
    let spare = rows - fixed - MIN_CONVERSATION_ROWS;
    let input_rows = input.len().min(INPUT_ROWS_MAX).min(spare);
    let input_top = cursor_row.saturating_sub(input_rows - 1);
    let menu_rows = state.menu.len().min(MENU_ROWS_MAX).min(spare - input_rows);
    let conversation_rows = rows - fixed - menu_rows - input_rows;

    let width = u16::try_from(cols).unwrap_or(u16::MAX);
    state.viewport.width = width;
    state.viewport.height = u16::try_from(conversation_rows).unwrap_or(u16::MAX);
    let mut visible = Vec::new();
    if let Some(mut pos) = state.viewport.top(state.conversation) {
        let mut spans = Vec::new();
        loop {
            let item_rows = state.conversation.item_rows(pos.item, width);
            let left = u32::try_from(conversation_rows - visible.len()).unwrap_or(u32::MAX);
            let take = item_rows.saturating_sub(pos.row).min(left);
            state
                .conversation
                .rows_of(pos.item, width, pos.row..pos.row + take, &mut spans);
            visible.extend(
                (pos.row..)
                    .zip(&spans)
                    .map(|(r, span)| (pos.item, r, *span)),
            );
            if visible.len() == conversation_rows {
                break;
            }
            match state.conversation.next_item(pos.item) {
                Some(next) => pos = Pos { item: next, row: 0 },
                None => break,
            }
        }
    }
    let new_below = visible
        .iter()
        .rev()
        .map(|(item, _, _)| *item)
        .find(|item| *item != EntryId::DROPPED_NOTICE)
        .map_or(0, |last| state.conversation.unseen_after(last));

    let mut row = 1;
    if let Some(banner) = banner {
        out.row(row)?;
        banner_row(out, banner, window.cols)?;
        row += 1;
    }
    out.row(row)?;
    header_row(out, state.header, new_below, cols)?;
    row += 1;
    let mut runs: Vec<(EntryId, Range<u32>)> = Vec::new();
    for at in 0..conversation_rows {
        out.row(row)?;
        if let Some(&(item, item_row, span)) = visible.get(at) {
            let mut line = Line::new(out, cols);
            line.chars(state.conversation.chars_of(item, span))?;
            if item != EntryId::DROPPED_NOTICE && (line.wrote || span.start == span.end) {
                match runs.last_mut() {
                    Some((id, rows)) if *id == item && rows.end == item_row => rows.end += 1,
                    _ => runs.push((item, item_row..item_row + 1)),
                }
            }
        }
        row += 1;
    }
    let mut seen: Vec<RangeInclusive<EntryId>> = Vec::new();
    let mut partly = Vec::new();
    for (item, rows) in runs {
        if rows.start > 0 || rows.end < state.conversation.item_rows(item, width) {
            partly.push((item, rows));
            continue;
        }
        match seen.last_mut() {
            Some(run) if run.end().get() + 1 == item.get() => *run = *run.start()..=item,
            _ => seen.push(item..=item),
        }
    }
    for line in state.status.iter().take(STATUS_ROWS_MAX) {
        out.row(row)?;
        Line::new(out, cols).text(line)?;
        row += 1;
    }
    if state.status.len() > STATUS_ROWS_MAX {
        out.row(row)?;
        let more = format!("+{} more", state.status.len() - STATUS_ROWS_MAX);
        Line::new(out, cols).text(&more)?;
        row += 1;
    }
    for item in state.menu.iter().take(menu_rows) {
        out.row(row)?;
        let mut line = Line::new(out, cols);
        line.text(CONTINUATION)?;
        line.text(&item.name)?;
        line.text(CONTINUATION)?;
        line.text(&item.help)?;
        row += 1;
    }
    let input_first = row;
    for (i, span) in input.iter().enumerate().skip(input_top).take(input_rows) {
        out.row(row)?;
        let mut line = Line::new(out, cols);
        line.text(if i == 0 { PROMPT } else { CONTINUATION })?;
        line.text(&text[span.start..span.end])?;
        row += 1;
    }
    let last_content = if banner.is_some() {
        window.rows - 1
    } else {
        window.rows
    };
    for empty in row..=last_content {
        out.row(empty)?;
    }
    if let Some(banner) = banner {
        out.row(window.rows)?;
        banner_row(out, banner, window.cols)?;
    }

    let span: RowSpan = input[cursor_row];
    let col = PROMPT.len() + text_width(&text[span.start..cursor.max(span.start)]);
    out.cup(input_first + cursor_row - input_top, (col + 1).min(cols))?;
    Ok(Drawn {
        seen,
        rows: partly,
        width,
        new_below,
        too_small: false,
    })
}

fn header_row(
    out: &mut Out<'_>,
    header: &HeaderLine,
    new_below: u32,
    cols: usize,
) -> Result<(), FrameError> {
    let right = match (new_below, header.right.is_empty()) {
        (0, _) => header.right.clone(),
        (n, true) => format!("↓ {n} new"),
        (n, false) => format!("{} · ↓ {n} new", header.right),
    };
    let right_width = text_width(&right);
    let mut line = Line::new(out, cols);
    if right_width < cols {
        line.cols = cols - right_width - 1;
        line.text(&header.left)?;
        line.cols += right_width + 1;
        line.spaces(line.cols - right_width)?;
    }
    line.text(&right)
}

fn too_small(
    banner: Option<&BannerSpec>,
    window: Window,
    cols: usize,
    out: &mut Out<'_>,
) -> Result<Drawn, FrameError> {
    let notice = if banner.is_some() { 2 } else { 1 };
    for row in 1..=window.rows {
        out.row(row)?;
        match banner {
            Some(banner) if row == 1 || row == window.rows => banner_row(out, banner, window.cols)?,
            _ if row == notice => Line::new(out, cols).text(TOO_SMALL)?,
            _ => {}
        }
    }
    out.cup(notice, 1)?;
    Ok(Drawn {
        too_small: true,
        ..Drawn::default()
    })
}

#[cfg(test)]
mod tests {
    use super::super::blocks::EntryKind;
    use super::super::editor::EditOutcome;
    use super::*;
    use maknae_proto::BannerColor;
    use unicode_width::UnicodeWidthChar;

    #[derive(Debug, PartialEq, Eq, Clone)]
    struct Term {
        cells: Vec<Vec<String>>,
        styles: Vec<Vec<String>>,
        cursor: (usize, usize),
    }

    impl Term {
        fn row(&self, r: usize) -> String {
            self.cells[r].concat().trim_end().to_string()
        }
        fn rows(&self) -> Vec<String> {
            (0..self.cells.len()).map(|r| self.row(r)).collect()
        }
    }

    /// A terminal with autowrap off that accepts only the composer's sequences.
    fn emulate(bytes: &[u8], rows: usize, cols: usize) -> Term {
        let text = std::str::from_utf8(bytes).expect("utf-8 frame");
        let mut t = Term {
            cells: vec![vec![String::new(); cols]; rows],
            styles: vec![vec![String::new(); cols]; rows],
            cursor: (0, 0),
        };
        let mut style = String::new();
        let mut erased = vec![false; rows];
        let mut chars = text.chars().peekable();
        let mut last_cell: Option<(usize, usize)> = None;
        let mut began = false;
        while let Some(c) = chars.next() {
            if c == '\u{1b}' {
                assert_eq!(chars.next(), Some('['), "foreign escape");
                let mut seq = String::new();
                loop {
                    let n = chars.next().expect("cut sequence");
                    seq.push(n);
                    if ('\u{40}'..='\u{7e}').contains(&n) {
                        break;
                    }
                }
                match seq.as_str() {
                    "?2026h" => began = true,
                    "?2026l" => assert!(chars.peek().is_none(), "bytes after the frame"),
                    "K" => {
                        let (r, c0) = t.cursor;
                        for c in c0..cols {
                            t.cells[r][c].clear();
                            t.styles[r][c].clear();
                        }
                        erased[r] = true;
                    }
                    "0m" => style.clear(),
                    s if s.ends_with('H') => {
                        let (r, c) = s[..s.len() - 1].split_once(';').unwrap();
                        let (r, c): (usize, usize) = (r.parse().unwrap(), c.parse().unwrap());
                        assert!(r >= 1 && r <= rows && c >= 1 && c <= cols, "{s}");
                        t.cursor = (r - 1, c - 1);
                        last_cell = None;
                    }
                    s if s == "7m"
                        || s == "30m"
                        || s == "97m"
                        || (s.len() == 3 && s.starts_with('4'))
                        || s.starts_with("48;2;") =>
                    {
                        style.push_str(s);
                        style.push('|');
                    }
                    s => panic!("foreign sequence ESC[{s}"),
                }
                continue;
            }
            assert!(began, "text before synchronized output began");
            assert!(!c.is_control(), "raw control {c:?}");
            assert!(!maknae_proto::is_display_unsafe(c), "raw unsafe {c:?}");
            let w = c.width().unwrap_or(0);
            let (r, col) = t.cursor;
            if w == 0 {
                let (lr, lc) = last_cell.expect("a mark with nothing to attach to");
                t.cells[lr][lc].push(c);
                continue;
            }
            assert!(col + w <= cols, "wrote past the row: {c:?} at {r},{col}");
            t.cells[r][col] = c.to_string();
            t.styles[r][col] = style.clone();
            for k in 1..w {
                t.cells[r][col + k] = String::new();
                t.styles[r][col + k] = style.clone();
            }
            last_cell = Some((r, col));
            t.cursor = (r, (col + w).min(cols - 1));
        }
        assert!(erased.iter().all(|e| *e), "a row was never erased");
        t
    }

    struct Fixture {
        banner: Option<BannerSpec>,
        header: HeaderLine,
        conv: Conversation,
        viewport: Viewport,
        status: Vec<String>,
        editor: Editor,
        menu: Vec<MenuItem>,
    }

    impl Fixture {
        fn new(banner: Option<BannerSpec>) -> Self {
            Self {
                banner,
                header: HeaderLine {
                    left: "hobi · connected".into(),
                    right: "2 reports waiting".into(),
                },
                conv: Conversation::new(1 << 20, 4096),
                viewport: Viewport::new(),
                status: Vec::new(),
                editor: Editor::new(256),
                menu: Vec::new(),
            }
        }

        fn frame(&mut self, rows: u16, cols: u16) -> (Vec<u8>, Drawn) {
            let size = TerminalSize { rows, cols };
            let mut out = Zeroizing::new(Vec::with_capacity(frame_capacity(size)));
            let cap = out.capacity();
            let mut state = ScreenState {
                banner: self.banner.as_ref(),
                header: &self.header,
                conversation: &mut self.conv,
                viewport: &mut self.viewport,
                status: &self.status,
                editor: &self.editor,
                menu: &self.menu,
            };
            let drawn = compose(&mut state, size, &mut out).unwrap();
            assert_eq!(out.capacity(), cap);
            drawn.mark(&mut self.conv);
            (out.to_vec(), drawn)
        }

        fn term(&mut self, rows: u16, cols: u16) -> (Term, Drawn) {
            let (bytes, drawn) = self.frame(rows, cols);
            (emulate(&bytes, rows.into(), cols.into()), drawn)
        }

        fn scroll(&mut self, by: Scroll) {
            self.viewport.scroll(&mut self.conv, by);
        }
    }

    fn banner(text: &str, color: Option<BannerColor>) -> BannerSpec {
        BannerSpec {
            text: text.into(),
            color,
        }
    }

    fn centred(text: &str, cols: usize) -> String {
        let left = (cols - text.chars().count()) / 2;
        format!("{}{}", " ".repeat(left), text)
    }

    fn lines(n: usize) -> Fixture {
        let mut f = Fixture::new(Some(banner("UNCLASSIFIED//TEST", Some(BannerColor::Green))));
        for i in 0..n {
            f.conv
                .push(EntryKind::Report, &format!("line {i}"))
                .unwrap();
        }
        f
    }

    #[test]
    fn the_layout_puts_each_region_on_its_rows() {
        let mut f = lines(30);
        f.status = vec!["⠋ #1 working 0:42".into()];
        for c in "hello".chars() {
            f.editor.apply(&Key::Char(c));
        }
        let (t, drawn) = f.term(12, 40);
        let rows = t.rows();
        assert_eq!(rows[0], centred("UNCLASSIFIED//TEST", 40));
        assert_eq!(
            rows[1],
            format!(
                "hobi · connected{}2 reports waiting",
                " ".repeat(40 - 16 - 17)
            )
        );
        assert_eq!(
            &rows[2..9],
            ["line 23", "line 24", "line 25", "line 26", "line 27", "line 28", "line 29"]
        );
        assert_eq!(rows[9], "⠋ #1 working 0:42");
        assert_eq!(rows[10], "> hello");
        assert_eq!(rows[11], rows[0]);
        assert_eq!(t.cursor, (10, 7));
        let first = f.conv.first().unwrap().get();
        assert_eq!(
            drawn.seen,
            [EntryId::nth(first + 23)..=EntryId::nth(first + 29)]
        );
        assert_eq!(drawn.new_below, 0);
        assert!(!drawn.too_small);
    }

    #[test]
    fn a_coloured_banner_fills_its_row_with_contrasting_text_and_none_is_reverse() {
        for (color, want) in [
            (Some(BannerColor::Red), "41|97|"),
            (Some(BannerColor::Yellow), "43|30|"),
            (Some(BannerColor::Black), "40|97|"),
            (Some(BannerColor::White), "47|30|"),
            (
                Some(BannerColor::Rgb(255, 255, 255)),
                "48;2;255;255;255|30|",
            ),
            (Some(BannerColor::Rgb(0, 0, 128)), "48;2;0;0;128|97|"),
            (None, "7m|"),
        ] {
            let mut f = Fixture::new(Some(banner("CUI", color)));
            let (t, _) = f.term(10, 20);
            let want = want.replace('|', "m|").replace("mm|", "m|");
            for r in [0, 9] {
                assert!(
                    t.styles[r].iter().all(|s| *s == want),
                    "{color:?} {:?}",
                    t.styles[r]
                );
            }
            assert!(t.styles[1].iter().all(String::is_empty));
        }
    }

    #[test]
    fn banners_are_rows_one_and_n_through_any_scroll() {
        let mut f = lines(200);
        let (first, _) = f.term(20, 40);
        let want = centred("UNCLASSIFIED//TEST", 40);
        let mut seen_rows = Vec::new();
        for by in [
            Scroll::Up(1),
            Scroll::PageUp,
            Scroll::Up(57),
            Scroll::Top,
            Scroll::Up(3),
            Scroll::Down(2),
            Scroll::PageDown,
            Scroll::Bottom,
        ] {
            f.scroll(by);
            let (t, _) = f.term(20, 40);
            assert_eq!(t.row(0), want, "{by:?}");
            assert_eq!(t.row(19), want, "{by:?}");
            assert_eq!(t.styles[0], first.styles[0]);
            assert_eq!(t.styles[19], first.styles[19]);
            seen_rows.push(t.row(2));
        }
        assert_eq!(seen_rows[3], "line 0");
        assert_eq!(seen_rows[4], "line 0");
        assert_eq!(seen_rows[5], "line 2");
        assert_eq!(seen_rows[7], first.row(2));
        assert_ne!(seen_rows[0], first.row(2));
    }

    #[test]
    fn hostile_report_text_cannot_move_the_cursor_or_forge_the_banner() {
        let text = "UNCLASSIFIED//TEST";
        let mut clean = lines(3);
        let mut hostile = lines(3);
        let forged = format!(
            "\u{1b}[1;1H\u{1b}[2J\u{202e}{text}\u{1b}[0m\u{9b}31m\n{}\n\u{2028}x",
            centred(text, 40)
        );
        hostile.conv.push(EntryKind::Report, &forged).unwrap();
        let (bytes, _) = hostile.frame(12, 40);
        let (clean_bytes, _) = clean.frame(12, 40);
        let t = emulate(&bytes, 12, 40);
        let c = emulate(&clean_bytes, 12, 40);
        let esc_count = |b: &[u8]| b.iter().filter(|&&x| x == 0x1b).count();
        assert_eq!(esc_count(&bytes), esc_count(&clean_bytes));
        for r in [0, 11] {
            assert_eq!(t.cells[r], c.cells[r]);
            assert_eq!(t.styles[r], c.styles[r]);
        }
        let shown = t.rows()[2..10].join("");
        assert!(
            shown.contains("\\u{001b}[1;1H\\u{001b}[2J\\u{202e}UNCLASSIFIED//TEST"),
            "{shown}"
        );
        assert!(shown.contains("\\u{009b}31m"), "{shown}");
        assert!(shown.contains("\\u{2028}x"), "{shown}");
        for r in 2..10 {
            assert!(t.styles[r].iter().all(String::is_empty), "row {r} styled");
        }
    }

    #[test]
    fn hostile_header_status_and_menu_text_is_escaped_too() {
        let mut f = lines(1);
        f.header.left = "\u{1b}[2Jagent".into();
        f.header.right = "\u{202e}".into();
        f.status = vec!["\u{1b}]0;title\u{7}".into()];
        f.menu = vec![MenuItem {
            name: "/x\u{1b}[H".into(),
            help: "\r\n".into(),
        }];
        f.editor.apply(&Key::Char('\u{1b}'));
        let (bytes, _) = f.frame(14, 60);
        let t = emulate(&bytes, 14, 60);
        let all = t.rows().join("\n");
        assert!(all.contains("\\u{001b}[2Jagent"));
        assert!(all.contains("\\u{202e}"));
        assert!(all.contains("\\u{001b}]0;title\\u{0007}"));
        assert!(all.contains("/x\\u{001b}[H"));
        assert!(all.contains("\\u{000d}\\u{000a}"));
        assert!(all.contains("> \\u{001b}"));
        assert_eq!(t.cursor, (12, 10));
    }

    #[test]
    fn shrinking_below_the_minimum_shows_only_the_notice_and_growing_back_restores() {
        let mut f = lines(40);
        f.status = vec!["⠋ #1 working 0:01".into()];
        let (before, _) = f.frame(12, 40);
        let (t, drawn) = f.term(7, 40);
        assert!(drawn.too_small);
        assert!(drawn.seen.is_empty());
        let rows = t.rows();
        assert_eq!(rows[0], centred("UNCLASSIFIED//TEST", 40));
        assert_eq!(rows[6], rows[0]);
        assert_eq!(rows.iter().filter(|r| r.contains(TOO_SMALL)).count(), 1);
        assert!(
            rows[1..6]
                .iter()
                .all(|r| r.is_empty() || r.trim() == TOO_SMALL),
            "{rows:?}"
        );
        let (t, drawn) = f.term(8, 40);
        assert!(!drawn.too_small);
        assert_eq!(t.row(2), "line 37");
        let (t, _) = f.term(2, 40);
        assert_eq!(t.rows(), [TOO_SMALL.to_string(), String::new()]);
        let (t, _) = f.term(1, 10);
        assert_eq!(t.rows(), ["terminal t"]);
        let (after, _) = f.frame(12, 40);
        assert_eq!(after, before);
    }

    #[test]
    fn scrolled_up_new_output_shows_a_count_not_a_jump() {
        let mut f = lines(30);
        f.term(12, 40);
        f.scroll(Scroll::Up(5));
        assert!(!f.viewport.following());
        let (held, _) = f.term(12, 40);
        let id = f.conv.push(EntryKind::Report, "fresh").unwrap();
        f.conv.push(EntryKind::Report, "fresher").unwrap();
        let (t, drawn) = f.term(12, 40);
        assert_eq!(t.rows()[2..9], held.rows()[2..9]);
        assert_eq!(drawn.new_below, 2);
        assert!(
            t.row(1).ends_with("2 reports waiting · ↓ 2 new"),
            "{}",
            t.row(1)
        );
        assert_eq!(f.conv.is_seen(id), Some(false));
        f.scroll(Scroll::Bottom);
        let (t, drawn) = f.term(12, 40);
        assert_eq!(drawn.new_below, 0);
        assert!(t.row(1).ends_with("2 reports waiting"));
        assert_eq!(t.row(9), "fresher");
        f.conv.mark_seen(drawn.seen[0].clone());
        assert_eq!(f.conv.is_seen(id), Some(true));
    }

    #[test]
    fn scrolling_down_to_the_end_resumes_following() {
        let mut f = lines(30);
        f.term(12, 40);
        f.scroll(Scroll::Up(2));
        f.scroll(Scroll::Down(1));
        assert!(!f.viewport.following());
        f.scroll(Scroll::Down(1));
        assert!(f.viewport.following());
        f.scroll(Scroll::Down(1));
        assert!(f.viewport.following());
        f.scroll(Scroll::Top);
        assert!(!f.viewport.following());
        f.scroll(Scroll::Up(4));
        let (t, _) = f.term(12, 40);
        assert_eq!(t.row(2), "line 0");
        let mut short = lines(2);
        short.term(12, 40);
        short.scroll(Scroll::Up(1));
        short.scroll(Scroll::Top);
        assert!(short.viewport.following());
    }

    #[test]
    fn the_scroll_keys_map_to_scrolls_and_others_are_left_alone() {
        let mut f = lines(60);
        f.term(12, 40);
        for key in [Key::Up, Key::PageUp, Key::Home, Key::PageDown, Key::Down] {
            assert!(f.viewport.key(&mut f.conv, &key), "{key:?}");
        }
        assert!(!f.viewport.key(&mut f.conv, &Key::Left));
        assert!(!f.viewport.key(&mut f.conv, &Key::Char('k')));
        assert!(!f.viewport.following());
        let (t, _) = f.term(12, 40);
        assert_eq!(t.row(2), "line 9");
        assert!(f.viewport.key(&mut f.conv, &Key::End));
        assert!(f.viewport.following());
        f.viewport.key(&mut f.conv, &Key::Home);
        f.viewport.key(&mut f.conv, &Key::PageDown);
        let (t, _) = f.term(12, 40);
        assert_eq!(t.row(2), "line 8");
    }

    #[test]
    fn a_banner_wider_than_the_window_shows_too_small_not_a_cut_banner() {
        let text = "SECRET//NOFORN//THIS-IS-LONG-X";
        let mut f = Fixture::new(Some(banner(text, Some(BannerColor::Red))));
        f.conv.push(EntryKind::Report, "report").unwrap();
        let (t, drawn) = f.term(20, 31);
        assert!(drawn.too_small);
        let all = t.rows().join("\n");
        assert!(all.contains(TOO_SMALL));
        assert!(!all.contains("SECRET"), "{all}");
        assert!(!all.contains("report"));
        assert!(t.styles.iter().flatten().all(String::is_empty));
        let (t, drawn) = f.term(20, 32);
        assert!(!drawn.too_small);
        assert_eq!(t.row(0), format!(" {text}"));
    }

    #[test]
    fn no_row_ends_with_a_newline_on_the_last_line() {
        let mut f = lines(30);
        f.editor.apply(&Key::Char('x'));
        for (rows, cols) in [(12, 40), (3, 40), (40, 120), (1, 1)] {
            let (bytes, _) = f.frame(rows, cols);
            assert!(!bytes.contains(&b'\n'), "{rows}x{cols}");
            assert!(!bytes.contains(&b'\r'), "{rows}x{cols}");
            assert!(bytes.starts_with(b"\x1b[?2026h"));
            assert!(bytes.ends_with(b"\x1b[?2026l"));
            let positions = (1..=rows)
                .filter(|r| {
                    let cup = format!("\x1b[{r};1H\x1b[K");
                    bytes
                        .windows(cup.len())
                        .filter(|w| *w == cup.as_bytes())
                        .count()
                        == 1
                })
                .count();
            assert_eq!(positions, usize::from(rows));
        }
    }

    #[test]
    fn status_lines_stop_at_three_and_count_the_rest() {
        let mut f = lines(30);
        f.status = (1..=5).map(|i| format!("#{i} working")).collect();
        let (t, _) = f.term(16, 40);
        let rows = t.rows();
        assert_eq!(
            &rows[10..14],
            ["#1 working", "#2 working", "#3 working", "+2 more"]
        );
        assert_eq!(rows[14], ">");
        f.status.truncate(3);
        let (t, _) = f.term(16, 40);
        assert_eq!(
            &t.rows()[11..15],
            ["#1 working", "#2 working", "#3 working", ">"]
        );
    }

    #[test]
    fn the_input_grows_to_three_rows_and_keeps_the_cursor_in_view() {
        let mut f = lines(30);
        for c in "one\ntwo\nthree\nfour".chars() {
            let key = if c == '\n' { Key::CtrlJ } else { Key::Char(c) };
            f.editor.apply(&key);
        }
        let (t, _) = f.term(14, 40);
        let rows = t.rows();
        assert_eq!(&rows[10..13], ["  two", "  three", "  four"]);
        assert_eq!(t.cursor, (12, 6));
        for _ in 0..12 {
            f.editor.apply(&Key::Left);
        }
        let (t, _) = f.term(14, 40);
        assert_eq!(&t.rows()[10..13], ["> one", "  two", "  three"]);
        assert_eq!(t.cursor, (11, 4));
        let mut wide = lines(1);
        for _ in 0..25 {
            wide.editor.apply(&Key::Char('가'));
        }
        let (t, _) = wide.term(12, 20);
        assert_eq!(
            &t.rows()[8..11],
            [
                "> 가가가가가가가가가",
                "  가가가가가가가가가",
                "  가가가가가가가"
            ]
        );
        assert_eq!(t.cursor, (10, 16));
    }

    #[test]
    fn the_slash_menu_sits_above_the_input() {
        let mut f = lines(30);
        f.menu = ["/stop", "/status"]
            .iter()
            .map(|n| MenuItem {
                name: (*n).into(),
                help: "do it".into(),
            })
            .collect();
        f.editor.apply(&Key::Char('/'));
        let (t, _) = f.term(14, 40);
        let rows = t.rows();
        assert_eq!(&rows[10..13], ["  /stop  do it", "  /status  do it", "> /"]);
        f.menu = (0..9)
            .map(|i| MenuItem {
                name: format!("/c{i}"),
                help: String::new(),
            })
            .collect();
        let (t, _) = f.term(20, 40);
        assert_eq!(t.rows().iter().filter(|r| r.starts_with("  /c")).count(), 5);
        let (t, _) = f.term(9, 40);
        assert_eq!(t.rows().iter().filter(|r| r.starts_with("  /c")).count(), 2);
        let (t, _) = f.term(8, 40);
        assert_eq!(t.rows().iter().filter(|r| r.starts_with("  /c")).count(), 1);
    }

    #[test]
    fn the_dropped_notice_heads_the_conversation_once_output_is_dropped() {
        let mut f = Fixture::new(None);
        f.conv = Conversation::new(64 * 3, 64);
        let a = f.conv.push(EntryKind::Report, &"a".repeat(64)).unwrap();
        f.conv.mark_seen(a..=a);
        for i in 0..2 {
            let id = f
                .conv
                .push(EntryKind::Report, &format!("{i}").repeat(64))
                .unwrap();
            f.conv.mark_seen(id..=id);
        }
        f.conv.push(EntryKind::Report, "new").unwrap();
        assert!(f.conv.dropped_earlier());
        f.scroll(Scroll::Top);
        let (t, drawn) = f.term(30, 80);
        assert_eq!(t.row(1), crate::screen::blocks::EARLIER_OUTPUT_DROPPED);
        assert_eq!(t.row(2), "0".repeat(64));
        assert_eq!(drawn.seen.first().map(|r| r.start().get()), Some(2));
    }

    #[test]
    fn a_wide_character_that_does_not_fit_the_row_is_not_written() {
        let mut f = Fixture::new(None);
        f.conv.push(EntryKind::Report, "가").unwrap();
        f.header = HeaderLine::default();
        let (t, _) = f.term(6, 1);
        assert_eq!(t.row(1), "");
    }

    fn worst_case(rows: u16, cols: u16) -> Fixture {
        let cell = "𝐀\u{1d167}\u{1d167}\u{1d167}";
        let mut f = Fixture::new(Some(banner(
            &"𝐀".repeat(64),
            Some(BannerColor::Rgb(255, 255, 255)),
        )));
        f.conv = Conversation::new(1 << 24, 1 << 16);
        let line = cell.repeat(usize::from(cols) + 3);
        for _ in 0..rows {
            f.conv.push(EntryKind::Report, &line).unwrap();
        }
        f.header = HeaderLine {
            left: line.clone(),
            right: line.clone(),
        };
        f.status = vec![line.clone(); 5];
        f.menu = vec![
            MenuItem {
                name: line.clone(),
                help: line.clone(),
            };
            5
        ];
        f.editor = Editor::new(1 << 16);
        f.editor.apply(&Key::Char('/'));
        for c in line.chars().take(usize::from(cols) * 12) {
            assert!(!matches!(f.editor.apply(&Key::Char(c)), EditOutcome::Full));
        }
        f
    }

    #[test]
    fn the_worst_case_frame_fits_its_capacity_without_growing() {
        for (rows, cols) in [(40, 200), (12, 80), (11, 66)] {
            let mut f = worst_case(rows, cols);
            let (bytes, drawn) = f.frame(rows, cols);
            assert!(!drawn.too_small);
            assert!(bytes.len() <= frame_capacity(TerminalSize { rows, cols }));
            emulate(&bytes, rows.into(), cols.into());
        }
    }

    #[test]
    fn the_oversize_worst_case_frame_fits_its_capacity_without_growing() {
        let (rows, cols) = (600u16, 1100u16);
        let mut f = worst_case(0, cols);
        let hostile = format!("{}{}", "\u{1b}".repeat(128), "𝐀".repeat(32));
        assert_eq!(hostile.len(), maknae_proto::BANNER_TEXT_MAX);
        f.banner = Some(banner(&hostile, Some(BannerColor::Rgb(1, 2, 3))));
        let big = "𝐀\u{1d167}\u{1d167}\u{1d167}".repeat(usize::from(MAX_COLS) * 520);
        f.conv.push(EntryKind::Report, &big).unwrap();
        f.conv
            .push(EntryKind::Report, &format!("a{}", "\u{301}".repeat(5000)))
            .unwrap();
        let size = TerminalSize { rows, cols };
        let mut out = Zeroizing::new(Vec::with_capacity(frame_capacity(size)));
        let (cap, ptr) = (out.capacity(), out.as_ptr());
        let mut state = ScreenState {
            banner: f.banner.as_ref(),
            header: &f.header,
            conversation: &mut f.conv,
            viewport: &mut f.viewport,
            status: &f.status,
            editor: &f.editor,
            menu: &f.menu,
        };
        let drawn = compose(&mut state, size, &mut out).unwrap();
        assert!(!drawn.too_small);
        assert_eq!(out.capacity(), cap);
        assert_eq!(out.as_ptr(), ptr);
        assert!(out.len() <= cap);
        let shown = rows_by_position(&out);
        assert_eq!(shown.len(), usize::from(rows));
        let banner_row = &shown[&1];
        assert_eq!(banner_row.chars().count(), usize::from(cols));
        assert!(banner_row.contains("\\u{001b}𝐀"));
        assert_eq!(shown[&usize::from(rows)], *banner_row);
        assert!(shown.values().any(|r| r.ends_with('…')));
    }

    #[test]
    fn a_buffer_below_the_capacity_is_refused_not_grown() {
        let mut f = worst_case(12, 80);
        let size = TerminalSize { rows: 12, cols: 80 };
        let mut out = Zeroizing::new(Vec::with_capacity(512));
        let cap = out.capacity();
        let ptr = out.as_ptr();
        let mut state = ScreenState {
            banner: f.banner.as_ref(),
            header: &f.header,
            conversation: &mut f.conv,
            viewport: &mut f.viewport,
            status: &f.status,
            editor: &f.editor,
            menu: &f.menu,
        };
        assert_eq!(
            compose(&mut state, size, &mut out),
            Err(FrameError::Overflow)
        );
        assert!(out.is_empty(), "a cut-short frame survived");
        assert_eq!(out.capacity(), cap);
        assert_eq!(out.as_ptr(), ptr);
    }

    /// Each row's text as written after its position, styles dropped.
    fn rows_by_position(bytes: &[u8]) -> std::collections::BTreeMap<usize, String> {
        let text = std::str::from_utf8(bytes).unwrap();
        let mut rows = std::collections::BTreeMap::new();
        let mut row = 0;
        let mut chars = text.chars();
        while let Some(c) = chars.next() {
            if c != '\u{1b}' {
                rows.entry(row).or_insert_with(String::new).push(c);
                continue;
            }
            assert_eq!(chars.next(), Some('['));
            let mut seq = String::new();
            for n in chars.by_ref() {
                seq.push(n);
                if ('\u{40}'..='\u{7e}').contains(&n) {
                    break;
                }
            }
            if let Some(pos) = seq.strip_suffix('H') {
                let (r, c) = pos.split_once(';').unwrap();
                if c == "1" {
                    row = r.parse().unwrap();
                    rows.entry(row).or_insert_with(String::new);
                }
            }
        }
        rows
    }

    #[test]
    fn banners_hold_rows_one_and_n_on_a_window_larger_than_the_clamp() {
        let mut f = lines(40);
        let (bytes, drawn) = f.frame(2000, 3000);
        assert!(!drawn.too_small);
        let rows = rows_by_position(&bytes);
        assert_eq!(
            rows.keys().copied().collect::<Vec<_>>(),
            (1..=2000).collect::<Vec<_>>()
        );
        let text = "UNCLASSIFIED//TEST";
        let left = (3000 - text.len()) / 2;
        let want = format!(
            "{}{text}{}",
            " ".repeat(left),
            " ".repeat(3000 - left - text.len())
        );
        assert_eq!(rows[&1], want);
        assert_eq!(rows[&2000], want);
        let bottom = b"\x1b[2000;1H\x1b[K\x1b[42m";
        assert!(bytes.windows(bottom.len()).any(|w| w == bottom));
        assert_eq!(rows[&3], "line 0");
        assert!((usize::from(MAX_ROWS)..2000).all(|r| rows[&r].is_empty()));
        assert!(rows
            .iter()
            .filter(|(r, _)| ![1, 2000].contains(*r))
            .all(|(_, t)| t.chars().count() <= usize::from(MAX_COLS)));

        let (t, _) = f.term(40, 1100);
        assert_eq!(t.row(0), centred(text, 1100));
        assert_eq!(t.row(39), t.row(0));
        assert!(t.styles[39].iter().all(|s| s == "42m|30m|"));
        assert!((2..39).all(|r| t.cells[r][usize::from(MAX_COLS)..]
            .iter()
            .all(String::is_empty)));
    }

    #[test]
    fn the_capacity_covers_the_clamped_content_and_full_width_banners() {
        let at = |rows, cols| frame_capacity(TerminalSize { rows, cols });
        let banner = 20 + BANNER_ROW_TEXT_BYTES + ROW_CONTROL_BYTES;
        assert_eq!(
            at(10, 20),
            10 * (20 * CELL_BYTES + ROW_CONTROL_BYTES) + 2 * banner + FRAME_CONTROL_BYTES
        );
        let wide = usize::from(u16::MAX) + BANNER_ROW_TEXT_BYTES + ROW_CONTROL_BYTES;
        assert_eq!(
            at(u16::MAX, u16::MAX),
            at(MAX_ROWS, MAX_COLS)
                - 2 * (usize::from(MAX_COLS) + BANNER_ROW_TEXT_BYTES + ROW_CONTROL_BYTES)
                + 2 * wide
                + usize::from(u16::MAX - MAX_ROWS) * ROW_CONTROL_BYTES
        );
        assert_eq!(
            at(0, 0),
            2 * (BANNER_ROW_TEXT_BYTES + ROW_CONTROL_BYTES) + FRAME_CONTROL_BYTES
        );
    }

    #[test]
    fn a_row_of_stacked_combining_marks_is_cut_not_overflowed() {
        let mut f = lines(0);
        let zalgo = format!("xyz a{}", "\u{301}".repeat(5000));
        f.conv.push(EntryKind::Report, &zalgo).unwrap();
        f.conv.push(EntryKind::Report, "after").unwrap();
        f.conv
            .push(EntryKind::Report, &format!("b{}c", "\u{302}".repeat(3)))
            .unwrap();
        let (t, drawn) = f.term(12, 40);
        assert_eq!(t.row(2), "xyz …");
        assert_eq!(t.row(3), "after");
        assert_eq!(t.row(4), "b\u{302}\u{302}\u{302}c");
        assert_eq!(drawn.seen.len(), 1);
        let mut tight = lines(0);
        let heavy = format!("a{}", "\u{301}".repeat(30)).repeat(60);
        tight.conv.push(EntryKind::Report, &heavy).unwrap();
        let (t, _) = tight.term(8, 20);
        let row = t.row(2);
        assert!(row.ends_with('…'), "{row}");
        assert!(row.len() <= 20 * CELL_BYTES);
    }

    #[test]
    fn a_report_with_no_cell_on_screen_is_not_marked_seen() {
        let mut f = Fixture::new(None);
        f.header = HeaderLine::default();
        let a = f.conv.push(EntryKind::Report, "a").unwrap();
        let wide = f.conv.push(EntryKind::Report, "가").unwrap();
        let b = f.conv.push(EntryKind::Report, "b").unwrap();
        let empty = f.conv.push(EntryKind::Report, "").unwrap();
        let (t, drawn) = f.term(8, 1);
        assert_eq!(&t.rows()[1..5], ["a", "", "b", ""]);
        assert_eq!(drawn.seen, [a..=a, b..=empty]);
        assert_eq!(f.conv.is_seen(wide), Some(false));
        assert_eq!(f.conv.is_seen(b), Some(true));
    }

    fn tall() -> (Fixture, EntryId) {
        let mut f = lines(0);
        let text = (0..40)
            .map(|i| format!("r{i}"))
            .collect::<Vec<_>>()
            .join("\n");
        let id = f.conv.push(EntryKind::Report, &text).unwrap();
        (f, id)
    }

    #[test]
    fn a_report_taller_than_the_screen_is_seen_only_once_every_row_was_drawn() {
        let (mut f, id) = tall();
        let (t, drawn) = f.term(12, 40);
        assert!(t.rows().iter().any(|r| r == "r39"), "{:?}", t.rows());
        assert!(drawn.seen.is_empty(), "{drawn:?}");
        assert_eq!(f.conv.is_seen(id), Some(false), "only its tail was drawn");
        let mut pages = 0;
        while f.conv.is_seen(id) == Some(false) && pages < 20 {
            f.scroll(Scroll::PageUp);
            f.term(12, 40);
            pages += 1;
        }
        assert_eq!(f.conv.is_seen(id), Some(true));
        assert!(pages > 1, "{pages}");
        f.scroll(Scroll::Bottom);
        f.term(12, 40);
        f.term(12, 30);
        assert_eq!(f.conv.is_seen(id), Some(true), "seen is for good");
    }

    #[test]
    fn rows_skipped_by_a_jump_leave_a_tall_report_unseen() {
        for jump in [Scroll::Top, Scroll::Up(20)] {
            let (mut f, id) = tall();
            f.term(12, 40);
            f.scroll(jump);
            let (t, _) = f.term(12, 40);
            assert!(t.rows().iter().all(|r| r != "r39"));
            assert_eq!(f.conv.is_seen(id), Some(false), "{jump:?}");
        }
    }

    #[test]
    fn a_resize_mid_way_forgets_the_rows_drawn_at_the_old_width() {
        let (mut f, id) = tall();
        f.term(12, 40);
        f.scroll(Scroll::PageUp);
        f.term(12, 40);
        f.scroll(Scroll::PageUp);
        f.term(12, 39);
        for _ in 0..20 {
            f.scroll(Scroll::PageUp);
            f.term(12, 39);
        }
        assert_eq!(
            f.conv.is_seen(id),
            Some(false),
            "the tail was drawn only at the old width"
        );
        for _ in 0..20 {
            f.scroll(Scroll::PageDown);
            f.term(12, 39);
        }
        assert_eq!(f.conv.is_seen(id), Some(true));
    }

    #[test]
    fn frame_error_says_the_frame_does_not_fit() {
        assert_eq!(
            FrameError::Overflow.to_string(),
            "the frame does not fit its buffer"
        );
    }

    #[test]
    fn a_window_with_no_rows_or_no_columns_is_too_small_and_draws_nothing() {
        let mut f = lines(3);
        for (rows, cols) in [(0, 40), (40, 0), (0, 0)] {
            let (bytes, drawn) = f.frame(rows, cols);
            assert_eq!(bytes, b"\x1b[?2026h\x1b[?2026l", "{rows}x{cols}");
            assert!(drawn.too_small, "{rows}x{cols}");
        }
    }

    #[test]
    fn a_buffer_of_exactly_the_frame_length_holds_it() {
        let mut f = lines(3);
        let size = TerminalSize { rows: 12, cols: 40 };
        let (want, _) = f.frame(12, 40);
        for (cap, fits) in [(want.len(), true), (want.len() - 1, false)] {
            let mut out = Zeroizing::new(Vec::with_capacity(cap));
            assert_eq!(out.capacity(), cap);
            let mut state = ScreenState {
                banner: f.banner.as_ref(),
                header: &f.header,
                conversation: &mut f.conv,
                viewport: &mut f.viewport,
                status: &f.status,
                editor: &f.editor,
                menu: &f.menu,
            };
            let drawn = compose(&mut state, size, &mut out);
            assert_eq!(drawn.is_ok(), fits, "{cap}");
            if fits {
                assert_eq!(*out, want);
            }
        }
    }

    fn written(cols: usize, budget: usize, text: &str) -> String {
        let mut buf = Vec::with_capacity(64);
        let mut out = Out { buf: &mut buf };
        Line::with_bytes(&mut out, cols, budget + CUT.len())
            .text(text)
            .unwrap();
        String::from_utf8(buf).unwrap()
    }

    #[test]
    fn a_piece_that_exactly_fills_the_byte_budget_is_written() {
        assert_eq!(written(5, 3, "abc"), "abc");
        assert_eq!(written(5, 3, "abcd"), "abc…");
        assert_eq!(written(5, 3, "ab\u{301}"), "a…");
        assert_eq!(written(5, 6, "ab\u{301}\u{301}c"), "ab\u{301}\u{301}…");
    }

    #[test]
    fn scrolling_before_any_frame_keeps_following() {
        let mut f = lines(30);
        for by in [
            Scroll::Up(1),
            Scroll::PageUp,
            Scroll::Down(1),
            Scroll::PageDown,
        ] {
            f.scroll(by);
            assert!(f.viewport.following(), "{by:?}");
        }
        f.scroll(Scroll::Top);
        assert!(!f.viewport.following());
    }

    #[test]
    fn a_held_row_whose_entry_was_dropped_moves_to_the_oldest_row_left() {
        let mut f = Fixture::new(None);
        f.header = HeaderLine::default();
        f.conv = Conversation::new(64 * 3, 64);
        let ids: Vec<EntryId> = ["a", "b", "c"]
            .iter()
            .map(|t| f.conv.push(EntryKind::Report, &t.repeat(64)).unwrap())
            .collect();
        f.conv.mark_seen(ids[0]..=ids[2]);
        f.term(6, 40);
        f.scroll(Scroll::Top);
        let (t, _) = f.term(6, 40);
        assert_eq!(t.row(1), "a".repeat(40));
        f.conv.push(EntryKind::Report, &"d".repeat(64)).unwrap();
        assert!(!f.conv.has_item(ids[0]));
        let (t, _) = f.term(6, 40);
        assert!(!f.viewport.following());
        assert_eq!(
            &t.rows()[1..5],
            [
                crate::screen::blocks::EARLIER_OUTPUT_DROPPED.to_string(),
                "b".repeat(40),
                "b".repeat(24),
                "c".repeat(40)
            ]
        );
    }

    #[test]
    fn a_held_view_that_a_taller_window_shows_to_the_end_follows_again() {
        let mut f = lines(30);
        f.term(12, 40);
        f.scroll(Scroll::Up(2));
        f.term(12, 40);
        assert!(!f.viewport.following());
        f.term(14, 40);
        assert!(f.viewport.following());
        f.conv.push(EntryKind::Report, "fresh").unwrap();
        let (t, drawn) = f.term(14, 40);
        assert_eq!(t.row(11), "fresh");
        assert_eq!(drawn.new_below, 0);
    }

    #[test]
    fn scrolling_down_from_inside_an_entry_crosses_into_the_next() {
        let mut f = Fixture::new(None);
        f.header = HeaderLine::default();
        for i in 0..10 {
            f.conv
                .push(EntryKind::Report, &format!("a{i}\nb{i}\nc{i}"))
                .unwrap();
        }
        f.term(12, 40);
        f.scroll(Scroll::Up(10));
        let (t, _) = f.term(12, 40);
        assert_eq!(t.row(1), "b3");
        for _ in 0..2 {
            f.conv.push(EntryKind::Report, "x\ny\nz").unwrap();
        }
        let (t, drawn) = f.term(12, 40);
        assert_eq!(t.row(1), "b3");
        assert_eq!(drawn.new_below, 2);
        f.scroll(Scroll::Down(4));
        let (t, _) = f.term(12, 40);
        assert_eq!(t.row(1), "c4");
    }

    #[test]
    fn a_row_with_no_cell_does_not_join_the_previous_entry_run() {
        let mut f = Fixture::new(None);
        f.header = HeaderLine::default();
        let a = f.conv.push(EntryKind::Report, "a").unwrap();
        let wide = f.conv.push(EntryKind::Report, "가\nb").unwrap();
        let (t, drawn) = f.term(8, 1);
        assert_eq!(&t.rows()[1..4], ["a", "", "b"]);
        assert_eq!(drawn.seen, [a..=a]);
        assert_eq!(drawn.rows, [(wide, 1..2)]);
    }

    #[test]
    fn the_header_keeps_a_column_between_its_halves_and_gives_a_full_right_all_of_it() {
        let mut f = lines(1);
        f.banner = None;
        f.header = HeaderLine {
            left: "L".repeat(30),
            right: "R".into(),
        };
        let (t, _) = f.term(8, 20);
        assert_eq!(t.row(0), format!("{} R", "L".repeat(18)));
        f.header.right = "r".repeat(20);
        let (t, _) = f.term(8, 20);
        assert_eq!(t.row(0), "r".repeat(20));
    }

    #[test]
    fn an_unchecked_banner_of_control_characters_is_drawn_escaped() {
        let text = "\u{1}".repeat(maknae_proto::BANNER_TEXT_MAX);
        let mut f = lines(3);
        f.banner = Some(banner(&text, Some(BannerColor::Red)));
        let cols = 8 * maknae_proto::BANNER_TEXT_MAX + 2;
        let (bytes, drawn) = f.frame(12, u16::try_from(cols).unwrap());
        assert!(!drawn.too_small);
        let rows = rows_by_position(&bytes);
        let want = format!(" {} ", "\\u{0001}".repeat(maknae_proto::BANNER_TEXT_MAX));
        assert_eq!(rows[&1], want);
        assert_eq!(rows[&12], want);
    }

    #[test]
    fn an_unchecked_banner_is_drawn_whole_within_its_byte_budget_and_cut_past_it() {
        for (marks, want) in [
            (
                1000,
                format!(
                    "{}A{}{}",
                    " ".repeat(19),
                    "\u{301}".repeat(1000),
                    " ".repeat(20)
                ),
            ),
            (1100, format!("{}…", " ".repeat(19))),
        ] {
            let mut f = lines(3);
            f.banner = Some(banner(
                &format!("A{}", "\u{301}".repeat(marks)),
                Some(BannerColor::Red),
            ));
            let (bytes, drawn) = f.frame(12, 40);
            assert!(!drawn.too_small);
            let rows = rows_by_position(&bytes);
            assert_eq!(rows[&1], want, "{marks}");
            assert_eq!(rows[&12], want, "{marks}");
        }
    }

    #[test]
    fn an_unchecked_multibyte_banner_on_a_wide_window_is_cut_at_its_byte_budget() {
        let mut f = lines(3);
        f.banner = Some(banner(&"€".repeat(2000), Some(BannerColor::Red)));
        let (bytes, drawn) = f.frame(12, 2002);
        assert!(!drawn.too_small);
        let want = format!(" {}…", "€".repeat(1348));
        let rows = rows_by_position(&bytes);
        assert_eq!(rows[&1], want);
        assert_eq!(rows[&12], want);
    }
}
