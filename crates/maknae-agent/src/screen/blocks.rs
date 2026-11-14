use super::fixed::{FixedText, Full};
use super::wrap::{cell_width, RowSpan, Wrapper};
use crate::render::{display_piece, DISPLAY_EXPANSION, DISPLAY_PIECE_MAX};
use std::collections::VecDeque;
use std::ops::{Range, RangeInclusive};

pub const BLOCK_BYTES: usize = 64 * 1024;
pub const EARLIER_OUTPUT_DROPPED: &str = "earlier output dropped";
const CHECKPOINT_ROWS: u32 = 256;
const TAB_STOP: usize = 8;
const TAB_SPACES: &str = "        ";

/// Calls `f` with each piece `text` is stored as: its display piece, or for a
/// tab the spaces to the next stop, counted from the start of its line.
fn stored_pieces(text: &str, mut f: impl FnMut(&str) -> Result<(), Full>) -> Result<(), Full> {
    let mut buf = [0; DISPLAY_PIECE_MAX];
    let mut col = 0;
    for c in text.chars() {
        match c {
            '\t' => {
                let n = TAB_STOP - col % TAB_STOP;
                col += n;
                f(&TAB_SPACES[..n])?;
            }
            '\n' => {
                col = 0;
                f("\n")?;
            }
            _ => {
                col += cell_width(c);
                f(display_piece(c, &mut buf))?;
            }
        }
    }
    Ok(())
}

/// The conversation cap for a host whose prompts are at most `prompt_ceiling`
/// bytes: room for one maximal report and one maximal request, each escaped at
/// the worst expansion, in [`BLOCK_BYTES`] blocks.
pub fn conversation_cap(prompt_ceiling: usize) -> usize {
    let one = blocks_for(
        DISPLAY_EXPANSION.saturating_mul(prompt_ceiling),
        BLOCK_BYTES,
    );
    one.saturating_mul(2)
        .saturating_add(1)
        .saturating_mul(BLOCK_BYTES)
}

/// Blocks needed for `bytes` of escaped text when every block may end in a
/// piece that did not fit.
fn blocks_for(bytes: usize, block_bytes: usize) -> usize {
    bytes.div_ceil(block_bytes - (DISPLAY_PIECE_MAX - 1))
}

#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Debug)]
pub struct EntryId(u64);

impl EntryId {
    /// The `earlier output dropped` line, shown above the oldest entry.
    pub const DROPPED_NOTICE: EntryId = EntryId(0);

    pub fn get(self) -> u64 {
        self.0
    }

    #[cfg(test)]
    pub(crate) fn nth(n: u64) -> EntryId {
        EntryId(n)
    }
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum EntryKind {
    Request,
    Report,
    Notice,
}

struct WrapIndex {
    width: u16,
    rows: u32,
    checkpoints: Vec<usize>,
}

struct Entry {
    id: EntryId,
    kind: EntryKind,
    block: u64,
    offset: usize,
    len: usize,
    seen: bool,
    index: Option<WrapIndex>,
}

/// The conversation's text, escaped as stored, in fixed-size zeroizing blocks
/// allocated as content arrives. Dropping it wipes every block.
pub struct Conversation {
    blocks: VecDeque<FixedText>,
    base: u64,
    block_bytes: usize,
    max_blocks: usize,
    entries: VecDeque<Entry>,
    next_id: u64,
    dropped: bool,
}

impl std::fmt::Debug for Conversation {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Conversation")
            .field("entries", &self.entries.len())
            .field("blocks", &self.blocks.len())
            .field("max_blocks", &self.max_blocks)
            .finish()
    }
}

impl Conversation {
    /// `block_bytes` below [`DISPLAY_PIECE_MAX`] is raised to it, so every
    /// piece fits a block.
    pub fn new(cap_bytes: usize, block_bytes: usize) -> Self {
        let block_bytes = block_bytes.max(DISPLAY_PIECE_MAX);
        Self {
            blocks: VecDeque::new(),
            base: 0,
            block_bytes,
            max_blocks: cap_bytes / block_bytes,
            entries: VecDeque::new(),
            next_id: 1,
            dropped: false,
        }
    }

    pub fn for_prompt_ceiling(prompt_ceiling: usize) -> Self {
        Self::new(conversation_cap(prompt_ceiling), BLOCK_BYTES)
    }

    /// Stores `text` escaped for display, dropping the oldest entries to make
    /// room. `Full`, with nothing changed, when that would drop a report not
    /// yet seen or the text does not fit the cap at all.
    pub fn push(&mut self, kind: EntryKind, text: &str) -> Result<EntryId, Full> {
        let with_tail = self.blocks_needed(text, self.tail_room());
        let fresh = self.blocks_needed(text, 0);
        let drop = self.plan(|all_dropped| if all_dropped { fresh } else { with_tail })?;
        self.drop_oldest(drop);

        let id = EntryId(self.next_id);
        let mut start = None;
        let mut len = 0;
        stored_pieces(text, |piece| {
            if self.tail_room() < piece.len() {
                self.blocks
                    .push_back(FixedText::with_capacity(self.block_bytes));
            }
            let block_index = self.blocks.len() - 1;
            let block = &mut self.blocks[block_index];
            start.get_or_insert((self.base + block_index as u64, block.len()));
            len += piece.len();
            block.push_str(piece)
        })?;
        let (block, offset) = start.unwrap_or_else(|| self.end_position());
        self.next_id += 1;
        self.entries.push_back(Entry {
            id,
            kind,
            block,
            offset,
            len,
            seen: false,
            index: None,
        });
        Ok(id)
    }

    pub fn mark_seen(&mut self, ids: RangeInclusive<EntryId>) {
        let Some(first) = self.first() else {
            return;
        };
        let from = ids.start().0.saturating_sub(first.0);
        let to = ids.end().0.saturating_sub(first.0);
        if ids.end().0 < first.0 {
            return;
        }
        for at in from..=to {
            match usize::try_from(at)
                .ok()
                .and_then(|at| self.entries.get_mut(at))
            {
                Some(entry) => entry.seen = true,
                None => return,
            }
        }
    }

    /// Whether storing `incoming` escaped bytes (see
    /// [`crate::render::display_safe_len`]) could drop a report not yet seen,
    /// or could not be stored at all.
    pub fn would_drop_unseen(&self, incoming: usize) -> bool {
        let with_tail = blocks_for(incoming.saturating_sub(self.tail_room()), self.block_bytes);
        let fresh = blocks_for(incoming, self.block_bytes);
        self.plan(|all_dropped| if all_dropped { fresh } else { with_tail })
            .is_err()
    }

    fn tail_room(&self) -> usize {
        self.blocks.back().map_or(0, FixedText::room)
    }

    fn end_position(&self) -> (u64, usize) {
        match self.blocks.back() {
            Some(last) => (self.base + self.blocks.len() as u64 - 1, last.len()),
            None => (self.base, 0),
        }
    }

    fn blocks_needed(&self, text: &str, mut room: usize) -> usize {
        let mut needed = 0;
        let _ = stored_pieces(text, |piece| {
            if piece.len() > room {
                needed += 1;
                room = self.block_bytes;
            }
            room -= piece.len();
            Ok(())
        });
        needed
    }

    /// How many of the oldest entries must go for `needed` more blocks, given
    /// whether every entry (and so every block) has gone.
    fn plan(&self, needed: impl Fn(bool) -> usize) -> Result<usize, Full> {
        for drop in 0..=self.entries.len() {
            if drop > 0 {
                let gone = &self.entries[drop - 1];
                if gone.kind == EntryKind::Report && !gone.seen {
                    return Err(Full);
                }
            }
            let kept = match self.entries.get(drop) {
                Some(next) => self.blocks.len() - (next.block - self.base) as usize,
                None if drop == 0 => self.blocks.len(),
                None => 0,
            };
            if kept + needed(kept == 0 && drop > 0) <= self.max_blocks {
                return Ok(drop);
            }
        }
        Err(Full)
    }

    fn drop_oldest(&mut self, count: usize) {
        if count == 0 {
            return;
        }
        self.entries.drain(..count);
        self.dropped = true;
        let keep_from = self
            .entries
            .front()
            .map_or(self.base + self.blocks.len() as u64, |e| e.block);
        while self.base < keep_from {
            if let Some(mut block) = self.blocks.pop_front() {
                block.clear();
            }
            self.base += 1;
        }
    }

    pub fn dropped_earlier(&self) -> bool {
        self.dropped
    }

    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    pub fn first(&self) -> Option<EntryId> {
        self.entries.front().map(|e| e.id)
    }

    pub fn last(&self) -> Option<EntryId> {
        self.entries.back().map(|e| e.id)
    }

    pub fn kind(&self, id: EntryId) -> Option<EntryKind> {
        self.entry(id).map(|e| e.kind)
    }

    pub fn is_seen(&self, id: EntryId) -> Option<bool> {
        self.entry(id).map(|e| e.seen)
    }

    /// The entry's stored text, in the order its blocks hold it.
    pub fn segments(&self, id: EntryId) -> impl Iterator<Item = &str> + '_ {
        let entry = self.entry(id);
        let mut left = entry.map_or(0, |e| e.len);
        let mut block = entry.map_or(0, |e| e.block - self.base);
        let mut offset = entry.map_or(0, |e| e.offset);
        std::iter::from_fn(move || {
            if left == 0 {
                return None;
            }
            let text = self.blocks.get(usize::try_from(block).ok()?)?.as_str();
            let end = text.len().min(offset + left);
            let piece = &text[offset..end];
            left -= piece.len();
            block += 1;
            offset = 0;
            Some(piece)
        })
    }

    fn entry(&self, id: EntryId) -> Option<&Entry> {
        let first = self.entries.front()?.id.0;
        self.entries
            .get(usize::try_from(id.0.checked_sub(first)?).ok()?)
    }

    /// The first row source: the dropped notice once output was dropped, else the oldest entry.
    pub fn first_item(&self) -> Option<EntryId> {
        if self.dropped {
            Some(EntryId::DROPPED_NOTICE)
        } else {
            self.first()
        }
    }

    pub fn last_item(&self) -> Option<EntryId> {
        self.last().or_else(|| self.first_item())
    }

    pub fn next_item(&self, id: EntryId) -> Option<EntryId> {
        if id == EntryId::DROPPED_NOTICE {
            return self.first();
        }
        let next = EntryId(id.0 + 1);
        self.entry(next).map(|e| e.id)
    }

    pub fn prev_item(&self, id: EntryId) -> Option<EntryId> {
        if id == EntryId::DROPPED_NOTICE {
            return None;
        }
        match self.entry(EntryId(id.0 - 1)) {
            Some(e) => Some(e.id),
            None if self.dropped => Some(EntryId::DROPPED_NOTICE),
            None => None,
        }
    }

    /// Whether `id` is still a row source.
    pub fn has_item(&self, id: EntryId) -> bool {
        if id == EntryId::DROPPED_NOTICE {
            self.dropped
        } else {
            self.entry(id).is_some()
        }
    }

    /// Entries after `id` not yet seen.
    pub fn unseen_after(&self, id: EntryId) -> u32 {
        let count = self
            .entries
            .iter()
            .rev()
            .take_while(|e| e.id > id)
            .filter(|e| !e.seen)
            .count();
        u32::try_from(count).unwrap_or(u32::MAX)
    }

    /// Rows `id` takes at `width`; the dropped notice is one row.
    pub fn item_rows(&mut self, id: EntryId, width: u16) -> u32 {
        if id == EntryId::DROPPED_NOTICE {
            return 1;
        }
        self.index(id, width).map_or(0, |i| i.rows)
    }

    /// The spans of rows `rows` of `id` at `width`, into `out` (cleared first).
    pub fn rows_of(&mut self, id: EntryId, width: u16, rows: Range<u32>, out: &mut Vec<RowSpan>) {
        out.clear();
        if id == EntryId::DROPPED_NOTICE {
            if rows.contains(&0) {
                out.push(RowSpan {
                    start: 0,
                    end: EARLIER_OUTPUT_DROPPED.len(),
                });
            }
            return;
        }
        let Some(index) = self.index(id, width) else {
            return;
        };
        let checkpoint = (rows.start / CHECKPOINT_ROWS) as usize;
        let Some(&from) = index.checkpoints.get(checkpoint) else {
            return;
        };
        let mut row = checkpoint as u32 * CHECKPOINT_ROWS;
        let mut wrapper = Wrapper::new(width, from);
        let mut end = from;
        for (off, c) in self.char_indices(id, from) {
            if row >= rows.end {
                return;
            }
            end = off + c.len_utf8();
            if let Some(span) = wrapper.feed(off, c) {
                if rows.contains(&row) {
                    out.push(span);
                }
                row += 1;
            }
        }
        if rows.contains(&row) {
            out.push(wrapper.finish(end.max(from)));
        }
    }

    /// The characters of one row span of `id`, offsets into its whole text.
    pub fn chars_of(&self, id: EntryId, span: RowSpan) -> impl Iterator<Item = char> + '_ {
        let notice = (id == EntryId::DROPPED_NOTICE)
            .then(|| EARLIER_OUTPUT_DROPPED[span.start..span.end].chars());
        let stored = (id != EntryId::DROPPED_NOTICE).then(|| {
            self.char_indices(id, span.start)
                .take_while(move |&(off, _)| off < span.end)
                .map(|(_, c)| c)
        });
        notice
            .into_iter()
            .flatten()
            .chain(stored.into_iter().flatten())
    }

    fn char_indices(&self, id: EntryId, from: usize) -> impl Iterator<Item = (usize, char)> + '_ {
        let mut base = 0;
        self.segments(id).flat_map(move |seg| {
            let at = base;
            base += seg.len();
            let skip = from.saturating_sub(at).min(seg.len());
            seg[skip..]
                .char_indices()
                .map(move |(i, c)| (at + skip + i, c))
        })
    }

    fn index(&mut self, id: EntryId, width: u16) -> Option<&WrapIndex> {
        let first = self.entries.front()?.id.0;
        let at = usize::try_from(id.0.checked_sub(first)?).ok()?;
        let fresh = self
            .entries
            .get(at)?
            .index
            .as_ref()
            .is_some_and(|i| i.width == width);
        if !fresh {
            let mut wrapper = Wrapper::new(width, 0);
            let mut rows = 0u32;
            let mut checkpoints = vec![0];
            for (off, c) in self.char_indices(id, 0) {
                if let Some(span) = wrapper.feed(off, c) {
                    rows += 1;
                    if rows.is_multiple_of(CHECKPOINT_ROWS) {
                        checkpoints.push(match c {
                            '\n' => span.end + 1,
                            _ => off,
                        });
                    }
                }
            }
            self.entries[at].index = Some(WrapIndex {
                width,
                rows: rows + 1,
                checkpoints,
            });
        }
        self.entries.get(at)?.index.as_ref()
    }

    #[cfg(test)]
    fn block_count(&self) -> usize {
        self.blocks.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::render::display_safe_len;

    fn text(c: &Conversation, id: EntryId) -> String {
        c.segments(id).collect()
    }

    #[test]
    fn the_cap_holds_a_maximal_report_and_a_maximal_request_at_the_worst_expansion() {
        let ceiling = maknae_config::PROMPT_MAX_CEILING;
        let cap = conversation_cap(ceiling);
        let blocks = cap / BLOCK_BYTES;
        assert_eq!(cap % BLOCK_BYTES, 0);
        let one = blocks_for(DISPLAY_EXPANSION * ceiling, BLOCK_BYTES);
        assert!(blocks > 2 * one, "{blocks} {one}");
        assert!(one * (BLOCK_BYTES - (DISPLAY_PIECE_MAX - 1)) >= DISPLAY_EXPANSION * ceiling);
        assert_eq!(blocks_for(0, 64), 0);
        assert_eq!(blocks_for(55, 64), 1);
        assert_eq!(blocks_for(56, 64), 2);
    }

    #[test]
    fn one_maximal_hostile_report_fits_the_cap() {
        let ceiling = maknae_config::PROMPT_MAX_CEILING;
        let mut c = Conversation::for_prompt_ceiling(ceiling);
        assert_eq!(c.block_count(), 0);
        let req = c.push(EntryKind::Request, "do the thing").unwrap();
        let hostile = "\u{1b}".repeat(ceiling);
        assert_eq!(display_safe_len(&hostile), DISPLAY_EXPANSION * ceiling);
        assert!(!c.would_drop_unseen(display_safe_len(&hostile)));
        let report = c.push(EntryKind::Report, &hostile).unwrap();
        drop(hostile);
        assert_eq!(c.first(), Some(req));
        assert_eq!(
            c.segments(report).map(str::len).sum::<usize>(),
            DISPLAY_EXPANSION * ceiling
        );
        assert!(c
            .segments(report)
            .all(|s| s.len() % 8 == 0 && s.starts_with("\\u{001b}")));
        assert!(!c.would_drop_unseen(DISPLAY_EXPANSION * ceiling));
        assert!(c.would_drop_unseen(DISPLAY_EXPANSION * ceiling * 2));
    }

    #[test]
    fn small_entries_share_a_block_and_a_large_one_spans_blocks_without_splitting_a_piece() {
        let mut c = Conversation::new(64 * 8, 64);
        let a = c.push(EntryKind::Request, "hello").unwrap();
        let b = c.push(EntryKind::Notice, "#1 submitted").unwrap();
        assert_eq!(c.block_count(), 1);
        let long = "가나다\u{1b}".repeat(10);
        let l = c.push(EntryKind::Report, &long).unwrap();
        assert_eq!(text(&c, a), "hello");
        assert_eq!(text(&c, b), "#1 submitted");
        assert_eq!(text(&c, l), "가나다\\u{001b}".repeat(10));
        assert!(c.segments(l).count() > 1);
        for seg in c.segments(l) {
            assert!(!seg.ends_with("\\u{00"), "{seg}");
        }
        assert_eq!(c.kind(l), Some(EntryKind::Report));
        assert_eq!(c.is_seen(l), Some(false));
        assert!(c.blocks.iter().all(|b| b.capacity() == 64));
    }

    #[test]
    fn the_oldest_seen_entry_is_wiped_and_dropped_first() {
        let mut c = Conversation::new(64 * 4, 64);
        let ids: Vec<EntryId> = (0..4)
            .map(|i| {
                c.push(EntryKind::Report, &format!("{i}").repeat(64))
                    .unwrap()
            })
            .collect();
        assert_eq!(c.block_count(), 4);
        assert!(!c.dropped_earlier());
        c.mark_seen(ids[0]..=ids[3]);
        let ptrs: Vec<*const u8> = c.blocks.iter().map(|b| b.as_str().as_ptr()).collect();
        let next = c.push(EntryKind::Report, &"n".repeat(64)).unwrap();
        assert!(c.dropped_earlier());
        assert_eq!(c.first(), Some(ids[1]));
        assert_eq!(c.is_seen(ids[0]), None);
        assert_eq!(c.block_count(), 4);
        let kept: Vec<*const u8> = c.blocks.iter().map(|b| b.as_str().as_ptr()).collect();
        assert_eq!(&kept[..3], &ptrs[1..]);
        assert_eq!(text(&c, ids[1]), "1".repeat(64));
        assert_eq!(text(&c, next), "n".repeat(64));
        let two = c.push(EntryKind::Notice, &"t".repeat(120)).unwrap();
        assert_eq!(c.first(), Some(ids[3]));
        assert_eq!(text(&c, two), "t".repeat(120));
    }

    #[test]
    fn a_full_store_stops_collecting_rather_than_drop_an_unseen_report() {
        let mut c = Conversation::new(64 * 4, 64);
        let ids: Vec<EntryId> = (0..4)
            .map(|i| {
                c.push(EntryKind::Report, &format!("{i}").repeat(64))
                    .unwrap()
            })
            .collect();
        assert!(c.would_drop_unseen(1));
        assert_eq!(c.push(EntryKind::Report, "late"), Err(Full));
        assert_eq!(c.push(EntryKind::Notice, "late"), Err(Full));
        assert_eq!(c.first(), Some(ids[0]));
        assert_eq!(c.last(), Some(ids[3]));
        assert!(!c.dropped_earlier());
        assert_eq!(text(&c, ids[0]), "0".repeat(64));
        c.mark_seen(ids[0]..=ids[0]);
        assert!(!c.would_drop_unseen(50));
        assert!(c.would_drop_unseen(120));
        let late = c.push(EntryKind::Report, "late").unwrap();
        assert_eq!(c.first(), Some(ids[1]));
        assert_eq!(text(&c, late), "late");
    }

    #[test]
    fn unseen_requests_and_notices_may_be_dropped() {
        let mut c = Conversation::new(64 * 2, 64);
        c.push(EntryKind::Request, &"r".repeat(60)).unwrap();
        c.push(EntryKind::Notice, &"n".repeat(60)).unwrap();
        assert!(!c.would_drop_unseen(60));
        let x = c.push(EntryKind::Request, &"x".repeat(120)).unwrap();
        assert_eq!(c.first(), Some(x));
        assert_eq!(c.block_count(), 2);
    }

    #[test]
    fn an_entry_larger_than_the_cap_is_refused_even_when_empty() {
        let mut c = Conversation::new(64 * 2, 64);
        assert_eq!(c.push(EntryKind::Report, &"a".repeat(129)), Err(Full));
        assert!(c.is_empty());
        assert_eq!(c.block_count(), 0);
        assert!(c.would_drop_unseen(129));
    }

    #[test]
    fn a_tab_expands_to_the_next_eight_column_stop() {
        let mut c = Conversation::new(64 * 8, 64);
        let cases = [
            ("a\tb", format!("a{}b", " ".repeat(7))),
            ("12345678\tx", format!("12345678{}x", " ".repeat(8))),
            (
                "a\tb\n\tc",
                format!("a{}b\n{}c", " ".repeat(7), " ".repeat(8)),
            ),
            ("가\tx", format!("가{}x", " ".repeat(6))),
            ("\u{1b}\tx", format!("\\u{{001b}}{}x", " ".repeat(8))),
            ("\t\t", " ".repeat(16)),
        ];
        for (input, want) in cases {
            let id = c.push(EntryKind::Report, input).unwrap();
            assert_eq!(text(&c, id), want, "{input:?}");
            assert!(!text(&c, id).contains('\t'));
        }
        let mut tight = Conversation::new(64, 64);
        assert!(tight.push(EntryKind::Report, &"\t".repeat(8)).is_ok());
        assert_eq!(tight.push(EntryKind::Report, "\t"), Err(Full));
    }

    #[test]
    fn mark_seen_marks_only_the_range() {
        let mut c = Conversation::new(64 * 4, 64);
        let ids: Vec<EntryId> = (0..4)
            .map(|_| c.push(EntryKind::Report, "r").unwrap())
            .collect();
        c.mark_seen(ids[1]..=ids[2]);
        let seen: Vec<bool> = ids.iter().map(|&i| c.is_seen(i).unwrap()).collect();
        assert_eq!(seen, [false, true, true, false]);
        c.mark_seen(EntryId(90)..=EntryId(99));
    }

    #[test]
    fn an_entry_spanning_blocks_wraps_as_one_text() {
        let mut c = Conversation::new(64 * 8, 64);
        let long = "abcdefghij".repeat(20);
        let id = c.push(EntryKind::Report, &long).unwrap();
        assert!(c.segments(id).count() > 2);
        assert_eq!(c.item_rows(id, 30), 7);
        let mut spans = Vec::new();
        c.rows_of(id, 30, 2..4, &mut spans);
        let rows: Vec<String> = spans.iter().map(|s| c.chars_of(id, *s).collect()).collect();
        assert_eq!(rows, [long[60..90].to_string(), long[90..120].to_string()]);
        assert_eq!(c.item_rows(id, 200), 1);
        assert_eq!(c.item_rows(EntryId::DROPPED_NOTICE, 10), 1);
    }

    #[test]
    fn row_lookups_past_a_checkpoint_match_a_full_wrap() {
        let mut c = Conversation::new(BLOCK_BYTES * 4, BLOCK_BYTES);
        let long: String = (0..2000).map(|i| format!("line {i}\n")).collect();
        let id = c.push(EntryKind::Report, &long).unwrap();
        assert_eq!(c.item_rows(id, 40), 2001);
        let mut spans = Vec::new();
        c.rows_of(id, 40, 700..703, &mut spans);
        let rows: Vec<String> = spans.iter().map(|s| c.chars_of(id, *s).collect()).collect();
        assert_eq!(rows, ["line 700", "line 701", "line 702"]);
        c.rows_of(id, 40, 1999..2005, &mut spans);
        let rows: Vec<String> = spans.iter().map(|s| c.chars_of(id, *s).collect()).collect();
        assert_eq!(rows, ["line 1999", ""]);
    }
}
