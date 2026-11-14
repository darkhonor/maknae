//! The session screen's pure core (#630): key decoding, the line editor, the
//! conversation's block store, display-width wrapping and the frame composer.
//! The terminal driver in `bins/maknae` reads the keys and writes the frames.
pub mod blocks;
pub mod editor;
pub mod fixed;
pub mod frame;
pub mod keys;
pub mod wrap;

/// The header row: `left` from the first column, `right` against the last.
#[derive(Clone, PartialEq, Eq, Debug, Default)]
pub struct HeaderLine {
    pub left: String,
    pub right: String,
}

#[derive(Clone, PartialEq, Eq, Debug)]
pub struct MenuItem {
    pub name: String,
    pub help: String,
}

/// The screen's caller: what its header says and which commands a `/` offers.
pub trait Commands {
    fn header(&self) -> HeaderLine;
    fn menu(&self, prefix: &str) -> Vec<MenuItem>;
}
