use zeroize::{Zeroize, Zeroizing};

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct Full;

impl std::fmt::Display for Full {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("buffer full")
    }
}

impl std::error::Error for Full {}

/// Text in one zeroizing allocation made at construction; a write that does not
/// fit is refused, never grown into.
pub struct FixedText {
    text: Zeroizing<String>,
    cap: usize,
}

impl FixedText {
    pub fn with_capacity(cap: usize) -> Self {
        Self {
            text: Zeroizing::new(String::with_capacity(cap)),
            cap,
        }
    }

    pub fn capacity(&self) -> usize {
        self.cap
    }

    pub fn len(&self) -> usize {
        self.text.len()
    }

    pub fn is_empty(&self) -> bool {
        self.text.is_empty()
    }

    pub fn room(&self) -> usize {
        self.cap - self.text.len()
    }

    #[cfg(test)]
    pub(crate) fn allocated(&self) -> usize {
        self.text.capacity()
    }

    pub fn as_str(&self) -> &str {
        &self.text
    }

    pub fn push_str(&mut self, s: &str) -> Result<(), Full> {
        if s.len() > self.room() {
            return Err(Full);
        }
        self.text.push_str(s);
        Ok(())
    }

    pub fn push(&mut self, c: char) -> Result<(), Full> {
        self.push_str(c.encode_utf8(&mut [0; 4]))
    }

    /// `at` must be a char boundary.
    pub fn insert_str(&mut self, at: usize, s: &str) -> Result<(), Full> {
        if s.len() > self.room() {
            return Err(Full);
        }
        self.text.insert_str(at, s);
        Ok(())
    }

    /// Removes `range` (char boundaries) and wipes the bytes the shift left behind.
    pub fn remove_range(&mut self, range: std::ops::Range<usize>) {
        let removed = range.len();
        let len = self.text.len() - removed;
        self.text.drain(range);
        self.text.extend(std::iter::repeat_n('\0', removed));
        self.text.truncate(len);
    }

    pub fn clear(&mut self) {
        self.text.zeroize();
    }
}

impl std::fmt::Debug for FixedText {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "FixedText(<{} of {} bytes>)", self.len(), self.cap)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn filling_to_capacity_keeps_the_allocation_and_refuses_the_rest() {
        let mut t = FixedText::with_capacity(8);
        let ptr = t.as_str().as_ptr();
        let real = t.allocated();
        t.push_str("abcd").unwrap();
        t.push('한').unwrap();
        assert_eq!(t.room(), 1);
        assert_eq!(t.push('é'), Err(Full));
        assert_eq!(t.push_str("xy"), Err(Full));
        t.push('z').unwrap();
        assert_eq!(t.push('z'), Err(Full));
        assert_eq!(t.as_str(), "abcd한z");
        assert_eq!(t.as_str().as_ptr(), ptr);
        assert_eq!(t.allocated(), real);
    }

    #[test]
    fn insert_and_remove_stay_in_place() {
        let mut t = FixedText::with_capacity(16);
        let ptr = t.as_str().as_ptr();
        t.push_str("held").unwrap();
        t.insert_str(2, "ő").unwrap();
        assert_eq!(t.as_str(), "heőld");
        assert_eq!(t.insert_str(0, "0123456789abc"), Err(Full));
        assert_eq!(t.as_str(), "heőld");
        t.remove_range(1..4);
        assert_eq!(t.as_str(), "hld");
        t.clear();
        assert!(t.is_empty());
        t.push_str("0123456789abcdef").unwrap();
        assert_eq!(t.as_str().as_ptr(), ptr);
        assert_eq!(t.capacity(), 16);
    }

    #[test]
    fn debug_prints_the_length_and_never_the_text() {
        let mut t = FixedText::with_capacity(32);
        t.push_str("sentinel-7f3a").unwrap();
        let d = format!("{t:?}");
        assert!(!d.contains("sentinel"), "{d}");
        assert!(d.contains("13"), "{d}");
    }
}
