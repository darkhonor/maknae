use crate::format::FormatError;

pub(crate) struct Reader<'a> {
    buf: &'a [u8],
    pos: usize,
}

impl<'a> Reader<'a> {
    pub(crate) fn new(buf: &'a [u8]) -> Self {
        Self { buf, pos: 0 }
    }

    pub(crate) fn take(&mut self, n: usize) -> Result<&'a [u8], FormatError> {
        let out = self.buf[self.pos..]
            .get(..n)
            .ok_or(FormatError::Truncated)?;
        self.pos += n;
        Ok(out)
    }

    pub(crate) fn u8(&mut self) -> Result<u8, FormatError> {
        Ok(self.take(1)?[0])
    }

    pub(crate) fn u16(&mut self) -> Result<u16, FormatError> {
        let mut a = [0u8; 2];
        a.copy_from_slice(self.take(2)?);
        Ok(u16::from_le_bytes(a))
    }

    pub(crate) fn u32(&mut self) -> Result<u32, FormatError> {
        let mut a = [0u8; 4];
        a.copy_from_slice(self.take(4)?);
        Ok(u32::from_le_bytes(a))
    }

    pub(crate) fn u64(&mut self) -> Result<u64, FormatError> {
        let mut a = [0u8; 8];
        a.copy_from_slice(self.take(8)?);
        Ok(u64::from_le_bytes(a))
    }

    pub(crate) fn is_empty(&self) -> bool {
        self.pos == self.buf.len()
    }
}

#[derive(Default)]
pub(crate) struct Writer {
    buf: Vec<u8>,
}

impl Writer {
    pub(crate) fn u8(&mut self, v: u8) {
        self.buf.push(v);
    }

    pub(crate) fn u16(&mut self, v: u16) {
        self.buf.extend_from_slice(&v.to_le_bytes());
    }

    pub(crate) fn u32(&mut self, v: u32) {
        self.buf.extend_from_slice(&v.to_le_bytes());
    }

    pub(crate) fn u64(&mut self, v: u64) {
        self.buf.extend_from_slice(&v.to_le_bytes());
    }

    pub(crate) fn bytes(&mut self, b: &[u8]) {
        self.buf.extend_from_slice(b);
    }

    pub(crate) fn into_inner(self) -> Vec<u8> {
        self.buf
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reader_reads_little_endian_and_refuses_past_the_end() {
        let mut w = Writer::default();
        w.u8(1);
        w.u16(0x0302);
        w.u32(0x0706_0504);
        w.u64(0x0f0e_0d0c_0b0a_0908);
        w.bytes(&[0x10]);
        let buf = w.into_inner();
        assert_eq!(buf, (1u8..=0x10).collect::<Vec<_>>());
        let mut r = Reader::new(&buf);
        assert_eq!(r.u8().unwrap(), 1);
        assert_eq!(r.u16().unwrap(), 0x0302);
        assert_eq!(r.u32().unwrap(), 0x0706_0504);
        assert_eq!(r.u64().unwrap(), 0x0f0e_0d0c_0b0a_0908);
        assert!(!r.is_empty());
        assert_eq!(r.take(1).unwrap(), &[0x10]);
        assert!(r.is_empty());
        assert_eq!(r.u8().unwrap_err(), FormatError::Truncated);
        let mut short = Reader::new(&buf[..3]);
        assert_eq!(short.u32().unwrap_err(), FormatError::Truncated);
        assert_eq!(short.u16().unwrap(), 0x0201);
        assert_eq!(short.u64().unwrap_err(), FormatError::Truncated);
    }
}
