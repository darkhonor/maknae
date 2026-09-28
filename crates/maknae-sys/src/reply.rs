use std::ffi::OsStr;
use std::io;
use std::os::unix::ffi::OsStrExt;
use std::path::PathBuf;

pub(crate) const PATH_MAX: usize = 1024;
pub(crate) const VDIR: u32 = 2;
const REFERENCE_AT: usize = 8;
const REFERENCE_LEN: usize = 8;
pub(crate) const REPLY_CAPACITY: usize = 4 + 4 + 8 + PATH_MAX + 8;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum ReplyError {
    LengthExceedsBuffer,
    Truncated,
    NegativeOffset,
    OffsetIntoFixedPart,
    PathTooLong,
    OffsetOutOfBounds,
    LengthOutOfBounds,
    MissingNul,
    InteriorNul,
    NotAbsolute,
}

impl ReplyError {
    pub(crate) fn errno(self) -> i32 {
        match self {
            ReplyError::PathTooLong => libc::ENAMETOOLONG,
            _ => libc::EIO,
        }
    }

    pub(crate) fn into_io(self) -> io::Error {
        io::Error::from_raw_os_error(self.errno())
    }
}

pub(crate) fn parse_fullpath_reply(
    buf: &[u8],
    returned_len: usize,
) -> Result<(u32, &[u8]), ReplyError> {
    let reply = buf
        .get(..returned_len)
        .ok_or(ReplyError::LengthExceedsBuffer)?;
    let Some(head) = reply.first_chunk::<16>() else {
        return Err(ReplyError::Truncated);
    };
    let [_, _, _, _, t0, t1, t2, t3, o0, o1, o2, o3, l0, l1, l2, l3] = *head;
    let objtype = u32::from_ne_bytes([t0, t1, t2, t3]);
    let offset = usize::try_from(i32::from_ne_bytes([o0, o1, o2, o3]))
        .map_err(|_| ReplyError::NegativeOffset)?;
    if offset < REFERENCE_LEN {
        return Err(ReplyError::OffsetIntoFixedPart);
    }
    let length = u32::from_ne_bytes([l0, l1, l2, l3]) as usize;
    if length > PATH_MAX {
        return Err(ReplyError::PathTooLong);
    }
    let from_field = reply
        .get(REFERENCE_AT + offset..)
        .ok_or(ReplyError::OffsetOutOfBounds)?;
    let field = from_field
        .get(..length)
        .ok_or(ReplyError::LengthOutOfBounds)?;
    let Some((&0, path)) = field.split_last() else {
        return Err(ReplyError::MissingNul);
    };
    if path.contains(&0) {
        return Err(ReplyError::InteriorNul);
    }
    if path.first() != Some(&b'/') {
        return Err(ReplyError::NotAbsolute);
    }
    Ok((objtype, path))
}

pub(crate) fn decode(buf: &[u8]) -> io::Result<PathBuf> {
    let Some(header) = buf.first_chunk::<4>() else {
        return Err(ReplyError::Truncated.into_io());
    };
    let returned_len = u32::from_ne_bytes(*header) as usize;
    let (objtype, path) = parse_fullpath_reply(buf, returned_len).map_err(ReplyError::into_io)?;
    if objtype != VDIR {
        return Err(io::Error::from_raw_os_error(libc::ENOTDIR));
    }
    Ok(PathBuf::from(OsStr::from_bytes(path)))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn reply(objtype: u32, offset: i32, length: u32, data: &[u8]) -> Vec<u8> {
        let total = u32::try_from(16 + data.len()).unwrap();
        let mut out = Vec::new();
        out.extend_from_slice(&total.to_ne_bytes());
        out.extend_from_slice(&objtype.to_ne_bytes());
        out.extend_from_slice(&offset.to_ne_bytes());
        out.extend_from_slice(&length.to_ne_bytes());
        out.extend_from_slice(data);
        out
    }

    fn field(path: &[u8]) -> Vec<u8> {
        let mut data = path.to_vec();
        data.push(0);
        data
    }

    fn well_formed(path: &[u8]) -> Vec<u8> {
        let data = field(path);
        reply(VDIR, 8, u32::try_from(data.len()).unwrap(), &data)
    }

    fn parse(buf: &[u8]) -> Result<(u32, &[u8]), ReplyError> {
        parse_fullpath_reply(buf, buf.len())
    }

    #[test]
    fn a_well_formed_reply_yields_the_object_type_and_the_path_without_its_nul() {
        let buf = well_formed(b"/private/tmp/d0700");
        assert_eq!(parse(&buf), Ok((VDIR, &b"/private/tmp/d0700"[..])));
    }

    #[test]
    fn the_field_offset_is_relative_to_the_attribute_reference() {
        let mut data = vec![0xAA; 4];
        data.extend_from_slice(&field(b"/x"));
        let buf = reply(VDIR, 12, 3, &data);
        assert_eq!(parse(&buf), Ok((VDIR, &b"/x"[..])));
    }

    #[test]
    fn every_reply_shorter_than_the_fixed_part_is_truncated() {
        let buf = well_formed(b"/a");
        for len in 0..16 {
            assert_eq!(
                parse_fullpath_reply(&buf, len),
                Err(ReplyError::Truncated),
                "returned_len {len}"
            );
        }
    }

    #[test]
    fn a_returned_length_beyond_the_buffer_is_refused() {
        let buf = well_formed(b"/a");
        assert_eq!(
            parse_fullpath_reply(&buf, buf.len() + 1),
            Err(ReplyError::LengthExceedsBuffer)
        );
    }

    #[test]
    fn the_field_is_bounded_by_the_returned_length_not_the_buffer() {
        let buf = well_formed(b"/abc");
        assert_eq!(
            parse_fullpath_reply(&buf, buf.len() - 1),
            Err(ReplyError::LengthOutOfBounds)
        );
    }

    #[test]
    fn an_offset_past_the_end_is_refused() {
        let buf = reply(VDIR, 1000, 3, &field(b"/a"));
        assert_eq!(parse(&buf), Err(ReplyError::OffsetOutOfBounds));
    }

    #[test]
    fn an_offset_into_the_fixed_part_is_refused() {
        for offset in [0, 4, 7] {
            let buf = reply(VDIR, offset, 3, &field(b"/a"));
            assert_eq!(
                parse(&buf),
                Err(ReplyError::OffsetIntoFixedPart),
                "offset {offset}"
            );
        }
    }

    #[test]
    fn a_length_past_the_end_is_refused() {
        let buf = reply(VDIR, 8, 4, &field(b"/a"));
        assert_eq!(parse(&buf), Err(ReplyError::LengthOutOfBounds));
    }

    #[test]
    fn a_negative_offset_is_refused() {
        for offset in [-1, -8, i32::MIN] {
            let buf = reply(VDIR, offset, 3, &field(b"/a"));
            assert_eq!(
                parse(&buf),
                Err(ReplyError::NegativeOffset),
                "offset {offset}"
            );
        }
    }

    #[test]
    fn a_field_without_a_trailing_nul_is_refused() {
        assert_eq!(
            parse(&reply(VDIR, 8, 2, b"/a")),
            Err(ReplyError::MissingNul)
        );
        assert_eq!(parse(&reply(VDIR, 8, 0, b"")), Err(ReplyError::MissingNul));
    }

    #[test]
    fn a_field_with_an_interior_nul_is_refused() {
        let buf = reply(VDIR, 8, 5, b"/a\0b\0");
        assert_eq!(parse(&buf), Err(ReplyError::InteriorNul));
    }

    #[test]
    fn a_relative_or_empty_path_is_refused() {
        assert_eq!(parse(&well_formed(b"tmp/d")), Err(ReplyError::NotAbsolute));
        assert_eq!(parse(&well_formed(b"")), Err(ReplyError::NotAbsolute));
    }

    #[test]
    fn a_field_longer_than_path_max_is_refused_and_path_max_is_accepted() {
        let mut longest = vec![b'a'; PATH_MAX - 1];
        longest[0] = b'/';
        let buf = well_formed(&longest);
        assert_eq!(parse(&buf).map(|(_, p)| p.len()), Ok(PATH_MAX - 1));
        let mut over = vec![b'a'; PATH_MAX];
        over[0] = b'/';
        assert_eq!(parse(&well_formed(&over)), Err(ReplyError::PathTooLong));
        let buf = reply(VDIR, 8, u32::MAX, &field(b"/a"));
        assert_eq!(parse(&buf), Err(ReplyError::PathTooLong));
    }

    #[test]
    fn the_reply_buffer_holds_the_longest_path_reply() {
        assert_eq!(REPLY_CAPACITY, 1048);
        let mut longest = vec![b'a'; PATH_MAX - 1];
        longest[0] = b'/';
        let mut buf = well_formed(&longest);
        assert_eq!(buf.len(), 1040);
        buf.resize(REPLY_CAPACITY, 0);
        assert_eq!(
            parse_fullpath_reply(&buf, 1040).map(|(t, p)| (t, p.len())),
            Ok((VDIR, PATH_MAX - 1))
        );
    }

    #[test]
    fn no_header_value_reads_outside_the_reply() {
        let data = field(b"/abc");
        for offset in [i32::MIN, -1, 0, 4, 7, 8, 9, 12, 13, 1000, i32::MAX] {
            for length in [0, 1, 4, 5, 6, 1024, 1025, u32::MAX] {
                let buf = reply(VDIR, offset, length, &data);
                for returned_len in 0..=buf.len() + 1 {
                    if let Ok((_, path)) = parse_fullpath_reply(&buf, returned_len) {
                        let start = path.as_ptr().addr() - buf.as_ptr().addr();
                        assert!(
                            start >= 16 && start + path.len() < returned_len,
                            "offset {offset} length {length} returned_len {returned_len}"
                        );
                    }
                }
            }
        }
    }

    #[test]
    fn decode_returns_the_directory_path() {
        let buf = well_formed(b"/Users/x");
        assert_eq!(decode(&buf).unwrap(), PathBuf::from("/Users/x"));
    }

    #[test]
    fn decode_reads_the_returned_length_from_the_header() {
        let mut buf = well_formed(b"/abc");
        buf.extend_from_slice(&[0u8; 32]);
        assert_eq!(decode(&buf).unwrap(), PathBuf::from("/abc"));
        buf[..4].copy_from_slice(&17u32.to_ne_bytes());
        assert_eq!(decode(&buf).unwrap_err().raw_os_error(), Some(libc::EIO));
    }

    #[test]
    fn decode_refuses_an_object_that_is_not_a_directory() {
        let data = field(b"/etc/hosts");
        let buf = reply(1, 8, u32::try_from(data.len()).unwrap(), &data);
        assert_eq!(
            decode(&buf).unwrap_err().raw_os_error(),
            Some(libc::ENOTDIR)
        );
    }

    #[test]
    fn decode_maps_a_malformed_reply_to_eio_and_an_overlong_one_to_enametoolong() {
        assert_eq!(
            decode(&[0u8; 3]).unwrap_err().raw_os_error(),
            Some(libc::EIO)
        );
        let buf = reply(VDIR, 8, u32::MAX, &field(b"/a"));
        assert_eq!(
            decode(&buf).unwrap_err().raw_os_error(),
            Some(libc::ENAMETOOLONG)
        );
        let buf = reply(VDIR, -1, 3, &field(b"/a"));
        assert_eq!(decode(&buf).unwrap_err().raw_os_error(), Some(libc::EIO));
    }

    #[test]
    fn every_malformed_reply_but_an_overlong_path_is_eio() {
        for e in [
            ReplyError::LengthExceedsBuffer,
            ReplyError::Truncated,
            ReplyError::NegativeOffset,
            ReplyError::OffsetIntoFixedPart,
            ReplyError::OffsetOutOfBounds,
            ReplyError::LengthOutOfBounds,
            ReplyError::MissingNul,
            ReplyError::InteriorNul,
            ReplyError::NotAbsolute,
        ] {
            assert_eq!(e.errno(), libc::EIO, "{e:?}");
            assert_eq!(e.into_io().raw_os_error(), Some(libc::EIO), "{e:?}");
        }
        assert_eq!(ReplyError::PathTooLong.errno(), libc::ENAMETOOLONG);
        assert_eq!(
            ReplyError::PathTooLong.into_io().raw_os_error(),
            Some(libc::ENAMETOOLONG)
        );
    }
}
