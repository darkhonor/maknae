use crate::SealError;

pub const SEAL_VERSION: u8 = 1;
pub const EPHEMERAL_KEY_LEN: usize = 97;
pub const NONCE_LEN: usize = 12;
pub const TAG_LEN: usize = 16;
pub const HEADER_LEN: usize = 1 + EPHEMERAL_KEY_LEN + NONCE_LEN;
pub const MAX_PLAINTEXT_LEN: usize = 1024;
pub const MIN_SEALED_LEN: usize = HEADER_LEN + 1 + TAG_LEN;
pub const MAX_SEALED_LEN: usize = HEADER_LEN + MAX_PLAINTEXT_LEN + TAG_LEN;
const UNCOMPRESSED_POINT: u8 = 0x04;

#[derive(Debug)]
pub(crate) struct BlobParts<'a> {
    pub(crate) ephemeral: &'a [u8],
    pub(crate) nonce: &'a [u8],
    pub(crate) sealed: &'a [u8],
}

pub(crate) fn check_plaintext_len(n: usize) -> Result<(), SealError> {
    if !(1..=MAX_PLAINTEXT_LEN).contains(&n) {
        return Err(SealError::PlaintextLength);
    }
    Ok(())
}

pub(crate) fn sealed_len(plaintext_len: usize) -> usize {
    HEADER_LEN + plaintext_len + TAG_LEN
}

pub(crate) fn parse_blob(blob: &[u8]) -> Result<BlobParts<'_>, SealError> {
    if !(MIN_SEALED_LEN..=MAX_SEALED_LEN).contains(&blob.len()) {
        return Err(SealError::BlobLength);
    }
    if blob[0] != SEAL_VERSION {
        return Err(SealError::Version);
    }
    if blob[1] != UNCOMPRESSED_POINT {
        return Err(SealError::EphemeralKey);
    }
    Ok(BlobParts {
        ephemeral: &blob[1..1 + EPHEMERAL_KEY_LEN],
        nonce: &blob[1 + EPHEMERAL_KEY_LEN..HEADER_LEN],
        sealed: &blob[HEADER_LEN..],
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn blob(len: usize) -> Vec<u8> {
        let mut b = vec![0u8; len];
        b[0] = SEAL_VERSION;
        b[1] = 0x04;
        b
    }

    #[test]
    fn the_v1_layout_is_pinned() {
        assert_eq!(
            (HEADER_LEN, MIN_SEALED_LEN, MAX_SEALED_LEN),
            (110, 127, 1150)
        );
        assert_eq!(sealed_len(95), 110 + 95 + 16);
    }

    #[test]
    fn the_proto_sealed_key_bounds_are_the_blob_bounds() {
        assert_eq!(
            (
                maknae_proto::SEALED_KEY_MIN_BYTES,
                maknae_proto::SEALED_KEY_MAX_BYTES
            ),
            (MIN_SEALED_LEN, MAX_SEALED_LEN)
        );
    }

    #[test]
    fn a_blob_splits_into_ephemeral_nonce_and_sealed_bytes() {
        let mut b = blob(MIN_SEALED_LEN);
        b[EPHEMERAL_KEY_LEN] = 0xEE;
        b[1 + EPHEMERAL_KEY_LEN] = 0xAA;
        b[HEADER_LEN - 1] = 0xAB;
        b[HEADER_LEN] = 0xBB;
        let p = parse_blob(&b).unwrap();
        assert_eq!(
            (
                p.ephemeral.len(),
                p.ephemeral[0],
                p.ephemeral[EPHEMERAL_KEY_LEN - 1]
            ),
            (EPHEMERAL_KEY_LEN, 0x04, 0xEE)
        );
        assert_eq!(
            (p.nonce.len(), p.nonce[0], p.nonce[NONCE_LEN - 1]),
            (NONCE_LEN, 0xAA, 0xAB)
        );
        assert_eq!((p.sealed.len(), p.sealed[0]), (1 + TAG_LEN, 0xBB));
        assert!(parse_blob(&blob(MAX_SEALED_LEN)).is_ok());
    }

    #[test]
    fn a_blob_out_of_bounds_or_of_another_version_or_point_form_is_refused() {
        assert_eq!(
            parse_blob(&blob(MIN_SEALED_LEN - 1)).unwrap_err(),
            SealError::BlobLength
        );
        assert_eq!(
            parse_blob(&blob(MAX_SEALED_LEN + 1)).unwrap_err(),
            SealError::BlobLength
        );
        assert_eq!(parse_blob(&[]).unwrap_err(), SealError::BlobLength);
        let mut v2 = blob(MIN_SEALED_LEN);
        v2[0] = 2;
        assert_eq!(parse_blob(&v2).unwrap_err(), SealError::Version);
        let mut compressed = blob(MIN_SEALED_LEN);
        compressed[1] = 0x02;
        assert_eq!(
            parse_blob(&compressed).unwrap_err(),
            SealError::EphemeralKey
        );
    }

    #[test]
    fn the_plaintext_bound_is_one_to_1024_inclusive() {
        assert_eq!(check_plaintext_len(0), Err(SealError::PlaintextLength));
        assert_eq!(check_plaintext_len(1), Ok(()));
        assert_eq!(check_plaintext_len(MAX_PLAINTEXT_LEN), Ok(()));
        assert_eq!(
            check_plaintext_len(MAX_PLAINTEXT_LEN + 1),
            Err(SealError::PlaintextLength)
        );
    }
}
