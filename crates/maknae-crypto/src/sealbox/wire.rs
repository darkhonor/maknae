use crate::CryptoError;

pub const VERSION: u8 = 1;
pub const EPHEMERAL_KEY_LEN: usize = 97;
pub const NONCE_LEN: usize = crate::aead::NONCE_LEN;
pub const TAG_LEN: usize = crate::aead::TAG_LEN;
pub const HEADER_LEN: usize = 1 + EPHEMERAL_KEY_LEN + NONCE_LEN;
pub(super) const MIN_BLOB_LEN: usize = HEADER_LEN + 1 + TAG_LEN;
const UNCOMPRESSED_POINT: u8 = 0x04;

pub(super) struct BlobParts<'a> {
    pub(super) ephemeral: &'a [u8],
    pub(super) nonce: [u8; NONCE_LEN],
    pub(super) sealed: &'a [u8],
}

pub(super) fn sealed_len(plaintext_len: usize) -> usize {
    HEADER_LEN + plaintext_len + TAG_LEN
}

pub(super) fn parse_blob(blob: &[u8]) -> Result<BlobParts<'_>, CryptoError> {
    if blob.len() < MIN_BLOB_LEN {
        return Err(CryptoError::SealBlob);
    }
    if blob[0] != VERSION {
        return Err(CryptoError::SealVersion);
    }
    if blob[1] != UNCOMPRESSED_POINT {
        return Err(CryptoError::SealEphemeralKey);
    }
    let mut nonce = [0u8; NONCE_LEN];
    nonce.copy_from_slice(&blob[1 + EPHEMERAL_KEY_LEN..HEADER_LEN]);
    Ok(BlobParts {
        ephemeral: &blob[1..1 + EPHEMERAL_KEY_LEN],
        nonce,
        sealed: &blob[HEADER_LEN..],
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn blob(len: usize) -> Vec<u8> {
        let mut b = vec![0u8; len];
        b[0] = VERSION;
        b[1] = 0x04;
        b
    }

    #[test]
    fn the_v1_layout_is_pinned() {
        assert_eq!(
            (VERSION, EPHEMERAL_KEY_LEN, NONCE_LEN, TAG_LEN, HEADER_LEN),
            (1, 97, 12, 16, 110)
        );
        assert_eq!(MIN_BLOB_LEN, 127);
        assert_eq!(sealed_len(95), 110 + 95 + 16);
    }

    #[test]
    fn a_blob_splits_into_ephemeral_nonce_and_sealed_bytes() {
        let mut b = blob(MIN_BLOB_LEN);
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
        assert_eq!((p.nonce[0], p.nonce[NONCE_LEN - 1]), (0xAA, 0xAB));
        assert_eq!((p.sealed.len(), p.sealed[0]), (1 + TAG_LEN, 0xBB));
        assert_eq!(
            parse_blob(&blob(4096)).unwrap().sealed.len(),
            4096 - HEADER_LEN
        );
    }

    #[test]
    fn a_short_blob_or_another_version_or_point_form_is_refused_in_that_order() {
        assert!(matches!(
            parse_blob(&blob(MIN_BLOB_LEN - 1)),
            Err(CryptoError::SealBlob)
        ));
        assert!(matches!(parse_blob(&[]), Err(CryptoError::SealBlob)));
        let mut short_v2 = blob(MIN_BLOB_LEN - 1);
        short_v2[0] = 2;
        assert!(matches!(parse_blob(&short_v2), Err(CryptoError::SealBlob)));
        let mut v2 = blob(MIN_BLOB_LEN);
        v2[0] = 2;
        v2[1] = 0x02;
        assert!(matches!(parse_blob(&v2), Err(CryptoError::SealVersion)));
        let mut compressed = blob(MIN_BLOB_LEN);
        compressed[1] = 0x02;
        assert!(matches!(
            parse_blob(&compressed),
            Err(CryptoError::SealEphemeralKey)
        ));
    }
}
