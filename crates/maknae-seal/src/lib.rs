mod aad;
mod error;
mod seal;

pub use aad::{SealAad, SealContext, AAD_DOMAIN, MAX_AAD_FIELD_BYTES};
pub use error::SealError;
pub use seal::{
    open, seal, SealPrivateKey, SealPublicKey, SealedBlob, EPHEMERAL_KEY_LEN, HEADER_LEN,
    MAX_PLAINTEXT_LEN, MAX_SEALED_LEN, MIN_SEALED_LEN, NONCE_LEN, SEAL_PUB_PEM_LEN, SEAL_VERSION,
    SPKI_P384_LEN, TAG_LEN,
};
