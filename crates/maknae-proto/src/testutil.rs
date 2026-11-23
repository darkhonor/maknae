#![cfg(test)]

use crate::{SealedForgeToken, SealedKey, SEALED_KEY_MAX_BYTES};

pub(crate) fn widest_forge_tokens(count: usize) -> Vec<SealedForgeToken> {
    (0..count)
        .map(|i| {
            let lead = char::from(b'a' + u8::try_from(i).unwrap());
            let server = format!("{lead}{}:65535", "a".repeat(crate::SERVER_MAX_BYTES - 7));
            let nonce = format!("{i:0>32x}");
            let sealed = SealedKey::new(vec![0x53; SEALED_KEY_MAX_BYTES]).unwrap();
            SealedForgeToken::new(server, nonce, sealed).unwrap()
        })
        .collect()
}
