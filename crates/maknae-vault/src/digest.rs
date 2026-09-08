//! SHA-256 through the pinned FIPS module (aws-lc-rs, the provider the TLS
//! stack asserts). Used for audit content digests (#172): the trail holds a
//! digest of what was sent, never the content. Incremental so callers need
//! not concatenate secret text into a second buffer.

pub struct Sha256(aws_lc_rs::digest::Context);

impl Sha256 {
    pub fn new() -> Self {
        Sha256(aws_lc_rs::digest::Context::new(&aws_lc_rs::digest::SHA256))
    }
    pub fn update(&mut self, b: &[u8]) {
        self.0.update(b)
    }
    pub fn finish_hex(self) -> String {
        self.0
            .finish()
            .as_ref()
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect()
    }
}

impl Default for Sha256 {
    fn default() -> Self {
        Self::new()
    }
}

pub fn sha256_hex(b: &[u8]) -> String {
    let mut h = Sha256::new();
    h.update(b);
    h.finish_hex()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn known_vector_and_incremental_equivalence() {
        assert_eq!(
            sha256_hex(b"abc"),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
        let mut h = Sha256::new();
        h.update(b"ab");
        h.update(b"c");
        assert_eq!(h.finish_hex(), sha256_hex(b"abc"));
        assert_ne!(sha256_hex(b""), sha256_hex(b"a"));
        assert_eq!(sha256_hex(b"").len(), 64);
        // T1 floor: the Default body is a region too (the maknae-audit-append session.rs precedent).
        assert_eq!(Sha256::default().finish_hex(), sha256_hex(b""));
    }
}
