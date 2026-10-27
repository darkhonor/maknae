//! SHA-256 through the FIPS module.
use aws_lc_rs::digest;

pub fn sha256(bytes: &[u8]) -> [u8; 32] {
    let mut out = [0u8; 32];
    out.copy_from_slice(digest::digest(&digest::SHA256, bytes).as_ref());
    out
}

pub fn sha256_hex(bytes: &[u8]) -> String {
    hex(&sha256(bytes))
}

pub struct Sha256(digest::Context);

impl Sha256 {
    pub fn new() -> Self {
        Sha256(digest::Context::new(&digest::SHA256))
    }

    pub fn update(&mut self, bytes: &[u8]) {
        self.0.update(bytes)
    }

    pub fn finish(self) -> [u8; 32] {
        let mut out = [0u8; 32];
        out.copy_from_slice(self.0.finish().as_ref());
        out
    }

    pub fn finish_hex(self) -> String {
        hex(&self.finish())
    }
}

impl Default for Sha256 {
    fn default() -> Self {
        Self::new()
    }
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    const ABC_SHA256: &str = "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad";

    #[test]
    fn sha256_matches_the_fips_180_4_abc_vector() {
        assert_eq!(sha256_hex(b"abc"), ABC_SHA256);
        let hexed: String = sha256(b"abc").iter().map(|b| format!("{b:02x}")).collect();
        assert_eq!(hexed, ABC_SHA256);
    }

    #[test]
    fn incremental_equals_one_shot() {
        let mut h = Sha256::new();
        h.update(b"a");
        h.update(b"bc");
        assert_eq!(h.finish(), sha256(b"abc"));
        let mut h = Sha256::default();
        h.update(b"abc");
        assert_eq!(h.finish_hex(), ABC_SHA256);
    }

    #[test]
    fn the_empty_input_has_its_known_digest() {
        assert_eq!(
            sha256_hex(b""),
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );
    }
}
