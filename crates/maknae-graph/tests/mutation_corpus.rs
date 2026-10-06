mod common;

use common::*;
use maknae_graph::format::{
    decode, encode, FormatError, HEADER_LEN, SECTIONS_START, SECTION_COUNT,
};
use maknae_graph::kernel::SCHEMA;
use maknae_graph::record::GraphSpace;

struct SplitMix(u64);

impl SplitMix {
    fn next(&mut self) -> u64 {
        self.0 = self.0.wrapping_add(0x9e37_79b9_7f4a_7c15);
        let mut z = self.0;
        z = (z ^ (z >> 30)).wrapping_mul(0xbf58_476d_1ce4_e5b9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94d0_49bb_1331_11eb);
        z ^ (z >> 31)
    }
    fn below(&mut self, n: usize) -> usize {
        (self.next() % n as u64) as usize
    }
}

fn mutate(rng: &mut SplitMix, base: &[u8]) -> Vec<u8> {
    let mut b = base.to_vec();
    for _ in 0..=rng.below(3) {
        match rng.below(6) {
            0 if !b.is_empty() => {
                let i = rng.below(b.len());
                b[i] ^= 1 << rng.below(8);
            }
            1 if !b.is_empty() => {
                let i = rng.below(b.len());
                b[i] = rng.next() as u8;
            }
            2 => b.truncate(rng.below(b.len() + 1)),
            3 if !b.is_empty() => {
                let i = rng.below(b.len());
                let v = (rng.next() as u32).to_le_bytes();
                for (k, byte) in v.iter().enumerate() {
                    if let Some(slot) = b.get_mut(i + k) {
                        *slot = *byte;
                    }
                }
            }
            4 if !b.is_empty() => {
                let i = rng.below(b.len());
                let j = (i + 1 + rng.below(16)).min(b.len());
                let chunk = b[i..j].to_vec();
                b.splice(i..i, chunk);
            }
            _ => b.push(rng.next() as u8),
        }
    }
    b
}

#[test]
fn mutated_stores_refuse_or_are_canonical_and_never_panic() {
    let base = encode(&builder().build(&SCHEMA, &compiled()).unwrap());
    let set = compiled();
    let mut rng = SplitMix(0x4d4b_4e47_0001);
    let mut accepted = 0usize;
    for _ in 0..20_000 {
        let candidate = mutate(&mut rng, &base);
        if let Ok(g) = decode(&candidate, GraphSpace::Kernel, &SCHEMA, &set) {
            assert_eq!(encode(&g), candidate, "an accepted store must be canonical");
            accepted += 1;
        }
    }
    assert!(
        accepted < 20_000,
        "mutation never produced a refusal; the harness is not exercising decode"
    );
    assert!(
        accepted > 0,
        "mutation never produced an accepted store; the harness never reaches the canonical check"
    );
}

#[test]
fn random_bodies_behind_a_valid_header_never_panic() {
    let base = encode(&builder().build(&SCHEMA, &compiled()).unwrap());
    let set = compiled();
    let mut rng = SplitMix(0x4d4b_4e47_0002);
    let mut reached = 0usize;
    for _ in 0..5_000 {
        let body = rng.below(2049);
        let mut cuts: Vec<usize> = (0..SECTION_COUNT - 1)
            .map(|_| rng.below(body + 1))
            .collect();
        cuts.push(0);
        cuts.push(body);
        cuts.sort_unstable();
        let mut b = base[..HEADER_LEN].to_vec();
        for w in cuts.windows(2) {
            b.extend_from_slice(&((SECTIONS_START + w[0]) as u64).to_le_bytes());
            b.extend_from_slice(&((w[1] - w[0]) as u64).to_le_bytes());
        }
        assert_eq!(b.len(), SECTIONS_START);
        for _ in 0..body {
            b.push(rng.next() as u8);
        }
        if !matches!(
            decode(&b, GraphSpace::Kernel, &SCHEMA, &set),
            Err(FormatError::BadSectionLayout)
        ) {
            reached += 1;
        }
    }
    assert!(
        reached > 2_500,
        "only {reached} of 5000 random bodies got past the section table"
    );
}
