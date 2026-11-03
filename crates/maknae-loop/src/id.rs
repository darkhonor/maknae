//! Conversation IDs. The ID is bound into each turn's sealed-key AAD, so two
//! loops in one process must never share one.

pub fn mint_conversation_id() -> Result<String, String> {
    let mut bytes = [0u8; 8];
    maknae_crypto::random::fill(&mut bytes).map_err(|_| {
        "could not draw a conversation ID from the system random source".to_string()
    })?;
    let mut id = String::with_capacity(17);
    id.push('c');
    for b in bytes {
        id.push_str(&format!("{b:02x}"));
    }
    Ok(id)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_conversation_id_is_minted_within_the_wire_bound() {
        let id = mint_conversation_id().unwrap();
        assert!(maknae_proto::conversation_id_is_acceptable(&id), "{id}");
        assert_eq!(id.len(), 17, "{id}");
        assert!(id.starts_with('c'), "{id}");
        assert!(
            id[1..]
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b)),
            "{id}"
        );
    }

    #[test]
    fn conversation_ids_are_unique_under_burst() {
        let mut seen = std::collections::HashSet::new();
        for _ in 0..10_000 {
            let id = mint_conversation_id().unwrap();
            assert!(maknae_proto::conversation_id_is_acceptable(&id), "{id}");
            assert!(seen.insert(id), "a conversation ID repeated");
        }
    }
}
