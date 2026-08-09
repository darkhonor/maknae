//! Language-neutral golden vectors for the fail-closed loading core (spec §7).
//! Assert the error/type, never a silently-wrong value.

use maknae_config::{load_str, ConfigError, Value};

// ---- duplicate keys ----

#[test]
fn v_dup_top_level() {
    assert!(matches!(
        load_str("a: 1\na: 2\n"),
        Err(ConfigError::DuplicateKey { .. })
    ));
}

#[test]
fn v_dup_nested() {
    assert!(matches!(
        load_str("m:\n  a: 1\n  a: 2\n"),
        Err(ConfigError::DuplicateKey { .. })
    ));
}

#[test]
fn v_dup_plain_vs_quoted_collide() {
    // plain `a` and quoted `"a"` both resolve to "a" → collision (fail-safe direction)
    assert!(matches!(
        load_str("a: 1\n\"a\": 2\n"),
        Err(ConfigError::DuplicateKey { .. })
    ));
}

#[test]
fn v_dup_then_more_content_returns_error_not_tree() {
    // surfacing glue: the recorded error is returned, the partial tree is NOT
    match load_str("a: 1\na: 2\nb: 3\n") {
        Err(ConfigError::DuplicateKey { key, .. }) => assert_eq!(key, "a"),
        other => panic!("expected DuplicateKey, got {other:?}"),
    }
}

// ---- reject-exotic ----

#[test]
fn v_alias_rejected() {
    assert!(matches!(
        load_str("a: &x 1\nb: *x\n"),
        Err(ConfigError::Parse { .. })
    ));
}

#[test]
fn v_tagged_scalar_rejected() {
    assert!(matches!(
        load_str("a: !!str 1\n"),
        Err(ConfigError::Parse { .. })
    ));
}

#[test]
fn v_tagged_container_rejected() {
    // tagged mapping (MappingStart tag) and tagged sequence (SequenceStart tag)
    assert!(matches!(
        load_str("a: !!map {p: 1}\n"),
        Err(ConfigError::Parse { .. })
    ));
    assert!(matches!(
        load_str("a: !!seq [1, 2]\n"),
        Err(ConfigError::Parse { .. })
    ));
}

#[test]
fn v_second_document_rejected() {
    assert!(matches!(
        load_str("a: 1\n---\nb: 2\n"),
        Err(ConfigError::Parse { .. })
    ));
}

#[test]
fn v_non_string_key_rejected() {
    assert!(matches!(load_str("1: a\n"), Err(ConfigError::Parse { .. })));
    assert!(matches!(
        load_str("true: a\n"),
        Err(ConfigError::Parse { .. })
    ));
}

#[test]
fn v_container_key_rejected() {
    assert!(matches!(
        load_str("? [a, b]\n: v\n"),
        Err(ConfigError::Parse { .. })
    ));
}

#[test]
fn v_depth_129_is_parse_not_panic() {
    let deep = "[".repeat(129) + &"]".repeat(129);
    assert!(matches!(load_str(&deep), Err(ConfigError::Parse { .. })));
}

#[test]
fn v_depth_128_accepted() {
    let ok = "[".repeat(128) + &"]".repeat(128);
    assert!(load_str(&ok).is_ok());
}

// ---- allowed-inert ----

#[test]
fn v_lone_anchor_builds() {
    assert_eq!(
        load_str("a: &x 1\n").unwrap(),
        Value::Map(vec![("a".into(), Value::Int(1))])
    );
}

// ---- scalar typing ----

#[test]
fn v_scalar_typing() {
    assert_eq!(
        load_str("x: \"1\"").unwrap(),
        Value::Map(vec![("x".into(), Value::Str("1".into()))])
    );
    assert_eq!(
        load_str("x: 1").unwrap(),
        Value::Map(vec![("x".into(), Value::Int(1))])
    );
    assert_eq!(
        load_str("x: ~").unwrap(),
        Value::Map(vec![("x".into(), Value::Null)])
    );
    assert_eq!(
        load_str("x: true").unwrap(),
        Value::Map(vec![("x".into(), Value::Bool(true))])
    );
    assert_eq!(
        load_str("x: hi").unwrap(),
        Value::Map(vec![("x".into(), Value::Str("hi".into()))])
    );
    assert_eq!(
        load_str("x: 0x1F").unwrap(),
        Value::Map(vec![("x".into(), Value::Int(31))])
    );
}

#[test]
fn v_inf_rejected() {
    // both spellings of infinity: the literal `.inf` and the overflow `1e999`
    assert!(matches!(
        load_str("x: .inf\n"),
        Err(ConfigError::Parse { .. })
    ));
    assert!(matches!(
        load_str("x: 1e999\n"),
        Err(ConfigError::Parse { .. })
    ));
    assert!(matches!(
        load_str("x: -1e999\n"),
        Err(ConfigError::Parse { .. })
    ));
    // i64-overflow integer must not silently become a lossy Float
    assert!(matches!(
        load_str("x: 99999999999999999999999\n"),
        Err(ConfigError::Parse { .. })
    ));
}

// ---- happy path ----

#[test]
fn v_nested_roundtrip_ordered() {
    let got = load_str("b: 2\na:\n  - 1\n  - two\n").unwrap();
    assert_eq!(
        got,
        Value::Map(vec![
            ("b".into(), Value::Int(2)),
            (
                "a".into(),
                Value::Seq(vec![Value::Int(1), Value::Str("two".into())])
            ),
        ])
    );
}

#[test]
fn v_empty_is_null() {
    assert_eq!(load_str("").unwrap(), Value::Null);
    assert_eq!(load_str("   \n").unwrap(), Value::Null);
}
