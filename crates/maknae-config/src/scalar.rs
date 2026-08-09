//! Scalar resolution (spec §3a) — reuse yaml-rust2's *tested* `Yaml::from_str`
//! rather than re-implement YAML's scalar ladder. Tag/anchor are handled by the
//! caller ([`crate::builder`]) from the event fields, not here.

use crate::value::Value;
use std::str::FromStr;
use yaml_rust2::scanner::TScalarStyle;
use yaml_rust2::yaml::Yaml;

/// Resolve a scalar's `(value, style)` to a `Value`. `Err(())` signals a real
/// that `f64` won't parse (e.g. `.inf`/`.nan`) — the caller records `Parse`.
pub(crate) fn resolve_scalar(value: String, style: TScalarStyle) -> Result<Value, ()> {
    if style != TScalarStyle::Plain {
        // Any quoted / literal / folded scalar is a string (yaml.rs:150).
        return Ok(Value::Str(value));
    }
    match Yaml::from_str(&value) {
        Yaml::Null => Ok(Value::Null),
        Yaml::Boolean(b) => Ok(Value::Bool(b)),
        Yaml::Integer(i) => Ok(Value::Int(i)),
        // Reject non-finite: `f64::from_str` returns Ok(inf) on magnitude overflow
        // (`1e999`), not Err — so filter for finiteness, else the ".inf"/"1e999"
        // spellings of infinity would diverge (a config needs no infinities).
        Yaml::Real(s) => match f64::from_str(&s) {
            Ok(f) if f.is_finite() => Ok(Value::Float(f)),
            _ => Err(()),
        },
        // String (reachable, e.g. "hi") + the variants from_str cannot emit → string.
        _ => Ok(Value::Str(value)),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn quoted_is_always_string() {
        assert_eq!(
            resolve_scalar("1".into(), TScalarStyle::DoubleQuoted),
            Ok(Value::Str("1".into()))
        );
    }

    #[test]
    fn plain_scalars_resolve_by_yaml_rules() {
        assert_eq!(
            resolve_scalar("1".into(), TScalarStyle::Plain),
            Ok(Value::Int(1))
        );
        assert_eq!(
            resolve_scalar("true".into(), TScalarStyle::Plain),
            Ok(Value::Bool(true))
        );
        assert_eq!(
            resolve_scalar("~".into(), TScalarStyle::Plain),
            Ok(Value::Null)
        );
        assert_eq!(
            resolve_scalar("hi".into(), TScalarStyle::Plain),
            Ok(Value::Str("hi".into()))
        );
        assert_eq!(
            resolve_scalar("1.5".into(), TScalarStyle::Plain),
            Ok(Value::Float(1.5))
        );
        assert_eq!(
            resolve_scalar("0x1F".into(), TScalarStyle::Plain),
            Ok(Value::Int(31))
        );
    }

    #[test]
    fn unparseable_real_is_err() {
        assert_eq!(resolve_scalar(".inf".into(), TScalarStyle::Plain), Err(()));
    }

    #[test]
    fn overflow_to_infinity_is_err() {
        // `1e999` parses to Ok(inf) via f64::from_str — must be rejected, not carried.
        assert_eq!(resolve_scalar("1e999".into(), TScalarStyle::Plain), Err(()));
        assert_eq!(
            resolve_scalar("-1e999".into(), TScalarStyle::Plain),
            Err(())
        );
    }
}
