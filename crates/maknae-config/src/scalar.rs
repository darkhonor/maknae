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
        // A `Real` reaches here only when yaml-rust2's `i64` parse failed but its
        // `parse_f64` succeeded. Reject two silent mis-values:
        //  - non-finite: `f64::from_str` returns Ok(inf) on overflow (`1e999`/`.inf`),
        //    not Err — so the ".inf"/"1e999" spellings must not diverge;
        //  - integer-shaped `Real` (no `.`/`e`): an i64 OVERFLOW (`999…9`) that would
        //    become a *lossy* `Float` — reject rather than silently lose precision.
        // (Other resolution — e.g. signed `-0x1` → String — is faithful yaml-rust2
        // behavior, not lossy; typed/range validation is a cycle-② schema concern.)
        Yaml::Real(s) => {
            let integer_shaped = !s.contains(['.', 'e', 'E']);
            match f64::from_str(&s) {
                Ok(f) if f.is_finite() && !integer_shaped => Ok(Value::Float(f)),
                _ => Err(()),
            }
        }
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

    #[test]
    fn i64_overflow_integer_is_err_not_lossy_float() {
        // an integer too big for i64 must not silently become a lossy Float
        assert_eq!(
            resolve_scalar("99999999999999999999999".into(), TScalarStyle::Plain),
            Err(())
        );
        assert_eq!(
            resolve_scalar("9223372036854775808".into(), TScalarStyle::Plain), // i64::MAX + 1
            Err(())
        );
        // genuine floats (with '.'/'e') still accepted
        assert_eq!(
            resolve_scalar("1e3".into(), TScalarStyle::Plain),
            Ok(Value::Float(1000.0))
        );
        assert_eq!(
            resolve_scalar("2.5".into(), TScalarStyle::Plain),
            Ok(Value::Float(2.5))
        );
    }
}
