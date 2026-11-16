//! The posture marker (`<config_dir>/private/posture.yaml`, spec §4.6/§5.2): `maknae enroll`
//! writes it and `maknaed` reads it at boot, so its format lives here, once (#79).

use crate::value::Value;
use yaml_rust2::yaml::Hash;
use yaml_rust2::{Yaml, YamlEmitter};

/// Relative to the config directory.
pub const POSTURE_MARKER_FILE: &str = "private/posture.yaml";
pub const MECHANISM_TPM2: &str = "tpm2";
pub const MECHANISM_KEYCHAIN: &str = "keychain";

/// The provisioning-time attestation: the sealing mechanism, the sealed target path, and
/// when it was written.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PostureMarker {
    pub mechanism: String,
    pub target: String,
    pub timestamp: String,
}

impl PostureMarker {
    pub fn render(&self) -> String {
        let mut map = Hash::new();
        for (key, value) in [
            ("mechanism", &self.mechanism),
            ("target", &self.target),
            ("timestamp", &self.timestamp),
        ] {
            map.insert(Yaml::String(key.into()), Yaml::String(value.clone()));
        }
        let mut out = String::new();
        YamlEmitter::new(&mut out)
            .dump(&Yaml::Hash(map))
            .expect("emitting into a String cannot fail");
        out.push('\n');
        out
    }

    /// `None` unless the document is a map holding all three keys as strings.
    pub fn from_value(value: &Value) -> Option<Self> {
        let Value::Map(entries) = value else {
            return None;
        };
        let get = |key: &str| {
            entries
                .iter()
                .find(|(k, _)| k == key)
                .and_then(|(_, v)| match v {
                    Value::Str(s) => Some(s.clone()),
                    _ => None,
                })
        };
        Some(PostureMarker {
            mechanism: get("mechanism")?,
            target: get("target")?,
            timestamp: get("timestamp")?,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn marker(target: &str, timestamp: &str) -> PostureMarker {
        PostureMarker {
            mechanism: MECHANISM_TPM2.to_string(),
            target: target.to_string(),
            timestamp: timestamp.to_string(),
        }
    }

    fn reparse(m: &PostureMarker) -> Option<PostureMarker> {
        PostureMarker::from_value(&crate::load_str(&m.render()).expect("rendered marker loads"))
    }

    #[test]
    fn a_rendered_marker_parses_back_to_itself() {
        for target in [
            "/etc/maknae/private/maknaed-secret-id.cred",
            "/odd: path #x",
            "- leading dash",
            "it's \"quoted\"",
            "",
        ] {
            let m = marker(target, "1786563711");
            assert_eq!(reparse(&m), Some(m.clone()), "target {target:?}");
        }
        let keychain = PostureMarker {
            mechanism: MECHANISM_KEYCHAIN.to_string(),
            ..marker("/x", "1")
        };
        assert_eq!(reparse(&keychain), Some(keychain.clone()));
    }

    #[test]
    fn the_mechanism_tokens_are_the_wire_values() {
        assert_eq!((MECHANISM_TPM2, MECHANISM_KEYCHAIN), ("tpm2", "keychain"));
    }

    #[test]
    fn an_all_digit_timestamp_is_written_as_a_string() {
        let text = marker("/etc/maknae/private/maknaed-secret-id.cred", "1786563711").render();
        assert_eq!(
            text,
            "---\nmechanism: tpm2\ntarget: /etc/maknae/private/maknaed-secret-id.cred\ntimestamp: \"1786563711\"\n"
        );
    }

    fn parse(text: &str) -> Option<PostureMarker> {
        PostureMarker::from_value(&crate::load_str(text).expect("fixture loads"))
    }

    #[test]
    fn a_complete_marker_parses() {
        assert_eq!(
            parse("mechanism: keychain\ntarget: /t\ntimestamp: \"9\"\n"),
            Some(PostureMarker {
                mechanism: "keychain".into(),
                target: "/t".into(),
                timestamp: "9".into(),
            })
        );
    }

    #[test]
    fn a_plain_iso_timestamp_parses() {
        assert_eq!(
            parse("mechanism: tpm2\ntarget: /t\ntimestamp: 2026-08-12T00:00:00.000Z\n")
                .map(|m| m.timestamp),
            Some("2026-08-12T00:00:00.000Z".to_string())
        );
    }

    #[test]
    fn a_marker_missing_any_key_is_none() {
        assert_eq!(parse("target: /t\ntimestamp: \"9\"\n"), None);
        assert_eq!(parse("mechanism: tpm2\ntimestamp: \"9\"\n"), None);
        assert_eq!(parse("mechanism: tpm2\ntarget: /t\n"), None);
    }

    #[test]
    fn a_marker_with_a_non_string_value_is_none() {
        assert_eq!(parse("mechanism: tpm2\ntarget: /t\ntimestamp: 9\n"), None);
        assert_eq!(
            parse("mechanism: [tpm2]\ntarget: /t\ntimestamp: \"9\"\n"),
            None
        );
        assert_eq!(
            parse("mechanism: tpm2\ntarget: true\ntimestamp: \"9\"\n"),
            None
        );
    }

    #[test]
    fn a_document_that_is_not_a_map_is_none() {
        assert_eq!(parse("just a scalar\n"), None);
        assert_eq!(parse("- mechanism\n- target\n"), None);
    }
}
