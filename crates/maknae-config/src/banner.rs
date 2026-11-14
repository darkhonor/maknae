//! `banner.yaml`: the operator's banner, read by `maknaed` and shown verbatim.

use crate::{ConfigError, Value};
use maknae_proto::{check_banner, BannerColor, BannerSpec};
use std::path::Path;

pub const BANNER_PATH: &str = "/etc/maknae/banner.yaml";

const BANNER_FILE: &str = "banner.yaml";

fn invalid(reason: impl std::fmt::Display) -> ConfigError {
    ConfigError::InvalidBanner(reason.to_string())
}

fn parse_color(text: &str) -> Result<BannerColor, ConfigError> {
    let named = match text {
        "black" => Some(BannerColor::Black),
        "red" => Some(BannerColor::Red),
        "green" => Some(BannerColor::Green),
        "yellow" => Some(BannerColor::Yellow),
        "blue" => Some(BannerColor::Blue),
        "magenta" => Some(BannerColor::Magenta),
        "cyan" => Some(BannerColor::Cyan),
        "white" => Some(BannerColor::White),
        _ => None,
    };
    if let Some(color) = named {
        return Ok(color);
    }
    let hex = text
        .strip_prefix('#')
        .filter(|h| h.len() == 6 && h.bytes().all(|b| b.is_ascii_hexdigit()));
    let Some(hex) = hex else {
        return Err(invalid(
            "color must be black, red, green, yellow, blue, magenta, cyan, white or #rrggbb",
        ));
    };
    let byte = |i: usize| u8::from_str_radix(&hex[i..i + 2], 16).map_err(invalid);
    Ok(BannerColor::Rgb(byte(0)?, byte(2)?, byte(4)?))
}

pub fn banner_from_document(doc: &Value) -> Result<BannerSpec, ConfigError> {
    let Value::Map(map) = doc else {
        return Err(invalid("the document must be a mapping"));
    };
    crate::reject_unknown_keys(BANNER_FILE, map, &["text", "color"])?;
    let get = |key: &str| map.iter().find(|(k, _)| k == key).map(|(_, v)| v);
    let text = match get("text") {
        Some(Value::Str(s)) => s.clone(),
        Some(_) => return Err(invalid("`text` must be a string")),
        None => return Err(invalid("`text` is required")),
    };
    let color = match get("color") {
        Some(Value::Str(s)) => Some(parse_color(s)?),
        Some(_) => return Err(invalid("`color` must be a quoted string")),
        None => None,
    };
    let spec = BannerSpec { text, color };
    check_banner(&spec).map_err(invalid)?;
    Ok(spec)
}

pub fn load_banner(path: &Path) -> Result<Option<BannerSpec>, ConfigError> {
    #[cfg(not(unix))]
    {
        let _ = path;
        Err(ConfigError::PermissionsUnsupported)
    }
    #[cfg(unix)]
    {
        load_required(path, crate::loader::ROOT_ARTIFACT)
    }
}

#[cfg(unix)]
fn load_required(
    path: &Path,
    target: maknae_io::TargetRequired,
) -> Result<Option<BannerSpec>, ConfigError> {
    use crate::authz::RootReadError;
    let absolute = std::path::absolute(path).map_err(|e| ConfigError::Io(e.to_string()))?;
    match crate::authz::read_in_root_dir(&absolute, target) {
        Ok(bytes) => {
            let text = std::str::from_utf8(&bytes)
                .map_err(|e| ConfigError::Io(format!("invalid UTF-8: {e}")))?;
            banner_from_document(&crate::load_str(text)?).map(Some)
        }
        Err(RootReadError::Directory(dir)) => Err(ConfigError::Io(format!(
            "the directory {} holding {BANNER_FILE} must be owned by root (uid 0) and not group- or other-writable",
            dir.display()
        ))),
        Err(RootReadError::Io(maknae_io::IoError::Io {
            kind: maknae_io::IoKind::NotFound,
            path: missing,
        })) if missing == absolute => Ok(None),
        Err(RootReadError::Io(other)) => Err(crate::loader::map_io(other)),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn doc(yaml: &str) -> Result<BannerSpec, ConfigError> {
        banner_from_document(&crate::load_str(yaml).unwrap())
    }

    #[test]
    fn text_only_is_reverse_video() {
        let spec = doc("text: \"UNCLASSIFIED\"\n").unwrap();
        assert_eq!(spec.text, "UNCLASSIFIED");
        assert_eq!(spec.color, None);
    }

    #[test]
    fn each_named_colour_and_rgb_parse() {
        for (name, want) in [
            ("black", BannerColor::Black),
            ("red", BannerColor::Red),
            ("green", BannerColor::Green),
            ("yellow", BannerColor::Yellow),
            ("blue", BannerColor::Blue),
            ("magenta", BannerColor::Magenta),
            ("cyan", BannerColor::Cyan),
            ("white", BannerColor::White),
        ] {
            let got = doc(&format!("text: x\ncolor: {name}\n")).unwrap();
            assert_eq!(got.color, Some(want), "{name}");
        }
        let rgb = doc("text: x\ncolor: \"#0a1B2c\"\n").unwrap();
        assert_eq!(rgb.color, Some(BannerColor::Rgb(0x0a, 0x1b, 0x2c)));
    }

    #[test]
    fn red_takes_white_text_and_yellow_takes_black() {
        use maknae_proto::Contrast;
        let colour = |name: &str| doc(&format!("text: x\ncolor: {name}\n")).unwrap().color;
        assert_eq!(colour("red").unwrap().contrast(), Contrast::WhiteText);
        assert_eq!(colour("yellow").unwrap().contrast(), Contrast::BlackText);
    }

    #[test]
    fn an_empty_long_or_control_text_refuses() {
        assert!(matches!(
            doc("text: \"\"\n"),
            Err(ConfigError::InvalidBanner(m)) if m.contains("empty")
        ));
        let long = "a".repeat(257);
        assert!(matches!(
            doc(&format!("text: \"{long}\"\n")),
            Err(ConfigError::InvalidBanner(m)) if m.contains("256")
        ));
        let exact = "a".repeat(256);
        assert!(doc(&format!("text: \"{exact}\"\n")).is_ok());
        for bad in ["a\\u001bb", "a\\nb", "a\\u2028b", "a\\u202eb", "a\\u007fb"] {
            assert!(
                matches!(
                    doc(&format!("text: \"{bad}\"\n")),
                    Err(ConfigError::InvalidBanner(m)) if m.contains("control")
                ),
                "{bad}"
            );
        }
        assert!(matches!(
            doc("color: red\n"),
            Err(ConfigError::InvalidBanner(m)) if m.contains("required")
        ));
        assert!(matches!(
            doc("text: 7\n"),
            Err(ConfigError::InvalidBanner(m)) if m.contains("string")
        ));
    }

    #[test]
    fn an_unknown_key_or_colour_refuses() {
        assert!(matches!(
            doc("text: x\ncolour: red\n"),
            Err(ConfigError::UnknownKey { section, key })
                if section == "banner.yaml" && key == "colour"
        ));
        for bad in [
            "\"Red\"",
            "orange",
            "\"#fff\"",
            "\"#ggg000\"",
            "\"#+f0000\"",
            "\"#ff00000\"",
            "7",
        ] {
            assert!(
                matches!(
                    doc(&format!("text: x\ncolor: {bad}\n")),
                    Err(ConfigError::InvalidBanner(_))
                ),
                "{bad}"
            );
        }
        assert!(matches!(
            banner_from_document(&Value::Seq(vec![])),
            Err(ConfigError::InvalidBanner(_))
        ));
    }

    #[test]
    fn a_received_spec_is_validated_like_the_file() {
        for text in ["", "ok", "a\u{1b}b", "a\u{202e}b", &"a".repeat(257)] {
            let spec = BannerSpec {
                text: text.to_string(),
                color: None,
            };
            let from_file = banner_from_document(&Value::Map(vec![(
                "text".into(),
                Value::Str(text.to_string()),
            )]));
            assert_eq!(check_banner(&spec).is_ok(), from_file.is_ok(), "{text:?}");
        }
    }

    #[test]
    fn every_banner_refusal_names_the_file() {
        let e = doc("text: \"\"\n").unwrap_err();
        assert!(e.to_string().starts_with("banner.yaml: "), "{e}");
    }

    #[cfg(unix)]
    mod io {
        use super::*;
        use std::os::unix::fs::{MetadataExt, PermissionsExt};

        fn dir(tag: &str) -> std::path::PathBuf {
            let d = std::env::temp_dir().join(format!("banner_{tag}_{}", std::process::id()));
            let _ = std::fs::remove_dir_all(&d);
            std::fs::create_dir_all(&d).unwrap();
            std::fs::set_permissions(&d, std::fs::Permissions::from_mode(0o750)).unwrap();
            d.canonicalize().unwrap()
        }

        fn own(d: &Path) -> maknae_io::TargetRequired {
            maknae_io::TargetRequired {
                owner: Some(std::fs::metadata(d).unwrap().uid()),
                ..crate::loader::ROOT_ARTIFACT
            }
        }

        #[test]
        fn a_missing_banner_file_is_no_banner() {
            let d = dir("missing");
            let got = load_required(&d.join(BANNER_FILE), own(&d));
            let _ = std::fs::remove_dir_all(&d);
            assert_eq!(got, Ok(None));
        }

        #[test]
        fn a_banner_file_in_an_unsafe_directory_refuses() {
            let d = dir("unsafe");
            let file = d.join(BANNER_FILE);
            std::fs::write(&file, "text: x\n").unwrap();
            std::fs::set_permissions(&file, std::fs::Permissions::from_mode(0o640)).unwrap();
            std::fs::set_permissions(&d, std::fs::Permissions::from_mode(0o770)).unwrap();
            let present = load_required(&file, own(&d));
            let absent = load_required(&d.join("gone.yaml"), own(&d));
            let _ = std::fs::remove_dir_all(&d);
            for got in [present, absent] {
                assert!(
                    matches!(&got, Err(ConfigError::Io(m)) if m.contains("holding banner.yaml")),
                    "{got:?}"
                );
            }
        }

        #[test]
        fn a_missing_directory_is_a_refusal_not_no_banner() {
            let d = dir("nodir");
            let got = load_required(&d.join("gone").join(BANNER_FILE), own(&d));
            let _ = std::fs::remove_dir_all(&d);
            assert!(got.is_err(), "{got:?}");
        }

        #[test]
        fn a_present_banner_file_is_read_and_checked() {
            let d = dir("present");
            let file = d.join(BANNER_FILE);
            std::fs::write(&file, "text: \"CUI\"\ncolor: yellow\n").unwrap();
            std::fs::set_permissions(&file, std::fs::Permissions::from_mode(0o640)).unwrap();
            let good = load_required(&file, own(&d));
            std::fs::write(&file, "text: \"\"\n").unwrap();
            let bad = load_required(&file, own(&d));
            std::fs::write(&file, "text: [\n").unwrap();
            let malformed = load_required(&file, own(&d));
            std::fs::write(&file, [0xff, 0xfe]).unwrap();
            let binary = load_required(&file, own(&d));
            let _ = std::fs::remove_dir_all(&d);
            assert_eq!(
                good,
                Ok(Some(BannerSpec {
                    text: "CUI".into(),
                    color: Some(BannerColor::Yellow)
                }))
            );
            assert!(matches!(bad, Err(ConfigError::InvalidBanner(_))));
            assert!(matches!(malformed, Err(ConfigError::Parse { .. })));
            assert!(matches!(binary, Err(ConfigError::Io(m)) if m.contains("UTF-8")));
        }

        #[test]
        fn the_production_reader_requires_a_root_owned_directory() {
            let d = dir("prod");
            let root = std::fs::metadata(&d).unwrap().uid() == 0;
            let got = load_banner(&d.join(BANNER_FILE));
            let _ = std::fs::remove_dir_all(&d);
            if root {
                assert_eq!(got, Ok(None));
            } else {
                assert!(
                    matches!(got, Err(ConfigError::Io(m)) if m.contains("holding banner.yaml"))
                );
            }
        }

        #[test]
        fn a_file_not_owned_by_the_required_owner_refuses() {
            let d = dir("owner");
            let file = d.join(BANNER_FILE);
            std::fs::write(&file, "text: x\n").unwrap();
            std::fs::set_permissions(&file, std::fs::Permissions::from_mode(0o640)).unwrap();
            let mut target = own(&d);
            target.owner = target.owner.map(|u| u.wrapping_add(1));
            let got = load_required(&file, target);
            let _ = std::fs::remove_dir_all(&d);
            assert!(got.is_err(), "{got:?}");
        }
    }
}
