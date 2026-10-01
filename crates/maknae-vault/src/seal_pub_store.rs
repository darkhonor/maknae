use crate::VaultError;
use maknae_io::{AnchorRequired, IoError, IoKind, TargetRequired};
use std::path::Path;

pub const MAX_SEAL_PUB_BYTES: usize = 215;
const NO_GROUP_OTHER_WRITE: u32 = 0o022;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SealPubHome {
    RedHat,
    Debian,
    MacOs,
}

pub fn seal_pub_path(home: SealPubHome) -> &'static str {
    match home {
        SealPubHome::RedHat => "/etc/pki/maknae/seal.pub",
        SealPubHome::Debian => "/etc/ssl/maknae/seal.pub",
        SealPubHome::MacOs => "/Library/Application Support/Maknae/pki/seal.pub",
    }
}

#[cfg(target_os = "macos")]
pub(crate) const HOST_HOMES: &[SealPubHome] = &[SealPubHome::MacOs];
#[cfg(not(target_os = "macos"))]
pub(crate) const HOST_HOMES: &[SealPubHome] = &[SealPubHome::RedHat, SealPubHome::Debian];

pub fn linux_home_from_os_release(text: &str) -> Option<SealPubHome> {
    let mut id = None;
    let mut id_like = None;
    for line in text.lines() {
        match line.trim().split_once('=') {
            Some(("ID", value)) => id = Some(unquote(value)),
            Some(("ID_LIKE", value)) => id_like = Some(unquote(value)),
            _ => {}
        }
    }
    id.into_iter()
        .chain(id_like.into_iter().flat_map(str::split_whitespace))
        .find_map(linux_family)
}

fn unquote(value: &str) -> &str {
    ['"', '\'']
        .into_iter()
        .find_map(|q| value.strip_prefix(q)?.strip_suffix(q))
        .unwrap_or(value)
}

fn linux_family(token: &str) -> Option<SealPubHome> {
    match token {
        "rhel" | "fedora" | "centos" | "rocky" | "almalinux" => Some(SealPubHome::RedHat),
        "debian" | "ubuntu" => Some(SealPubHome::Debian),
        _ => None,
    }
}

pub fn choose_present(found: &[(SealPubHome, bool)]) -> Result<SealPubHome, VaultError> {
    let mut present = found
        .iter()
        .filter(|(_, here)| *here)
        .map(|(home, _)| *home);
    match (present.next(), present.next()) {
        (None, _) => Err(VaultError::SealPubAbsent),
        (Some(home), None) => Ok(home),
        (Some(first), Some(second)) => Err(VaultError::SealPubAmbiguous {
            first: seal_pub_path(first),
            second: seal_pub_path(second),
        }),
    }
}

pub(crate) fn seal_pub_dir_required(owner: u32) -> AnchorRequired {
    AnchorRequired {
        owner: Some(owner),
        mode_mask: Some(NO_GROUP_OTHER_WRITE),
    }
}

pub(crate) fn seal_pub_file_required(owner: u32) -> TargetRequired {
    TargetRequired {
        owner: Some(owner),
        mode_mask: Some(NO_GROUP_OTHER_WRITE),
        nlink_exactly_one: true,
        regular_file: true,
        max_bytes: Some(MAX_SEAL_PUB_BYTES as u64),
    }
}

pub(crate) fn seal_pub_refusal(e: IoError, path: &Path) -> Option<VaultError> {
    match e {
        IoError::Io {
            kind: IoKind::NotFound,
            ..
        } => None,
        custody @ (IoError::Symlink { .. }
        | IoError::NotRegularFile { .. }
        | IoError::InsecurePermissions { .. }
        | IoError::NotOwned { .. }
        | IoError::MultiplyLinked { .. }
        | IoError::TargetTooLarge { .. }) => Some(VaultError::SealPubRefused {
            path: path.to_path_buf(),
            detail: custody.to_string(),
        }),
        other => Some(VaultError::SealPubMalformed {
            path: path.to_path_buf(),
            detail: other.to_string(),
        }),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const ROCKY_10: &str = "NAME=\"Rocky Linux\"\nVERSION=\"10.0 (Red Quartz)\"\nID=\"rocky\"\nID_LIKE=\"rhel centos fedora\"\nVERSION_ID=\"10.0\"\n";
    const RHEL_9: &str =
        "NAME=\"Red Hat Enterprise Linux\"\nID=\"rhel\"\nID_LIKE=\"fedora\"\nVERSION_ID=\"9.6\"\n";
    const DEBIAN_13: &str = "PRETTY_NAME=\"Debian GNU/Linux 13 (trixie)\"\nNAME=\"Debian GNU/Linux\"\nVERSION_ID=\"13\"\nID=debian\n";
    const UBUNTU: &str = "NAME=\"Ubuntu\"\nID=ubuntu\nID_LIKE=debian\nVERSION_ID=\"24.04\"\n";
    const MINT: &str = "NAME=\"Linux Mint\"\nID=linuxmint\nID_LIKE=\"ubuntu debian\"\n";

    #[test]
    fn the_three_locations_are_fixed() {
        assert_eq!(
            seal_pub_path(SealPubHome::RedHat),
            "/etc/pki/maknae/seal.pub"
        );
        assert_eq!(
            seal_pub_path(SealPubHome::Debian),
            "/etc/ssl/maknae/seal.pub"
        );
        assert_eq!(
            seal_pub_path(SealPubHome::MacOs),
            "/Library/Application Support/Maknae/pki/seal.pub"
        );
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn macos_reads_only_its_own_location() {
        assert_eq!(HOST_HOMES, [SealPubHome::MacOs]);
    }

    #[cfg(not(target_os = "macos"))]
    #[test]
    fn linux_reads_both_linux_locations() {
        assert_eq!(HOST_HOMES, [SealPubHome::RedHat, SealPubHome::Debian]);
    }

    #[test]
    fn the_seal_pub_bound_is_the_canonical_pem_length() {
        assert_eq!(MAX_SEAL_PUB_BYTES, maknae_seal::SEAL_PUB_PEM_LEN);
    }

    #[test]
    fn os_release_id_then_id_like_picks_the_family() {
        let rows: [(&str, Option<SealPubHome>); 14] = [
            (ROCKY_10, Some(SealPubHome::RedHat)),
            (RHEL_9, Some(SealPubHome::RedHat)),
            (
                "ID=\"almalinux\"\nID_LIKE=\"rhel centos fedora\"\n",
                Some(SealPubHome::RedHat),
            ),
            (
                "ID=\"centos\"\nID_LIKE=\"rhel fedora\"\n",
                Some(SealPubHome::RedHat),
            ),
            ("ID=fedora\n", Some(SealPubHome::RedHat)),
            (DEBIAN_13, Some(SealPubHome::Debian)),
            (UBUNTU, Some(SealPubHome::Debian)),
            (MINT, Some(SealPubHome::Debian)),
            ("ID='rocky'\n", Some(SealPubHome::RedHat)),
            ("ID=debian\nID_LIKE=\"rhel\"\n", Some(SealPubHome::Debian)),
            (
                "ID=foo\nID_LIKE=\"rhel debian\"\n",
                Some(SealPubHome::RedHat),
            ),
            ("ID=arch\n", None),
            (
                "ID=\"opensuse-tumbleweed\"\nID_LIKE=\"opensuse suse\"\n",
                None,
            ),
            ("", None),
        ];
        for (text, want) in rows {
            assert_eq!(linux_home_from_os_release(text), want, "{text:?}");
        }
        for text in [
            "ID=\"rocky\n",
            "VERSION_ID=rhel\n",
            "# ID=rocky\n",
            "ID=Rocky\n",
            "ID=rhel9\n",
        ] {
            assert_eq!(linux_home_from_os_release(text), None, "{text:?}");
        }
    }

    #[test]
    fn exactly_one_present_location_is_chosen() {
        use SealPubHome::{Debian, MacOs, RedHat};
        assert_eq!(
            choose_present(&[(RedHat, true), (Debian, false)]).unwrap(),
            RedHat
        );
        assert_eq!(
            choose_present(&[(RedHat, false), (Debian, true)]).unwrap(),
            Debian
        );
        assert_eq!(choose_present(&[(MacOs, true)]).unwrap(), MacOs);
        for none in [
            &[(RedHat, false), (Debian, false)][..],
            &[(MacOs, false)][..],
            &[][..],
        ] {
            assert!(matches!(
                choose_present(none),
                Err(VaultError::SealPubAbsent)
            ));
        }
        assert!(matches!(
            choose_present(&[(RedHat, true), (Debian, true)]),
            Err(VaultError::SealPubAmbiguous {
                first: "/etc/pki/maknae/seal.pub",
                second: "/etc/ssl/maknae/seal.pub"
            })
        ));
    }

    #[test]
    fn the_seal_pub_is_root_owned_unwritable_by_others_single_link_and_bounded() {
        assert_eq!(
            seal_pub_dir_required(0),
            AnchorRequired {
                owner: Some(0),
                mode_mask: Some(0o022)
            }
        );
        assert_eq!(
            seal_pub_file_required(0),
            TargetRequired {
                owner: Some(0),
                mode_mask: Some(0o022),
                nlink_exactly_one: true,
                regular_file: true,
                max_bytes: Some(215)
            }
        );
        assert_eq!(seal_pub_dir_required(501).owner, Some(501));
        assert_eq!(seal_pub_file_required(501).owner, Some(501));
    }

    #[test]
    fn only_a_missing_location_is_absent() {
        let path = Path::new("/etc/pki/maknae/seal.pub");
        let missing = IoError::Io {
            path: path.into(),
            kind: IoKind::NotFound,
        };
        assert!(seal_pub_refusal(missing, path).is_none());
        let writable = IoError::InsecurePermissions {
            path: path.into(),
            mode: 0o664,
        };
        match seal_pub_refusal(writable, path) {
            Some(VaultError::SealPubRefused { path: p, detail }) => {
                assert_eq!(p, path);
                assert!(!detail.is_empty());
            }
            other => panic!("{other:?}"),
        }
        let denied = IoError::Io {
            path: path.into(),
            kind: IoKind::PermissionDenied,
        };
        assert!(matches!(
            seal_pub_refusal(denied, path),
            Some(VaultError::SealPubMalformed { .. })
        ));
        for custody in [
            IoError::Symlink { path: path.into() },
            IoError::NotRegularFile { path: path.into() },
            IoError::NotOwned {
                path: path.into(),
                uid: 501,
                want: 0,
            },
            IoError::MultiplyLinked {
                path: path.into(),
                nlink: 2,
            },
            IoError::TargetTooLarge {
                path: path.into(),
                limit: 215,
                actual: 216,
            },
        ] {
            assert!(
                matches!(
                    seal_pub_refusal(custody, path),
                    Some(VaultError::SealPubRefused { .. })
                ),
                "custody failure"
            );
        }
    }
}
