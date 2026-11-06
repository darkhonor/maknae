//! The boot self-check of `deployment.mode` against the host, and what the mode
//! binds.

use std::path::Path;

use maknae_config::DeploymentMode;

use crate::baseline_check::Env;

pub(crate) const SYSTEMD_RUNNING: &str = "/run/systemd/system";

pub(crate) const CONTAINER_FILE_MARKERS: [&str; 3] = [
    "/var/run/secrets/kubernetes.io/serviceaccount",
    "/run/.containerenv",
    "/.dockerenv",
];

pub(crate) const CONTAINER_ENV_MARKERS: [&str; 2] = ["KUBERNETES_SERVICE_HOST", "container"];

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Platform {
    Linux,
    Macos,
}

impl Platform {
    pub fn of_build() -> Self {
        if cfg!(target_os = "macos") {
            Platform::Macos
        } else {
            Platform::Linux
        }
    }
}

pub(crate) fn client_listener_wanted(mode: DeploymentMode) -> bool {
    match mode {
        DeploymentMode::LinuxHost | DeploymentMode::MacosHost => true,
        DeploymentMode::Container => false,
    }
}

fn refuse(mode: DeploymentMode, why: impl std::fmt::Display) -> String {
    format!("deployment.mode is {}, but {why}", mode.as_str())
}

pub(crate) fn verify_deployment(
    mode: DeploymentMode,
    env: &dyn Env,
    platform: Platform,
) -> Result<(), String> {
    let container = match (platform, mode) {
        (Platform::Macos, DeploymentMode::MacosHost) => return Ok(()),
        (Platform::Macos, DeploymentMode::LinuxHost | DeploymentMode::Container) => {
            return Err(refuse(
                mode,
                "this is a macOS build; only macos-host runs here",
            ))
        }
        (Platform::Linux, DeploymentMode::MacosHost) => {
            return Err(refuse(mode, "this is a Linux build"))
        }
        (Platform::Linux, DeploymentMode::LinuxHost) => false,
        (Platform::Linux, DeploymentMode::Container) => true,
    };
    let mut file_marker = None;
    for marker in CONTAINER_FILE_MARKERS {
        let present = env
            .presence(Path::new(marker))
            .map_err(|e| refuse(mode, format_args!("{marker} cannot be examined: {e}")))?;
        if present {
            file_marker = Some(marker);
        }
    }
    if container {
        let env_marker = CONTAINER_ENV_MARKERS
            .iter()
            .any(|k| env.env_var(k).is_some_and(|v| !v.is_empty()));
        return if file_marker.is_some() || env_marker {
            Ok(())
        } else {
            Err(refuse(mode, "no container marker is present"))
        };
    }
    if let Some(marker) = file_marker {
        return Err(refuse(mode, format_args!("{marker} marks a container")));
    }
    let systemd = env.presence(Path::new(SYSTEMD_RUNNING)).map_err(|e| {
        refuse(
            mode,
            format_args!("{SYSTEMD_RUNNING} cannot be examined: {e}"),
        )
    })?;
    if systemd {
        Ok(())
    } else {
        Err(refuse(
            mode,
            format_args!("{SYSTEMD_RUNNING} is absent, so systemd is not running"),
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_fixtures::FakeEnv;
    use DeploymentMode::{Container, LinuxHost, MacosHost};
    use Platform::{Linux, Macos};

    fn env(present: &[&str], unreadable: &[&str], vars: &[(&str, &str)]) -> FakeEnv {
        FakeEnv {
            present: present.iter().map(|p| p.into()).collect(),
            unreadable: unreadable.iter().map(|p| p.into()).collect(),
            vars: vars
                .iter()
                .map(|(k, v)| (k.to_string(), v.to_string()))
                .collect(),
            ..FakeEnv::default()
        }
    }

    #[test]
    fn a_linux_host_needs_systemd_and_no_file_marker() {
        assert_eq!(
            verify_deployment(LinuxHost, &env(&[SYSTEMD_RUNNING], &[], &[]), Linux),
            Ok(())
        );
        for marker in CONTAINER_FILE_MARKERS {
            let e = verify_deployment(LinuxHost, &env(&[SYSTEMD_RUNNING, marker], &[], &[]), Linux)
                .unwrap_err();
            assert!(e.contains(marker) && e.contains("linux-host"), "{e}");
        }
        let e = verify_deployment(LinuxHost, &env(&[], &[], &[]), Linux).unwrap_err();
        assert!(e.contains(SYSTEMD_RUNNING), "{e}");
    }

    #[test]
    fn a_probe_that_cannot_answer_refuses() {
        for unreadable in CONTAINER_FILE_MARKERS.iter().chain([&SYSTEMD_RUNNING]) {
            for mode in [LinuxHost, Container] {
                let e = verify_deployment(
                    mode,
                    &env(
                        &[SYSTEMD_RUNNING],
                        &[unreadable],
                        &[("container", "podman")],
                    ),
                    Linux,
                );
                if mode == Container && *unreadable == SYSTEMD_RUNNING {
                    assert_eq!(e, Ok(()), "container does not consult systemd");
                    continue;
                }
                let e = e.unwrap_err();
                assert!(
                    e.contains(unreadable) && e.contains("cannot be examined"),
                    "{e}"
                );
            }
        }
    }

    #[test]
    fn an_environment_marker_never_refuses_a_linux_host() {
        let vars = [
            ("KUBERNETES_SERVICE_HOST", "10.0.0.1"),
            ("container", "podman"),
        ];
        assert_eq!(
            verify_deployment(LinuxHost, &env(&[SYSTEMD_RUNNING], &[], &vars), Linux),
            Ok(())
        );
    }

    #[test]
    fn a_container_needs_a_marker() {
        for marker in CONTAINER_FILE_MARKERS {
            assert_eq!(
                verify_deployment(Container, &env(&[marker], &[], &[]), Linux),
                Ok(()),
                "{marker}"
            );
        }
        for var in CONTAINER_ENV_MARKERS {
            assert_eq!(
                verify_deployment(Container, &env(&[], &[], &[(var, "podman")]), Linux),
                Ok(()),
                "{var}"
            );
            let e = verify_deployment(Container, &env(&[], &[], &[(var, "")]), Linux).unwrap_err();
            assert!(e.contains("no container marker"), "{e}");
        }
        let e =
            verify_deployment(Container, &env(&[SYSTEMD_RUNNING], &[], &[]), Linux).unwrap_err();
        assert!(
            e.contains("container") && e.contains("no container marker"),
            "{e}"
        );
    }

    #[test]
    fn each_build_accepts_only_its_own_host_modes() {
        let host = env(&[SYSTEMD_RUNNING], &[], &[]);
        assert!(verify_deployment(MacosHost, &host, Linux).is_err());
        assert_eq!(verify_deployment(MacosHost, &host, Macos), Ok(()));
        for mode in [LinuxHost, Container] {
            let in_a_container = env(&["/.dockerenv", SYSTEMD_RUNNING], &[], &[]);
            let e = verify_deployment(mode, &in_a_container, Macos).unwrap_err();
            assert!(e.contains("macOS"), "{e}");
        }
    }

    #[test]
    fn the_build_platform_is_the_target_os() {
        assert_eq!(
            Platform::of_build(),
            if cfg!(target_os = "macos") {
                Macos
            } else {
                Linux
            }
        );
    }

    #[test]
    fn only_a_container_binds_no_client_listener() {
        assert!(client_listener_wanted(LinuxHost));
        assert!(client_listener_wanted(MacosHost));
        assert!(!client_listener_wanted(Container));
    }
}
