//! The programs a Maknae binary may execute, each at one absolute path (#327).

use std::path::Path;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Program {
    SystemdCreds,
    Setfacl,
    Getfacl,
    Restorecon,
    ApparmorParser,
    Usermod,
    Dseditgroup,
    Sudo,
    Env,
    Id,
    Security,
    Codesign,
    Chmod,
    Ls,
    Systemctl,
    Launchctl,
    Stat,
}

impl Program {
    pub const ALL: [Program; 17] = [
        Program::SystemdCreds,
        Program::Setfacl,
        Program::Getfacl,
        Program::Restorecon,
        Program::ApparmorParser,
        Program::Usermod,
        Program::Dseditgroup,
        Program::Sudo,
        Program::Env,
        Program::Id,
        Program::Security,
        Program::Codesign,
        Program::Chmod,
        Program::Ls,
        Program::Systemctl,
        Program::Launchctl,
        Program::Stat,
    ];

    pub fn path(self) -> &'static Path {
        Path::new(match self {
            Program::SystemdCreds => "/usr/bin/systemd-creds",
            Program::Setfacl => "/usr/bin/setfacl",
            Program::Getfacl => "/usr/bin/getfacl",
            Program::Restorecon => "/usr/sbin/restorecon",
            Program::ApparmorParser => "/usr/sbin/apparmor_parser",
            Program::Usermod => "/usr/sbin/usermod",
            Program::Dseditgroup => "/usr/sbin/dseditgroup",
            Program::Sudo => "/usr/bin/sudo",
            Program::Env => "/usr/bin/env",
            Program::Id => "/usr/bin/id",
            Program::Security => "/usr/bin/security",
            Program::Codesign => "/usr/bin/codesign",
            Program::Chmod => "/bin/chmod",
            Program::Ls => "/bin/ls",
            Program::Systemctl => "/usr/bin/systemctl",
            Program::Launchctl => "/bin/launchctl",
            Program::Stat => "/usr/bin/stat",
        })
    }
}

impl std::fmt::Display for Program {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        self.path().display().fmt(f)
    }
}

/// The one place a Maknae binary builds a process; `Command` does not search
/// `PATH` for a program named by absolute path.
#[expect(
    clippy::disallowed_methods,
    reason = "the one trusted spawn point (#327)"
)]
pub fn command(program: Program) -> std::process::Command {
    std::process::Command::new(program.path())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn position(p: Program) -> usize {
        match p {
            Program::SystemdCreds => 0,
            Program::Setfacl => 1,
            Program::Getfacl => 2,
            Program::Restorecon => 3,
            Program::ApparmorParser => 4,
            Program::Usermod => 5,
            Program::Dseditgroup => 6,
            Program::Sudo => 7,
            Program::Env => 8,
            Program::Id => 9,
            Program::Security => 10,
            Program::Codesign => 11,
            Program::Chmod => 12,
            Program::Ls => 13,
            Program::Systemctl => 14,
            Program::Launchctl => 15,
            Program::Stat => 16,
        }
    }

    /// A new variant does not compile until `position` names it, and then this
    /// fails until `ALL` lists it.
    #[test]
    fn all_lists_every_variant_once() {
        let mut seen = [false; Program::ALL.len()];
        for p in Program::ALL {
            assert_eq!(Program::ALL.get(position(p)), Some(&p), "{p:?}");
            seen[position(p)] = true;
        }
        assert!(seen.iter().all(|s| *s));
        assert_eq!(position(Program::Stat), Program::ALL.len() - 1);
    }

    #[test]
    fn a_program_displays_as_its_path() {
        for p in Program::ALL {
            assert_eq!(p.to_string(), p.path().to_str().unwrap(), "{p:?}");
        }
    }

    #[test]
    fn every_program_path_is_absolute() {
        for p in Program::ALL {
            assert!(p.path().is_absolute(), "{p:?}");
        }
    }

    #[test]
    fn command_runs_the_named_path_not_a_path_search() {
        for p in Program::ALL {
            assert_eq!(command(p).get_program(), p.path().as_os_str(), "{p:?}");
        }
    }

    fn table() -> Vec<(Program, &'static str)> {
        Program::ALL
            .into_iter()
            .map(|p| (p, p.path().to_str().unwrap()))
            .collect()
    }

    #[test]
    fn every_path_is_pinned() {
        assert_eq!(
            table(),
            vec![
                (Program::SystemdCreds, "/usr/bin/systemd-creds"),
                (Program::Setfacl, "/usr/bin/setfacl"),
                (Program::Getfacl, "/usr/bin/getfacl"),
                (Program::Restorecon, "/usr/sbin/restorecon"),
                (Program::ApparmorParser, "/usr/sbin/apparmor_parser"),
                (Program::Usermod, "/usr/sbin/usermod"),
                (Program::Dseditgroup, "/usr/sbin/dseditgroup"),
                (Program::Sudo, "/usr/bin/sudo"),
                (Program::Env, "/usr/bin/env"),
                (Program::Id, "/usr/bin/id"),
                (Program::Security, "/usr/bin/security"),
                (Program::Codesign, "/usr/bin/codesign"),
                (Program::Chmod, "/bin/chmod"),
                (Program::Ls, "/bin/ls"),
                (Program::Systemctl, "/usr/bin/systemctl"),
                (Program::Launchctl, "/bin/launchctl"),
                (Program::Stat, "/usr/bin/stat"),
            ]
        );
    }
}
