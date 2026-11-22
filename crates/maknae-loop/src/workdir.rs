//! The remotes of the checkout a tasker runs in: the nearest `.git` above the
//! working directory, its `config` read only when it is owned by the tasker and
//! not world-writable.
use maknae_agent::hints::{git_config_remotes, RemoteUrl};
use maknae_io::{Anchor, AnchorRequired, IoError, IoKind, StrategyPref, TargetRequired};
use std::path::{Path, PathBuf};

pub const GIT_CONFIG_MAX_BYTES: u64 = 64 * 1024;
pub const GIT_FILE_MAX_BYTES: u64 = 4096;

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Unreadable {
    Io(IoError),
    Walk { path: PathBuf, why: String },
    GitFile(PathBuf),
    CommonDir(PathBuf),
    Config(PathBuf),
}

impl std::fmt::Display for Unreadable {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Unreadable::Io(e) => write!(f, "{e}"),
            Unreadable::Walk { path, why } => write!(f, "{}: {why}", path.display()),
            Unreadable::GitFile(p) => write!(f, "{}: no gitdir line", p.display()),
            Unreadable::CommonDir(p) => write!(f, "{}: no path line", p.display()),
            Unreadable::Config(p) => write!(f, "{}: not a git config", p.display()),
        }
    }
}

/// `None` outside a checkout. `cwd` is absolute; every file read and every directory
/// it is read from must be owned by `uid` and not world-writable, and every file
/// read must have a single link. A symlinked `.git` is refused, never followed.
pub fn remotes(cwd: &Path, uid: u32) -> Result<Option<Vec<RemoteUrl>>, Unreadable> {
    let Some(dir) = nearest_checkout(cwd)? else {
        return Ok(None);
    };
    let dot_git = dir.join(".git");
    let (anchor, config) = match maknae_io::open_anchor(&dot_git, owned(uid), StrategyPref::Auto) {
        Ok(anchor) => (anchor, dot_git.join("config")),
        Err(IoError::Io {
            kind: IoKind::NotADirectory,
            ..
        }) => common_dir(dir, &dot_git, uid)?,
        Err(e) => return Err(Unreadable::Io(e)),
    };
    let bytes = anchor
        .read(Path::new("config"), None, file(uid, GIT_CONFIG_MAX_BYTES))
        .map_err(Unreadable::Io)?
        .value;
    git_config_remotes(&bytes)
        .map(Some)
        .map_err(|_| Unreadable::Config(config))
}

fn nearest_checkout(cwd: &Path) -> Result<Option<&Path>, Unreadable> {
    for dir in cwd.ancestors() {
        let dot_git = dir.join(".git");
        match maknae_io::presence(&dot_git) {
            Ok(true) => return Ok(Some(dir)),
            Ok(false) => {}
            Err(e) => {
                return Err(Unreadable::Walk {
                    path: dot_git,
                    why: e.to_string(),
                })
            }
        }
    }
    Ok(None)
}

/// A worktree's or submodule's `.git` file: `gitdir:` names the git directory,
/// whose `commondir`, when present, names the one holding `config`.
fn common_dir(dir: &Path, dot_git: &Path, uid: u32) -> Result<(Anchor, PathBuf), Unreadable> {
    let line = maknae_io::read_absolute(dot_git, file(uid, GIT_FILE_MAX_BYTES), StrategyPref::Auto)
        .map_err(Unreadable::Io)?
        .value;
    let gitdir = path_line(&line, Some("gitdir: "))
        .ok_or_else(|| Unreadable::GitFile(dot_git.to_path_buf()))?;
    let gitdir = dir.join(gitdir);
    let anchor = resolved(&gitdir, uid)?;
    let common = match anchor.read(Path::new("commondir"), None, file(uid, GIT_FILE_MAX_BYTES)) {
        Ok(read) => path_line(&read.value, None)
            .map(|common| gitdir.join(common))
            .ok_or_else(|| Unreadable::CommonDir(gitdir.join("commondir")))?,
        Err(IoError::Io {
            kind: IoKind::NotFound,
            ..
        }) => return Ok((anchor, gitdir.join("config"))),
        Err(e) => return Err(Unreadable::Io(e)),
    };
    Ok((resolved(&common, uid)?, common.join("config")))
}

fn path_line<'a>(bytes: &'a [u8], prefix: Option<&str>) -> Option<&'a Path> {
    let text = std::str::from_utf8(bytes).ok()?;
    let line = text.lines().next()?;
    let rest = match prefix {
        Some(p) => line.strip_prefix(p)?,
        None => line,
    };
    (!rest.is_empty()).then(|| Path::new(rest))
}

fn resolved(dir: &Path, uid: u32) -> Result<Anchor, Unreadable> {
    maknae_io::open_anchor_resolved(dir, owned(uid), StrategyPref::Auto).map_err(Unreadable::Io)
}

fn owned(uid: u32) -> AnchorRequired {
    AnchorRequired {
        owner: Some(uid),
        mode_mask: Some(0o002),
    }
}

fn file(uid: u32, max: u64) -> TargetRequired {
    TargetRequired {
        owner: Some(uid),
        mode_mask: Some(0o002),
        nlink_exactly_one: true,
        regular_file: true,
        max_bytes: Some(max),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;

    fn me() -> u32 {
        nix::unistd::geteuid().as_raw()
    }

    fn config(url: &str) -> String {
        format!("[core]\n\tbare = false\n[remote \"origin\"]\n\turl = {url}\n")
    }

    fn mkdir(dir: &Path) {
        std::fs::create_dir_all(dir).unwrap();
        std::fs::set_permissions(dir, std::fs::Permissions::from_mode(0o755)).unwrap();
    }

    fn write(path: &Path, text: &str, mode: u32) {
        mkdir(path.parent().unwrap());
        std::fs::write(path, text).unwrap();
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(mode)).unwrap();
    }

    fn git_dir(root: &Path, url: &str) {
        let git = root.join(".git");
        mkdir(&git);
        write(&git.join("config"), &config(url), 0o644);
    }

    fn hosts(got: Option<Vec<RemoteUrl>>) -> Vec<(String, String)> {
        got.expect("a checkout")
            .iter()
            .map(|r| (r.host().to_string(), r.path().to_string()))
            .collect()
    }

    fn pair(host: &str, path: &str) -> Vec<(String, String)> {
        vec![(host.into(), path.into())]
    }

    #[test]
    fn the_nearest_git_dirs_config_is_read() {
        let t = tempfile::tempdir().unwrap();
        git_dir(t.path(), "git@outer.example:o/outer.git");
        let repo = t.path().join("repo");
        git_dir(&repo, "git@github.com:o/inner.git");
        let deep = repo.join("a/b");
        std::fs::create_dir_all(&deep).unwrap();
        assert_eq!(
            hosts(remotes(&deep, me()).unwrap()),
            pair("github.com", "o/inner")
        );
        assert_eq!(
            hosts(remotes(&repo, me()).unwrap()),
            pair("github.com", "o/inner")
        );
        let beside = t.path().join("beside");
        std::fs::create_dir_all(&beside).unwrap();
        assert_eq!(
            hosts(remotes(&beside, me()).unwrap()),
            pair("outer.example", "o/outer")
        );
    }

    #[test]
    fn a_worktree_git_file_leads_to_the_common_config() {
        let t = tempfile::tempdir().unwrap();
        let main = t.path().join("main");
        git_dir(&main, "ssh://git@gitlab.example/g/p.git");
        let gitdir = main.join(".git/worktrees/wt");
        write(&gitdir.join("commondir"), "../..\n", 0o644);
        write(
            &gitdir.join("config"),
            &config("git@decoy.example:o/decoy.git"),
            0o644,
        );
        let wt = t.path().join("wt");
        write(
            &wt.join(".git"),
            &format!("gitdir: {}\n", gitdir.display()),
            0o644,
        );
        let inside = wt.join("src");
        std::fs::create_dir_all(&inside).unwrap();
        assert_eq!(
            hosts(remotes(&inside, me()).unwrap()),
            pair("gitlab.example", "g/p")
        );

        let module = main.join(".git/modules/sub");
        write(
            &module.join("config"),
            &config("https://github.com/o/sub.git"),
            0o644,
        );
        let sub = main.join("sub");
        write(&sub.join(".git"), "gitdir: ../.git/modules/sub\n", 0o644);
        assert_eq!(
            hosts(remotes(&sub, me()).unwrap()),
            pair("github.com", "o/sub")
        );

        let lost = t.path().join("lost");
        write(&lost.join(".git"), "not a gitdir line\n", 0o644);
        assert_eq!(
            remotes(&lost, me()),
            Err(Unreadable::GitFile(lost.join(".git")))
        );

        let empty = main.join(".git/worktrees/empty");
        write(&empty.join("commondir"), "\n", 0o644);
        let wt2 = t.path().join("wt2");
        write(
            &wt2.join(".git"),
            &format!("gitdir: {}\n", empty.display()),
            0o644,
        );
        let got = remotes(&wt2, me());
        assert_eq!(got, Err(Unreadable::CommonDir(empty.join("commondir"))));
        assert!(got
            .unwrap_err()
            .to_string()
            .ends_with("commondir: no path line"));
    }

    #[test]
    fn outside_a_checkout_nothing_is_read() {
        let t = tempfile::tempdir().unwrap();
        let dir = t.path().join("plain/dir");
        std::fs::create_dir_all(&dir).unwrap();
        assert_eq!(remotes(&dir, me()), Ok(None));
        git_dir(
            t.path().join("plain/dir/below").as_path(),
            "git@github.com:o/r",
        );
        assert_eq!(remotes(&dir, me()), Ok(None));
    }

    #[test]
    fn a_config_others_can_write_is_not_read() {
        for mode in [0o646, 0o666] {
            let t = tempfile::tempdir().unwrap();
            git_dir(t.path(), "git@github.com:o/r.git");
            let cfg = t.path().join(".git/config");
            std::fs::set_permissions(&cfg, std::fs::Permissions::from_mode(mode)).unwrap();
            match remotes(t.path(), me()) {
                Err(Unreadable::Io(IoError::InsecurePermissions { .. })) => {}
                other => panic!("{mode:o}: {other:?}"),
            }
        }
        let t = tempfile::tempdir().unwrap();
        git_dir(t.path(), "git@github.com:o/r.git");
        let git = t.path().join(".git");
        std::fs::set_permissions(&git, std::fs::Permissions::from_mode(0o775)).unwrap();
        std::fs::set_permissions(git.join("config"), std::fs::Permissions::from_mode(0o664))
            .unwrap();
        assert_eq!(
            hosts(remotes(t.path(), me()).unwrap()),
            pair("github.com", "o/r")
        );
        std::fs::set_permissions(&git, std::fs::Permissions::from_mode(0o777)).unwrap();
        match remotes(t.path(), me()) {
            Err(Unreadable::Io(IoError::InsecurePermissions { .. })) => {}
            other => panic!("{other:?}"),
        }
        std::fs::set_permissions(&git, std::fs::Permissions::from_mode(0o755)).unwrap();
        match remotes(t.path(), me().wrapping_add(1)) {
            Err(Unreadable::Io(IoError::NotOwned { .. })) => {}
            other => panic!("{other:?}"),
        }
    }

    #[test]
    fn an_oversize_config_is_not_read() {
        let t = tempfile::tempdir().unwrap();
        git_dir(t.path(), "git@github.com:o/r.git");
        let cfg = t.path().join(".git/config");
        let head = config("git@github.com:o/r.git");
        let fill = GIT_CONFIG_MAX_BYTES as usize - head.len() - 1;
        let at_bound = format!("{head}#{}", "x".repeat(fill));
        assert_eq!(at_bound.len() as u64, GIT_CONFIG_MAX_BYTES);
        write(&cfg, &at_bound, 0o644);
        assert_eq!(
            hosts(remotes(t.path(), me()).unwrap()),
            pair("github.com", "o/r")
        );
        write(&cfg, &format!("{at_bound}x"), 0o644);
        match remotes(t.path(), me()) {
            Err(Unreadable::Io(IoError::TargetTooLarge { .. })) => {}
            other => panic!("{other:?}"),
        }

        let wt = t.path().join("wt");
        let gitfile = format!("gitdir: {}", t.path().join(".git").display());
        let pad = GIT_FILE_MAX_BYTES as usize + 1 - gitfile.len();
        write(
            &wt.join(".git"),
            &format!("{gitfile}{}", "\n".repeat(pad)),
            0o644,
        );
        match remotes(&wt, me()) {
            Err(Unreadable::Io(IoError::TargetTooLarge { .. })) => {}
            other => panic!("{other:?}"),
        }
    }

    #[test]
    fn a_symlinked_config_is_refused() {
        let t = tempfile::tempdir().unwrap();
        let real = t.path().join("real");
        git_dir(&real, "git@github.com:o/r.git");

        let linked = t.path().join("linked");
        mkdir(&linked.join(".git"));
        std::os::unix::fs::symlink(real.join(".git/config"), linked.join(".git/config")).unwrap();
        match remotes(&linked, me()) {
            Err(Unreadable::Io(IoError::Symlink { .. })) => {}
            other => panic!("{other:?}"),
        }

        let dot_git = t.path().join("dot-git");
        std::fs::create_dir_all(&dot_git).unwrap();
        std::os::unix::fs::symlink(real.join(".git"), dot_git.join(".git")).unwrap();
        match remotes(&dot_git, me()) {
            Err(Unreadable::Io(IoError::Symlink { .. })) => {}
            other => panic!("{other:?}"),
        }

        let module = t.path().join("module");
        std::fs::create_dir_all(&module).unwrap();
        std::os::unix::fs::symlink(real.join(".git/config"), module.join("config")).unwrap();
        let wt = t.path().join("wt");
        write(
            &wt.join(".git"),
            &format!("gitdir: {}\n", module.display()),
            0o644,
        );
        match remotes(&wt, me()) {
            Err(Unreadable::Io(IoError::Symlink { .. })) => {}
            other => panic!("{other:?}"),
        }
    }
    #[test]
    fn every_file_and_directory_read_is_owned_by_the_tasker_and_not_world_writable() {
        assert_eq!(
            file(7, 9),
            TargetRequired {
                owner: Some(7),
                mode_mask: Some(0o002),
                nlink_exactly_one: true,
                regular_file: true,
                max_bytes: Some(9),
            }
        );
        assert_eq!(
            owned(7),
            AnchorRequired {
                owner: Some(7),
                mode_mask: Some(0o002),
            }
        );
    }
    #[test]
    fn a_hardlinked_config_is_refused() {
        let t = tempfile::tempdir().unwrap();
        let root = t.path().join("r");
        git_dir(&root, "git@github.com:o/r.git");
        std::fs::hard_link(root.join(".git/config"), t.path().join("second")).unwrap();
        match remotes(&root, me()) {
            Err(Unreadable::Io(IoError::MultiplyLinked { .. })) => {}
            other => panic!("{other:?}"),
        }
    }

    #[test]
    fn a_hardlinked_git_file_or_commondir_is_refused() {
        let t = tempfile::tempdir().unwrap();
        let main = t.path().join("main");
        git_dir(&main, "git@github.com:o/r.git");
        let planted = t.path().join("planted");
        write(
            &planted,
            &format!("gitdir: {}\n", main.join(".git").display()),
            0o644,
        );
        let wt = t.path().join("wt");
        mkdir(&wt);
        std::fs::hard_link(&planted, wt.join(".git")).unwrap();
        match remotes(&wt, me()) {
            Err(Unreadable::Io(IoError::MultiplyLinked { .. })) => {}
            other => panic!("{other:?}"),
        }

        let gitdir = main.join(".git/worktrees/x");
        write(&gitdir.join("commondir"), "../..\n", 0o644);
        std::fs::hard_link(gitdir.join("commondir"), t.path().join("second")).unwrap();
        let wt2 = t.path().join("wt2");
        write(
            &wt2.join(".git"),
            &format!("gitdir: {}\n", gitdir.display()),
            0o644,
        );
        match remotes(&wt2, me()) {
            Err(Unreadable::Io(IoError::MultiplyLinked { .. })) => {}
            other => panic!("{other:?}"),
        }
    }
}
