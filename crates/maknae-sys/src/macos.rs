use std::ffi::CString;
use std::io;
use std::os::unix::ffi::OsStrExt;
use std::path::{Path, PathBuf};

use crate::reply;

const COMMON_ATTRS: libc::attrgroup_t = 0x0800_0008;

/// The kernel's canonical path of the directory at `path`, from `getattrlist(ATTR_CMN_FULLPATH)`.
#[allow(unsafe_code)]
pub fn full_path(path: &Path) -> io::Result<PathBuf> {
    let c_path = CString::new(path.as_os_str().as_bytes())
        .map_err(|_| io::Error::from_raw_os_error(libc::EINVAL))?;
    let mut request = libc::attrlist {
        bitmapcount: libc::ATTR_BIT_MAP_COUNT,
        reserved: 0,
        commonattr: COMMON_ATTRS,
        volattr: 0,
        dirattr: 0,
        fileattr: 0,
        forkattr: 0,
    };
    let mut buf = [0u8; reply::REPLY_CAPACITY];
    // SAFETY: `c_path` is a NUL-terminated string that outlives the call. `request` is an
    // initialised `attrlist` that the kernel only reads. `buf` is a live, writable array,
    // and the size passed is `buf.len()`, so the kernel cannot write past its end.
    // Options 0 asks for nothing that dereferences any other memory.
    let rc = unsafe {
        libc::getattrlist(
            c_path.as_ptr(),
            (&raw mut request).cast(),
            buf.as_mut_ptr().cast(),
            buf.len(),
            0,
        )
    };
    if rc != 0 {
        return Err(io::Error::last_os_error());
    }
    reply::decode(&buf)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::ffi::OsStr;
    use std::os::unix::fs::{symlink, MetadataExt, PermissionsExt};

    struct Scratch {
        root: PathBuf,
        locked: Vec<PathBuf>,
    }

    impl Scratch {
        fn new(tag: &str) -> Self {
            let root =
                std::env::temp_dir().join(format!("maknae_sys_{tag}_{}", std::process::id()));
            let _ = std::fs::remove_dir_all(&root);
            std::fs::create_dir_all(&root).unwrap();
            let scratch = Scratch {
                root,
                locked: Vec::new(),
            };
            assert_ne!(
                std::fs::metadata(&scratch.root).unwrap().uid(),
                0,
                "these fixtures need a non-root user: root ignores the permission bits they set"
            );
            scratch
        }

        fn dir(&self, name: &str) -> PathBuf {
            let p = self.root.join(name);
            std::fs::create_dir_all(&p).unwrap();
            p
        }

        fn lock(&mut self, p: &Path) {
            std::fs::set_permissions(p, std::fs::Permissions::from_mode(0o000)).unwrap();
            self.locked.push(p.to_path_buf());
        }
    }

    impl Drop for Scratch {
        fn drop(&mut self) {
            for p in &self.locked {
                let _ = std::fs::set_permissions(p, std::fs::Permissions::from_mode(0o700));
            }
            let _ = std::fs::remove_dir_all(&self.root);
        }
    }

    #[test]
    fn the_request_is_objtype_then_fullpath() {
        assert_eq!(COMMON_ATTRS, 0x0800_0008);
    }

    #[test]
    fn the_request_mask_is_the_libc_objtype_and_fullpath_bits() {
        assert_eq!(
            COMMON_ATTRS,
            libc::ATTR_CMN_OBJTYPE | libc::ATTR_CMN_FULLPATH
        );
    }

    #[test]
    fn a_directory_resolves_to_its_canonical_absolute_path() {
        let s = Scratch::new("plain");
        let dir = s.dir("plain");
        let got = full_path(&dir).unwrap();
        assert!(got.is_absolute(), "{got:?}");
        assert!(got.ends_with("plain"), "{got:?}");
        assert_eq!(full_path(&got).unwrap(), got);
    }

    #[test]
    fn a_directory_with_no_permission_bits_resolves() {
        let mut s = Scratch::new("d000");
        let dir = s.dir("d000");
        let open = full_path(&dir).unwrap();
        s.lock(&dir);
        assert_eq!(full_path(&dir).unwrap(), open);
    }

    #[test]
    fn a_symlink_to_a_directory_with_no_permission_bits_resolves_to_the_target() {
        let mut s = Scratch::new("link000");
        let dir = s.dir("d000");
        let target = full_path(&dir).unwrap();
        let link = s.root.join("link");
        symlink(&dir, &link).unwrap();
        s.lock(&dir);
        let got = full_path(&link).unwrap();
        assert_eq!(got, target);
        assert!(!got.ends_with("link"), "{got:?}");
    }

    #[test]
    fn a_regular_file_is_not_a_directory() {
        let s = Scratch::new("file");
        let file = s.root.join("f");
        std::fs::write(&file, b"x").unwrap();
        assert_eq!(
            full_path(&file).unwrap_err().raw_os_error(),
            Some(libc::ENOTDIR)
        );
    }

    #[test]
    fn a_missing_path_is_not_found() {
        let s = Scratch::new("missing");
        assert_eq!(
            full_path(&s.root.join("absent"))
                .unwrap_err()
                .raw_os_error(),
            Some(libc::ENOENT)
        );
    }

    #[test]
    fn an_ancestor_with_no_permission_bits_is_refused() {
        let mut s = Scratch::new("ancestor");
        let a = s.dir("a");
        let b = s.dir("a/b");
        s.lock(&a);
        assert_eq!(
            full_path(&b).unwrap_err().raw_os_error(),
            Some(libc::EACCES)
        );
    }

    #[test]
    fn an_interior_nul_is_invalid() {
        let p = Path::new(OsStr::from_bytes(b"/tmp/a\0b"));
        assert_eq!(full_path(p).unwrap_err().raw_os_error(), Some(libc::EINVAL));
    }
}
