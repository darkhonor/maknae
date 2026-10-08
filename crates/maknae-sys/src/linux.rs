use std::io;
use std::os::fd::{AsRawFd, BorrowedFd};

/// The inode flags `lsattr` reads, from `ioctl(FS_IOC_GETFLAGS)` on the open file.
#[allow(unsafe_code)]
pub(crate) fn inode_flags(fd: BorrowedFd<'_>) -> io::Result<libc::c_int> {
    let mut flags: libc::c_long = 0;
    // SAFETY: the descriptor is borrowed, so it stays open for the whole call. The
    // request encodes an 8-byte (`long`) argument, so no handler copies out more than 8 bytes,
    // and the pointer is to `flags`, a zeroed local `c_long` that outlives the call.
    let rc = unsafe { libc::ioctl(fd.as_raw_fd(), libc::FS_IOC_GETFLAGS, &raw mut flags) };
    if rc == -1 {
        return Err(io::Error::last_os_error());
    }
    Ok(flags as libc::c_int)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::fd::AsFd;
    use std::os::unix::fs::OpenOptionsExt;

    #[test]
    fn a_path_only_descriptor_is_an_error_not_an_answer() {
        let p = std::env::temp_dir().join(format!("maknae_sys_linux_{}_opath", std::process::id()));
        std::fs::write(&p, b"").unwrap();
        let f = std::fs::OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_PATH)
            .open(&p)
            .unwrap();
        let flags = inode_flags(f.as_fd()).map_err(|e| e.raw_os_error());
        let answer = crate::is_append_only(&f).map_err(|e| e.raw_os_error());
        std::fs::remove_file(p).unwrap();
        assert_eq!(flags, Err(Some(libc::EBADF)));
        assert_eq!(answer, Err(Some(libc::EBADF)));
    }
}
